import { createHash } from "crypto";
import type { AuditResult, Finding } from "../types";

const SQLI_PAYLOADS = ["'", '"', "OR 1=1"];
const SQL_ERROR_PATTERNS = [
  /sql syntax/gi, /mysql/gi, /postgresql/gi, /sqlite/gi,
  /odbc/gi, /sqlstate/gi, /unterminated quoted string/gi,
  /syntax error at or near/gi,
];
const RATE_LIMIT_HEADERS = new Set([
  "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
  "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
]);
const KNOWN_WAF_SIGNATURES: Record<string, string> = {
  cloudflare: "Cloudflare", akamai: "Akamai", sucuri: "Sucuri",
  imperva: "Imperva", fastly: "Fastly", aws: "AWS",
};
const EXPOSED_SERVER_PATTERNS = [
  /apache\/\d/i, /nginx\/\d/i, /iis\/\d/i, /php\/\d/i,
  /express/i, /gunicorn\/\d/i, /uvicorn/i,
];

function findingId(prefix: string, ...parts: string[]): string {
  const digest = createHash("sha1").update(parts.join(":")).digest("hex").slice(0, 12);
  return `${prefix}:${digest}`;
}

async function requestSnapshot(targetUrl: string) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(targetUrl, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "AETHER-Security-Auditor/1.0" },
    });
    clearTimeout(timeout);
    const headers: Record<string, string> = {};
    response.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    const text = (await response.text()).slice(0, 8000);
    return { url: response.url, status_code: response.status, headers, text };
  } catch (error) {
    clearTimeout(timeout);
    throw error;
  }
}

function profileTarget(targetUrl: string, baseResponse: { headers: Record<string, string>; status_code: number; url: string }) {
  const headers = baseResponse.headers;
  const findings: Finding[] = [];
  const profiles: AuditResult["profiles"] = [];

  const rateLimitPresent = Object.keys(headers).some((h) => RATE_LIMIT_HEADERS.has(h));
  const headerBlob = JSON.stringify(headers).toLowerCase();
  const wafMatches = Object.entries(KNOWN_WAF_SIGNATURES)
    .filter(([sig]) => headerBlob.includes(sig))
    .map(([, label]) => label);
  const serverBanner = headers["server"] || "";
  const exposedBanner = serverBanner && EXPOSED_SERVER_PATTERNS.some((p) => p.test(serverBanner));

  if (!rateLimitPresent) {
    findings.push({
      id: findingId("vuln", "rate-limit", targetUrl),
      category: "ddos_heuristic",
      title: "Missing Rate-Limit Signaling",
      severity: "Medium",
      detail: "No standard rate-limit headers were observed, which may indicate weak request-throttling controls.",
      attack_vector: "Response header inspection",
      detected_threat: "Missing rate-limit headers",
      evidence_snippet: JSON.stringify(Object.keys(headers).slice(0, 20)),
      provided_solution: "Add rate-limiting headers to API responses.",
      evidence: { headers_seen: Object.keys(headers).slice(0, 20) },
    });
  }
  if (wafMatches.length === 0) {
    findings.push({
      id: findingId("vuln", "waf", targetUrl),
      category: "ddos_heuristic",
      title: "No WAF Signature Detected",
      severity: "Low",
      detail: "No common upstream WAF signature was detected in the response headers.",
      attack_vector: "Response header inspection",
      detected_threat: "No WAF signature",
      evidence_snippet: JSON.stringify(Object.keys(headers).slice(0, 20)),
      provided_solution: "Consider deploying a WAF in front of the application.",
      evidence: { headers_seen: Object.keys(headers).slice(0, 20) },
    });
  }
  if (exposedBanner) {
    findings.push({
      id: findingId("vuln", "server-banner", serverBanner),
      category: "ddos_heuristic",
      title: "Verbose Server Banner",
      severity: "Medium",
      detail: "The server banner exposes implementation details that can help attackers tune exploit strategies.",
      attack_vector: "Response header inspection",
      detected_threat: `Server banner: ${serverBanner}`,
      evidence_snippet: serverBanner,
      provided_solution: "Remove or obfuscate the Server header.",
      evidence: { server: serverBanner },
    });
  }

  profiles.push({
    profile_type: "vulnerability_profiler",
    label: "Transport Resilience",
    summary: "Profiles rate-limit signaling, edge filtering, and banner exposure for abuse resistance.",
    details: {
      rate_limit_present: rateLimitPresent,
      waf_signatures: wafMatches,
      server_banner: serverBanner || null,
      exposed_banner: !!exposedBanner,
    },
  });

  return { findings, profiles };
}

async function testSqlReflections(targetUrl: string): Promise<{ tested_params: string[]; findings: Finding[] }> {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { tested_params: [], findings: [] };
  }

  const params = Array.from(parsed.searchParams.entries());
  if (params.length === 0) return { tested_params: [], findings: [] };

  const findings: Finding[] = [];
  const testedParams: string[] = [];

  for (const [key, value] of params) {
    for (const payload of SQLI_PAYLOADS) {
      testedParams.push(`${key}:${payload}`);
      const mutatedUrl = new URL(parsed.toString());
      mutatedUrl.searchParams.set(key, `${value}${payload}`);

      try {
        const result = await Promise.race([
          requestSnapshot(mutatedUrl.toString()),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000)),
        ]);
        const text = result.text || "";
        const hasSqlError = SQL_ERROR_PATTERNS.some((p) => p.test(text));
        const payloadReflected = text.includes(payload);

        if (hasSqlError) {
          findings.push({
            id: findingId("vuln", "sqli-error", key, payload),
            category: "sqli_heuristic",
            title: `SQL Error Reflection via ${key}`,
            severity: "High",
            detail: `The parameter '${key}' triggered a database-flavored error response.`,
            attack_vector: "SQL injection payload injection",
            detected_threat: `SQL error from parameter: ${key}`,
            evidence_snippet: `Payload: ${payload}, Status: ${result.status_code}`,
            provided_solution: "Use parameterized queries for all database interactions.",
            evidence: { parameter: key, payload, status_code: result.status_code, url: result.url },
          });
        } else if (payloadReflected) {
          findings.push({
            id: findingId("vuln", "reflection", key, payload),
            category: "sqli_heuristic",
            title: `Reflected Input Surface via ${key}`,
            severity: "Medium",
            detail: `The parameter '${key}' reflected a probe payload in the response body.`,
            attack_vector: "Input reflection testing",
            detected_threat: `Reflected payload in parameter: ${key}`,
            evidence_snippet: `Payload: ${payload}, Status: ${result.status_code}`,
            provided_solution: "Review input handling and apply contextual output encoding.",
            evidence: { parameter: key, payload, status_code: result.status_code, url: result.url },
          });
        }
      } catch {
        continue;
      }
    }
  }

  return { tested_params: testedParams, findings };
}

export async function auditEngine(targetUrl: string): Promise<AuditResult> {
  try {
    const baseResponse = await requestSnapshot(targetUrl);
    const sqliResult = await testSqlReflections(targetUrl);
    const profileResult = profileTarget(targetUrl, baseResponse);

    return {
      target_url: targetUrl,
      tested_params: sqliResult.tested_params,
      base_response: {
        url: baseResponse.url,
        status_code: baseResponse.status_code,
        headers: baseResponse.headers,
      },
      findings: [...sqliResult.findings, ...profileResult.findings],
      profiles: profileResult.profiles,
    };
  } catch (error) {
    return {
      target_url: targetUrl,
      tested_params: [],
      base_response: {},
      findings: [],
      profiles: [],
      error: `Audit engine failed: ${error}`,
    };
  }
}

export function formatAuditLogs(result: AuditResult): string[] {
  if (result.error) return [`[EXECUTE] AUDIT_ENGINE: ${result.error.toUpperCase()}.`];
  const logs = [
    `[EXECUTE] AUDIT_ENGINE: PROFILED ${result.tested_params.length} PARAMETER PROBES AND ${result.profiles.length} RESILIENCE PROFILES.`,
  ];
  if (result.findings.length > 0) {
    const summary = result.findings.slice(0, 3)
      .map((f) => `${f.category.toUpperCase()}::${f.title.toUpperCase().slice(0, 42)}`)
      .join("; ");
    logs.push(`[EXECUTE] AUDIT_ENGINE: VULNERABILITY SIGNALS DETECTED - ${summary}.`);
  } else {
    logs.push("[EXECUTE] AUDIT_ENGINE: NO SQLI OR ABUSE-RESILIENCE HEURISTICS TRIPPED DURING THIS HUNT.");
  }
  return logs;
}
