import { createHash } from "crypto";
import type { Finding, HeuristicResult, AuditResult } from "../types";
import { auditEngine, formatAuditLogs } from "../tools/audit-engine";
import { isSafeUrl } from "../tools/validators";

const SENSITIVE_FILES = [
  { path: ".env", expected: [/^[A-Z0-9_]+=/m], ct: ["text/plain", "application/octet-stream", ""] },
  { path: ".git/config", expected: [/\[core\]/], ct: ["text/plain", "application/octet-stream", ""] },
  { path: "wp-config.php", expected: [/<\?php/, /DB_PASSWORD/], ct: ["text/plain", "application/x-httpd-php", "application/octet-stream", ""] },
  { path: "package.json", expected: [/"name":/, /"dependencies":/], ct: ["application/json", "text/plain", ""] },
  { path: "docker-compose.yml", expected: [/services:/, /version:/], ct: ["text/yaml", "text/plain", "application/octet-stream", ""] },
];

const CORS_PROBE_HEADERS = {
  Origin: "https://evil-attacker-domain.com",
  "Access-Control-Request-Method": "POST",
};

async function guardedGet(url: string): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "AETHER-Security-Auditor/1.0" },
    });
    clearTimeout(timeout);
    return res;
  } catch (e) {
    clearTimeout(timeout);
    throw e;
  }
}

async function guardedOptions(url: string, headers?: Record<string, string>): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(url, {
      method: "OPTIONS",
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "AETHER-Security-Auditor/1.0", ...headers },
    });
    clearTimeout(timeout);
    return res;
  } catch (e) {
    clearTimeout(timeout);
    throw e;
  }
}

async function checkSensitiveFiles(targetUrl: string, findings: Finding[]): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return;
  }
  if (!isSafeUrl(targetUrl)) return;

  const baseUrl = `${parsed.protocol}//${parsed.host}`;

  let baselineHash: string | null = null;
  try {
    const bogusUrl = `${baseUrl}/aether_nonexistent_${createHash("md5").update(baseUrl).digest("hex").slice(0, 8)}`;
    const response = await guardedGet(bogusUrl);
    if (response.status === 200) {
      const buf = Buffer.from(await response.arrayBuffer());
      baselineHash = createHash("sha256").update(buf).digest("hex");
    }
  } catch { /* ignore */ }

  for (const fileInfo of SENSITIVE_FILES) {
    const probeUrl = `${baseUrl}/${fileInfo.path}`;
    try {
      const response = await guardedGet(probeUrl);
      if (response.status === 200) {
        const buf = Buffer.from(await response.arrayBuffer());
        const contentHash = createHash("sha256").update(buf).digest("hex");
        if (baselineHash && contentHash === baselineHash) continue;

        const ct = (response.headers.get("content-type") || "").split(";")[0].toLowerCase();
        if (fileInfo.ct.length > 0 && !fileInfo.ct.includes(ct) && !fileInfo.ct.includes("")) continue;

        const text = await response.text();
        const matches = fileInfo.expected.every((p) => p.test(text));
        if (matches) {
          findings.push({
            id: `sensitive:${fileInfo.path}`,
            category: "A05:2021-Security Misconfiguration",
            title: `Sensitive File Exposure: ${fileInfo.path}`,
            severity: "High",
            detail: `The sensitive file '${fileInfo.path}' was found to be publicly accessible.`,
            attack_vector: "Direct URL path probing",
            detected_threat: `Exposed file: ${fileInfo.path}`,
            evidence_snippet: `HTTP 200 OK at ${probeUrl}. Content matched fingerprint.`,
            provided_solution: `Remove or restrict access to ${fileInfo.path}.`,
            evidence: { path: fileInfo.path, status_code: 200, content_type: ct, url: probeUrl },
          });
        }
      }
    } catch {
      continue;
    }
  }
}

async function checkCorsMisconfiguration(targetUrl: string, findings: Finding[]): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return;
  }
  const baseUrl = `${parsed.protocol}//${parsed.host}`;
  const targets = [...new Set([targetUrl, baseUrl])];

  for (const url of targets) {
    try {
      const response = await guardedOptions(url, CORS_PROBE_HEADERS);
      const allowOrigin = response.headers.get("access-control-allow-origin");
      const allowCreds = response.headers.get("access-control-allow-credentials")?.toLowerCase() === "true";

      const isWildcard = allowOrigin === "*";
      const isReflected = allowOrigin === CORS_PROBE_HEADERS.Origin;

      if (isWildcard || isReflected) {
        let severity: Finding["severity"] = "Low";
        if (allowCreds) severity = "High";
        else if (isWildcard) severity = "Low";

        if (severity !== "Low") {
          findings.push({
            id: `cors:${severity.toLowerCase()}`,
            category: "A05:2021-Security Misconfiguration",
            title: `Permissive CORS Policy (${severity})`,
            severity,
            detail: `The server implements a permissive CORS policy (Access-Control-Allow-Origin: ${allowOrigin}, Allow-Credentials: ${allowCreds}).`,
            attack_vector: "CORS preflight request with arbitrary Origin",
            detected_threat: `CORS: ${allowOrigin}`,
            evidence_snippet: `Access-Control-Allow-Origin: ${allowOrigin}, Allow-Credentials: ${allowCreds}`,
            provided_solution: "Restrict CORS to trusted origins and avoid allowing credentials with wildcard.",
            evidence: { allow_origin: allowOrigin, allow_credentials: allowCreds, url },
          });
        }
      }
    } catch {
      continue;
    }
  }
}

export async function heuristicEngine(targetUrl: string): Promise<HeuristicResult> {
  const findings: Finding[] = [];
  const profiles: HeuristicResult["profiles"] = [];

  // Base audit
  try {
    const baseAudit = await auditEngine(targetUrl);
    findings.push(...baseAudit.findings);
    profiles.push(...baseAudit.profiles);
  } catch { /* ignore */ }

  // Sensitive files
  await checkSensitiveFiles(targetUrl, findings);

  // CORS
  await checkCorsMisconfiguration(targetUrl, findings);

  return { target_url: targetUrl, findings, profiles };
}
