import type { HeaderAuditResult, Finding } from "../types";

const SECURITY_HEADERS: Record<string, string> = {
  "strict-transport-security": "Missing HSTS leaves transport downgrade gaps.",
  "content-security-policy": "Missing CSP increases script injection exposure.",
  "x-frame-options": "Missing X-Frame-Options permits clickjacking frames.",
  "x-content-type-options": "Missing X-Content-Type-Options enables MIME sniffing.",
  "referrer-policy": "Missing Referrer-Policy may leak navigation metadata.",
};

export async function headerAudit(targetUrl: string): Promise<HeaderAuditResult> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const response = await fetch(targetUrl, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "AETHER-Security-Auditor/1.0" },
    });
    clearTimeout(timeout);

    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const findings: Finding[] = [];
    for (const [header, detail] of Object.entries(SECURITY_HEADERS)) {
      if (!headers[header]) {
        findings.push({
          id: `header:${header}`,
          category: "missing_header",
          title: `Missing ${header}`,
          severity: "Medium",
          detail,
          attack_vector: "Response header inspection",
          detected_threat: detail,
          evidence_snippet: detail,
          provided_solution: `Add the '${header}' response header.`,
          evidence: { header, url: targetUrl },
        });
      }
    }

    return {
      final_url: response.url,
      status_code: response.status,
      headers,
      findings,
    };
  } catch (error) {
    return {
      final_url: targetUrl,
      status_code: null,
      headers: {},
      findings: [],
      error: `Header audit request failed: ${error}`,
    };
  }
}

export function formatHeaderLogs(result: HeaderAuditResult): string[] {
  if (result.error) return [`[EXECUTE] HEADER_AUDIT: ${result.error.toUpperCase()}.`];
  const logs: string[] = [];
  if (result.status_code) {
    logs.push(`[EXECUTE] HEADER_AUDIT: RECEIVED HTTP ${result.status_code} FROM ${result.final_url.toUpperCase()}.`);
  } else {
    logs.push(`[EXECUTE] HEADER_AUDIT: REQUEST FAILED FOR ${result.final_url.toUpperCase()}.`);
  }
  if (result.findings.length > 0) {
    const summary = result.findings.slice(0, 3).map((f) => f.category.toUpperCase()).join("; ");
    logs.push(`[EXECUTE] HEADER_AUDIT: MISCONFIGURATION SIGNALS DETECTED IN ${summary}.`);
  } else {
    logs.push("[EXECUTE] HEADER_AUDIT: CORE SECURITY HEADER CHECKS RETURNED CLEAN.");
  }
  return logs;
}
