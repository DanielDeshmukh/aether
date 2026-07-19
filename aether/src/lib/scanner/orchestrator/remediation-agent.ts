import type { Finding } from "../types";

const NVIDIA_BASE = "https://integrate.api.nvidia.com/v1";

export async function generateRemediation(
  targetUrl: string,
  vulnerability: Finding,
  results: Record<string, unknown>
): Promise<{ vuln_id: string; title: string; language: string; code: string; summary: string }> {
  const apiKey = process.env.NVIDIA_API_KEY?.trim();
  if (!apiKey || apiKey.toLowerCase().startsWith("your_")) {
    return fallbackFix(vulnerability);
  }

  const prompt = `You are a Lead Security Consultant generating a copy-paste remediation patch for a web security finding.
Target URL: ${targetUrl}
Vulnerability: ${JSON.stringify(vulnerability)}
Related Scan Results: ${JSON.stringify(results)}

Return raw JSON only in this shape:
{ "vuln_id": "...", "title": "...", "language": "...", "code": "...", "summary": "..." }

Rules:
- Prefer deployable Nginx, Apache, Node.js, or Python fixes when appropriate.
- The code must be copy-paste ready.
- Keep the summary concise and implementation-focused.`;

  try {
    const response = await fetch(`${NVIDIA_BASE}/chat/completions`, {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "nvidia/llama-3.3-nemotron-super-49b-v1.5",
        messages: [{ role: "user", content: prompt }],
        response_format: { type: "json_object" },
        max_tokens: 2048,
        temperature: 0.2,
      }),
    });
    const data = await response.json();
    let cleaned = (data.choices?.[0]?.message?.content || "").trim();
    if (cleaned.startsWith("```")) cleaned = cleaned.replace(/^```json?\n?/, "").replace(/\n?```$/, "");
    const parsed = JSON.parse(cleaned);
    return {
      vuln_id: parsed.vuln_id || vulnerability.id,
      title: parsed.title || "Generated Remediation",
      language: parsed.language || "text",
      code: parsed.code || fallbackFix(vulnerability).code,
      summary: parsed.summary || vulnerability.detail,
    };
  } catch {
    return fallbackFix(vulnerability);
  }
}

function fallbackFix(vuln: Finding) {
  return {
    vuln_id: vuln.id,
    title: "Review application configuration",
    language: "text",
    code: "Review the affected service configuration and add an explicit hardening control for the reported issue.",
    summary: vuln.detail || "Apply the generated hardening change and redeploy the service.",
  };
}
