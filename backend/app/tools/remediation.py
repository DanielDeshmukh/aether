import json
import os
from typing import Any, Dict, List

try:
    from google import genai
except ImportError:  # pragma: no cover - resolved when requirements are installed
    genai = None


HEADER_FIXES = {
    "strict-transport-security": {
        "title": "Enable HSTS in Nginx",
        "language": "nginx",
        "code": """add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;""",
    },
    "content-security-policy": {
        "title": "Add CSP in Nginx",
        "language": "nginx",
        "code": """add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';" always;""",
    },
    "x-frame-options": {
        "title": "Block framing in Nginx",
        "language": "nginx",
        "code": """add_header X-Frame-Options "DENY" always;""",
    },
    "x-content-type-options": {
        "title": "Disable MIME sniffing in Nginx",
        "language": "nginx",
        "code": """add_header X-Content-Type-Options "nosniff" always;""",
    },
    "referrer-policy": {
        "title": "Set Referrer-Policy in Nginx",
        "language": "nginx",
        "code": """add_header Referrer-Policy "strict-origin-when-cross-origin" always;""",
    },
}


def _fallback_fix(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    header = vulnerability.get("header", "")
    base = HEADER_FIXES.get(
        header,
        {
            "title": "Review application configuration",
            "language": "text",
            "code": "Review the affected service configuration and add an explicit hardening control for the reported issue.",
        },
    )
    return {
        "vuln_id": vulnerability.get("id"),
        "title": base["title"],
        "language": base["language"],
        "code": base["code"],
        "summary": vulnerability.get("detail", "Apply the generated hardening change and redeploy the service."),
    }


def generate_remediation(target_url: str, vulnerability: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if genai is None or not api_key or api_key.lower().startswith("your_"):
        return _fallback_fix(vulnerability)

    prompt = f"""
You are a Lead Security Consultant generating a copy-paste remediation patch for a web security finding.
Target URL: {target_url}
Vulnerability JSON: {json.dumps(vulnerability)}
Related Scan Results JSON: {json.dumps(results)}

Return raw JSON only in this shape:
{{
  "vuln_id": "...",
  "title": "...",
  "language": "...",
  "code": "...",
  "summary": "..."
}}

Rules:
- Prefer deployable Nginx, Apache, Node.js, or Python fixes when appropriate.
- The code must be copy-paste ready.
- Keep the summary concise and implementation-focused.
- Do not mention prompts, schemas, or yourself.
""".strip()

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config={"response_mime_type": "application/json"},
        )
        cleaned = response.text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            cleaned = cleaned.removeprefix("json").strip()
        parsed = json.loads(cleaned)
        return {
            "vuln_id": parsed.get("vuln_id", vulnerability.get("id")),
            "title": parsed.get("title", "Generated Remediation"),
            "language": parsed.get("language", "text"),
            "code": parsed.get("code", _fallback_fix(vulnerability)["code"]),
            "summary": parsed.get("summary", vulnerability.get("detail", "")),
        }
    except Exception:
        return _fallback_fix(vulnerability)


def find_vulnerability(results: Dict[str, Any], vuln_id: str) -> Dict[str, Any] | None:
    header_findings: List[Dict[str, Any]] = (results.get("header_audit") or {}).get("findings", [])
    for finding in header_findings:
        if finding.get("id") == vuln_id:
            return finding
    audit_findings: List[Dict[str, Any]] = (results.get("audit_engine") or {}).get("findings", [])
    for finding in audit_findings:
        if finding.get("id") == vuln_id:
            return finding
    return None
