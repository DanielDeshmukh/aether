import json
import os
from typing import Any, Dict, List

try:
    from google import genai
except ImportError:  # pragma: no cover - resolved when requirements are installed
    genai = None


HEADER_FIXES = {
    "strict-transport-security": {
        "title": "Enable HSTS",
        "language": "nginx",
        "variants": {
            "nginx": {"language": "nginx", "code": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'},
            "apache": {"language": "apache", "code": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'},
            "node": {"language": "javascript", "code": "const helmet = require('helmet');\napp.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));"},
            "python": {"language": "python", "code": "# Django settings.py\nSECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True\nSECURE_HSTS_PRELOAD = True"},
            "cloudfront": {"language": "yaml", "code": "# AWS CloudFront response headers policy\nType: AWS::CloudFront::ResponseHeadersPolicy\nProperties:\n  ResponseHeadersPolicyConfig:\n    Name: HSTS-Policy\n    CustomHeadersConfig:\n      Items:\n        - Header: Strict-Transport-Security\n          Value: max-age=31536000; includeSubDomains\n          Override: true"},
            "cloudflare": {"language": "javascript", "code": "// Cloudflare Workers\naddEventListener('fetch', event => {\n  event.respondWith(handleRequest(event.request));\n});\n\nasync function handleRequest(request) {\n  const response = await fetch(request);\n  const newHeaders = new Headers(response.headers);\n  newHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');\n  return new Response(response.body, { headers: newHeaders });\n}"},
        },
        "code": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
    },
    "content-security-policy": {
        "title": "Add CSP",
        "language": "nginx",
        "variants": {
            "nginx": {"language": "nginx", "code": 'add_header Content-Security-Policy "default-src \'self\'; object-src \'none\'; frame-ancestors \'none\'; base-uri \'self\';" always;'},
            "apache": {"language": "apache", "code": "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\""},
            "node": {"language": "javascript", "code": "const helmet = require('helmet');\napp.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self\"], objectSrc: [\"'none\"], frameAncestors: [\"'none\"] } }));"},
            "cloudfront": {"language": "yaml", "code": "# AWS CloudFront response headers policy\nType: AWS::CloudFront::ResponseHeadersPolicy\nProperties:\n  ResponseHeadersPolicyConfig:\n    Name: CSP-Policy\n    CustomHeadersConfig:\n      Items:\n        - Header: Content-Security-Policy\n          Value: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\n          Override: true"},
        },
        "code": 'add_header Content-Security-Policy "default-src \'self\'; object-src \'none\'; frame-ancestors \'none\'; base-uri \'self\';" always;',
    },
    "x-frame-options": {
        "title": "Block framing",
        "language": "nginx",
        "variants": {
            "nginx": {"language": "nginx", "code": 'add_header X-Frame-Options "DENY" always;'},
            "apache": {"language": "apache", "code": 'Header always set X-Frame-Options "DENY"'},
            "node": {"language": "javascript", "code": "const helmet = require('helmet');\napp.use(helmet.frameguard({ action: 'deny' }));"},
            "cloudfront": {"language": "yaml", "code": "# AWS CloudFront response headers policy\nType: AWS::CloudFront::ResponseHeadersPolicy\nProperties:\n  ResponseHeadersPolicyConfig:\n    Name: XFrameOptions-Policy\n    CustomHeadersConfig:\n      Items:\n        - Header: X-Frame-Options\n          Value: DENY\n          Override: true"},
        },
        "code": 'add_header X-Frame-Options "DENY" always;',
    },
    "x-content-type-options": {
        "title": "Disable MIME sniffing",
        "language": "nginx",
        "variants": {
            "nginx": {"language": "nginx", "code": 'add_header X-Content-Type-Options "nosniff" always;'},
            "apache": {"language": "apache", "code": 'Header always set X-Content-Type-Options "nosniff"'},
            "node": {"language": "javascript", "code": "const helmet = require('helmet');\napp.use(helmet.noSniff());"},
            "cloudfront": {"language": "yaml", "code": "# AWS CloudFront response headers policy\nType: AWS::CloudFront::ResponseHeadersPolicy\nProperties:\n  ResponseHeadersPolicyConfig:\n    Name: NoSniff-Policy\n    CustomHeadersConfig:\n      Items:\n        - Header: X-Content-Type-Options\n          Value: nosniff\n          Override: true"},
        },
        "code": 'add_header X-Content-Type-Options "nosniff" always;',
    },
    "referrer-policy": {
        "title": "Set Referrer-Policy",
        "language": "nginx",
        "variants": {
            "nginx": {"language": "nginx", "code": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'},
            "apache": {"language": "apache", "code": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"'},
            "node": {"language": "javascript", "code": "const helmet = require('helmet');\napp.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));"},
            "cloudfront": {"language": "yaml", "code": "# AWS CloudFront response headers policy\nType: AWS::CloudFront::ResponseHeadersPolicy\nProperties:\n  ResponseHeadersPolicyConfig:\n    Name: ReferrerPolicy\n    CustomHeadersConfig:\n      Items:\n        - Header: Referrer-Policy\n          Value: strict-origin-when-cross-origin\n          Override: true"},
        },
        "code": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    },
}

# Docker/Kubernetes security context templates
DOCKER_K8S_TEMPLATES = {
    "read_only_root_fs": {
        "title": "Read-only root filesystem",
        "docker": "docker run --read-only ...",
        "kubernetes": """securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false""",
    },
    "non_root_user": {
        "title": "Run as non-root user",
        "docker": "docker run --user 1000:1000 ...",
        "kubernetes": """securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000""",
    },
    "drop_capabilities": {
        "title": "Drop Linux capabilities",
        "docker": "docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ...",
        "kubernetes": """securityContext:
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE""",
    },
    "seccomp_profile": {
        "title": "Seccomp profile",
        "docker": "docker run --security-opt seccomp=default ...",
        "kubernetes": """securityContext:
  seccompProfile:
    type: RuntimeDefault""",
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
            contents=genai.types.Content(parts=[genai.types.Part(text=prompt)]),
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


def find_vulnerability(results: Dict[str, Any], vuln_id: str, scan_id: str = None, user_id: str = None) -> Dict[str, Any] | None:
    header_findings: List[Dict[str, Any]] = (results.get("header_audit") or {}).get("findings", [])
    for finding in header_findings:
        if finding.get("id") == vuln_id:
            return finding
    audit_findings: List[Dict[str, Any]] = (results.get("audit_engine") or {}).get("findings", [])
    for finding in audit_findings:
        if finding.get("id") == vuln_id:
            return finding

    if scan_id and user_id:
        try:
            from app.services.storage import ScanStorage
            storage = ScanStorage()
            if storage.database_configured():
                vulns = storage.fetch_vulnerabilities(scan_id, user_id)
                for v in vulns:
                    if str(v.get("id")) == vuln_id:
                        return v
        except Exception:
            pass

    return None
