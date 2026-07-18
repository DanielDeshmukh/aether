import asyncio
from typing import Any, Dict, List

import requests


SECURITY_HEADERS = {
    "strict-transport-security": "Missing HSTS leaves transport downgrade gaps.",
    "content-security-policy": "Missing CSP increases script injection exposure.",
    "x-frame-options": "Missing X-Frame-Options permits clickjacking frames.",
    "x-content-type-options": "Missing X-Content-Type-Options enables MIME sniffing.",
    "referrer-policy": "Missing Referrer-Policy may leak navigation metadata.",
}


def _fetch_headers(target_url: str) -> Dict[str, Any]:
    response = requests.get(target_url, timeout=8, allow_redirects=True)
    normalized_headers = {key.lower(): value for key, value in response.headers.items()}
    findings = [
        {
            "id": f"header:{header}",
            "type": "missing_header",
            "header": header,
            "severity": "medium",
            "detail": detail,
        }
        for header, detail in SECURITY_HEADERS.items()
        if header not in normalized_headers
    ]
    return {
        "final_url": response.url,
        "status_code": response.status_code,
        "headers": normalized_headers,
        "findings": findings,
    }


async def header_audit(target_url: str) -> Dict[str, Any]:
    try:
        return await asyncio.to_thread(_fetch_headers, target_url)
    except Exception as error:
        return {
            "final_url": target_url,
            "status_code": None,
            "headers": {},
            "findings": [],
            "error": f"Header audit request failed: {error}",
        }


def format_header_logs(audit_result: Dict[str, Any]) -> List[str]:
    if audit_result.get("error"):
        return [f"[EXECUTE] HEADER_AUDIT: {audit_result['error'].upper()}."]

    status_code = audit_result.get("status_code")
    findings = audit_result.get("findings", [])

    if status_code:
        logs = [f"[EXECUTE] HEADER_AUDIT: RECEIVED HTTP {status_code} FROM {audit_result.get('final_url', '').upper()}."]
    else:
        logs = [f"[EXECUTE] HEADER_AUDIT: REQUEST FAILED FOR {audit_result.get('final_url', '').upper()}."]

    if findings:
        finding_summary = "; ".join(finding["header"].upper() for finding in findings[:3])
        logs.append(f"[EXECUTE] HEADER_AUDIT: MISCONFIGURATION SIGNALS DETECTED IN {finding_summary}.")
    else:
        logs.append("[EXECUTE] HEADER_AUDIT: CORE SECURITY HEADER CHECKS RETURNED CLEAN.")

    return logs
