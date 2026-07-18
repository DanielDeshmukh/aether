import asyncio
import hashlib
import json
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

SQLI_PAYLOADS = ["'", '"', "OR 1=1"]
SQL_ERROR_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"sql syntax",
        r"mysql",
        r"postgresql",
        r"sqlite",
        r"odbc",
        r"sqlstate",
        r"unterminated quoted string",
        r"syntax error at or near",
    )
]
RATE_LIMIT_HEADERS = {
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
}
KNOWN_WAF_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "sucuri": "Sucuri",
    "imperva": "Imperva",
    "fastly": "Fastly",
    "aws": "AWS",
}
EXPOSED_SERVER_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"apache/\d",
        r"nginx/\d",
        r"iis/\d",
        r"php/\d",
        r"express",
        r"gunicorn/\d",
        r"uvicorn",
    )
]


def _finding_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha1(":".join([prefix, *parts]).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}:{digest}"


def _request_snapshot(target_url: str) -> Dict[str, Any]:
    response = requests.get(target_url, timeout=8, allow_redirects=True)
    return {
        "url": response.url,
        "status_code": response.status_code,
        "headers": {key.lower(): value for key, value in response.headers.items()},
        "text": response.text[:8000],
    }


def _profile_target(target_url: str, base_response: Dict[str, Any]) -> Dict[str, Any]:
    headers = base_response.get("headers", {})
    findings: List[Dict[str, Any]] = []
    profiles: List[Dict[str, Any]] = []

    rate_limit_present = any(header in headers for header in RATE_LIMIT_HEADERS)
    header_blob = json.dumps(headers).lower()
    waf_matches = [label for signature, label in KNOWN_WAF_SIGNATURES.items() if signature in header_blob]
    server_banner = headers.get("server", "")
    exposed_banner = bool(server_banner and any(pattern.search(server_banner) for pattern in EXPOSED_SERVER_PATTERNS))

    if not rate_limit_present:
        findings.append(
            {
                "id": _finding_id("vuln", "rate-limit", target_url),
                "category": "ddos_heuristic",
                "title": "Missing Rate-Limit Signaling",
                "severity": "medium",
                "detail": "No standard rate-limit headers were observed, which may indicate weak request-throttling controls.",
                "evidence": {"headers_seen": sorted(headers.keys())[:20]},
            }
        )

    if not waf_matches:
        findings.append(
            {
                "id": _finding_id("vuln", "waf", target_url),
                "category": "ddos_heuristic",
                "title": "No WAF Signature Detected",
                "severity": "low",
                "detail": "No common upstream WAF signature was detected in the response headers, reducing confidence in edge-layer request filtering.",
                "evidence": {"headers_seen": sorted(headers.keys())[:20]},
            }
        )

    if exposed_banner:
        findings.append(
            {
                "id": _finding_id("vuln", "server-banner", server_banner),
                "category": "ddos_heuristic",
                "title": "Verbose Server Banner",
                "severity": "medium",
                "detail": "The server banner exposes implementation details that can help attackers tune exploit and traffic-flood strategies.",
                "evidence": {"server": server_banner},
            }
        )

    profiles.append(
        {
            "profile_type": "vulnerability_profiler",
            "label": "Transport Resilience",
            "summary": "Profiles rate-limit signaling, edge filtering, and banner exposure for abuse resistance.",
            "details": {
                "rate_limit_present": rate_limit_present,
                "waf_signatures": waf_matches,
                "server_banner": server_banner or None,
                "exposed_banner": exposed_banner,
            },
        }
    )

    return {"findings": findings, "profiles": profiles}


def _test_sqli_reflections(target_url: str) -> Dict[str, Any]:
    parsed = urlparse(target_url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    findings: List[Dict[str, Any]] = []

    if not params:
        return {"tested_params": [], "findings": []}

    tested_params: List[str] = []

    for index, (key, value) in enumerate(params):
        for payload in SQLI_PAYLOADS:
            mutated_params = list(params)
            mutated_params[index] = (key, f"{value}{payload}")
            mutated_url = urlunparse(parsed._replace(query=urlencode(mutated_params, doseq=True)))
            tested_params.append(f"{key}:{payload}")

            try:
                response = _request_snapshot(mutated_url)
            except Exception:
                continue

            text = response.get("text", "")
            has_sql_error = any(pattern.search(text) for pattern in SQL_ERROR_PATTERNS)
            payload_reflected = payload in text

            if has_sql_error:
                findings.append(
                    {
                        "id": _finding_id("vuln", "sqli-error", key, payload),
                        "category": "sqli_heuristic",
                        "title": f"SQL Error Reflection via {key}",
                        "severity": "high",
                        "detail": f"The parameter '{key}' triggered a database-flavored error response when probed with a minimal SQLi heuristic payload.",
                        "evidence": {
                            "parameter": key,
                            "payload": payload,
                            "status_code": response.get("status_code"),
                            "url": response.get("url"),
                        },
                    }
                )
            elif payload_reflected:
                findings.append(
                    {
                        "id": _finding_id("vuln", "reflection", key, payload),
                        "category": "sqli_heuristic",
                        "title": f"Reflected Input Surface via {key}",
                        "severity": "medium",
                        "detail": f"The parameter '{key}' reflected a probe payload in the response body, which warrants deeper input-handling review.",
                        "evidence": {
                            "parameter": key,
                            "payload": payload,
                            "status_code": response.get("status_code"),
                            "url": response.get("url"),
                        },
                    }
                )

    return {"tested_params": tested_params, "findings": findings}


def _run_audit(target_url: str) -> Dict[str, Any]:
    base_response = _request_snapshot(target_url)
    sqli_result = _test_sqli_reflections(target_url)
    profile_result = _profile_target(target_url, base_response)

    return {
        "target_url": target_url,
        "tested_params": sqli_result["tested_params"],
        "base_response": {
            "url": base_response.get("url"),
            "status_code": base_response.get("status_code"),
            "headers": base_response.get("headers"),
        },
        "findings": [*sqli_result["findings"], *profile_result["findings"]],
        "profiles": profile_result["profiles"],
    }


async def audit_engine(target_url: str) -> Dict[str, Any]:
    try:
        return await asyncio.to_thread(_run_audit, target_url)
    except Exception as error:
        return {
            "target_url": target_url,
            "tested_params": [],
            "base_response": {},
            "findings": [],
            "profiles": [],
            "error": f"Audit engine failed: {error}",
        }


def format_audit_logs(audit_result: Dict[str, Any]) -> List[str]:
    if audit_result.get("error"):
        return [f"[EXECUTE] AUDIT_ENGINE: {audit_result['error'].upper()}."]

    findings = audit_result.get("findings", [])
    tested_params = audit_result.get("tested_params", [])
    profiles = audit_result.get("profiles", [])
    logs = [
        f"[EXECUTE] AUDIT_ENGINE: PROFILED {len(tested_params)} PARAMETER PROBES AND {len(profiles)} RESILIENCE PROFILES."
    ]

    if findings:
        summary = "; ".join(
            f"{finding.get('category', 'finding').upper()}::{finding.get('title', 'UNKNOWN')[:42].upper()}"
            for finding in findings[:3]
        )
        logs.append(f"[EXECUTE] AUDIT_ENGINE: VULNERABILITY SIGNALS DETECTED - {summary}.")
    else:
        logs.append("[EXECUTE] AUDIT_ENGINE: NO SQLI OR ABUSE-RESILIENCE HEURISTICS TRIPPED DURING THIS HUNT.")

    return logs
