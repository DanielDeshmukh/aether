import asyncio
import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx

from app.tools.audit_engine import _request_snapshot, _profile_target, _test_sqli_reflections

logger = logging.getLogger("aether.heuristic_engine")

SENSITIVE_FILES = [
    ".env",
    ".git/config",
    "wp-config.php",
    "config.php",
    "package.json",
    "docker-compose.yml",
    ".aws/credentials",
]

CORS_PROBE_HEADERS = {
    "Origin": "https://evil-attacker-domain.com",
    "Access-Control-Request-Method": "POST",
}

class HeuristicEngine:
    """
    Formalized Heuristic Engine for AETHER.
    Extends the basic audit engine with additional deep heuristic checks.
    """
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.findings: List[Dict[str, Any]] = []
        self.profiles: List[Dict[str, Any]] = []

    async def run_all(self) -> Dict[str, Any]:
        """
        Run all heuristic passes.
        """
        # Run base audit passes (from audit_engine.py logic)
        base_results = await asyncio.to_thread(self._run_base_audit)
        self.findings.extend(base_results.get("findings", []))
        self.profiles.extend(base_results.get("profiles", []))

        # Run additional passes
        await self.check_sensitive_files()
        await self.check_cors_misconfiguration()

        return {
            "target_url": self.target_url,
            "findings": self.findings,
            "profiles": self.profiles,
        }

    def _run_base_audit(self) -> Dict[str, Any]:
        try:
            base_response = _request_snapshot(self.target_url)
            sqli_result = _test_sqli_reflections(self.target_url)
            profile_result = _profile_target(self.target_url, base_response)
            return {
                "findings": [*sqli_result["findings"], *profile_result["findings"]],
                "profiles": profile_result["profiles"]
            }
        except Exception as e:
            logger.error(f"Base heuristic audit failed: {e}")
            return {"findings": [], "profiles": []}

    async def check_sensitive_files(self):
        """
        Check for exposure of sensitive files.
        """
        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            for file_path in SENSITIVE_FILES:
                probe_url = f"{base_url}/{file_path}"
                try:
                    response = await client.get(probe_url)
                    if response.status_code == 200:
                        self.findings.append({
                            "category": "A05:2021-Security Misconfiguration",
                            "title": f"Sensitive File Exposure: {file_path}",
                            "severity": "High",
                            "detail": f"The sensitive file '{file_path}' was found to be publicly accessible. This can lead to information disclosure of credentials, configuration, or source code.",
                            "attack_vector": "Direct URL path probing",
                            "evidence_snippet": f"HTTP 200 OK at {probe_url}",
                            "evidence": {"path": file_path, "status_code": response.status_code}
                        })
                except Exception:
                    continue

    async def check_cors_misconfiguration(self):
        """
        Check for loose CORS policies.
        """
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                response = await client.options(self.target_url, headers=CORS_PROBE_HEADERS)
                allow_origin = response.headers.get("Access-Control-Allow-Origin")

                if allow_origin == "*" or allow_origin == CORS_PROBE_HEADERS["Origin"]:
                    self.findings.append({
                        "category": "A05:2021-Security Misconfiguration",
                        "title": "Permissive CORS Policy",
                        "severity": "Medium",
                        "detail": f"The server implements a permissive CORS policy (Access-Control-Allow-Origin: {allow_origin}). This can allow malicious sites to interact with the application on behalf of users.",
                        "attack_vector": "CORS preflight request with arbitrary Origin",
                        "evidence_snippet": f"Access-Control-Allow-Origin: {allow_origin}",
                        "evidence": {"allow_origin": allow_origin, "headers": dict(response.headers)}
                    })
            except Exception:
                pass
