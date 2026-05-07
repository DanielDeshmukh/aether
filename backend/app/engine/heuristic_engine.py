import asyncio
import hashlib
import logging
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.tools.audit_engine import _request_snapshot, _profile_target, _test_sqli_reflections
from app.tools.validators import is_safe_url

logger = logging.getLogger("aether.heuristic_engine")

SENSITIVE_FILES = [
    {
        "path": ".env",
        "expected_content": [re.compile(r"^[A-Z0-9_]+=", re.MULTILINE)],
        "content_type": ["text/plain", "application/octet-stream", None],
    },
    {
        "path": ".git/config",
        "expected_content": [re.compile(r"\[core\]")],
        "content_type": ["text/plain", "application/octet-stream", None],
    },
    {
        "path": "wp-config.php",
        "expected_content": [re.compile(r"<\?php"), re.compile(r"DB_PASSWORD")],
        "content_type": ["text/plain", "application/x-httpd-php", "application/octet-stream", None],
    },
    {
        "path": "package.json",
        "expected_content": [re.compile(r"\"name\":"), re.compile(r"\"dependencies\":")],
        "content_type": ["application/json", "text/plain", None],
    },
    {
        "path": "docker-compose.yml",
        "expected_content": [re.compile(r"services:"), re.compile(r"version:")],
        "content_type": ["text/yaml", "text/plain", "application/octet-stream", None],
    },
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
    def __init__(
        self,
        target_url: str,
        request_hook: Optional[Callable[[str, str, Optional[Dict[str, str]]], Awaitable[httpx.Response]]] = None
    ):
        self.target_url = target_url
        self.findings: List[Dict[str, Any]] = []
        self.profiles: List[Dict[str, Any]] = []
        self.request_hook = request_hook

    async def _guarded_get(self, url: str, headers: Optional[Dict[str, str]] = None) -> httpx.Response:
        if self.request_hook:
            return await self.request_hook(url, "GET", headers)

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            return await client.get(url, headers=headers)

    async def _guarded_options(self, url: str, headers: Optional[Dict[str, str]] = None) -> httpx.Response:
        if self.request_hook:
            return await self.request_hook(url, "OPTIONS", headers)

        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            return await client.options(url, headers=headers)

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
            logger.error("Base heuristic audit failed: %s", e)
            return {"findings": [], "profiles": []}

    async def check_sensitive_files(self):
        """
        Check for exposure of sensitive files with false-positive reduction.
        """
        parsed = urlparse(self.target_url)
        if not all([parsed.scheme, parsed.netloc]) or not is_safe_url(self.target_url):
            logger.warning("Target URL %s is invalid or unsafe for sensitive file probing.", self.target_url)
            return

        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Establish a baseline for 200 response (e.g. index.html or catch-all)
        baseline_hash = None
        try:
            # Probe a known-bogus path to see if it returns 200 (catch-all behavior)
            bogus_url = f"{base_url}/aether_nonexistent_path_{hashlib.md5(base_url.encode()).hexdigest()[:8]}"
            response = await self._guarded_get(bogus_url)
            if response.status_code == 200:
                baseline_hash = hashlib.sha256(response.content).hexdigest()
                logger.info("Catch-all behavior detected for %s. Baseline established.", base_url)
        except Exception as e:
            logger.debug("Baseline establishment failed for %s: %s", base_url, e)

        for file_info in SENSITIVE_FILES:
            file_path = file_info["path"]
            probe_url = f"{base_url}/{file_path}"
            try:
                response = await self._guarded_get(probe_url)
                if response.status_code == 200:
                    # Check against baseline to avoid SPA/CDN catch-alls
                    content_hash = hashlib.sha256(response.content).hexdigest()
                    if baseline_hash and content_hash == baseline_hash:
                        continue

                    # Check Content-Type
                    ct = response.headers.get("content-type", "").split(";")[0].lower() or None
                    if file_info["content_type"] and ct not in file_info["content_type"]:
                        # Content type mismatch, lower confidence
                        logger.debug("Content-Type mismatch for %s: expected %s, got %s", probe_url, file_info["content_type"], ct)
                        continue

                    # Check body fingerprints
                    content_text = response.text
                    matches = all(p.search(content_text) for p in file_info["expected_content"])

                    if matches:
                        self.findings.append({
                            "category": "A05:2021-Security Misconfiguration",
                            "title": f"Sensitive File Exposure: {file_path}",
                            "severity": "High",
                            "detail": f"The sensitive file '{file_path}' was found to be publicly accessible. This can lead to information disclosure of credentials, configuration, or source code.",
                            "attack_vector": "Direct URL path probing",
                            "evidence_snippet": f"HTTP 200 OK at {probe_url}. Content matched fingerprint.",
                            "evidence": {
                                "path": file_path,
                                "status_code": response.status_code,
                                "content_type": ct,
                                "url": probe_url
                            }
                        })
            except httpx.RequestError as e:
                logger.debug("Request error during sensitive file probe for %s: %s", probe_url, e)
                continue
            except Exception as e:
                logger.error("Unexpected error during sensitive file probe for %s: %s", probe_url, e)
                continue

    async def check_cors_misconfiguration(self):
        """
        Check for loose CORS policies.
        """
        parsed = urlparse(self.target_url)
        if not all([parsed.scheme, parsed.netloc]):
            return

        base_url = f"{parsed.scheme}://{parsed.netloc}"
        targets = sorted({self.target_url, base_url})

        for url in targets:
            try:
                response = await self._guarded_options(url, headers=CORS_PROBE_HEADERS)
                allow_origin = response.headers.get("Access-Control-Allow-Origin")
                allow_creds = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

                # Permissive origin check
                is_wildcard = allow_origin == "*"
                is_reflected = allow_origin == CORS_PROBE_HEADERS["Origin"]

                if (is_wildcard or is_reflected):
                    # Flag as high-confidence finding only if credentials are also allowed
                    # (Wildcard with credentials is an invalid configuration in browsers, but still noteworthy)
                    severity = "Medium"
                    if allow_creds:
                        severity = "High"
                    elif is_wildcard:
                        severity = "Low" # Wildcard without credentials is common for public APIs

                    if severity != "Low":
                        self.findings.append({
                            "category": "A05:2021-Security Misconfiguration",
                            "title": f"Permissive CORS Policy ({severity})",
                            "severity": severity,
                            "detail": f"The server implements a permissive CORS policy (Access-Control-Allow-Origin: {allow_origin}, Allow-Credentials: {allow_creds}). This can allow malicious sites to interact with the application on behalf of users.",
                            "attack_vector": "CORS preflight request with arbitrary Origin",
                            "evidence_snippet": f"Access-Control-Allow-Origin: {allow_origin}, Access-Control-Allow-Credentials: {allow_creds}",
                            "evidence": {"allow_origin": allow_origin, "allow_credentials": allow_creds, "headers": dict(response.headers), "url": url}
                        })
            except Exception as e:
                logger.debug("CORS misconfiguration check failed for %s: %s", url, e)
                continue
