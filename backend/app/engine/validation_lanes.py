import asyncio
import base64
import re
import socket
import ssl
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List
from urllib.parse import urlparse

try:
    from playwright.async_api import BrowserContext
    from playwright.async_api import Page
except ImportError:  # pragma: no cover - resolved when requirements are installed
    BrowserContext = Any  # type: ignore[assignment]
    Page = Any  # type: ignore[assignment]


# SQL error patterns used to detect successful SQL injection attacks.
# These regex patterns match common database error messages that leak
# information when input is not properly sanitized.
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

# XSS probe markers - safe payloads injected to test for reflected XSS.
# The marker prefix is unique to AETHER to avoid false positives from
# existing content on the target page.
SAFE_XSS_MARKER_PREFIX = "AETHER_XSS_PROBE"
SAFE_XSS_PAYLOAD_TEMPLATE = '<div data-aether-marker="{marker}">{marker}</div>'

# SQLi test payloads - classic injection patterns that trigger database
# errors when input is not properly parameterized.
SAFE_INJECTION_PAYLOADS = ["' OR '1'='1", "'; WAITFOR DELAY '0:0:03' --"]


# Represents a single security finding discovered by a validation lane.
# Each finding includes evidence, severity, and actionable remediation guidance.
@dataclass
class LaneFinding:
    category: str
    title: str
    severity: str
    detail: str
    attack_vector: str
    evidence_snippet: str
    provided_solution: str
    evidence: Dict[str, Any]


class ValidationLaneManager:
    def __init__(
        self,
        *,
        verification_service: Any,
        user_id: str,
        trace_writer: Callable[[str, str], Awaitable[None]],
        abort_check: Callable[[], None],
        rate_limit: Callable[[], Awaitable[None]] | None = None,
        interaction_delay_ms: Callable[[], int] | None = None,
    ) -> None:
        self.verification_service = verification_service
        self.user_id = user_id
        self.trace_writer = trace_writer
        self.abort_check = abort_check
        self.rate_limit = rate_limit
        self.interaction_delay_ms = interaction_delay_ms or (lambda: 0)

    async def _throttle(self) -> None:
        if self.rate_limit is not None:
            await self.rate_limit()

    async def _wait_after_interaction(self) -> None:
        delay_ms = max(0, int(self.interaction_delay_ms()))
        if delay_ms:
            await asyncio.sleep(delay_ms / 1000)

    async def _require_verified_target(self, target_url: str) -> None:
        self.abort_check()
        verification = await self.verification_service.verify_target(target_url, user_id=self.user_id)
        if not verification.allowed:
            raise RuntimeError(verification.failure_message or "DOMAIN VERIFICATION FAILED.")

    async def screenshot_capture(
        self,
        page: Page,
        *,
        lane_name: str,
        confirmation_label: str,
        response_snapshot: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        self.abort_check()
        screenshot_bytes = await page.screenshot(full_page=False, type="png")
        title = await page.title()
        content = await page.content()
        return {
            "lane": lane_name,
            "confirmation_label": confirmation_label,
            "captured_at": time.time(),
            "final_url": page.url,
            "title": title,
            "dom_excerpt": content[:4000],
            "screenshot_base64": base64.b64encode(screenshot_bytes).decode("ascii"),
            "response_snapshot": response_snapshot or {},
        }

    async def _visible_input(self, page: Page) -> Any | None:
        inputs = await page.locator("input[type='text'], input:not([type]), textarea").all()
        return inputs[0] if inputs else None

    async def run_xss_lane(self, context: BrowserContext, target_url: str) -> List[LaneFinding]:
        await self._require_verified_target(target_url)
        marker = f"{SAFE_XSS_MARKER_PREFIX}_{uuid.uuid4().hex[:10]}"
        payload = SAFE_XSS_PAYLOAD_TEMPLATE.format(marker=marker)
        await self.trace_writer("execute", f"LAMBO-DARK XSS LANE INJECTING MARKER {marker}.")

        page = await context.new_page()
        try:
            await self._require_verified_target(target_url)
            await self._throttle()
            await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            input_handle = await self._visible_input(page)
            if input_handle is None:
                await self.trace_writer("execute", "LAMBO-DARK XSS LANE FOUND NO VISIBLE TEXT INPUTS.")
                return []

            await self._require_verified_target(target_url)
            await input_handle.fill(payload)
            await self._require_verified_target(target_url)
            await input_handle.press("Enter")
            await self._wait_after_interaction()
            content = await page.content()
            if marker not in content:
                await self.trace_writer("analyze", "LAMBO-DARK XSS LANE DID NOT OBSERVE UNSANITIZED DOM REFLECTION.")
                return []

            artifact = await self.screenshot_capture(
                page,
                lane_name="xss",
                confirmation_label="confirmed_dom_reflection",
            )
            await self.trace_writer("analyze", f"LAMBO-DARK XSS LANE CONFIRMED UNSANITIZED DOM REFLECTION FOR {marker}.")
            return [
                LaneFinding(
                    category="A03:2021-Injection",
                    title="Confirmed Unsanitized DOM Reflection",
                    severity="High",
                    detail="A Playwright validation lane reflected a controlled marker into the DOM without effective sanitization.",
                    attack_vector="Headless Playwright XSS reflection validation",
                    evidence_snippet=f"Controlled marker {marker} rendered in the DOM after input submission.",
                    provided_solution="Apply contextual output encoding and sanitize untrusted input before rendering it into the DOM.",
                    evidence={
                        "confirmation_status": "confirmed",
                        "marker": marker,
                        "payload": payload,
                        "artifact": artifact,
                    },
                )
            ]
        finally:
            await page.close()

    async def run_injection_lane(self, context: BrowserContext, target_url: str) -> List[LaneFinding]:
        await self._require_verified_target(target_url)
        await self.trace_writer("execute", "LAMBO-DARK INJECTION LANE MONITORING RESPONSE TELEMETRY.")

        page = await context.new_page()
        response_events: List[Dict[str, Any]] = []

        async def record_response(response: Any) -> None:
            try:
                body = await response.text()
            except Exception:
                body = ""
            response_events.append(
                {
                    "url": response.url,
                    "status": response.status,
                    "body_excerpt": body[:1000],
                }
            )

        page.on("response", lambda response: asyncio.create_task(record_response(response)))

        try:
            await self._require_verified_target(target_url)
            await self._throttle()
            await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            input_handle = await self._visible_input(page)
            if input_handle is None:
                await self.trace_writer("execute", "LAMBO-DARK INJECTION LANE FOUND NO VISIBLE TEXT INPUTS.")
                return []

            for payload in SAFE_INJECTION_PAYLOADS:
                await self._require_verified_target(target_url)
                start = time.monotonic()
                await input_handle.fill(payload)
                await self._require_verified_target(target_url)
                await input_handle.press("Enter")
                await self._wait_after_interaction()
                elapsed = time.monotonic() - start

                matching_response = next(
                    (
                        response
                        for response in reversed(response_events)
                        if response.get("status", 200) >= 500
                        or any(pattern.search(response.get("body_excerpt", "")) for pattern in SQL_ERROR_PATTERNS)
                    ),
                    None,
                )
                if matching_response is None and elapsed < 2.5:
                    continue

                artifact = await self.screenshot_capture(
                    page,
                    lane_name="injection",
                    confirmation_label="confirmed_response_anomaly",
                    response_snapshot=matching_response or {
                        "status": 200,
                        "body_excerpt": "Time-based delay threshold exceeded without a visible SQL error body.",
                    },
                )
                await self.trace_writer("analyze", f"LAMBO-DARK INJECTION LANE CONFIRMED RESPONSE ANOMALY FOR PAYLOAD {payload!r}.")
                evidence_snippet = (
                    f"Observed response anomaly for payload {payload!r}. "
                    f"Elapsed={elapsed:.2f}s status={artifact['response_snapshot'].get('status')}."
                )
                return [
                    LaneFinding(
                        category="A03:2021-Injection",
                        title="Confirmed Injection Response Anomaly",
                        severity="High" if matching_response else "Medium",
                        detail="A Playwright validation lane confirmed an error-based or time-based response anomaly consistent with unsafe query handling.",
                        attack_vector="Headless Playwright injection response monitoring",
                        evidence_snippet=evidence_snippet,
                        provided_solution="Replace dynamic query construction with parameterized statements and reject unsafe input patterns before execution.",
                        evidence={
                            "confirmation_status": "confirmed",
                            "payload": payload,
                            "elapsed_seconds": round(elapsed, 3),
                            "response_events": response_events[-5:],
                            "artifact": artifact,
                        },
                    )
                ]

            await self.trace_writer("analyze", "LAMBO-DARK INJECTION LANE FOUND NO CONFIRMED RESPONSE ANOMALY.")
            return []
        finally:
            await page.close()

    async def run_crypto_failures_lane(self, context: BrowserContext, target_url: str) -> List[LaneFinding]:
        await self._require_verified_target(target_url)
        await self.trace_writer("execute", "LAMBO-DARK CRYPTO FAILURES LANE CHECKING TLS AND TRANSPORT SECURITY.")
        findings: List[LaneFinding] = []
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        hostname = parsed.hostname or ""
        is_https = parsed.scheme == "https"

        if not is_https:
            findings.append(LaneFinding(
                category="A02:2021-Cryptographic Failures",
                title="HTTP (Non-TLS) Endpoint",
                severity="High",
                detail=f"The target {hostname} is served over plain HTTP without TLS encryption.",
                attack_vector="Transport layer analysis",
                evidence_snippet=f"Scheme is {parsed.scheme} — data transmitted in cleartext.",
                provided_solution="Enforce HTTPS with a valid TLS certificate and redirect all HTTP traffic.",
                evidence={"scheme": parsed.scheme, "hostname": hostname},
            ))

        if is_https and hostname:
            try:
                loop = asyncio.get_event_loop()
                ssl_ok, cert_expiry = await loop.run_in_executor(None, self._check_tls_version_and_cert, hostname, 443)
                if not ssl_ok:
                    findings.append(LaneFinding(
                        category="A02:2021-Cryptographic Failures",
                        title="Weak TLS Version Detected",
                        severity="High",
                        detail=f"Server at {hostname} accepts TLS 1.0 or TLS 1.1 connections.",
                        attack_vector="TLS version negotiation",
                        evidence_snippet="Server negotiated an outdated TLS version.",
                        provided_solution="Disable TLS 1.0/1.1 and enforce TLS 1.2+ only.",
                        evidence={"hostname": hostname},
                    ))
                if cert_expiry:
                    from datetime import datetime, timezone
                    try:
                        expiry_dt = datetime.fromisoformat(cert_expiry.replace("Z", "+00:00"))
                        days_left = (expiry_dt - datetime.now(timezone.utc)).days
                        if days_left < 0:
                            findings.append(LaneFinding(
                                category="A02:2021-Cryptographic Failures",
                                title="Expired SSL/TLS Certificate",
                                severity="Critical",
                                detail=f"SSL certificate for {hostname} expired {abs(days_left)} days ago.",
                                attack_vector="Certificate validity check",
                                evidence_snippet=f"Certificate expired on {cert_expiry}",
                                provided_solution="Renew the SSL/TLS certificate immediately.",
                                evidence={"hostname": hostname, "expiry": cert_expiry, "days_expired": abs(days_left)},
                            ))
                        elif days_left < 30:
                            findings.append(LaneFinding(
                                category="A02:2021-Cryptographic Failures",
                                title="SSL/TLS Certificate Expiring Soon",
                                severity="Medium",
                                detail=f"SSL certificate for {hostname} expires in {days_left} days.",
                                attack_vector="Certificate validity check",
                                evidence_snippet=f"Certificate expires on {cert_expiry}",
                                provided_solution="Renew the SSL/TLS certificate before expiration.",
                                evidence={"hostname": hostname, "expiry": cert_expiry, "days_remaining": days_left},
                            ))
                    except Exception:
                        pass
            except Exception:
                pass

        page = await context.new_page()
        try:
            await self._require_verified_target(target_url)
            await self._throttle()
            response = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            if response:
                headers = await response.all_headers()
                hsts = headers.get("strict-transport-security", "")
                if is_https and not hsts:
                    findings.append(LaneFinding(
                        category="A02:2021-Cryptographic Failures",
                        title="Missing Strict-Transport-Security Header",
                        severity="Medium",
                        detail=f"The target {hostname} does not set an HSTS header.",
                        attack_vector="HTTP response header analysis",
                        evidence_snippet="No Strict-Transport-Security header observed.",
                        provided_solution="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                        evidence={"headers": {k: v for k, v in headers.items() if "strict" in k.lower() or "transport" in k.lower()}},
                    ))

                set_cookie = headers.get("set-cookie", "")
                if set_cookie:
                    insecure_flags = []
                    cookie_lower = set_cookie.lower()
                    if "secure" not in cookie_lower and is_https:
                        insecure_flags.append("Secure")
                    if "httponly" not in cookie_lower:
                        insecure_flags.append("HttpOnly")
                    if "samesite" not in cookie_lower:
                        insecure_flags.append("SameSite")
                    if insecure_flags:
                        findings.append(LaneFinding(
                            category="A02:2021-Cryptographic Failures",
                            title="Insecure Cookie Flags",
                            severity="Medium" if len(insecure_flags) <= 2 else "High",
                            detail=f"Cookies missing security flags: {', '.join(insecure_flags)}.",
                            attack_vector="HTTP response cookie analysis",
                            evidence_snippet=f"Set-Cookie: {set_cookie[:200]}",
                            provided_solution="Set Secure, HttpOnly, and SameSite=Strict/Lax flags on all cookies.",
                            evidence={"insecure_flags": insecure_flags, "cookie_excerpt": set_cookie[:300]},
                        ))

                # Check for mixed content (HTTPS page loading HTTP resources)
                if is_https:
                    try:
                        body_text = await page.content()
                        http_resources = re.findall(r'(?:src|href|action)=["\']http://[^"\']+["\']', body_text, re.IGNORECASE)
                        if http_resources:
                            findings.append(LaneFinding(
                                category="A02:2021-Cryptographic Failures",
                                title="Mixed Content Detected",
                                severity="Medium",
                                detail=f"HTTPS page loads {len(http_resources)} resource(s) over insecure HTTP.",
                                attack_vector="Mixed content analysis",
                                evidence_snippet=http_resources[0][:200],
                                provided_solution="Load all resources over HTTPS or use protocol-relative URLs.",
                                evidence={"http_resources": [r[:150] for r in http_resources[:5]]},
                            ))
                    except Exception:
                        pass

            await self.trace_writer("analyze", "LAMBO-DARK CRYPTO FAILURES LANE COMPLETED.")
        finally:
            await page.close()

        return findings

    def _check_tls_version_and_cert(self, hostname: str, port: int) -> tuple[bool, str | None]:
        """Check TLS version and certificate expiry.
        
        Returns:
            Tuple of (tls_ok, cert_expiry_date_string)
        """
        ctx = ssl.create_default_context()
        sock = socket.create_connection((hostname, port), timeout=5)
        cert_expiry = None
        tls_ok = True
        try:
            with ctx.wrap_socket(sock, server_hostname=hostname) as s:
                ver = s.version()
                if ver and ("TLSv1" in ver or "TLSv1.1" in ver):
                    tls_ok = False
                cert = s.getpeercert()
                if cert and "notAfter" in cert:
                    cert_expiry = cert["notAfter"]
        except Exception:
            pass
        finally:
            sock.close()
        return tls_ok, cert_expiry

    async def run_insecure_design_lane(self, context: BrowserContext, target_url: str) -> List[LaneFinding]:
        await self._require_verified_target(target_url)
        await self.trace_writer("execute", "LAMBO-DARK INSECURE DESIGN LANE CHECKING EXPOSED ENDPOINTS AND ERROR HANDLING.")
        findings: List[LaneFinding] = []
        page = await context.new_page()
        try:
            await self._require_verified_target(target_url)
            await self._throttle()
            response = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)

            exposed_docs = ["/docs", "/redoc", "/swagger", "/swagger-ui", "/api-docs"]
            base = f"{parsed.scheme}://{parsed.netloc}" if (parsed := urlparse(target_url)) else target_url.rstrip("/")
            for path in exposed_docs:
                try:
                    doc_resp = await page.goto(base + path, wait_until="domcontentloaded", timeout=8000)
                    if doc_resp and doc_resp.status == 200:
                        body = await page.content()
                        if any(kw in body.lower() for kw in ["swagger", "openapi", "api documentation", "redoc"]):
                            findings.append(LaneFinding(
                                category="A04:2021-Insecure Design",
                                title="Exposed API Documentation",
                                severity="Medium",
                                detail=f"API documentation endpoint is publicly accessible at {path}.",
                                attack_vector="Playwright endpoint enumeration",
                                evidence_snippet=f"GET {path} returned 200 with documentation content.",
                                provided_solution="Restrict API documentation endpoints to internal networks or disable in production.",
                                evidence={"path": path, "status": doc_resp.status},
                            ))
                            break
                except Exception:
                    continue

            # Check for missing rate limiting on sensitive endpoints
            sensitive_endpoints = ["/login", "/signin", "/api/auth", "/api/login", "/api/signup"]
            for endpoint in sensitive_endpoints:
                try:
                    test_url = base + endpoint
                    resp = await page.goto(test_url, wait_until="domcontentloaded", timeout=5000)
                    if resp and resp.status in [200, 302, 404]:
                        # Check for rate limit headers
                        resp_headers = await resp.all_headers() if resp else {}
                        has_rate_limit = any("ratelimit" in k.lower() or "retry-after" in k.lower() for k in resp_headers)
                        if not has_rate_limit:
                            findings.append(LaneFinding(
                                category="A04:2021-Insecure Design",
                                title="Missing Rate Limiting on Sensitive Endpoint",
                                severity="Medium",
                                detail=f"Endpoint {endpoint} does not appear to have rate limiting protection.",
                                attack_vector="Rate limit header analysis",
                                evidence_snippet=f"GET {endpoint} returned {resp.status} without rate limit headers.",
                                provided_solution="Implement rate limiting on authentication endpoints to prevent brute-force attacks.",
                                evidence={"endpoint": endpoint, "status": resp.status, "headers": list(resp_headers.keys())[:10]},
                            ))
                            break
                except Exception:
                    continue

            # Check for open redirect via query parameter manipulation
            redirect_params = ["url", "redirect", "next", "return", "continue"]
            for param in redirect_params:
                try:
                    redirect_url = f"{target_url}?{param}=https://evil.com"
                    resp = await page.goto(redirect_url, wait_until="domcontentloaded", timeout=5000)
                    if resp and resp.url and "evil.com" in resp.url:
                        findings.append(LaneFinding(
                            category="A04:2021-Insecure Design",
                            title="Open Redirect Vulnerability",
                            severity="High",
                            detail=f"Application redirects to external URL via {param} parameter.",
                            attack_vector="Open redirect test",
                            evidence_snippet=f"Redirected to: {resp.url}",
                            provided_solution="Validate and whitelist redirect URLs; never redirect to untrusted domains.",
                            evidence={"param": param, "redirect_url": resp.url},
                        ))
                        break
                except Exception:
                    continue

            if response:
                status = response.status
                try:
                    body_text = await response.text()
                except Exception:
                    body_text = ""
                stack_indicators = ["traceback", "stack trace", "exception", "file \"/", "line \\d+"]
                if status >= 500 and any(re.search(p, body_text, re.IGNORECASE) for p in stack_indicators):
                    findings.append(LaneFinding(
                        category="A04:2021-Insecure Design",
                        title="Verbose Error Message with Stack Trace",
                        severity="Medium",
                        detail="Server returns verbose error messages exposing internal stack traces.",
                        attack_vector="Playwright error response analysis",
                        evidence_snippet=body_text[:500],
                        provided_solution="Use custom error pages and log stack traces server-side only.",
                        evidence={"status": status, "body_excerpt": body_text[:500]},
                    ))

            await self.trace_writer("analyze", "LAMBO-DARK INSECURE DESIGN LANE COMPLETED.")
        finally:
            await page.close()

        return findings

    async def run_misconfiguration_lane(self, context: BrowserContext, target_url: str) -> List[LaneFinding]:
        await self._require_verified_target(target_url)
        await self.trace_writer("execute", "LAMBO-DARK MISCONFIGURATION LANE CHECKING HEADERS, CORS, AND DIRECTORY LISTING.")
        findings: List[LaneFinding] = []
        page = await context.new_page()
        try:
            await self._require_verified_target(target_url)
            await self._throttle()
            response = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            if not response:
                return findings

            headers = await response.all_headers()
            server = headers.get("server", "")
            x_powered = headers.get("x-powered-by", "")
            if server:
                findings.append(LaneFinding(
                    category="A05:2021-Security Misconfiguration",
                    title="Server Version Disclosure",
                    severity="Low",
                    detail=f"Server header reveals: {server}",
                    attack_vector="HTTP response header analysis",
                    evidence_snippet=f"Server: {server}",
                    provided_solution="Remove or obfuscate the Server header to avoid version disclosure.",
                    evidence={"server": server},
                ))
            if x_powered:
                findings.append(LaneFinding(
                    category="A05:2021-Security Misconfiguration",
                    title="X-Powered-By Header Disclosure",
                    severity="Low",
                    detail=f"X-Powered-By header reveals: {x_powered}",
                    attack_vector="HTTP response header analysis",
                    evidence_snippet=f"X-Powered-By: {x_powered}",
                    provided_solution="Remove the X-Powered-By header.",
                    evidence={"x_powered_by": x_powered},
                ))

            access_control = headers.get("access-control-allow-origin", "")
            if access_control == "*":
                findings.append(LaneFinding(
                    category="A05:2021-Security Misconfiguration",
                    title="CORS Wildcard Misconfiguration",
                    severity="Medium",
                    detail="Access-Control-Allow-Origin is set to '*', allowing any origin.",
                    attack_vector="CORS configuration analysis",
                    evidence_snippet=f"Access-Control-Allow-Origin: {access_control}",
                    provided_solution="Restrict CORS to specific trusted origins instead of using a wildcard.",
                    evidence={"access_control_allow_origin": access_control},
                ))

            parsed = urlparse(target_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for dir_path in ["/admin", "/.git/config", "/.env", "/backup", "/config"]:
                try:
                    dir_resp = await page.goto(base + dir_path, wait_until="domcontentloaded", timeout=5000)
                    if dir_resp and dir_resp.status == 200:
                        body = await page.content()
                        if "index of" in body.lower() or "parent directory" in body.lower():
                            findings.append(LaneFinding(
                                category="A05:2021-Security Misconfiguration",
                                title="Directory Listing Enabled",
                                severity="High",
                                detail=f"Directory listing is accessible at {dir_path}.",
                                attack_vector="Playwright directory enumeration",
                                evidence_snippet=f"GET {dir_path} returned directory listing.",
                                provided_solution="Disable directory listing on the web server.",
                                evidence={"path": dir_path, "status": dir_resp.status},
                            ))
                except Exception:
                    continue

            # Check for unnecessary HTTP methods (TRACE, OPTIONS leaking info)
            try:
                trace_resp = await page.goto(target_url, wait_until="domcontentloaded", timeout=5000)
                # Try OPTIONS request to check allowed methods
                options_headers = {"Access-Control-Request-Method": "TRACE"}
                options_resp = await page.evaluate("""
                    async () => {
                        try {
                            const resp = await fetch(window.location.href, { method: 'OPTIONS' });
                            return { status: resp.status, headers: Object.fromEntries(resp.headers) };
                        } catch(e) { return null; }
                    }
                """)
                if options_resp and options_resp.get("headers", {}).get("allow", ""):
                    allowed_methods = options_resp["headers"]["allow"]
                    dangerous_methods = ["TRACE", "DEBUG", "CONNECT"]
                    for method in dangerous_methods:
                        if method in allowed_methods.upper():
                            findings.append(LaneFinding(
                                category="A05:2021-Security Misconfiguration",
                                title=f"Dangerous HTTP Method Allowed: {method}",
                                severity="Medium" if method == "TRACE" else "High",
                                detail=f"Server allows {method} method which can be exploited.",
                                attack_vector="HTTP method enumeration",
                                evidence_snippet=f"Allowed methods: {allowed_methods}",
                                provided_solution=f"Disable {method} method on the web server.",
                                evidence={"allowed_methods": allowed_methods, "dangerous_method": method},
                            ))
            except Exception:
                pass

            # Check for default credentials on known admin panels
            admin_paths = ["/admin", "/admin/login", "/wp-admin", "/phpmyadmin"]
            for admin_path in admin_paths:
                try:
                    admin_resp = await page.goto(base + admin_path, wait_until="domcontentloaded", timeout=5000)
                    if admin_resp and admin_resp.status == 200:
                        body = await page.content()
                        login_indicators = ["login", "password", "username", "sign in"]
                        if any(ind in body.lower() for ind in login_indicators):
                            findings.append(LaneFinding(
                                category="A05:2021-Security Misconfiguration",
                                title="Admin Panel Accessible",
                                severity="Medium",
                                detail=f"Admin panel is accessible at {admin_path}.",
                                attack_vector="Admin panel enumeration",
                                evidence_snippet=f"GET {admin_path} returned login form.",
                                provided_solution="Restrict admin panel access to internal networks or VPN.",
                                evidence={"path": admin_path, "status": admin_resp.status},
                            ))
                            break
                except Exception:
                    continue

            await self.trace_writer("analyze", "LAMBO-DARK MISCONFIGURATION LANE COMPLETED.")
        finally:
            await page.close()

        return findings

    async def run_vulnerable_components_lane(self, context: BrowserContext, target_url: str) -> List[LaneFinding]:
        await self._require_verified_target(target_url)
        await self.trace_writer("execute", "LAMBO-DARK VULNERABLE COMPONENTS LANE CHECKING SCRIPT VERSIONS AND HEADERS.")
        findings: List[LaneFinding] = []
        page = await context.new_page()
        try:
            await self._require_verified_target(target_url)
            await self._throttle()
            response = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            if not response:
                return findings

            headers = await response.all_headers()
            x_powered = headers.get("x-powered-by", "")
            if x_powered:
                findings.append(LaneFinding(
                    category="A06:2021-Vulnerable and Outdated Components",
                    title="Framework Version Disclosure",
                    severity="Low",
                    detail=f"X-Powered-By header reveals technology stack: {x_powered}",
                    attack_vector="HTTP header analysis",
                    evidence_snippet=f"X-Powered-By: {x_powered}",
                    provided_solution="Remove X-Powered-By header to prevent version fingerprinting.",
                    evidence={"x_powered_by": x_powered},
                ))

            content = await page.content()
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE)
            known_libraries = {
                "jquery": {"pattern": r"jquery[.-](\d+\.\d+\.\d+)", "severity": "Medium", "min_safe": "3.5.0"},
                "angular": {"pattern": r"angular[.-](\d+\.\d+\.\d+)", "severity": "High", "min_safe": "13.0.0"},
                "react": {"pattern": r"react[.-](\d+\.\d+\.\d+)", "severity": "Low", "min_safe": "18.0.0"},
                "bootstrap": {"pattern": r"bootstrap[.-](\d+\.\d+\.\d+)", "severity": "Medium", "min_safe": "5.0.0"},
            }
            for src in script_srcs:
                for lib_name, lib_info in known_libraries.items():
                    match = re.search(lib_info["pattern"], src, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        findings.append(LaneFinding(
                            category="A06:2021-Vulnerable and Outdated Components",
                            title=f"Detected {lib_name.title()} v{version}",
                            severity=lib_info["severity"],
                            detail=f"CDN script loads {lib_name} version {version}. Check for known CVEs.",
                            attack_vector="HTML script tag analysis",
                            evidence_snippet=f"<script src=\"{src[:150]}\">",
                            provided_solution=f"Update {lib_name} to the latest stable version.",
                            evidence={"library": lib_name, "version": version, "src": src[:300]},
                        ))

            # Check for SourceMap files that may expose source code
            for src in script_srcs:
                if src.endswith(".js"):
                    sourcemap_url = src + ".map"
                    try:
                        sm_resp = await page.goto(sourcemap_url, wait_until="domcontentloaded", timeout=3000)
                        if sm_resp and sm_resp.status == 200:
                            sm_body = await sm_resp.text()
                            if '"sources"' in sm_body or '"mappings"' in sm_body:
                                findings.append(LaneFinding(
                                    category="A06:2021-Vulnerable and Outdated Components",
                                    title="SourceMap File Exposed",
                                    severity="Low",
                                    detail=f"SourceMap file accessible at {sourcemap_url}",
                                    attack_vector="SourceMap file enumeration",
                                    evidence_snippet=f"GET {sourcemap_url} returned source map content.",
                                    provided_solution="Remove SourceMap files from production builds.",
                                    evidence={"sourcemap_url": sourcemap_url},
                                ))
                    except Exception:
                        pass

            await self.trace_writer("analyze", "LAMBO-DARK VULNERABLE COMPONENTS LANE COMPLETED.")
        finally:
            await page.close()

        return findings

    async def run_auth_failures_lane(self, context: BrowserContext, target_url: str) -> List[LaneFinding]:
        await self._require_verified_target(target_url)
        await self.trace_writer("execute", "LAMBO-DARK AUTH FAILURES LANE CHECKING LOGIN FLOW AND SESSION HANDLING.")
        findings: List[LaneFinding] = []
        page = await context.new_page()
        try:
            await self._require_verified_target(target_url)
            await self._throttle()
            response = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            if not response:
                return findings

            headers = await response.all_headers()
            set_cookie = headers.get("set-cookie", "")
            if set_cookie and "secure" not in set_cookie.lower() and urlparse(target_url).scheme == "https":
                findings.append(LaneFinding(
                    category="A07:2021-Identification and Authentication Failures",
                    title="Insecure Session Cookie",
                    severity="Medium",
                    detail="Session cookie is set without the Secure flag over HTTPS.",
                    attack_vector="Cookie attribute analysis",
                    evidence_snippet=f"Set-Cookie: {set_cookie[:200]}",
                    provided_solution="Set the Secure flag on all session cookies.",
                    evidence={"cookie_excerpt": set_cookie[:300]},
                ))

            content = await page.content()
            login_indicators = ["login", "signin", "sign-in", "authenticate", "password"]
            has_login_form = any(ind in content.lower() for ind in login_indicators)
            if has_login_form:
                error_patterns = ["invalid credentials", "incorrect password", "wrong email", "user not found"]
                has_enumeration = any(pat in content.lower() for pat in error_patterns)
                if has_enumeration:
                    findings.append(LaneFinding(
                        category="A07:2021-Identification and Authentication Failures",
                        title="Account Enumeration via Login Error",
                        severity="Medium",
                        detail="Login form returns specific error messages that reveal whether an account exists.",
                        attack_vector="Playwright login form analysis",
                        evidence_snippet="Specific error messages differentiate between invalid user and invalid password.",
                        provided_solution="Use generic error messages like 'Invalid email or password' for all login failures.",
                        evidence={"error_patterns_found": True},
                    ))

                # Check for session fixation (session ID changes after login)
                try:
                    initial_cookies = await page.evaluate("() => document.cookie")
                    # Try to submit login form with invalid credentials
                    login_forms = await page.query_selector_all("form")
                    for form in login_forms:
                        action = await form.get_attribute("action") or ""
                        if any(ind in action.lower() for ind in login_indicators):
                            # Fill in dummy credentials
                            await page.evaluate("""
                                () => {
                                    const inputs = document.querySelectorAll('input');
                                    inputs.forEach(input => {
                                        if (input.type === 'email' || input.type === 'text') {
                                            input.value = 'test@example.com';
                                        } else if (input.type === 'password') {
                                            input.value = 'dummy_password';
                                        }
                                    });
                                }
                            """)
                            await page.evaluate("() => document.querySelector('form').submit()")
                            await page.wait_for_load_state("domcontentloaded", timeout=5000)
                            post_login_cookies = await page.evaluate("() => document.cookie")
                            if initial_cookies == post_login_cookies and len(initial_cookies) > 0:
                                findings.append(LaneFinding(
                                    category="A07:2021-Identification and Authentication Failures",
                                    title="Potential Session Fixation",
                                    severity="Medium",
                                    detail="Session ID does not change after login attempt.",
                                    attack_vector="Session fixation test",
                                    evidence_snippet="Session cookie remained the same after login submission.",
                                    provided_solution="Regenerate session ID after successful authentication.",
                                    evidence={"initial_cookies": initial_cookies[:100], "post_login_cookies": post_login_cookies[:100]},
                                ))
                            break
                except Exception:
                    pass

            await self.trace_writer("analyze", "LAMBO-DARK AUTH FAILURES LANE COMPLETED.")
        finally:
            await page.close()

        return findings

    async def run_data_integrity_lane(self, context: BrowserContext, target_url: str) -> List[LaneFinding]:
        await self._require_verified_target(target_url)
        await self.trace_writer("execute", "LAMBO-DARK DATA INTEGRITY LANE CHECKING SRI AND INSECURE JS SOURCES.")
        findings: List[LaneFinding] = []
        page = await context.new_page()
        try:
            await self._require_verified_target(target_url)
            await self._throttle()
            response = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            if not response:
                return findings

            content = await page.content()
            script_tags = re.findall(r'<script[^>]*>', content, re.IGNORECASE)
            scripts_with_src = [s for s in script_tags if "src=" in s.lower()]
            scripts_without_sri = [s for s in scripts_with_src if "integrity=" not in s.lower()]
            if scripts_without_sri and len(scripts_without_sri) >= 2:
                findings.append(LaneFinding(
                    category="A08:2021-Software and Data Integrity Failures",
                    title="Missing Subresource Integrity (SRI)",
                    severity="Medium",
                    detail=f"{len(scripts_without_sri)} script tags load external resources without SRI hashes.",
                    attack_vector="HTML script tag integrity analysis",
                    evidence_snippet=scripts_without_sri[0][:200],
                    provided_solution="Add integrity attributes with SHA-256 hashes to all external script tags.",
                    evidence={"count": len(scripts_without_sri), "sample": [s[:150] for s in scripts_without_sri[:3]]},
                ))

            script_contents = re.findall(r'<script[^>]*>(.*?)</script>', content, re.IGNORECASE | re.DOTALL)
            http_scripts = []
            for sc in script_contents:
                http_matches = re.findall(r'(https?://[^\s"\']+)', sc)
                http_scripts.extend(http_matches)
            if http_scripts:
                findings.append(LaneFinding(
                    category="A08:2021-Software and Data Integrity Failures",
                    title="JavaScript Loaded from Non-HTTPS Source",
                    severity="High",
                    detail=f"{len(http_scripts)} JavaScript resource(s) loaded over insecure HTTP.",
                    attack_vector="Script source protocol analysis",
                    evidence_snippet=http_scripts[0][:200],
                    provided_solution="Load all JavaScript resources over HTTPS.",
                    evidence={"http_scripts": [s[:200] for s in http_scripts[:5]]},
                ))

            # Check for CI/CD pipeline files exposed
            cicd_paths = ["/.github", "/.gitlab-ci.yml", "/Jenkinsfile", "/.circleci", "/.travis.yml"]
            parsed = urlparse(target_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for path in cicd_paths:
                try:
                    cicd_resp = await page.goto(base + path, wait_until="domcontentloaded", timeout=3000)
                    if cicd_resp and cicd_resp.status == 200:
                        body = await page.content()
                        if any(kw in body.lower() for kw in ["pipeline", "stages", "build", "deploy"]):
                            findings.append(LaneFinding(
                                category="A08:2021-Software and Data Integrity Failures",
                                title="CI/CD Pipeline Configuration Exposed",
                                severity="Medium",
                                detail=f"CI/CD configuration file accessible at {path}.",
                                attack_vector="CI/CD file enumeration",
                                evidence_snippet=f"GET {path} returned CI/CD configuration.",
                                provided_solution="Restrict access to CI/CD configuration files.",
                                evidence={"path": path, "status": cicd_resp.status},
                            ))
                            break
                except Exception:
                    continue

            await self.trace_writer("analyze", "LAMBO-DARK DATA INTEGRITY LANE COMPLETED.")
        finally:
            await page.close()

        return findings

    async def run_logging_failures_lane(self, context: BrowserContext, target_url: str) -> List[LaneFinding]:
        await self._require_verified_target(target_url)
        await self.trace_writer("execute", "LAMBO-DARK LOGGING FAILURES LANE CHECKING MONITORING AND ERROR EXPOSURE.")
        findings: List[LaneFinding] = []
        page = await context.new_page()
        try:
            await self._require_verified_target(target_url)
            await self._throttle()
            response = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            if not response:
                return findings

            headers = await response.all_headers()
            has_request_id = any(k.lower() == "x-request-id" for k in headers)
            if not has_request_id:
                findings.append(LaneFinding(
                    category="A09:2021-Security Logging and Monitoring Failures",
                    title="Missing X-Request-Id Header",
                    severity="Low",
                    detail="Responses do not include X-Request-Id for request correlation and monitoring.",
                    attack_vector="HTTP response header analysis",
                    evidence_snippet="No X-Request-Id header observed.",
                    provided_solution="Add X-Request-Id header to all responses for distributed tracing.",
                    evidence={"headers_observed": list(headers.keys())[:15]},
                ))

            has_rate_limit = any("ratelimit" in k.lower() or "rate-limit" in k.lower() for k in headers)
            if not has_rate_limit:
                findings.append(LaneFinding(
                    category="A09:2021-Security Logging and Monitoring Failures",
                    title="Missing Rate Limit Headers",
                    severity="Low",
                    detail="Responses do not include rate limit headers, indicating no visible throttling.",
                    attack_vector="HTTP response header analysis",
                    evidence_snippet="No X-RateLimit-* or RateLimit-* headers observed.",
                    provided_solution="Add rate limit headers to signal request throttling status to clients.",
                    evidence={"headers_observed": list(headers.keys())[:15]},
                ))

            status = response.status
            try:
                body_text = await response.text()
            except Exception:
                body_text = ""
            error_exposure = ["stack trace", "traceback", "internal server error", "debug mode"]
            if status >= 500 and any(p in body_text.lower() for p in error_exposure):
                findings.append(LaneFinding(
                    category="A09:2021-Security Logging and Monitoring Failures",
                    title="Error Page Exposes Internal Information",
                    severity="Medium",
                    detail="Error page returns internal details that should not be exposed to end users.",
                    attack_vector="HTTP error response analysis",
                    evidence_snippet=body_text[:500],
                    provided_solution="Use generic error pages for production and log details server-side.",
                    evidence={"status": status, "body_excerpt": body_text[:500]},
                ))

            # Check for debug mode indicators
            debug_indicators = ["debug=true", "debug_mode", "x-debug", "x-debug-token"]
            has_debug = any(ind in body_text.lower() or ind in str(headers).lower() for ind in debug_indicators)
            if has_debug:
                findings.append(LaneFinding(
                    category="A09:2021-Security Logging and Monitoring Failures",
                    title="Debug Mode Enabled in Production",
                    severity="Medium",
                    detail="Application appears to have debug mode enabled.",
                    attack_vector="Debug mode detection",
                    evidence_snippet="Debug indicators found in response.",
                    provided_solution="Disable debug mode in production environments.",
                    evidence={"debug_indicators_found": True},
                ))

            await self.trace_writer("analyze", "LAMBO-DARK LOGGING FAILURES LANE COMPLETED.")
        finally:
            await page.close()

        return findings

    async def run_ssrf_lane(self, context: BrowserContext, target_url: str) -> List[LaneFinding]:
        await self._require_verified_target(target_url)
        await self.trace_writer("execute", "LAMBO-DARK SSRF LANE PROBING INTERNAL REDIRECTS AND PROTOCOL HANDLERS.")
        findings: List[LaneFinding] = []
        ssrf_payloads = [
            {"label": "loopback_ipv4", "url": "http://127.0.0.1", "desc": "Loopback IPv4"},
            {"label": "private_10", "url": "http://10.0.0.1", "desc": "Private 10.x range"},
            {"label": "private_192", "url": "http://192.168.1.1", "desc": "Private 192.168.x range"},
            {"label": "link_local", "url": "http://169.254.169.254", "desc": "Cloud metadata endpoint"},
            {"label": "file_protocol", "url": "file:///etc/passwd", "desc": "File protocol handler"},
            {"label": "gopher_protocol", "url": "gopher://127.0.0.1:25/", "desc": "Gopher protocol handler"},
        ]
        page = await context.new_page()
        try:
            for payload in ssrf_payloads:
                try:
                    await self._require_verified_target(target_url)
                    await self._throttle()
                    test_url = f"{target_url}?url={payload['url']}" if "?" not in target_url else f"{target_url}&url={payload['url']}"
                    resp = await page.goto(test_url, wait_until="domcontentloaded", timeout=8000)
                    if resp and resp.status == 200:
                        body = await page.content()
                        if payload["url"] not in body and any(kw in body.lower() for kw in ["root:", "metadata", "ami-id", "127.0.0", "root:x"]):
                            artifact = await self.screenshot_capture(
                                page,
                                lane_name="ssrf",
                                confirmation_label=f"confirmed_{payload['label']}",
                            )
                            findings.append(LaneFinding(
                                category="A10:2021-Server-Side Request Forgery",
                                title=f"SSRF via {payload['desc']}",
                                severity="Critical" if "169.254" in payload["url"] or "file" in payload["url"] else "High",
                                detail=f"Application fetches internal resource at {payload['desc']} ({payload['url']}).",
                                attack_vector=f"Playwright SSRF probe: {payload['label']}",
                                evidence_snippet=f"Target followed redirect to {payload['url']}.",
                                provided_solution="Validate and whitelist URLs before fetching; block internal IP ranges and protocol handlers.",
                                evidence={"payload": payload, "artifact": artifact},
                            ))
                            break
                except Exception:
                    continue

            # Test with different user agents to detect user-agent based filtering
            user_agents = [
                {"name": "Googlebot", "ua": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
                {"name": "Internal", "ua": "Mozilla/5.0 (Internal)"},
            ]
            for ua_info in user_agents:
                try:
                    await self._require_verified_target(target_url)
                    await self._throttle()
                    test_url = f"{target_url}?url=http://169.254.169.254" if "?" not in target_url else f"{target_url}&url=http://169.254.169.254"
                    await page.set_extra_http_headers({"User-Agent": ua_info["ua"]})
                    resp = await page.goto(test_url, wait_until="domcontentloaded", timeout=8000)
                    if resp and resp.status == 200:
                        body = await page.content()
                        if any(kw in body.lower() for kw in ["ami-id", "metadata", "instance-id"]):
                            findings.append(LaneFinding(
                                category="A10:2021-Server-Side Request Forgery",
                                title=f"SSRF via User-Agent Bypass ({ua_info['name']})",
                                severity="Critical",
                                detail=f"SSRF protection bypassed using {ua_info['name']} user agent.",
                                attack_vector="User-Agent based SSRF bypass",
                                evidence_snippet=f"SSRF successful with User-Agent: {ua_info['ua'][:100]}",
                                provided_solution="Do not rely on User-Agent filtering for SSRF protection.",
                                evidence={"user_agent": ua_info["name"], "ua_string": ua_info["ua"]},
                            ))
                            break
                except Exception:
                    continue

            await self.trace_writer("analyze", "LAMBO-DARK SSRF LANE COMPLETED.")
        finally:
            await page.close()

        return findings
