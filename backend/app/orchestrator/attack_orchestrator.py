import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List
from urllib.parse import urlparse

import httpx

try:
    import requests
except ImportError:  # pragma: no cover - resolved when requirements are installed
    requests = None

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - resolved when requirements are installed
    OpenAI = None

try:
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover - resolved when requirements are installed
    async_playwright = None

from app.engine.playwright_driver import build_safety_headers, create_hardened_browser_context
from app.engine.validation_lanes import ValidationLaneManager
from app.engine.heuristic_engine import HeuristicEngine
from app.orchestrator.remediation_agent import RemediationAgent
from app.services.log_monitor import LogMonitor


logger = logging.getLogger("aether.attack_orchestrator")

OWASP_TOP_10_2021 = [
    "A01:2021-Broken Access Control",
    "A02:2021-Cryptographic Failures",
    "A03:2021-Injection",
    "A04:2021-Insecure Design",
    "A05:2021-Security Misconfiguration",
    "A06:2021-Vulnerable and Outdated Components",
    "A07:2021-Identification and Authentication Failures",
    "A08:2021-Software and Data Integrity Failures",
    "A09:2021-Security Logging and Monitoring Failures",
    "A10:2021-Server-Side Request Forgery",
]

SENSITIVE_PATH_CANDIDATES = ["/admin", "/dashboard", "/settings", "/api/admin"]


class RateLimiter:
    def __init__(self, max_requests_per_second: float = 2.0) -> None:
        self.max_requests_per_second = max(float(max_requests_per_second), 0.1)
        self._interval_seconds = 1.0 / self.max_requests_per_second
        self._lock = asyncio.Lock()
        self._next_allowed_at = 0.0
        self.request_timestamps: List[float] = []

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait_for = self._next_allowed_at - now
            if wait_for > 0:
                await asyncio.sleep(wait_for)
                now = time.monotonic()
            self._next_allowed_at = now + self._interval_seconds
            self.request_timestamps.append(now)

    def set_requests_per_second(self, value: float) -> None:
        self.max_requests_per_second = max(float(value), 0.1)
        self._interval_seconds = 1.0 / self.max_requests_per_second


@dataclass
class GlobalAbort:
    is_triggered: Callable[[], bool]
    reason: Callable[[], str | None] | None = None

    def active(self) -> bool:
        return bool(self.is_triggered())

    def message(self) -> str:
        if self.reason is None:
            return "SCAN_TERMINATED_BY_SAFETY_GATE"
        return self.reason() or "SCAN_TERMINATED_BY_SAFETY_GATE"


class AttackOrchestrator:
    """
    Controlled validation orchestrator for local or explicitly allowlisted lab targets.

    This class wires NVIDIA-hosted reasoning and safety checks into a Playwright-driven
    validation loop, but it refuses to run active validation against non-local targets.
    """

    def __init__(
        self,
        user_id: str,
        scan_id: str,
        session_id: str,
        storage_engine: Any | None,
        global_abort: GlobalAbort | None = None,
        on_stage_update: Callable[[Dict[str, Any]], Awaitable[None]] | None = None,
        on_finding_discovered: Callable[[Dict[str, Any]], Awaitable[None]] | None = None,
        verification_service: Any | None = None,
        max_requests_per_second: float = 2.0,
        latency_warning_threshold_ms: int = 2000,
    ) -> None:
        self.user_id = uuid.UUID(str(user_id))
        self.scan_id = uuid.UUID(str(scan_id))
        self.session_id = uuid.UUID(str(session_id))
        self.storage = storage_engine
        self.global_abort = global_abort or GlobalAbort(is_triggered=lambda: False)
        self.on_stage_update = on_stage_update
        self.on_finding_discovered = on_finding_discovered
        self.verification_service = verification_service
        self.discovered_findings: List[Dict[str, Any]] = []
        self.generated_remediations: Dict[str, Dict[str, Any]] = {}
        self.remediation_agent = RemediationAgent()
        self.rate_limiter = RateLimiter(max_requests_per_second=max_requests_per_second)
        self.max_requests_per_second = float(max_requests_per_second)
        self.latency_warning_threshold_ms = int(latency_warning_threshold_ms)
        self.request_delay_multiplier = 1
        self.base_interaction_delay_ms = 700
        self.safety_headers = build_safety_headers(str(self.scan_id), str(self.user_id))
        self.log_monitor = LogMonitor(
            scan_id=str(self.scan_id),
            user_id=str(self.user_id),
            max_rps=max_requests_per_second,
        )
        self.api_key = os.getenv("NVIDIA_API_KEY") or os.getenv("API_KEY")
        self.allowed_hosts = {
            host.strip().lower()
            for host in os.getenv("AETHER_VALIDATION_HOSTS", "localhost,127.0.0.1,::1,babujichaay.com").split(",")
            if host.strip()
        }
        self.client = None
        if OpenAI is not None and self.api_key:
            self.client = OpenAI(
                base_url="https://integrate.api.nvidia.com/v1",
                api_key=self.api_key,
            )

    def _target_host(self, target_url: str) -> str:
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        return (parsed.hostname or "").lower()

    def _ensure_allowed_target(self, target_url: str) -> None:
        host = self._target_host(target_url)
        if host not in self.allowed_hosts:
            raise RuntimeError(
                f"TARGET_NOT_ALLOWED: '{host}' is not in the AETHER_VALIDATION_HOSTS allowlist. "
                f"Allowed: {sorted(self.allowed_hosts)}"
            )

    async def _require_verified_target(self, target_url: str) -> None:
        self._check_abort()
        if self.verification_service is None:
            raise RuntimeError("DOMAIN VERIFICATION FAILED: verification service unavailable for active Playwright actions.")
        verification = await self.verification_service.verify_target(target_url, user_id=str(self.user_id))
        if not verification.allowed:
            raise RuntimeError(verification.failure_message or "DOMAIN VERIFICATION FAILED.")

    async def _persist_trace(self, trace: List[Dict[str, Any]]) -> None:
        if self.storage is None:
            return
        await asyncio.to_thread(
            self.storage.update_scan_trace,
            self.user_id,
            self.scan_id,
            trace,
        )

    async def _emit_stage_update(self, phase: str, message: str, **extra: Any) -> None:
        if self.on_stage_update is None:
            return
        payload = {
            "type": "error" if phase == "error" else "thought",
            "phase": phase,
            "msg": message,
        }
        payload.update(extra)
        await self.on_stage_update(payload)

    async def _append_trace(self, trace: List[Dict[str, Any]], phase: str, message: str, **extra: Any) -> None:
        trace.append(
            {
                "phase": phase,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **extra,
            }
        )
        await self._persist_trace(trace)
        await self._emit_stage_update(phase, message, **extra)

    def _requires_remediation(self, severity: str) -> bool:
        return str(severity).strip().lower() in {"medium", "high", "critical"}

    async def _generate_remediation_payload(
        self,
        finding_payload: Dict[str, Any],
        trace: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        self._check_abort()
        await self._append_trace(
            trace,
            "remediate",
            f"LAMBO-DARK REMEDIATION CHAIN STARTED FOR {str(finding_payload.get('title', 'UNTITLED FINDING')).upper()}.",
            category=finding_payload.get("category"),
        )
        remediation = await asyncio.to_thread(
            self.remediation_agent.generate,
            finding_payload,
            str(finding_payload.get("evidence_snippet", "")),
        )
        remediation_payload = remediation.model_dump()
        finding_payload["provided_solution"] = remediation.render_provided_solution()
        finding_payload["remediation"] = remediation_payload
        self.generated_remediations[str(finding_payload["id"])] = remediation_payload
        await self._append_trace(
            trace,
            "remediate",
            f"LAMBO-DARK REMEDIATION PACKAGE READY FOR {str(finding_payload.get('title', 'UNTITLED FINDING')).upper()}.",
            category=finding_payload.get("category"),
        )
        return remediation_payload

    def _check_abort(self) -> None:
        if self.global_abort.active():
            raise RuntimeError(self.global_abort.message())

    async def _throttle_request(self) -> None:
        self._check_abort()
        await self.rate_limiter.acquire()

    def current_interaction_delay_ms(self) -> int:
        return self.base_interaction_delay_ms * self.request_delay_multiplier

    def _guarded_post(self, url: str, headers: Dict[str, str], payload: Dict[str, Any]) -> Any:
        self._check_abort()
        if requests is None:
            raise RuntimeError("requests is not installed")
        return requests.post(url, headers=headers, json=payload, timeout=20)

    async def safety_filter(self, payload: str) -> bool:
        """
        Run the candidate module description through NVIDIA content safety before dispatch.
        """
        self._check_abort()
        if not self.api_key or requests is None:
            logger.warning("Safety filter unavailable because NVIDIA API key or requests dependency is missing.")
            return False

        invoke_url = "https://integrate.api.nvidia.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        body = {
            "model": "nvidia/nemotron-3-content-safety",
            "messages": [{"role": "user", "content": payload}],
        }
        response = await asyncio.to_thread(self._guarded_post, invoke_url, headers, body)
        response.raise_for_status()
        content = response.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        return str(content).strip().lower() == "safe"

    async def _preflight_latency_check(self, target_url: str, trace: List[Dict[str, Any]]) -> None:
        await self._require_verified_target(target_url)
        await self._throttle_request()
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
                response = await client.get(target_url)
                status_code = response.status_code
        except Exception as e:
            status_code = None
            logger.warning(f"Preflight latency check failed: {e}")
        latency_ms = int((time.monotonic() - started) * 1000)
        await self.log_monitor.log_request(
            request_url=target_url,
            safety_token=self.safety_headers.get("X-Aether-Safety-Token", ""),
            status="success" if status_code and 200 <= status_code < 400 else "blocked",
            status_code=status_code,
            latency_ms=latency_ms,
            notes="preflight_latency_check",
        )
        await self._append_trace(trace, "observe", f"Pre-flight latency check recorded {latency_ms}ms.", latency_ms=latency_ms)
        if latency_ms > self.latency_warning_threshold_ms:
            self.request_delay_multiplier *= 2
            await self._emit_stage_update(
                "observe",
                "TARGET INSTABILITY DETECTED. SLOWING DOWN SCAN.",
                type="warning",
                latency_ms=latency_ms,
                delay_multiplier=self.request_delay_multiplier,
            )

    async def nemotron_reasoning_stream(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Capture reasoning_content for persistence in scans.thought_trace.
        """
        trace: List[Dict[str, Any]] = []
        if self.client is None:
            await self._append_trace(
                trace,
                "plan",
                "NVIDIA reasoning client unavailable; using local fallback validation plan.",
            )
            return trace

        self._check_abort()
        stream = self.client.chat.completions.create(
            model="nvidia/nemotron-3-super-120b-a12b",
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Produce a defensive OWASP Top 10 validation plan for this lab target. "
                        f"Target: {target_url}. Restrict the plan to local, non-destructive, controlled validation."
                    ),
                }
            ],
            extra_body={
                "chat_template_kwargs": {"enable_thinking": True},
                "reasoning_budget": 16384,
            },
            stream=True,
        )

        full_reasoning = ""
        for chunk in stream:
            self._check_abort()
            if not getattr(chunk, "choices", None):
                continue
            delta = chunk.choices[0].delta
            reasoning = getattr(delta, "reasoning_content", None)
            if reasoning:
                full_reasoning += reasoning

        await self._append_trace(
            trace,
            "plan",
            full_reasoning or "Nemotron reasoning stream completed without exposed reasoning tokens.",
        )
        return trace

    async def _insert_finding(
        self,
        trace: List[Dict[str, Any]],
        *,
        category: str,
        title: str,
        severity: str,
        detail: str,
        attack_vector: str,
        evidence_snippet: str,
        provided_solution: str,
        evidence: Dict[str, Any] | None = None,
    ) -> str:
        finding_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"nvidia-finding:{self.scan_id}:{self.session_id}:{category}:{title}:{severity}",
            )
        )
        finding_payload = {
            "id": finding_id,
            "category": category,
            "title": title,
            "severity": severity,
            "detail": detail,
            "attack_vector": attack_vector,
            "detected_threat": title,
            "evidence_snippet": evidence_snippet,
            "provided_solution": provided_solution,
            "evidence": evidence or {},
        }
        if self._requires_remediation(severity):
            await self._generate_remediation_payload(finding_payload, trace)
        self.discovered_findings.append(finding_payload)
        if self.on_finding_discovered is not None:
            await self.on_finding_discovered(finding_payload)
        if self.storage is not None:
            await asyncio.to_thread(
                self.storage.insert_vulnerability,
                self.user_id,
                self.scan_id,
                category,
                title,
                severity,
                detail,
                self.session_id,
                attack_vector,
                title,
                evidence_snippet,
                provided_solution,
                evidence or {},
                finding_id,
            )
        return finding_id

    async def _tech_stack_recon(self, target_url: str, trace: List[Dict[str, Any]]) -> Dict[str, Any]:
        if async_playwright is None:
            await self._append_trace(trace, "observe", "Playwright unavailable; tech stack recon skipped.")
            return {"title": None, "url": target_url, "scripts": []}

        self._check_abort()
        await self._require_verified_target(target_url)
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(args=["--no-sandbox"])
            try:
                context = await create_hardened_browser_context(
                    browser,
                    scan_id=str(self.scan_id),
                    user_id=str(self.user_id),
                )
                page = await context.new_page()
                self._check_abort()
                await self._require_verified_target(target_url)
                await self._throttle_request()
                started_recon = time.monotonic()
                response = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
                latency_recon = int((time.monotonic() - started_recon) * 1000)
                title = await page.title()
                scripts = await page.eval_on_selector_all("script[src]", "els => els.map((el) => el.src)")
                final_url = page.url
                status_code = response.status if response else None
                await self.log_monitor.log_request(
                    request_url=target_url,
                    safety_token=self.safety_headers.get("X-Aether-Safety-Token", ""),
                    status="success" if status_code and 200 <= status_code < 400 else "blocked",
                    status_code=status_code,
                    latency_ms=latency_recon,
                    notes="tech_stack_recon",
                )
                await self._append_trace(
                    trace,
                    "observe",
                    f"Playwright recon captured title='{title or 'unknown'}' status={status_code} scripts={len(scripts)}.",
                )
                return {
                    "title": title,
                    "url": final_url,
                    "scripts": scripts[:25],
                    "status_code": status_code,
                }
            finally:
                await browser.close()

    async def _validate_a01_broken_access_control(self, context: Any, target_url: str, trace: List[Dict[str, Any]]) -> None:
        payload_description = "Local lab validation for A01 using controlled header and cookie variation against known sensitive paths."
        if not await self.safety_filter(payload_description):
            await self._append_trace(trace, "plan", "A01 module skipped by NVIDIA content safety.")
            return

        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        await self._append_trace(trace, "execute", "Dispatching A01 access-control validation against allowlisted lab target.")

        for path in SENSITIVE_PATH_CANDIDATES:
            self._check_abort()
            await self._require_verified_target(target_url)
            page = await context.new_page()
            try:
                await context.set_extra_http_headers({**self.safety_headers, "X-User-Role": "admin"})
                await context.add_cookies(
                    [{"name": "role", "value": "admin", "url": base_url, "path": "/"}]
                )
                await self._require_verified_target(target_url)
                await self._throttle_request()
                started_a01 = time.monotonic()
                response = await page.goto(f"{base_url}{path}", wait_until="domcontentloaded", timeout=10000)
                latency_a01 = int((time.monotonic() - started_a01) * 1000)
                status_code = response.status if response else None
                await self.log_monitor.log_request(
                    request_url=f"{base_url}{path}",
                    safety_token=self.safety_headers.get("X-Aether-Safety-Token", ""),
                    status="success" if status_code and 200 <= status_code < 400 else "blocked",
                    status_code=status_code,
                    latency_ms=latency_a01,
                    notes=f"a01_validation_path:{path}",
                )
                await self._append_trace(trace, "execute", f"A01 checked {path} and observed status {status_code}.", category="A01")

                if status_code == 200:
                    evidence_snippet = f"{path} returned 200 after controlled role header/cookie variation."
                    await self._insert_finding(
                        trace,
                        category="A01:2021-Broken Access Control",
                        title="Potential Access Control Bypass in Local Validation",
                        severity="High",
                        detail="A sensitive path remained accessible after controlled privilege variation in a lab-only validation run.",
                        attack_vector="Controlled role header and cookie variation",
                        evidence_snippet=evidence_snippet,
                        provided_solution="Enforce server-side authorization on every sensitive route and ignore client-controlled role assertions.",
                        evidence={"path": path, "status_code": status_code},
                    )
                    await self._append_trace(trace, "analyze", f"A01 logged a finding for {path}; stopping the current validation branch.", category="A01")
                    break
            finally:
                await page.close()

    async def _run_playwright_validation_lanes(self, context: Any, target_url: str, trace: List[Dict[str, Any]]) -> None:
        payload_description = "Local lab validation for A03 using Playwright-backed XSS and injection confirmation lanes."
        if not await self.safety_filter(payload_description):
            await self._append_trace(trace, "plan", "A03 Playwright validation lanes were skipped by NVIDIA content safety.")
            return
        if self.verification_service is None:
            await self._append_trace(trace, "plan", "A03 Playwright validation lanes skipped because no verification service was available.")
            return

        lane_manager = ValidationLaneManager(
            verification_service=self.verification_service,
            user_id=str(self.user_id),
            trace_writer=lambda phase, message: self._append_trace(trace, phase, message, category="A03"),
            abort_check=self._check_abort,
            rate_limit=self._throttle_request,
            interaction_delay_ms=self.current_interaction_delay_ms,
        )
        confirmed_findings = []
        confirmed_findings.extend(await lane_manager.run_xss_lane(context, target_url))
        confirmed_findings.extend(await lane_manager.run_injection_lane(context, target_url))

        if not confirmed_findings:
            await self._append_trace(trace, "analyze", "A03 Playwright validation lanes completed without a confirmed active hit.", category="A03")
            return

        for finding in confirmed_findings:
            await self._insert_finding(
                trace,
                category=finding.category,
                title=finding.title,
                severity=finding.severity,
                detail=finding.detail,
                attack_vector=finding.attack_vector,
                evidence_snippet=finding.evidence_snippet,
                provided_solution=finding.provided_solution,
                evidence=finding.evidence,
            )
            await self._append_trace(trace, "analyze", f"{finding.title.upper()} confirmed and persisted from Playwright lane evidence.", category="A03")

    async def _run_lane_for_category(self, lane_method_name: str, category: str, context: Any, target_url: str, trace: List[Dict[str, Any]]) -> None:
        if self.verification_service is None:
            await self._append_trace(trace, "plan", f"{category} skipped: no verification service.", category=category)
            return
        lane_manager = ValidationLaneManager(
            verification_service=self.verification_service,
            user_id=str(self.user_id),
            trace_writer=lambda phase, message: self._append_trace(trace, phase, message, category=category),
            abort_check=self._check_abort,
            rate_limit=self._throttle_request,
            interaction_delay_ms=self.current_interaction_delay_ms,
        )
        lane_method = getattr(lane_manager, lane_method_name, None)
        if lane_method is None:
            await self._append_trace(trace, "analyze", f"{category}: lane method {lane_method_name} not found.", category=category)
            return
        confirmed_findings = await lane_method(context, target_url)
        for finding in confirmed_findings:
            await self._insert_finding(
                trace,
                category=finding.category,
                title=finding.title,
                severity=finding.severity,
                detail=finding.detail,
                attack_vector=finding.attack_vector,
                evidence_snippet=finding.evidence_snippet,
                provided_solution=finding.provided_solution,
                evidence=finding.evidence,
            )
            await self._append_trace(trace, "analyze", f"{finding.title.upper()} confirmed from {category} lane.", category=category)
        if not confirmed_findings:
            await self._append_trace(trace, "analyze", f"{category} lane completed with no confirmed findings.", category=category)

    async def _validate_a02_crypto_failures(self, context: Any, target_url: str, trace: List[Dict[str, Any]]) -> None:
        await self._run_lane_for_category("run_crypto_failures_lane", "A02:2021-Cryptographic Failures", context, target_url, trace)

    async def _validate_a04_insecure_design(self, context: Any, target_url: str, trace: List[Dict[str, Any]]) -> None:
        await self._run_lane_for_category("run_insecure_design_lane", "A04:2021-Insecure Design", context, target_url, trace)

    async def _validate_a05_misconfiguration(self, context: Any, target_url: str, trace: List[Dict[str, Any]]) -> None:
        await self._run_lane_for_category("run_misconfiguration_lane", "A05:2021-Security Misconfiguration", context, target_url, trace)

    async def _validate_a06_vulnerable_components(self, context: Any, target_url: str, trace: List[Dict[str, Any]]) -> None:
        await self._run_lane_for_category("run_vulnerable_components_lane", "A06:2021-Vulnerable and Outdated Components", context, target_url, trace)

    async def _validate_a07_auth_failures(self, context: Any, target_url: str, trace: List[Dict[str, Any]]) -> None:
        await self._run_lane_for_category("run_auth_failures_lane", "A07:2021-Identification and Authentication Failures", context, target_url, trace)

    async def _validate_a08_data_integrity(self, context: Any, target_url: str, trace: List[Dict[str, Any]]) -> None:
        await self._run_lane_for_category("run_data_integrity_lane", "A08:2021-Software and Data Integrity Failures", context, target_url, trace)

    async def _validate_a09_logging_failures(self, context: Any, target_url: str, trace: List[Dict[str, Any]]) -> None:
        await self._run_lane_for_category("run_logging_failures_lane", "A09:2021-Security Logging and Monitoring Failures", context, target_url, trace)

    async def _validate_a10_ssrf(self, context: Any, target_url: str, trace: List[Dict[str, Any]]) -> None:
        await self._run_lane_for_category("run_ssrf_lane", "A10:2021-Server-Side Request Forgery", context, target_url, trace)

    async def run_validation_loop(self, target_url: str) -> Dict[str, Any]:
        """
        Execute the controlled validation loop.

        Active modules are restricted to local or explicitly allowlisted lab targets.
        """
        self._ensure_allowed_target(target_url)
        await self.log_monitor.mark_scan_start()
        trace = await self.nemotron_reasoning_stream(target_url)
        await self._append_trace(trace, "plan", "Attack Surface Orchestrator initialized.")
        await self._preflight_latency_check(target_url, trace)

        # Deep heuristic pass as part of attack surface orchestration
        await self._append_trace(trace, "observe", "Launching deep heuristic engine pass.")

        async def heuristic_request_hook(url: str, method: str, headers: Dict[str, str] | None = None) -> httpx.Response:
            self._check_abort()
            await self._throttle_request()

            combined_headers = {**self.safety_headers}
            if headers:
                combined_headers.update(headers)

            started = time.monotonic()
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                if method.upper() == "GET":
                    response = await client.get(url, headers=combined_headers)
                elif method.upper() == "OPTIONS":
                    response = await client.options(url, headers=combined_headers)
                else:
                    raise ValueError(f"Unsupported method in heuristic request hook: {method}")

            latency_ms = int((time.monotonic() - started) * 1000)
            await self.log_monitor.log_request(
                request_url=url,
                safety_token=combined_headers.get("X-Aether-Safety-Token", ""),
                status="success" if 200 <= response.status_code < 400 else "blocked",
                status_code=response.status_code,
                latency_ms=latency_ms,
                notes=f"heuristic_engine_{method.lower()}",
            )
            return response

        heuristic_engine = HeuristicEngine(target_url, request_hook=heuristic_request_hook)
        heuristic_results = await heuristic_engine.run_all()

        for finding in heuristic_results.get("findings", []):
            await self._insert_finding(
                trace,
                category=finding.get("category", "unknown"),
                title=finding.get("title", "Untitled finding"),
                severity=finding.get("severity", "info"),
                detail=finding.get("detail", ""),
                attack_vector=finding.get("attack_vector", "unspecified"),
                evidence_snippet=finding.get("evidence_snippet", ""),
                provided_solution=finding.get("provided_solution", "Apply standard hardening."),
                evidence=finding.get("evidence"),
            )

        tech_stack = await self._tech_stack_recon(target_url, trace)
        profile_rows = [
            {
                "user_id": str(self.user_id),
                "email": None,
                "profile_type": "vulnerability_profiler",
                "label": "NVIDIA Validation Loop",
                "summary": "Profiles the live Nemotron-guided validation loop and lab-only OWASP category coverage.",
                "details": {
                    "source": "nvidia_orchestrator",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "tech_stack": tech_stack,
                    "allowed_hosts": sorted(self.allowed_hosts),
                    "remediation_findings": list(self.generated_remediations.keys()),
                },
            }
        ]

        if async_playwright is None:
            raise RuntimeError("Playwright is required for validation modules.")

        modules = {
            "A01:2021-Broken Access Control": self._validate_a01_broken_access_control,
            "A02:2021-Cryptographic Failures": self._validate_a02_crypto_failures,
            "A03:2021-Injection": self._run_playwright_validation_lanes,
            "A04:2021-Insecure Design": self._validate_a04_insecure_design,
            "A05:2021-Security Misconfiguration": self._validate_a05_misconfiguration,
            "A06:2021-Vulnerable and Outdated Components": self._validate_a06_vulnerable_components,
            "A07:2021-Identification and Authentication Failures": self._validate_a07_auth_failures,
            "A08:2021-Software and Data Integrity Failures": self._validate_a08_data_integrity,
            "A09:2021-Security Logging and Monitoring Failures": self._validate_a09_logging_failures,
            "A10:2021-Server-Side Request Forgery": self._validate_a10_ssrf,
        }

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(args=["--no-sandbox"])
            try:
                context = await create_hardened_browser_context(
                    browser,
                    scan_id=str(self.scan_id),
                    user_id=str(self.user_id),
                )
                for category in OWASP_TOP_10_2021:
                    self._check_abort()
                    await self._append_trace(trace, "plan", f"Starting category evaluation for {category}.", category=category)
                    module = modules.get(category)
                    if module is None:
                        await self._evaluate_placeholder_category(category, trace)
                        continue
                    await module(context, target_url, trace)
            except RuntimeError as error:
                if "SAFETY_GATE" in str(error).upper():
                    await self._append_trace(trace, "error", "SCAN_TERMINATED_BY_SAFETY_GATE")
                    logger.warning("Validation loop aborted by safety gate for scan=%s", self.scan_id)
                    await self.log_monitor.mark_scan_end()
                    safety_audit = await self.log_monitor.generate_safety_audit_report(
                        self.rate_limiter.request_timestamps
                    )
                    profile_rows[0]["details"]["remediation_findings"] = list(self.generated_remediations.keys())
                    return {
                        "status": "terminated",
                        "reason": "SCAN_TERMINATED_BY_SAFETY_GATE",
                        "tech_stack": tech_stack,
                        "findings": list(self.discovered_findings),
                        "remediations": dict(self.generated_remediations),
                        "profiles": profile_rows,
                        "trace": trace,
                        "safety_audit": self.log_monitor.to_dict(safety_audit),
                    }
                raise
            finally:
                await browser.close()

        await self._append_trace(trace, "analyze", "Validation loop completed for all OWASP categories.")
        await self.log_monitor.mark_scan_end()
        safety_audit = await self.log_monitor.generate_safety_audit_report(
            self.rate_limiter.request_timestamps
        )
        profile_rows[0]["details"]["remediation_findings"] = list(self.generated_remediations.keys())
        return {
            "status": "completed",
            "tech_stack": tech_stack,
            "thought_trace_entries": len(trace),
            "findings": list(self.discovered_findings),
            "remediations": dict(self.generated_remediations),
            "profiles": profile_rows,
            "trace": trace,
            "safety_audit": self.log_monitor.to_dict(safety_audit),
        }
