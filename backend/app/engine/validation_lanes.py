import asyncio
import base64
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List

try:
    from playwright.async_api import BrowserContext
    from playwright.async_api import Page
except ImportError:  # pragma: no cover - resolved when requirements are installed
    BrowserContext = Any  # type: ignore[assignment]
    Page = Any  # type: ignore[assignment]


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
SAFE_XSS_MARKER_PREFIX = "AETHER_XSS_PROBE"
SAFE_XSS_PAYLOAD_TEMPLATE = '<div data-aether-marker="{marker}">{marker}</div>'
SAFE_INJECTION_PAYLOADS = ["' OR '1'='1", "'; WAITFOR DELAY '0:0:03' --"]


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
