import asyncio
import json
import os
import time
import random
import logging
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, ValidationError
try:
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover - resolved when requirements are installed
    PlaywrightTimeoutError = Exception  # type: ignore[misc,assignment]
    async_playwright = None  # type: ignore[assignment]

from app.tools.audit_engine import format_audit_logs
from app.engine.heuristic_engine import HeuristicEngine
from app.tools.headers import format_header_logs, header_audit
from app.tools.remediation import find_vulnerability, generate_remediation
from app.tools.scanner import format_port_logs, port_scan

try:
    from google import genai
except ImportError:  # pragma: no cover - resolved when requirements are installed
    genai = None  # type: ignore[assignment]

logger = logging.getLogger("aether.brain")

# OWASP Top 10 (2021) - The 10 critical web application security risks.
# Each category maps to validation lanes in validation_lanes.py that execute
# Playwright-based checks against the target URL.
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

# Prescriptive remediation guidance per OWASP category.
# Used by the AI orchestrator to generate context-specific fix recommendations.
OWASP_REMEDIATIONS = {
    "A01:2021-Broken Access Control": "Enforce server-side authorization checks on every object and route, and deny access by default.",
    "A02:2021-Cryptographic Failures": "Enforce HTTPS everywhere, set HSTS, and remove mixed-content or weak transport defaults.",
    "A03:2021-Injection": "Use parameterized queries, strict input validation, and contextual output encoding across all dynamic sinks.",
    "A04:2021-Insecure Design": "Model abuse cases during design review and add guardrails for risky workflows before implementation.",
    "A05:2021-Security Misconfiguration": "Harden default headers, reduce exposed metadata, and align runtime configuration with OWASP secure defaults.",
    "A06:2021-Vulnerable and Outdated Components": "Inventory framework and server versions, patch supported releases, and automate dependency review.",
    "A07:2021-Identification and Authentication Failures": "Review session handling, MFA coverage, and cookie protections for every authentication boundary.",
    "A08:2021-Software and Data Integrity Failures": "Sign and verify build artifacts, lock trusted update channels, and constrain privileged runtime loading.",
    "A09:2021-Security Logging and Monitoring Failures": "Ensure high-risk actions are logged centrally with alerting and verified retention coverage.",
    "A10:2021-Server-Side Request Forgery": "Constrain outbound requests with allowlists, network egress controls, and strict URL validation.",
}


async def analyze_tech_stack(target_url: str) -> Dict[str, Any]:
    if async_playwright is None:
        return {"target_url": target_url, "frameworks": [], "scripts": [], "headers": {}, "error": "Playwright is unavailable."}

    browser = None
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(args=["--no-sandbox"])
            page = await browser.new_page()
            response = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightTimeoutError:
                logger.info("Playwright networkidle timeout for %s; continuing with captured DOM.", target_url)

            title = await page.title()
            final_url = page.url
            scripts = await page.eval_on_selector_all("script[src]", "els => els.map((el) => el.src)")
            metas = await page.eval_on_selector_all(
                "meta",
                "els => els.map((el) => ({name: el.getAttribute('name') || el.getAttribute('property') || el.getAttribute('http-equiv'), content: el.getAttribute('content')}))",
            )
            html = await page.content()
            headers = {key.lower(): value for key, value in ((response.headers if response else {}) or {}).items()}

            frameworks: List[str] = []
            if "__NEXT_DATA__" in html or any("/_next/" in script for script in scripts):
                frameworks.append("Next.js")
            if "data-reactroot" in html or any("react" in script.lower() for script in scripts):
                frameworks.append("React")
            if any("vue" in script.lower() for script in scripts):
                frameworks.append("Vue")
            if any("angular" in script.lower() for script in scripts):
                frameworks.append("Angular")
            if headers.get("x-powered-by"):
                frameworks.append(headers["x-powered-by"])
            if headers.get("server"):
                frameworks.append(headers["server"])

            return {
                "target_url": target_url,
                "final_url": final_url,
                "title": title,
                "headers": headers,
                "scripts": scripts[:25],
                "meta": metas[:20],
                "frameworks": sorted({framework for framework in frameworks if framework}),
            }
    except Exception as error:
        return {
            "target_url": target_url,
            "frameworks": [], "scripts": [],
            "headers": {},
            "error": f"Playwright tech stack analysis failed: {error}",
        }
    finally:
        if browser is not None:
            await browser.close()


class PlanStep(BaseModel):
    label: Literal["THOUGHT", "OBSERVE", "PLAN"]
    message: str = Field(min_length=12, max_length=220)


class InitialPlan(BaseModel):
    steps: List[PlanStep] = Field(min_length=3, max_length=3)


class FinalVerdict(BaseModel):
    threat_level: Literal["low", "medium", "high", "critical"]
    risk_impact: str = Field(min_length=20, max_length=420)
    remediation_steps: List[str] = Field(min_length=2, max_length=4)


class BrainStatus(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    TERMINATED = "terminated"
    COMPLETE = "complete"
    FAILED = "failed"


class BrainBoundaryError(Exception):
    def __init__(self, message: str, *, phase: str = "analyze") -> None:
        super().__init__(message)
        self.message = message
        self.phase = phase


class AgentFinding(BaseModel):
    category: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Literal["Low", "Medium", "High", "Critical"]
    attack_vector: str = Field(min_length=1)
    detected_threat: str = Field(min_length=1)
    evidence_snippet: str = Field(min_length=1)
    provided_solution: str | None = None
    remediation_code: str | None = None
    detail: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)


class AgentResponsePayload(BaseModel):
    thought_trace: Dict[str, Any] | List[Any]
    vulnerabilities: List[AgentFinding] = Field(default_factory=list)


@dataclass
class BrainState:
    scan_id: str
    target_url: str # The URL being scanned
    phase: str = "observe"
    status: BrainStatus = BrainStatus.RUNNING
    current_step: int = 0
    requires_operator: bool = False
    resume_token: str = "PLAN_ACK"
    resume_reason: str | None = None
    error_message: str | None = None
    notes: List[str] = field(default_factory=list)
    pause_event: asyncio.Event = field(default_factory=asyncio.Event)

    def __post_init__(self) -> None:
        self.pause_event.set()

    def snapshot(self) -> Dict[str, str | int | bool | None]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "phase": self.phase,
            "status": self.status.value,
            "current_step": self.current_step,
            "requires_operator": self.requires_operator,
            "resume_reason": self.resume_reason,
            "error_message": self.error_message,
        }


class PentestAgent:
    def __init__(self) -> None:
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.model_name = "gemini-2.5-flash"
        self.request_timeout_seconds = 20

    def _has_usable_api_key(self) -> bool:
        return bool(self.api_key) and not self.api_key.lower().startswith("your_")

    def _fallback_plan(self, hostname: str, target_url: str) -> InitialPlan:
        return InitialPlan(
            steps=[
                PlanStep(
                    label="THOUGHT",
                    message=f"Target {hostname} resolved. Analyzing transport clues, security headers, and visible attack surface before first contact.",
                ),
                PlanStep(
                    label="OBSERVE",
                    message=f"Map passive signals on {target_url} to identify framework fingerprints, route shapes, and authentication boundaries.",
                ),
                PlanStep(
                    label="PLAN",
                    message="Stage a multi-phase hunt across access control, hostile input reflection, and abuse-resilience signals before active execution.",
                ),
            ]
        )

    def _build_prompt(self, target_url: str, hostname: str) -> str:
        return f"""
You are AETHER, a senior vulnerability hunter for an agentic SaaS security platform.
Target URL: {target_url}
Host: {hostname}

Return a JSON object with exactly this shape:
{{
  "steps": [
    {{"label": "THOUGHT", "message": "..."}},
    {{"label": "OBSERVE", "message": "..."}},
    {{"label": "PLAN", "message": "..."}}
  ]
}}

Rules:
- Exactly 3 steps in this order: THOUGHT, OBSERVE, PLAN.
- Each message must be concise, technical, and specific to the target.
- Focus on pre-execution reasoning only.
- Mention headers, sessions, routes, access control, or entry points when relevant.
- Do not mention the user, the prompt, the schema, JSON, or that you are generating a response.
- Do not explain your instructions or describe yourself.
- Treat the target as a real web asset and reason about a staged hunt across passive HTTP, application-layer reconnaissance, and safe heuristic validation.
- Output raw JSON only.
""".strip()

    def _generate_with_retry(self, client, contents, config, max_retries=5):
        """Generates content with model fallback and exponential backoff for transient errors."""
        model_options = [self.model_name, "gemini-2.5-flash-lite", "gemini-2.5-pro"]
        last_exception = None

        for model in model_options:
            for attempt in range(max_retries):
                try:
                    return client.models.generate_content(
                        model=model,
                        contents=contents,
                        config=config,
                    )
                except Exception as e:
                    last_exception = e
                    error_msg = str(e).upper()
                    # Check for transient/overload errors (503, 504, 429, Resource Exhausted)
                    if any(err in error_msg for err in ["503", "504", "429", "UNAVAILABLE", "RESOURCE_EXHAUSTED", "DEADLINE_EXCEEDED", "TIMEOUT"]):
                        wait = (2 ** attempt) + random.uniform(0, 1)
                        logger.warning("Gemini model %s overloaded. Attempt %d/%d, retrying in %.2fs", model, attempt+1, max_retries, wait)
                        time.sleep(wait)
                    else:
                        # Non-transient error (e.g. invalid auth, safety filters), try next model in chain
                        logger.error("Gemini model %s failed with non-transient error: %s", model, error_msg)
                        break
        raise last_exception or RuntimeError("Gemini failed after retries and model fallback. Check API key and quota.")

    def generate_initial_plan(self, target_url: str) -> InitialPlan:
        hostname = urlparse(target_url).netloc.upper()

        if genai is None or not self._has_usable_api_key():
            return self._fallback_plan(hostname, target_url)

        try:
            client = genai.Client(api_key=self.api_key)
            prompt_text = self._build_prompt(target_url, hostname)
            response = self._generate_with_retry(
                client,
                contents=genai.types.Content(parts=[genai.types.Part(text=prompt_text)]),
                config={
                    "response_mime_type": "application/json",
                    "response_json_schema": InitialPlan.model_json_schema(),
                },
            )
            return self._validate_response(response.text, hostname, target_url)
        except Exception as error:
            logger.error("Initial planning failed after retries: %s. Degrading to fallback plan.", str(error))
            return self._fallback_plan(hostname, target_url)

    def _fallback_verdict(self, results: Dict[str, Any]) -> FinalVerdict:
        port_scan_result = results.get("port_scan") or {}
        header_audit_result = results.get("header_audit") or {}
        audit_result = results.get("audit_engine") or {}
        open_ports = port_scan_result.get("open_ports", [])
        findings = header_audit_result.get("findings", [])
        hunt_findings = audit_result.get("findings", [])

        threat_level: Literal["low", "medium", "high", "critical"] = "low"
        if findings or hunt_findings or len(open_ports) >= 3:
            threat_level = "medium"
        if len(findings) + len(hunt_findings) >= 3 or any(port in open_ports for port in (8080, 3000, 5000)):
            threat_level = "high"
        if len(findings) + len(hunt_findings) >= 5:
            threat_level = "critical"

        risk_impact = (
            f"The exposed ports {open_ports or ['none']} and header findings "
            f"({len(findings) + len(hunt_findings)} total hunt signals) indicate a {threat_level.upper()} probability of avoidable web-surface exposure."
        )
        remediation_steps = [
            "Restrict public-facing ports to required production services and place non-essential listeners behind access controls.",
            "Add missing browser security headers including HSTS, CSP, X-Frame-Options, and X-Content-Type-Options.",
            "Review input-handling and abuse-control paths for reflected parameter handling, throttling, and unnecessary infrastructure disclosures.",
            "Review upstream proxy and application defaults to align deployment hardening with the observed attack surface.",
        ]
        if threat_level in {"high", "critical"}:
            remediation_steps.append(
                "Prioritize a targeted validation pass on the exposed alternate ports before the next production release window."
            )

        return FinalVerdict(
            threat_level=threat_level,
            risk_impact=risk_impact,
            remediation_steps=remediation_steps[:4],
        )

    def _validate_response(self, raw_text: str, hostname: str, target_url: str) -> InitialPlan:
        cleaned = raw_text.strip()

        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            cleaned = cleaned.removeprefix("json").strip()

        try:
            plan = InitialPlan.model_validate_json(cleaned)
        except ValidationError:
            return self._fallback_plan(hostname, target_url)
        except json.JSONDecodeError:
            return self._fallback_plan(hostname, target_url)

        labels = [step.label for step in plan.steps]
        if labels != ["THOUGHT", "OBSERVE", "PLAN"]:
            return self._fallback_plan(hostname, target_url)

        banned_fragments = (
            "USER IS ASKING",
            "I WILL GENERATE",
            "JSON",
            "SCHEMA",
            "PROMPT",
            "PLACEHOLDER",
            "I NEED TO",
        )
        if any(fragment in step.message.upper() for step in plan.steps for fragment in banned_fragments):
            return self._fallback_plan(hostname, target_url)

        return plan

    def generate_final_verdict(self, target_url: str, results: Dict[str, Any]) -> FinalVerdict:
        if genai is None or not self._has_usable_api_key():
            return self._fallback_verdict(results)

        # Filter results to keep size manageable for LLM
        lite_results = {k: v for k, v in results.items() if v is not None}

        prompt = f"""
You are a Lead Security Consultant writing the closing security posture summary for a tactical vulnerability hunt.
Target URL: {target_url}
Tool Results JSON:
{json.dumps(lite_results)}

Return raw JSON only in this exact shape:
{{
  "threat_level": "low|medium|high|critical",
  "risk_impact": "...",
  "remediation_steps": ["...", "..."]
}}

Rules:
- Summarize the business and technical impact of the discovered exposure.
- Remediation steps must be concrete, prioritized, and implementation-focused.
- Do not mention prompts, JSON, schema, or yourself.
- Keep risk_impact concise and executive-ready.
""".strip()

        try:
            client = genai.Client(api_key=self.api_key)
            verdict_prompt = prompt.strip()
            response = self._generate_with_retry(
                client,
                contents=genai.types.Content(parts=[genai.types.Part(text=verdict_prompt)]),
                config={
                    "response_mime_type": "application/json",
                    "response_json_schema": FinalVerdict.model_json_schema(),
                },
            )
            cleaned = response.text.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.strip("`")
                cleaned = cleaned.removeprefix("json").strip()
            return FinalVerdict.model_validate_json(cleaned)
        except Exception as error:
            logger.error("Final verdict generation failed after retries: %s. Using fallback verdict.", str(error))
            return self._fallback_verdict(results)


class BrainOrchestrator:
    def __init__(self, scan_id: str, target_url: str, user_identity: str | None = None):
        self.state = BrainState(scan_id=scan_id, target_url=target_url)
        self.hostname = urlparse(target_url).netloc.upper()
        self.user_identity = user_identity
        self.plan_hold_triggered = False
        self.agent = PentestAgent()
        self.initial_plan: InitialPlan | None = None
        self.execution_results: Dict[str, Any] = {"tech_stack": None, "port_scan": None, "header_audit": None, "audit_engine": None}
        self.final_report: Dict[str, Any] | None = None
        self.remediations: Dict[str, Any] = {}
        self.decision_trace: List[Dict[str, Any]] = []
        self.global_abort = False
        self.global_abort_reason: str | None = None

    async def ensure_initial_plan(self) -> InitialPlan:
        if self.initial_plan is None:
            try:
                self.initial_plan = await asyncio.wait_for(
                    asyncio.to_thread(self.agent.generate_initial_plan, self.state.target_url),
                    timeout=60,
                )
            except asyncio.TimeoutError as error:
                raise BrainBoundaryError(
                    "Planning is taking longer than expected due to upstream AI load. Please retry in a moment.",
                    phase="observe",
                ) from error
        return self.initial_plan

    async def build_steps(self) -> List[dict]:
        initial_plan = await self.ensure_initial_plan()
        ai_steps = [
            {
                "type": step.label.lower(),
                "phase": step.label.lower(),
                "msg": f"{step.label}: {step.message.upper()}",
            }
            for step in initial_plan.steps
        ]

        return [
            *ai_steps,
            {
                "type": "observe",
                "phase": "observe",
                "msg": f"OBSERVE: TARGET LOCKED ON {self.hostname}. PASSIVE ROUTE AND HEADER COLLECTION NOW IN MOTION.",
            },
            {
                "type": "plan",
                "phase": "plan",
                "msg": "PLAN: HUNT MATRIX READY. OPERATOR REVIEW WINDOW OPEN.",
            },
            {
                "type": "plan",
                "phase": "plan",
                "msg": "PLAN: PRIMARY HUNT TARGETS ACCESS CONTROL, INPUT REFLECTION, AND RESILIENCE GAPS.",
            },
            {
                "type": "execute",
                "phase": "execute",
                "msg": "EXECUTE: CONTROLLED HUNT TOOLING STAGED. ACTIVE RECON WILL FOLLOW APPROVED PLAN SIGNALS.",
            },
            {
                "type": "execute",
                "phase": "execute",
                "msg": "EXECUTE: TELEMETRY STREAM ACTIVE. PORT, HEADER, AND HUNT CHECKS REMAIN CONSTRAINED AND AUDITABLE.",
            },
            {
                "type": "plan",
                "phase": "analyze",
                "msg": "PLAN: CORRELATING HUNT SIGNALS FOR ROOT-CAUSE ANALYSIS AND FALSE-POSITIVE FILTERING.",
            },
            {
                "type": "observe",
                "phase": "analyze",
                "msg": "OBSERVE: INITIAL HUNT SURFACE MAP COMPLETE. READY FOR NEXT REASONING PASS.",
            },
        ]

    def append_thought(self, phase: str, message: str, *, category: str | None = None) -> Dict[str, Any]:
        entry = {
            "phase": phase,
            "message": message,
            "category": category,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.decision_trace.append(entry)
        self.state.notes.append(message)
        return entry

    def serialize_thought_trace(self) -> List[Dict[str, Any]]:
        if self.decision_trace:
            return self.decision_trace
        if self.initial_plan is not None:
            return [
                {"phase": step.label.lower(), "message": step.message, "timestamp": datetime.now(timezone.utc).isoformat()}
                for step in self.initial_plan.steps
            ]
        return []

    def should_abort(self) -> bool:
        return self.global_abort or self.state.status == BrainStatus.TERMINATED

    def trigger_safety_gate(self, reason: str) -> None:
        self.global_abort = True
        self.global_abort_reason = reason
        self.state.status = BrainStatus.TERMINATED
        self.state.requires_operator = False
        self.state.resume_reason = None
        self.state.error_message = reason
        self.state.notes.append(reason)
        self.state.pause_event.set()

    def _evidence_snippet(self, finding: Dict[str, Any]) -> str:
        if finding.get("evidence_snippet"):
            return str(finding["evidence_snippet"])[:600]
        evidence = finding.get("evidence")
        if isinstance(evidence, dict) and evidence:
            return json.dumps(evidence, ensure_ascii=True)[:600]
        return str(finding.get("detail") or finding.get("title") or "No evidence captured.")[:600]

    def _finding_to_payload(self, category: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        severity = str(finding.get("severity", "Low")).capitalize()
        return {
            "category": category,
            "title": finding.get("title", f"{category} signal"),
            "severity": severity if severity in {"Low", "Medium", "High", "Critical"} else "Low",
            "attack_vector": finding.get("attack_vector") or finding.get("header") or f"{category} assessment signal",
            "detected_threat": finding.get("detected_threat") or finding.get("title") or finding.get("detail") or category,
            "evidence_snippet": self._evidence_snippet(finding),
            "provided_solution": finding.get("provided_solution") or OWASP_REMEDIATIONS.get(category, "Review the relevant control and apply OWASP-aligned hardening."),
            "detail": finding.get("detail") or finding.get("title") or category,
            "evidence": finding.get("evidence") or {},
        }

    def _category_signal(self, category: str) -> Dict[str, Any] | None:
        header_findings = list((self.execution_results.get("header_audit") or {}).get("findings") or [])
        audit_findings = list((self.execution_results.get("audit_engine") or {}).get("findings") or [])
        tech_stack = self.execution_results.get("tech_stack") or {}
        headers = tech_stack.get("headers") or {}

        if category == "A03:2021-Injection":
            finding = next((item for item in audit_findings if "sqli" in str(item.get("category", "")).lower()), None)
            if finding:
                finding = {**finding, "attack_vector": "Input reflection and SQL error heuristic"}
            return finding

        if category == "A05:2021-Security Misconfiguration":
            finding = next(iter(header_findings), None)
            if finding:
                return {
                    "title": finding.get("header", "Security header weakness"),
                    "detail": finding.get("detail", "Response hardening control missing or misconfigured."),
                    "severity": finding.get("severity", "Medium"),
                    "attack_vector": f"Header audit via {finding.get('header', 'response inspection')}",
                    "evidence": finding,
                }
            if headers.get("server"):
                return {
                    "title": "Verbose Server Banner",
                    "detail": "Server banner disclosed implementation details during passive reconnaissance.",
                    "severity": "Low",
                    "attack_vector": "Passive response header inspection",
                    "evidence": {"server": headers.get("server")},
                }
            return None

        if category == "A06:2021-Vulnerable and Outdated Components":
            server_banner = headers.get("server", "")
            if any(char.isdigit() for char in server_banner):
                return {
                    "title": "Versioned Component Disclosure",
                    "detail": "Observed a version-bearing server banner during tech stack fingerprinting.",
                    "severity": "Low",
                    "attack_vector": "Playwright-assisted header and DOM fingerprinting",
                    "evidence": {"server": server_banner, "frameworks": tech_stack.get("frameworks", [])},
                }
            return None

        if category == "A02:2021-Cryptographic Failures":
            finding = next((item for item in header_findings if "strict" in str(item.get("header", "")).lower() or "transport" in str(item.get("detail", "")).lower()), None)
            if finding:
                return {
                    "title": finding.get("header", "Transport protection weakness"),
                    "detail": finding.get("detail", "Transport hardening is incomplete."),
                    "severity": finding.get("severity", "Medium"),
                    "attack_vector": "TLS and browser-header review",
                    "evidence": finding,
                }
            return None

        return None

    async def _persist_trace(self, storage: Any, user_id: str, resolved_scan_id: str, resolved_session_id: str, vulnerabilities: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        return await process_agent_response(
            {
                "thought_trace": self.serialize_thought_trace(),
                "vulnerabilities": vulnerabilities or [],
            },
            user_id=user_id,
            scan_id=resolved_scan_id,
            session_id=resolved_session_id,
            storage=storage,
        )

    async def _run_owasp_assessment_loop(
        self,
        *,
        user_id: str,
        resolved_scan_id: str,
        resolved_session_id: str,
        storage: Any,
    ) -> AsyncIterator[dict]:
        for index, category in enumerate(OWASP_TOP_10_2021, start=1):
            if self.should_abort():
                self.append_thought("execute", "SCAN_TERMINATED_BY_SAFETY_GATE", category=category)
                await self._persist_trace(storage, user_id, resolved_scan_id, resolved_session_id)
                yield {
                    "type": "error",
                    "phase": "execute",
                    "msg": "SCAN_TERMINATED_BY_SAFETY_GATE",
                    "brain": self.state.snapshot(),
                }
                return

            self.state.current_step += 1
            self.append_thought("execute", f"Evaluating {category} with passive and bounded telemetry.", category=category)
            await self._persist_trace(storage, user_id, resolved_scan_id, resolved_session_id)
            yield {
                "type": "thought",
                "phase": "execute",
                "msg": f"OWASP LOOP {index}/10: {category.upper()}",
                "brain": self.state.snapshot(),
                "results": self.serialize_results(),
            }

            finding = self._category_signal(category)
            if finding:
                payload = self._finding_to_payload(category, finding)
                self.append_thought("analyze", f"Signal logged for {category}; moving to the next assessment lane.", category=category)
                await self._persist_trace(storage, user_id, resolved_scan_id, resolved_session_id, [payload])
                yield {
                    "type": "alert",
                    "phase": "analyze",
                    "msg": f"ACTIVE HIT: {payload['title'].upper()}",
                    "brain": self.state.snapshot(),
                    "attack_vector": payload["attack_vector"],
                    "severity": payload["severity"],
                    "evidence_snippet": payload["evidence_snippet"],
                    "provided_solution": payload["provided_solution"],
                    "category": payload["category"],
                }
                yield {
                    "type": "remediation",
                    "phase": "remediate",
                    "msg": f"FIX THIS: {payload['title'].upper()}",
                    "brain": self.state.snapshot(),
                    "provided_solution": payload["provided_solution"],
                    "category": payload["category"],
                }
                continue

            self.append_thought("analyze", f"No bounded signal was confirmed for {category}; marking the category evaluated.", category=category)
            await self._persist_trace(storage, user_id, resolved_scan_id, resolved_session_id)
            yield {
                "type": "thought",
                "phase": "analyze",
                "msg": f"ASSESSMENT COMPLETE: {category.upper()} EVALUATED WITH NO CONFIRMED SAFE SIGNAL.",
                "brain": self.state.snapshot(),
                "results": self.serialize_results(),
            }

    async def run_execute_phase(
        self,
        *,
        user_id: str | None = None,
        resolved_scan_id: str | None = None,
        resolved_session_id: str | None = None,
        storage: Any | None = None,
    ) -> AsyncIterator[dict]:
        self.state.phase = "execute"
        tech_stack_result = await analyze_tech_stack(self.state.target_url)
        self.execution_results["tech_stack"] = tech_stack_result
        self.append_thought("observe", "Playwright reconnaissance completed for technology fingerprinting.")
        if storage and user_id and resolved_scan_id and resolved_session_id:
            await self._persist_trace(storage, user_id, resolved_scan_id, resolved_session_id)
        yield {
            "type": "thought",
            "phase": "observe",
            "msg": (
                f"PLAYWRIGHT RECON: STACK={', '.join(tech_stack_result.get('frameworks', [])) or 'UNKNOWN'} "
                f"TITLE={tech_stack_result.get('title', 'UNAVAILABLE')}"
            ),
            "brain": self.state.snapshot(),
            "results": self.serialize_results(),
        }

        if self.should_abort():
            self.append_thought("execute", "SCAN_TERMINATED_BY_SAFETY_GATE")
            if storage and user_id and resolved_scan_id and resolved_session_id:
                await self._persist_trace(storage, user_id, resolved_scan_id, resolved_session_id)
            yield {
                "type": "error",
                "phase": "execute",
                "msg": "SCAN_TERMINATED_BY_SAFETY_GATE",
                "brain": self.state.snapshot(),
            }
            return

        try:
            port_result = await asyncio.wait_for(port_scan(self.state.target_url), timeout=12)
        except asyncio.TimeoutError as error:
            raise BrainBoundaryError(
                "Port scan timed out before AETHER could map the exposed surface.",
                phase="execute",
            ) from error
        except Exception as error:
            raise BrainBoundaryError(
                "Port scan failed before execution telemetry could complete.",
                phase="execute",
            ) from error

        if port_result.get("error"):
            raise BrainBoundaryError(str(port_result["error"]), phase="execute")
        self.execution_results["port_scan"] = port_result
        self.append_thought("execute", "Port exposure mapping completed.")
        if storage and user_id and resolved_scan_id and resolved_session_id:
            await self._persist_trace(storage, user_id, resolved_scan_id, resolved_session_id)

        for message in format_port_logs(port_result):
            yield {
                "type": "execute",
                "phase": "execute",
                "msg": message,
                "brain": self.state.snapshot(),
                "results": self.serialize_results(),
            }

        try:
            header_audit_result = await asyncio.wait_for(header_audit(self.state.target_url), timeout=12)
        except asyncio.TimeoutError as error:
            raise BrainBoundaryError(
                "Header audit timed out before response hardening could be evaluated.",
                phase="execute",
            ) from error
        except Exception as error:
            raise BrainBoundaryError(
                "Header audit failed before HTTP security posture could be evaluated.",
                phase="execute",
            ) from error

        if header_audit_result.get("error"):
            raise BrainBoundaryError(str(header_audit_result["error"]), phase="execute")
        self.execution_results["header_audit"] = header_audit_result
        self.append_thought("execute", "Header security review completed.")
        if storage and user_id and resolved_scan_id and resolved_session_id:
            await self._persist_trace(storage, user_id, resolved_scan_id, resolved_session_id)

        for message in format_header_logs(header_audit_result):
            yield {
                "type": "execute",
                "phase": "execute",
                "msg": message,
                "brain": self.state.snapshot(),
                "results": self.serialize_results(),
            }

        try:
            engine = HeuristicEngine(self.state.target_url)
            audit_result = await asyncio.wait_for(engine.run_all(), timeout=30)
        except asyncio.TimeoutError as error:
            raise BrainBoundaryError(
                "Audit engine timed out before vulnerability profiling could complete.",
                phase="execute",
            ) from error
        except Exception as error:
            raise BrainBoundaryError(
                "Audit engine failed before vulnerability profiling could complete.",
                phase="execute",
            ) from error

        if audit_result.get("error"):
            raise BrainBoundaryError(str(audit_result["error"]), phase="execute")
        profiles = audit_result.get("profiles") or []
        if not profiles:
            profiles = [
                {
                    "profile_type": "security_operator",
                    "label": "Fallback Hunt Profile",
                    "summary": "Generated in orchestrator to preserve profile telemetry continuity.",
                    "details": {"source": "brain_fallback_profile"},
                    "email": self.user_identity,
                    "user_id": self.user_identity,
                }
            ]
        else:
            for profile in profiles:
                profile.setdefault("email", self.user_identity)
                profile.setdefault("user_id", self.user_identity)
        audit_result["profiles"] = profiles
        self.execution_results["audit_engine"] = audit_result
        self.append_thought("execute", "Bounded application audit completed.")
        if storage and user_id and resolved_scan_id and resolved_session_id:
            await self._persist_trace(storage, user_id, resolved_scan_id, resolved_session_id)

        for message in format_audit_logs(audit_result):
            yield {
                "type": "execute",
                "phase": "execute",
                "msg": message,
                "brain": self.state.snapshot(),
                "results": self.serialize_results(),
            }

        if storage and user_id and resolved_scan_id and resolved_session_id:
            async for category_log in self._run_owasp_assessment_loop(
                user_id=user_id,
                resolved_scan_id=resolved_scan_id,
                resolved_session_id=resolved_session_id,
                storage=storage,
            ):
                yield category_log

        try:
            verdict = await asyncio.wait_for(
                asyncio.to_thread(
                    self.agent.generate_final_verdict,
                    self.state.target_url,
                    self.serialize_results(),
                ),
                timeout=self.agent.request_timeout_seconds,
            )
        except asyncio.TimeoutError as error:
            raise BrainBoundaryError(
                "Gemini analysis timed out while generating the final verdict.",
                phase="analyze",
            ) from error
        self.final_report = verdict.model_dump()
        self.state.phase = "analyze"
        yield {
            "type": "analyze",
            "phase": "analyze",
            "msg": f"ANALYZE: FINAL VERDICT LOCKED AT {verdict.threat_level.upper()} RISK. MISSION DEBRIEF READY.",
            "brain": self.state.snapshot(),
            "results": self.serialize_results(),
            "final_report": self.serialize_final_report(),
        }

    async def stream(
        self,
        *,
        user_id: str | None = None,
        resolved_scan_id: str | None = None,
        resolved_session_id: str | None = None,
        storage: Any | None = None,
    ) -> AsyncIterator[dict]:
        steps = await self.build_steps()

        for index, step in enumerate(steps):
            self.state.current_step = index
            self.state.phase = step["phase"]

            if self.state.status == BrainStatus.TERMINATED:
                yield {
                    "type": "error",
                    "phase": "analyze",
                    "msg": "SCAN TERMINATED BY OPERATOR.",
                    "brain": self.state.snapshot(),
                }
                return

            if step["phase"] == "plan" and not self.plan_hold_triggered:
                self.plan_hold_triggered = True
                self.pause("PLAN SIGNAL RECEIVED. AWAITING RESUME COMMAND.")
                yield {
                    **step,
                    "brain": self.state.snapshot(),
                    "control": {
                        "action": "resume",
                        "resume_token": self.state.resume_token,
                        "label": "RESUME REASONING",
                    },
                }
                await self.state.pause_event.wait()
                yield {
                    "type": "plan",
                    "phase": "plan",
                    "msg": f"PLAN: OPERATOR CLEARANCE ACCEPTED. RESUMING WITH TOKEN {self.state.resume_token}.",
                    "brain": self.state.snapshot(),
                }
                async for execute_log in self.run_execute_phase(
                    user_id=user_id,
                    resolved_scan_id=resolved_scan_id,
                    resolved_session_id=resolved_session_id,
                    storage=storage,
                ):
                    yield execute_log
                await asyncio.sleep(0.5)
                continue

            yield {**step, "brain": self.state.snapshot()}
            await asyncio.sleep(0.9)

        self.state.status = BrainStatus.COMPLETE
        self.state.requires_operator = False
        yield {
            "type": "plan",
            "phase": "analyze",
            "msg": "PLAN: HUNT LOOP COMPLETE. ENGINE READY FOR TARGETED VALIDATION.",
            "brain": self.state.snapshot(),
        }

    def serialize_initial_plan(self) -> Dict[str, List[dict]]:
        if self.initial_plan is None:
            return {"steps": []}
        return self.initial_plan.model_dump()

    def serialize_results(self) -> Dict[str, Any]:
        return {
            "tech_stack": self.execution_results.get("tech_stack"),
            "port_scan": self.execution_results.get("port_scan"),
            "header_audit": self.execution_results.get("header_audit"),
            "audit_engine": self.execution_results.get("audit_engine"),
        }

    def serialize_final_report(self) -> Dict[str, Any]:
        return self.final_report or {}

    def serialize_remediations(self) -> Dict[str, Any]:
        return self.remediations

    async def generate_fix(self, vuln_id: str) -> Dict[str, Any]:
        vulnerability = find_vulnerability(self.serialize_results(), vuln_id)
        if vulnerability is None:
            return {
                "vuln_id": vuln_id,
                "title": "Remediation Unavailable",
                "language": "text",
                "code": "No matching vulnerability was found in the persisted scan results.",
                "summary": "Re-run the scan or choose a finding from the current header audit results.",
            }

        try:
            remediation = await asyncio.wait_for(
                asyncio.to_thread(
                    generate_remediation,
                    self.state.target_url,
                    vulnerability,
                    self.serialize_results(),
                ),
                timeout=self.agent.request_timeout_seconds,
            )
        except asyncio.TimeoutError:
            remediation = {
                "vuln_id": vuln_id,
                "title": "Remediation Timeout",
                "language": "text",
                "code": "Remediation generation timed out. Retry to request a fresh patch suggestion.",
                "summary": "The AI remediation request took too long to complete, so no code sample was persisted.",
                "error": "Gemini remediation generation timed out.",
            }
        self.remediations[vuln_id] = remediation
        self.state.phase = "remediate"
        return remediation

    def pause(self, reason: str) -> None:
        self.state.status = BrainStatus.PAUSED
        self.state.requires_operator = True
        self.state.resume_reason = reason
        self.state.pause_event.clear()
        self.state.notes.append(reason)

    def resume(self, reason: str | None = None) -> None:
        self.state.status = BrainStatus.RUNNING
        self.state.requires_operator = False
        self.state.resume_reason = reason or "PLAN ACKNOWLEDGED"
        self.state.error_message = None
        self.state.notes.append(self.state.resume_reason)
        self.state.pause_event.set()

    def terminate(self) -> None:
        self.trigger_safety_gate("SCAN_TERMINATED_BY_SAFETY_GATE")

    def fail(self, reason: str, *, phase: str = "analyze") -> None:
        self.state.status = BrainStatus.FAILED
        self.state.phase = phase
        self.state.requires_operator = False
        self.state.resume_reason = None
        self.state.error_message = reason
        self.state.notes.append(reason)
        truncated_reason = reason[:417] + "..." if len(reason) > 420 else reason
        self.final_report = {
            "threat_level": "critical",
            "risk_impact": truncated_reason,
            "remediation_steps": [
                "Review the scan logs for the failing tool or upstream service.",
                "Restore connectivity or credentials, then rerun the scan.",
            ],
            "error_message": reason,
        }
        self.state.pause_event.set()

    def apply_signal(self, signal: str, reason: str | None = None) -> Dict[str, str | int | bool | None]:
        normalized_signal = signal.strip().lower()

        if normalized_signal == "pause":
            self.pause(reason or "OPERATOR REQUESTED HOLD.")
        elif normalized_signal == "resume":
            self.resume(reason)
        elif normalized_signal == "terminate":
            self.terminate()

        return self.state.snapshot()


async def process_agent_response(
    model_output: Dict[str, Any] | str,
    user_id: str,
    scan_id: str,
    session_id: str,
    storage: Any,
) -> Dict[str, Any]:
    """
    Parse a structured model payload and persist scan trace plus findings.

    This helper only handles storage mapping. It does not generate or execute
    offensive test logic itself.
    """
    payload = (
        AgentResponsePayload.model_validate_json(model_output)
        if isinstance(model_output, str)
        else AgentResponsePayload.model_validate(model_output)
    )

    normalized_user_id = uuid.UUID(str(user_id))
    normalized_scan_id = uuid.UUID(str(scan_id))
    normalized_session_id = uuid.UUID(str(session_id))

    trace_updated = await asyncio.to_thread(
        storage.update_scan_trace,
        normalized_user_id,
        normalized_scan_id,
        payload.thought_trace,
    )

    inserted_ids: List[str] = []
    for flaw in payload.vulnerabilities:
        print(f"DEBUG: [{datetime.now(timezone.utc).isoformat()}] User {normalized_user_id} found {flaw.category}")
        vulnerability_id = await asyncio.to_thread(
            storage.insert_vulnerability,
            normalized_user_id,
            normalized_scan_id,
            flaw.category,
            flaw.title,
            flaw.severity,
            flaw.detail or flaw.detected_threat,
            normalized_session_id,
            flaw.attack_vector,
            flaw.detected_threat,
            flaw.evidence_snippet,
            flaw.provided_solution or flaw.remediation_code or "",
            flaw.evidence,
            None,
        )
        inserted_ids.append(str(vulnerability_id))

    return {
        "trace_updated": trace_updated,
        "vulnerability_ids": inserted_ids,
        "vulnerability_count": len(inserted_ids),
    }
