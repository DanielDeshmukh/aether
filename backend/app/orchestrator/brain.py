import asyncio
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator, Dict, List, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, ValidationError

try:
    from google import genai
except ImportError:  # pragma: no cover - resolved when requirements are installed
    genai = None


class PlanStep(BaseModel):
    label: Literal["THOUGHT", "OBSERVE", "PLAN"]
    message: str = Field(min_length=12, max_length=220)


class InitialPlan(BaseModel):
    steps: List[PlanStep] = Field(min_length=3, max_length=3)


class BrainStatus(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    TERMINATED = "terminated"
    COMPLETE = "complete"


@dataclass
class BrainState:
    scan_id: str
    target_url: str
    phase: str = "observe"
    status: BrainStatus = BrainStatus.RUNNING
    current_step: int = 0
    requires_operator: bool = False
    resume_token: str = "PLAN_ACK"
    resume_reason: str | None = None
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
        }


class PentestAgent:
    def __init__(self) -> None:
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.model_name = "gemini-2.5-flash"

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
                    message="Stage three minimal checks around access control, session handling, and hostile input validation before active execution.",
                ),
            ]
        )

    def _build_prompt(self, target_url: str, hostname: str) -> str:
        return f"""
You are AETHER, a senior penetration testing strategist for an agentic SaaS security platform.
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
- Treat the target as a real web asset and reason about passive HTTP and application-layer reconnaissance.
- Output raw JSON only.
""".strip()

    def generate_initial_plan(self, target_url: str) -> InitialPlan:
        hostname = urlparse(target_url).netloc.upper()

        if genai is None or not self._has_usable_api_key():
            return self._fallback_plan(hostname, target_url)

        try:
            client = genai.Client(api_key=self.api_key)
            response = client.models.generate_content(
                model=self.model_name,
                contents=self._build_prompt(target_url, hostname),
                config={
                    "response_mime_type": "application/json",
                    "response_json_schema": InitialPlan.model_json_schema(),
                },
            )
            return self._validate_response(response.text, hostname, target_url)
        except Exception:
            return self._fallback_plan(hostname, target_url)

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


class BrainOrchestrator:
    def __init__(self, scan_id: str, target_url: str):
        self.state = BrainState(scan_id=scan_id, target_url=target_url)
        self.hostname = urlparse(target_url).netloc.upper()
        self.plan_hold_triggered = False
        self.agent = PentestAgent()
        self.initial_plan: InitialPlan | None = None

    async def ensure_initial_plan(self) -> InitialPlan:
        if self.initial_plan is None:
            self.initial_plan = await asyncio.to_thread(self.agent.generate_initial_plan, self.state.target_url)
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
                "msg": "PLAN: HYPOTHESIS MATRIX READY. OPERATOR REVIEW WINDOW OPEN.",
            },
            {
                "type": "plan",
                "phase": "plan",
                "msg": "PLAN: PRIMARY CHECKS TARGET ACCESS CONTROL, SESSION FLOW, AND INPUT SURFACES.",
            },
            {
                "type": "observe",
                "phase": "execute",
                "msg": "OBSERVE: CONTROLLED BROWSER STAGED. FIRST ACTIVE REQUEST WILL FOLLOW APPROVED PLAN SIGNALS.",
            },
            {
                "type": "observe",
                "phase": "execute",
                "msg": "OBSERVE: TELEMETRY STREAM ACTIVE. PAYLOAD WINDOW REMAINS CONSTRAINED AND AUDITABLE.",
            },
            {
                "type": "plan",
                "phase": "analyze",
                "msg": "PLAN: CORRELATING RESPONSES FOR ROOT-CAUSE SIGNALS AND FALSE-POSITIVE FILTERING.",
            },
            {
                "type": "observe",
                "phase": "analyze",
                "msg": "OBSERVE: INITIAL SURFACE MAP COMPLETE. READY FOR NEXT REASONING PASS.",
            },
        ]

    async def stream(self) -> AsyncIterator[dict]:
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
                await asyncio.sleep(0.5)
                continue

            yield {**step, "brain": self.state.snapshot()}
            await asyncio.sleep(0.9)

        self.state.status = BrainStatus.COMPLETE
        self.state.requires_operator = False
        yield {
            "type": "plan",
            "phase": "analyze",
            "msg": "PLAN: REASONING LOOP COMPLETE. ENGINE READY FOR TARGETED VALIDATION.",
            "brain": self.state.snapshot(),
        }

    def serialize_initial_plan(self) -> List[dict]:
        if self.initial_plan is None:
            return []
        return [step.model_dump() for step in self.initial_plan.steps]

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
        self.state.notes.append(self.state.resume_reason)
        self.state.pause_event.set()

    def terminate(self) -> None:
        self.state.status = BrainStatus.TERMINATED
        self.state.requires_operator = False
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
