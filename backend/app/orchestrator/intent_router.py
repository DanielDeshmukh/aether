import logging
from typing import Literal, Dict, Any, Iterable, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("aether.intent_router")

class ScanIntent(BaseModel):
    target_url: str
    mode: Literal["heuristic", "active_validation", "auto"] = "auto"
    depth: Literal["passive", "deep"] = "passive"

class IntentRoutingVerdict(BaseModel):
    orchestrator: Literal["brain", "attack_orchestrator"]
    reason: str
    config: Dict[str, Any] = Field(default_factory=dict)

class IntentRouter:
    """
    Deterministic schema-based routing of scan intents.
    Determines the best orchestrator and configuration for a given scan intent.
    Actual consent/verification is handled by enforce_target_verification in main.py.
    """
    def __init__(self, allowed_hosts: Optional[Iterable[str]] = None):
        # Keep for backward compatibility but don't enforce restrictions
        if allowed_hosts is None:
            self.allowed_hosts = set()
        else:
            self.allowed_hosts = {host.strip().lower() for host in allowed_hosts if host and host.strip()}

    def route(self, intent: ScanIntent) -> IntentRoutingVerdict:
        # Rule: Active/deep validation → attack_orchestrator (consent verified separately)
        if intent.mode == "active_validation" or (intent.mode == "auto" and intent.depth == "deep"):
            return IntentRoutingVerdict(
                orchestrator="attack_orchestrator",
                reason="Active validation requested - consent verified by domain verification.",
                config={"mode": "full_active"}
            )

        # Default to standard brain orchestrator
        return IntentRoutingVerdict(
            orchestrator="brain",
            reason="Standard heuristic intent routed to BrainOrchestrator.",
            config={"mode": "default"}
        )
