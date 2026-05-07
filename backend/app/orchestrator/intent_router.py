import logging
from typing import Literal, Dict, Any
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
    """
    def __init__(self, allowed_hosts: set[str] | None = None):
        self.allowed_hosts = allowed_hosts or {"localhost", "127.0.0.1"}

    def route(self, intent: ScanIntent) -> IntentRoutingVerdict:
        from urllib.parse import urlparse
        parsed = urlparse(intent.target_url if "://" in intent.target_url else f"http://{intent.target_url}")
        host = (parsed.hostname or "").lower()

        # Rule 1: Active validation is ONLY for allowed/verified hosts
        if intent.mode == "active_validation" or (intent.mode == "auto" and intent.depth == "deep"):
            if host in self.allowed_hosts:
                return IntentRoutingVerdict(
                    orchestrator="attack_orchestrator",
                    reason="Target is in allowlist and deep validation requested.",
                    config={"mode": "full_active"}
                )
            else:
                logger.warning(f"Restricting deep intent for non-allowlisted host: {host}")
                return IntentRoutingVerdict(
                    orchestrator="brain",
                    reason="Target NOT in allowlist. Degrading to passive heuristic mode.",
                    config={"mode": "heuristic_only"}
                )

        # Default to standard brain orchestrator
        return IntentRoutingVerdict(
            orchestrator="brain",
            reason="Standard heuristic intent routed to BrainOrchestrator.",
            config={"mode": "default"}
        )
