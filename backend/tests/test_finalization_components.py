import pytest
from app.api.shield import AetherShield
from app.orchestrator.intent_router import IntentRouter, ScanIntent
from app.engine.heuristic_engine import HeuristicEngine
import asyncio
import inspect

def test_aether_shield_token_generation_and_verification():
    scan_id = "test-scan"
    user_id = "test-user"
    token = AetherShield.generate_token(scan_id, user_id)
    assert token is not None
    assert len(token) == 64  # SHA256 hex
    assert AetherShield.verify_token(token, scan_id, user_id) is True
    assert AetherShield.verify_token("wrong-token", scan_id, user_id) is False

def test_intent_router_logic():
    # Allowed hosts kept for backward compat but not enforced
    router = IntentRouter(allowed_hosts={"lab.local", "127.0.0.1"})
    assert "lab.local" in router.allowed_hosts

    # Heuristic intent → brain
    intent = ScanIntent(target_url="https://example.com", mode="heuristic")
    verdict = router.route(intent)
    assert verdict.orchestrator == "brain"

    # Active validation on any domain → attack_orchestrator
    # (consent verified by domain verification, not allowlist)
    intent = ScanIntent(target_url="https://example.com", mode="active_validation")
    verdict = router.route(intent)
    assert verdict.orchestrator == "attack_orchestrator"
    assert "consent verified" in verdict.reason.lower()

    # Deep auto intent → attack_orchestrator
    intent = ScanIntent(target_url="https://any-domain.com", mode="auto", depth="deep")
    verdict = router.route(intent)
    assert verdict.orchestrator == "attack_orchestrator"

@pytest.mark.asyncio
async def test_heuristic_engine_structure():
    # We won't run full network tests here, but check it initializes
    engine = HeuristicEngine("https://example.com")
    assert engine.target_url == "https://example.com"
    assert engine.findings == []
    # Verify it is an async function
    assert inspect.iscoroutinefunction(engine.run_all)
