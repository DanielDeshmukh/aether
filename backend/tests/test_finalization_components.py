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
    router = IntentRouter(allowed_hosts={"Lab.Local", " 127.0.0.1 "})
    assert "lab.local" in router.allowed_hosts
    assert "127.0.0.1" in router.allowed_hosts

    # Heuristic intent
    intent = ScanIntent(target_url="https://example.com", mode="heuristic")
    verdict = router.route(intent)
    assert verdict.orchestrator == "brain"

    # Active validation on non-allowlisted host
    intent = ScanIntent(target_url="https://example.com", mode="active_validation")
    verdict = router.route(intent)
    assert verdict.orchestrator == "brain"  # Degraded
    assert "NOT in allowlist" in verdict.reason

    # Active validation on allowlisted host
    intent = ScanIntent(target_url="https://lab.local", mode="active_validation")
    verdict = router.route(intent)
    assert verdict.orchestrator == "attack_orchestrator"
    assert "in allowlist" in verdict.reason

@pytest.mark.asyncio
async def test_heuristic_engine_structure():
    # We won't run full network tests here, but check it initializes
    engine = HeuristicEngine("https://example.com")
    assert engine.target_url == "https://example.com"
    assert engine.findings == []
    # Verify it is an async function
    assert inspect.iscoroutinefunction(engine.run_all)
