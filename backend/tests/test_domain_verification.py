import asyncio
import sys
import uuid
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.api import main as api_main  # noqa: E402
from app.orchestrator.brain import BrainOrchestrator  # noqa: E402
from app.services.domain_verification import (  # noqa: E402
    DomainVerificationManager,
    DomainVerificationResult,
    VerificationMethodResult,
)


class StubStorage:
    def __init__(self, record):
        self.record = record

    def fetch_target_verification_record(self, domain: str, user_id: str | None = None):
        return self.record


class TestDomainVerification(unittest.TestCase):
    def setUp(self) -> None:
        api_main.active_scans.clear()
        api_main.brain_sessions.clear()
        self.client = TestClient(api_main.app)

    def tearDown(self) -> None:
        api_main.active_scans.clear()
        api_main.brain_sessions.clear()

    def test_verify_target_reports_missing_txt_and_http_token(self) -> None:
        manager = DomainVerificationManager(
            StubStorage(
                {
                    "domain": "example.com",
                    "is_verified": False,
                    "verification_token": "abc123",
                    "dns_record": "_aether-verification.example.com",
                    "http_path": "/.well-known/aether-verification.json",
                }
            )
        )

        async def run_check() -> DomainVerificationResult:
            with patch.object(
                manager,
                "verify_via_dns",
                new=AsyncMock(
                    return_value=VerificationMethodResult(
                        method="dns",
                        success=False,
                        expected_location="_aether-verification.example.com",
                        expected_value="abc123",
                        detail="TXT token missing.",
                    )
                ),
            ), patch.object(
                manager,
                "verify_via_http",
                new=AsyncMock(
                    return_value=VerificationMethodResult(
                        method="http",
                        success=False,
                        expected_location="https://example.com/.well-known/aether-verification.json",
                        expected_value="abc123",
                        detail="HTTP token missing.",
                    )
                ),
            ):
                return await manager.verify_target("https://example.com")

        result = asyncio.run(run_check())
        self.assertFalse(result.allowed)
        self.assertIn("_aether-verification.example.com", result.failure_message or "")
        self.assertIn(".well-known/aether-verification.json", result.failure_message or "")
        self.assertIn("abc123", result.failure_message or "")

    def test_websocket_scan_refuses_unverified_domain_in_observe_phase(self) -> None:
        scan_id = "scan-unverified"
        target_url = "https://example.com"
        user_id = str(uuid.uuid4())
        api_main.active_scans[scan_id] = {
            "active": True,
            "target_url": target_url,
            "user_id": user_id,
        }
        api_main.brain_sessions[scan_id] = BrainOrchestrator(scan_id=scan_id, target_url=target_url)

        verification_result = DomainVerificationResult(
            domain="example.com",
            allowed=False,
            is_verified=False,
            record_found=True,
            failure_message=(
                "DOMAIN VERIFICATION FAILED: missing TXT record `_aether-verification.example.com` "
                "with token `abc123` and missing verification file "
                "`https://example.com/.well-known/aether-verification.json` with JSON token `abc123`."
            ),
        )

        with patch.object(api_main.domain_verification_manager, "verify_target", new=AsyncMock(return_value=verification_result)), \
             patch.object(api_main, "persist_scan_state", return_value=True):
            with self.client.websocket_connect(f"/ws/scan/{scan_id}") as websocket:
                first_message = websocket.receive_json()
                second_message = websocket.receive_json()

        self.assertEqual(first_message["phase"], "observe")
        self.assertEqual(second_message["type"], "error")
        self.assertEqual(second_message["phase"], "observe")
        self.assertIn(".well-known/aether-verification.json", second_message["msg"])


    def test_caching_works(self) -> None:
        manager = DomainVerificationManager(
            StubStorage(
                {
                    "domain": "cached.com",
                    "is_verified": True,
                    "verification_token": "token123",
                }
            )
        )

        async def run_check() -> DomainVerificationResult:
            return await manager.verify_target("https://cached.com")

        result1 = asyncio.run(run_check())
        result2 = asyncio.run(run_check())

        # Second call should use cache
        self.assertTrue(result1.allowed)
        self.assertTrue(result2.allowed)

    def test_rate_limiter_works(self) -> None:
        manager = DomainVerificationManager(
            StubStorage(
                {
                    "domain": "ratelimit.com",
                    "is_verified": False,
                    "verification_token": "token123",
                }
            )
        )

        # Test rate limiter
        status = manager.get_rate_limit_status("ratelimit.com")
        self.assertIn("remaining_attempts", status)
        self.assertIn("max_attempts", status)


if __name__ == "__main__":
    unittest.main()
