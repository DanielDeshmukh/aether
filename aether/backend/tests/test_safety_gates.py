import asyncio
import socket
import sys
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import httpx
import uvicorn
from fastapi import FastAPI


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.engine.playwright_driver import build_aether_safety_token, create_hardened_browser_context  # noqa: E402
from app.orchestrator.attack_orchestrator import AttackOrchestrator, RateLimiter  # noqa: E402


class AllowedVerificationService:
    async def verify_target(self, target_url: str, user_id: str | None = None):
        class Result:
            allowed = True
        return Result()


class FakeResponse:
    def __init__(self, delay_seconds: float = 0.0) -> None:
        self.delay_seconds = delay_seconds


class SlowAsyncClient:
    def __init__(self, *args, **kwargs) -> None:
        self.delay_seconds = 2.05

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url: str):
        await asyncio.sleep(self.delay_seconds)
        return FakeResponse(self.delay_seconds)


class FakeBrowser:
    def __init__(self) -> None:
        self.kwargs = None

    async def new_context(self, **kwargs):
        self.kwargs = kwargs
        return kwargs


class LocalFastAPIServer:
    def __init__(self) -> None:
        self.host = "127.0.0.1"
        self.port = self._get_free_port()
        self.app = FastAPI()

        @self.app.get("/")
        async def root():
            return {"ok": True}

        self.config = uvicorn.Config(self.app, host=self.host, port=self.port, log_level="error")
        self.server = uvicorn.Server(config=self.config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @staticmethod
    def _get_free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def start(self) -> None:
        self.thread.start()
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                with socket.create_connection((self.host, self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Local FastAPI test server failed to start.")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


class TestSafetyGates(unittest.IsolatedAsyncioTestCase):
    async def test_preflight_latency_check_slows_scan_and_emits_warning(self) -> None:
        updates = []

        async def on_stage_update(payload):
            updates.append(payload)

        orchestrator = AttackOrchestrator(
            user_id=str(uuid.uuid4()),
            scan_id=str(uuid.uuid4()),
            session_id=str(uuid.uuid4()),
            storage_engine=None,
            verification_service=AllowedVerificationService(),
            on_stage_update=on_stage_update,
            max_requests_per_second=2,
            latency_warning_threshold_ms=2000,
        )
        trace = []

        with patch("app.orchestrator.attack_orchestrator.httpx.AsyncClient", SlowAsyncClient):
            await orchestrator._preflight_latency_check("http://localhost:3000", trace)

        self.assertEqual(orchestrator.request_delay_multiplier, 2)
        warning_updates = [payload for payload in updates if payload.get("type") == "warning"]
        self.assertTrue(warning_updates)
        self.assertEqual(
            "TARGET INSTABILITY DETECTED. SLOWING DOWN SCAN.",
            warning_updates[-1].get("msg"),
        )

    async def test_create_hardened_browser_context_includes_safety_token_header(self) -> None:
        browser = FakeBrowser()
        scan_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())

        await create_hardened_browser_context(browser, scan_id=scan_id, user_id=user_id)

        self.assertIsNotNone(browser.kwargs)
        headers = browser.kwargs.get("extra_http_headers", {})
        self.assertEqual(build_aether_safety_token(scan_id, user_id), headers.get("X-Aether-Safety-Token"))

    async def test_rate_limiter_smoke_test_keeps_requests_within_rps_budget(self) -> None:
        server = LocalFastAPIServer()
        server.start()
        limiter = RateLimiter(max_requests_per_second=2)
        timestamps = []

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                for _ in range(5):
                    await limiter.acquire()
                    timestamps.append(time.monotonic())
                    response = await client.get(f"http://{server.host}:{server.port}/")
                    self.assertEqual(response.status_code, 200)
        finally:
            server.stop()

        elapsed = timestamps[-1] - timestamps[0]
        self.assertGreaterEqual(elapsed, 1.8)


if __name__ == "__main__":
    unittest.main()
