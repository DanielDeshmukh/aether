import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.engine.validation_lanes import SAFE_XSS_MARKER_PREFIX, ValidationLaneManager  # noqa: E402


class FakeInput:
    def __init__(self, page):
        self.page = page
        self.last_payload = ""

    async def fill(self, payload: str) -> None:
        self.last_payload = payload
        self.page.last_payload = payload

    async def press(self, key: str) -> None:
        self.page.submitted = True


class FakeLocator:
    def __init__(self, page):
        self.page = page

    async def all(self):
        return [FakeInput(self.page)]


class FakePage:
    def __init__(self):
        self.url = "http://localhost:3000"
        self.last_payload = ""
        self.submitted = False

    async def goto(self, url: str, **kwargs):
        self.url = url
        return None

    def locator(self, selector: str):
        return FakeLocator(self)

    async def wait_for_timeout(self, timeout_ms: int) -> None:
        return None

    async def content(self) -> str:
        return f"<html><body>{self.last_payload}</body></html>"

    async def screenshot(self, **kwargs):
        return b"fake-image"

    async def title(self) -> str:
        return "Mock Title"

    def on(self, event_name: str, callback):
        return None

    async def close(self) -> None:
        return None


class FakeContext:
    async def new_page(self):
        return FakePage()


class AllowedVerificationService:
    async def verify_target(self, target_url: str, user_id: str | None = None):
        class Result:
            allowed = True
        return Result()


class TestValidationLanes(unittest.IsolatedAsyncioTestCase):
    async def test_xss_lane_returns_confirmed_finding_with_screenshot_artifact(self) -> None:
        trace_messages = []

        async def write_trace(phase: str, message: str) -> None:
            trace_messages.append((phase, message))

        manager = ValidationLaneManager(
            verification_service=AllowedVerificationService(),
            user_id="test-user",
            trace_writer=write_trace,
            abort_check=lambda: None,
        )

        findings = await manager.run_xss_lane(FakeContext(), "http://localhost:3000")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["confirmation_status"], "confirmed")
        self.assertIn("screenshot_base64", findings[0].evidence["artifact"])
        self.assertIn(SAFE_XSS_MARKER_PREFIX, findings[0].evidence_snippet)
        self.assertTrue(any(phase == "execute" for phase, _ in trace_messages))


if __name__ == "__main__":
    unittest.main()
