import unittest
from app.orchestrator.intent_router import IntentRouter, ScanIntent


class TestIntentRouter(unittest.TestCase):
    def setUp(self):
        self.router = IntentRouter()

    def test_initialization(self):
        assert self.router is not None

    def test_route_scan_command(self):
        intent = ScanIntent(target_url="https://example.com", mode="heuristic")
        result = self.router.route(intent)
        assert result is not None
        assert result.orchestrator == "brain"

    def test_route_remediation_command(self):
        intent = ScanIntent(target_url="https://example.com", mode="active_validation")
        result = self.router.route(intent)
        assert result is not None
        assert result.orchestrator == "attack_orchestrator"

    def test_route_unknown_command(self):
        intent = ScanIntent(target_url="https://example.com", mode="auto")
        result = self.router.route(intent)
        assert result is not None


if __name__ == "__main__":
    unittest.main()