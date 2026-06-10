import unittest
from app.orchestrator.intent_router import IntentRouter


class TestIntentRouter(unittest.TestCase):
    def setUp(self):
        self.router = IntentRouter()

    def test_initialization(self):
        assert self.router is not None

    def test_route_scan_command(self):
        result = self.router.route("scan example.com")
        assert result is not None

    def test_route_remediation_command(self):
        result = self.router.route("fix vulnerability")
        assert result is not None

    def test_route_unknown_command(self):
        result = self.router.route("unknown command")
        assert result is not None


if __name__ == "__main__":
    unittest.main()