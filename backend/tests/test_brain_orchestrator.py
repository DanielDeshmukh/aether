import unittest
from app.orchestrator.brain import BrainOrchestrator


class TestBrainOrchestrator(unittest.TestCase):
    def setUp(self):
        self.scan_id = "test-scan-123"
        self.target_url = "https://example.com"
        self.brain = BrainOrchestrator(scan_id=self.scan_id, target_url=self.target_url)

    def test_initial_state(self):
        assert self.brain.state.scan_id == self.scan_id
        assert self.brain.state.target_url == self.target_url
        assert self.brain.state is not None
        assert self.brain.execution_results == {"tech_stack": None, "port_scan": None, "header_audit": None, "audit_engine": None}

    def test_append_thought(self):
        self.brain.append_thought("plan", "Test thought")
        assert len(self.brain.state.notes) > 0

    def test_serialize_results(self):
        results = self.brain.serialize_results()
        assert isinstance(results, dict)

    def test_serialize_final_report(self):
        report = self.brain.serialize_final_report()
        assert isinstance(report, dict)

    def test_serialize_remediations(self):
        remediations = self.brain.serialize_remediations()
        assert isinstance(remediations, dict)

    def test_fail(self):
        self.brain.fail("Test error", phase="observe")
        assert self.brain.state.status == "failed"

    def test_terminate(self):
        self.brain.terminate()
        assert self.brain.state.status == "terminated"


if __name__ == "__main__":
    unittest.main()