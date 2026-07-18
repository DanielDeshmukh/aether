import asyncio
import unittest
from unittest.mock import MagicMock, patch

from app.orchestrator.brain import BrainBoundaryError, BrainOrchestrator
from main import persist_scan_state, scan_storage


class TestTimeoutAndPersistenceRefactor(unittest.TestCase):
    def test_persist_scan_state_uses_persist_full_pipeline(self):
        brain = MagicMock()
        brain.serialize_initial_plan.return_value = {"steps": []}
        brain.state = MagicMock()
        brain.state.status = MagicMock(value="failed")
        brain.serialize_results.return_value = {}
        brain.serialize_final_report.return_value = {"error_message": "boom"}
        brain.serialize_remediations.return_value = {}

        with patch.object(scan_storage, "persist_full_pipeline", return_value=True) as persist_mock:
            persisted = persist_scan_state("abc12345", brain, "https://example.com", "a7988ba7-c5f5-4ad1-a35d-6814f75c6bf4")

        self.assertTrue(persisted)
        persist_mock.assert_called_once()
        call_kwargs = persist_mock.call_args.kwargs
        self.assertEqual(call_kwargs["brain_status"], "failed")
        self.assertEqual(call_kwargs["scan_id"], "abc12345")

    def test_initial_plan_timeout_raises_user_friendly_boundary_error(self):
        orchestrator = BrainOrchestrator(scan_id="scan1", target_url="https://example.com")

        with (
            patch("app.orchestrator.brain.asyncio.to_thread", new=MagicMock(return_value=object())),
            patch("app.orchestrator.brain.asyncio.wait_for", side_effect=asyncio.TimeoutError),
        ):
            with self.assertRaises(BrainBoundaryError) as context:
                asyncio.run(orchestrator.ensure_initial_plan())

        self.assertEqual(context.exception.phase, "observe")
        self.assertIn("upstream AI load", context.exception.message)


if __name__ == "__main__":
    unittest.main()
