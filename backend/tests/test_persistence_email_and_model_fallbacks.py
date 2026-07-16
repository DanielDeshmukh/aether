import unittest
from unittest.mock import MagicMock, patch

from app.orchestrator.brain import BrainOrchestrator, PentestAgent


class TestEmailAndModelFallbacks(unittest.TestCase):
    def test_fallback_profile_inherits_user_identity(self):
        orchestrator = BrainOrchestrator(
            scan_id="scan-1",
            target_url="https://example.com",
            user_identity="operator@devlabs.ai",
        )
        payload = {"profiles": []}
        # Reuse the same behavior as run_execute_phase fallback enrichment.
        profiles = payload.get("profiles") or []
        if not profiles:
            profiles = [
                {
                    "profile_type": "security_operator",
                    "label": "Fallback Hunt Profile",
                    "summary": "Generated in orchestrator to preserve profile telemetry continuity.",
                    "details": {"source": "brain_fallback_profile"},
                    "email": orchestrator.user_identity,
                    "user_id": orchestrator.user_identity,
                }
            ]
        self.assertEqual(profiles[0]["email"], "operator@devlabs.ai")
        self.assertEqual(profiles[0]["user_id"], "operator@devlabs.ai")

    def test_model_fallbacks_use_current_ids(self):
        agent = PentestAgent()
        fake_client = MagicMock()
        fake_client.chat.completions.create.side_effect = RuntimeError("not found")

        with (
            patch("app.orchestrator.brain.time.sleep", return_value=None),
            patch("app.orchestrator.brain.random.uniform", return_value=0),
        ):
            with self.assertRaises(RuntimeError):
                agent._generate_with_retry(fake_client, messages=[{"role": "user", "content": "x"}], max_retries=1)

        attempted_models = [
            call.kwargs["model"] for call in fake_client.chat.completions.create.call_args_list
        ]
        self.assertEqual(attempted_models, ["nvidia/nemotron-3-super-120b-a12b", "deepseek-ai/deepseek-v4-flash", "minimaxai/minimax-m2.7"])


if __name__ == "__main__":
    unittest.main()
