import base64
import os
import sys
import uuid
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.api import main as api_main  # noqa: E402
from app.orchestrator.brain import BrainOrchestrator  # noqa: E402
from app.orchestrator.remediation_agent import RemediationAgent  # noqa: E402
from app.services.domain_verification import DomainVerificationResult  # noqa: E402


class TestRemediationFlow(unittest.TestCase):
    def setUp(self) -> None:
        self.original_flag = os.environ.get("AETHER_USE_NVIDIA_ORCHESTRATOR")
        os.environ["AETHER_USE_NVIDIA_ORCHESTRATOR"] = "true"
        api_main.active_scans.clear()
        api_main.brain_sessions.clear()
        self.client = TestClient(api_main.app)

    def tearDown(self) -> None:
        api_main.active_scans.clear()
        api_main.brain_sessions.clear()
        if self.original_flag is None:
            os.environ.pop("AETHER_USE_NVIDIA_ORCHESTRATOR", None)
        else:
            os.environ["AETHER_USE_NVIDIA_ORCHESTRATOR"] = self.original_flag

    def test_remediation_agent_returns_parameterized_query_for_sqli(self) -> None:
        agent = RemediationAgent()
        agent.client = None
        finding = {
            "id": "finding-sqli",
            "category": "A03:2021-Injection",
            "title": "SQL Injection via email parameter",
            "severity": "High",
            "detail": "The login handler appears to build a query from the email parameter.",
            "attack_vector": "Reflected SQL probe",
        }

        remediation = agent.generate(finding, "SQL syntax error triggered when the email probe included a quote.")

        self.assertEqual(remediation.language, "python")
        self.assertIn("%s", remediation.secure_refactor)
        self.assertIn("parameterized query", remediation.summary.lower())

    def test_websocket_emits_remediation_message_and_actionable_final_report(self) -> None:
        scan_id = "scan-remediate"
        target_url = "http://localhost:3000"
        user_id = str(uuid.uuid4())
        api_main.active_scans[scan_id] = {
            "active": True,
            "target_url": target_url,
            "user_id": user_id,
        }
        api_main.brain_sessions[scan_id] = BrainOrchestrator(scan_id=scan_id, target_url=target_url)

        remediation_payload = {
            "vuln_id": "finding-sqli",
            "title": "SQL Injection via email parameter",
            "vulnerable_code_analysis": "The handler concatenates user-controlled input into a SQL query.",
            "secure_refactor": 'cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))',
            "language": "python",
            "summary": "Replace the string-built SQL with a parameterized query and validate the email before execution.",
        }
        finding_payload = {
            "id": "finding-sqli",
            "category": "A03:2021-Injection",
            "title": "SQL Injection via email parameter",
            "severity": "High",
            "detail": "User-controlled input can alter the query structure.",
            "attack_vector": "SQLi probe",
            "detected_threat": "SQL Injection via email parameter",
            "evidence_snippet": "A quote in the email probe triggered a database-flavored error.",
            "provided_solution": (
                "Vulnerable Code Analysis:\n"
                "The handler concatenates user-controlled input into a SQL query.\n\n"
                "Secure Refactor:\n"
                'cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))'
            ),
            "remediation": remediation_payload,
        }

        async def fake_run_validation_loop(self, target_url: str) -> dict:
            if self.on_stage_update is not None:
                await self.on_stage_update(
                    {
                        "type": "thought",
                        "phase": "execute",
                        "msg": "EXECUTE: LAMBO-DARK VALIDATION LANE ACTIVE.",
                    }
                )
                await self.on_stage_update(
                    {
                        "type": "thought",
                        "phase": "remediate",
                        "msg": "REMEDIATE: PATCH SYNTHESIS UNDERWAY.",
                    }
                )
            if self.on_finding_discovered is not None:
                await self.on_finding_discovered(dict(finding_payload))
            return {
                "status": "completed",
                "tech_stack": {"title": "Mock App", "url": target_url, "scripts": []},
                "findings": [dict(finding_payload)],
                "remediations": {"finding-sqli": dict(remediation_payload)},
                "profiles": [
                    {
                        "user_id": str(self.user_id),
                        "email": None,
                        "profile_type": "vulnerability_profiler",
                        "label": "NVIDIA Validation Loop",
                        "summary": "Mock profile for remediation integration test.",
                        "details": {"source": "test"},
                    }
                ],
                "trace": [{"phase": "remediate", "message": "REMEDIATE: PATCH SYNTHESIS UNDERWAY."}],
            }

        with patch.object(api_main.scan_storage, "ensure_schema", return_value=None), \
             patch.object(api_main, "persist_scan_state", return_value=True), \
             patch.object(
                 api_main.domain_verification_manager,
                 "verify_target",
                 new=AsyncMock(
                     return_value=DomainVerificationResult(
                         domain="localhost",
                         allowed=True,
                         is_verified=True,
                         record_found=True,
                     )
                ),
             ), \
             patch.object(
                 api_main.scan_storage,
                 "resolve_git_target_for_url",
                 return_value={
                     "id": "target-github",
                     "provider": "github",
                     "repository": "acme/aether-demo",
                     "access_token": "token",
                 },
             ), \
             patch("app.api.main.AttackOrchestrator.run_validation_loop", new=fake_run_validation_loop):
            with self.client.websocket_connect(f"/ws/scan/{scan_id}") as websocket:
                messages = []
                while True:
                    try:
                        payload = websocket.receive_json()
                        messages.append(payload)
                        if payload.get("type") == "analyze" and payload.get("final_report"):
                            break
                    except Exception:
                        break

        remediation_messages = [message for message in messages if message.get("type") == "remediation"]
        self.assertTrue(remediation_messages, "Expected at least one remediation WebSocket message.")
        self.assertIn("%s", remediation_messages[0].get("provided_solution", ""))
        final_messages = [message for message in messages if message.get("type") == "analyze" and message.get("final_report")]
        self.assertTrue(final_messages, "Expected a final analyze message with final_report.")
        self.assertTrue(final_messages[-1]["final_report"].get("remediation_steps"))
        self.assertTrue(final_messages[-1]["final_report"].get("auto_remediation", {}).get("pr_ready"))

    def test_persist_scan_state_includes_generated_remediation_data(self) -> None:
        brain = BrainOrchestrator(scan_id="scan-persist", target_url="http://localhost:3000")
        brain.initial_plan = MagicMock(model_dump=lambda: {"steps": []})
        brain.execution_results["audit_engine"] = {
            "target_url": "http://localhost:3000",
            "findings": [
                {
                    "id": "finding-sqli",
                    "category": "A03:2021-Injection",
                    "title": "SQL Injection via email parameter",
                    "severity": "High",
                    "detail": "User-controlled input can alter SQL structure.",
                    "provided_solution": (
                        "Vulnerable Code Analysis:\n"
                        "The handler concatenates user-controlled input into a SQL query.\n\n"
                        "Secure Refactor:\n"
                        'cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))'
                    ),
                }
            ],
            "profiles": [],
        }
        brain.remediations = {
            "finding-sqli": {
                "summary": "Replace the string-built SQL with a parameterized query.",
                "secure_refactor": 'cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))',
            }
        }
        brain.final_report = {
            "threat_level": "high",
            "risk_impact": "Validated SQL injection risk.",
            "remediation_steps": ["Replace the string-built SQL with a parameterized query."],
        }

        with patch.object(api_main.scan_storage, "persist_full_pipeline", return_value=True) as persist_mock:
            result = api_main.persist_scan_state(
                scan_id="scan-persist",
                brain=brain,
                target_url="http://localhost:3000",
                user_id=str(uuid.uuid4()),
            )

        self.assertTrue(result)
        persist_kwargs = persist_mock.call_args.kwargs
        self.assertIn("finding-sqli", persist_kwargs["remediations"])
        self.assertIn("%s", persist_kwargs["results"]["audit_engine"]["findings"][0]["provided_solution"])

    def test_remediation_websocket_emits_git_push_status_for_pull_request_creation(self) -> None:
        scan_id = "scan-pr"
        user_id = str(uuid.uuid4())
        screenshot_base64 = base64.b64encode(b"fake-png-bytes").decode("ascii")
        remediation_payload = {
            "vuln_id": "finding-sqli",
            "title": "SQL Injection via email parameter",
            "vulnerable_code_analysis": "The handler concatenates user-controlled input into a SQL query.",
            "secure_refactor": 'cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))',
            "language": "python",
            "summary": "Replace the string-built SQL with a parameterized query and validate the email before execution.",
        }
        record = {
            "target_url": "http://localhost:3000",
            "results": {},
            "final_report": {
                "threat_level": "high",
                "risk_impact": "Validated injection risk.",
                "remediation_steps": ["Use parameterized queries."],
                "auto_remediation": {
                    "pr_ready": True,
                    "target_id": "target-github",
                    "provider": "github",
                    "repository": "acme/aether-demo",
                },
            },
            "remediations": {"finding-sqli": remediation_payload},
        }
        vulnerability = {
            "id": "finding-sqli",
            "title": "SQL Injection via email parameter",
            "evidence_snippet": "Observed SQL error after quote probe.",
            "evidence": {
                "artifact": {
                    "screenshot_base64": screenshot_base64,
                }
            },
        }

        with patch.object(api_main.scan_storage, "ensure_schema", return_value=None), \
             patch.object(api_main.scan_storage, "fetch_scan", return_value=record), \
             patch.object(api_main.scan_storage, "fetch_vulnerabilities", return_value=[vulnerability]), \
             patch.object(api_main.scan_storage, "save_final_report", return_value=True), \
             patch.object(
                 api_main.git_integration_service,
                 "stage_remediation_pr",
                 return_value={
                     "provider": "github",
                     "target_id": "target-github",
                     "repository": "acme/aether-demo",
                     "branch": "aether/remediation/finding-sqli",
                     "base_branch": "main",
                     "pull_request_url": "https://github.com/acme/aether-demo/pull/42",
                     "pull_request_number": 42,
                 },
             ):
            with self.client.websocket_connect(f"/ws/remediation/{scan_id}?user_id={user_id}") as websocket:
                websocket.send_json(
                    {
                        "action": "create_pull_request",
                        "vuln_id": "finding-sqli",
                        "target_id": "target-github",
                    }
                )
                pending_payload = websocket.receive_json()
                success_payload = websocket.receive_json()

        self.assertEqual("git_push_status", pending_payload.get("type"))
        self.assertEqual("pending", pending_payload.get("status"))
        self.assertEqual("git_push_status", success_payload.get("type"))
        self.assertEqual("success", success_payload.get("status"))
        self.assertEqual(
            "https://github.com/acme/aether-demo/pull/42",
            success_payload.get("git_result", {}).get("pull_request_url"),
        )


if __name__ == "__main__":
    unittest.main()
