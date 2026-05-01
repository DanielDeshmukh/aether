import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.api.deps import check_scan_quota
from main import app, scan_storage


class TestPhase14FinalAudit(unittest.TestCase):
    def setUp(self):
        app.dependency_overrides = {}
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides = {}

    def test_cheater_fourth_scan_blocked_with_mvp_limit_message(self):
        def _quota_block_override():
            from fastapi import HTTPException

            raise HTTPException(
                status_code=403,
                detail="AETHER MVP Limit Reached: 3/3 scans used. Contact DevLabs for access.",
            )

        app.dependency_overrides[check_scan_quota] = _quota_block_override

        response = self.client.post(
            "/api/v1/scans",
            json={"target_url": "https://example.com", "consent_confirmed": True},
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn("AETHER MVP Limit Reached", response.json().get("detail", ""))

    @patch.object(scan_storage, "ensure_schema", MagicMock(return_value=None))
    @patch.object(scan_storage, "log_consent", MagicMock(return_value=True))
    def test_dirty_url_injection_returns_validation_error(self):
        app.dependency_overrides[check_scan_quota] = lambda: "a7988ba7-c5f5-4ad1-a35d-6814f75c6bf4"

        response = self.client.post(
            "/api/v1/scans",
            json={
                "target_url": "http://example.com'; DROP TABLE scans;--",
                "consent_confirmed": True,
            },
        )

        self.assertIn(response.status_code, {400, 403})
        self.assertNotEqual(response.status_code, 500)


if __name__ == "__main__":
    unittest.main()
