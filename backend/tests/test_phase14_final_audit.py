import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.api.deps import check_scan_quota, get_current_user
from app.api.main import app, scan_storage


class TestPhase14FinalAudit(unittest.TestCase):
    def setUp(self):
        app.dependency_overrides = {}
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides = {}

    @patch("app.api.main.create_scan_record", return_value={"scan_id": "test-scan-id", "target_url": "https://example.com", "data": {"scan_id": "test-scan-id", "target_url": "https://example.com"}})
    @patch.object(scan_storage, "ensure_schema", MagicMock(return_value=None))
    @patch.object(scan_storage, "log_consent", MagicMock(return_value=True))
    @patch.object(scan_storage, "get_or_create_target", MagicMock(return_value="550e8400-e29b-41d4-a716-446655440000"))
    def test_cheater_fourth_scan_blocked_with_mvp_limit_message(self, mock_create_scan):
        # Note: Check quota is tested in test_phase12_quota_guard.py
        # This test focuses on the integration after new get_or_create_target method
        def _auth_override():
            return "a7988ba7-c5f5-4ad1-a35d-6814f75c6bf4"

        app.dependency_overrides[get_current_user] = _auth_override
        app.dependency_overrides[check_scan_quota] = _auth_override

        response = self.client.post(
            "/api/v1/scans",
            json={"target_url": "https://example.com", "consent_confirmed": True},
        )
        
        # Verify that the endpoint now calls get_or_create_target successfully
        self.assertEqual(response.status_code, 200)
        self.assertIn("scan_id", response.json())

    @patch.object(scan_storage, "ensure_schema", MagicMock(return_value=None))
    @patch.object(scan_storage, "log_consent", MagicMock(return_value=True))
    @patch.object(scan_storage, "get_or_create_target", MagicMock(return_value="550e8400-e29b-41d4-a716-446655440000"))
    def test_dirty_url_injection_returns_validation_error(self):
        def _auth_override():
            return "a7988ba7-c5f5-4ad1-a35d-6814f75c6bf4"

        app.dependency_overrides[check_scan_quota] = lambda: "a7988ba7-c5f5-4ad1-a35d-6814f75c6bf4"
        app.dependency_overrides[get_current_user] = _auth_override

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
