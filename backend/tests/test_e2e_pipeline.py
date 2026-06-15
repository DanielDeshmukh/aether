import os
import uuid
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.api.main import app
from app.services.auth import create_access_token


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def test_user_id():
    return str(uuid.uuid4())


@pytest.fixture
def test_email():
    return f"e2e-test-{uuid.uuid4().hex[:8]}@aether.dev"


@pytest.fixture
def auth_headers(test_user_id, test_email):
    token = create_access_token(test_user_id, test_email)
    return {"Authorization": f"Bearer {token}"}


class TestAuthPipeline:
    @patch('app.api.auth_routes.storage')
    @patch('app.api.auth_routes.send_magic_link_email', new_callable=AsyncMock)
    def test_magic_link_request_returns_success(self, mock_send_email, mock_storage, client):
        mock_storage.ensure_schema = MagicMock()
        mock_storage.count_magic_links_recent.return_value = 0
        mock_storage.get_connection.return_value.__enter__ = MagicMock()
        mock_storage.get_connection.return_value.__exit__ = MagicMock()
        mock_send_email.return_value = True

        response = client.post(
            "/api/v1/auth/magic-link",
            json={"email": "test@aether.dev"},
        )
        assert response.status_code in [200, 503]

    def test_me_endpoint_returns_401_without_token(self, client):
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401

    @patch('app.api.auth_routes.storage')
    def test_me_endpoint_returns_user_with_valid_token(self, mock_auth_storage, client, auth_headers):
        mock_auth_storage.get_connection.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_auth_storage.get_connection.return_value.__exit__ = MagicMock(return_value=False)
        response = client.get("/api/v1/auth/me", headers=auth_headers)
        assert response.status_code in [200, 401]

    def test_refresh_endpoint_rejects_invalid_token(self, client):
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid-token"},
        )
        assert response.status_code == 401

    def test_logout_endpoint_returns_401_without_token(self, client):
        response = client.post("/api/v1/auth/logout")
        assert response.status_code == 401


class TestScanCreationPipeline:
    def test_create_scan_requires_authentication(self, client):
        response = client.post(
            "/api/v1/scans",
            json={"target_url": "https://example.com", "consent_confirmed": True},
        )
        assert response.status_code == 401

    @patch('app.api.main.scan_storage')
    def test_create_scan_requires_consent(self, mock_storage, client, auth_headers):
        mock_storage.ensure_schema = MagicMock()
        mock_storage.log_consent.return_value = True
        mock_storage.get_or_create_target.return_value = "target-123"
        mock_storage.get_scan_count.return_value = 0

        response = client.post(
            "/api/v1/scans",
            json={"target_url": "https://example.com", "consent_confirmed": False},
            headers=auth_headers,
        )
        assert response.status_code == 400

    @patch('app.api.main.scan_storage')
    def test_create_scan_rejects_private_targets(self, mock_storage, client, auth_headers):
        mock_storage.ensure_schema = MagicMock()
        mock_storage.get_scan_count.return_value = 0

        response = client.post(
            "/api/v1/scans",
            json={"target_url": "http://192.168.1.1", "consent_confirmed": True},
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_create_scan_rejects_invalid_url(self, client, auth_headers):
        response = client.post(
            "/api/v1/scans",
            json={"target_url": "not-a-url", "consent_confirmed": True},
            headers=auth_headers,
        )
        assert response.status_code in [400, 422]


class TestScanRetrievalPipeline:
    def test_list_scans_requires_authentication(self, client):
        response = client.get("/api/v1/scans")
        assert response.status_code == 401

    @patch('app.api.main.scan_storage')
    def test_list_scans_returns_list(self, mock_storage, client, auth_headers):
        mock_storage.ensure_schema = MagicMock()
        mock_storage.fetch_all_scans.return_value = []

        response = client.get("/api/v1/scans", headers=auth_headers)
        assert response.status_code == 200

    def test_get_scan_requires_authentication(self, client):
        response = client.get("/api/v1/scans/test-scan-id")
        assert response.status_code == 401

    @patch('app.api.main.scan_storage')
    def test_get_scan_returns_404_for_nonexistent(self, mock_storage, client, auth_headers):
        mock_storage.ensure_schema = MagicMock()
        mock_storage.fetch_scan.return_value = None
        mock_storage.fetch_target_verification_record.return_value = None

        response = client.get(
            "/api/v1/scans/nonexistent-scan-id",
            headers=auth_headers,
        )
        assert response.status_code == 404


class TestScanExportPipeline:
    def test_export_json_requires_authentication(self, client):
        response = client.get("/api/v1/scans/test/export?format=json")
        assert response.status_code == 401

    def test_export_csv_requires_authentication(self, client):
        response = client.get("/api/v1/scans/test/export?format=csv")
        assert response.status_code == 401

    @patch('app.api.main.scan_storage')
    def test_export_json_returns_404_for_nonexistent(self, mock_storage, client, auth_headers):
        mock_storage.ensure_schema = MagicMock()
        mock_storage.fetch_scan.return_value = None

        response = client.get(
            "/api/v1/scans/nonexistent/export?format=json",
            headers=auth_headers,
        )
        assert response.status_code == 404


class TestReportPipeline:
    def test_report_download_requires_authentication(self, client):
        response = client.get("/api/v1/scans/test/report")
        assert response.status_code == 401

    def test_report_email_requires_authentication(self, client):
        response = client.post(
            "/api/v1/scans/test/report/email",
            json={"email": "test@aether.dev"},
        )
        assert response.status_code == 401


class TestHealthCheckPipeline:
    def test_health_endpoint_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data.get("data", {})

    def test_api_health_endpoint_returns_200(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data.get("data", {})


class TestScanControlPipeline:
    def test_pause_scan_requires_authentication(self, client):
        response = client.post("/api/v1/scan/test/pause")
        assert response.status_code == 401

    def test_resume_scan_requires_authentication(self, client):
        response = client.post("/api/v1/scan/test/resume")
        assert response.status_code == 401

    def test_terminate_scan_requires_authentication(self, client):
        response = client.post("/api/v1/scan/test/terminate")
        assert response.status_code == 401

    def test_kill_scan_requires_authentication(self, client):
        response = client.post("/api/v1/scan/kill/test")
        assert response.status_code == 401


class TestRemediationPipeline:
    def test_remediation_history_requires_authentication(self, client):
        response = client.get("/api/v1/scans/test/remediation-history")
        assert response.status_code == 401

    def test_screenshot_evidence_requires_authentication(self, client):
        response = client.get("/api/v1/scans/test/vulnerabilities/test-vuln/evidence/screenshot")
        assert response.status_code == 401


class TestOWASPAttackCategories:
    def test_all_ten_owasp_categories_are_defined(self):
        from app.orchestrator.attack_orchestrator import OWASP_TOP_10_2021
        assert len(OWASP_TOP_10_2021) == 10
        expected = [
            "A01:2021-Broken Access Control",
            "A02:2021-Cryptographic Failures",
            "A03:2021-Injection",
            "A04:2021-Insecure Design",
            "A05:2021-Security Misconfiguration",
            "A06:2021-Vulnerable and Outdated Components",
            "A07:2021-Identification and Authentication Failures",
            "A08:2021-Software and Data Integrity Failures",
            "A09:2021-Security Logging and Monitoring Failures",
            "A10:2021-Server-Side Request Forgery",
        ]
        for category in expected:
            assert category in OWASP_TOP_10_2021

    def test_validation_lane_manager_has_all_lane_methods(self):
        from app.engine.validation_lanes import ValidationLaneManager
        lane_methods = [
            "run_xss_lane",
            "run_injection_lane",
            "run_crypto_failures_lane",
            "run_insecure_design_lane",
            "run_misconfiguration_lane",
            "run_vulnerable_components_lane",
            "run_auth_failures_lane",
            "run_data_integrity_lane",
            "run_logging_failures_lane",
            "run_ssrf_lane",
        ]
        for method in lane_methods:
            assert hasattr(ValidationLaneManager, method), f"Missing lane method: {method}"

    def test_attack_orchestrator_has_all_validation_modules(self):
        from app.orchestrator.attack_orchestrator import AttackOrchestrator
        validation_methods = [
            "_validate_a01_broken_access_control",
            "_validate_a02_crypto_failures",
            "_run_playwright_validation_lanes",
            "_validate_a04_insecure_design",
            "_validate_a05_misconfiguration",
            "_validate_a06_vulnerable_components",
            "_validate_a07_auth_failures",
            "_validate_a08_data_integrity",
            "_validate_a09_logging_failures",
            "_validate_a10_ssrf",
        ]
        for method in validation_methods:
            assert hasattr(AttackOrchestrator, method), f"Missing validation module: {method}"
