import uuid
import unittest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi.testclient import TestClient
from app.api.main import app


class TestAuthRoutes(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.test_email = f"test_{uuid.uuid4().hex[:8]}@example.com"

    @patch('app.api.auth_routes.storage')
    @patch('app.api.auth_routes.send_magic_link_email', new_callable=AsyncMock)
    def test_magic_link_request(self, mock_send_email, mock_storage):
        mock_storage.ensure_schema = MagicMock()
        mock_storage.count_magic_links_recent.return_value = 0
        mock_storage.get_connection.return_value.__enter__ = MagicMock()
        mock_storage.get_connection.return_value.__exit__ = MagicMock()
        mock_send_email.return_value = True

        response = self.client.post(
            "/api/v1/auth/magic-link",
            json={"email": self.test_email}
        )
        # Response should be 200 or 503 (if email fails)
        assert response.status_code in [200, 503]

    @patch('app.api.auth_routes.storage')
    def test_me_endpoint_without_token(self, mock_storage):
        response = self.client.get("/api/v1/auth/me")
        assert response.status_code == 401

    @patch('app.api.auth_routes.storage')
    def test_refresh_endpoint_without_token(self, mock_storage):
        response = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid_token"}
        )
        assert response.status_code == 401

    @patch('app.api.auth_routes.storage')
    def test_logout_endpoint_without_token(self, mock_storage):
        response = self.client.post("/api/v1/auth/logout")
        assert response.status_code == 401

    @patch('app.api.auth_routes.storage')
    def test_delete_account_endpoint_without_token(self, mock_storage):
        response = self.client.delete("/api/v1/auth/account")
        assert response.status_code == 401

    @patch('app.api.auth_routes.storage')
    def test_update_profile_endpoint_without_token(self, mock_storage):
        response = self.client.patch("/api/v1/auth/me")
        assert response.status_code == 401


if __name__ == "__main__":
    unittest.main()