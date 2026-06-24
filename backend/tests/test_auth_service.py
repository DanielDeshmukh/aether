import os
import unittest
from unittest.mock import patch, MagicMock

from app.services.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_magic_link_token,
    get_google_auth_url,
    get_github_auth_url,
)


class TestCreateAccessToken(unittest.TestCase):
    @patch.dict(os.environ, {"AETHER_JWT_SECRET": "test-secret-key-for-testing"})
    def test_creates_valid_jwt(self):
        token = create_access_token("user-123", "test@example.com")
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 20)

    @patch.dict(os.environ, {"AETHER_JWT_SECRET": "test-secret-key-for-testing"})
    def test_token_decodes_correctly(self):
        token = create_access_token("user-456", "a@b.com")
        data = decode_token(token, expected_type="access")
        self.assertEqual(data["sub"], "user-456")
        self.assertEqual(data["email"], "a@b.com")
        self.assertEqual(data["type"], "access")
        self.assertEqual(data["aud"], "authenticated")

    @patch.dict(os.environ, {"AETHER_JWT_SECRET": ""})
    def test_missing_secret_raises(self):
        with self.assertRaises(RuntimeError):
            create_access_token("user", "e@e.com")


class TestCreateRefreshToken(unittest.TestCase):
    @patch.dict(os.environ, {"AETHER_JWT_SECRET": "test-secret-key-for-testing"})
    def test_creates_valid_refresh_token(self):
        token = create_refresh_token("user-789")
        data = decode_token(token, expected_type="refresh")
        self.assertEqual(data["sub"], "user-789")
        self.assertEqual(data["type"], "refresh")


class TestDecodeToken(unittest.TestCase):
    @patch.dict(os.environ, {"AETHER_JWT_SECRET": "test-secret-key-for-testing"})
    def test_wrong_type_raises(self):
        token = create_access_token("user", "e@e.com")
        with self.assertRaises(ValueError) as ctx:
            decode_token(token, expected_type="refresh")
        self.assertIn("Expected token type", str(ctx.exception))

    @patch.dict(os.environ, {"AETHER_JWT_SECRET": "test-secret-key-for-testing"})
    def test_invalid_token_raises(self):
        with self.assertRaises(Exception):
            decode_token("not-a-valid-token")

    @patch.dict(os.environ, {"AETHER_JWT_SECRET": "test-secret-key-for-testing"})
    def test_missing_secret_raises(self):
        with patch.dict(os.environ, {"AETHER_JWT_SECRET": ""}):
            with self.assertRaises(RuntimeError):
                decode_token("some-token")


class TestGenerateMagicLinkToken(unittest.TestCase):
    def test_returns_urlsafe_string(self):
        token = generate_magic_link_token()
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 20)

    def test_unique_tokens(self):
        t1 = generate_magic_link_token()
        t2 = generate_magic_link_token()
        self.assertNotEqual(t1, t2)


class TestGetGoogleAuthUrl(unittest.TestCase):
    @patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "my-client-id", "GOOGLE_REDIRECT_URI": "http://localhost:8000/callback"})
    def test_builds_correct_url(self):
        url = get_google_auth_url()
        self.assertIn("client_id=my-client-id", url)
        self.assertIn("redirect_uri=http://localhost:8000/callback", url)
        self.assertIn("response_type=code", url)
        self.assertIn("scope=openid", url)

    @patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "cid", "GOOGLE_REDIRECT_URI": "", "FRONTEND_URL": "https://app.com"}, clear=False)
    def test_fallback_redirect_uri(self):
        url = get_google_auth_url()
        self.assertIn("https://app.com/api/v1/auth/google/callback", url)


class TestGetGithubAuthUrl(unittest.TestCase):
    @patch.dict(os.environ, {"GITHUB_CLIENT_ID": "gh-id", "GITHUB_REDIRECT_URI": "http://localhost:8000/gh"})
    def test_builds_correct_url(self):
        url = get_github_auth_url()
        self.assertIn("client_id=gh-id", url)
        self.assertIn("redirect_uri=http://localhost:8000/gh", url)
        self.assertIn("scope=user:email", url)

    @patch.dict(os.environ, {"GITHUB_CLIENT_ID": "gh-id", "FRONTEND_URL": "https://app.com"}, clear=False)
    def test_fallback_redirect_uri(self):
        url = get_github_auth_url()
        self.assertIn("https://app.com/api/v1/auth/github/callback", url)


if __name__ == "__main__":
    unittest.main()
