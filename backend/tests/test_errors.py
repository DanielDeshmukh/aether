import unittest
from unittest.mock import MagicMock

from app.api.errors import (
    AetherError,
    ScanNotFoundError,
    UnauthorizedError,
    RateLimitError,
    ValidationError,
    ExternalServiceError,
    create_error_response,
    global_exception_handler,
    aether_error_handler,
)


class TestAetherError(unittest.TestCase):
    def test_default_error_code(self):
        err = AetherError(500, "something broke")
        self.assertEqual(err.status_code, 500)
        self.assertEqual(err.detail, "something broke")
        self.assertEqual(err.error_code, "ERROR_500")

    def test_custom_error_code(self):
        err = AetherError(400, "bad", error_code="CUSTOM_ERR")
        self.assertEqual(err.error_code, "CUSTOM_ERR")

    def test_headers(self):
        err = AetherError(429, "slow", headers={"Retry-After": "30"})
        self.assertEqual(err.headers, {"Retry-After": "30"})


class TestScanNotFoundError(unittest.TestCase):
    def test_fields(self):
        err = ScanNotFoundError("abc-123")
        self.assertEqual(err.status_code, 404)
        self.assertEqual(err.error_code, "SCAN_NOT_FOUND")
        self.assertIn("abc-123", err.detail)


class TestUnauthorizedError(unittest.TestCase):
    def test_default(self):
        err = UnauthorizedError()
        self.assertEqual(err.status_code, 403)
        self.assertEqual(err.error_code, "UNAUTHORIZED")
        self.assertEqual(err.detail, "Unauthorized access")

    def test_custom_message(self):
        err = UnauthorizedError("no access")
        self.assertEqual(err.detail, "no access")


class TestRateLimitError(unittest.TestCase):
    def test_default(self):
        err = RateLimitError()
        self.assertEqual(err.status_code, 429)
        self.assertEqual(err.error_code, "RATE_LIMIT_EXCEEDED")
        self.assertEqual(err.headers, {"Retry-After": "60"})

    def test_custom_message(self):
        err = RateLimitError("slow down")
        self.assertEqual(err.detail, "slow down")


class TestValidationError(unittest.TestCase):
    def test_fields(self):
        err = ValidationError("email", "invalid format")
        self.assertEqual(err.status_code, 422)
        self.assertEqual(err.error_code, "VALIDATION_ERROR")
        self.assertIn("email", err.detail)
        self.assertIn("invalid format", err.detail)


class TestExternalServiceError(unittest.TestCase):
    def test_fields(self):
        err = ExternalServiceError("Gemini")
        self.assertEqual(err.status_code, 502)
        self.assertEqual(err.error_code, "EXTERNAL_SERVICE_ERROR")
        self.assertIn("Gemini", err.detail)

    def test_custom_message(self):
        err = ExternalServiceError("Gemini", "timeout")
        self.assertIn("timeout", err.detail)


class TestCreateErrorResponse(unittest.TestCase):
    def test_basic(self):
        resp = create_error_response(404, "not found")
        self.assertEqual(resp.status_code, 404)
        import json
        body = json.loads(resp.body)
        self.assertEqual(body["error"]["code"], "ERROR_404")
        self.assertEqual(body["error"]["message"], "not found")

    def test_custom_error_code_and_details(self):
        resp = create_error_response(422, "bad", error_code="CUSTOM", details={"field": "email"})
        import json
        body = json.loads(resp.body)
        self.assertEqual(body["error"]["code"], "CUSTOM")
        self.assertEqual(body["data"]["field"], "email")


class TestGlobalExceptionHandler(unittest.TestCase):
    def test_returns_500(self):
        import asyncio
        request = MagicMock()
        resp = asyncio.run(global_exception_handler(request, Exception("boom")))
        self.assertEqual(resp.status_code, 500)
        import json
        body = json.loads(resp.body)
        self.assertEqual(body["error"]["code"], "INTERNAL_SERVER_ERROR")


class TestAetherErrorHandler(unittest.TestCase):
    def test_returns_correct_status(self):
        import asyncio
        request = MagicMock()
        exc = RateLimitError("too fast")
        resp = asyncio.run(aether_error_handler(request, exc))
        self.assertEqual(resp.status_code, 429)
        import json
        body = json.loads(resp.body)
        self.assertEqual(body["error"]["code"], "RATE_LIMIT_EXCEEDED")
        self.assertEqual(body["error"]["message"], "too fast")


if __name__ == "__main__":
    unittest.main()
