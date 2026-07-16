import os
import unittest
from unittest.mock import patch

from app.tools.remediation import _fallback_fix, generate_remediation, find_vulnerability


class TestFallbackFix(unittest.TestCase):
    def test_hsts_header(self):
        result = _fallback_fix({"id": "v1", "header": "strict-transport-security"})
        self.assertEqual(result["vuln_id"], "v1")
        self.assertEqual(result["title"], "Enable HSTS")
        self.assertEqual(result["language"], "nginx")
        self.assertIn("Strict-Transport-Security", result["code"])

    def test_csp_header(self):
        result = _fallback_fix({"id": "v2", "header": "content-security-policy"})
        self.assertEqual(result["title"], "Add CSP")

    def test_x_frame_options(self):
        result = _fallback_fix({"id": "v3", "header": "x-frame-options"})
        self.assertEqual(result["title"], "Block framing")

    def test_x_content_type_options(self):
        result = _fallback_fix({"id": "v4", "header": "x-content-type-options"})
        self.assertEqual(result["title"], "Disable MIME sniffing")

    def test_referrer_policy(self):
        result = _fallback_fix({"id": "v5", "header": "referrer-policy"})
        self.assertEqual(result["title"], "Set Referrer-Policy")

    def test_unknown_header_generic_fallback(self):
        result = _fallback_fix({"id": "v6", "header": "x-custom-header"})
        self.assertEqual(result["title"], "Review application configuration")
        self.assertEqual(result["language"], "text")

    def test_empty_header(self):
        result = _fallback_fix({"id": "v7"})
        self.assertEqual(result["title"], "Review application configuration")

    def test_fallback_summary_uses_detail(self):
        result = _fallback_fix({"id": "v8", "header": "strict-transport-security", "detail": "Custom detail"})
        self.assertEqual(result["summary"], "Custom detail")


class TestGenerateRemediation(unittest.TestCase):
    @patch.dict(os.environ, {"NVIDIA_API_KEY": ""}, clear=False)
    def test_no_api_key_returns_fallback(self):
        result = generate_remediation("http://example.com", {"id": "v1", "header": "strict-transport-security"}, {})
        self.assertEqual(result["title"], "Enable HSTS")

    @patch.dict(os.environ, {"NVIDIA_API_KEY": "your_key_here"}, clear=False)
    def test_placeholder_key_returns_fallback(self):
        result = generate_remediation("http://example.com", {"id": "v1", "header": "content-security-policy"}, {})
        self.assertEqual(result["title"], "Add CSP")

    @patch.dict(os.environ, {"NVIDIA_API_KEY": ""}, clear=False)
    def test_unknown_header_returns_generic_fallback(self):
        result = generate_remediation("http://example.com", {"id": "v1", "header": "x-unknown"}, {})
        self.assertEqual(result["title"], "Review application configuration")


class TestFindVulnerability(unittest.TestCase):
    def test_finds_in_header_findings(self):
        results = {
            "header_audit": {
                "findings": [{"id": "header:abc", "title": "Missing HSTS"}]
            }
        }
        found = find_vulnerability(results, "header:abc")
        self.assertIsNotNone(found)
        self.assertEqual(found["id"], "header:abc")

    def test_finds_in_audit_findings(self):
        results = {
            "audit_engine": {
                "findings": [{"id": "audit:1", "title": "SQL Injection"}]
            }
        }
        found = find_vulnerability(results, "audit:1")
        self.assertIsNotNone(found)
        self.assertEqual(found["id"], "audit:1")

    def test_returns_none_when_not_found(self):
        results = {"header_audit": {"findings": []}, "audit_engine": {"findings": []}}
        found = find_vulnerability(results, "nonexistent")
        self.assertIsNone(found)

    def test_empty_results(self):
        found = find_vulnerability({}, "anything")
        self.assertIsNone(found)


if __name__ == "__main__":
    unittest.main()
