import unittest

from app.tools.headers import format_header_logs


class TestFormatHeaderLogs(unittest.TestCase):
    def test_error_result(self):
        result = format_header_logs({"error": "connection refused"})
        self.assertEqual(len(result), 1)
        self.assertIn("CONNECTION REFUSED", result[0])

    def test_with_findings(self):
        result = format_header_logs({
            "status_code": 200,
            "final_url": "http://example.com",
            "findings": [{"header": "strict-transport-security"}, {"header": "content-security-policy"}],
        })
        self.assertEqual(len(result), 2)
        self.assertIn("HTTP 200", result[0])
        self.assertIn("MISCONFIGURATION", result[1])
        self.assertIn("STRICT-TRANSPORT-SECURITY", result[1])

    def test_no_findings(self):
        result = format_header_logs({
            "status_code": 200,
            "final_url": "http://example.com",
            "findings": [],
        })
        self.assertEqual(len(result), 2)
        self.assertIn("CLEAN", result[1])

    def test_no_status_code(self):
        result = format_header_logs({
            "status_code": None,
            "final_url": "http://example.com",
            "findings": [],
        })
        self.assertIn("REQUEST FAILED", result[0])

    def test_many_findings_truncated(self):
        findings = [{"header": f"header-{i}"} for i in range(10)]
        result = format_header_logs({
            "status_code": 200,
            "final_url": "http://example.com",
            "findings": findings,
        })
        self.assertIn("HEADER-0", result[1])
        self.assertIn("HEADER-2", result[1])


if __name__ == "__main__":
    unittest.main()
