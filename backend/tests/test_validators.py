import unittest
from uuid import uuid4

from app.services.validators import VulnerabilityRow, validate_and_build_rows


class TestVulnerabilityRowCoerceSeverity(unittest.TestCase):
    def test_valid_severity(self):
        self.assertEqual(VulnerabilityRow.coerce_severity("high"), "High")
        self.assertEqual(VulnerabilityRow.coerce_severity("CRITICAL"), "Critical")
        self.assertEqual(VulnerabilityRow.coerce_severity("medium"), "Medium")
        self.assertEqual(VulnerabilityRow.coerce_severity("low"), "Low")

    def test_unknown_severity_falls_back_to_low(self):
        self.assertEqual(VulnerabilityRow.coerce_severity("unknown"), "Low")
        self.assertEqual(VulnerabilityRow.coerce_severity("fatal"), "Low")

    def test_non_string_falls_back_to_low(self):
        self.assertEqual(VulnerabilityRow.coerce_severity(123), "Low")
        self.assertEqual(VulnerabilityRow.coerce_severity(None), "Low")
        self.assertEqual(VulnerabilityRow.coerce_severity(["high"]), "Low")


class TestVulnerabilityRowSanitizeStrings(unittest.TestCase):
    def test_none_returns_empty(self):
        self.assertEqual(VulnerabilityRow.sanitize_strings(None), "")

    def test_strips_whitespace(self):
        self.assertEqual(VulnerabilityRow.sanitize_strings("  hello  "), "hello")

    def test_non_string_coerced(self):
        self.assertEqual(VulnerabilityRow.sanitize_strings(123), "123")


class TestVulnerabilityRowEnsureValidJsonb(unittest.TestCase):
    def test_dict_passes_through(self):
        d = {"key": "value"}
        self.assertEqual(VulnerabilityRow.ensure_valid_jsonb(d), d)

    def test_non_dict_returns_empty(self):
        self.assertEqual(VulnerabilityRow.ensure_valid_jsonb("not a dict"), {})
        self.assertEqual(VulnerabilityRow.ensure_valid_jsonb(None), {})
        self.assertEqual(VulnerabilityRow.ensure_valid_jsonb(123), {})


class TestValidateAndBuildRows(unittest.TestCase):
    def setUp(self):
        self.scan_id = uuid4()
        self.session_id = uuid4()

    def test_none_session_id_raises(self):
        with self.assertRaises(ValueError) as ctx:
            validate_and_build_rows([], self.scan_id, None)
        self.assertIn("session_id is required", str(ctx.exception))

    def test_invalid_scan_id_raises(self):
        with self.assertRaises(ValueError) as ctx:
            validate_and_build_rows([{"title": "x"}], "not-a-uuid", self.session_id)
        self.assertIn("Invalid UUID", str(ctx.exception))

    def test_empty_findings_auto_fallback(self):
        valid_rows, errors = validate_and_build_rows([], self.scan_id, self.session_id)
        self.assertEqual(len(valid_rows), 1)
        self.assertEqual(len(errors), 0)
        self.assertIn("Heuristic Pass", valid_rows[0]["title"])

    def test_none_findings_auto_fallback(self):
        valid_rows, errors = validate_and_build_rows(None, self.scan_id, self.session_id)
        self.assertEqual(len(valid_rows), 1)

    def test_string_findings_auto_fallback(self):
        valid_rows, errors = validate_and_build_rows("garbage", self.scan_id, self.session_id)
        self.assertEqual(len(valid_rows), 1)

    def test_valid_findings(self):
        findings = [
            {
                "title": "XSS in search",
                "detail": "Reflected XSS found",
                "severity": "High",
                "category": "xss",
                "evidence": {"url": "http://test.com?q=<script>"},
            }
        ]
        valid_rows, errors = validate_and_build_rows(findings, self.scan_id, self.session_id)
        self.assertEqual(len(valid_rows), 1)
        self.assertEqual(len(errors), 0)
        self.assertEqual(valid_rows[0]["title"], "XSS in search")
        self.assertEqual(valid_rows[0]["severity"], "High")

    def test_mixed_valid_and_invalid(self):
        findings = [
            {"title": "Good finding", "severity": "Low"},
            "not a dict",
            {"title": "Another good", "severity": "Critical"},
        ]
        valid_rows, errors = validate_and_build_rows(findings, self.scan_id, self.session_id)
        self.assertEqual(len(valid_rows), 2)
        self.assertEqual(len(errors), 1)

    def test_severity_coercion(self):
        findings = [{"title": "test", "severity": "CRITICAL"}]
        valid_rows, _ = validate_and_build_rows(findings, self.scan_id, self.session_id)
        self.assertEqual(valid_rows[0]["severity"], "Critical")

    def test_non_dict_in_list_raises_error(self):
        findings = [42]
        with self.assertRaises(Exception) as ctx:
            validate_and_build_rows(findings, self.scan_id, self.session_id)
        self.assertIn("CRITICAL_VALIDATION_FAILURE", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
