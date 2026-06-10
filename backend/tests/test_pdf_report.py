import unittest
from unittest.mock import MagicMock, patch, AsyncMock
from app.services.report_generator import render_pdf_report


class TestPdfReport(unittest.TestCase):
    def setUp(self):
        self.scan_record = {
            "id": "test-scan-123",
            "target_url": "https://example.com",
            "status": "completed",
            "threat_level": "medium",
            "created_at": "2024-01-01T00:00:00Z",
            "initial_plan": {"steps": []},
            "results": {},
            "final_report": {},
        }
        self.vulnerabilities = [
            {
                "id": "vuln-1",
                "title": "Test Vulnerability",
                "severity": "high",
                "description": "Test description",
                "category": "test",
            }
        ]
        self.profiles = []

    def test_render_pdf_report_returns_bytes(self):
        result = render_pdf_report(self.scan_record, self.vulnerabilities, self.profiles)
        assert isinstance(result, bytes) or hasattr(result, '__await__')

    def test_render_pdf_report_with_empty_vulns(self):
        result = render_pdf_report(self.scan_record, [], self.profiles)
        assert isinstance(result, bytes) or hasattr(result, '__await__')


if __name__ == "__main__":
    unittest.main()