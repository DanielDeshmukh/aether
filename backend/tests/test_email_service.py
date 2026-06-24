import os
import unittest
from unittest.mock import patch, AsyncMock, MagicMock
import asyncio

from app.services.email import send_magic_link_email, send_report_email


class TestSendMagicLinkEmail(unittest.TestCase):
    @patch.dict(os.environ, {"SMTP_HOST": ""}, clear=False)
    def test_no_smtp_returns_true(self):
        result = asyncio.run(send_magic_link_email("user@test.com", "http://link"))
        self.assertTrue(result)

    @patch.dict(os.environ, {"SMTP_HOST": ""}, clear=False)
    def test_empty_smtp_host_returns_true(self):
        result = asyncio.run(send_magic_link_email("user@test.com", "http://link"))
        self.assertTrue(result)


class TestSendReportEmail(unittest.TestCase):
    @patch.dict(os.environ, {"SMTP_HOST": ""}, clear=False)
    def test_no_smtp_returns_true(self):
        result = asyncio.run(send_report_email(
            to_email="user@test.com",
            target_url="http://example.com",
            vuln_count=5,
            threat_level="high",
            pdf_bytes=b"fake-pdf",
            scan_id="scan-123",
        ))
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
