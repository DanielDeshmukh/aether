import unittest
from unittest.mock import patch

from app.tools.validators import is_safe_url


class TestPhase13AttackSurface(unittest.TestCase):
    @patch("app.tools.validators.socket.gethostbyname", return_value="127.0.0.1")
    def test_ssrf_validator_blocks_loopback(self, _mock_lookup):
        self.assertFalse(is_safe_url("http://127.0.0.1:8000"))

    @patch("app.tools.validators.socket.gethostbyname", return_value="10.1.2.3")
    def test_ssrf_validator_blocks_private_range(self, _mock_lookup):
        self.assertFalse(is_safe_url("http://internal.example"))

    @patch("app.tools.validators.socket.gethostbyname", return_value="93.184.216.34")
    def test_ssrf_validator_allows_public_ipv4(self, _mock_lookup):
        self.assertTrue(is_safe_url("https://example.com"))


if __name__ == "__main__":
    unittest.main()
