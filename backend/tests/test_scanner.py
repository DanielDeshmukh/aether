import unittest

from app.tools.scanner import format_port_logs


class TestFormatPortLogs(unittest.TestCase):
    def test_error_result(self):
        result = format_port_logs({"error": "timeout"})
        self.assertEqual(len(result), 1)
        self.assertIn("TIMEOUT", result[0])

    def test_open_ports(self):
        result = format_port_logs({"host": "example.com", "open_ports": [80, 443]})
        self.assertEqual(len(result), 2)
        self.assertIn("80", result[0])
        self.assertIn("443", result[0])
        self.assertIn("RESPONDED", result[0])

    def test_no_open_ports(self):
        result = format_port_logs({"host": "example.com", "open_ports": []})
        self.assertEqual(len(result), 2)
        self.assertIn("NO COMMON WEB PORTS", result[0])

    def test_empty_result(self):
        result = format_port_logs({})
        self.assertEqual(len(result), 2)
        self.assertIn("UNKNOWN HOST", result[0])

    def test_single_open_port(self):
        result = format_port_logs({"host": "test.com", "open_ports": [8080]})
        self.assertIn("8080", result[0])


if __name__ == "__main__":
    unittest.main()
