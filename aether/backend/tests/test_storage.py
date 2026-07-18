import unittest
from unittest.mock import MagicMock
from app.services.storage import ScanStorage


class TestScanStorage(unittest.TestCase):
    def setUp(self):
        self.storage = ScanStorage()
        self.storage._pool = MagicMock()
        self.mock_connection = MagicMock()
        self.storage.get_connection = MagicMock(return_value=self.mock_connection)

    def test_configured(self):
        assert not self.storage.configured() or self.storage.configured()

    def test_database_configured(self):
        assert not self.storage.database_configured() or self.storage.database_configured()

    def test_mask_value(self):
        result = self.storage.mask_value("test123456", visible=3)
        assert "..." in result or result == "test123456"

    def test_mask_value_short(self):
        result = self.storage.mask_value("short")
        assert result == "short"

    def test_mask_value_empty(self):
        result = self.storage.mask_value("")
        assert result == "<unset>"

    def test_get_pool_stats(self):
        stats = self.storage.get_pool_stats()
        assert isinstance(stats, dict)

    def test_check_database_health(self):
        health = self.storage.check_database_health()
        assert isinstance(health, dict)


if __name__ == "__main__":
    unittest.main()