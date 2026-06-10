import unittest
from unittest.mock import MagicMock, patch

from app.services.quota_manager import QuotaManager
from app.services.storage import ScanStorage


class TestQuotaManager(unittest.TestCase):
    def setUp(self):
        self.storage = MagicMock(spec=ScanStorage)
        self.quota_manager = QuotaManager(self.storage)

    def test_get_limit_free_tier(self):
        self.assertEqual(self.quota_manager.get_limit("free"), 3)

    def test_get_limit_pro_tier(self):
        self.assertEqual(self.quota_manager.get_limit("pro"), 50)

    def test_get_limit_enterprise_tier(self):
        self.assertEqual(self.quota_manager.get_limit("enterprise"), 999)

    def test_get_limit_unknown_tier_defaults_to_free(self):
        self.assertEqual(self.quota_manager.get_limit("unknown"), 3)

    def test_check_quota_allows_under_limit(self):
        self.storage.get_total_scan_count.return_value = 2
        result = self.quota_manager.check_quota("user123")
        
        self.assertTrue(result["allowed"])
        self.assertEqual(result["used"], 2)
        self.assertEqual(result["limit"], 3)
        self.assertEqual(result["remaining"], 1)

    def test_check_quota_blocks_at_limit(self):
        self.storage.get_total_scan_count.return_value = 3
        result = self.quota_manager.check_quota("user123")
        
        self.assertFalse(result["allowed"])
        self.assertEqual(result["used"], 3)
        self.assertEqual(result["limit"], 3)
        self.assertEqual(result["remaining"], 0)

    def test_check_quota_allows_over_limit(self):
        self.storage.get_total_scan_count.return_value = 5
        result = self.quota_manager.check_quota("user123")
        
        self.assertFalse(result["allowed"])
        self.assertEqual(result["used"], 5)
        self.assertEqual(result["limit"], 3)
        self.assertEqual(result["remaining"], 0)

    def test_check_quota_pro_tier(self):
        self.storage.get_total_scan_count.return_value = 25
        result = self.quota_manager.check_quota("user123", tier="pro")
        
        self.assertTrue(result["allowed"])
        self.assertEqual(result["used"], 25)
        self.assertEqual(result["limit"], 50)
        self.assertEqual(result["remaining"], 25)

    def test_check_quota_enterprise_tier(self):
        self.storage.get_total_scan_count.return_value = 998
        result = self.quota_manager.check_quota("user123", tier="enterprise")
        
        self.assertTrue(result["allowed"])
        self.assertEqual(result["used"], 998)
        self.assertEqual(result["limit"], 999)
        self.assertEqual(result["remaining"], 1)

    @patch.dict("os.environ", {"QUOTA_FREE_LIMIT": "10"})
    def test_check_quota_custom_env_limit(self):
        manager = QuotaManager(self.storage)
        self.storage.get_total_scan_count.return_value = 8
        result = manager.check_quota("user123")
        
        self.assertTrue(result["allowed"])
        self.assertEqual(result["limit"], 10)
        self.assertEqual(result["remaining"], 2)


if __name__ == "__main__":
    unittest.main()