import unittest
from unittest.mock import MagicMock, patch
from aether.backend.app.services.storage import ScanStorage

class TestScanStoragePrivacy(unittest.TestCase):
    def setUp(self):
        self.storage = ScanStorage()
        self.storage.get_client = MagicMock()
        self.mock_client = self.storage.get_client.return_value
        self.current_user_id = "test-user-id"

    def test_fetch_scan_filters_by_user_id(self):
        # We want to ensure that fetch_scan takes user_id and uses it in the query
        scan_id = "test-scan-id"
        
        # Setup mock behavior for chaining
        self.mock_client.table.return_value = self.mock_client
        self.mock_client.select.return_value = self.mock_client
        self.mock_client.eq.return_value = self.mock_client
        self.mock_client.limit.return_value = self.mock_client
        self.mock_client.execute.return_value = MagicMock(data=[])

        self.storage.fetch_scan(scan_id, user_id=self.current_user_id)
        
        # Verify that it filters by id AND user_id
        calls = self.mock_client.eq.call_args_list
        found_user_id_filter = any(call.args[0] == "user_id" and call.args[1] == self.current_user_id for call in calls)
        self.assertTrue(found_user_id_filter, "Should have filtered by user_id")

    def test_fetch_profiles_joins_and_filters(self):
        scan_id = "test-scan-id"
        
        # Setup mock behavior for chaining
        self.mock_client.table.return_value = self.mock_client
        self.mock_client.select.return_value = self.mock_client
        self.mock_client.eq.return_value = self.mock_client
        self.mock_client.order.return_value = self.mock_client
        self.mock_client.execute.return_value = MagicMock(data=[])

        self.storage.fetch_profiles(scan_id, user_id=self.current_user_id)
        
        # Verify select includes the join
        self.mock_client.select.assert_called_with("*, scan_sessions!inner(user_id)")
        
        # Verify filtering
        calls = self.mock_client.eq.call_args_list
        found_user_id_filter = any(call.args[0] == "scan_sessions.user_id" and call.args[1] == self.current_user_id for call in calls)
        self.assertTrue(found_user_id_filter, "Should have filtered by scan_sessions.user_id")

    def test_fetch_vulnerabilities_joins_and_filters(self):
        scan_id = "test-scan-id"
        
        # Setup mock behavior for chaining
        self.mock_client.table.return_value = self.mock_client
        self.mock_client.select.return_value = self.mock_client
        self.mock_client.eq.return_value = self.mock_client
        self.mock_client.order.return_value = self.mock_client
        self.mock_client.execute.return_value = MagicMock(data=[])

        self.storage.fetch_vulnerabilities(scan_id, user_id=self.current_user_id)
        
        # Verify select includes the join
        self.mock_client.select.assert_called_with("*, scan_sessions!inner(user_id)")
        
        # Verify filtering
        calls = self.mock_client.eq.call_args_list
        found_user_id_filter = any(call.args[0] == "scan_sessions.user_id" and call.args[1] == self.current_user_id for call in calls)
        self.assertTrue(found_user_id_filter, "Should have filtered by scan_sessions.user_id")

    def test_upsert_scan_includes_user_id(self):
        scan_id = "test-scan-id"
        target_url = "http://example.com"
        initial_plan = {"steps": []}
        brain_status = "pending"
        
        self.mock_client.table.return_value = self.mock_client
        self.mock_client.upsert.return_value = self.mock_client
        self.mock_client.execute.return_value = MagicMock(data={})

        self.storage.upsert_scan(scan_id, target_url, initial_plan, brain_status, user_id=self.current_user_id)
        
        args, kwargs = self.mock_client.upsert.call_args
        payload = args[0]
        self.assertEqual(payload["user_id"], self.current_user_id)

    def test_log_consent_includes_user_id(self):
        target_url = "http://example.com"
        ip_address = "127.0.0.1"
        
        self.mock_client.table.return_value = self.mock_client
        self.mock_client.insert.return_value = self.mock_client
        self.mock_client.execute.return_value = MagicMock(data={})

        self.storage.log_consent(user_id=self.current_user_id, target_url=target_url, ip_address=ip_address)
        
        args, kwargs = self.mock_client.insert.call_args
        payload = args[0]
        self.assertEqual(payload["user_id"], self.current_user_id)

    def test_save_remediations_filters_by_user_id(self):
        scan_id = "test-scan-id"
        remediations = {"fix": "details"}
        
        self.mock_client.table.return_value = self.mock_client
        self.mock_client.update.return_value = self.mock_client
        self.mock_client.eq.return_value = self.mock_client
        self.mock_client.execute.return_value = MagicMock(data={})

        self.storage.save_remediations(scan_id, user_id=self.current_user_id, remediations=remediations)
        
        calls = self.mock_client.eq.call_args_list
        found_user_id_filter = any(call.args[0] == "user_id" and call.args[1] == self.current_user_id for call in calls)
        self.assertTrue(found_user_id_filter, "Should have filtered by user_id")

    def test_replace_hunt_findings_verifies_ownership(self):
        scan_id = "test-scan-id"
        
        self.mock_client.table.return_value = self.mock_client
        self.mock_client.select.return_value = self.mock_client
        self.mock_client.eq.return_value = self.mock_client
        
        # First call to execute checks ownership
        # Second call to delete...
        # We can use side_effect to return different values
        self.mock_client.execute.side_effect = [
            MagicMock(data=[{"id": "some-id"}]), # ownership check success
            MagicMock(data={}), # delete vulnerabilities
            MagicMock(data={}) # delete profiles
        ]
        self.mock_client.delete.return_value = self.mock_client

        self.storage.replace_hunt_findings(scan_id, user_id=self.current_user_id, vulnerabilities=[], profiles=[])
        
        # Verify ownership check filter
        calls = self.mock_client.eq.call_args_list
        found_user_id_filter = any(call.args[0] == "user_id" and call.args[1] == self.current_user_id for call in calls)
        self.assertTrue(found_user_id_filter, "Should have checked ownership by user_id")

if __name__ == "__main__":
    unittest.main()
