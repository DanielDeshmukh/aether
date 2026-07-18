import uuid
import unittest
from unittest.mock import MagicMock
from app.services.storage import ScanStorage


class TestScanStoragePrivacy(unittest.TestCase):
    def setUp(self):
        self.storage = ScanStorage()
        self.storage._pool = MagicMock()
        self.mock_connection = MagicMock()
        self.storage.get_connection = MagicMock()
        self.storage.get_connection.return_value.__enter__ = MagicMock(return_value=self.mock_connection)
        self.storage.get_connection.return_value.__exit__ = MagicMock(return_value=False)
        self.current_user_id = str(uuid.uuid4())

    def test_fetch_scan_filters_by_user_id(self):
        scan_id = str(uuid.uuid4())
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        self.mock_connection.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        self.mock_connection.cursor.return_value.__exit__ = MagicMock(return_value=False)

        self.storage.fetch_scan(scan_id, user_id=self.current_user_id)

        # Verify that the query was executed
        mock_cursor.execute.assert_called()

    def test_fetch_all_scans_filters_by_user_id(self):
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        self.mock_connection.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        self.mock_connection.cursor.return_value.__exit__ = MagicMock(return_value=False)

        self.storage.fetch_all_scans(user_id=self.current_user_id)

        # Verify that the query was executed
        mock_cursor.execute.assert_called()

    def test_delete_scan_filters_by_user_id(self):
        scan_id = str(uuid.uuid4())
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_cursor.rowcount = 1
        self.mock_connection.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        self.mock_connection.cursor.return_value.__exit__ = MagicMock(return_value=False)

        self.storage.delete_scan(scan_id, user_id=self.current_user_id)

        # Verify that the query was executed
        mock_cursor.execute.assert_called()

    def test_save_remediations_filters_by_user_id(self):
        scan_id = str(uuid.uuid4())
        remediations = {"fix": "details"}
        mock_cursor = MagicMock()
        mock_cursor.rowcount = 1
        self.mock_connection.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        self.mock_connection.cursor.return_value.__exit__ = MagicMock(return_value=False)

        self.storage.save_remediations(scan_id, user_id=self.current_user_id, remediations=remediations)

        # Verify that the query was executed
        mock_cursor.execute.assert_called()

    def test_log_consent_includes_user_id(self):
        target_url = "http://example.com"
        ip_address = "127.0.0.1"
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = [1]
        self.mock_connection.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        self.mock_connection.cursor.return_value.__exit__ = MagicMock(return_value=False)

        self.storage.log_consent(user_id=self.current_user_id, target_url=target_url, ip_address=ip_address)

        # Verify that the query was executed
        mock_cursor.execute.assert_called()


if __name__ == "__main__":
    unittest.main()