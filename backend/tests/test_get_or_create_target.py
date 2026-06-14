import unittest
import uuid
from unittest.mock import MagicMock, patch

from app.services.storage import ScanStorage


class MockCursor:
    """Mock cursor for testing database operations."""
    
    def __init__(self, fetchone_result=None):
        self.fetchone_result = fetchone_result
        self.executed_queries = []
        self.executed_params = []
    
    def execute(self, query, params=None):
        self.executed_queries.append(query)
        self.executed_params.append(params or ())
        return self
    
    def fetchone(self):
        return self.fetchone_result
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass


class MockConnection:
    """Mock connection for testing database operations."""
    
    def __init__(self, cursor_result=None):
        self.cursor_result = cursor_result
        self.committed = False
    
    def cursor(self, row_factory=None):
        return MockCursor(self.cursor_result)
    
    def commit(self):
        self.committed = True
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass


class TestGetOrCreateTarget(unittest.TestCase):
    """Test suite for the get_or_create_target upsert pattern."""
    
    def setUp(self):
        self.storage = ScanStorage()
        self.test_url = "example.com"
        self.test_user_id = str(uuid.uuid4())
        self.test_target_id = str(uuid.uuid4())
    
    @patch.object(ScanStorage, 'get_connection')
    def test_get_or_create_target_returns_existing_id(self, mock_get_connection):
        """Test that existing target is returned without creating a new one."""
        mock_cursor = MockCursor(fetchone_result={'id': self.test_target_id})
        mock_conn = MockConnection()
        mock_conn.cursor = MagicMock(return_value=mock_cursor)
        
        mock_get_connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_get_connection.return_value.__exit__ = MagicMock(return_value=None)
        
        # First call returns existing target, second doesn't matter
        mock_cursor.execute = MagicMock()
        mock_cursor.fetchone = MagicMock(return_value={'id': self.test_target_id})
        
        with patch.object(mock_conn, 'cursor', return_value=mock_cursor):
            result = self.storage.get_or_create_target(self.test_url, self.test_user_id)
        
        self.assertEqual(result, self.test_target_id)
    
    @patch.object(ScanStorage, 'get_connection')
    def test_get_or_create_target_creates_new_target(self, mock_get_connection):
        """Test that new target is created and ID is returned."""
        mock_cursor = MockCursor()
        mock_conn = MockConnection()
        
        # First call (SELECT) returns None, second call (INSERT) returns new ID
        fetchone_values = [None, {'id': self.test_target_id}]
        call_count = [0]
        
        def fetchone_side_effect():
            result = fetchone_values[call_count[0]]
            call_count[0] += 1
            return result
        
        mock_cursor.fetchone = MagicMock(side_effect=fetchone_side_effect)
        mock_cursor.execute = MagicMock()
        
        mock_get_connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_get_connection.return_value.__exit__ = MagicMock(return_value=None)
        
        with patch.object(mock_conn, 'cursor', return_value=mock_cursor):
            result = self.storage.get_or_create_target(self.test_url, self.test_user_id)
        
        self.assertEqual(result, self.test_target_id)
        self.assertTrue(mock_conn.committed)
    
    @patch.object(ScanStorage, 'get_connection')
    def test_get_or_create_target_raises_on_error(self, mock_get_connection):
        """Test that method raises exception on database error."""
        mock_get_connection.return_value.__enter__ = MagicMock(
            side_effect=Exception("Database connection failed")
        )
        
        with self.assertRaises(Exception) as context:
            self.storage.get_or_create_target(self.test_url, self.test_user_id)
        
        self.assertIn("Database connection failed", str(context.exception))
    
    @patch.object(ScanStorage, 'get_connection')
    def test_get_or_create_target_includes_user_id_in_insert(self, mock_get_connection):
        """Test that user_id is included in the INSERT statement."""
        mock_cursor = MockCursor()
        mock_conn = MockConnection()
        
        # First call (SELECT) returns None, second call (INSERT) returns new ID
        fetchone_values = [None, {'id': self.test_target_id}]
        call_count = [0]
        
        def fetchone_side_effect():
            result = fetchone_values[call_count[0]]
            call_count[0] += 1
            return result
        
        mock_cursor.fetchone = MagicMock(side_effect=fetchone_side_effect)
        execute_calls = []
        
        def execute_side_effect(query, params=None):
            execute_calls.append((query, params))
            return mock_cursor
        
        mock_cursor.execute = MagicMock(side_effect=execute_side_effect)
        
        mock_get_connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_get_connection.return_value.__exit__ = MagicMock(return_value=None)
        
        with patch.object(mock_conn, 'cursor', return_value=mock_cursor):
            self.storage.get_or_create_target(self.test_url, self.test_user_id)
        
        # Verify user_id was included in INSERT call
        self.assertEqual(len(execute_calls), 2)
        insert_query, insert_params = execute_calls[1]
        self.assertIn("user_id", insert_query)
        self.assertIn(self.test_user_id, insert_params)
    
    @patch.object(ScanStorage, 'get_connection')
    def test_get_or_create_target_uses_domain_column(self, mock_get_connection):
        """Test that the query uses 'domain' column, not 'url'."""
        mock_cursor = MockCursor(fetchone_result={'id': self.test_target_id})
        mock_conn = MockConnection()
        
        execute_calls = []
        
        def execute_side_effect(query, params=None):
            execute_calls.append((query, params))
            return mock_cursor
        
        mock_cursor.execute = MagicMock(side_effect=execute_side_effect)
        
        mock_get_connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_get_connection.return_value.__exit__ = MagicMock(return_value=None)
        
        with patch.object(mock_conn, 'cursor', return_value=mock_cursor):
            result = self.storage.get_or_create_target(self.test_url, self.test_user_id)
        
        # Verify SELECT query uses 'domain' column
        select_query, select_params = execute_calls[0]
        self.assertIn("domain", select_query)
        self.assertNotIn("url", select_query)
        self.assertEqual(result, self.test_target_id)


if __name__ == "__main__":
    unittest.main()
