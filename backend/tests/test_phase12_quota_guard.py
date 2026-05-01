import asyncio
import unittest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.api import deps
from app.services.storage import ScanStorage


class _DummyTransaction:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _DummyConnection:
    def transaction(self):
        return _DummyTransaction()

    def cursor(self):
        return MagicMock()


class _DummyConnectionContext:
    def __enter__(self):
        return _DummyConnection()

    def __exit__(self, exc_type, exc, tb):
        return False


class TestPhase12QuotaGuard(unittest.TestCase):
    def test_check_scan_quota_allows_under_limit(self):
        with patch.object(deps.scan_storage, "get_total_scan_count", return_value=2):
            user_id = "a7988ba7-c5f5-4ad1-a35d-6814f75c6bf4"
            resolved_user = asyncio.run(deps.check_scan_quota(user_id))
            self.assertEqual(resolved_user, user_id)

    def test_check_scan_quota_blocks_at_limit(self):
        with patch.object(deps.scan_storage, "get_total_scan_count", return_value=3):
            with self.assertRaises(HTTPException) as context:
                asyncio.run(deps.check_scan_quota("a7988ba7-c5f5-4ad1-a35d-6814f75c6bf4"))
            self.assertEqual(context.exception.status_code, 403)
            self.assertEqual(
                context.exception.detail,
                "AETHER MVP Limit Reached: 3/3 scans used. Contact DevLabs for access.",
            )

    def test_log_consent_persists_origin_ip(self):
        storage = ScanStorage()
        storage.get_connection = MagicMock(return_value=_DummyConnectionContext())
        storage.safe_insert = MagicMock(return_value=1)

        user_id = "a7988ba7-c5f5-4ad1-a35d-6814f75c6bf4"
        target_url = "https://example.com"
        origin_ip = "203.0.113.8"

        persisted = storage.log_consent(
            user_id=user_id,
            target_url=target_url,
            origin_ip=origin_ip,
        )

        self.assertTrue(persisted)
        rows = storage.safe_insert.call_args.args[2]
        self.assertEqual(rows[0]["ip_address"], origin_ip)


if __name__ == "__main__":
    unittest.main()
