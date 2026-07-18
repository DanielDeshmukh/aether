import os
import sys
import uuid
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from dotenv import load_dotenv
load_dotenv(BACKEND_DIR.parent / ".env")

from app.services.storage import ScanStorage

def _has_required_tables() -> bool:
    storage = ScanStorage()
    if not storage.database_configured():
        return False
    try:
        with storage.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM information_schema.tables WHERE table_name IN ('users','scans') LIMIT 2")
                return cur.fetchone() is not None
    except Exception:
        return False


_HAS_DB = _has_required_tables()


def _needs_db(test_func):
    """Decorator to skip test when PostgreSQL is not available."""
    @unittest.skipUnless(_HAS_DB, "PostgreSQL not available — skipping integration test")
    def wrapper(self, *args, **kwargs):
        return test_func(self, *args, **kwargs)
    wrapper.__name__ = test_func.__name__
    return wrapper


class TestScanStorageGitTargetMethods(unittest.TestCase):
    def setUp(self):
        self.storage = ScanStorage()
        self.user_id = str(uuid.uuid4())

    def _create_target(self, domain: str) -> str:
        unique = f"{uuid.uuid4().hex[:8]}.{domain}"
        return self.storage.get_or_create_target(f"https://{unique}", self.user_id)

    @_needs_db
    def test_upsert_git_target(self):
        tid = self._create_target("upsert.com")
        result = self.storage.upsert_git_target(
            tid, self.user_id, "github", "ghp_test", "user/repo",
            default_branch="main", base_branch="develop",
        )
        self.assertTrue(result)

    def test_upsert_git_target_nonexistent(self):
        result = self.storage.upsert_git_target(
            str(uuid.uuid4()), self.user_id, "github", "ghp_test", "user/repo",
        )
        self.assertFalse(result)

    def test_list_git_targets_empty(self):
        targets = self.storage.list_git_targets(self.user_id)
        self.assertIsInstance(targets, list)

    @_needs_db
    def test_list_git_targets_after_upsert(self):
        tid = self._create_target("list.com")
        self.storage.upsert_git_target(tid, self.user_id, "gitlab", "glpat", "group/proj")
        targets = self.storage.list_git_targets(self.user_id)
        git_targets = [t for t in targets if t.get("git_provider") == "gitlab"]
        self.assertTrue(len(git_targets) >= 1)

    @_needs_db
    def test_delete_git_target(self):
        tid = self._create_target("delete.com")
        self.storage.upsert_git_target(tid, self.user_id, "github", "ghp_x", "u/r")
        result = self.storage.delete_git_target(tid, self.user_id)
        self.assertTrue(result)

    def test_delete_git_target_nonexistent(self):
        result = self.storage.delete_git_target(str(uuid.uuid4()), self.user_id)
        self.assertFalse(result)

    @_needs_db
    def test_fetch_git_target(self):
        tid = self._create_target("fetch.com")
        self.storage.upsert_git_target(tid, self.user_id, "github", "ghp_tok", "u/r")
        target = self.storage.fetch_git_target(tid, self.user_id)
        self.assertIsNotNone(target)
        self.assertEqual(target["provider"], "github")
        self.assertEqual(target["repository"], "u/r")

    @_needs_db
    def test_resolve_git_target_for_url(self):
        tid = self._create_target("resolve.com")
        self.storage.upsert_git_target(tid, self.user_id, "github", "ghp_tok", "u/r")
        target = self.storage.resolve_git_target_for_url("https://resolve.com/page", self.user_id)
        self.assertIsNotNone(target)
        self.assertEqual(target["provider"], "github")

    def test_resolve_git_target_not_found(self):
        target = self.storage.resolve_git_target_for_url("https://nonexistent999.com", self.user_id)
        self.assertIsNone(target)


class TestScanStorageVulnerabilityMethods(unittest.TestCase):
    def setUp(self):
        self.storage = ScanStorage()

    @_needs_db
    def test_fetch_vulnerabilities_empty(self):
        vulns = self.storage.fetch_vulnerabilities(str(uuid.uuid4()), user_id=str(uuid.uuid4()))
        self.assertIsInstance(vulns, list)
        self.assertEqual(len(vulns), 0)


class TestScanStorageRemediationMethods(unittest.TestCase):
    def setUp(self):
        self.storage = ScanStorage()

    @_needs_db
    def test_save_remediations_nonexistent_scan_returns_false(self):
        result = self.storage.save_remediations(
            scan_id=str(uuid.uuid4()), user_id=str(uuid.uuid4()), remediations={"v1": {}},
        )
        self.assertFalse(result)

    @_needs_db
    def test_save_final_report_nonexistent_scan_returns_false(self):
        result = self.storage.save_final_report(
            scan_id=str(uuid.uuid4()), user_id=str(uuid.uuid4()), final_report={"risk": "low"},
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
