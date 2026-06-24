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


class TestScanStorageGitTargetMethods(unittest.TestCase):
    def setUp(self):
        from app.services.storage import ScanStorage
        self.storage = ScanStorage()
        self.user_id = str(uuid.uuid4())

    def _create_target(self, domain: str) -> str:
        unique = f"{uuid.uuid4().hex[:8]}.{domain}"
        return self.storage.get_or_create_target(f"https://{unique}", self.user_id)

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

    def test_list_git_targets_after_upsert(self):
        tid = self._create_target("list.com")
        self.storage.upsert_git_target(tid, self.user_id, "gitlab", "glpat", "group/proj")
        targets = self.storage.list_git_targets(self.user_id)
        git_targets = [t for t in targets if t.get("git_provider") == "gitlab"]
        self.assertTrue(len(git_targets) >= 1)

    def test_delete_git_target(self):
        tid = self._create_target("delete.com")
        self.storage.upsert_git_target(tid, self.user_id, "github", "ghp_x", "u/r")
        result = self.storage.delete_git_target(tid, self.user_id)
        self.assertTrue(result)

    def test_delete_git_target_nonexistent(self):
        result = self.storage.delete_git_target(str(uuid.uuid4()), self.user_id)
        self.assertFalse(result)

    def test_fetch_git_target(self):
        tid = self._create_target("fetch.com")
        self.storage.upsert_git_target(tid, self.user_id, "github", "ghp_tok", "u/r")
        target = self.storage.fetch_git_target(tid, self.user_id)
        self.assertIsNotNone(target)
        self.assertEqual(target["provider"], "github")
        self.assertEqual(target["repository"], "u/r")

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
        from app.services.storage import ScanStorage
        self.storage = ScanStorage()

    def test_fetch_vulnerabilities_empty(self):
        vulns = self.storage.fetch_vulnerabilities(str(uuid.uuid4()), user_id=str(uuid.uuid4()))
        self.assertIsInstance(vulns, list)
        self.assertEqual(len(vulns), 0)


class TestScanStorageRemediationMethods(unittest.TestCase):
    def setUp(self):
        from app.services.storage import ScanStorage
        self.storage = ScanStorage()

    def test_save_remediations_nonexistent_scan_returns_false(self):
        result = self.storage.save_remediations(
            scan_id=str(uuid.uuid4()), user_id=str(uuid.uuid4()), remediations={"v1": {}},
        )
        self.assertFalse(result)

    def test_save_final_report_nonexistent_scan_returns_false(self):
        result = self.storage.save_final_report(
            scan_id=str(uuid.uuid4()), user_id=str(uuid.uuid4()), final_report={"risk": "low"},
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
