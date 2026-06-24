import os
import sys
import uuid
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.api import main as api_main
from app.services.auth import create_access_token


class TestGitTargetEndpoints(unittest.TestCase):
    def setUp(self) -> None:
        api_main.active_scans.clear()
        api_main.brain_sessions.clear()
        self.client = TestClient(api_main.app)
        self.user_id = str(uuid.uuid4())

    def tearDown(self) -> None:
        api_main.active_scans.clear()
        api_main.brain_sessions.clear()

    def _auth_headers(self) -> dict:
        token = create_access_token(self.user_id, f"{self.user_id}@test.com")
        return {"Authorization": f"Bearer {token}"}

    def _create_target_via_storage(self, domain: str) -> str:
        unique_domain = f"{uuid.uuid4().hex[:8]}.{domain}"
        storage = api_main.scan_storage
        target_id = storage.get_or_create_target(
            target_url=f"https://{unique_domain}",
            user_id=self.user_id,
        )
        return target_id

    def test_list_git_targets_empty(self) -> None:
        resp = self.client.get("/api/v1/git-targets", headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("data", data)
        self.assertIsInstance(data["data"]["targets"], list)

    def test_list_git_targets_requires_auth(self) -> None:
        resp = self.client.get("/api/v1/git-targets")
        self.assertEqual(resp.status_code, 401)

    def test_create_git_target(self) -> None:
        target_id = self._create_target_via_storage("example.com")
        resp = self.client.post(
            "/api/v1/git-targets",
            json={
                "target_id": target_id,
                "git_provider": "github",
                "access_token": "ghp_test123",
                "repository": "user/repo",
                "default_branch": "main",
            },
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("data", data)
        self.assertEqual(data["data"]["target_id"], target_id)

    def test_create_git_target_invalid_provider(self) -> None:
        target_id = self._create_target_via_storage("example2.com")
        resp = self.client.post(
            "/api/v1/git-targets",
            json={
                "target_id": target_id,
                "git_provider": "bitbucket",
                "access_token": "token",
                "repository": "user/repo",
            },
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 422)

    def test_create_git_target_nonexistent(self) -> None:
        fake_id = str(uuid.uuid4())
        resp = self.client.post(
            "/api/v1/git-targets",
            json={
                "target_id": fake_id,
                "git_provider": "github",
                "access_token": "ghp_test123",
                "repository": "user/repo",
            },
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 404)

    def test_list_git_targets_after_create(self) -> None:
        target_id = self._create_target_via_storage("listed.com")
        self.client.post(
            "/api/v1/git-targets",
            json={
                "target_id": target_id,
                "git_provider": "gitlab",
                "access_token": "glpat-test",
                "repository": "group/project",
                "project_id": "12345",
            },
            headers=self._auth_headers(),
        )
        resp = self.client.get("/api/v1/git-targets", headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        targets = resp.json()["data"]["targets"]
        self.assertTrue(len(targets) >= 1)
        git_targets = [t for t in targets if t.get("git_provider") == "gitlab"]
        self.assertTrue(len(git_targets) >= 1)

    def test_delete_git_target(self) -> None:
        target_id = self._create_target_via_storage("deleteme.com")
        self.client.post(
            "/api/v1/git-targets",
            json={
                "target_id": target_id,
                "git_provider": "github",
                "access_token": "ghp_test",
                "repository": "user/repo",
            },
            headers=self._auth_headers(),
        )
        resp = self.client.delete(f"/api/v1/git-targets/{target_id}", headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)

    def test_delete_nonexistent_target(self) -> None:
        fake_id = str(uuid.uuid4())
        resp = self.client.delete(f"/api/v1/git-targets/{fake_id}", headers=self._auth_headers())
        self.assertEqual(resp.status_code, 404)

    def test_update_git_target(self) -> None:
        target_id = self._create_target_via_storage("update.com")
        self.client.post(
            "/api/v1/git-targets",
            json={
                "target_id": target_id,
                "git_provider": "github",
                "access_token": "old_token",
                "repository": "user/old-repo",
            },
            headers=self._auth_headers(),
        )
        resp = self.client.post(
            "/api/v1/git-targets",
            json={
                "target_id": target_id,
                "git_provider": "github",
                "access_token": "new_token",
                "repository": "user/new-repo",
                "default_branch": "develop",
            },
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 200)

        targets_resp = self.client.get("/api/v1/git-targets", headers=self._auth_headers())
        targets = targets_resp.json()["data"]["targets"]
        updated = [t for t in targets if t["id"] == target_id]
        self.assertEqual(len(updated), 1)
        self.assertEqual(updated[0]["repository"], "user/new-repo")
        self.assertEqual(updated[0]["default_branch"], "develop")


if __name__ == "__main__":
    unittest.main()
