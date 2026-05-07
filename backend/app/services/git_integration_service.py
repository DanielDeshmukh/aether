import base64
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict
from urllib.parse import quote

import requests


def _slugify(value: str) -> str:
    lowered = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return lowered or "remediation"


@dataclass
class GitTargetConfig:
    id: str
    provider: str
    access_token: str
    repository: str | None = None
    project_id: str | None = None
    default_branch: str | None = None
    base_branch: str | None = None
    api_base_url: str | None = None
    repo_web_url: str | None = None


class GitProvider(ABC):
    provider_name = "git"

    def __init__(self, target: GitTargetConfig) -> None:
        self.target = target

    def _request(self, method: str, url: str, **kwargs: Any) -> Dict[str, Any]:
        response = requests.request(method=method, url=url, timeout=30, **kwargs)
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()

    def _branch_name(self, remediation_payload: Dict[str, Any]) -> str:
        vuln_id = str(remediation_payload.get("vuln_id") or remediation_payload.get("finding_id") or "finding")
        return f"aether/remediation/{_slugify(vuln_id)}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    def _file_path(self, remediation_payload: Dict[str, Any]) -> str:
        vuln_id = str(remediation_payload.get("vuln_id") or remediation_payload.get("finding_id") or "finding")
        return f"aether-remediations/{_slugify(vuln_id)}.md"

    def _file_contents(self, remediation_payload: Dict[str, Any], pr_body: str) -> str:
        title = remediation_payload.get("title") or remediation_payload.get("finding_title") or "Generated remediation"
        return (
            f"# {title}\n\n"
            f"{pr_body}\n"
        )

    def _pr_body(self, remediation_payload: Dict[str, Any]) -> str:
        screenshot_url = remediation_payload.get("playwright_screenshot_url") or "Not available"
        evidence_snippet = remediation_payload.get("evidence_snippet") or "No evidence snippet captured."
        target_url = remediation_payload.get("target_url") or "Unknown target"
        vulnerable_code_analysis = remediation_payload.get("vulnerable_code_analysis") or "No vulnerable code analysis supplied."
        secure_refactor = remediation_payload.get("secure_refactor") or "No secure refactor supplied."
        summary = remediation_payload.get("summary") or "No summary supplied."

        return (
            "## AETHER Auto-Remediation Package\n\n"
            f"- Target: `{target_url}`\n"
            f"- Finding ID: `{remediation_payload.get('vuln_id') or remediation_payload.get('finding_id') or 'unknown'}`\n"
            f"- Evidence: {evidence_snippet}\n"
            f"- Playwright Screenshot: {screenshot_url}\n\n"
            "## Vulnerable Code Analysis\n\n"
            f"{vulnerable_code_analysis}\n\n"
            "## Secure Refactor\n\n"
            f"```{remediation_payload.get('language') or 'text'}\n{secure_refactor}\n```\n\n"
            "## Summary\n\n"
            f"{summary}\n"
        )

    @abstractmethod
    def stage_remediation_pr(self, remediation_payload: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class GitHubProvider(GitProvider):
    provider_name = "github"

    def stage_remediation_pr(self, remediation_payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.target.repository:
            raise ValueError("GitHub remediation target is missing repository.")

        api_base = (self.target.api_base_url or "https://api.github.com").rstrip("/")
        headers = {
            "Authorization": f"Bearer {self.target.access_token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        }
        repo_meta = self._request("GET", f"{api_base}/repos/{self.target.repository}", headers=headers)
        base_branch = self.target.base_branch or self.target.default_branch or repo_meta.get("default_branch") or "main"
        ref_meta = self._request("GET", f"{api_base}/repos/{self.target.repository}/git/ref/heads/{base_branch}", headers=headers)
        branch_name = self._branch_name(remediation_payload)
        self._request(
            "POST",
            f"{api_base}/repos/{self.target.repository}/git/refs",
            headers=headers,
            json={"ref": f"refs/heads/{branch_name}", "sha": ref_meta["object"]["sha"]},
        )

        pr_body = self._pr_body(remediation_payload)
        self._request(
            "PUT",
            f"{api_base}/repos/{self.target.repository}/contents/{self._file_path(remediation_payload)}",
            headers=headers,
            json={
                "message": f"Add remediation package for {remediation_payload.get('title') or remediation_payload.get('vuln_id')}",
                "content": base64.b64encode(self._file_contents(remediation_payload, pr_body).encode("utf-8")).decode("ascii"),
                "branch": branch_name,
            },
        )
        pr_response = self._request(
            "POST",
            f"{api_base}/repos/{self.target.repository}/pulls",
            headers=headers,
            json={
                "title": f"AETHER remediation: {remediation_payload.get('title') or remediation_payload.get('vuln_id')}",
                "body": pr_body,
                "head": branch_name,
                "base": base_branch,
            },
        )
        return {
            "provider": self.provider_name,
            "target_id": self.target.id,
            "repository": self.target.repository,
            "branch": branch_name,
            "base_branch": base_branch,
            "pull_request_url": pr_response.get("html_url"),
            "pull_request_number": pr_response.get("number"),
        }


class GitLabProvider(GitProvider):
    provider_name = "gitlab"

    def stage_remediation_pr(self, remediation_payload: Dict[str, Any]) -> Dict[str, Any]:
        project_id = self.target.project_id or self.target.repository
        if not project_id:
            raise ValueError("GitLab remediation target is missing project_id or repository.")

        api_base = (self.target.api_base_url or "https://gitlab.com/api/v4").rstrip("/")
        headers = {
            "PRIVATE-TOKEN": self.target.access_token,
        }
        encoded_project = quote(project_id, safe="")
        project_meta = self._request("GET", f"{api_base}/projects/{encoded_project}", headers=headers)
        base_branch = self.target.base_branch or self.target.default_branch or project_meta.get("default_branch") or "main"
        branch_name = self._branch_name(remediation_payload)
        self._request(
            "POST",
            f"{api_base}/projects/{encoded_project}/repository/branches",
            headers=headers,
            params={"branch": branch_name, "ref": base_branch},
        )

        pr_body = self._pr_body(remediation_payload)
        self._request(
            "POST",
            f"{api_base}/projects/{encoded_project}/repository/files/{quote(self._file_path(remediation_payload), safe='')}",
            headers=headers,
            json={
                "branch": branch_name,
                "content": self._file_contents(remediation_payload, pr_body),
                "commit_message": f"Add remediation package for {remediation_payload.get('title') or remediation_payload.get('vuln_id')}",
            },
        )
        mr_response = self._request(
            "POST",
            f"{api_base}/projects/{encoded_project}/merge_requests",
            headers=headers,
            json={
                "title": f"AETHER remediation: {remediation_payload.get('title') or remediation_payload.get('vuln_id')}",
                "description": pr_body,
                "source_branch": branch_name,
                "target_branch": base_branch,
            },
        )
        return {
            "provider": self.provider_name,
            "target_id": self.target.id,
            "repository": self.target.repository or project_id,
            "branch": branch_name,
            "base_branch": base_branch,
            "pull_request_url": mr_response.get("web_url"),
            "pull_request_number": mr_response.get("iid"),
        }


class GitIntegrationService:
    def __init__(self, storage: Any) -> None:
        self.storage = storage
        self.public_api_base_url = (
            os.getenv("AETHER_PUBLIC_API_URL", "").strip().rstrip("/")
            or os.getenv("VITE_API_URL", "").strip().rstrip("/")
            or os.getenv("FRONTEND_URL", "").strip().rstrip("/")
        )

    def _provider_for_target(self, target: Dict[str, Any]) -> GitProvider:
        config = GitTargetConfig(
            id=str(target["id"]),
            provider=str(target["provider"]).strip().lower(),
            access_token=str(target["access_token"]),
            repository=target.get("repository"),
            project_id=target.get("project_id"),
            default_branch=target.get("default_branch"),
            base_branch=target.get("base_branch"),
            api_base_url=target.get("api_base_url"),
            repo_web_url=target.get("repo_web_url"),
        )
        if config.provider == "github":
            return GitHubProvider(config)
        if config.provider == "gitlab":
            return GitLabProvider(config)
        raise ValueError(f"Unsupported git provider: {config.provider}")

    def build_git_summary(self, target_url: str, user_id: str | None, has_remediations: bool) -> Dict[str, Any]:
        target = self.storage.resolve_git_target_for_url(target_url=target_url, user_id=user_id) if user_id else None
        if not target:
            return {
                "pr_ready": False,
                "action_label": "Create Pull Request",
                "reason": "No git remediation target is configured for this verified asset.",
            }

        provider = str(target.get("provider") or "").lower()
        repository = target.get("repository") or target.get("project_id")
        token_present = bool(target.get("access_token"))
        return {
            "pr_ready": bool(has_remediations and provider and repository and token_present),
            "action_label": "Create Pull Request",
            "target_id": str(target.get("id")),
            "provider": provider,
            "repository": repository,
            "repository_url": target.get("repo_web_url"),
            "reason": None if has_remediations and token_present else "Generate or persist a remediation package before opening a PR.",
        }

    def build_screenshot_url(self, scan_id: str, vuln_id: str, public_api_base_url: str | None = None) -> str | None:
        base_url = (public_api_base_url or self.public_api_base_url or "").rstrip("/")
        if not base_url:
            return None
        return f"{base_url}/api/v1/scans/{scan_id}/vulnerabilities/{quote(vuln_id, safe='')}/evidence/screenshot"

    def build_pr_payload(
        self,
        *,
        scan_id: str,
        target_url: str,
        vulnerability: Dict[str, Any],
        remediation_payload: Dict[str, Any],
        public_api_base_url: str | None = None,
    ) -> Dict[str, Any]:
        payload = dict(remediation_payload)
        payload["finding_id"] = vulnerability.get("id")
        payload["finding_title"] = vulnerability.get("title")
        payload["evidence_snippet"] = vulnerability.get("evidence_snippet") or remediation_payload.get("summary")
        payload["target_url"] = target_url
        payload["playwright_screenshot_url"] = self.build_screenshot_url(
            scan_id,
            str(vulnerability.get("id") or remediation_payload.get("vuln_id") or ""),
            public_api_base_url=public_api_base_url,
        )
        return payload

    def stage_remediation_pr(self, target_id: str, remediation_payload: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        target = self.storage.fetch_git_target(target_id=target_id, user_id=user_id)
        if not target:
            raise ValueError("Configured git remediation target could not be found.")
        provider = self._provider_for_target(target)
        return provider.stage_remediation_pr(remediation_payload)
