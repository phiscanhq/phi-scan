"""GitHub Actions CI adapter.

Posts PR comments via the ``gh`` CLI and sets commit statuses via the
GitHub REST API. Uses ``GITHUB_TOKEN`` from the environment for auth.
"""

from __future__ import annotations

import logging
import os
import subprocess

from phi_scan.ci._base import BaseCIAdapter
from phi_scan.ci._detect import PRContext, fetch_env_variable
from phi_scan.ci._transport import HttpMethod, HttpRequestConfig, execute_http_request
from phi_scan.exceptions import CIIntegrationError
from phi_scan.models import ScanResult

_LOG: logging.Logger = logging.getLogger(__name__)

_ENV_GITHUB_TOKEN: str = "GITHUB_TOKEN"

_GITHUB_API_BASE_URL: str = "https://api.github.com"
_GITHUB_API_COMMIT_STATUSES_PATH: str = "/repos/{repository}/statuses/{sha}"

_COMMIT_STATUS_CONTEXT: str = "phi-scan"
_COMMIT_STATUS_DESCRIPTION_CLEAN: str = "No PHI/PII violations found"
_COMMIT_STATUS_DESCRIPTION_VIOLATIONS: str = "{count} PHI/PII violation(s) found"

_MAX_ERROR_RESPONSE_LOG_LENGTH: int = 200
_SHA_LOG_PREFIX_LENGTH: int = 8


class GitHubAdapter(BaseCIAdapter):
    """GitHub Actions adapter using ``gh`` CLI for comments and REST API for statuses."""

    @property
    def supports_sarif_upload(self) -> bool:
        return True

    def post_pr_comment(self, comment_body: str, pr_context: PRContext) -> None:
        pr_number = pr_context.pr_number
        if not pr_number:
            _LOG.debug("GitHub: no PR number — skipping comment")
            return

        token = fetch_env_variable(_ENV_GITHUB_TOKEN)
        if not token:
            _LOG.warning("GitHub: GITHUB_TOKEN not set — skipping comment")
            return

        env = {**os.environ, "GITHUB_TOKEN": token}
        if pr_context.repository:
            env["GH_REPO"] = pr_context.repository

        try:
            gh_result = subprocess.run(
                ["gh", "pr", "comment", str(pr_number), "--body", comment_body, "--edit-last"],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            if gh_result.returncode != 0:
                gh_result = subprocess.run(
                    ["gh", "pr", "comment", str(pr_number), "--body", comment_body],
                    capture_output=True,
                    text=True,
                    env=env,
                    check=False,
                )
            if gh_result.returncode != 0:
                raise CIIntegrationError(
                    f"gh pr comment failed (exit {gh_result.returncode}): "
                    f"{gh_result.stderr.strip()[:_MAX_ERROR_RESPONSE_LOG_LENGTH]}"
                )
        except FileNotFoundError as not_found_error:
            raise CIIntegrationError(
                "gh CLI not found — install the GitHub CLI to enable PR comment posting"
            ) from not_found_error

        _LOG.debug("GitHub: PR comment posted to #%s", pr_number)

    def set_commit_status(self, scan_result: ScanResult, pr_context: PRContext) -> None:
        sha = pr_context.sha
        repository = pr_context.repository
        if not sha or not repository:
            _LOG.debug("GitHub: missing SHA or repository — skipping status")
            return

        token = fetch_env_variable(_ENV_GITHUB_TOKEN)
        if not token:
            _LOG.warning("GitHub: GITHUB_TOKEN not set — skipping commit status")
            return

        github_state = "success" if scan_result.is_clean else "failure"
        findings_count = len(scan_result.findings)
        description = (
            _COMMIT_STATUS_DESCRIPTION_CLEAN
            if scan_result.is_clean
            else _COMMIT_STATUS_DESCRIPTION_VIOLATIONS.format(count=findings_count)
        )

        url = _GITHUB_API_BASE_URL + _GITHUB_API_COMMIT_STATUSES_PATH.format(
            repository=repository,
            sha=sha,
        )
        payload = {
            "state": github_state,
            "description": description,
            "context": _COMMIT_STATUS_CONTEXT,
        }

        execute_http_request(
            HttpRequestConfig(
                method=HttpMethod.POST,
                url=url,
                operation_label="GitHub commit status",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json_body=payload,
            )
        )

        sha_prefix = sha[:_SHA_LOG_PREFIX_LENGTH]
        _LOG.debug("GitHub: commit status set to %s for %s", github_state, sha_prefix)
