"""GitHub Actions CI adapter.

Posts PR comments via the ``gh`` CLI and sets commit statuses via the
GitHub REST API. Uses ``GITHUB_TOKEN`` from the environment for auth.
"""

from __future__ import annotations

import logging
import os
import subprocess

from phi_scan.ci._base import BaseCIAdapter, SanitisedCommentBody
from phi_scan.ci._detect import PullRequestContext
from phi_scan.ci._env import fetch_environment_variable
from phi_scan.ci._transport import (
    HttpMethod,
    HttpRequestConfig,
    OperationLabel,
    execute_http_request,
)
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

_HTTP_HEADER_AUTHORIZATION: str = "Authorization"
_HTTP_HEADER_ACCEPT: str = "Accept"
_GITHUB_ACCEPT_HEADER_VALUE: str = "application/vnd.github+json"
_GITHUB_API_VERSION_HEADER: str = "X-GitHub-Api-Version"
_GITHUB_API_VERSION_VALUE: str = "2022-11-28"
_GITHUB_STATUS_SUCCESS: str = "success"
_GITHUB_STATUS_FAILURE: str = "failure"


class GitHubAdapter(BaseCIAdapter):
    """GitHub Actions adapter using ``gh`` CLI for comments and REST API for statuses."""

    @property
    def can_upload_sarif_report(self) -> bool:
        return True

    def post_pull_request_comment(
        self, comment_body: SanitisedCommentBody, pull_request_context: PullRequestContext
    ) -> None:
        pull_request_number = pull_request_context.pull_request_number
        if not pull_request_number:
            _LOG.warning("GitHub: no PR number — skipping comment")
            return

        github_token = fetch_environment_variable(_ENV_GITHUB_TOKEN)
        if not github_token:
            _LOG.warning("GitHub: GITHUB_TOKEN not set — skipping comment")
            return

        env = {**os.environ, "GITHUB_TOKEN": github_token}
        if pull_request_context.repository:
            env["GH_REPO"] = pull_request_context.repository

        try:
            gh_result = subprocess.run(
                [
                    "gh",
                    "pr",
                    "comment",
                    str(pull_request_number),
                    "--body",
                    comment_body,
                    "--edit-last",
                ],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            if gh_result.returncode != 0:
                gh_result = subprocess.run(
                    ["gh", "pr", "comment", str(pull_request_number), "--body", comment_body],
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

        _LOG.debug("GitHub: PR comment posted to #%s", pull_request_number)

    def set_commit_status(
        self, scan_result: ScanResult, pull_request_context: PullRequestContext
    ) -> None:
        sha = pull_request_context.sha
        repository = pull_request_context.repository
        if not sha or not repository:
            _LOG.warning("GitHub: missing SHA or repository — skipping status")
            return

        github_token = fetch_environment_variable(_ENV_GITHUB_TOKEN)
        if not github_token:
            _LOG.warning("GitHub: GITHUB_TOKEN not set — skipping commit status")
            return

        github_state = _GITHUB_STATUS_SUCCESS if scan_result.is_clean else _GITHUB_STATUS_FAILURE
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
                operation_label=OperationLabel.GITHUB_COMMIT_STATUS,
                headers={
                    _HTTP_HEADER_AUTHORIZATION: f"Bearer {github_token}",
                    _HTTP_HEADER_ACCEPT: _GITHUB_ACCEPT_HEADER_VALUE,
                    _GITHUB_API_VERSION_HEADER: _GITHUB_API_VERSION_VALUE,
                },
                json_body=payload,
            )
        )

        sha_prefix = sha[:_SHA_LOG_PREFIX_LENGTH]
        _LOG.debug("GitHub: commit status set to %s for %s", github_state, sha_prefix)
