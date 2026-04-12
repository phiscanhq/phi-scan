"""Bitbucket Pipelines CI adapter.

Posts PR comments and sets commit build statuses via the Bitbucket
Cloud REST API. Uses ``BITBUCKET_TOKEN`` for authentication.
"""

from __future__ import annotations

import logging
from typing import Any

from phi_scan.ci._base import BaseCIAdapter, SanitisedCommentBody
from phi_scan.ci._detect import PullRequestContext
from phi_scan.ci._env import fetch_environment_variable
from phi_scan.ci._transport import (
    HttpMethod,
    HttpRequestConfig,
    OperationLabel,
    execute_http_request,
)
from phi_scan.models import ScanResult

_LOG: logging.Logger = logging.getLogger(__name__)

_ENV_BITBUCKET_TOKEN: str = "BITBUCKET_TOKEN"

_BITBUCKET_API_BASE_URL: str = "https://api.bitbucket.org/2.0"
_BITBUCKET_PR_COMMENTS_PATH: str = (
    "/repositories/{workspace}/{repo_slug}/pullrequests/{pull_request_identifier}/comments"
)
_BITBUCKET_COMMIT_STATUS_PATH: str = (
    "/repositories/{workspace}/{repo_slug}/commit/{commit}/statuses/build"
)

_HTTP_HEADER_AUTHORIZATION: str = "Authorization"
_HTTP_HEADER_CONTENT_TYPE: str = "Content-Type"
_JSON_CONTENT_TYPE: str = "application/json"
_BITBUCKET_COMMENT_CONTENT_KEY: str = "content"
_BITBUCKET_COMMENT_RAW_KEY: str = "raw"
_COMMIT_STATUS_CONTEXT: str = "phi-scan"
_COMMIT_STATUS_DESCRIPTION_CLEAN: str = "No PHI/PII violations found"
_COMMIT_STATUS_DESCRIPTION_VIOLATIONS: str = "{count} PHI/PII violation(s) found"
_BITBUCKET_STATUS_SUCCESSFUL: str = "SUCCESSFUL"
_BITBUCKET_STATUS_FAILED: str = "FAILED"
_SHA_LOG_PREFIX_LENGTH: int = 8


def _build_auth_headers(token: str) -> dict[str, str]:
    return {
        _HTTP_HEADER_AUTHORIZATION: f"Bearer {token}",
        _HTTP_HEADER_CONTENT_TYPE: _JSON_CONTENT_TYPE,
    }


def _build_commit_status_payload(scan_result: ScanResult) -> dict[str, Any]:
    commit_build_state = (
        _BITBUCKET_STATUS_SUCCESSFUL if scan_result.is_clean else _BITBUCKET_STATUS_FAILED
    )
    return {
        "key": _COMMIT_STATUS_CONTEXT,
        "state": commit_build_state,
        "name": _COMMIT_STATUS_CONTEXT,
        "description": (
            _COMMIT_STATUS_DESCRIPTION_CLEAN
            if scan_result.is_clean
            else _COMMIT_STATUS_DESCRIPTION_VIOLATIONS.format(count=len(scan_result.findings))
        ),
    }


class BitbucketAdapter(BaseCIAdapter):
    """Bitbucket Cloud adapter using the Bitbucket REST API."""

    @property
    def can_annotate_code_findings(self) -> bool:
        return True

    def post_pull_request_comment(
        self, comment_body: SanitisedCommentBody, pull_request_context: PullRequestContext
    ) -> None:
        pull_request_identifier = pull_request_context.pull_request_number
        workspace = pull_request_context.extras.get("workspace", "")
        repo_slug = pull_request_context.repository or ""

        if not all((pull_request_identifier, workspace, repo_slug)):
            _LOG.warning("Bitbucket: missing PR context — skipping comment")
            return

        bitbucket_token = fetch_environment_variable(_ENV_BITBUCKET_TOKEN)
        if not bitbucket_token:
            _LOG.warning("Bitbucket: BITBUCKET_TOKEN not set — skipping comment")
            return

        url = _BITBUCKET_API_BASE_URL + _BITBUCKET_PR_COMMENTS_PATH.format(
            workspace=workspace,
            repo_slug=repo_slug,
            pull_request_identifier=pull_request_identifier,
        )
        execute_http_request(
            HttpRequestConfig(
                method=HttpMethod.POST,
                url=url,
                operation_label=OperationLabel.BITBUCKET_PR_COMMENT,
                headers=_build_auth_headers(bitbucket_token),
                json_body={
                    _BITBUCKET_COMMENT_CONTENT_KEY: {_BITBUCKET_COMMENT_RAW_KEY: comment_body},
                },
            )
        )
        _LOG.debug("Bitbucket: PR comment posted to PR #%s", pull_request_identifier)

    def set_commit_status(
        self, scan_result: ScanResult, pull_request_context: PullRequestContext
    ) -> None:
        sha = pull_request_context.sha
        workspace = pull_request_context.extras.get("workspace", "")
        repo_slug = pull_request_context.repository or ""
        if not sha or not workspace or not repo_slug:
            _LOG.warning("Bitbucket: missing context — skipping commit status")
            return

        bitbucket_token = fetch_environment_variable(_ENV_BITBUCKET_TOKEN)
        if not bitbucket_token:
            _LOG.warning("Bitbucket: BITBUCKET_TOKEN not set — skipping commit status")
            return

        url = _BITBUCKET_API_BASE_URL + _BITBUCKET_COMMIT_STATUS_PATH.format(
            workspace=workspace,
            repo_slug=repo_slug,
            commit=sha,
        )
        execute_http_request(
            HttpRequestConfig(
                method=HttpMethod.POST,
                url=url,
                operation_label=OperationLabel.BITBUCKET_COMMIT_STATUS,
                headers=_build_auth_headers(bitbucket_token),
                json_body=_build_commit_status_payload(scan_result),
            )
        )
        sha_prefix = sha[:_SHA_LOG_PREFIX_LENGTH]
        _LOG.debug("Bitbucket: commit status set to %s for %s", scan_result.is_clean, sha_prefix)
