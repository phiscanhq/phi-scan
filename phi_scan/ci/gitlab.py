"""GitLab CI adapter.

Posts MR notes and sets commit statuses via the GitLab REST API.
Uses ``GITLAB_TOKEN`` or ``CI_JOB_TOKEN`` for authentication.
"""

from __future__ import annotations

import logging

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

_ENV_GITLAB_TOKEN: str = "GITLAB_TOKEN"
_ENV_CI_JOB_TOKEN: str = "CI_JOB_TOKEN"

_GITLAB_DEFAULT_SERVER_URL: str = "https://gitlab.com"
_GITLAB_API_MR_NOTES_PATH: str = "/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
_GITLAB_API_COMMIT_STATUSES_PATH: str = "/api/v4/projects/{project_id}/statuses/{sha}"

_HTTP_HEADER_PRIVATE_TOKEN: str = "PRIVATE-TOKEN"
_HTTP_HEADER_CONTENT_TYPE: str = "Content-Type"
_JSON_CONTENT_TYPE: str = "application/json"
_COMMIT_STATUS_CONTEXT: str = "phi-scan"
_GITLAB_STATUS_SUCCESS: str = "success"
_GITLAB_STATUS_FAILED: str = "failed"
_COMMIT_STATUS_DESCRIPTION_CLEAN: str = "No PHI/PII violations found"
_COMMIT_STATUS_DESCRIPTION_VIOLATIONS: str = "{count} PHI/PII violation(s) found"
_SHA_LOG_PREFIX_LENGTH: int = 8


class GitLabAdapter(BaseCIAdapter):
    """GitLab CI adapter using the GitLab REST API."""

    def post_pull_request_comment(
        self, comment_body: SanitisedCommentBody, pull_request_context: PullRequestContext
    ) -> None:
        mr_iid = pull_request_context.pull_request_number
        project_id = pull_request_context.repository
        if not mr_iid or not project_id:
            _LOG.warning("GitLab: missing MR IID or project ID — skipping comment")
            return

        gitlab_token = fetch_environment_variable(_ENV_GITLAB_TOKEN) or fetch_environment_variable(
            _ENV_CI_JOB_TOKEN
        )
        if not gitlab_token:
            _LOG.warning("GitLab: GITLAB_TOKEN and CI_JOB_TOKEN not set — skipping comment")
            return

        server_url = pull_request_context.extras.get("ci_server_url") or _GITLAB_DEFAULT_SERVER_URL
        url = server_url.rstrip("/") + _GITLAB_API_MR_NOTES_PATH.format(
            project_id=project_id,
            mr_iid=mr_iid,
        )
        headers = {
            _HTTP_HEADER_PRIVATE_TOKEN: gitlab_token,
            _HTTP_HEADER_CONTENT_TYPE: _JSON_CONTENT_TYPE,
        }
        payload = {"body": comment_body}

        execute_http_request(
            HttpRequestConfig(
                method=HttpMethod.POST,
                url=url,
                operation_label=OperationLabel.GITLAB_MR_COMMENT,
                headers=headers,
                json_body=payload,
            )
        )

        _LOG.debug("GitLab: MR note posted to !%s", mr_iid)

    def set_commit_status(
        self, scan_result: ScanResult, pull_request_context: PullRequestContext
    ) -> None:
        sha = pull_request_context.sha
        project_id = pull_request_context.repository
        if not sha or not project_id:
            _LOG.warning("GitLab: missing SHA or project ID — skipping status")
            return

        gitlab_token = fetch_environment_variable(_ENV_GITLAB_TOKEN) or fetch_environment_variable(
            _ENV_CI_JOB_TOKEN
        )
        if not gitlab_token:
            _LOG.warning("GitLab: no token — skipping commit status")
            return

        server_url = pull_request_context.extras.get("ci_server_url") or _GITLAB_DEFAULT_SERVER_URL
        commit_status_state = (
            _GITLAB_STATUS_SUCCESS if scan_result.is_clean else _GITLAB_STATUS_FAILED
        )
        url = server_url.rstrip("/") + _GITLAB_API_COMMIT_STATUSES_PATH.format(
            project_id=project_id,
            sha=sha,
        )
        payload = {
            "state": commit_status_state,
            "name": _COMMIT_STATUS_CONTEXT,
            "description": (
                _COMMIT_STATUS_DESCRIPTION_CLEAN
                if scan_result.is_clean
                else _COMMIT_STATUS_DESCRIPTION_VIOLATIONS.format(count=len(scan_result.findings))
            ),
        }

        execute_http_request(
            HttpRequestConfig(
                method=HttpMethod.POST,
                url=url,
                operation_label=OperationLabel.GITLAB_COMMIT_STATUS,
                headers={_HTTP_HEADER_PRIVATE_TOKEN: gitlab_token},
                json_body=payload,
            )
        )

        sha_prefix = sha[:_SHA_LOG_PREFIX_LENGTH]
        _LOG.debug("GitLab: commit status set to %s for %s", commit_status_state, sha_prefix)
