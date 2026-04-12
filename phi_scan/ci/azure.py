"""Azure DevOps CI adapter.

Posts PR thread comments via the Azure DevOps REST API.
Uses ``SYSTEM_ACCESSTOKEN`` for authentication.
"""

from __future__ import annotations

import enum
import logging
from typing import Any

from phi_scan.ci._base import BaseCIAdapter, SanitisedCommentBody, UnsupportedOperation
from phi_scan.ci._detect import PRContext
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

_ENV_SYSTEM_ACCESSTOKEN: str = "SYSTEM_ACCESSTOKEN"

_AZURE_API_VERSION: str = "7.1"
_AZURE_PR_THREADS_PATH: str = (
    "{collection_uri}{team_project}/_apis/git/repositories/{repo_id}"
    "/pullRequests/{pr_id}/threads?api-version={api_version}"
)

_COMMIT_STATUS_CONTEXT: str = "phi-scan"
_AZURE_COMMENT_PARENT_ID_ROOT: int = 0


class _AzureCommentType(enum.IntEnum):
    """Azure DevOps PR thread comment types (REST API)."""

    TEXT = 1


class _AzureThreadStatus(enum.StrEnum):
    """Azure DevOps PR thread statuses (REST API)."""

    ACTIVE = "active"


def _build_pr_threads_url(pr_context: PRContext) -> str:
    return _AZURE_PR_THREADS_PATH.format(
        collection_uri=pr_context.extras.get("collection_uri", ""),
        team_project=pr_context.extras.get("team_project", ""),
        repo_id=pr_context.repository,
        pr_id=pr_context.pr_number,
        api_version=_AZURE_API_VERSION,
    )


def _build_azure_thread_payload(comment_body: str) -> dict[str, Any]:
    return {
        "comments": [
            {
                "parentCommentId": _AZURE_COMMENT_PARENT_ID_ROOT,
                "content": comment_body,
                "commentType": _AzureCommentType.TEXT,
            }
        ],
        "status": _AzureThreadStatus.ACTIVE,
    }


class AzureAdapter(BaseCIAdapter):
    """Azure DevOps adapter using the Azure DevOps REST API."""

    @property
    def can_post_commit_status(self) -> bool:
        return False

    @property
    def can_create_work_item(self) -> bool:
        return True

    def post_pr_comment(self, comment_body: SanitisedCommentBody, pr_context: PRContext) -> None:
        pr_id = pr_context.pr_number
        repo_id = pr_context.repository
        collection_uri = pr_context.extras.get("collection_uri", "")
        team_project = pr_context.extras.get("team_project", "")

        if not all((pr_id, repo_id, collection_uri, team_project)):
            raise CIIntegrationError(
                "Azure DevOps: missing PR context fields required for PR comment"
            )

        system_access_token = fetch_environment_variable(_ENV_SYSTEM_ACCESSTOKEN)
        if not system_access_token:
            raise CIIntegrationError("Azure DevOps: SYSTEM_ACCESSTOKEN not set")

        url = _build_pr_threads_url(pr_context)
        execute_http_request(
            HttpRequestConfig(
                method=HttpMethod.POST,
                url=url,
                operation_label=OperationLabel.AZURE_PR_COMMENT,
                json_body=_build_azure_thread_payload(comment_body),
                basic_auth_credentials=("", system_access_token),
            )
        )
        _LOG.debug("Azure DevOps: PR thread comment posted to PR #%s", pr_id)

    def set_commit_status(self, scan_result: ScanResult, pr_context: PRContext) -> None:
        self._raise_unsupported_operation_error(UnsupportedOperation.COMMIT_STATUS)
