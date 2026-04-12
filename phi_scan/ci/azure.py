"""Azure DevOps CI adapter.

Posts PR thread comments via the Azure DevOps REST API.
Uses ``SYSTEM_ACCESSTOKEN`` for authentication.
"""

from __future__ import annotations

import logging

from phi_scan.ci._base import BaseCIAdapter
from phi_scan.ci._detect import PRContext, fetch_env_variable
from phi_scan.ci._transport import HttpMethod, HttpRequestConfig, execute_http_request
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
_AZURE_COMMENT_TYPE_TEXT: int = 1
_AZURE_THREAD_STATUS_ACTIVE: str = "active"


class AzureAdapter(BaseCIAdapter):
    """Azure DevOps adapter using the Azure DevOps REST API."""

    @property
    def supports_commit_status(self) -> bool:
        return False

    @property
    def supports_work_item_creation(self) -> bool:
        return True

    def post_pr_comment(self, comment_body: str, pr_context: PRContext) -> None:
        pr_id = pr_context.pr_number
        repo_id = pr_context.repository
        collection_uri = pr_context.extras.get("collection_uri", "")
        team_project = pr_context.extras.get("team_project", "")

        if not all([pr_id, repo_id, collection_uri, team_project]):
            _LOG.debug("Azure DevOps: missing PR context — skipping comment")
            return

        token = fetch_env_variable(_ENV_SYSTEM_ACCESSTOKEN)
        if not token:
            _LOG.warning(
                "Azure DevOps: SYSTEM_ACCESSTOKEN not set — "
                "enable 'Allow scripts to access the OAuth token' in pipeline settings"
            )
            return

        url = _AZURE_PR_THREADS_PATH.format(
            collection_uri=collection_uri,
            team_project=team_project,
            repo_id=repo_id,
            pr_id=pr_id,
            api_version=_AZURE_API_VERSION,
        )
        payload = {
            "comments": [
                {
                    "parentCommentId": _AZURE_COMMENT_PARENT_ID_ROOT,
                    "content": comment_body,
                    "commentType": _AZURE_COMMENT_TYPE_TEXT,
                }
            ],
            "status": _AZURE_THREAD_STATUS_ACTIVE,
        }

        execute_http_request(
            HttpRequestConfig(
                method=HttpMethod.POST,
                url=url,
                operation_label="Azure DevOps PR comment",
                json_body=payload,
                auth=("", token),
            )
        )

        _LOG.debug("Azure DevOps: PR thread comment posted to PR #%s", pr_id)

    def set_commit_status(self, scan_result: ScanResult, pr_context: PRContext) -> None:
        self._raise_unsupported("commit status")
