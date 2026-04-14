"""Azure DevOps build tags, PR statuses, and Boards work items.

Extracted from phi_scan.ci_integration. Call sites continue to import from
phi_scan.ci_integration via re-export; this module owns the implementation.

PHI safety: all outbound payloads transmit counts, severity labels, file
paths, and line numbers only. No raw entity values, value_hash, or
code_context ever enters any Azure DevOps request body.
"""

from __future__ import annotations

import logging
from typing import Any

from phi_scan.ci import PullRequestContext
from phi_scan.ci._env import fetch_environment_variable
from phi_scan.ci._transport import (
    HttpMethod,
    HttpRequestConfig,
    OperationLabel,
    execute_http_request,
)
from phi_scan.models import ScanFinding, ScanResult

_LOG: logging.Logger = logging.getLogger(__name__)

_ENV_SYSTEM_ACCESSTOKEN: str = "SYSTEM_ACCESSTOKEN"
_ENV_AZURE_BOARDS_INTEGRATION: str = "AZURE_BOARDS_INTEGRATION"
_ENV_AZURE_BOARDS_INTEGRATION_ENABLED_VALUE: str = "true"

_AZURE_PATCH_CONTENT_TYPE: str = "application/json-patch+json"
_AZURE_BUILD_TAG_EMPTY_BODY: bytes = b""

_AZURE_API_VERSION: str = "7.1"
_AZURE_BUILD_TAGS_PATH: str = (
    "{collection_uri}{team_project}/_apis/build/builds/{build_id}"
    "/tags/{tag}?api-version={api_version}"
)
_AZURE_PR_STATUSES_PATH: str = (
    "{collection_uri}{team_project}/_apis/git/repositories/{repo_id}"
    "/pullRequests/{pr_id}/statuses?api-version={api_version}"
)
_AZURE_WORK_ITEMS_PATH: str = (
    "{collection_uri}{team_project}/_apis/wit/workitems/${work_item_type}?api-version={api_version}"
)

_AZURE_TAG_CLEAN: str = "phi-scan:clean"
_AZURE_TAG_VIOLATIONS: str = "phi-scan:violations-found"

_AZURE_PR_STATE_SUCCEEDED: str = "succeeded"
_AZURE_PR_STATE_FAILED: str = "failed"
_AZURE_STATUS_CONTEXT_NAME: str = "phi-scan"
_AZURE_STATUS_CONTEXT_GENRE: str = "phi-scan"
_AZURE_STATUS_DESCRIPTION_CLEAN: str = "No PHI/PII violations found"
_AZURE_STATUS_DESCRIPTION_VIOLATIONS: str = "{count} PHI/PII violation(s) found"

_AZURE_WORK_ITEM_TYPE: str = "Task"
_AZURE_WORK_ITEM_TITLE_FORMAT: str = (
    "phi-scan: {count} HIGH severity PHI/PII violation(s) in PR #{pull_request_number}"
)
_AZURE_WORK_ITEM_DESCRIPTION_FORMAT: str = (
    "phi-scan detected {count} HIGH severity PHI/PII violation(s) in PR #{pull_request_number}. "
    "Remediate before merging."
)
_AZURE_WORK_ITEM_TAGS_VALUE: str = "phi-scan;security;phi-pii"
_AZURE_JSON_PATCH_OP_ADD: str = "add"
_AZURE_FIELD_PATH_TITLE: str = "/fields/System.Title"
_AZURE_FIELD_PATH_DESCRIPTION: str = "/fields/System.Description"
_AZURE_FIELD_PATH_TAGS: str = "/fields/System.Tags"

_SEVERITY_HIGH_LABEL: str = "high"
_UNKNOWN_PR_ID: str = "unknown"

_EXTRAS_KEY_COLLECTION_URI: str = "collection_uri"
_EXTRAS_KEY_TEAM_PROJECT: str = "team_project"
_EXTRAS_KEY_BUILD_ID: str = "build_id"


def _fetch_azure_access_token(skip_log_message: str) -> str | None:
    token = fetch_environment_variable(_ENV_SYSTEM_ACCESSTOKEN)
    if not token:
        _LOG.warning(skip_log_message)
        return None
    return token


def set_azure_build_tag(scan_result: ScanResult, pr_context: PullRequestContext) -> None:
    """Tag the Azure DevOps build with phi-scan:clean or phi-scan:violations-found."""
    collection_uri = pr_context.extras.get(_EXTRAS_KEY_COLLECTION_URI, "")
    team_project = pr_context.extras.get(_EXTRAS_KEY_TEAM_PROJECT, "")
    build_id = pr_context.extras.get(_EXTRAS_KEY_BUILD_ID, "")

    if not all((collection_uri, team_project, build_id)):
        _LOG.debug("Azure DevOps build tag: missing context — skipping")
        return

    token = _fetch_azure_access_token(
        "Azure DevOps build tag: SYSTEM_ACCESSTOKEN not set — skipping"
    )
    if not token:
        return

    tag = _AZURE_TAG_CLEAN if scan_result.is_clean else _AZURE_TAG_VIOLATIONS
    url = _AZURE_BUILD_TAGS_PATH.format(
        collection_uri=collection_uri,
        team_project=team_project,
        build_id=build_id,
        tag=tag,
        api_version=_AZURE_API_VERSION,
    )

    execute_http_request(
        HttpRequestConfig(
            method=HttpMethod.PUT,
            url=url,
            operation_label=OperationLabel.AZURE_BUILD_TAG,
            binary_body=_AZURE_BUILD_TAG_EMPTY_BODY,
            basic_auth_credentials=("", token),
        )
    )

    _LOG.debug("Azure DevOps: build tagged with %s", tag)


def set_azure_pr_status(scan_result: ScanResult, pr_context: PullRequestContext) -> None:
    """Set an Azure DevOps PR status to block or allow completion via branch policy."""
    pr_id = pr_context.pull_request_number
    repo_id = pr_context.repository
    collection_uri = pr_context.extras.get(_EXTRAS_KEY_COLLECTION_URI, "")
    team_project = pr_context.extras.get(_EXTRAS_KEY_TEAM_PROJECT, "")

    if not all((pr_id, repo_id, collection_uri, team_project)):
        _LOG.debug("Azure DevOps PR status: missing context — skipping")
        return

    token = _fetch_azure_access_token(
        "Azure DevOps PR status: SYSTEM_ACCESSTOKEN not set — skipping"
    )
    if not token:
        return

    state = _AZURE_PR_STATE_SUCCEEDED if scan_result.is_clean else _AZURE_PR_STATE_FAILED
    description = (
        _AZURE_STATUS_DESCRIPTION_CLEAN
        if scan_result.is_clean
        else _AZURE_STATUS_DESCRIPTION_VIOLATIONS.format(count=len(scan_result.findings))
    )
    url = _AZURE_PR_STATUSES_PATH.format(
        collection_uri=collection_uri,
        team_project=team_project,
        repo_id=repo_id,
        pr_id=pr_id,
        api_version=_AZURE_API_VERSION,
    )
    payload = {
        "state": state,
        "description": description,
        "context": {
            "name": _AZURE_STATUS_CONTEXT_NAME,
            "genre": _AZURE_STATUS_CONTEXT_GENRE,
        },
    }

    execute_http_request(
        HttpRequestConfig(
            method=HttpMethod.POST,
            url=url,
            operation_label=OperationLabel.AZURE_PR_STATUS,
            json_body=payload,
            basic_auth_credentials=("", token),
        )
    )

    _LOG.debug("Azure DevOps: PR status set to %s for PR #%s", state, pr_id)


def _filter_high_severity_findings(scan_result: ScanResult) -> list[ScanFinding]:
    return [
        finding
        for finding in scan_result.findings
        if finding.severity.value.lower() == _SEVERITY_HIGH_LABEL
    ]


def _build_work_item_patch(
    high_finding_count: int, pull_request_number: str
) -> list[dict[str, Any]]:
    title = _AZURE_WORK_ITEM_TITLE_FORMAT.format(
        count=high_finding_count, pull_request_number=pull_request_number
    )
    description = _AZURE_WORK_ITEM_DESCRIPTION_FORMAT.format(
        count=high_finding_count, pull_request_number=pull_request_number
    )
    return [
        {"op": _AZURE_JSON_PATCH_OP_ADD, "path": _AZURE_FIELD_PATH_TITLE, "value": title},
        {
            "op": _AZURE_JSON_PATCH_OP_ADD,
            "path": _AZURE_FIELD_PATH_DESCRIPTION,
            "value": description,
        },
        {
            "op": _AZURE_JSON_PATCH_OP_ADD,
            "path": _AZURE_FIELD_PATH_TAGS,
            "value": _AZURE_WORK_ITEM_TAGS_VALUE,
        },
    ]


def create_azure_boards_work_item(scan_result: ScanResult, pr_context: PullRequestContext) -> None:
    """Create an Azure Boards Task work item for HIGH severity PHI/PII findings."""
    if (
        fetch_environment_variable(_ENV_AZURE_BOARDS_INTEGRATION)
        != _ENV_AZURE_BOARDS_INTEGRATION_ENABLED_VALUE
    ):
        _LOG.debug("Azure Boards: AZURE_BOARDS_INTEGRATION not enabled — skipping")
        return

    high_findings = _filter_high_severity_findings(scan_result)
    if not high_findings:
        _LOG.debug("Azure Boards: no HIGH severity findings — skipping work item")
        return

    collection_uri = pr_context.extras.get(_EXTRAS_KEY_COLLECTION_URI, "")
    team_project = pr_context.extras.get(_EXTRAS_KEY_TEAM_PROJECT, "")
    pull_request_number = pr_context.pull_request_number or _UNKNOWN_PR_ID

    if not all((collection_uri, team_project)):
        _LOG.debug("Azure Boards: missing context — skipping work item")
        return

    token = _fetch_azure_access_token("Azure Boards: SYSTEM_ACCESSTOKEN not set — skipping")
    if not token:
        return

    url = _AZURE_WORK_ITEMS_PATH.format(
        collection_uri=collection_uri,
        team_project=team_project,
        work_item_type=_AZURE_WORK_ITEM_TYPE,
        api_version=_AZURE_API_VERSION,
    )
    patch_payload = _build_work_item_patch(len(high_findings), pull_request_number)

    execute_http_request(
        HttpRequestConfig(
            method=HttpMethod.POST,
            url=url,
            operation_label=OperationLabel.AZURE_WORK_ITEM,
            headers={"Content-Type": _AZURE_PATCH_CONTENT_TYPE},
            json_body=patch_payload,
            basic_auth_credentials=("", token),
        )
    )

    _LOG.debug(
        "Azure Boards: work item created for PR #%s (%d HIGH findings)",
        pull_request_number,
        len(high_findings),
    )
