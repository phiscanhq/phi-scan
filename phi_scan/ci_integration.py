# phi-scan:ignore-file
"""CI/CD platform integration for phi-scan.

This module is the backward-compatible entry point for CI/CD integration.
Platform detection, PR context extraction, and per-platform adapters now
live in the ``phi_scan.ci`` package. This module provides:

  1. **Orchestration**: ``post_pr_comment`` and ``set_commit_status``
     dispatch to per-platform adapters via ``phi_scan.ci.resolve_adapter``.
  2. **Comment formatting**: ``build_comment_body`` and
     ``build_comment_body_with_baseline`` produce the markdown PR body.
  3. **Platform-specific extras**: SARIF upload, Bitbucket Code Insights,
     Azure build tags/PR statuses/Boards work items, and AWS Security Hub
     ASFF import remain here pending a follow-up migration PR.
  4. **Backward-compatible re-exports**: all names previously importable
     from ``phi_scan.ci_integration`` continue to work.

Security audit summary
----------------------
All outbound HTTP calls go through ``phi_scan.ci._transport.execute_http_request``,
which re-raises both ``httpx.HTTPStatusError`` and ``httpx.RequestError`` as
``CIIntegrationError``. Error messages include only the status code and reason
phrase — never the response body.
"""

from __future__ import annotations

import base64
import gzip
import json
import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Any

from phi_scan.ci import (  # noqa: F401 — backward-compatible re-exports
    AzureAdapter,
    BaseCIAdapter,
    BitbucketAdapter,
    CIPlatform,
    CircleCIAdapter,
    CodeBuildAdapter,
    GitHubAdapter,
    GitLabAdapter,
    JenkinsAdapter,
    PullRequestContext,
    detect_platform,
    get_pull_request_context,
    resolve_adapter,
)
from phi_scan.ci._base import SanitisedCommentBody
from phi_scan.ci._transport import (
    HttpMethod,
    HttpRequestConfig,
    OperationLabel,
    execute_http_request,
)
from phi_scan.constants import SeverityLevel
from phi_scan.exceptions import CIIntegrationError  # noqa: F401 — backward-compatible re-export
from phi_scan.models import ScanResult
from phi_scan.output import format_sarif

PRContext = PullRequestContext
get_pr_context = get_pull_request_context

__all__ = [
    "AzureAdapter",
    "BaseCIAdapter",
    "BaselineComparison",
    "BitbucketAdapter",
    "CIIntegrationError",
    "CIPlatform",
    "CircleCIAdapter",
    "CodeBuildAdapter",
    "GitHubAdapter",
    "GitLabAdapter",
    "HttpMethod",
    "HttpRequestConfig",
    "JenkinsAdapter",
    "OperationLabel",
    "PRContext",
    "PullRequestContext",
    "SanitisedCommentBody",
    "build_comment_body",
    "build_comment_body_with_baseline",
    "convert_findings_to_asff",
    "create_azure_boards_work_item",
    "detect_platform",
    "execute_http_request",
    "get_pr_context",
    "get_pull_request_context",
    "import_findings_to_security_hub",
    "post_bitbucket_code_insights",
    "post_pr_comment",
    "post_pull_request_comment",
    "resolve_adapter",
    "set_azure_build_tag",
    "set_azure_pr_status",
    "set_commit_status",
    "upload_sarif_to_github",
]

_LOG: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — comment formatting
# ---------------------------------------------------------------------------

_COMMENT_HEADER_CLEAN: str = "## phi-scan: No PHI/PII Violations Found"
_COMMENT_HEADER_VIOLATIONS: str = "## phi-scan: PHI/PII Violations Detected"
_COMMENT_BADGE_CLEAN: str = "![clean](https://img.shields.io/badge/phi--scan-clean-green)"
_COMMENT_BADGE_VIOLATIONS: str = (
    "![violations](https://img.shields.io/badge/phi--scan-violations-red)"
)

_COMMIT_STATUS_CONTEXT: str = "phi-scan"
_COMMIT_STATUS_DESCRIPTION_CLEAN: str = "No PHI/PII violations found"
_COMMIT_STATUS_DESCRIPTION_VIOLATIONS: str = "{count} PHI/PII violation(s) found"

_MAX_COMMENT_LENGTH: int = 60_000
_MAX_ERROR_RESPONSE_LOG_LENGTH: int = 200
_DEFAULT_GIT_REF: str = "refs/heads/main"
_COMMENT_BODY_SPLIT_MAX_PARTS: int = 2
_COMMENT_MIN_SECTION_COUNT: int = 2
_BASELINE_CONTEXT_FORMAT: str = (
    "**{new_findings_count} new** | "
    "{baselined_count} baselined | "
    "{resolved_count} resolved since last scan"
)

_MAX_FINDINGS_IN_COMMENT_TABLE: int = 50

# ---------------------------------------------------------------------------
# Constants — platform-specific extras
# ---------------------------------------------------------------------------

_ENV_GITHUB_TOKEN: str = "GITHUB_TOKEN"
_ENV_SYSTEM_ACCESSTOKEN: str = "SYSTEM_ACCESSTOKEN"
_ENV_BITBUCKET_TOKEN: str = "BITBUCKET_TOKEN"

_HTTP_TIMEOUT_SECONDS: float = 15.0
_JSON_CONTENT_TYPE: str = "application/json"
_AZURE_PATCH_CONTENT_TYPE: str = "application/json-patch+json"
_AZURE_BUILD_TAG_EMPTY_BODY: bytes = b""

_GITHUB_API_BASE_URL: str = "https://api.github.com"
_GITHUB_API_SARIF_UPLOAD_PATH: str = "/repos/{repository}/code-scanning/sarifs"
_SARIF_MAX_MESSAGE_TEXT_LENGTH: int = 1_500

_AZURE_API_VERSION: str = "7.1"
_AZURE_BUILD_TAGS_PATH: str = (
    "{collection_uri}{team_project}/_apis/build/builds/{build_id}"
    "/tags/{tag}?api-version={api_version}"
)
_AZURE_PR_STATUSES_PATH: str = (
    "{collection_uri}{team_project}/_apis/git/repositories/{repo_id}"
    "/pullRequests/{pr_id}/statuses?api-version={api_version}"
)
_AZURE_TAG_CLEAN: str = "phi-scan:clean"
_AZURE_TAG_VIOLATIONS: str = "phi-scan:violations-found"
_AZURE_WORK_ITEM_TYPE: str = "Task"
_AZURE_WORK_ITEMS_PATH: str = (
    "{collection_uri}{team_project}/_apis/wit/workitems/${work_item_type}?api-version={api_version}"
)
_AZURE_WORK_ITEM_TITLE_FORMAT: str = (
    "phi-scan: {count} HIGH severity PHI/PII violation(s) in PR #{pull_request_number}"
)

_AWS_SECURITY_HUB_PRODUCT_ARN_FORMAT: str = (
    "arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"
)
_AWS_SECURITY_HUB_HIGH_SEVERITY_LABEL: str = "HIGH"
_AWS_SECURITY_HUB_MEDIUM_SEVERITY_LABEL: str = "MEDIUM"
_AWS_SECURITY_HUB_LOW_SEVERITY_LABEL: str = "LOW"
_AWS_SECURITY_HUB_INFO_SEVERITY_LABEL: str = "INFORMATIONAL"
_AWS_SECURITY_HUB_SEVERITY_MAP: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _AWS_SECURITY_HUB_HIGH_SEVERITY_LABEL,
    SeverityLevel.MEDIUM: _AWS_SECURITY_HUB_MEDIUM_SEVERITY_LABEL,
    SeverityLevel.LOW: _AWS_SECURITY_HUB_LOW_SEVERITY_LABEL,
    SeverityLevel.INFO: _AWS_SECURITY_HUB_INFO_SEVERITY_LABEL,
}

_BITBUCKET_API_BASE_URL: str = "https://api.bitbucket.org/2.0"
_BITBUCKET_REPORTS_PATH: str = (
    "/repositories/{workspace}/{repo_slug}/commit/{commit}/reports/{report_id}"
)
_BITBUCKET_ANNOTATIONS_PATH: str = (
    "/repositories/{workspace}/{repo_slug}/commit/{commit}/reports/{report_id}/annotations"
)
_BITBUCKET_REPORT_ID: str = "phi-scan"
_BITBUCKET_HIGH_SEVERITY_LABEL: str = "HIGH"
_BITBUCKET_MEDIUM_SEVERITY_LABEL: str = "MEDIUM"
_BITBUCKET_LOW_SEVERITY_LABEL: str = "LOW"
_BITBUCKET_INFO_SEVERITY_LABEL: str = _BITBUCKET_LOW_SEVERITY_LABEL
_BITBUCKET_ANNOTATION_SEVERITY_MAP: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _BITBUCKET_HIGH_SEVERITY_LABEL,
    SeverityLevel.MEDIUM: _BITBUCKET_MEDIUM_SEVERITY_LABEL,
    SeverityLevel.LOW: _BITBUCKET_LOW_SEVERITY_LABEL,
    SeverityLevel.INFO: _BITBUCKET_INFO_SEVERITY_LABEL,
}


# ---------------------------------------------------------------------------
# Backward-compatible type re-exports
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineComparison:
    """Counts from a baseline comparison to include in PR/MR comment context."""

    new_findings_count: int
    baselined_count: int
    resolved_count: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env(name: str) -> str | None:
    """Return the environment variable value, or None if unset or empty."""
    env_value = os.environ.get(name, "").strip()
    return env_value if env_value else None


# ---------------------------------------------------------------------------
# Comment body builder
# ---------------------------------------------------------------------------


def build_comment_body(scan_result: ScanResult) -> SanitisedCommentBody:
    """Build a markdown PR/MR comment body from a ``ScanResult``.

    The body contains only counts, file names, and line numbers — never raw
    entity values. Truncated to ``_MAX_COMMENT_LENGTH`` characters to stay
    within platform comment size limits.
    """
    if scan_result.is_clean:
        header = _COMMENT_HEADER_CLEAN
        badge = _COMMENT_BADGE_CLEAN
        body_lines = [
            f"{badge}",
            "",
            f"**{header}**",
            "",
            f"Scanned **{scan_result.files_scanned}** file(s) — no PHI/PII detected.",
            "",
            f"*Scan duration: {scan_result.scan_duration:.2f}s*",
        ]
        return SanitisedCommentBody("\n".join(body_lines))

    findings_count = len(scan_result.findings)
    header = _COMMENT_HEADER_VIOLATIONS
    badge = _COMMENT_BADGE_VIOLATIONS

    severity_summary = ", ".join(
        f"{count} {level.value}"
        for level, count in sorted(
            scan_result.severity_counts.items(),
            key=lambda severity_item: severity_item[0].value,
        )
        if count > 0
    )

    body_lines = [
        badge,
        "",
        f"**{header}**",
        "",
        f"phi-scan detected **{findings_count}** PHI/PII finding(s) across "
        f"**{scan_result.files_with_findings}** file(s).",
        "",
        f"**Risk level:** {scan_result.risk_level.value}  ",
        f"**Severity breakdown:** {severity_summary}",
        "",
        "### Findings",
        "",
        "| File | Line | Type | Severity | Confidence |",
        "|------|------|------|----------|------------|",
    ]

    for finding in scan_result.findings[:_MAX_FINDINGS_IN_COMMENT_TABLE]:
        body_lines.append(
            f"| `{finding.file_path}` | {finding.line_number} "
            f"| {finding.hipaa_category.value} "
            f"| {finding.severity.value} "
            f"| {finding.confidence:.0%} |"
        )

    if findings_count > _MAX_FINDINGS_IN_COMMENT_TABLE:
        body_lines.append(
            f"| … and {findings_count - _MAX_FINDINGS_IN_COMMENT_TABLE} more | | | | |"
        )

    body_lines += [
        "",
        "> **Action required:** Remove or de-identify all flagged values before merging.",
        "> Run `phi-scan scan . --output table` locally for full details.",
        "",
        f"*Scan duration: {scan_result.scan_duration:.2f}s | "
        f"Files scanned: {scan_result.files_scanned}*",
    ]

    comment_body = "\n".join(body_lines)
    if len(comment_body) > _MAX_COMMENT_LENGTH:
        comment_body = (
            comment_body[:_MAX_COMMENT_LENGTH] + "\n\n*(comment truncated — too many findings)*"
        )
    return SanitisedCommentBody(comment_body)


def _insert_baseline_context_into_comment(
    comment_body: str,
    baseline_line: str,
) -> str:
    """Insert a baseline context line after the first header line of a comment body."""
    lines = comment_body.split("\n", _COMMENT_BODY_SPLIT_MAX_PARTS)
    if len(lines) < _COMMENT_MIN_SECTION_COUNT:
        return baseline_line + "\n\n" + comment_body
    return "\n".join([lines[0], "", baseline_line, "", *lines[1:]])


def build_comment_body_with_baseline(
    scan_result: ScanResult,
    baseline_comparison: BaselineComparison,
) -> SanitisedCommentBody:
    """Build a PR/MR comment body that includes baseline comparison context."""
    baseline_line = _BASELINE_CONTEXT_FORMAT.format(
        new_findings_count=baseline_comparison.new_findings_count,
        baselined_count=baseline_comparison.baselined_count,
        resolved_count=baseline_comparison.resolved_count,
    )
    return SanitisedCommentBody(
        _insert_baseline_context_into_comment(build_comment_body(scan_result), baseline_line)
    )


# ---------------------------------------------------------------------------
# Public API — post PR/MR comment (dispatches to adapter)
# ---------------------------------------------------------------------------


def post_pr_comment(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Post a PR/MR comment with scan findings to the detected CI/CD platform.

    Selects the platform-specific adapter based on ``pr_context.platform``.
    Does nothing and logs a warning when the platform is ``UNKNOWN`` or when
    required context (PR number, token) is missing.
    """
    if not pr_context.pull_request_number:
        _LOG.debug("No PR number in context — skipping comment posting")
        return

    try:
        adapter = resolve_adapter(pr_context.platform)
    except CIIntegrationError:
        _LOG.warning(
            "PR comment posting not implemented for platform %s",
            pr_context.platform.value,
        )
        return

    comment_body = build_comment_body(scan_result)
    adapter.post_pull_request_comment(comment_body, pr_context)


post_pull_request_comment = post_pr_comment


# ---------------------------------------------------------------------------
# Public API — set commit status (dispatches to adapter)
# ---------------------------------------------------------------------------


def set_commit_status(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Set the commit status (PASS/FAIL) on the CI/CD platform.

    Selects the platform-specific adapter based on ``pr_context.platform``.
    Does nothing and logs a warning when required context (SHA, token) is missing.
    """
    if not pr_context.sha:
        _LOG.debug("No commit SHA in context — skipping status posting")
        return

    try:
        adapter = resolve_adapter(pr_context.platform)
    except CIIntegrationError:
        _LOG.warning(
            "Commit status not implemented for platform %s",
            pr_context.platform.value,
        )
        return

    if not adapter.can_post_commit_status:
        _LOG.debug(
            "Adapter %s does not support commit status — skipping",
            type(adapter).__name__,
        )
        return

    adapter.set_commit_status(scan_result, pr_context)


# ---------------------------------------------------------------------------
# Public API — upload SARIF to GitHub Code Scanning
# ---------------------------------------------------------------------------


def _verify_sarif_excludes_code_snippets(sarif_content: str) -> None:
    """Verify the SARIF output contains no code snippet or contextRegion fields."""
    sarif_doc: dict[str, Any] = json.loads(sarif_content)
    for sarif_run in sarif_doc.get("runs", []):
        for sarif_result in sarif_run.get("results", []):
            message_text = sarif_result.get("message", {}).get("text", "")
            if len(message_text) > _SARIF_MAX_MESSAGE_TEXT_LENGTH:
                raise CIIntegrationError(
                    f"SARIF upload aborted: message.text length {len(message_text)} "
                    f"exceeds limit of {_SARIF_MAX_MESSAGE_TEXT_LENGTH} — "
                    "unexpected content may be embedded"
                )
            for location in sarif_result.get("locations", []):
                physical_location = location.get("physicalLocation", {})
                region = physical_location.get("region", {})
                if "snippet" in region:
                    raise CIIntegrationError(
                        "SARIF upload aborted: code snippet detected in SARIF output — "
                        "uploading would expose raw source content to GitHub Code Scanning API"
                    )
                if "contextRegion" in physical_location:
                    raise CIIntegrationError(
                        "SARIF upload aborted: contextRegion detected in SARIF output — "
                        "uploading would expose raw source content to GitHub Code Scanning API"
                    )


def _gzip_compress_sarif(sarif_content: str) -> bytes:
    return gzip.compress(sarif_content.encode("utf-8"))


def _base64_encode_bytes(raw_bytes: bytes) -> str:
    return base64.b64encode(raw_bytes).decode("ascii")


def upload_sarif_to_github(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Upload a SARIF report to the GitHub Code Scanning API for inline annotations."""
    repository = pr_context.repository
    sha = pr_context.sha
    if not repository or not sha:
        _LOG.debug("GitHub SARIF upload: missing repository or SHA — skipping")
        return

    token = _env(_ENV_GITHUB_TOKEN)
    if not token:
        _LOG.warning("GitHub SARIF upload: GITHUB_TOKEN not set — skipping")
        return

    sarif_content = format_sarif(scan_result)
    _verify_sarif_excludes_code_snippets(sarif_content)
    sarif_base64_encoded = _base64_encode_bytes(_gzip_compress_sarif(sarif_content))

    url = _GITHUB_API_BASE_URL + _GITHUB_API_SARIF_UPLOAD_PATH.format(repository=repository)
    sarif_upload_payload = {
        "commit_sha": sha,
        "ref": pr_context.branch or _DEFAULT_GIT_REF,
        "sarif": sarif_base64_encoded,
        "tool_name": "phi-scan",
    }

    execute_http_request(
        HttpRequestConfig(
            method=HttpMethod.POST,
            url=url,
            operation_label=OperationLabel.GITHUB_SARIF_UPLOAD,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json_body=sarif_upload_payload,
        )
    )

    _LOG.debug("GitHub: SARIF uploaded to Code Scanning for %s", sha[:8])


# ---------------------------------------------------------------------------
# Public API — Bitbucket Code Insights annotations
# ---------------------------------------------------------------------------


def post_bitbucket_code_insights(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Post Bitbucket Code Insights report and inline annotations."""
    sha = pr_context.sha
    workspace = pr_context.extras.get("workspace", "")
    repo_slug = pr_context.extras.get("repo_slug", "")

    if not sha or not workspace or not repo_slug:
        _LOG.debug("Bitbucket Code Insights: missing context — skipping")
        return

    token = _env(_ENV_BITBUCKET_TOKEN)
    if not token:
        _LOG.warning("Bitbucket: BITBUCKET_TOKEN not set — skipping Code Insights")
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": _JSON_CONTENT_TYPE,
    }
    report_url = _BITBUCKET_API_BASE_URL + _BITBUCKET_REPORTS_PATH.format(
        workspace=workspace,
        repo_slug=repo_slug,
        commit=sha,
        report_id=_BITBUCKET_REPORT_ID,
    )

    findings_count = len(scan_result.findings)
    report_payload: dict[str, Any] = {
        "title": "phi-scan PHI/PII Scan",
        "report_type": "SECURITY",
        "reporter": "phi-scan",
        "result": "PASSED" if scan_result.is_clean else "FAILED",
        "data": [
            {"title": "Total findings", "type": "NUMBER", "value": findings_count},
            {
                "title": "Risk level",
                "type": "TEXT",
                "value": scan_result.risk_level.value,
            },
        ],
    }

    execute_http_request(
        HttpRequestConfig(
            method=HttpMethod.PUT,
            url=report_url,
            operation_label=OperationLabel.BITBUCKET_CODE_INSIGHTS_REPORT,
            headers=headers,
            json_body=report_payload,
        )
    )

    if not scan_result.findings:
        return

    annotations_url = _BITBUCKET_API_BASE_URL + _BITBUCKET_ANNOTATIONS_PATH.format(
        workspace=workspace,
        repo_slug=repo_slug,
        commit=sha,
        report_id=_BITBUCKET_REPORT_ID,
    )
    annotations = [
        {
            "external_id": f"phi-scan-{finding.file_path}-{finding.line_number}-{idx}",
            "annotation_type": "VULNERABILITY",
            "path": str(finding.file_path),
            "line": finding.line_number,
            "message": (
                f"{finding.hipaa_category.value} detected "
                f"({finding.severity.value}, {finding.confidence:.0%} confidence)"
            ),
            "severity": _BITBUCKET_ANNOTATION_SEVERITY_MAP.get(finding.severity, "MEDIUM"),
        }
        for idx, finding in enumerate(scan_result.findings[:1000])
    ]

    execute_http_request(
        HttpRequestConfig(
            method=HttpMethod.POST,
            url=annotations_url,
            operation_label=OperationLabel.BITBUCKET_CODE_INSIGHTS_ANNOTATIONS,
            headers=headers,
            json_body=annotations,
        )
    )

    _LOG.debug(
        "Bitbucket: Code Insights report + %d annotation(s) posted for %s",
        len(annotations),
        sha[:8],
    )


# ---------------------------------------------------------------------------
# Public API — Azure DevOps build tag + PR status
# ---------------------------------------------------------------------------


def set_azure_build_tag(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Tag the Azure DevOps build with phi-scan:clean or phi-scan:violations-found."""
    collection_uri = pr_context.extras.get("collection_uri", "")
    team_project = pr_context.extras.get("team_project", "")
    build_id = pr_context.extras.get("build_id", "")

    if not all((collection_uri, team_project, build_id)):
        _LOG.debug("Azure DevOps build tag: missing context — skipping")
        return

    token = _env(_ENV_SYSTEM_ACCESSTOKEN)
    if not token:
        _LOG.warning("Azure DevOps build tag: SYSTEM_ACCESSTOKEN not set — skipping")
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


def set_azure_pr_status(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Set an Azure DevOps PR status to block or allow completion via branch policy."""
    pr_id = pr_context.pull_request_number
    repo_id = pr_context.repository
    collection_uri = pr_context.extras.get("collection_uri", "")
    team_project = pr_context.extras.get("team_project", "")

    if not all((pr_id, repo_id, collection_uri, team_project)):
        _LOG.debug("Azure DevOps PR status: missing context — skipping")
        return

    token = _env(_ENV_SYSTEM_ACCESSTOKEN)
    if not token:
        _LOG.warning("Azure DevOps PR status: SYSTEM_ACCESSTOKEN not set — skipping")
        return

    state = "succeeded" if scan_result.is_clean else "failed"
    findings_count = len(scan_result.findings)
    description = (
        _COMMIT_STATUS_DESCRIPTION_CLEAN
        if scan_result.is_clean
        else _COMMIT_STATUS_DESCRIPTION_VIOLATIONS.format(count=findings_count)
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
            "name": _COMMIT_STATUS_CONTEXT,
            "genre": "phi-scan",
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


# ---------------------------------------------------------------------------
# Public API — Azure Boards work-item linking
# ---------------------------------------------------------------------------


def create_azure_boards_work_item(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Create an Azure Boards Task work item for HIGH severity PHI/PII findings."""
    if _env("AZURE_BOARDS_INTEGRATION") != "true":
        _LOG.debug("Azure Boards: AZURE_BOARDS_INTEGRATION not enabled — skipping")
        return

    high_findings = [f for f in scan_result.findings if f.severity.value.lower() == "high"]
    if not high_findings:
        _LOG.debug("Azure Boards: no HIGH severity findings — skipping work item")
        return

    collection_uri = pr_context.extras.get("collection_uri", "")
    team_project = pr_context.extras.get("team_project", "")
    pr_id = pr_context.pull_request_number or "unknown"

    if not all((collection_uri, team_project)):
        _LOG.debug("Azure Boards: missing context — skipping work item")
        return

    token = _env(_ENV_SYSTEM_ACCESSTOKEN)
    if not token:
        _LOG.warning("Azure Boards: SYSTEM_ACCESSTOKEN not set — skipping")
        return

    title = _AZURE_WORK_ITEM_TITLE_FORMAT.format(
        count=len(high_findings), pull_request_number=pr_id
    )
    url = _AZURE_WORK_ITEMS_PATH.format(
        collection_uri=collection_uri,
        team_project=team_project,
        work_item_type=_AZURE_WORK_ITEM_TYPE,
        api_version=_AZURE_API_VERSION,
    )

    patch_payload = [
        {"op": "add", "path": "/fields/System.Title", "value": title},
        {
            "op": "add",
            "path": "/fields/System.Description",
            "value": (
                f"phi-scan detected {len(high_findings)} HIGH severity PHI/PII "
                f"violation(s) in PR #{pr_id}. "
                "Remediate before merging."
            ),
        },
        {"op": "add", "path": "/fields/System.Tags", "value": "phi-scan;security;phi-pii"},
    ]

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
        pr_id,
        len(high_findings),
    )


# ---------------------------------------------------------------------------
# Public API — AWS Security Hub ASFF import
# ---------------------------------------------------------------------------


def convert_findings_to_asff(
    scan_result: ScanResult,
    aws_account_id: str,
    aws_region: str,
    repository: str,
) -> list[dict[str, Any]]:
    """Convert phi-scan findings to AWS Security Finding Format (ASFF)."""
    from datetime import UTC, datetime

    product_arn = _AWS_SECURITY_HUB_PRODUCT_ARN_FORMAT.format(
        region=aws_region,
        account_id=aws_account_id,
    )
    now_iso = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    asff_findings = []
    for finding in scan_result.findings:
        severity_label = _AWS_SECURITY_HUB_SEVERITY_MAP.get(finding.severity, "MEDIUM")
        severity_score_map = {"HIGH": 70, "MEDIUM": 40, "LOW": 10, "INFORMATIONAL": 0}
        severity_score = severity_score_map.get(severity_label, 40)

        asff_finding: dict[str, Any] = {
            "SchemaVersion": "2018-10-08",
            "Id": (f"{repository}/{finding.file_path}/{finding.line_number}/{finding.entity_type}"),
            "ProductArn": product_arn,
            "GeneratorId": f"phi-scan/{finding.entity_type}",
            "AwsAccountId": aws_account_id,
            "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
            "FirstObservedAt": now_iso,
            "UpdatedAt": now_iso,
            "CreatedAt": now_iso,
            "Severity": {
                "Label": severity_label,
                "Normalized": severity_score,
            },
            "Title": (
                f"PHI/PII detected: {finding.hipaa_category.value} "
                f"in {finding.file_path}:{finding.line_number}"
            ),
            "Description": (
                f"phi-scan detected a {finding.hipaa_category.value} ({finding.entity_type}) "
                f"with {finding.confidence:.0%} confidence at "
                f"{finding.file_path} line {finding.line_number}. "
                "No raw value is stored — only a one-way hash of the detected entity."
            ),
            "Remediation": {
                "Recommendation": {
                    "Text": finding.remediation_hint or "Remove or de-identify the PHI/PII value.",
                }
            },
            "SourceUrl": f"https://github.com/{repository}/blob/HEAD/{finding.file_path}#L{finding.line_number}",
            "Resources": [
                {
                    "Type": "Other",
                    "Id": f"file://{finding.file_path}",
                    "Details": {
                        "Other": {
                            "line_number": str(finding.line_number),
                            "entity_type": finding.entity_type,
                            "hipaa_category": finding.hipaa_category.value,
                            "confidence": f"{finding.confidence:.4f}",
                        }
                    },
                }
            ],
        }
        asff_findings.append(asff_finding)

    return asff_findings


def import_findings_to_security_hub(
    scan_result: ScanResult,
    pr_context: PRContext,
) -> None:
    """Import phi-scan findings to AWS Security Hub via BatchImportFindings."""
    if _env("AWS_SECURITY_HUB") != "true":
        _LOG.debug("Security Hub: AWS_SECURITY_HUB not enabled — skipping")
        return

    if scan_result.is_clean:
        _LOG.debug("Security Hub: no findings to import")
        return

    account_id = _env("AWS_ACCOUNT_ID") or ""
    region = _env("AWS_DEFAULT_REGION") or _env("AWS_REGION") or "us-east-1"
    repository = pr_context.repository or _env("GITHUB_REPOSITORY") or "unknown/repo"

    if not account_id:
        _LOG.warning("Security Hub: AWS_ACCOUNT_ID not set — skipping")
        return

    import json as _json

    asff_findings = convert_findings_to_asff(scan_result, account_id, region, repository)
    findings_json = _json.dumps({"Findings": asff_findings})

    try:
        aws_cli_result = subprocess.run(
            ["aws", "securityhub", "batch-import-findings", "--cli-input-json", findings_json],
            capture_output=True,
            text=True,
            check=False,
        )
        if aws_cli_result.returncode != 0:
            raise CIIntegrationError(
                f"AWS Security Hub import failed (exit {aws_cli_result.returncode}): "
                f"{aws_cli_result.stderr.strip()[:_MAX_ERROR_RESPONSE_LOG_LENGTH]}"
            )
    except FileNotFoundError as not_found_error:
        raise CIIntegrationError(
            "AWS CLI not found — install awscli to enable Security Hub integration"
        ) from not_found_error

    _LOG.debug("Security Hub: imported %d ASFF finding(s)", len(asff_findings))
