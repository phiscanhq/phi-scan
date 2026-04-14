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

import logging
from dataclasses import dataclass

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
from phi_scan.ci.aws_security_hub import (
    convert_findings_to_asff as convert_findings_to_asff,
)
from phi_scan.ci.aws_security_hub import (
    import_findings_to_security_hub as import_findings_to_security_hub,
)
from phi_scan.ci.azure_devops import (
    create_azure_boards_work_item as create_azure_boards_work_item,
)
from phi_scan.ci.azure_devops import set_azure_build_tag as set_azure_build_tag
from phi_scan.ci.azure_devops import set_azure_pr_status as set_azure_pr_status
from phi_scan.ci.bitbucket_insights import (
    post_bitbucket_code_insights as post_bitbucket_code_insights,
)
from phi_scan.ci.sarif import upload_sarif_to_github as upload_sarif_to_github
from phi_scan.exceptions import CIIntegrationError  # noqa: F401 — backward-compatible re-export
from phi_scan.models import ScanResult

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
# Implementation now lives in phi_scan.ci.sarif; re-exported at module top.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Public API — Bitbucket Code Insights annotations
# Implementation now lives in phi_scan.ci.bitbucket_insights; re-exported at
# module top.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Public API — Azure DevOps build tag, PR status, and Boards work item
# Implementation now lives in phi_scan.ci.azure_devops; re-exported at
# module top.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Public API — AWS Security Hub ASFF import
# Implementation now lives in phi_scan.ci.aws_security_hub; re-exported at
# module top.
# ---------------------------------------------------------------------------
