"""CI/CD platform integration for phi-scan.

Provides auto-detection of the running CI/CD platform, extraction of PR/MR
context from environment variables, PR/MR comment posting, and commit status
reporting across all seven supported platforms:

  - GitHub Actions    (via ``gh`` CLI)
  - GitLab CI         (via GitLab REST API)
  - Jenkins           (via GitHub/GitLab API depending on VCS source)
  - Azure DevOps      (via Azure DevOps REST API)
  - CircleCI          (via GitHub/Bitbucket API depending on VCS)
  - Bitbucket         (via Bitbucket Cloud REST API)
  - AWS CodeBuild     (via GitHub/Bitbucket API depending on webhook source)

Each public function accepts a ``ScanResult`` and a ``PRContext`` and returns
``None``. Network errors are caught and re-raised as ``CIIntegrationError`` so
the caller (CLI scan command) can decide whether to fail the build or continue.

Design constraints:
  - No PHI leaves the process — comment bodies contain only counts, file names,
    and line numbers. Raw entity values are never included.
  - HTTP error messages include only the status code and reason phrase, never the
    response body — API error responses for comment endpoints could echo back
    request content containing finding metadata (HIPAA categories, file paths).
  - All HTTP calls use ``httpx`` (already a project dependency).
  - ``gh`` CLI is used for GitHub because it handles token auth and API versioning.
  - Authentication tokens are read from environment variables only — never from
    config files (which may be committed to version control).
"""

from __future__ import annotations

import base64
import enum
import gzip
import json
import logging
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from phi_scan.constants import SeverityLevel
from phi_scan.exceptions import PhiScanError
from phi_scan.models import ScanResult
from phi_scan.output import format_sarif

_LOG: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — environment variable names
# ---------------------------------------------------------------------------

# GitHub Actions
_ENV_GITHUB_ACTIONS: str = "GITHUB_ACTIONS"
_ENV_GITHUB_TOKEN: str = "GITHUB_TOKEN"
_ENV_GITHUB_REPOSITORY: str = "GITHUB_REPOSITORY"
_ENV_GITHUB_SHA: str = "GITHUB_SHA"
_ENV_GITHUB_REF: str = "GITHUB_REF"
_ENV_PR_NUMBER: str = "PR_NUMBER"

# GitLab CI
_ENV_GITLAB_CI: str = "GITLAB_CI"
_ENV_GITLAB_TOKEN: str = "GITLAB_TOKEN"
_ENV_CI_JOB_TOKEN: str = "CI_JOB_TOKEN"
_ENV_CI_PROJECT_ID: str = "CI_PROJECT_ID"
_ENV_CI_MERGE_REQUEST_IID: str = "CI_MERGE_REQUEST_IID"
_ENV_CI_SERVER_URL: str = "CI_SERVER_URL"
_ENV_CI_COMMIT_SHA: str = "CI_COMMIT_SHA"
_ENV_CI_COMMIT_REF_NAME: str = "CI_COMMIT_REF_NAME"

# Jenkins
_ENV_JENKINS_URL: str = "JENKINS_URL"
_ENV_CHANGE_ID: str = "CHANGE_ID"
_ENV_CHANGE_URL: str = "CHANGE_URL"

# Azure DevOps
_ENV_TF_BUILD: str = "TF_BUILD"
_ENV_SYSTEM_TEAMFOUNDATIONCOLLECTIONURI: str = "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"
_ENV_SYSTEM_TEAMPROJECT: str = "SYSTEM_TEAMPROJECT"
_ENV_SYSTEM_ACCESSTOKEN: str = "SYSTEM_ACCESSTOKEN"
_ENV_BUILD_REPOSITORY_ID: str = "BUILD_REPOSITORY_ID"
_ENV_BUILD_REPOSITORY_URI: str = "BUILD_REPOSITORY_URI"
_ENV_SYSTEM_PULLREQUEST_PULLREQUESTID: str = "SYSTEM_PULLREQUEST_PULLREQUESTID"
_ENV_BUILD_BUILDID: str = "BUILD_BUILDID"
_ENV_BUILD_SOURCEVERSION: str = "BUILD_SOURCEVERSION"

# CircleCI
_ENV_CIRCLECI: str = "CIRCLECI"
_ENV_CIRCLE_PULL_REQUEST: str = "CIRCLE_PULL_REQUEST"
_ENV_CIRCLE_SHA1: str = "CIRCLE_SHA1"
_ENV_CIRCLE_BRANCH: str = "CIRCLE_BRANCH"

# Bitbucket Pipelines
_ENV_BITBUCKET_BUILD_NUMBER: str = "BITBUCKET_BUILD_NUMBER"
_ENV_BITBUCKET_TOKEN: str = "BITBUCKET_TOKEN"
_ENV_BITBUCKET_PR_ID: str = "BITBUCKET_PR_ID"
_ENV_BITBUCKET_REPO_SLUG: str = "BITBUCKET_REPO_SLUG"
_ENV_BITBUCKET_WORKSPACE: str = "BITBUCKET_WORKSPACE"
_ENV_BITBUCKET_COMMIT: str = "BITBUCKET_COMMIT"

# AWS CodeBuild
_ENV_CODEBUILD_BUILD_ID: str = "CODEBUILD_BUILD_ID"
_ENV_CODEBUILD_WEBHOOK_TRIGGER: str = "CODEBUILD_WEBHOOK_TRIGGER"
_ENV_CODEBUILD_SOURCE_VERSION: str = "CODEBUILD_SOURCE_VERSION"
_ENV_CODEBUILD_WEBHOOK_BASE_REF: str = "CODEBUILD_WEBHOOK_BASE_REF"

# GitHub API
_GITHUB_API_BASE_URL: str = "https://api.github.com"
_GITHUB_API_PR_COMMENTS_PATH: str = "/repos/{repository}/issues/{pr_number}/comments"
_GITHUB_API_COMMIT_STATUSES_PATH: str = "/repos/{repository}/statuses/{sha}"

# GitLab API
_GITLAB_DEFAULT_SERVER_URL: str = "https://gitlab.com"
_GITLAB_API_MR_NOTES_PATH: str = "/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
_GITLAB_API_COMMIT_STATUSES_PATH: str = "/api/v4/projects/{project_id}/statuses/{sha}"

# Azure DevOps API
_AZURE_API_VERSION: str = "7.1"
_AZURE_PR_THREADS_PATH: str = (
    "{collection_uri}{team_project}/_apis/git/repositories/{repo_id}"
    "/pullRequests/{pr_id}/threads?api-version={api_version}"
)

# Bitbucket Cloud API
_BITBUCKET_API_BASE_URL: str = "https://api.bitbucket.org/2.0"
_BITBUCKET_PR_COMMENTS_PATH: str = (
    "/repositories/{workspace}/{repo_slug}/pullrequests/{pr_id}/comments"
)
_BITBUCKET_COMMIT_STATUS_PATH: str = (
    "/repositories/{workspace}/{repo_slug}/commit/{commit}/statuses/build"
)

# Comment templates
_COMMENT_HEADER_CLEAN: str = "## phi-scan: No PHI/PII Violations Found"
_COMMENT_HEADER_VIOLATIONS: str = "## phi-scan: PHI/PII Violations Detected"
_COMMENT_BADGE_CLEAN: str = "![clean](https://img.shields.io/badge/phi--scan-clean-green)"
_COMMENT_BADGE_VIOLATIONS: str = (
    "![violations](https://img.shields.io/badge/phi--scan-violations-red)"
)

# Commit status context name used across all platforms
_COMMIT_STATUS_CONTEXT: str = "phi-scan"
_COMMIT_STATUS_DESCRIPTION_CLEAN: str = "No PHI/PII violations found"
_COMMIT_STATUS_DESCRIPTION_VIOLATIONS: str = "{count} PHI/PII violation(s) found"

# HTTP timeout for all API calls
_HTTP_TIMEOUT_SECONDS: float = 15.0

# Maximum characters in a PR comment to stay within GitHub's 65536-char limit
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

# Maximum length of a SARIF result message.text before upload is aborted.
# _build_sarif_finding_message() produces at most ~1200 chars
# (remediation_hint max 1024 + category/layer/confidence overhead).
# Values well above this indicate unexpected content was embedded.
_SARIF_MAX_MESSAGE_TEXT_LENGTH: int = 1_500

# GitHub Code Scanning SARIF upload API
_GITHUB_API_SARIF_UPLOAD_PATH: str = "/repos/{repository}/code-scanning/sarifs"

# Azure DevOps build tag + PR status API paths
_AZURE_BUILD_TAGS_PATH: str = (
    "{collection_uri}{team_project}/_apis/build/builds/{build_id}"
    "/tags/{tag}?api-version={api_version}"
)
_AZURE_PR_STATUSES_PATH: str = (
    "{collection_uri}{team_project}/_apis/git/repositories/{repo_id}"
    "/pullRequests/{pr_id}/statuses?api-version={api_version}"
)
# Azure build tag values
_AZURE_TAG_CLEAN: str = "phi-scan:clean"
_AZURE_TAG_VIOLATIONS: str = "phi-scan:violations-found"

# Azure Boards work-item API
_AZURE_WORKITEM_TYPE: str = "Task"
_AZURE_WORKITEMS_PATH: str = (
    "{collection_uri}{team_project}/_apis/wit/workitems/${work_item_type}?api-version={api_version}"
)
_AZURE_WORKITEM_TITLE_FORMAT: str = (
    "phi-scan: {count} HIGH severity PHI/PII violation(s) in PR #{pull_request_number}"
)

# AWS Security Hub ASFF (Amazon Security Finding Format)
_AWS_SECURITY_HUB_PRODUCT_ARN_FORMAT: str = (
    "arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"
)
# ASFF uses "INFORMATIONAL" for INFO-level findings — different from SeverityLevel.INFO.value
_ASFF_INFO_SEVERITY_LABEL: str = "INFORMATIONAL"
_AWS_SECURITY_HUB_SEVERITY_MAP: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: SeverityLevel.HIGH.value.upper(),
    SeverityLevel.MEDIUM: SeverityLevel.MEDIUM.value.upper(),
    SeverityLevel.LOW: SeverityLevel.LOW.value.upper(),
    SeverityLevel.INFO: _ASFF_INFO_SEVERITY_LABEL,
}

# Bitbucket Code Insights API
_BITBUCKET_REPORTS_PATH: str = (
    "/repositories/{workspace}/{repo_slug}/commit/{commit}/reports/{report_id}"
)
_BITBUCKET_ANNOTATIONS_PATH: str = (
    "/repositories/{workspace}/{repo_slug}/commit/{commit}/reports/{report_id}/annotations"
)
_BITBUCKET_REPORT_ID: str = "phi-scan"
# Bitbucket Code Insights does not have an INFO severity level — INFO findings map to LOW
_BITBUCKET_INFO_MAPPED_SEVERITY: str = SeverityLevel.LOW.value.upper()
_BITBUCKET_ANNOTATION_SEVERITY_MAP: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: SeverityLevel.HIGH.value.upper(),
    SeverityLevel.MEDIUM: SeverityLevel.MEDIUM.value.upper(),
    SeverityLevel.LOW: SeverityLevel.LOW.value.upper(),
    SeverityLevel.INFO: _BITBUCKET_INFO_MAPPED_SEVERITY,
}


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class CIPlatform(enum.Enum):
    """Enumeration of supported CI/CD platforms."""

    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    AZURE_DEVOPS = "azure_devops"
    CIRCLECI = "circleci"
    BITBUCKET = "bitbucket"
    CODEBUILD = "codebuild"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PRContext:
    """Platform-neutral PR/MR context extracted from environment variables.

    Fields that are not available on the current platform are ``None``.
    The CLI passes this object to ``post_pr_comment`` and ``set_commit_status``.
    """

    platform: CIPlatform
    pr_number: str | None
    repository: str | None
    sha: str | None
    branch: str | None
    base_branch: str | None
    # Platform-specific extras stored as a plain dict
    extras: dict[str, str] = field(default_factory=dict)


class CIIntegrationError(PhiScanError):
    """Raised when a CI/CD platform API call fails."""


@dataclass(frozen=True)
class BaselineComparison:
    """Counts from a baseline comparison to include in PR/MR comment context.

    Wraps the three integer counts produced by comparing the current scan
    against an accepted findings baseline.
    """

    new_findings_count: int
    baselined_count: int
    resolved_count: int


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


def detect_platform() -> CIPlatform:
    """Detect the currently running CI/CD platform from environment variables.

    Checks well-known platform sentinel variables in order of specificity.
    Returns ``CIPlatform.UNKNOWN`` when none of the known sentinels are set.

    Returns:
        The detected ``CIPlatform`` enum member.
    """
    env_get = os.environ.get

    if env_get(_ENV_GITHUB_ACTIONS) == "true":
        return CIPlatform.GITHUB_ACTIONS
    if env_get(_ENV_GITLAB_CI) == "true":
        return CIPlatform.GITLAB_CI
    if env_get(_ENV_TF_BUILD) == "True":
        return CIPlatform.AZURE_DEVOPS
    if env_get(_ENV_CIRCLECI) == "true":
        return CIPlatform.CIRCLECI
    if env_get(_ENV_BITBUCKET_BUILD_NUMBER):
        return CIPlatform.BITBUCKET
    if env_get(_ENV_CODEBUILD_BUILD_ID):
        return CIPlatform.CODEBUILD
    if env_get(_ENV_JENKINS_URL):
        return CIPlatform.JENKINS
    return CIPlatform.UNKNOWN


def get_pr_context() -> PRContext:
    """Build a ``PRContext`` from the current environment.

    Reads platform-specific environment variables to extract the PR number,
    repository, commit SHA, and branch. Works for all seven supported platforms.
    Auto-detects the platform via ``detect_platform()``.

    Returns:
        A ``PRContext`` populated with whatever context is available.
    """
    platform = detect_platform()
    builder = _PLATFORM_CONTEXT_BUILDERS.get(platform, _build_unknown_context)
    return builder()


# ---------------------------------------------------------------------------
# Context builders — one per platform
# ---------------------------------------------------------------------------


def _env(name: str) -> str | None:
    """Return the environment variable value, or None if unset or empty."""
    value = os.environ.get(name, "").strip()
    return value if value else None


def _build_github_context() -> PRContext:
    pr_number = _env(_ENV_PR_NUMBER)
    if not pr_number:
        # Fall back to extracting from GITHUB_REF (refs/pull/N/merge)
        ref = _env(_ENV_GITHUB_REF) or ""
        if ref.startswith("refs/pull/"):
            pr_number = ref.split("/")[2]
    return PRContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pr_number=pr_number,
        repository=_env(_ENV_GITHUB_REPOSITORY),
        sha=_env(_ENV_GITHUB_SHA),
        branch=_env(_ENV_GITHUB_REF),
        base_branch=None,
    )


def _build_gitlab_context() -> PRContext:
    return PRContext(
        platform=CIPlatform.GITLAB_CI,
        pr_number=_env(_ENV_CI_MERGE_REQUEST_IID),
        repository=_env(_ENV_CI_PROJECT_ID),
        sha=_env(_ENV_CI_COMMIT_SHA),
        branch=_env(_ENV_CI_COMMIT_REF_NAME),
        base_branch=None,
        extras={
            "ci_server_url": _env(_ENV_CI_SERVER_URL) or _GITLAB_DEFAULT_SERVER_URL,
        },
    )


def _build_azure_context() -> PRContext:
    collection_uri = _env(_ENV_SYSTEM_TEAMFOUNDATIONCOLLECTIONURI) or ""
    # Normalize: ensure trailing slash
    if collection_uri and not collection_uri.endswith("/"):
        collection_uri += "/"
    return PRContext(
        platform=CIPlatform.AZURE_DEVOPS,
        pr_number=_env(_ENV_SYSTEM_PULLREQUEST_PULLREQUESTID),
        repository=_env(_ENV_BUILD_REPOSITORY_ID),
        sha=_env(_ENV_BUILD_SOURCEVERSION),
        branch=None,
        base_branch=None,
        extras={
            "collection_uri": collection_uri,
            "team_project": _env(_ENV_SYSTEM_TEAMPROJECT) or "",
            "build_id": _env(_ENV_BUILD_BUILDID) or "",
        },
    )


def _build_circleci_context() -> PRContext:
    pr_url = _env(_ENV_CIRCLE_PULL_REQUEST) or ""
    pr_number: str | None = None
    if pr_url:
        # URL form: https://github.com/org/repo/pull/42
        parts = pr_url.rstrip("/").split("/")
        if parts:
            candidate = parts[-1]
            if candidate.isdigit():
                pr_number = candidate
    return PRContext(
        platform=CIPlatform.CIRCLECI,
        pr_number=pr_number,
        repository=None,
        sha=_env(_ENV_CIRCLE_SHA1),
        branch=_env(_ENV_CIRCLE_BRANCH),
        base_branch=None,
        extras={"circle_pull_request_url": pr_url},
    )


def _build_bitbucket_context() -> PRContext:
    return PRContext(
        platform=CIPlatform.BITBUCKET,
        pr_number=_env(_ENV_BITBUCKET_PR_ID),
        repository=_env(_ENV_BITBUCKET_REPO_SLUG),
        sha=_env(_ENV_BITBUCKET_COMMIT),
        branch=None,
        base_branch=None,
        extras={
            "workspace": _env(_ENV_BITBUCKET_WORKSPACE) or "",
            "repo_slug": _env(_ENV_BITBUCKET_REPO_SLUG) or "",
        },
    )


def _build_codebuild_context() -> PRContext:
    trigger = _env(_ENV_CODEBUILD_WEBHOOK_TRIGGER) or ""
    pr_number: str | None = None
    if trigger.startswith("pr/"):
        pr_number = trigger[3:]
    return PRContext(
        platform=CIPlatform.CODEBUILD,
        pr_number=pr_number,
        repository=None,
        sha=_env(_ENV_CODEBUILD_SOURCE_VERSION),
        branch=None,
        base_branch=_env(_ENV_CODEBUILD_WEBHOOK_BASE_REF),
    )


def _build_jenkins_context() -> PRContext:
    return PRContext(
        platform=CIPlatform.JENKINS,
        pr_number=_env(_ENV_CHANGE_ID),
        repository=None,
        sha=None,
        branch=None,
        base_branch=None,
        extras={"change_url": _env(_ENV_CHANGE_URL) or ""},
    )


def _build_unknown_context() -> PRContext:
    return PRContext(
        platform=CIPlatform.UNKNOWN,
        pr_number=None,
        repository=None,
        sha=None,
        branch=None,
        base_branch=None,
    )


_PLATFORM_CONTEXT_BUILDERS: dict[CIPlatform, Callable[[], PRContext]] = {
    CIPlatform.GITHUB_ACTIONS: _build_github_context,
    CIPlatform.GITLAB_CI: _build_gitlab_context,
    CIPlatform.AZURE_DEVOPS: _build_azure_context,
    CIPlatform.CIRCLECI: _build_circleci_context,
    CIPlatform.BITBUCKET: _build_bitbucket_context,
    CIPlatform.CODEBUILD: _build_codebuild_context,
    CIPlatform.JENKINS: _build_jenkins_context,
}


# ---------------------------------------------------------------------------
# Comment body builder
# ---------------------------------------------------------------------------


def build_comment_body(scan_result: ScanResult) -> str:
    """Build a markdown PR/MR comment body from a ``ScanResult``.

    The body contains only counts, file names, and line numbers — never raw
    entity values. Truncated to ``_MAX_COMMENT_LENGTH`` characters to stay
    within platform comment size limits.

    Args:
        scan_result: The completed scan result to summarise.

    Returns:
        Markdown string suitable for posting as a PR/MR comment.
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
        return "\n".join(body_lines)

    findings_count = len(scan_result.findings)
    header = _COMMENT_HEADER_VIOLATIONS
    badge = _COMMENT_BADGE_VIOLATIONS

    severity_summary = ", ".join(
        f"{count} {level.value}"
        for level, count in sorted(
            scan_result.severity_counts.items(),
            key=lambda item: item[0].value,
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

    for finding in scan_result.findings[:50]:  # cap table at 50 rows
        body_lines.append(
            f"| `{finding.file_path}` | {finding.line_number} "
            f"| {finding.hipaa_category.value} "
            f"| {finding.severity.value} "
            f"| {finding.confidence:.0%} |"
        )

    if findings_count > 50:
        body_lines.append(f"| … and {findings_count - 50} more | | | | |")

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
    return comment_body


def _insert_baseline_context_into_comment(
    comment_body: str,
    baseline_line: str,
) -> str:
    """Insert a baseline context line after the first header line of a comment body.

    Splits on the first newline to separate the badge/header from the rest of the
    comment, then reassembles with the baseline line inserted between them.

    Args:
        comment_body:   Standard comment body produced by ``build_comment_body()``.
        baseline_line:  Pre-formatted baseline summary line to insert.

    Returns:
        Comment body with the baseline line inserted after the first header line.
    """
    lines = comment_body.split("\n", _COMMENT_BODY_SPLIT_MAX_PARTS)
    if len(lines) < _COMMENT_MIN_SECTION_COUNT:
        # Comment body has no header/body split — prepend baseline line instead
        return baseline_line + "\n\n" + comment_body
    return "\n".join([lines[0], "", baseline_line, "", *lines[1:]])


def build_comment_body_with_baseline(
    scan_result: ScanResult,
    baseline_comparison: BaselineComparison,
) -> str:
    """Build a PR/MR comment body that includes baseline comparison context.

    Adds a summary line of the form:
    "N new findings | M baselined | K resolved since last scan"

    Args:
        scan_result:          The completed scan result (all findings, pre-baseline filtering).
        baseline_comparison:  Counts from comparing the scan against an accepted baseline.

    Returns:
        Markdown string with baseline context prepended to the standard comment body.
    """
    baseline_line = _BASELINE_CONTEXT_FORMAT.format(
        new_findings_count=baseline_comparison.new_findings_count,
        baselined_count=baseline_comparison.baselined_count,
        resolved_count=baseline_comparison.resolved_count,
    )
    return _insert_baseline_context_into_comment(build_comment_body(scan_result), baseline_line)


# ---------------------------------------------------------------------------
# Public API — upload SARIF to GitHub Code Scanning (6C.5)
# ---------------------------------------------------------------------------


def _verify_sarif_excludes_code_snippets(sarif_content: str) -> None:
    """Verify the SARIF output contains no code snippet or contextRegion fields.

    This is a structural PHI-safety guard at the network boundary. It checks for
    two specific SARIF fields that would expose raw source content:

    - ``region.snippet``: inline code snippet of the matched line.
    - ``physicalLocation.contextRegion``: surrounding context lines.

    What this check does NOT cover: ``message.text`` content, file path strings,
    rule descriptions, or any other free-text fields. Those are trusted to be safe
    by the ``format_sarif()`` contract (which uses only PHI-safe ``ScanFinding``
    fields) and by ``ScanFinding.__post_init__`` validation. This guard defends
    against structural additions to the SARIF formatter (e.g. adding snippets),
    not against PHI inadvertently embedded in text fields.

    Args:
        sarif_content: SARIF 2.1.0 JSON string to validate.

    Raises:
        CIIntegrationError: When any result location contains a ``snippet`` or
            ``contextRegion`` field that could expose raw source content.
    """
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
    """Gzip-compress a SARIF JSON string to bytes.

    Args:
        sarif_content: Raw SARIF 2.1.0 JSON string.

    Returns:
        Gzip-compressed bytes of the UTF-8 encoded SARIF content.
    """
    return gzip.compress(sarif_content.encode("utf-8"))


def _base64_encode_bytes(raw_bytes: bytes) -> str:
    """Base64-encode bytes to an ASCII string.

    Args:
        raw_bytes: Bytes to encode.

    Returns:
        Base64-encoded ASCII string.
    """
    return base64.b64encode(raw_bytes).decode("ascii")


def upload_sarif_to_github(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Upload a SARIF report to the GitHub Code Scanning API for inline annotations.

    Each finding appears as an inline annotation on the exact line in the PR diff.
    Severity is mapped: HIGH→error, MEDIUM→warning, LOW/INFO→note.

    PHI-safety: ``scan_result`` is passed to ``format_sarif()`` internally — this
    function is the only path by which SARIF reaches the GitHub API, ensuring the
    formatter's PHI exclusions are always applied. ``format_sarif()`` emits only
    file path, line number, entity type, HIPAA category, detection layer, and
    remediation hint. It deliberately omits ``value_hash``, ``code_context``, and
    any raw matched values. This is enforced by ``ScanFinding.__post_init__``
    validation, not by caller discipline.

    Requires the ``security-events: write`` permission in the GitHub Actions workflow.

    Args:
        scan_result: Completed scan result — SARIF is generated internally.
        pr_context:  GitHub PR context with repository and SHA.

    Raises:
        CIIntegrationError: When the API call fails or authentication is missing.
    """
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

    url = _GITHUB_API_BASE_URL + _GITHUB_API_SARIF_UPLOAD_PATH.format(
        repository=repository,
    )
    sarif_upload_payload = {
        "commit_sha": sha,
        "ref": pr_context.branch or _DEFAULT_GIT_REF,
        "sarif": sarif_base64_encoded,
        "tool_name": "phi-scan",
    }

    try:
        response = httpx.post(
            url,
            json=sarif_upload_payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"GitHub SARIF upload failed (HTTP {status_error.response.status_code} "
            f"{status_error.response.reason_phrase})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"GitHub SARIF upload request failed: {request_error}"
        ) from request_error

    _LOG.debug("GitHub: SARIF uploaded to Code Scanning for %s", sha[:8])


# ---------------------------------------------------------------------------
# Public API — Bitbucket Code Insights annotations (6C.23 supplement)
# ---------------------------------------------------------------------------


def post_bitbucket_code_insights(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Post Bitbucket Code Insights report and inline annotations.

    Creates a Code Insights report on the commit and then adds one annotation
    per finding, pointing to the exact file and line in the PR diff.

    Args:
        scan_result: The completed scan result.
        pr_context:  Bitbucket context with commit SHA and workspace/repo.

    Raises:
        CIIntegrationError: When any API call fails.
    """
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
        "Content-Type": "application/json",
    }
    report_url = _BITBUCKET_API_BASE_URL + _BITBUCKET_REPORTS_PATH.format(
        workspace=workspace,
        repo_slug=repo_slug,
        commit=sha,
        report_id=_BITBUCKET_REPORT_ID,
    )

    # Create / update the report summary
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

    try:
        response = httpx.put(
            report_url,
            json=report_payload,
            headers=headers,
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"Bitbucket Code Insights report failed (HTTP {status_error.response.status_code})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"Bitbucket Code Insights report request failed: {request_error}"
        ) from request_error

    if not scan_result.findings:
        return

    # Post inline annotations (capped at 1000 — Bitbucket API limit)
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

    try:
        response = httpx.post(
            annotations_url,
            json=annotations,
            headers=headers,
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"Bitbucket Code Insights annotations failed (HTTP {status_error.response.status_code})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"Bitbucket Code Insights annotations request failed: {request_error}"
        ) from request_error

    _LOG.debug(
        "Bitbucket: Code Insights report + %d annotation(s) posted for %s",
        len(annotations),
        sha[:8],
    )


# ---------------------------------------------------------------------------
# Public API — Azure DevOps build tag + PR status (6C.17)
# ---------------------------------------------------------------------------


def set_azure_build_tag(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Tag the Azure DevOps build with phi-scan:clean or phi-scan:violations-found.

    Uses ``SYSTEM_ACCESSTOKEN`` for authentication. The build ID is read from
    the ``BUILD_BUILDID`` environment variable.

    Args:
        scan_result: The completed scan result.
        pr_context:  Azure DevOps context with collection URI, team project, build ID.

    Raises:
        CIIntegrationError: When the API call fails.
    """
    collection_uri = pr_context.extras.get("collection_uri", "")
    team_project = pr_context.extras.get("team_project", "")
    build_id = pr_context.extras.get("build_id", "")

    if not all([collection_uri, team_project, build_id]):
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

    try:
        response = httpx.put(
            url,
            content=b"",
            auth=("", token),
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"Azure DevOps build tag failed (HTTP {status_error.response.status_code})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"Azure DevOps build tag request failed: {request_error}"
        ) from request_error

    _LOG.debug("Azure DevOps: build tagged with %s", tag)


def set_azure_pr_status(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Set an Azure DevOps PR status to block or allow completion via branch policy.

    Posts to the Pull Request Statuses API so that a branch policy requiring
    a green phi-scan status can block PR completion on violations.

    Args:
        scan_result: The completed scan result.
        pr_context:  Azure DevOps PR context.

    Raises:
        CIIntegrationError: When the API call fails.
    """
    pr_id = pr_context.pr_number
    repo_id = pr_context.repository
    collection_uri = pr_context.extras.get("collection_uri", "")
    team_project = pr_context.extras.get("team_project", "")

    if not all([pr_id, repo_id, collection_uri, team_project]):
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

    try:
        response = httpx.post(
            url,
            json=payload,
            auth=("", token),
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"Azure DevOps PR status failed (HTTP {status_error.response.status_code})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"Azure DevOps PR status request failed: {request_error}"
        ) from request_error

    _LOG.debug("Azure DevOps: PR status set to %s for PR #%s", state, pr_id)


# ---------------------------------------------------------------------------
# Public API — Azure Boards work-item linking (6C.18, optional)
# ---------------------------------------------------------------------------


def create_azure_boards_work_item(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Create an Azure Boards Task work item for HIGH severity PHI/PII findings.

    Only creates a work item when there are HIGH severity findings and the
    ``AZURE_BOARDS_INTEGRATION`` environment variable is set to ``true``.
    Work items are linked to the current build for traceability.

    Args:
        scan_result: The completed scan result.
        pr_context:  Azure DevOps context.

    Raises:
        CIIntegrationError: When the API call fails.
    """
    if _env("AZURE_BOARDS_INTEGRATION") != "true":
        _LOG.debug("Azure Boards: AZURE_BOARDS_INTEGRATION not enabled — skipping")
        return

    high_findings = [f for f in scan_result.findings if f.severity.value.lower() == "high"]
    if not high_findings:
        _LOG.debug("Azure Boards: no HIGH severity findings — skipping work item")
        return

    collection_uri = pr_context.extras.get("collection_uri", "")
    team_project = pr_context.extras.get("team_project", "")
    pr_id = pr_context.pr_number or "unknown"

    if not all([collection_uri, team_project]):
        _LOG.debug("Azure Boards: missing context — skipping work item")
        return

    token = _env(_ENV_SYSTEM_ACCESSTOKEN)
    if not token:
        _LOG.warning("Azure Boards: SYSTEM_ACCESSTOKEN not set — skipping")
        return

    # PHI-safety: title and description contain only counts (int) and PR number (str) —
    # no finding text, entity values, matched strings, or file paths are included.
    title = _AZURE_WORKITEM_TITLE_FORMAT.format(count=len(high_findings), pull_request_number=pr_id)
    url = _AZURE_WORKITEMS_PATH.format(
        collection_uri=collection_uri,
        team_project=team_project,
        work_item_type=_AZURE_WORKITEM_TYPE,
        api_version=_AZURE_API_VERSION,
    )
    # Azure DevOps work-item PATCH format
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

    try:
        response = httpx.post(
            url,
            json=patch_payload,
            headers={
                "Content-Type": "application/json-patch+json",
            },
            auth=("", token),
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"Azure Boards work item failed (HTTP {status_error.response.status_code})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"Azure Boards work item request failed: {request_error}"
        ) from request_error

    _LOG.debug(
        "Azure Boards: work item created for PR #%s (%d HIGH findings)",
        pr_id,
        len(high_findings),
    )


# ---------------------------------------------------------------------------
# Public API — AWS Security Hub ASFF import (6C.27, optional)
# ---------------------------------------------------------------------------


def convert_findings_to_asff(
    scan_result: ScanResult,
    aws_account_id: str,
    aws_region: str,
    repository: str,
) -> list[dict[str, Any]]:
    """Convert phi-scan findings to AWS Security Finding Format (ASFF).

    Produces one ASFF finding per phi-scan finding. Each ASFF finding includes:
    file path, line number, severity, HIPAA category, confidence, and remediation hint.
    No raw entity values are included — only the value hash.

    Args:
        scan_result:    The completed scan result.
        aws_account_id: AWS account ID (12-digit string).
        aws_region:     AWS region (e.g. ``us-east-1``).
        repository:     Repository identifier for the ProductArn.

    Returns:
        List of ASFF finding dicts ready to pass to BatchImportFindings.
    """
    from datetime import UTC, datetime

    product_arn = _AWS_SECURITY_HUB_PRODUCT_ARN_FORMAT.format(
        region=aws_region,
        account_id=aws_account_id,
    )
    now_iso = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    asff_findings = []
    for finding in scan_result.findings:
        severity_label = _AWS_SECURITY_HUB_SEVERITY_MAP.get(finding.severity, "MEDIUM")
        # ASFF severity normalised score: HIGH=70, MEDIUM=40, LOW=10, INFO=0
        severity_score_map = {"HIGH": 70, "MEDIUM": 40, "LOW": 10, "INFORMATIONAL": 0}
        severity_score = severity_score_map.get(severity_label, 40)

        asff_finding: dict[str, Any] = {
            "SchemaVersion": "2018-10-08",
            "Id": (
                f"{repository}/{finding.file_path}/{finding.line_number}/{finding.value_hash[:16]}"
            ),
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
                            "value_hash": finding.value_hash,
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
    """Import phi-scan findings to AWS Security Hub via BatchImportFindings.

    Only runs when ``AWS_SECURITY_HUB`` environment variable is set to ``true``
    and ``AWS_ACCOUNT_ID`` / ``AWS_DEFAULT_REGION`` are available. Uses the
    AWS CLI (``aws securityhub batch-import-findings``) to avoid adding boto3
    as a hard dependency.

    Args:
        scan_result: The completed scan result.
        pr_context:  Context providing the repository identifier.

    Raises:
        CIIntegrationError: When the AWS CLI invocation fails.
    """
    if _env("AWS_SECURITY_HUB") != "true":
        _LOG.debug("Security Hub: AWS_SECURITY_HUB not enabled — skipping")
        return

    if scan_result.is_clean:
        _LOG.debug("Security Hub: no findings to import")
        return

    account_id = _env("AWS_ACCOUNT_ID") or ""
    region = _env("AWS_DEFAULT_REGION") or _env("AWS_REGION") or "us-east-1"
    repository = pr_context.repository or _env(_ENV_GITHUB_REPOSITORY) or "unknown/repo"

    if not account_id:
        _LOG.warning("Security Hub: AWS_ACCOUNT_ID not set — skipping")
        return

    import json as _json

    asff_findings = convert_findings_to_asff(scan_result, account_id, region, repository)
    findings_json = _json.dumps({"Findings": asff_findings})

    try:
        result = subprocess.run(
            ["aws", "securityhub", "batch-import-findings", "--cli-input-json", findings_json],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise CIIntegrationError(
                f"AWS Security Hub import failed (exit {result.returncode}): "
                f"{result.stderr.strip()[:_MAX_ERROR_RESPONSE_LOG_LENGTH]}"
            )
    except FileNotFoundError as not_found_error:
        raise CIIntegrationError(
            "AWS CLI not found — install awscli to enable Security Hub integration"
        ) from not_found_error

    _LOG.debug("Security Hub: imported %d ASFF finding(s)", len(asff_findings))


# ---------------------------------------------------------------------------
# Public API — post PR/MR comment
# ---------------------------------------------------------------------------


def post_pr_comment(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Post a PR/MR comment with scan findings to the detected CI/CD platform.

    Selects the platform-specific implementation based on ``pr_context.platform``.
    Does nothing and logs a warning when the platform is ``UNKNOWN`` or when
    required context (PR number, token) is missing.

    Args:
        scan_result: The completed scan result.
        pr_context:  Platform context extracted from environment variables.

    Raises:
        CIIntegrationError: When the platform API call fails.
    """
    if not pr_context.pr_number:
        _LOG.debug("No PR number in context — skipping comment posting")
        return

    poster = _PLATFORM_COMMENT_POSTERS.get(pr_context.platform)
    if poster is None:
        _LOG.warning(
            "PR comment posting not implemented for platform %s",
            pr_context.platform.value,
        )
        return

    comment_body = build_comment_body(scan_result)
    poster(comment_body, pr_context)


# ---------------------------------------------------------------------------
# Public API — set commit status
# ---------------------------------------------------------------------------


def set_commit_status(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Set the commit status (PASS/FAIL) on the CI/CD platform.

    Selects the platform-specific implementation based on ``pr_context.platform``.
    Does nothing and logs a warning when required context (SHA, token) is missing.

    Args:
        scan_result: The completed scan result.
        pr_context:  Platform context extracted from environment variables.

    Raises:
        CIIntegrationError: When the platform API call fails.
    """
    if not pr_context.sha:
        _LOG.debug("No commit SHA in context — skipping status posting")
        return

    setter = _PLATFORM_STATUS_SETTERS.get(pr_context.platform)
    if setter is None:
        _LOG.warning(
            "Commit status not implemented for platform %s",
            pr_context.platform.value,
        )
        return

    setter(scan_result, pr_context)


# ---------------------------------------------------------------------------
# Platform-specific comment posters
# ---------------------------------------------------------------------------


def _post_github_pr_comment(comment_body: str, pr_context: PRContext) -> None:
    """Post a GitHub PR comment using the ``gh`` CLI.

    Uses ``gh pr comment`` so that authentication, pagination, and API version
    negotiation are handled by the GitHub CLI. Requires ``gh`` to be installed
    and authenticated (``GITHUB_TOKEN`` in the environment).

    Args:
        comment_body: Markdown comment text.
        pr_context:   GitHub PR context.

    Raises:
        CIIntegrationError: When the ``gh`` CLI invocation fails.
    """
    pr_number = pr_context.pr_number
    if not pr_number:
        _LOG.debug("GitHub: no PR number — skipping comment")
        return

    token = _env(_ENV_GITHUB_TOKEN)
    if not token:
        _LOG.warning("GitHub: GITHUB_TOKEN not set — skipping comment")
        return

    env = {**os.environ, "GITHUB_TOKEN": token}
    if pr_context.repository:
        env["GH_REPO"] = pr_context.repository

    try:
        result = subprocess.run(
            [
                "gh",
                "pr",
                "comment",
                str(pr_number),
                "--body",
                comment_body,
                "--edit-last",
            ],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        if result.returncode != 0:
            # --edit-last fails when there is no existing comment — fall back to create
            result = subprocess.run(
                ["gh", "pr", "comment", str(pr_number), "--body", comment_body],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
        if result.returncode != 0:
            raise CIIntegrationError(
                f"gh pr comment failed (exit {result.returncode}): "
                f"{result.stderr.strip()[:_MAX_ERROR_RESPONSE_LOG_LENGTH]}"
            )
    except FileNotFoundError as not_found_error:
        raise CIIntegrationError(
            "gh CLI not found — install the GitHub CLI to enable PR comment posting"
        ) from not_found_error

    _LOG.debug("GitHub: PR comment posted to #%s", pr_number)


def _post_gitlab_mr_comment(comment_body: str, pr_context: PRContext) -> None:
    """Post a GitLab MR note using the GitLab REST API.

    Uses ``GITLAB_TOKEN`` (personal access token or project access token) or
    ``CI_JOB_TOKEN`` (automatically available in GitLab CI pipelines).

    Args:
        comment_body: Markdown comment text.
        pr_context:   GitLab MR context.

    Raises:
        CIIntegrationError: When the API call fails or authentication is missing.
    """
    mr_iid = pr_context.pr_number
    project_id = pr_context.repository
    if not mr_iid or not project_id:
        _LOG.debug("GitLab: missing MR IID or project ID — skipping comment")
        return

    token = _env(_ENV_GITLAB_TOKEN) or _env(_ENV_CI_JOB_TOKEN)
    if not token:
        _LOG.warning("GitLab: GITLAB_TOKEN and CI_JOB_TOKEN not set — skipping comment")
        return

    server_url = pr_context.extras.get("ci_server_url") or _GITLAB_DEFAULT_SERVER_URL
    url = server_url.rstrip("/") + _GITLAB_API_MR_NOTES_PATH.format(
        project_id=project_id,
        mr_iid=mr_iid,
    )
    headers = {"PRIVATE-TOKEN": token, "Content-Type": "application/json"}
    payload = {"body": comment_body}

    try:
        response = httpx.post(
            url,
            headers=headers,
            json=payload,
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"GitLab MR comment failed (HTTP {status_error.response.status_code} "
            f"{status_error.response.reason_phrase})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"GitLab MR comment request failed: {request_error}"
        ) from request_error

    _LOG.debug("GitLab: MR note posted to !%s", mr_iid)


def _post_azure_pr_comment(comment_body: str, pr_context: PRContext) -> None:
    """Post an Azure DevOps PR thread comment using the Azure DevOps REST API.

    Uses ``SYSTEM_ACCESSTOKEN`` (automatically available in Azure Pipelines when
    'Allow scripts to access the OAuth token' is enabled in the pipeline settings).

    Args:
        comment_body: Markdown comment text.
        pr_context:   Azure DevOps PR context.

    Raises:
        CIIntegrationError: When the API call fails or authentication is missing.
    """
    pr_id = pr_context.pr_number
    repo_id = pr_context.repository
    collection_uri = pr_context.extras.get("collection_uri", "")
    team_project = pr_context.extras.get("team_project", "")

    if not all([pr_id, repo_id, collection_uri, team_project]):
        _LOG.debug("Azure DevOps: missing PR context — skipping comment")
        return

    token = _env(_ENV_SYSTEM_ACCESSTOKEN)
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
        "comments": [{"parentCommentId": 0, "content": comment_body, "commentType": 1}],
        "status": "active",
    }

    try:
        response = httpx.post(
            url,
            json=payload,
            auth=("", token),
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"Azure DevOps PR comment failed (HTTP {status_error.response.status_code} "
            f"{status_error.response.reason_phrase})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"Azure DevOps PR comment request failed: {request_error}"
        ) from request_error

    _LOG.debug("Azure DevOps: PR thread comment posted to PR #%s", pr_id)


def _post_bitbucket_pr_comment(comment_body: str, pr_context: PRContext) -> None:
    """Post a Bitbucket Cloud PR comment using the Bitbucket REST API.

    Uses ``BITBUCKET_TOKEN`` (repository or workspace access token).

    Args:
        comment_body: Markdown comment text.
        pr_context:   Bitbucket PR context.

    Raises:
        CIIntegrationError: When the API call fails or authentication is missing.
    """
    pr_id = pr_context.pr_number
    workspace = pr_context.extras.get("workspace", "")
    repo_slug = pr_context.extras.get("repo_slug", "")

    if not all([pr_id, workspace, repo_slug]):
        _LOG.debug("Bitbucket: missing PR context — skipping comment")
        return

    token = _env(_ENV_BITBUCKET_TOKEN)
    if not token:
        _LOG.warning("Bitbucket: BITBUCKET_TOKEN not set — skipping comment")
        return

    url = _BITBUCKET_API_BASE_URL + _BITBUCKET_PR_COMMENTS_PATH.format(
        workspace=workspace,
        repo_slug=repo_slug,
        pr_id=pr_id,
    )

    try:
        response = httpx.post(
            url,
            json={"content": {"raw": comment_body}},
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"Bitbucket PR comment failed (HTTP {status_error.response.status_code} "
            f"{status_error.response.reason_phrase})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"Bitbucket PR comment request failed: {request_error}"
        ) from request_error

    _LOG.debug("Bitbucket: PR comment posted to PR #%s", pr_id)


def _post_circleci_pr_comment(comment_body: str, pr_context: PRContext) -> None:
    """Post a CircleCI PR comment by auto-detecting the VCS provider.

    Inspects ``CIRCLE_PULL_REQUEST`` to determine whether the VCS is GitHub
    (github.com) or Bitbucket (bitbucket.org), then posts via the appropriate
    platform API.

    Args:
        comment_body: Markdown comment text.
        pr_context:   CircleCI PR context.
    """
    pr_url = pr_context.extras.get("circle_pull_request_url", "")
    if not pr_url:
        _LOG.debug("CircleCI: CIRCLE_PULL_REQUEST not set — skipping comment")
        return

    if "github.com" in pr_url:
        # Re-use GitHub poster via a synthetic GitHub context
        # Extract org/repo from the PR URL
        parts = pr_url.rstrip("/").split("/")
        # https://github.com/ORG/REPO/pull/N  ->  parts[-4] = ORG, parts[-3] = REPO
        if len(parts) >= 5:
            repository = f"{parts[-4]}/{parts[-3]}"
        else:
            repository = None
        github_context = PRContext(
            platform=CIPlatform.GITHUB_ACTIONS,
            pr_number=pr_context.pr_number,
            repository=repository,
            sha=pr_context.sha,
            branch=pr_context.branch,
            base_branch=pr_context.base_branch,
        )
        _post_github_pr_comment(comment_body, github_context)
    elif "bitbucket.org" in pr_url:
        parts = pr_url.rstrip("/").split("/")
        if len(parts) >= 5:
            workspace = parts[-4]
            repo_slug = parts[-3]
        else:
            workspace = repo_slug = ""
        bb_context = PRContext(
            platform=CIPlatform.BITBUCKET,
            pr_number=pr_context.pr_number,
            repository=pr_context.repository,
            sha=pr_context.sha,
            branch=pr_context.branch,
            base_branch=pr_context.base_branch,
            extras={"workspace": workspace, "repo_slug": repo_slug},
        )
        _post_bitbucket_pr_comment(comment_body, bb_context)
    else:
        _LOG.warning("CircleCI: unrecognized VCS in CIRCLE_PULL_REQUEST URL — skipping comment")


def _post_codebuild_pr_comment(comment_body: str, pr_context: PRContext) -> None:
    """Post a CodeBuild PR comment by auto-detecting the source provider.

    Uses ``GITHUB_TOKEN`` for GitHub-sourced builds and ``BITBUCKET_TOKEN``
    for Bitbucket-sourced builds.  Source is detected from the build environment
    — CodeBuild sets ``CODEBUILD_SOURCE_REPO_URL`` for webhook-triggered builds.

    Args:
        comment_body: Markdown comment text.
        pr_context:   CodeBuild PR context.
    """
    # CodeBuild doesn't expose an explicit VCS-type env var; infer from repo URL
    repo_url = os.environ.get("CODEBUILD_SOURCE_REPO_URL", "")
    if "github.com" in repo_url:
        parts = repo_url.rstrip("/").rstrip(".git").split("/")
        repository = f"{parts[-2]}/{parts[-1]}" if len(parts) >= 2 else None
        github_context = PRContext(
            platform=CIPlatform.GITHUB_ACTIONS,
            pr_number=pr_context.pr_number,
            repository=repository,
            sha=pr_context.sha,
            branch=pr_context.branch,
            base_branch=pr_context.base_branch,
        )
        _post_github_pr_comment(comment_body, github_context)
    elif "bitbucket.org" in repo_url:
        parts = repo_url.rstrip("/").rstrip(".git").split("/")
        workspace = parts[-2] if len(parts) >= 2 else ""
        repo_slug = parts[-1] if parts else ""
        bb_context = PRContext(
            platform=CIPlatform.BITBUCKET,
            pr_number=pr_context.pr_number,
            repository=pr_context.repository,
            sha=pr_context.sha,
            branch=pr_context.branch,
            base_branch=pr_context.base_branch,
            extras={"workspace": workspace, "repo_slug": repo_slug},
        )
        _post_bitbucket_pr_comment(comment_body, bb_context)
    else:
        _LOG.warning("CodeBuild: unrecognised source repo URL — skipping PR comment")


_PLATFORM_COMMENT_POSTERS: dict[CIPlatform, Any] = {
    CIPlatform.GITHUB_ACTIONS: _post_github_pr_comment,
    CIPlatform.GITLAB_CI: _post_gitlab_mr_comment,
    CIPlatform.AZURE_DEVOPS: _post_azure_pr_comment,
    CIPlatform.BITBUCKET: _post_bitbucket_pr_comment,
    CIPlatform.CIRCLECI: _post_circleci_pr_comment,
    CIPlatform.CODEBUILD: _post_codebuild_pr_comment,
}


# ---------------------------------------------------------------------------
# Platform-specific commit status setters
# ---------------------------------------------------------------------------


def _set_github_commit_status(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Set a GitHub commit status via the GitHub REST API.

    Uses ``GITHUB_TOKEN`` from the environment.

    Args:
        scan_result: The completed scan result.
        pr_context:  GitHub PR context with SHA and repository.

    Raises:
        CIIntegrationError: When the API call fails.
    """
    sha = pr_context.sha
    repository = pr_context.repository
    if not sha or not repository:
        _LOG.debug("GitHub: missing SHA or repository — skipping status")
        return

    token = _env(_ENV_GITHUB_TOKEN)
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

    try:
        response = httpx.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"GitHub commit status failed (HTTP {status_error.response.status_code} "
            f"{status_error.response.reason_phrase})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"GitHub commit status request failed: {request_error}"
        ) from request_error

    _LOG.debug("GitHub: commit status set to %s for %s", github_state, sha[:8])


def _set_gitlab_commit_status(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Set a GitLab commit status using the GitLab REST API.

    Args:
        scan_result: The completed scan result.
        pr_context:  GitLab context with SHA and project ID.

    Raises:
        CIIntegrationError: When the API call fails.
    """
    sha = pr_context.sha
    project_id = pr_context.repository
    if not sha or not project_id:
        _LOG.debug("GitLab: missing SHA or project ID — skipping status")
        return

    token = _env(_ENV_GITLAB_TOKEN) or _env(_ENV_CI_JOB_TOKEN)
    if not token:
        _LOG.warning("GitLab: no token — skipping commit status")
        return

    server_url = pr_context.extras.get("ci_server_url") or _GITLAB_DEFAULT_SERVER_URL
    state = "success" if scan_result.is_clean else "failed"
    url = server_url.rstrip("/") + _GITLAB_API_COMMIT_STATUSES_PATH.format(
        project_id=project_id,
        sha=sha,
    )
    payload = {
        "state": state,
        "name": _COMMIT_STATUS_CONTEXT,
        "description": (
            _COMMIT_STATUS_DESCRIPTION_CLEAN
            if scan_result.is_clean
            else _COMMIT_STATUS_DESCRIPTION_VIOLATIONS.format(count=len(scan_result.findings))
        ),
    }

    try:
        response = httpx.post(
            url,
            json=payload,
            headers={"PRIVATE-TOKEN": token},
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"GitLab commit status failed (HTTP {status_error.response.status_code})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"GitLab commit status request failed: {request_error}"
        ) from request_error

    _LOG.debug("GitLab: commit status set to %s for %s", state, sha[:8])


def _set_bitbucket_commit_status(scan_result: ScanResult, pr_context: PRContext) -> None:
    """Set a Bitbucket commit build status using the Bitbucket Commit Status API.

    Args:
        scan_result: The completed scan result.
        pr_context:  Bitbucket context with commit SHA.

    Raises:
        CIIntegrationError: When the API call fails.
    """
    sha = pr_context.sha
    workspace = pr_context.extras.get("workspace", "")
    repo_slug = pr_context.extras.get("repo_slug", "")
    if not sha or not workspace or not repo_slug:
        _LOG.debug("Bitbucket: missing context — skipping commit status")
        return

    token = _env(_ENV_BITBUCKET_TOKEN)
    if not token:
        _LOG.warning("Bitbucket: BITBUCKET_TOKEN not set — skipping commit status")
        return

    state = "SUCCESSFUL" if scan_result.is_clean else "FAILED"
    url = _BITBUCKET_API_BASE_URL + _BITBUCKET_COMMIT_STATUS_PATH.format(
        workspace=workspace,
        repo_slug=repo_slug,
        commit=sha,
    )
    payload = {
        "key": _COMMIT_STATUS_CONTEXT,
        "state": state,
        "name": "phi-scan",
        "description": (
            _COMMIT_STATUS_DESCRIPTION_CLEAN
            if scan_result.is_clean
            else _COMMIT_STATUS_DESCRIPTION_VIOLATIONS.format(count=len(scan_result.findings))
        ),
    }

    try:
        response = httpx.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            f"Bitbucket commit status failed (HTTP {status_error.response.status_code})"
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            f"Bitbucket commit status request failed: {request_error}"
        ) from request_error

    _LOG.debug("Bitbucket: commit status set to %s for %s", state, sha[:8])


_PLATFORM_STATUS_SETTERS: dict[CIPlatform, Any] = {
    CIPlatform.GITHUB_ACTIONS: _set_github_commit_status,
    CIPlatform.GITLAB_CI: _set_gitlab_commit_status,
    CIPlatform.BITBUCKET: _set_bitbucket_commit_status,
}
