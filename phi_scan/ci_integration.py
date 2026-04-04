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
  - All HTTP calls use ``httpx`` (already a project dependency).
  - ``gh`` CLI is used for GitHub because it handles token auth and API versioning.
  - Authentication tokens are read from environment variables only — never from
    config files (which may be committed to version control).
"""

from __future__ import annotations

import enum
import logging
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from phi_scan.exceptions import PhiScanError
from phi_scan.models import ScanResult

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
                f"gh pr comment failed (exit {result.returncode}): {result.stderr.strip()}"
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
            f"GitLab MR comment failed (HTTP {status_error.response.status_code}): "
            f"{status_error.response.text[:200]}"
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
            f"Azure DevOps PR comment failed (HTTP {status_error.response.status_code}): "
            f"{status_error.response.text[:200]}"
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
            f"Bitbucket PR comment failed (HTTP {status_error.response.status_code}): "
            f"{status_error.response.text[:200]}"
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
            f"GitHub commit status failed (HTTP {status_error.response.status_code}): "
            f"{status_error.response.text[:200]}"
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
