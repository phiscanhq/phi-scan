"""CI/CD platform detection and PR context extraction.

Auto-detects the running CI/CD platform from environment variables and
extracts PR/MR context into a platform-neutral ``PRContext`` dataclass.
"""

from __future__ import annotations

import enum
import os
from collections.abc import Callable
from dataclasses import dataclass, field

__all__ = [
    "CIPlatform",
    "PRContext",
    "detect_platform",
    "get_pr_context",
    "read_env_variable",
]

# ---------------------------------------------------------------------------
# Environment variable names — one block per platform
# ---------------------------------------------------------------------------

# GitHub Actions
_ENV_GITHUB_ACTIONS: str = "GITHUB_ACTIONS"
_ENV_GITHUB_REPOSITORY: str = "GITHUB_REPOSITORY"
_ENV_GITHUB_SHA: str = "GITHUB_SHA"
_ENV_GITHUB_REF: str = "GITHUB_REF"
_ENV_PR_NUMBER: str = "PR_NUMBER"

# GitLab CI
_ENV_GITLAB_CI: str = "GITLAB_CI"
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
_ENV_BUILD_REPOSITORY_ID: str = "BUILD_REPOSITORY_ID"
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
_ENV_BITBUCKET_PR_ID: str = "BITBUCKET_PR_ID"
_ENV_BITBUCKET_REPO_SLUG: str = "BITBUCKET_REPO_SLUG"
_ENV_BITBUCKET_WORKSPACE: str = "BITBUCKET_WORKSPACE"
_ENV_BITBUCKET_COMMIT: str = "BITBUCKET_COMMIT"

# AWS CodeBuild
_ENV_CODEBUILD_BUILD_ID: str = "CODEBUILD_BUILD_ID"
_ENV_CODEBUILD_WEBHOOK_TRIGGER: str = "CODEBUILD_WEBHOOK_TRIGGER"
_ENV_CODEBUILD_SOURCE_VERSION: str = "CODEBUILD_SOURCE_VERSION"
_ENV_CODEBUILD_WEBHOOK_BASE_REF: str = "CODEBUILD_WEBHOOK_BASE_REF"

# GitLab default
_GITLAB_DEFAULT_SERVER_URL: str = "https://gitlab.com"

# GitHub ref prefix for PR detection (e.g. "refs/pull/42/merge")
_GITHUB_PR_REF_PREFIX: str = "refs/pull/"
_GITHUB_PR_REF_NUMBER_INDEX: int = 2

# CodeBuild webhook trigger prefix for PR detection (e.g. "pr/42")
_CODEBUILD_PR_TRIGGER_PREFIX: str = "pr/"


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
    extras: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


def detect_platform() -> CIPlatform:
    """Detect the currently running CI/CD platform from environment variables.

    Checks well-known platform sentinel variables in order of specificity.
    Returns ``CIPlatform.UNKNOWN`` when none of the known sentinels are set.
    """
    if os.environ.get(_ENV_GITHUB_ACTIONS) == "true":
        return CIPlatform.GITHUB_ACTIONS
    if os.environ.get(_ENV_GITLAB_CI) == "true":
        return CIPlatform.GITLAB_CI
    if os.environ.get(_ENV_TF_BUILD) == "True":
        return CIPlatform.AZURE_DEVOPS
    if os.environ.get(_ENV_CIRCLECI) == "true":
        return CIPlatform.CIRCLECI
    if os.environ.get(_ENV_BITBUCKET_BUILD_NUMBER):
        return CIPlatform.BITBUCKET
    if os.environ.get(_ENV_CODEBUILD_BUILD_ID):
        return CIPlatform.CODEBUILD
    if os.environ.get(_ENV_JENKINS_URL):
        return CIPlatform.JENKINS
    return CIPlatform.UNKNOWN


def get_pr_context() -> PRContext:
    """Build a ``PRContext`` from the current environment.

    Reads platform-specific environment variables to extract the PR number,
    repository, commit SHA, and branch.
    """
    platform = detect_platform()
    builder = _PLATFORM_CONTEXT_BUILDERS.get(platform, _build_unknown_context)
    return builder()


# ---------------------------------------------------------------------------
# Context builders — one per platform
# ---------------------------------------------------------------------------


def read_env_variable(name: str) -> str | None:
    """Return the environment variable value, or None if unset or empty."""
    env_value = os.environ.get(name, "").strip()
    return env_value if env_value else None


def _extract_github_pr_number(ref: str) -> str | None:
    if ref.startswith(_GITHUB_PR_REF_PREFIX):
        return ref.split("/")[_GITHUB_PR_REF_NUMBER_INDEX]
    return None


def _build_github_context() -> PRContext:
    pr_number = read_env_variable(_ENV_PR_NUMBER)
    if not pr_number:
        ref = read_env_variable(_ENV_GITHUB_REF) or ""
        pr_number = _extract_github_pr_number(ref)
    return PRContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pr_number=pr_number,
        repository=read_env_variable(_ENV_GITHUB_REPOSITORY),
        sha=read_env_variable(_ENV_GITHUB_SHA),
        branch=read_env_variable(_ENV_GITHUB_REF),
        base_branch=None,
    )


def _build_gitlab_context() -> PRContext:
    return PRContext(
        platform=CIPlatform.GITLAB_CI,
        pr_number=read_env_variable(_ENV_CI_MERGE_REQUEST_IID),
        repository=read_env_variable(_ENV_CI_PROJECT_ID),
        sha=read_env_variable(_ENV_CI_COMMIT_SHA),
        branch=read_env_variable(_ENV_CI_COMMIT_REF_NAME),
        base_branch=None,
        extras={
            "ci_server_url": read_env_variable(_ENV_CI_SERVER_URL) or _GITLAB_DEFAULT_SERVER_URL,
        },
    )


def _append_trailing_slash(uri: str) -> str:
    if uri and not uri.endswith("/"):
        return uri + "/"
    return uri


def _build_azure_context() -> PRContext:
    unformatted_uri = read_env_variable(_ENV_SYSTEM_TEAMFOUNDATIONCOLLECTIONURI) or ""
    collection_uri = _append_trailing_slash(unformatted_uri)
    return PRContext(
        platform=CIPlatform.AZURE_DEVOPS,
        pr_number=read_env_variable(_ENV_SYSTEM_PULLREQUEST_PULLREQUESTID),
        repository=read_env_variable(_ENV_BUILD_REPOSITORY_ID),
        sha=read_env_variable(_ENV_BUILD_SOURCEVERSION),
        branch=None,
        base_branch=None,
        extras={
            "collection_uri": collection_uri,
            "team_project": read_env_variable(_ENV_SYSTEM_TEAMPROJECT) or "",
            "build_id": read_env_variable(_ENV_BUILD_BUILDID) or "",
        },
    )


def _extract_pr_number_from_url(pr_url: str) -> str | None:
    if not pr_url:
        return None
    url_segments = pr_url.rstrip("/").split("/")
    if not url_segments:
        return None
    pr_number_candidate = url_segments[-1]
    return pr_number_candidate if pr_number_candidate.isdigit() else None


def _build_circleci_context() -> PRContext:
    pr_url = read_env_variable(_ENV_CIRCLE_PULL_REQUEST) or ""
    pr_number = _extract_pr_number_from_url(pr_url)
    return PRContext(
        platform=CIPlatform.CIRCLECI,
        pr_number=pr_number,
        repository=None,
        sha=read_env_variable(_ENV_CIRCLE_SHA1),
        branch=read_env_variable(_ENV_CIRCLE_BRANCH),
        base_branch=None,
        extras={"circle_pull_request_url": pr_url},
    )


def _build_bitbucket_context() -> PRContext:
    return PRContext(
        platform=CIPlatform.BITBUCKET,
        pr_number=read_env_variable(_ENV_BITBUCKET_PR_ID),
        repository=read_env_variable(_ENV_BITBUCKET_REPO_SLUG),
        sha=read_env_variable(_ENV_BITBUCKET_COMMIT),
        branch=None,
        base_branch=None,
        extras={
            "workspace": read_env_variable(_ENV_BITBUCKET_WORKSPACE) or "",
            "repo_slug": read_env_variable(_ENV_BITBUCKET_REPO_SLUG) or "",
        },
    )


def _build_codebuild_context() -> PRContext:
    trigger = read_env_variable(_ENV_CODEBUILD_WEBHOOK_TRIGGER) or ""
    pr_number: str | None = None
    if trigger.startswith(_CODEBUILD_PR_TRIGGER_PREFIX):
        pr_number = trigger[len(_CODEBUILD_PR_TRIGGER_PREFIX) :]
    return PRContext(
        platform=CIPlatform.CODEBUILD,
        pr_number=pr_number,
        repository=None,
        sha=read_env_variable(_ENV_CODEBUILD_SOURCE_VERSION),
        branch=None,
        base_branch=read_env_variable(_ENV_CODEBUILD_WEBHOOK_BASE_REF),
    )


def _build_jenkins_context() -> PRContext:
    return PRContext(
        platform=CIPlatform.JENKINS,
        pr_number=read_env_variable(_ENV_CHANGE_ID),
        repository=None,
        sha=None,
        branch=None,
        base_branch=None,
        extras={"change_url": read_env_variable(_ENV_CHANGE_URL) or ""},
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
