"""CI/CD platform integration package.

Provides per-platform adapters for posting PR comments and setting
commit statuses, plus platform auto-detection from environment variables.

Public API — all names below are importable from ``phi_scan.ci``:

    from phi_scan.ci import (
        BaseCIAdapter,
        CIPlatform,
        PullRequestContext,
        detect_platform,
        get_pull_request_context,
        resolve_adapter,
    )
"""

from __future__ import annotations

from phi_scan.ci._base import BaseCIAdapter, SanitisedCommentBody
from phi_scan.ci._detect import (
    CIPlatform,
    PullRequestContext,
    detect_platform,
    get_pull_request_context,
)
from phi_scan.ci.azure import AzureAdapter
from phi_scan.ci.bitbucket import BitbucketAdapter
from phi_scan.ci.circleci import CircleCIAdapter
from phi_scan.ci.codebuild import CodeBuildAdapter
from phi_scan.ci.github import GitHubAdapter
from phi_scan.ci.gitlab import GitLabAdapter
from phi_scan.ci.jenkins import JenkinsAdapter
from phi_scan.exceptions import CIIntegrationError

PRContext = PullRequestContext
get_pr_context = get_pull_request_context

_PLATFORM_ADAPTERS: dict[CIPlatform, type[BaseCIAdapter]] = {
    CIPlatform.GITHUB_ACTIONS: GitHubAdapter,
    CIPlatform.GITLAB_CI: GitLabAdapter,
    CIPlatform.AZURE_DEVOPS: AzureAdapter,
    CIPlatform.BITBUCKET: BitbucketAdapter,
    CIPlatform.CIRCLECI: CircleCIAdapter,
    CIPlatform.CODEBUILD: CodeBuildAdapter,
    CIPlatform.JENKINS: JenkinsAdapter,
}


_UNKNOWN_PLATFORM_MESSAGE: str = "No CI adapter available for platform: {platform}"


def resolve_adapter(platform: CIPlatform) -> BaseCIAdapter:
    """Return an adapter instance for the given platform.

    Raises:
        CIIntegrationError: When no adapter exists for the platform.
    """
    adapter_class = _PLATFORM_ADAPTERS.get(platform)
    if adapter_class is None:
        raise CIIntegrationError(_UNKNOWN_PLATFORM_MESSAGE.format(platform=platform.value))
    return adapter_class()


__all__ = [
    "AzureAdapter",
    "BaseCIAdapter",
    "BitbucketAdapter",
    "CIPlatform",
    "CircleCIAdapter",
    "CodeBuildAdapter",
    "GitHubAdapter",
    "GitLabAdapter",
    "JenkinsAdapter",
    "PRContext",
    "PullRequestContext",
    "SanitisedCommentBody",
    "detect_platform",
    "get_pr_context",
    "get_pull_request_context",
    "resolve_adapter",
]
