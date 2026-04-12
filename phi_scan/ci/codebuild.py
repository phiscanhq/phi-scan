"""AWS CodeBuild adapter.

CodeBuild is a meta-platform that delegates PR comment posting to
GitHub or Bitbucket based on the source repository URL detected from
``CODEBUILD_SOURCE_REPO_URL``.
"""

from __future__ import annotations

import logging
import os

from phi_scan.ci._base import BaseCIAdapter, SanitisedCommentBody, UnsupportedOperation
from phi_scan.ci._detect import CIPlatform, PRContext
from phi_scan.ci.bitbucket import BitbucketAdapter
from phi_scan.ci.github import GitHubAdapter
from phi_scan.models import ScanResult

_LOG: logging.Logger = logging.getLogger(__name__)

_GITHUB_URL_HOSTNAME: str = "github.com"
_BITBUCKET_URL_HOSTNAME: str = "bitbucket.org"
_MIN_URL_PARTS_FOR_REPO_EXTRACTION: int = 2


class CodeBuildAdapter(BaseCIAdapter):
    """AWS CodeBuild adapter that delegates to GitHub or Bitbucket."""

    @property
    def can_post_commit_status(self) -> bool:
        return False

    @property
    def can_import_findings_to_security_hub(self) -> bool:
        return True

    def post_pr_comment(self, comment_body: SanitisedCommentBody, pr_context: PRContext) -> None:
        repo_url = os.environ.get("CODEBUILD_SOURCE_REPO_URL", "")
        if _GITHUB_URL_HOSTNAME in repo_url:
            github_context = _build_github_context_from_codebuild(repo_url, pr_context)
            GitHubAdapter().post_pr_comment(comment_body, github_context)
        elif _BITBUCKET_URL_HOSTNAME in repo_url:
            bitbucket_context = _build_bitbucket_context_from_codebuild(repo_url, pr_context)
            BitbucketAdapter().post_pr_comment(comment_body, bitbucket_context)
        else:
            _LOG.warning("CodeBuild: unrecognised source repo URL — skipping PR comment")

    def set_commit_status(self, scan_result: ScanResult, pr_context: PRContext) -> None:
        self._abort_unsupported_operation(UnsupportedOperation.COMMIT_STATUS)


def _build_github_context_from_codebuild(repo_url: str, pr_context: PRContext) -> PRContext:
    url_segments = repo_url.rstrip("/").rstrip(".git").split("/")
    repository = (
        f"{url_segments[-2]}/{url_segments[-1]}"
        if len(url_segments) >= _MIN_URL_PARTS_FOR_REPO_EXTRACTION
        else None
    )
    return PRContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pr_number=pr_context.pr_number,
        repository=repository,
        sha=pr_context.sha,
        branch=pr_context.branch,
        base_branch=pr_context.base_branch,
    )


def _build_bitbucket_context_from_codebuild(repo_url: str, pr_context: PRContext) -> PRContext:
    url_segments = repo_url.rstrip("/").rstrip(".git").split("/")
    workspace = url_segments[-2] if len(url_segments) >= _MIN_URL_PARTS_FOR_REPO_EXTRACTION else ""
    repo_slug = url_segments[-1] if url_segments else ""
    return PRContext(
        platform=CIPlatform.BITBUCKET,
        pr_number=pr_context.pr_number,
        repository=pr_context.repository,
        sha=pr_context.sha,
        branch=pr_context.branch,
        base_branch=pr_context.base_branch,
        extras={"workspace": workspace, "repo_slug": repo_slug},
    )
