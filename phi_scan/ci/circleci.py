"""CircleCI adapter.

CircleCI is a meta-platform that delegates PR comment posting to
GitHub or Bitbucket based on the VCS provider detected from
``CIRCLE_PULL_REQUEST``. CircleCI does not have a native commit
status API — status is set via the underlying VCS platform.
"""

from __future__ import annotations

import logging

from phi_scan.ci._base import BaseCIAdapter, SanitisedCommentBody
from phi_scan.ci._detect import CIPlatform, PRContext
from phi_scan.ci.bitbucket import BitbucketAdapter
from phi_scan.ci.github import GitHubAdapter
from phi_scan.models import ScanResult

_LOG: logging.Logger = logging.getLogger(__name__)

_GITHUB_URL_HOSTNAME: str = "github.com"
_BITBUCKET_URL_HOSTNAME: str = "bitbucket.org"
_MIN_URL_PARTS_FOR_REPO_EXTRACTION: int = 5


class CircleCIAdapter(BaseCIAdapter):
    """CircleCI adapter that delegates to GitHub or Bitbucket."""

    @property
    def can_post_commit_status(self) -> bool:
        return False

    def post_pr_comment(self, comment_body: SanitisedCommentBody, pr_context: PRContext) -> None:
        pr_url = pr_context.extras.get("circle_pull_request_url", "")
        if not pr_url:
            _LOG.warning("CircleCI: CIRCLE_PULL_REQUEST not set — skipping comment")
            return

        if _GITHUB_URL_HOSTNAME in pr_url:
            github_context = _build_github_context_from_circle(pr_url, pr_context)
            GitHubAdapter().post_pr_comment(comment_body, github_context)
        elif _BITBUCKET_URL_HOSTNAME in pr_url:
            bitbucket_context = _build_bitbucket_context_from_circle(pr_url, pr_context)
            BitbucketAdapter().post_pr_comment(comment_body, bitbucket_context)
        else:
            _LOG.warning("CircleCI: unrecognized VCS in CIRCLE_PULL_REQUEST URL — skipping comment")

    def set_commit_status(self, scan_result: ScanResult, pr_context: PRContext) -> None:
        self._raise_unsupported_operation_error("commit status")


def _build_github_context_from_circle(pr_url: str, pr_context: PRContext) -> PRContext:
    url_segments = pr_url.rstrip("/").split("/")
    repository = (
        f"{url_segments[-4]}/{url_segments[-3]}"
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


def _build_bitbucket_context_from_circle(pr_url: str, pr_context: PRContext) -> PRContext:
    url_segments = pr_url.rstrip("/").split("/")
    if len(url_segments) >= _MIN_URL_PARTS_FOR_REPO_EXTRACTION:
        workspace = url_segments[-4]
        repo_slug = url_segments[-3]
    else:
        workspace = repo_slug = ""
    return PRContext(
        platform=CIPlatform.BITBUCKET,
        pr_number=pr_context.pr_number,
        repository=pr_context.repository,
        sha=pr_context.sha,
        branch=pr_context.branch,
        base_branch=pr_context.base_branch,
        extras={"workspace": workspace, "repo_slug": repo_slug},
    )
