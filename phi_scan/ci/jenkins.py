"""Jenkins CI adapter.

Jenkins is a meta-platform that delegates PR comment posting to
GitHub or GitLab based on the ``CHANGE_URL`` environment variable.
Jenkins does not set a native commit status — status is handled
via the underlying VCS platform.
"""

from __future__ import annotations

import logging

from phi_scan.ci._base import BaseCIAdapter, SanitisedCommentBody, UnsupportedOperation
from phi_scan.ci._detect import CIPlatform, PullRequestContext
from phi_scan.ci.github import GitHubAdapter
from phi_scan.ci.gitlab import GitLabAdapter
from phi_scan.models import ScanResult

_LOG: logging.Logger = logging.getLogger(__name__)

_GITHUB_URL_HOSTNAME: str = "github.com"
_GITLAB_URL_KEYWORD: str = "gitlab"
_MIN_URL_PARTS_FOR_REPO_EXTRACTION: int = 5


class JenkinsAdapter(BaseCIAdapter):
    """Jenkins adapter that delegates to GitHub or GitLab based on VCS."""

    @property
    def can_post_commit_status(self) -> bool:
        return False

    def post_pull_request_comment(
        self, comment_body: SanitisedCommentBody, pull_request_context: PullRequestContext
    ) -> None:
        change_url = pull_request_context.extras.get("change_url", "")
        if not change_url:
            _LOG.warning("Jenkins: CHANGE_URL not set — skipping comment")
            return

        if _GITHUB_URL_HOSTNAME in change_url:
            github_context = _build_github_context_from_jenkins(change_url, pull_request_context)
            GitHubAdapter().post_pull_request_comment(comment_body, github_context)
        elif _GITLAB_URL_KEYWORD in change_url:
            _LOG.debug("Jenkins: GitLab VCS detected — delegating to GitLab adapter")
            GitLabAdapter().post_pull_request_comment(comment_body, pull_request_context)
        else:
            _LOG.warning("Jenkins: unrecognized VCS in CHANGE_URL — skipping comment")

    def set_commit_status(
        self, scan_result: ScanResult, pull_request_context: PullRequestContext
    ) -> None:
        self._abort_unsupported_operation(UnsupportedOperation.COMMIT_STATUS)


def _build_github_context_from_jenkins(
    change_url: str, pull_request_context: PullRequestContext
) -> PullRequestContext:
    url_segments = change_url.rstrip("/").split("/")
    repository = (
        f"{url_segments[-4]}/{url_segments[-3]}"
        if len(url_segments) >= _MIN_URL_PARTS_FOR_REPO_EXTRACTION
        else None
    )
    return PullRequestContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pull_request_number=pull_request_context.pull_request_number,
        repository=repository,
        sha=pull_request_context.sha,
        branch=pull_request_context.branch,
        base_branch=pull_request_context.base_branch,
    )
