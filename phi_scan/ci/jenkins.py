"""Jenkins CI adapter.

Jenkins is a meta-platform that delegates PR comment posting to
GitHub or GitLab based on the ``CHANGE_URL`` environment variable.
Jenkins does not set a native commit status — status is handled
via the underlying VCS platform.
"""

from __future__ import annotations

import logging

from phi_scan.ci._base import BaseCIAdapter
from phi_scan.ci._detect import CIPlatform, PRContext
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
    def supports_commit_status(self) -> bool:
        return False

    def post_pr_comment(self, comment_body: str, pr_context: PRContext) -> None:
        change_url = pr_context.extras.get("change_url", "")
        if not change_url:
            _LOG.debug("Jenkins: CHANGE_URL not set — skipping comment")
            return

        if _GITHUB_URL_HOSTNAME in change_url:
            github_context = _build_github_context_from_jenkins(change_url, pr_context)
            GitHubAdapter().post_pr_comment(comment_body, github_context)
        elif _GITLAB_URL_KEYWORD in change_url:
            _LOG.debug("Jenkins: GitLab VCS detected — delegating to GitLab adapter")
            GitLabAdapter().post_pr_comment(comment_body, pr_context)
        else:
            _LOG.warning("Jenkins: unrecognized VCS in CHANGE_URL — skipping comment")

    def set_commit_status(self, scan_result: ScanResult, pr_context: PRContext) -> None:
        self._raise_unsupported("commit status")


def _build_github_context_from_jenkins(change_url: str, pr_context: PRContext) -> PRContext:
    url_segments = change_url.rstrip("/").split("/")
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
