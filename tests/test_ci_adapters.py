# phi-scan:ignore-file
"""Tests for the phi_scan.ci adapter package.

Covers:
  - resolve_adapter returns correct adapter types
  - Adapter capability flags
  - BaseCIAdapter.upload_sarif default raises CIIntegrationError
  - Import parity: all names importable via both old and new paths
  - Meta-platform delegation (Jenkins, CircleCI, CodeBuild)
  - Transport error wrapping
  - Platform detection from env vars
  - PullRequestContext builders
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from phi_scan.ci import (
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
from phi_scan.ci._transport import (
    HttpMethod,
    HttpRequestConfig,
    OperationLabel,
    execute_http_request,
)
from phi_scan.exceptions import CIIntegrationError

# ---------------------------------------------------------------------------
# resolve_adapter
# ---------------------------------------------------------------------------


_EXPECTED_ADAPTER_TYPES: list[tuple[CIPlatform, type[BaseCIAdapter]]] = [
    (CIPlatform.GITHUB_ACTIONS, GitHubAdapter),
    (CIPlatform.GITLAB_CI, GitLabAdapter),
    (CIPlatform.AZURE_DEVOPS, AzureAdapter),
    (CIPlatform.BITBUCKET, BitbucketAdapter),
    (CIPlatform.CIRCLECI, CircleCIAdapter),
    (CIPlatform.CODEBUILD, CodeBuildAdapter),
    (CIPlatform.JENKINS, JenkinsAdapter),
]


@pytest.mark.parametrize(
    ("platform", "expected_type"),
    _EXPECTED_ADAPTER_TYPES,
    ids=[p.value for p, _ in _EXPECTED_ADAPTER_TYPES],
)
def test_resolve_adapter_returns_correct_type(
    platform: CIPlatform, expected_type: type[BaseCIAdapter]
) -> None:
    adapter = resolve_adapter(platform)
    assert isinstance(adapter, expected_type)


def test_resolve_adapter_unknown_raises_error() -> None:
    with pytest.raises(CIIntegrationError):
        resolve_adapter(CIPlatform.UNKNOWN)


# ---------------------------------------------------------------------------
# Capability flags
# ---------------------------------------------------------------------------


def test_github_can_upload_sarif_report() -> None:
    assert GitHubAdapter().can_upload_sarif_report is True


def test_bitbucket_can_annotate_code_findings() -> None:
    assert BitbucketAdapter().can_annotate_code_findings is True


def test_azure_can_create_work_item_from_findings() -> None:
    assert AzureAdapter().can_create_work_item_from_findings is True


def test_codebuild_can_import_findings_to_security_hub() -> None:
    assert CodeBuildAdapter().can_import_findings_to_security_hub is True


def test_adapters_with_commit_status_support() -> None:
    assert GitHubAdapter().can_post_commit_status is True
    assert GitLabAdapter().can_post_commit_status is True
    assert BitbucketAdapter().can_post_commit_status is True


def test_adapters_without_commit_status_support() -> None:
    assert AzureAdapter().can_post_commit_status is False
    assert JenkinsAdapter().can_post_commit_status is False
    assert CircleCIAdapter().can_post_commit_status is False
    assert CodeBuildAdapter().can_post_commit_status is False


def test_gitlab_default_capabilities_are_false() -> None:
    adapter = GitLabAdapter()
    assert adapter.can_upload_sarif_report is False
    assert adapter.can_annotate_code_findings is False
    assert adapter.can_create_work_item_from_findings is False
    assert adapter.can_import_findings_to_security_hub is False


# ---------------------------------------------------------------------------
# BaseCIAdapter.upload_sarif_report raises domain error
# ---------------------------------------------------------------------------


def test_upload_sarif_report_raises_ci_integration_error() -> None:
    adapter = GitLabAdapter()
    scan_result_mock = MagicMock()
    pull_request_context = PullRequestContext(
        platform=CIPlatform.GITLAB_CI,
        pull_request_number="1",
        repository="123",
        sha="abc",
        branch="main",
        base_branch=None,
    )
    with pytest.raises(CIIntegrationError, match="GitLabAdapter.*SARIF upload"):
        adapter.upload_sarif_report(scan_result_mock, pull_request_context)


# ---------------------------------------------------------------------------
# Import parity — old path still works
# ---------------------------------------------------------------------------

_BACKWARD_COMPAT_NAMES: list[str] = [
    "CIPlatform",
    "PRContext",
    "PullRequestContext",
    "CIIntegrationError",
    "detect_platform",
    "get_pr_context",
    "get_pull_request_context",
    "BaseCIAdapter",
    "GitHubAdapter",
    "GitLabAdapter",
    "AzureAdapter",
    "BitbucketAdapter",
    "CircleCIAdapter",
    "CodeBuildAdapter",
    "JenkinsAdapter",
    "resolve_adapter",
    "HttpMethod",
    "HttpRequestConfig",
    "OperationLabel",
    "execute_http_request",
]


@pytest.mark.parametrize("name", _BACKWARD_COMPAT_NAMES)
def test_backward_compat_import_from_ci_integration(name: str) -> None:
    import phi_scan.ci_integration as old_module

    assert hasattr(old_module, name), f"{name} not importable from phi_scan.ci_integration"


_TRANSPORT_NAMES: set[str] = {
    "HttpMethod",
    "HttpRequestConfig",
    "OperationLabel",
    "execute_http_request",
}


@pytest.mark.parametrize("name", _BACKWARD_COMPAT_NAMES)
def test_old_and_new_paths_resolve_to_same_object(name: str) -> None:
    import phi_scan.ci as new_module
    import phi_scan.ci._transport as transport_module
    import phi_scan.ci_integration as old_module

    if name == "CIIntegrationError":
        import phi_scan.exceptions

        new_obj = phi_scan.exceptions.CIIntegrationError
    elif name in _TRANSPORT_NAMES:
        new_obj = getattr(transport_module, name)
    else:
        new_obj = getattr(new_module, name)
    old_obj = getattr(old_module, name)
    assert old_obj is new_obj, f"{name} differs between old and new import paths"


# ---------------------------------------------------------------------------
# Transport — error wrapping
# ---------------------------------------------------------------------------


def test_execute_http_request_wraps_status_error() -> None:
    mock_response = httpx.Response(
        status_code=403,
        request=httpx.Request("POST", "https://example.com"),
    )
    with patch("phi_scan.ci._transport.httpx.request", return_value=mock_response):
        with pytest.raises(CIIntegrationError, match="403"):
            execute_http_request(
                HttpRequestConfig(
                    method=HttpMethod.POST,
                    url="https://example.com",
                    operation_label=OperationLabel.GITHUB_COMMIT_STATUS,
                )
            )


def test_execute_http_request_wraps_network_error() -> None:
    with patch(
        "phi_scan.ci._transport.httpx.request",
        side_effect=httpx.ConnectError("connection refused"),
    ):
        with pytest.raises(CIIntegrationError, match="request failed \\(network error\\)"):
            execute_http_request(
                HttpRequestConfig(
                    method=HttpMethod.POST,
                    url="https://example.com",
                    operation_label=OperationLabel.GITHUB_COMMIT_STATUS,
                )
            )


def test_execute_http_request_network_error_excludes_url() -> None:
    with patch(
        "phi_scan.ci._transport.httpx.request",
        side_effect=httpx.ConnectError("connection refused to https://secret.example.com/phi-data"),
    ):
        with pytest.raises(CIIntegrationError) as exc_info:
            execute_http_request(
                HttpRequestConfig(
                    method=HttpMethod.POST,
                    url="https://secret.example.com/phi-data",
                    operation_label=OperationLabel.GITHUB_COMMIT_STATUS,
                )
            )
        assert "secret.example.com" not in str(exc_info.value)
        assert "network error" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

_DETECTION_CASES: list[tuple[dict[str, str], CIPlatform]] = [
    ({"GITHUB_ACTIONS": "true"}, CIPlatform.GITHUB_ACTIONS),
    ({"GITLAB_CI": "true"}, CIPlatform.GITLAB_CI),
    ({"TF_BUILD": "True"}, CIPlatform.AZURE_DEVOPS),
    ({"CIRCLECI": "true"}, CIPlatform.CIRCLECI),
    ({"BITBUCKET_BUILD_NUMBER": "42"}, CIPlatform.BITBUCKET),
    ({"CODEBUILD_BUILD_ID": "build-123"}, CIPlatform.CODEBUILD),
    ({"JENKINS_URL": "https://jenkins.example.com"}, CIPlatform.JENKINS),
    ({}, CIPlatform.UNKNOWN),
]


@pytest.mark.parametrize(
    ("env_vars", "expected_platform"),
    _DETECTION_CASES,
    ids=[p.value for _, p in _DETECTION_CASES],
)
def test_detect_platform(env_vars: dict[str, str], expected_platform: CIPlatform) -> None:
    with patch.dict("os.environ", env_vars, clear=True):
        assert detect_platform() == expected_platform


# ---------------------------------------------------------------------------
# PullRequestContext builders
# ---------------------------------------------------------------------------


def test_get_pr_context_github() -> None:
    env = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_SHA": "abc123",
        "GITHUB_REF": "refs/pull/42/merge",
        "PR_NUMBER": "42",
    }
    with patch.dict("os.environ", env, clear=True):
        context = get_pull_request_context()
    assert context.platform == CIPlatform.GITHUB_ACTIONS
    assert context.pull_request_number == "42"
    assert context.repository == "owner/repo"
    assert context.sha == "abc123"


def test_get_pr_context_github_extracts_pr_from_ref() -> None:
    env = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_SHA": "abc123",
        "GITHUB_REF": "refs/pull/99/merge",
    }
    with patch.dict("os.environ", env, clear=True):
        context = get_pull_request_context()
    assert context.pull_request_number == "99"


def test_get_pr_context_gitlab() -> None:
    env = {
        "GITLAB_CI": "true",
        "CI_PROJECT_ID": "12345",
        "CI_MERGE_REQUEST_IID": "7",
        "CI_COMMIT_SHA": "def456",
        "CI_COMMIT_REF_NAME": "feature",
        "CI_SERVER_URL": "https://gitlab.example.com",
    }
    with patch.dict("os.environ", env, clear=True):
        context = get_pull_request_context()
    assert context.platform == CIPlatform.GITLAB_CI
    assert context.pull_request_number == "7"
    assert context.extras["ci_server_url"] == "https://gitlab.example.com"


def test_get_pr_context_unknown() -> None:
    with patch.dict("os.environ", {}, clear=True):
        context = get_pull_request_context()
    assert context.platform == CIPlatform.UNKNOWN
    assert context.pull_request_number is None


# ---------------------------------------------------------------------------
# Meta-platform delegation
# ---------------------------------------------------------------------------


def test_jenkins_delegates_to_github(monkeypatch: pytest.MonkeyPatch) -> None:
    pull_request_context = PullRequestContext(
        platform=CIPlatform.JENKINS,
        pull_request_number="10",
        repository=None,
        sha=None,
        branch=None,
        base_branch=None,
        extras={"change_url": "https://github.com/owner/repo/pull/10"},
    )
    with patch.object(GitHubAdapter, "post_pull_request_comment") as mock_gh:
        JenkinsAdapter().post_pull_request_comment("test body", pull_request_context)
        mock_gh.assert_called_once()
        delegated_context = mock_gh.call_args[0][1]
        assert delegated_context.platform == CIPlatform.GITHUB_ACTIONS
        assert delegated_context.repository == "owner/repo"


def test_jenkins_delegates_to_gitlab() -> None:
    pull_request_context = PullRequestContext(
        platform=CIPlatform.JENKINS,
        pull_request_number="5",
        repository=None,
        sha=None,
        branch=None,
        base_branch=None,
        extras={"change_url": "https://gitlab.example.com/group/project/-/merge_requests/5"},
    )
    with patch.object(GitLabAdapter, "post_pull_request_comment") as mock_gl:
        JenkinsAdapter().post_pull_request_comment("test body", pull_request_context)
        mock_gl.assert_called_once()


def test_jenkins_skips_when_no_change_url() -> None:
    pull_request_context = PullRequestContext(
        platform=CIPlatform.JENKINS,
        pull_request_number="5",
        repository=None,
        sha=None,
        branch=None,
        base_branch=None,
        extras={},
    )
    with (
        patch.object(GitHubAdapter, "post_pull_request_comment") as mock_gh,
        patch.object(GitLabAdapter, "post_pull_request_comment") as mock_gl,
    ):
        JenkinsAdapter().post_pull_request_comment("test body", pull_request_context)
        mock_gh.assert_not_called()
        mock_gl.assert_not_called()


def test_circleci_delegates_to_github() -> None:
    pull_request_context = PullRequestContext(
        platform=CIPlatform.CIRCLECI,
        pull_request_number="20",
        repository=None,
        sha="abc",
        branch="feature",
        base_branch=None,
        extras={"circle_pull_request_url": "https://github.com/owner/repo/pull/20"},
    )
    with patch.object(GitHubAdapter, "post_pull_request_comment") as mock_gh:
        CircleCIAdapter().post_pull_request_comment("test body", pull_request_context)
        mock_gh.assert_called_once()
        delegated_context = mock_gh.call_args[0][1]
        assert delegated_context.repository == "owner/repo"


def test_circleci_delegates_to_bitbucket() -> None:
    pull_request_context = PullRequestContext(
        platform=CIPlatform.CIRCLECI,
        pull_request_number="15",
        repository=None,
        sha="abc",
        branch="feature",
        base_branch=None,
        extras={"circle_pull_request_url": "https://bitbucket.org/workspace/repo/pull-requests/15"},
    )
    with patch.object(BitbucketAdapter, "post_pull_request_comment") as mock_bb:
        CircleCIAdapter().post_pull_request_comment("test body", pull_request_context)
        mock_bb.assert_called_once()


def test_codebuild_delegates_to_github() -> None:
    pull_request_context = PullRequestContext(
        platform=CIPlatform.CODEBUILD,
        pull_request_number="30",
        repository=None,
        sha="abc",
        branch=None,
        base_branch=None,
    )
    with patch.dict("os.environ", {"CODEBUILD_SOURCE_REPO_URL": "https://github.com/owner/repo"}):
        with patch.object(GitHubAdapter, "post_pull_request_comment") as mock_gh:
            CodeBuildAdapter().post_pull_request_comment("test body", pull_request_context)
            mock_gh.assert_called_once()
            delegated_context = mock_gh.call_args[0][1]
            assert delegated_context.repository == "owner/repo"


def test_codebuild_delegates_to_bitbucket() -> None:
    pull_request_context = PullRequestContext(
        platform=CIPlatform.CODEBUILD,
        pull_request_number="30",
        repository=None,
        sha="abc",
        branch=None,
        base_branch=None,
    )
    with patch.dict(
        "os.environ", {"CODEBUILD_SOURCE_REPO_URL": "https://bitbucket.org/workspace/repo"}
    ):
        with patch.object(BitbucketAdapter, "post_pull_request_comment") as mock_bb:
            CodeBuildAdapter().post_pull_request_comment("test body", pull_request_context)
            mock_bb.assert_called_once()


# ---------------------------------------------------------------------------
# PullRequestContext is frozen
# ---------------------------------------------------------------------------


def test_pr_context_is_frozen() -> None:
    context = PullRequestContext(
        platform=CIPlatform.UNKNOWN,
        pull_request_number=None,
        repository=None,
        sha=None,
        branch=None,
        base_branch=None,
    )
    with pytest.raises(AttributeError):
        context.pull_request_number = "999"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# HttpRequestConfig is frozen
# ---------------------------------------------------------------------------


def test_http_request_config_is_frozen() -> None:
    config = HttpRequestConfig(
        method=HttpMethod.POST,
        url="https://example.com",
        operation_label=OperationLabel.GITHUB_COMMIT_STATUS,
    )
    with pytest.raises(AttributeError):
        config.url = "https://other.com"  # type: ignore[misc]
