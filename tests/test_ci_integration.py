# phi-scan:ignore-file
"""Tests for phi_scan.ci_integration — platform detection, comment building, and API calls.

Phase 6D.1 through 6D.10: CI/CD platform detection, PR context extraction,
comment body generation, and end-to-end CLI --post-comment / --set-status flags.

Each test covers exactly one observable behaviour. Network calls are intercepted
via monkeypatching and subprocess mocks so the suite never makes real HTTP requests.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import MappingProxyType
from unittest.mock import MagicMock, patch

import httpx
import pytest
import yaml
from typer.testing import CliRunner

from phi_scan.ci_integration import (
    CIIntegrationError,
    CIPlatform,
    PRContext,
    build_comment_body,
    detect_platform,
    get_pr_context,
    post_pr_comment,
    set_commit_status,
)
from phi_scan.cli import app
from phi_scan.config import create_default_config
from phi_scan.constants import (
    EXIT_CODE_CLEAN,
    EXIT_CODE_VIOLATION,
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

_TEST_ENCODING: str = "utf-8"
_SCAN_TARGET_DIR: str = "scan_root"
_PHI_FILE_NAME: str = "patient.py"
_PLANTED_SSN: str = 'ssn = "321-54-9870"\n'
_AUDIT_DB_NAME: str = "audit.db"
_CONFIG_FILE_NAME: str = ".phi-scanner.yml"

_TEST_ENTITY_TYPE: str = "us_ssn"
_TEST_VALUE_HASH: str = "a" * 64
_TEST_CODE_CONTEXT: str = 'field = "[REDACTED]"'
_TEST_REMEDIATION_HINT: str = "Replace SSN with synthetic value"
_TEST_FILE_PATH: Path = Path("src/patient.py")
_TEST_LINE_NUMBER: int = 42
_TEST_SCAN_DURATION: float = 0.5
_TEST_FILES_SCANNED: int = 3

_GITHUB_REPO: str = "org/my-repo"
_GITHUB_SHA: str = "abc123def456" * 3
_GITHUB_PR_NUMBER: str = "42"

_GITLAB_PROJECT_ID: str = "999"
_GITLAB_MR_IID: str = "7"
_GITLAB_SHA: str = "deadbeef" * 5

_AZURE_COLLECTION_URI: str = "https://dev.azure.com/myorg/"
_AZURE_TEAM_PROJECT: str = "MyProject"
_AZURE_REPO_ID: str = "repo-uuid-1234"
_AZURE_PR_ID: str = "55"
_AZURE_SHA: str = "cafe0000" * 5

_BITBUCKET_WORKSPACE: str = "myworkspace"
_BITBUCKET_REPO_SLUG: str = "my-repo"
_BITBUCKET_PR_ID: str = "12"
_BITBUCKET_COMMIT: str = "0123456789ab" * 3

_COMMENT_VIOLATIONS_HEADER_FRAGMENT: str = "PHI/PII Violations Detected"
_COMMENT_CLEAN_HEADER_FRAGMENT: str = "No PHI/PII Violations Found"
_COMMENT_FILES_SCANNED_FRAGMENT: str = "file(s) scanned"

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _empty_counts(enum_type: type) -> MappingProxyType:
    return MappingProxyType({member: 0 for member in enum_type})


def _make_finding(
    *,
    severity: SeverityLevel = SeverityLevel.HIGH,
    hipaa_category: PhiCategory = PhiCategory.SSN,
    line_number: int = _TEST_LINE_NUMBER,
    file_path: Path = _TEST_FILE_PATH,
) -> ScanFinding:
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=_TEST_ENTITY_TYPE,
        hipaa_category=hipaa_category,
        confidence=0.95,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_TEST_VALUE_HASH,
        severity=severity,
        code_context=_TEST_CODE_CONTEXT,
        remediation_hint=_TEST_REMEDIATION_HINT,
    )


def _make_clean_result() -> ScanResult:
    return ScanResult(
        findings=(),
        files_scanned=_TEST_FILES_SCANNED,
        files_with_findings=0,
        scan_duration=_TEST_SCAN_DURATION,
        is_clean=True,
        risk_level=RiskLevel.CLEAN,
        severity_counts=_empty_counts(SeverityLevel),
        category_counts=_empty_counts(PhiCategory),
    )


def _make_violation_result() -> ScanResult:
    finding = _make_finding()
    severity_counts = MappingProxyType(
        {**{level: 0 for level in SeverityLevel}, SeverityLevel.HIGH: 1}
    )
    category_counts = MappingProxyType({**{cat: 0 for cat in PhiCategory}, PhiCategory.SSN: 1})
    return ScanResult(
        findings=(finding,),
        files_scanned=_TEST_FILES_SCANNED,
        files_with_findings=1,
        scan_duration=_TEST_SCAN_DURATION,
        is_clean=False,
        risk_level=RiskLevel.CRITICAL,
        severity_counts=severity_counts,
        category_counts=category_counts,
    )


def _write_config(tmp_path: Path, database_path: Path) -> Path:
    config_path = tmp_path / _CONFIG_FILE_NAME
    create_default_config(config_path)
    document = yaml.safe_load(config_path.read_text(encoding=_TEST_ENCODING))
    document["audit"]["database_path"] = str(database_path)
    config_path.write_text(
        yaml.dump(document, default_flow_style=False, sort_keys=False),
        encoding=_TEST_ENCODING,
    )
    return config_path


# ---------------------------------------------------------------------------
# detect_platform tests
# ---------------------------------------------------------------------------


def test_detect_platform_returns_github_when_github_actions_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GITHUB_ACTIONS=true is detected as CIPlatform.GITHUB_ACTIONS."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert detect_platform() == CIPlatform.GITHUB_ACTIONS


def test_detect_platform_returns_gitlab_when_gitlab_ci_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GITLAB_CI=true is detected as CIPlatform.GITLAB_CI."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("GITLAB_CI", "true")
    assert detect_platform() == CIPlatform.GITLAB_CI


def test_detect_platform_returns_azure_when_tf_build_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TF_BUILD=True is detected as CIPlatform.AZURE_DEVOPS."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITLAB_CI", raising=False)
    monkeypatch.setenv("TF_BUILD", "True")
    assert detect_platform() == CIPlatform.AZURE_DEVOPS


def test_detect_platform_returns_circleci_when_circleci_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CIRCLECI=true is detected as CIPlatform.CIRCLECI."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITLAB_CI", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    monkeypatch.setenv("CIRCLECI", "true")
    assert detect_platform() == CIPlatform.CIRCLECI


def test_detect_platform_returns_bitbucket_when_build_number_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BITBUCKET_BUILD_NUMBER set is detected as CIPlatform.BITBUCKET."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITLAB_CI", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    monkeypatch.delenv("CIRCLECI", raising=False)
    monkeypatch.setenv("BITBUCKET_BUILD_NUMBER", "42")
    assert detect_platform() == CIPlatform.BITBUCKET


def test_detect_platform_returns_codebuild_when_build_id_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CODEBUILD_BUILD_ID set is detected as CIPlatform.CODEBUILD."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITLAB_CI", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    monkeypatch.delenv("CIRCLECI", raising=False)
    monkeypatch.delenv("BITBUCKET_BUILD_NUMBER", raising=False)
    monkeypatch.setenv("CODEBUILD_BUILD_ID", "arn:aws:codebuild:us-east-1:123:build/foo:bar")
    assert detect_platform() == CIPlatform.CODEBUILD


def test_detect_platform_returns_jenkins_when_jenkins_url_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JENKINS_URL set is detected as CIPlatform.JENKINS."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITLAB_CI", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    monkeypatch.delenv("CIRCLECI", raising=False)
    monkeypatch.delenv("BITBUCKET_BUILD_NUMBER", raising=False)
    monkeypatch.delenv("CODEBUILD_BUILD_ID", raising=False)
    monkeypatch.setenv("JENKINS_URL", "http://jenkins.example.com")
    assert detect_platform() == CIPlatform.JENKINS


def test_detect_platform_returns_unknown_when_no_ci_env_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No CI environment variables present returns CIPlatform.UNKNOWN."""
    for env_var in (
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "TF_BUILD",
        "CIRCLECI",
        "BITBUCKET_BUILD_NUMBER",
        "CODEBUILD_BUILD_ID",
        "JENKINS_URL",
    ):
        monkeypatch.delenv(env_var, raising=False)
    assert detect_platform() == CIPlatform.UNKNOWN


# ---------------------------------------------------------------------------
# get_pr_context tests
# ---------------------------------------------------------------------------


def test_get_pr_context_github_extracts_pr_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub PR context extracts PR_NUMBER from environment."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("PR_NUMBER", _GITHUB_PR_NUMBER)
    monkeypatch.setenv("GITHUB_REPOSITORY", _GITHUB_REPO)
    monkeypatch.setenv("GITHUB_SHA", _GITHUB_SHA)
    monkeypatch.setenv("GITHUB_REF", "refs/pull/42/merge")

    context = get_pr_context()

    assert context.platform == CIPlatform.GITHUB_ACTIONS
    assert context.pr_number == _GITHUB_PR_NUMBER
    assert context.repository == _GITHUB_REPO
    assert context.sha == _GITHUB_SHA


def test_get_pr_context_github_falls_back_to_ref_for_pr_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub PR context extracts PR number from GITHUB_REF when PR_NUMBER absent."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("PR_NUMBER", raising=False)
    monkeypatch.setenv("GITHUB_REF", "refs/pull/99/merge")

    context = get_pr_context()

    assert context.pr_number == "99"


def test_get_pr_context_gitlab_extracts_mr_iid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitLab MR context extracts CI_MERGE_REQUEST_IID."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", _GITLAB_MR_IID)
    monkeypatch.setenv("CI_PROJECT_ID", _GITLAB_PROJECT_ID)
    monkeypatch.setenv("CI_COMMIT_SHA", _GITLAB_SHA)

    context = get_pr_context()

    assert context.platform == CIPlatform.GITLAB_CI
    assert context.pr_number == _GITLAB_MR_IID
    assert context.repository == _GITLAB_PROJECT_ID
    assert context.sha == _GITLAB_SHA


def test_get_pr_context_azure_extracts_pr_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure DevOps context extracts SYSTEM_PULLREQUEST_PULLREQUESTID."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITLAB_CI", raising=False)
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", _AZURE_PR_ID)
    monkeypatch.setenv("BUILD_REPOSITORY_ID", _AZURE_REPO_ID)
    monkeypatch.setenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", _AZURE_COLLECTION_URI)
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", _AZURE_TEAM_PROJECT)
    monkeypatch.setenv("BUILD_SOURCEVERSION", _AZURE_SHA)

    context = get_pr_context()

    assert context.platform == CIPlatform.AZURE_DEVOPS
    assert context.pr_number == _AZURE_PR_ID
    assert context.repository == _AZURE_REPO_ID


def test_get_pr_context_bitbucket_extracts_pr_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bitbucket context extracts BITBUCKET_PR_ID and workspace."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITLAB_CI", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    monkeypatch.delenv("CIRCLECI", raising=False)
    monkeypatch.setenv("BITBUCKET_BUILD_NUMBER", "100")
    monkeypatch.setenv("BITBUCKET_PR_ID", _BITBUCKET_PR_ID)
    monkeypatch.setenv("BITBUCKET_REPO_SLUG", _BITBUCKET_REPO_SLUG)
    monkeypatch.setenv("BITBUCKET_WORKSPACE", _BITBUCKET_WORKSPACE)
    monkeypatch.setenv("BITBUCKET_COMMIT", _BITBUCKET_COMMIT)

    context = get_pr_context()

    assert context.platform == CIPlatform.BITBUCKET
    assert context.pr_number == _BITBUCKET_PR_ID
    assert context.extras["workspace"] == _BITBUCKET_WORKSPACE
    assert context.extras["repo_slug"] == _BITBUCKET_REPO_SLUG


# ---------------------------------------------------------------------------
# build_comment_body tests
# ---------------------------------------------------------------------------


def test_build_comment_body_clean_result_contains_clean_header() -> None:
    """Clean scan result comment contains the no-violations header."""
    comment = build_comment_body(_make_clean_result())
    assert _COMMENT_CLEAN_HEADER_FRAGMENT in comment


def test_build_comment_body_violation_result_contains_violations_header() -> None:
    """Violation scan result comment contains the violations header."""
    comment = build_comment_body(_make_violation_result())
    assert _COMMENT_VIOLATIONS_HEADER_FRAGMENT in comment


def test_build_comment_body_violation_contains_finding_file_path() -> None:
    """Violation comment body contains the file path of the finding."""
    comment = build_comment_body(_make_violation_result())
    assert str(_TEST_FILE_PATH) in comment


def test_build_comment_body_violation_contains_line_number() -> None:
    """Violation comment body contains the line number of the finding."""
    comment = build_comment_body(_make_violation_result())
    assert str(_TEST_LINE_NUMBER) in comment


def test_build_comment_body_truncates_when_exceeds_max_length() -> None:
    """Comment body is truncated when it exceeds the platform character limit."""
    # Build a result with many findings to trigger truncation
    findings = tuple(_make_finding(line_number=i) for i in range(1, 200))
    severity_counts = MappingProxyType(
        {**{level: 0 for level in SeverityLevel}, SeverityLevel.HIGH: len(findings)}
    )
    category_counts = MappingProxyType(
        {**{cat: 0 for cat in PhiCategory}, PhiCategory.SSN: len(findings)}
    )
    large_result = ScanResult(
        findings=findings,
        files_scanned=len(findings),
        files_with_findings=len(findings),
        scan_duration=1.0,
        is_clean=False,
        risk_level=RiskLevel.CRITICAL,
        severity_counts=severity_counts,
        category_counts=category_counts,
    )
    comment = build_comment_body(large_result)
    assert len(comment) <= 60_100  # some tolerance for the truncation suffix


def test_build_comment_body_clean_does_not_contain_raw_entity_value() -> None:
    """Clean comment never includes entity values (PHI must not leak into comments)."""
    comment = build_comment_body(_make_clean_result())
    assert "321-54-9870" not in comment


def test_build_comment_body_violation_does_not_contain_raw_entity_value() -> None:
    """Violation comment never includes entity values (PHI must not leak into comments)."""
    comment = build_comment_body(_make_violation_result())
    # The value hash is in the comment, not the raw value
    assert "321-54-9870" not in comment


# ---------------------------------------------------------------------------
# post_pr_comment — platform-specific tests (GitHub via gh CLI)
# ---------------------------------------------------------------------------


def test_post_pr_comment_github_calls_gh_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub PR comment posting invokes the gh CLI."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken123")
    github_context = PRContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pr_number=_GITHUB_PR_NUMBER,
        repository=_GITHUB_REPO,
        sha=_GITHUB_SHA,
        branch=None,
        base_branch=None,
    )
    captured_calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        captured_calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        post_pr_comment(_make_clean_result(), github_context)

    assert any("gh" in call for call in captured_calls)
    assert any("pr" in call for call in captured_calls)


def test_post_pr_comment_github_skips_when_no_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub comment posting is skipped when GITHUB_TOKEN is absent."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    github_context = PRContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pr_number=_GITHUB_PR_NUMBER,
        repository=_GITHUB_REPO,
        sha=_GITHUB_SHA,
        branch=None,
        base_branch=None,
    )
    call_count = 0

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        nonlocal call_count
        call_count += 1
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        post_pr_comment(_make_clean_result(), github_context)

    assert call_count == 0


def test_post_pr_comment_skips_when_no_pr_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PR comment posting is skipped when pr_number is None."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken123")
    no_pr_context = PRContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pr_number=None,
        repository=_GITHUB_REPO,
        sha=_GITHUB_SHA,
        branch=None,
        base_branch=None,
    )
    call_count = 0

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        nonlocal call_count
        call_count += 1
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        post_pr_comment(_make_clean_result(), no_pr_context)

    assert call_count == 0


def test_post_pr_comment_github_raises_ci_integration_error_on_gh_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CIIntegrationError raised when gh CLI is not installed."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken123")
    github_context = PRContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pr_number=_GITHUB_PR_NUMBER,
        repository=_GITHUB_REPO,
        sha=_GITHUB_SHA,
        branch=None,
        base_branch=None,
    )

    def raise_not_found(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError("gh not found")

    with patch("subprocess.run", side_effect=raise_not_found):
        with pytest.raises(CIIntegrationError, match="gh CLI not found"):
            post_pr_comment(_make_clean_result(), github_context)


# ---------------------------------------------------------------------------
# post_pr_comment — GitLab (HTTP)
# ---------------------------------------------------------------------------


def test_post_pr_comment_gitlab_posts_to_notes_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitLab MR comment posting calls the GitLab Notes API endpoint."""
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-testtoken")
    gitlab_context = PRContext(
        platform=CIPlatform.GITLAB_CI,
        pr_number=_GITLAB_MR_IID,
        repository=_GITLAB_PROJECT_ID,
        sha=_GITLAB_SHA,
        branch=None,
        base_branch=None,
        extras={"ci_server_url": "https://gitlab.com"},
    )
    captured_urls: list[str] = []

    def fake_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=fake_request):
        post_pr_comment(_make_violation_result(), gitlab_context)

    assert any(
        f"projects/{_GITLAB_PROJECT_ID}/merge_requests/{_GITLAB_MR_IID}/notes" in url
        for url in captured_urls
    )


def test_post_pr_comment_gitlab_raises_on_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CIIntegrationError raised when GitLab API returns an HTTP error."""
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-testtoken")
    gitlab_context = PRContext(
        platform=CIPlatform.GITLAB_CI,
        pr_number=_GITLAB_MR_IID,
        repository=_GITLAB_PROJECT_ID,
        sha=_GITLAB_SHA,
        branch=None,
        base_branch=None,
        extras={"ci_server_url": "https://gitlab.com"},
    )

    def fake_request(method: str, url: str, **kwargs: object) -> MagicMock:
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.reason_phrase = "Forbidden"
        mock_response.text = "Forbidden"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "403 Forbidden", request=MagicMock(), response=mock_response
        )
        return mock_response

    with patch("httpx.request", side_effect=fake_request):
        with pytest.raises(CIIntegrationError, match="GitLab MR comment failed"):
            post_pr_comment(_make_violation_result(), gitlab_context)


# ---------------------------------------------------------------------------
# post_pr_comment — Bitbucket (HTTP)
# ---------------------------------------------------------------------------


def test_post_pr_comment_bitbucket_posts_to_pr_comments_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bitbucket PR comment posting calls the Bitbucket Cloud PR comments endpoint."""
    monkeypatch.setenv("BITBUCKET_TOKEN", "bb_testtoken")
    bb_context = PRContext(
        platform=CIPlatform.BITBUCKET,
        pr_number=_BITBUCKET_PR_ID,
        repository=_BITBUCKET_REPO_SLUG,
        sha=_BITBUCKET_COMMIT,
        branch=None,
        base_branch=None,
        extras={
            "workspace": _BITBUCKET_WORKSPACE,
            "repo_slug": _BITBUCKET_REPO_SLUG,
        },
    )
    captured_urls: list[str] = []

    def fake_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=fake_request):
        post_pr_comment(_make_clean_result(), bb_context)

    assert any(f"pullrequests/{_BITBUCKET_PR_ID}/comments" in url for url in captured_urls)


# ---------------------------------------------------------------------------
# set_commit_status tests
# ---------------------------------------------------------------------------


def test_set_commit_status_github_calls_statuses_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub commit status posts to the /repos/.../statuses/{sha} endpoint."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken123")
    github_context = PRContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pr_number=_GITHUB_PR_NUMBER,
        repository=_GITHUB_REPO,
        sha=_GITHUB_SHA,
        branch=None,
        base_branch=None,
    )
    captured_payloads: list[dict] = []

    def fake_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_payloads.append(kwargs.get("json", {}))
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=fake_request):
        set_commit_status(_make_clean_result(), github_context)

    assert any(payload.get("state") == "success" for payload in captured_payloads)


def test_set_commit_status_github_posts_failure_for_violations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub commit status state is 'failure' when violations are found."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken123")
    github_context = PRContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pr_number=_GITHUB_PR_NUMBER,
        repository=_GITHUB_REPO,
        sha=_GITHUB_SHA,
        branch=None,
        base_branch=None,
    )
    captured_payloads: list[dict] = []

    def fake_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_payloads.append(kwargs.get("json", {}))
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=fake_request):
        set_commit_status(_make_violation_result(), github_context)

    assert any(payload.get("state") == "failure" for payload in captured_payloads)


def test_set_commit_status_skips_when_no_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Commit status is skipped when pr_context.sha is None."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken123")
    no_sha_context = PRContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pr_number=_GITHUB_PR_NUMBER,
        repository=_GITHUB_REPO,
        sha=None,
        branch=None,
        base_branch=None,
    )
    call_count = 0

    def fake_request(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.request", side_effect=fake_request):
        set_commit_status(_make_clean_result(), no_sha_context)

    assert call_count == 0


def test_set_commit_status_unknown_platform_does_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Commit status for UNKNOWN platform logs a warning and returns without error."""
    unknown_context = PRContext(
        platform=CIPlatform.UNKNOWN,
        pr_number="1",
        repository="org/repo",
        sha=_GITHUB_SHA,
        branch=None,
        base_branch=None,
    )
    call_count = 0

    def fake_request(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.request", side_effect=fake_request):
        set_commit_status(_make_clean_result(), unknown_context)

    assert call_count == 0


# ---------------------------------------------------------------------------
# CLI --post-comment integration tests (6D.3)
# ---------------------------------------------------------------------------


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _create_phi_scan_root(tmp_path: Path) -> tuple[Path, Path]:
    scan_root = tmp_path / _SCAN_TARGET_DIR
    scan_root.mkdir()
    phi_file = scan_root / _PHI_FILE_NAME
    phi_file.write_text(_PLANTED_SSN, encoding=_TEST_ENCODING)
    return scan_root, phi_file


def test_scan_with_post_comment_flag_does_not_change_exit_code_on_clean(
    tmp_path: Path,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--post-comment flag on a clean scan does not change exit code."""
    database_path = tmp_path / _AUDIT_DB_NAME
    config_path = _write_config(tmp_path, database_path)
    scan_root = tmp_path / _SCAN_TARGET_DIR
    scan_root.mkdir()

    # Disable CI comment — no GitHub token set, platform is UNKNOWN
    for env_var in ("GITHUB_ACTIONS", "GITHUB_TOKEN", "GITLAB_CI"):
        monkeypatch.delenv(env_var, raising=False)

    invocation = runner.invoke(
        app,
        [
            "scan",
            str(scan_root),
            "--output",
            "json",
            "--config",
            str(config_path),
            "--post-comment",
        ],
    )

    assert invocation.exit_code == EXIT_CODE_CLEAN


def test_scan_with_post_comment_flag_does_not_change_exit_code_on_violation(
    tmp_path: Path,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--post-comment flag on a violation scan does not change exit code."""
    database_path = tmp_path / _AUDIT_DB_NAME
    config_path = _write_config(tmp_path, database_path)
    scan_root, _ = _create_phi_scan_root(tmp_path)

    # Disable CI comment — no GitHub token set, platform is UNKNOWN
    for env_var in ("GITHUB_ACTIONS", "GITHUB_TOKEN", "GITLAB_CI"):
        monkeypatch.delenv(env_var, raising=False)

    invocation = runner.invoke(
        app,
        [
            "scan",
            str(scan_root),
            "--output",
            "json",
            "--config",
            str(config_path),
            "--post-comment",
        ],
    )

    assert invocation.exit_code == EXIT_CODE_VIOLATION


def test_scan_with_set_status_flag_does_not_change_exit_code(
    tmp_path: Path,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--set-status flag does not change exit code when status posting is skipped."""
    database_path = tmp_path / _AUDIT_DB_NAME
    config_path = _write_config(tmp_path, database_path)
    scan_root = tmp_path / _SCAN_TARGET_DIR
    scan_root.mkdir()

    for env_var in ("GITHUB_ACTIONS", "GITHUB_TOKEN", "GITLAB_CI"):
        monkeypatch.delenv(env_var, raising=False)

    invocation = runner.invoke(
        app,
        [
            "scan",
            str(scan_root),
            "--output",
            "json",
            "--config",
            str(config_path),
            "--set-status",
        ],
    )

    assert invocation.exit_code == EXIT_CODE_CLEAN


def test_scan_with_post_comment_invokes_gh_cli_on_github_platform(
    tmp_path: Path,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--post-comment on a GitHub Actions platform invokes the gh CLI."""
    database_path = tmp_path / _AUDIT_DB_NAME
    config_path = _write_config(tmp_path, database_path)
    scan_root = tmp_path / _SCAN_TARGET_DIR
    scan_root.mkdir()

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken")
    monkeypatch.setenv("GITHUB_REPOSITORY", _GITHUB_REPO)
    monkeypatch.setenv("GITHUB_SHA", _GITHUB_SHA)
    monkeypatch.setenv("PR_NUMBER", _GITHUB_PR_NUMBER)

    captured_calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        captured_calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        invocation = runner.invoke(
            app,
            [
                "scan",
                str(scan_root),
                "--output",
                "json",
                "--config",
                str(config_path),
                "--post-comment",
            ],
        )

    assert invocation.exit_code == EXIT_CODE_CLEAN
    assert any(isinstance(call, list) and "gh" in call for call in captured_calls)
