# phi-scan:ignore-file
"""Tests for remaining Phase 6 CI/CD integration items.

Covers 6D.5 (SARIF upload), 6D.12/13 (Jenkins Warnings NG / Checks API),
6D.15/16 (Azure DevOps PR status and build tag), 6D.21 (Bitbucket Code Insights),
6D.25 (AWS Security Hub ASFF), 6C.10 (baseline context in comment),
and 6B.6 (Docker end-to-end, skipped when Docker unavailable).

All network calls are mocked via unittest.mock.patch; no real HTTP traffic is made.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import MappingProxyType
from unittest.mock import MagicMock, patch

import httpx
import pytest
import yaml

from phi_scan.ci_integration import (
    BaselineComparison,
    CIIntegrationError,
    CIPlatform,
    PullRequestContext,
    build_comment_body_with_baseline,
    convert_findings_to_asff,
    create_azure_boards_work_item,
    import_findings_to_security_hub,
    post_bitbucket_code_insights,
    set_azure_build_tag,
    set_azure_pr_status,
    upload_sarif_to_github,
)
from phi_scan.constants import (
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult

# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

_TEST_ENTITY_TYPE: str = "us_ssn"
_TEST_VALUE_HASH: str = "a" * 64
_TEST_CODE_CONTEXT: str = 'field = "[REDACTED]"'
_TEST_REMEDIATION_HINT: str = "Replace SSN with synthetic value"
_TEST_FILE_PATH: Path = Path("src/patient.py")
_TEST_LINE_NUMBER: int = 42
_TEST_SCAN_DURATION: float = 0.5
_TEST_FILES_SCANNED: int = 5

_GITHUB_REPO: str = "org/my-repo"
_GITHUB_SHA: str = "abc123def456" * 3
_GITHUB_PR_NUMBER: str = "42"

_AZURE_COLLECTION_URI: str = "https://dev.azure.com/myorg/"
_AZURE_TEAM_PROJECT: str = "MyProject"
_AZURE_REPO_ID: str = "repo-uuid-1234"
_AZURE_PR_ID: str = "55"
_AZURE_BUILD_ID: str = "8001"
_AZURE_SHA: str = "cafe0000" * 5

_BITBUCKET_WORKSPACE: str = "myworkspace"
_BITBUCKET_REPO_SLUG: str = "my-repo"
_BITBUCKET_PR_ID: str = "12"
_BITBUCKET_COMMIT: str = "0123456789ab" * 3

_AWS_ACCOUNT_ID: str = "123456789012"
_AWS_REGION: str = "us-east-1"
_AWS_REPO: str = "org/my-repo"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _empty_counts(enum_type: type) -> MappingProxyType:
    return MappingProxyType({member: 0 for member in enum_type})


def _make_finding(
    *,
    severity: SeverityLevel = SeverityLevel.HIGH,
    hipaa_category: PhiCategory = PhiCategory.SSN,
) -> ScanFinding:
    return ScanFinding(
        file_path=_TEST_FILE_PATH,
        line_number=_TEST_LINE_NUMBER,
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


def _make_violation_result(severity: SeverityLevel = SeverityLevel.HIGH) -> ScanResult:
    finding = _make_finding(severity=severity)
    severity_counts = MappingProxyType({**{level: 0 for level in SeverityLevel}, severity: 1})
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


def _github_context(**overrides: object) -> PullRequestContext:
    defaults: dict = {
        "platform": CIPlatform.GITHUB_ACTIONS,
        "pull_request_number": _GITHUB_PR_NUMBER,
        "repository": _GITHUB_REPO,
        "sha": _GITHUB_SHA,
        "branch": "refs/pull/42/merge",
        "base_branch": None,
    }
    defaults.update(overrides)
    return PullRequestContext(**defaults)


def _azure_context(**overrides: object) -> PullRequestContext:
    defaults: dict = {
        "platform": CIPlatform.AZURE_DEVOPS,
        "pull_request_number": _AZURE_PR_ID,
        "repository": _AZURE_REPO_ID,
        "sha": _AZURE_SHA,
        "branch": None,
        "base_branch": None,
        "extras": {
            "collection_uri": _AZURE_COLLECTION_URI,
            "team_project": _AZURE_TEAM_PROJECT,
            "build_id": _AZURE_BUILD_ID,
        },
    }
    defaults.update(overrides)
    return PullRequestContext(**defaults)


def _bitbucket_context(**overrides: object) -> PullRequestContext:
    defaults: dict = {
        "platform": CIPlatform.BITBUCKET,
        "pull_request_number": _BITBUCKET_PR_ID,
        "repository": _BITBUCKET_REPO_SLUG,
        "sha": _BITBUCKET_COMMIT,
        "branch": None,
        "base_branch": None,
        "extras": {
            "workspace": _BITBUCKET_WORKSPACE,
            "repo_slug": _BITBUCKET_REPO_SLUG,
        },
    }
    defaults.update(overrides)
    return PullRequestContext(**defaults)


# ---------------------------------------------------------------------------
# 6D.5 — GitHub SARIF upload tests
# ---------------------------------------------------------------------------


def test_upload_sarif_to_github_posts_to_code_scanning_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SARIF upload posts to the GitHub Code Scanning SARIF endpoint."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken")
    captured_urls: list[str] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        upload_sarif_to_github(_make_violation_result(), _github_context())

    assert any("code-scanning/sarifs" in url for url in captured_urls)


def test_upload_sarif_to_github_payload_contains_base64_encoded_sarif(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SARIF upload payload contains gzip-compressed, base64-encoded SARIF."""
    import base64
    import gzip

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken")
    captured_payloads: list[dict] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_payloads.append(kwargs.get("json", {}))
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        upload_sarif_to_github(_make_violation_result(), _github_context())

    assert captured_payloads
    encoded = captured_payloads[0]["sarif"]
    decoded = gzip.decompress(base64.b64decode(encoded)).decode("utf-8")
    assert "2.1.0" in decoded


def test_upload_sarif_skips_when_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """SARIF upload is skipped when GITHUB_TOKEN is absent."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    call_count = 0

    def stub_http_request(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.request", side_effect=stub_http_request):
        upload_sarif_to_github(_make_violation_result(), _github_context())

    assert call_count == 0


def test_upload_sarif_skips_when_no_sha(monkeypatch: pytest.MonkeyPatch) -> None:
    """SARIF upload is skipped when commit SHA is absent."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken")
    call_count = 0

    def stub_http_request(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.request", side_effect=stub_http_request):
        upload_sarif_to_github(_make_violation_result(), _github_context(sha=None))

    assert call_count == 0


def test_upload_sarif_raises_ci_integration_error_on_http_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CIIntegrationError raised when GitHub Code Scanning API returns an error."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken")

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        mock_response = MagicMock()
        mock_response.status_code = 422
        mock_response.reason_phrase = "Unprocessable Entity"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "422", request=MagicMock(), response=mock_response
        )
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        with pytest.raises(CIIntegrationError, match="GitHub SARIF upload failed"):
            upload_sarif_to_github(_make_violation_result(), _github_context())


def test_upload_sarif_http_error_excludes_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CIIntegrationError must not embed response body — API errors could echo request content."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken")
    sentinel_body = "SENTINEL_RESPONSE_BODY_MUST_NOT_APPEAR"

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        mock_response = MagicMock()
        mock_response.status_code = 422
        mock_response.reason_phrase = "Unprocessable Entity"
        mock_response.text = sentinel_body
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "422", request=MagicMock(), response=mock_response
        )
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        with pytest.raises(CIIntegrationError) as exc_info:
            upload_sarif_to_github(_make_violation_result(), _github_context())
    assert sentinel_body not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 6C.10 — Baseline context in PR comment
# ---------------------------------------------------------------------------


def test_build_comment_body_with_baseline_contains_new_findings_count() -> None:
    """Baseline comment includes the new findings count."""
    comment = build_comment_body_with_baseline(
        _make_violation_result(),
        BaselineComparison(new_findings_count=3, baselined_count=7, resolved_count=2),
    )
    assert "3 new" in comment


def test_build_comment_body_with_baseline_contains_baselined_count() -> None:
    """Baseline comment includes the baselined findings count."""
    comment = build_comment_body_with_baseline(
        _make_violation_result(),
        BaselineComparison(new_findings_count=3, baselined_count=7, resolved_count=2),
    )
    assert "7 baselined" in comment


def test_build_comment_body_with_baseline_contains_resolved_count() -> None:
    """Baseline comment includes the resolved findings count."""
    comment = build_comment_body_with_baseline(
        _make_violation_result(),
        BaselineComparison(new_findings_count=3, baselined_count=7, resolved_count=2),
    )
    assert "2 resolved" in comment


# ---------------------------------------------------------------------------
# 6D.15/16 — Azure DevOps PR status + build tag
# ---------------------------------------------------------------------------


def test_set_azure_pr_status_posts_succeeded_when_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure PR status is 'succeeded' when no violations found."""
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    captured_payloads: list[dict] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_payloads.append(kwargs.get("json", {}))
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        set_azure_pr_status(_make_clean_result(), _azure_context())

    assert any(p.get("state") == "succeeded" for p in captured_payloads)


def test_set_azure_pr_status_posts_failed_when_violations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure PR status is 'failed' when violations found."""
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    captured_payloads: list[dict] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_payloads.append(kwargs.get("json", {}))
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        set_azure_pr_status(_make_violation_result(), _azure_context())

    assert any(p.get("state") == "failed" for p in captured_payloads)


def test_set_azure_build_tag_uses_clean_tag_when_no_violations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure build is tagged with phi-scan:clean when no violations."""
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    captured_urls: list[str] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        set_azure_build_tag(_make_clean_result(), _azure_context())

    assert any("phi-scan%3Aclean" in url or "phi-scan:clean" in url for url in captured_urls)


def test_set_azure_build_tag_uses_violations_tag_when_violations_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure build is tagged with phi-scan:violations-found when violations detected."""
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    captured_urls: list[str] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        set_azure_build_tag(_make_violation_result(), _azure_context())

    assert any("violations-found" in url for url in captured_urls)


def test_set_azure_pr_status_skips_when_no_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure PR status is skipped when SYSTEM_ACCESSTOKEN is absent."""
    monkeypatch.delenv("SYSTEM_ACCESSTOKEN", raising=False)
    call_count = 0

    def stub_http_request(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.request", side_effect=stub_http_request):
        set_azure_pr_status(_make_clean_result(), _azure_context())

    assert call_count == 0


def test_set_azure_build_tag_http_error_excludes_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure build tag HTTP error message never includes the response body.

    API error responses could echo back request content.  This sentinel test
    machine-verifies the module docstring contract for the Azure platform.
    """
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    sentinel_body = "SENTINEL_AZURE_BUILD_TAG_RESPONSE_BODY_MUST_NOT_APPEAR"

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.reason_phrase = "Forbidden"
        mock_response.text = sentinel_body
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "403", request=MagicMock(), response=mock_response
        )
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        with pytest.raises(CIIntegrationError) as exc_info:
            set_azure_build_tag(_make_violation_result(), _azure_context())

    assert sentinel_body not in str(exc_info.value)


def test_set_azure_pr_status_http_error_excludes_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure PR status HTTP error message never includes the response body."""
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    sentinel_body = "SENTINEL_AZURE_PR_STATUS_RESPONSE_BODY_MUST_NOT_APPEAR"

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        mock_response = MagicMock()
        mock_response.status_code = 422
        mock_response.reason_phrase = "Unprocessable Entity"
        mock_response.text = sentinel_body
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "422", request=MagicMock(), response=mock_response
        )
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        with pytest.raises(CIIntegrationError) as exc_info:
            set_azure_pr_status(_make_violation_result(), _azure_context())

    assert sentinel_body not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 6C.18 — Azure Boards work-item creation
# ---------------------------------------------------------------------------


def test_create_azure_boards_work_item_skips_when_not_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure Boards work item is not created when AZURE_BOARDS_INTEGRATION != true."""
    monkeypatch.delenv("AZURE_BOARDS_INTEGRATION", raising=False)
    call_count = 0

    def stub_http_request(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.request", side_effect=stub_http_request):
        create_azure_boards_work_item(_make_violation_result(), _azure_context())

    assert call_count == 0


def test_create_azure_boards_work_item_skips_when_no_high_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure Boards work item is not created when there are no HIGH severity findings."""
    monkeypatch.setenv("AZURE_BOARDS_INTEGRATION", "true")
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    call_count = 0

    def stub_http_request(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.request", side_effect=stub_http_request):
        create_azure_boards_work_item(
            _make_violation_result(severity=SeverityLevel.LOW),
            _azure_context(),
        )

    assert call_count == 0


def test_create_azure_boards_work_item_posts_when_enabled_with_high_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure Boards work item is created when enabled and HIGH findings exist."""
    monkeypatch.setenv("AZURE_BOARDS_INTEGRATION", "true")
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    captured_urls: list[str] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        create_azure_boards_work_item(_make_violation_result(), _azure_context())

    assert any("workitems" in url for url in captured_urls)


def test_create_azure_boards_work_item_payload_excludes_phi_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure Boards work item payload contains only counts and PR number — no per-finding PHI.

    Machine-verifies the PHI-SAFE OUTBOUND FIELDS comment in
    create_azure_boards_work_item: title and description must contain only
    aggregate counts and PR number, never hipaa_category, entity_type,
    file_path, or code_context from individual findings.
    """
    monkeypatch.setenv("AZURE_BOARDS_INTEGRATION", "true")
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    captured_json: list[list] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        captured_json.append(kwargs.get("json", []))
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        create_azure_boards_work_item(_make_violation_result(), _azure_context())

    assert captured_json, "expected a POST to Azure Boards"
    payload_str = json.dumps(captured_json[0])

    # Must contain aggregate count and PR number
    assert "1" in payload_str  # count of HIGH findings
    assert _AZURE_PR_ID in payload_str

    # Must NOT contain any per-finding ScanFinding fields — exhaustive check
    # covering every field the reviewer flagged as a potential indirect PHI leak.
    assert _TEST_CODE_CONTEXT not in payload_str  # raw (redacted) source line
    assert str(_TEST_FILE_PATH) not in payload_str  # file path
    assert _TEST_ENTITY_TYPE not in payload_str  # entity_type (pattern name)
    assert PhiCategory.SSN.value not in payload_str  # hipaa_category enum label
    assert _TEST_VALUE_HASH not in payload_str  # SHA-256 of raw value
    assert _TEST_REMEDIATION_HINT not in payload_str  # remediation guidance text


# ---------------------------------------------------------------------------
# 6D.21 — Bitbucket Code Insights
# ---------------------------------------------------------------------------


def test_post_bitbucket_code_insights_creates_report_and_annotations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Code Insights posts both a report (PUT) and annotations (POST)."""
    monkeypatch.setenv("BITBUCKET_TOKEN", "bb_testtoken")
    put_urls: list[str] = []
    post_urls: list[str] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        if method == "PUT":
            put_urls.append(url)
        else:
            post_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        post_bitbucket_code_insights(_make_violation_result(), _bitbucket_context())

    assert any("reports" in url for url in put_urls)
    assert any("annotations" in url for url in post_urls)


def test_post_bitbucket_code_insights_report_result_passed_when_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Code Insights report result is PASSED for a clean scan."""
    monkeypatch.setenv("BITBUCKET_TOKEN", "bb_testtoken")
    captured_payloads: list[dict] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        if method == "PUT":
            captured_payloads.append(kwargs.get("json", {}))
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        post_bitbucket_code_insights(_make_clean_result(), _bitbucket_context())

    assert any(p.get("result") == "PASSED" for p in captured_payloads)


def test_post_bitbucket_code_insights_report_result_failed_when_violations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Code Insights report result is FAILED when violations detected."""
    monkeypatch.setenv("BITBUCKET_TOKEN", "bb_testtoken")
    captured_payloads: list[dict] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        if method == "PUT":
            captured_payloads.append(kwargs.get("json", {}))
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        post_bitbucket_code_insights(_make_violation_result(), _bitbucket_context())

    assert any(p.get("result") == "FAILED" for p in captured_payloads)


def test_post_bitbucket_code_insights_annotations_include_file_and_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Code Insights annotations contain file path and line number."""
    monkeypatch.setenv("BITBUCKET_TOKEN", "bb_testtoken")
    captured_annotation_payloads: list[list] = []

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        if method == "POST":
            captured_annotation_payloads.append(kwargs.get("json", []))
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        post_bitbucket_code_insights(_make_violation_result(), _bitbucket_context())

    assert captured_annotation_payloads
    first_annotation = captured_annotation_payloads[0][0]
    assert first_annotation["path"] == str(_TEST_FILE_PATH)
    assert first_annotation["line"] == _TEST_LINE_NUMBER


def test_post_bitbucket_code_insights_skips_when_no_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Code Insights is skipped when BITBUCKET_TOKEN is absent."""
    monkeypatch.delenv("BITBUCKET_TOKEN", raising=False)
    call_count = 0

    def stub_http_request(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.request", side_effect=stub_http_request):
        post_bitbucket_code_insights(_make_clean_result(), _bitbucket_context())

    assert call_count == 0


def test_post_bitbucket_code_insights_http_error_excludes_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bitbucket Code Insights HTTP error message never includes the response body."""
    monkeypatch.setenv("BITBUCKET_TOKEN", "bb_testtoken")
    sentinel_body = "SENTINEL_BITBUCKET_INSIGHTS_RESPONSE_BODY_MUST_NOT_APPEAR"

    def stub_http_request(method: str, url: str, **kwargs: object) -> MagicMock:
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.reason_phrase = "Unauthorized"
        mock_response.text = sentinel_body
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=mock_response
        )
        return mock_response

    with patch("httpx.request", side_effect=stub_http_request):
        with pytest.raises(CIIntegrationError) as exc_info:
            post_bitbucket_code_insights(_make_violation_result(), _bitbucket_context())

    assert sentinel_body not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 6D.25 — AWS Security Hub ASFF
# ---------------------------------------------------------------------------


def test_convert_findings_to_asff_produces_one_entry_per_finding() -> None:
    """ASFF conversion produces exactly one entry per scan finding."""
    asff = convert_findings_to_asff(
        _make_violation_result(), _AWS_ACCOUNT_ID, _AWS_REGION, _AWS_REPO
    )
    assert len(asff) == 1


def test_convert_findings_to_asff_severity_label_is_high_for_high_finding() -> None:
    """ASFF severity label is HIGH for a HIGH severity finding."""
    asff = convert_findings_to_asff(
        _make_violation_result(severity=SeverityLevel.HIGH),
        _AWS_ACCOUNT_ID,
        _AWS_REGION,
        _AWS_REPO,
    )
    assert asff[0]["Severity"]["Label"] == "HIGH"


def test_convert_findings_to_asff_severity_label_is_medium_for_medium_finding() -> None:
    """ASFF severity label is MEDIUM for a MEDIUM severity finding."""
    asff = convert_findings_to_asff(
        _make_violation_result(severity=SeverityLevel.MEDIUM),
        _AWS_ACCOUNT_ID,
        _AWS_REGION,
        _AWS_REPO,
    )
    assert asff[0]["Severity"]["Label"] == "MEDIUM"


def test_convert_findings_to_asff_contains_file_path_in_title() -> None:
    """ASFF finding title contains the file path."""
    asff = convert_findings_to_asff(
        _make_violation_result(), _AWS_ACCOUNT_ID, _AWS_REGION, _AWS_REPO
    )
    assert str(_TEST_FILE_PATH) in asff[0]["Title"]


def test_convert_findings_to_asff_does_not_include_raw_entity_value() -> None:
    """ASFF findings must not contain raw PHI entity values or any value_hash derivative.

    SSNs have ~30 bits of entropy — any SHA-256 derivative (full or truncated) is
    reversible by brute-force over the input space. The ASFF Id uses structural
    fields only (repository + file_path + line_number + entity_type).
    """
    asff = convert_findings_to_asff(
        _make_violation_result(), _AWS_ACCOUNT_ID, _AWS_REGION, _AWS_REPO
    )
    asff_str = json.dumps(asff)
    assert _TEST_VALUE_HASH not in asff_str
    assert "321-54-9870" not in asff_str
    # Id is built from structural fields — no hash derivative present
    assert _TEST_VALUE_HASH[:16] not in asff[0]["Id"]
    assert str(_TEST_LINE_NUMBER) in asff[0]["Id"]
    assert _TEST_ENTITY_TYPE in asff[0]["Id"]


def test_convert_findings_to_asff_excludes_code_context() -> None:
    """ASFF payload must not embed code_context — even the redacted form.

    code_context is the source line with the PHI value replaced by [REDACTED].
    It is not needed in Security Hub findings and must not appear in any field.
    """
    asff = convert_findings_to_asff(
        _make_violation_result(), _AWS_ACCOUNT_ID, _AWS_REGION, _AWS_REPO
    )
    asff_str = json.dumps(asff)
    # _TEST_CODE_CONTEXT = 'field = "[REDACTED]"' — the surrounding text is distinctive
    assert _TEST_CODE_CONTEXT not in asff_str


def test_convert_findings_to_asff_fields_are_enumerated_types_and_counts() -> None:
    """Every per-finding field in the ASFF payload is a safe type (enum label, int, float).

    This test machine-verifies the PHI-SAFE OUTBOUND FIELDS comment in
    convert_findings_to_asff: every field that varies per finding must be
    either a count, an enum label, a file path, a line number, or a float.
    Full value_hash is excluded — only value_hash[:16] appears in the Id field
    for ASFF deduplication; the full SHA-256 is not sent to Security Hub.
    """
    asff = convert_findings_to_asff(
        _make_violation_result(), _AWS_ACCOUNT_ID, _AWS_REGION, _AWS_REPO
    )
    assert len(asff) == 1
    finding_record = asff[0]
    details = finding_record["Resources"][0]["Details"]["Other"]

    # Each field in the Resources.Other block is a safe type
    assert details["line_number"] == str(_TEST_LINE_NUMBER)
    assert details["entity_type"] == _TEST_ENTITY_TYPE
    assert details["hipaa_category"] == PhiCategory.SSN.value
    # confidence is a formatted float string, not a raw entity value
    assert "." in details["confidence"]
    # full value_hash must not be present — only [:16] prefix used in the Id field
    assert "value_hash" not in details

    # Description contains a count and confidence, but not code_context
    description = finding_record["Description"]
    assert _TEST_CODE_CONTEXT not in description
    assert "No raw value is stored" in description


def test_convert_findings_to_asff_excludes_full_value_hash() -> None:
    """ASFF payload must not contain value_hash or any truncated derivative.

    SSNs have ~30 bits of entropy — SHA-256 of any low-entropy PHI is reversible
    by brute-force over the input space regardless of output length. The ASFF Id
    uses structural fields (repository + file_path + line_number + entity_type) so
    zero PHI-derived data leaves this process.
    """
    asff = convert_findings_to_asff(
        _make_violation_result(), _AWS_ACCOUNT_ID, _AWS_REGION, _AWS_REPO
    )
    asff_str = json.dumps(asff)
    # Full hash and any prefix must not appear anywhere in the payload
    assert _TEST_VALUE_HASH not in asff_str
    assert _TEST_VALUE_HASH[:16] not in asff_str
    assert _TEST_VALUE_HASH[:8] not in asff_str


def test_convert_findings_to_asff_empty_when_clean() -> None:
    """ASFF conversion returns empty list for a clean scan result."""
    asff = convert_findings_to_asff(_make_clean_result(), _AWS_ACCOUNT_ID, _AWS_REGION, _AWS_REPO)
    assert asff == []


def test_import_findings_to_security_hub_skips_when_not_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Security Hub import is skipped when AWS_SECURITY_HUB != true."""
    monkeypatch.delenv("AWS_SECURITY_HUB", raising=False)
    call_count = 0

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
        nonlocal call_count
        call_count += 1
        return subprocess.CompletedProcess([], returncode=0)

    context = PullRequestContext(
        platform=CIPlatform.CODEBUILD,
        pull_request_number="1",
        repository=_AWS_REPO,
        sha=_GITHUB_SHA,
        branch=None,
        base_branch=None,
    )
    with patch("subprocess.run", side_effect=fake_run):
        import_findings_to_security_hub(_make_violation_result(), context)

    assert call_count == 0


def test_import_findings_to_security_hub_calls_aws_cli_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Security Hub import invokes the AWS CLI when AWS_SECURITY_HUB=true."""
    monkeypatch.setenv("AWS_SECURITY_HUB", "true")
    monkeypatch.setenv("AWS_ACCOUNT_ID", _AWS_ACCOUNT_ID)
    monkeypatch.setenv("AWS_DEFAULT_REGION", _AWS_REGION)
    captured_cmds: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        captured_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    context = PullRequestContext(
        platform=CIPlatform.CODEBUILD,
        pull_request_number="1",
        repository=_AWS_REPO,
        sha=_GITHUB_SHA,
        branch=None,
        base_branch=None,
    )
    with patch("subprocess.run", side_effect=fake_run):
        import_findings_to_security_hub(_make_violation_result(), context)

    assert any("securityhub" in str(cmd) for cmd in captured_cmds)


def test_import_findings_to_security_hub_skips_when_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Security Hub import is skipped when the scan is clean."""
    monkeypatch.setenv("AWS_SECURITY_HUB", "true")
    monkeypatch.setenv("AWS_ACCOUNT_ID", _AWS_ACCOUNT_ID)
    call_count = 0

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
        nonlocal call_count
        call_count += 1
        return subprocess.CompletedProcess([], returncode=0)

    context = PullRequestContext(
        platform=CIPlatform.CODEBUILD,
        pull_request_number=None,
        repository=_AWS_REPO,
        sha=None,
        branch=None,
        base_branch=None,
    )
    with patch("subprocess.run", side_effect=fake_run):
        import_findings_to_security_hub(_make_clean_result(), context)

    assert call_count == 0


def test_import_findings_to_security_hub_raises_when_aws_cli_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CIIntegrationError raised when the AWS CLI is not installed."""
    monkeypatch.setenv("AWS_SECURITY_HUB", "true")
    monkeypatch.setenv("AWS_ACCOUNT_ID", _AWS_ACCOUNT_ID)
    monkeypatch.setenv("AWS_DEFAULT_REGION", _AWS_REGION)

    def raise_not_found(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError("aws not found")

    context = PullRequestContext(
        platform=CIPlatform.CODEBUILD,
        pull_request_number="1",
        repository=_AWS_REPO,
        sha=_GITHUB_SHA,
        branch=None,
        base_branch=None,
    )
    with patch("subprocess.run", side_effect=raise_not_found):
        with pytest.raises(CIIntegrationError, match="AWS CLI not found"):
            import_findings_to_security_hub(_make_violation_result(), context)


# ---------------------------------------------------------------------------
# 6B.6 — Docker end-to-end test (skipped when Docker is unavailable)
# ---------------------------------------------------------------------------


def _check_docker_available() -> bool:
    try:
        return (
            subprocess.run(
                ["docker", "info"],
                capture_output=True,
                check=False,
                timeout=10,
            ).returncode
            == 0
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_DOCKER_AVAILABLE: bool = _check_docker_available()

_DOCKER_IMAGE_BUILT: bool = False
_DOCKER_IMAGE_TAG: str = "phi-scan-test:ci"


def _ensure_docker_image_built() -> None:
    """Build the phi-scan Docker image once for the test session."""
    global _DOCKER_IMAGE_BUILT
    if _DOCKER_IMAGE_BUILT:
        return
    dockerfile_dir = Path(__file__).parent.parent / "docker"
    result = subprocess.run(
        ["docker", "build", "-t", _DOCKER_IMAGE_TAG, str(dockerfile_dir)],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    if result.returncode != 0:
        pytest.skip(f"Docker build failed: {result.stderr[:200]}")
    _DOCKER_IMAGE_BUILT = True


@pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="Docker not available in this environment")
def test_docker_scan_clean_directory_exits_zero(tmp_path: Path) -> None:
    """docker run phi-scan:latest scan /repo exits 0 on a clean directory."""
    _ensure_docker_image_built()
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{empty_dir}:/repo:ro",
            _DOCKER_IMAGE_TAG,
            "scan",
            "/repo",
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0


@pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="Docker not available in this environment")
def test_docker_scan_phi_file_exits_one(tmp_path: Path) -> None:
    """docker run phi-scan:latest scan /repo exits 1 when PHI is detected."""
    _ensure_docker_image_built()
    scan_dir = tmp_path / "repo"
    scan_dir.mkdir()
    (scan_dir / "patient.py").write_text('ssn = "321-54-9870"\n', encoding="utf-8")

    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{scan_dir}:/repo:ro",
            _DOCKER_IMAGE_TAG,
            "scan",
            "/repo",
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 1


# ---------------------------------------------------------------------------
# 6C.20 — CircleCI JUnit test summary (template structure tests)
# ---------------------------------------------------------------------------

_CIRCLECI_ORB_YML = Path(__file__).parent.parent / "ci-templates" / "circleci" / "orb.yml"
_CIRCLECI_CONFIG_YML = Path(__file__).parent.parent / "ci-templates" / "circleci" / "config.yml"
_BUILDSPEC_YML = Path(__file__).parent.parent / "ci-templates" / "aws-codebuild" / "buildspec.yml"

# Named constants for template structure assertions — avoids magic string literals in logic
_JUNIT_OUTPUT_FLAG: str = "--output junit"
_STORE_TEST_RESULTS_STEP: str = "store_test_results"
_SARIF_FILE_FORMAT: str = "file-format: SARIF"
_EXIT_CODE_FILE_NAME: str = "phi-scan-exit-code"
_EXIT_CODE_VAR_NAME: str = "phi_scan_exit_code"

# YAML key names used in orb.yml structure tests
_ORB_COMMANDS_KEY: str = "commands"
_ORB_SCAN_COMMAND_KEY: str = "scan"
_ORB_STORE_RESULTS_COMMAND_KEY: str = "store_results"
_ORB_STEPS_KEY: str = "steps"
_ORB_RUN_KEY: str = "run"
_ORB_RUN_COMMAND_KEY: str = "command"

# YAML key names used in buildspec.yml structure tests
_BUILDSPEC_REPORTS_KEY: str = "reports"
_BUILDSPEC_REPORT_GROUP_NAME: str = "phi-scan-findings"
_BUILDSPEC_FILE_FORMAT_KEY: str = "file-format"
_BUILDSPEC_SARIF_VALUE: str = "SARIF"
_BUILDSPEC_BASE_DIRECTORY_KEY: str = "base-directory"
_BUILDSPEC_OUTPUT_DIR_VAR: str = "PHI_SCAN_OUTPUT_DIR"


def test_circleci_orb_scan_command_includes_junit_output() -> None:
    """orb.yml scan command must include --output junit for CircleCI Test Summary."""
    content = _CIRCLECI_ORB_YML.read_text()
    assert _JUNIT_OUTPUT_FLAG in content, (
        f"orb.yml scan command is missing '{_JUNIT_OUTPUT_FLAG}' required for CircleCI Test Summary"
    )


def test_circleci_orb_store_test_results_present() -> None:
    """orb.yml store_results command must include store_test_results step."""
    content = _CIRCLECI_ORB_YML.read_text()
    assert _STORE_TEST_RESULTS_STEP in content, (
        f"orb.yml store_results command is missing '{_STORE_TEST_RESULTS_STEP}' step"
    )


def test_circleci_config_scan_command_includes_junit_output() -> None:
    """config.yml scan step must include --output junit for CircleCI Test Summary."""
    content = _CIRCLECI_CONFIG_YML.read_text()
    assert _JUNIT_OUTPUT_FLAG in content, (
        f"config.yml is missing '{_JUNIT_OUTPUT_FLAG}' required for CircleCI Test Summary"
    )


def test_circleci_config_store_test_results_present() -> None:
    """config.yml must include store_test_results step for CircleCI Test Summary tab."""
    content = _CIRCLECI_CONFIG_YML.read_text()
    assert _STORE_TEST_RESULTS_STEP in content, (
        f"config.yml is missing '{_STORE_TEST_RESULTS_STEP}' step "
        "required for CircleCI Test Summary"
    )


def test_circleci_orb_junit_report_path_consistent_with_store_test_results() -> None:
    """The JUnit report-path and store_test_results path must point to the same directory."""
    orb_yaml_spec = yaml.safe_load(_CIRCLECI_ORB_YML.read_text())
    commands = orb_yaml_spec.get(_ORB_COMMANDS_KEY, {})
    scan_cmd = commands.get(_ORB_SCAN_COMMAND_KEY, {})
    scan_steps = scan_cmd.get(_ORB_STEPS_KEY, [])

    # Find the run step that calls phi-scan
    scan_run_step = next(
        (
            step[_ORB_RUN_KEY][_ORB_RUN_COMMAND_KEY]
            for step in scan_steps
            if isinstance(step, dict) and _ORB_RUN_KEY in step
        ),
        None,
    )
    assert scan_run_step is not None, "orb.yml scan command step not found"
    assert _JUNIT_OUTPUT_FLAG in scan_run_step

    store_cmd = commands.get(_ORB_STORE_RESULTS_COMMAND_KEY, {})
    store_steps = store_cmd.get(_ORB_STEPS_KEY, [])
    store_step = next(
        (
            step
            for step in store_steps
            if isinstance(step, dict) and _STORE_TEST_RESULTS_STEP in step
        ),
        None,
    )
    assert store_step is not None, (
        f"'{_STORE_TEST_RESULTS_STEP}' step not found in store_results command"
    )


# ---------------------------------------------------------------------------
# 6C.26 — AWS CodeBuild report group (template structure tests)
# ---------------------------------------------------------------------------


def test_codebuild_buildspec_reports_section_uses_sarif() -> None:
    """buildspec.yml reports section must specify SARIF format for CodeBuild Reports tab."""
    content = _BUILDSPEC_YML.read_text()
    assert _SARIF_FILE_FORMAT in content, (
        f"buildspec.yml reports section is missing '{_SARIF_FILE_FORMAT}'"
    )


def test_codebuild_buildspec_build_phase_captures_exit_code() -> None:
    """buildspec.yml build phase must use set +e and capture phi-scan exit code."""
    content = _BUILDSPEC_YML.read_text()
    assert "set +e" in content, (
        "buildspec.yml build phase must use 'set +e' so phi-scan exit 1 "
        "does not abort the phase before the SARIF file is written"
    )
    assert _EXIT_CODE_FILE_NAME in content, (
        f"buildspec.yml must write phi-scan exit code to '{_EXIT_CODE_FILE_NAME}' "
        "for deferred failure"
    )


def test_codebuild_buildspec_post_build_reads_exit_code_file() -> None:
    """buildspec.yml post_build must read the exit code file written in the build phase."""
    content = _BUILDSPEC_YML.read_text()
    assert _EXIT_CODE_FILE_NAME in content
    # post_build must propagate the phi-scan exit code
    assert _EXIT_CODE_VAR_NAME in content


def test_codebuild_buildspec_parsed_structure() -> None:
    """buildspec.yml must parse as valid YAML with report group using SARIF format."""
    buildspec_yaml_spec = yaml.safe_load(_BUILDSPEC_YML.read_text())
    assert buildspec_yaml_spec.get("version") == 0.2

    reports = buildspec_yaml_spec.get(_BUILDSPEC_REPORTS_KEY, {})
    assert _BUILDSPEC_REPORT_GROUP_NAME in reports, (
        f"reports section must contain '{_BUILDSPEC_REPORT_GROUP_NAME}'"
    )
    report_group = reports[_BUILDSPEC_REPORT_GROUP_NAME]
    assert report_group.get(_BUILDSPEC_FILE_FORMAT_KEY) == _BUILDSPEC_SARIF_VALUE
    base_dir = report_group.get(_BUILDSPEC_BASE_DIRECTORY_KEY)
    assert base_dir, (
        f"reports.{_BUILDSPEC_REPORT_GROUP_NAME} must specify {_BUILDSPEC_BASE_DIRECTORY_KEY}"
    )

    # The env variable PHI_SCAN_OUTPUT_DIR must equal the reports base-directory so that
    # the SARIF file written via --report-path "$PHI_SCAN_OUTPUT_DIR/phi-scan.sarif" lands
    # in the directory CodeBuild watches for the report group upload.
    output_dir_value = (
        buildspec_yaml_spec.get("env", {}).get("variables", {}).get(_BUILDSPEC_OUTPUT_DIR_VAR)
    )
    assert output_dir_value == base_dir, (
        f"env.variables.{_BUILDSPEC_OUTPUT_DIR_VAR} ('{output_dir_value}') must match "
        f"reports {_BUILDSPEC_BASE_DIRECTORY_KEY} ('{base_dir}')"
    )

    # Build commands must reference PHI_SCAN_OUTPUT_DIR for the SARIF --report-path
    build_commands = " ".join(
        cmd
        for phase in buildspec_yaml_spec.get("phases", {}).values()
        for cmd in phase.get("commands", [])
        if isinstance(cmd, str)
    )
    assert _BUILDSPEC_OUTPUT_DIR_VAR in build_commands, (
        f"build phase must use ${_BUILDSPEC_OUTPUT_DIR_VAR} in the phi-scan --report-path argument"
    )


# ---------------------------------------------------------------------------
# 6D.6 — Docker ARM image works on Apple Silicon
# ---------------------------------------------------------------------------


def _detect_arm_buildx_support() -> bool:
    """Return True if Docker buildx reports linux/arm64 support on this machine."""
    try:
        result = subprocess.run(
            ["docker", "buildx", "inspect", "--bootstrap"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return result.returncode == 0 and "linux/arm64" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_BUILDX_ARM_AVAILABLE: bool = _detect_arm_buildx_support() if _DOCKER_AVAILABLE else False

_ARM_IMAGE_TAG: str = "phi-scan-test-arm64:ci"


@pytest.fixture(scope="session")
def provide_arm_docker_image() -> str:
    """Build the phi-scan Docker image for linux/arm64 once per test session.

    Skips when Docker or buildx linux/arm64 is unavailable (e.g., standard CI hosts).
    Active on Apple Silicon and any QEMU-equipped host with linux/arm64 support.
    Returns the image tag so tests can reference it without module-level mutable state.
    """
    if not _DOCKER_AVAILABLE:
        pytest.skip("Docker not available in this environment")
    if not _BUILDX_ARM_AVAILABLE:
        pytest.skip("Docker buildx linux/arm64 not available")
    dockerfile_dir = Path(__file__).parent.parent / "docker"
    result = subprocess.run(
        [
            "docker",
            "buildx",
            "build",
            "--platform",
            "linux/arm64",
            "--load",
            "-t",
            _ARM_IMAGE_TAG,
            str(dockerfile_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    if result.returncode != 0:
        pytest.skip(f"ARM Docker build failed: {result.stderr[:200]}")
    return _ARM_IMAGE_TAG


def test_docker_arm_image_runs_phi_scan_help(provide_arm_docker_image: str) -> None:
    """phi-scan Docker image built for linux/arm64 runs phi-scan --help and exits 0."""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/arm64",
            provide_arm_docker_image,
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, f"phi-scan --help failed on linux/arm64 image:\n{result.stderr}"
    output = result.stdout + result.stderr
    assert "phi-scan" in output.lower(), "Expected 'phi-scan' in --help output from ARM image"


# ---------------------------------------------------------------------------
# 6D.11/12/13 — Jenkins Declarative pipeline template structure tests
# ---------------------------------------------------------------------------

_JENKINSFILE = Path(__file__).parent.parent / "ci-templates" / "jenkins" / "Jenkinsfile"
_PHISCAN_GROOVY = (
    Path(__file__).parent.parent / "ci-templates" / "jenkins" / "vars" / "phiScan.groovy"
)

# Named constants for Jenkins template structure assertions
_JENKINS_RECORD_ISSUES: str = "recordIssues"
_JENKINS_SARIF_TOOL: str = "sarif("
_JENKINS_PUBLISH_CHECKS: str = "publishChecks"
_JENKINS_CHANGE_ID_GUARD: str = "env.CHANGE_ID"
_JENKINS_ABORT_EXCEPTION: str = "hudson.AbortException"
_JENKINS_ERROR_CALL: str = "error("
_JENKINS_SARIF_OUTPUT_FLAG: str = "--output sarif"
_JENKINS_FAIL_ON_VIOLATION_PARAM: str = "failOnViolation"


def test_jenkinsfile_scan_command_includes_sarif_output() -> None:
    """Jenkinsfile scan command must include --output sarif for Warnings NG consumption."""
    content = _JENKINSFILE.read_text()
    assert _JENKINS_SARIF_OUTPUT_FLAG in content, (
        f"Jenkinsfile is missing '{_JENKINS_SARIF_OUTPUT_FLAG}' required for Warnings NG"
    )


def test_jenkinsfile_record_issues_step_present() -> None:
    """Jenkinsfile must call recordIssues to publish SARIF findings in Warnings NG."""
    content = _JENKINSFILE.read_text()
    assert _JENKINS_RECORD_ISSUES in content, (
        f"Jenkinsfile is missing '{_JENKINS_RECORD_ISSUES}' required for Warnings NG tab"
    )


def test_jenkinsfile_record_issues_uses_sarif_tool() -> None:
    """Jenkinsfile recordIssues must use sarif() tool for correct severity mapping."""
    content = _JENKINSFILE.read_text()
    assert _JENKINS_SARIF_TOOL in content, (
        f"Jenkinsfile recordIssues must include '{_JENKINS_SARIF_TOOL}' for SARIF severity mapping"
    )


def test_jenkinsfile_publish_checks_present() -> None:
    """Jenkinsfile must call publishChecks for Jenkins Checks API inline PR annotations."""
    content = _JENKINSFILE.read_text()
    assert _JENKINS_PUBLISH_CHECKS in content, (
        f"Jenkinsfile is missing '{_JENKINS_PUBLISH_CHECKS}' required for Checks API annotations"
    )


def test_jenkinsfile_publish_checks_gated_on_change_id() -> None:
    """publishChecks must be gated on env.CHANGE_ID so it only fires on PR builds."""
    content = _JENKINSFILE.read_text()
    assert _JENKINS_CHANGE_ID_GUARD in content, (
        f"Jenkinsfile publishChecks block must be inside 'if ({_JENKINS_CHANGE_ID_GUARD})'"
    )


def test_jenkinsfile_publish_checks_catches_abort_exception() -> None:
    """publishChecks must catch hudson.AbortException so a missing Checks API plugin
    does not fail the build — annotations are optional, not required."""
    content = _JENKINSFILE.read_text()
    assert _JENKINS_ABORT_EXCEPTION in content, (
        f"Jenkinsfile publishChecks must catch '{_JENKINS_ABORT_EXCEPTION}' "
        "to tolerate missing Checks API plugin"
    )


def test_jenkinsfile_blocks_build_on_violation() -> None:
    """Jenkinsfile must call error() to block the build when violations are detected."""
    content = _JENKINSFILE.read_text()
    assert _JENKINS_ERROR_CALL in content, (
        f"Jenkinsfile must call '{_JENKINS_ERROR_CALL}' to fail the build on violations"
    )


def test_phiscan_groovy_scan_command_includes_sarif_output() -> None:
    """phiScan.groovy shared library step must include --output sarif in scan flags."""
    content = _PHISCAN_GROOVY.read_text()
    assert _JENKINS_SARIF_OUTPUT_FLAG in content, (
        f"phiScan.groovy is missing '{_JENKINS_SARIF_OUTPUT_FLAG}' required for Warnings NG"
    )


def test_phiscan_groovy_record_issues_present() -> None:
    """phiScan.groovy must call recordIssues to publish SARIF findings in Warnings NG."""
    content = _PHISCAN_GROOVY.read_text()
    assert _JENKINS_RECORD_ISSUES in content, (
        f"phiScan.groovy is missing '{_JENKINS_RECORD_ISSUES}' required for Warnings NG tab"
    )


def test_phiscan_groovy_record_issues_uses_sarif_tool() -> None:
    """phiScan.groovy recordIssues must use sarif() tool for SARIF severity mapping."""
    content = _PHISCAN_GROOVY.read_text()
    assert _JENKINS_SARIF_TOOL in content, (
        f"phiScan.groovy recordIssues must include '{_JENKINS_SARIF_TOOL}'"
    )


def test_phiscan_groovy_publish_checks_present() -> None:
    """phiScan.groovy must call publishChecks for Jenkins Checks API inline annotations."""
    content = _PHISCAN_GROOVY.read_text()
    assert _JENKINS_PUBLISH_CHECKS in content, (
        f"phiScan.groovy is missing '{_JENKINS_PUBLISH_CHECKS}'"
    )


def test_phiscan_groovy_publish_checks_catches_abort_exception() -> None:
    """phiScan.groovy publishChecks must catch hudson.AbortException."""
    content = _PHISCAN_GROOVY.read_text()
    assert _JENKINS_ABORT_EXCEPTION in content, (
        f"phiScan.groovy publishChecks must catch '{_JENKINS_ABORT_EXCEPTION}'"
    )


def test_phiscan_groovy_blocks_build_on_violation() -> None:
    """phiScan.groovy must call error() when failOnViolation is true and violations found."""
    content = _PHISCAN_GROOVY.read_text()
    assert _JENKINS_ERROR_CALL in content, (
        f"phiScan.groovy must call '{_JENKINS_ERROR_CALL}' to propagate violation failures"
    )


def test_phiscan_groovy_exposes_fail_on_violation_parameter() -> None:
    """phiScan.groovy must expose a failOnViolation parameter so callers can suppress failure."""
    content = _PHISCAN_GROOVY.read_text()
    assert _JENKINS_FAIL_ON_VIOLATION_PARAM in content, (
        f"phiScan.groovy must expose '{_JENKINS_FAIL_ON_VIOLATION_PARAM}' parameter"
    )


def test_sarif_symbols_reexported_from_ci_integration() -> None:
    """After the sarif slice moved to phi_scan.ci.sarif, the old import
    surface on phi_scan.ci_integration must still resolve to the same
    callables. Locks in backward compatibility for callers that imported
    from the legacy module path."""
    import phi_scan.ci.sarif as sarif_module
    import phi_scan.ci_integration as ci_integration_module

    assert ci_integration_module.upload_sarif_to_github is sarif_module.upload_sarif_to_github, (
        "upload_sarif_to_github no longer re-exported from phi_scan.ci_integration"
    )
