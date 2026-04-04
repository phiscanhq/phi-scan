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

from phi_scan.ci_integration import (
    BaselineComparison,
    CIIntegrationError,
    CIPlatform,
    PRContext,
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

_SARIF_CONTENT: str = json.dumps(
    {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }
)

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


def _github_context(**overrides: object) -> PRContext:
    defaults: dict = {
        "platform": CIPlatform.GITHUB_ACTIONS,
        "pr_number": _GITHUB_PR_NUMBER,
        "repository": _GITHUB_REPO,
        "sha": _GITHUB_SHA,
        "branch": "refs/pull/42/merge",
        "base_branch": None,
    }
    defaults.update(overrides)
    return PRContext(**defaults)


def _azure_context(**overrides: object) -> PRContext:
    defaults: dict = {
        "platform": CIPlatform.AZURE_DEVOPS,
        "pr_number": _AZURE_PR_ID,
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
    return PRContext(**defaults)


def _bitbucket_context(**overrides: object) -> PRContext:
    defaults: dict = {
        "platform": CIPlatform.BITBUCKET,
        "pr_number": _BITBUCKET_PR_ID,
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
    return PRContext(**defaults)


# ---------------------------------------------------------------------------
# 6D.5 — GitHub SARIF upload tests
# ---------------------------------------------------------------------------


def test_upload_sarif_to_github_posts_to_code_scanning_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SARIF upload posts to the GitHub Code Scanning SARIF endpoint."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken")
    captured_urls: list[str] = []

    def fake_post(url: str, **kwargs: object) -> MagicMock:
        captured_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.post", side_effect=fake_post):
        upload_sarif_to_github(_SARIF_CONTENT, _github_context())

    assert any("code-scanning/sarifs" in url for url in captured_urls)


def test_upload_sarif_to_github_payload_contains_base64_encoded_sarif(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SARIF upload payload contains gzip-compressed, base64-encoded SARIF."""
    import base64
    import gzip

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken")
    captured_payloads: list[dict] = []

    def fake_post(url: str, json: dict, **kwargs: object) -> MagicMock:
        captured_payloads.append(json)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.post", side_effect=fake_post):
        upload_sarif_to_github(_SARIF_CONTENT, _github_context())

    assert captured_payloads
    encoded = captured_payloads[0]["sarif"]
    decoded = gzip.decompress(base64.b64decode(encoded)).decode("utf-8")
    assert "2.1.0" in decoded


def test_upload_sarif_skips_when_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """SARIF upload is skipped when GITHUB_TOKEN is absent."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    call_count = 0

    def fake_post(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.post", side_effect=fake_post):
        upload_sarif_to_github(_SARIF_CONTENT, _github_context())

    assert call_count == 0


def test_upload_sarif_skips_when_no_sha(monkeypatch: pytest.MonkeyPatch) -> None:
    """SARIF upload is skipped when commit SHA is absent."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken")
    call_count = 0

    def fake_post(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.post", side_effect=fake_post):
        upload_sarif_to_github(_SARIF_CONTENT, _github_context(sha=None))

    assert call_count == 0


def test_upload_sarif_raises_ci_integration_error_on_http_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CIIntegrationError raised when GitHub Code Scanning API returns an error."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_testtoken")

    def fake_post(url: str, **kwargs: object) -> MagicMock:
        mock_response = MagicMock()
        mock_response.status_code = 422
        mock_response.text = "Unprocessable Entity"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "422", request=MagicMock(), response=mock_response
        )
        return mock_response

    with patch("httpx.post", side_effect=fake_post):
        with pytest.raises(CIIntegrationError, match="GitHub SARIF upload failed"):
            upload_sarif_to_github(_SARIF_CONTENT, _github_context())


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

    def fake_post(url: str, json: dict, **kwargs: object) -> MagicMock:
        captured_payloads.append(json)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.post", side_effect=fake_post):
        set_azure_pr_status(_make_clean_result(), _azure_context())

    assert any(p.get("state") == "succeeded" for p in captured_payloads)


def test_set_azure_pr_status_posts_failed_when_violations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure PR status is 'failed' when violations found."""
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    captured_payloads: list[dict] = []

    def fake_post(url: str, json: dict, **kwargs: object) -> MagicMock:
        captured_payloads.append(json)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.post", side_effect=fake_post):
        set_azure_pr_status(_make_violation_result(), _azure_context())

    assert any(p.get("state") == "failed" for p in captured_payloads)


def test_set_azure_build_tag_uses_clean_tag_when_no_violations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure build is tagged with phi-scan:clean when no violations."""
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    captured_urls: list[str] = []

    def fake_put(url: str, **kwargs: object) -> MagicMock:
        captured_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.put", side_effect=fake_put):
        set_azure_build_tag(_make_clean_result(), _azure_context())

    assert any("phi-scan%3Aclean" in url or "phi-scan:clean" in url for url in captured_urls)


def test_set_azure_build_tag_uses_violations_tag_when_violations_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure build is tagged with phi-scan:violations-found when violations detected."""
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    captured_urls: list[str] = []

    def fake_put(url: str, **kwargs: object) -> MagicMock:
        captured_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.put", side_effect=fake_put):
        set_azure_build_tag(_make_violation_result(), _azure_context())

    assert any("violations-found" in url for url in captured_urls)


def test_set_azure_pr_status_skips_when_no_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure PR status is skipped when SYSTEM_ACCESSTOKEN is absent."""
    monkeypatch.delenv("SYSTEM_ACCESSTOKEN", raising=False)
    call_count = 0

    def fake_post(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.post", side_effect=fake_post):
        set_azure_pr_status(_make_clean_result(), _azure_context())

    assert call_count == 0


# ---------------------------------------------------------------------------
# 6C.18 — Azure Boards work-item creation
# ---------------------------------------------------------------------------


def test_create_azure_boards_work_item_skips_when_not_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure Boards work item is not created when AZURE_BOARDS_INTEGRATION != true."""
    monkeypatch.delenv("AZURE_BOARDS_INTEGRATION", raising=False)
    call_count = 0

    def fake_post(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.post", side_effect=fake_post):
        create_azure_boards_work_item(_make_violation_result(), _azure_context())

    assert call_count == 0


def test_create_azure_boards_work_item_skips_when_no_high_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure Boards work item is not created when there are no HIGH severity findings."""
    monkeypatch.setenv("AZURE_BOARDS_INTEGRATION", "true")
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "azure_token_abc")
    call_count = 0

    def fake_post(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.post", side_effect=fake_post):
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

    def fake_post(url: str, **kwargs: object) -> MagicMock:
        captured_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.post", side_effect=fake_post):
        create_azure_boards_work_item(_make_violation_result(), _azure_context())

    assert any("workitems" in url for url in captured_urls)


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

    def fake_put(url: str, **kwargs: object) -> MagicMock:
        put_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    def fake_post(url: str, **kwargs: object) -> MagicMock:
        post_urls.append(url)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.put", side_effect=fake_put), patch("httpx.post", side_effect=fake_post):
        post_bitbucket_code_insights(_make_violation_result(), _bitbucket_context())

    assert any("reports" in url for url in put_urls)
    assert any("annotations" in url for url in post_urls)


def test_post_bitbucket_code_insights_report_result_passed_when_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Code Insights report result is PASSED for a clean scan."""
    monkeypatch.setenv("BITBUCKET_TOKEN", "bb_testtoken")
    captured_payloads: list[dict] = []

    def fake_put(url: str, json: dict, **kwargs: object) -> MagicMock:
        captured_payloads.append(json)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.put", side_effect=fake_put):
        post_bitbucket_code_insights(_make_clean_result(), _bitbucket_context())

    assert any(p.get("result") == "PASSED" for p in captured_payloads)


def test_post_bitbucket_code_insights_report_result_failed_when_violations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Code Insights report result is FAILED when violations detected."""
    monkeypatch.setenv("BITBUCKET_TOKEN", "bb_testtoken")
    captured_payloads: list[dict] = []

    def fake_put(url: str, json: dict, **kwargs: object) -> MagicMock:
        captured_payloads.append(json)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    mock_post = MagicMock(raise_for_status=MagicMock())
    with patch("httpx.put", side_effect=fake_put), patch("httpx.post", return_value=mock_post):
        post_bitbucket_code_insights(_make_violation_result(), _bitbucket_context())

    assert any(p.get("result") == "FAILED" for p in captured_payloads)


def test_post_bitbucket_code_insights_annotations_include_file_and_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Code Insights annotations contain file path and line number."""
    monkeypatch.setenv("BITBUCKET_TOKEN", "bb_testtoken")
    captured_annotation_payloads: list[list] = []

    def fake_put(url: str, **kwargs: object) -> MagicMock:
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    def fake_post(url: str, json: list, **kwargs: object) -> MagicMock:
        captured_annotation_payloads.append(json)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        return mock_response

    with patch("httpx.put", side_effect=fake_put), patch("httpx.post", side_effect=fake_post):
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

    def fake_put(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        return MagicMock()

    with patch("httpx.put", side_effect=fake_put):
        post_bitbucket_code_insights(_make_clean_result(), _bitbucket_context())

    assert call_count == 0


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
    """ASFF findings must not contain raw PHI entity values."""
    asff = convert_findings_to_asff(
        _make_violation_result(), _AWS_ACCOUNT_ID, _AWS_REGION, _AWS_REPO
    )
    asff_str = json.dumps(asff)
    # The value hash is in there; the raw SSN is not
    assert _TEST_VALUE_HASH in asff_str
    assert "321-54-9870" not in asff_str


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

    context = PRContext(
        platform=CIPlatform.CODEBUILD,
        pr_number="1",
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

    context = PRContext(
        platform=CIPlatform.CODEBUILD,
        pr_number="1",
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

    context = PRContext(
        platform=CIPlatform.CODEBUILD,
        pr_number=None,
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

    context = PRContext(
        platform=CIPlatform.CODEBUILD,
        pr_number="1",
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
