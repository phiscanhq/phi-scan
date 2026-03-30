"""Tests for Phase 3A output formatters and CLI flags.

Covers:
  - format_junit  (JUnit XML)
  - format_codequality  (GitLab Code Quality JSON)
  - format_gitlab_sast  (GitLab SAST JSON v15.0.4)
  - --verbose flag (timestamped phase markers on stderr)
  - --report-path flag (writes serialized output to a file)
"""

from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from types import MappingProxyType

import pytest
from typer.testing import CliRunner

from phi_scan.cli import app
from phi_scan.constants import (
    EXIT_CODE_CLEAN,
    EXIT_CODE_ERROR,
    DetectionLayer,
    OutputFormat,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.output import format_codequality, format_gitlab_sast, format_junit

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

_TEST_FILE_PATH: Path = Path("src/patient_handler.py")
_TEST_LINE_NUMBER: int = 42
_TEST_ENTITY_TYPE: str = "us_ssn"
_TEST_FILES_SCANNED: int = 1
_TEST_FILES_WITH_FINDINGS_CLEAN: int = 0
_TEST_FILES_WITH_FINDINGS_DIRTY: int = 1
_TEST_SCAN_DURATION: float = 0.25
_TEST_CONFIDENCE: float = 0.95
_TEST_VALUE_HASH: str = hashlib.sha256(b"3a-test-seed").hexdigest()

# JUnit XML constants
_JUNIT_XML_DECLARATION_PREFIX: str = "<?xml"
_JUNIT_TESTSUITE_TAG: str = "testsuite"
_JUNIT_TESTCASE_TAG: str = "testcase"
_JUNIT_FAILURE_TAG: str = "failure"
_JUNIT_FAILURE_TYPE: str = "PHIViolation"
_JUNIT_TESTSUITE_NAME: str = "phi-scan"
_JUNIT_TESTS_ATTR: str = "tests"
_JUNIT_FAILURES_ATTR: str = "failures"
_JUNIT_ERRORS_ATTR: str = "errors"
_JUNIT_ERRORS_VALUE: str = "0"
_JUNIT_NAME_ATTR: str = "name"

# Code Quality constants
_CODEQUALITY_DESCRIPTION_KEY: str = "description"
_CODEQUALITY_FINGERPRINT_KEY: str = "fingerprint"
_CODEQUALITY_SEVERITY_KEY: str = "severity"
_CODEQUALITY_LOCATION_KEY: str = "location"
_CODEQUALITY_SEVERITY_CRITICAL: str = "critical"
_CODEQUALITY_SEVERITY_MAJOR: str = "major"
_CODEQUALITY_SEVERITY_MINOR: str = "minor"
_CODEQUALITY_SEVERITY_INFO_VALUE: str = "info"
_SHA256_HEX_DIGEST_LENGTH: int = 64

# GitLab SAST constants
_GITLAB_SAST_VERSION_PINNED: str = "15.0.4"
_GITLAB_SAST_VERSION_KEY: str = "version"
_GITLAB_SAST_VULNERABILITIES_KEY: str = "vulnerabilities"
_GITLAB_SAST_SCAN_KEY: str = "scan"
_GITLAB_SAST_SEVERITY_CRITICAL: str = "Critical"
_GITLAB_SAST_SEVERITY_HIGH: str = "High"
_GITLAB_SAST_SEVERITY_MEDIUM: str = "Medium"
_GITLAB_SAST_SEVERITY_LOW: str = "Low"
_GITLAB_SAST_ID_KEY: str = "id"
_GITLAB_SAST_CATEGORY_VALUE: str = "sast"

# CLI test constants
_VERBOSE_PHASE_PREFIX: str = "[20"
_REPORT_PATH_WRITTEN_PREFIX: str = "Report written to"
# SYNTHETIC TEST FIXTURE — NOT A REAL SSN.
# Area 900 is in SSN_EXCLUDED_AREA_NUMBERS — never assigned by the SSA.
_PHI_VIOLATION_FIXTURE_CONTENT: str = 'ssn = "900-00-0001"\n'


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def runner() -> CliRunner:
    """Fresh CliRunner per test."""
    return CliRunner()


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------


def _build_finding() -> ScanFinding:
    return ScanFinding(
        file_path=_TEST_FILE_PATH,
        line_number=_TEST_LINE_NUMBER,
        entity_type=_TEST_ENTITY_TYPE,
        hipaa_category=PhiCategory.SSN,
        confidence=_TEST_CONFIDENCE,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_TEST_VALUE_HASH,
        severity=SeverityLevel.HIGH,
        code_context="",
        remediation_hint="",
    )


def _build_clean_result() -> ScanResult:
    return ScanResult(
        findings=(),
        files_scanned=_TEST_FILES_SCANNED,
        files_with_findings=_TEST_FILES_WITH_FINDINGS_CLEAN,
        scan_duration=_TEST_SCAN_DURATION,
        is_clean=True,
        risk_level=RiskLevel.CLEAN,
        severity_counts=MappingProxyType({level: 0 for level in SeverityLevel}),
        category_counts=MappingProxyType({cat: 0 for cat in PhiCategory}),
    )


def _build_dirty_result() -> ScanResult:
    finding = _build_finding()
    return ScanResult(
        findings=(finding,),
        files_scanned=_TEST_FILES_SCANNED,
        files_with_findings=_TEST_FILES_WITH_FINDINGS_DIRTY,
        scan_duration=_TEST_SCAN_DURATION,
        is_clean=False,
        risk_level=RiskLevel.CRITICAL,
        severity_counts=MappingProxyType(
            {**{level: 0 for level in SeverityLevel}, SeverityLevel.HIGH: 1}
        ),
        category_counts=MappingProxyType({**{cat: 0 for cat in PhiCategory}, PhiCategory.SSN: 1}),
    )


# ---------------------------------------------------------------------------
# format_junit — clean result
# ---------------------------------------------------------------------------


def test_format_junit_starts_with_xml_declaration_for_clean_result() -> None:
    clean_result = _build_clean_result()

    output = format_junit(clean_result)

    assert output.startswith(_JUNIT_XML_DECLARATION_PREFIX)


def test_format_junit_root_tag_is_testsuite_for_clean_result() -> None:
    clean_result = _build_clean_result()

    output = format_junit(clean_result)
    root = ET.fromstring(output.split("\n", 1)[-1])

    assert root.tag == _JUNIT_TESTSUITE_TAG


def test_format_junit_testsuite_name_is_phi_scan() -> None:
    clean_result = _build_clean_result()

    output = format_junit(clean_result)
    root = ET.fromstring(output.split("\n", 1)[-1])

    assert root.attrib[_JUNIT_NAME_ATTR] == _JUNIT_TESTSUITE_NAME


def test_format_junit_has_zero_tests_for_clean_result() -> None:
    clean_result = _build_clean_result()

    output = format_junit(clean_result)
    root = ET.fromstring(output.split("\n", 1)[-1])

    assert root.attrib[_JUNIT_TESTS_ATTR] == "0"


def test_format_junit_has_zero_failures_for_clean_result() -> None:
    clean_result = _build_clean_result()

    output = format_junit(clean_result)
    root = ET.fromstring(output.split("\n", 1)[-1])

    assert root.attrib[_JUNIT_FAILURES_ATTR] == "0"


def test_format_junit_errors_attribute_is_always_zero() -> None:
    clean_result = _build_clean_result()

    output = format_junit(clean_result)
    root = ET.fromstring(output.split("\n", 1)[-1])

    assert root.attrib[_JUNIT_ERRORS_ATTR] == _JUNIT_ERRORS_VALUE


# ---------------------------------------------------------------------------
# format_junit — dirty result
# ---------------------------------------------------------------------------


def test_format_junit_has_one_testcase_per_finding() -> None:
    dirty_result = _build_dirty_result()

    output = format_junit(dirty_result)
    root = ET.fromstring(output.split("\n", 1)[-1])
    testcases = root.findall(_JUNIT_TESTCASE_TAG)

    assert len(testcases) == len(dirty_result.findings)


def test_format_junit_testcase_has_failure_child() -> None:
    dirty_result = _build_dirty_result()

    output = format_junit(dirty_result)
    root = ET.fromstring(output.split("\n", 1)[-1])
    testcase = root.find(_JUNIT_TESTCASE_TAG)

    assert testcase is not None
    assert testcase.find(_JUNIT_FAILURE_TAG) is not None


def test_format_junit_failure_type_is_phi_violation() -> None:
    dirty_result = _build_dirty_result()

    output = format_junit(dirty_result)
    root = ET.fromstring(output.split("\n", 1)[-1])
    failure = root.find(f".//{_JUNIT_FAILURE_TAG}")

    assert failure is not None
    assert failure.attrib["type"] == _JUNIT_FAILURE_TYPE


def test_format_junit_tests_and_failures_equal_finding_count() -> None:
    dirty_result = _build_dirty_result()

    output = format_junit(dirty_result)
    root = ET.fromstring(output.split("\n", 1)[-1])

    finding_count = str(len(dirty_result.findings))
    assert root.attrib[_JUNIT_TESTS_ATTR] == finding_count
    assert root.attrib[_JUNIT_FAILURES_ATTR] == finding_count


# ---------------------------------------------------------------------------
# format_codequality — clean result
# ---------------------------------------------------------------------------


def test_format_codequality_returns_empty_array_for_clean_result() -> None:
    clean_result = _build_clean_result()

    output = format_codequality(clean_result)
    parsed = json.loads(output)

    assert parsed == []


def test_format_codequality_output_is_a_json_array() -> None:
    dirty_result = _build_dirty_result()

    output = format_codequality(dirty_result)
    parsed = json.loads(output)

    assert isinstance(parsed, list)


# ---------------------------------------------------------------------------
# format_codequality — dirty result
# ---------------------------------------------------------------------------


def test_format_codequality_has_one_entry_per_finding() -> None:
    dirty_result = _build_dirty_result()

    output = format_codequality(dirty_result)
    parsed = json.loads(output)

    assert len(parsed) == len(dirty_result.findings)


def test_format_codequality_entry_has_required_keys() -> None:
    dirty_result = _build_dirty_result()

    output = format_codequality(dirty_result)
    entry = json.loads(output)[0]

    assert _CODEQUALITY_DESCRIPTION_KEY in entry
    assert _CODEQUALITY_FINGERPRINT_KEY in entry
    assert _CODEQUALITY_SEVERITY_KEY in entry
    assert _CODEQUALITY_LOCATION_KEY in entry


def test_format_codequality_fingerprint_is_sha256_hex_digest() -> None:
    dirty_result = _build_dirty_result()

    output = format_codequality(dirty_result)
    entry = json.loads(output)[0]

    assert len(entry[_CODEQUALITY_FINGERPRINT_KEY]) == _SHA256_HEX_DIGEST_LENGTH


def test_format_codequality_maps_high_severity_to_critical() -> None:
    dirty_result = _build_dirty_result()

    output = format_codequality(dirty_result)
    entry = json.loads(output)[0]

    assert entry[_CODEQUALITY_SEVERITY_KEY] == _CODEQUALITY_SEVERITY_CRITICAL


@pytest.mark.parametrize(
    ("severity_level", "expected_codequality_value"),
    [
        (SeverityLevel.HIGH, _CODEQUALITY_SEVERITY_CRITICAL),
        (SeverityLevel.MEDIUM, _CODEQUALITY_SEVERITY_MAJOR),
        (SeverityLevel.LOW, _CODEQUALITY_SEVERITY_MINOR),
        (SeverityLevel.INFO, _CODEQUALITY_SEVERITY_INFO_VALUE),
    ],
)
def test_format_codequality_severity_mapping(
    severity_level: SeverityLevel, expected_codequality_value: str
) -> None:
    finding = _build_finding()
    result = ScanResult(
        findings=(ScanFinding(**{**finding.__dict__, "severity": severity_level}),),
        files_scanned=_TEST_FILES_SCANNED,
        files_with_findings=_TEST_FILES_WITH_FINDINGS_DIRTY,
        scan_duration=_TEST_SCAN_DURATION,
        is_clean=False,
        risk_level=RiskLevel.CRITICAL,
        severity_counts=MappingProxyType({level: 0 for level in SeverityLevel}),
        category_counts=MappingProxyType({cat: 0 for cat in PhiCategory}),
    )

    output = format_codequality(result)
    entry = json.loads(output)[0]

    assert entry[_CODEQUALITY_SEVERITY_KEY] == expected_codequality_value


# ---------------------------------------------------------------------------
# format_gitlab_sast — top-level structure
# ---------------------------------------------------------------------------


def test_format_gitlab_sast_version_is_pinned_to_15_0_4() -> None:
    clean_result = _build_clean_result()

    output = format_gitlab_sast(clean_result)
    parsed = json.loads(output)

    assert parsed[_GITLAB_SAST_VERSION_KEY] == _GITLAB_SAST_VERSION_PINNED


def test_format_gitlab_sast_has_vulnerabilities_key() -> None:
    clean_result = _build_clean_result()

    output = format_gitlab_sast(clean_result)
    parsed = json.loads(output)

    assert _GITLAB_SAST_VULNERABILITIES_KEY in parsed


def test_format_gitlab_sast_has_scan_key() -> None:
    clean_result = _build_clean_result()

    output = format_gitlab_sast(clean_result)
    parsed = json.loads(output)

    assert _GITLAB_SAST_SCAN_KEY in parsed


def test_format_gitlab_sast_clean_result_has_empty_vulnerabilities() -> None:
    clean_result = _build_clean_result()

    output = format_gitlab_sast(clean_result)
    parsed = json.loads(output)

    assert parsed[_GITLAB_SAST_VULNERABILITIES_KEY] == []


# ---------------------------------------------------------------------------
# format_gitlab_sast — vulnerability structure
# ---------------------------------------------------------------------------


def test_format_gitlab_sast_has_one_vulnerability_per_finding() -> None:
    dirty_result = _build_dirty_result()

    output = format_gitlab_sast(dirty_result)
    parsed = json.loads(output)

    assert len(parsed[_GITLAB_SAST_VULNERABILITIES_KEY]) == len(dirty_result.findings)


def test_format_gitlab_sast_vulnerability_has_id_field() -> None:
    dirty_result = _build_dirty_result()

    output = format_gitlab_sast(dirty_result)
    vulnerability = json.loads(output)[_GITLAB_SAST_VULNERABILITIES_KEY][0]

    assert _GITLAB_SAST_ID_KEY in vulnerability
    assert len(vulnerability[_GITLAB_SAST_ID_KEY]) == _SHA256_HEX_DIGEST_LENGTH


def test_format_gitlab_sast_vulnerability_category_is_sast() -> None:
    dirty_result = _build_dirty_result()

    output = format_gitlab_sast(dirty_result)
    vulnerability = json.loads(output)[_GITLAB_SAST_VULNERABILITIES_KEY][0]

    assert vulnerability["category"] == _GITLAB_SAST_CATEGORY_VALUE


def test_format_gitlab_sast_maps_high_severity_to_critical() -> None:
    dirty_result = _build_dirty_result()

    output = format_gitlab_sast(dirty_result)
    vulnerability = json.loads(output)[_GITLAB_SAST_VULNERABILITIES_KEY][0]

    assert vulnerability["severity"] == _GITLAB_SAST_SEVERITY_CRITICAL


@pytest.mark.parametrize(
    ("severity_level", "expected_sast_severity"),
    [
        (SeverityLevel.HIGH, _GITLAB_SAST_SEVERITY_CRITICAL),
        (SeverityLevel.MEDIUM, _GITLAB_SAST_SEVERITY_HIGH),
        (SeverityLevel.LOW, _GITLAB_SAST_SEVERITY_MEDIUM),
        (SeverityLevel.INFO, _GITLAB_SAST_SEVERITY_LOW),
    ],
)
def test_format_gitlab_sast_severity_mapping(
    severity_level: SeverityLevel, expected_sast_severity: str
) -> None:
    finding = _build_finding()
    result = ScanResult(
        findings=(ScanFinding(**{**finding.__dict__, "severity": severity_level}),),
        files_scanned=_TEST_FILES_SCANNED,
        files_with_findings=_TEST_FILES_WITH_FINDINGS_DIRTY,
        scan_duration=_TEST_SCAN_DURATION,
        is_clean=False,
        risk_level=RiskLevel.CRITICAL,
        severity_counts=MappingProxyType({level: 0 for level in SeverityLevel}),
        category_counts=MappingProxyType({cat: 0 for cat in PhiCategory}),
    )

    output = format_gitlab_sast(result)
    vulnerability = json.loads(output)[_GITLAB_SAST_VULNERABILITIES_KEY][0]

    assert vulnerability["severity"] == expected_sast_severity


# ---------------------------------------------------------------------------
# --verbose flag
# ---------------------------------------------------------------------------


def test_verbose_flag_emits_phase_markers_to_stderr(tmp_path: Path, runner: CliRunner) -> None:
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--verbose", "--quiet"], catch_exceptions=False
    )

    assert result.exit_code == EXIT_CODE_CLEAN
    assert _VERBOSE_PHASE_PREFIX in result.output


def test_verbose_flag_does_not_suppress_exit_code(tmp_path: Path, runner: CliRunner) -> None:
    phi_file = tmp_path / "patient.py"
    phi_file.write_text(_PHI_VIOLATION_FIXTURE_CONTENT, encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--verbose", "--quiet"])

    assert result.exit_code != EXIT_CODE_CLEAN


# ---------------------------------------------------------------------------
# --report-path flag
# ---------------------------------------------------------------------------


def test_report_path_writes_json_output_to_file(tmp_path: Path, runner: CliRunner) -> None:
    report_file = tmp_path / "report.json"
    scan_dir = tmp_path / "src"
    scan_dir.mkdir()

    result = runner.invoke(
        app,
        [
            "scan",
            str(scan_dir),
            "--output",
            OutputFormat.JSON.value,
            "--report-path",
            str(report_file),
        ],
    )

    assert result.exit_code == EXIT_CODE_CLEAN
    assert report_file.exists()
    parsed = json.loads(report_file.read_text(encoding="utf-8"))
    assert "findings" in parsed


def test_report_path_writes_confirmation_message_to_stderr(
    tmp_path: Path, runner: CliRunner
) -> None:
    report_file = tmp_path / "report.json"
    scan_dir = tmp_path / "src"
    scan_dir.mkdir()

    result = runner.invoke(
        app,
        [
            "scan",
            str(scan_dir),
            "--output",
            OutputFormat.JSON.value,
            "--report-path",
            str(report_file),
        ],
    )

    assert _REPORT_PATH_WRITTEN_PREFIX in result.output


def test_report_path_with_table_format_exits_with_error(tmp_path: Path, runner: CliRunner) -> None:
    report_file = tmp_path / "report.txt"

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--output",
            OutputFormat.TABLE.value,
            "--report-path",
            str(report_file),
        ],
    )

    assert result.exit_code == EXIT_CODE_ERROR


def test_report_path_does_not_write_to_stdout(tmp_path: Path, runner: CliRunner) -> None:
    report_file = tmp_path / "report.json"
    scan_dir = tmp_path / "src"
    scan_dir.mkdir()

    result = runner.invoke(
        app,
        [
            "scan",
            str(scan_dir),
            "--output",
            OutputFormat.JSON.value,
            "--report-path",
            str(report_file),
        ],
        catch_exceptions=False,
    )

    # stdout (mix_stderr=True by default in CliRunner) should not contain the JSON body
    assert '"findings"' not in result.output


def test_report_path_with_sarif_format_produces_valid_sarif_file(
    tmp_path: Path, runner: CliRunner
) -> None:
    report_file = tmp_path / "results.sarif"
    scan_dir = tmp_path / "src"
    scan_dir.mkdir()

    result = runner.invoke(
        app,
        [
            "scan",
            str(scan_dir),
            "--output",
            OutputFormat.SARIF.value,
            "--report-path",
            str(report_file),
        ],
    )

    assert result.exit_code == EXIT_CODE_CLEAN
    assert report_file.exists()
    parsed = json.loads(report_file.read_text(encoding="utf-8"))
    assert parsed["version"] == "2.1.0"
