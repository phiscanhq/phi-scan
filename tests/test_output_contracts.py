# phi-scan:ignore-file
"""Output format contract tests — pin stable schema and exit-code behavior.

These tests assert the contracts that downstream consumers (CI/CD integrations,
dashboards, parsers) depend on:

  - IMPLEMENTED_OUTPUT_FORMATS is the single source of truth for capability gating.
  - JSON top-level keys and per-finding field names are stable.
  - CSV header columns are stable and in the documented order.
  - SARIF version and schema URL are pinned to 2.1.0.
  - Exit codes are deterministic: 0 (CLEAN), 1 (VIOLATION), 2 (format error).

When Phase 3 adds a new format, add it to IMPLEMENTED_OUTPUT_FORMATS and add a
corresponding contract block here before expanding the format surface.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType

import pytest
from typer.testing import CliRunner

from phi_scan.cli import app
from phi_scan.constants import (
    EXIT_CODE_CLEAN,
    EXIT_CODE_ERROR,
    EXIT_CODE_VIOLATION,
    IMPLEMENTED_OUTPUT_FORMATS,
    DetectionLayer,
    OutputFormat,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.output import (
    format_codequality,
    format_csv,
    format_gitlab_sast,
    format_json,
    format_junit,
    format_sarif,
)

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

# Expected count of formats in IMPLEMENTED_OUTPUT_FORMATS.
# Paired with individual membership tests below so that both adding and
# removing a format without updating the tests is caught.
_IMPLEMENTED_FORMAT_COUNT: int = 9

# JSON schema: exact top-level keys emitted by format_json
_JSON_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {
        "files_scanned",
        "files_with_findings",
        "scan_duration",
        "is_clean",
        "risk_level",
        "severity_counts",
        "category_counts",
        "findings",
    }
)

# JSON schema: exact keys emitted per finding by format_json
_JSON_FINDING_KEYS: frozenset[str] = frozenset(
    {
        "file_path",
        "line_number",
        "entity_type",
        "hipaa_category",
        "confidence",
        "severity",
        "detection_layer",
        "value_hash",
        "remediation_hint",
    }
)

# CSV schema: exact header columns in documented order (order matters for tooling)
_CSV_HEADERS_IN_ORDER: list[str] = [
    "file_path",
    "line_number",
    "entity_type",
    "hipaa_category",
    "confidence",
    "severity",
    "detection_layer",
    "remediation_hint",
]

# SARIF schema: pinned fields
_SARIF_VERSION_PINNED: str = "2.1.0"
_SARIF_SCHEMA_URL_FRAGMENT: str = "sarif-2.1.0"
_SARIF_SCHEMA_FIELD: str = "$schema"
_SARIF_VERSION_FIELD: str = "version"
_SARIF_RUNS_FIELD: str = "runs"
_SARIF_TOOL_FIELD: str = "tool"
_SARIF_RESULTS_FIELD: str = "results"

# CSV row count constants
_CSV_HEADER_ROW_COUNT: int = 1
_CSV_EXPECTED_ROW_COUNT_ONE_FINDING: int = _CSV_HEADER_ROW_COUNT + 1

# SHA-256 hex digest length — 32 bytes × 2 hex chars = 64 characters
_SHA256_HEX_DIGEST_LENGTH: int = 64

# Minimal finding data — synthetic, not real PHI
_TEST_VALUE_HASH: str = hashlib.sha256(b"contract-test-seed").hexdigest()
_TEST_FILE_PATH: Path = Path("src/contract_test.py")
_TEST_LINE_NUMBER: int = 1
_TEST_ENTITY_TYPE: str = "us_ssn"
_TEST_FILES_SCANNED: int = 1
_TEST_FILES_WITH_FINDINGS_CLEAN: int = 0
_TEST_FILES_WITH_FINDINGS_DIRTY: int = 1
_TEST_SCAN_DURATION: float = 0.1

# A value that is not a valid OutputFormat enum member (used to test CLI rejection)
_UNIMPLEMENTED_FORMAT_VALUE: str = "xml"

# SYNTHETIC TEST FIXTURE — NOT A REAL SSN.
# Area 900 is in SSN_EXCLUDED_AREA_NUMBERS — never assigned by the SSA.
# 900-00-0001 cannot identify any real individual.
_PHI_VIOLATION_FIXTURE_CONTENT: str = 'ssn = "900-00-0001"\n'

# Sentinel value embedded in code_context to verify that no CI output format
# serializes the surrounding-source-lines field. The value is deliberately
# non-PHI and structured to be unmistakable if it ever appears in output.
_CODE_CONTEXT_SENTINEL: str = "SENTINEL__[REDACTED]__CODE_CTX__MUST_NOT_APPEAR_IN_CI_OUTPUT"

# All CI formatters share the signature (ScanResult) -> str. Parametrized with
# a human-readable name so pytest failure output identifies the failing format.
_CI_FORMATTERS: list[tuple[str, Callable[[ScanResult], str]]] = [
    ("json", format_json),
    ("csv", format_csv),
    ("sarif", format_sarif),
    ("junit", format_junit),
    ("codequality", format_codequality),
    ("gitlab_sast", format_gitlab_sast),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def runner() -> CliRunner:
    """Fresh CliRunner per test — avoids shared mutable state across tests."""
    return CliRunner()


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------


def _build_contract_finding() -> ScanFinding:
    return ScanFinding(
        file_path=_TEST_FILE_PATH,
        line_number=_TEST_LINE_NUMBER,
        entity_type=_TEST_ENTITY_TYPE,
        hipaa_category=PhiCategory.SSN,
        confidence=0.95,
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
    finding = _build_contract_finding()
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


def _build_dirty_result_with_code_context_sentinel() -> ScanResult:
    """Build a dirty ScanResult whose finding carries the code_context sentinel value.

    Used to assert that no CI output formatter serializes the surrounding-source-lines
    field — only location metadata (file, line, entity type) should appear in output.
    """
    finding = ScanFinding(
        file_path=_TEST_FILE_PATH,
        line_number=_TEST_LINE_NUMBER,
        entity_type=_TEST_ENTITY_TYPE,
        hipaa_category=PhiCategory.SSN,
        confidence=0.95,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_TEST_VALUE_HASH,
        severity=SeverityLevel.HIGH,
        code_context=_CODE_CONTEXT_SENTINEL,
        remediation_hint="",
    )
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
# Registry contract
# ---------------------------------------------------------------------------


def test_implemented_output_formats_contains_table() -> None:
    """TABLE must always be implemented — it is the default output format."""
    assert OutputFormat.TABLE in IMPLEMENTED_OUTPUT_FORMATS


def test_implemented_output_formats_contains_json() -> None:
    """JSON must be implemented — it is the primary machine-readable format."""
    assert OutputFormat.JSON in IMPLEMENTED_OUTPUT_FORMATS


def test_implemented_output_formats_contains_csv() -> None:
    """CSV must be implemented — it is required for spreadsheet and audit export."""
    assert OutputFormat.CSV in IMPLEMENTED_OUTPUT_FORMATS


def test_implemented_output_formats_contains_sarif() -> None:
    """SARIF must be implemented — it is the native format for all CI/CD platforms."""
    assert OutputFormat.SARIF in IMPLEMENTED_OUTPUT_FORMATS


def test_implemented_output_formats_contains_junit() -> None:
    """JUnit must be implemented — it is the CI test-summary format for CircleCI/Jenkins."""
    assert OutputFormat.JUNIT in IMPLEMENTED_OUTPUT_FORMATS


def test_implemented_output_formats_contains_codequality() -> None:
    """Code Quality must be implemented — it is the GitLab MR annotation format."""
    assert OutputFormat.CODEQUALITY in IMPLEMENTED_OUTPUT_FORMATS


def test_implemented_output_formats_contains_gitlab_sast() -> None:
    """GitLab SAST must be implemented — it is the GitLab Security Dashboard format."""
    assert OutputFormat.GITLAB_SAST in IMPLEMENTED_OUTPUT_FORMATS


def test_implemented_output_formats_has_expected_member_count() -> None:
    """IMPLEMENTED_OUTPUT_FORMATS contains exactly _IMPLEMENTED_FORMAT_COUNT members.

    Paired with the four membership tests above: adding a format without a
    membership test raises the count; removing a format without updating a
    membership test breaks that test.
    """
    assert len(IMPLEMENTED_OUTPUT_FORMATS) == _IMPLEMENTED_FORMAT_COUNT


def test_implemented_output_formats_contains_pdf() -> None:
    """PDF must be implemented — it is the enterprise report format (Phase 4)."""
    assert OutputFormat.PDF in IMPLEMENTED_OUTPUT_FORMATS


def test_implemented_output_formats_contains_html() -> None:
    """HTML must be implemented — it is the browser-readable enterprise report format (Phase 4)."""
    assert OutputFormat.HTML in IMPLEMENTED_OUTPUT_FORMATS


# ---------------------------------------------------------------------------
# JSON schema contract
# ---------------------------------------------------------------------------


def test_json_output_has_exactly_the_documented_top_level_keys() -> None:
    """format_json emits all and only the 8 documented top-level keys."""
    clean_result = _build_clean_result()

    json_output = format_json(clean_result)
    parsed = json.loads(json_output)

    assert set(parsed.keys()) == _JSON_TOP_LEVEL_KEYS


def test_json_finding_has_exactly_the_documented_field_names() -> None:
    """Each finding dict in format_json output has exactly the documented fields."""
    dirty_result = _build_dirty_result()

    json_output = format_json(dirty_result)
    parsed = json.loads(json_output)

    assert len(parsed["findings"]) == 1
    assert set(parsed["findings"][0].keys()) == _JSON_FINDING_KEYS


def test_json_output_never_contains_raw_phi_value() -> None:
    """format_json stores value_hash (SHA-256), never the raw PHI value."""
    dirty_result = _build_dirty_result()

    json_output = format_json(dirty_result)
    parsed = json.loads(json_output)

    finding_dict = parsed["findings"][0]
    assert finding_dict["value_hash"] == _TEST_VALUE_HASH
    assert len(finding_dict["value_hash"]) == _SHA256_HEX_DIGEST_LENGTH


# ---------------------------------------------------------------------------
# CSV schema contract
# ---------------------------------------------------------------------------


def test_csv_output_headers_are_the_eight_documented_columns_in_order() -> None:
    """format_csv emits exactly the 8 documented header columns in the documented order."""
    clean_result = _build_clean_result()

    csv_output = format_csv(clean_result)
    reader = csv.reader(io.StringIO(csv_output))
    headers = next(reader)

    assert headers == _CSV_HEADERS_IN_ORDER


def test_csv_output_has_one_data_row_per_finding() -> None:
    """format_csv emits one data row per finding (plus the header row)."""
    dirty_result = _build_dirty_result()

    csv_output = format_csv(dirty_result)
    rows = list(csv.reader(io.StringIO(csv_output)))

    assert len(rows) == _CSV_EXPECTED_ROW_COUNT_ONE_FINDING


# ---------------------------------------------------------------------------
# SARIF schema contract
# ---------------------------------------------------------------------------


def test_sarif_output_version_is_pinned_to_2_1_0() -> None:
    """format_sarif emits SARIF version 2.1.0 — the version expected by all CI/CD platforms."""
    clean_result = _build_clean_result()

    sarif_output = format_sarif(clean_result)
    parsed = json.loads(sarif_output)

    assert parsed[_SARIF_VERSION_FIELD] == _SARIF_VERSION_PINNED


def test_sarif_output_schema_url_references_2_1_0() -> None:
    """format_sarif $schema URL references sarif-2.1.0 for schema validation."""
    clean_result = _build_clean_result()

    sarif_output = format_sarif(clean_result)
    parsed = json.loads(sarif_output)

    assert _SARIF_SCHEMA_URL_FRAGMENT in parsed[_SARIF_SCHEMA_FIELD]


def test_sarif_runs_array_contains_tool_field() -> None:
    """format_sarif runs[0] contains the tool field required by the SARIF spec."""
    clean_result = _build_clean_result()

    sarif_output = format_sarif(clean_result)
    parsed = json.loads(sarif_output)

    assert _SARIF_TOOL_FIELD in parsed[_SARIF_RUNS_FIELD][0]


def test_sarif_runs_array_contains_results_field() -> None:
    """format_sarif runs[0] contains the results field required by the SARIF spec."""
    clean_result = _build_clean_result()

    sarif_output = format_sarif(clean_result)
    parsed = json.loads(sarif_output)

    assert _SARIF_RESULTS_FIELD in parsed[_SARIF_RUNS_FIELD][0]


# ---------------------------------------------------------------------------
# Exit-code contract
# ---------------------------------------------------------------------------


def test_exit_code_is_clean_when_scan_produces_no_findings(
    tmp_path: Path, runner: CliRunner
) -> None:
    """Exit 0 (CLEAN) when the scanned directory contains no PHI."""
    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

    assert result.exit_code == EXIT_CODE_CLEAN


def test_exit_code_is_violation_when_scan_produces_findings(
    tmp_path: Path, runner: CliRunner
) -> None:
    """Exit 1 (VIOLATION) when the scanned directory contains PHI."""
    phi_file = tmp_path / "patient.py"
    phi_file.write_text(_PHI_VIOLATION_FIXTURE_CONTENT, encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

    assert result.exit_code == EXIT_CODE_VIOLATION


def test_exit_code_is_error_for_unimplemented_output_format(
    tmp_path: Path, runner: CliRunner
) -> None:
    """Exit 2 (error) when an unimplemented output format is requested via --output."""
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", _UNIMPLEMENTED_FORMAT_VALUE])

    assert result.exit_code == EXIT_CODE_ERROR


# ---------------------------------------------------------------------------
# Implemented-formats roundtrip contract
# ---------------------------------------------------------------------------

# Binary formats cannot write to stdout and require --report-path.
_BINARY_OUTPUT_FORMATS: frozenset[OutputFormat] = frozenset({OutputFormat.PDF, OutputFormat.HTML})
_TEXT_OUTPUT_FORMATS: frozenset[OutputFormat] = (
    IMPLEMENTED_OUTPUT_FORMATS - {OutputFormat.TABLE} - _BINARY_OUTPUT_FORMATS
)


@pytest.mark.parametrize(
    "output_format",
    sorted(_TEXT_OUTPUT_FORMATS, key=lambda fmt: fmt.value),
)
def test_each_text_format_exits_clean_without_error(
    tmp_path: Path, output_format: OutputFormat, runner: CliRunner
) -> None:
    """Every text format in IMPLEMENTED_OUTPUT_FORMATS exits 0 on a clean scan."""
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", output_format.value, "--quiet"])

    assert result.exit_code == EXIT_CODE_CLEAN


@pytest.mark.parametrize(
    "output_format",
    sorted(_BINARY_OUTPUT_FORMATS, key=lambda fmt: fmt.value),
)
def test_each_binary_format_exits_clean_with_report_path(
    tmp_path: Path, output_format: OutputFormat, runner: CliRunner
) -> None:
    """Every binary format exits 0 on a clean scan when --report-path is given."""
    report_file = tmp_path / f"report.{output_format.value}"

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--output",
            output_format.value,
            "--report-path",
            str(report_file),
            "--quiet",
        ],
    )

    assert result.exit_code == EXIT_CODE_CLEAN


@pytest.mark.parametrize(
    "output_format",
    sorted(_BINARY_OUTPUT_FORMATS, key=lambda fmt: fmt.value),
)
def test_each_binary_format_exits_error_without_report_path(
    tmp_path: Path, output_format: OutputFormat, runner: CliRunner
) -> None:
    """Binary formats exit 2 (error) when --report-path is omitted."""
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", output_format.value, "--quiet"])

    assert result.exit_code == EXIT_CODE_ERROR


# ---------------------------------------------------------------------------
# PHI-safety contract — code_context must not appear in CI output formats
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("format_name,serializer", _CI_FORMATTERS)
def test_ci_format_does_not_serialize_code_context(
    format_name: str,
    serializer: Callable[[ScanResult], str],
) -> None:
    """No CI output format serializes code_context (surrounding source lines).

    code_context holds raw source lines adjacent to the detection — those lines
    may contain PHI values beyond the detected entity. CI consumers (dashboards,
    SAST tools, JUnit panels) need only location metadata to act on a finding;
    they must never receive the source context itself.

    If this test fails for a new format, the formatter must strip code_context
    before serializing, or document a deliberate policy exception here.
    """
    dirty_result = _build_dirty_result_with_code_context_sentinel()

    serialized = serializer(dirty_result)

    assert _CODE_CONTEXT_SENTINEL not in serialized, (
        f"format '{format_name}' serialized code_context sentinel value — "
        "surrounding source lines must not appear in CI output"
    )
