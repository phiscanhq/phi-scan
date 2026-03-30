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
from pathlib import Path
from types import MappingProxyType

import pytest
from typer.testing import CliRunner

from phi_scan.cli import app
from phi_scan.constants import (
    EXIT_CODE_CLEAN,
    EXIT_CODE_VIOLATION,
    IMPLEMENTED_OUTPUT_FORMATS,
    DetectionLayer,
    OutputFormat,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.output import format_csv, format_json, format_sarif

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

_EXPECTED_IMPLEMENTED_FORMATS: frozenset[OutputFormat] = frozenset(
    {
        OutputFormat.TABLE,
        OutputFormat.JSON,
        OutputFormat.CSV,
        OutputFormat.SARIF,
    }
)

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

# Exit codes
_EXIT_CODE_CLI_ERROR: int = 2

# Minimal finding data — synthetic, not real PHI
_TEST_VALUE_HASH: str = hashlib.sha256(b"contract-test-seed").hexdigest()
_TEST_FILE_PATH: Path = Path("src/contract_test.py")
_TEST_LINE_NUMBER: int = 1
_TEST_ENTITY_TYPE: str = "us_ssn"
_TEST_FILES_SCANNED: int = 1
_TEST_FILES_WITH_FINDINGS_CLEAN: int = 0
_TEST_FILES_WITH_FINDINGS_DIRTY: int = 1
_TEST_SCAN_DURATION: float = 0.1

# A format that is a valid OutputFormat enum member but not yet implemented
_UNIMPLEMENTED_FORMAT_VALUE: str = OutputFormat.GITLAB_SAST.value

_runner = CliRunner()

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


# ---------------------------------------------------------------------------
# Registry contract
# ---------------------------------------------------------------------------


def test_implemented_output_formats_contains_exactly_the_four_current_formats() -> None:
    """IMPLEMENTED_OUTPUT_FORMATS matches the documented supported set exactly."""
    assert IMPLEMENTED_OUTPUT_FORMATS == _EXPECTED_IMPLEMENTED_FORMATS


def test_implemented_output_formats_does_not_include_phase_3_formats() -> None:
    """Phase 3 formats are not in IMPLEMENTED_OUTPUT_FORMATS until their formatters ship."""
    phase_3_formats = set(OutputFormat) - IMPLEMENTED_OUTPUT_FORMATS

    assert OutputFormat.PDF in phase_3_formats
    assert OutputFormat.HTML in phase_3_formats
    assert OutputFormat.JUNIT in phase_3_formats
    assert OutputFormat.CODEQUALITY in phase_3_formats
    assert OutputFormat.GITLAB_SAST in phase_3_formats


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
    assert len(finding_dict["value_hash"]) == 64  # SHA-256 hex digest length


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

    # rows[0] is the header; rows[1:] are data rows
    assert len(rows) == 2  # noqa: PLR2004 — 1 header + 1 finding


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


def test_sarif_output_has_runs_array_with_tool_and_results() -> None:
    """format_sarif runs[0] contains both tool and results keys."""
    clean_result = _build_clean_result()

    sarif_output = format_sarif(clean_result)
    parsed = json.loads(sarif_output)

    first_run = parsed[_SARIF_RUNS_FIELD][0]
    assert _SARIF_TOOL_FIELD in first_run
    assert _SARIF_RESULTS_FIELD in first_run


# ---------------------------------------------------------------------------
# Exit-code contract
# ---------------------------------------------------------------------------


def test_exit_code_is_clean_when_scan_produces_no_findings(tmp_path: Path) -> None:
    """Exit 0 (CLEAN) when the scanned directory contains no PHI."""
    result = _runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

    assert result.exit_code == EXIT_CODE_CLEAN


def test_exit_code_is_violation_when_scan_produces_findings(tmp_path: Path) -> None:
    """Exit 1 (VIOLATION) when the scanned directory contains PHI."""
    phi_file = tmp_path / "patient.py"
    # SYNTHETIC TEST FIXTURE — NOT A REAL SSN.
    # Area 900 is in SSN_EXCLUDED_AREA_NUMBERS — never assigned by the SSA.
    # 900-00-0001 cannot identify any real individual.
    phi_file.write_text('ssn = "900-00-0001"\n', encoding="utf-8")

    result = _runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

    assert result.exit_code == EXIT_CODE_VIOLATION


def test_exit_code_is_error_for_unimplemented_output_format(tmp_path: Path) -> None:
    """Exit 2 (error) when an unimplemented output format is requested via --output."""
    result = _runner.invoke(app, ["scan", str(tmp_path), "--output", _UNIMPLEMENTED_FORMAT_VALUE])

    assert result.exit_code == _EXIT_CODE_CLI_ERROR


# ---------------------------------------------------------------------------
# Implemented-formats roundtrip contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "output_format",
    sorted(IMPLEMENTED_OUTPUT_FORMATS - {OutputFormat.TABLE}, key=lambda fmt: fmt.value),
)
def test_each_implemented_format_exits_clean_without_error(
    tmp_path: Path, output_format: OutputFormat
) -> None:
    """Every format in IMPLEMENTED_OUTPUT_FORMATS (except TABLE) exits 0 on a clean scan."""
    result = _runner.invoke(
        app, ["scan", str(tmp_path), "--output", output_format.value, "--quiet"]
    )

    assert result.exit_code == EXIT_CODE_CLEAN
