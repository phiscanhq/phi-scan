"""Tests for phi_scan.output — formatters and Rich UI components."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import MappingProxyType

from rich.table import Table

from phi_scan.constants import DetectionLayer, PhiCategory, RiskLevel, SeverityLevel
from phi_scan.models import ScanConfig, ScanFinding, ScanResult
from phi_scan.output import (
    create_scan_progress,
    display_banner,
    display_category_breakdown,
    display_clean_result,
    display_file_tree,
    display_findings_table,
    display_scan_header,
    display_summary_panel,
    display_violation_alert,
    format_csv,
    format_json,
    format_sarif,
    format_table,
)

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

_TEST_VALUE_HASH: str = hashlib.sha256(b"test-phi-value").hexdigest()
_TEST_FILE_PATH: Path = Path("src/patient.py")
_TEST_LINE_NUMBER: int = 42
_TEST_ENTITY_TYPE: str = "us_ssn"
_TEST_CONFIDENCE_HIGH: float = 0.95
_TEST_CONFIDENCE_MEDIUM: float = 0.75
# Deliberately not PHI-shaped — the SSN 000-00-0000 is in the SSN_EXCLUDED_AREA_NUMBERS
# reserved range (area 000) and is therefore structurally invalid as a real identifier.
_TEST_CODE_CONTEXT: str = 'field = "000-00-0000"'
_TEST_REMEDIATION_HINT: str = "Replace SSN with synthetic value"
_TEST_FILES_SCANNED: int = 10
_TEST_FILES_WITH_FINDINGS_CLEAN: int = 0
_TEST_FILES_WITH_FINDINGS_DIRTY: int = 1
_TEST_SCAN_DURATION: float = 0.5

_SARIF_VERSION_EXPECTED: str = "2.1.0"
_SARIF_SCHEMA_FRAGMENT: str = "sarif"
_JSON_FINDINGS_KEY: str = "findings"
_JSON_FILES_SCANNED_KEY: str = "files_scanned"
_JSON_IS_CLEAN_KEY: str = "is_clean"
_JSON_RISK_LEVEL_KEY: str = "risk_level"
_CSV_EXPECTED_HEADER_FILE_PATH: str = "file_path"
_CSV_EXPECTED_HEADER_ENTITY_TYPE: str = "entity_type"
_FINDINGS_TABLE_EXPECTED_COLUMN_COUNT: int = 6
_SARIF_VERSION_KEY: str = "version"
_SARIF_RUNS_KEY: str = "runs"
_SARIF_RESULTS_KEY: str = "results"
_SARIF_LEVEL_KEY: str = "level"
_SARIF_RULE_ID_KEY: str = "ruleId"
_SARIF_LEVEL_ERROR_EXPECTED: str = "error"

# ---------------------------------------------------------------------------
# Shared test data builders
# ---------------------------------------------------------------------------

_EMPTY_SEVERITY_COUNTS: MappingProxyType[SeverityLevel, int] = MappingProxyType(
    {level: 0 for level in SeverityLevel}
)
_EMPTY_CATEGORY_COUNTS: MappingProxyType[PhiCategory, int] = MappingProxyType(
    {cat: 0 for cat in PhiCategory}
)


def _make_finding(
    *,
    entity_type: str = _TEST_ENTITY_TYPE,
    hipaa_category: PhiCategory = PhiCategory.SSN,
    confidence: float = _TEST_CONFIDENCE_HIGH,
    severity: SeverityLevel = SeverityLevel.HIGH,
    line_number: int = _TEST_LINE_NUMBER,
    file_path: Path = _TEST_FILE_PATH,
) -> ScanFinding:
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=entity_type,
        hipaa_category=hipaa_category,
        confidence=confidence,
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
        files_with_findings=_TEST_FILES_WITH_FINDINGS_CLEAN,
        scan_duration=_TEST_SCAN_DURATION,
        is_clean=True,
        risk_level=RiskLevel.CLEAN,
        severity_counts=_EMPTY_SEVERITY_COUNTS,
        category_counts=_EMPTY_CATEGORY_COUNTS,
    )


def _make_dirty_result(finding: ScanFinding) -> ScanResult:
    severity_counts: MappingProxyType[SeverityLevel, int] = MappingProxyType(
        {**{level: 0 for level in SeverityLevel}, finding.severity: 1}
    )
    category_counts: MappingProxyType[PhiCategory, int] = MappingProxyType(
        {**{cat: 0 for cat in PhiCategory}, finding.hipaa_category: 1}
    )
    return ScanResult(
        findings=(finding,),
        files_scanned=_TEST_FILES_SCANNED,
        files_with_findings=_TEST_FILES_WITH_FINDINGS_DIRTY,
        scan_duration=_TEST_SCAN_DURATION,
        is_clean=False,
        risk_level=RiskLevel.CRITICAL,
        severity_counts=severity_counts,
        category_counts=category_counts,
    )


# ---------------------------------------------------------------------------
# format_table tests
# ---------------------------------------------------------------------------


def test_format_table_returns_rich_table_instance() -> None:
    clean_result = _make_clean_result()

    result = format_table(clean_result)

    assert isinstance(result, Table)


def test_format_table_has_expected_column_count() -> None:
    clean_result = _make_clean_result()

    table = format_table(clean_result)

    assert len(table.columns) == _FINDINGS_TABLE_EXPECTED_COLUMN_COUNT


def test_format_table_row_count_equals_finding_count() -> None:
    finding = _make_finding()
    dirty_result = _make_dirty_result(finding)

    table = format_table(dirty_result)

    assert table.row_count == len(dirty_result.findings)


def test_format_table_empty_when_no_findings() -> None:
    clean_result = _make_clean_result()

    table = format_table(clean_result)

    assert table.row_count == 0


# ---------------------------------------------------------------------------
# format_json tests
# ---------------------------------------------------------------------------


def test_format_json_returns_valid_json_string() -> None:
    clean_result = _make_clean_result()

    raw = format_json(clean_result)

    parsed = json.loads(raw)
    assert isinstance(parsed, dict)


def test_format_json_contains_expected_top_level_keys() -> None:
    clean_result = _make_clean_result()

    parsed = json.loads(format_json(clean_result))

    assert _JSON_FINDINGS_KEY in parsed
    assert _JSON_FILES_SCANNED_KEY in parsed
    assert _JSON_IS_CLEAN_KEY in parsed
    assert _JSON_RISK_LEVEL_KEY in parsed


def test_format_json_findings_array_length_matches_result() -> None:
    finding = _make_finding()
    dirty_result = _make_dirty_result(finding)

    parsed = json.loads(format_json(dirty_result))

    assert len(parsed[_JSON_FINDINGS_KEY]) == len(dirty_result.findings)


def test_format_json_finding_value_hash_is_hex_digest_not_raw_phi() -> None:
    finding = _make_finding()
    dirty_result = _make_dirty_result(finding)

    parsed = json.loads(format_json(dirty_result))
    serialized_hash: str = parsed[_JSON_FINDINGS_KEY][0]["value_hash"]

    # The value_hash must be exactly 64 lowercase hex characters — never a raw PHI value.
    assert len(serialized_hash) == 64
    assert all(c in "0123456789abcdef" for c in serialized_hash)


def test_format_json_clean_result_has_empty_findings_array() -> None:
    clean_result = _make_clean_result()

    parsed = json.loads(format_json(clean_result))

    assert parsed[_JSON_FINDINGS_KEY] == []


def test_format_json_is_clean_true_for_clean_result() -> None:
    clean_result = _make_clean_result()

    parsed = json.loads(format_json(clean_result))

    assert parsed[_JSON_IS_CLEAN_KEY] is True


# ---------------------------------------------------------------------------
# format_csv tests
# ---------------------------------------------------------------------------


def test_format_csv_returns_non_empty_string() -> None:
    clean_result = _make_clean_result()

    raw = format_csv(clean_result)

    assert isinstance(raw, str)
    assert len(raw) > 0


def test_format_csv_first_row_contains_expected_headers() -> None:
    clean_result = _make_clean_result()

    raw = format_csv(clean_result)
    first_line = raw.splitlines()[0]

    assert _CSV_EXPECTED_HEADER_FILE_PATH in first_line
    assert _CSV_EXPECTED_HEADER_ENTITY_TYPE in first_line


def test_format_csv_data_row_count_equals_finding_count() -> None:
    finding = _make_finding()
    dirty_result = _make_dirty_result(finding)

    raw = format_csv(dirty_result)
    # Lines: header + one data row + possible trailing newline
    data_lines = [line for line in raw.splitlines()[1:] if line]

    assert len(data_lines) == len(dirty_result.findings)


def test_format_csv_no_data_rows_when_clean() -> None:
    clean_result = _make_clean_result()

    raw = format_csv(clean_result)
    data_lines = [line for line in raw.splitlines()[1:] if line]

    assert len(data_lines) == 0


# ---------------------------------------------------------------------------
# format_sarif tests
# ---------------------------------------------------------------------------


def test_format_sarif_returns_valid_json_string() -> None:
    clean_result = _make_clean_result()

    raw = format_sarif(clean_result)

    parsed = json.loads(raw)
    assert isinstance(parsed, dict)


def test_format_sarif_version_is_2_1_0() -> None:
    clean_result = _make_clean_result()

    parsed = json.loads(format_sarif(clean_result))

    assert parsed[_SARIF_VERSION_KEY] == _SARIF_VERSION_EXPECTED


def test_format_sarif_schema_url_contains_sarif() -> None:
    clean_result = _make_clean_result()

    parsed = json.loads(format_sarif(clean_result))

    assert _SARIF_SCHEMA_FRAGMENT in parsed["$schema"]


def test_format_sarif_results_count_matches_findings() -> None:
    finding = _make_finding()
    dirty_result = _make_dirty_result(finding)

    parsed = json.loads(format_sarif(dirty_result))
    results = parsed[_SARIF_RUNS_KEY][0][_SARIF_RESULTS_KEY]

    assert len(results) == len(dirty_result.findings)


def test_format_sarif_high_severity_maps_to_error_level() -> None:
    finding = _make_finding(severity=SeverityLevel.HIGH)
    dirty_result = _make_dirty_result(finding)

    parsed = json.loads(format_sarif(dirty_result))
    first_result = parsed[_SARIF_RUNS_KEY][0][_SARIF_RESULTS_KEY][0]

    assert first_result[_SARIF_LEVEL_KEY] == _SARIF_LEVEL_ERROR_EXPECTED


def test_format_sarif_rule_id_matches_entity_type() -> None:
    finding = _make_finding()
    dirty_result = _make_dirty_result(finding)

    parsed = json.loads(format_sarif(dirty_result))
    first_result = parsed[_SARIF_RUNS_KEY][0][_SARIF_RESULTS_KEY][0]

    assert first_result[_SARIF_RULE_ID_KEY] == _TEST_ENTITY_TYPE


def test_format_sarif_empty_results_when_clean() -> None:
    clean_result = _make_clean_result()

    parsed = json.loads(format_sarif(clean_result))
    results = parsed[_SARIF_RUNS_KEY][0][_SARIF_RESULTS_KEY]

    assert results == []


# ---------------------------------------------------------------------------
# Display function smoke tests — verify no exceptions are raised
# ---------------------------------------------------------------------------


def test_display_banner_does_not_raise() -> None:
    display_banner()


def test_display_clean_result_does_not_raise() -> None:
    display_clean_result()


def test_display_scan_header_does_not_raise() -> None:
    display_scan_header(Path("."), ScanConfig())


def test_display_findings_table_does_not_raise_with_empty_findings() -> None:
    display_findings_table(())


def test_display_findings_table_does_not_raise_with_findings() -> None:
    finding = _make_finding()

    display_findings_table((finding,))


def test_display_file_tree_does_not_raise_with_empty_findings() -> None:
    display_file_tree(())


def test_display_file_tree_does_not_raise_with_findings() -> None:
    finding = _make_finding()

    display_file_tree((finding,))


def test_display_summary_panel_does_not_raise_for_clean_result() -> None:
    clean_result = _make_clean_result()

    display_summary_panel(clean_result)


def test_display_summary_panel_does_not_raise_for_dirty_result() -> None:
    finding = _make_finding()
    dirty_result = _make_dirty_result(finding)

    display_summary_panel(dirty_result)


def test_display_violation_alert_does_not_raise() -> None:
    finding = _make_finding()
    dirty_result = _make_dirty_result(finding)

    display_violation_alert(dirty_result)


def test_display_category_breakdown_does_not_raise_for_clean_result() -> None:
    clean_result = _make_clean_result()

    display_category_breakdown(clean_result)


def test_display_category_breakdown_does_not_raise_for_dirty_result() -> None:
    finding = _make_finding()
    dirty_result = _make_dirty_result(finding)

    display_category_breakdown(dirty_result)


def test_display_scan_progress_context_manager_does_not_raise() -> None:
    with create_scan_progress(total_files=5) as (progress, task_id):
        assert progress is not None
        assert task_id is not None


def test_display_scan_progress_yields_progress_and_task_id() -> None:
    with create_scan_progress(total_files=3) as (progress, task_id):
        # Verify callers can advance the progress bar without error.
        progress.update(task_id, advance=1)


# ---------------------------------------------------------------------------
# display_file_tree grouping behaviour
# ---------------------------------------------------------------------------


def test_display_file_tree_groups_multiple_findings_per_file() -> None:
    finding_one = _make_finding(line_number=10)
    finding_two = _make_finding(line_number=20)
    # Both findings share _TEST_FILE_PATH — should appear under one branch.
    # If grouping is broken, this would raise or render incorrectly.
    display_file_tree((finding_one, finding_two))


def test_display_file_tree_handles_findings_across_multiple_files() -> None:
    finding_a = _make_finding(file_path=Path("src/a.py"))
    finding_b = _make_finding(file_path=Path("src/b.py"))

    display_file_tree((finding_a, finding_b))


# ---------------------------------------------------------------------------
# _build_count_bar precondition tests
# ---------------------------------------------------------------------------


def test_build_count_bar_raises_value_error_when_max_count_is_zero() -> None:
    import pytest

    from phi_scan.output import _build_count_bar

    with pytest.raises(ValueError):
        _build_count_bar(count=1, max_count=0)
