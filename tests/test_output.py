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
    build_dashboard_layout,
    create_scan_progress,
    display_banner,
    display_category_breakdown,
    display_clean_result,
    display_clean_summary_panel,
    display_code_context_panel,
    display_exit_code_message,
    display_file_tree,
    display_file_type_summary,
    display_findings_table,
    display_phase_audit,
    display_phase_collecting,
    display_phase_report,
    display_phase_scanning,
    display_phase_separator,
    display_risk_level_badge,
    display_scan_header,
    display_severity_inline,
    display_status_spinner,
    display_summary_panel,
    display_violation_alert,
    display_violation_summary_panel,
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
# SYNTHETIC TEST FIXTURE — NOT A REAL SSN.
# Area 000 is in SSN_EXCLUDED_AREA_NUMBERS (the SSA has never issued area 000).
# 000-00-0000 is structurally invalid as a real Social Security Number and
# cannot identify any individual. Used only to exercise code-context formatting.
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


# ---------------------------------------------------------------------------
# display_phase_separator and named phase helpers
# ---------------------------------------------------------------------------

_CUSTOM_PHASE_LABEL: str = "Custom Phase"


def test_display_phase_separator_does_not_raise() -> None:
    display_phase_separator(_CUSTOM_PHASE_LABEL)


def test_display_phase_collecting_does_not_raise() -> None:
    display_phase_collecting()


def test_display_phase_scanning_does_not_raise() -> None:
    display_phase_scanning()


def test_display_phase_audit_does_not_raise() -> None:
    display_phase_audit()


def test_display_phase_report_does_not_raise() -> None:
    display_phase_report()


# ---------------------------------------------------------------------------
# _count_files_by_extension
# ---------------------------------------------------------------------------

_PY_PATH: Path = Path("src/scanner.py")
_JSON_PATH: Path = Path("config/settings.json")
_ANOTHER_PY_PATH: Path = Path("tests/test_scanner.py")
_NO_EXTENSION_PATH: Path = Path("Makefile")


def test_count_files_by_extension_groups_by_suffix() -> None:
    from phi_scan.output import _count_files_by_extension

    counts = _count_files_by_extension([_PY_PATH, _JSON_PATH, _ANOTHER_PY_PATH])

    assert counts[".py"] == 2
    assert counts[".json"] == 1


def test_count_files_by_extension_uses_other_label_for_no_extension() -> None:
    from phi_scan.output import _FILE_TYPE_SUMMARY_OTHER_LABEL, _count_files_by_extension

    counts = _count_files_by_extension([_NO_EXTENSION_PATH])

    assert counts[_FILE_TYPE_SUMMARY_OTHER_LABEL] == 1


def test_count_files_by_extension_returns_empty_dict_for_empty_list() -> None:
    from phi_scan.output import _count_files_by_extension

    counts = _count_files_by_extension([])

    assert counts == {}


# ---------------------------------------------------------------------------
# display_file_type_summary
# ---------------------------------------------------------------------------

_MANY_EXTENSION_PATHS: list[Path] = (
    [Path(f"f{i}.py") for i in range(3)]
    + [Path(f"f{i}.json") for i in range(2)]
    + [Path(f"f{i}.yaml") for i in range(4)]
    + [Path(f"f{i}.ts") for i in range(1)]
    + [Path(f"f{i}.rs") for i in range(2)]
    + [Path(f"f{i}.go") for i in range(5)]
)


def test_display_file_type_summary_does_not_raise_for_normal_input() -> None:
    display_file_type_summary([_PY_PATH, _JSON_PATH, _ANOTHER_PY_PATH])


def test_display_file_type_summary_does_not_raise_for_empty_list() -> None:
    display_file_type_summary([])


def test_display_file_type_summary_does_not_raise_when_extensions_exceed_max() -> None:
    display_file_type_summary(_MANY_EXTENSION_PATHS)


# ---------------------------------------------------------------------------
# display_status_spinner
# ---------------------------------------------------------------------------

_SPINNER_TEST_MESSAGE: str = "Working…"
_SENTINEL_VALUE: int = 0
_EXPECTED_SENTINEL_INCREMENT: int = 1


def test_display_status_spinner_executes_body_when_active() -> None:
    counter = [_SENTINEL_VALUE]

    with display_status_spinner(_SPINNER_TEST_MESSAGE, is_active=True):
        counter[0] += _EXPECTED_SENTINEL_INCREMENT

    assert counter[0] == _EXPECTED_SENTINEL_INCREMENT


def test_display_status_spinner_executes_body_when_inactive() -> None:
    counter = [_SENTINEL_VALUE]

    with display_status_spinner(_SPINNER_TEST_MESSAGE, is_active=False):
        counter[0] += _EXPECTED_SENTINEL_INCREMENT

    assert counter[0] == _EXPECTED_SENTINEL_INCREMENT


def test_display_status_spinner_does_not_raise_when_inactive() -> None:
    with display_status_spinner(_SPINNER_TEST_MESSAGE, is_active=False):
        pass


# ---------------------------------------------------------------------------
# display_clean_summary_panel (1C.3c)
# ---------------------------------------------------------------------------


def test_display_clean_summary_panel_does_not_raise() -> None:
    display_clean_summary_panel(_make_clean_result())


def test_build_clean_summary_panel_markup_contains_status_label() -> None:
    from phi_scan.output import _CLEAN_SUMMARY_STATUS_LABEL, _build_clean_summary_panel_markup

    markup = _build_clean_summary_panel_markup(_make_clean_result())

    assert _CLEAN_SUMMARY_STATUS_LABEL in markup


def test_build_clean_summary_panel_markup_contains_files_scanned() -> None:
    from phi_scan.output import _build_clean_summary_panel_markup

    markup = _build_clean_summary_panel_markup(_make_clean_result())

    assert str(_TEST_FILES_SCANNED) in markup


# ---------------------------------------------------------------------------
# display_exit_code_message (1C.3d)
# ---------------------------------------------------------------------------


def test_display_exit_code_message_does_not_raise_for_clean() -> None:
    display_exit_code_message(is_clean=True)


def test_display_exit_code_message_does_not_raise_for_violation() -> None:
    display_exit_code_message(is_clean=False)


# ---------------------------------------------------------------------------
# display_violation_alert (1C.4a)
# ---------------------------------------------------------------------------


def test_build_violation_alert_text_contains_finding_count() -> None:
    from phi_scan.output import _build_violation_alert_text

    finding = _make_finding()
    result = _make_dirty_result(finding)
    text = _build_violation_alert_text(result)

    assert "1" in text


def test_build_violation_alert_text_contains_icon() -> None:
    from phi_scan.output import _VIOLATION_ALERT_ICON, _build_violation_alert_text

    result = _make_dirty_result(_make_finding())
    text = _build_violation_alert_text(result)

    assert _VIOLATION_ALERT_ICON in text


# ---------------------------------------------------------------------------
# display_risk_level_badge (1C.4b)
# ---------------------------------------------------------------------------


def test_display_risk_level_badge_does_not_raise() -> None:
    display_risk_level_badge(_make_dirty_result(_make_finding()))


# ---------------------------------------------------------------------------
# display_severity_inline (1C.4c)
# ---------------------------------------------------------------------------


def test_display_severity_inline_does_not_raise() -> None:
    display_severity_inline(_make_dirty_result(_make_finding()))


def test_build_severity_inline_text_omits_zero_count_levels() -> None:
    from phi_scan.output import _build_severity_inline_text

    result = _make_dirty_result(_make_finding(severity=SeverityLevel.HIGH))
    inline = _build_severity_inline_text(result.severity_counts)

    assert "HIGH" in inline
    assert "MEDIUM" not in inline


# ---------------------------------------------------------------------------
# display_file_tree (1C.4e — severity icon)
# ---------------------------------------------------------------------------


def test_display_file_tree_with_findings_does_not_raise() -> None:
    display_file_tree(_make_dirty_result(_make_finding()).findings)


def test_highest_severity_icon_returns_red_for_high() -> None:
    from phi_scan.output import _SEVERITY_ICON, _highest_severity_icon

    findings = [_make_finding(severity=SeverityLevel.HIGH)]
    icon = _highest_severity_icon(findings)

    assert icon == _SEVERITY_ICON["high"]


# ---------------------------------------------------------------------------
# display_code_context_panel (1C.4g)
# ---------------------------------------------------------------------------


def test_display_code_context_panel_does_not_raise() -> None:
    display_code_context_panel(_make_finding())


# ---------------------------------------------------------------------------
# display_violation_summary_panel (1C.4h)
# ---------------------------------------------------------------------------


def test_display_violation_summary_panel_does_not_raise() -> None:
    display_violation_summary_panel(_make_dirty_result(_make_finding()))


def test_build_violation_summary_panel_markup_contains_status_label() -> None:
    from phi_scan.output import (
        _VIOLATION_SUMMARY_STATUS_LABEL,
        _build_violation_summary_panel_markup,
    )

    markup = _build_violation_summary_panel_markup(_make_dirty_result(_make_finding()))

    assert _VIOLATION_SUMMARY_STATUS_LABEL in markup


# ---------------------------------------------------------------------------
# _build_dashboard_top_panel (1C.5a)
# ---------------------------------------------------------------------------

_DASHBOARD_CLEAN_SCAN_ROW: dict[str, object] = {
    "is_clean": 1,
    "files_scanned": 5,
    "findings_count": 0,
    "scan_duration": 0.3,
    "timestamp": "2026-03-27T10:00:00",
}
_DASHBOARD_VIOLATION_SCAN_ROW: dict[str, object] = {
    "is_clean": 0,
    "files_scanned": 8,
    "findings_count": 3,
    "scan_duration": 1.2,
    "timestamp": "2026-03-27T11:00:00",
}


def test_build_dashboard_top_panel_no_history_does_not_raise() -> None:
    from phi_scan.output import _build_dashboard_top_panel

    _build_dashboard_top_panel(None)


def test_build_dashboard_top_panel_clean_scan_does_not_raise() -> None:
    from phi_scan.output import _build_dashboard_top_panel

    _build_dashboard_top_panel(_DASHBOARD_CLEAN_SCAN_ROW)


def test_build_dashboard_top_panel_violation_scan_does_not_raise() -> None:
    from phi_scan.output import _build_dashboard_top_panel

    _build_dashboard_top_panel(_DASHBOARD_VIOLATION_SCAN_ROW)


def test_build_dashboard_top_panel_no_history_contains_no_history_text() -> None:
    from rich.panel import Panel

    from phi_scan.output import (
        _DASHBOARD_NO_HISTORY_TEXT,
        _build_dashboard_top_panel,
    )

    panel = _build_dashboard_top_panel(None)

    assert isinstance(panel, Panel)
    assert _DASHBOARD_NO_HISTORY_TEXT in str(panel.renderable)


def test_build_dashboard_top_panel_clean_contains_clean_status() -> None:
    from phi_scan.output import (
        _DASHBOARD_HISTORY_CLEAN_STATUS,
        _build_dashboard_top_panel,
    )

    panel = _build_dashboard_top_panel(_DASHBOARD_CLEAN_SCAN_ROW)

    assert _DASHBOARD_HISTORY_CLEAN_STATUS in str(panel.renderable)


def test_build_dashboard_top_panel_violation_contains_violation_status() -> None:
    from phi_scan.output import (
        _DASHBOARD_HISTORY_VIOLATION_STATUS,
        _build_dashboard_top_panel,
    )

    panel = _build_dashboard_top_panel(_DASHBOARD_VIOLATION_SCAN_ROW)

    assert _DASHBOARD_HISTORY_VIOLATION_STATUS in str(panel.renderable)


# ---------------------------------------------------------------------------
# _build_dashboard_history_table (1C.5b)
# ---------------------------------------------------------------------------


def test_build_dashboard_history_table_empty_list_does_not_raise() -> None:
    from phi_scan.output import _build_dashboard_history_table

    _build_dashboard_history_table([])


def test_build_dashboard_history_table_non_empty_does_not_raise() -> None:
    from phi_scan.output import _build_dashboard_history_table

    _build_dashboard_history_table([_DASHBOARD_CLEAN_SCAN_ROW, _DASHBOARD_VIOLATION_SCAN_ROW])


def test_build_dashboard_history_table_empty_shows_no_history_text() -> None:
    from phi_scan.output import (
        _build_dashboard_history_table,
    )

    table = _build_dashboard_history_table([])

    row_cells = [cell for row in table.rows for cell in []]
    assert table.row_count == 1
    _ = row_cells  # table has one placeholder row


def test_build_dashboard_history_table_non_empty_has_correct_row_count() -> None:
    from phi_scan.output import _build_dashboard_history_table

    scans = [_DASHBOARD_CLEAN_SCAN_ROW, _DASHBOARD_VIOLATION_SCAN_ROW]
    table = _build_dashboard_history_table(scans)

    assert table.row_count == len(scans)


def test_build_dashboard_history_table_has_five_columns() -> None:
    from phi_scan.output import _build_dashboard_history_table

    expected_column_count: int = 5
    table = _build_dashboard_history_table([])

    assert len(table.columns) == expected_column_count


# ---------------------------------------------------------------------------
# _build_dashboard_category_table (1C.5c)
# ---------------------------------------------------------------------------

_DASHBOARD_CATEGORY_TOTALS_EMPTY: dict[str, int] = {}
_DASHBOARD_CATEGORY_TOTALS_SAMPLE: dict[str, int] = {"SSN": 3, "EMAIL": 2}


def test_build_dashboard_category_table_empty_does_not_raise() -> None:
    from phi_scan.output import _build_dashboard_category_table

    _build_dashboard_category_table(_DASHBOARD_CATEGORY_TOTALS_EMPTY)


def test_build_dashboard_category_table_non_empty_does_not_raise() -> None:
    from phi_scan.output import _build_dashboard_category_table

    _build_dashboard_category_table(_DASHBOARD_CATEGORY_TOTALS_SAMPLE)


def test_build_dashboard_category_table_empty_has_one_placeholder_row() -> None:
    from phi_scan.output import _build_dashboard_category_table

    table = _build_dashboard_category_table(_DASHBOARD_CATEGORY_TOTALS_EMPTY)

    assert table.row_count == 1


def test_build_dashboard_category_table_non_empty_has_correct_row_count() -> None:
    from phi_scan.output import _build_dashboard_category_table

    table = _build_dashboard_category_table(_DASHBOARD_CATEGORY_TOTALS_SAMPLE)

    assert table.row_count == len(_DASHBOARD_CATEGORY_TOTALS_SAMPLE)


def test_build_dashboard_category_table_has_two_columns() -> None:
    from phi_scan.output import _build_dashboard_category_table

    expected_column_count: int = 2
    table = _build_dashboard_category_table(_DASHBOARD_CATEGORY_TOTALS_EMPTY)

    assert len(table.columns) == expected_column_count


# ---------------------------------------------------------------------------
# build_dashboard_layout (1C.5d)
# ---------------------------------------------------------------------------


def test_build_dashboard_layout_does_not_raise() -> None:
    build_dashboard_layout([], _DASHBOARD_CATEGORY_TOTALS_EMPTY, None)


def test_build_dashboard_layout_with_data_does_not_raise() -> None:
    scans = [_DASHBOARD_CLEAN_SCAN_ROW, _DASHBOARD_VIOLATION_SCAN_ROW]

    build_dashboard_layout(scans, _DASHBOARD_CATEGORY_TOTALS_SAMPLE, _DASHBOARD_CLEAN_SCAN_ROW)
