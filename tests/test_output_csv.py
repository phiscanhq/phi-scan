# phi-scan:ignore-file
"""Tests for format_csv — csv module parseable, special character escaping, data rows.

test_output_contracts.py pins the header column names and row count invariant.
This file verifies:

  - The output is parseable by the Python csv module without error.
  - Clean result produces exactly one row (the header).
  - N findings produce N+1 rows (header + one data row per finding).
  - Data row field order matches the documented header order.
  - Commas inside a field value are properly quoted by csv.writer so the field
    is not split into extra columns on re-parse.
  - Double-quotes inside a field value are properly escaped.
  - Each field in the data row is non-empty for a fully-populated finding.
  - Line number is serialised as a string parseable back to int.
  - Confidence is serialised as a decimal string parseable back to float.
"""

from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path
from types import MappingProxyType

import pytest

from phi_scan.constants import (
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.output import format_csv

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

_TEST_FILE_PATH: Path = Path("src/patient.py")
_TEST_ALT_FILE_PATH: Path = Path("src/records.py")
_TEST_LINE_NUMBER: int = 5
_TEST_ENTITY_TYPE: str = "us_ssn"
_TEST_FILES_SCANNED: int = 3
_TEST_SCAN_DURATION: float = 0.4
_TEST_VALUE_HASH: str = hashlib.sha256(b"csv-test-seed").hexdigest()
_TEST_ALT_VALUE_HASH: str = hashlib.sha256(b"csv-test-seed-alt").hexdigest()

# Documented CSV header columns in order — must match output exactly.
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

_CSV_HEADER_ROW_COUNT: int = 1

# A value that contains a comma — must be quoted by csv.writer
_REMEDIATION_HINT_WITH_COMMA: str = "Replace SSN, use synthetic data instead."

# A value that contains a double-quote — must be escaped by csv.writer
_REMEDIATION_HINT_WITH_QUOTE: str = 'Replace with "REDACTED" placeholder.'

# Column indices (0-indexed) matching _CSV_HEADERS_IN_ORDER
_COL_FILE_PATH: int = 0
_COL_LINE_NUMBER: int = 1
_COL_ENTITY_TYPE: int = 2
_COL_CONFIDENCE: int = 4
_COL_SEVERITY: int = 5


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------


def _make_finding(
    file_path: Path = _TEST_FILE_PATH,
    value_hash: str = _TEST_VALUE_HASH,
    severity: SeverityLevel = SeverityLevel.HIGH,
    remediation_hint: str = "Replace with synthetic value.",
) -> ScanFinding:
    return ScanFinding(
        file_path=file_path,
        line_number=_TEST_LINE_NUMBER,
        entity_type=_TEST_ENTITY_TYPE,
        hipaa_category=PhiCategory.SSN,
        confidence=0.92,
        detection_layer=DetectionLayer.REGEX,
        value_hash=value_hash,
        severity=severity,
        code_context="",
        remediation_hint=remediation_hint,
    )


def _make_result(findings: tuple[ScanFinding, ...] = ()) -> ScanResult:
    is_clean = len(findings) == 0
    return ScanResult(
        findings=findings,
        files_scanned=_TEST_FILES_SCANNED,
        files_with_findings=0 if is_clean else 1,
        scan_duration=_TEST_SCAN_DURATION,
        is_clean=is_clean,
        risk_level=RiskLevel.CLEAN if is_clean else RiskLevel.CRITICAL,
        severity_counts=MappingProxyType({level: 0 for level in SeverityLevel}),
        category_counts=MappingProxyType({cat: 0 for cat in PhiCategory}),
    )


def _parse_csv(scan_result: ScanResult) -> list[list[str]]:
    """Return all rows (including header) parsed by csv.reader."""
    csv_output = format_csv(scan_result)
    return list(csv.reader(io.StringIO(csv_output)))


# ---------------------------------------------------------------------------
# Parseability
# ---------------------------------------------------------------------------


class TestCsvParseability:
    def test_csv_output_is_parseable_by_csv_reader_on_clean_result(self) -> None:
        csv_output = format_csv(_make_result())

        # Must not raise — proves the output is valid CSV
        rows = list(csv.reader(io.StringIO(csv_output)))

        assert rows is not None

    def test_csv_output_is_parseable_by_csv_reader_with_findings(self) -> None:
        csv_output = format_csv(_make_result(findings=(_make_finding(),)))

        rows = list(csv.reader(io.StringIO(csv_output)))

        assert rows is not None


# ---------------------------------------------------------------------------
# Row counts
# ---------------------------------------------------------------------------


class TestCsvRowCounts:
    def test_clean_result_has_exactly_one_row(self) -> None:
        rows = _parse_csv(_make_result())

        assert len(rows) == _CSV_HEADER_ROW_COUNT

    def test_one_finding_produces_two_rows(self) -> None:
        rows = _parse_csv(_make_result(findings=(_make_finding(),)))

        assert len(rows) == _CSV_HEADER_ROW_COUNT + 1

    def test_two_findings_produce_three_rows(self) -> None:
        findings = (
            _make_finding(file_path=_TEST_FILE_PATH, value_hash=_TEST_VALUE_HASH),
            _make_finding(file_path=_TEST_ALT_FILE_PATH, value_hash=_TEST_ALT_VALUE_HASH),
        )
        rows = _parse_csv(_make_result(findings=findings))

        assert len(rows) == _CSV_HEADER_ROW_COUNT + len(findings)

    def test_header_row_is_always_first(self) -> None:
        rows = _parse_csv(_make_result(findings=(_make_finding(),)))

        assert rows[0] == _CSV_HEADERS_IN_ORDER


# ---------------------------------------------------------------------------
# Data row field values
# ---------------------------------------------------------------------------


class TestCsvDataRowFields:
    @pytest.fixture()
    def data_row(self) -> list[str]:
        rows = _parse_csv(_make_result(findings=(_make_finding(),)))
        return rows[1]

    def test_data_row_has_correct_number_of_columns(self, data_row: list[str]) -> None:
        assert len(data_row) == len(_CSV_HEADERS_IN_ORDER)

    def test_data_row_file_path_matches_finding(self, data_row: list[str]) -> None:
        assert data_row[_COL_FILE_PATH] == _TEST_FILE_PATH.as_posix()

    def test_data_row_line_number_is_parseable_as_int(self, data_row: list[str]) -> None:
        line_number = int(data_row[_COL_LINE_NUMBER])

        assert line_number == _TEST_LINE_NUMBER

    def test_data_row_entity_type_matches_finding(self, data_row: list[str]) -> None:
        assert data_row[_COL_ENTITY_TYPE] == _TEST_ENTITY_TYPE

    def test_data_row_confidence_is_parseable_as_float(self, data_row: list[str]) -> None:
        confidence = float(data_row[_COL_CONFIDENCE])

        assert 0.0 <= confidence <= 1.0

    def test_data_row_severity_is_a_valid_severity_value(self, data_row: list[str]) -> None:
        valid_values = {level.value for level in SeverityLevel}

        assert data_row[_COL_SEVERITY] in valid_values

    def test_all_data_row_fields_are_non_empty(self, data_row: list[str]) -> None:
        # Every field on a populated finding must produce a non-empty string value.
        for field_value in data_row:
            assert field_value != ""


# ---------------------------------------------------------------------------
# Special character handling
# ---------------------------------------------------------------------------


class TestCsvSpecialCharacters:
    def test_comma_in_remediation_hint_does_not_produce_extra_columns(self) -> None:
        finding = _make_finding(remediation_hint=_REMEDIATION_HINT_WITH_COMMA)
        rows = _parse_csv(_make_result(findings=(finding,)))
        data_row = rows[1]

        # csv.reader should reconstruct the full field including the comma.
        assert len(data_row) == len(_CSV_HEADERS_IN_ORDER)

    def test_comma_in_remediation_hint_round_trips_correctly(self) -> None:
        finding = _make_finding(remediation_hint=_REMEDIATION_HINT_WITH_COMMA)
        rows = _parse_csv(_make_result(findings=(finding,)))
        data_row = rows[1]
        remediation_hint_col_index = _CSV_HEADERS_IN_ORDER.index("remediation_hint")

        assert data_row[remediation_hint_col_index] == _REMEDIATION_HINT_WITH_COMMA

    def test_double_quote_in_field_does_not_break_csv_structure(self) -> None:
        finding = _make_finding(remediation_hint=_REMEDIATION_HINT_WITH_QUOTE)
        rows = _parse_csv(_make_result(findings=(finding,)))
        data_row = rows[1]

        # Still exactly the right number of columns even with a quoted field.
        assert len(data_row) == len(_CSV_HEADERS_IN_ORDER)

    def test_double_quote_in_field_round_trips_correctly(self) -> None:
        finding = _make_finding(remediation_hint=_REMEDIATION_HINT_WITH_QUOTE)
        rows = _parse_csv(_make_result(findings=(finding,)))
        data_row = rows[1]
        remediation_hint_col_index = _CSV_HEADERS_IN_ORDER.index("remediation_hint")

        assert data_row[remediation_hint_col_index] == _REMEDIATION_HINT_WITH_QUOTE
