# phi-scan:ignore-file
"""Tests for format_json — JSON output value types, structure, and multi-finding arrays.

test_output_contracts.py pins the schema *keys*. This file verifies the value
*types* and structural invariants that downstream consumers depend on:

  - All numeric fields are int/float (not strings).
  - is_clean is a Python bool.
  - severity_counts and category_counts contain every enum member.
  - risk_level is a valid RiskLevel value.
  - findings array length matches the number of findings in the result.
  - value_hash is a 64-character lowercase hex string.
  - confidence is a float in [0.0, 1.0].
  - Clean result has an empty findings array.
  - Multiple findings produce multiple objects in the array.
"""

from __future__ import annotations

import hashlib
import json
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
from phi_scan.output import format_json

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

_TEST_FILE_PATH: Path = Path("src/patient.py")
_TEST_ALT_FILE_PATH: Path = Path("src/records.py")
_TEST_LINE_NUMBER: int = 10
_TEST_ENTITY_TYPE: str = "us_ssn"
_TEST_CONFIDENCE: float = 0.95
_TEST_SCAN_DURATION: float = 1.23
_TEST_FILES_SCANNED: int = 5
_TEST_FILES_WITH_FINDINGS: int = 1
_TEST_VALUE_HASH: str = hashlib.sha256(b"json-test-seed").hexdigest()
_TEST_ALT_VALUE_HASH: str = hashlib.sha256(b"json-test-seed-alt").hexdigest()

_SHA256_HEX_DIGEST_LENGTH: int = 64
_CONFIDENCE_MIN: float = 0.0
_CONFIDENCE_MAX: float = 1.0

_JSON_FINDINGS_KEY: str = "findings"
_JSON_FILES_SCANNED_KEY: str = "files_scanned"
_JSON_FILES_WITH_FINDINGS_KEY: str = "files_with_findings"
_JSON_SCAN_DURATION_KEY: str = "scan_duration"
_JSON_IS_CLEAN_KEY: str = "is_clean"
_JSON_RISK_LEVEL_KEY: str = "risk_level"
_JSON_SEVERITY_COUNTS_KEY: str = "severity_counts"
_JSON_CATEGORY_COUNTS_KEY: str = "category_counts"

_JSON_FINDING_FILE_PATH_KEY: str = "file_path"
_JSON_FINDING_LINE_NUMBER_KEY: str = "line_number"
_JSON_FINDING_CONFIDENCE_KEY: str = "confidence"
_JSON_FINDING_VALUE_HASH_KEY: str = "value_hash"
_JSON_FINDING_SEVERITY_KEY: str = "severity"
_JSON_FINDING_ENTITY_TYPE_KEY: str = "entity_type"


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------


def _make_finding(
    file_path: Path = _TEST_FILE_PATH,
    value_hash: str = _TEST_VALUE_HASH,
    severity: SeverityLevel = SeverityLevel.HIGH,
    confidence: float = _TEST_CONFIDENCE,
) -> ScanFinding:
    return ScanFinding(
        file_path=file_path,
        line_number=_TEST_LINE_NUMBER,
        entity_type=_TEST_ENTITY_TYPE,
        hipaa_category=PhiCategory.SSN,
        confidence=confidence,
        detection_layer=DetectionLayer.REGEX,
        value_hash=value_hash,
        severity=severity,
        code_context="",
        remediation_hint="",
    )


def _make_result(
    findings: tuple[ScanFinding, ...] = (),
    files_scanned: int = _TEST_FILES_SCANNED,
    scan_duration: float = _TEST_SCAN_DURATION,
) -> ScanResult:
    is_clean = len(findings) == 0
    files_with = 0 if is_clean else 1
    severity_counts = {level: 0 for level in SeverityLevel}
    category_counts = {cat: 0 for cat in PhiCategory}
    for finding in findings:
        severity_counts[finding.severity] += 1
        category_counts[finding.hipaa_category] += 1
    return ScanResult(
        findings=findings,
        files_scanned=files_scanned,
        files_with_findings=files_with,
        scan_duration=scan_duration,
        is_clean=is_clean,
        risk_level=RiskLevel.CLEAN if is_clean else RiskLevel.CRITICAL,
        severity_counts=MappingProxyType(severity_counts),
        category_counts=MappingProxyType(category_counts),
    )


def _parse(scan_result: ScanResult) -> dict[str, object]:
    return json.loads(format_json(scan_result))  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Top-level numeric field types
# ---------------------------------------------------------------------------


class TestJsonTopLevelFieldTypes:
    def test_files_scanned_is_an_integer(self) -> None:
        parsed = _parse(_make_result())

        assert isinstance(parsed[_JSON_FILES_SCANNED_KEY], int)

    def test_files_with_findings_is_an_integer(self) -> None:
        parsed = _parse(_make_result())

        assert isinstance(parsed[_JSON_FILES_WITH_FINDINGS_KEY], int)

    def test_scan_duration_is_a_float(self) -> None:
        parsed = _parse(_make_result(scan_duration=_TEST_SCAN_DURATION))

        assert isinstance(parsed[_JSON_SCAN_DURATION_KEY], float)

    def test_scan_duration_is_non_negative(self) -> None:
        parsed = _parse(_make_result(scan_duration=0.0))

        assert parsed[_JSON_SCAN_DURATION_KEY] >= 0.0  # type: ignore[operator]

    def test_is_clean_is_a_boolean(self) -> None:
        parsed = _parse(_make_result())

        assert isinstance(parsed[_JSON_IS_CLEAN_KEY], bool)

    def test_is_clean_true_for_empty_findings(self) -> None:
        parsed = _parse(_make_result(findings=()))

        assert parsed[_JSON_IS_CLEAN_KEY] is True

    def test_is_clean_false_when_findings_present(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))

        assert parsed[_JSON_IS_CLEAN_KEY] is False

    def test_risk_level_is_a_valid_risk_level_value(self) -> None:
        valid_values = {level.value for level in RiskLevel}
        parsed = _parse(_make_result())

        assert parsed[_JSON_RISK_LEVEL_KEY] in valid_values


# ---------------------------------------------------------------------------
# severity_counts structure
# ---------------------------------------------------------------------------


class TestJsonSeverityCounts:
    def test_severity_counts_has_every_severity_level(self) -> None:
        expected_keys = {level.value for level in SeverityLevel}
        parsed = _parse(_make_result())

        assert set(parsed[_JSON_SEVERITY_COUNTS_KEY].keys()) == expected_keys  # type: ignore[union-attr]

    def test_severity_counts_values_are_integers(self) -> None:
        parsed = _parse(_make_result())
        severity_counts: dict[str, object] = parsed[_JSON_SEVERITY_COUNTS_KEY]  # type: ignore[assignment]

        for value in severity_counts.values():
            assert isinstance(value, int)

    def test_severity_counts_sum_equals_finding_count(self) -> None:
        findings = (_make_finding(), _make_finding(value_hash=_TEST_ALT_VALUE_HASH))
        parsed = _parse(_make_result(findings=findings))
        severity_counts: dict[str, int] = parsed[_JSON_SEVERITY_COUNTS_KEY]  # type: ignore[assignment]

        assert sum(severity_counts.values()) == len(findings)

    def test_severity_counts_all_zero_for_clean_result(self) -> None:
        parsed = _parse(_make_result())
        severity_counts: dict[str, int] = parsed[_JSON_SEVERITY_COUNTS_KEY]  # type: ignore[assignment]

        assert all(count == 0 for count in severity_counts.values())


# ---------------------------------------------------------------------------
# category_counts structure
# ---------------------------------------------------------------------------


class TestJsonCategoryCounts:
    def test_category_counts_has_every_phi_category(self) -> None:
        expected_keys = {cat.value for cat in PhiCategory}
        parsed = _parse(_make_result())

        assert set(parsed[_JSON_CATEGORY_COUNTS_KEY].keys()) == expected_keys  # type: ignore[union-attr]

    def test_category_counts_values_are_integers(self) -> None:
        parsed = _parse(_make_result())
        category_counts: dict[str, object] = parsed[_JSON_CATEGORY_COUNTS_KEY]  # type: ignore[assignment]

        for value in category_counts.values():
            assert isinstance(value, int)

    def test_category_counts_all_zero_for_clean_result(self) -> None:
        parsed = _parse(_make_result())
        category_counts: dict[str, int] = parsed[_JSON_CATEGORY_COUNTS_KEY]  # type: ignore[assignment]

        assert all(count == 0 for count in category_counts.values())


# ---------------------------------------------------------------------------
# findings array
# ---------------------------------------------------------------------------


class TestJsonFindingsArray:
    def test_clean_result_has_empty_findings_array(self) -> None:
        parsed = _parse(_make_result(findings=()))

        assert parsed[_JSON_FINDINGS_KEY] == []

    def test_one_finding_produces_one_finding_object(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))

        assert len(parsed[_JSON_FINDINGS_KEY]) == 1  # type: ignore[arg-type]

    def test_two_findings_produce_two_finding_objects(self) -> None:
        findings = (
            _make_finding(file_path=_TEST_FILE_PATH, value_hash=_TEST_VALUE_HASH),
            _make_finding(file_path=_TEST_ALT_FILE_PATH, value_hash=_TEST_ALT_VALUE_HASH),
        )
        parsed = _parse(_make_result(findings=findings))

        assert len(parsed[_JSON_FINDINGS_KEY]) == len(findings)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Per-finding field value types
# ---------------------------------------------------------------------------


class TestJsonFindingFieldTypes:
    @pytest.fixture()
    def finding_dict(self) -> dict[str, object]:
        finding = _make_finding()
        parsed = _parse(_make_result(findings=(finding,)))
        return parsed[_JSON_FINDINGS_KEY][0]  # type: ignore[index,return-value]

    def test_finding_file_path_is_a_string(self, finding_dict: dict[str, object]) -> None:
        assert isinstance(finding_dict[_JSON_FINDING_FILE_PATH_KEY], str)

    def test_finding_line_number_is_an_integer(self, finding_dict: dict[str, object]) -> None:
        assert isinstance(finding_dict[_JSON_FINDING_LINE_NUMBER_KEY], int)

    def test_finding_confidence_is_a_float(self, finding_dict: dict[str, object]) -> None:
        assert isinstance(finding_dict[_JSON_FINDING_CONFIDENCE_KEY], float)

    def test_finding_confidence_is_within_valid_range(
        self, finding_dict: dict[str, object]
    ) -> None:
        confidence = finding_dict[_JSON_FINDING_CONFIDENCE_KEY]
        assert _CONFIDENCE_MIN <= confidence <= _CONFIDENCE_MAX  # type: ignore[operator]

    def test_finding_value_hash_is_a_string(self, finding_dict: dict[str, object]) -> None:
        assert isinstance(finding_dict[_JSON_FINDING_VALUE_HASH_KEY], str)

    def test_finding_value_hash_is_64_characters(self, finding_dict: dict[str, object]) -> None:
        assert len(finding_dict[_JSON_FINDING_VALUE_HASH_KEY]) == _SHA256_HEX_DIGEST_LENGTH  # type: ignore[arg-type]

    def test_finding_value_hash_is_lowercase_hex(self, finding_dict: dict[str, object]) -> None:
        value_hash = finding_dict[_JSON_FINDING_VALUE_HASH_KEY]
        assert isinstance(value_hash, str)
        assert all(c in "0123456789abcdef" for c in value_hash)

    def test_finding_severity_is_a_valid_severity_level_value(
        self, finding_dict: dict[str, object]
    ) -> None:
        valid_values = {level.value for level in SeverityLevel}
        assert finding_dict[_JSON_FINDING_SEVERITY_KEY] in valid_values

    def test_finding_entity_type_matches_input(self, finding_dict: dict[str, object]) -> None:
        assert finding_dict[_JSON_FINDING_ENTITY_TYPE_KEY] == _TEST_ENTITY_TYPE
