# phi-scan:ignore-file
"""Tests for format_sarif — per-result structure, level mapping, and tool.driver.rules.

test_output_contracts.py pins the top-level shape (version, $schema, runs[0].tool,
runs[0].results). This file verifies the internal structure that SARIF consumers
depend on:

  - runs[0].tool.driver.name and .version
  - runs[0].tool.driver.rules — one rule per unique entity_type
  - Each result has ruleId, level, message.text, and locations
  - locations[0].physicalLocation.artifactLocation.uri matches file_path
  - locations[0].physicalLocation.region.startLine matches line_number
  - SARIF level mapping: HIGH→"error", MEDIUM→"warning", LOW→"note", INFO→"none"
  - Clean scan produces an empty results array
  - Multiple findings produce multiple result objects
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from phi_scan import __version__
from phi_scan.constants import (
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.output import format_sarif

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

_TEST_FILE_PATH: Path = Path("src/patient.py")
_TEST_ALT_FILE_PATH: Path = Path("src/records.py")
_TEST_LINE_NUMBER: int = 15
_TEST_ALT_LINE_NUMBER: int = 30
_TEST_ENTITY_TYPE: str = "us_ssn"
_TEST_ALT_ENTITY_TYPE: str = "email_address"
_TEST_FILES_SCANNED: int = 1
_TEST_SCAN_DURATION: float = 0.5
_TEST_VALUE_HASH: str = hashlib.sha256(b"sarif-test-seed").hexdigest()
_TEST_ALT_VALUE_HASH: str = hashlib.sha256(b"sarif-test-seed-alt").hexdigest()

_SARIF_TOOL_DRIVER_NAME: str = "PhiScan"
_SARIF_URI_BASE_ID: str = "%SRCROOT%"

# SARIF level values per SARIF 2.1.0 spec
_SARIF_LEVEL_ERROR: str = "error"
_SARIF_LEVEL_WARNING: str = "warning"
_SARIF_LEVEL_NOTE: str = "note"
_SARIF_LEVEL_NONE: str = "none"

# Rule fields
_SARIF_RULE_ID_KEY: str = "id"
_SARIF_RULE_NAME_KEY: str = "name"
_SARIF_RULE_SHORT_DESCRIPTION_KEY: str = "shortDescription"
_SARIF_RULE_HELP_KEY: str = "help"

# Result fields
_SARIF_RESULT_RULE_ID_KEY: str = "ruleId"
_SARIF_RESULT_LEVEL_KEY: str = "level"
_SARIF_RESULT_MESSAGE_KEY: str = "message"
_SARIF_RESULT_LOCATIONS_KEY: str = "locations"

# Location path
_SARIF_PHYSICAL_LOCATION_KEY: str = "physicalLocation"
_SARIF_ARTIFACT_LOCATION_KEY: str = "artifactLocation"
_SARIF_URI_KEY: str = "uri"
_SARIF_URI_BASE_ID_KEY: str = "uriBaseId"
_SARIF_REGION_KEY: str = "region"
_SARIF_START_LINE_KEY: str = "startLine"


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------


def _make_finding(
    file_path: Path = _TEST_FILE_PATH,
    line_number: int = _TEST_LINE_NUMBER,
    entity_type: str = _TEST_ENTITY_TYPE,
    value_hash: str = _TEST_VALUE_HASH,
    severity: SeverityLevel = SeverityLevel.HIGH,
) -> ScanFinding:
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=entity_type,
        hipaa_category=PhiCategory.SSN,
        confidence=0.95,
        detection_layer=DetectionLayer.REGEX,
        value_hash=value_hash,
        severity=severity,
        code_context="",
        remediation_hint="Replace with synthetic value.",
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


def _parse(scan_result: ScanResult) -> dict[str, object]:
    return json.loads(format_sarif(scan_result))  # type: ignore[return-value]


def _get_run(parsed: dict[str, object]) -> dict[str, object]:
    runs: list[dict[str, object]] = parsed["runs"]  # type: ignore[assignment]
    return runs[0]


# ---------------------------------------------------------------------------
# tool.driver structure
# ---------------------------------------------------------------------------


class TestSarifToolDriver:
    def test_tool_driver_name_is_phi_scan(self) -> None:
        parsed = _parse(_make_result())
        driver: dict[str, object] = _get_run(parsed)["tool"]["driver"]  # type: ignore[index]

        assert driver["name"] == _SARIF_TOOL_DRIVER_NAME

    def test_tool_driver_version_matches_package_version(self) -> None:
        parsed = _parse(_make_result())
        driver: dict[str, object] = _get_run(parsed)["tool"]["driver"]  # type: ignore[index]

        assert driver["version"] == __version__

    def test_tool_driver_has_rules_field(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))
        driver: dict[str, object] = _get_run(parsed)["tool"]["driver"]  # type: ignore[index]

        assert "rules" in driver

    def test_tool_driver_rules_is_a_list(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))
        driver: dict[str, object] = _get_run(parsed)["tool"]["driver"]  # type: ignore[index]

        assert isinstance(driver["rules"], list)

    def test_tool_driver_rules_has_one_entry_per_unique_entity_type(self) -> None:
        findings = (
            _make_finding(entity_type=_TEST_ENTITY_TYPE, value_hash=_TEST_VALUE_HASH),
            _make_finding(entity_type=_TEST_ALT_ENTITY_TYPE, value_hash=_TEST_ALT_VALUE_HASH),
        )
        parsed = _parse(_make_result(findings=findings))
        rules: list[dict[str, object]] = _get_run(parsed)["tool"]["driver"]["rules"]  # type: ignore[index,assignment]

        unique_entity_types = {f.entity_type for f in findings}
        assert len(rules) == len(unique_entity_types)

    def test_tool_driver_rule_has_id_field(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))
        rule: dict[str, object] = _get_run(parsed)["tool"]["driver"]["rules"][0]  # type: ignore[index,assignment]

        assert _SARIF_RULE_ID_KEY in rule

    def test_tool_driver_rule_has_name_field(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))
        rule: dict[str, object] = _get_run(parsed)["tool"]["driver"]["rules"][0]  # type: ignore[index,assignment]

        assert _SARIF_RULE_NAME_KEY in rule

    def test_tool_driver_rule_has_short_description_field(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))
        rule: dict[str, object] = _get_run(parsed)["tool"]["driver"]["rules"][0]  # type: ignore[index,assignment]

        assert _SARIF_RULE_SHORT_DESCRIPTION_KEY in rule

    def test_tool_driver_rule_has_help_field(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))
        rule: dict[str, object] = _get_run(parsed)["tool"]["driver"]["rules"][0]  # type: ignore[index,assignment]

        assert _SARIF_RULE_HELP_KEY in rule

    def test_tool_driver_rule_id_matches_entity_type(self) -> None:
        finding = _make_finding(entity_type=_TEST_ENTITY_TYPE)
        parsed = _parse(_make_result(findings=(finding,)))
        rule: dict[str, object] = _get_run(parsed)["tool"]["driver"]["rules"][0]  # type: ignore[index,assignment]

        assert rule[_SARIF_RULE_ID_KEY] == _TEST_ENTITY_TYPE

    def test_tool_driver_rules_empty_for_clean_result(self) -> None:
        parsed = _parse(_make_result())
        rules: list[object] = _get_run(parsed)["tool"]["driver"]["rules"]  # type: ignore[index,assignment]

        assert rules == []


# ---------------------------------------------------------------------------
# results array
# ---------------------------------------------------------------------------


class TestSarifResults:
    def test_clean_result_has_empty_results_array(self) -> None:
        parsed = _parse(_make_result())
        results: list[object] = _get_run(parsed)["results"]  # type: ignore[index,assignment]

        assert results == []

    def test_one_finding_produces_one_result_object(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))
        results: list[object] = _get_run(parsed)["results"]  # type: ignore[index,assignment]

        assert len(results) == 1

    def test_two_findings_produce_two_result_objects(self) -> None:
        findings = (
            _make_finding(value_hash=_TEST_VALUE_HASH),
            _make_finding(file_path=_TEST_ALT_FILE_PATH, value_hash=_TEST_ALT_VALUE_HASH),
        )
        parsed = _parse(_make_result(findings=findings))
        results: list[object] = _get_run(parsed)["results"]  # type: ignore[index,assignment]

        assert len(results) == len(findings)

    def test_result_has_rule_id_field(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))
        result: dict[str, object] = _get_run(parsed)["results"][0]  # type: ignore[index,assignment]

        assert _SARIF_RESULT_RULE_ID_KEY in result

    def test_result_rule_id_matches_entity_type(self) -> None:
        finding = _make_finding(entity_type=_TEST_ENTITY_TYPE)
        parsed = _parse(_make_result(findings=(finding,)))
        result: dict[str, object] = _get_run(parsed)["results"][0]  # type: ignore[index,assignment]

        assert result[_SARIF_RESULT_RULE_ID_KEY] == _TEST_ENTITY_TYPE

    def test_result_has_level_field(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))
        result: dict[str, object] = _get_run(parsed)["results"][0]  # type: ignore[index,assignment]

        assert _SARIF_RESULT_LEVEL_KEY in result

    def test_result_has_message_text_field(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))
        result: dict[str, object] = _get_run(parsed)["results"][0]  # type: ignore[index,assignment]

        assert "text" in result[_SARIF_RESULT_MESSAGE_KEY]  # type: ignore[operator]

    def test_result_has_locations_field(self) -> None:
        parsed = _parse(_make_result(findings=(_make_finding(),)))
        result: dict[str, object] = _get_run(parsed)["results"][0]  # type: ignore[index,assignment]

        assert _SARIF_RESULT_LOCATIONS_KEY in result


# ---------------------------------------------------------------------------
# SARIF level mapping
# ---------------------------------------------------------------------------


class TestSarifLevelMapping:
    @pytest.mark.parametrize(
        ("severity", "expected_level"),
        [
            (SeverityLevel.HIGH, _SARIF_LEVEL_ERROR),
            (SeverityLevel.MEDIUM, _SARIF_LEVEL_WARNING),
            (SeverityLevel.LOW, _SARIF_LEVEL_NOTE),
            (SeverityLevel.INFO, _SARIF_LEVEL_NONE),
        ],
    )
    def test_severity_maps_to_correct_sarif_level(
        self, severity: SeverityLevel, expected_level: str
    ) -> None:
        finding = _make_finding(severity=severity)
        result_obj = ScanResult(
            findings=(finding,),
            files_scanned=_TEST_FILES_SCANNED,
            files_with_findings=1,
            scan_duration=_TEST_SCAN_DURATION,
            is_clean=False,
            risk_level=RiskLevel.CRITICAL,
            severity_counts=MappingProxyType({level: 0 for level in SeverityLevel}),
            category_counts=MappingProxyType({cat: 0 for cat in PhiCategory}),
        )

        parsed = _parse(result_obj)
        sarif_result: dict[str, object] = _get_run(parsed)["results"][0]  # type: ignore[index,assignment]

        assert sarif_result[_SARIF_RESULT_LEVEL_KEY] == expected_level


# ---------------------------------------------------------------------------
# Location structure
# ---------------------------------------------------------------------------


class TestSarifLocation:
    @pytest.fixture()
    def physical_location(self) -> dict[str, object]:
        finding = _make_finding(file_path=_TEST_FILE_PATH, line_number=_TEST_LINE_NUMBER)
        parsed = _parse(_make_result(findings=(finding,)))
        result: dict[str, object] = _get_run(parsed)["results"][0]  # type: ignore[index,assignment]
        locations: list[dict[str, object]] = result[_SARIF_RESULT_LOCATIONS_KEY]  # type: ignore[assignment]
        return locations[0][_SARIF_PHYSICAL_LOCATION_KEY]  # type: ignore[return-value,index]

    def test_physical_location_has_artifact_location(
        self, physical_location: dict[str, object]
    ) -> None:
        assert _SARIF_ARTIFACT_LOCATION_KEY in physical_location

    def test_artifact_location_uri_matches_file_path(
        self, physical_location: dict[str, object]
    ) -> None:
        artifact_location: dict[str, object] = physical_location[_SARIF_ARTIFACT_LOCATION_KEY]  # type: ignore[assignment]

        assert artifact_location[_SARIF_URI_KEY] == _TEST_FILE_PATH.as_posix()

    def test_artifact_location_uri_base_id_is_srcroot(
        self, physical_location: dict[str, object]
    ) -> None:
        artifact_location: dict[str, object] = physical_location[_SARIF_ARTIFACT_LOCATION_KEY]  # type: ignore[assignment]

        assert artifact_location[_SARIF_URI_BASE_ID_KEY] == _SARIF_URI_BASE_ID

    def test_region_start_line_matches_line_number(
        self, physical_location: dict[str, object]
    ) -> None:
        region: dict[str, object] = physical_location[_SARIF_REGION_KEY]  # type: ignore[assignment]

        assert region[_SARIF_START_LINE_KEY] == _TEST_LINE_NUMBER

    def test_region_start_line_is_an_integer(self, physical_location: dict[str, object]) -> None:
        region: dict[str, object] = physical_location[_SARIF_REGION_KEY]  # type: ignore[assignment]

        assert isinstance(region[_SARIF_START_LINE_KEY], int)
