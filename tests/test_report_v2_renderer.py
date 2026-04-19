"""Tests for the v2 terminal report renderer structure and output."""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from rich.console import Console

from phi_scan.constants import PhiCategory, RiskLevel, SeverityLevel
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.report.v2.console import display_rich_scan_results_v2

_HASH_PLACEHOLDER: str = "a" * 64

_EXPECTED_SECTIONS_VIOLATION: list[str] = [
    "phi-scan",
    "VIOLATION",
    "FINDINGS",
    "TOP ACTIONS",
    "CATEGORY BREAKDOWN",
    "FINDINGS BY LINE",
    "REMEDIATION PLAYBOOK",
    "SCAN COMPLETE",
]

_EXPECTED_SECTIONS_CLEAN: list[str] = [
    "phi-scan",
    "CLEAN",
    "SCAN COMPLETE",
]


def _make_finding(
    file_path: str = "test.py",
    line_number: int = 1,
    entity_type: str = "SSN",
    hipaa_category: PhiCategory = PhiCategory.SSN,
    confidence: float = 0.9,
    severity: SeverityLevel = SeverityLevel.HIGH,
    remediation_hint: str = "Remove SSN immediately.",
    code_context: str = "SSN: [REDACTED]",
) -> ScanFinding:
    return ScanFinding(
        file_path=Path(file_path),
        line_number=line_number,
        entity_type=entity_type,
        hipaa_category=hipaa_category,
        confidence=confidence,
        detection_layer="regex",
        value_hash=_HASH_PLACEHOLDER,
        severity=severity,
        code_context=code_context,
        remediation_hint=remediation_hint,
    )


def _make_violation_result() -> ScanResult:
    findings = [
        _make_finding(line_number=1, severity=SeverityLevel.HIGH),
        _make_finding(
            line_number=1,
            entity_type="DATE",
            hipaa_category=PhiCategory.DATE,
            severity=SeverityLevel.HIGH,
            remediation_hint="Replace dates with year only.",
            code_context="DOB: [REDACTED]",
        ),
        _make_finding(
            line_number=2,
            entity_type="EMAIL",
            hipaa_category=PhiCategory.EMAIL,
            severity=SeverityLevel.MEDIUM,
            remediation_hint="Fake email addresses.",
            code_context="email: [REDACTED]",
        ),
        _make_finding(
            line_number=3,
            entity_type="ACCOUNT_NUMBER",
            hipaa_category=PhiCategory.ACCOUNT,
            severity=SeverityLevel.LOW,
            remediation_hint="Replace account numbers.",
            code_context="acct: [REDACTED]",
        ),
    ]
    return ScanResult(
        findings=tuple(findings),
        files_scanned=1,
        files_with_findings=1,
        scan_duration=0.05,
        is_clean=False,
        risk_level=RiskLevel.CRITICAL,
        severity_counts=MappingProxyType(
            {
                SeverityLevel.HIGH: 2,
                SeverityLevel.MEDIUM: 1,
                SeverityLevel.LOW: 1,
            }
        ),
        category_counts=MappingProxyType(
            {
                PhiCategory.SSN: 1,
                PhiCategory.DATE: 1,
                PhiCategory.EMAIL: 1,
                PhiCategory.ACCOUNT: 1,
            }
        ),
    )


def _make_clean_result() -> ScanResult:
    return ScanResult(
        findings=(),
        files_scanned=5,
        files_with_findings=0,
        scan_duration=0.02,
        is_clean=True,
        risk_level=RiskLevel.CLEAN,
        severity_counts=MappingProxyType({}),
        category_counts=MappingProxyType({}),
    )


def _capture_v2_output(
    scan_result: ScanResult,
    is_verbose: bool = False,
    severity_threshold: SeverityLevel = SeverityLevel.LOW,
) -> str:
    console = Console(record=True, width=120, force_terminal=True)
    from phi_scan.report.v2 import console as v2_console_module

    original_get_console = v2_console_module.get_console
    v2_console_module.get_console = lambda: console  # type: ignore[assignment]
    try:
        display_rich_scan_results_v2(
            scan_result,
            scan_target="test.py",
            severity_threshold=severity_threshold,
            is_verbose=is_verbose,
        )
    finally:
        v2_console_module.get_console = original_get_console  # type: ignore[assignment]
    return console.export_text()


class TestV2ViolationOutput:
    def test_all_sections_present(self) -> None:
        output = _capture_v2_output(_make_violation_result())
        for section in _EXPECTED_SECTIONS_VIOLATION:
            assert section in output, f"Missing section: {section}"

    def test_section_ordering(self) -> None:
        output = _capture_v2_output(_make_violation_result())
        positions = [output.index(section) for section in _EXPECTED_SECTIONS_VIOLATION]
        assert positions == sorted(positions), "Sections are out of order"

    def test_remediation_strings_unique(self) -> None:
        output = _capture_v2_output(_make_violation_result())
        playbook_start = output.index("REMEDIATION PLAYBOOK")
        scan_complete_start = output.index("SCAN COMPLETE")
        playbook_section = output[playbook_start:scan_complete_start]
        hint = "Remove SSN immediately."
        assert playbook_section.count(hint) == 1

    def test_no_duplicate_findings_table(self) -> None:
        output = _capture_v2_output(_make_violation_result())
        assert "FINDINGS TABLE" not in output.upper() or output.upper().count("FINDINGS TABLE") == 0

    def test_output_under_200_lines(self) -> None:
        output = _capture_v2_output(_make_violation_result())
        line_count = len(output.strip().split("\n"))
        assert line_count <= 200, f"Output is {line_count} lines, expected <= 200"


class TestV2CleanOutput:
    def test_clean_sections_present(self) -> None:
        output = _capture_v2_output(_make_clean_result())
        for section in _EXPECTED_SECTIONS_CLEAN:
            assert section in output, f"Missing section: {section}"

    def test_no_violation_sections_in_clean(self) -> None:
        output = _capture_v2_output(_make_clean_result())
        assert "FINDINGS BY LINE" not in output
        assert "REMEDIATION PLAYBOOK" not in output
        assert "TOP ACTIONS" not in output


class TestV2CollapseExpand:
    def test_low_severity_collapsed_by_default(self) -> None:
        output = _capture_v2_output(
            _make_violation_result(),
            severity_threshold=SeverityLevel.MEDIUM,
        )
        assert "collapsed" in output.lower() or "more lines" in output.lower()

    def test_verbose_expands_all(self) -> None:
        output = _capture_v2_output(
            _make_violation_result(),
            is_verbose=True,
        )
        assert "line 3" in output

    def test_low_threshold_shows_low_inline(self) -> None:
        output = _capture_v2_output(
            _make_violation_result(),
            severity_threshold=SeverityLevel.LOW,
        )
        assert "line 3" in output
