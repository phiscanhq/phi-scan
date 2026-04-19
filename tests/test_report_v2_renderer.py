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


def _make_multi_finding_line_result() -> ScanResult:
    """Build a result with two findings on the same line, each with different raw spans."""
    findings = (
        _make_finding(
            line_number=10,
            entity_type="SSN",
            hipaa_category=PhiCategory.SSN,
            remediation_hint="Remove SSN immediately.",
            code_context="pt {'ssn': [REDACTED], 'dob': '1942-07-03'}",
        ),
        _make_finding(
            line_number=10,
            entity_type="DATE",
            hipaa_category=PhiCategory.DATE,
            remediation_hint="Replace dates with year only.",
            code_context="pt {'ssn': '123-45-6789', 'dob': [REDACTED]}",
        ),
    )
    return ScanResult(
        findings=findings,
        files_scanned=1,
        files_with_findings=1,
        scan_duration=0.01,
        is_clean=False,
        risk_level=RiskLevel.CRITICAL,
        severity_counts=MappingProxyType({SeverityLevel.HIGH: 2}),
        category_counts=MappingProxyType({PhiCategory.SSN: 1, PhiCategory.DATE: 1}),
    )


class TestV2MultiFindingLineSafety:
    """When a line has multiple findings, the preview must redact ALL raw spans."""

    def test_no_raw_ssn_leaked(self) -> None:
        output = _capture_v2_output(_make_multi_finding_line_result())
        assert "123-45-6789" not in output

    def test_no_raw_dob_leaked(self) -> None:
        output = _capture_v2_output(_make_multi_finding_line_result())
        assert "1942-07-03" not in output

    def test_collapsed_marker_present(self) -> None:
        output = _capture_v2_output(_make_multi_finding_line_result())
        assert "[REDACTED]" in output


def _make_quasi_combo_result() -> ScanResult:
    """Quasi-identifier combination findings with differing hints per instance."""
    findings = tuple(
        _make_finding(
            line_number=line_number,
            entity_type="QUASI_IDENTIFIER_COMBINATION",
            hipaa_category=PhiCategory.QUASI_IDENTIFIER_COMBINATION,
            severity=SeverityLevel.HIGH,
            remediation_hint=(
                f"This finding indicates quasi-identifier combination #{line_number}. "
                "Break up the combination or generalize at least one field."
            ),
            code_context=f"record_{line_number}: [REDACTED]",
        )
        for line_number in (1, 3, 6)
    )
    return ScanResult(
        findings=findings,
        files_scanned=1,
        files_with_findings=1,
        scan_duration=0.01,
        is_clean=False,
        risk_level=RiskLevel.CRITICAL,
        severity_counts=MappingProxyType({SeverityLevel.HIGH: 3}),
        category_counts=MappingProxyType({PhiCategory.QUASI_IDENTIFIER_COMBINATION: 3}),
    )


class TestV2PlaybookCategoryDedupe:
    """Playbook must collapse per-category findings even when hint strings differ."""

    def test_quasi_combo_single_card(self) -> None:
        output = _capture_v2_output(_make_quasi_combo_result())
        playbook_start = output.index("REMEDIATION PLAYBOOK")
        scan_complete_start = output.index("SCAN COMPLETE")
        playbook_section = output[playbook_start:scan_complete_start]
        assert playbook_section.count("Break up quasi-identifier combinations") == 1

    def test_playbook_shows_aggregate_count(self) -> None:
        output = _capture_v2_output(_make_quasi_combo_result())
        assert "3 findings" in output


def _make_long_hint_result() -> ScanResult:
    """Result with a >100-char remediation hint to verify no truncation in playbook."""
    long_hint = (
        "Remove or generalize at least one of the quasi-identifiers: use only "
        "the first 3 digits of the ZIP code, replace the full date of birth "
        "with birth year only, or remove the combination entirely from test "
        "fixtures. Do not rely on any single field being 'safe'."
    )
    findings = (
        _make_finding(
            line_number=42,
            entity_type="QUASI_IDENTIFIER_COMBINATION",
            hipaa_category=PhiCategory.QUASI_IDENTIFIER_COMBINATION,
            severity=SeverityLevel.HIGH,
            remediation_hint=long_hint,
            code_context="row_42: [REDACTED]",
        ),
    )
    return (
        ScanResult(
            findings=findings,
            files_scanned=1,
            files_with_findings=1,
            scan_duration=0.01,
            is_clean=False,
            risk_level=RiskLevel.CRITICAL,
            severity_counts=MappingProxyType({SeverityLevel.HIGH: 1}),
            category_counts=MappingProxyType({PhiCategory.QUASI_IDENTIFIER_COMBINATION: 1}),
        ),
        long_hint,
    )


class TestV2PlaybookHintUncapped:
    def test_full_hint_rendered(self) -> None:
        result, _ = _make_long_hint_result()
        output = _capture_v2_output(result)
        tail_phrase = "any single field being"
        assert tail_phrase in output


class TestV2MultiHintFixLineCollapse:
    """Line cards with multiple distinct hints must collapse to a playbook pointer."""

    def test_multi_hint_line_points_to_playbook(self) -> None:
        output = _capture_v2_output(_make_violation_result())
        assert "see REMEDIATION PLAYBOOK" in output

    def test_single_hint_line_still_shows_hint_inline(self) -> None:
        single_finding = _make_finding(
            line_number=1,
            remediation_hint="Replace patient SSN with a synthetic identifier.",
        )
        result = ScanResult(
            findings=(single_finding,),
            files_scanned=1,
            files_with_findings=1,
            scan_duration=0.01,
            is_clean=False,
            risk_level=RiskLevel.CRITICAL,
            severity_counts=MappingProxyType({SeverityLevel.HIGH: 1}),
            category_counts=MappingProxyType({PhiCategory.SSN: 1}),
        )
        output = _capture_v2_output(result)
        assert "Replace patient SSN with a synthetic identifier." in output
        assert "see REMEDIATION PLAYBOOK" not in output


class TestV2FullReportPanelRemoved:
    """FULL REPORT panel between playbook and footer has been folded into footer."""

    def test_no_full_report_panel(self) -> None:
        output = _capture_v2_output(_make_violation_result())
        assert "FULL REPORT" not in output

    def test_footer_shows_report_hint_when_no_path(self) -> None:
        output = _capture_v2_output(_make_violation_result())
        assert "--output html" in output


class TestV2FooterLayout:
    """Scan-complete footer must not wrap at standard terminal widths."""

    def test_wide_terminal_uses_side_by_side(self) -> None:
        console = Console(record=True, width=140, force_terminal=True)
        from phi_scan.report.v2 import console as v2_console_module

        original_get_console = v2_console_module.get_console
        v2_console_module.get_console = lambda: console  # type: ignore[assignment]
        try:
            display_rich_scan_results_v2(
                _make_violation_result(),
                scan_target="test.py",
                severity_threshold=SeverityLevel.LOW,
                is_verbose=False,
            )
        finally:
            v2_console_module.get_console = original_get_console  # type: ignore[assignment]
        output = console.export_text()
        next_steps_line = [ln for ln in output.splitlines() if "Next steps" in ln]
        assert next_steps_line, "Next steps label must be on some line"
        assert any("VIOLATION" in ln and "Next steps" in ln for ln in next_steps_line), (
            "At 140 cols, Next steps and VIOLATION must share a row"
        )

    def test_narrow_terminal_stacks_sections(self) -> None:
        console = Console(record=True, width=80, force_terminal=True)
        from phi_scan.report.v2 import console as v2_console_module

        original_get_console = v2_console_module.get_console
        v2_console_module.get_console = lambda: console  # type: ignore[assignment]
        try:
            display_rich_scan_results_v2(
                _make_violation_result(),
                scan_target="test.py",
                severity_threshold=SeverityLevel.LOW,
                is_verbose=False,
            )
        finally:
            v2_console_module.get_console = original_get_console  # type: ignore[assignment]
        output = console.export_text()
        violation_line = next(
            (line for line in output.splitlines() if "VIOLATION" in line and "│" in line),
            None,
        )
        assert violation_line is not None
        assert "Next steps" not in violation_line


class TestV2CategoryBarDifferentiation:
    """Category bars must show proportional fill, not a solid wall of blocks."""

    def test_bar_empty_portion_uses_track_glyph(self) -> None:
        findings = (
            _make_finding(
                line_number=1,
                entity_type="SSN",
                hipaa_category=PhiCategory.SSN,
                severity=SeverityLevel.HIGH,
            ),
            _make_finding(
                line_number=2,
                entity_type="EMAIL",
                hipaa_category=PhiCategory.EMAIL,
                severity=SeverityLevel.LOW,
            ),
            _make_finding(
                line_number=3,
                entity_type="EMAIL",
                hipaa_category=PhiCategory.EMAIL,
                severity=SeverityLevel.LOW,
            ),
        )
        result = ScanResult(
            findings=findings,
            files_scanned=1,
            files_with_findings=1,
            scan_duration=0.01,
            is_clean=False,
            risk_level=RiskLevel.CRITICAL,
            severity_counts=MappingProxyType({SeverityLevel.HIGH: 1, SeverityLevel.LOW: 2}),
            category_counts=MappingProxyType({PhiCategory.SSN: 1, PhiCategory.EMAIL: 2}),
        )
        output = _capture_v2_output(result)
        assert "░" in output, "Empty bar portion must use the track glyph"
