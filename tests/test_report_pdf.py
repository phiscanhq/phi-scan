# phi-scan:ignore-file
"""Tests for phi_scan.report — generate_pdf_report (Phase 4D.1).

Verifies that PDF generation:
  - returns non-empty bytes beginning with the PDF magic header
  - succeeds for clean (no-findings) and dirty (with-findings) scan results
  - handles multiple severity levels and all PHI categories
  - accepts optional audit_rows and framework_annotations without error
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from phi_scan.compliance import (
    ComplianceFramework,
    annotate_findings,
)
from phi_scan.constants import (
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.report import generate_pdf_report

# ---------------------------------------------------------------------------
# Test constants — no magic values in test logic
# ---------------------------------------------------------------------------

_PDF_MAGIC_HEADER: bytes = b"%PDF-"
_SAMPLE_HASH: str = "c" * 64
_SAMPLE_FILE_PATH: Path = Path("src/patient_handler.py")
_SAMPLE_SCAN_TARGET: Path = Path(".")
_SAMPLE_LINE_NUMBER: int = 10
_SAMPLE_CONFIDENCE: float = 0.92
_SAMPLE_ENTITY_TYPE: str = "us_ssn"
_SAMPLE_CODE_CONTEXT: str = "ssn = '[REDACTED]'"
_SAMPLE_REMEDIATION_HINT: str = "Replace SSN with synthetic value."

_AUDIT_ROWS_SAMPLE: list[dict[str, object]] = [
    {"timestamp": "2025-01-01T00:00:00Z", "findings_count": 3},
    {"timestamp": "2025-01-02T00:00:00Z", "findings_count": 1},
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    category: PhiCategory = PhiCategory.SSN,
    severity: SeverityLevel = SeverityLevel.HIGH,
    line_number: int = _SAMPLE_LINE_NUMBER,
) -> ScanFinding:
    return ScanFinding(
        file_path=_SAMPLE_FILE_PATH,
        line_number=line_number,
        entity_type=_SAMPLE_ENTITY_TYPE,
        hipaa_category=category,
        confidence=_SAMPLE_CONFIDENCE,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_SAMPLE_HASH,
        severity=severity,
        code_context=_SAMPLE_CODE_CONTEXT,
        remediation_hint=_SAMPLE_REMEDIATION_HINT,
    )


def _make_scan_result(
    findings: tuple[ScanFinding, ...] = (),
    risk_level: RiskLevel = RiskLevel.CLEAN,
) -> ScanResult:
    severity_counts: MappingProxyType[SeverityLevel, int] = MappingProxyType(
        {level: sum(1 for f in findings if f.severity == level) for level in SeverityLevel}
    )
    category_counts: MappingProxyType[PhiCategory, int] = MappingProxyType(
        {cat: sum(1 for f in findings if f.hipaa_category == cat) for cat in PhiCategory}
    )
    return ScanResult(
        findings=findings,
        files_scanned=max(1, len(findings)),
        files_with_findings=1 if findings else 0,
        scan_duration=0.25,
        is_clean=not findings,
        risk_level=risk_level if findings else RiskLevel.CLEAN,
        severity_counts=severity_counts,
        category_counts=category_counts,
    )


# ---------------------------------------------------------------------------
# Basic output contract
# ---------------------------------------------------------------------------


def test_pdf_report_returns_bytes() -> None:
    """generate_pdf_report must return a bytes object."""
    result = _make_scan_result()
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert isinstance(output, bytes)


def test_pdf_report_is_non_empty() -> None:
    """generate_pdf_report must return non-empty bytes."""
    result = _make_scan_result()
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert len(output) > 0


def test_pdf_magic_header_present_for_clean_result() -> None:
    """PDF bytes must start with the %PDF- magic header for a clean result."""
    result = _make_scan_result()
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert output.startswith(_PDF_MAGIC_HEADER)


def test_pdf_magic_header_present_for_dirty_result() -> None:
    """PDF bytes must start with the %PDF- magic header when findings are present."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert output.startswith(_PDF_MAGIC_HEADER)


# ---------------------------------------------------------------------------
# Clean scan
# ---------------------------------------------------------------------------


def test_pdf_generates_for_clean_result_without_error() -> None:
    """generate_pdf_report must succeed when there are no findings."""
    result = _make_scan_result()
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert len(output) > 0


# ---------------------------------------------------------------------------
# Findings content
# ---------------------------------------------------------------------------


def test_pdf_generates_with_single_finding() -> None:
    """PDF must be generated without error for a scan result with one finding."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert output.startswith(_PDF_MAGIC_HEADER)


def test_pdf_generates_with_multiple_findings() -> None:
    """PDF must be generated without error for a scan result with multiple findings."""
    findings = (
        _make_finding(PhiCategory.SSN, SeverityLevel.HIGH, line_number=1),
        _make_finding(PhiCategory.NAME, SeverityLevel.MEDIUM, line_number=2),
        _make_finding(PhiCategory.EMAIL, SeverityLevel.LOW, line_number=3),
        _make_finding(PhiCategory.DATE, SeverityLevel.INFO, line_number=4),
    )
    result = _make_scan_result(findings, RiskLevel.CRITICAL)
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert output.startswith(_PDF_MAGIC_HEADER)


def test_pdf_generates_with_all_severity_levels_represented() -> None:
    """PDF must generate when findings span all four severity levels."""
    findings = tuple(
        _make_finding(PhiCategory.SSN, severity, line_number=i + 1)
        for i, severity in enumerate(SeverityLevel)
    )
    result = _make_scan_result(findings, RiskLevel.CRITICAL)
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert output.startswith(_PDF_MAGIC_HEADER)


def test_pdf_generates_with_all_phi_categories() -> None:
    """PDF must generate when one finding exists per PHI category."""
    findings = tuple(
        _make_finding(category, SeverityLevel.HIGH, line_number=i + 1)
        for i, category in enumerate(PhiCategory)
    )
    result = _make_scan_result(findings, RiskLevel.CRITICAL)
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert output.startswith(_PDF_MAGIC_HEADER)


# ---------------------------------------------------------------------------
# Optional parameters
# ---------------------------------------------------------------------------


def test_pdf_generates_with_audit_rows() -> None:
    """PDF must be generated without error when audit_rows are provided."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET, audit_rows=_AUDIT_ROWS_SAMPLE)
    assert output.startswith(_PDF_MAGIC_HEADER)


def test_pdf_generates_with_framework_annotations() -> None:
    """PDF must be generated without error when framework_annotations are provided."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    annotations = annotate_findings(
        findings, frozenset({ComplianceFramework.SOC2, ComplianceFramework.GDPR})
    )
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET, framework_annotations=annotations)
    assert output.startswith(_PDF_MAGIC_HEADER)


def test_pdf_generates_with_audit_rows_and_framework_annotations() -> None:
    """PDF must generate with both audit_rows and framework_annotations provided."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    annotations = annotate_findings(findings, frozenset({ComplianceFramework.HIPAA}))
    output = generate_pdf_report(
        result,
        _SAMPLE_SCAN_TARGET,
        audit_rows=_AUDIT_ROWS_SAMPLE,
        framework_annotations=annotations,
    )
    assert output.startswith(_PDF_MAGIC_HEADER)


def test_pdf_generates_with_empty_audit_rows() -> None:
    """PDF must generate without error when audit_rows is an empty list."""
    result = _make_scan_result()
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET, audit_rows=[])
    assert output.startswith(_PDF_MAGIC_HEADER)


# ---------------------------------------------------------------------------
# Non-default scan target
# ---------------------------------------------------------------------------


def test_pdf_accepts_subdirectory_scan_target() -> None:
    """PDF must generate when scan_target is a non-default subdirectory path."""
    result = _make_scan_result()
    output = generate_pdf_report(result, Path("src/services"))
    assert output.startswith(_PDF_MAGIC_HEADER)


def test_pdf_size_increases_with_more_findings() -> None:
    """A PDF with many findings should be larger than a clean PDF."""
    clean_result = _make_scan_result()
    findings = tuple(
        _make_finding(PhiCategory.SSN, SeverityLevel.HIGH, line_number=i + 1) for i in range(20)
    )
    dirty_result = _make_scan_result(findings, RiskLevel.CRITICAL)
    clean_pdf = generate_pdf_report(clean_result, _SAMPLE_SCAN_TARGET)
    dirty_pdf = generate_pdf_report(dirty_result, _SAMPLE_SCAN_TARGET)
    assert len(dirty_pdf) > len(clean_pdf)
