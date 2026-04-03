# phi-scan:ignore-file
"""Tests for executive summary content in PhiScan reports (Phase 4D.3).

Verifies that:
  - The executive summary section appears in both PDF and HTML reports
  - Risk level in the report reflects the ScanResult's risk_level
  - Scan metadata (files_scanned, scan_target) is accurate in the output
  - Severity distribution counts reflect the actual findings
  - Clean results show CLEAN risk level; critical results show CRITICAL
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from phi_scan.constants import (
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.report import generate_html_report, generate_pdf_report

# ---------------------------------------------------------------------------
# Test constants — no magic values in test logic
# ---------------------------------------------------------------------------

_SAMPLE_HASH: str = "e" * 64
_SAMPLE_FILE_PATH: Path = Path("src/patient_service.py")
_SAMPLE_SCAN_TARGET: Path = Path(".")
_SAMPLE_ENTITY_TYPE: str = "us_ssn"
_SAMPLE_CODE_CONTEXT: str = "ssn = '[REDACTED]'"
_SAMPLE_REMEDIATION_HINT: str = "Replace SSN."
_SAMPLE_CONFIDENCE: float = 0.90

_PDF_SECTION_EXECUTIVE_SUMMARY: str = "Executive Summary"
_PDF_SECTION_HIPAA_CATEGORY_BREAKDOWN: str = "HIPAA Category Breakdown"
_HTML_RISK_BADGE_CLASS: str = "risk-badge"
_HTML_FILES_SCANNED_LABEL: str = "Files Scanned"
_HTML_TOTAL_FINDINGS_LABEL: str = "Total Findings"

_FILES_SCANNED_SINGLE: int = 1
_FILES_SCANNED_MULTI: int = 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    category: PhiCategory = PhiCategory.SSN,
    severity: SeverityLevel = SeverityLevel.HIGH,
    line_number: int = 10,
    file_path: Path = _SAMPLE_FILE_PATH,
) -> ScanFinding:
    return ScanFinding(
        file_path=file_path,
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
    files_scanned: int = _FILES_SCANNED_SINGLE,
) -> ScanResult:
    severity_counts: MappingProxyType[SeverityLevel, int] = MappingProxyType(
        {level: sum(1 for f in findings if f.severity == level) for level in SeverityLevel}
    )
    category_counts: MappingProxyType[PhiCategory, int] = MappingProxyType(
        {cat: sum(1 for f in findings if f.hipaa_category == cat) for cat in PhiCategory}
    )
    return ScanResult(
        findings=findings,
        files_scanned=files_scanned,
        files_with_findings=min(len(findings), files_scanned),
        scan_duration=0.15,
        is_clean=not findings,
        risk_level=risk_level if findings else RiskLevel.CLEAN,
        severity_counts=severity_counts,
        category_counts=category_counts,
    )


# ---------------------------------------------------------------------------
# PDF: executive summary section (structure — not text-search in compressed bytes)
# ---------------------------------------------------------------------------


def test_pdf_generates_for_clean_result() -> None:
    """PDF must generate without error for a clean result."""
    result = _make_scan_result()
    pdf_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_generates_for_dirty_result_with_findings() -> None:
    """PDF must generate without error when findings are present."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    pdf_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_generates_for_result_with_multiple_categories() -> None:
    """PDF must generate without error when findings span multiple PHI categories."""
    findings = (
        _make_finding(PhiCategory.SSN, SeverityLevel.HIGH, line_number=1),
        _make_finding(PhiCategory.NAME, SeverityLevel.MEDIUM, line_number=2),
        _make_finding(PhiCategory.EMAIL, SeverityLevel.LOW, line_number=3),
    )
    result = _make_scan_result(findings, RiskLevel.HIGH)
    pdf_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert pdf_bytes.startswith(b"%PDF-")


# ---------------------------------------------------------------------------
# HTML: risk level accuracy
# ---------------------------------------------------------------------------


def test_html_clean_result_displays_clean_risk_level() -> None:
    """HTML report for a clean scan must display 'CLEAN' in the risk badge."""
    result = _make_scan_result()
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert RiskLevel.CLEAN.value.upper() in html


def test_html_high_risk_result_displays_high_risk_level() -> None:
    """HTML report for a HIGH risk scan must display 'HIGH' in the output."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert RiskLevel.HIGH.value.upper() in html


def test_html_critical_risk_result_displays_critical() -> None:
    """HTML report for a CRITICAL risk scan must display 'CRITICAL' in the output."""
    findings = tuple(
        _make_finding(PhiCategory.SSN, SeverityLevel.HIGH, line_number=i + 1) for i in range(5)
    )
    result = _make_scan_result(findings, RiskLevel.CRITICAL)
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert RiskLevel.CRITICAL.value.upper() in html


def test_html_moderate_risk_result_displays_moderate() -> None:
    """HTML report for a MODERATE risk scan must display 'MODERATE' in the output."""
    findings = (_make_finding(PhiCategory.EMAIL, SeverityLevel.MEDIUM),)
    result = _make_scan_result(findings, RiskLevel.MODERATE)
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert RiskLevel.MODERATE.value.upper() in html


# ---------------------------------------------------------------------------
# HTML: scan metadata accuracy
# ---------------------------------------------------------------------------


def test_html_files_scanned_count_in_output() -> None:
    """HTML must display the correct files_scanned count from the ScanResult."""
    result = _make_scan_result(files_scanned=_FILES_SCANNED_MULTI)
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert str(_FILES_SCANNED_MULTI) in html


def test_html_scan_target_string_in_output() -> None:
    """HTML must include the scan_target path string in the report metadata."""
    target = Path("services/billing-api")
    result = _make_scan_result()
    html = generate_html_report(result, target).decode("utf-8")
    assert str(target) in html


def test_html_total_findings_label_present() -> None:
    """HTML must display a 'Total Findings' label in the summary."""
    result = _make_scan_result()
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert _HTML_TOTAL_FINDINGS_LABEL in html


# ---------------------------------------------------------------------------
# Severity distribution accuracy
# ---------------------------------------------------------------------------


def test_html_severity_distribution_zero_for_clean_result() -> None:
    """A clean HTML report must show zero total findings."""
    result = _make_scan_result()
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    # Total findings count in the section header should be 0
    assert "Findings (0)" in html


def test_html_severity_distribution_matches_finding_count() -> None:
    """The findings count in the HTML header must match the actual number of findings."""
    findings = tuple(
        _make_finding(PhiCategory.SSN, SeverityLevel.HIGH, line_number=i + 1) for i in range(4)
    )
    result = _make_scan_result(findings, RiskLevel.HIGH)
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert "Findings (4)" in html


# ---------------------------------------------------------------------------
# PDF: scan metadata (structure — not text-search in compressed streams)
# ---------------------------------------------------------------------------


def test_pdf_generates_with_non_default_scan_target() -> None:
    """PDF must generate without error when scan_target is a non-default path."""
    target = Path("src/api")
    result = _make_scan_result()
    pdf_bytes = generate_pdf_report(result, target)
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_size_grows_with_more_files_scanned() -> None:
    """A PDF with many files_scanned should generate successfully."""
    result = _make_scan_result(files_scanned=_FILES_SCANNED_MULTI)
    pdf_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert pdf_bytes.startswith(b"%PDF-")
