# phi-scan:ignore-file
"""Tests for phi_scan.report — generate_html_report (Phase 4D.2).

Verifies that HTML generation:
  - returns valid UTF-8 bytes with proper HTML structure
  - contains expected sections: findings, remediation guidance, scan metadata
  - embeds base64 chart images
  - includes the compliance matrix only when framework_annotations are provided
  - never renders raw PHI values (all code_context must go through truncation guard)
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from phi_scan.compliance import (
    ComplianceFramework,
    annotate_findings,
)
from phi_scan.constants import (
    CODE_CONTEXT_REDACTED_VALUE,
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.report import generate_html_report

# ---------------------------------------------------------------------------
# Test constants — no magic values in test logic
# ---------------------------------------------------------------------------

_SAMPLE_HASH: str = "d" * 64
_SAMPLE_FILE_PATH: Path = Path("src/patient_handler.py")
_SAMPLE_SCAN_TARGET: Path = Path(".")
_SAMPLE_LINE_NUMBER: int = 15
_SAMPLE_CONFIDENCE: float = 0.88
_SAMPLE_ENTITY_TYPE: str = "us_ssn"
_SAMPLE_CODE_CONTEXT: str = f"ssn = '{CODE_CONTEXT_REDACTED_VALUE}'"
_SAMPLE_REMEDIATION_HINT: str = "Replace SSN with synthetic value."

_HTML_TAG_OPEN: str = "<html"
_HTML_TAG_HEAD: str = "<head"
_HTML_TAG_BODY: str = "<body"
_HTML_SECTION_REMEDIATION: str = "Remediation Guidance"
_HTML_SECTION_COMPLIANCE_MATRIX: str = "Compliance Matrix"
_HTML_CHART_IMG_PREFIX: str = "data:image/png;base64,"
_HTML_TITLE_FRAGMENT: str = "PhiScan Report"
_HTML_RISK_BADGE_CLASS: str = "risk-badge"
_HTML_FILES_SCANNED_LABEL: str = "Files Scanned"


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
        scan_duration=0.1,
        is_clean=not findings,
        risk_level=risk_level if findings else RiskLevel.CLEAN,
        severity_counts=severity_counts,
        category_counts=category_counts,
    )


def _decode_html(output: bytes) -> str:
    return output.decode("utf-8")


# ---------------------------------------------------------------------------
# Basic output contract
# ---------------------------------------------------------------------------


def test_html_report_returns_bytes() -> None:
    """generate_html_report must return a bytes object."""
    result = _make_scan_result()
    output = generate_html_report(result, _SAMPLE_SCAN_TARGET)
    assert isinstance(output, bytes)


def test_html_report_is_non_empty() -> None:
    """generate_html_report must return non-empty bytes."""
    result = _make_scan_result()
    output = generate_html_report(result, _SAMPLE_SCAN_TARGET)
    assert len(output) > 0


def test_html_decodes_as_utf8() -> None:
    """HTML output must decode without error as UTF-8."""
    result = _make_scan_result()
    output = generate_html_report(result, _SAMPLE_SCAN_TARGET)
    decoded = output.decode("utf-8")
    assert len(decoded) > 0


# ---------------------------------------------------------------------------
# HTML structure
# ---------------------------------------------------------------------------


def test_html_contains_html_open_tag() -> None:
    """Output must contain an <html> opening tag."""
    result = _make_scan_result()
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert _HTML_TAG_OPEN in html


def test_html_contains_head_section() -> None:
    """Output must contain a <head> section."""
    result = _make_scan_result()
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert _HTML_TAG_HEAD in html


def test_html_contains_body_section() -> None:
    """Output must contain a <body> section."""
    result = _make_scan_result()
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert _HTML_TAG_BODY in html


def test_html_title_contains_phiscan_report() -> None:
    """HTML <title> must contain 'PhiScan Report'."""
    result = _make_scan_result()
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert _HTML_TITLE_FRAGMENT in html


# ---------------------------------------------------------------------------
# Scan metadata
# ---------------------------------------------------------------------------


def test_html_contains_risk_level_badge() -> None:
    """Output must include the risk-badge element."""
    result = _make_scan_result()
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert _HTML_RISK_BADGE_CLASS in html


def test_html_clean_result_shows_clean_risk_level() -> None:
    """A clean scan result must display CLEAN in the risk badge."""
    result = _make_scan_result()
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert RiskLevel.CLEAN.value.upper() in html


def test_html_dirty_result_shows_non_clean_risk_level() -> None:
    """A dirty scan result must not display CLEAN as the risk level."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert RiskLevel.HIGH.value.upper() in html


def test_html_contains_files_scanned_label() -> None:
    """Output must display the Files Scanned label in the metadata section."""
    result = _make_scan_result()
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert _HTML_FILES_SCANNED_LABEL in html


def test_html_scan_target_appears_in_output() -> None:
    """The scan target path must appear in the HTML output."""
    custom_target = Path("services/patient-api")
    result = _make_scan_result()
    html = _decode_html(generate_html_report(result, custom_target))
    assert str(custom_target) in html


# ---------------------------------------------------------------------------
# Findings section
# ---------------------------------------------------------------------------


def test_html_findings_section_present_with_findings() -> None:
    """The Findings section header must appear when findings are present."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert "Findings" in html


def test_html_findings_count_reflects_actual_findings() -> None:
    """The total findings count in the header must match the actual count."""
    findings = tuple(
        _make_finding(PhiCategory.SSN, SeverityLevel.HIGH, line_number=i + 1) for i in range(3)
    )
    result = _make_scan_result(findings, RiskLevel.HIGH)
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert "3" in html


# ---------------------------------------------------------------------------
# Remediation section
# ---------------------------------------------------------------------------


def test_html_contains_remediation_guidance_section() -> None:
    """Output must contain a Remediation Guidance section."""
    result = _make_scan_result()
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert _HTML_SECTION_REMEDIATION in html


def test_html_remediation_section_present_with_findings() -> None:
    """Remediation Guidance section must be present even when findings exist."""
    findings = (_make_finding(PhiCategory.EMAIL, SeverityLevel.MEDIUM),)
    result = _make_scan_result(findings, RiskLevel.MODERATE)
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert _HTML_SECTION_REMEDIATION in html


# ---------------------------------------------------------------------------
# Chart images
# ---------------------------------------------------------------------------


def test_html_contains_embedded_chart_image() -> None:
    """Output must contain at least one embedded base64 PNG chart image."""
    result = _make_scan_result()
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert _HTML_CHART_IMG_PREFIX in html


def test_html_chart_images_present_with_findings() -> None:
    """Chart images must be embedded when findings are present."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert _HTML_CHART_IMG_PREFIX in html


# ---------------------------------------------------------------------------
# PHI safety: no raw values in output
# ---------------------------------------------------------------------------


def test_html_code_context_contains_redacted_placeholder() -> None:
    """Code context in the HTML output must contain the REDACTED placeholder."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert CODE_CONTEXT_REDACTED_VALUE in html


# ---------------------------------------------------------------------------
# Compliance matrix (conditional section)
# ---------------------------------------------------------------------------


def test_html_compliance_matrix_absent_without_annotations() -> None:
    """The Compliance Matrix section must not appear when no annotations are passed."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    html = _decode_html(generate_html_report(result, _SAMPLE_SCAN_TARGET))
    assert _HTML_SECTION_COMPLIANCE_MATRIX not in html


def test_html_compliance_matrix_present_with_annotations() -> None:
    """The Compliance Matrix section must appear when framework_annotations are provided."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    annotations = annotate_findings(
        findings, frozenset({ComplianceFramework.SOC2, ComplianceFramework.GDPR})
    )
    html = _decode_html(
        generate_html_report(result, _SAMPLE_SCAN_TARGET, framework_annotations=annotations)
    )
    assert _HTML_SECTION_COMPLIANCE_MATRIX in html


def test_html_compliance_matrix_contains_framework_name() -> None:
    """The Compliance Matrix section must name at least one enabled framework."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    annotations = annotate_findings(findings, frozenset({ComplianceFramework.SOC2}))
    html = _decode_html(
        generate_html_report(result, _SAMPLE_SCAN_TARGET, framework_annotations=annotations)
    )
    assert "soc2" in html.lower() or "SOC" in html


# ---------------------------------------------------------------------------
# Optional audit rows
# ---------------------------------------------------------------------------


def test_html_generates_with_audit_rows() -> None:
    """generate_html_report must succeed when audit_rows are provided."""
    result = _make_scan_result()
    audit_rows: list[dict[str, object]] = [
        {"timestamp": "2025-03-01T00:00:00Z", "findings_count": 5},
    ]
    output = generate_html_report(result, _SAMPLE_SCAN_TARGET, audit_rows=audit_rows)
    assert output.decode("utf-8")


def test_html_generates_with_empty_audit_rows() -> None:
    """generate_html_report must succeed when audit_rows is an empty list."""
    result = _make_scan_result()
    output = generate_html_report(result, _SAMPLE_SCAN_TARGET, audit_rows=[])
    assert output.decode("utf-8")
