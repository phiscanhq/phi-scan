# phi-scan:ignore-file
"""Tests for multi-framework compliance annotation (Phase 4D.8).

Verifies that:
  - parse_framework_flag handles single and combined framework tokens correctly
  - annotate_findings produces correct combined controls for multiple frameworks
  - HTML and PDF reports include the Compliance Matrix when annotations are provided
  - All 12 supported frameworks can be specified and annotate without error
  - HIPAA is always active regardless of which other frameworks are enabled
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from phi_scan.compliance import (
    ComplianceFramework,
    annotate_findings,
    parse_framework_flag,
)
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

_SAMPLE_HASH: str = "7" * 64
_SAMPLE_FILE_PATH: Path = Path("src/patient_handler.py")
_SAMPLE_SCAN_TARGET: Path = Path(".")
_SAMPLE_ENTITY_TYPE: str = "us_ssn"
_SAMPLE_CODE_CONTEXT: str = "ssn = '[REDACTED]'"
_SAMPLE_REMEDIATION_HINT: str = "Replace SSN."
_SAMPLE_CONFIDENCE: float = 0.93
_SAMPLE_LINE_NUMBER: int = 10

_ALL_12_FRAMEWORKS: str = "hipaa,hitech,soc2,hitrust,nist,gdpr,42cfr2,gina,cmia,bipa,shield,mrpa"

_HTML_SECTION_COMPLIANCE_MATRIX: str = "Compliance Matrix"
_PDF_SECTION_COMPLIANCE_MATRIX: str = "Compliance Matrix"


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
        scan_duration=0.08,
        is_clean=not findings,
        risk_level=risk_level if findings else RiskLevel.CLEAN,
        severity_counts=severity_counts,
        category_counts=category_counts,
    )


# ---------------------------------------------------------------------------
# parse_framework_flag: single framework
# ---------------------------------------------------------------------------


def test_parse_soc2_returns_soc2_framework() -> None:
    """parse_framework_flag('soc2') must return ComplianceFramework.SOC2."""
    result = parse_framework_flag("soc2")
    assert ComplianceFramework.SOC2 in result


def test_parse_hitrust_returns_hitrust_framework() -> None:
    """parse_framework_flag('hitrust') must return ComplianceFramework.HITRUST."""
    result = parse_framework_flag("hitrust")
    assert ComplianceFramework.HITRUST in result


def test_parse_nist_returns_nist_framework() -> None:
    """parse_framework_flag('nist') must return ComplianceFramework.NIST."""
    result = parse_framework_flag("nist")
    assert ComplianceFramework.NIST in result


def test_parse_gdpr_returns_gdpr_framework() -> None:
    """parse_framework_flag('gdpr') must return ComplianceFramework.GDPR."""
    result = parse_framework_flag("gdpr")
    assert ComplianceFramework.GDPR in result


def test_parse_hitech_returns_hitech_framework() -> None:
    """parse_framework_flag('hitech') must return ComplianceFramework.HITECH."""
    result = parse_framework_flag("hitech")
    assert ComplianceFramework.HITECH in result


def test_parse_42cfr2_returns_cfr_part_2_framework() -> None:
    """parse_framework_flag('42cfr2') must return ComplianceFramework.CFR_PART_2."""
    result = parse_framework_flag("42cfr2")
    assert ComplianceFramework.CFR_PART_2 in result


def test_parse_bipa_returns_bipa_framework() -> None:
    """parse_framework_flag('bipa') must return ComplianceFramework.BIPA."""
    result = parse_framework_flag("bipa")
    assert ComplianceFramework.BIPA in result


# ---------------------------------------------------------------------------
# parse_framework_flag: combined frameworks
# ---------------------------------------------------------------------------


def test_parse_hipaa_plus_hitrust_returns_both() -> None:
    """'hipaa,hitrust' must return both HIPAA and HITRUST."""
    result = parse_framework_flag("hipaa,hitrust")
    assert ComplianceFramework.HIPAA in result
    assert ComplianceFramework.HITRUST in result


def test_parse_soc2_plus_gdpr_returns_both() -> None:
    """'soc2,gdpr' must return both SOC2 and GDPR."""
    result = parse_framework_flag("soc2,gdpr")
    assert ComplianceFramework.SOC2 in result
    assert ComplianceFramework.GDPR in result


def test_parse_all_12_frameworks_returns_all_members() -> None:
    """A comma-separated string of all 12 framework tokens must parse to all 12 members."""
    result = parse_framework_flag(_ALL_12_FRAMEWORKS)
    for member in ComplianceFramework:
        assert member in result, f"ComplianceFramework.{member.name} missing from result"


def test_parse_combined_framework_count_matches_token_count() -> None:
    """The number of frameworks returned must equal the number of unique tokens."""
    flag = "hipaa,soc2,gdpr"
    result = parse_framework_flag(flag)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# annotate_findings: combined frameworks
# ---------------------------------------------------------------------------


def test_annotate_findings_soc2_includes_soc2_and_hipaa_controls() -> None:
    """annotate_findings with soc2 must include both SOC2 and HIPAA controls."""
    finding = _make_finding(PhiCategory.SSN)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.SOC2}))
    frameworks_present = {c.framework for c in result[0]}
    assert ComplianceFramework.SOC2 in frameworks_present
    assert ComplianceFramework.HIPAA in frameworks_present


def test_annotate_findings_hipaa_plus_hitrust_includes_both() -> None:
    """annotate_findings with hipaa+hitrust must include both HIPAA and HITRUST controls."""
    finding = _make_finding(PhiCategory.MRN)
    result = annotate_findings(
        (finding,), frozenset({ComplianceFramework.HIPAA, ComplianceFramework.HITRUST})
    )
    frameworks_present = {c.framework for c in result[0]}
    assert ComplianceFramework.HIPAA in frameworks_present
    assert ComplianceFramework.HITRUST in frameworks_present


def test_annotate_findings_four_frameworks_combined() -> None:
    """annotate_findings with 4 frameworks must include controls from all 4."""
    finding = _make_finding(PhiCategory.SSN)
    enabled = frozenset(
        {
            ComplianceFramework.SOC2,
            ComplianceFramework.HITRUST,
            ComplianceFramework.NIST,
            ComplianceFramework.GDPR,
        }
    )
    result = annotate_findings((finding,), enabled)
    frameworks_present = {c.framework for c in result[0]}
    assert ComplianceFramework.HIPAA in frameworks_present  # always included
    assert ComplianceFramework.SOC2 in frameworks_present
    assert ComplianceFramework.HITRUST in frameworks_present
    assert ComplianceFramework.NIST in frameworks_present
    assert ComplianceFramework.GDPR in frameworks_present


def test_annotate_findings_all_12_frameworks_does_not_raise() -> None:
    """annotate_findings with all 12 frameworks must succeed without error."""
    findings = tuple(_make_finding(cat, line_number=i + 1) for i, cat in enumerate(PhiCategory))
    all_frameworks = frozenset(ComplianceFramework)
    result = annotate_findings(findings, all_frameworks)
    assert len(result) == len(findings)


def test_annotate_findings_combined_controls_are_tuples_of_compliance_control() -> None:
    """Each value in the annotation dict must be a tuple of ComplianceControl."""
    from phi_scan.compliance import ComplianceControl

    finding = _make_finding(PhiCategory.SSN)
    result = annotate_findings(
        (finding,),
        frozenset({ComplianceFramework.SOC2, ComplianceFramework.GDPR}),
    )
    assert isinstance(result[0], tuple)
    for control in result[0]:
        assert isinstance(control, ComplianceControl)


# ---------------------------------------------------------------------------
# HTML report: compliance matrix with multiple frameworks
# ---------------------------------------------------------------------------


def test_html_compliance_matrix_present_with_soc2() -> None:
    """HTML must include Compliance Matrix when soc2 annotations are provided."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    annotations = annotate_findings(findings, frozenset({ComplianceFramework.SOC2}))
    html = generate_html_report(
        result, _SAMPLE_SCAN_TARGET, framework_annotations=annotations
    ).decode("utf-8")
    assert _HTML_SECTION_COMPLIANCE_MATRIX in html


def test_html_compliance_matrix_present_with_hipaa_plus_hitrust() -> None:
    """HTML must include Compliance Matrix when hipaa+hitrust annotations are provided."""
    findings = (_make_finding(PhiCategory.MRN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    annotations = annotate_findings(
        findings,
        frozenset({ComplianceFramework.HIPAA, ComplianceFramework.HITRUST}),
    )
    html = generate_html_report(
        result, _SAMPLE_SCAN_TARGET, framework_annotations=annotations
    ).decode("utf-8")
    assert _HTML_SECTION_COMPLIANCE_MATRIX in html


def test_html_compliance_matrix_present_with_all_12_frameworks() -> None:
    """HTML must include Compliance Matrix when all 12 frameworks are annotated."""
    findings = tuple(
        _make_finding(cat, line_number=i + 1) for i, cat in enumerate(list(PhiCategory)[:5])
    )
    result = _make_scan_result(findings, RiskLevel.CRITICAL)
    annotations = annotate_findings(findings, frozenset(ComplianceFramework))
    html = generate_html_report(
        result, _SAMPLE_SCAN_TARGET, framework_annotations=annotations
    ).decode("utf-8")
    assert _HTML_SECTION_COMPLIANCE_MATRIX in html


# ---------------------------------------------------------------------------
# PDF report: compliance matrix with multiple frameworks
# ---------------------------------------------------------------------------


def test_pdf_generates_with_soc2_annotations() -> None:
    """PDF must generate without error when soc2 framework annotations are provided."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    annotations = annotate_findings(findings, frozenset({ComplianceFramework.SOC2}))
    pdf_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET, framework_annotations=annotations)
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_generates_with_hipaa_plus_hitrust_annotations() -> None:
    """PDF must generate without error when hipaa+hitrust annotations are provided."""
    findings = (_make_finding(PhiCategory.MRN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    annotations = annotate_findings(
        findings,
        frozenset({ComplianceFramework.HIPAA, ComplianceFramework.HITRUST}),
    )
    pdf_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET, framework_annotations=annotations)
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_generates_without_annotations() -> None:
    """PDF must generate without error when no framework annotations are provided."""
    result = _make_scan_result()
    pdf_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert pdf_bytes.startswith(b"%PDF-")


# ---------------------------------------------------------------------------
# HIPAA always active
# ---------------------------------------------------------------------------


def test_hipaa_controls_present_regardless_of_other_frameworks() -> None:
    """HIPAA controls must be present when only non-HIPAA frameworks are enabled."""
    finding = _make_finding(PhiCategory.SSN)
    for framework in ComplianceFramework:
        if framework is ComplianceFramework.HIPAA:
            continue
        result = annotate_findings((finding,), frozenset({framework}))
        hipaa_controls = [c for c in result[0] if c.framework is ComplianceFramework.HIPAA]
        assert hipaa_controls, f"HIPAA controls missing when only {framework.value} is enabled"
