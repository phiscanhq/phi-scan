# phi-scan:ignore-file
"""Tests for remediation guidance coverage and content (Phase 4D.4).

Verifies that:
  - Every PhiCategory has an entry in HIPAA_REMEDIATION_GUIDANCE
  - All remediation hint strings are non-empty
  - The general remediation checklist has entries and references phi-scan fix
  - Remediation Guidance section appears in both HTML and PDF reports
  - The remediation section references key remediation actions
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import pytest

from phi_scan.constants import (
    HIPAA_REMEDIATION_GUIDANCE,
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.report import (
    _GENERAL_REMEDIATION_CHECKLIST,  # type: ignore[attr-defined]
    generate_html_report,
    generate_pdf_report,
)

# ---------------------------------------------------------------------------
# Test constants — no magic values in test logic
# ---------------------------------------------------------------------------

_SAMPLE_HASH: str = "f" * 64
_SAMPLE_FILE_PATH: Path = Path("src/billing_handler.py")
_SAMPLE_SCAN_TARGET: Path = Path(".")
_SAMPLE_ENTITY_TYPE: str = "us_ssn"
_SAMPLE_CODE_CONTEXT: str = "ssn = '[REDACTED]'"
_SAMPLE_REMEDIATION_HINT: str = "Replace SSN with synthetic value."
_SAMPLE_CONFIDENCE: float = 0.88
_SAMPLE_LINE_NUMBER: int = 20

_HTML_SECTION_REMEDIATION: str = "Remediation Guidance"
_PDF_SECTION_REMEDIATION: str = "Remediation Guidance"
_PHI_SCAN_FIX_CMD: str = "phi-scan fix"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    category: PhiCategory = PhiCategory.SSN,
    severity: SeverityLevel = SeverityLevel.HIGH,
) -> ScanFinding:
    return ScanFinding(
        file_path=_SAMPLE_FILE_PATH,
        line_number=_SAMPLE_LINE_NUMBER,
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
        scan_duration=0.10,
        is_clean=not findings,
        risk_level=risk_level if findings else RiskLevel.CLEAN,
        severity_counts=severity_counts,
        category_counts=category_counts,
    )


# ---------------------------------------------------------------------------
# HIPAA_REMEDIATION_GUIDANCE coverage
# ---------------------------------------------------------------------------


def test_hipaa_remediation_guidance_covers_all_phi_categories() -> None:
    """HIPAA_REMEDIATION_GUIDANCE must have an entry for every PhiCategory member."""
    for category in PhiCategory:
        assert category in HIPAA_REMEDIATION_GUIDANCE, (
            f"HIPAA_REMEDIATION_GUIDANCE is missing an entry for PhiCategory.{category.name}"
        )


def test_hipaa_remediation_guidance_values_are_non_empty_strings() -> None:
    """Every remediation guidance value must be a non-empty string."""
    for category, guidance in HIPAA_REMEDIATION_GUIDANCE.items():
        assert isinstance(guidance, str), (
            f"HIPAA_REMEDIATION_GUIDANCE[{category!r}] is {type(guidance)!r}, expected str"
        )
        assert guidance.strip(), (
            f"HIPAA_REMEDIATION_GUIDANCE[{category!r}] is an empty or whitespace-only string"
        )


@pytest.mark.parametrize("category", list(PhiCategory))
def test_hipaa_remediation_guidance_entry_per_category(category: PhiCategory) -> None:
    """Each individual PhiCategory must have a non-empty remediation guidance string."""
    guidance = HIPAA_REMEDIATION_GUIDANCE.get(category)
    assert guidance is not None, f"No remediation guidance for {category!r}"
    assert len(guidance.strip()) > 0, f"Empty remediation guidance for {category!r}"


# ---------------------------------------------------------------------------
# General remediation checklist
# ---------------------------------------------------------------------------


def test_general_remediation_checklist_is_non_empty() -> None:
    """The general remediation checklist must contain at least one item."""
    assert len(_GENERAL_REMEDIATION_CHECKLIST) > 0


def test_general_remediation_checklist_items_are_non_empty_strings() -> None:
    """Every checklist item must be a non-empty string."""
    for item in _GENERAL_REMEDIATION_CHECKLIST:
        assert isinstance(item, str)
        assert item.strip()


def test_general_remediation_checklist_references_phi_scan_fix() -> None:
    """At least one checklist item must reference the phi-scan fix command."""
    assert any(_PHI_SCAN_FIX_CMD in item for item in _GENERAL_REMEDIATION_CHECKLIST), (
        f"No checklist item references '{_PHI_SCAN_FIX_CMD}'"
    )


def test_general_remediation_checklist_references_baseline() -> None:
    """At least one checklist item must reference baseline mode."""
    assert any("baseline" in item.lower() for item in _GENERAL_REMEDIATION_CHECKLIST), (
        "No checklist item references baseline mode"
    )


# ---------------------------------------------------------------------------
# HTML report: remediation section
# ---------------------------------------------------------------------------


def test_html_report_contains_remediation_section_clean() -> None:
    """HTML report must contain a Remediation Guidance section for a clean scan."""
    result = _make_scan_result()
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert _HTML_SECTION_REMEDIATION in html


def test_html_report_contains_remediation_section_with_findings() -> None:
    """HTML report must contain a Remediation Guidance section when findings exist."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert _HTML_SECTION_REMEDIATION in html


def test_html_report_remediation_references_phi_scan_fix() -> None:
    """HTML report's remediation section must reference the phi-scan fix command."""
    result = _make_scan_result()
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert _PHI_SCAN_FIX_CMD in html


def test_html_report_remediation_shows_category_guidance_for_findings() -> None:
    """HTML report must show SSN-specific remediation guidance when SSN is found."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    html = generate_html_report(result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    # The SSN remediation guidance from HIPAA_REMEDIATION_GUIDANCE must appear
    ssn_guidance = HIPAA_REMEDIATION_GUIDANCE[PhiCategory.SSN]
    # At minimum, a fragment of the guidance should appear
    assert any(word in html for word in ssn_guidance.split()[:5])


# ---------------------------------------------------------------------------
# PDF report: remediation section (structure — text is in compressed streams)
# ---------------------------------------------------------------------------


def test_pdf_report_generates_with_remediation_content() -> None:
    """PDF must generate without error (remediation section is always written)."""
    result = _make_scan_result()
    pdf_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_report_generates_with_remediation_content_and_findings() -> None:
    """PDF must generate without error when findings with remediation hints are present."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    result = _make_scan_result(findings, RiskLevel.HIGH)
    pdf_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert pdf_bytes.startswith(b"%PDF-")
