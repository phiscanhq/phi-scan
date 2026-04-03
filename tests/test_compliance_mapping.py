# phi-scan:ignore-file
"""Tests for compliance control mapping per finding (Phase 4D.6).

Verifies that:
  - Each PHI finding maps to the correct HIPAA Safe Harbor identifier
  - SOC2 controls appear for relevant categories when soc2 is enabled
  - HITRUST controls appear for relevant categories when hitrust is enabled
  - Specific control IDs match the expected regulatory citations
  - HIPAA is always included regardless of enabled frameworks
"""

from __future__ import annotations

from pathlib import Path

from phi_scan.compliance import (
    CATEGORY_CONTROLS,
    ComplianceControl,
    ComplianceFramework,
    annotate_findings,
)
from phi_scan.constants import (
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.models import ScanFinding

# ---------------------------------------------------------------------------
# Test constants — no magic values in test logic
# ---------------------------------------------------------------------------

_SAMPLE_HASH: str = "a" * 64
_SAMPLE_FILE_PATH: Path = Path("src/patient_service.py")
_SAMPLE_LINE_NUMBER: int = 10
_SAMPLE_CONFIDENCE: float = 0.92
_SAMPLE_ENTITY_TYPE: str = "us_ssn"
_SAMPLE_CODE_CONTEXT: str = "ssn = '[REDACTED]'"
_SAMPLE_REMEDIATION_HINT: str = "Replace SSN."

# Expected HIPAA Safe Harbor sub-item control IDs (45 CFR §164.514(b)(2)(i))
_HIPAA_CONTROL_ID_NAME: str = "A"  # Names
_HIPAA_CONTROL_ID_SSN: str = "G"  # Social Security Numbers
_HIPAA_CONTROL_ID_MRN: str = "H"  # Medical Record Numbers
_HIPAA_CONTROL_ID_EMAIL: str = "F"  # Email Addresses
_HIPAA_CONTROL_ID_DATE: str = "C"  # Elements of Dates
_HIPAA_CONTROL_ID_PHONE: str = "D"  # Phone Numbers
_HIPAA_CONTROL_ID_BIOMETRIC: str = "P"  # Biometric Identifiers

# Expected SOC2 control IDs
_SOC2_CONTROL_CC6_1: str = "CC6.1"
_SOC2_CONTROL_CC6_6: str = "CC6.6"
_SOC2_CONTROL_CC6_7: str = "CC6.7"

# Expected HITRUST control IDs
_HITRUST_CONTROL_07A: str = "07.a"
_HITRUST_CONTROL_01V: str = "01.v"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    category: PhiCategory = PhiCategory.SSN,
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
        severity=SeverityLevel.HIGH,
        code_context=_SAMPLE_CODE_CONTEXT,
        remediation_hint=_SAMPLE_REMEDIATION_HINT,
    )


def _extract_hipaa_control_ids(controls: tuple[ComplianceControl, ...]) -> list[str]:
    return [c.control_id for c in controls if c.framework is ComplianceFramework.HIPAA]


def _extract_framework_control_ids(
    controls: tuple[ComplianceControl, ...], framework: ComplianceFramework
) -> list[str]:
    return [c.control_id for c in controls if c.framework is framework]


# ---------------------------------------------------------------------------
# HIPAA identifier mapping — specific Safe Harbor sub-items
# ---------------------------------------------------------------------------


def test_name_finding_maps_to_hipaa_safeharbor_item_a() -> None:
    """A NAME finding must map to HIPAA Safe Harbor item A (Names)."""
    controls = CATEGORY_CONTROLS[PhiCategory.NAME]
    hipaa_ids = _extract_hipaa_control_ids(controls)
    assert any(_HIPAA_CONTROL_ID_NAME in cid for cid in hipaa_ids)


def test_ssn_finding_maps_to_hipaa_safeharbor_item_g() -> None:
    """An SSN finding must map to HIPAA Safe Harbor item G (Social Security Numbers)."""
    controls = CATEGORY_CONTROLS[PhiCategory.SSN]
    hipaa_ids = _extract_hipaa_control_ids(controls)
    assert any(_HIPAA_CONTROL_ID_SSN in cid for cid in hipaa_ids)


def test_mrn_finding_maps_to_hipaa_safeharbor_item_h() -> None:
    """An MRN finding must map to HIPAA Safe Harbor item H (Medical Record Numbers)."""
    controls = CATEGORY_CONTROLS[PhiCategory.MRN]
    hipaa_ids = _extract_hipaa_control_ids(controls)
    assert any(_HIPAA_CONTROL_ID_MRN in cid for cid in hipaa_ids)


def test_email_finding_maps_to_hipaa_safeharbor_item_f() -> None:
    """An EMAIL finding must map to HIPAA Safe Harbor item F (Email Addresses)."""
    controls = CATEGORY_CONTROLS[PhiCategory.EMAIL]
    hipaa_ids = _extract_hipaa_control_ids(controls)
    assert any(_HIPAA_CONTROL_ID_EMAIL in cid for cid in hipaa_ids)


def test_date_finding_maps_to_hipaa_safeharbor_item_c() -> None:
    """A DATE finding must map to HIPAA Safe Harbor item C (Elements of Dates)."""
    controls = CATEGORY_CONTROLS[PhiCategory.DATE]
    hipaa_ids = _extract_hipaa_control_ids(controls)
    assert any(_HIPAA_CONTROL_ID_DATE in cid for cid in hipaa_ids)


def test_phone_finding_maps_to_hipaa_safeharbor_item_d() -> None:
    """A PHONE finding must map to HIPAA Safe Harbor item D (Phone Numbers)."""
    controls = CATEGORY_CONTROLS[PhiCategory.PHONE]
    hipaa_ids = _extract_hipaa_control_ids(controls)
    assert any(_HIPAA_CONTROL_ID_PHONE in cid for cid in hipaa_ids)


def test_biometric_finding_maps_to_hipaa_safeharbor_item_p() -> None:
    """A BIOMETRIC finding must map to HIPAA Safe Harbor item P (Biometric Identifiers)."""
    controls = CATEGORY_CONTROLS[PhiCategory.BIOMETRIC]
    hipaa_ids = _extract_hipaa_control_ids(controls)
    assert any(_HIPAA_CONTROL_ID_BIOMETRIC in cid for cid in hipaa_ids)


# ---------------------------------------------------------------------------
# HIPAA always included in annotate_findings
# ---------------------------------------------------------------------------


def test_annotate_findings_hipaa_present_with_empty_enabled_frameworks() -> None:
    """HIPAA controls must be present even when enabled_frameworks is empty."""
    finding = _make_finding(PhiCategory.SSN)
    result = annotate_findings((finding,), frozenset())
    hipaa_controls = [c for c in result[0] if c.framework is ComplianceFramework.HIPAA]
    assert hipaa_controls


def test_annotate_findings_hipaa_present_with_non_hipaa_framework() -> None:
    """HIPAA controls must be present when only a non-HIPAA framework is enabled."""
    finding = _make_finding(PhiCategory.SSN)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.GDPR}))
    hipaa_controls = [c for c in result[0] if c.framework is ComplianceFramework.HIPAA]
    assert hipaa_controls


# ---------------------------------------------------------------------------
# SOC2 control mapping
# ---------------------------------------------------------------------------


def test_ssn_maps_to_soc2_cc6_controls_when_enabled() -> None:
    """SSN finding must include SOC2 CC6-series controls when soc2 is enabled."""
    finding = _make_finding(PhiCategory.SSN)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.SOC2}))
    soc2_ids = _extract_framework_control_ids(result[0], ComplianceFramework.SOC2)
    assert any("CC6" in cid for cid in soc2_ids), f"No SOC2 CC6 control found; got: {soc2_ids}"


def test_mrn_maps_to_soc2_cc6_controls_when_enabled() -> None:
    """MRN finding must include SOC2 CC6 controls when soc2 is enabled."""
    finding = _make_finding(PhiCategory.MRN)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.SOC2}))
    soc2_ids = _extract_framework_control_ids(result[0], ComplianceFramework.SOC2)
    assert soc2_ids, "SOC2 controls must be present for MRN when soc2 is enabled"


def test_category_controls_soc2_cc6_1_control_id() -> None:
    """CATEGORY_CONTROLS must contain a SOC2 control with ID CC6.1."""
    all_soc2_ids: list[str] = []
    for controls in CATEGORY_CONTROLS.values():
        all_soc2_ids.extend(
            c.control_id for c in controls if c.framework is ComplianceFramework.SOC2
        )
    assert _SOC2_CONTROL_CC6_1 in all_soc2_ids, (
        "SOC2 CC6.1 control not found in any CATEGORY_CONTROLS entry"
    )


def test_category_controls_soc2_cc6_6_control_id() -> None:
    """CATEGORY_CONTROLS must contain a SOC2 control with ID CC6.6."""
    all_soc2_ids: list[str] = []
    for controls in CATEGORY_CONTROLS.values():
        all_soc2_ids.extend(
            c.control_id for c in controls if c.framework is ComplianceFramework.SOC2
        )
    assert _SOC2_CONTROL_CC6_6 in all_soc2_ids, (
        "SOC2 CC6.6 control not found in any CATEGORY_CONTROLS entry"
    )


# ---------------------------------------------------------------------------
# HITRUST control mapping
# ---------------------------------------------------------------------------


def test_ssn_maps_to_hitrust_controls_when_enabled() -> None:
    """SSN finding must include HITRUST controls when hitrust is enabled."""
    finding = _make_finding(PhiCategory.SSN)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.HITRUST}))
    hitrust_ids = _extract_framework_control_ids(result[0], ComplianceFramework.HITRUST)
    assert hitrust_ids, "HITRUST controls must be present for SSN when hitrust is enabled"


def test_category_controls_hitrust_07a_control_id() -> None:
    """CATEGORY_CONTROLS must contain a HITRUST control with ID 07.a."""
    all_hitrust_ids: list[str] = []
    for controls in CATEGORY_CONTROLS.values():
        all_hitrust_ids.extend(
            c.control_id for c in controls if c.framework is ComplianceFramework.HITRUST
        )
    assert _HITRUST_CONTROL_07A in all_hitrust_ids, (
        "HITRUST 07.a control not found in any CATEGORY_CONTROLS entry"
    )


def test_category_controls_hitrust_01v_control_id() -> None:
    """CATEGORY_CONTROLS must contain a HITRUST control with ID 01.v."""
    all_hitrust_ids: list[str] = []
    for controls in CATEGORY_CONTROLS.values():
        all_hitrust_ids.extend(
            c.control_id for c in controls if c.framework is ComplianceFramework.HITRUST
        )
    assert _HITRUST_CONTROL_01V in all_hitrust_ids, (
        "HITRUST 01.v control not found in any CATEGORY_CONTROLS entry"
    )


def test_mrn_maps_to_hitrust_controls_when_enabled() -> None:
    """MRN finding must include HITRUST controls when hitrust is enabled."""
    finding = _make_finding(PhiCategory.MRN)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.HITRUST}))
    hitrust_ids = _extract_framework_control_ids(result[0], ComplianceFramework.HITRUST)
    assert hitrust_ids, "HITRUST controls must be present for MRN when hitrust is enabled"


# ---------------------------------------------------------------------------
# Multi-finding index accuracy
# ---------------------------------------------------------------------------


def test_annotate_findings_each_finding_has_its_own_controls() -> None:
    """Controls at index 0 must correspond to finding 0, index 1 to finding 1."""
    ssn_finding = _make_finding(PhiCategory.SSN, line_number=1)
    biometric_finding = _make_finding(PhiCategory.BIOMETRIC, line_number=2)
    result = annotate_findings(
        (ssn_finding, biometric_finding),
        frozenset({ComplianceFramework.BIPA}),
    )
    # Index 0 = SSN: must not have BIPA
    ssn_bipa = [c for c in result[0] if c.framework is ComplianceFramework.BIPA]
    assert not ssn_bipa, "SSN finding must not carry BIPA controls"

    # Index 1 = BIOMETRIC: must have BIPA
    bio_bipa = [c for c in result[1] if c.framework is ComplianceFramework.BIPA]
    assert bio_bipa, "BIOMETRIC finding must carry BIPA controls when bipa is enabled"


def test_annotate_findings_all_indices_covered() -> None:
    """annotate_findings must return an entry for every finding index."""
    findings = tuple(_make_finding(PhiCategory.SSN, line_number=i + 1) for i in range(5))
    result = annotate_findings(findings, frozenset({ComplianceFramework.SOC2}))
    assert set(result.keys()) == {0, 1, 2, 3, 4}
