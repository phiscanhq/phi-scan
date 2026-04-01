"""Tests for phi_scan.compliance — Phase 4B multi-framework compliance mapping."""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import pytest

from phi_scan.compliance import (
    CATEGORY_CONTROLS,
    FRAMEWORK_METADATA,
    IMPLEMENTED_FRAMEWORKS,
    ComplianceControl,
    ComplianceFramework,
    FrameworkMetadata,
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

# ---------------------------------------------------------------------------
# Test constants — no magic values in test logic
# ---------------------------------------------------------------------------

_SAMPLE_VALUE_HASH: str = "b" * 64
_SAMPLE_ENTITY_TYPE: str = "us_ssn"
_SAMPLE_LINE_NUMBER: int = 10
_SAMPLE_CONFIDENCE: float = 0.95
_SAMPLE_CODE_CONTEXT: str = "ssn = '[REDACTED]'"
_SAMPLE_REMEDIATION_HINT: str = "Remove SSN."
_SAMPLE_FILE_PATH: Path = Path("src/config.py")

_INVALID_FRAMEWORK_TOKEN: str = "nonexistent_framework"
_VALID_FRAMEWORK_PAIR: str = "gdpr,soc2"


def _make_finding(
    category: PhiCategory = PhiCategory.SSN,
    file_path: Path = _SAMPLE_FILE_PATH,
    line_number: int = _SAMPLE_LINE_NUMBER,
) -> ScanFinding:
    """Return a minimal valid ScanFinding for a given category."""
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=_SAMPLE_ENTITY_TYPE,
        hipaa_category=category,
        confidence=_SAMPLE_CONFIDENCE,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_SAMPLE_VALUE_HASH,
        severity=SeverityLevel.HIGH,
        code_context=_SAMPLE_CODE_CONTEXT,
        remediation_hint=_SAMPLE_REMEDIATION_HINT,
    )


def _make_scan_result(findings: tuple[ScanFinding, ...]) -> ScanResult:
    """Return a minimal ScanResult wrapping the given findings."""
    severity_counts: MappingProxyType[SeverityLevel, int] = MappingProxyType(
        {level: 0 for level in SeverityLevel}
    )
    category_counts: MappingProxyType[PhiCategory, int] = MappingProxyType(
        {cat: 0 for cat in PhiCategory}
    )
    return ScanResult(
        findings=findings,
        files_scanned=1,
        files_with_findings=1 if findings else 0,
        scan_duration=0.1,
        is_clean=not findings,
        risk_level=RiskLevel.CRITICAL if findings else RiskLevel.CLEAN,
        severity_counts=severity_counts,
        category_counts=category_counts,
    )


# ---------------------------------------------------------------------------
# ComplianceFramework enum
# ---------------------------------------------------------------------------


def test_compliance_framework_values_are_lowercase() -> None:
    """All ComplianceFramework values must be lowercase strings."""
    for member in ComplianceFramework:
        assert member.value == member.value.lower(), (
            f"ComplianceFramework.{member.name} value {member.value!r} is not lowercase"
        )


def test_implemented_frameworks_matches_enum_members() -> None:
    """IMPLEMENTED_FRAMEWORKS must contain exactly the ComplianceFramework members."""
    assert IMPLEMENTED_FRAMEWORKS == frozenset(ComplianceFramework)


def test_hipaa_member_exists() -> None:
    """HIPAA must be a member of ComplianceFramework and always active."""
    assert ComplianceFramework.HIPAA in ComplianceFramework
    assert ComplianceFramework.HIPAA.value == "hipaa"


# ---------------------------------------------------------------------------
# ComplianceControl dataclass
# ---------------------------------------------------------------------------


def test_compliance_control_is_frozen() -> None:
    """ComplianceControl must be immutable (frozen dataclass)."""
    control = ComplianceControl(
        framework=ComplianceFramework.HIPAA,
        control_id="45 CFR §164.514(b)(2)(i)(G)",
        control_name="Social Security Numbers",
        citation="Test citation.",
    )
    with pytest.raises(AttributeError):
        control.control_id = "mutated"  # type: ignore[misc]


def test_compliance_control_stores_fields() -> None:
    """ComplianceControl must store all fields correctly."""
    control = ComplianceControl(
        framework=ComplianceFramework.GDPR,
        control_id="GDPR Art. 9",
        control_name="Special Categories",
        citation="Article 9 citation.",
    )
    assert control.framework is ComplianceFramework.GDPR
    assert control.control_id == "GDPR Art. 9"
    assert control.control_name == "Special Categories"
    assert "Article 9" in control.citation


# ---------------------------------------------------------------------------
# FRAMEWORK_METADATA
# ---------------------------------------------------------------------------


def test_framework_metadata_covers_all_frameworks() -> None:
    """FRAMEWORK_METADATA must have an entry for every ComplianceFramework member."""
    for member in ComplianceFramework:
        assert member in FRAMEWORK_METADATA, (
            f"FRAMEWORK_METADATA is missing an entry for ComplianceFramework.{member.name}"
        )


def test_framework_metadata_values_are_framework_meta() -> None:
    """Every FRAMEWORK_METADATA value must be a FrameworkMetadata instance."""
    for member, meta in FRAMEWORK_METADATA.items():
        assert isinstance(meta, FrameworkMetadata), (
            f"FRAMEWORK_METADATA[{member!r}] is {type(meta)!r}, expected FrameworkMetadata"
        )


def test_framework_metadata_fields_are_non_empty() -> None:
    """Each FrameworkMetadata must have non-empty display_name, enforcement_body, penalty_range."""
    for member, meta in FRAMEWORK_METADATA.items():
        assert meta.display_name, f"display_name is empty for {member!r}"
        assert meta.enforcement_body, f"enforcement_body is empty for {member!r}"
        assert meta.penalty_range, f"penalty_range is empty for {member!r}"
        assert meta.description, f"description is empty for {member!r}"


# ---------------------------------------------------------------------------
# CATEGORY_CONTROLS mapping
# ---------------------------------------------------------------------------


def test_category_controls_covers_all_phi_categories() -> None:
    """CATEGORY_CONTROLS must have an entry for every PhiCategory member."""
    for category in PhiCategory:
        assert category in CATEGORY_CONTROLS, (
            f"CATEGORY_CONTROLS is missing an entry for PhiCategory.{category.name}"
        )


def test_category_controls_each_value_is_tuple_of_controls() -> None:
    """Each CATEGORY_CONTROLS value must be a tuple of ComplianceControl instances."""
    for category, controls in CATEGORY_CONTROLS.items():
        assert isinstance(controls, tuple), (
            f"CATEGORY_CONTROLS[{category!r}] is {type(controls)!r}, expected tuple"
        )
        for control in controls:
            assert isinstance(control, ComplianceControl), (
                f"CATEGORY_CONTROLS[{category!r}] contains non-ComplianceControl: {control!r}"
            )


def test_every_category_has_at_least_one_hipaa_control() -> None:
    """Every PhiCategory must have at least one HIPAA control in CATEGORY_CONTROLS."""
    for category, controls in CATEGORY_CONTROLS.items():
        hipaa_controls = [c for c in controls if c.framework is ComplianceFramework.HIPAA]
        assert hipaa_controls, (
            f"PhiCategory.{category.name} has no HIPAA controls in CATEGORY_CONTROLS"
        )


def test_substance_use_disorder_has_42cfr2_control() -> None:
    """SUBSTANCE_USE_DISORDER must include a 42 CFR Part 2 control."""
    controls = CATEGORY_CONTROLS[PhiCategory.SUBSTANCE_USE_DISORDER]
    cfr2_controls = [c for c in controls if c.framework is ComplianceFramework.CFR_PART_2]
    assert cfr2_controls, "SUBSTANCE_USE_DISORDER has no 42 CFR Part 2 control"


def test_biometric_has_bipa_control() -> None:
    """BIOMETRIC category must include a BIPA control."""
    controls = CATEGORY_CONTROLS[PhiCategory.BIOMETRIC]
    bipa_controls = [c for c in controls if c.framework is ComplianceFramework.BIPA]
    assert bipa_controls, "BIOMETRIC has no BIPA control"


def test_biometric_has_gdpr_art9_control() -> None:
    """BIOMETRIC category must include a GDPR Art. 9 control."""
    controls = CATEGORY_CONTROLS[PhiCategory.BIOMETRIC]
    gdpr_art9 = [c for c in controls if "Art. 9" in c.control_id or "Art. 9" in c.citation]
    assert gdpr_art9, "BIOMETRIC has no GDPR Art. 9 control"


def test_ssn_has_no_42cfr2_control() -> None:
    """SSN must not have a 42 CFR Part 2 control (only SUD has that)."""
    controls = CATEGORY_CONTROLS[PhiCategory.SSN]
    cfr2_controls = [c for c in controls if c.framework is ComplianceFramework.CFR_PART_2]
    assert not cfr2_controls, "SSN should not have a 42 CFR Part 2 control"


# ---------------------------------------------------------------------------
# parse_framework_flag
# ---------------------------------------------------------------------------


def test_parse_framework_flag_returns_empty_frozenset_for_none() -> None:
    """parse_framework_flag(None) must return an empty frozenset."""
    result = parse_framework_flag(None)
    assert result == frozenset()


def test_parse_framework_flag_returns_empty_frozenset_for_blank_string() -> None:
    """parse_framework_flag('') must return an empty frozenset."""
    result = parse_framework_flag("")
    assert result == frozenset()


def test_parse_framework_flag_single_valid_token() -> None:
    """A single valid token must return a frozenset with one member."""
    result = parse_framework_flag("gdpr")
    assert result == frozenset({ComplianceFramework.GDPR})


def test_parse_framework_flag_multiple_valid_tokens() -> None:
    """Comma-separated valid tokens must all be returned."""
    result = parse_framework_flag(_VALID_FRAMEWORK_PAIR)
    assert result == frozenset({ComplianceFramework.GDPR, ComplianceFramework.SOC2})


def test_parse_framework_flag_is_case_insensitive() -> None:
    """Token matching must be case-insensitive."""
    result = parse_framework_flag("GDPR,SOC2")
    assert result == frozenset({ComplianceFramework.GDPR, ComplianceFramework.SOC2})


def test_parse_framework_flag_trims_whitespace() -> None:
    """Leading/trailing whitespace around tokens must be ignored."""
    result = parse_framework_flag(" gdpr , soc2 ")
    assert result == frozenset({ComplianceFramework.GDPR, ComplianceFramework.SOC2})


def test_parse_framework_flag_raises_value_error_for_unknown_token() -> None:
    """An unknown framework token must raise ValueError."""
    with pytest.raises(ValueError, match=_INVALID_FRAMEWORK_TOKEN):
        parse_framework_flag(_INVALID_FRAMEWORK_TOKEN)


def test_parse_framework_flag_raises_value_error_listing_valid_values() -> None:
    """The ValueError message must list valid framework values."""
    with pytest.raises(ValueError, match="hipaa"):
        parse_framework_flag(_INVALID_FRAMEWORK_TOKEN)


def test_parse_framework_flag_hipaa_token_is_valid() -> None:
    """'hipaa' must be a valid token for parse_framework_flag."""
    result = parse_framework_flag("hipaa")
    assert ComplianceFramework.HIPAA in result


def test_parse_framework_flag_42cfr2_token_is_valid() -> None:
    """'42cfr2' (hyphenated-style token) must be accepted."""
    result = parse_framework_flag("42cfr2")
    assert ComplianceFramework.CFR_PART_2 in result


# ---------------------------------------------------------------------------
# annotate_findings
# ---------------------------------------------------------------------------


def test_annotate_findings_returns_empty_dict_for_empty_findings() -> None:
    """annotate_findings on an empty findings tuple must return an empty dict."""
    result = annotate_findings((), frozenset({ComplianceFramework.GDPR}))
    assert result == {}


def test_annotate_findings_always_includes_hipaa_controls() -> None:
    """HIPAA controls must be present even when enabled_frameworks is empty."""
    finding = _make_finding(PhiCategory.SSN)
    result = annotate_findings((finding,), frozenset())
    controls = result[0]
    hipaa_controls = [c for c in controls if c.framework is ComplianceFramework.HIPAA]
    assert hipaa_controls, "HIPAA controls must always be included"


def test_annotate_findings_includes_enabled_framework_controls() -> None:
    """Controls for an enabled framework must appear in the annotations."""
    finding = _make_finding(PhiCategory.SSN)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.GDPR}))
    controls = result[0]
    gdpr_controls = [c for c in controls if c.framework is ComplianceFramework.GDPR]
    assert gdpr_controls, "GDPR controls must be included when gdpr framework is enabled"


def test_annotate_findings_excludes_disabled_framework_controls() -> None:
    """Controls for a disabled framework must not appear in the annotations."""
    finding = _make_finding(PhiCategory.SSN)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.HIPAA}))
    controls = result[0]
    bipa_controls = [c for c in controls if c.framework is ComplianceFramework.BIPA]
    assert not bipa_controls, "BIPA controls must not appear when bipa is not enabled"


def test_annotate_findings_indices_match_findings_tuple() -> None:
    """Keys in the returned dict must be 0-based indices into findings."""
    findings = (
        _make_finding(PhiCategory.SSN, line_number=1),
        _make_finding(PhiCategory.NAME, line_number=2),
        _make_finding(PhiCategory.EMAIL, line_number=3),
    )
    result = annotate_findings(findings, frozenset({ComplianceFramework.GDPR}))
    assert set(result.keys()) == {0, 1, 2}


def test_annotate_findings_substance_use_disorder_includes_42cfr2() -> None:
    """SUD findings must carry 42 CFR Part 2 controls when 42cfr2 is enabled."""
    finding = _make_finding(PhiCategory.SUBSTANCE_USE_DISORDER)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.CFR_PART_2}))
    controls = result[0]
    cfr2_controls = [c for c in controls if c.framework is ComplianceFramework.CFR_PART_2]
    assert cfr2_controls, "SUD finding must have 42 CFR Part 2 controls"


def test_annotate_findings_ssn_excludes_42cfr2_when_enabled() -> None:
    """SSN findings must not carry 42 CFR Part 2 controls even when 42cfr2 is enabled."""
    finding = _make_finding(PhiCategory.SSN)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.CFR_PART_2}))
    controls = result[0]
    cfr2_controls = [c for c in controls if c.framework is ComplianceFramework.CFR_PART_2]
    assert not cfr2_controls, "SSN finding must not have 42 CFR Part 2 controls"


def test_annotate_findings_biometric_includes_bipa_when_enabled() -> None:
    """BIOMETRIC findings must carry BIPA controls when bipa is enabled."""
    finding = _make_finding(PhiCategory.BIOMETRIC)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.BIPA}))
    controls = result[0]
    bipa_controls = [c for c in controls if c.framework is ComplianceFramework.BIPA]
    assert bipa_controls, "BIOMETRIC finding must have BIPA controls when bipa is enabled"


def test_annotate_findings_returns_tuples_of_controls() -> None:
    """Each value in the result dict must be a tuple of ComplianceControl."""
    finding = _make_finding(PhiCategory.SSN)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.GDPR}))
    assert isinstance(result[0], tuple)
    for control in result[0]:
        assert isinstance(control, ComplianceControl)


def test_annotate_findings_hipaa_added_even_if_not_in_enabled() -> None:
    """HIPAA must be added automatically even if not in enabled_frameworks."""
    finding = _make_finding(PhiCategory.EMAIL)
    result = annotate_findings((finding,), frozenset({ComplianceFramework.SOC2}))
    controls = result[0]
    frameworks_present = {c.framework for c in controls}
    assert ComplianceFramework.HIPAA in frameworks_present
    assert ComplianceFramework.SOC2 in frameworks_present
