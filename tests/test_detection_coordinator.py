"""Tests for phi_scan.detection_coordinator — Phase 2E orchestration layer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from phi_scan.constants import (
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_MEDIUM_FLOOR,
    CONFIDENCE_SCORE_MAXIMUM,
    HIPAA_AGE_RESTRICTION_THRESHOLD,
    QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES,
    VARIABLE_CONTEXT_CONFIDENCE_BOOST,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.detection_coordinator import (
    _apply_variable_name_confidence_boost as apply_variable_name_confidence_boost,
)
from phi_scan.detection_coordinator import (
    deduplicate_overlapping_findings,
    detect_phi_in_text_content,
    detect_quasi_identifier_combination,
    evaluate_age_geographic_combination,
    evaluate_colocated_identifier_combination,
    evaluate_name_date_combination,
    evaluate_zip_dob_sex_combination,
)
from phi_scan.hashing import compute_value_hash, severity_from_confidence
from phi_scan.models import ScanFinding

# ---------------------------------------------------------------------------
# Shared test fixtures and factories
# ---------------------------------------------------------------------------

_FAKE_FILE_PATH: Path = Path("fake/repo/patient_data.py")
_FAKE_HASH: str = compute_value_hash("test-value")
_LINE_ONE: int = 1
_LINE_TWO: int = 2
_LINE_FAR_AWAY: int = QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES + 100

_CONFIDENCE_MEDIUM: float = CONFIDENCE_MEDIUM_FLOOR
_CONFIDENCE_HIGH: float = CONFIDENCE_HIGH_FLOOR


def _make_finding(
    *,
    hipaa_category: PhiCategory = PhiCategory.NAME,
    entity_type: str = "test_entity",
    line_number: int = _LINE_ONE,
    confidence: float = _CONFIDENCE_MEDIUM,
    value_hash: str = _FAKE_HASH,
    file_path: Path = _FAKE_FILE_PATH,
    detection_layer: DetectionLayer = DetectionLayer.REGEX,
) -> ScanFinding:
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=entity_type,
        hipaa_category=hipaa_category,
        confidence=confidence,
        detection_layer=detection_layer,
        value_hash=value_hash,
        severity=severity_from_confidence(confidence),
        code_context="test [REDACTED]",
        remediation_hint="test hint",
    )


# ---------------------------------------------------------------------------
# deduplicate_overlapping_findings
# ---------------------------------------------------------------------------


def test_deduplicate_overlapping_findings_removes_lower_confidence_duplicate():
    high_confidence_finding = _make_finding(confidence=_CONFIDENCE_HIGH)
    low_confidence_finding = _make_finding(
        confidence=_CONFIDENCE_MEDIUM,
        detection_layer=DetectionLayer.NLP,
    )

    result = deduplicate_overlapping_findings([high_confidence_finding, low_confidence_finding])

    assert len(result) == 1
    assert result[0].detection_layer == DetectionLayer.REGEX


def test_deduplicate_overlapping_findings_keeps_different_value_hashes():
    finding_a = _make_finding(value_hash=compute_value_hash("value-a"))
    finding_b = _make_finding(value_hash=compute_value_hash("value-b"))

    result = deduplicate_overlapping_findings([finding_a, finding_b])

    assert len(result) == 2


def test_deduplicate_overlapping_findings_keeps_different_line_numbers():
    finding_line_1 = _make_finding(line_number=_LINE_ONE)
    finding_line_2 = _make_finding(line_number=_LINE_TWO)

    result = deduplicate_overlapping_findings([finding_line_1, finding_line_2])

    assert len(result) == 2


def test_deduplicate_overlapping_findings_sorts_by_file_path_and_line_number():
    path_b = Path("b/file.py")
    path_a = Path("a/file.py")
    finding_b_line_2 = _make_finding(file_path=path_b, line_number=_LINE_TWO)
    finding_a_line_1 = _make_finding(file_path=path_a, line_number=_LINE_ONE)

    result = deduplicate_overlapping_findings([finding_b_line_2, finding_a_line_1])

    assert result[0].file_path == path_a
    assert result[1].file_path == path_b


def test_deduplicate_overlapping_findings_returns_empty_for_empty_input():
    result = deduplicate_overlapping_findings([])

    assert result == []


# ---------------------------------------------------------------------------
# evaluate_zip_dob_sex_combination
# ---------------------------------------------------------------------------


def test_evaluate_zip_dob_sex_combination_fires_when_geographic_and_date_present():
    findings = [
        _make_finding(hipaa_category=PhiCategory.GEOGRAPHIC, line_number=_LINE_ONE),
        _make_finding(
            hipaa_category=PhiCategory.DATE,
            line_number=_LINE_TWO,
            value_hash=compute_value_hash("dob"),
        ),
    ]

    result = evaluate_zip_dob_sex_combination(findings)

    assert len(result) == 1
    assert result[0].hipaa_category == PhiCategory.QUASI_IDENTIFIER_COMBINATION


def test_evaluate_zip_dob_sex_combination_returns_empty_when_no_geographic():
    findings = [_make_finding(hipaa_category=PhiCategory.DATE)]

    result = evaluate_zip_dob_sex_combination(findings)

    assert result == []


def test_evaluate_zip_dob_sex_combination_returns_empty_when_no_date():
    findings = [_make_finding(hipaa_category=PhiCategory.GEOGRAPHIC)]

    result = evaluate_zip_dob_sex_combination(findings)

    assert result == []


def test_evaluate_zip_dob_sex_combination_returns_empty_outside_proximity_window():
    findings = [
        _make_finding(hipaa_category=PhiCategory.GEOGRAPHIC, line_number=_LINE_ONE),
        _make_finding(
            hipaa_category=PhiCategory.DATE,
            line_number=_LINE_FAR_AWAY,
            value_hash=compute_value_hash("dob"),
        ),
    ]

    result = evaluate_zip_dob_sex_combination(findings)

    assert result == []


def test_evaluate_zip_dob_sex_combination_produces_high_confidence_finding():
    findings = [
        _make_finding(
            hipaa_category=PhiCategory.GEOGRAPHIC,
            confidence=_CONFIDENCE_MEDIUM,
        ),
        _make_finding(
            hipaa_category=PhiCategory.DATE,
            confidence=_CONFIDENCE_MEDIUM,
            value_hash=compute_value_hash("dob"),
        ),
    ]

    result = evaluate_zip_dob_sex_combination(findings)

    assert result[0].confidence == CONFIDENCE_HIGH_FLOOR
    assert result[0].severity == SeverityLevel.HIGH


# ---------------------------------------------------------------------------
# evaluate_name_date_combination
# ---------------------------------------------------------------------------


def test_evaluate_name_date_combination_fires_when_name_and_date_present():
    findings = [
        _make_finding(hipaa_category=PhiCategory.NAME),
        _make_finding(
            hipaa_category=PhiCategory.DATE,
            value_hash=compute_value_hash("date"),
        ),
    ]

    result = evaluate_name_date_combination(findings)

    assert len(result) == 1
    assert result[0].hipaa_category == PhiCategory.QUASI_IDENTIFIER_COMBINATION


def test_evaluate_name_date_combination_returns_empty_when_no_name():
    findings = [_make_finding(hipaa_category=PhiCategory.DATE)]

    result = evaluate_name_date_combination(findings)

    assert result == []


def test_evaluate_name_date_combination_returns_empty_when_outside_window():
    findings = [
        _make_finding(hipaa_category=PhiCategory.NAME, line_number=_LINE_ONE),
        _make_finding(
            hipaa_category=PhiCategory.DATE,
            line_number=_LINE_FAR_AWAY,
            value_hash=compute_value_hash("date"),
        ),
    ]

    result = evaluate_name_date_combination(findings)

    assert result == []


# ---------------------------------------------------------------------------
# evaluate_age_geographic_combination
# ---------------------------------------------------------------------------


_AGE_ENTITY_TYPE: str = "AGE_OVER_THRESHOLD"
_AGE_OVER_THRESHOLD_LINE: int = 5


def test_evaluate_age_geographic_combination_fires_for_age_and_geographic():
    findings = [
        _make_finding(
            entity_type=_AGE_ENTITY_TYPE,
            hipaa_category=PhiCategory.DATE,
            line_number=_AGE_OVER_THRESHOLD_LINE,
        ),
        _make_finding(
            hipaa_category=PhiCategory.GEOGRAPHIC,
            line_number=_AGE_OVER_THRESHOLD_LINE + 1,
            value_hash=compute_value_hash("geo"),
        ),
    ]

    result = evaluate_age_geographic_combination(findings)

    assert len(result) == 1
    assert result[0].hipaa_category == PhiCategory.QUASI_IDENTIFIER_COMBINATION


def test_evaluate_age_geographic_combination_returns_empty_when_no_age_finding():
    findings = [_make_finding(hipaa_category=PhiCategory.GEOGRAPHIC)]

    result = evaluate_age_geographic_combination(findings)

    assert result == []


def test_evaluate_age_geographic_combination_does_not_fire_for_non_age_date():
    # A DATE finding without the specific AGE_OVER_THRESHOLD entity_type must not trigger.
    findings = [
        _make_finding(hipaa_category=PhiCategory.DATE, entity_type="us_date"),
        _make_finding(
            hipaa_category=PhiCategory.GEOGRAPHIC,
            value_hash=compute_value_hash("geo"),
        ),
    ]

    result = evaluate_age_geographic_combination(findings)

    assert result == []


def test_evaluate_age_geographic_combination_label_references_threshold_constant():
    findings = [
        _make_finding(entity_type=_AGE_ENTITY_TYPE, hipaa_category=PhiCategory.DATE),
        _make_finding(
            hipaa_category=PhiCategory.GEOGRAPHIC,
            value_hash=compute_value_hash("geo"),
        ),
    ]

    result = evaluate_age_geographic_combination(findings)

    assert str(HIPAA_AGE_RESTRICTION_THRESHOLD) in result[0].entity_type


# ---------------------------------------------------------------------------
# evaluate_colocated_identifier_combination
# ---------------------------------------------------------------------------


def test_evaluate_colocated_identifier_combination_fires_for_two_distinct_categories():
    findings = [
        _make_finding(hipaa_category=PhiCategory.SSN, value_hash=compute_value_hash("ssn")),
        _make_finding(
            hipaa_category=PhiCategory.NAME,
            value_hash=compute_value_hash("name"),
        ),
    ]

    result = evaluate_colocated_identifier_combination(findings)

    assert len(result) == 1
    assert result[0].hipaa_category == PhiCategory.QUASI_IDENTIFIER_COMBINATION


def test_evaluate_colocated_identifier_combination_returns_empty_for_single_category():
    findings = [
        _make_finding(hipaa_category=PhiCategory.SSN, value_hash=compute_value_hash("ssn1")),
        _make_finding(
            hipaa_category=PhiCategory.SSN,
            line_number=_LINE_TWO,
            value_hash=compute_value_hash("ssn2"),
        ),
    ]

    result = evaluate_colocated_identifier_combination(findings)

    assert result == []


def test_evaluate_colocated_identifier_combination_returns_empty_outside_proximity_window():
    findings = [
        _make_finding(hipaa_category=PhiCategory.SSN, line_number=_LINE_ONE),
        _make_finding(
            hipaa_category=PhiCategory.NAME,
            line_number=_LINE_FAR_AWAY,
            value_hash=compute_value_hash("name"),
        ),
    ]

    result = evaluate_colocated_identifier_combination(findings)

    assert result == []


def test_evaluate_colocated_identifier_combination_excludes_existing_combination_findings():
    combination_finding = _make_finding(hipaa_category=PhiCategory.QUASI_IDENTIFIER_COMBINATION)
    # Only one base-category finding — should not fire.
    findings = [combination_finding, _make_finding(hipaa_category=PhiCategory.SSN)]

    result = evaluate_colocated_identifier_combination(findings)

    assert result == []


# ---------------------------------------------------------------------------
# detect_quasi_identifier_combination — coordinator
# ---------------------------------------------------------------------------


def test_detect_quasi_identifier_combination_returns_empty_for_no_findings():
    result = detect_quasi_identifier_combination([])

    assert result == []


def test_detect_quasi_identifier_combination_returns_finding_for_name_and_date():
    findings = [
        _make_finding(hipaa_category=PhiCategory.NAME),
        _make_finding(
            hipaa_category=PhiCategory.DATE,
            value_hash=compute_value_hash("date"),
        ),
    ]

    result = detect_quasi_identifier_combination(findings)

    assert any(f.hipaa_category == PhiCategory.QUASI_IDENTIFIER_COMBINATION for f in result)


def test_detect_quasi_identifier_combination_uses_detection_layer_combination():
    findings = [
        _make_finding(hipaa_category=PhiCategory.NAME),
        _make_finding(
            hipaa_category=PhiCategory.DATE,
            value_hash=compute_value_hash("date"),
        ),
    ]

    result = detect_quasi_identifier_combination(findings)

    combination_findings = [
        f for f in result if f.hipaa_category == PhiCategory.QUASI_IDENTIFIER_COMBINATION
    ]
    assert all(f.detection_layer == DetectionLayer.COMBINATION for f in combination_findings)


# ---------------------------------------------------------------------------
# apply_variable_name_confidence_boost
# ---------------------------------------------------------------------------


_PATIENT_NAME_ASSIGNMENT_LINE: str = 'patient_name = "John Smith"'
_NEUTRAL_ASSIGNMENT_LINE: str = 'x = "John Smith"'
_SSN_KEY_JSON_LINE: str = '  "ssn": "123-45-6789"'


def test_apply_variable_name_confidence_boost_boosts_phi_suggestive_assignment():
    finding = _make_finding(line_number=_LINE_ONE, confidence=_CONFIDENCE_MEDIUM)
    file_content = _PATIENT_NAME_ASSIGNMENT_LINE

    result = apply_variable_name_confidence_boost([finding], file_content)

    assert result[0].confidence > finding.confidence


def test_apply_variable_name_confidence_boost_does_not_boost_neutral_assignment():
    finding = _make_finding(line_number=_LINE_ONE, confidence=_CONFIDENCE_MEDIUM)
    file_content = _NEUTRAL_ASSIGNMENT_LINE

    result = apply_variable_name_confidence_boost([finding], file_content)

    assert result[0].confidence == finding.confidence


def test_apply_variable_name_confidence_boost_caps_at_score_maximum():
    finding = _make_finding(line_number=_LINE_ONE, confidence=CONFIDENCE_SCORE_MAXIMUM)
    file_content = _PATIENT_NAME_ASSIGNMENT_LINE

    result = apply_variable_name_confidence_boost([finding], file_content)

    assert result[0].confidence == CONFIDENCE_SCORE_MAXIMUM


def test_apply_variable_name_confidence_boost_applies_correct_delta():
    finding = _make_finding(line_number=_LINE_ONE, confidence=_CONFIDENCE_MEDIUM)
    file_content = _PATIENT_NAME_ASSIGNMENT_LINE

    result = apply_variable_name_confidence_boost([finding], file_content)

    expected = min(_CONFIDENCE_MEDIUM + VARIABLE_CONTEXT_CONFIDENCE_BOOST, CONFIDENCE_SCORE_MAXIMUM)
    assert result[0].confidence == pytest.approx(expected)


def test_apply_variable_name_confidence_boost_updates_severity():
    # A MEDIUM-confidence finding boosted into the HIGH band must update severity.
    confidence_just_below_high = CONFIDENCE_HIGH_FLOOR - 0.05
    finding = _make_finding(line_number=_LINE_ONE, confidence=confidence_just_below_high)
    file_content = _PATIENT_NAME_ASSIGNMENT_LINE

    result = apply_variable_name_confidence_boost([finding], file_content)

    assert result[0].severity == SeverityLevel.HIGH


def test_apply_variable_name_confidence_boost_boosts_json_key():
    finding = _make_finding(line_number=_LINE_ONE, confidence=_CONFIDENCE_MEDIUM)
    file_content = _SSN_KEY_JSON_LINE

    result = apply_variable_name_confidence_boost([finding], file_content)

    assert result[0].confidence > finding.confidence


def test_apply_variable_name_confidence_boost_ignores_out_of_range_line_number():
    finding = _make_finding(line_number=999, confidence=_CONFIDENCE_MEDIUM)
    file_content = _PATIENT_NAME_ASSIGNMENT_LINE

    result = apply_variable_name_confidence_boost([finding], file_content)

    assert result[0].confidence == finding.confidence


def test_apply_variable_name_confidence_boost_returns_empty_for_empty_findings():
    result = apply_variable_name_confidence_boost([], "content")

    assert result == []


# ---------------------------------------------------------------------------
# detect_phi_in_text_content — coordinator integration
# ---------------------------------------------------------------------------


def test_detect_phi_in_text_content_returns_empty_for_clean_content():
    with (
        patch("phi_scan.detection_coordinator.detect_phi_with_regex", return_value=[]),
        patch("phi_scan.detection_coordinator.detect_phi_with_nlp", return_value=[]),
        patch(
            "phi_scan.detection_coordinator.detect_phi_in_structured_content",
            return_value=[],
        ),
    ):
        result = detect_phi_in_text_content("no phi here", _FAKE_FILE_PATH)

    assert result == []


def test_detect_phi_in_text_content_aggregates_findings_from_all_layers():
    regex_finding = _make_finding(
        value_hash=compute_value_hash("regex-val"),
        detection_layer=DetectionLayer.REGEX,
    )
    nlp_finding = _make_finding(
        value_hash=compute_value_hash("nlp-val"),
        line_number=_LINE_TWO,
        detection_layer=DetectionLayer.NLP,
    )

    with (
        patch(
            "phi_scan.detection_coordinator.detect_phi_with_regex",
            return_value=[regex_finding],
        ),
        patch(
            "phi_scan.detection_coordinator.detect_phi_with_nlp",
            return_value=[nlp_finding],
        ),
        patch(
            "phi_scan.detection_coordinator.detect_phi_in_structured_content",
            return_value=[],
        ),
    ):
        result = detect_phi_in_text_content("content", _FAKE_FILE_PATH)

    hashes = {f.value_hash for f in result}
    assert compute_value_hash("regex-val") in hashes
    assert compute_value_hash("nlp-val") in hashes


def test_detect_phi_in_text_content_deduplicates_cross_layer_duplicates():
    shared_hash = compute_value_hash("shared-phi")
    regex_finding = _make_finding(
        value_hash=shared_hash,
        confidence=_CONFIDENCE_HIGH,
        detection_layer=DetectionLayer.REGEX,
    )
    nlp_finding = _make_finding(
        value_hash=shared_hash,
        confidence=_CONFIDENCE_MEDIUM,
        detection_layer=DetectionLayer.NLP,
    )

    with (
        patch(
            "phi_scan.detection_coordinator.detect_phi_with_regex",
            return_value=[regex_finding],
        ),
        patch(
            "phi_scan.detection_coordinator.detect_phi_with_nlp",
            return_value=[nlp_finding],
        ),
        patch(
            "phi_scan.detection_coordinator.detect_phi_in_structured_content",
            return_value=[],
        ),
    ):
        result = detect_phi_in_text_content("content", _FAKE_FILE_PATH)

    findings_with_shared_hash = [f for f in result if f.value_hash == shared_hash]
    assert len(findings_with_shared_hash) == 1
    assert findings_with_shared_hash[0].detection_layer == DetectionLayer.REGEX
