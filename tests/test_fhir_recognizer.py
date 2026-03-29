"""Tests for phi_scan.fhir_recognizer — Layer 3 FHIR/HL7 PHI detection."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from phi_scan.constants import (
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_LOW_FLOOR,
    CONFIDENCE_MEDIUM_FLOOR,
    CONFIDENCE_STRUCTURED_MAX,
    CONFIDENCE_STRUCTURED_MIN,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.exceptions import MissingOptionalDependencyError
from phi_scan.fhir_recognizer import (  # type: ignore[attr-defined]
    _FHIR_FIELD_BASE_CONFIDENCE,
    _FHIR_JSON_NULL_SENTINEL,
    _REDACTED_VALUE_PLACEHOLDER,
    _build_fhir_finding,
    _detect_phi_in_fhir_content,
    _extract_fhir_matches_from_line,
    _FhirLineMatch,
    _is_null_or_empty_fhir_value,
    detect_phi_in_structured_content,
)
from phi_scan.hashing import severity_from_confidence

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FAKE_FILE_PATH: Path = Path("fake/test_patient.json")
_FAKE_FAMILY_NAME: str = "TestFamilyName"
_FAKE_BIRTH_DATE: str = "1990-01-01"
_FAKE_CITY_NAME: str = "TestCity"
_EXPECTED_FAMILY_HASH: str = hashlib.sha256(_FAKE_FAMILY_NAME.encode()).hexdigest()
_EXPECTED_BIRTH_DATE_HASH: str = hashlib.sha256(_FAKE_BIRTH_DATE.encode()).hexdigest()

_JSON_FAMILY_LINE: str = f'  "family": "{_FAKE_FAMILY_NAME}"'
_XML_ATTR_BIRTH_DATE_LINE: str = f'  <birthDate value="{_FAKE_BIRTH_DATE}"/>'
_XML_TEXT_CITY_LINE: str = f"  <city>{_FAKE_CITY_NAME}</city>"
_FHIR_JSON_NO_PHI_LINE: str = '  "resourceType": "Patient"'
_FHIR_JSON_NULL_VALUE_LINE: str = '  "family": "null"'

_LINE_NUMBER_ONE: int = 1
_LINE_NUMBER_TWO: int = 2
_SCORE_AT_HIGH_FLOOR: float = CONFIDENCE_HIGH_FLOOR
_SCORE_JUST_BELOW_HIGH: float = CONFIDENCE_HIGH_FLOOR - 0.01
_SCORE_AT_MEDIUM_FLOOR: float = CONFIDENCE_MEDIUM_FLOOR
_SCORE_JUST_BELOW_MEDIUM: float = CONFIDENCE_MEDIUM_FLOOR - 0.01
_SCORE_AT_LOW_FLOOR: float = CONFIDENCE_LOW_FLOOR
_SCORE_BELOW_LOW_FLOOR: float = CONFIDENCE_LOW_FLOOR - 0.01


# ---------------------------------------------------------------------------
# _is_null_or_empty_fhir_value
# ---------------------------------------------------------------------------


def test_is_null_or_empty_fhir_value_returns_true_for_null_sentinel():
    result = _is_null_or_empty_fhir_value(_FHIR_JSON_NULL_SENTINEL)

    assert result is True


def test_is_null_or_empty_fhir_value_returns_true_for_empty_string():
    empty_value = ""

    result = _is_null_or_empty_fhir_value(empty_value)

    assert result is True


def test_is_null_or_empty_fhir_value_returns_false_for_non_empty_value():
    result = _is_null_or_empty_fhir_value(_FAKE_FAMILY_NAME)

    assert result is False


def test_is_null_or_empty_fhir_value_returns_true_for_single_character():
    # Single chars are structural artefacts (separators, placeholders) — excluded by
    # _FHIR_MIN_VALUE_LENGTH = 2, which requires at least two characters for a meaningful value.
    single_char = "A"

    result = _is_null_or_empty_fhir_value(single_char)

    assert result is True


def test_is_null_or_empty_fhir_value_accepts_two_character_value():
    two_char_value = "AB"

    result = _is_null_or_empty_fhir_value(two_char_value)

    assert result is False


# ---------------------------------------------------------------------------
# severity_from_confidence
# ---------------------------------------------------------------------------


def testseverity_from_confidence_returns_high_at_high_floor():
    result = severity_from_confidence(_SCORE_AT_HIGH_FLOOR)

    assert result == SeverityLevel.HIGH


def testseverity_from_confidence_returns_medium_just_below_high_floor():
    result = severity_from_confidence(_SCORE_JUST_BELOW_HIGH)

    assert result == SeverityLevel.MEDIUM


def testseverity_from_confidence_returns_medium_at_medium_floor():
    result = severity_from_confidence(_SCORE_AT_MEDIUM_FLOOR)

    assert result == SeverityLevel.MEDIUM


def testseverity_from_confidence_returns_low_just_below_medium_floor():
    result = severity_from_confidence(_SCORE_JUST_BELOW_MEDIUM)

    assert result == SeverityLevel.LOW


def testseverity_from_confidence_returns_low_at_low_floor():
    result = severity_from_confidence(_SCORE_AT_LOW_FLOOR)

    assert result == SeverityLevel.LOW


def testseverity_from_confidence_returns_info_below_low_floor():
    result = severity_from_confidence(_SCORE_BELOW_LOW_FLOOR)

    assert result == SeverityLevel.INFO


# ---------------------------------------------------------------------------
# _extract_fhir_matches_from_line
# ---------------------------------------------------------------------------


def test_extract_fhir_matches_from_line_returns_match_for_json_phi_field():
    matches = _extract_fhir_matches_from_line(_JSON_FAMILY_LINE, _LINE_NUMBER_ONE)

    assert len(matches) == 1
    assert matches[0].field_name == "family"
    assert matches[0].line_number == _LINE_NUMBER_ONE
    assert matches[0].raw_value == _FAKE_FAMILY_NAME


def test_extract_fhir_matches_from_line_returns_match_for_xml_attribute_field():
    matches = _extract_fhir_matches_from_line(_XML_ATTR_BIRTH_DATE_LINE, _LINE_NUMBER_TWO)

    assert len(matches) == 1
    assert matches[0].field_name == "birthDate"
    assert matches[0].line_number == _LINE_NUMBER_TWO
    assert matches[0].raw_value == _FAKE_BIRTH_DATE


def test_extract_fhir_matches_from_line_returns_match_for_xml_text_field():
    matches = _extract_fhir_matches_from_line(_XML_TEXT_CITY_LINE, _LINE_NUMBER_ONE)

    assert len(matches) == 1
    assert matches[0].field_name == "city"
    assert matches[0].raw_value == _FAKE_CITY_NAME


def test_extract_fhir_matches_from_line_returns_empty_for_unknown_field():
    matches = _extract_fhir_matches_from_line(_FHIR_JSON_NO_PHI_LINE, _LINE_NUMBER_ONE)

    assert matches == []


def test_extract_fhir_matches_from_line_skips_null_value():
    matches = _extract_fhir_matches_from_line(_FHIR_JSON_NULL_VALUE_LINE, _LINE_NUMBER_ONE)

    assert matches == []


def test_extract_fhir_matches_from_line_preserves_line_text_in_match():
    matches = _extract_fhir_matches_from_line(_JSON_FAMILY_LINE, _LINE_NUMBER_ONE)

    assert matches[0].line_text == _JSON_FAMILY_LINE


# ---------------------------------------------------------------------------
# _build_fhir_finding
# ---------------------------------------------------------------------------


def test_build_fhir_finding_returns_finding_with_correct_category():
    line_match = _FhirLineMatch(
        field_name="family",
        raw_value=_FAKE_FAMILY_NAME,
        line_number=_LINE_NUMBER_ONE,
        line_text=_JSON_FAMILY_LINE,
    )

    finding = _build_fhir_finding(_FAKE_FILE_PATH, line_match)

    assert finding.hipaa_category == PhiCategory.NAME


def test_build_fhir_finding_stores_hash_not_raw_value():
    line_match = _FhirLineMatch(
        field_name="family",
        raw_value=_FAKE_FAMILY_NAME,
        line_number=_LINE_NUMBER_ONE,
        line_text=_JSON_FAMILY_LINE,
    )

    finding = _build_fhir_finding(_FAKE_FILE_PATH, line_match)

    assert finding.value_hash == _EXPECTED_FAMILY_HASH
    assert _FAKE_FAMILY_NAME not in str(finding.value_hash)


def test_build_fhir_finding_uses_fhir_detection_layer():
    line_match = _FhirLineMatch(
        field_name="birthDate",
        raw_value=_FAKE_BIRTH_DATE,
        line_number=_LINE_NUMBER_ONE,
        line_text=_XML_ATTR_BIRTH_DATE_LINE,
    )

    finding = _build_fhir_finding(_FAKE_FILE_PATH, line_match)

    assert finding.detection_layer == DetectionLayer.FHIR


def test_build_fhir_finding_applies_base_confidence():
    line_match = _FhirLineMatch(
        field_name="family",
        raw_value=_FAKE_FAMILY_NAME,
        line_number=_LINE_NUMBER_ONE,
        line_text=_JSON_FAMILY_LINE,
    )

    finding = _build_fhir_finding(_FAKE_FILE_PATH, line_match)

    assert finding.confidence == _FHIR_FIELD_BASE_CONFIDENCE


def test_build_fhir_finding_strips_trailing_whitespace_from_code_context():
    padded_line = _JSON_FAMILY_LINE + "   "
    line_match = _FhirLineMatch(
        field_name="family",
        raw_value=_FAKE_FAMILY_NAME,
        line_number=_LINE_NUMBER_ONE,
        line_text=padded_line,
    )

    finding = _build_fhir_finding(_FAKE_FILE_PATH, line_match)

    assert not finding.code_context.endswith(" ")


def test_build_fhir_finding_redacts_raw_value_in_code_context():
    line_match = _FhirLineMatch(
        field_name="family",
        raw_value=_FAKE_FAMILY_NAME,
        line_number=_LINE_NUMBER_ONE,
        line_text=_JSON_FAMILY_LINE,
    )

    finding = _build_fhir_finding(_FAKE_FILE_PATH, line_match)

    assert _FAKE_FAMILY_NAME not in finding.code_context
    assert _REDACTED_VALUE_PLACEHOLDER in finding.code_context


# ---------------------------------------------------------------------------
# _detect_phi_in_fhir_content
# ---------------------------------------------------------------------------


def test_detect_phi_in_fhir_content_returns_one_finding_per_phi_field():
    fhir_json = f'{{\n  "family": "{_FAKE_FAMILY_NAME}",\n  "birthDate": "{_FAKE_BIRTH_DATE}"\n}}'

    findings = _detect_phi_in_fhir_content(fhir_json, _FAKE_FILE_PATH)

    assert len(findings) == 2


def test_detect_phi_in_fhir_content_returns_empty_for_no_phi_fields():
    non_phi_json = '{\n  "resourceType": "Patient",\n  "status": "active"\n}'

    findings = _detect_phi_in_fhir_content(non_phi_json, _FAKE_FILE_PATH)

    assert findings == []


def test_detect_phi_in_fhir_content_assigns_correct_line_numbers():
    fhir_json = f'{{\n  "resourceType": "Patient",\n  "family": "{_FAKE_FAMILY_NAME}"\n}}'

    findings = _detect_phi_in_fhir_content(fhir_json, _FAKE_FILE_PATH)

    assert len(findings) == 1
    assert findings[0].line_number == 3


def test_detect_phi_in_fhir_content_records_correct_file_path():
    fhir_json = f'  "family": "{_FAKE_FAMILY_NAME}"'

    findings = _detect_phi_in_fhir_content(fhir_json, _FAKE_FILE_PATH)

    assert findings[0].file_path == _FAKE_FILE_PATH


# ---------------------------------------------------------------------------
# detect_phi_in_structured_content — routing
# ---------------------------------------------------------------------------


def test_detect_phi_in_structured_content_routes_fhir_for_json_content():
    fhir_json = f'{{"family": "{_FAKE_FAMILY_NAME}"}}'

    findings = detect_phi_in_structured_content(fhir_json, _FAKE_FILE_PATH)

    assert len(findings) == 1
    assert findings[0].hipaa_category == PhiCategory.NAME


def test_detect_phi_in_structured_content_returns_empty_for_non_phi_content():
    plain_json = '{"resourceType": "Patient", "status": "active"}'

    findings = detect_phi_in_structured_content(plain_json, _FAKE_FILE_PATH)

    assert findings == []


def test_detect_phi_in_structured_content_routes_to_hl7_for_msh_content(monkeypatch):
    hl7_content = "MSH|^~\\&|TestApp|TestFacility"
    hl7_findings = []

    monkeypatch.setattr(
        "phi_scan.hl7_scanner.is_hl7_message_format",
        lambda _content: True,
    )
    # Stub the library probe so the test does not require the hl7 package.
    monkeypatch.setattr("phi_scan.hl7_scanner._load_hl7_library", lambda: None)
    monkeypatch.setattr(
        "phi_scan.hl7_scanner.detect_phi_in_hl7_content",
        lambda _content, _path: hl7_findings,
    )

    result = detect_phi_in_structured_content(hl7_content, _FAKE_FILE_PATH)

    assert result is hl7_findings


def test_detect_phi_in_structured_content_logs_warning_and_returns_empty_when_hl7_library_missing(
    monkeypatch,
    caplog,
):
    hl7_content = "MSH|^~\\&|TestApp|TestFacility"

    monkeypatch.setattr(
        "phi_scan.hl7_scanner.is_hl7_message_format",
        lambda _content: True,
    )
    # Patch only the library probe — detect_phi_in_hl7_content must not be
    # wrapped by the catch so that scan errors propagate unmasked.
    monkeypatch.setattr(
        "phi_scan.hl7_scanner._load_hl7_library",
        lambda: (_ for _ in ()).throw(MissingOptionalDependencyError("hl7 not installed")),
    )

    with caplog.at_level(logging.WARNING, logger="phi_scan.fhir_recognizer"):
        findings = detect_phi_in_structured_content(hl7_content, _FAKE_FILE_PATH)

    assert findings == []
    assert "phi-scan[hl7]" in caplog.text


# ---------------------------------------------------------------------------
# FHIR confidence range validation
# ---------------------------------------------------------------------------


def test_fhir_field_base_confidence_is_within_layer_three_range():
    assert CONFIDENCE_STRUCTURED_MIN <= _FHIR_FIELD_BASE_CONFIDENCE <= CONFIDENCE_STRUCTURED_MAX
