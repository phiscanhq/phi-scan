"""Tests for phi_scan.hl7_scanner — Layer 3 HL7 v2 PHI detection."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from phi_scan.constants import (
    CODE_CONTEXT_REDACTED_VALUE,
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
from phi_scan.hashing import compute_value_hash, severity_from_confidence
from phi_scan.hl7_scanner import (  # type: ignore[attr-defined]
    _HL7_FIELD_BASE_CONFIDENCE,
    _build_hl7_finding,
    _is_null_or_empty_hl7_value,
    detect_phi_in_hl7_content,
    detect_phi_in_hl7_segment,
    is_hl7_library_available,
    is_hl7_message_format,
)
from phi_scan.models import Hl7ScanContext

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FAKE_FILE_PATH: Path = Path("fake/test_patient.hl7")
_FAKE_MRN_VALUE: str = "MRN-TEST-12345"
_FAKE_PATIENT_NAME: str = "TestPatientName"
_FAKE_SEGMENT_TYPE: str = "PID"
_EXPECTED_MRN_HASH: str = hashlib.sha256(_FAKE_MRN_VALUE.encode()).hexdigest()
_EXPECTED_NAME_HASH: str = hashlib.sha256(_FAKE_PATIENT_NAME.encode()).hexdigest()

_SEGMENT_INDEX_ZERO: int = 0
_SEGMENT_INDEX_ONE: int = 1
_PID_FIELD_INDEX_MRN: int = 3
_PID_FIELD_INDEX_NAME: int = 5
_PID_FIELD_INDEX_DOB: int = 7
_UNKNOWN_FIELD_INDEX: int = 999

_SCORE_AT_HIGH_FLOOR: float = CONFIDENCE_HIGH_FLOOR
_SCORE_JUST_BELOW_HIGH: float = CONFIDENCE_HIGH_FLOOR - 0.01
_SCORE_AT_MEDIUM_FLOOR: float = CONFIDENCE_MEDIUM_FLOOR
_SCORE_JUST_BELOW_MEDIUM: float = CONFIDENCE_MEDIUM_FLOOR - 0.01
_SCORE_AT_LOW_FLOOR: float = CONFIDENCE_LOW_FLOOR
_SCORE_BELOW_LOW_FLOOR: float = CONFIDENCE_LOW_FLOOR - 0.01

# Minimal valid HL7 PID content — synthetic, no real patient data
_FAKE_HL7_MESSAGE: str = (
    "MSH|^~\\&|TestApp|TestFacility|TestApp|TestFacility|20230101120000||ADT^A01|MSG001|P|2.5\r"
    "PID|1||MRN-TEST-12345^^^TestFacility||TestPatientName||19900101|M\r"
)
_FAKE_FHIR_JSON: str = '{"resourceType": "Patient"}'
_EMPTY_CONTENT: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _MockHl7Segment:
    """Minimal HL7 segment stub supporting index access and IndexError."""

    def __init__(self, fields: dict[int, str]) -> None:
        self._fields = fields

    def __getitem__(self, index: int) -> str:
        if index not in self._fields:
            raise IndexError(f"No field at index {index}")
        return self._fields[index]

    def __str__(self) -> str:
        segment_name = self._fields.get(0, "UNK")
        return f"{segment_name}|field1|field2|field3"


class _MockHl7Message:
    """Minimal HL7 message stub that iterates over its segments."""

    def __init__(self, segments: list[_MockHl7Segment]) -> None:
        self._segments = segments

    def __iter__(self):
        return iter(self._segments)


def _build_pid_segment(
    mrn: str = _FAKE_MRN_VALUE,
    name: str = _FAKE_PATIENT_NAME,
) -> _MockHl7Segment:
    """Build a mock PID segment with the given MRN and patient name."""
    return _MockHl7Segment(
        {
            0: "PID",
            _PID_FIELD_INDEX_MRN: mrn,
            _PID_FIELD_INDEX_NAME: name,
        }
    )


def _build_mock_hl7_lib(message: _MockHl7Message) -> MagicMock:
    """Build a mock hl7 library whose parse() returns the given message."""
    mock_lib = MagicMock()
    mock_lib.parse.return_value = message
    return mock_lib


def _build_context(segment_index: int = _SEGMENT_INDEX_ZERO) -> Hl7ScanContext:
    """Build an Hl7ScanContext with the standard fake file path and segment text."""
    return Hl7ScanContext(
        file_path=_FAKE_FILE_PATH,
        segment_index=segment_index,
        segment_type=_FAKE_SEGMENT_TYPE,
    )


# ---------------------------------------------------------------------------
# is_hl7_message_format
# ---------------------------------------------------------------------------


def test_is_hl7_message_format_returns_true_for_msh_prefix():
    result = is_hl7_message_format(_FAKE_HL7_MESSAGE)

    assert result is True


def test_is_hl7_message_format_returns_false_for_fhir_json():
    result = is_hl7_message_format(_FAKE_FHIR_JSON)

    assert result is False


def test_is_hl7_message_format_returns_false_for_empty_string():
    result = is_hl7_message_format(_EMPTY_CONTENT)

    assert result is False


def test_is_hl7_message_format_returns_false_for_content_without_pipe():
    non_hl7_content = "MSH without pipe separator"

    result = is_hl7_message_format(non_hl7_content)

    assert result is False


# ---------------------------------------------------------------------------
# is_hl7_library_available
# ---------------------------------------------------------------------------


def test_is_hl7_library_available_returns_false_when_load_raises(monkeypatch):
    monkeypatch.setattr(
        "phi_scan.hl7_scanner._load_hl7_library",
        lambda: (_ for _ in ()).throw(MissingOptionalDependencyError("hl7 not installed")),
    )

    result = is_hl7_library_available()

    assert result is False


def test_is_hl7_library_available_returns_true_when_load_succeeds(monkeypatch):
    monkeypatch.setattr("phi_scan.hl7_scanner._load_hl7_library", lambda: object())

    result = is_hl7_library_available()

    assert result is True


# ---------------------------------------------------------------------------
# _is_null_or_empty_hl7_value
# ---------------------------------------------------------------------------


def test_is_null_or_empty_hl7_value_returns_true_for_empty_string():
    result = _is_null_or_empty_hl7_value("")

    assert result is True


def test_is_null_or_empty_hl7_value_returns_false_for_non_empty_value():
    result = _is_null_or_empty_hl7_value(_FAKE_MRN_VALUE)

    assert result is False


def test_is_null_or_empty_hl7_value_accepts_single_character():
    result = _is_null_or_empty_hl7_value("X")

    assert result is False


# ---------------------------------------------------------------------------
# compute_value_hash (shared via phi_scan.hashing)
# ---------------------------------------------------------------------------


def test_compute_value_hash_returns_64_char_hex_digest():
    result = compute_value_hash(_FAKE_MRN_VALUE)

    assert len(result) == 64
    assert result == _EXPECTED_MRN_HASH


def test_compute_value_hash_is_deterministic():
    first_result = compute_value_hash(_FAKE_MRN_VALUE)
    second_result = compute_value_hash(_FAKE_MRN_VALUE)

    assert first_result == second_result


# ---------------------------------------------------------------------------
# severity_from_confidence (shared via phi_scan.hashing)
# ---------------------------------------------------------------------------


def test_severity_from_confidence_returns_high_at_high_floor():
    result = severity_from_confidence(_SCORE_AT_HIGH_FLOOR)

    assert result == SeverityLevel.HIGH


def test_severity_from_confidence_returns_medium_just_below_high_floor():
    result = severity_from_confidence(_SCORE_JUST_BELOW_HIGH)

    assert result == SeverityLevel.MEDIUM


def test_severity_from_confidence_returns_low_just_below_medium_floor():
    result = severity_from_confidence(_SCORE_JUST_BELOW_MEDIUM)

    assert result == SeverityLevel.LOW


def test_severity_from_confidence_returns_info_below_low_floor():
    result = severity_from_confidence(_SCORE_BELOW_LOW_FLOOR)

    assert result == SeverityLevel.INFO


def test_severity_from_confidence_raises_for_negative_confidence():
    negative_confidence = -0.01

    with pytest.raises(ValueError):
        severity_from_confidence(negative_confidence)


def test_severity_from_confidence_raises_for_confidence_above_maximum():
    above_maximum_confidence = 1.01

    with pytest.raises(ValueError):
        severity_from_confidence(above_maximum_confidence)


# ---------------------------------------------------------------------------
# _build_hl7_finding
# ---------------------------------------------------------------------------


def test_build_hl7_finding_constructs_finding_with_correct_phi_category():
    context = _build_context()

    finding = _build_hl7_finding(_FAKE_MRN_VALUE, PhiCategory.MRN, context)

    assert finding.hipaa_category == PhiCategory.MRN


def test_build_hl7_finding_stores_hash_not_raw_value():
    context = _build_context()

    finding = _build_hl7_finding(_FAKE_MRN_VALUE, PhiCategory.MRN, context)

    assert finding.value_hash == _EXPECTED_MRN_HASH
    assert _FAKE_MRN_VALUE not in str(finding.value_hash)


def test_build_hl7_finding_uses_hl7_detection_layer():
    context = _build_context()

    finding = _build_hl7_finding(_FAKE_MRN_VALUE, PhiCategory.MRN, context)

    assert finding.detection_layer == DetectionLayer.HL7


def test_build_hl7_finding_computes_line_number_from_segment_index():
    context = _build_context(segment_index=_SEGMENT_INDEX_ONE)

    finding = _build_hl7_finding(_FAKE_MRN_VALUE, PhiCategory.MRN, context)

    # segment_index 1 → line_number 2 (1-indexed)
    assert finding.line_number == _SEGMENT_INDEX_ONE + 1


def test_build_hl7_finding_records_correct_file_path():
    context = _build_context()

    finding = _build_hl7_finding(_FAKE_MRN_VALUE, PhiCategory.MRN, context)

    assert finding.file_path == _FAKE_FILE_PATH


def test_build_hl7_finding_uses_segment_type_as_code_context():
    context = _build_context()

    finding = _build_hl7_finding(_FAKE_MRN_VALUE, PhiCategory.MRN, context)

    assert finding.code_context == f"{_FAKE_SEGMENT_TYPE}: {CODE_CONTEXT_REDACTED_VALUE}"


# ---------------------------------------------------------------------------
# detect_phi_in_hl7_segment
# ---------------------------------------------------------------------------


def test_detect_phi_in_hl7_segment_returns_finding_for_present_phi_field():
    segment = _build_pid_segment(mrn=_FAKE_MRN_VALUE)
    field_categories = {_PID_FIELD_INDEX_MRN: PhiCategory.MRN}
    context = _build_context()

    findings = detect_phi_in_hl7_segment(segment, field_categories, context)

    assert len(findings) == 1
    assert findings[0].hipaa_category == PhiCategory.MRN


def test_detect_phi_in_hl7_segment_skips_empty_field_value():
    segment = _MockHl7Segment({0: "PID", _PID_FIELD_INDEX_MRN: ""})
    field_categories = {_PID_FIELD_INDEX_MRN: PhiCategory.MRN}
    context = _build_context()

    findings = detect_phi_in_hl7_segment(segment, field_categories, context)

    assert findings == []


def test_detect_phi_in_hl7_segment_skips_field_that_raises_index_error():
    segment = _MockHl7Segment({0: "PID"})  # MRN field not present
    field_categories = {_PID_FIELD_INDEX_MRN: PhiCategory.MRN}
    context = _build_context()

    findings = detect_phi_in_hl7_segment(segment, field_categories, context)

    assert findings == []


def test_detect_phi_in_hl7_segment_returns_multiple_findings_for_multiple_phi_fields():
    segment = _build_pid_segment(mrn=_FAKE_MRN_VALUE, name=_FAKE_PATIENT_NAME)
    field_categories = {
        _PID_FIELD_INDEX_MRN: PhiCategory.MRN,
        _PID_FIELD_INDEX_NAME: PhiCategory.NAME,
    }
    context = _build_context()

    findings = detect_phi_in_hl7_segment(segment, field_categories, context)

    assert len(findings) == 2


# ---------------------------------------------------------------------------
# detect_phi_in_hl7_content
# ---------------------------------------------------------------------------


def test_detect_phi_in_hl7_content_raises_missing_dependency_error_when_hl7_absent(
    monkeypatch,
):
    monkeypatch.setattr(
        "phi_scan.hl7_scanner._load_hl7_library",
        lambda: (_ for _ in ()).throw(MissingOptionalDependencyError("hl7 not installed")),
    )

    with pytest.raises(MissingOptionalDependencyError):
        detect_phi_in_hl7_content(_FAKE_HL7_MESSAGE, _FAKE_FILE_PATH)


def test_detect_phi_in_hl7_content_returns_findings_for_pid_segment(monkeypatch):
    pid_segment = _build_pid_segment(mrn=_FAKE_MRN_VALUE)
    message = _MockHl7Message([pid_segment])
    mock_lib = _build_mock_hl7_lib(message)
    monkeypatch.setattr("phi_scan.hl7_scanner._load_hl7_library", lambda: mock_lib)

    findings = detect_phi_in_hl7_content(_FAKE_HL7_MESSAGE, _FAKE_FILE_PATH)

    mrn_findings = [f for f in findings if f.hipaa_category == PhiCategory.MRN]
    assert len(mrn_findings) == 1


def test_detect_phi_in_hl7_content_skips_unknown_segment_types(monkeypatch):
    unknown_segment = _MockHl7Segment({0: "ZZZ", 1: "some-value"})
    message = _MockHl7Message([unknown_segment])
    mock_lib = _build_mock_hl7_lib(message)
    monkeypatch.setattr("phi_scan.hl7_scanner._load_hl7_library", lambda: mock_lib)

    findings = detect_phi_in_hl7_content(_FAKE_HL7_MESSAGE, _FAKE_FILE_PATH)

    assert findings == []


def test_detect_phi_in_hl7_content_processes_multiple_known_segments(monkeypatch):
    pid_segment = _build_pid_segment(mrn=_FAKE_MRN_VALUE, name=_FAKE_PATIENT_NAME)
    nk1_segment = _MockHl7Segment({0: "NK1", 2: "NextOfKinTestName"})
    message = _MockHl7Message([pid_segment, nk1_segment])
    mock_lib = _build_mock_hl7_lib(message)
    monkeypatch.setattr("phi_scan.hl7_scanner._load_hl7_library", lambda: mock_lib)

    findings = detect_phi_in_hl7_content(_FAKE_HL7_MESSAGE, _FAKE_FILE_PATH)

    assert len(findings) >= 2


# ---------------------------------------------------------------------------
# HL7 confidence range validation
# ---------------------------------------------------------------------------


def test_hl7_field_base_confidence_is_within_layer_three_range():
    assert CONFIDENCE_STRUCTURED_MIN <= _HL7_FIELD_BASE_CONFIDENCE <= CONFIDENCE_STRUCTURED_MAX
