"""Tests for phi_scan.nlp_detector — Layer 2 NLP PHI detection."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from phi_scan.constants import (
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_LOW_FLOOR,
    CONFIDENCE_MEDIUM_FLOOR,
    CONFIDENCE_NLP_MAX,
    CONFIDENCE_NLP_MIN,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.nlp_detector import (  # type: ignore[attr-defined]
    _NLP_AVAILABLE,
    _build_line_start_offsets,
    _build_nlp_finding,
    _clamp_to_nlp_range,
    _compute_value_hash,
    _NlpScanContext,
    _offset_to_line_number,
    _severity_from_confidence,
    detect_phi_with_nlp,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FAKE_FILE_PATH: Path = Path("/tmp/test_file.py")

# Presidio entity type strings — must match _PRESIDIO_ENTITY_* constants
_ENTITY_TYPE_PERSON: str = "PERSON"
_ENTITY_TYPE_LOCATION: str = "LOCATION"
_ENTITY_TYPE_GPE: str = "GPE"
_ENTITY_TYPE_DATE_TIME: str = "DATE_TIME"
_ENTITY_TYPE_ORG: str = "ORG"

# Single-line content for basic finding tests
_SINGLE_LINE_CONTENT: str = "patient_name = 'John Smith'\n"
# Character offsets for "John Smith" in _SINGLE_LINE_CONTENT
_JOHN_SMITH_START: int = 16
_JOHN_SMITH_END: int = 26

# Multi-line content for line-offset tests
_MULTILINE_CONTENT: str = "first_line = 'data'\nsecond_line = 'more'\nthird_line = 'end'\n"
# Character offset of the start of line 2 (after "first_line = 'data'\n" = 20 chars)
_SECOND_LINE_OFFSET: int = 20
# Character offset of the start of line 3 (after first two lines = 40 chars)
_THIRD_LINE_OFFSET: int = 41

# Confidence values for boundary tests
_SCORE_BELOW_NLP_MIN: float = CONFIDENCE_NLP_MIN - 0.10
_SCORE_ABOVE_NLP_MAX: float = CONFIDENCE_NLP_MAX + 0.05
_SCORE_WITHIN_RANGE: float = (CONFIDENCE_NLP_MIN + CONFIDENCE_NLP_MAX) / 2

# Expected SHA-256 of "John Smith"
_JOHN_SMITH_HASH: str = hashlib.sha256(b"John Smith").hexdigest()


def _make_fake_analyzer_result(
    entity_type: str,
    start: int,
    end: int,
    score: float,
) -> MagicMock:
    """Build a MagicMock that looks like a Presidio RecognizerResult."""
    fake_result = MagicMock()
    fake_result.entity_type = entity_type
    fake_result.start = start
    fake_result.end = end
    fake_result.score = score
    return fake_result


def _make_scan_context(
    file_content: str,
    file_path: Path = _FAKE_FILE_PATH,
) -> _NlpScanContext:
    """Build an _NlpScanContext for the given content."""
    return _NlpScanContext(
        file_path=file_path,
        file_content=file_content,
        file_lines=file_content.splitlines(),
        line_start_offsets=_build_line_start_offsets(file_content),
    )


# ---------------------------------------------------------------------------
# _clamp_to_nlp_range
# ---------------------------------------------------------------------------


class TestClampToNlpRange:
    def test_score_below_minimum_is_raised_to_minimum(self) -> None:
        clamped = _clamp_to_nlp_range(_SCORE_BELOW_NLP_MIN)

        assert clamped == CONFIDENCE_NLP_MIN

    def test_score_above_maximum_is_lowered_to_maximum(self) -> None:
        clamped = _clamp_to_nlp_range(_SCORE_ABOVE_NLP_MAX)

        assert clamped == CONFIDENCE_NLP_MAX

    def test_score_within_range_is_unchanged(self) -> None:
        clamped = _clamp_to_nlp_range(_SCORE_WITHIN_RANGE)

        assert clamped == _SCORE_WITHIN_RANGE

    def test_minimum_boundary_is_unchanged(self) -> None:
        clamped = _clamp_to_nlp_range(CONFIDENCE_NLP_MIN)

        assert clamped == CONFIDENCE_NLP_MIN

    def test_maximum_boundary_is_unchanged(self) -> None:
        clamped = _clamp_to_nlp_range(CONFIDENCE_NLP_MAX)

        assert clamped == CONFIDENCE_NLP_MAX


# ---------------------------------------------------------------------------
# _severity_from_confidence
# ---------------------------------------------------------------------------


class TestSeverityFromConfidence:
    @pytest.mark.parametrize(
        ("confidence", "expected_severity"),
        [
            (CONFIDENCE_HIGH_FLOOR, SeverityLevel.HIGH),
            (CONFIDENCE_HIGH_FLOOR + 0.05, SeverityLevel.HIGH),
            (CONFIDENCE_MEDIUM_FLOOR, SeverityLevel.MEDIUM),
            (CONFIDENCE_MEDIUM_FLOOR + 0.05, SeverityLevel.MEDIUM),
            (CONFIDENCE_LOW_FLOOR, SeverityLevel.LOW),
            (CONFIDENCE_LOW_FLOOR + 0.05, SeverityLevel.LOW),
            (CONFIDENCE_LOW_FLOOR - 0.01, SeverityLevel.INFO),
            (0.0, SeverityLevel.INFO),
        ],
    )
    def test_confidence_maps_to_expected_severity(
        self, confidence: float, expected_severity: SeverityLevel
    ) -> None:
        severity = _severity_from_confidence(confidence)

        assert severity == expected_severity


# ---------------------------------------------------------------------------
# _compute_value_hash
# ---------------------------------------------------------------------------


class TestComputeValueHash:
    def test_returns_expected_sha256_digest(self) -> None:
        computed = _compute_value_hash("John Smith")

        assert computed == _JOHN_SMITH_HASH

    def test_returns_64_character_hex_string(self) -> None:
        computed = _compute_value_hash("any text value")

        assert len(computed) == 64
        assert all(character in "0123456789abcdef" for character in computed)

    def test_different_inputs_produce_different_hashes(self) -> None:
        first_hash = _compute_value_hash("Alice")
        second_hash = _compute_value_hash("Bob")

        assert first_hash != second_hash

    def test_same_input_produces_same_hash(self) -> None:
        assert _compute_value_hash("repeat") == _compute_value_hash("repeat")


# ---------------------------------------------------------------------------
# _build_line_start_offsets
# ---------------------------------------------------------------------------


class TestBuildLineStartOffsets:
    def test_single_line_file_starts_at_zero(self) -> None:
        offsets = _build_line_start_offsets("hello\n")

        assert offsets == [0]

    def test_multiline_offsets_are_cumulative(self) -> None:
        # "abc\n" is 4 chars; "def\n" starts at 4; "ghi\n" starts at 8
        offsets = _build_line_start_offsets("abc\ndef\nghi\n")

        assert offsets == [0, 4, 8]

    def test_empty_content_returns_empty_list(self) -> None:
        offsets = _build_line_start_offsets("")

        assert offsets == []

    def test_offsets_respect_varying_line_lengths(self) -> None:
        # "a\n" = 2 chars, "bb\n" = 3 chars, "ccc\n" = 4 chars
        offsets = _build_line_start_offsets("a\nbb\nccc\n")

        assert offsets == [0, 2, 5]


# ---------------------------------------------------------------------------
# _offset_to_line_number
# ---------------------------------------------------------------------------


class TestOffsetToLineNumber:
    def test_offset_zero_is_line_one(self) -> None:
        offsets = [0, 10, 20]

        line_number = _offset_to_line_number(0, offsets)

        assert line_number == 1

    def test_offset_at_second_line_start_is_line_two(self) -> None:
        offsets = [0, 10, 20]

        line_number = _offset_to_line_number(10, offsets)

        assert line_number == 2

    def test_offset_within_second_line_is_line_two(self) -> None:
        offsets = [0, 10, 20]

        line_number = _offset_to_line_number(15, offsets)

        assert line_number == 2

    def test_offset_at_last_line_start_is_correct(self) -> None:
        offsets = [0, 10, 20]

        line_number = _offset_to_line_number(20, offsets)

        assert line_number == 3

    def test_offset_within_last_line_is_correct(self) -> None:
        offsets = [0, 10, 20]

        line_number = _offset_to_line_number(25, offsets)

        assert line_number == 3


# ---------------------------------------------------------------------------
# _build_nlp_finding
# ---------------------------------------------------------------------------


class TestBuildNlpFinding:
    def test_entity_type_is_preserved_from_analyzer_result(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.entity_type == _ENTITY_TYPE_PERSON

    def test_person_entity_maps_to_name_phi_category(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.hipaa_category == PhiCategory.NAME

    def test_org_entity_maps_to_name_phi_category(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_ORG, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.hipaa_category == PhiCategory.NAME

    def test_location_entity_maps_to_geographic_phi_category(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_LOCATION, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.hipaa_category == PhiCategory.GEOGRAPHIC

    def test_gpe_entity_maps_to_geographic_phi_category(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_GPE, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.hipaa_category == PhiCategory.GEOGRAPHIC

    def test_date_time_entity_maps_to_date_phi_category(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_DATE_TIME, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.hipaa_category == PhiCategory.DATE

    def test_detection_layer_is_nlp(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.detection_layer == DetectionLayer.NLP

    def test_value_hash_matches_matched_text_hash(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.value_hash == _JOHN_SMITH_HASH

    def test_confidence_is_clamped_to_nlp_range(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_ABOVE_NLP_MAX
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.confidence == CONFIDENCE_NLP_MAX

    def test_line_number_is_one_for_first_line_match(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.line_number == 1

    def test_code_context_is_the_source_line_stripped_of_trailing_whitespace(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.code_context == _SINGLE_LINE_CONTENT.rstrip()

    def test_file_path_is_preserved_in_finding(self) -> None:
        custom_path = Path("/project/src/records.py")
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT, file_path=custom_path)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.file_path == custom_path

    def test_line_number_is_two_for_second_line_match(self) -> None:
        content = "irrelevant = 'first'\npatient = 'Jane Doe'\n"
        # "Jane Doe" starts at offset 31 in the above string
        jane_start = content.index("Jane Doe")
        jane_end = jane_start + len("Jane Doe")
        scan_context = _make_scan_context(content)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, jane_start, jane_end, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.line_number == 2

    def test_remediation_hint_is_non_empty_for_name_category(self) -> None:
        scan_context = _make_scan_context(_SINGLE_LINE_CONTENT)
        analyzer_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )

        finding = _build_nlp_finding(scan_context, analyzer_result)

        assert finding.remediation_hint != ""


# ---------------------------------------------------------------------------
# NLP unavailable — graceful degradation
# ---------------------------------------------------------------------------


class TestNlpLayerUnavailable:
    def test_returns_empty_list_when_nlp_not_installed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", False)
        monkeypatch.setattr("phi_scan.nlp_detector._nlp_unavailable_warning_issued", False)

        findings = detect_phi_with_nlp(_SINGLE_LINE_CONTENT, _FAKE_FILE_PATH)

        assert findings == []

    def test_warning_is_logged_once_when_nlp_not_installed(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", False)
        monkeypatch.setattr("phi_scan.nlp_detector._nlp_unavailable_warning_issued", False)

        with caplog.at_level(logging.WARNING, logger="phi_scan.nlp_detector"):
            detect_phi_with_nlp(_SINGLE_LINE_CONTENT, _FAKE_FILE_PATH)
            detect_phi_with_nlp(_SINGLE_LINE_CONTENT, _FAKE_FILE_PATH)

        assert sum(1 for record in caplog.records if "phi-scan[nlp]" in record.message) == 1

    def test_warning_message_references_install_command(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", False)
        monkeypatch.setattr("phi_scan.nlp_detector._nlp_unavailable_warning_issued", False)

        with caplog.at_level(logging.WARNING, logger="phi_scan.nlp_detector"):
            detect_phi_with_nlp(_SINGLE_LINE_CONTENT, _FAKE_FILE_PATH)

        warning_messages = [r.message for r in caplog.records]
        assert any("phi-scan[nlp]" in message for message in warning_messages)


# ---------------------------------------------------------------------------
# detect_phi_with_nlp — with mocked AnalyzerEngine
# ---------------------------------------------------------------------------


class TestDetectPhiWithNlp:
    def test_returns_empty_list_when_analyzer_finds_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = []
        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", True)
        monkeypatch.setattr("phi_scan.nlp_detector._singleton_analyzer_engine", mock_engine)

        findings = detect_phi_with_nlp("x = 1\n", _FAKE_FILE_PATH)

        assert findings == []

    def test_returns_one_finding_per_analyzer_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = [fake_result]
        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", True)
        monkeypatch.setattr("phi_scan.nlp_detector._singleton_analyzer_engine", mock_engine)

        findings = detect_phi_with_nlp(_SINGLE_LINE_CONTENT, _FAKE_FILE_PATH)

        assert len(findings) == 1

    def test_finding_entity_type_matches_analyzer_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = [fake_result]
        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", True)
        monkeypatch.setattr("phi_scan.nlp_detector._singleton_analyzer_engine", mock_engine)

        findings = detect_phi_with_nlp(_SINGLE_LINE_CONTENT, _FAKE_FILE_PATH)

        assert findings[0].entity_type == _ENTITY_TYPE_PERSON

    def test_analyzer_is_called_with_correct_language(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = []
        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", True)
        monkeypatch.setattr("phi_scan.nlp_detector._singleton_analyzer_engine", mock_engine)

        detect_phi_with_nlp(_SINGLE_LINE_CONTENT, _FAKE_FILE_PATH)

        call_kwargs = mock_engine.analyze.call_args.kwargs
        assert call_kwargs["language"] == "en"

    def test_analyzer_is_called_with_correct_entities(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = []
        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", True)
        monkeypatch.setattr("phi_scan.nlp_detector._singleton_analyzer_engine", mock_engine)

        detect_phi_with_nlp(_SINGLE_LINE_CONTENT, _FAKE_FILE_PATH)

        call_kwargs = mock_engine.analyze.call_args.kwargs
        detected_entities = call_kwargs["entities"]
        assert _ENTITY_TYPE_PERSON in detected_entities
        assert _ENTITY_TYPE_LOCATION in detected_entities
        assert _ENTITY_TYPE_GPE in detected_entities
        assert _ENTITY_TYPE_DATE_TIME in detected_entities
        assert _ENTITY_TYPE_ORG in detected_entities

    def test_finding_file_path_matches_input_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = [fake_result]
        custom_path = Path("/workspace/records/patient.py")
        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", True)
        monkeypatch.setattr("phi_scan.nlp_detector._singleton_analyzer_engine", mock_engine)

        findings = detect_phi_with_nlp(_SINGLE_LINE_CONTENT, custom_path)

        assert findings[0].file_path == custom_path

    def test_finding_detection_layer_is_nlp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_PERSON, _JOHN_SMITH_START, _JOHN_SMITH_END, _SCORE_WITHIN_RANGE
        )
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = [fake_result]
        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", True)
        monkeypatch.setattr("phi_scan.nlp_detector._singleton_analyzer_engine", mock_engine)

        findings = detect_phi_with_nlp(_SINGLE_LINE_CONTENT, _FAKE_FILE_PATH)

        assert findings[0].detection_layer == DetectionLayer.NLP

    def test_multiple_results_produce_multiple_findings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        content = "name = 'John Smith'\nlocation = 'Boston'\n"
        john_start = content.index("John Smith")
        john_end = john_start + len("John Smith")
        boston_start = content.index("Boston")
        boston_end = boston_start + len("Boston")
        fake_results = [
            _make_fake_analyzer_result(
                _ENTITY_TYPE_PERSON, john_start, john_end, _SCORE_WITHIN_RANGE
            ),
            _make_fake_analyzer_result(
                _ENTITY_TYPE_GPE, boston_start, boston_end, _SCORE_WITHIN_RANGE
            ),
        ]
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = fake_results
        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", True)
        monkeypatch.setattr("phi_scan.nlp_detector._singleton_analyzer_engine", mock_engine)

        findings = detect_phi_with_nlp(content, _FAKE_FILE_PATH)

        assert len(findings) == 2

    def test_second_finding_has_correct_line_number_for_second_line(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        content = "name = 'John Smith'\nlocation = 'Boston'\n"
        boston_start = content.index("Boston")
        boston_end = boston_start + len("Boston")
        fake_result = _make_fake_analyzer_result(
            _ENTITY_TYPE_GPE, boston_start, boston_end, _SCORE_WITHIN_RANGE
        )
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = [fake_result]
        monkeypatch.setattr("phi_scan.nlp_detector._NLP_AVAILABLE", True)
        monkeypatch.setattr("phi_scan.nlp_detector._singleton_analyzer_engine", mock_engine)

        findings = detect_phi_with_nlp(content, _FAKE_FILE_PATH)

        assert findings[0].line_number == 2

    def test_nlp_available_flag_is_false_when_presidio_not_installed(self) -> None:
        # _NLP_AVAILABLE reflects the import-time state.
        # In the test environment presidio is not installed, so it must be False.
        assert _NLP_AVAILABLE is False
