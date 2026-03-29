"""Layer 3: HL7 v2 message scanner for HIPAA PHI detection (Phase 2D).

Implements ``detect_phi_in_hl7_content`` and ``is_hl7_message_format`` — the
HL7 branch of the Layer 3 structured-format scanner. Delegated to by
``detect_phi_in_structured_content`` in ``phi_scan.fhir_recognizer``.

Inspects PHI-bearing HL7 v2 segments: PID (patient identification), NK1
(next of kin), and IN1 (insurance). Field indices follow the HL7 v2.x field
numbering convention (1-based, segment-name field is index 0).

Requires the optional ``hl7`` library. If absent, ``_import_hl7_library``
raises ``MissingOptionalDependencyError`` and the caller (fhir_recognizer)
handles the graceful degradation.

Design constraints:
- Raw PHI values are never stored — only their SHA-256 hex digests (HIPAA).
- HL7 findings are attributed to ``DetectionLayer.FHIR`` (Layer 3 covers both
  FHIR R4 and HL7 v2; the enum has no separate HL7 value).
- ``detect_phi_in_hl7_segment`` is a named public function so it can be tested
  independently without parsing a full HL7 message.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from phi_scan.constants import (
    CONFIDENCE_FHIR_MIN,
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_LOW_FLOOR,
    CONFIDENCE_MEDIUM_FLOOR,
    HIPAA_REMEDIATION_GUIDANCE,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.exceptions import MissingOptionalDependencyError
from phi_scan.models import Hl7ScanContext, ScanFinding

__all__ = [
    "detect_phi_in_hl7_content",
    "detect_phi_in_hl7_segment",
    "is_hl7_message_format",
]

_logger: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_LINE_NUMBER_START: int = 1
# HL7 structural matches are schema-confirmed; confidence matches the FHIR
# layer minimum to keep Layer 3 findings in a consistent range.
_HL7_FIELD_BASE_CONFIDENCE: float = CONFIDENCE_FHIR_MIN
_HL7_INSTALL_HINT: str = (
    "HL7 v2 scanning requires the 'hl7' library — "
    "run 'pip install phi-scan[hl7]' to enable segment-level detection"
)
# HL7 v2 messages begin with the MSH (Message Header) segment.
# The | after MSH is the field separator and is always present.
_HL7_MESSAGE_START_PREFIX: str = "MSH|"
# HL7 uses an empty string for optional fields that are not present.
_HL7_MIN_FIELD_VALUE_LENGTH: int = 1
# Field index 0 in every HL7 segment is the three-character segment name.
_HL7_SEGMENT_NAME_INDEX: int = 0

# ---------------------------------------------------------------------------
# HL7 v2 segment → field-index → HIPAA PHI category registry
# ---------------------------------------------------------------------------
# Field indices follow the HL7 v2.x standard (1-based; index 0 is the segment
# name itself). Only fields that are unambiguously PHI are included.

_HL7_SEGMENT_FIELD_CATEGORIES: dict[str, dict[int, PhiCategory]] = {
    # PID — Patient Identification Segment
    "PID": {
        3: PhiCategory.MRN,  # Patient Identifier List
        5: PhiCategory.NAME,  # Patient Name
        7: PhiCategory.DATE,  # Date/Time of Birth
        11: PhiCategory.GEOGRAPHIC,  # Patient Address
        13: PhiCategory.PHONE,  # Phone Number – Home
        14: PhiCategory.PHONE,  # Phone Number – Business
        19: PhiCategory.SSN,  # SSN Number - Patient
    },
    # NK1 — Next of Kin / Associated Parties Segment
    "NK1": {
        2: PhiCategory.NAME,  # Name
        5: PhiCategory.PHONE,  # Phone Number
        6: PhiCategory.PHONE,  # Business Phone Number
    },
    # IN1 — Insurance Segment
    "IN1": {
        2: PhiCategory.HEALTH_PLAN,  # Insurance Plan ID
        16: PhiCategory.NAME,  # Name of Insured
        18: PhiCategory.DATE,  # Insured's Date of Birth
        49: PhiCategory.HEALTH_PLAN,  # Insured's ID Number
    },
}

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _import_hl7_library() -> Any:
    """Import the optional ``hl7`` library or raise MissingOptionalDependencyError.

    Centralises the single import-failure raise point so callers never need to
    catch ``ImportError`` directly.

    Returns:
        The ``hl7`` module ready for use.

    Raises:
        MissingOptionalDependencyError: If ``hl7`` is not installed.
    """
    try:
        import hl7 as hl7_lib  # type: ignore[import-not-found]

        return hl7_lib
    except ImportError as import_error:
        raise MissingOptionalDependencyError(_HL7_INSTALL_HINT) from import_error


def _compute_value_hash(text: str) -> str:
    """Return the SHA-256 hex digest of text.

    Raw PHI values are never stored — only their hashes (HIPAA audit
    requirement). The hash is computed over the UTF-8 encoding of the text.

    Args:
        text: The raw matched PHI value.

    Returns:
        64-character lowercase hex digest.
    """
    return hashlib.sha256(text.encode()).hexdigest()


def _severity_from_confidence(confidence: float) -> SeverityLevel:
    """Derive SeverityLevel from a confidence score.

    Args:
        confidence: Score in [CONFIDENCE_SCORE_MINIMUM, CONFIDENCE_SCORE_MAXIMUM].

    Returns:
        SeverityLevel for the given confidence band.
    """
    if confidence >= CONFIDENCE_HIGH_FLOOR:
        return SeverityLevel.HIGH
    if confidence >= CONFIDENCE_MEDIUM_FLOOR:
        return SeverityLevel.MEDIUM
    if confidence >= CONFIDENCE_LOW_FLOOR:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def _is_null_or_empty_hl7_value(field_value: str) -> bool:
    """Return True when an HL7 field value carries no PHI-bearing content.

    HL7 v2 uses empty strings for optional fields not present in the message.
    Skipping these avoids hashing a meaningless value.

    Args:
        field_value: String representation of the HL7 field.

    Returns:
        True if the value should be skipped; False if it should be flagged.
    """
    return len(field_value) < _HL7_MIN_FIELD_VALUE_LENGTH


def _build_hl7_finding(
    field_value: str,
    phi_category: PhiCategory,
    context: Hl7ScanContext,
) -> ScanFinding:
    """Construct a ScanFinding from a single HL7 field match.

    The raw field value is hashed immediately; only the digest is stored
    (HIPAA audit requirement).

    Args:
        field_value: Raw string content of the HL7 field.
        phi_category: HIPAA category for this field.
        context: File path and segment index for finding attribution.

    Returns:
        Immutable ScanFinding for this HL7 field detection.
    """
    confidence = _HL7_FIELD_BASE_CONFIDENCE
    line_number = context.segment_index + _LINE_NUMBER_START
    return ScanFinding(
        file_path=context.file_path,
        line_number=line_number,
        entity_type=phi_category.value,
        hipaa_category=phi_category,
        confidence=confidence,
        detection_layer=DetectionLayer.FHIR,
        value_hash=_compute_value_hash(field_value),
        severity=_severity_from_confidence(confidence),
        code_context="",
        remediation_hint=HIPAA_REMEDIATION_GUIDANCE.get(phi_category, ""),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_hl7_message_format(file_content: str) -> bool:
    """Return True if the content appears to be an HL7 v2 message.

    HL7 v2 messages always begin with an MSH segment whose first three
    characters are ``MSH`` followed immediately by the field separator ``|``.

    Args:
        file_content: Full text content of the file to inspect.

    Returns:
        True if the content begins with ``MSH|``; False otherwise.
    """
    return file_content.startswith(_HL7_MESSAGE_START_PREFIX)


def detect_phi_in_hl7_segment(
    segment: Any,
    segment_field_categories: dict[int, PhiCategory],
    context: Hl7ScanContext,
) -> list[ScanFinding]:
    """Scan one HL7 v2 segment for PHI in its known PHI-bearing fields.

    Args:
        segment: HL7 segment object from ``hl7.parse()``.
        segment_field_categories: Mapping of 1-based field indices to HIPAA
            PHI categories for this segment type.
        context: File path and segment index for finding attribution.

    Returns:
        List of ScanFinding objects, one per non-empty PHI field found.
    """
    findings: list[ScanFinding] = []
    for field_index, phi_category in segment_field_categories.items():
        try:
            field_value = str(segment[field_index])
        except IndexError:
            continue
        if _is_null_or_empty_hl7_value(field_value):
            continue
        findings.append(_build_hl7_finding(field_value, phi_category, context))
    return findings


def detect_phi_in_hl7_content(
    file_content: str,
    file_path: Path,
) -> list[ScanFinding]:
    """Scan HL7 v2 message content for PHI across all known segments.

    Parses the message with the ``hl7`` library and inspects every PID, NK1,
    and IN1 segment found. Raises ``MissingOptionalDependencyError`` if the
    ``hl7`` library is not installed.

    Args:
        file_content: Full text of the HL7 v2 message.
        file_path: Source path recorded in each finding for reporting.

    Returns:
        List of ScanFinding objects for all PHI found in the message.

    Raises:
        MissingOptionalDependencyError: If the ``hl7`` library is not installed.
    """
    hl7_lib = _import_hl7_library()
    message = hl7_lib.parse(file_content)
    findings: list[ScanFinding] = []
    for segment_index, segment in enumerate(message):
        segment_type = str(segment[_HL7_SEGMENT_NAME_INDEX])
        if segment_type not in _HL7_SEGMENT_FIELD_CATEGORIES:
            continue
        segment_field_categories = _HL7_SEGMENT_FIELD_CATEGORIES[segment_type]
        context = Hl7ScanContext(file_path=file_path, segment_index=segment_index)
        findings.extend(detect_phi_in_hl7_segment(segment, segment_field_categories, context))
    return findings
