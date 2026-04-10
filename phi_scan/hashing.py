"""Shared PHI detection utilities: value hashing, severity scoring, and finding construction.

All three functions are used by every detection layer (regex, NLP, FHIR, HL7) to
build ``ScanFinding`` objects. Centralising them here ensures the HIPAA-critical
hash function has a single implementation, severity bands stay consistent across
all layers, and the structured-finding construction pattern (hash + severity +
remediation lookup) cannot diverge between FHIR and HL7.

This module is an intentional exception to the "no premature abstraction"
rule — the identical functions existed verbatim in four detection modules
(regex_detector, nlp_detector, fhir_recognizer, hl7_scanner) before being
extracted here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from phi_scan.constants import (
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_LOW_FLOOR,
    CONFIDENCE_MEDIUM_FLOOR,
    CONFIDENCE_SCORE_MAXIMUM,
    CONFIDENCE_SCORE_MINIMUM,
    HIPAA_REMEDIATION_GUIDANCE,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.models import ScanFinding

__all__ = [
    "StructuredFindingRequest",
    "build_structured_finding",
    "compute_value_hash",
    "severity_from_confidence",
]

_NO_REMEDIATION_HINT: str = ""


@dataclass(frozen=True)
class StructuredFindingRequest:
    """Input bundle for build_structured_finding.

    Groups the 7 layer-specific inputs required to construct a ScanFinding,
    satisfying the ≤3 argument rule for build_structured_finding.
    Callers must call compute_value_hash() before constructing this object —
    raw PHI must never be stored in a field.
    """

    file_path: Path
    line_number: int
    entity_type: str
    hipaa_category: PhiCategory
    confidence: float
    detection_layer: DetectionLayer
    value_hash: str
    code_context: str


def compute_value_hash(text: str) -> str:
    """Return the SHA-256 hex digest of text.

    Raw PHI values are never stored — only their hashes (HIPAA audit
    requirement). The hash is computed over the UTF-8 encoding of the text.

    Args:
        text: The raw matched PHI value.

    Returns:
        64-character lowercase hex digest.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def reject_out_of_range_confidence(confidence: float) -> None:
    """Raise ValueError when confidence is outside the valid [0.0, 1.0] range.

    Args:
        confidence: The confidence score to validate.

    Raises:
        ValueError: If confidence is not in [CONFIDENCE_SCORE_MINIMUM, CONFIDENCE_SCORE_MAXIMUM].
    """
    if confidence < CONFIDENCE_SCORE_MINIMUM or confidence > CONFIDENCE_SCORE_MAXIMUM:
        raise ValueError(
            f"confidence {confidence!r} is outside the valid range "
            f"[{CONFIDENCE_SCORE_MINIMUM}, {CONFIDENCE_SCORE_MAXIMUM}]"
        )


def severity_from_confidence(confidence: float) -> SeverityLevel:
    """Derive SeverityLevel from a confidence score.

    Args:
        confidence: Score in [CONFIDENCE_SCORE_MINIMUM, CONFIDENCE_SCORE_MAXIMUM].

    Returns:
        SeverityLevel for the given confidence band.

    Raises:
        ValueError: If confidence is outside [0.0, 1.0].
    """
    reject_out_of_range_confidence(confidence)
    if confidence >= CONFIDENCE_HIGH_FLOOR:
        return SeverityLevel.HIGH
    if confidence >= CONFIDENCE_MEDIUM_FLOOR:
        return SeverityLevel.MEDIUM
    if confidence >= CONFIDENCE_LOW_FLOOR:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def build_structured_finding(request: StructuredFindingRequest) -> ScanFinding:
    """Construct a ScanFinding for structured detectors (FHIR, HL7).

    Centralises severity + remediation-hint derivation so the HIPAA-critical
    operations cannot diverge between FHIR and HL7 layers. The caller is
    responsible for hashing the raw PHI value before constructing the request.

    Args:
        request: All layer-specific inputs bundled as a StructuredFindingRequest.

    Returns:
        Immutable ScanFinding with severity and remediation_hint derived from
        the request.
    """
    return ScanFinding(
        file_path=request.file_path,
        line_number=request.line_number,
        entity_type=request.entity_type,
        hipaa_category=request.hipaa_category,
        confidence=request.confidence,
        detection_layer=request.detection_layer,
        value_hash=request.value_hash,
        severity=severity_from_confidence(request.confidence),
        code_context=request.code_context,
        remediation_hint=HIPAA_REMEDIATION_GUIDANCE.get(
            request.hipaa_category, _NO_REMEDIATION_HINT
        ),
    )
