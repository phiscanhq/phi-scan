"""Layer 3: Structured healthcare format detection for HIPAA PHI (Phase 2D).

Implements ``detect_phi_in_structured_content`` — the Layer 3 delegated
function called by the detection engine. Routes content to the HL7 v2 scanner
(``phi_scan.hl7_scanner``) or the FHIR R4 field-name scanner depending on the
detected format.

FHIR R4 scanning: compiled regex patterns match JSON key-value pairs and XML
element/attribute values against a fixed set of known PHI field names
(``_FHIR_PHI_FIELD_CATEGORIES``). No ``fhir.resources`` dependency is required.

HL7 v2 scanning: delegated to ``phi_scan.hl7_scanner`` which wraps the
optional ``hl7`` library. If the library is absent a structured WARNING is
logged and an empty list is returned (graceful degradation).

Design constraints:
- Raw PHI values are never stored — only their SHA-256 hex digests (HIPAA).
- FHIR confidence is fixed at ``_FHIR_FIELD_BASE_CONFIDENCE`` (schema-confirmed
  structural match; no probabilistic scoring required).
- HL7 detection is lazy-imported to avoid coupling the module graph at load time.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from phi_scan.constants import (
    CODE_CONTEXT_REDACTED_VALUE,
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_STRUCTURED_MAX,
    CONFIDENCE_STRUCTURED_MIN,
    DetectionLayer,
    PhiCategory,
)
from phi_scan.hashing import (
    StructuredFindingRequest,
    build_structured_finding,
    compute_value_hash,
)
from phi_scan.models import ScanFinding

__all__ = ["detect_phi_in_structured_content"]

_logger: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_LINE_NUMBER_START: int = 1
# FHIR structural matches are schema-confirmed, placing them at HIGH confidence.
# CONFIDENCE_HIGH_FLOOR (0.90) falls within the Layer 3 range
# [CONFIDENCE_STRUCTURED_MIN=0.80, CONFIDENCE_STRUCTURED_MAX=0.95].
_FHIR_FIELD_BASE_CONFIDENCE: float = CONFIDENCE_HIGH_FLOOR
assert CONFIDENCE_STRUCTURED_MIN <= _FHIR_FIELD_BASE_CONFIDENCE <= CONFIDENCE_STRUCTURED_MAX, (
    f"_FHIR_FIELD_BASE_CONFIDENCE {_FHIR_FIELD_BASE_CONFIDENCE} is outside the "
    f"Layer 3 band [{CONFIDENCE_STRUCTURED_MIN}, {CONFIDENCE_STRUCTURED_MAX}]"
)
_HL7_UNAVAILABLE_WARNING: str = "HL7 v2 scanning disabled — install phi-scan[hl7] to enable"
# JSON-specific null sentinel. FHIR JSON may encode absent values as the
# string literal "null"; XML encodes absence by omitting the element entirely,
# so no XML equivalent sentinel is needed here.
_FHIR_JSON_NULL_SENTINEL: str = "null"
# Minimum number of characters a FHIR field value must have to be flagged.
# Values with fewer than 2 characters (empty strings and single-character tokens)
# are structural artefacts — field separators, placeholder markers — not PHI.
_FHIR_MIN_VALUE_LENGTH: int = 2

# ---------------------------------------------------------------------------
# FHIR R4 PHI field-name registry
# ---------------------------------------------------------------------------

# Maps FHIR R4 field names to their HIPAA Safe Harbor categories.
# Only fields that are unambiguously PHI when present are included —
# generic names like "value" and "id" are excluded to minimise false positives.
_FHIR_PHI_FIELD_CATEGORIES: dict[str, PhiCategory] = {
    # HumanName — HIPAA identifier: Name
    "family": PhiCategory.NAME,
    "given": PhiCategory.NAME,
    "prefix": PhiCategory.NAME,
    "suffix": PhiCategory.NAME,
    # Dates — HIPAA identifier: Dates (except year)
    "birthDate": PhiCategory.DATE,
    "deceasedDateTime": PhiCategory.DATE,
    "effectiveDateTime": PhiCategory.DATE,
    "onsetDateTime": PhiCategory.DATE,
    "abatementDateTime": PhiCategory.DATE,
    "recordedDate": PhiCategory.DATE,
    # Address — HIPAA identifier: Geographic data
    "line": PhiCategory.GEOGRAPHIC,
    "city": PhiCategory.GEOGRAPHIC,
    "district": PhiCategory.GEOGRAPHIC,
    "postalCode": PhiCategory.GEOGRAPHIC,
    # Contact — HIPAA identifiers: Phone / Fax / Email
    "phone": PhiCategory.PHONE,
    "fax": PhiCategory.FAX,
    "email": PhiCategory.EMAIL,
    # Patient identifiers — HIPAA identifier: MRN / Health plan
    "mrn": PhiCategory.MRN,
    "patientId": PhiCategory.MRN,
    "subscriberId": PhiCategory.HEALTH_PLAN,
    "memberId": PhiCategory.HEALTH_PLAN,
    "policyHolder": PhiCategory.NAME,
    # Provider identifiers — HIPAA identifier: Certificate/licence
    "npi": PhiCategory.CERTIFICATE,
    "dea": PhiCategory.CERTIFICATE,
    # Network identifiers — HIPAA identifier: URL / IP
    "url": PhiCategory.URL,
}

_FHIR_PHI_FIELD_NAMES: frozenset[str] = frozenset(_FHIR_PHI_FIELD_CATEGORIES)

# ---------------------------------------------------------------------------
# Compiled regex patterns for FHIR JSON and XML formats
# ---------------------------------------------------------------------------

# HL7/FHIR field names start with a letter and contain only letters and digits.
# This fragment is shared by all three scan patterns below.
_FHIR_FIELD_NAME_RE: str = r"[a-zA-Z][a-zA-Z0-9]*"

# Matches JSON key-value pairs: "fieldName": "value"
_FHIR_JSON_FIELD_PATTERN: re.Pattern[str] = re.compile(
    rf'"(?P<field>{_FHIR_FIELD_NAME_RE})"\s*:\s*"(?P<value>[^"]+)"'
)
# Matches FHIR XML element-attribute pairs: <fieldName value="...">
_FHIR_XML_ATTR_PATTERN: re.Pattern[str] = re.compile(
    rf"<(?P<field>{_FHIR_FIELD_NAME_RE})\s[^>]*\bvalue=\"(?P<value>[^\"]+)\""
)
# Matches FHIR XML text-content elements: <fieldName>value</fieldName>
_FHIR_XML_TEXT_PATTERN: re.Pattern[str] = re.compile(
    rf"<(?P<field>{_FHIR_FIELD_NAME_RE})>(?P<value>[^<]+)</(?P=field)>"
)

_FHIR_SCAN_PATTERNS: tuple[re.Pattern[str], ...] = (
    _FHIR_JSON_FIELD_PATTERN,
    _FHIR_XML_ATTR_PATTERN,
    _FHIR_XML_TEXT_PATTERN,
)


# ---------------------------------------------------------------------------
# Private data container
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FhirLineMatch:
    """A PHI field match extracted from a single line of FHIR content."""

    field_name: str
    raw_value: str
    line_number: int


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _is_null_or_empty_fhir_value(raw_value: str) -> bool:
    """Return True when a FHIR field value carries no PHI-bearing content.

    Skips explicit null sentinels and empty strings to avoid hashing
    a meaningless value and generating a misleading finding.

    Args:
        raw_value: The value string extracted from the FHIR field.

    Returns:
        True if the value should be skipped; False if it should be flagged.
    """
    return raw_value == _FHIR_JSON_NULL_SENTINEL or len(raw_value) < _FHIR_MIN_VALUE_LENGTH


def _build_fhir_finding(file_path: Path, line_match: _FhirLineMatch) -> ScanFinding:
    """Construct a ScanFinding from a FHIR field match.

    The raw matched value is hashed immediately; only the digest is stored
    (HIPAA audit requirement). Delegates hash + severity + remediation derivation
    to build_structured_finding to keep this pattern consistent across layers.

    Args:
        file_path: Source path recorded in the finding for reporting.
        line_match: Extracted field match including name, value, and line context.

    Returns:
        Immutable ScanFinding for this FHIR field detection.
    """
    phi_category = _FHIR_PHI_FIELD_CATEGORIES[line_match.field_name]
    # Store only the matched field name — never the raw line text.
    # A single FHIR line may contain multiple PHI fields; using line_text
    # would expose every other field's value regardless of how many
    # str.replace() calls are applied. The field name is sufficient for a
    # developer to locate and remediate the finding.
    code_context = f'"{line_match.field_name}": {CODE_CONTEXT_REDACTED_VALUE}'
    return build_structured_finding(
        StructuredFindingRequest(
            file_path=file_path,
            line_number=line_match.line_number,
            entity_type=line_match.field_name,
            hipaa_category=phi_category,
            confidence=_FHIR_FIELD_BASE_CONFIDENCE,
            detection_layer=DetectionLayer.FHIR,
            value_hash=compute_value_hash(line_match.raw_value),
            code_context=code_context,
        )
    )


def _extract_fhir_matches_from_line(
    line_text: str,
    line_number: int,
) -> list[_FhirLineMatch]:
    """Extract all PHI-bearing FHIR field matches from a single source line.

    Applies all three compiled patterns (JSON key-value, XML attribute,
    XML text content) and filters to field names in ``_FHIR_PHI_FIELD_NAMES``.

    Args:
        line_text: Raw text of the line being scanned.
        line_number: 1-indexed line number for attribution in findings.

    Returns:
        List of ``_FhirLineMatch`` objects for each PHI field found on the line.
    """
    line_matches: list[_FhirLineMatch] = []
    for pattern in _FHIR_SCAN_PATTERNS:
        for regex_match in pattern.finditer(line_text):
            field_name = regex_match.group("field")
            raw_value = regex_match.group("value")
            if field_name not in _FHIR_PHI_FIELD_NAMES:
                continue
            if _is_null_or_empty_fhir_value(raw_value):
                continue
            line_matches.append(
                _FhirLineMatch(
                    field_name=field_name,
                    raw_value=raw_value,
                    line_number=line_number,
                )
            )
    return line_matches


def _detect_phi_in_fhir_content(file_content: str, file_path: Path) -> list[ScanFinding]:
    """Scan FHIR R4 content for PHI field names and their values.

    Iterates line by line and applies all FHIR regex patterns. One
    ScanFinding is produced per matched PHI field per line.

    Args:
        file_content: Full text of the file to scan.
        file_path: Source path recorded in each finding for reporting.

    Returns:
        List of ScanFinding objects, one per PHI field detected.
    """
    findings: list[ScanFinding] = []
    for line_index, line_text in enumerate(file_content.splitlines()):
        line_number = line_index + _LINE_NUMBER_START
        for line_match in _extract_fhir_matches_from_line(line_text, line_number):
            findings.append(_build_fhir_finding(file_path, line_match))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_phi_in_structured_content(
    file_content: str,
    file_path: Path,
) -> list[ScanFinding]:
    """Scan structured healthcare content (FHIR R4 or HL7 v2) for PHI.

    Layer 3 of the detection engine. Routes to the HL7 v2 scanner when the
    content begins with an MSH segment, and to the FHIR R4 field-name scanner
    otherwise. HL7 scanning requires the optional ``hl7`` library; if absent a
    structured WARNING is logged and an empty list is returned.

    Args:
        file_content: Full text content of the file to scan.
        file_path: Source path recorded in each ScanFinding for reporting.

    Returns:
        List of ScanFinding objects for all PHI detected in the content.
        Returns an empty list if HL7 content is found but the library is absent.
    """
    from phi_scan import hl7_scanner  # lazy import — avoids circular dependency at load time

    if hl7_scanner.is_hl7_message_format(file_content):
        if not hl7_scanner.is_hl7_library_available():
            _logger.warning(_HL7_UNAVAILABLE_WARNING)
            return []
        return hl7_scanner.detect_phi_in_hl7_content(file_content, file_path)
    return _detect_phi_in_fhir_content(file_content, file_path)
