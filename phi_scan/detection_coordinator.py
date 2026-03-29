"""Detection coordinator — orchestrates all PHI detection layers.

Defines ``detect_phi_in_text_content``, the single entry point that wires
together the four detection layers in order (regex → NLP → FHIR/HL7 →
quasi-identifier combination) and returns a deduplicated finding list.

Design constraints enforced here:
- The coordinator body consists exclusively of delegated function calls.
- No pattern matching, entity recognition, or structural parsing may appear
  inline — every detection concern is delegated to a named function.
- file_path is attribution metadata only; no routing or dispatch is performed
  based on its value inside this module.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from pathlib import Path

from phi_scan.constants import (
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_SCORE_MAXIMUM,
    HIPAA_AGE_RESTRICTION_THRESHOLD,
    HIPAA_REMEDIATION_GUIDANCE,
    MINIMUM_QUASI_IDENTIFIER_COUNT,
    PHI_SUGGESTIVE_VARIABLE_PATTERNS,
    QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES,
    SWEENEY_REIDENTIFICATION_PERCENTAGE,
    VARIABLE_CONTEXT_CONFIDENCE_BOOST,
    DetectionLayer,
    PhiCategory,
)
from phi_scan.fhir_recognizer import detect_phi_in_structured_content
from phi_scan.hashing import compute_value_hash, severity_from_confidence
from phi_scan.models import ScanFinding
from phi_scan.nlp_detector import detect_phi_with_nlp
from phi_scan.regex_detector import detect_phi_with_regex

__all__ = [
    "deduplicate_overlapping_findings",
    "detect_phi_in_text_content",
    "detect_quasi_identifier_combination",
    "evaluate_age_geographic_combination",
    "evaluate_colocated_identifier_combination",
    "evaluate_name_date_combination",
    "evaluate_zip_dob_sex_combination",
]

_logger: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# entity_type string produced by the regex layer's age-over-threshold pattern.
# Used to identify age findings in the quasi-identifier evaluators without
# storing or inspecting the raw age value.
_AGE_OVER_THRESHOLD_ENTITY_TYPE: str = "AGE_OVER_THRESHOLD"

# Prefix written into code_context for combination findings so reviewers can
# immediately distinguish combination findings from single-identifier findings.
_COMBINATION_CODE_CONTEXT_PREFIX: str = "Quasi-identifier combination: "

# Matches the left side of assignment and key-value expressions for variable-
# name context boosting (2E.4). Captures the identifier before = or : across
# Python, JS/TS, Java, JSON, and YAML assignment styles.
_ASSIGNMENT_LEFT_SIDE_PATTERN: re.Pattern[str] = re.compile(
    r'(?:^|[\s;{,\(])"?\'?(\w+)"?\'?\s*[:=]',
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Public coordinator
# ---------------------------------------------------------------------------


def detect_phi_in_text_content(
    file_content: str,
    file_path: Path,
) -> list[ScanFinding]:
    """Orchestrate all detection layers and return deduplicated PHI findings.

    Applies layers in order: regex (Layer 1) → NLP (Layer 2) → structured
    healthcare formats (Layer 3) → quasi-identifier combination (Layer 4).
    Variable-name confidence boosting is applied before combination detection
    so that boosted scores feed the combination evaluators.

    ``file_path`` is attribution metadata only — no routing or dispatch is
    performed based on its value. Format-detection gating lives inside each
    delegated function.

    Args:
        file_content: Full decoded text content of the file to scan.
        file_path: Source path recorded in each ScanFinding for reporting.

    Returns:
        Deduplicated list of ScanFinding objects, sorted by file_path and
        line_number. Empty list when no PHI is found.
    """
    all_findings: list[ScanFinding] = []
    all_findings.extend(detect_phi_with_regex(file_content, file_path))
    all_findings.extend(detect_phi_with_nlp(file_content, file_path))
    all_findings.extend(detect_phi_in_structured_content(file_content, file_path))
    all_findings = _apply_variable_name_confidence_boost(all_findings, file_content)
    all_findings.extend(detect_quasi_identifier_combination(all_findings))
    return deduplicate_overlapping_findings(all_findings)


def deduplicate_overlapping_findings(
    findings: list[ScanFinding],
) -> list[ScanFinding]:
    """Return findings with cross-layer duplicates removed.

    Two findings are considered duplicates when they share the same file_path,
    line_number, and value_hash — meaning multiple detection layers identified
    the same underlying PHI value on the same line. The finding with the highest
    confidence is kept; ties are broken by detection layer order (regex wins
    over NLP, NLP wins over FHIR/HL7).

    Args:
        findings: All findings from all detection layers, unsorted.

    Returns:
        Deduplicated list sorted by (file_path, line_number).
    """
    best: dict[tuple[Path, int, str], ScanFinding] = {}
    for finding in findings:
        dedup_key = (finding.file_path, finding.line_number, finding.value_hash)
        existing = best.get(dedup_key)
        if existing is None or finding.confidence > existing.confidence:
            best[dedup_key] = finding
    return sorted(best.values(), key=lambda f: (str(f.file_path), f.line_number))


# ---------------------------------------------------------------------------
# Quasi-identifier combination detection (2E.11)
# ---------------------------------------------------------------------------


def detect_quasi_identifier_combination(
    findings: list[ScanFinding],
) -> list[ScanFinding]:
    """Apply all combination rules and return any triggered combination findings.

    Called after all layer findings are collected so the evaluators have full
    visibility into co-located identifiers. Returns an empty list when no
    combination rule fires. Each returned finding uses
    ``PhiCategory.QUASI_IDENTIFIER_COMBINATION`` and HIGH confidence.

    Args:
        findings: All findings from Layers 1–3, including variable-name boosts.

    Returns:
        List of combination ScanFinding objects; empty if no rule fires.
    """
    combination_findings: list[ScanFinding] = []
    combination_findings.extend(evaluate_zip_dob_sex_combination(findings))
    combination_findings.extend(evaluate_name_date_combination(findings))
    combination_findings.extend(evaluate_age_geographic_combination(findings))
    combination_findings.extend(evaluate_colocated_identifier_combination(findings))
    return combination_findings


def evaluate_zip_dob_sex_combination(
    findings: list[ScanFinding],
) -> list[ScanFinding]:
    """Return a combination finding when ZIP + date of birth appear together.

    Sweeney (2000) demonstrated that ZIP code + date of birth + sex uniquely
    re-identifies 87% of the US population. Fires at HIGH confidence even if
    each individual field scored MEDIUM or LOW.

    Args:
        findings: All layer findings for the current file.

    Returns:
        A single-element list with a QUASI_IDENTIFIER_COMBINATION finding, or
        an empty list if the combination is absent or outside the proximity window.
    """
    geographic = [f for f in findings if f.hipaa_category == PhiCategory.GEOGRAPHIC]
    dates = [f for f in findings if f.hipaa_category == PhiCategory.DATE]
    if not geographic or not dates:
        return []
    candidate_group = geographic[:1] + dates[:1]
    if not _findings_within_proximity_window(candidate_group):
        return []
    return [
        _build_combination_finding(
            source_findings=candidate_group,
            combination_label="ZIP + DOB + SEX",
            note=(
                f"ZIP code + date of birth combination re-identifies "
                f"{SWEENEY_REIDENTIFICATION_PERCENTAGE}% of the "
                "US population (Sweeney 2000). Generalize at least one field."
            ),
        )
    ]


def evaluate_name_date_combination(
    findings: list[ScanFinding],
) -> list[ScanFinding]:
    """Return a combination finding when a name and a date appear together.

    Name + any date is a well-known re-identification vector. Fires at HIGH
    confidence regardless of the individual finding scores.

    Args:
        findings: All layer findings for the current file.

    Returns:
        A single-element list with a QUASI_IDENTIFIER_COMBINATION finding, or
        an empty list if the combination is absent or outside the proximity window.
    """
    names = [f for f in findings if f.hipaa_category == PhiCategory.NAME]
    dates = [f for f in findings if f.hipaa_category == PhiCategory.DATE]
    if not names or not dates:
        return []
    candidate_group = names[:1] + dates[:1]
    if not _findings_within_proximity_window(candidate_group):
        return []
    return [
        _build_combination_finding(
            source_findings=candidate_group,
            combination_label="NAME + DATE",
            note="Name and date together are uniquely identifying. Remove or generalize one.",
        )
    ]


def evaluate_age_geographic_combination(
    findings: list[ScanFinding],
) -> list[ScanFinding]:
    """Return a combination finding when age > threshold and geographic data appear together.

    HIPAA §164.514(b)(2)(i) requires ages strictly greater than
    HIPAA_AGE_RESTRICTION_THRESHOLD to be generalized because they re-identify
    when combined with any geographic indicator.

    Args:
        findings: All layer findings for the current file.

    Returns:
        A single-element list with a QUASI_IDENTIFIER_COMBINATION finding, or
        an empty list if the combination is absent or outside the proximity window.
    """
    # entity_type "AGE_OVER_THRESHOLD" is produced by the regex layer for ages
    # strictly above HIPAA_AGE_RESTRICTION_THRESHOLD (i.e., 91+). Never compare
    # against the literal threshold value here — reference the constant.
    age_findings = [f for f in findings if f.entity_type == _AGE_OVER_THRESHOLD_ENTITY_TYPE]
    geographic = [f for f in findings if f.hipaa_category == PhiCategory.GEOGRAPHIC]
    if not age_findings or not geographic:
        return []
    candidate_group = age_findings[:1] + geographic[:1]
    if not _findings_within_proximity_window(candidate_group):
        return []
    return [
        _build_combination_finding(
            source_findings=candidate_group,
            combination_label=f"AGE_OVER_{HIPAA_AGE_RESTRICTION_THRESHOLD} + GEOGRAPHIC",
            note=(
                f"HIPAA §164.514(b)(2)(i): ages over {HIPAA_AGE_RESTRICTION_THRESHOLD} "
                "combined with geographic data re-identify individuals. "
                "Generalize the age to a range or remove the geographic field."
            ),
        )
    ]


def evaluate_colocated_identifier_combination(
    findings: list[ScanFinding],
) -> list[ScanFinding]:
    """Return a combination finding when multiple identifier categories are co-located.

    Catches arbitrary combinations of MINIMUM_QUASI_IDENTIFIER_COUNT or more
    distinct PHI categories within QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES of
    each other — a catch-all for configurations not covered by the three
    specific evaluators above.

    Args:
        findings: All layer findings for the current file.

    Returns:
        A single-element list with a QUASI_IDENTIFIER_COMBINATION finding, or
        an empty list when no qualifying window is found.
    """
    base_findings = [
        f for f in findings if f.hipaa_category != PhiCategory.QUASI_IDENTIFIER_COMBINATION
    ]
    if len(base_findings) < MINIMUM_QUASI_IDENTIFIER_COUNT:
        return []
    windowed = _find_densest_window(base_findings)
    if windowed is None:
        return []
    distinct_categories = {f.hipaa_category for f in windowed}
    if len(distinct_categories) < MINIMUM_QUASI_IDENTIFIER_COUNT:
        return []
    category_label = " + ".join(sorted(c.value.upper() for c in distinct_categories))
    return [
        _build_combination_finding(
            source_findings=list(windowed),
            combination_label=category_label,
            note=(
                f"{len(distinct_categories)} distinct PHI categories co-located "
                f"within {QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES} lines."
            ),
        )
    ]


# ---------------------------------------------------------------------------
# Variable-name confidence boosting (2E.4)
# ---------------------------------------------------------------------------


def _apply_variable_name_confidence_boost(
    findings: list[ScanFinding],
    file_content: str,
) -> list[ScanFinding]:
    """Boost confidence when a PHI finding is on a line with a PHI-suggestive variable.

    Applies a VARIABLE_CONTEXT_CONFIDENCE_BOOST delta to any finding whose
    source line contains an assignment or key-value expression whose left-hand
    side matches PHI_SUGGESTIVE_VARIABLE_PATTERNS. Covers Python, JS/TS, Java,
    JSON, and YAML assignment styles. The boosted score is capped at
    CONFIDENCE_SCORE_MAXIMUM. Severity is recomputed from the boosted score.

    Args:
        findings: Findings from all detection layers.
        file_content: Full decoded text content used to read the source line.

    Returns:
        New list with boosted findings where applicable; unaffected findings
        are returned unchanged (same object identity).
    """
    file_lines = file_content.splitlines()
    return [_boost_finding_if_phi_variable(finding, file_lines) for finding in findings]


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _boost_finding_if_phi_variable(
    finding: ScanFinding,
    file_lines: list[str],
) -> ScanFinding:
    """Return a new ScanFinding with boosted confidence, or the original if no boost applies.

    Args:
        finding: The finding to inspect.
        file_lines: All lines of the source file (0-indexed).

    Returns:
        A new ScanFinding with updated confidence and severity if the line
        contains a PHI-suggestive assignment; the original finding otherwise.
    """
    line_index = finding.line_number - 1
    if line_index < 0 or line_index >= len(file_lines):
        return finding
    if not _line_has_phi_suggestive_assignment(file_lines[line_index]):
        return finding
    boosted_confidence = min(
        finding.confidence + VARIABLE_CONTEXT_CONFIDENCE_BOOST,
        CONFIDENCE_SCORE_MAXIMUM,
    )
    return dataclasses.replace(
        finding,
        confidence=boosted_confidence,
        severity=severity_from_confidence(boosted_confidence),
    )


def _line_has_phi_suggestive_assignment(line: str) -> bool:
    """Return True if the line contains a PHI-suggestive variable or key name.

    Extracts the left-hand side of assignment and key-value expressions using
    _ASSIGNMENT_LEFT_SIDE_PATTERN, then checks whether any captured identifier
    contains a substring from PHI_SUGGESTIVE_VARIABLE_PATTERNS.

    Args:
        line: A single source line to inspect.

    Returns:
        True if a PHI-suggestive identifier appears on the assignment left side.
    """
    line_lower = line.lower()
    for match in _ASSIGNMENT_LEFT_SIDE_PATTERN.finditer(line_lower):
        variable_name = match.group(1)
        if any(pattern in variable_name for pattern in PHI_SUGGESTIVE_VARIABLE_PATTERNS):
            return True
    return False


def _findings_within_proximity_window(findings: list[ScanFinding]) -> bool:
    """Return True if all findings fall within QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES.

    Args:
        findings: A group of findings to check for proximity.

    Returns:
        True if the distance between the lowest and highest line number is
        within QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES; False otherwise.
    """
    if not findings:
        return False
    line_numbers = [f.line_number for f in findings]
    return max(line_numbers) - min(line_numbers) <= QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES


def _find_densest_window(
    findings: list[ScanFinding],
) -> list[ScanFinding] | None:
    """Find the first window of findings with the most distinct PHI categories.

    Slides a QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES-line window over the
    findings sorted by line_number. Returns the set of findings in the first
    window that contains MINIMUM_QUASI_IDENTIFIER_COUNT or more distinct
    hipaa_category values, or None if no qualifying window exists.

    Args:
        findings: Base layer findings (combination findings excluded).

    Returns:
        List of findings within the qualifying window, or None.
    """
    sorted_findings = sorted(findings, key=lambda f: f.line_number)
    for left_index, anchor in enumerate(sorted_findings):
        window_end_line = anchor.line_number + QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES
        window = [f for f in sorted_findings[left_index:] if f.line_number <= window_end_line]
        if len({f.hipaa_category for f in window}) >= MINIMUM_QUASI_IDENTIFIER_COUNT:
            return window
    return None


def _build_combination_finding(
    source_findings: list[ScanFinding],
    combination_label: str,
    note: str,
) -> ScanFinding:
    """Construct a HIGH-confidence QUASI_IDENTIFIER_COMBINATION ScanFinding.

    The value_hash is computed from the combination_label so the finding is
    deterministic and deduplicated correctly. The line_number is set to the
    minimum line number among source findings so the finding points to the
    earliest contributing identifier.

    Args:
        source_findings: The findings that triggered this combination rule.
        combination_label: Short label describing the combination (e.g. "NAME + DATE").
        note: Remediation context appended after the standard guidance.

    Returns:
        An immutable ScanFinding for this combination.
    """
    confidence = CONFIDENCE_HIGH_FLOOR
    file_path = source_findings[0].file_path
    line_number = min(f.line_number for f in source_findings)
    base_hint = HIPAA_REMEDIATION_GUIDANCE.get(PhiCategory.QUASI_IDENTIFIER_COMBINATION, "")
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=combination_label,
        hipaa_category=PhiCategory.QUASI_IDENTIFIER_COMBINATION,
        confidence=confidence,
        detection_layer=DetectionLayer.COMBINATION,
        value_hash=compute_value_hash(combination_label),
        severity=severity_from_confidence(confidence),
        code_context=f"{_COMBINATION_CODE_CONTEXT_PREFIX}{combination_label}",
        remediation_hint=f"{base_hint} {note}".strip(),
    )
