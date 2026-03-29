"""Layer 2: NLP named entity recognition for HIPAA PHI detection (Phase 2C).

Implements ``detect_phi_with_nlp`` — the Layer 2 delegated function called by
``detect_phi_in_text_content`` (Phase 2E). Uses Microsoft Presidio with spaCy
``en_core_web_lg`` to detect PHI entities (PERSON, ORG, LOCATION, GPE,
DATE_TIME) in source code with contextual understanding.

Graceful degradation: if ``presidio_analyzer`` or ``spacy`` is not installed,
``detect_phi_with_nlp`` returns an empty list and logs a one-time install hint.
Enable the NLP layer with: pip install phi-scan[nlp]

Design constraints:
- Matched values are never stored — only their SHA-256 hex digests (HIPAA).
- Confidence scores are clamped to [CONFIDENCE_NLP_MIN, CONFIDENCE_NLP_MAX].
- The AnalyzerEngine is a lazy singleton — created on first call, reused
  thereafter to avoid reloading the spaCy model on every file.
"""

from __future__ import annotations

import bisect
import functools
import logging
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from phi_scan.constants import (
    CONFIDENCE_NLP_MAX,
    CONFIDENCE_NLP_MIN,
    HIPAA_REMEDIATION_GUIDANCE,
    DetectionLayer,
    PhiCategory,
)
from phi_scan.hashing import compute_value_hash, severity_from_confidence
from phi_scan.models import ScanFinding

__all__ = ["detect_phi_with_nlp"]

_logger: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency detection
# ---------------------------------------------------------------------------

try:
    from presidio_analyzer import AnalyzerEngine  # type: ignore[import-not-found]
    from presidio_analyzer.nlp_engine import (  # type: ignore[import-not-found]
        NlpEngineProvider,
    )

    _NLP_AVAILABLE: bool = True
except ImportError:
    _NLP_AVAILABLE = False

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_NLP_INSTALL_HINT: str = (
    "NLP detection layer disabled — run 'pip install phi-scan[nlp]' and "
    "'phi-scan setup' to enable named-entity recognition"
)
_NLP_LANGUAGE_CODE: str = "en"
_NLP_ENGINE_NAME: str = "spacy"
_SPACY_MODEL_NAME: str = "en_core_web_lg"
_LINE_NUMBER_START: int = 1
# Returned as code_context when an offset maps past the last line of a file.
# This cannot happen in practice (Presidio only returns offsets within the text
# it analysed) but the guard keeps the index-out-of-range path well-defined.
_EMPTY_LINE_TEXT: str = ""

# Presidio entity type names — must match AnalyzerEngine output identifiers exactly.
# These strings are defined by the Presidio library; never change them.
_PRESIDIO_ENTITY_PERSON: str = "PERSON"
_PRESIDIO_ENTITY_LOCATION: str = "LOCATION"
_PRESIDIO_ENTITY_GPE: str = "GPE"
_PRESIDIO_ENTITY_DATE_TIME: str = "DATE_TIME"
_PRESIDIO_ENTITY_ORG: str = "ORG"

_PRESIDIO_ENTITIES_TO_DETECT: tuple[str, ...] = (
    _PRESIDIO_ENTITY_PERSON,
    _PRESIDIO_ENTITY_LOCATION,
    _PRESIDIO_ENTITY_GPE,
    _PRESIDIO_ENTITY_DATE_TIME,
    _PRESIDIO_ENTITY_ORG,
)

# Maps Presidio entity types to HIPAA PHI categories.
# ORG is included because organisation names in patient-facing contexts (care
# providers, insurance plans) can constitute PHI under HIPAA Safe Harbor.
_PRESIDIO_ENTITY_TO_PHI_CATEGORY: dict[str, PhiCategory] = {
    _PRESIDIO_ENTITY_PERSON: PhiCategory.NAME,
    _PRESIDIO_ENTITY_ORG: PhiCategory.NAME,
    _PRESIDIO_ENTITY_LOCATION: PhiCategory.GEOGRAPHIC,
    _PRESIDIO_ENTITY_GPE: PhiCategory.GEOGRAPHIC,
    _PRESIDIO_ENTITY_DATE_TIME: PhiCategory.DATE,
}


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


@dataclass
class _NlpScanContext:
    """Per-file derived data passed to _build_nlp_finding.

    Bundling these four values avoids recomputing them for each RecognizerResult
    and keeps _build_nlp_finding within the 3-argument limit.
    """

    file_path: Path
    file_content: str
    file_lines: list[str]
    line_start_offsets: list[int]


@functools.lru_cache(maxsize=1)
def _create_analyzer_engine() -> Any:
    """Create and cache a Presidio AnalyzerEngine configured with spaCy en_core_web_lg.

    ``lru_cache(maxsize=1)`` acts as the lazy singleton — the spaCy model
    (~750 MB) is loaded exactly once per process lifetime and reused for every
    scanned file. Monkeypatch this function in tests to inject a mock engine.

    Returns:
        Configured AnalyzerEngine ready to analyse English source code.
    """
    nlp_configuration: dict[str, Any] = {
        "nlp_engine_name": _NLP_ENGINE_NAME,
        "models": [{"lang_code": _NLP_LANGUAGE_CODE, "model_name": _SPACY_MODEL_NAME}],
    }
    nlp_engine_provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
    spacy_nlp_engine = nlp_engine_provider.create_engine()
    return AnalyzerEngine(
        nlp_engine=spacy_nlp_engine,
        supported_languages=[_NLP_LANGUAGE_CODE],
    )


def _emit_nlp_unavailable_warning() -> None:
    """Emit a UserWarning that the NLP layer is disabled.

    Uses ``warnings.warn`` so Python's default filter deduplicates automatically
    — the message is shown at most once per call-site per process, without any
    module-level mutable flag. ``stacklevel=2`` attributes the warning to the
    ``detect_phi_with_nlp`` call rather than this internal helper.
    """
    warnings.warn(_NLP_INSTALL_HINT, UserWarning, stacklevel=2)


def _clamp_to_nlp_range(raw_score: float) -> float:
    """Clamp a Presidio score to [CONFIDENCE_NLP_MIN, CONFIDENCE_NLP_MAX].

    Presidio may return scores slightly outside the documented NLP layer range
    due to model variance. Clamping ensures ScanFinding.confidence always falls
    within the layer's declared band.

    Args:
        raw_score: Score in [0.0, 1.0] from a Presidio RecognizerResult.

    Returns:
        Score clamped to [CONFIDENCE_NLP_MIN, CONFIDENCE_NLP_MAX].
    """
    return max(CONFIDENCE_NLP_MIN, min(CONFIDENCE_NLP_MAX, raw_score))


def _build_line_start_offsets(file_content: str) -> list[int]:
    """Return the character offset of the first character on each line.

    Used to map Presidio's character-level result offsets to 1-indexed line
    numbers via bisect.

    Args:
        file_content: Full text of the source file.

    Returns:
        List where index i holds the character offset of line i+1 (1-indexed).
    """
    offsets: list[int] = []
    current_offset = 0
    for line in file_content.splitlines(keepends=True):
        offsets.append(current_offset)
        current_offset += len(line)
    return offsets


def _offset_to_line_number(character_offset: int, line_start_offsets: list[int]) -> int:
    """Convert a character offset to a 1-indexed line number.

    Args:
        character_offset: Zero-based character position in the full file content.
        line_start_offsets: Output of _build_line_start_offsets.

    Returns:
        1-indexed line number containing the character at character_offset.
    """
    # bisect_right returns the insertion point after any equal values, so
    # subtracting 1 gives the 0-based index of the line whose start is <= offset.
    line_index = bisect.bisect_right(line_start_offsets, character_offset) - 1
    return line_index + _LINE_NUMBER_START


def _build_nlp_finding(
    scan_context: _NlpScanContext,
    analyzer_result: Any,
) -> ScanFinding:
    """Construct a ScanFinding from one Presidio RecognizerResult.

    The raw matched text is hashed immediately; only the digest is stored
    (HIPAA audit requirement).

    Args:
        scan_context: File path, content, lines, and line start offsets.
        analyzer_result: RecognizerResult from AnalyzerEngine.analyze().
            Expected attributes: entity_type (str), start (int), end (int),
            score (float).

    Returns:
        Immutable ScanFinding for this NLP detection.
    """
    line_number = _offset_to_line_number(
        analyzer_result.start,
        scan_context.line_start_offsets,
    )
    line_index = line_number - _LINE_NUMBER_START
    line_text = (
        scan_context.file_lines[line_index]
        if line_index < len(scan_context.file_lines)
        else _EMPTY_LINE_TEXT
    )
    phi_category = _PRESIDIO_ENTITY_TO_PHI_CATEGORY[analyzer_result.entity_type]
    confidence = _clamp_to_nlp_range(analyzer_result.score)
    return ScanFinding(
        file_path=scan_context.file_path,
        line_number=line_number,
        entity_type=analyzer_result.entity_type,
        hipaa_category=phi_category,
        confidence=confidence,
        detection_layer=DetectionLayer.NLP,
        # The matched slice is passed directly to the hash function — no named
        # local variable is created, so the raw PHI value is never bound to a
        # name that could be accidentally referenced elsewhere in this scope.
        value_hash=compute_value_hash(
            scan_context.file_content[analyzer_result.start : analyzer_result.end]
        ),
        severity=severity_from_confidence(confidence),
        code_context=line_text.rstrip(),
        remediation_hint=HIPAA_REMEDIATION_GUIDANCE.get(phi_category, ""),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_phi_with_nlp(file_content: str, file_path: Path) -> list[ScanFinding]:
    """Scan file content for PHI using NLP named entity recognition.

    Layer 2 of the detection engine. Uses Presidio AnalyzerEngine with spaCy
    en_core_web_lg to detect PERSON, ORG, LOCATION, GPE, and DATE_TIME entities.
    Confidence scores are clamped to [CONFIDENCE_NLP_MIN, CONFIDENCE_NLP_MAX].
    Matched values are never stored — only their SHA-256 hashes (HIPAA).

    Returns an empty list and logs a one-time install hint when presidio_analyzer
    is not installed. Enable the NLP layer with: pip install phi-scan[nlp]

    Args:
        file_content: Full text content of the file to scan.
        file_path: Source path recorded in each ScanFinding for reporting.

    Returns:
        List of ScanFinding objects, one per entity detected by Presidio.
        Returns an empty list if the NLP layer is unavailable.
    """
    if not _NLP_AVAILABLE:
        _emit_nlp_unavailable_warning()
        return []
    analyzer = _create_analyzer_engine()
    analyzer_results: list[Any] = analyzer.analyze(
        text=file_content,
        language=_NLP_LANGUAGE_CODE,
        entities=_PRESIDIO_ENTITIES_TO_DETECT,
    )
    if not analyzer_results:
        return []
    scan_context = _NlpScanContext(
        file_path=file_path,
        file_content=file_content,
        file_lines=file_content.splitlines(),
        line_start_offsets=_build_line_start_offsets(file_content),
    )
    return [_build_nlp_finding(scan_context, result) for result in analyzer_results]
