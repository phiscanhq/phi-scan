"""Plugin API v1 — stable public surface for third-party PhiScan recognizers.

This module defines the contract that third-party packages register
against the ``phi_scan.plugins`` entry-point group. The public surface
is intentionally minimal: a base class, two frozen dataclasses, and a
version constant. Internal PhiScan models are NOT exposed here so that
future refactors cannot break installed plugins.

Version-compatibility policy for v1:

    * The host declares ``PLUGIN_API_VERSION`` (currently ``"1.0"``).
    * A plugin must declare the same string on
      ``BaseRecognizer.plugin_api_version`` for the loader to accept
      it. Any other value results in the plugin being skipped with a
      WARNING.
    * The exact-match rule is deliberate — v1 rollout prioritises a
      clear compatibility boundary. Semver-range support may be added
      in a future API version once the deprecation process is in
      place; see ``docs/plugin-api-v1.md`` for the full policy.

Canonical imports::

    from phi_scan.plugin_api import (
        BaseRecognizer,
        PLUGIN_API_VERSION,
        ScanContext,
        ScanFinding,
    )

The same four names are re-exported at the ``phi_scan`` package root
for convenience; both import paths are supported and stable across
the 1.x line.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "BaseRecognizer",
    "BaseSuppressor",
    "PLUGIN_API_VERSION",
    "SUPPRESSOR_API_VERSION",
    "ScanContext",
    "ScanFinding",
    "SuppressDecision",
    "SuppressorFindingView",
]

PLUGIN_API_VERSION: str = "1.0"
SUPPRESSOR_API_VERSION: str = "1.1"

RECOGNIZER_NAME_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_]*$")
ENTITY_TYPE_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z][A-Z0-9_]*$")

MIN_CONFIDENCE_SCORE: float = 0.0
MAX_CONFIDENCE_SCORE: float = 1.0
MIN_START_OFFSET: int = 0
MIN_LINE_NUMBER: int = 1

_DEFAULT_PLUGIN_VERSION: str = "0.0.0"
_DEFAULT_PLUGIN_DESCRIPTION: str = ""

_INVALID_START_OFFSET_ERROR: str = (
    "ScanFinding.start_offset must be >= {minimum}, got {start_offset}"
)
_INVALID_END_OFFSET_ERROR: str = (
    "ScanFinding.end_offset ({end_offset}) must be strictly greater than "
    "start_offset ({start_offset})"
)
_INVALID_CONFIDENCE_ERROR: str = (
    "ScanFinding.confidence must be in [{minimum}, {maximum}], got {confidence}"
)
_INVALID_ENTITY_TYPE_ERROR: str = (
    "ScanFinding.entity_type {entity_type!r} must match pattern {pattern!r} "
    "(uppercase ASCII, starting with a letter)"
)
_INVALID_LINE_NUMBER_ERROR: str = "ScanContext.line_number must be >= {minimum}, got {line_number}"


@dataclass(frozen=True)
class ScanContext:
    """Per-line context passed to ``BaseRecognizer.detect``.

    Attributes:
        file_path: Absolute path of the file currently being scanned.
            Plugins must not open or stat this path; it is provided
            for logging and language-gating only.
        line_number: 1-indexed line number of the line being examined.
        file_extension: File extension including the leading dot (e.g.
            ``".py"``). Empty string when the file has no extension.
            Plugins use this to skip files whose language they do not
            handle.
    """

    file_path: Path
    line_number: int
    file_extension: str

    def __post_init__(self) -> None:
        if self.line_number < MIN_LINE_NUMBER:
            raise ValueError(
                _INVALID_LINE_NUMBER_ERROR.format(
                    minimum=MIN_LINE_NUMBER, line_number=self.line_number
                )
            )


@dataclass(frozen=True)
class ScanFinding:
    """A single detection emitted by a plugin recognizer.

    The dataclass validates its arguments in ``__post_init__`` so
    plugin authors see malformed findings at construction time. The
    host applies additional defensive checks at runtime (see the
    plugin-loader module for the execution-time validation rules).

    Note:
        ``end_offset`` is NOT bounds-checked against the line text
        here because the line is not part of the dataclass. The host
        validates ``end_offset <= len(line)`` at execution time and
        drops any overrunning finding with a WARNING.

    Attributes:
        entity_type: One of the uppercase entity-type strings declared
            on the recognizer's ``entity_types`` list. Must match
            ``ENTITY_TYPE_PATTERN``.
        start_offset: 0-indexed column where the match starts.
        end_offset: Exclusive 0-indexed column where the match ends.
            Must be strictly greater than ``start_offset``.
        confidence: Match confidence in [0.0, 1.0]. Host-side severity
            derivation combines this with a per-entity weight; plugins
            must not pre-inflate confidence to raise severity.
    """

    entity_type: str
    start_offset: int
    end_offset: int
    confidence: float

    def __post_init__(self) -> None:
        if not ENTITY_TYPE_PATTERN.match(self.entity_type):
            raise ValueError(
                _INVALID_ENTITY_TYPE_ERROR.format(
                    entity_type=self.entity_type,
                    pattern=ENTITY_TYPE_PATTERN.pattern,
                )
            )
        if self.start_offset < MIN_START_OFFSET:
            raise ValueError(
                _INVALID_START_OFFSET_ERROR.format(
                    minimum=MIN_START_OFFSET,
                    start_offset=self.start_offset,
                )
            )
        if self.end_offset <= self.start_offset:
            raise ValueError(
                _INVALID_END_OFFSET_ERROR.format(
                    end_offset=self.end_offset,
                    start_offset=self.start_offset,
                )
            )
        if not MIN_CONFIDENCE_SCORE <= self.confidence <= MAX_CONFIDENCE_SCORE:
            raise ValueError(
                _INVALID_CONFIDENCE_ERROR.format(
                    minimum=MIN_CONFIDENCE_SCORE,
                    maximum=MAX_CONFIDENCE_SCORE,
                    confidence=self.confidence,
                )
            )


class BaseRecognizer(ABC):
    """Abstract base class for third-party recognizer plugins.

    Subclasses declare class-level ``name``, ``entity_types``, and
    (optionally) ``version`` and ``description``. The host instantiates
    subclasses with no constructor arguments and calls ``detect`` once
    per scanned line.

    Class attribute contract:

        * ``name`` — lowercase snake_case identifier matching
          ``RECOGNIZER_NAME_PATTERN``. Used as the collision key for
          deduplicating recognizers across installed distributions.
        * ``entity_types`` — non-empty sequence of uppercase strings
          (``tuple`` preferred for immutability, ``list`` also accepted
          for backwards compatibility). Each string must match
          ``ENTITY_TYPE_PATTERN`` and be unique within the sequence.
          Every ``ScanFinding`` returned by this recognizer MUST
          declare an ``entity_type`` that appears in this sequence.
        * ``plugin_api_version`` — must equal the host's
          ``PLUGIN_API_VERSION`` constant for the plugin to be loaded.
          Defaults to ``"1.0"``.
        * ``version`` — plugin's own semantic version, informational.
          Defaults to ``"0.0.0"``.
        * ``description`` — one-line human description, informational.
          Defaults to ``""``.

    Lifecycle:

        1. The host discovers the class via the ``phi_scan.plugins``
           entry-point group at startup.
        2. The loader validates the class attributes and
           ``plugin_api_version`` and rejects any plugin whose metadata
           fails validation (logged at WARNING, never raised).
        3. The loader calls ``RecognizerClass()`` — no arguments —
           and stores the resulting instance in the plugin registry.
        4. During a scan the host calls ``detect(line, context)`` once
           per line; the recognizer returns zero or more
           ``ScanFinding`` objects.

    Plugin authors MUST NOT:

        * Read, open, or mutate files at ``context.file_path`` — it
          is supplied for language-gating and logging only.
        * Include raw PHI values in any ``ScanFinding`` — the host
          hashes the matched line slice to enforce value-hash
          consistency and the plugin never sees the hash.
        * Send any data to a remote service — PhiScan is an offline
          scanner and plugins inherit that guarantee.
    """

    name: str
    entity_types: Sequence[str]
    plugin_api_version: str = PLUGIN_API_VERSION
    version: str = _DEFAULT_PLUGIN_VERSION
    description: str = _DEFAULT_PLUGIN_DESCRIPTION

    @abstractmethod
    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        """Return ``ScanFinding`` objects for the given line.

        Args:
            line: The full text of the line, without its trailing
                newline. May be empty.
            context: Per-line metadata about where the line lives.

        Returns:
            A freshly constructed list of zero or more ``ScanFinding``
            objects. Plugins MUST return a new list on every call and
            MUST NOT retain or reuse a shared mutable list across
            invocations — the host may iterate, extend, or otherwise
            consume the returned list, and aliasing would cause findings
            from one line to bleed into another. An empty list means
            the line contains nothing this recognizer cares about.
            Raising from ``detect`` is allowed; the host catches the
            exception and drops the batch for that line with a
            WARNING-level log entry.
        """


@dataclass(frozen=True)
class SuppressorFindingView:
    """Plugin-stable view of a host finding passed to ``BaseSuppressor.evaluate``.

    Exposes only the fields a suppressor needs to make a decision. The
    raw matched value is never included — suppressors operate on
    metadata and the surrounding line text only. Host-internal fields
    (``value_hash``, ``code_context``, ``detection_layer``) are
    intentionally withheld so the API surface stays stable across
    future host refactors.

    Attributes:
        entity_type: Uppercase entity-type string of the finding.
        confidence: Host-computed confidence in [0.0, 1.0].
        line_number: 1-indexed line number of the finding.
        file_path: Path of the scanned file. Suppressors MUST NOT open
            or stat this path; it is supplied for language-gating and
            logging only.
        file_extension: File extension including the leading dot (e.g.
            ``".py"``); empty string when the file has no extension.
    """

    entity_type: str
    confidence: float
    line_number: int
    file_path: Path
    file_extension: str


@dataclass(frozen=True)
class SuppressDecision:
    """Outcome of one ``BaseSuppressor.evaluate`` call.

    Attributes:
        is_suppressed: When ``True`` the finding is dropped before the
            confidence and severity filters run. The first suppressor
            whose decision sets this to ``True`` wins; later
            suppressors for the same finding are not consulted.
        reason: Short human-readable description of why the suppressor
            chose this outcome. Logged for diagnostics and surfaced by
            future audit tooling. Plugins MUST NOT include raw PHI in
            the reason string.
    """

    is_suppressed: bool
    reason: str


class BaseSuppressor(ABC):
    """Abstract base class for third-party suppressor plugins (API v1.1).

    Suppressors run after inline ``phi-scan:ignore`` directives and
    before the confidence and severity filters. Each loaded suppressor
    is consulted once per surviving finding, in deterministic
    ``(distribution_name, entry_point_name)`` order; the first
    ``SuppressDecision`` with ``is_suppressed=True`` drops the finding.

    Class attribute contract:

        * ``name`` — lowercase snake_case identifier matching
          ``RECOGNIZER_NAME_PATTERN``. Used as the collision key for
          deduplicating suppressors across installed distributions.
        * ``plugin_api_version`` — must equal the host's
          ``SUPPRESSOR_API_VERSION`` constant (``"1.1"``) for the
          plugin to be loaded.
        * ``version`` — plugin's own semantic version, informational.
        * ``description`` — one-line human description, informational.

    Plugin authors MUST NOT:

        * Open, stat, or mutate ``finding.file_path``.
        * Send any data to a remote service.
        * Mutate the passed ``SuppressorFindingView`` or ``line`` string.
        * Include raw PHI in ``SuppressDecision.reason``.

    Raising from ``evaluate`` is allowed; the host catches the
    exception at the designated isolation boundary and treats the
    suppressor as having decided ``is_suppressed=False`` for that one
    finding. Other suppressors and findings are unaffected.
    """

    name: str
    plugin_api_version: str = SUPPRESSOR_API_VERSION
    version: str = _DEFAULT_PLUGIN_VERSION
    description: str = _DEFAULT_PLUGIN_DESCRIPTION

    @abstractmethod
    def evaluate(self, finding: SuppressorFindingView, line: str) -> SuppressDecision:
        """Decide whether ``finding`` should be suppressed.

        Args:
            finding: Plugin-stable projection of the host finding.
            line: Full text of the source line containing the finding,
                without the trailing newline. May be empty when the
                line cannot be reconstructed.

        Returns:
            A ``SuppressDecision``. ``is_suppressed=True`` drops the
            finding; ``False`` passes it through to the next
            suppressor and ultimately to the confidence and severity
            filters.
        """
