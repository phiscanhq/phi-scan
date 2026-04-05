"""Inline phi-scan:ignore comment parser (Phase 2).

Parses suppression directives embedded in source file comments. Suppressed
findings are still written to the audit log with suppressed=True so compliance
teams can track intentional suppressions.

Supported directives:
    # phi-scan:ignore              — suppress all findings on this line
    # phi-scan:ignore[SSN,MRN]     — suppress only the listed entity types
    # phi-scan:ignore-next-line    — suppress all findings on the next line
    # phi-scan:ignore-file         — suppress entire file (must appear in first 5 lines)

Language-aware comment prefixes supported:
    #          Python, Ruby, Shell, YAML, TOML
    //         JavaScript, TypeScript, Java, Go, C, C++
    --         SQL, Haskell, Lua
    <!-- -->   HTML, XML (full block comment token)
    %          LaTeX, Erlang
    ;          INI, Assembly, Lisp
"""

from __future__ import annotations

import re

from phi_scan.models import ScanFinding

__all__ = [
    "FILE_SUPPRESS_SENTINEL_LINE",
    "SUPPRESS_ALL_SENTINEL",
    "is_finding_suppressed",
    "load_suppressions",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum line index (0-based) at which phi-scan:ignore-file is recognised.
# Directive must appear in the first 5 lines (indices 0–4) so scanners can
# short-circuit at file open time rather than reading the entire file.
_IGNORE_FILE_MAX_LINE_INDEX: int = 4

# Sentinel set stored at a line number when ALL entity types on that line are
# suppressed (phi-scan:ignore with no type list, or phi-scan:ignore-next-line).
SUPPRESS_ALL_SENTINEL: str = "*"

# ---------------------------------------------------------------------------
# Comment prefix patterns
# ---------------------------------------------------------------------------

# Each prefix is a regex fragment matching the comment opener for a language.
# Listed longest-first so alternation matches <!-- before < in XML.
_COMMENT_PREFIX_PATTERNS: tuple[str, ...] = (
    r"<!--\s*",  # HTML / XML
    r"//\s*",  # C-family, JS, TS, Java, Go
    r"--\s*",  # SQL, Haskell, Lua
    r"#\s*",  # Python, Ruby, Shell, YAML, TOML
    r"%\s*",  # LaTeX, Erlang
    r";\s*",  # INI, Assembly, Lisp
)

_COMMENT_PREFIX_ALTERNATIVES: str = "(?:" + "|".join(_COMMENT_PREFIX_PATTERNS) + ")"

# ---------------------------------------------------------------------------
# Compiled directive patterns
# ---------------------------------------------------------------------------

# Optional trailing HTML/XML closer — <!-- phi-scan:ignore --> has " -->" after
# the directive. The closer must be tolerated for all patterns so that HTML/XML
# inline suppressions work without a separate pattern per language.
_HTML_COMMENT_CLOSER: str = r"(?:\s*-->)?"

# phi-scan:ignore            — suppress all on this line
_PATTERN_IGNORE_LINE: re.Pattern[str] = re.compile(
    _COMMENT_PREFIX_ALTERNATIVES + r"phi-scan:ignore" + _HTML_COMMENT_CLOSER + r"\s*$",
    re.IGNORECASE,
)

# phi-scan:ignore[SSN,MRN]   — suppress specific types on this line
_PATTERN_IGNORE_LINE_TYPED: re.Pattern[str] = re.compile(
    _COMMENT_PREFIX_ALTERNATIVES + r"phi-scan:ignore\[([A-Z0-9_,\s]+)\]",
    re.IGNORECASE,
)

# phi-scan:ignore-next-line  — suppress all on the following line
_PATTERN_IGNORE_NEXT_LINE: re.Pattern[str] = re.compile(
    _COMMENT_PREFIX_ALTERNATIVES + r"phi-scan:ignore-next-line" + _HTML_COMMENT_CLOSER + r"\s*$",
    re.IGNORECASE,
)

# phi-scan:ignore-file       — suppress entire file
_PATTERN_IGNORE_FILE: re.Pattern[str] = re.compile(
    _COMMENT_PREFIX_ALTERNATIVES + r"phi-scan:ignore-file" + _HTML_COMMENT_CLOSER + r"\s*$",
    re.IGNORECASE,
)

# Separator between entity type tokens inside [...] brackets.
_TYPE_LIST_SEPARATOR: re.Pattern[str] = re.compile(r"[,\s]+")

# Sentinel line number stored in the suppression map when the entire file is
# suppressed. Callers check for this key to short-circuit per-finding lookups.
FILE_SUPPRESS_SENTINEL_LINE: int = -1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_suppressions(file_lines: list[str]) -> dict[int, set[str]]:
    """Parse inline suppression directives from the lines of a source file.

    Line numbers in the returned map are 1-indexed to match ScanFinding.line_number.
    The sentinel key -1 (``FILE_SUPPRESS_SENTINEL_LINE``) is present when a
    ``phi-scan:ignore-file`` directive was found in the first five lines, indicating
    that the entire file is suppressed.

    Args:
        file_lines: Raw lines of the source file (as returned by Path.readlines() or
            str.splitlines()). Line 1 corresponds to index 0.

    Returns:
        Mapping of 1-indexed line number → set of suppressed entity type strings.
        A set containing ``"*"`` means all entity types are suppressed on that line.
        The key ``-1`` means the entire file is suppressed.
    """
    suppression_map: dict[int, set[str]] = {}

    for line_index, raw_line in enumerate(file_lines):
        line_number = line_index + 1  # convert to 1-indexed

        if _is_ignore_file_directive(raw_line, line_index):
            suppression_map[FILE_SUPPRESS_SENTINEL_LINE] = {SUPPRESS_ALL_SENTINEL}
            # No need to parse further — entire file is suppressed.
            return suppression_map

        if _PATTERN_IGNORE_NEXT_LINE.search(raw_line):
            next_line_number = line_number + 1
            suppression_map.setdefault(next_line_number, set()).add(SUPPRESS_ALL_SENTINEL)
            continue

        typed_match = _PATTERN_IGNORE_LINE_TYPED.search(raw_line)
        if typed_match:
            entity_types = _parse_entity_type_list(typed_match.group(1))
            suppression_map.setdefault(line_number, set()).update(entity_types)
            continue

        if _PATTERN_IGNORE_LINE.search(raw_line):
            suppression_map.setdefault(line_number, set()).add(SUPPRESS_ALL_SENTINEL)

    return suppression_map


def is_finding_suppressed(finding: ScanFinding, suppression_map: dict[int, set[str]]) -> bool:
    """Return True if this finding is covered by an inline suppression directive.

    Checks file-level suppression first (O(1)), then line-level suppression.

    Args:
        finding: The finding to check.
        suppression_map: Map produced by ``load_suppressions``.

    Returns:
        True if the finding should be treated as suppressed; False otherwise.
    """
    if FILE_SUPPRESS_SENTINEL_LINE in suppression_map:
        return True

    suppressed_types = suppression_map.get(finding.line_number)
    if suppressed_types is None:
        return False

    return (
        SUPPRESS_ALL_SENTINEL in suppressed_types or finding.entity_type.upper() in suppressed_types
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _is_ignore_file_directive(raw_line: str, line_index: int) -> bool:
    """Return True if raw_line is a phi-scan:ignore-file within the first 5 lines."""
    return (
        line_index <= _IGNORE_FILE_MAX_LINE_INDEX
        and _PATTERN_IGNORE_FILE.search(raw_line) is not None
    )


def _parse_entity_type_list(type_list_text: str) -> set[str]:
    """Split and normalise the entity type tokens from a phi-scan:ignore[...] directive.

    Args:
        type_list_text: The raw text captured inside the square brackets,
            e.g. ``"SSN, MRN"`` or ``"ssn MRN"``.

    Returns:
        Set of upper-cased entity type strings, e.g. ``{"SSN", "MRN"}``.
    """
    tokens = _TYPE_LIST_SEPARATOR.split(type_list_text.strip())
    return {t.upper() for token in tokens if (t := token.strip())}
