"""Platform-aware glyph constants for the v2 terminal renderer.

Windows legacy consoles use codepage 1252 which cannot encode most Unicode
box-drawing and symbol characters.  This module checks the stdout encoding
at import time: if it supports UTF-8 (Linux, macOS, or Windows Terminal
with PYTHONUTF8=1) the full Unicode glyphs are used; otherwise ASCII-safe
fallbacks are selected.
"""

from __future__ import annotations

import sys


def _stdout_supports_utf8() -> bool:
    """Return True when stdout can encode Unicode glyphs."""
    try:
        encoding = (sys.stdout.encoding or "").lower().replace("-", "")
        return encoding in ("utf8", "utf_8")
    except (AttributeError, LookupError):
        return False


_USE_UNICODE: bool = _stdout_supports_utf8()

VIOLATION_MARKER: str = "\u26a0" if _USE_UNICODE else "[!]"
CLEAN_MARKER: str = "\u2713" if _USE_UNICODE else "[ok]"
SECTION_BAR: str = "\u258e" if _USE_UNICODE else "|"
PREVIEW_MARKER: str = "\u25b8" if _USE_UNICODE else ">"
BAR_FILLED: str = "\u2588" if _USE_UNICODE else "#"
BAR_TRACK: str = "\u2591" if _USE_UNICODE else "."
CONFIDENCE_DOT_FILLED: str = "\u25cf" if _USE_UNICODE else "*"
CONFIDENCE_DOT_EMPTY: str = "\u25cb" if _USE_UNICODE else "."
SEPARATOR: str = "\u00b7" if _USE_UNICODE else "-"
MULTIPLIER: str = "\u00d7" if _USE_UNICODE else "x"
ARROW: str = "\u2192" if _USE_UNICODE else "->"
EM_DASH: str = "\u2014" if _USE_UNICODE else "--"
EN_DASH: str = "\u2013" if _USE_UNICODE else "-"
