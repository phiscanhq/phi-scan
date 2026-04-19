"""Platform-aware glyph constants for the v2 terminal renderer.

Windows legacy consoles use codepage 1252 which cannot encode most Unicode
box-drawing and symbol characters.  This module detects the platform at
import time and exposes ASCII-safe fallbacks on Windows.
"""

from __future__ import annotations

import sys

_IS_WINDOWS: bool = sys.platform == "win32"

VIOLATION_MARKER: str = "[!]" if _IS_WINDOWS else "\u26a0"
CLEAN_MARKER: str = "[ok]" if _IS_WINDOWS else "\u2713"
SECTION_BAR: str = "|" if _IS_WINDOWS else "\u258e"
PREVIEW_MARKER: str = ">" if _IS_WINDOWS else "\u25b8"
BAR_FILLED: str = "#" if _IS_WINDOWS else "\u2588"
CONFIDENCE_DOT_FILLED: str = "*" if _IS_WINDOWS else "\u25cf"
CONFIDENCE_DOT_EMPTY: str = "." if _IS_WINDOWS else "\u25cb"
SEPARATOR: str = "-" if _IS_WINDOWS else "\u00b7"
MULTIPLIER: str = "x" if _IS_WINDOWS else "\u00d7"
ARROW: str = "->" if _IS_WINDOWS else "\u2192"
EM_DASH: str = "--" if _IS_WINDOWS else "\u2014"
EN_DASH: str = "-" if _IS_WINDOWS else "\u2013"
