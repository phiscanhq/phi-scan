"""Shared helpers for the report package — colours, matplotlib backend, chart rendering."""

from __future__ import annotations

import base64
import functools
import io
from typing import Protocol

from phi_scan.constants import RiskLevel
from phi_scan.logging_config import get_logger

_logger = get_logger("report")

# ---------------------------------------------------------------------------
# Canonical raw hex values (no leading #) shared between PDF and chart contexts.
# fpdf2 requires bare hex strings; matplotlib requires the "#" prefix.
# A single canonical constant is the source of truth so a colour change propagates
# to both rendering backends automatically.
# ---------------------------------------------------------------------------

_HEX_CRITICAL_RED: str = "C0392B"  # flat red — CRITICAL risk, HIGH severity, active chart bars
_HEX_HIGH_ORANGE: str = "E67E22"  # warm orange — HIGH risk, MEDIUM severity
_HEX_LOW_GREEN: str = "27AE60"  # muted green — LOW risk, LOW severity

# Risk-level colours for PDF (fpdf2 format: hex, no leading #)
_COLOUR_CRITICAL: str = _HEX_CRITICAL_RED
_COLOUR_HIGH: str = _HEX_HIGH_ORANGE
_COLOUR_MODERATE: str = "F1C40F"
_COLOUR_LOW: str = _HEX_LOW_GREEN
_COLOUR_CLEAN: str = "2ECC71"

# ---------------------------------------------------------------------------
# Chart dimensions and DPI (shared because _render_chart_to_buffer uses _CHART_DPI
# and chart builders live in charts.py; the chart geometry constants themselves
# are chart-module concerns).
# ---------------------------------------------------------------------------

_CHART_WIDTH_INCHES: float = 7.0
_CHART_HEIGHT_CATEGORY_INCHES: float = 4.0
_CHART_HEIGHT_PIE_INCHES: float = 3.5
_CHART_HEIGHT_FILES_INCHES: float = 3.5
_CHART_HEIGHT_TREND_INCHES: float = 3.0
_CHART_DPI: int = 120

# ---------------------------------------------------------------------------
# Remediation checklist — rendered by both HTML and PDF paths.
# ---------------------------------------------------------------------------

_GENERAL_REMEDIATION_CHECKLIST: tuple[str, ...] = (
    "Run `phi-scan fix --dry-run <path>` to preview synthetic replacements for all findings.",
    "Add `phi-scan scan --diff HEAD` as a required pre-commit hook via `phi-scan install-hook`.",
    "Run `phi-scan baseline create` after resolving all findings to establish a clean baseline.",
    "Enable `phi-scan scan --baseline` in CI to block only new regressions going forward.",
    "Rotate any credentials or tokens that were exposed — treat them as compromised.",
    "Review the HIPAA Safe Harbor checklist in `phi-scan explain hipaa` for each category found.",
    "Document remediation actions taken in your organisation's HIPAA risk management plan.",
)

# ---------------------------------------------------------------------------
# Hex byte-slice positions within a 6-character hex colour string (e.g. "C0392B").
# Each colour channel occupies 2 hex digits (1 byte = 8 bits = 2 hex chars).
# ---------------------------------------------------------------------------

_HEX_RED_START: int = 0
_HEX_RED_END: int = 2
_HEX_GREEN_START: int = 2
_HEX_GREEN_END: int = 4
_HEX_BLUE_START: int = 4
_HEX_BLUE_END: int = 6


class _MatplotlibFigure(Protocol):
    """Structural interface for matplotlib Figure objects used in chart rendering.

    Defines only the savefig method consumed by _render_chart_to_buffer.
    Avoids a hard type dependency on matplotlib, which is an optional reports
    dependency — the Protocol is satisfied by any object with a compatible
    savefig method regardless of import availability at type-check time.
    """

    def savefig(self, fname: object, **kwargs: object) -> None: ...


def _convert_hex_to_rgb(hex_colour: str) -> tuple[int, int, int]:
    """Convert a 6-char hex colour string to an (R, G, B) int tuple."""
    return (
        int(hex_colour[_HEX_RED_START:_HEX_RED_END], 16),
        int(hex_colour[_HEX_GREEN_START:_HEX_GREEN_END], 16),
        int(hex_colour[_HEX_BLUE_START:_HEX_BLUE_END], 16),
    )


def _get_risk_colour(risk_level: RiskLevel) -> str:
    """Return the hex colour string for a given RiskLevel."""
    colour_map: dict[RiskLevel, str] = {
        RiskLevel.CRITICAL: _COLOUR_CRITICAL,
        RiskLevel.HIGH: _COLOUR_HIGH,
        RiskLevel.MODERATE: _COLOUR_MODERATE,
        RiskLevel.LOW: _COLOUR_LOW,
        RiskLevel.CLEAN: _COLOUR_CLEAN,
    }
    return colour_map.get(risk_level, _COLOUR_LOW)


@functools.cache
def _configure_matplotlib_backend() -> None:
    """Configure the non-interactive Agg backend — executed exactly once per process.

    lru_cache with no arguments makes this a call-once function: the first
    invocation sets the backend; every subsequent call is a cache hit that
    returns immediately. Chart builders must not call this directly — it is
    called once before the chart-building block in each public report entry point
    so that individual chart builders have a single responsibility.
    """
    import matplotlib

    matplotlib.use("Agg")


def _render_chart_to_buffer(figure: _MatplotlibFigure) -> io.BytesIO:
    """Render a matplotlib Figure into an in-memory PNG buffer."""
    buffer = io.BytesIO()
    figure.savefig(buffer, format="png", bbox_inches="tight", dpi=_CHART_DPI)
    buffer.seek(0)
    return buffer


def _render_chart_to_base64(figure: _MatplotlibFigure) -> str:
    """Render a matplotlib Figure to a base64-encoded PNG string."""
    buffer = _render_chart_to_buffer(figure)
    encoded = base64.b64encode(buffer.read()).decode("ascii")
    buffer.close()
    return encoded


def _render_chart_to_bytes(figure: _MatplotlibFigure) -> bytes:
    """Render a matplotlib Figure to raw PNG bytes."""
    buffer = _render_chart_to_buffer(figure)
    png_bytes = buffer.read()
    buffer.close()
    return png_bytes
