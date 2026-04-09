"""Summary and phase UI: banner, phase separators, scan header, clean/violation panels."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from types import MappingProxyType

from rich import box as rich_box
from rich.panel import Panel
from rich.text import Text

from phi_scan import __version__
from phi_scan.constants import RiskLevel, SeverityLevel
from phi_scan.models import ScanConfig, ScanResult
from phi_scan.output.console import (
    _BANNER_FONT,
    _BANNER_GRADIENT_COLORS,
    _BANNER_PYFIGLET_MISSING_NOTE,
    _BANNER_TAGLINE_STYLE,
    _BANNER_TAGLINE_TEMPLATE,
    _BANNER_TEXT,
    _CLEAN_RESULT_ICON,
    _CLEAN_RESULT_STYLE,
    _CLEAN_RESULT_TEXT,
    _CLEAN_SUMMARY_BORDER_STYLE,
    _CLEAN_SUMMARY_FILES_LABEL,
    _CLEAN_SUMMARY_PANEL_TITLE,
    _CLEAN_SUMMARY_RISK_LABEL,
    _CLEAN_SUMMARY_STATUS_LABEL,
    _CLEAN_SUMMARY_STATUS_VALUE,
    _CLEAN_SUMMARY_TIME_LABEL,
    _COLOR_INDEX_OFFSET,
    _CONFIDENCE_FORMAT,
    _DURATION_FORMAT,
    _EXIT_CODE_CLEAN_MESSAGE,
    _EXIT_CODE_CLEAN_STYLE,
    _EXIT_CODE_VIOLATION_MESSAGE,
    _EXIT_CODE_VIOLATION_STYLE,
    _FILE_TYPE_SUMMARY_ENTRY_FORMAT,
    _FILE_TYPE_SUMMARY_MAX_EXTENSIONS,
    _FILE_TYPE_SUMMARY_OTHER_LABEL,
    _FILE_TYPE_SUMMARY_SEPARATOR,
    _FILE_TYPE_SUMMARY_STYLE,
    _FILE_TYPE_SUMMARY_ZERO_FILES_MESSAGE,
    _FILE_WORD,
    _FILE_WORD_PLURAL,
    _FINDING_WORD,
    _FINDING_WORD_PLURAL,
    _JUSTIFY_CENTER,
    _MARKUP_BLANK_LINE,
    _PANEL_BORDER_STYLE,
    _PANEL_LABEL_STYLE,
    _PHASE_SEPARATOR_AUDIT,
    _PHASE_SEPARATOR_COLLECTING,
    _PHASE_SEPARATOR_REPORT,
    _PHASE_SEPARATOR_SCANNING,
    _PHASE_SEPARATOR_STYLE,
    _RISK_LEVEL_BADGE_STYLE,
    _RISK_LEVEL_STYLE,
    _RULE_STYLE,
    _SCAN_HEADER_TITLE,
    _SEVERITY_ICON,
    _SEVERITY_INLINE_FORMAT,
    _SEVERITY_INLINE_SEPARATOR,
    _SEVERITY_STYLE,
    _SINGULAR_COUNT,
    _STYLE_BOLD,
    _STYLE_BOLD_RED,
    _STYLE_DIM,
    _SUMMARY_PANEL_TITLE,
    _TIMESTAMP_TIMESPEC,
    _VIOLATION_ALERT_BOX_STYLE,
    _VIOLATION_ALERT_ICON,
    _VIOLATION_ALERT_MESSAGE_FORMAT,
    _VIOLATION_BORDER_STYLE,
    _VIOLATION_SUMMARY_ACTION_LABEL,
    _VIOLATION_SUMMARY_ACTION_VALUE,
    _VIOLATION_SUMMARY_FILES_FORMAT,
    _VIOLATION_SUMMARY_FILES_LABEL,
    _VIOLATION_SUMMARY_FINDINGS_LABEL,
    _VIOLATION_SUMMARY_PANEL_TITLE,
    _VIOLATION_SUMMARY_RISK_LABEL,
    _VIOLATION_SUMMARY_STATUS_LABEL,
    _VIOLATION_SUMMARY_STATUS_VALUE,
    _VIOLATION_SUMMARY_TIME_LABEL,
    _ZERO_FINDINGS,
)
from phi_scan.output.console.core import get_console


def _select_banner_gradient_color(line_index: int, total_lines: int) -> str:
    """Pick a gradient color for a banner line by evenly distributing across the palette.

    Args:
        line_index: Zero-based position of the line within the banner.
        total_lines: Total number of lines in the banner.

    Returns:
        A Rich color name from _BANNER_GRADIENT_COLORS.
    """
    color_count = len(_BANNER_GRADIENT_COLORS)
    max_color_index = color_count - _COLOR_INDEX_OFFSET
    color_index = min(int(line_index * color_count / total_lines), max_color_index)
    return _BANNER_GRADIENT_COLORS[color_index]


def _build_banner_gradient_text(banner_str: str) -> Text:
    """Wrap the banner string in a Rich Text object with a cyan→blue→magenta gradient.

    Each line of the banner receives a color from _BANNER_GRADIENT_COLORS, distributed
    evenly from top to bottom. Under NO_COLOR, Rich strips ANSI codes automatically —
    the Text object renders as plain text with no color escapes.

    Args:
        banner_str: The pyfiglet ASCII art string (or plain text fallback).

    Returns:
        A Rich Text object with per-line color spans applied.
    """
    gradient_text = Text()
    lines = banner_str.splitlines()
    total_lines = max(len(lines), 1)
    for index, line in enumerate(lines):
        color = _select_banner_gradient_color(index, total_lines)
        gradient_text.append(line + "\n", style=color)
    return gradient_text


def _build_severity_inline_text(severity_counts: MappingProxyType[SeverityLevel, int]) -> str:
    """Build a single-line severity breakdown with colored emoji icons.

    Only includes levels with at least one finding, so a scan with only HIGH
    findings shows just '🔴 HIGH: 4' without trailing zero entries.

    Args:
        severity_counts: Mapping from severity level to finding count.

    Returns:
        Inline Rich markup string: '🔴 HIGH: 4    🟡 MEDIUM: 5    🟢 LOW: 3'
    """
    severity_entries = []
    for level in SeverityLevel:
        count = severity_counts.get(level, _ZERO_FINDINGS)
        if count == _ZERO_FINDINGS:
            continue
        icon = _SEVERITY_ICON.get(level, "")
        style = _SEVERITY_STYLE[level]
        count_markup = f"[{style}]{count}[/{style}]"
        severity_entries.append(
            _SEVERITY_INLINE_FORMAT.format(icon=icon, level=level.value.upper(), count=count_markup)
        )
    return _SEVERITY_INLINE_SEPARATOR.join(severity_entries)


def _build_severity_breakdown(severity_counts: MappingProxyType[SeverityLevel, int]) -> str:
    """Build a Rich markup string listing count per severity level.

    Args:
        severity_counts: Mapping from severity level to finding count.

    Returns:
        Newline-separated Rich markup lines, one per severity level.
    """
    severity_markup_lines = []
    for level in SeverityLevel:
        count = severity_counts.get(level, _ZERO_FINDINGS)
        style = _SEVERITY_STYLE[level]
        severity_markup_lines.append(
            f"[{_PANEL_LABEL_STYLE}]{level.value.title()}:[/{_PANEL_LABEL_STYLE}]"
            f" [{style}]{count}[/{style}]"
        )
    return "\n".join(severity_markup_lines)


def _format_risk_level_display(risk_level: RiskLevel) -> str:
    """Format a risk level as uppercase text for panel display.

    Centralised so the display format (uppercase) is defined once. Both
    display_summary_panel and display_violation_alert use this helper to
    avoid duplicating the .upper() transformation.

    Args:
        risk_level: The risk level to format.

    Returns:
        Uppercase string representation (e.g., "CRITICAL", "HIGH").
    """
    return risk_level.value.upper()


def _build_ascii_banner_text() -> tuple[str, bool]:
    """Return the PhiScan ASCII art string and whether pyfiglet was available.

    pyfiglet is an optional dependency. The caller is responsible for emitting
    any fallback notice to the console.

    Returns:
        Tuple of (banner text, is_pyfiglet_available). When pyfiglet is absent,
        returns (plain fallback text, False).
    """
    try:
        import pyfiglet  # noqa: PLC0415 — optional dependency, import deferred

        return str(pyfiglet.figlet_format(_BANNER_TEXT, font=_BANNER_FONT)), True
    except ImportError:
        return _BANNER_TEXT, False


def _build_summary_panel_markup(scan_result: ScanResult) -> str:
    """Build the Rich markup string for the scan summary panel.

    Args:
        scan_result: The completed scan result.

    Returns:
        Newline-separated Rich markup string with risk level, file stats, and severity.
    """
    risk_style = _RISK_LEVEL_STYLE[scan_result.risk_level]
    label_style = _PANEL_LABEL_STYLE
    duration_str = _DURATION_FORMAT.format(scan_result.scan_duration)
    return "\n".join(
        [
            f"[{label_style}]Risk Level:[/{label_style}] [{risk_style}]"
            f"{_format_risk_level_display(scan_result.risk_level)}[/{risk_style}]",
            f"[{label_style}]Files Scanned:[/{label_style}] {scan_result.files_scanned}",
            f"[{label_style}]Files with Findings:[/{label_style}]"
            f" {scan_result.files_with_findings}",
            f"[{label_style}]Scan Duration:[/{label_style}] {duration_str}",
            _MARKUP_BLANK_LINE,
            _build_severity_breakdown(scan_result.severity_counts),
        ]
    )


def _build_clean_summary_panel_markup(scan_result: ScanResult) -> str:
    """Build the Rich markup string for the clean scan summary panel.

    Args:
        scan_result: A completed scan result with zero findings.

    Returns:
        Newline-separated Rich markup string showing status, file count,
        scan time, and risk level.
    """
    label_style = _PANEL_LABEL_STYLE
    duration_str = _DURATION_FORMAT.format(scan_result.scan_duration)
    return "\n".join(
        [
            f"[{label_style}]{_CLEAN_SUMMARY_STATUS_LABEL}:[/{label_style}]"
            f"  {_CLEAN_SUMMARY_STATUS_VALUE}",
            f"[{label_style}]{_CLEAN_SUMMARY_FILES_LABEL}:[/{label_style}]"
            f"  {scan_result.files_scanned:,}",
            f"[{label_style}]{_CLEAN_SUMMARY_TIME_LABEL}:[/{label_style}]  {duration_str}",
            f"[{label_style}]{_CLEAN_SUMMARY_RISK_LABEL}:[/{label_style}]"
            f"  [{_CLEAN_RESULT_STYLE}]{_format_risk_level_display(scan_result.risk_level)}"
            f"[/{_CLEAN_RESULT_STYLE}]",
        ]
    )


def _build_violation_alert_text(scan_result: ScanResult) -> str:
    """Build the full-width alert message for the heavy-box violation banner.

    Args:
        scan_result: The completed scan result that contains violations.

    Returns:
        Rich markup string: '⚠  PHI/PII DETECTED — N findings in M files'
    """
    count = len(scan_result.findings)
    finding_word = _FINDING_WORD if count == _SINGULAR_COUNT else _FINDING_WORD_PLURAL
    files = scan_result.files_with_findings
    file_word = _FILE_WORD if files == _SINGULAR_COUNT else _FILE_WORD_PLURAL
    return _VIOLATION_ALERT_MESSAGE_FORMAT.format(
        icon=_VIOLATION_ALERT_ICON,
        count=count,
        finding_word=finding_word,
        files=files,
        file_word=file_word,
    )


def _build_violation_summary_panel_markup(scan_result: ScanResult) -> str:
    """Build the Rich markup string for the violation scan summary panel.

    Args:
        scan_result: The completed scan result with findings.

    Returns:
        Newline-separated Rich markup showing status, risk, findings, files,
        time, audit log path, and action.
    """
    label_style = _PANEL_LABEL_STYLE
    risk_level_name = scan_result.risk_level.value
    badge_style = _RISK_LEVEL_BADGE_STYLE.get(scan_result.risk_level, _STYLE_BOLD)
    duration_str = _DURATION_FORMAT.format(scan_result.scan_duration)
    severity_inline = _build_severity_inline_text(scan_result.severity_counts)
    files_line = _VIOLATION_SUMMARY_FILES_FORMAT.format(
        with_findings=scan_result.files_with_findings,
        total=scan_result.files_scanned,
    )
    return "\n".join(
        [
            f"[{label_style}]{_VIOLATION_SUMMARY_STATUS_LABEL}:[/{label_style}]"
            f"  [{_VIOLATION_ALERT_BOX_STYLE}]{_VIOLATION_SUMMARY_STATUS_VALUE}"
            f"[/{_VIOLATION_ALERT_BOX_STYLE}]",
            f"[{label_style}]{_VIOLATION_SUMMARY_RISK_LABEL}:[/{label_style}]"
            f"  [{badge_style}]{risk_level_name}[/{badge_style}]",
            f"[{label_style}]{_VIOLATION_SUMMARY_FINDINGS_LABEL}:[/{label_style}]"
            f"  {len(scan_result.findings)}  ({severity_inline})",
            f"[{label_style}]{_VIOLATION_SUMMARY_FILES_LABEL}:[/{label_style}]  {files_line}",
            f"[{label_style}]{_VIOLATION_SUMMARY_TIME_LABEL}:[/{label_style}]  {duration_str}",
            f"[{label_style}]{_VIOLATION_SUMMARY_ACTION_LABEL}:[/{label_style}]"
            f"  [{_STYLE_BOLD_RED}]{_VIOLATION_SUMMARY_ACTION_VALUE}[/{_STYLE_BOLD_RED}]",
        ]
    )


def _build_scan_header_markup(path: Path, config: ScanConfig, timestamp: str) -> str:
    """Build the Rich markup string for the scan header panel.

    Pure function — timestamp is passed in so the caller (display_scan_header)
    owns the datetime.now() side effect and this builder remains testable.

    Args:
        path: The directory or file being scanned.
        config: Active scan configuration.
        timestamp: ISO-format timestamp string to display in the header.

    Returns:
        Newline-separated Rich markup string with target, thresholds, and timestamp.
    """
    label_style = _PANEL_LABEL_STYLE
    return "\n".join(
        [
            f"[{label_style}]Target:[/{label_style}] {path}",
            f"[{label_style}]Severity threshold:[/{label_style}] {config.severity_threshold.value}",
            f"[{label_style}]Confidence threshold:[/{label_style}]"
            f" {_CONFIDENCE_FORMAT.format(config.confidence_threshold)}",
            f"[{label_style}]Timestamp:[/{label_style}] {timestamp}",
        ]
    )


def _count_files_by_extension(scan_targets: list[Path]) -> dict[str, int]:
    """Count scan targets grouped by lowercased file extension.

    Files with no extension are tallied under the 'other' bucket key so they
    surface in the summary without a misleading blank label.

    Args:
        scan_targets: Paths returned by _resolve_scan_targets.

    Returns:
        Mapping of extension string (e.g. '.py') to file count.
        The 'other' key is only present when at least one file has no extension.
    """
    counts: dict[str, int] = {}
    for file_path in scan_targets:
        extension = file_path.suffix.lower() if file_path.suffix else _FILE_TYPE_SUMMARY_OTHER_LABEL
        counts[extension] = counts.get(extension, 0) + 1
    return counts


def display_banner() -> None:
    """Render the PhiScan ASCII art banner with a cyan→blue→magenta gradient, tagline, and rule."""
    banner_text, is_pyfiglet_available = _build_ascii_banner_text()
    if not is_pyfiglet_available:
        get_console().print(_BANNER_PYFIGLET_MISSING_NOTE, style=_STYLE_DIM)
    get_console().print(_build_banner_gradient_text(banner_text))
    get_console().print(
        _BANNER_TAGLINE_TEMPLATE.format(version=__version__),
        style=_BANNER_TAGLINE_STYLE,
    )
    get_console().rule(style=_RULE_STYLE)


def display_phase_separator(title: str) -> None:
    """Render a styled console rule marking the start of a named scan phase.

    Used between the four scan stages (Collecting Files, Scanning for PHI/PII,
    Writing Audit Log, Generating Report) to give the user a clear visual cue
    that the terminal is progressing through distinct work phases.

    Args:
        title: Short human-readable phase name to embed in the rule line.
    """
    get_console().rule(title, style=_PHASE_SEPARATOR_STYLE)


def display_phase_collecting() -> None:
    """Render the 'Collecting Files' phase separator rule."""
    display_phase_separator(_PHASE_SEPARATOR_COLLECTING)


def display_phase_scanning() -> None:
    """Render the 'Scanning for PHI/PII' phase separator rule."""
    display_phase_separator(_PHASE_SEPARATOR_SCANNING)


def display_phase_audit() -> None:
    """Render the 'Writing Audit Log' phase separator rule."""
    display_phase_separator(_PHASE_SEPARATOR_AUDIT)


def display_phase_report() -> None:
    """Render the 'Generating Report' phase separator rule."""
    display_phase_separator(_PHASE_SEPARATOR_REPORT)


def display_file_type_summary(scan_targets: list[Path]) -> None:
    """Print a one-line file type breakdown after the collection phase.

    Shows up to _FILE_TYPE_SUMMARY_MAX_EXTENSIONS named extensions sorted by
    count descending. Remaining files are folded into an 'other' bucket.
    Outputs nothing if scan_targets is empty — the zero-files message is
    printed instead.

    Args:
        scan_targets: Collected file paths, as returned by _resolve_scan_targets.
    """
    if not scan_targets:
        get_console().print(_FILE_TYPE_SUMMARY_ZERO_FILES_MESSAGE, style=_FILE_TYPE_SUMMARY_STYLE)
        return
    counts = _count_files_by_extension(scan_targets)
    sorted_extensions = sorted(
        counts.items(), key=lambda extension_count_pair: extension_count_pair[1], reverse=True
    )
    top_extensions = sorted_extensions[:_FILE_TYPE_SUMMARY_MAX_EXTENSIONS]
    overflow_extensions = sorted_extensions[_FILE_TYPE_SUMMARY_MAX_EXTENSIONS:]
    overflow_count = sum(count for _, count in overflow_extensions)
    extension_entries = [
        _FILE_TYPE_SUMMARY_ENTRY_FORMAT.format(ext=ext, count=count)
        for ext, count in top_extensions
    ]
    if overflow_count:
        extension_entries.append(
            _FILE_TYPE_SUMMARY_ENTRY_FORMAT.format(
                ext=_FILE_TYPE_SUMMARY_OTHER_LABEL, count=overflow_count
            )
        )
    get_console().print(
        _FILE_TYPE_SUMMARY_SEPARATOR.join(extension_entries), style=_FILE_TYPE_SUMMARY_STYLE
    )


def display_scan_header(path: Path, config: ScanConfig) -> None:
    """Render a styled panel showing the scan target and active configuration.

    Args:
        path: The directory or file being scanned.
        config: Active scan configuration (severity threshold, confidence, etc.).
    """
    timestamp = datetime.now().isoformat(timespec=_TIMESTAMP_TIMESPEC)
    scan_header_markup = _build_scan_header_markup(path, config, timestamp)
    get_console().print(
        Panel(scan_header_markup, title=_SCAN_HEADER_TITLE, border_style=_PANEL_BORDER_STYLE)
    )


def display_summary_panel(scan_result: ScanResult) -> None:
    """Render a bordered summary panel with risk level, file stats, and severity breakdown.

    Deprecated: superseded by display_clean_summary_panel and
    display_violation_summary_panel which provide split clean/violation UI.
    Retained for test coverage only — not part of the public API.

    Args:
        scan_result: The completed scan result to summarise.
    """
    risk_style = _RISK_LEVEL_STYLE[scan_result.risk_level]
    get_console().print(
        Panel(
            _build_summary_panel_markup(scan_result),
            title=_SUMMARY_PANEL_TITLE,
            border_style=risk_style,
        )
    )


def display_clean_result() -> None:
    """Render a large green checkmark and CLEAN headline for zero-finding scans."""
    get_console().print()
    get_console().print(_CLEAN_RESULT_ICON, justify=_JUSTIFY_CENTER)
    get_console().print(
        f"[{_CLEAN_RESULT_STYLE}]{_CLEAN_RESULT_TEXT}[/{_CLEAN_RESULT_STYLE}]",
        justify=_JUSTIFY_CENTER,
    )
    get_console().print()


def display_clean_summary_panel(scan_result: ScanResult) -> None:
    """Render the green-bordered 'Scan Complete' summary panel for clean scans.

    Args:
        scan_result: A completed scan result with zero findings.
    """
    get_console().print(
        Panel(
            _build_clean_summary_panel_markup(scan_result),
            title=_CLEAN_SUMMARY_PANEL_TITLE,
            border_style=_CLEAN_SUMMARY_BORDER_STYLE,
        )
    )


def display_exit_code_message(is_clean: bool) -> None:
    """Print a colored exit code line at the end of the scan output.

    Args:
        is_clean: True for a clean scan (exit 0), False for violations (exit 1).
    """
    if is_clean:
        get_console().print(_EXIT_CODE_CLEAN_MESSAGE, style=_EXIT_CODE_CLEAN_STYLE)
    else:
        get_console().print(_EXIT_CODE_VIOLATION_MESSAGE, style=_EXIT_CODE_VIOLATION_STYLE)


def display_violation_alert(scan_result: ScanResult) -> None:
    """Render a full-width heavy-box red alert banner for violation scans.

    Uses rich.box.HEAVY (┏━━━┓ borders) and embeds the ⚠ icon, finding
    count, and affected file count directly in the panel content.

    Args:
        scan_result: The completed scan result that contains violations.
    """
    get_console().print(
        Panel(
            f"[{_VIOLATION_ALERT_BOX_STYLE}]{_build_violation_alert_text(scan_result)}"
            f"[/{_VIOLATION_ALERT_BOX_STYLE}]",
            box=rich_box.HEAVY,
            border_style=_VIOLATION_BORDER_STYLE,
            expand=True,
        )
    )


def display_risk_level_badge(scan_result: ScanResult) -> None:
    """Print a color-coded risk level badge on its own line.

    Badge styles per level:
      CRITICAL — bold white text on red background
      HIGH     — bold red text
      MODERATE — yellow text
      LOW      — dim yellow text

    Args:
        scan_result: The completed scan result whose risk level to badge.
    """
    level_name = scan_result.risk_level.value
    badge_style = _RISK_LEVEL_BADGE_STYLE.get(scan_result.risk_level, _STYLE_BOLD)
    get_console().print(f"[{badge_style}] {level_name} [/{badge_style}]")


def display_severity_inline(scan_result: ScanResult) -> None:
    """Print a single-line severity breakdown with colored emoji icons.

    Args:
        scan_result: The completed scan result.
    """
    get_console().print(_build_severity_inline_text(scan_result.severity_counts))


def display_violation_summary_panel(scan_result: ScanResult) -> None:
    """Render the risk-level-colored summary panel for violation scans.

    Args:
        scan_result: The completed scan result with findings.
    """
    risk_style = _RISK_LEVEL_STYLE[scan_result.risk_level]
    get_console().print(
        Panel(
            _build_violation_summary_panel_markup(scan_result),
            title=_VIOLATION_SUMMARY_PANEL_TITLE,
            border_style=risk_style,
        )
    )
