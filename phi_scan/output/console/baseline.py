"""Baseline display functions: summary, diff, drift warning, and scan notice panels."""

from __future__ import annotations

from rich.panel import Panel

from phi_scan.baseline import BaselineDiff, BaselineSummary
from phi_scan.output.console import (
    _BASELINE_DIFF_ENTRY_ROW,
    _BASELINE_DIFF_FINDING_ROW,
    _BASELINE_DIFF_TITLE,
    _BASELINE_DRIFT_BORDER_STYLE,
    _BASELINE_DRIFT_MESSAGE,
    _BASELINE_DRIFT_TITLE,
    _BASELINE_ENTRIES_LABEL,
    _BASELINE_ENTRY_LABEL,
    _BASELINE_NEW_SECTION_HEADER,
    _BASELINE_NOTICE_BORDER_STYLE,
    _BASELINE_NOTICE_TITLE,
    _BASELINE_PERSISTING_SECTION_HEADER,
    _BASELINE_RESOLVED_SECTION_HEADER,
    _BASELINE_SCAN_CLEAN_MESSAGE,
    _BASELINE_SCAN_NOTICE_MESSAGE,
    _BASELINE_SUMMARY_BORDER_STYLE,
    _BASELINE_SUMMARY_TITLE,
    _ENTRY_PLURAL_THRESHOLD,
)
from phi_scan.output.console.core import get_console


def _format_entry_label(count: int) -> str:
    """Return 'entry' for exactly 1, 'entries' otherwise."""
    return _BASELINE_ENTRY_LABEL if count == _ENTRY_PLURAL_THRESHOLD else _BASELINE_ENTRIES_LABEL


def display_baseline_summary(summary: BaselineSummary) -> None:
    """Render a Rich summary panel for a baseline snapshot.

    Displays total/active/expired entry counts, oldest entry age, and
    per-severity breakdown. Called by ``phi-scan baseline show``.

    Args:
        summary: Computed statistics for the current baseline snapshot.
    """
    lines: list[str] = [
        f"  File:            {summary.baseline_path}",
        f"  Created:         {summary.created_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"  Scanner version: {summary.scanner_version}",
        "",
        f"  Total entries:   {summary.total_entries}",
        f"  Active:          [green]{summary.active_entries}[/green]",
        f"  Expired:         [dim]{summary.expired_entries}[/dim]",
        f"  Oldest entry:    {summary.oldest_entry_age_days} day(s) ago",
    ]
    if summary.severity_counts:
        lines.append("")
        lines.append("  Severity breakdown:")
        for severity, count in sorted(
            summary.severity_counts.items(), key=lambda item: item[0].value
        ):
            lines.append(f"    {severity.value.upper():<8} {count}")
    get_console().print(
        Panel(
            "\n".join(lines),
            title=_BASELINE_SUMMARY_TITLE,
            border_style=_BASELINE_SUMMARY_BORDER_STYLE,
        )
    )


def display_baseline_diff(diff: BaselineDiff) -> None:
    """Render a Rich diff panel comparing baseline against the current scan.

    Shows new, resolved, and persisting finding counts with per-finding details
    for new and resolved sets. Called by ``phi-scan baseline diff``.

    Args:
        diff: Computed diff between the baseline and the current scan.
    """
    lines: list[str] = [
        _BASELINE_NEW_SECTION_HEADER.format(count=len(diff.new_findings)),
    ]
    for finding in diff.new_findings:
        lines.append(
            _BASELINE_DIFF_FINDING_ROW.format(
                file_path=finding.file_path,
                line=finding.line_number,
                entity_type=finding.entity_type,
                severity=finding.severity.value,
            )
        )
    lines += [
        "",
        _BASELINE_RESOLVED_SECTION_HEADER.format(count=len(diff.resolved_entries)),
    ]
    for entry in diff.resolved_entries:
        lines.append(
            _BASELINE_DIFF_ENTRY_ROW.format(
                file_path=entry.file_path,
                line=entry.line_number,
                entity_type=entry.entity_type,
                severity=entry.severity.value,
            )
        )
    lines += [
        "",
        _BASELINE_PERSISTING_SECTION_HEADER.format(count=len(diff.persisting_findings)),
    ]
    get_console().print(Panel("\n".join(lines), title=_BASELINE_DIFF_TITLE))


def display_baseline_drift_warning(old_count: int, new_count: int, drift_percent: int) -> None:
    """Render a warning panel when a baseline update significantly increases entry count.

    Called by ``phi-scan baseline update`` when drift exceeds
    BASELINE_DRIFT_WARNING_PERCENT.

    Args:
        old_count: Entry count in the previous baseline.
        new_count: Entry count in the updated baseline.
        drift_percent: Percent increase, as returned by detect_baseline_drift.
    """
    get_console().print(
        Panel(
            _BASELINE_DRIFT_MESSAGE.format(percent=drift_percent, old=old_count, new=new_count),
            title=_BASELINE_DRIFT_TITLE,
            border_style=_BASELINE_DRIFT_BORDER_STYLE,
        )
    )


def display_baseline_scan_notice(new_count: int, baselined_count: int) -> None:
    """Render a one-line panel summarising baseline-filtered scan results.

    Shows how many findings are new vs. suppressed by the baseline. Called
    after ``scan --baseline`` completes to clarify the exit-code decision.

    Args:
        new_count: Findings not covered by any active baseline entry.
        baselined_count: Findings suppressed by an active baseline entry.
    """
    if new_count == 0:
        message = _BASELINE_SCAN_CLEAN_MESSAGE.format(baselined_count=baselined_count)
    else:
        message = _BASELINE_SCAN_NOTICE_MESSAGE.format(
            new_count=new_count, baselined_count=baselined_count
        )
    get_console().print(
        Panel(message, title=_BASELINE_NOTICE_TITLE, border_style=_BASELINE_NOTICE_BORDER_STYLE)
    )
