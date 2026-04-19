"""V2 terminal report renderer — public entry point.

Composes overview, findings-by-line, remediation playbook, and scan-complete
footer into a single terminal report. Called from display_rich_scan_results_v2
when --report-format v2 or PHI_SCAN_REPORT_V2=1 is active.
"""

from __future__ import annotations

from pathlib import Path

from phi_scan.constants import SEVERITY_RANK, SeverityLevel
from phi_scan.models import ScanResult
from phi_scan.output.console.core import get_console
from phi_scan.report.v2.aggregation import (
    dedupe_remediations,
    group_by_file,
    group_by_line,
)
from phi_scan.report.v2.findings import render_findings_by_line
from phi_scan.report.v2.footer import render_scan_complete
from phi_scan.report.v2.overview import render_overview
from phi_scan.report.v2.playbook import render_remediation_playbook

_DEFAULT_EXPAND_CUTOFF: SeverityLevel = SeverityLevel.MEDIUM


def _resolve_expand_cutoff(severity_threshold: SeverityLevel) -> SeverityLevel:
    """Determine the expansion cutoff for line cards.

    When the user passes a threshold at or below LOW (i.e. LOW or INFO),
    all findings at that level and above are expanded inline.  Otherwise
    the default cutoff of MEDIUM applies, collapsing LOW and INFO cards.
    """
    if SEVERITY_RANK[severity_threshold] <= SEVERITY_RANK[SeverityLevel.LOW]:
        return severity_threshold
    return _DEFAULT_EXPAND_CUTOFF


def display_rich_scan_results_v2(
    scan_result: ScanResult,
    scan_target: str = ".",
    severity_threshold: SeverityLevel = SeverityLevel.LOW,
    is_verbose: bool = False,
    report_path: Path | None = None,
) -> None:
    """Render the full v2 terminal report.

    This is the public entry point called by the CLI when v2 rendering is
    active. It replaces display_rich_scan_results for v2 mode only.

    Args:
        scan_result: Completed scan result from the detection engine.
        scan_target: Display name of the scan target (file or directory path).
        severity_threshold: Effective severity threshold from config/CLI.
        is_verbose: Whether --verbose was passed.
        report_path: Path to generated report file, if any.
    """
    console = get_console()

    line_aggregates = group_by_line(scan_result.findings)
    all_actions = dedupe_remediations(scan_result.findings)
    file_aggregates = group_by_file(line_aggregates)

    render_overview(console, scan_result, scan_target, all_actions)

    if not scan_result.is_clean:
        expand_cutoff = _resolve_expand_cutoff(severity_threshold)
        total_line_count = len(line_aggregates)

        render_findings_by_line(
            console,
            file_aggregates,
            total_finding_count=len(scan_result.findings),
            total_line_count=total_line_count,
            severity_threshold=expand_cutoff,
            is_verbose=is_verbose,
        )

        render_remediation_playbook(
            console,
            all_actions,
            total_finding_count=len(scan_result.findings),
        )

    render_scan_complete(
        console,
        scan_result,
        unique_action_count=len(all_actions),
        report_path=report_path,
    )
