"""Progress-bar integration for the `phi-scan scan` command.

Extracted from ``cli/scan.py`` so the command entry point focuses on wiring
CLI flags, while the Rich progress-bar orchestration (sequential vs. parallel
dispatch and per-file advancement) lives in one cohesive module.
"""

from __future__ import annotations

import time
from pathlib import Path

from phi_scan.cli._shared import (
    _PARALLEL_SCAN_PROGRESS_LABEL,
    _ProgressScanContext,
    _ScanExecutionOptions,
    _truncate_filename_for_progress,
)
from phi_scan.models import ScanConfig, ScanFinding, ScanResult
from phi_scan.output import create_scan_progress
from phi_scan.scanner import (
    MIN_WORKER_COUNT,
    build_scan_result,
    execute_scan,
    run_parallel_scan,
    scan_file,
)

__all__ = [
    "execute_scan_with_progress",
]


def _run_sequential_scan_with_progress(
    scan_context: _ProgressScanContext,
) -> list[ScanFinding]:
    """Scan files one at a time, advancing the progress bar after each file."""
    accumulated_findings: list[ScanFinding] = []
    for file_path in scan_context.scan_targets:
        progress_label = _truncate_filename_for_progress(file_path)
        scan_context.progress.update(scan_context.task_id, description=progress_label)
        accumulated_findings.extend(scan_file(file_path, scan_context.config))
        scan_context.progress.update(scan_context.task_id, advance=1)
    return accumulated_findings


def _run_parallel_scan_with_progress(
    scan_context: _ProgressScanContext,
) -> list[ScanFinding]:
    """Scan files concurrently, advancing the progress bar as each file completes."""

    def _advance_progress_bar(completed_file_path: Path) -> None:
        scan_context.progress.update(
            scan_context.task_id,
            description=_PARALLEL_SCAN_PROGRESS_LABEL,
            advance=1,
        )

    return run_parallel_scan(
        list(scan_context.scan_targets),
        scan_context.config,
        scan_context.worker_count,
        on_file_complete=_advance_progress_bar,
    )


def _run_scan_with_progress(
    scan_context: _ProgressScanContext,
) -> list[ScanFinding]:
    """Dispatch to sequential or parallel progress scanning based on worker_count."""
    if scan_context.worker_count > MIN_WORKER_COUNT:
        return _run_parallel_scan_with_progress(scan_context)
    return _run_sequential_scan_with_progress(scan_context)


def execute_scan_with_progress(
    scan_targets: list[Path],
    config: ScanConfig,
    execution_options: _ScanExecutionOptions,
) -> ScanResult:
    """Run the scan loop, showing a Rich progress bar when should_show_progress is True."""
    if not execution_options.should_show_progress:
        return execute_scan(scan_targets, config, execution_options.worker_count)
    scan_start = time.monotonic()
    with create_scan_progress(total_files=len(scan_targets)) as (progress, task_id):
        progress_scan_context = _ProgressScanContext(
            scan_targets=tuple(scan_targets),
            config=config,
            worker_count=execution_options.worker_count,
            progress=progress,
            task_id=task_id,
        )
        accumulated_findings = _run_scan_with_progress(progress_scan_context)
    scan_duration = time.monotonic() - scan_start
    return build_scan_result(tuple(accumulated_findings), len(scan_targets), scan_duration)
