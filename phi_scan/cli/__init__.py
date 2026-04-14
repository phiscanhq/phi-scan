"""Typer CLI entry point for PhiScan."""

from __future__ import annotations

from typing import Annotated

import typer

# Imported as a module (not `from .scan import scan, watch`) so the submodule
# attribute `phi_scan.cli.watch` continues to resolve to the watch-helpers
# module, not the watch command function. Used below in app.command wiring.
from phi_scan.cli import scan as _scan_module
from phi_scan.cli import watch as _watch_module
from phi_scan.cli._shared import (
    _DEFAULT_WORKER_COUNT,
    _GIT_DIR_NOT_FOUND_MESSAGE,
    _GIT_DIR_PATH,
    _HOOK_SYMLINKED_COMPONENT_ERROR,
    _LOG_LEVEL_DEBUG,
    _LOG_LEVEL_ERROR,
    _LOG_LEVEL_INFO,
    _LOG_LEVEL_MAP,
    _LOG_LEVEL_WARNING,
    _PARALLEL_SCAN_PROGRESS_LABEL,
    _PROGRESS_FILENAME_ELLIPSIS,
    _PROGRESS_FILENAME_MAX_CHARS,
    _VERSION_FLAG_HELP,
    _VERSION_OUTPUT_FORMAT,
    _WORKERS_ABOVE_MAXIMUM_ERROR,
    _WORKERS_BELOW_MINIMUM_ERROR,
    _configure_logging,
    _echo_version,
    _load_combined_ignore_patterns,
    _normalize_diff_path,
    _ProgressScanContext,
    _reject_hook_path_with_symlinked_component,
    _reject_missing_git_directory,
    _resolve_scan_targets,
    _ScanExecutionOptions,
    _ScanPhaseOptions,
    _ScanTargetOptions,
    _truncate_filename_for_progress,
    _validate_worker_count,
)
from phi_scan.cli.baseline import baseline_app
from phi_scan.cli.config import config_app
from phi_scan.cli.dashboard import _aggregate_category_totals, display_dashboard
from phi_scan.cli.explain import explain_app
from phi_scan.cli.fix import fix_command
from phi_scan.cli.history import display_history, display_last_scan
from phi_scan.cli.hooks import (
    download_models,
    initialize_project,
    install_hook,
    uninstall_hook,
)
from phi_scan.cli.plugins import plugins_app

# Private helpers re-exported for backwards-compatible imports from
# ``phi_scan.cli`` (tests and historical callers reach for these names).
__all__ = [
    "_DEFAULT_WORKER_COUNT",
    "_GIT_DIR_NOT_FOUND_MESSAGE",
    "_GIT_DIR_PATH",
    "_HOOK_SYMLINKED_COMPONENT_ERROR",
    "_LOG_LEVEL_DEBUG",
    "_LOG_LEVEL_ERROR",
    "_LOG_LEVEL_INFO",
    "_LOG_LEVEL_MAP",
    "_LOG_LEVEL_WARNING",
    "_PARALLEL_SCAN_PROGRESS_LABEL",
    "_PROGRESS_FILENAME_ELLIPSIS",
    "_PROGRESS_FILENAME_MAX_CHARS",
    "_ProgressScanContext",
    "_ScanExecutionOptions",
    "_ScanPhaseOptions",
    "_ScanTargetOptions",
    "_VERSION_FLAG_HELP",
    "_VERSION_OUTPUT_FORMAT",
    "_WORKERS_ABOVE_MAXIMUM_ERROR",
    "_WORKERS_BELOW_MINIMUM_ERROR",
    "_aggregate_category_totals",
    "_configure_logging",
    "_echo_version",
    "_load_combined_ignore_patterns",
    "_normalize_diff_path",
    "_reject_hook_path_with_symlinked_component",
    "_reject_missing_git_directory",
    "_resolve_scan_targets",
    "_truncate_filename_for_progress",
    "_validate_worker_count",
    "app",
]

app = typer.Typer(
    name="phi-scan",
    help="PHI/PII Scanner for CI/CD pipelines. HIPAA & FHIR compliant. Local execution only.",
    no_args_is_help=True,
)

app.add_typer(config_app)
app.add_typer(explain_app)
app.add_typer(baseline_app)
app.add_typer(plugins_app)


@app.callback()
def main_callback(
    is_version_requested: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_echo_version,
            is_eager=True,
            help=_VERSION_FLAG_HELP,
        ),
    ] = False,
) -> None:
    """PHI/PII Scanner for CI/CD pipelines. HIPAA & FHIR compliant. Local execution only."""


app.command("scan")(_scan_module.scan)
app.command("watch")(_watch_module.start_watch)
app.command("fix")(fix_command)
app.command("report")(display_last_scan)
app.command("history")(display_history)
app.command("dashboard")(display_dashboard)
app.command("install-hook")(install_hook)
app.command("uninstall-hook")(uninstall_hook)
app.command("init")(initialize_project)
app.command("setup")(download_models)
