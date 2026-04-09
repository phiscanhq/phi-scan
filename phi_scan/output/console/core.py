"""Shared console infrastructure: Rich console instance, Unicode detection, and progress UI."""

from __future__ import annotations

import sys
from collections.abc import Generator
from contextlib import contextmanager

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Column

# ---------------------------------------------------------------------------
# Module-level Rich console — all display functions write to this instance.
# Rich automatically respects the NO_COLOR environment variable (no-color.org).
# Note: NO_COLOR suppresses ANSI color codes only — Unicode glyphs are unaffected,
# which is correct per the no-color.org specification.
# ---------------------------------------------------------------------------

_rich_console: Console = Console()


def get_console() -> Console:
    """Return the shared module-level Rich console.

    Callers that need to print Rich markup should use this rather than
    constructing their own Console instance — a single instance ensures
    consistent output buffering and colour detection across the CLI.
    """
    return _rich_console


# ---------------------------------------------------------------------------
# Unicode support detection
# Defined before symbol constants so _resolve_symbol is available at constant
# initialization time. Detection is done once at import and stored as a module
# constant to avoid repeated encoding lookups on every render call.
# ---------------------------------------------------------------------------

_UNICODE_ENCODING_PREFIX: str = "UTF"


def _detect_unicode_support() -> bool:
    """Return True when the terminal encoding can represent Unicode characters.

    Checks sys.stdout.encoding. Falls back to False when encoding is absent or
    non-UTF — covers ASCII-only terminals, legacy Windows cmd.exe, and pipes
    redirected to ASCII sinks.

    Returns:
        True if the stdout encoding starts with "UTF" (e.g. UTF-8, UTF-16).
    """
    encoding: str = getattr(sys.stdout, "encoding", None) or ""
    return encoding.upper().startswith(_UNICODE_ENCODING_PREFIX)


# ---------------------------------------------------------------------------
# Progress and spinner constants (used only by create_scan_progress and
# display_status_spinner — co-located to avoid scattering single-use constants)
# ---------------------------------------------------------------------------

_SPINNER_STYLE: str = "dots"
_PROGRESS_DESCRIPTION: str = "Scanning"
_PROGRESS_CURRENT_FILE_WIDTH: int = 40


@contextmanager
def display_status_spinner(message: str, is_active: bool) -> Generator[None, None, None]:
    """Show a spinner with status text for the duration of the wrapped block.

    When is_active is False the context manager is a no-op, allowing call
    sites to pass is_rich_mode directly without a conditional at every usage.

    Args:
        message: Status text shown beside the spinner.
        is_active: Show the spinner only when True.

    Yields:
        None — caller wraps the work block.
    """
    if is_active:
        with _rich_console.status(message, spinner=_SPINNER_STYLE):
            yield
    else:
        yield


@contextmanager
def create_scan_progress(total_files: int) -> Generator[tuple[Progress, TaskID], None, None]:
    """Yield a configured Rich Progress bar for file-by-file scan updates.

    Usage::

        with create_scan_progress(total) as (progress, task_id):
            for path in files:
                progress.update(task_id, advance=1, description=str(path))

    Args:
        total_files: Total number of files to be scanned (sets the bar maximum).

    Yields:
        A tuple of (Progress instance, TaskID) so callers can update per file.
    """
    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TextColumn(
            "[progress.description]{task.description}",
            table_column=Column(min_width=_PROGRESS_CURRENT_FILE_WIDTH, no_wrap=True),
        ),
        TimeElapsedColumn(),
        console=_rich_console,
    ) as progress:
        task_id = progress.add_task(_PROGRESS_DESCRIPTION, total=total_files)
        yield progress, task_id
