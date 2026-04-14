"""Watch-mode domain: dataclasses, event handler, and live-screen helpers.

Extracted from ``cli.py`` to isolate the watch-specific file-change monitoring
logic, watchdog integration, and Rich Live rendering from the main CLI wiring.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.live import Live
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from phi_scan.constants import EXIT_CODE_CLEAN
from phi_scan.logging_config import get_logger
from phi_scan.models import ScanConfig, ScanFinding
from phi_scan.output import (
    WATCH_RESULT_CLEAN_TEXT,
    WATCH_RESULT_VIOLATION_FORMAT,
    WatchEvent,
    build_watch_layout,
)
from phi_scan.scanner import scan_file

__all__ = [
    "FileChangeMonitor",
    "WatchConfig",
    "WatchScanOutcome",
    "append_watch_event",
    "build_relative_display_path",
    "build_watch_result",
    "count_files_in_directory",
    "display_watch_live_screen",
    "scan_changed_file",
    "start_watch",
]

_WATCH_PATH_HELP: str = "Directory to watch for file system changes."
_WATCH_PATH_DOES_NOT_EXIST: str = "Path does not exist: {path}"
_WATCH_PATH_NOT_DIRECTORY: str = "Path is not a directory: {path}"
_WATCH_PATH_PARAM_HINT: str = "'PATH'"

_logger: logging.Logger = get_logger("cli_watch")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WATCH_POLL_INTERVAL_SECONDS: float = 1.0
WATCH_LIVE_REFRESH_RATE: float = 4.0
WATCH_LOG_MAX_EVENTS: int = 10
_WATCH_PATH_OUTSIDE_ROOT_DISPLAY: str = "[outside watch root]"
_RGLOB_ALL_FILES_PATTERN: str = "*"

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WatchScanOutcome:
    """The outcome of scanning one file during watch mode.

    Carries the human-readable result text and a typed boolean that
    output.py uses to derive the Rich style for the rolling event table.
    """

    result_text: str
    is_clean: bool


@dataclass(frozen=True)
class WatchConfig:
    """Immutable configuration shared between watch() and FileChangeMonitor.

    Frozen enforces the invariant that watch_root and scan_config are read-only
    once constructed — mutation on the watchdog background thread would be an
    unsynchronized write with no lock protection.
    The mutable watch_events deque is kept separate and passed explicitly so
    that immutable and mutable state are never mixed in one dataclass.
    """

    watch_root: Path
    scan_config: ScanConfig


# ---------------------------------------------------------------------------
# File-count helper
# ---------------------------------------------------------------------------


def count_files_in_directory(directory: Path) -> int:
    """Return the number of regular files under directory (non-recursive cap is not applied).

    Args:
        directory: Root directory to traverse.

    Returns:
        Count of all regular files found via rglob.
    """
    return sum(
        1
        for candidate in directory.rglob(_RGLOB_ALL_FILES_PATTERN)
        if candidate.is_file() and not candidate.is_symlink()
    )


# ---------------------------------------------------------------------------
# Event handler
# ---------------------------------------------------------------------------


class FileChangeMonitor(FileSystemEventHandler):
    """Watchdog event handler — appends a watch event to the rolling log on each file change.

    Each file-change event triggers a full scan of the changed file. Findings are
    displayed inline; the watch header shows cumulative session state.
    """

    def __init__(self, watch_config: WatchConfig, watch_events: deque[WatchEvent]) -> None:
        """Bind the immutable watch configuration and the mutable event buffer.

        watch_config and watch_events are kept separate so that frozen=True on
        WatchConfig enforces the read-only invariant — scan_config must not be
        mutated on the watchdog background thread.

        Args:
            watch_config: Frozen config holding watch_root and scan_config.
            watch_events: Shared rolling deque appended to on each file change.
        """
        super().__init__()
        self._watch_config = watch_config
        self._watch_events = watch_events

    def on_any_event(self, event: FileSystemEvent) -> None:
        """Append a timestamped event record on any non-directory file change.

        Args:
            event: The watchdog file system event.
        """
        if event.is_directory:
            return
        changed_path = Path(str(event.src_path))
        # HIPAA traversal rule: never follow symlinks — a watchdog event can fire
        # for a symlinked path, which could point outside the watched directory and
        # expose files containing PHI that were never intended to be scanned.
        if changed_path.is_symlink():
            return
        scan_outcome = scan_changed_file(changed_path, self._watch_config)
        if scan_outcome is not None:
            append_watch_event(changed_path, scan_outcome, self._watch_config, self._watch_events)


# ---------------------------------------------------------------------------
# Watch helpers
# ---------------------------------------------------------------------------


def build_relative_display_path(changed_path: Path, watch_root: Path) -> str:
    """Return changed_path relative to watch_root for PHI-safe display.

    File paths can contain PHI (patient IDs, names) in directory components.
    Storing the absolute path verbatim would persist raw PHI in the shared deque.
    Converting to a watch-root-relative path removes the sensitive prefix that
    appears in deep patient-directory structures. If relativisation fails (edge
    case where the path is outside watch_root), a safe sentinel is returned —
    the bare filename is NOT used because filenames themselves may contain PHI
    (e.g. john_doe_mrn_123456.hl7).

    Args:
        changed_path: Absolute path to the changed file.
        watch_root: The watched directory root.

    Returns:
        A relative path string safe for terminal display, or a fixed sentinel
        when the path cannot be relativised.
    """
    try:
        return str(changed_path.relative_to(watch_root))
    except ValueError:
        return _WATCH_PATH_OUTSIDE_ROOT_DISPLAY


def scan_changed_file(changed_path: Path, watch_config: WatchConfig) -> WatchScanOutcome | None:
    """Run scan_file on a watchdog-reported path and return a structured outcome.

    Returns None when the file cannot be read (deleted or permissions changed between
    the watchdog event and the scan call) — caller skips appending to the deque.

    Args:
        changed_path: The file that changed, already confirmed non-symlink.
        watch_config: Immutable watch configuration; provides the scan config.

    Returns:
        WatchScanOutcome with result text and is_clean flag, or None on I/O error.
    """
    try:
        findings = scan_file(changed_path, watch_config.scan_config)
    except (PermissionError, FileNotFoundError):
        _logger.warning("Skipping unreadable or deleted file during watch: %s", changed_path.name)
        return None
    return build_watch_result(findings)


def append_watch_event(
    changed_path: Path,
    scan_outcome: WatchScanOutcome,
    watch_config: WatchConfig,
    watch_events: deque[WatchEvent],
) -> None:
    """Build a WatchEvent from the scan outcome and append it to the rolling deque.

    Args:
        changed_path: The file that changed; used to compute the display path.
        scan_outcome: Structured result from scan_changed_file.
        watch_config: Immutable watch configuration; provides the watch root path.
        watch_events: Mutable rolling event buffer; receives the new WatchEvent.
    """
    # deque.append is atomic under CPython's GIL, so no explicit lock is needed here.
    # The main thread reads the deque via list(watch_events) (also atomic), making
    # this cross-thread access safe without threading.Lock for CPython.
    watch_events.append(
        WatchEvent(
            event_time=datetime.now(),
            file_path=build_relative_display_path(changed_path, watch_config.watch_root),
            result_text=scan_outcome.result_text,
            is_clean=scan_outcome.is_clean,
        )
    )


def build_watch_result(findings: list[ScanFinding]) -> WatchScanOutcome:
    """Return a structured scan outcome for a per-file watch event.

    Maps the finding list to a display-ready outcome and clean/not-clean flag.

    Args:
        findings: Findings returned by scan_file for the changed file.

    Returns:
        WatchScanOutcome with display text and a typed is_clean boolean.
    """
    if findings:
        return WatchScanOutcome(
            result_text=WATCH_RESULT_VIOLATION_FORMAT.format(count=len(findings)),
            is_clean=False,
        )
    return WatchScanOutcome(result_text=WATCH_RESULT_CLEAN_TEXT, is_clean=True)


def display_watch_live_screen(
    watch_path: Path,
    watch_events: deque[WatchEvent],
) -> None:
    """Drive the Rich Live render loop, refreshing until the caller's context ends.

    Single responsibility: render only. KeyboardInterrupt is not caught here —
    it propagates naturally to watch(), which translates it to a clean exit code.
    Rich's Live context manager handles alternate-screen teardown via __exit__
    when any exception (including KeyboardInterrupt) unwinds the with block.

    Args:
        watch_path: The watched directory, shown in the persistent header.
        watch_events: Shared deque updated by FileChangeMonitor on the watchdog thread.
    """
    with Live(refresh_per_second=WATCH_LIVE_REFRESH_RATE, screen=True) as live:
        while True:
            live.update(build_watch_layout(watch_path, list(watch_events)))
            time.sleep(_WATCH_POLL_INTERVAL_SECONDS)


def _validate_watch_path(path: Path) -> Path:
    """Resolve and validate that the requested watch target is an existing directory."""
    watch_path = path.resolve()
    if not watch_path.exists():
        raise typer.BadParameter(
            _WATCH_PATH_DOES_NOT_EXIST.format(path=watch_path),
            param_hint=_WATCH_PATH_PARAM_HINT,
        )
    if not watch_path.is_dir():
        raise typer.BadParameter(
            _WATCH_PATH_NOT_DIRECTORY.format(path=watch_path),
            param_hint=_WATCH_PATH_PARAM_HINT,
        )
    return watch_path


def start_watch(
    path: Annotated[Path, typer.Argument(help=_WATCH_PATH_HELP)] = Path("."),
) -> None:
    """Watch a directory and re-scan changed files. Detection active from Phase 2."""
    watch_path = _validate_watch_path(path)
    watch_config = WatchConfig(watch_root=watch_path, scan_config=ScanConfig())
    watch_events: deque[WatchEvent] = deque(maxlen=WATCH_LOG_MAX_EVENTS)
    event_handler = FileChangeMonitor(watch_config, watch_events)
    observer = Observer()
    observer.schedule(event_handler, str(watch_path), recursive=True)  # type: ignore[no-untyped-call]
    observer.start()  # type: ignore[no-untyped-call]
    try:
        display_watch_live_screen(watch_path, watch_events)
    except KeyboardInterrupt:
        raise typer.Exit(code=EXIT_CODE_CLEAN) from None
    finally:
        observer.stop()  # type: ignore[no-untyped-call]
        observer.join()
