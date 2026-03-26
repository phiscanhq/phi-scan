"""Git diff file extraction for --diff scan mode."""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Sequence
from pathlib import Path

from phi_scan.exceptions import TraversalError
from phi_scan.logging_config import get_logger

__all__ = [
    "get_changed_files_from_diff",
    "get_staged_files",
]

_logger: logging.Logger = get_logger("diff")

# ---------------------------------------------------------------------------
# Log and error message templates
# ---------------------------------------------------------------------------

_NOT_A_GIT_REPOSITORY_ERROR: str = (
    "Not inside a git repository — diff mode requires a git repository"
)
_INVALID_DIFF_REF_ERROR: str = "Invalid or unknown diff reference {ref!r}: {detail}"
_GIT_NOT_FOUND_ERROR: str = "git executable not found — install git to use --diff mode"
_GIT_EXECUTION_ERROR: str = "git could not be executed: {detail}"
_GIT_COMMAND_FAILED_ERROR: str = "git command exited with code {code}: {detail}"
_GIT_TIMEOUT_ERROR: str = "git command timed out after {timeout} seconds"

# ---------------------------------------------------------------------------
# Implementation constants
# ---------------------------------------------------------------------------

_GIT_EXECUTABLE: str = "git"
_GIT_SUCCESS_EXIT_CODE: int = 0
_GIT_COMMAND_TIMEOUT_SECONDS: int = 30
# ACMR: Added, Copied, Modified, Renamed — excludes Deleted from output so
# scan targets are never built for files that no longer exist on disk.
_DIFF_FILTER_SPECIFIER: str = "ACMR"
_GIT_DIFF_FILTER_FLAG: str = f"--diff-filter={_DIFF_FILTER_SPECIFIER}"
_GIT_TOPLEVEL_ARGS: tuple[str, ...] = ("rev-parse", "--show-toplevel")
_GIT_DIFF_BASE_ARGS: tuple[str, ...] = ("diff", "--name-only", _GIT_DIFF_FILTER_FLAG)
_GIT_STAGED_DIFF_ARGS: tuple[str, ...] = (
    "diff",
    "--cached",
    "--name-only",
    _GIT_DIFF_FILTER_FLAG,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_changed_files_from_diff(diff_ref: str) -> list[Path]:
    """Return files changed relative to diff_ref that currently exist on disk.

    Runs ``git diff --name-only --diff-filter=ACMR <diff_ref>`` from the
    repository root. Deleted files are excluded both by the diff filter and
    by the filesystem existence check performed before returning.

    Supported diff_ref formats: ``HEAD~N``, ``branch..branch``, ``commit_sha``.

    Args:
        diff_ref: Git revision or range to diff against.

    Returns:
        Ordered list of absolute Path objects for files changed since diff_ref.

    Raises:
        TraversalError: If not inside a git repository, if diff_ref is
            invalid or unknown, or if git cannot be executed.
    """
    repo_root = _get_git_repository_root()
    git_args = [*_GIT_DIFF_BASE_ARGS, diff_ref]
    try:
        git_output = _run_git_command(git_args)
    except TraversalError as git_error:
        raise TraversalError(
            _INVALID_DIFF_REF_ERROR.format(ref=diff_ref, detail=git_error)
        ) from git_error
    return _resolve_existing_paths(git_output, repo_root)


def get_staged_files() -> list[Path]:
    """Return files currently in the git staging area that exist on disk.

    Runs ``git diff --cached --name-only --diff-filter=ACMR`` from the
    repository root. Intended for use in pre-commit hooks.

    Returns:
        Ordered list of absolute Path objects for staged files.

    Raises:
        TraversalError: If not inside a git repository or if git cannot
            be executed.
    """
    repo_root = _get_git_repository_root()
    git_output = _run_git_command(_GIT_STAGED_DIFF_ARGS)
    return _resolve_existing_paths(git_output, repo_root)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _get_git_repository_root() -> Path:
    """Return the absolute path of the current git repository root.

    Returns:
        Absolute Path to the repository root directory.

    Raises:
        TraversalError: If the working directory is not inside a git
            repository or if git cannot be executed.
    """
    try:
        root_output = _run_git_command(_GIT_TOPLEVEL_ARGS)
    except TraversalError as git_error:
        raise TraversalError(_NOT_A_GIT_REPOSITORY_ERROR) from git_error
    return Path(root_output.strip())


def _run_git_command(git_args: Sequence[str]) -> str:
    """Run a git subcommand and return its stdout.

    Args:
        git_args: Arguments to pass to the git executable.

    Returns:
        The stdout of the git command as a string.

    Raises:
        TraversalError: If git is not found, cannot be executed, or exits
            with a non-zero return code.
    """
    try:
        completed_process = subprocess.run(
            [_GIT_EXECUTABLE, *git_args],
            capture_output=True,
            text=True,
            timeout=_GIT_COMMAND_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as not_found_error:
        raise TraversalError(_GIT_NOT_FOUND_ERROR) from not_found_error
    except subprocess.TimeoutExpired as timeout_error:
        raise TraversalError(
            _GIT_TIMEOUT_ERROR.format(timeout=_GIT_COMMAND_TIMEOUT_SECONDS)
        ) from timeout_error
    except OSError as execution_error:
        raise TraversalError(
            _GIT_EXECUTION_ERROR.format(detail=execution_error)
        ) from execution_error
    if completed_process.returncode != _GIT_SUCCESS_EXIT_CODE:
        raise TraversalError(
            _GIT_COMMAND_FAILED_ERROR.format(
                code=completed_process.returncode,
                detail=completed_process.stderr.strip(),
            )
        )
    return completed_process.stdout


def _resolve_existing_paths(git_output: str, repo_root: Path) -> list[Path]:
    """Parse git --name-only output and return only non-symlink paths that exist on disk.

    Paths are resolved relative to repo_root so the result is correct
    regardless of the caller's working directory. Deleted files and blank
    lines are excluded. Symlinks are excluded and logged at WARNING level —
    a staged symlink pointing outside the repository is a suspicious security
    event that operators should be aware of.

    Args:
        git_output: Raw stdout from a ``git diff --name-only`` command.
        repo_root: Absolute path to the repository root; used to resolve
            relative paths emitted by git.

    Returns:
        List of absolute Path objects for files that currently exist on disk.
    """
    existing_paths: list[Path] = []
    for raw_line in git_output.splitlines():
        relative_file_path = raw_line.strip()
        if not relative_file_path:
            continue
        candidate_path = repo_root / relative_file_path
        if candidate_path.is_symlink():
            _logger.warning("Skipping symlink in diff output: %s", candidate_path)
            continue
        if candidate_path.exists():
            existing_paths.append(candidate_path)
    return existing_paths
