"""Tests for phi_scan.diff — git diff file extraction."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from phi_scan.constants import DEFAULT_TEXT_ENCODING
from phi_scan.diff import (
    _GIT_SUCCESS_EXIT_CODE,
    _get_git_repository_root,
    _resolve_existing_paths,
    _run_git_command,
    get_changed_files_from_diff,
    get_staged_files,
)
from phi_scan.exceptions import TraversalError

# Private symbols (_resolve_existing_paths, _run_git_command, _get_git_repository_root)
# are imported directly even though they are excluded from __all__. Their boundary
# conditions (symlink exclusion, git failure modes, path resolution) are not fully
# exercisable through the public API alone, so direct unit tests are warranted.

# ---------------------------------------------------------------------------
# Module-level test constants — no magic values in test logic
# ---------------------------------------------------------------------------

_SAMPLE_DIFF_REF: str = "HEAD~1"
_SAMPLE_REPO_ROOT_STR: str = "/repo"
_SAMPLE_GIT_TOPLEVEL_OUTPUT: str = "/repo\n"
_EMPTY_GIT_OUTPUT: str = ""
_BLANK_LINE_GIT_OUTPUT: str = "\n\n"
_SINGLE_FILE_NAME: str = "src/main.py"
_SINGLE_FILE_GIT_OUTPUT: str = f"{_SINGLE_FILE_NAME}\n"
_SECOND_FILE_NAME: str = "lib/utils.py"
_MULTI_FILE_GIT_OUTPUT: str = f"{_SINGLE_FILE_NAME}\n{_SECOND_FILE_NAME}\n"
_DELETED_FILE_NAME: str = "removed/gone.py"
_SYMLINKED_FILE_NAME: str = "link/target.py"
_EXPECTED_MULTI_FILE_COUNT: int = 2
_GIT_FAILURE_EXIT_CODE: int = 128
_INVALID_DIFF_REF: str = "HEAD~99"
_GIT_STDERR_INVALID_REF: str = f"fatal: ambiguous argument '{_INVALID_DIFF_REF}': unknown revision"
_GIT_STDERR_NOT_A_REPO: str = "fatal: not a git repository"
_SAMPLE_FILE_CONTENT: str = "x = 1\n"


def _build_subprocess_result(
    stdout: str = "",
    stderr: str = "",
    returncode: int = _GIT_SUCCESS_EXIT_CODE,
) -> MagicMock:
    """Return a MagicMock shaped like a subprocess.CompletedProcess result."""
    mock_result = MagicMock()
    mock_result.stdout = stdout
    mock_result.stderr = stderr
    mock_result.returncode = returncode
    return mock_result


# ---------------------------------------------------------------------------
# _resolve_existing_paths
# ---------------------------------------------------------------------------


def test_resolve_existing_paths_returns_empty_list_for_empty_output(
    tmp_path: Path,
) -> None:
    result = _resolve_existing_paths(_EMPTY_GIT_OUTPUT, tmp_path)

    assert result == []


def test_resolve_existing_paths_returns_empty_list_for_blank_line_output(
    tmp_path: Path,
) -> None:
    result = _resolve_existing_paths(_BLANK_LINE_GIT_OUTPUT, tmp_path)

    assert result == []


def test_resolve_existing_paths_returns_absolute_path_for_existing_file(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / _SINGLE_FILE_NAME
    source_file.parent.mkdir(parents=True)
    source_file.write_text(_SAMPLE_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    result = _resolve_existing_paths(_SINGLE_FILE_GIT_OUTPUT, tmp_path)

    assert result == [tmp_path / _SINGLE_FILE_NAME]


def test_resolve_existing_paths_excludes_file_not_on_disk(
    tmp_path: Path,
) -> None:
    deleted_output = f"{_DELETED_FILE_NAME}\n"

    result = _resolve_existing_paths(deleted_output, tmp_path)

    assert result == []


def test_resolve_existing_paths_excludes_symlinked_file(
    tmp_path: Path,
) -> None:
    target_path = tmp_path / _SINGLE_FILE_NAME
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(_SAMPLE_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
    symlink_path = tmp_path / _SYMLINKED_FILE_NAME
    symlink_path.parent.mkdir(parents=True, exist_ok=True)
    symlink_path.symlink_to(target_path)
    symlink_output = f"{_SYMLINKED_FILE_NAME}\n"

    result = _resolve_existing_paths(symlink_output, tmp_path)

    assert result == []


def test_resolve_existing_paths_returns_only_existing_files_from_mixed_output(
    tmp_path: Path,
) -> None:
    existing_file = tmp_path / _SINGLE_FILE_NAME
    existing_file.parent.mkdir(parents=True)
    existing_file.write_text(_SAMPLE_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
    mixed_output = f"{_SINGLE_FILE_NAME}\n{_DELETED_FILE_NAME}\n"

    result = _resolve_existing_paths(mixed_output, tmp_path)

    assert result == [tmp_path / _SINGLE_FILE_NAME]


def test_resolve_existing_paths_returns_multiple_existing_files(
    tmp_path: Path,
) -> None:
    for file_name in (_SINGLE_FILE_NAME, _SECOND_FILE_NAME):
        file_path = tmp_path / file_name
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(_SAMPLE_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    result = _resolve_existing_paths(_MULTI_FILE_GIT_OUTPUT, tmp_path)

    assert len(result) == _EXPECTED_MULTI_FILE_COUNT
    assert tmp_path / _SINGLE_FILE_NAME in result
    assert tmp_path / _SECOND_FILE_NAME in result


def test_resolve_existing_paths_resolves_paths_relative_to_repo_root(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / _SINGLE_FILE_NAME
    source_file.parent.mkdir(parents=True)
    source_file.write_text(_SAMPLE_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    result = _resolve_existing_paths(_SINGLE_FILE_GIT_OUTPUT, tmp_path)

    assert result[0].is_absolute()
    assert result[0] == tmp_path / _SINGLE_FILE_NAME


# ---------------------------------------------------------------------------
# _run_git_command
# ---------------------------------------------------------------------------


def test_run_git_command_returns_stdout_on_success() -> None:
    mock_result = _build_subprocess_result(stdout=_SAMPLE_GIT_TOPLEVEL_OUTPUT)

    with patch("phi_scan.diff.subprocess.run", return_value=mock_result):
        output = _run_git_command(["rev-parse", "--show-toplevel"])

    assert output == _SAMPLE_GIT_TOPLEVEL_OUTPUT


def test_run_git_command_raises_traversal_error_on_nonzero_exit_code() -> None:
    mock_result = _build_subprocess_result(
        stderr=_GIT_STDERR_NOT_A_REPO,
        returncode=_GIT_FAILURE_EXIT_CODE,
    )

    with patch("phi_scan.diff.subprocess.run", return_value=mock_result):
        with pytest.raises(TraversalError):
            _run_git_command(["rev-parse", "--show-toplevel"])


def test_run_git_command_includes_exit_code_in_error_message() -> None:
    mock_result = _build_subprocess_result(
        stderr=_GIT_STDERR_NOT_A_REPO,
        returncode=_GIT_FAILURE_EXIT_CODE,
    )

    with patch("phi_scan.diff.subprocess.run", return_value=mock_result):
        with pytest.raises(TraversalError) as exc_info:
            _run_git_command(["rev-parse", "--show-toplevel"])

    assert str(_GIT_FAILURE_EXIT_CODE) in str(exc_info.value)


def test_run_git_command_includes_stderr_in_error_message() -> None:
    mock_result = _build_subprocess_result(
        stderr=_GIT_STDERR_INVALID_REF,
        returncode=_GIT_FAILURE_EXIT_CODE,
    )

    with patch("phi_scan.diff.subprocess.run", return_value=mock_result):
        with pytest.raises(TraversalError) as exc_info:
            _run_git_command(["diff", "--name-only", _SAMPLE_DIFF_REF])

    assert _GIT_STDERR_INVALID_REF in str(exc_info.value)


def test_run_git_command_raises_traversal_error_when_git_not_found() -> None:
    with patch("phi_scan.diff.subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(TraversalError):
            _run_git_command(["--version"])


def test_run_git_command_raises_traversal_error_on_os_error() -> None:
    with patch("phi_scan.diff.subprocess.run", side_effect=OSError("I/O error")):
        with pytest.raises(TraversalError):
            _run_git_command(["--version"])


def test_run_git_command_raises_traversal_error_on_timeout() -> None:
    import subprocess as _subprocess

    with patch(
        "phi_scan.diff.subprocess.run",
        side_effect=_subprocess.TimeoutExpired(cmd="git", timeout=30),
    ):
        with pytest.raises(TraversalError):
            _run_git_command(["--version"])


# ---------------------------------------------------------------------------
# _get_git_repository_root
# ---------------------------------------------------------------------------


def test_get_git_repository_root_returns_path_from_git_output() -> None:
    with patch(
        "phi_scan.diff._run_git_command",
        return_value=_SAMPLE_GIT_TOPLEVEL_OUTPUT,
    ):
        root = _get_git_repository_root()

    assert root == Path(_SAMPLE_REPO_ROOT_STR)


def test_get_git_repository_root_strips_trailing_newline() -> None:
    with patch(
        "phi_scan.diff._run_git_command",
        return_value=_SAMPLE_GIT_TOPLEVEL_OUTPUT,
    ):
        root = _get_git_repository_root()

    assert "\n" not in str(root)


def test_get_git_repository_root_raises_traversal_error_when_not_in_git_repo() -> None:
    with patch(
        "phi_scan.diff._run_git_command",
        side_effect=TraversalError(_GIT_STDERR_NOT_A_REPO),
    ):
        with pytest.raises(TraversalError):
            _get_git_repository_root()


def test_get_git_repository_root_error_message_indicates_not_a_git_repository() -> None:
    with patch(
        "phi_scan.diff._run_git_command",
        side_effect=TraversalError(_GIT_STDERR_NOT_A_REPO),
    ):
        with pytest.raises(TraversalError) as exc_info:
            _get_git_repository_root()

    assert "git repository" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# get_changed_files_from_diff
# ---------------------------------------------------------------------------


def test_get_changed_files_from_diff_raises_traversal_error_when_not_in_git_repo() -> None:
    with patch(
        "phi_scan.diff._get_git_repository_root",
        side_effect=TraversalError(_GIT_STDERR_NOT_A_REPO),
    ):
        with pytest.raises(TraversalError):
            get_changed_files_from_diff(_SAMPLE_DIFF_REF)


def test_get_changed_files_from_diff_returns_existing_changed_files(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / _SINGLE_FILE_NAME
    source_file.parent.mkdir(parents=True)
    source_file.write_text(_SAMPLE_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=tmp_path),
        patch("phi_scan.diff._run_git_command", return_value=_SINGLE_FILE_GIT_OUTPUT),
    ):
        result = get_changed_files_from_diff(_SAMPLE_DIFF_REF)

    assert result == [tmp_path / _SINGLE_FILE_NAME]


def test_get_changed_files_from_diff_raises_traversal_error_for_invalid_diff_ref() -> None:
    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=Path(_SAMPLE_REPO_ROOT_STR)),
        patch(
            "phi_scan.diff._run_git_command",
            side_effect=TraversalError(_GIT_STDERR_INVALID_REF),
        ),
    ):
        with pytest.raises(TraversalError):
            get_changed_files_from_diff(_INVALID_DIFF_REF)


def test_get_changed_files_from_diff_error_includes_diff_ref() -> None:
    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=Path(_SAMPLE_REPO_ROOT_STR)),
        patch(
            "phi_scan.diff._run_git_command",
            side_effect=TraversalError(_GIT_STDERR_INVALID_REF),
        ),
    ):
        with pytest.raises(TraversalError) as exc_info:
            get_changed_files_from_diff(_INVALID_DIFF_REF)

    assert _INVALID_DIFF_REF in str(exc_info.value)


def test_get_changed_files_from_diff_excludes_deleted_files(tmp_path: Path) -> None:
    deleted_only_output = f"{_DELETED_FILE_NAME}\n"

    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=tmp_path),
        patch("phi_scan.diff._run_git_command", return_value=deleted_only_output),
    ):
        result = get_changed_files_from_diff(_SAMPLE_DIFF_REF)

    assert result == []


def test_get_changed_files_from_diff_returns_empty_list_when_no_changes(
    tmp_path: Path,
) -> None:
    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=tmp_path),
        patch("phi_scan.diff._run_git_command", return_value=_EMPTY_GIT_OUTPUT),
    ):
        result = get_changed_files_from_diff(_SAMPLE_DIFF_REF)

    assert result == []


def test_get_changed_files_from_diff_passes_diff_ref_to_git_command(
    tmp_path: Path,
) -> None:
    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=tmp_path),
        patch("phi_scan.diff._run_git_command", return_value=_EMPTY_GIT_OUTPUT) as mock_cmd,
    ):
        get_changed_files_from_diff(_SAMPLE_DIFF_REF)

    called_args = mock_cmd.call_args[0][0]
    assert _SAMPLE_DIFF_REF in called_args


def test_get_changed_files_from_diff_uses_diff_filter_flag(tmp_path: Path) -> None:
    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=tmp_path),
        patch("phi_scan.diff._run_git_command", return_value=_EMPTY_GIT_OUTPUT) as mock_cmd,
    ):
        get_changed_files_from_diff(_SAMPLE_DIFF_REF)

    called_args = mock_cmd.call_args[0][0]
    assert any("--diff-filter" in arg for arg in called_args)


# ---------------------------------------------------------------------------
# get_staged_files
# ---------------------------------------------------------------------------


def test_get_staged_files_raises_traversal_error_when_not_in_git_repo() -> None:
    with patch(
        "phi_scan.diff._get_git_repository_root",
        side_effect=TraversalError(_GIT_STDERR_NOT_A_REPO),
    ):
        with pytest.raises(TraversalError):
            get_staged_files()


def test_get_staged_files_returns_staged_files(tmp_path: Path) -> None:
    source_file = tmp_path / _SINGLE_FILE_NAME
    source_file.parent.mkdir(parents=True)
    source_file.write_text(_SAMPLE_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=tmp_path),
        patch("phi_scan.diff._run_git_command", return_value=_SINGLE_FILE_GIT_OUTPUT),
    ):
        result = get_staged_files()

    assert result == [tmp_path / _SINGLE_FILE_NAME]


def test_get_staged_files_returns_empty_list_when_nothing_staged(
    tmp_path: Path,
) -> None:
    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=tmp_path),
        patch("phi_scan.diff._run_git_command", return_value=_EMPTY_GIT_OUTPUT),
    ):
        result = get_staged_files()

    assert result == []


def test_get_staged_files_excludes_deleted_files(tmp_path: Path) -> None:
    deleted_only_output = f"{_DELETED_FILE_NAME}\n"

    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=tmp_path),
        patch("phi_scan.diff._run_git_command", return_value=deleted_only_output),
    ):
        result = get_staged_files()

    assert result == []


def test_get_staged_files_uses_cached_flag(tmp_path: Path) -> None:
    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=tmp_path),
        patch("phi_scan.diff._run_git_command", return_value=_EMPTY_GIT_OUTPUT) as mock_cmd,
    ):
        get_staged_files()

    called_args = mock_cmd.call_args[0][0]
    assert "--cached" in called_args


def test_get_staged_files_uses_diff_filter_flag(tmp_path: Path) -> None:
    with (
        patch("phi_scan.diff._get_git_repository_root", return_value=tmp_path),
        patch("phi_scan.diff._run_git_command", return_value=_EMPTY_GIT_OUTPUT) as mock_cmd,
    ):
        get_staged_files()

    called_args = mock_cmd.call_args[0][0]
    assert any("--diff-filter" in arg for arg in called_args)
