"""Tests for .phi-scanignore pattern matching at any depth (task 1F.5).

Covers is_path_excluded, load_ignore_patterns, and collect_scan_targets
with gitignore-style patterns compiled via pathspec.
"""

from pathlib import Path

import pathspec

from phi_scan.constants import (
    DEFAULT_TEXT_ENCODING,
    OutputFormat,
    PathspecMatchStyle,
    SeverityLevel,
)
from phi_scan.models import ScanConfig
from phi_scan.scanner import collect_scan_targets, is_path_excluded, load_ignore_patterns

# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

_NODE_MODULES_PATTERN: str = "node_modules/"
_EXTENSION_PATTERN_PYC: str = "*.pyc"
_EXTENSION_PATTERN_LOG: str = "*.log"
_DOUBLE_STAR_PATTERN: str = "**/test_data/"
_NEGATION_LOG_PATTERN: str = "!important.log"
_IMPORTANT_LOG_FILENAME: str = "important.log"
_ROOT_ANCHORED_BUILD_PATTERN: str = "/build/"

# Path literals used in multiple tests
_NODE_MODULES_DEPTH_ONE_FILE: str = "node_modules/index.js"
_NODE_MODULES_DEPTH_THREE_FILE: str = "a/b/node_modules/index.js"
_APP_PYC_FILE: str = "app.pyc"
_SRC_APP_PYC_FILE: str = "src/app.pyc"
_SRC_APP_PY_FILE: str = "src/app.py"
_DEEP_TEST_DATA_FILE: str = "a/b/c/test_data/file.py"
_ANCHORED_BUILD_INCLUDED_FILE: str = "src/build/output.js"
_ANCHORED_BUILD_EXCLUDED_FILE: str = "build/output.js"

# File content written into temporary integration test files
_MINIMAL_FILE_CONTENT: str = "# placeholder\n"

# Comment and blank lines used for the load_ignore_patterns test
_COMMENT_LINE: str = "# this is a comment\n"
_BLANK_LINE: str = "\n"
_REAL_PATTERN_ONE: str = "*.pyc"
_REAL_PATTERN_TWO: str = "node_modules/"

# ScanConfig construction values — named to avoid magic numbers
_DEFAULT_MAX_FILE_SIZE_MB: int = 10
_DEFAULT_CONFIDENCE_THRESHOLD: float = 0.6


def _build_minimal_scan_configuration() -> ScanConfig:
    """Return a minimal ScanConfig suitable for integration tests."""
    return ScanConfig(
        max_file_size_mb=_DEFAULT_MAX_FILE_SIZE_MB,
        confidence_threshold=_DEFAULT_CONFIDENCE_THRESHOLD,
        severity_threshold=SeverityLevel.LOW,
        include_extensions=None,
        exclude_paths=[],
        output_format=OutputFormat.TABLE,
    )


# ---------------------------------------------------------------------------
# is_path_excluded unit tests
# ---------------------------------------------------------------------------


def test_directory_pattern_excludes_file_at_depth_one() -> None:
    spec = pathspec.PathSpec.from_lines(PathspecMatchStyle.GITIGNORE, [_NODE_MODULES_PATTERN])

    is_excluded = is_path_excluded(Path(_NODE_MODULES_DEPTH_ONE_FILE), spec)

    assert is_excluded is True


def test_directory_pattern_excludes_file_at_depth_three() -> None:
    spec = pathspec.PathSpec.from_lines(PathspecMatchStyle.GITIGNORE, [_NODE_MODULES_PATTERN])

    is_excluded = is_path_excluded(Path(_NODE_MODULES_DEPTH_THREE_FILE), spec)

    assert is_excluded is True


def test_extension_pattern_excludes_matching_file() -> None:
    spec = pathspec.PathSpec.from_lines(PathspecMatchStyle.GITIGNORE, [_EXTENSION_PATTERN_PYC])

    is_excluded = is_path_excluded(Path(_APP_PYC_FILE), spec)

    assert is_excluded is True


def test_extension_pattern_excludes_matching_file_in_subdirectory() -> None:
    spec = pathspec.PathSpec.from_lines(PathspecMatchStyle.GITIGNORE, [_EXTENSION_PATTERN_PYC])

    is_excluded = is_path_excluded(Path(_SRC_APP_PYC_FILE), spec)

    assert is_excluded is True


def test_non_matching_path_is_not_excluded() -> None:
    spec = pathspec.PathSpec.from_lines(PathspecMatchStyle.GITIGNORE, [_NODE_MODULES_PATTERN])

    is_excluded = is_path_excluded(Path(_SRC_APP_PY_FILE), spec)

    assert is_excluded is False


def test_double_star_pattern_matches_at_any_depth() -> None:
    spec = pathspec.PathSpec.from_lines(PathspecMatchStyle.GITIGNORE, [_DOUBLE_STAR_PATTERN])

    is_excluded = is_path_excluded(Path(_DEEP_TEST_DATA_FILE), spec)

    assert is_excluded is True


def test_negation_pattern_reincludes_excluded_file() -> None:
    patterns = [_EXTENSION_PATTERN_LOG, _NEGATION_LOG_PATTERN]
    spec = pathspec.PathSpec.from_lines(PathspecMatchStyle.GITIGNORE, patterns)

    is_excluded = is_path_excluded(Path(_IMPORTANT_LOG_FILENAME), spec)

    assert is_excluded is False


def test_leading_slash_anchors_to_root_excludes_root_level_path() -> None:
    spec = pathspec.PathSpec.from_lines(
        PathspecMatchStyle.GITIGNORE, [_ROOT_ANCHORED_BUILD_PATTERN]
    )

    is_excluded = is_path_excluded(Path(_ANCHORED_BUILD_EXCLUDED_FILE), spec)

    assert is_excluded is True


def test_leading_slash_anchors_to_root_does_not_exclude_nested_path() -> None:
    spec = pathspec.PathSpec.from_lines(
        PathspecMatchStyle.GITIGNORE, [_ROOT_ANCHORED_BUILD_PATTERN]
    )

    is_excluded = is_path_excluded(Path(_ANCHORED_BUILD_INCLUDED_FILE), spec)

    assert is_excluded is False


# ---------------------------------------------------------------------------
# load_ignore_patterns unit test
# ---------------------------------------------------------------------------


def test_load_ignore_patterns_strips_comments_and_blanks(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".phi-scanignore"
    ignore_file.write_text(
        _COMMENT_LINE + _BLANK_LINE + _REAL_PATTERN_ONE + "\n" + _REAL_PATTERN_TWO + "\n",
        encoding=DEFAULT_TEXT_ENCODING,
    )

    loaded_patterns = load_ignore_patterns(ignore_file)

    assert loaded_patterns == [_REAL_PATTERN_ONE, _REAL_PATTERN_TWO]


# ---------------------------------------------------------------------------
# collect_scan_targets integration tests
# ---------------------------------------------------------------------------


def test_collect_scan_targets_excludes_nested_node_modules_at_any_depth(
    tmp_path: Path,
) -> None:
    nested_node_modules_dir = tmp_path / "src" / "a" / "b" / "node_modules"
    nested_node_modules_dir.mkdir(parents=True)
    secret_file = nested_node_modules_dir / "secret.py"
    secret_file.write_text(_MINIMAL_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    src_dir = tmp_path / "src"
    app_file = src_dir / "app.py"
    app_file.write_text(_MINIMAL_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    scan_configuration = _build_minimal_scan_configuration()

    scan_targets = collect_scan_targets(
        root_path=tmp_path,
        excluded_patterns=[_NODE_MODULES_PATTERN],
        config=scan_configuration,
    )

    assert app_file in scan_targets
    assert secret_file not in scan_targets


def test_collect_scan_targets_respects_extension_exclusion_at_any_depth(
    tmp_path: Path,
) -> None:
    shallow_log = tmp_path / "app.log"
    shallow_log.write_text(_MINIMAL_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    deep_dir = tmp_path / "a" / "b" / "c"
    deep_dir.mkdir(parents=True)
    deep_log = deep_dir / "debug.log"
    deep_log.write_text(_MINIMAL_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    py_file = tmp_path / "app.py"
    py_file.write_text(_MINIMAL_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    scan_configuration = _build_minimal_scan_configuration()

    scan_targets = collect_scan_targets(
        root_path=tmp_path,
        excluded_patterns=[_EXTENSION_PATTERN_LOG],
        config=scan_configuration,
    )

    assert shallow_log not in scan_targets
    assert deep_log not in scan_targets
    assert py_file in scan_targets
