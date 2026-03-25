"""Tests for phi_scan.scanner — recursive file traversal and scan execution."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import pathspec
import pytest

from phi_scan.constants import (
    BINARY_CHECK_BYTE_COUNT,
    BYTES_PER_MEGABYTE,
    DEFAULT_TEXT_ENCODING,
    KNOWN_BINARY_EXTENSIONS,
    MAX_FILE_SIZE_MB,
    PathspecMatchStyle,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.exceptions import TraversalError
from phi_scan.models import ScanConfig, ScanResult
from phi_scan.scanner import (
    collect_scan_targets,
    execute_scan,
    is_binary_file,
    is_path_excluded,
    load_ignore_patterns,
    scan_file,
)

_SAMPLE_TEXT_CONTENT: str = "name = 'hello world'\n"
_SAMPLE_IGNORE_PATTERN: str = "*.log"
_IGNORE_COMMENT_LINE: str = "# this is a comment"
# Extension guaranteed to be in KNOWN_BINARY_EXTENSIONS — sorted for determinism.
# If the constant is empty, _KNOWN_BINARY_EXTENSION falls back to "" so that
# test_known_binary_extensions_is_not_empty fails with a clear message rather
# than a cryptic StopIteration at import time.
_SORTED_BINARY_EXTENSIONS: list[str] = sorted(KNOWN_BINARY_EXTENSIONS)
_KNOWN_BINARY_EXTENSION: str = _SORTED_BINARY_EXTENSIONS[0] if _SORTED_BINARY_EXTENSIONS else ""
# File size exactly one byte over the default limit — guaranteed to be skipped.
_OVERSIZED_FILE_SIZE_BYTES: int = MAX_FILE_SIZE_MB * BYTES_PER_MEGABYTE + 1
# Number of files created in multi-file execute_scan tests.
_MULTI_FILE_SCAN_COUNT: int = 3
# Minimum acceptable scan duration — time.monotonic() guarantees non-negative values.
_MINIMUM_SCAN_DURATION: float = 0.0


def _build_exclusion_spec(patterns: list[str]) -> pathspec.PathSpec:
    """Return a compiled PathSpec from the given pattern list."""
    return pathspec.PathSpec.from_lines(PathspecMatchStyle.GITIGNORE, patterns)


def _build_default_config() -> ScanConfig:
    """Return a ScanConfig with all defaults."""
    return ScanConfig()


# ---------------------------------------------------------------------------
# load_ignore_patterns — happy path
# ---------------------------------------------------------------------------


def test_load_ignore_patterns_returns_pattern_lines_from_file(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".phi-scanignore"
    ignore_file.write_text(_SAMPLE_IGNORE_PATTERN, encoding=DEFAULT_TEXT_ENCODING)

    patterns = load_ignore_patterns(ignore_file)

    assert patterns == [_SAMPLE_IGNORE_PATTERN]


def test_load_ignore_patterns_skips_blank_lines(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".phi-scanignore"
    ignore_file.write_text(
        f"{_SAMPLE_IGNORE_PATTERN}\n\n*.tmp\n",
        encoding=DEFAULT_TEXT_ENCODING,
    )

    patterns = load_ignore_patterns(ignore_file)

    assert "" not in patterns
    assert len(patterns) == 2


def test_load_ignore_patterns_skips_comment_lines(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".phi-scanignore"
    ignore_file.write_text(
        f"{_IGNORE_COMMENT_LINE}\n{_SAMPLE_IGNORE_PATTERN}\n",
        encoding=DEFAULT_TEXT_ENCODING,
    )

    patterns = load_ignore_patterns(ignore_file)

    assert _IGNORE_COMMENT_LINE not in patterns
    assert _SAMPLE_IGNORE_PATTERN in patterns


def test_load_ignore_patterns_returns_empty_list_when_file_not_found(tmp_path: Path) -> None:
    missing_path = tmp_path / ".phi-scanignore"

    patterns = load_ignore_patterns(missing_path)

    assert patterns == []


def test_load_ignore_patterns_logs_info_when_file_not_found(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    missing_path = tmp_path / ".phi-scanignore"

    with caplog.at_level(logging.INFO, logger="phi_scan.scanner"):
        load_ignore_patterns(missing_path)

    assert any("not found" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# KNOWN_BINARY_EXTENSIONS guard
# ---------------------------------------------------------------------------


def test_known_binary_extensions_is_not_empty_for_binary_detection() -> None:
    # _KNOWN_BINARY_EXTENSION is derived from KNOWN_BINARY_EXTENSIONS at module
    # level. If the constant is ever emptied, this test fails with a diagnostic
    # message before the binary-detection tests fail for confusing reasons.
    assert KNOWN_BINARY_EXTENSIONS, "KNOWN_BINARY_EXTENSIONS must not be empty"


# ---------------------------------------------------------------------------
# is_path_excluded
# ---------------------------------------------------------------------------


def test_is_path_excluded_returns_true_when_path_matches_pattern() -> None:
    exclusion_spec = _build_exclusion_spec(["node_modules/"])

    assert is_path_excluded(Path("node_modules/index.js"), exclusion_spec) is True


def test_is_path_excluded_returns_false_when_no_pattern_matches() -> None:
    exclusion_spec = _build_exclusion_spec(["node_modules/"])

    assert is_path_excluded(Path("src/main.py"), exclusion_spec) is False


def test_is_path_excluded_returns_false_for_empty_spec() -> None:
    exclusion_spec = _build_exclusion_spec([])

    assert is_path_excluded(Path("anything/file.py"), exclusion_spec) is False


def test_is_path_excluded_matches_extension_pattern() -> None:
    exclusion_spec = _build_exclusion_spec(["*.pyc"])

    assert is_path_excluded(Path("module/__pycache__/module.pyc"), exclusion_spec) is True


# ---------------------------------------------------------------------------
# is_binary_file
# ---------------------------------------------------------------------------


def test_is_binary_file_returns_true_for_known_binary_extension(tmp_path: Path) -> None:
    binary_file = tmp_path / f"artifact{_KNOWN_BINARY_EXTENSION}"
    binary_file.write_bytes(b"\x89PNG\r\n")

    assert is_binary_file(binary_file) is True


def test_is_binary_file_returns_true_when_null_byte_present(tmp_path: Path) -> None:
    binary_file = tmp_path / "data.bin"
    binary_file.write_bytes(b"some text\x00more text")

    assert is_binary_file(binary_file) is True


def test_is_binary_file_returns_false_for_plain_text_file(tmp_path: Path) -> None:
    text_file = tmp_path / "hello.py"
    text_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    assert is_binary_file(text_file) is False


def test_is_binary_file_returns_false_for_empty_file(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.py"
    empty_file.write_bytes(b"")

    assert is_binary_file(empty_file) is False


def test_is_binary_file_inspects_only_first_chunk_of_large_file(tmp_path: Path) -> None:
    # Null byte appears after the checked chunk — file must be treated as text.
    large_file = tmp_path / "large.py"
    large_file.write_bytes(b"a" * BINARY_CHECK_BYTE_COUNT + b"\x00")

    assert is_binary_file(large_file) is False


# ---------------------------------------------------------------------------
# collect_scan_targets — error conditions
# ---------------------------------------------------------------------------


def test_collect_scan_targets_raises_traversal_error_for_nonexistent_root(
    tmp_path: Path,
) -> None:
    missing_root = tmp_path / "does_not_exist"

    with pytest.raises(TraversalError):
        collect_scan_targets(missing_root, [], _build_default_config())


def test_collect_scan_targets_raises_traversal_error_when_root_is_a_file(
    tmp_path: Path,
) -> None:
    file_root = tmp_path / "not_a_dir.py"
    file_root.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    with pytest.raises(TraversalError):
        collect_scan_targets(file_root, [], _build_default_config())


# ---------------------------------------------------------------------------
# collect_scan_targets — happy path
# ---------------------------------------------------------------------------


def test_collect_scan_targets_returns_empty_list_for_empty_directory(
    tmp_path: Path,
) -> None:
    scan_targets = collect_scan_targets(tmp_path, [], _build_default_config())

    assert scan_targets == []


def test_collect_scan_targets_returns_text_file_in_root(tmp_path: Path) -> None:
    text_file = tmp_path / "source.py"
    text_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    scan_targets = collect_scan_targets(tmp_path, [], _build_default_config())

    assert text_file in scan_targets


def test_collect_scan_targets_recurses_into_subdirectories(tmp_path: Path) -> None:
    nested_dir = tmp_path / "src" / "module"
    nested_dir.mkdir(parents=True)
    nested_file = nested_dir / "deep.py"
    nested_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    scan_targets = collect_scan_targets(tmp_path, [], _build_default_config())

    assert nested_file in scan_targets


# ---------------------------------------------------------------------------
# collect_scan_targets — exclusion filters
# ---------------------------------------------------------------------------


def test_collect_scan_targets_excludes_file_matching_exclusion_pattern(
    tmp_path: Path,
) -> None:
    excluded_file = tmp_path / "debug.log"
    excluded_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    scan_targets = collect_scan_targets(tmp_path, ["*.log"], _build_default_config())

    assert excluded_file not in scan_targets


def test_collect_scan_targets_excludes_directory_matching_exclusion_pattern(
    tmp_path: Path,
) -> None:
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    js_file = node_modules / "index.js"
    js_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    scan_targets = collect_scan_targets(tmp_path, ["node_modules/"], _build_default_config())

    assert js_file not in scan_targets


def test_collect_scan_targets_respects_include_extensions_filter(tmp_path: Path) -> None:
    py_file = tmp_path / "source.py"
    py_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
    js_file = tmp_path / "source.js"
    js_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    config = ScanConfig(include_extensions=[".py"])
    scan_targets = collect_scan_targets(tmp_path, [], config)

    assert py_file in scan_targets
    assert js_file not in scan_targets


# ---------------------------------------------------------------------------
# collect_scan_targets — skip conditions
# ---------------------------------------------------------------------------


def test_collect_scan_targets_skips_symlinks(tmp_path: Path) -> None:
    real_file = tmp_path / "real.py"
    real_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
    symlink_file = tmp_path / "link.py"
    symlink_file.symlink_to(real_file)

    scan_targets = collect_scan_targets(tmp_path, [], _build_default_config())

    assert symlink_file not in scan_targets


def test_collect_scan_targets_logs_warning_when_symlink_skipped(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    real_file = tmp_path / "real.py"
    real_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
    symlink_file = tmp_path / "link.py"
    symlink_file.symlink_to(real_file)

    with caplog.at_level(logging.WARNING, logger="phi_scan.scanner"):
        collect_scan_targets(tmp_path, [], _build_default_config())

    assert any("symlink" in record.message.lower() for record in caplog.records)


def test_collect_scan_targets_skips_oversized_files(tmp_path: Path) -> None:
    large_file = tmp_path / "large.py"
    large_file.write_bytes(b"x" * _OVERSIZED_FILE_SIZE_BYTES)

    scan_targets = collect_scan_targets(tmp_path, [], _build_default_config())

    assert large_file not in scan_targets


def test_collect_scan_targets_skips_binary_files(tmp_path: Path) -> None:
    binary_file = tmp_path / "image.png"
    binary_file.write_bytes(b"\x89PNG\r\n\x1a\n")

    scan_targets = collect_scan_targets(tmp_path, [], _build_default_config())

    assert binary_file not in scan_targets


def test_collect_scan_targets_skips_file_on_os_error(tmp_path: Path) -> None:
    # Raise OSError during binary detection — fires after symlink/dir/exclusion
    # checks, so root_path traversal is unaffected.
    text_file = tmp_path / "restricted.py"
    text_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    with patch("phi_scan.scanner.is_binary_file", side_effect=OSError("I/O error")):
        scan_targets = collect_scan_targets(tmp_path, [], _build_default_config())

    assert text_file not in scan_targets


def test_collect_scan_targets_logs_warning_on_os_error(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    text_file = tmp_path / "restricted.py"
    text_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    with (
        caplog.at_level(logging.WARNING, logger="phi_scan.scanner"),
        patch("phi_scan.scanner.is_binary_file", side_effect=OSError("I/O error")),
    ):
        collect_scan_targets(tmp_path, [], _build_default_config())

    assert any("os error" in record.message.lower() for record in caplog.records)


# ---------------------------------------------------------------------------
# scan_file — placeholder
# ---------------------------------------------------------------------------


def test_scan_file_returns_empty_list_for_any_file(tmp_path: Path) -> None:
    text_file = tmp_path / "source.py"
    text_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    findings = scan_file(text_file, _build_default_config())

    assert findings == []


def test_scan_file_logs_stub_warning(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Phase 1B stub must emit a WARNING so it cannot silently survive into
    # Phase 2 wiring without the integration failure being visible in logs.
    text_file = tmp_path / "source.py"
    text_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    with caplog.at_level(logging.WARNING, logger="phi_scan.scanner"):
        scan_file(text_file, _build_default_config())

    assert any("stub" in record.message.lower() for record in caplog.records)


# ---------------------------------------------------------------------------
# execute_scan — clean scan
# ---------------------------------------------------------------------------


def test_execute_scan_returns_scan_result_instance(tmp_path: Path) -> None:
    scan_result = execute_scan([], _build_default_config())

    assert isinstance(scan_result, ScanResult)


def test_execute_scan_files_scanned_matches_target_count(tmp_path: Path) -> None:
    text_files = [tmp_path / f"file_{index}.py" for index in range(_MULTI_FILE_SCAN_COUNT)]
    for text_file in text_files:
        text_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    scan_result = execute_scan(text_files, _build_default_config())

    assert scan_result.files_scanned == len(text_files)


def test_execute_scan_is_clean_is_true_when_no_findings(tmp_path: Path) -> None:
    scan_result = execute_scan([], _build_default_config())

    assert scan_result.is_clean is True


def test_execute_scan_risk_level_is_clean_when_no_findings(tmp_path: Path) -> None:
    scan_result = execute_scan([], _build_default_config())

    assert scan_result.risk_level is RiskLevel.CLEAN


def test_execute_scan_files_with_findings_is_zero_for_clean_scan(tmp_path: Path) -> None:
    scan_result = execute_scan([], _build_default_config())

    assert scan_result.files_with_findings == 0


def test_execute_scan_scan_duration_is_non_negative(tmp_path: Path) -> None:
    scan_result = execute_scan([], _build_default_config())

    assert scan_result.scan_duration >= _MINIMUM_SCAN_DURATION


def test_execute_scan_findings_is_empty_tuple_for_clean_scan() -> None:
    scan_result = execute_scan([], _build_default_config())

    assert scan_result.findings == ()


def test_execute_scan_severity_counts_all_zero_for_clean_scan() -> None:
    scan_result = execute_scan([], _build_default_config())

    assert all(count == 0 for count in scan_result.severity_counts.values())


def test_execute_scan_severity_counts_contains_all_severity_levels() -> None:
    scan_result = execute_scan([], _build_default_config())

    assert set(scan_result.severity_counts.keys()) == set(SeverityLevel)


def test_execute_scan_category_counts_all_zero_for_clean_scan() -> None:
    scan_result = execute_scan([], _build_default_config())

    assert all(count == 0 for count in scan_result.category_counts.values())
