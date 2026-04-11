"""Tests for phi_scan.scanner — recursive file traversal and scan execution."""

from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path
from unittest.mock import patch

import pathspec
import pytest

from phi_scan.constants import (
    ARCHIVE_MAX_COMPRESSION_RATIO,
    ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES,
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
    MAX_WORKER_COUNT,
    MIN_WORKER_COUNT,
    _passes_decompression_bomb_guards,  # noqa: PLC2701
    _scan_files_parallel,  # noqa: PLC2701
    _scan_files_sequential,  # noqa: PLC2701
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
if not _SORTED_BINARY_EXTENSIONS:
    raise RuntimeError("KNOWN_BINARY_EXTENSIONS is empty — binary detection tests cannot run")
_KNOWN_BINARY_EXTENSION: str = _SORTED_BINARY_EXTENSIONS[0]
# File size exactly one byte over the default limit — guaranteed to be skipped.
_OVERSIZED_FILE_SIZE_BYTES: int = MAX_FILE_SIZE_MB * BYTES_PER_MEGABYTE + 1
# Number of files created in multi-file execute_scan tests.
_MULTI_FILE_SCAN_COUNT: int = 3
# Minimum acceptable scan duration — time.monotonic() guarantees non-negative values.
_MINIMUM_SCAN_DURATION: float = 0.0
# Number of files used in parallel scan parity tests — large enough to exercise
# the thread pool but small enough for fast test execution.
_PARITY_FILE_COUNT: int = 6
# Worker count used in parallel parity tests — must be > 1 to activate the parallel code path.
_PARITY_WORKER_COUNT: int = 2
# PHI content written to parity test files. Uses a structurally valid SSN pattern
# (high confidence regex match) so findings are consistently generated across both code paths.
# 123-45-6789 uses area number 123, which the SSA has never assigned — it is
# a well-known synthetic test value and is not a real individual's SSN.
_PARITY_PHI_CONTENT: str = "patient_ssn = '123-45-6789'\n"
# Number of non-blank, non-comment patterns written by
# test_load_ignore_patterns_skips_blank_lines: _SAMPLE_IGNORE_PATTERN ("*.log") and "*.tmp".
# Update this constant if that test's fixture content changes.
_EXPECTED_NON_BLANK_NON_COMMENT_PATTERN_COUNT: int = 2


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
    assert len(patterns) == _EXPECTED_NON_BLANK_NON_COMMENT_PATTERN_COUNT


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


def test_collect_scan_targets_raises_traversal_error_when_root_is_a_symlink(
    tmp_path: Path,
) -> None:
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    symlink_root = tmp_path / "link_root"
    symlink_root.symlink_to(real_dir)

    with pytest.raises(TraversalError):
        collect_scan_targets(symlink_root, [], _build_default_config())


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


def test_collect_scan_targets_skips_symlinked_directory(tmp_path: Path) -> None:
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    nested_file = real_dir / "secret.py"
    nested_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
    link_dir = tmp_path / "link_dir"
    link_dir.symlink_to(real_dir)

    scan_targets = collect_scan_targets(tmp_path, [], _build_default_config())

    assert not any("link_dir" in str(p) for p in scan_targets)


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
# scan_file — Phase 2E integration
# ---------------------------------------------------------------------------


def test_scan_file_returns_list_for_clean_file(tmp_path: Path) -> None:
    # A file with no PHI-like content must produce no findings.
    clean_file = tmp_path / "config.py"
    clean_file.write_text("DEBUG = True\n", encoding=DEFAULT_TEXT_ENCODING)

    findings = scan_file(clean_file, _build_default_config())

    assert isinstance(findings, list)


def test_scan_file_returns_empty_list_for_undecodable_file(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    binary_file = tmp_path / "binary.bin"
    # Write bytes that are not valid UTF-8 to trigger the decode-error path.
    binary_file.write_bytes(b"\xff\xfe\x00\x01invalid utf-8 \x80\x81")

    with caplog.at_level(logging.WARNING, logger="phi_scan.scanner"):
        findings = scan_file(binary_file, _build_default_config())

    assert findings == []
    assert any("decode" in record.message.lower() for record in caplog.records)


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


# ---------------------------------------------------------------------------
# execute_scan — worker_count parameter
# ---------------------------------------------------------------------------


def test_execute_scan_worker_count_one_returns_scan_result() -> None:
    scan_result = execute_scan([], _build_default_config(), worker_count=MIN_WORKER_COUNT)

    assert isinstance(scan_result, ScanResult)


def test_execute_scan_worker_count_two_returns_scan_result() -> None:
    scan_result = execute_scan([], _build_default_config(), worker_count=_PARITY_WORKER_COUNT)

    assert isinstance(scan_result, ScanResult)


def test_execute_scan_parallel_files_scanned_matches_target_count(tmp_path: Path) -> None:
    text_files = [tmp_path / f"file_{i}.py" for i in range(_MULTI_FILE_SCAN_COUNT)]
    for text_file in text_files:
        text_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    scan_result = execute_scan(
        text_files, _build_default_config(), worker_count=_PARITY_WORKER_COUNT
    )

    assert scan_result.files_scanned == len(text_files)


def test_execute_scan_parallel_is_clean_for_no_phi_content(tmp_path: Path) -> None:
    text_files = [tmp_path / f"file_{i}.py" for i in range(_MULTI_FILE_SCAN_COUNT)]
    for text_file in text_files:
        text_file.write_text(_SAMPLE_TEXT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    scan_result = execute_scan(
        text_files, _build_default_config(), worker_count=_PARITY_WORKER_COUNT
    )

    assert scan_result.is_clean is True


# ---------------------------------------------------------------------------
# Parallel scan parity — sequential and parallel produce identical results
# ---------------------------------------------------------------------------


def _build_parity_files(root: Path, file_count: int) -> list[Path]:
    """Create file_count Python files with PHI content under root; return ordered list."""
    files = [root / f"file_{index:03d}.py" for index in range(file_count)]
    for phi_file in files:
        phi_file.write_text(_PARITY_PHI_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
    return files


def test_parallel_scan_finding_count_matches_sequential(tmp_path: Path) -> None:
    phi_files = _build_parity_files(tmp_path, _PARITY_FILE_COUNT)
    config = _build_default_config()

    sequential_result = execute_scan(phi_files, config, worker_count=MIN_WORKER_COUNT)
    parallel_result = execute_scan(phi_files, config, worker_count=_PARITY_WORKER_COUNT)

    assert len(parallel_result.findings) == len(sequential_result.findings)


def test_parallel_scan_file_paths_match_sequential(tmp_path: Path) -> None:
    phi_files = _build_parity_files(tmp_path, _PARITY_FILE_COUNT)
    config = _build_default_config()

    sequential_result = execute_scan(phi_files, config, worker_count=MIN_WORKER_COUNT)
    parallel_result = execute_scan(phi_files, config, worker_count=_PARITY_WORKER_COUNT)

    sequential_paths = [f.file_path for f in sequential_result.findings]
    parallel_paths = [f.file_path for f in parallel_result.findings]
    assert parallel_paths == sequential_paths


def test_parallel_scan_value_hashes_match_sequential(tmp_path: Path) -> None:
    phi_files = _build_parity_files(tmp_path, _PARITY_FILE_COUNT)
    config = _build_default_config()

    sequential_result = execute_scan(phi_files, config, worker_count=MIN_WORKER_COUNT)
    parallel_result = execute_scan(phi_files, config, worker_count=_PARITY_WORKER_COUNT)

    sequential_hashes = [f.value_hash for f in sequential_result.findings]
    parallel_hashes = [f.value_hash for f in parallel_result.findings]
    assert parallel_hashes == sequential_hashes


def test_parallel_scan_risk_level_matches_sequential(tmp_path: Path) -> None:
    phi_files = _build_parity_files(tmp_path, _PARITY_FILE_COUNT)
    config = _build_default_config()

    sequential_result = execute_scan(phi_files, config, worker_count=MIN_WORKER_COUNT)
    parallel_result = execute_scan(phi_files, config, worker_count=_PARITY_WORKER_COUNT)

    assert parallel_result.risk_level == sequential_result.risk_level


# ---------------------------------------------------------------------------
# _scan_files_sequential and _scan_files_parallel — unit tests
# ---------------------------------------------------------------------------


def test_scan_files_sequential_returns_empty_for_no_targets() -> None:
    findings = _scan_files_sequential([], _build_default_config())

    assert findings == []


def test_scan_files_parallel_returns_empty_for_no_targets() -> None:
    findings = _scan_files_parallel([], _build_default_config(), worker_count=_PARITY_WORKER_COUNT)

    assert findings == []


def test_scan_files_parallel_preserves_order(tmp_path: Path) -> None:
    phi_files = _build_parity_files(tmp_path, _PARITY_FILE_COUNT)
    config = _build_default_config()

    sequential_findings = _scan_files_sequential(phi_files, config)
    parallel_findings = _scan_files_parallel(phi_files, config, worker_count=_PARITY_WORKER_COUNT)

    sequential_paths = [f.file_path for f in sequential_findings]
    parallel_paths = [f.file_path for f in parallel_findings]
    assert parallel_paths == sequential_paths


def test_max_worker_count_is_positive_integer() -> None:
    assert isinstance(MAX_WORKER_COUNT, int)
    assert MAX_WORKER_COUNT >= 1


# ---------------------------------------------------------------------------
# Decompression bomb protection — _passes_decompression_bomb_guards
# ---------------------------------------------------------------------------

_ARCHIVE_PATH: Path = Path("test.zip")
_SMALL_MEMBER_SIZE: int = 1024  # 1 KB — well within limits
_LARGE_MEMBER_SIZE: int = ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES + 1
_BOMB_COMPRESS_SIZE: int = 100  # tiny compressed size
_NORMAL_COMPRESS_SIZE: int = 512  # normal compressed size


def _make_zip_info(
    filename: str,
    file_size: int,
    compress_size: int,
) -> zipfile.ZipInfo:
    """Build a ZipInfo with controlled file_size and compress_size."""
    info = zipfile.ZipInfo(filename)
    info.file_size = file_size
    info.compress_size = compress_size
    return info


def test_archive_member_size_accepts_small_member() -> None:
    """_passes_decompression_bomb_guards must return True for a normal-sized member."""
    info = _make_zip_info("config.json", _SMALL_MEMBER_SIZE, _NORMAL_COMPRESS_SIZE)
    assert _passes_decompression_bomb_guards(info, _ARCHIVE_PATH) is True


def test_archive_member_size_rejects_oversized_member(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """_passes_decompression_bomb_guards must return False and log WARNING for oversized members."""
    info = _make_zip_info("big.json", _LARGE_MEMBER_SIZE, _NORMAL_COMPRESS_SIZE)
    with caplog.at_level(logging.WARNING, logger="phi_scan.scanner"):
        result = _passes_decompression_bomb_guards(info, _ARCHIVE_PATH)
    assert result is False
    assert "decompression bomb" in caplog.text.lower()


def test_archive_member_size_rejects_high_compression_ratio(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """_passes_decompression_bomb_guards must return False for compression ratio > limit."""
    bomb_size = (ARCHIVE_MAX_COMPRESSION_RATIO + 1) * _BOMB_COMPRESS_SIZE
    info = _make_zip_info("bomb.json", bomb_size, _BOMB_COMPRESS_SIZE)
    with caplog.at_level(logging.WARNING, logger="phi_scan.scanner"):
        result = _passes_decompression_bomb_guards(info, _ARCHIVE_PATH)
    assert result is False
    assert "decompression bomb" in caplog.text.lower()


def test_archive_member_size_accepts_zero_compress_size() -> None:
    """_passes_decompression_bomb_guards must not divide by zero when compress_size is 0."""
    info = _make_zip_info("empty.json", _SMALL_MEMBER_SIZE, 0)
    assert _passes_decompression_bomb_guards(info, _ARCHIVE_PATH) is True


def test_archive_member_size_accepts_ratio_at_limit() -> None:
    """_passes_decompression_bomb_guards must accept a ratio exactly at the limit."""
    exactly_at_limit = ARCHIVE_MAX_COMPRESSION_RATIO * _BOMB_COMPRESS_SIZE
    info = _make_zip_info("ok.json", exactly_at_limit, _BOMB_COMPRESS_SIZE)
    assert _passes_decompression_bomb_guards(info, _ARCHIVE_PATH) is True


def test_scan_file_skips_bomb_member_in_real_zip(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """scan_file must skip archive members that fail the decompression bomb check."""
    archive_path = tmp_path / "test.zip"
    member_content = b"x" * _SMALL_MEMBER_SIZE
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("config.json", member_content)
    archive_path.write_bytes(buf.getvalue())

    oversized = ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES + 1

    def _fake_is_safe(member_info: zipfile.ZipInfo, path: Path) -> bool:
        return member_info.file_size < oversized

    with (
        patch("phi_scan.scanner._passes_decompression_bomb_guards", side_effect=_fake_is_safe),
        caplog.at_level(logging.WARNING, logger="phi_scan.scanner"),
    ):
        from phi_scan.scanner import scan_file as _scan_file

        config = ScanConfig()
        findings = _scan_file(archive_path, config)

    assert findings == []
