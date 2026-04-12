"""Recursive file traversal and detection engine entry point."""

from __future__ import annotations

import hashlib
import json
import logging
import time
import zipfile
import zlib
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

import pathspec

if TYPE_CHECKING:
    from collections.abc import Callable

    from phi_scan.ai_review import AIUsageSummary

from phi_scan.cache import FileCacheKey, get_cached_result, store_cached_result
from phi_scan.constants import (
    ARCHIVE_EXTENSIONS,
    ARCHIVE_MAX_COMPRESSION_RATIO,
    ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES,
    ARCHIVE_SCANNABLE_EXTENSIONS,
    BINARY_CHECK_BYTE_COUNT,
    BYTES_PER_MEGABYTE,
    DEFAULT_TEXT_ENCODING,
    KNOWN_BINARY_EXTENSIONS,
    SEVERITY_RANK,
    PathspecMatchStyle,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.detection_coordinator import detect_phi_in_text_content
from phi_scan.exceptions import FileReadError, PhiDetectionError, TraversalError
from phi_scan.logging_config import get_logger
from phi_scan.models import ScanConfig, ScanFinding, ScanResult
from phi_scan.plugin_loader import PluginRegistry, load_plugin_registry
from phi_scan.plugin_runtime import execute_plugin_pass
from phi_scan.suppression import is_finding_suppressed, load_suppressions

__all__ = [
    "MAX_WORKER_COUNT",
    "MIN_WORKER_COUNT",
    "collect_scan_targets",
    "execute_scan",
    "is_binary_file",
    "is_path_excluded",
    "load_ignore_patterns",
    "run_parallel_scan",
    "scan_file",
]

_logger: logging.Logger = get_logger("scanner")

# ---------------------------------------------------------------------------
# Log and error message templates
# ---------------------------------------------------------------------------

_ROOT_PATH_NOT_FOUND_ERROR: str = "Scan root {path!r} does not exist"
_ROOT_PATH_NOT_DIRECTORY_ERROR: str = "Scan root {path!r} is not a directory"
_WORKER_COUNT_OUT_OF_RANGE_ERROR: str = (
    "worker_count {worker_count} is out of range [{minimum}, {maximum}]"
)
_SYMLINK_SKIPPED_WARNING: str = "Skipping symlink {path!r} — symlink traversal is prohibited"
_OVERSIZED_FILE_SKIPPED_WARNING: str = "Skipping {path!r} — size exceeds the {limit_mb} MB limit"
_BINARY_FILE_SKIPPED_INFO: str = "Skipping {path!r} — detected as binary"
_EXTENSION_SKIPPED_DEBUG: str = "Skipping {path!r} — extension not in include_extensions"
_EXCLUDED_PATH_DEBUG: str = "Skipping {path!r} — matched exclusion pattern"
_FILE_OS_ERROR_WARNING: str = "Skipping {path!r} — OS error: {error}"
_ROOT_PATH_IS_SYMLINK_ERROR: str = (
    "Scan root {path!r} is a symlink — symlink traversal is prohibited"
)
_IGNORE_FILE_MISSING_INFO: str = "Ignore file {path!r} not found — no patterns loaded"
_UNMAPPED_SEVERITY_LEVELS_ERROR: str = (
    "No RiskLevel mapping for severity levels {levels!r} — update _derive_risk_level"
)
_FILE_DECODE_ERROR_WARNING: str = (
    "Skipping {path!r} — could not decode content as {encoding!r}: {error}"
)
_ARCHIVE_BAD_FORMAT_WARNING: str = (
    "Skipping archive {path!r} — not a valid ZIP/JAR/WAR file: {error}"
)
_ARCHIVE_MEMBER_READ_ERROR_WARNING: str = "Skipping archive member {member!r} in {path!r}: {error}"
_ARCHIVE_MEMBER_TOO_LARGE_WARNING: str = (
    "Skipping archive member {member!r} in {path!r} — uncompressed size "
    "{size} bytes exceeds limit of {limit} bytes (decompression bomb protection)"
)
_ARCHIVE_MEMBER_RATIO_WARNING: str = (
    "Skipping archive member {member!r} in {path!r} — compression ratio "
    "{ratio}:1 exceeds limit of {limit}:1 (decompression bomb protection)"
)
_ARCHIVE_MEMBER_UNSAFE_PATH_DEBUG: str = (
    "Skipping archive member {member!r} in {path!r} — unsafe path traversal sequence detected"
)
_CACHE_HIT_DEBUG: str = "Cache hit for {path!r} — returning {count} cached findings"
_FILE_READ_OS_ERROR_MESSAGE: str = "Skipping {path!r} — cannot read file: {error}"
_DISPLAY_PATH_OUTSIDE_CWD_DEBUG: str = (
    "Path {path!r} is outside the current working directory — using filename only for display"
)

# ---------------------------------------------------------------------------
# Implementation constants — traversal and binary detection
# ---------------------------------------------------------------------------

# Passed to rglob to match every filesystem entry at every depth.
_RGLOB_ALL_FILES_PATTERN: str = "*"
# Lines beginning with this prefix are treated as comments in .phi-scanignore files.
_IGNORE_COMMENT_PREFIX: str = "#"
# Used by is_binary_file — never embed these literals in logic code.
_NULL_BYTE: bytes = b"\x00"
_BINARY_READ_MODE: str = "rb"

# Path component used in ZIP-slip attacks. Archive members whose path parts
# include this component could traverse outside the intended directory if extracted.
# ZipFile.read() is used (not extract()), but unsafe members are rejected early.
_DOTDOT_PATH_COMPONENT: str = ".."

# Hash algorithm used to compute the content hash for cache keys. Must match
# the algorithm used by compute_file_hash in cache.py (sha256).
_SHA256_ALGORITHM: str = "sha256"

# Jupyter notebook (.ipynb) content extraction keys — used by
# _extract_notebook_text to pull cell source and output text from
# the JSON structure without embedding string literals in logic code.
_NOTEBOOK_EXTENSION: str = ".ipynb"
_NOTEBOOK_CELLS_KEY: str = "cells"
_NOTEBOOK_CELL_SOURCE_KEY: str = "source"
_NOTEBOOK_CELL_OUTPUTS_KEY: str = "outputs"
_NOTEBOOK_OUTPUT_TEXT_KEY: str = "text"
# Jupyter nbformat stores each source line with its trailing newline already
# embedded (e.g. ["line 1\n", "line 2\n", "last line"]). Joining with "" is
# correct per the spec — joining with "\n" would insert double newlines.
_NOTEBOOK_CELL_JOIN_SEPARATOR: str = ""
_NOTEBOOK_SECTION_SEPARATOR: str = "\n"

# ---------------------------------------------------------------------------
# Parallel scan constants
# ---------------------------------------------------------------------------

# Maximum number of worker threads accepted by execute_scan and the CLI.
# Values above this are rejected at the call site before reaching the executor.
MAX_WORKER_COUNT: int = 32
# Minimum worker count. Values at or below this run sequentially; values above
# this switch execute_scan to the parallel code path.
MIN_WORKER_COUNT: int = 1
# Thread name prefix used by ThreadPoolExecutor for log and debugger visibility.
_PARALLEL_THREAD_NAME_PREFIX: str = "phi-scan-worker"


# ---------------------------------------------------------------------------
# Plugin registry (scan-scoped cache)
# ---------------------------------------------------------------------------


@cache
def _load_cached_plugin_registry() -> PluginRegistry:
    """Return the plugin registry for the current scan, discovering once.

    The result is cached for the duration of the process. ``execute_scan``
    clears the cache at the start of every invocation so a fresh registry
    is discovered per scan while per-file calls inside one scan share the
    same registry instance.

    Invariant: ``execute_scan`` is the only supported entry point for this
    cache's lifecycle. Callers that invoke ``execute_plugin_pass`` directly
    (outside ``execute_scan``) must pass a registry they constructed
    themselves and must not rely on this function; tests that exercise
    ``execute_scan`` are responsible for clearing the cache between runs
    (see the autouse fixture in ``tests/test_plugin_runtime.py``).
    """
    return load_plugin_registry()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_ignore_patterns(ignore_file_path: Path) -> list[str]:
    """Load gitignore-style exclusion patterns from a .phi-scanignore file.

    Blank lines and lines beginning with # are ignored. If the file does not
    exist, an info message is logged and an empty list is returned — a missing
    ignore file is not an error.

    Args:
        ignore_file_path: Path to the ignore file to load.

    Returns:
        A list of non-blank, non-comment pattern strings from the file, or an
        empty list if the file does not exist.
    """
    if not ignore_file_path.exists():
        _logger.info(_IGNORE_FILE_MISSING_INFO.format(path=ignore_file_path))
        return []
    raw_lines = ignore_file_path.read_text(encoding=DEFAULT_TEXT_ENCODING).splitlines()
    return [
        line for line in raw_lines if line.strip() and not line.startswith(_IGNORE_COMMENT_PREFIX)
    ]


def is_path_excluded(file_path: Path, exclusion_spec: pathspec.PathSpec) -> bool:
    """Return True if file_path matches any pattern in exclusion_spec.

    The path should be relative to the scan root so that patterns like
    ``node_modules/`` match at any directory depth.

    Args:
        file_path: The candidate path, relative to the scan root.
        exclusion_spec: A compiled pathspec.PathSpec built from gitignore-style
            patterns via ``pathspec.PathSpec.from_lines``.

    Returns:
        True if the path matches at least one exclusion pattern, False otherwise.
    """
    # as_posix() ensures forward slashes on Windows; pathspec gitignore patterns
    # always use forward slashes so str() would produce non-matching backslash paths.
    return exclusion_spec.match_file(file_path.as_posix())


def is_binary_file(file_path: Path) -> bool:
    """Return True if file_path appears to be a binary file.

    Checks the file extension first against KNOWN_BINARY_EXTENSIONS; if the
    extension is not in that set, reads the first BINARY_CHECK_BYTE_COUNT bytes
    and checks for a null byte, which strongly indicates binary content.

    Args:
        file_path: Path to the file to inspect. Must be a regular file.

    Returns:
        True if the file is binary, False if it appears to be a text file.

    Raises:
        OSError: If the file cannot be opened or read (e.g. PermissionError,
            I/O error on a networked or FUSE filesystem). Callers inside
            collect_scan_targets have an outer OSError handler; direct callers
            must handle this themselves.
    """
    extension = file_path.suffix.lower()
    if extension in KNOWN_BINARY_EXTENSIONS:
        return True
    # Archive files contain binary data (ZIP magic bytes include null bytes) but
    # are handled by the archive scanner, not skipped as binary. Returning False
    # here allows collect_scan_targets to pass archives to scan_file.
    if extension in ARCHIVE_EXTENSIONS:
        return False
    # open(_BINARY_READ_MODE).read(N) reads only the first N bytes — read_bytes()
    # would load the entire file before slicing, wasting memory on files near the limit.
    with file_path.open(_BINARY_READ_MODE) as binary_reader:
        file_header = binary_reader.read(BINARY_CHECK_BYTE_COUNT)
    return _NULL_BYTE in file_header


def collect_scan_targets(
    root_path: Path,
    excluded_patterns: list[str],
    config: ScanConfig,
) -> list[Path]:
    """Return all scannable files under root_path after applying all filters.

    Filters applied to each candidate, in order:

    1. Skip symlinks (log WARNING — symlink traversal is prohibited).
    2. Skip directories.
    3. Skip paths matching any exclusion pattern (log DEBUG).
    4. Skip files whose extension is not in include_extensions, if set (log DEBUG).
    5. Skip files exceeding config.max_file_size_mb (log WARNING).
    6. Skip binary files (log INFO).

    An OSError on any individual file (including PermissionError) is caught,
    logged as a WARNING, and skipped. The scan continues with remaining files.

    Args:
        root_path: Root directory to scan recursively via rglob("*").
        excluded_patterns: Combined gitignore-style patterns from .phi-scanignore
            and config.exclude_paths. Compiled once before traversal begins.
        config: Scan configuration controlling size limits and extension filters.

    Returns:
        Ordered list of Path objects representing files to scan.

    Raises:
        TraversalError: If root_path does not exist or is not a directory.
    """
    _reject_invalid_scan_root(root_path)
    exclusion_spec = pathspec.PathSpec.from_lines(PathspecMatchStyle.GITIGNORE, excluded_patterns)
    max_file_size_bytes = config.max_file_size_mb * BYTES_PER_MEGABYTE
    scan_targets: list[Path] = []
    for candidate in root_path.rglob(_RGLOB_ALL_FILES_PATTERN):
        try:
            if _should_skip_symlink_candidate(candidate):
                continue
            if _should_skip_directory_candidate(candidate):
                continue
            # relative_to cannot raise ValueError — every candidate is yielded by
            # root_path.rglob(), which guarantees it is a descendant of root_path.
            relative_path = candidate.relative_to(root_path)
            if _should_skip_excluded_candidate(relative_path, exclusion_spec):
                continue
            if _should_skip_wrong_extension(candidate, config.include_extensions):
                continue
            if _should_skip_oversized_file(candidate, max_file_size_bytes):
                continue
            if _should_skip_binary_file(candidate):
                continue
            scan_targets.append(candidate)
        except OSError as file_error:
            # Catches PermissionError and other OS-level errors (e.g. I/O errors
            # from networked or fuse filesystems). Each file is isolated — one
            # unreadable file must never abort the entire scan.
            _logger.warning(_FILE_OS_ERROR_WARNING.format(path=candidate, error=file_error))
    return scan_targets


def _compute_display_path(file_path: Path) -> Path:
    """Return a CWD-relative path suitable for use in ScanFinding.file_path.

    ScanFinding requires a relative path to prevent PHI leakage via directory
    names (e.g. /patients/john_doe/ would embed patient context into every
    output format). This function converts absolute paths to relative before
    any ScanFinding is constructed.

    Args:
        file_path: The path as received from the filesystem (may be absolute).

    Returns:
        A relative path: unchanged if already relative; relative to CWD if the
        path is under CWD; or filename-only (Path(file_path.name)) as a safe
        fallback when the path is outside the current working directory.
    """
    if not file_path.is_absolute():
        return file_path
    try:
        return file_path.relative_to(Path.cwd())
    except ValueError:
        _logger.debug(_DISPLAY_PATH_OUTSIDE_CWD_DEBUG.format(path=file_path))
        return Path(file_path.name)


def scan_file(file_path: Path, config: ScanConfig) -> list[ScanFinding]:
    """Scan a single file for PHI/PII findings.

    Dispatches to the archive inspector for .jar/.war/.zip files; reads and
    decodes text for all other file types. Applies the scan cache, all four
    detection layers via ``detect_phi_in_text_content``, inline suppression
    directives, and confidence-threshold filtering before returning.

    Args:
        file_path: Path to the file to scan.
        config: Scan configuration controlling the confidence threshold.

    Returns:
        List of ScanFinding objects that passed suppression and threshold
        filtering. Empty list when no reportable PHI is found.
    """
    if file_path.suffix.lower() in ARCHIVE_EXTENSIONS:
        return _scan_archive_content(file_path, config)
    try:
        content_hash, file_content = _read_file_with_hash(file_path)
    except FileReadError as read_error:
        _logger.warning(str(read_error))
        return []
    display_path = _compute_display_path(file_path)
    return _execute_scan_with_cache(file_content, content_hash, display_path, config)


def execute_scan(
    scan_targets: list[Path],
    config: ScanConfig,
    worker_count: int = MIN_WORKER_COUNT,
) -> ScanResult:
    """Scan every file in scan_targets and return the aggregated ScanResult.

    Runs all local detection layers first, then applies the optional AI
    confidence review layer to medium-confidence findings before building
    the final result. When worker_count > 1, files are scanned concurrently
    using a bounded ThreadPoolExecutor; output order matches scan_targets order.

    Args:
        scan_targets: Ordered list of files to scan, as returned by
            collect_scan_targets.
        config: Scan configuration controlling thresholds and output format.
        worker_count: Number of worker threads. 1 (default) runs sequentially.
            Values above 1 enable parallel scanning up to MAX_WORKER_COUNT.

    Returns:
        A ScanResult aggregating all findings, file counts, timing, and
        risk classification.

    Raises:
        ValueError: If worker_count is outside
            [MIN_WORKER_COUNT, MAX_WORKER_COUNT].

    Not safe to call concurrently from multiple threads of a single
    process: the plugin-registry cache is cleared and warm-loaded at the
    top of this function, so an overlapping invocation would race the
    first call's workers. This is a CLI-scoped scanner, not a service;
    one ``execute_scan`` call per process lifecycle is the supported use.
    """
    from phi_scan.ai_review import apply_ai_review_to_findings

    if not MIN_WORKER_COUNT <= worker_count <= MAX_WORKER_COUNT:
        raise ValueError(
            _WORKER_COUNT_OUT_OF_RANGE_ERROR.format(
                worker_count=worker_count,
                minimum=MIN_WORKER_COUNT,
                maximum=MAX_WORKER_COUNT,
            ),
        )
    _load_cached_plugin_registry.cache_clear()
    _load_cached_plugin_registry()
    scan_start = time.monotonic()
    all_findings = _collect_all_findings(scan_targets, config, worker_count)
    reviewed_findings, ai_usage = apply_ai_review_to_findings(all_findings, config.ai_review_config)
    scan_duration = time.monotonic() - scan_start
    return build_scan_result(tuple(reviewed_findings), len(scan_targets), scan_duration, ai_usage)


def _collect_all_findings(
    scan_targets: list[Path],
    config: ScanConfig,
    worker_count: int,
) -> list[ScanFinding]:
    """Dispatch scan_targets to the sequential or parallel scan path.

    Args:
        scan_targets: Ordered list of files to scan.
        config: Scan configuration forwarded to each scan_file call.
        worker_count: Number of worker threads. Values at or below
            MIN_WORKER_COUNT run sequentially; higher values run in parallel.

    Returns:
        All findings from all files, in scan_targets order.
    """
    if worker_count > MIN_WORKER_COUNT:
        return run_parallel_scan(scan_targets, config, worker_count)
    return _run_sequential_scan(scan_targets, config)


def _run_sequential_scan(
    scan_targets: list[Path],
    config: ScanConfig,
) -> list[ScanFinding]:
    """Scan scan_targets one at a time and return all findings in input order.

    Args:
        scan_targets: Ordered list of files to scan.
        config: Scan configuration forwarded to each scan_file call.

    Returns:
        All findings from all files, in scan_targets order.
    """
    all_findings: list[ScanFinding] = []
    for file_path in scan_targets:
        all_findings.extend(scan_file(file_path, config))
    return all_findings


def run_parallel_scan(
    scan_targets: list[Path],
    config: ScanConfig,
    worker_count: int,
    on_file_complete: Callable[[Path], None] | None = None,
) -> list[ScanFinding]:
    """Scan scan_targets concurrently using a bounded ThreadPoolExecutor.

    This is the single parallel executor used by both ``execute_scan`` and the
    CLI progress-bar scan path. Uses ``submit`` + ``as_completed`` so per-file
    results become available in completion order, enabling callers to advance a
    progress UI as each file finishes. Results are re-sorted by original
    scan_targets index before flattening, so the returned findings list is
    deterministic regardless of thread completion order. Worker-thread
    exceptions are re-raised by ``Future.result()`` and propagate to the caller.

    This function does not apply the AI confidence review layer — callers that
    need a full ``ScanResult`` with AI review and timing should use
    ``execute_scan`` instead. ``run_parallel_scan`` is the lower-level primitive
    that returns raw findings from the local detection layers only.

    Args:
        scan_targets: Ordered list of files to scan.
        config: Scan configuration forwarded to each scan_file call.
        worker_count: Number of worker threads; must be > MIN_WORKER_COUNT.
        on_file_complete: Optional callback invoked on the orchestrating thread
            once per file, immediately after its ``scan_file`` result is
            collected. Receives the completed file path. Any exception raised
            by the callback propagates to the caller.

    Returns:
        All findings from all files, in scan_targets order.
    """
    if not scan_targets:
        return []
    indexed_results: dict[int, list[ScanFinding]] = {}
    future_to_index: dict[Future[list[ScanFinding]], int] = {}
    with ThreadPoolExecutor(
        max_workers=worker_count,
        thread_name_prefix=_PARALLEL_THREAD_NAME_PREFIX,
    ) as executor:
        for index, file_path in enumerate(scan_targets):
            future_to_index[executor.submit(scan_file, file_path, config)] = index
        for completed_future in as_completed(future_to_index):
            original_index = future_to_index[completed_future]
            indexed_results[original_index] = completed_future.result()
            if on_file_complete is not None:
                on_file_complete(scan_targets[original_index])
    ordered_per_file = [indexed_results[i] for i in range(len(scan_targets))]
    return [finding for file_findings in ordered_per_file for finding in file_findings]


# ---------------------------------------------------------------------------
# Private helpers — scan execution
# ---------------------------------------------------------------------------


def _read_file_with_hash(file_path: Path) -> tuple[str, str]:
    """Read file_path as raw bytes, compute its SHA-256 hash, and decode to text.

    Reads the file exactly once in binary mode so that the content hash is
    computed from the same bytes that are decoded to text — eliminating the
    TOCTOU race that would occur if hashing and reading were separate operations.

    Args:
        file_path: Path to the text file to read.

    Returns:
        Tuple of (content_hash, file_content) where content_hash is the
        SHA-256 hex digest of the raw bytes and file_content is the decoded text.

    Raises:
        FileReadError: If the file cannot be read (OSError) or decoded as
            DEFAULT_TEXT_ENCODING (UnicodeDecodeError).
    """
    try:
        raw_bytes = file_path.read_bytes()
    except OSError as os_error:
        raise FileReadError(
            _FILE_READ_OS_ERROR_MESSAGE.format(path=file_path, error=os_error)
        ) from os_error
    content_hash = hashlib.new(_SHA256_ALGORITHM, raw_bytes).hexdigest()
    try:
        file_content = raw_bytes.decode(DEFAULT_TEXT_ENCODING)
    except UnicodeDecodeError as decode_error:
        raise FileReadError(
            _FILE_DECODE_ERROR_WARNING.format(
                path=file_path, encoding=DEFAULT_TEXT_ENCODING, error=decode_error
            )
        ) from decode_error
    return content_hash, file_content


def _execute_scan_with_cache(
    file_content: str,
    content_hash: str,
    file_path: Path,
    config: ScanConfig,
) -> list[ScanFinding]:
    """Look up the cache, detect PHI on a miss, and apply post-scan filters.

    Stores only raw (unfiltered) findings in the cache so that a threshold
    change takes effect on the next run without invalidating the detection result.
    Post-scan filters are applied both on cache hits and fresh detections so the
    threshold is always evaluated against the current config.

    Args:
        file_content: Decoded text content of the file.
        content_hash: SHA-256 hex digest of the raw file bytes.
        file_path: Source path for attribution in findings.
        config: Scan configuration controlling threshold and suppression.

    Returns:
        Post-filtered findings for the file.
    """
    # Security note: content_hash is the SHA-256 hex digest of the raw file
    # bytes — it is never raw file content or decoded text. FileCacheKey stores
    # only file_path, content_hash (hex digest), and config_hash (hex digest).
    # store_cached_result serialises ScanFinding objects, which store only
    # value_hash (SHA-256 of the detected value), never the raw PHI value.
    cache_key = FileCacheKey(file_path=file_path, content_hash=content_hash)
    cached_raw = get_cached_result(cache_key)
    if cached_raw is not None:
        _logger.debug(_CACHE_HIT_DEBUG.format(path=file_path, count=len(cached_raw)))
        plugin_findings = _execute_plugin_pass_for_file(file_content, file_path)
        return _apply_post_scan_filters(cached_raw + plugin_findings, file_content, config)
    scannable_content = _preprocess_content_for_scan(file_content, file_path)
    raw_findings = detect_phi_in_text_content(scannable_content, file_path)
    store_cached_result(cache_key, raw_findings)
    plugin_findings = _execute_plugin_pass_for_file(file_content, file_path)
    return _apply_post_scan_filters(raw_findings + plugin_findings, file_content, config)


def _execute_plugin_pass_for_file(file_content: str, file_path: Path) -> list[ScanFinding]:
    """Run the scan-scoped plugin pass against one file and return findings.

    ``execute_scan`` performs ``cache_clear`` + warm-load synchronously
    before any worker threads are spawned, so every call here is a
    GIL-atomic dict lookup against a fully-populated, no-longer-mutated
    cache. ``execute_scan`` is documented as single-invocation per
    process, which is the contract that makes this lock-free read safe.
    """
    registry = _load_cached_plugin_registry()
    return execute_plugin_pass(file_content, file_path, registry)


def _apply_post_scan_filters(
    raw_findings: list[ScanFinding],
    file_content: str,
    config: ScanConfig,
) -> list[ScanFinding]:
    """Apply suppression, confidence, and severity filters to raw detection findings.

    Called after detection (fresh scan) and after cache retrieval so that
    threshold or suppression changes take effect even when returning cached results.

    Args:
        raw_findings: Unfiltered findings from detect_phi_in_text_content.
        file_content: Raw file content used to parse suppression directives.
        config: Scan configuration controlling the confidence and severity thresholds.

    Returns:
        Findings that passed suppression, confidence, and severity filtering.
    """
    filtered = _apply_suppression_filter(raw_findings, file_content)
    filtered = _apply_confidence_filter(filtered, config.confidence_threshold)
    return _apply_severity_filter(filtered, config.severity_threshold)


def _preprocess_content_for_scan(file_content: str, file_path: Path) -> str:
    """Return the content to pass to detect_phi_in_text_content.

    For Jupyter notebooks (.ipynb), extracts cell source and output text so
    the detection layers operate on executable content rather than JSON
    structure. All other file types are returned unchanged.

    Args:
        file_content: Raw decoded file content.
        file_path: Path used only to determine the preprocessing strategy.

    Returns:
        Text content ready for PHI scanning.
    """
    if file_path.suffix.lower() == _NOTEBOOK_EXTENSION:
        return _extract_notebook_text(file_content)
    return file_content


def _extract_notebook_text(notebook_content: str) -> str:
    """Extract cell source and output text from a Jupyter notebook JSON string.

    Joins multi-line source lists into single strings and concatenates all
    cells into a flat text block. Cells that cannot be parsed are skipped.
    If the top-level JSON is malformed, the raw content is returned so the
    detection layers can still attempt a scan.

    Args:
        notebook_content: Raw JSON content of a .ipynb file.

    Returns:
        Flat text containing all scannable notebook content.
    """
    try:
        notebook = json.loads(notebook_content)
    except json.JSONDecodeError:
        return notebook_content
    text_sections: list[str] = []
    for cell in notebook.get(_NOTEBOOK_CELLS_KEY, []):
        source = cell.get(_NOTEBOOK_CELL_SOURCE_KEY, [])
        if isinstance(source, list):
            text_sections.append(_NOTEBOOK_CELL_JOIN_SEPARATOR.join(source))
        elif isinstance(source, str):
            text_sections.append(source)
        for output in cell.get(_NOTEBOOK_CELL_OUTPUTS_KEY, []):
            output_text = output.get(_NOTEBOOK_OUTPUT_TEXT_KEY, [])
            if isinstance(output_text, list):
                text_sections.append(_NOTEBOOK_CELL_JOIN_SEPARATOR.join(output_text))
            elif isinstance(output_text, str):
                text_sections.append(output_text)
    return _NOTEBOOK_SECTION_SEPARATOR.join(text_sections)


def _apply_suppression_filter(
    findings: list[ScanFinding],
    file_content: str,
) -> list[ScanFinding]:
    """Remove findings covered by inline phi-scan:ignore directives.

    Args:
        findings: All findings produced by detect_phi_in_text_content.
        file_content: Raw file content used to parse suppression directives.

    Returns:
        Findings not suppressed by any inline directive.
    """
    suppression_map = load_suppressions(file_content.splitlines())
    return [f for f in findings if not is_finding_suppressed(f, suppression_map)]


def _apply_confidence_filter(
    findings: list[ScanFinding],
    confidence_threshold: float,
) -> list[ScanFinding]:
    """Remove findings below the configured confidence threshold.

    Args:
        findings: Suppression-filtered findings.
        confidence_threshold: Minimum confidence to retain a finding.

    Returns:
        Findings at or above confidence_threshold.
    """
    return [f for f in findings if f.confidence >= confidence_threshold]


def _apply_severity_filter(
    findings: list[ScanFinding],
    severity_threshold: SeverityLevel,
) -> list[ScanFinding]:
    """Remove findings below the configured severity threshold.

    Args:
        findings: Confidence-filtered findings.
        severity_threshold: Minimum severity level to retain a finding.

    Returns:
        Findings whose severity rank is at or above severity_threshold.
    """
    minimum_rank = SEVERITY_RANK[severity_threshold]
    return [f for f in findings if SEVERITY_RANK[f.severity] >= minimum_rank]


def _scan_archive_content(
    archive_path: Path,
    config: ScanConfig,
) -> list[ScanFinding]:
    """Scan text resources inside a ZIP, JAR, or WAR archive entirely in memory.

    Reads each eligible member using ZipFile.read() into a BytesIO-backed
    buffer — ZipFile.extract() and ZipFile.extractall() are never called
    because they write to disk, which would violate the local-execution-only
    contract. Only members whose extension appears in ARCHIVE_SCANNABLE_EXTENSIONS
    are scanned; .class files and other binary members are skipped.

    Args:
        archive_path: Path to the .zip, .jar, or .war file to inspect.
        config: Scan configuration forwarded to suppression and threshold logic.

    Returns:
        All findings from eligible archive members. Empty list on failure.
    """
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            return _scan_archive_members(archive, archive_path, config)
    except zipfile.BadZipFile as bad_zip_error:
        _logger.warning(_ARCHIVE_BAD_FORMAT_WARNING.format(path=archive_path, error=bad_zip_error))
        return []


def _is_safe_archive_member_path(member_name: str) -> bool:
    """Return True if the archive member path does not contain path traversal sequences.

    Rejects members whose name is an absolute path or whose path components
    contain ``..`` — both are ZIP-slip attack vectors. Although this scanner
    uses ZipFile.read() (not extract()), unsafe members are rejected early to
    avoid constructing invalid virtual_path values that could mislead reporting.

    Args:
        member_name: The archive member name as returned by ZipFile.namelist().

    Returns:
        True if the path is safe to process, False if it contains a traversal
        component or is an absolute path.
    """
    member_path = Path(member_name)
    if member_path.is_absolute():
        return False
    return _DOTDOT_PATH_COMPONENT not in member_path.parts


def _warn_member_too_large(member_info: zipfile.ZipInfo, archive_path: Path) -> None:
    """Emit a WARNING log when a member exceeds the absolute size limit."""
    _logger.warning(
        _ARCHIVE_MEMBER_TOO_LARGE_WARNING.format(
            member=member_info.filename,
            path=archive_path,
            size=member_info.file_size,
            limit=ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES,
        )
    )


def _warn_member_ratio_exceeded(
    member_info: zipfile.ZipInfo, archive_path: Path, ratio: float
) -> None:
    """Emit a WARNING log when a member's compression ratio exceeds the limit.

    Args:
        member_info: ZipInfo for the member (provides filename for the message).
        archive_path: Path to the containing archive (used in the message).
        ratio: Pre-computed compression ratio (caller must ensure compress_size > 0).
    """
    _logger.warning(
        _ARCHIVE_MEMBER_RATIO_WARNING.format(
            member=member_info.filename,
            path=archive_path,
            ratio=f"{ratio:.1f}",
            limit=ARCHIVE_MAX_COMPRESSION_RATIO,
        )
    )


def _passes_decompression_bomb_guards(member_info: zipfile.ZipInfo, archive_path: Path) -> bool:
    """Return True if the member passes both decompression bomb guards; False and log if not.

    Applies two independent guards before the member is read into memory:
    1. Absolute uncompressed size must not exceed ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES.
    2. Uncompressed size must not exceed ARCHIVE_MAX_COMPRESSION_RATIO × compressed size.
       Uses multiplication (file_size > limit × compress_size) to avoid floor-rounding
       ambiguity at the boundary and floating-point imprecision.

    Args:
        member_info: ZipInfo metadata for the member (read before decompression).
        archive_path: Path to the archive on disk (used for log messages only).

    Returns:
        True if the member passes both guards, False if either guard triggers.
    """
    if member_info.file_size > ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES:
        _warn_member_too_large(member_info, archive_path)
        return False
    if (
        member_info.compress_size > 0
        and member_info.file_size > ARCHIVE_MAX_COMPRESSION_RATIO * member_info.compress_size
    ):
        ratio = member_info.file_size / member_info.compress_size
        _warn_member_ratio_exceeded(member_info, archive_path, ratio)
        return False
    return True


def _scan_archive_members(
    archive: zipfile.ZipFile,
    archive_path: Path,
    config: ScanConfig,
) -> list[ScanFinding]:
    """Scan every eligible text member inside an open ZipFile.

    Args:
        archive: Open ZipFile object.
        archive_path: Path to the archive on disk (used for virtual member paths).
        config: Scan configuration.

    Returns:
        Aggregated findings from all eligible members.
    """
    findings: list[ScanFinding] = []
    for member_info in archive.infolist():
        member_name = member_info.filename
        if not _is_safe_archive_member_path(member_name):
            _logger.debug(
                _ARCHIVE_MEMBER_UNSAFE_PATH_DEBUG.format(member=member_name, path=archive_path)
            )
            continue
        if Path(member_name).suffix.lower() not in ARCHIVE_SCANNABLE_EXTENSIONS:
            continue
        if not _passes_decompression_bomb_guards(member_info, archive_path):
            continue
        try:
            member_bytes = archive.read(member_name)
            member_content = member_bytes.decode(DEFAULT_TEXT_ENCODING, errors="replace")
        except (  # noqa: PERF203 — per-member skip is intentional
            zipfile.BadZipFile,
            NotImplementedError,
            RuntimeError,
            OSError,
            zlib.error,
        ) as read_error:
            # zipfile.ZipFile.read() raises: BadZipFile (structural corruption),
            # NotImplementedError (unsupported compression method),
            # RuntimeError (encrypted member without password),
            # OSError (underlying I/O failure).
            # zlib.error (decompression failure on deflate-compressed member).
            # bytes.decode() with errors="replace" never raises UnicodeDecodeError.
            # Each failed member is skipped — one unreadable member must never
            # abort scanning of the remaining members in the archive.
            _logger.warning(
                _ARCHIVE_MEMBER_READ_ERROR_WARNING.format(
                    member=member_name, path=archive_path, error=read_error
                )
            )
            continue
        virtual_path = _compute_display_path(archive_path) / member_name
        raw_findings = detect_phi_in_text_content(member_content, virtual_path)
        plugin_findings = _execute_plugin_pass_for_file(member_content, virtual_path)
        member_findings = _apply_post_scan_filters(
            raw_findings + plugin_findings, member_content, config
        )
        findings.extend(member_findings)
    return findings


def build_scan_result(
    findings: tuple[ScanFinding, ...],
    files_scanned: int,
    scan_duration: float,
    ai_usage: AIUsageSummary | None = None,
) -> ScanResult:
    """Construct and return a fully populated ScanResult from aggregated scan data.

    Derives all computed fields (is_clean, files_with_findings, risk_level,
    severity_counts, category_counts) from the findings tuple so that
    execute_scan owns only the scan loop and nothing else.

    Args:
        findings: All findings produced by the scan.
        files_scanned: Total number of files passed to scan_file.
        scan_duration: Wall-clock seconds measured by execute_scan.
        ai_usage: Aggregated token usage from AI confidence review, or None
            when AI review was disabled for this scan.

    Returns:
        A fully populated, immutable ScanResult.
    """
    is_clean = not findings
    # file_path is location metadata used for deduplication, not the detected
    # PHI value itself (which is stored only as value_hash per policy).
    # KNOWN RISK: filenames can embed PHI (e.g. john_doe_ssn.csv). Whether
    # file_path requires hashing is an architectural decision deferred to
    # Phase 2 security review — do not dismiss this without that review.
    files_with_findings = len({finding.file_path for finding in findings})
    return ScanResult(
        findings=findings,
        files_scanned=files_scanned,
        files_with_findings=files_with_findings,
        scan_duration=scan_duration,
        is_clean=is_clean,
        risk_level=_derive_risk_level(findings),
        severity_counts=_count_by_severity(findings),
        category_counts=_count_by_category(findings),
        ai_usage=ai_usage,
    )


# ---------------------------------------------------------------------------
# Private helpers — traversal filters
# ---------------------------------------------------------------------------


def _reject_invalid_scan_root(root_path: Path) -> None:
    """Raise TraversalError if root_path is not a readable, existing, non-symlink directory.

    Covers three distinct invalid states: a symlink (traversal is prohibited through
    symlinked roots), a path that does not exist, and a path that exists but is not a
    directory (e.g. a file passed where a root was expected).

    Args:
        root_path: The scan root to validate.

    Raises:
        TraversalError: If root_path is a symlink, does not exist, or is not a directory.
    """
    if root_path.is_symlink():
        raise TraversalError(_ROOT_PATH_IS_SYMLINK_ERROR.format(path=root_path))
    if not root_path.exists():
        raise TraversalError(_ROOT_PATH_NOT_FOUND_ERROR.format(path=root_path))
    if not root_path.is_dir():
        raise TraversalError(_ROOT_PATH_NOT_DIRECTORY_ERROR.format(path=root_path))


def _should_skip_directory_candidate(candidate: Path) -> bool:
    """Return True if candidate is a directory.

    Called after ``_should_skip_symlink_candidate`` in the traversal loop —
    symlinks (including symlinks pointing to directories) are already handled
    before this function is reached.

    Args:
        candidate: The filesystem entry to check.

    Returns:
        True if the candidate is a directory and should be skipped.
    """
    return candidate.is_dir()


def _should_skip_symlink_candidate(candidate: Path) -> bool:
    """Return True and log a warning if candidate is a symlink.

    Args:
        candidate: The filesystem entry to check.

    Returns:
        True if the candidate is a symlink and should be skipped.
    """
    if candidate.is_symlink():
        _logger.warning(_SYMLINK_SKIPPED_WARNING.format(path=candidate))
        return True
    return False


def _should_skip_excluded_candidate(
    relative_path: Path,
    exclusion_spec: pathspec.PathSpec,
) -> bool:
    """Return True and log a debug message if relative_path matches an exclusion pattern.

    Args:
        relative_path: The candidate path relative to the scan root.
        exclusion_spec: Compiled gitignore-style pattern spec.

    Returns:
        True if the path matches at least one exclusion pattern.
    """
    if is_path_excluded(relative_path, exclusion_spec):
        _logger.debug(_EXCLUDED_PATH_DEBUG.format(path=relative_path))
        return True
    return False


def _should_skip_wrong_extension(candidate: Path, include_extensions: list[str] | None) -> bool:
    """Return True and log a debug message if candidate's extension is not in the allowlist.

    Args:
        candidate: The file to check.
        include_extensions: Allowlisted extensions (e.g. [".py", ".ts"]), or None
            to scan all extensions.

    Returns:
        True if include_extensions is set and the file's extension is not in the list.
    """
    if include_extensions is None:
        return False
    if candidate.suffix.lower() not in include_extensions:
        _logger.debug(_EXTENSION_SKIPPED_DEBUG.format(path=candidate))
        return True
    return False


def _should_skip_oversized_file(candidate: Path, max_file_size_bytes: int) -> bool:
    """Return True and log a warning if candidate's size exceeds the configured limit.

    The megabyte value shown in the log message is derived from max_file_size_bytes
    to guarantee consistency — there is no separate MB parameter that could diverge.

    Args:
        candidate: The file to check.
        max_file_size_bytes: Maximum allowed size in bytes.

    Returns:
        True if the file is larger than max_file_size_bytes.
    """
    if candidate.lstat().st_size > max_file_size_bytes:
        limit_mb = max_file_size_bytes // BYTES_PER_MEGABYTE
        _logger.warning(_OVERSIZED_FILE_SKIPPED_WARNING.format(path=candidate, limit_mb=limit_mb))
        return True
    return False


def _should_skip_binary_file(candidate: Path) -> bool:
    """Return True and log an info message if candidate is a binary file.

    Args:
        candidate: The file to check.

    Returns:
        True if the file is detected as binary.
    """
    if is_binary_file(candidate):
        _logger.info(_BINARY_FILE_SKIPPED_INFO.format(path=candidate))
        return True
    return False


# ---------------------------------------------------------------------------
# Private helpers — result aggregation
# ---------------------------------------------------------------------------


def _derive_risk_level(findings: tuple[ScanFinding, ...]) -> RiskLevel:
    """Derive the overall risk level from the severity distribution of findings.

    Mapping (highest severity present → risk level):
    - No findings            → CLEAN
    - Any HIGH findings      → CRITICAL
    - Only MEDIUM findings   → HIGH
    - Only LOW findings      → MODERATE
    - Only INFO findings     → LOW

    Args:
        findings: All findings produced by the scan.

    Returns:
        The overall RiskLevel for the scan result.
    """
    if not findings:
        return RiskLevel.CLEAN
    severity_levels = {finding.severity for finding in findings}
    if SeverityLevel.HIGH in severity_levels:
        return RiskLevel.CRITICAL
    if SeverityLevel.MEDIUM in severity_levels:
        return RiskLevel.HIGH
    if SeverityLevel.LOW in severity_levels:
        return RiskLevel.MODERATE
    if SeverityLevel.INFO in severity_levels:
        return RiskLevel.LOW
    raise PhiDetectionError(_UNMAPPED_SEVERITY_LEVELS_ERROR.format(levels=sorted(severity_levels)))


def _count_by_severity(
    findings: tuple[ScanFinding, ...],
) -> MappingProxyType[SeverityLevel, int]:
    """Return finding counts keyed by SeverityLevel.

    All severity levels are present in the returned mapping; levels with no
    findings have a count of zero.

    Args:
        findings: All findings to aggregate.

    Returns:
        An immutable mapping from SeverityLevel to finding count.
    """
    raw_counts = Counter(finding.severity for finding in findings)
    severity_counts: dict[SeverityLevel, int] = {
        level: raw_counts.get(level, 0) for level in SeverityLevel
    }
    return MappingProxyType(severity_counts)


def _count_by_category(
    findings: tuple[ScanFinding, ...],
) -> MappingProxyType[PhiCategory, int]:
    """Return finding counts keyed by PhiCategory.

    All PHI categories are present in the returned mapping; categories with no
    findings have a count of zero.

    Args:
        findings: All findings to aggregate.

    Returns:
        An immutable mapping from PhiCategory to finding count.
    """
    raw_counts = Counter(finding.hipaa_category for finding in findings)
    category_counts: dict[PhiCategory, int] = {
        category: raw_counts.get(category, 0) for category in PhiCategory
    }
    return MappingProxyType(category_counts)
