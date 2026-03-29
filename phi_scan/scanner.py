"""Recursive file traversal and detection engine entry point."""

from __future__ import annotations

import json
import logging
import time
import zipfile
from collections import Counter
from pathlib import Path
from types import MappingProxyType

import pathspec

from phi_scan.cache import FileCacheKey, compute_file_hash, get_cached_result, store_cached_result
from phi_scan.constants import (
    ARCHIVE_EXTENSIONS,
    ARCHIVE_SCANNABLE_EXTENSIONS,
    BINARY_CHECK_BYTE_COUNT,
    BYTES_PER_MEGABYTE,
    DEFAULT_TEXT_ENCODING,
    KNOWN_BINARY_EXTENSIONS,
    PathspecMatchStyle,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.detection_coordinator import detect_phi_in_text_content
from phi_scan.exceptions import PhiDetectionError, TraversalError
from phi_scan.logging_config import get_logger
from phi_scan.models import ScanConfig, ScanFinding, ScanResult
from phi_scan.suppression import is_finding_suppressed, load_suppressions

__all__ = [
    "collect_scan_targets",
    "execute_scan",
    "is_binary_file",
    "is_path_excluded",
    "load_ignore_patterns",
    "scan_file",
]

_logger: logging.Logger = get_logger("scanner")

# ---------------------------------------------------------------------------
# Log and error message templates
# ---------------------------------------------------------------------------

_ROOT_PATH_NOT_FOUND_ERROR: str = "Scan root {path!r} does not exist"
_ROOT_PATH_NOT_DIRECTORY_ERROR: str = "Scan root {path!r} is not a directory"
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
_CACHE_HIT_DEBUG: str = "Cache hit for {path!r} — returning {count} cached findings"

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

# Jupyter notebook (.ipynb) content extraction keys — used by
# _extract_notebook_text to pull cell source and output text from
# the JSON structure without embedding string literals in logic code.
_NOTEBOOK_EXTENSION: str = ".ipynb"
_NOTEBOOK_CELLS_KEY: str = "cells"
_NOTEBOOK_CELL_SOURCE_KEY: str = "source"
_NOTEBOOK_CELL_OUTPUTS_KEY: str = "outputs"
_NOTEBOOK_OUTPUT_TEXT_KEY: str = "text"
_NOTEBOOK_CELL_JOIN_SEPARATOR: str = ""
_NOTEBOOK_SECTION_SEPARATOR: str = "\n"


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
    file_content = _read_file_content(file_path)
    if file_content is None:
        return []
    cache_key = FileCacheKey(file_path=file_path, content_hash=compute_file_hash(file_path))
    cached = get_cached_result(cache_key)
    if cached is not None:
        _logger.debug(_CACHE_HIT_DEBUG.format(path=file_path, count=len(cached)))
        return cached
    scannable_content = _preprocess_content_for_scan(file_content, file_path)
    raw_findings = detect_phi_in_text_content(scannable_content, file_path)
    findings = _apply_suppression_filter(raw_findings, file_content)
    findings = _apply_confidence_filter(findings, config.confidence_threshold)
    store_cached_result(cache_key, findings)
    return findings


def execute_scan(scan_targets: list[Path], config: ScanConfig) -> ScanResult:
    """Scan every file in scan_targets and return the aggregated ScanResult.

    Responsibility: run the scan loop. Result construction is delegated to
    build_scan_result so this function is describable in one sentence.

    Args:
        scan_targets: Ordered list of files to scan, as returned by
            collect_scan_targets.
        config: Scan configuration controlling thresholds and output format.

    Returns:
        A ScanResult aggregating all findings, file counts, timing, and
        risk classification.
    """
    scan_start = time.monotonic()
    all_findings: list[ScanFinding] = []
    for file_path in scan_targets:
        file_findings = scan_file(file_path, config)
        all_findings.extend(file_findings)
    scan_duration = time.monotonic() - scan_start
    return build_scan_result(tuple(all_findings), len(scan_targets), scan_duration)


# ---------------------------------------------------------------------------
# Private helpers — scan execution
# ---------------------------------------------------------------------------


def _read_file_content(file_path: Path) -> str | None:
    """Read and decode file_path as UTF-8 text, returning None on failure.

    Decoding errors are treated as warnings rather than hard failures so that
    a single malformed file cannot abort an entire scan.

    Args:
        file_path: Path to the text file to read.

    Returns:
        Decoded file content, or None if the file cannot be read or decoded.
    """
    try:
        return file_path.read_text(encoding=DEFAULT_TEXT_ENCODING)
    except UnicodeDecodeError as decode_error:
        _logger.warning(
            _FILE_DECODE_ERROR_WARNING.format(
                path=file_path, encoding=DEFAULT_TEXT_ENCODING, error=decode_error
            )
        )
        return None


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
    for member_name in archive.namelist():
        if Path(member_name).suffix.lower() not in ARCHIVE_SCANNABLE_EXTENSIONS:
            continue
        try:
            member_bytes = archive.read(member_name)
            member_content = member_bytes.decode(DEFAULT_TEXT_ENCODING, errors="replace")
        except Exception as read_error:
            _logger.warning(
                _ARCHIVE_MEMBER_READ_ERROR_WARNING.format(
                    member=member_name, path=archive_path, error=read_error
                )
            )
            continue
        virtual_path = archive_path / member_name
        raw_findings = detect_phi_in_text_content(member_content, virtual_path)
        member_findings = _apply_suppression_filter(raw_findings, member_content)
        member_findings = _apply_confidence_filter(member_findings, config.confidence_threshold)
        findings.extend(member_findings)
    return findings


def build_scan_result(
    findings: tuple[ScanFinding, ...],
    files_scanned: int,
    scan_duration: float,
) -> ScanResult:
    """Construct and return a fully populated ScanResult from aggregated scan data.

    Derives all computed fields (is_clean, files_with_findings, risk_level,
    severity_counts, category_counts) from the findings tuple so that
    execute_scan owns only the scan loop and nothing else.

    Args:
        findings: All findings produced by the scan.
        files_scanned: Total number of files passed to scan_file.
        scan_duration: Wall-clock seconds measured by execute_scan.

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
