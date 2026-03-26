"""Recursive file traversal and detection engine entry point."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from types import MappingProxyType

import pathspec

from phi_scan.constants import (
    BINARY_CHECK_BYTE_COUNT,
    BYTES_PER_MEGABYTE,
    DEFAULT_TEXT_ENCODING,
    KNOWN_BINARY_EXTENSIONS,
    PathspecMatchStyle,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.exceptions import PhiDetectionError, TraversalError
from phi_scan.logging_config import get_logger
from phi_scan.models import ScanConfig, ScanFinding, ScanResult

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
_IGNORE_FILE_MISSING_INFO: str = "Ignore file {path!r} not found — no patterns loaded"
# Phase 1B stub — emitted once per call to scan_file to prevent silent integration
# failures if the placeholder is accidentally left in place during Phase 2 wiring.
_SCAN_FILE_STUB_WARNING: str = (
    "scan_file is a Phase 1B stub — no PHI detection performed on {path!r}"
)
_UNMAPPED_SEVERITY_LEVELS_ERROR: str = (
    "No RiskLevel mapping for severity levels {levels!r} — update _derive_risk_level"
)
# Binary file detection constants — never embed these literals in logic code.
_RGLOB_ALL_FILES_PATTERN: str = "*"
_NULL_BYTE: bytes = b"\x00"
_BINARY_READ_MODE: str = "rb"


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
    return [line for line in raw_lines if line.strip() and not line.startswith("#")]


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
    return exclusion_spec.match_file(str(file_path))


def is_binary_file(file_path: Path) -> bool:
    """Return True if file_path appears to be a binary file.

    Checks the file extension first against KNOWN_BINARY_EXTENSIONS; if the
    extension is not in that set, reads the first BINARY_CHECK_BYTE_COUNT bytes
    and checks for a null byte, which strongly indicates binary content.

    Args:
        file_path: Path to the file to inspect. Must be a regular file.

    Returns:
        True if the file is binary, False if it appears to be a text file.
    """
    if file_path.suffix.lower() in KNOWN_BINARY_EXTENSIONS:
        return True
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

    Phase 1B placeholder — detection layers are implemented in Phase 2.
    Always returns an empty list. A WARNING is logged on every call so that
    the stub cannot silently survive into Phase 2 wiring without detection.

    Args:
        file_path: Path to the file to scan.
        config: Scan configuration (reserved for Phase 2 detection logic).

    Returns:
        An empty list. Detection logic is added in Phase 2B.
    """
    _logger.warning(_SCAN_FILE_STUB_WARNING.format(path=file_path))
    return []


def execute_scan(scan_targets: list[Path], config: ScanConfig) -> ScanResult:
    """Scan every file in scan_targets and return the aggregated ScanResult.

    Responsibility: run the scan loop. Result construction is delegated to
    _build_scan_result so this function is describable in one sentence.

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
    return _build_scan_result(tuple(all_findings), len(scan_targets), scan_duration)


# ---------------------------------------------------------------------------
# Private helpers — scan execution
# ---------------------------------------------------------------------------


def _build_scan_result(
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
    is_clean = len(findings) == 0
    files_with_findings = len({f.file_path for f in findings})
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
    """Raise TraversalError if root_path is not a readable, existing directory.

    Covers two distinct invalid states: a path that does not exist, and a path
    that exists but is not a directory (e.g. a file passed where a root was expected).

    Args:
        root_path: The scan root to validate.

    Raises:
        TraversalError: If root_path does not exist or is not a directory.
    """
    if not root_path.exists():
        raise TraversalError(_ROOT_PATH_NOT_FOUND_ERROR.format(path=root_path))
    if not root_path.is_dir():
        raise TraversalError(_ROOT_PATH_NOT_DIRECTORY_ERROR.format(path=root_path))


def _should_skip_directory_candidate(candidate: Path) -> bool:
    """Return True if candidate is a directory.

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
    if candidate.stat().st_size > max_file_size_bytes:
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
    raise PhiDetectionError(_UNMAPPED_SEVERITY_LEVELS_ERROR.format(levels=severity_levels))


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
    severity_counts: dict[SeverityLevel, int] = {level: 0 for level in SeverityLevel}
    for finding in findings:
        severity_counts[finding.severity] += 1
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
    category_counts: dict[PhiCategory, int] = {category: 0 for category in PhiCategory}
    for finding in findings:
        category_counts[finding.hipaa_category] += 1
    return MappingProxyType(category_counts)
