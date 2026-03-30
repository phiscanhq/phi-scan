"""Baseline snapshot management for incremental PHI scanning (Phase 3B).

A baseline lets teams adopt PhiScan incrementally in existing codebases:
acknowledge the current finding set as accepted, then enforce zero *new* PHI
going forward. Each baseline entry expires after ``baseline_max_age_days`` days
(default 90) so that teams cannot baseline a finding forever — it eventually
reverts to an active finding and must be remediated.

Baseline file: ``.phi-scanbaseline`` — committed to the repository.
No raw PHI values are ever stored. Each entry carries only the SHA-256 hash of
the detected value (identical to ``ScanFinding.value_hash``), the relative file
path, and metadata needed to match future findings without re-exposing the value.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType

import yaml

from phi_scan import __version__
from phi_scan.constants import (
    BASELINE_SCHEMA_VERSION,
    DEFAULT_BASELINE_FILENAME,
    DEFAULT_BASELINE_MAX_AGE_DAYS,
    DEFAULT_TEXT_ENCODING,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.exceptions import BaselineError
from phi_scan.models import ScanFinding, ScanResult

__all__ = [
    "BaselineDiff",
    "BaselineEntry",
    "BaselineSnapshot",
    "BaselineSummary",
    "check_baseline_drift",
    "compute_baseline_diff",
    "create_baseline",
    "filter_baselined_findings",
    "get_baseline_summary",
    "is_finding_baselined",
    "load_baseline",
    "save_baseline",
]

# ---------------------------------------------------------------------------
# Private constants
# ---------------------------------------------------------------------------

_DEFAULT_BASELINE_PATH: Path = Path(DEFAULT_BASELINE_FILENAME)

# YAML file header written before the data block.
# Explains the file's purpose and safety properties for developers who encounter
# it in a PR diff or while auditing the repository.
_YAML_FILE_HEADER: str = (
    "# PhiScan Baseline Snapshot — .phi-scanbaseline\n"
    "# Commit this file to track accepted PHI findings in your codebase.\n"
    "#\n"
    "# phi-scan scan --baseline   report only NEW findings not in this file\n"
    "# phi-scan baseline update   refresh after remediating findings\n"
    "# phi-scan baseline show     display summary statistics\n"
    "#\n"
    "# Entries expire after baseline_max_age_days days and revert to active.\n"
    "# No raw PHI values are stored — only SHA-256 hashes and finding metadata.\n"
    "#\n"
)

# Datetime format used in the YAML file.  ISO 8601 with explicit UTC offset so
# the file is unambiguous across machines in different time zones.
_ISO_DATETIME_FORMAT: str = "%Y-%m-%dT%H:%M:%S+00:00"

# YAML key names — centralised to prevent typo drift between read and write paths.
_KEY_FILE_PATH: str = "file_path"
_KEY_LINE_NUMBER: str = "line_number"
_KEY_LINE_CONTENT_HASH: str = "line_content_hash"
_KEY_ENTITY_TYPE: str = "entity_type"
_KEY_HIPAA_CATEGORY: str = "hipaa_category"
_KEY_VALUE_HASH: str = "value_hash"
_KEY_SEVERITY: str = "severity"
_KEY_CREATED_AT: str = "created_at"
_KEY_EXPIRES_AT: str = "expires_at"
_KEY_SCHEMA_VERSION: str = "schema_version"
_KEY_SCANNER_VERSION: str = "scanner_version"
_KEY_BASELINE_MAX_AGE_DAYS: str = "baseline_max_age_days"
_KEY_ENTRIES: str = "entries"

_SCHEMA_MISMATCH_ERROR: str = (
    "Baseline file schema version {actual} is not supported (expected {expected}). "
    "Run 'phi-scan baseline clear' then 'phi-scan baseline create' to reset."
)
_READ_ERROR: str = "Failed to read baseline file {path!r}: {error}"
_WRITE_ERROR: str = "Failed to write baseline file {path!r}: {error}"
_PARSE_ENTRY_ERROR: str = "Malformed baseline entry at index {index}: {error}"

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineEntry:
    """One accepted PHI finding stored in the baseline.

    Matching is keyed by ``(file_path, entity_type, value_hash)`` — the
    combination that uniquely identifies one PHI value of a given type in a
    given file, independent of line number shifts from code refactoring.
    ``line_content_hash`` is stored for informational display in ``baseline diff``
    but is not used as part of the match key.
    """

    file_path: Path
    line_number: int
    line_content_hash: str
    entity_type: str
    hipaa_category: PhiCategory
    value_hash: str
    severity: SeverityLevel
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class BaselineSnapshot:
    """Complete baseline state for one repository at a point in time."""

    entries: tuple[BaselineEntry, ...]
    schema_version: int
    created_at: datetime
    scanner_version: str
    baseline_max_age_days: int


@dataclass(frozen=True)
class BaselineDiff:
    """Comparison of a baseline against a current scan result.

    ``new_findings`` drive the exit-code decision in ``scan --baseline`` mode.
    ``resolved_entries`` confirm remediated work since the baseline was created.
    ``persisting_findings`` are still present but covered by a non-expired entry.
    """

    new_findings: tuple[ScanFinding, ...]
    resolved_entries: tuple[BaselineEntry, ...]
    persisting_findings: tuple[ScanFinding, ...]


@dataclass(frozen=True)
class BaselineSummary:
    """Statistics for a baseline snapshot, computed on demand."""

    total_entries: int
    active_entries: int
    expired_entries: int
    category_counts: MappingProxyType[PhiCategory, int]
    severity_counts: MappingProxyType[SeverityLevel, int]
    oldest_entry_age_days: int
    baseline_path: Path
    created_at: datetime
    scanner_version: str


# ---------------------------------------------------------------------------
# Private helpers — entry lifecycle
# ---------------------------------------------------------------------------


def _is_entry_expired(entry: BaselineEntry, now: datetime) -> bool:
    """Return True when the entry's expiry timestamp is in the past."""
    return now > entry.expires_at


def _entry_matches_finding(entry: BaselineEntry, finding: ScanFinding) -> bool:
    """Return True when entry and finding refer to the same PHI value in the same file.

    Matching is intentionally line-number-independent so that refactoring that
    shifts line numbers does not create false-new-finding noise.
    """
    return (
        entry.file_path == finding.file_path
        and entry.entity_type == finding.entity_type
        and entry.value_hash == finding.value_hash
    )


def _make_baseline_entry(finding: ScanFinding, max_age_days: int) -> BaselineEntry:
    """Construct a BaselineEntry from a ScanFinding with computed expiry."""
    now = datetime.now(UTC)
    # SHA-256 of code_context approximates the source-line hash. ScanFinding
    # does not expose the raw matched line separately; code_context (surrounding
    # lines) is the closest available representation for informational purposes.
    line_content_hash = hashlib.sha256(
        finding.code_context.encode(DEFAULT_TEXT_ENCODING)
    ).hexdigest()
    return BaselineEntry(
        file_path=finding.file_path,
        line_number=finding.line_number,
        line_content_hash=line_content_hash,
        entity_type=finding.entity_type,
        hipaa_category=finding.hipaa_category,
        value_hash=finding.value_hash,
        severity=finding.severity,
        created_at=now,
        expires_at=now + timedelta(days=max_age_days),
    )


def _is_finding_in_snapshot(
    finding: ScanFinding, snapshot: BaselineSnapshot, now: datetime
) -> bool:
    """Return True when finding is covered by a non-expired baseline entry."""
    return any(
        _entry_matches_finding(entry, finding) and not _is_entry_expired(entry, now)
        for entry in snapshot.entries
    )


# ---------------------------------------------------------------------------
# Private helpers — diff computation
# ---------------------------------------------------------------------------


def _find_new_findings(
    findings: tuple[ScanFinding, ...],
    active_entries: tuple[BaselineEntry, ...],
) -> list[ScanFinding]:
    """Return findings with no matching active baseline entry."""
    return [f for f in findings if not any(_entry_matches_finding(e, f) for e in active_entries)]


def _find_resolved_entries(
    active_entries: tuple[BaselineEntry, ...],
    findings: tuple[ScanFinding, ...],
) -> list[BaselineEntry]:
    """Return active entries with no matching current finding (remediated)."""
    return [e for e in active_entries if not any(_entry_matches_finding(e, f) for f in findings)]


def _find_persisting_findings(
    findings: tuple[ScanFinding, ...],
    active_entries: tuple[BaselineEntry, ...],
) -> list[ScanFinding]:
    """Return findings that have a matching active baseline entry (still present)."""
    return [f for f in findings if any(_entry_matches_finding(e, f) for e in active_entries)]


# ---------------------------------------------------------------------------
# Private helpers — summary statistics
# ---------------------------------------------------------------------------


def _count_entries_by_category(
    entries: list[BaselineEntry],
) -> dict[PhiCategory, int]:
    counts: dict[PhiCategory, int] = {}
    for entry in entries:
        counts[entry.hipaa_category] = counts.get(entry.hipaa_category, 0) + 1
    return counts


def _count_entries_by_severity(
    entries: list[BaselineEntry],
) -> dict[SeverityLevel, int]:
    counts: dict[SeverityLevel, int] = {}
    for entry in entries:
        counts[entry.severity] = counts.get(entry.severity, 0) + 1
    return counts


def _compute_oldest_entry_age_days(entries: list[BaselineEntry], now: datetime) -> int:
    """Return the age in days of the oldest entry, or 0 when entries is empty."""
    if not entries:
        return 0
    oldest_created_at = min(entry.created_at for entry in entries)
    return (now - oldest_created_at).days


# ---------------------------------------------------------------------------
# Private helpers — YAML serialization / deserialization
# ---------------------------------------------------------------------------


def _parse_iso_datetime(raw: object) -> datetime:
    """Parse an ISO 8601 string or datetime to a timezone-aware datetime.

    PyYAML may parse datetime strings to native datetime objects directly.
    Both forms are handled here so the deserialization path is robust.
    """
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            return raw.replace(tzinfo=UTC)
        return raw
    try:
        return datetime.fromisoformat(str(raw))
    except (ValueError, TypeError) as error:
        raise ValueError(f"Invalid datetime value {raw!r}: {error}") from error


def _parse_baseline_entry(raw: dict[str, object], index: int) -> BaselineEntry:
    """Deserialize one YAML mapping to a BaselineEntry.

    Args:
        raw: Dict from yaml.safe_load for one entry.
        index: Zero-based position in the entries list, used in error messages.

    Raises:
        BaselineError: If any required field is missing, malformed, or invalid.
    """
    try:
        return BaselineEntry(
            file_path=Path(str(raw[_KEY_FILE_PATH])),
            line_number=int(str(raw[_KEY_LINE_NUMBER])),
            line_content_hash=str(raw[_KEY_LINE_CONTENT_HASH]),
            entity_type=str(raw[_KEY_ENTITY_TYPE]),
            hipaa_category=PhiCategory(str(raw[_KEY_HIPAA_CATEGORY])),
            value_hash=str(raw[_KEY_VALUE_HASH]),
            severity=SeverityLevel(str(raw[_KEY_SEVERITY])),
            created_at=_parse_iso_datetime(raw[_KEY_CREATED_AT]),
            expires_at=_parse_iso_datetime(raw[_KEY_EXPIRES_AT]),
        )
    except (KeyError, ValueError, TypeError) as error:
        raise BaselineError(_PARSE_ENTRY_ERROR.format(index=index, error=error)) from error


def _serialize_baseline_entry(entry: BaselineEntry) -> dict[str, object]:
    """Serialize a BaselineEntry to a YAML-compatible dict."""
    return {
        _KEY_FILE_PATH: str(entry.file_path),
        _KEY_LINE_NUMBER: entry.line_number,
        _KEY_LINE_CONTENT_HASH: entry.line_content_hash,
        _KEY_ENTITY_TYPE: entry.entity_type,
        _KEY_HIPAA_CATEGORY: entry.hipaa_category.value,
        _KEY_VALUE_HASH: entry.value_hash,
        _KEY_SEVERITY: entry.severity.value,
        _KEY_CREATED_AT: entry.created_at.strftime(_ISO_DATETIME_FORMAT),
        _KEY_EXPIRES_AT: entry.expires_at.strftime(_ISO_DATETIME_FORMAT),
    }


def _snapshot_to_dict(snapshot: BaselineSnapshot) -> dict[str, object]:
    """Serialize a BaselineSnapshot to a YAML-compatible dict."""
    return {
        _KEY_SCHEMA_VERSION: snapshot.schema_version,
        _KEY_CREATED_AT: snapshot.created_at.strftime(_ISO_DATETIME_FORMAT),
        _KEY_SCANNER_VERSION: snapshot.scanner_version,
        _KEY_BASELINE_MAX_AGE_DAYS: snapshot.baseline_max_age_days,
        _KEY_ENTRIES: [_serialize_baseline_entry(e) for e in snapshot.entries],
    }


def _load_baseline_raw(baseline_path: Path) -> dict[str, object]:
    """Read and YAML-parse the baseline file.

    Raises:
        BaselineError: On I/O or YAML parse failure.
    """
    try:
        raw_text = baseline_path.read_text(encoding=DEFAULT_TEXT_ENCODING)
    except OSError as error:
        raise BaselineError(_READ_ERROR.format(path=baseline_path, error=error)) from error
    try:
        return yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as error:
        raise BaselineError(_READ_ERROR.format(path=baseline_path, error=error)) from error


def _parse_baseline_snapshot(raw: dict[str, object]) -> BaselineSnapshot:
    """Validate schema version and parse a raw YAML dict into a BaselineSnapshot.

    Raises:
        BaselineError: If the schema version is unsupported or any entry is malformed.
    """
    schema_raw = raw.get(_KEY_SCHEMA_VERSION, 0)
    schema_version = int(schema_raw) if isinstance(schema_raw, (int, str)) else 0
    if schema_version != BASELINE_SCHEMA_VERSION:
        raise BaselineError(
            _SCHEMA_MISMATCH_ERROR.format(actual=schema_version, expected=BASELINE_SCHEMA_VERSION)
        )
    raw_entries: list[dict[str, object]] = raw.get(_KEY_ENTRIES) or []  # type: ignore[assignment]
    entries = tuple(_parse_baseline_entry(entry, index) for index, entry in enumerate(raw_entries))
    age_raw = raw.get(_KEY_BASELINE_MAX_AGE_DAYS, DEFAULT_BASELINE_MAX_AGE_DAYS)
    max_age = int(age_raw) if isinstance(age_raw, (int, str)) else DEFAULT_BASELINE_MAX_AGE_DAYS
    return BaselineSnapshot(
        entries=entries,
        schema_version=schema_version,
        created_at=_parse_iso_datetime(raw.get(_KEY_CREATED_AT, "")),
        scanner_version=str(raw.get(_KEY_SCANNER_VERSION, "")),
        baseline_max_age_days=max_age,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_baseline(*, baseline_path: Path = _DEFAULT_BASELINE_PATH) -> BaselineSnapshot | None:
    """Load the baseline snapshot from disk.

    Args:
        baseline_path: Path to the .phi-scanbaseline file.

    Returns:
        Parsed BaselineSnapshot, or None when the file does not exist.

    Raises:
        BaselineError: If the file exists but cannot be read, parsed, or has
            an unsupported schema version.
    """
    if not baseline_path.exists():
        return None
    raw = _load_baseline_raw(baseline_path)
    return _parse_baseline_snapshot(raw)


def save_baseline(
    snapshot: BaselineSnapshot, *, baseline_path: Path = _DEFAULT_BASELINE_PATH
) -> None:
    """Serialize snapshot to YAML and write to baseline_path.

    Args:
        snapshot: The snapshot to persist.
        baseline_path: Destination file path.

    Raises:
        BaselineError: If the file cannot be written.
    """
    yaml_content = _YAML_FILE_HEADER + yaml.safe_dump(
        _snapshot_to_dict(snapshot),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    try:
        baseline_path.write_text(yaml_content, encoding=DEFAULT_TEXT_ENCODING)
    except OSError as error:
        raise BaselineError(_WRITE_ERROR.format(path=baseline_path, error=error)) from error


def create_baseline(
    scan_result: ScanResult,
    max_age_days: int = DEFAULT_BASELINE_MAX_AGE_DAYS,
    *,
    baseline_path: Path = _DEFAULT_BASELINE_PATH,
) -> BaselineSnapshot:
    """Create and persist a new baseline from the current scan result.

    Replaces any existing baseline file. Entries expire after max_age_days.

    Args:
        scan_result: Completed scan whose findings become the new baseline.
        max_age_days: Days until each entry expires.
        baseline_path: Destination file path.

    Returns:
        The newly created BaselineSnapshot (already written to disk).
    """
    entries = tuple(_make_baseline_entry(finding, max_age_days) for finding in scan_result.findings)
    snapshot = BaselineSnapshot(
        entries=entries,
        schema_version=BASELINE_SCHEMA_VERSION,
        created_at=datetime.now(UTC),
        scanner_version=__version__,
        baseline_max_age_days=max_age_days,
    )
    save_baseline(snapshot, baseline_path=baseline_path)
    return snapshot


def is_finding_baselined(finding: ScanFinding, snapshot: BaselineSnapshot) -> bool:
    """Return True when finding is covered by a non-expired baseline entry.

    Args:
        finding: The finding to check.
        snapshot: The active baseline snapshot.

    Returns:
        True if an active (non-expired) entry matches file_path + entity_type +
        value_hash; False otherwise.
    """
    now = datetime.now(UTC)
    return _is_finding_in_snapshot(finding, snapshot, now)


def filter_baselined_findings(
    findings: Sequence[ScanFinding], snapshot: BaselineSnapshot
) -> tuple[list[ScanFinding], list[ScanFinding]]:
    """Split findings into (new_findings, baselined_findings).

    ``new_findings`` are not covered by any active baseline entry.
    ``baselined_findings`` are covered and suppress the exit-code decision.

    Args:
        findings: All findings from the current scan.
        snapshot: The active baseline snapshot.

    Returns:
        Tuple of (new_findings, baselined_findings).
    """
    now = datetime.now(UTC)
    new_findings: list[ScanFinding] = []
    baselined_findings: list[ScanFinding] = []
    for finding in findings:
        if _is_finding_in_snapshot(finding, snapshot, now):
            baselined_findings.append(finding)
        else:
            new_findings.append(finding)
    return new_findings, baselined_findings


def compute_baseline_diff(snapshot: BaselineSnapshot, scan_result: ScanResult) -> BaselineDiff:
    """Compare a baseline against the current scan result.

    Args:
        snapshot: The baseline to compare against.
        scan_result: The current scan whose findings are the comparison target.

    Returns:
        BaselineDiff with new, resolved, and persisting finding sets.
    """
    now = datetime.now(UTC)
    active_entries = tuple(entry for entry in snapshot.entries if not _is_entry_expired(entry, now))
    new_findings = _find_new_findings(scan_result.findings, active_entries)
    resolved_entries = _find_resolved_entries(active_entries, scan_result.findings)
    persisting = _find_persisting_findings(scan_result.findings, active_entries)
    return BaselineDiff(
        new_findings=tuple(new_findings),
        resolved_entries=tuple(resolved_entries),
        persisting_findings=tuple(persisting),
    )


def get_baseline_summary(snapshot: BaselineSnapshot, baseline_path: Path) -> BaselineSummary:
    """Compute display statistics for a baseline snapshot.

    Args:
        snapshot: The snapshot to summarise.
        baseline_path: Path where the snapshot was loaded from (stored in summary).

    Returns:
        BaselineSummary with counts, age, and metadata.
    """
    now = datetime.now(UTC)
    active = [e for e in snapshot.entries if not _is_entry_expired(e, now)]
    expired = [e for e in snapshot.entries if _is_entry_expired(e, now)]
    return BaselineSummary(
        total_entries=len(snapshot.entries),
        active_entries=len(active),
        expired_entries=len(expired),
        category_counts=MappingProxyType(_count_entries_by_category(active)),
        severity_counts=MappingProxyType(_count_entries_by_severity(active)),
        oldest_entry_age_days=_compute_oldest_entry_age_days(active, now),
        baseline_path=baseline_path,
        created_at=snapshot.created_at,
        scanner_version=snapshot.scanner_version,
    )


def check_baseline_drift(old_snapshot: BaselineSnapshot, new_snapshot: BaselineSnapshot) -> int:
    """Return the percent change in entry count between two snapshots.

    A positive value means the new baseline has more entries than the old one,
    indicating PHI accumulation rather than remediation. The caller should
    compare this against BASELINE_DRIFT_WARNING_PERCENT.

    Args:
        old_snapshot: The baseline before the update.
        new_snapshot: The baseline after the update.

    Returns:
        Percent change as an integer (positive = increase, negative = decrease).
        Returns 0 when old_snapshot has no entries (no meaningful base to compare).
    """
    if not old_snapshot.entries:
        return 0
    old_count = len(old_snapshot.entries)
    new_count = len(new_snapshot.entries)
    return round((new_count - old_count) * 100 / old_count)
