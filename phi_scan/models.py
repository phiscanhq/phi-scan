"""Dataclasses representing scan findings, results, and configuration for PhiScan."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from phi_scan.constants import (
    CONFIDENCE_SCORE_MAXIMUM,
    CONFIDENCE_SCORE_MINIMUM,
    DEFAULT_CONFIDENCE_THRESHOLD,
    MAX_FILE_SIZE_MB,
    SHA256_HEX_DIGEST_LENGTH,
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.exceptions import ConfigurationError, PhiDetectionError

__all__ = [
    "ScanConfig",
    "ScanFinding",
    "ScanResult",
]

_MINIMUM_LINE_NUMBER: int = 1


@dataclass(frozen=True)
class ScanFinding:
    """A single PHI/PII finding detected in a source file.

    Frozen to prevent accidental mutation after detection — findings are
    immutable records of what was observed at scan time.

    Args:
        file_path: Path to the file containing the finding.
        line_number: Line number (1-indexed) where the finding appears.
        entity_type: Pattern name that matched (e.g. "us_ssn", "email_address").
        hipaa_category: HIPAA Safe Harbor category of the detected identifier.
        confidence: Detection confidence score in the range [0.0, 1.0].
        detection_layer: Layer that produced the finding.
        value_hash: SHA-256 hex digest of the raw detected value — never the raw value itself.
        severity: Severity level derived from the confidence score.
        code_context: Surrounding source lines shown in reports for human review.
        remediation_hint: Actionable guidance for removing or replacing this PHI.
    """

    file_path: Path
    line_number: int
    entity_type: str
    hipaa_category: PhiCategory
    confidence: float
    detection_layer: DetectionLayer
    value_hash: str
    severity: SeverityLevel
    code_context: str
    remediation_hint: str

    def __post_init__(self) -> None:
        if self.line_number < _MINIMUM_LINE_NUMBER:
            raise PhiDetectionError(
                f"line_number {self.line_number!r} is invalid — "
                f"line numbers are 1-indexed and must be >= {_MINIMUM_LINE_NUMBER}"
            )
        if len(self.value_hash) != SHA256_HEX_DIGEST_LENGTH:
            raise PhiDetectionError(
                f"value_hash has length {len(self.value_hash)} "
                f"but a SHA-256 hex digest must be exactly {SHA256_HEX_DIGEST_LENGTH} characters"
            )
        if not CONFIDENCE_SCORE_MINIMUM <= self.confidence <= CONFIDENCE_SCORE_MAXIMUM:
            raise PhiDetectionError(
                f"confidence {self.confidence!r} is outside the valid range "
                f"[{CONFIDENCE_SCORE_MINIMUM}, {CONFIDENCE_SCORE_MAXIMUM}]"
            )


@dataclass(frozen=True)
class ScanResult:
    """The aggregated outcome of a completed scan operation.

    All container fields use immutable types so the sealed record cannot be
    mutated after the scanner produces it.

    Args:
        findings: All findings produced by the scan, ordered by file path then line number.
        files_scanned: Total number of files examined.
        files_with_findings: Number of files that contained at least one finding.
        scan_duration: Wall-clock time in seconds the scan took to complete.
        is_clean: True when the scan produced zero findings at or above the threshold.
        risk_level: Overall risk classification for the scanned codebase.
        severity_counts: Number of findings per severity level.
        category_counts: Number of findings per HIPAA PHI category.
    """

    findings: tuple[ScanFinding, ...]
    files_scanned: int
    files_with_findings: int
    scan_duration: float
    is_clean: bool
    risk_level: RiskLevel
    severity_counts: MappingProxyType[SeverityLevel, int]
    category_counts: MappingProxyType[PhiCategory, int]


@dataclass
class ScanConfig:
    """Configuration that controls the behaviour of a scan operation.

    All fields have safe defaults so callers can construct a minimal config
    and override only the settings relevant to their context.

    Args:
        exclude_paths: Glob patterns for paths to skip, evaluated at every directory depth.
        severity_threshold: Minimum severity level to include in the report.
        confidence_threshold: Minimum confidence score [0.0, 1.0] for a finding to be reported.
        should_follow_symlinks: Must remain False — symlink traversal is prohibited.
            Raises ConfigurationError immediately on construction if set to True.
        max_file_size_mb: Files larger than this value in megabytes are skipped.
        include_extensions: If set, only files with a suffix in this list are scanned.
            None (default) scans all non-binary text files regardless of extension.
    """

    exclude_paths: list[str] = field(default_factory=list)
    severity_threshold: SeverityLevel = SeverityLevel.LOW
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    should_follow_symlinks: bool = False
    max_file_size_mb: int = MAX_FILE_SIZE_MB
    include_extensions: list[str] | None = None

    def __post_init__(self) -> None:
        if self.should_follow_symlinks:
            raise ConfigurationError(
                "should_follow_symlinks must be False — symlink traversal is prohibited "
                "to prevent infinite loops and directory escape attacks."
            )
        if not CONFIDENCE_SCORE_MINIMUM <= self.confidence_threshold <= CONFIDENCE_SCORE_MAXIMUM:
            raise ConfigurationError(
                f"confidence_threshold {self.confidence_threshold!r} is outside the valid range "
                f"[{CONFIDENCE_SCORE_MINIMUM}, {CONFIDENCE_SCORE_MAXIMUM}]"
            )
        # Defensive copies prevent callers from mutating config state after construction.
        self.exclude_paths = list(self.exclude_paths)
        if self.include_extensions is not None:
            self.include_extensions = list(self.include_extensions)
