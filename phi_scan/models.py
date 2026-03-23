"""Dataclasses representing scan findings, results, and configuration for PhiScan."""

from __future__ import annotations

import re
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
# Both fields can legitimately be zero: a scan of an empty directory has
# files_scanned=0, and a scan that finds no PHI has files_with_findings=0.
_MINIMUM_ELIGIBLE_FILE_COUNT: int = 0
_MINIMUM_SCAN_DURATION: float = 0.0
# Zero is not a valid file-size limit — a scanner that skips all files is broken.
_MINIMUM_FILE_SIZE_MB: int = 1

# Build the pattern string explicitly — avoids the non-obvious triple-brace
# rf-string rf"[0-9a-f]{{{SHA256_HEX_DIGEST_LENGTH}}}". The result is "[0-9a-f]{64}".
_SHA256_PATTERN_STRING: str = "[0-9a-f]{" + str(SHA256_HEX_DIGEST_LENGTH) + "}"
# fullmatch matches the entire string — explicit ^ and $ anchors are redundant and omitted.
# A length-only check would accept base64 or truncated raw values of the right
# length — the hex character class enforces that value_hash is actually a SHA-256 digest.
_VALID_SHA256_PATTERN: re.Pattern[str] = re.compile(_SHA256_PATTERN_STRING)


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
        if not _VALID_SHA256_PATTERN.fullmatch(self.value_hash):
            raise PhiDetectionError(
                f"value_hash is not a valid SHA-256 hex digest — "
                f"must be exactly {SHA256_HEX_DIGEST_LENGTH} lowercase hex characters [0-9a-f], "
                f"got {len(self.value_hash)} characters"
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
            is_clean=False with findings=() is explicitly valid — it means raw
            detections were produced but all fell below the confidence threshold
            and were filtered out before the result was built.
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

    def __post_init__(self) -> None:
        _validate_file_counts(self)
        _validate_scan_duration(self)
        _validate_clean_findings_consistency(self)
        _validate_clean_risk_level_consistency(self)


def _validate_file_counts(result: ScanResult) -> None:
    if result.files_scanned < _MINIMUM_ELIGIBLE_FILE_COUNT:
        raise PhiDetectionError(
            f"files_scanned ({result.files_scanned}) must be >= {_MINIMUM_ELIGIBLE_FILE_COUNT}"
        )
    if result.files_with_findings < _MINIMUM_ELIGIBLE_FILE_COUNT:
        raise PhiDetectionError(
            f"files_with_findings ({result.files_with_findings}) "
            f"must be >= {_MINIMUM_ELIGIBLE_FILE_COUNT}"
        )
    if result.files_with_findings > result.files_scanned:
        raise PhiDetectionError(
            f"files_with_findings ({result.files_with_findings}) exceeds "
            f"files_scanned ({result.files_scanned})"
        )


def _validate_scan_duration(result: ScanResult) -> None:
    if result.scan_duration < _MINIMUM_SCAN_DURATION:
        raise PhiDetectionError(
            f"scan_duration ({result.scan_duration!r}) must be >= {_MINIMUM_SCAN_DURATION}"
        )


def _validate_clean_findings_consistency(result: ScanResult) -> None:
    if result.is_clean and result.findings:
        raise PhiDetectionError(
            f"is_clean is True but findings contains {len(result.findings)} finding(s) — "
            "a clean result must have zero findings"
        )


def _validate_clean_risk_level_consistency(result: ScanResult) -> None:
    if result.is_clean and result.risk_level != RiskLevel.CLEAN:
        raise PhiDetectionError(
            f"is_clean is True but risk_level is {result.risk_level!r} — "
            "a clean result must have RiskLevel.CLEAN"
        )
    if not result.is_clean and result.risk_level == RiskLevel.CLEAN:
        raise PhiDetectionError(
            "risk_level is RiskLevel.CLEAN but is_clean is False — "
            "RiskLevel.CLEAN requires is_clean to be True"
        )


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
            Raises ConfigurationError on construction or post-construction mutation
            if set to True. The __setattr__ override enforces this at every assignment.
        max_file_size_mb: Files larger than this value in megabytes are skipped.
        include_extensions: If set, only files with a suffix in this list are scanned.
            None (default) scans all non-binary text files regardless of extension.
    """

    # ScanConfig is intentionally mutable (not frozen=True) so callers can update
    # individual fields post-construction (e.g. a CLI that applies flag overrides to a
    # file-loaded config). Defensive copies in __post_init__ guard against the caller
    # mutating the lists they passed in; they do not prevent mutation of the config itself.
    exclude_paths: list[str] = field(default_factory=list)
    severity_threshold: SeverityLevel = SeverityLevel.LOW
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    should_follow_symlinks: bool = False
    max_file_size_mb: int = MAX_FILE_SIZE_MB
    include_extensions: list[str] | None = None

    def __post_init__(self) -> None:
        # Field validation runs in __setattr__, which fires for every assignment
        # including those in __init__ — no duplicate guards needed here.
        # Compute both copies before assigning so both fields are updated together;
        # readers of this object never observe one updated field and one original.
        exclude_paths_copy = list(self.exclude_paths)
        include_extensions_copy: list[str] | None = (
            list(self.include_extensions) if self.include_extensions is not None else None
        )
        self.exclude_paths = exclude_paths_copy
        self.include_extensions = include_extensions_copy

    def __setattr__(self, name: str, value: object) -> None:
        # Re-enforce security-critical invariants on every field assignment so
        # post-construction mutation cannot bypass the __post_init__ guards.
        if name == "should_follow_symlinks" and value is True:
            raise ConfigurationError(
                "should_follow_symlinks must be False — symlink traversal is prohibited "
                "to prevent infinite loops and directory escape attacks."
            )
        if name == "max_file_size_mb" and isinstance(value, int) and not isinstance(value, bool):
            if value < _MINIMUM_FILE_SIZE_MB:
                raise ConfigurationError(
                    f"max_file_size_mb {value!r} must be >= {_MINIMUM_FILE_SIZE_MB}"
                )
        if name == "confidence_threshold" and isinstance(value, float):
            if not CONFIDENCE_SCORE_MINIMUM <= value <= CONFIDENCE_SCORE_MAXIMUM:
                raise ConfigurationError(
                    f"confidence_threshold {value!r} is outside the valid range "
                    f"[{CONFIDENCE_SCORE_MINIMUM}, {CONFIDENCE_SCORE_MAXIMUM}]"
                )
        super().__setattr__(name, value)
