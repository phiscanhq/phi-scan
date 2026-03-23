"""Dataclasses representing scan findings, results, and configuration for PhiScan."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import final

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
_MINIMUM_FILE_COUNT: int = 0
_MINIMUM_SCAN_DURATION: float = 0.0
# Zero is not a valid file-size limit — a scanner that skips all files is broken.
_MINIMUM_FILE_SIZE_MB: int = 1
# An empty list means "scan no files" — callers who want unrestricted scanning
# must pass None, not []. Enforced to prevent silent HIPAA coverage gaps.
_MINIMUM_INCLUDE_EXTENSIONS_COUNT: int = 1
# Extensions must start with a dot so they match pathlib.Path.suffix values
# (e.g. ".py", not "py"). Bare extensions silently match nothing.
_EXTENSION_DOT_PREFIX: str = "."


class _ConfigField(StrEnum):
    """Field names for ScanConfig — used in __setattr__ dispatch.

    StrEnum values equal the Python attribute names so Python's attribute
    protocol (which passes field names as plain strings) can be compared
    directly against enum members with ==. Using an enum instead of bare
    string constants means a misspelled member raises AttributeError at
    import time rather than silently skipping validation at runtime.
    """

    SHOULD_FOLLOW_SYMLINKS = "should_follow_symlinks"
    MAX_FILE_SIZE_MB = "max_file_size_mb"
    CONFIDENCE_THRESHOLD = "confidence_threshold"
    SEVERITY_THRESHOLD = "severity_threshold"
    EXCLUDE_PATHS = "exclude_paths"
    INCLUDE_EXTENSIONS = "include_extensions"


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
            Callers are responsible for hashing before construction. Hashing belongs in the
            detection layer (scanner.py), not here — the model stores data, does not transform
            it. The format is enforced (64 lowercase hex chars) but the model cannot verify the
            caller hashed the correct value; that obligation rests with the detection layer.
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
        _reject_invalid_line_number(self)
        _reject_invalid_value_hash(self)
        _reject_out_of_range_confidence(self)


def _reject_invalid_line_number(finding: ScanFinding) -> None:
    if finding.line_number < _MINIMUM_LINE_NUMBER:
        raise PhiDetectionError(
            f"line_number {finding.line_number!r} is invalid — "
            f"line numbers are 1-indexed and must be >= {_MINIMUM_LINE_NUMBER}"
        )


def _reject_invalid_value_hash(finding: ScanFinding) -> None:
    if not _VALID_SHA256_PATTERN.fullmatch(finding.value_hash):
        raise PhiDetectionError(
            f"value_hash {finding.value_hash!r} is not a valid SHA-256 hex digest — "
            f"must be exactly {SHA256_HEX_DIGEST_LENGTH} lowercase hex characters [0-9a-f], "
            f"got {len(finding.value_hash)} characters"
        )


def _reject_out_of_range_confidence(finding: ScanFinding) -> None:
    if not CONFIDENCE_SCORE_MINIMUM <= finding.confidence <= CONFIDENCE_SCORE_MAXIMUM:
        raise PhiDetectionError(
            f"confidence {finding.confidence!r} is outside the valid range "
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
        _reject_negative_files_scanned(self)
        _reject_negative_files_with_findings(self)
        _reject_files_with_findings_exceeding_files_scanned(self)
        _reject_negative_scan_duration(self)
        _reject_clean_result_with_findings(self)
        _reject_clean_flag_with_non_clean_risk_level(self)
        _reject_non_clean_flag_with_clean_risk_level(self)


def _reject_negative_files_scanned(result: ScanResult) -> None:
    if result.files_scanned < _MINIMUM_FILE_COUNT:
        raise PhiDetectionError(
            f"files_scanned ({result.files_scanned}) must be >= {_MINIMUM_FILE_COUNT}"
        )


def _reject_negative_files_with_findings(result: ScanResult) -> None:
    if result.files_with_findings < _MINIMUM_FILE_COUNT:
        raise PhiDetectionError(
            f"files_with_findings ({result.files_with_findings}) must be >= {_MINIMUM_FILE_COUNT}"
        )


def _reject_files_with_findings_exceeding_files_scanned(result: ScanResult) -> None:
    if result.files_with_findings > result.files_scanned:
        raise PhiDetectionError(
            f"files_with_findings ({result.files_with_findings}) exceeds "
            f"files_scanned ({result.files_scanned})"
        )


def _reject_negative_scan_duration(result: ScanResult) -> None:
    if result.scan_duration < _MINIMUM_SCAN_DURATION:
        raise PhiDetectionError(
            f"scan_duration ({result.scan_duration!r}) must be >= {_MINIMUM_SCAN_DURATION}"
        )


def _reject_clean_result_with_findings(result: ScanResult) -> None:
    if result.is_clean and result.findings:
        raise PhiDetectionError(
            f"is_clean is True but findings contains {len(result.findings)} finding(s) — "
            "a clean result must have zero findings"
        )


def _reject_clean_flag_with_non_clean_risk_level(result: ScanResult) -> None:
    if result.is_clean and result.risk_level != RiskLevel.CLEAN:
        raise PhiDetectionError(
            f"is_clean is True but risk_level is {result.risk_level!r} — "
            "a clean result must have RiskLevel.CLEAN"
        )


def _reject_non_clean_flag_with_clean_risk_level(result: ScanResult) -> None:
    if not result.is_clean and result.risk_level == RiskLevel.CLEAN:
        raise PhiDetectionError(
            "risk_level is RiskLevel.CLEAN but is_clean is False — "
            "RiskLevel.CLEAN requires is_clean to be True"
        )


@final
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
            if set to True. The __setattr__ override enforces this at every normal
            assignment. Callers must not bypass __setattr__ via object.__setattr__.
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
        # __init__ already validated both list fields via __setattr__; make
        # defensive copies so the caller's original list cannot be mutated
        # through a reference they still hold after construction.
        exclude_paths_copy = list(self.exclude_paths)
        include_extensions_copy: list[str] | None = (
            list(self.include_extensions) if self.include_extensions is not None else None
        )
        self.exclude_paths = exclude_paths_copy
        self.include_extensions = include_extensions_copy

    def __setattr__(self, name: str, value: object) -> None:
        validator = _FIELD_VALIDATORS.get(name)
        if validator is not None:
            validator(value)
        else:
            # Reject unknown attribute names — a typo like shold_follow_symlinks
            # would silently create a phantom attribute while leaving the real
            # security control unchanged.
            raise ConfigurationError(
                f"ScanConfig has no field named {name!r} — "
                "assignment to unknown attributes is not permitted"
            )
        super().__setattr__(name, value)


def _validate_should_follow_symlinks(should_follow_symlinks: object) -> None:
    if not isinstance(should_follow_symlinks, bool):
        raise ConfigurationError(
            f"should_follow_symlinks must be a bool, got {should_follow_symlinks!r}"
        )
    if should_follow_symlinks:
        raise ConfigurationError(
            "should_follow_symlinks must be False — symlink traversal is prohibited "
            "to prevent infinite loops and directory escape attacks."
        )


def _validate_max_file_size_mb(max_file_size_mb: object) -> None:
    if not isinstance(max_file_size_mb, int) or isinstance(max_file_size_mb, bool):
        raise ConfigurationError(f"max_file_size_mb must be an int, got {max_file_size_mb!r}")
    if max_file_size_mb < _MINIMUM_FILE_SIZE_MB:
        raise ConfigurationError(
            f"max_file_size_mb {max_file_size_mb!r} must be >= {_MINIMUM_FILE_SIZE_MB}"
        )


def _validate_confidence_threshold(confidence_threshold: object) -> None:
    # Strict float — confidence is a ratio; passing 1 (int) instead of 1.0 is a caller
    # bug. Unlike max_file_size_mb (a natural integer count), a confidence score has no
    # meaningful integer representation. No coercion is performed; strict type required.
    if isinstance(confidence_threshold, bool) or not isinstance(confidence_threshold, float):
        raise ConfigurationError(
            f"confidence_threshold must be a float, got {confidence_threshold!r}"
        )
    if not CONFIDENCE_SCORE_MINIMUM <= confidence_threshold <= CONFIDENCE_SCORE_MAXIMUM:
        raise ConfigurationError(
            f"confidence_threshold {confidence_threshold!r} is outside the valid range "
            f"[{CONFIDENCE_SCORE_MINIMUM}, {CONFIDENCE_SCORE_MAXIMUM}]"
        )


def _validate_severity_threshold(severity_threshold: object) -> None:
    if not isinstance(severity_threshold, SeverityLevel):
        raise ConfigurationError(
            f"severity_threshold must be a SeverityLevel member, got {severity_threshold!r}"
        )


def _validate_exclude_paths(exclude_paths: object) -> None:
    if not isinstance(exclude_paths, list):
        raise ConfigurationError(f"exclude_paths must be a list, got {exclude_paths!r}")
    if not all(isinstance(path_pattern, str) for path_pattern in exclude_paths):
        raise ConfigurationError(f"exclude_paths must be a list of strings, got {exclude_paths!r}")


def _validate_include_extensions(include_extensions: object) -> None:
    if include_extensions is None:
        return
    if not isinstance(include_extensions, list):
        raise ConfigurationError(
            f"include_extensions must be a list or None, got {include_extensions!r}"
        )
    if len(include_extensions) < _MINIMUM_INCLUDE_EXTENSIONS_COUNT:
        raise ConfigurationError(
            "include_extensions must not be empty — "
            "use None to scan all non-binary text files regardless of extension"
        )
    if not all(isinstance(extension, str) for extension in include_extensions):
        raise ConfigurationError(
            f"include_extensions must be a list of strings, got {include_extensions!r}"
        )
    if not all(extension.startswith(_EXTENSION_DOT_PREFIX) for extension in include_extensions):
        raise ConfigurationError(
            f"include_extensions entries must start with '{_EXTENSION_DOT_PREFIX}', "
            f"got {include_extensions!r}"
        )


# Dispatch table for ScanConfig.__setattr__ — maps each field name to its validator.
# Defined after all _validate_* functions so the references are valid at module load.
# __setattr__ resolves this name at call time (not at class definition time), so the
# forward reference from inside the class body is safe.
_FIELD_VALIDATORS: dict[str, Callable[[object], None]] = {
    _ConfigField.SHOULD_FOLLOW_SYMLINKS: _validate_should_follow_symlinks,
    _ConfigField.MAX_FILE_SIZE_MB: _validate_max_file_size_mb,
    _ConfigField.CONFIDENCE_THRESHOLD: _validate_confidence_threshold,
    _ConfigField.SEVERITY_THRESHOLD: _validate_severity_threshold,
    _ConfigField.EXCLUDE_PATHS: _validate_exclude_paths,
    _ConfigField.INCLUDE_EXTENSIONS: _validate_include_extensions,
}
