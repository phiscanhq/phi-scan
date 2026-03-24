"""Named constants, enums, and remediation guidance for PhiScan."""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "AUDIT_RETENTION_DAYS",
    "AUDIT_SCHEMA_VERSION",
    "BINARY_CHECK_BYTE_COUNT",
    "CACHE_SCHEMA_VERSION",
    "SHA256_HEX_DIGEST_LENGTH",
    "AI_LAYER_CONFIDENCE_ADJUSTMENT_MAX",
    "CONFIDENCE_FHIR_MAX",
    "CONFIDENCE_FHIR_MIN",
    "CONFIDENCE_HIGH_FLOOR",
    "CONFIDENCE_LOW_FLOOR",
    "CONFIDENCE_MEDIUM_FLOOR",
    "CONFIDENCE_NLP_MAX",
    "CONFIDENCE_NLP_MIN",
    "CONFIDENCE_REGEX_MAX",
    "CONFIDENCE_REGEX_MIN",
    "CONFIDENCE_SCORE_MAXIMUM",
    "CONFIDENCE_SCORE_MINIMUM",
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "DEFAULT_CONFIG_FILENAME",
    "DEFAULT_IGNORE_FILENAME",
    "DetectionLayer",
    "EXIT_CODE_CLEAN",
    "EXIT_CODE_VIOLATION",
    "HIPAA_REMEDIATION_GUIDANCE",
    "KNOWN_BINARY_EXTENSIONS",
    "BYTES_PER_MEGABYTE",
    "MAX_FILE_SIZE_BYTES",
    "MAX_FILE_SIZE_MB",
    "OutputFormat",
    "PhiCategory",
    "RiskLevel",
    "SeverityLevel",
]

# ---------------------------------------------------------------------------
# File names
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_FILENAME: str = ".phi-scanner.yml"
DEFAULT_IGNORE_FILENAME: str = ".phi-scanignore"

# ---------------------------------------------------------------------------
# Binary file detection
# ---------------------------------------------------------------------------

# TODO(2E.9): When archive inspection ships, remove .jar and .war from
# KNOWN_BINARY_EXTENSIONS so those files are passed to the archive inspector
# instead of being skipped as opaque binary. See PLAN.md Phase 2E.9.
KNOWN_BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".gif",
        ".ico",
        ".wasm",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".zip",
        ".tar",
        ".gz",
        ".jar",
        ".war",
        ".pyc",
        ".pyo",
        ".o",
        ".a",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".mp3",
        ".mp4",
        ".mov",
        ".avi",
        ".wav",
        ".ttf",
        ".woff",
        ".woff2",
        ".eot",
    }
)

# Number of bytes read from a file to detect binary content via null bytes.
BINARY_CHECK_BYTE_COUNT: int = 8192

# Length of a SHA-256 hex digest in characters. ScanFinding.value_hash must
# be exactly this length — raw PHI values are never stored, only their hashes.
SHA256_HEX_DIGEST_LENGTH: int = 64

# ---------------------------------------------------------------------------
# Confidence thresholds
# ---------------------------------------------------------------------------

# Default minimum confidence for a finding to be reported.
# 0.6 falls in the upper half of the LOW band (CONFIDENCE_LOW_FLOOR=0.40 to
# CONFIDENCE_MEDIUM_FLOOR=0.70), surfacing findings that are plausibly PHI
# while discarding very weak signals. Callers can raise this in .phi-scanner.yml
# to reduce noise at the cost of missing lower-confidence matches.
DEFAULT_CONFIDENCE_THRESHOLD: float = 0.6

# Confidence floor that separates HIGH severity from MEDIUM.
CONFIDENCE_HIGH_FLOOR: float = 0.90

# Confidence floor that separates MEDIUM severity from LOW.
CONFIDENCE_MEDIUM_FLOOR: float = 0.70

# Confidence floor that separates LOW severity from INFO.
# Findings below this value are assigned SeverityLevel.INFO and are logged
# but not flagged by default (below DEFAULT_CONFIDENCE_THRESHOLD).
CONFIDENCE_LOW_FLOOR: float = 0.40

# ---------------------------------------------------------------------------
# Confidence ranges by detection layer (informational — used in docs/logging)
# ---------------------------------------------------------------------------

# Valid confidence scores occupy [CONFIDENCE_SCORE_MINIMUM, CONFIDENCE_SCORE_MAXIMUM].
# Both bounds are inclusive. Scores outside this range are a bug in the detection layer.
CONFIDENCE_SCORE_MINIMUM: float = 0.0
# Absolute ceiling — used as the upper bound for layer ranges and normalization.
# All CONFIDENCE_*_MAX values reference this.
CONFIDENCE_SCORE_MAXIMUM: float = 1.0

# Score bounds per detection layer — the range a layer assigns to its findings.
# Layer 1 — Regex: structured patterns are unambiguous.
CONFIDENCE_REGEX_MIN: float = 0.85
CONFIDENCE_REGEX_MAX: float = CONFIDENCE_SCORE_MAXIMUM

# Layer 2 — NLP/NER: context-dependent, model uncertainty applies.
CONFIDENCE_NLP_MIN: float = 0.50
CONFIDENCE_NLP_MAX: float = 0.90

# Layer 3 — FHIR: schema-based structural match.
CONFIDENCE_FHIR_MIN: float = 0.80
CONFIDENCE_FHIR_MAX: float = 0.95

# Adjustment delta — not a score floor or ceiling.
# Layer 4 (AI) refines an existing score by at most this amount in either
# direction. Do not compare this constant against raw confidence scores.
AI_LAYER_CONFIDENCE_ADJUSTMENT_MAX: float = 0.15

# ---------------------------------------------------------------------------
# File size limit
# ---------------------------------------------------------------------------

# Files larger than this are skipped to bound memory usage during scanning.
# At 8192-byte chunks, a 10 MB file requires ~1280 reads — a reasonable cap
# that excludes accidental binary blobs while covering all realistic source files.
# Use MAX_FILE_SIZE_BYTES in logic code — never multiply MAX_FILE_SIZE_MB inline.
MAX_FILE_SIZE_MB: int = 10
_BYTES_PER_KILOBYTE: int = 1024
_KILOBYTES_PER_MEGABYTE: int = 1024
# Exported so any module that converts MB → bytes can import the factor rather
# than duplicating the inline multiply. Do not use this for ad-hoc conversions
# outside a named constant — always define a named constant at the call site.
BYTES_PER_MEGABYTE: int = _BYTES_PER_KILOBYTE * _KILOBYTES_PER_MEGABYTE
MAX_FILE_SIZE_BYTES: int = MAX_FILE_SIZE_MB * BYTES_PER_MEGABYTE

# ---------------------------------------------------------------------------
# HIPAA audit retention
# ---------------------------------------------------------------------------

# HIPAA §164.530(j) requires audit log retention for a minimum of 6 years.
# A 6-year window contains either 1 or 2 leap years depending on start date.
# Using 2 leap years ensures we always satisfy the minimum even in the
# worst-case distribution. Must match audit_retention_days in .phi-scanner.yml.
_HIPAA_RETENTION_YEARS: int = 6
_DAYS_IN_STANDARD_YEAR: int = 365
_DAYS_IN_LEAP_YEAR: int = 366
_LEAP_YEARS_IN_RETENTION_WINDOW: int = 2
_STANDARD_YEARS_IN_RETENTION_WINDOW: int = _HIPAA_RETENTION_YEARS - _LEAP_YEARS_IN_RETENTION_WINDOW

AUDIT_RETENTION_DAYS: int = (
    _STANDARD_YEARS_IN_RETENTION_WINDOW * _DAYS_IN_STANDARD_YEAR
    + _LEAP_YEARS_IN_RETENTION_WINDOW * _DAYS_IN_LEAP_YEAR
)

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_CODE_CLEAN: int = 0
EXIT_CODE_VIOLATION: int = 1

# ---------------------------------------------------------------------------
# Database schema versions
# ---------------------------------------------------------------------------

# Increment when the audit SQLite schema changes; triggers migration logic.
AUDIT_SCHEMA_VERSION: int = 1

# Increment when the scan-cache SQLite schema changes; triggers migration logic.
CACHE_SCHEMA_VERSION: int = 1

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class OutputFormat(StrEnum):
    """Supported --output format values for the scan command.

    Always look up members by value: OutputFormat("gitlab-sast"), not by name.
    OutputFormat["gitlab-sast"] raises KeyError because key lookup uses the
    member name (GITLAB_SAST), not the string value. The _missing_ hook below
    handles case-insensitive value lookups as a convenience for CLI input.
    """

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"
    CSV = "csv"
    PDF = "pdf"
    HTML = "html"
    JUNIT = "junit"
    # "codequality" matches the GitLab Code Quality artifact type name exactly.
    CODEQUALITY = "codequality"
    # "gitlab-sast" matches the GitLab SAST artifact type name exactly.
    # The hyphen is intentional — do not normalize to underscore.
    GITLAB_SAST = "gitlab-sast"

    @classmethod
    def _missing_(cls, candidate_string: object) -> OutputFormat | None:
        """Allow case-insensitive value lookup from CLI input."""
        if not isinstance(candidate_string, str):
            return None
        for member in cls:
            if member.value == candidate_string.lower():
                return member
        return None


class SeverityLevel(StrEnum):
    """Severity level assigned to a ScanFinding based on confidence score."""

    # INFO: confidence < CONFIDENCE_LOW_FLOOR — very weak signal, logged only.
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DetectionLayer(StrEnum):
    """The four detection layers that can produce a ScanFinding.

    Layers are applied in order: REGEX first (fastest, highest confidence),
    then NLP, FHIR, and optionally AI. A finding records which layer observed it.
    """

    REGEX = "regex"
    NLP = "nlp"
    FHIR = "fhir"
    AI = "ai"


class RiskLevel(StrEnum):
    """Overall risk level for a completed ScanResult."""

    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    CLEAN = "clean"


class PhiCategory(StrEnum):
    """PHI and regulated-data identifier categories.

    The first 18 members are the HIPAA Safe Harbor categories (45 CFR §164.514(b)(2)).
    Members below the Safe Harbor block are additional regulatory categories that require
    distinct treatment at compliance-mapping time and must not be aliased to a Safe Harbor
    member — doing so would create a semantic collision that breaks Layer 4 compliance mapping.
    """

    # -------------------------------------------------------------------------
    # HIPAA Safe Harbor — 45 CFR §164.514(b)(2) — 18 named identifiers
    # -------------------------------------------------------------------------
    NAME = "name"
    GEOGRAPHIC = "geographic"
    DATE = "date"
    PHONE = "phone"
    FAX = "fax"
    EMAIL = "email"
    SSN = "ssn"
    MRN = "mrn"
    HEALTH_PLAN = "health_plan"
    ACCOUNT = "account"
    CERTIFICATE = "certificate"
    VEHICLE = "vehicle"
    DEVICE = "device"
    URL = "url"
    IP = "ip"
    BIOMETRIC = "biometric"
    PHOTO = "photo"
    UNIQUE_ID = "unique_id"

    # -------------------------------------------------------------------------
    # Extended regulatory categories — distinct statutes, distinct consent rules
    # -------------------------------------------------------------------------

    # 42 CFR Part 2: Substance Use Disorder records. Stricter than HIPAA — requires
    # explicit patient consent even for treatment referrals and prohibits re-disclosure.
    # Must not be aliased to UNIQUE_ID or any Safe Harbor member.
    SUBSTANCE_USE_DISORDER = "substance_use_disorder"

    # Re-identification risk from quasi-identifier combinations (ZIP + DOB + sex, etc.).
    # Not a HIPAA Safe Harbor category — a finding of this type means that individually
    # non-identifying fields are present together in a configuration known to re-identify
    # individuals. Must not be aliased to UNIQUE_ID.
    QUASI_IDENTIFIER_COMBINATION = "quasi_identifier_combination"


# ---------------------------------------------------------------------------
# HIPAA remediation guidance
# ---------------------------------------------------------------------------

HIPAA_REMEDIATION_GUIDANCE: dict[PhiCategory, str] = {
    PhiCategory.NAME: (
        "Remove or replace the patient name with a synthetic placeholder. "
        "Use faker-generated names in test fixtures. Never commit real patient names."
    ),
    PhiCategory.GEOGRAPHIC: (
        "Replace geographic data smaller than state level with a placeholder. "
        "State abbreviations are generally safe; zip codes and street addresses are not."
    ),
    PhiCategory.DATE: (
        "Replace dates more specific than year with a synthetic date. "
        "Year-only values are acceptable under the Safe Harbor method."
    ),
    PhiCategory.PHONE: (
        "Replace phone numbers with a synthetic value such as (555) 000-0001. "
        "All area codes in the 555 range are reserved and safe for testing."
    ),
    PhiCategory.FAX: (
        "Replace fax numbers with a synthetic value. "
        "Treat fax numbers with the same care as phone numbers."
    ),
    PhiCategory.EMAIL: (
        "Replace email addresses with a synthetic address such as patient@example.com. "
        "The example.com domain is reserved and will never reach a real recipient."
    ),
    PhiCategory.SSN: (
        "Remove Social Security Numbers immediately. Use the format 000-00-0000 "
        "or a faker-generated SSN for test data. Never commit real SSNs."
    ),
    PhiCategory.MRN: (
        "Replace Medical Record Numbers with a synthetic identifier. "
        "Use a prefix such as TEST- to make synthetic MRNs self-evident."
    ),
    PhiCategory.HEALTH_PLAN: (
        "Replace health plan beneficiary numbers with synthetic values. "
        "These identifiers link directly to insurance records and must be protected."
    ),
    PhiCategory.ACCOUNT: (
        "Replace account numbers with synthetic values. "
        "Use a test-prefix convention so synthetic accounts are identifiable."
    ),
    PhiCategory.CERTIFICATE: (
        "Replace certificate and license numbers with synthetic values. "
        "These identifiers can be used to impersonate licensed practitioners."
    ),
    PhiCategory.VEHICLE: (
        "Replace vehicle identifiers and serial numbers with synthetic values. "
        "VINs are linkable to registered owners via public databases."
    ),
    PhiCategory.DEVICE: (
        "Replace device identifiers and serial numbers with synthetic values. "
        "Device IDs can be linked back to individual patients via medical records."
    ),
    PhiCategory.URL: (
        "Review URLs containing path segments that encode patient identifiers. "
        "Replace patient-specific URL components with synthetic values."
    ),
    PhiCategory.IP: (
        "Replace IP addresses that could identify individual patients with "
        "documentation-range addresses such as 192.0.2.x (RFC 5737 TEST-NET-1)."
    ),
    PhiCategory.BIOMETRIC: (
        "Remove biometric identifiers entirely. These cannot be changed if exposed "
        "and represent a permanent privacy risk."
    ),
    PhiCategory.PHOTO: (
        "Remove full-face photographs and comparable images. "
        "Do not commit patient photos to version control under any circumstances."
    ),
    PhiCategory.UNIQUE_ID: (
        "Replace unique identifying numbers with synthetic values. "
        "Any number that uniquely identifies a person is a HIPAA identifier."
    ),
    PhiCategory.SUBSTANCE_USE_DISORDER: (
        "Substance Use Disorder records are governed by 42 CFR Part 2, which imposes "
        "stricter protections than HIPAA. Remove all SUD-related field names, diagnosis "
        "codes, treatment program references, and medication names (methadone, buprenorphine, "
        "naloxone) from source code and test fixtures. Disclosure without explicit written "
        "patient consent — even for treatment — violates federal law. Never commit SUD data "
        "to version control under any circumstances."
    ),
    PhiCategory.QUASI_IDENTIFIER_COMBINATION: (
        "This finding indicates that multiple individually low-risk fields are present "
        "together in a configuration known to re-identify individuals (e.g., ZIP code + "
        "date of birth + sex can re-identify 87%% of the US population). Remove or "
        "generalize at least one of the quasi-identifiers: use only the first 3 digits of "
        "the ZIP code, replace the full date of birth with birth year only, or remove the "
        "combination entirely from test fixtures. Do not rely on any single field being "
        "'safe' — the risk is in the combination."
    ),
}
