"""Named constants, enums, and remediation guidance for PhiScan."""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "AUDIT_RETENTION_DAYS",
    "AUDIT_SCHEMA_VERSION",
    "BASELINE_DRIFT_WARNING_PERCENT",
    "BASELINE_SCHEMA_VERSION",
    "BINARY_CHECK_BYTE_COUNT",
    "CACHE_SCHEMA_VERSION",
    "DEFAULT_BASELINE_FILENAME",
    "DEFAULT_BASELINE_MAX_AGE_DAYS",
    "SHA256_HEX_DIGEST_LENGTH",
    "AI_LAYER_CONFIDENCE_ADJUSTMENT_MAX",
    "CONFIDENCE_STRUCTURED_MAX",
    "CONFIDENCE_STRUCTURED_MIN",
    "CONFIDENCE_HIGH_FLOOR",
    "CONFIDENCE_LOW_FLOOR",
    "CONFIDENCE_MEDIUM_FLOOR",
    "CONFIDENCE_NLP_MAX",
    "CONFIDENCE_NLP_MIN",
    "CONFIDENCE_REGEX_MAX",
    "CONFIDENCE_REGEX_MIN",
    "CONFIDENCE_SCORE_MAXIMUM",
    "CONFIDENCE_SCORE_MINIMUM",
    "CODE_CONTEXT_REDACTED_VALUE",
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "DEFAULT_CONFIG_FILENAME",
    "DEFAULT_DATABASE_PATH",
    "DEFAULT_IGNORE_FILENAME",
    "DEFAULT_TEXT_ENCODING",
    "DBSNP_RS_ID_MAX_DIGITS",
    "DBSNP_RS_ID_MIN_DIGITS",
    "DEA_NUMBER_DIGIT_COUNT",
    "DEA_NUMBER_PREFIX_LENGTH",
    "DetectionLayer",
    "ENSEMBL_GENE_ID_DIGIT_COUNT",
    "EXIT_CODE_CLEAN",
    "EXIT_CODE_ERROR",
    "EXIT_CODE_VIOLATION",
    "FICTIONAL_PHONE_EXCHANGE",
    "FICTIONAL_PHONE_SUBSCRIBER_DISPLAY_PREFIX",
    "FICTIONAL_PHONE_SUBSCRIBER_MAX",
    "FICTIONAL_PHONE_SUBSCRIBER_MIN",
    "HIPAA_AGE_RESTRICTION_THRESHOLD",
    "HIPAA_REMEDIATION_GUIDANCE",
    "ARCHIVE_EXTENSIONS",
    "ARCHIVE_SCANNABLE_EXTENSIONS",
    "KNOWN_BINARY_EXTENSIONS",
    "BYTES_PER_MEGABYTE",
    "MAX_FILE_SIZE_BYTES",
    "MAX_FILE_SIZE_MB",
    "BIOMETRIC_FIELD_NAMES",
    "MBI_ALLOWED_LETTERS",
    "MBI_CHARACTER_COUNT",
    "NPI_CMS_LUHN_ISSUER_PREFIX",
    "VCF_GENETIC_DATA_COLUMN_HEADER",
    "ZIP_CODE_DIGIT_COUNT",
    "ZIP_PLUS4_SUFFIX_DIGIT_COUNT",
    "COMBINATION_REPRESENTATIVE_COUNT",
    "MINIMUM_QUASI_IDENTIFIER_COUNT",
    "IMPLEMENTED_OUTPUT_FORMATS",
    "OutputFormat",
    "SWEENEY_REIDENTIFICATION_PERCENTAGE",
    "PHI_SUGGESTIVE_VARIABLE_PATTERNS",
    "VARIABLE_CONTEXT_CONFIDENCE_BOOST",
    "PathspecMatchStyle",
    "PhiCategory",
    "QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES",
    "RiskLevel",
    "SeverityLevel",
    "SSN_EXCLUDED_AREA_NUMBERS",
    "SUD_FIELD_NAME_PATTERNS",
    "VIN_CHARACTER_COUNT",
    "WebhookType",
    "ZIP_CODE_SAFE_HARBOR_POPULATION_MIN",
    "AUDIT_KEY_FILENAME",
    "AUDIT_KEY_DIR",
    "AUDIT_ENCRYPTION_PREFIX",
    "AUDIT_GENESIS_CHAIN_HASH",
    "SMTP_DEFAULT_PORT",
    "SMTP_DEFAULT_TLS_PORT",
    "WEBHOOK_DEFAULT_RETRY_COUNT",
    "WEBHOOK_DEFAULT_TIMEOUT_SECONDS",
    "NOTIFICATION_SUBJECT_FORMAT",
    "ACTION_TAKEN_PASS",
    "ACTION_TAKEN_FAIL",
    "ACTION_TAKEN_WARN",
    "AI_CONFIDENCE_REVIEW_LOWER_BOUND",
    "AI_CONFIDENCE_REVIEW_UPPER_BOUND",
    "AI_DEFAULT_MODEL",
    "AI_ANTHROPIC_COST_PER_MILLION_INPUT_TOKENS",
    "AI_ANTHROPIC_COST_PER_MILLION_OUTPUT_TOKENS",
    "AI_OPENAI_COST_PER_MILLION_INPUT_TOKENS",
    "AI_OPENAI_COST_PER_MILLION_OUTPUT_TOKENS",
    "AI_GOOGLE_COST_PER_MILLION_INPUT_TOKENS",
    "AI_GOOGLE_COST_PER_MILLION_OUTPUT_TOKENS",
    "AI_MESSAGE_CONTENT_KEY",
    "AI_MESSAGE_ROLE_KEY",
    "AI_MESSAGE_ROLE_SYSTEM",
    "AI_MESSAGE_ROLE_USER",
    "AI_PROVIDER_ANTHROPIC",
    "AI_PROVIDER_GOOGLE",
    "AI_PROVIDER_OPENAI",
    "AI_RESPONSE_FIRST_CHOICE_INDEX",
    "AI_RESPONSE_FIRST_CONTENT_BLOCK_INDEX",
    "AI_RESPONSE_MAX_TOKENS",
    "AI_RESPONSE_REQUIRED_KEYS",
    "AI_RESPONSE_TRUNCATION_LENGTH",
    "ANTHROPIC_API_KEY_ENV_VAR",
    "GOOGLE_API_KEY_ENV_VAR",
    "OPENAI_API_KEY_ENV_VAR",
    "AI_REVIEW_PERMITTED_EMPTY_CONTEXT_ENTITY_TYPES",
    "AI_REVIEW_REDACTED_PLACEHOLDER",
    "AI_REVIEW_SYSTEM_PROMPT",
    "AI_TOKENS_PER_MILLION",
]

# ---------------------------------------------------------------------------
# File names
# ---------------------------------------------------------------------------

DEFAULT_BASELINE_FILENAME: str = ".phi-scanbaseline"
# Baseline entries expire after this many days; finding reverts to active when expired.
# 90 days forces quarterly remediation reviews without blocking emergency baselines.
DEFAULT_BASELINE_MAX_AGE_DAYS: int = 90
BASELINE_SCHEMA_VERSION: int = 1
# Warn when a baseline update adds more than this percent more entries than before.
# A 20 % increase signals the team may be accumulating rather than remediating PHI.
BASELINE_DRIFT_WARNING_PERCENT: int = 20
# Substituted in place of the raw matched PHI value when building code_context.
# The source line is shown to help developers locate the finding; the actual
# matched value is replaced so raw PHI never flows through the model or display.
CODE_CONTEXT_REDACTED_VALUE: str = "[REDACTED]"
DEFAULT_CONFIG_FILENAME: str = ".phi-scanner.yml"
DEFAULT_DATABASE_PATH: str = "~/.phi-scanner/audit.db"
DEFAULT_IGNORE_FILENAME: str = ".phi-scanignore"
# UTF-8 is the only encoding PhiScan reads or writes. Centralised here so
# every module imports the same constant rather than embedding "utf-8" inline.
DEFAULT_TEXT_ENCODING: str = "utf-8"

# ---------------------------------------------------------------------------
# Binary file detection
# ---------------------------------------------------------------------------

# Archive formats inspected in-memory by the archive scanner (Phase 2E.9).
# These extensions are intentionally excluded from KNOWN_BINARY_EXTENSIONS so
# that collect_scan_targets passes them to scan_file rather than skipping them.
# ARCHIVE_EXTENSIONS must never overlap with KNOWN_BINARY_EXTENSIONS.
ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({".jar", ".war", ".zip"})

# Text resource extensions that are eligible for scanning inside archives.
# Compiled bytecode (.class, .pyc), media, and other binary members are skipped.
# Only members whose extension appears here are passed to detect_phi_in_text_content.
ARCHIVE_SCANNABLE_EXTENSIONS: frozenset[str] = frozenset(
    {".conf", ".json", ".properties", ".xml", ".yaml", ".yml"}
)

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
        # .zip, .jar, .war are NOT listed here — they are inspected by the
        # archive scanner (see ARCHIVE_EXTENSIONS above).
        ".tar",
        ".gz",
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

# Layer 3 — Structured healthcare formats (FHIR R4 + HL7 v2): schema-based structural match.
# Named STRUCTURED rather than FHIR to correctly cover both Layer 3 sub-scanners —
# HL7 v2 findings use the same confidence band and must not be attributed to FHIR.
CONFIDENCE_STRUCTURED_MIN: float = 0.80
CONFIDENCE_STRUCTURED_MAX: float = 0.95

# Adjustment delta — not a score floor or ceiling.
# Layer 4 (AI) refines an existing score by at most this amount in either
# direction. Do not compare this constant against raw confidence scores.
AI_LAYER_CONFIDENCE_ADJUSTMENT_MAX: float = 0.15

# ---------------------------------------------------------------------------
# AI confidence review band (Phase 7A)
# ---------------------------------------------------------------------------

# Findings with confidence in [AI_CONFIDENCE_REVIEW_LOWER_BOUND,
# AI_CONFIDENCE_REVIEW_UPPER_BOUND) are sent to Claude for re-scoring.
# High-confidence findings (≥ upper bound) bypass AI review entirely —
# they are already definitive and the API call adds no value.
# Low-confidence findings (< lower bound) are below the scan threshold
# and are never reported regardless of AI review.
# Environment variable names for AI provider API keys — part of the public BYOAK
# contract documented in ai_review.py and user-facing documentation.  Exported so
# any module that reads these env vars imports the name rather than duplicating it.
ANTHROPIC_API_KEY_ENV_VAR: str = "ANTHROPIC_API_KEY"
OPENAI_API_KEY_ENV_VAR: str = "OPENAI_API_KEY"
GOOGLE_API_KEY_ENV_VAR: str = "GOOGLE_API_KEY"

# Provider name tokens — used by _detect_provider_name() and _get_provider() in ai_review.py
# to map a model name to the correct adapter and env var.
AI_PROVIDER_ANTHROPIC: str = "anthropic"
AI_PROVIDER_OPENAI: str = "openai"
AI_PROVIDER_GOOGLE: str = "google"

AI_CONFIDENCE_REVIEW_LOWER_BOUND: float = 0.50
AI_CONFIDENCE_REVIEW_UPPER_BOUND: float = 0.80

# Default model for AI confidence review — Anthropic claude-sonnet-4-6.
# Users can override this with ai.model in .phi-scanner.yml to use any
# supported model (claude-*, gpt-*, o1/o3/o4, gemini-*).
AI_DEFAULT_MODEL: str = "claude-sonnet-4-6"

# Maximum tokens in Claude's response — the JSON answer is short.
AI_RESPONSE_MAX_TOKENS: int = 256

# Placeholder that replaces matched PHI values in code context before any
# API call. Must appear in every outbound payload — verified by sentinel tests.
AI_REVIEW_REDACTED_PLACEHOLDER: str = "[REDACTED]"

# Keys and values used when constructing the messages list for provider APIs.
# String literals in logic code are banned — these named constants must be used
# everywhere a messages=[{"role": ..., "content": ...}] payload is built.
# Applies to Anthropic, OpenAI, and any provider that uses the role/content schema.
AI_MESSAGE_ROLE_KEY: str = "role"
AI_MESSAGE_ROLE_SYSTEM: str = "system"
AI_MESSAGE_ROLE_USER: str = "user"
AI_MESSAGE_CONTENT_KEY: str = "content"

# Keys Claude must return for the response to be actionable. Only the fields we
# actually read and act on are required — reasoning is intentionally excluded:
# we have explicitly decided not to store or log it (PHI-adjacent), so requiring
# it would create an implicit dependency on a field we throw away and would fail
# scans if Claude omits it in a future model version.
AI_RESPONSE_REQUIRED_KEYS: frozenset[str] = frozenset({"is_phi_risk", "confidence"})

# Entity types for which an empty code_context is permitted at the outbound API
# boundary.  All current production detection layers (regex, NLP, HL7, FHIR,
# quasi-identifier) always provide at least a segment/field label that includes
# the redaction marker, so this set is intentionally empty.  A future finding
# type that carries no source line at all must be added here explicitly — it may
# NOT silently bypass the redaction check by leaving code_context empty.
AI_REVIEW_PERMITTED_EMPTY_CONTEXT_ENTITY_TYPES: frozenset[str] = frozenset()

# Index of the first content block in an Anthropic response message.
AI_RESPONSE_FIRST_CONTENT_BLOCK_INDEX: int = 0
# Index of the first choice in an OpenAI chat completions response.
AI_RESPONSE_FIRST_CHOICE_INDEX: int = 0

# Maximum characters of a raw Claude response included in error messages.
# Enough context to diagnose malformed JSON without logging verbose output.
AI_RESPONSE_TRUNCATION_LENGTH: int = 200

# Token cost rates per provider (USD per million tokens).
# Used to compute estimated_cost_usd in the per-scan AI usage summary.
# Rates are based on each provider's published pricing for their default model tier
# and are approximations — actual charges depend on the specific model selected.
# Anthropic: claude-sonnet-4-6
AI_ANTHROPIC_COST_PER_MILLION_INPUT_TOKENS: float = 3.00
AI_ANTHROPIC_COST_PER_MILLION_OUTPUT_TOKENS: float = 15.00
# OpenAI: gpt-4o
AI_OPENAI_COST_PER_MILLION_INPUT_TOKENS: float = 2.50
AI_OPENAI_COST_PER_MILLION_OUTPUT_TOKENS: float = 10.00
# Google: gemini-1.5-flash
AI_GOOGLE_COST_PER_MILLION_INPUT_TOKENS: float = 0.075
AI_GOOGLE_COST_PER_MILLION_OUTPUT_TOKENS: float = 0.30
AI_TOKENS_PER_MILLION: int = 1_000_000

# System prompt for Claude confidence review calls.
AI_REVIEW_SYSTEM_PROMPT: str = (
    "You are a HIPAA compliance expert reviewing code for PHI/PII risk. "
    "You will be shown code context where the matched value has been replaced "
    "with [REDACTED]. Based only on the code structure, variable names, and "
    "surrounding context, determine whether this is a genuine PHI risk in "
    "production code or a false positive (test data, example values, config "
    "templates, comments, etc.). "
    "Respond ONLY with valid JSON in this exact format: "
    '{"is_phi_risk": true, "confidence": 0.85, "reasoning": "brief explanation"}'
)

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
# Exit 2 signals a CLI or configuration error (bad argument, unsupported format).
EXIT_CODE_ERROR: int = 2

# ---------------------------------------------------------------------------
# Detection parameters
# ---------------------------------------------------------------------------

# Maximum line distance between two identifiers in the same file for them to
# be considered a quasi-identifier combination (2E.11). Never compare against
# the literal 50 in logic code — always reference this constant.
QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES: int = 50

# Minimum number of distinct quasi-identifier categories that must be present
# within QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES of each other to trigger a
# combination finding. The literal 2 must never appear in detection logic —
# always import and reference this constant.
MINIMUM_QUASI_IDENTIFIER_COUNT: int = 2

# Number of representative findings taken from each PHI category when building
# a combination candidate group. Using one representative per category prevents
# combinatorial explosion (N×M finding pairs) when multiple findings of the same
# category are present. The literal 1 must never appear as a slice literal in
# combination detection logic — always reference this constant.
COMBINATION_REPRESENTATIVE_COUNT: int = 1

# HIPAA §164.514(b)(2)(i) requires ages "over 90" to be generalized (reported
# as "90 or older"). "Over 90" means strictly greater than 90, i.e., ages 91+.
# Logic code must use: age > HIPAA_AGE_RESTRICTION_THRESHOLD.
# Never compare against the literal 90 in detection logic.
HIPAA_AGE_RESTRICTION_THRESHOLD: int = 90

# Sweeney (2000) demonstrated that ZIP code + date of birth + sex uniquely
# re-identifies this percentage of the US population. Used in combination-
# finding messages — never embed the literal 87 in detection or reporting code.
SWEENEY_REIDENTIFICATION_PERCENTAGE: int = 87

# ---------------------------------------------------------------------------
# Variable-name contextual boosting (Phase 2E.4)
# ---------------------------------------------------------------------------

# Confidence delta applied when a PHI finding's source line contains an
# assignment whose left-hand side contains one of PHI_SUGGESTIVE_VARIABLE_PATTERNS.
# The boosted score is capped at CONFIDENCE_SCORE_MAXIMUM.
VARIABLE_CONTEXT_CONFIDENCE_BOOST: float = 0.15

# Substrings that, when found in a variable or key name on the same line as a
# PHI finding, suggest the developer intended to store PHI there — increasing
# the credibility of the finding. All strings are matched case-insensitively.
PHI_SUGGESTIVE_VARIABLE_PATTERNS: frozenset[str] = frozenset(
    {
        "address",
        "beneficiary",
        "birth",
        "diagnosis",
        "dob",
        "email",
        "insurance",
        "mrn",
        "name",
        "patient",
        "phone",
        "ssn",
    }
)

# ---------------------------------------------------------------------------
# Identifier structure constants
# ---------------------------------------------------------------------------
# These constants encode the structural properties of specific PHI identifiers.
# They are used by the regex layer (Phase 2B) to construct patterns without
# embedding magic numbers. Never use the literal values inline in logic code.

# Medicare Beneficiary Identifier (MBI) — fixed-length alphanumeric format
# introduced in 2019 to replace the SSN-based HICN.
MBI_CHARACTER_COUNT: int = 11

# DEA registration number — 2-letter prefix followed by exactly this many digits,
# validated by a checksum over digits 1, 3, 5, 2, 4, 6.
DEA_NUMBER_DIGIT_COUNT: int = 7
DEA_NUMBER_PREFIX_LENGTH: int = 2  # two letter characters before the digit sequence

# Vehicle Identification Number — fixed-length per ISO 3779 (WMI + VDS + VIS).
# Position 9 is a check digit; I, O, Q are never used.
VIN_CHARACTER_COUNT: int = 17

# dbSNP rs-ID digit bounds — rs-IDs currently range from 7 to 9 digits after
# the "rs" prefix. Both ends are needed to construct the regex quantifier.
DBSNP_RS_ID_MIN_DIGITS: int = 7
DBSNP_RS_ID_MAX_DIGITS: int = 9

# Ensembl gene ID — "ENSG" prefix followed by exactly this many zero-padded digits.
ENSEMBL_GENE_ID_DIGIT_COUNT: int = 11

# NPI Luhn validation — CMS prepends this ISO 7812 issuer prefix to the 10-digit NPI
# before computing the Luhn check. The 5-digit prefix "80840" is the Health Care
# Provider designation assigned by CMS under the ISO 7812 financial card standard.
NPI_CMS_LUHN_ISSUER_PREFIX: str = "80840"


# FCC-reserved fictional NANP telephone exchange and subscriber range.
# Numbers in this range (555-0100 through 555-0199) are never assigned to real
# subscribers and are safe for use in synthetic test data. The scanner excludes
# this range to avoid false positives on test fixtures.
FICTIONAL_PHONE_EXCHANGE: int = 555
# NANP subscriber numbers are displayed as 4 digits. The integer constants
# FICTIONAL_PHONE_SUBSCRIBER_MIN (100) and FICTIONAL_PHONE_SUBSCRIBER_MAX (199)
# represent the numeric values, but the display format requires a leading zero
# (0100–0199). Use this prefix when building strings, not a bare "0" literal.
FICTIONAL_PHONE_SUBSCRIBER_DISPLAY_PREFIX: str = "0"
FICTIONAL_PHONE_SUBSCRIBER_MIN: int = 100
FICTIONAL_PHONE_SUBSCRIBER_MAX: int = 199

# HIPAA Safe Harbor §164.514(b)(2)(i): a 3-digit ZIP code prefix is safe only
# when the geographic unit it represents contains at least this many people.
# The scanner cannot verify population counts, so it flags 3-digit prefixes
# in patient-geographic context and defers the decision to the user.
ZIP_CODE_SAFE_HARBOR_POPULATION_MIN: int = 20_000

# ---------------------------------------------------------------------------
# Regex pattern string constants
# ---------------------------------------------------------------------------
# These string/set constants encode structured pattern components. Using named
# constants instead of inline string literals prevents copy-paste errors and
# makes the compliance rationale traceable to its regulatory source.

# CMS-approved letter set for MBI positions 2, 3, 5, 6, 8, and 9.
# CMS excludes S, L, O, I, B, Z to avoid visual ambiguity with digits.
# Use this in regex character classes: f"[{MBI_ALLOWED_LETTERS}]"
# Never embed "AC-HJ-KM-NP-RT-Y" as an inline string in detection code.
MBI_ALLOWED_LETTERS: str = "AC-HJ-KM-NP-RT-Y"

# SSN area numbers that SSA has never assigned and never will (§205.20 regulations).
# Area 000, group 00, and serial 0000 are additional exclusions but are enforced
# structurally by the regex (zero fields), not by membership in this set.
# Use this set to construct the area-number exclusion branch of the SSN regex.
# Never embed 666, 900, or 999 as literals in pattern strings.
SSN_EXCLUDED_AREA_NUMBERS: frozenset[int] = frozenset({666, *range(900, 1000)})

# 42 CFR Part 2 substance use disorder field name patterns.
# The scanner flags any variable name, JSON key, or column name that matches
# a member of this set as a potential SUD record under 42 CFR Part 2.
# Detection logic must iterate this constant — never embed these strings inline.
# Biometric identifiers that must never be stored in source code.
# Any variable or field with one of these names is flagged as a HIPAA biometric
# identifier under Safe Harbor §164.514(b)(2) category 16.
# Use this tuple to build the biometric field name pattern — never embed inline.
BIOMETRIC_FIELD_NAMES: tuple[str, ...] = (
    "fingerprint",
    "iris_scan",
    "retinal_scan",
    "face_template",
    "voiceprint",
    "palm_print",
    "gait_signature",
    "dna_sequence",
    "biometric_hash",
)

# VCF (Variant Call Format) genomic data column header sentinel.
# Presence of this header in source code indicates embedded genomic data,
# which is a genetic identifier under GINA and GDPR Art. 9 in addition to HIPAA.
VCF_GENETIC_DATA_COLUMN_HEADER: str = "CHROM"

# ZIP code digit counts for the US Postal Service standard and extended formats.
ZIP_CODE_DIGIT_COUNT: int = 5  # standard 5-digit ZIP code
ZIP_PLUS4_SUFFIX_DIGIT_COUNT: int = 4  # ZIP+4 extension suffix

SUD_FIELD_NAME_PATTERNS: frozenset[str] = frozenset(
    {
        "substance_use",
        "addiction_treatment",
        "sud_diagnosis",
        "alcohol_abuse",
        "opioid_treatment",
        "methadone",
        "buprenorphine",
        "naloxone",
        "substance_use_disorder",
        "drug_treatment",
        "detox_program",
        "mat_program",
    }
)

# ---------------------------------------------------------------------------
# Notification constants
# ---------------------------------------------------------------------------

# Default SMTP port for STARTTLS connections.
SMTP_DEFAULT_PORT: int = 587
# Default SMTP port for SMTPS (implicit TLS, port 465).
SMTP_DEFAULT_TLS_PORT: int = 465

# Default number of retry attempts for a failed webhook POST before giving up.
WEBHOOK_DEFAULT_RETRY_COUNT: int = 3
# Seconds to wait for a webhook HTTP response before timing out.
WEBHOOK_DEFAULT_TIMEOUT_SECONDS: int = 10

# Subject template for PHI alert email notifications.
# Formatted with: risk_level, findings_count, repo, branch.
NOTIFICATION_SUBJECT_FORMAT: str = (
    "[PHI ALERT] {risk_level} — {findings_count} findings in {repo}/{branch}"
)

# Audit action_taken values — recorded after each scan.
ACTION_TAKEN_PASS: str = "pass"
ACTION_TAKEN_FAIL: str = "fail"
ACTION_TAKEN_WARN: str = "warn"

# ---------------------------------------------------------------------------
# Audit encryption and hash chain constants
# ---------------------------------------------------------------------------

# Directory under the user's home that stores the audit key and database.
# Mirrored in DEFAULT_DATABASE_PATH — never hardcode "~/.phi-scanner/" in logic.
AUDIT_KEY_DIR: str = "~/.phi-scanner"
# File name of the AES-256-GCM encryption key for audit findings_json.
AUDIT_KEY_FILENAME: str = "audit.key"
# Prefix written into encrypted findings_json to distinguish ciphertext from
# plaintext JSON. Old rows without this prefix are treated as unencrypted.
AUDIT_ENCRYPTION_PREFIX: str = "enc:"
# Constant genesis hash used as the prev_chain_hash for the very first row.
# Fixed string rather than zeros to make accidental collision with a real row hash
# practically impossible. Never change this value — doing so invalidates all
# existing hash chains.
AUDIT_GENESIS_CHAIN_HASH: str = "phi-scan-genesis-v1"

# ---------------------------------------------------------------------------
# Database schema versions
# ---------------------------------------------------------------------------

# Increment when the audit SQLite schema changes; triggers migration logic.
# v1 → v2 (Phase 5): added event_type, committer_name_hash, committer_email_hash,
# pr_number, pipeline, action_taken, notifications_sent, row_chain_hash columns.
# v2 → v3 (Phase 7A): added ai_input_tokens, ai_output_tokens, ai_cost_usd columns.
AUDIT_SCHEMA_VERSION: int = 3

# Increment when the scan-cache SQLite schema changes; triggers migration logic.
CACHE_SCHEMA_VERSION: int = 1

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PathspecMatchStyle(StrEnum):
    """Match-style tokens accepted by pathspec.PathSpec.from_lines.

    GITIGNORE is the current canonical token (replaces the deprecated
    gitwildmatch alias). Only one style is used by PhiScan, but an Enum
    prevents the token from being duplicated as bare string literals across
    modules.
    """

    GITIGNORE = "gitignore"


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


# Output formats with a complete runtime serializer. This is the single source
# of truth for which formats are accepted by CLI validation, config validation,
# and explain-reports documentation. When Phase 3 adds a new formatter, add its
# OutputFormat member here — one change enables the format everywhere.
IMPLEMENTED_OUTPUT_FORMATS: frozenset[OutputFormat] = frozenset(
    {
        OutputFormat.TABLE,
        OutputFormat.JSON,
        OutputFormat.CSV,
        OutputFormat.SARIF,
        OutputFormat.JUNIT,
        OutputFormat.CODEQUALITY,
        OutputFormat.GITLAB_SAST,
        OutputFormat.PDF,
        OutputFormat.HTML,
    }
)


class SeverityLevel(StrEnum):
    """Severity level assigned to a ScanFinding based on confidence score."""

    # INFO: confidence < CONFIDENCE_LOW_FLOOR — very weak signal, logged only.
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Numeric rank for each SeverityLevel — used for threshold comparisons.
# Higher rank = more severe. INFO=0, LOW=1, MEDIUM=2, HIGH=3.
SEVERITY_RANK: dict[SeverityLevel, int] = {
    SeverityLevel.INFO: 0,
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
}


class DetectionLayer(StrEnum):
    """The detection layers that can produce a ScanFinding.

    Layers are applied in order: REGEX first (fastest, highest confidence),
    then NLP, FHIR, HL7, and optionally AI. A finding records which layer
    observed it. FHIR and HL7 are separate values so that audit queries can
    distinguish FHIR R4 field-name findings from HL7 v2 segment findings.
    """

    REGEX = "regex"
    NLP = "nlp"
    FHIR = "fhir"
    HL7 = "hl7"
    AI = "ai"
    COMBINATION = "combination"


class WebhookType(StrEnum):
    """Webhook delivery target types supported by the notifier."""

    SLACK = "slack"
    TEAMS = "teams"
    GENERIC = "generic"


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
        "date of birth + sex can re-identify 87% of the US population). Remove or "
        "generalize at least one of the quasi-identifiers: use only the first 3 digits of "
        "the ZIP code, replace the full date of birth with birth year only, or remove the "
        "combination entirely from test fixtures. Do not rely on any single field being "
        "'safe' — the risk is in the combination."
    ),
}
