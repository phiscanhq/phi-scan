"""Layer 1: Regex pattern registry for HIPAA PHI detection (Phase 2B).

Implements ``detect_phi_with_regex`` — the Layer 1 delegated function called by
``detect_phi_in_text_content`` (Phase 2E). Scans file content line-by-line
against a compiled pattern registry covering all 18 HIPAA Safe Harbor identifiers
and additional regulated categories (MBI, DEA, HICN, genetic IDs, SUD fields).

Design constraints from PLAN.md (enforced throughout this module):
- All regex quantifiers referencing PHI structural lengths must use named
  constants — never inline integer literals.
- The SSN area-exclusion must be constructed from ``SSN_EXCLUDED_AREA_NUMBERS``.
- The phone fictional-range exclusion must use ``FICTIONAL_PHONE_EXCHANGE``,
  ``FICTIONAL_PHONE_SUBSCRIBER_MIN``, and ``FICTIONAL_PHONE_SUBSCRIBER_MAX``.
- Matched values are never stored — only their SHA-256 hex digests.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from phi_scan.constants import (
    BIOMETRIC_FIELD_NAMES,
    CODE_CONTEXT_REDACTED_VALUE,
    CONFIDENCE_REGEX_MAX,
    DBSNP_RS_ID_MAX_DIGITS,
    DBSNP_RS_ID_MIN_DIGITS,
    DEA_NUMBER_DIGIT_COUNT,
    DEA_NUMBER_PREFIX_LENGTH,
    ENSEMBL_GENE_ID_DIGIT_COUNT,
    FICTIONAL_PHONE_EXCHANGE,
    FICTIONAL_PHONE_SUBSCRIBER_MAX,
    FICTIONAL_PHONE_SUBSCRIBER_MIN,
    HIPAA_AGE_RESTRICTION_THRESHOLD,
    HIPAA_REMEDIATION_GUIDANCE,
    MBI_ALLOWED_LETTERS,
    NPI_CMS_LUHN_ISSUER_PREFIX,
    SSN_EXCLUDED_AREA_NUMBERS,
    SUD_FIELD_NAME_PATTERNS,
    VCF_GENETIC_DATA_COLUMN_HEADER,
    VIN_CHARACTER_COUNT,
    ZIP_CODE_DIGIT_COUNT,
    ZIP_PLUS4_SUFFIX_DIGIT_COUNT,
    DetectionLayer,
    PhiCategory,
)
from phi_scan.hashing import compute_value_hash, severity_from_confidence
from phi_scan.models import ScanFinding

__all__ = ["PhiPattern", "detect_phi_with_regex", "get_phi_pattern_registry"]

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_LINE_NUMBER_START: int = 1

# --- SSN structure ---
_SSN_AREA_DIGIT_COUNT: int = 3
_SSN_GROUP_DIGIT_COUNT: int = 2
_SSN_SERIAL_DIGIT_COUNT: int = 4
_SSN_ZERO_AREA: str = "0" * _SSN_AREA_DIGIT_COUNT
_SSN_ZERO_GROUP: str = "0" * _SSN_GROUP_DIGIT_COUNT
_SSN_ZERO_SERIAL: str = "0" * _SSN_SERIAL_DIGIT_COUNT
# Alternation of all SSN area numbers that are never assigned (§205.20 SSA).
# Built from SSN_EXCLUDED_AREA_NUMBERS — literals 666/900/999 must not appear.
_SSN_EXCLUDED_AREA_ALTERNATION: str = "|".join(
    f"{area_number:03d}" for area_number in sorted(SSN_EXCLUDED_AREA_NUMBERS)
)

# --- NPI ---
_NPI_DIGIT_COUNT: int = 10
# NPI_CMS_LUHN_ISSUER_PREFIX imported from constants — "80840" must not appear as literal

# --- DEA ---
# DEA_NUMBER_PREFIX_LENGTH imported from constants — must not duplicate the literal 2
_LAST_DIGIT_INDEX_OFFSET: int = 1  # length minus this gives the 0-based last index
_DEA_CHECKSUM_INDEX: int = DEA_NUMBER_DIGIT_COUNT - _LAST_DIGIT_INDEX_OFFSET
_DEA_EVEN_DIGIT_MULTIPLIER: int = 2

# --- VIN ---
_VIN_CHAR_CLASS: str = r"[A-HJ-NPR-Z0-9]"  # VIN never uses I, O, Q
_VIN_CHECK_POSITION_INDEX: int = 8  # position 9 (1-indexed) is index 8 (0-indexed)
_VIN_CHECK_MODULUS: int = 11
_VIN_CHECK_REMAINDER_FOR_X: int = 10

# --- Luhn ---
_LUHN_MODULUS: int = 10
_LUHN_DOUBLE_EVERY_NTH: int = 2  # double every second digit from the right
_LUHN_DOUBLE_MAX_SINGLE_DIGIT: int = 9
_LUHN_DOUBLE_ADJUSTMENT: int = 9

# --- Decimal base (distinct from _LUHN_MODULUS — used for integer decomposition) ---
_DECIMAL_BASE: int = 10

# --- MRN ---
_MRN_MIN_DIGIT_COUNT: int = 6
_MRN_MAX_DIGIT_COUNT: int = 10

# --- HICN ---
_HICN_BASE_DIGIT_COUNT: int = 9  # 9-digit SSN base
_HICN_SUFFIX_MIN_COUNT: int = 1
_HICN_SUFFIX_MAX_COUNT: int = 2

# --- Phone ---
_PHONE_DIGIT_COUNT_DOMESTIC: int = 10
_PHONE_DIGIT_COUNT_E164: int = 11
_PHONE_E164_COUNTRY_CODE: str = "1"

# --- Age over HIPAA threshold ---
_AGE_THRESHOLD_OFFSET: int = 1  # threshold is exclusive: flag ages strictly above it
_MIN_RESTRICTED_AGE: int = HIPAA_AGE_RESTRICTION_THRESHOLD + _AGE_THRESHOLD_OFFSET  # 91
_MIN_RESTRICTED_AGE_TENS: int = _MIN_RESTRICTED_AGE // _DECIMAL_BASE  # 9
_MIN_RESTRICTED_AGE_UNITS: int = _MIN_RESTRICTED_AGE % _DECIMAL_BASE  # 1

# --- IPv4 exclusion ranges ---
_RFC5737_TESTNET_PREFIXES: tuple[str, ...] = (
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
)
_IPV4_OCTET_SEPARATOR: str = "."
_IPV4_OCTET_SPLIT_LIMIT: int = 4

# --- Email exclusion ---
_DOCUMENTATION_EMAIL_DOMAINS: frozenset[str] = frozenset(
    {"example.com", "example.org", "example.net", "test.com"}
)
_EMAIL_DOMAIN_SEPARATOR: str = "@"

# --- Context keywords for ambiguous identifiers ---
_MRN_CONTEXT_KEYWORDS: tuple[str, ...] = (
    "mrn",
    "medical_record",
    "patient_id",
    "chart_number",
)
_ACCOUNT_CONTEXT_KEYWORDS: tuple[str, ...] = (
    "account_number",
    "account_id",
    "member_id",
    "subscriber_id",
    "patient_account",
    "hsa_account",
    "fsa_account",
)
_HEALTH_PLAN_CONTEXT_KEYWORDS: tuple[str, ...] = (
    "health_plan_number",
    "insurance_id",
    "group_number",
    "beneficiary_id",
    "plan_number",
    "coverage_id",
    "policy_number",
)
_CERTIFICATE_CONTEXT_KEYWORDS: tuple[str, ...] = (
    "license_number",
    "medical_license",
    "nursing_license",
    "pharmacy_license",
    "license_id",
)
_NPI_CONTEXT_KEYWORDS: tuple[str, ...] = (
    "npi",
    "national_provider",
    "provider_id",
    "prescriber_npi",
    "rendering_provider",
    "billing_provider",
)
_HICN_CONTEXT_KEYWORDS: tuple[str, ...] = (
    "hicn",
    "medicare",
    "claim_number",
    "beneficiary",
)
_AGE_CONTEXT_KEYWORDS: tuple[str, ...] = (
    "patient_age",
    "age_at_admission",
    "age_in_years",
    "years_old",
    "dob_age",
)

# --- Confidence floor offset ---
_CONFIDENCE_VALIDATED_FLOOR_OFFSET: float = 0.15  # subtracted from CONFIDENCE_REGEX_MAX

# --- IPv4 octet max value (255) and derived character-class anchors ---
_IPV4_OCTET_MAX_VALUE: int = 255
# 250–255 range: tens pair = 25, max unit digit = 5
_IPV4_OCTET_MAX_TENS_PAIR: int = _IPV4_OCTET_MAX_VALUE // _DECIMAL_BASE
_IPV4_OCTET_MAX_UNITS_DIGIT: int = _IPV4_OCTET_MAX_VALUE % _DECIMAL_BASE
# 200–249 range: hundreds digit = 2, max tens digit in range = 4
_IPV4_OCTET_HIGH_RANGE_HUNDREDS: int = _IPV4_OCTET_MAX_VALUE // 100
_IPV4_OCTET_HIGH_RANGE_MAX_TENS: int = (
    _IPV4_OCTET_MAX_TENS_PAIR % _DECIMAL_BASE - _LAST_DIGIT_INDEX_OFFSET
)

# --- IPv6 hex group structure ---
_IPV6_HEX_GROUP_MIN_CHARS: int = 1  # minimum hex characters per group (e.g., ":1:")
_IPV6_HEX_GROUP_MAX_CHARS: int = 4  # maximum hex characters per group (e.g., ":ffff:")
_IPV6_GROUP_COUNT: int = 8  # total colon-separated groups in a full IPv6 address

# --- Phone ---
_NANP_SEGMENT_DIGIT_COUNT: int = 3  # area code and exchange are each 3 digits
_PHONE_SUBSCRIBER_LAST_DIGIT_COUNT: int = 4  # final 4-digit subscriber block
_PHONE_INTL_MIN_DIGITS: int = 6  # minimum digits after country code (non-NANP)
_PHONE_INTL_MAX_DIGITS: int = 14  # maximum digits after country code (non-NANP)

# --- Email ---
_EMAIL_TLD_MIN_CHARS: int = 2  # minimum TLD length (.io, .uk)

# --- Date ---
_YEAR_DIGIT_COUNT: int = 4  # 4-digit Gregorian year (YYYY)

# --- Street address house number ---
_STREET_NUMBER_MIN_DIGITS: int = 1
_STREET_NUMBER_MAX_DIGITS: int = 5

# --- FDA UDI GS1 Application Identifiers and structure ---
_FDA_UDI_AI_GTIN: str = "01"  # GS1 AI for GTIN-14
_FDA_UDI_AI_LOT: str = "10"  # GS1 AI for lot / batch number
_FDA_UDI_AI_MFG_DATE: str = "11"  # GS1 AI for manufacture date (YYMMDD)
_FDA_UDI_GTIN_DIGIT_COUNT: int = 14  # GTIN-14 is always exactly 14 digits
_FDA_UDI_LOT_MIN_LENGTH: int = 1
_FDA_UDI_LOT_MAX_LENGTH: int = 20
_FDA_UDI_DATE_DIGIT_COUNT: int = 6  # YYMMDD = 6 digits

# --- VCF_COLUMN_HEADER now lives in constants.py as VCF_GENETIC_DATA_COLUMN_HEADER ---

# --- Account / health-plan / certificate pattern length bounds ---
_ACCOUNT_NUMBER_MIN_LENGTH: int = 6
_ACCOUNT_NUMBER_MAX_LENGTH: int = 20
_HEALTH_PLAN_NUMBER_MIN_LENGTH: int = 8
_HEALTH_PLAN_NUMBER_MAX_LENGTH: int = 20
_CERTIFICATE_PREFIX_MIN_LENGTH: int = 2
_CERTIFICATE_PREFIX_MAX_LENGTH: int = 3
_CERTIFICATE_DIGIT_MIN_LENGTH: int = 5
_CERTIFICATE_DIGIT_MAX_LENGTH: int = 10

# --- Confidence values ---
# Highest-confidence regex patterns: structured with checksum validation.
_CONFIDENCE_VALIDATED_STRUCTURED: float = 0.97
# High-confidence structural patterns with no checksum (email, MBI format).
_CONFIDENCE_HIGH_STRUCTURAL: float = 0.92
# Standard high-confidence regex (phone, IPv4, date, biometric fields).
_CONFIDENCE_STANDARD_REGEX: float = 0.88
# Context-dependent patterns when context is confirmed on the same line.
_CONFIDENCE_CONTEXT_CONFIRMED: float = 0.88
# Context-dependent patterns when required context is absent.
_CONFIDENCE_CONTEXT_ABSENT: float = 0.65
# Regex floor — validated patterns must stay at or above this.
_CONFIDENCE_REGEX_VALIDATED_FLOOR: float = CONFIDENCE_REGEX_MAX - _CONFIDENCE_VALIDATED_FLOOR_OFFSET

# --- URL patient-path segments ---
_URL_PATIENT_PATH_SEGMENTS: tuple[str, ...] = (
    r"/patient/\w+",
    r"/record/[\w\-]+",
    r"/member/[\w\-]+",
    r"/mrn/[\w\-]+",
)

# --- VCF format column header pattern ---
# VCF_GENETIC_DATA_COLUMN_HEADER now lives in constants.py


# ---------------------------------------------------------------------------
# PhiPattern dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PhiPattern:
    """A single compiled detection pattern for the regex layer.

    Args:
        entity_type: String label stored in ScanFinding.entity_type.
        phi_category: PhiCategory enum value for the finding.
        compiled_pattern: Pre-compiled regex applied to each source line.
        base_confidence: Confidence when pattern matches (and context is found
            if context_pattern is set).
        validator: Optional post-match function. Returns True if the matched
            string passes structural validation (e.g. Luhn, checksum).
        context_pattern: Optional compiled regex checked on the same line.
            If present and the context matches, ``base_confidence`` is used.
        no_context_confidence: Confidence when ``context_pattern`` is set but
            does not match. If None, ``base_confidence`` is used regardless.
    """

    entity_type: str
    phi_category: PhiCategory
    compiled_pattern: re.Pattern[str]
    base_confidence: float
    validator: Callable[[str], bool] | None = None
    context_pattern: re.Pattern[str] | None = None
    no_context_confidence: float | None = None


# ---------------------------------------------------------------------------
# Validator functions
# ---------------------------------------------------------------------------


def _compute_luhn_total(digit_string: str) -> int:
    """Compute the Luhn mod-10 total for a string of digits.

    Doubles every second digit from the right. Values that exceed 9 after
    doubling are reduced by 9 (equivalent to summing their digits).

    Args:
        digit_string: String of ASCII digit characters.

    Returns:
        Integer sum used for mod-10 validity check.
    """
    running_total = 0
    for position_index, digit_character in enumerate(reversed(digit_string)):
        digit_value = int(digit_character)
        if position_index % _LUHN_DOUBLE_EVERY_NTH == 1:
            digit_value *= 2
            if digit_value > _LUHN_DOUBLE_MAX_SINGLE_DIGIT:
                digit_value -= _LUHN_DOUBLE_ADJUSTMENT
        running_total += digit_value
    return running_total


def _validate_npi_luhn(npi_text: str) -> bool:
    """Return True if the 10-digit NPI passes the CMS Luhn check.

    CMS validation prepends the ISO 7812 issuer prefix ``80840`` to the NPI
    digits, then verifies that the Luhn total of all 15 digits is divisible
    by 10.

    Args:
        npi_text: The 10-digit NPI string to validate.

    Returns:
        True if the NPI check digit is valid.
    """
    full_sequence = NPI_CMS_LUHN_ISSUER_PREFIX + npi_text
    return _compute_luhn_total(full_sequence) % _LUHN_MODULUS == 0


def _validate_dea_checksum(dea_text: str) -> bool:
    """Return True if the DEA registration number passes its digit checksum.

    Formula: (d1+d3+d5) + 2*(d2+d4+d6) mod 10 must equal d7.
    Digits are counted from the start of the digit portion (after the
    2-letter prefix).

    Args:
        dea_text: Full DEA number string (2 letters + 7 digits).

    Returns:
        True if the checksum is valid.
    """
    digit_characters = dea_text[DEA_NUMBER_PREFIX_LENGTH:]
    digit_values = [int(character) for character in digit_characters]
    odd_position_sum = digit_values[0] + digit_values[2] + digit_values[4]
    even_position_sum = digit_values[1] + digit_values[3] + digit_values[5]
    expected_check_digit = (
        odd_position_sum + _DEA_EVEN_DIGIT_MULTIPLIER * even_position_sum
    ) % _LUHN_MODULUS
    return expected_check_digit == digit_values[_DEA_CHECKSUM_INDEX]


_VIN_TRANSLITERATION: dict[str, int] = {
    "A": 1,
    "B": 2,
    "C": 3,
    "D": 4,
    "E": 5,
    "F": 6,
    "G": 7,
    "H": 8,
    "J": 1,
    "K": 2,
    "L": 3,
    "M": 4,
    "N": 5,
    "P": 7,
    "R": 9,
    "S": 2,
    "T": 3,
    "U": 4,
    "V": 5,
    "W": 6,
    "X": 7,
    "Y": 8,
    "Z": 9,
    **{str(digit): digit for digit in range(_LUHN_MODULUS)},
}
_VIN_POSITION_WEIGHTS: tuple[int, ...] = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def _validate_vin_check_digit(vin_text: str) -> bool:
    """Return True if the VIN check digit at position 9 is valid (ISO 3779).

    Args:
        vin_text: The 17-character VIN string to validate.

    Returns:
        True if the check digit at position 9 (index 8) is correct.
    """
    vin_upper = vin_text.upper()
    weighted_total = sum(
        _VIN_TRANSLITERATION.get(character, 0) * weight
        for character, weight in zip(vin_upper, _VIN_POSITION_WEIGHTS)
    )
    remainder = weighted_total % _VIN_CHECK_MODULUS
    expected_check_character = "X" if remainder == _VIN_CHECK_REMAINDER_FOR_X else str(remainder)
    return vin_upper[_VIN_CHECK_POSITION_INDEX] == expected_check_character


def _is_not_fictional_phone(matched_text: str) -> bool:
    """Return True if the number is not in the FCC fictional NANP range.

    The fictional range is exchange ``FICTIONAL_PHONE_EXCHANGE`` (555) with
    subscriber numbers ``FICTIONAL_PHONE_SUBSCRIBER_MIN``–
    ``FICTIONAL_PHONE_SUBSCRIBER_MAX`` (0100–0199 display format).

    Args:
        matched_text: The full matched phone number string.

    Returns:
        True if the number is a real NANP number (not in fictional range).
    """
    digits_only = re.sub(r"\D", "", matched_text)
    if len(digits_only) == _PHONE_DIGIT_COUNT_DOMESTIC:
        exchange = int(digits_only[3:6])
        subscriber = int(digits_only[6:10])
    elif len(digits_only) == _PHONE_DIGIT_COUNT_E164 and digits_only[0] == _PHONE_E164_COUNTRY_CODE:
        exchange = int(digits_only[4:7])
        subscriber = int(digits_only[7:11])
    else:
        return True
    if exchange == FICTIONAL_PHONE_EXCHANGE:
        return not (FICTIONAL_PHONE_SUBSCRIBER_MIN <= subscriber <= FICTIONAL_PHONE_SUBSCRIBER_MAX)
    return True


def _is_not_documentation_email(matched_text: str) -> bool:
    """Return True if the email domain is not an RFC 2606 documentation domain.

    Excluded domains: example.com, example.org, example.net, test.com.

    Args:
        matched_text: The full matched email address string.

    Returns:
        True if the domain is not a known documentation domain.
    """
    domain_portion = matched_text.split(_EMAIL_DOMAIN_SEPARATOR, maxsplit=1)[-1].lower()
    return domain_portion not in _DOCUMENTATION_EMAIL_DOMAINS


def _is_not_testnet_ipv4(matched_text: str) -> bool:
    """Return True if the IPv4 address is not an RFC 5737 TEST-NET address.

    RFC 5737 documentation ranges are never PHI and are excluded entirely.
    RFC 1918 private ranges are still flagged (may appear in patient logs).

    Args:
        matched_text: The matched IPv4 address string.

    Returns:
        False for TEST-NET documentation ranges; True for all others.
    """
    if any(matched_text.startswith(prefix) for prefix in _RFC5737_TESTNET_PREFIXES):
        return False
    return True


# ---------------------------------------------------------------------------
# Pattern string / regex builders
# ---------------------------------------------------------------------------


def _build_ssn_pattern() -> re.Pattern[str]:
    """Build the SSN regex from named constants (no magic number literals).

    Excludes area 000 (structurally via _SSN_ZERO_AREA), group 00, serial
    0000, and all area numbers in SSN_EXCLUDED_AREA_NUMBERS.

    Returns:
        Compiled case-insensitive SSN pattern.
    """
    area_exclusion = f"(?!(?:{_SSN_ZERO_AREA}|{_SSN_EXCLUDED_AREA_ALTERNATION})-)"
    group_exclusion = f"(?!{_SSN_ZERO_GROUP})"
    serial_exclusion = f"(?!{_SSN_ZERO_SERIAL})"
    pattern_string = (
        r"\b"
        + area_exclusion
        + r"\d{"
        + str(_SSN_AREA_DIGIT_COUNT)
        + r"}-"
        + group_exclusion
        + r"\d{"
        + str(_SSN_GROUP_DIGIT_COUNT)
        + r"}-"
        + serial_exclusion
        + r"\d{"
        + str(_SSN_SERIAL_DIGIT_COUNT)
        + r"}"
        + r"\b"
    )
    return re.compile(pattern_string)


def _build_mbi_pattern() -> re.Pattern[str]:
    """Build the MBI pattern from MBI_ALLOWED_LETTERS and structural formula.

    The 11-character structure is: [1-9][L][L|0-9][0-9][L][L|0-9][0-9][L][L][0-9][0-9]
    where L expands to the CMS-approved letter set (MBI_ALLOWED_LETTERS).
    Neither MBI_CHARACTER_COUNT nor the raw letter string may appear as literals.

    Returns:
        Compiled MBI pattern.
    """
    letter_class = f"[{MBI_ALLOWED_LETTERS}]"
    letter_or_digit_class = f"[{MBI_ALLOWED_LETTERS}0-9]"
    # Structure verified against MBI_CHARACTER_COUNT: 11 position blocks below.
    pattern_string = (
        r"\b"
        + r"[1-9]"  # position 1
        + letter_class  # position 2
        + letter_or_digit_class  # position 3
        + r"[0-9]"  # position 4
        + letter_class  # position 5
        + letter_or_digit_class  # position 6
        + r"[0-9]"  # position 7
        + letter_class  # position 8
        + letter_class  # position 9
        + r"[0-9]"  # position 10
        + r"[0-9]"  # position 11 (= MBI_CHARACTER_COUNT)
        + r"\b"
    )
    return re.compile(pattern_string)


def _build_dea_pattern() -> re.Pattern[str]:
    """Build the DEA pattern from DEA_NUMBER_DIGIT_COUNT (never embed 7).

    Returns:
        Compiled case-insensitive DEA pattern.
    """
    pattern_string = (
        r"\b[A-Z]{"
        + str(DEA_NUMBER_PREFIX_LENGTH)
        + r"}"
        + r"\d{"
        + str(DEA_NUMBER_DIGIT_COUNT)
        + r"}"
        + r"\b"
    )
    return re.compile(pattern_string, re.IGNORECASE)


def _build_vin_pattern() -> re.Pattern[str]:
    """Build the VIN pattern from VIN_CHARACTER_COUNT (never embed 17).

    Returns:
        Compiled case-insensitive VIN pattern.
    """
    pattern_string = r"\b" + _VIN_CHAR_CLASS + r"{" + str(VIN_CHARACTER_COUNT) + r"}" + r"\b"
    return re.compile(pattern_string, re.IGNORECASE)


def _build_dbsnp_pattern() -> re.Pattern[str]:
    """Build the dbSNP rs-ID pattern from DBSNP_RS_ID_MIN/MAX_DIGITS constants.

    Never uses the literals 7 or 9 in the regex quantifier.

    Returns:
        Compiled dbSNP pattern.
    """
    pattern_string = (
        r"\brs\d{" + str(DBSNP_RS_ID_MIN_DIGITS) + r"," + str(DBSNP_RS_ID_MAX_DIGITS) + r"}\b"
    )
    return re.compile(pattern_string, re.IGNORECASE)


def _build_ensembl_pattern() -> re.Pattern[str]:
    """Build the Ensembl gene ID pattern from ENSEMBL_GENE_ID_DIGIT_COUNT.

    Never uses the literal 11 in the regex quantifier.

    Returns:
        Compiled Ensembl pattern.
    """
    pattern_string = r"\bENSG\d{" + str(ENSEMBL_GENE_ID_DIGIT_COUNT) + r"}\b"
    return re.compile(pattern_string, re.IGNORECASE)


def _build_age_over_threshold_pattern() -> re.Pattern[str]:
    """Build the age-over-90 pattern from HIPAA_AGE_RESTRICTION_THRESHOLD.

    The literal 90 must not appear in logic code. Pattern matches ages
    strictly greater than HIPAA_AGE_RESTRICTION_THRESHOLD (i.e., 91+).

    Returns:
        Compiled pattern for ages 91 and above.
    """
    # Matches 91-99 using tens/units digits derived from the threshold constant.
    # Also matches 100+ (three or more digits starting with 1-9).
    pattern_string = (
        r"\b(?:"
        + str(_MIN_RESTRICTED_AGE_TENS)
        + r"["
        + str(_MIN_RESTRICTED_AGE_UNITS)
        + r"-9]"
        + r"|[1-9]\d{2,}"
        + r")\b"
    )
    return re.compile(pattern_string)


def _build_context_pattern(keywords: tuple[str, ...]) -> re.Pattern[str]:
    """Build a case-insensitive alternation pattern from a keyword tuple.

    Args:
        keywords: Tuple of literal keyword strings to match.

    Returns:
        Compiled pattern that matches any keyword (word-boundary anchored).
    """
    alternation = "|".join(re.escape(keyword) for keyword in keywords)
    return re.compile(r"\b(?:" + alternation + r")\b", re.IGNORECASE)


def _build_hicn_pattern() -> re.Pattern[str]:
    """Build the HICN pattern from named digit-count constants.

    HICN: 9-digit SSN base + 1–2 letter suffix (A–D, T).

    Returns:
        Compiled HICN pattern.
    """
    pattern_string = (
        r"\b\d{"
        + str(_HICN_BASE_DIGIT_COUNT)
        + r"}"
        + r"[A-DT]"
        + r"{"
        + str(_HICN_SUFFIX_MIN_COUNT)
        + r","
        + str(_HICN_SUFFIX_MAX_COUNT)
        + r"}"
        + r"\b"
    )
    return re.compile(pattern_string, re.IGNORECASE)


def _build_phone_pattern() -> re.Pattern[str]:
    """Build the phone pattern from NANP structural constants.

    Returns:
        Compiled phone pattern covering NANP, E.164, and international formats.
    """
    seg = r"\d{" + str(_NANP_SEGMENT_DIGIT_COUNT) + r"}"
    sub = r"\d{" + str(_PHONE_SUBSCRIBER_LAST_DIGIT_COUNT) + r"}"
    domestic = str(_PHONE_DIGIT_COUNT_DOMESTIC)
    intl_range = str(_PHONE_INTL_MIN_DIGITS) + r"," + str(_PHONE_INTL_MAX_DIGITS)
    pattern_string = (
        r"(?:\+1[-.\s]?)?(?:\("
        + seg
        + r"\)|"
        + seg
        + r")[-.\s]"
        + seg
        + r"[-.\s]"
        + sub
        + r"|\+1\d{"
        + domestic
        + r"}"
        + r"|\+[2-9]\d{"
        + intl_range
        + r"}"
    )
    return re.compile(pattern_string)


def _build_email_pattern() -> re.Pattern[str]:
    """Build the email pattern with TLD minimum length from a named constant.

    Returns:
        Compiled email pattern.
    """
    pattern_string = (
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{" + str(_EMAIL_TLD_MIN_CHARS) + r",}\b"
    )
    return re.compile(pattern_string)


def _build_ipv4_pattern() -> re.Pattern[str]:
    """Build the IPv4 octet pattern anchored on _IPV4_OCTET_MAX_VALUE (255).

    Constructs the three-range octet form: 250–255 | 200–249 | 0–199.
    All character-class boundaries are derived from _IPV4_OCTET_MAX_VALUE.

    Returns:
        Compiled IPv4 pattern.
    """
    tens_pair = str(_IPV4_OCTET_MAX_TENS_PAIR)
    max_unit = str(_IPV4_OCTET_MAX_UNITS_DIGIT)
    hundreds = str(_IPV4_OCTET_HIGH_RANGE_HUNDREDS)
    high_tens_max = str(_IPV4_OCTET_HIGH_RANGE_MAX_TENS)
    octet = (
        r"(?:"
        + tens_pair
        + r"[0-"
        + max_unit
        + r"]"
        + r"|"
        + hundreds
        + r"[0-"
        + high_tens_max
        + r"]\d"
        + r"|[01]?\d\d?"
        + r")"
    )
    pattern_string = r"\b(?:" + octet + r"\.){3}" + octet + r"\b"
    return re.compile(pattern_string)


def _build_ipv6_pattern() -> re.Pattern[str]:
    """Build the IPv6 address pattern from _IPV6_GROUP_COUNT and hex group constants.

    IPv6 has _IPV6_GROUP_COUNT (8) hex groups. All quantifiers in the pattern
    are derived from this constant. The nine alternations cover full notation
    and all compressed (::) forms defined by RFC 5952.

    Returns:
        Compiled IPv6 pattern.
    """
    hex_group = (
        r"[0-9a-fA-F]{"
        + str(_IPV6_HEX_GROUP_MIN_CHARS)
        + r","
        + str(_IPV6_HEX_GROUP_MAX_CHARS)
        + r"}"
    )
    n = _IPV6_GROUP_COUNT  # 8 total groups; all quantifiers derive from this
    one = _LAST_DIGIT_INDEX_OFFSET  # 1
    full = str(n - one)  # "7" prefix groups in full notation
    alternations = [
        r"(?:" + hex_group + r":){" + full + r"}" + hex_group,
        r"(?:" + hex_group + r":){1," + full + r"}:",
        r"(?:" + hex_group + r":){1," + str(n - 2) + r"}:" + hex_group,
        r"(?:" + hex_group + r":){1," + str(n - 3) + r"}(?::" + hex_group + r"){1,2}",
        r"(?:" + hex_group + r":){1," + str(n - 4) + r"}(?::" + hex_group + r"){1,3}",
        r"(?:" + hex_group + r":){1," + str(n - 5) + r"}(?::" + hex_group + r"){1,4}",
        r"(?:" + hex_group + r":){1," + str(n - 6) + r"}(?::" + hex_group + r"){1,5}",
        hex_group + r":(?::" + hex_group + r"){1," + str(n - 2) + r"}",
        r"::(?:" + hex_group + r":){0," + str(n - 3) + r"}" + hex_group,
    ]
    return re.compile("|".join(alternations))


def _build_zip_plus4_pattern() -> re.Pattern[str]:
    """Build the ZIP+4 pattern from ZIP_CODE_DIGIT_COUNT and ZIP_PLUS4_SUFFIX_DIGIT_COUNT.

    Returns:
        Compiled ZIP+4 pattern.
    """
    pattern_string = (
        r"\b\d{"
        + str(ZIP_CODE_DIGIT_COUNT)
        + r"}"
        + r"-\d{"
        + str(ZIP_PLUS4_SUFFIX_DIGIT_COUNT)
        + r"}\b"
    )
    return re.compile(pattern_string)


def _build_zip5_pattern() -> re.Pattern[str]:
    """Build the 5-digit ZIP code pattern from ZIP_CODE_DIGIT_COUNT.

    Returns:
        Compiled 5-digit ZIP pattern.
    """
    return re.compile(r"\b\d{" + str(ZIP_CODE_DIGIT_COUNT) + r"}\b")


def _build_street_address_pattern() -> re.Pattern[str]:
    """Build the street address pattern from street number digit count constants.

    Returns:
        Compiled street address pattern.
    """
    pattern_string = (
        r"\b\d{"
        + str(_STREET_NUMBER_MIN_DIGITS)
        + r","
        + str(_STREET_NUMBER_MAX_DIGITS)
        + r"}\s+(?:[A-Z][a-z]+\s+)+"
        + r"(?:St(?:reet)?|Ave(?:nue)?|Blvd|Rd|Dr(?:ive)?|Ln|Ct|Circle|Way|Pkwy|Hwy)\b"
    )
    return re.compile(pattern_string)


def _build_date_pattern(separator: str, year_position: str) -> re.Pattern[str]:
    """Build an ISO or US date pattern with _YEAR_DIGIT_COUNT for the year.

    Args:
        separator: Character separating date components ("-" or "/").
        year_position: "prefix" puts year first (ISO), "suffix" puts year last (US).

    Returns:
        Compiled date pattern.
    """
    year = r"\d{" + str(_YEAR_DIGIT_COUNT) + r"}"
    month = r"(?:0[1-9]|1[0-2])"
    day = r"(?:0[1-9]|[12]\d|3[01])"
    if year_position == "prefix":
        pattern_string = r"\b" + year + separator + month + separator + day + r"\b"
    else:
        pattern_string = r"\b" + month + separator + day + separator + year + r"\b"
    return re.compile(pattern_string)


def _build_fda_udi_pattern() -> re.Pattern[str]:
    """Build the FDA UDI pattern from GS1 Application Identifier constants.

    Returns:
        Compiled FDA UDI pattern covering GTIN-14, lot number, and manufacture date.
    """
    gtin = r"\(" + _FDA_UDI_AI_GTIN + r"\)\d{" + str(_FDA_UDI_GTIN_DIGIT_COUNT) + r"}"
    lot = (
        r"\("
        + _FDA_UDI_AI_LOT
        + r"\)[A-Z0-9]{"
        + str(_FDA_UDI_LOT_MIN_LENGTH)
        + r","
        + str(_FDA_UDI_LOT_MAX_LENGTH)
        + r"}"
    )
    mfg_date = r"\(" + _FDA_UDI_AI_MFG_DATE + r"\)\d{" + str(_FDA_UDI_DATE_DIGIT_COUNT) + r"}"
    return re.compile(r"(?:" + gtin + r"|" + lot + r"|" + mfg_date + r")", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Pre-compiled patterns used in the registry
# ---------------------------------------------------------------------------

_PATTERN_SSN = _build_ssn_pattern()
_PATTERN_MBI = _build_mbi_pattern()
_PATTERN_DEA = _build_dea_pattern()
_PATTERN_VIN = _build_vin_pattern()
_PATTERN_DBSNP = _build_dbsnp_pattern()
_PATTERN_ENSEMBL = _build_ensembl_pattern()
_PATTERN_AGE_OVER_THRESHOLD = _build_age_over_threshold_pattern()
_PATTERN_HICN = _build_hicn_pattern()

_PATTERN_NPI = re.compile(r"\b\d{" + str(_NPI_DIGIT_COUNT) + r"}\b")
_PATTERN_PHONE = _build_phone_pattern()
_PATTERN_FAX = _PATTERN_PHONE  # Same structural patterns as phone
_PATTERN_EMAIL = _build_email_pattern()
_PATTERN_IPV4 = _build_ipv4_pattern()
_PATTERN_IPV6 = _build_ipv6_pattern()
_PATTERN_DATE_ISO = _build_date_pattern(separator="-", year_position="prefix")
_PATTERN_DATE_US = _build_date_pattern(separator="/", year_position="suffix")
_PATTERN_DATE_LONG = re.compile(
    r"\b(?:January|February|March|April|May|June|July|August|"
    r"September|October|November|December)"
    r"\s+(?:0?[1-9]|[12]\d|3[01]),\s*\d{" + str(_YEAR_DIGIT_COUNT) + r"}\b",
    re.IGNORECASE,
)
_PATTERN_DATE_SHORT_MON = re.compile(
    r"\b(?:0?[1-9]|[12]\d|3[01])-"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-\d{" + str(_YEAR_DIGIT_COUNT) + r"}\b",
    re.IGNORECASE,
)
_PATTERN_ZIP_PLUS4 = _build_zip_plus4_pattern()
_PATTERN_ZIP5 = _build_zip5_pattern()
_PATTERN_STREET_ADDRESS = _build_street_address_pattern()
_PATTERN_URL_PATIENT = re.compile(
    r"https?://[^\s\"']+" + r"(?:" + "|".join(_URL_PATIENT_PATH_SEGMENTS) + r")" + r"[^\s\"']*",
    re.IGNORECASE,
)
_PATTERN_MRN_VALUE = re.compile(
    r"\b\d{" + str(_MRN_MIN_DIGIT_COUNT) + r"," + str(_MRN_MAX_DIGIT_COUNT) + r"}\b"
)
_PATTERN_ACCOUNT_VALUE = re.compile(
    r"\b[A-Z0-9]{"
    + str(_ACCOUNT_NUMBER_MIN_LENGTH)
    + r","
    + str(_ACCOUNT_NUMBER_MAX_LENGTH)
    + r"}\b"
)
_PATTERN_HEALTH_PLAN_VALUE = re.compile(
    r"\b[A-Z0-9]{"
    + str(_HEALTH_PLAN_NUMBER_MIN_LENGTH)
    + r","
    + str(_HEALTH_PLAN_NUMBER_MAX_LENGTH)
    + r"}\b",
    re.IGNORECASE,
)
_PATTERN_CERTIFICATE_VALUE = re.compile(
    r"\b[A-Z]{"
    + str(_CERTIFICATE_PREFIX_MIN_LENGTH)
    + r","
    + str(_CERTIFICATE_PREFIX_MAX_LENGTH)
    + r"}\d{"
    + str(_CERTIFICATE_DIGIT_MIN_LENGTH)
    + r","
    + str(_CERTIFICATE_DIGIT_MAX_LENGTH)
    + r"}\b",
    re.IGNORECASE,
)
_PATTERN_BIOMETRIC_FIELDS = re.compile(
    r"\b(?:" + "|".join(re.escape(name) for name in BIOMETRIC_FIELD_NAMES) + r")\b",
    re.IGNORECASE,
)
_PATTERN_SUD_FIELDS = re.compile(
    r"\b(?:" + "|".join(re.escape(name) for name in sorted(SUD_FIELD_NAME_PATTERNS)) + r")\b",
    re.IGNORECASE,
)
_PATTERN_VCF_DATA = re.compile(
    r"\b" + re.escape(VCF_GENETIC_DATA_COLUMN_HEADER) + r"\s+POS\s+ID\s+REF\s+ALT\b",
    re.IGNORECASE,
)
_PATTERN_FDA_UDI = _build_fda_udi_pattern()

# Context patterns (same-line variable name checks)
_CONTEXT_NPI = _build_context_pattern(_NPI_CONTEXT_KEYWORDS)
_CONTEXT_MRN = _build_context_pattern(_MRN_CONTEXT_KEYWORDS)
_CONTEXT_ACCOUNT = _build_context_pattern(_ACCOUNT_CONTEXT_KEYWORDS)
_CONTEXT_HEALTH_PLAN = _build_context_pattern(_HEALTH_PLAN_CONTEXT_KEYWORDS)
_CONTEXT_CERTIFICATE = _build_context_pattern(_CERTIFICATE_CONTEXT_KEYWORDS)
_CONTEXT_HICN = _build_context_pattern(_HICN_CONTEXT_KEYWORDS)
_CONTEXT_AGE = _build_context_pattern(_AGE_CONTEXT_KEYWORDS)

# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

_PATTERN_REGISTRY: tuple[PhiPattern, ...] = (
    # --- SSN ---
    PhiPattern(
        entity_type="SSN",
        phi_category=PhiCategory.SSN,
        compiled_pattern=_PATTERN_SSN,
        base_confidence=_CONFIDENCE_VALIDATED_STRUCTURED,
    ),
    # --- MBI (Medicare Beneficiary Identifier) ---
    PhiPattern(
        entity_type="MBI",
        phi_category=PhiCategory.UNIQUE_ID,
        compiled_pattern=_PATTERN_MBI,
        base_confidence=_CONFIDENCE_HIGH_STRUCTURAL,
    ),
    # --- DEA number (checksum validated) ---
    PhiPattern(
        entity_type="DEA",
        phi_category=PhiCategory.CERTIFICATE,
        compiled_pattern=_PATTERN_DEA,
        base_confidence=_CONFIDENCE_VALIDATED_STRUCTURED,
        validator=_validate_dea_checksum,
    ),
    # --- NPI (Luhn validated, context-dependent) ---
    # Any 10-digit number can match the NPI pattern; the Luhn check reduces but
    # does not eliminate false positives. A context_pattern is required to keep
    # no-context confidence below the reporting threshold for ambiguous matches.
    PhiPattern(
        entity_type="NPI",
        phi_category=PhiCategory.UNIQUE_ID,
        compiled_pattern=_PATTERN_NPI,
        base_confidence=_CONFIDENCE_HIGH_STRUCTURAL,
        validator=_validate_npi_luhn,
        context_pattern=_CONTEXT_NPI,
        no_context_confidence=_CONFIDENCE_CONTEXT_ABSENT,
    ),
    # --- VIN (ISO 3779 check digit validated) ---
    PhiPattern(
        entity_type="VIN",
        phi_category=PhiCategory.VEHICLE,
        compiled_pattern=_PATTERN_VIN,
        base_confidence=_CONFIDENCE_HIGH_STRUCTURAL,
        validator=_validate_vin_check_digit,
    ),
    # --- HICN (legacy Medicare, lower confidence, context-dependent) ---
    PhiPattern(
        entity_type="HICN",
        phi_category=PhiCategory.UNIQUE_ID,
        compiled_pattern=_PATTERN_HICN,
        base_confidence=_CONFIDENCE_CONTEXT_CONFIRMED,
        context_pattern=_CONTEXT_HICN,
        no_context_confidence=_CONFIDENCE_CONTEXT_ABSENT,
    ),
    # --- Phone ---
    PhiPattern(
        entity_type="PHONE",
        phi_category=PhiCategory.PHONE,
        compiled_pattern=_PATTERN_PHONE,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
        validator=_is_not_fictional_phone,
    ),
    # --- Fax (same patterns as phone) ---
    PhiPattern(
        entity_type="FAX",
        phi_category=PhiCategory.FAX,
        compiled_pattern=_PATTERN_FAX,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
        validator=_is_not_fictional_phone,
    ),
    # --- Email ---
    PhiPattern(
        entity_type="EMAIL",
        phi_category=PhiCategory.EMAIL,
        compiled_pattern=_PATTERN_EMAIL,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
        validator=_is_not_documentation_email,
    ),
    # --- IPv4 ---
    PhiPattern(
        entity_type="IPV4_ADDRESS",
        phi_category=PhiCategory.IP,
        compiled_pattern=_PATTERN_IPV4,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
        validator=_is_not_testnet_ipv4,
    ),
    # --- IPv6 ---
    PhiPattern(
        entity_type="IPV6_ADDRESS",
        phi_category=PhiCategory.IP,
        compiled_pattern=_PATTERN_IPV6,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
    ),
    # --- Dates (ISO 8601: YYYY-MM-DD) ---
    PhiPattern(
        entity_type="DATE",
        phi_category=PhiCategory.DATE,
        compiled_pattern=_PATTERN_DATE_ISO,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
    ),
    # --- Dates (US format: MM/DD/YYYY) ---
    PhiPattern(
        entity_type="DATE",
        phi_category=PhiCategory.DATE,
        compiled_pattern=_PATTERN_DATE_US,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
    ),
    # --- Dates (long: Month DD, YYYY) ---
    PhiPattern(
        entity_type="DATE",
        phi_category=PhiCategory.DATE,
        compiled_pattern=_PATTERN_DATE_LONG,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
    ),
    # --- Dates (short-month: DD-Mon-YYYY) ---
    PhiPattern(
        entity_type="DATE",
        phi_category=PhiCategory.DATE,
        compiled_pattern=_PATTERN_DATE_SHORT_MON,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
    ),
    # --- Age over HIPAA threshold (HIPAA §164.514(b)(2)(i)) ---
    PhiPattern(
        entity_type="AGE_OVER_THRESHOLD",
        phi_category=PhiCategory.UNIQUE_ID,
        compiled_pattern=_PATTERN_AGE_OVER_THRESHOLD,
        base_confidence=_CONFIDENCE_CONTEXT_CONFIRMED,
        context_pattern=_CONTEXT_AGE,
        no_context_confidence=_CONFIDENCE_CONTEXT_ABSENT,
    ),
    # --- ZIP+4 (always flagged at medium-high confidence) ---
    PhiPattern(
        entity_type="ZIP_PLUS4",
        phi_category=PhiCategory.GEOGRAPHIC,
        compiled_pattern=_PATTERN_ZIP_PLUS4,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
    ),
    # --- ZIP 5-digit ---
    PhiPattern(
        entity_type="ZIP_CODE",
        phi_category=PhiCategory.GEOGRAPHIC,
        compiled_pattern=_PATTERN_ZIP5,
        base_confidence=_CONFIDENCE_REGEX_VALIDATED_FLOOR,
    ),
    # --- Street address ---
    PhiPattern(
        entity_type="STREET_ADDRESS",
        phi_category=PhiCategory.GEOGRAPHIC,
        compiled_pattern=_PATTERN_STREET_ADDRESS,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
    ),
    # --- URL with patient-identifier path segment ---
    PhiPattern(
        entity_type="PATIENT_URL",
        phi_category=PhiCategory.URL,
        compiled_pattern=_PATTERN_URL_PATIENT,
        base_confidence=_CONFIDENCE_STANDARD_REGEX,
    ),
    # --- MRN (context-dependent) ---
    PhiPattern(
        entity_type="MRN",
        phi_category=PhiCategory.MRN,
        compiled_pattern=_PATTERN_MRN_VALUE,
        base_confidence=_CONFIDENCE_CONTEXT_CONFIRMED,
        context_pattern=_CONTEXT_MRN,
        no_context_confidence=_CONFIDENCE_CONTEXT_ABSENT,
    ),
    # --- Account number (context-dependent) ---
    PhiPattern(
        entity_type="ACCOUNT_NUMBER",
        phi_category=PhiCategory.ACCOUNT,
        compiled_pattern=_PATTERN_ACCOUNT_VALUE,
        base_confidence=_CONFIDENCE_CONTEXT_CONFIRMED,
        context_pattern=_CONTEXT_ACCOUNT,
        no_context_confidence=_CONFIDENCE_CONTEXT_ABSENT,
    ),
    # --- Health plan number (context-dependent) ---
    PhiPattern(
        entity_type="HEALTH_PLAN_NUMBER",
        phi_category=PhiCategory.HEALTH_PLAN,
        compiled_pattern=_PATTERN_HEALTH_PLAN_VALUE,
        base_confidence=_CONFIDENCE_CONTEXT_CONFIRMED,
        context_pattern=_CONTEXT_HEALTH_PLAN,
        no_context_confidence=_CONFIDENCE_CONTEXT_ABSENT,
    ),
    # --- Certificate / license number (context-dependent) ---
    PhiPattern(
        entity_type="CERTIFICATE_NUMBER",
        phi_category=PhiCategory.CERTIFICATE,
        compiled_pattern=_PATTERN_CERTIFICATE_VALUE,
        base_confidence=_CONFIDENCE_CONTEXT_CONFIRMED,
        context_pattern=_CONTEXT_CERTIFICATE,
        no_context_confidence=_CONFIDENCE_CONTEXT_ABSENT,
    ),
    # --- Biometric field names ---
    PhiPattern(
        entity_type="BIOMETRIC_FIELD",
        phi_category=PhiCategory.BIOMETRIC,
        compiled_pattern=_PATTERN_BIOMETRIC_FIELDS,
        base_confidence=_CONFIDENCE_REGEX_VALIDATED_FLOOR,
    ),
    # --- SUD field names (42 CFR Part 2) ---
    PhiPattern(
        entity_type="SUD_FIELD",
        phi_category=PhiCategory.SUBSTANCE_USE_DISORDER,
        compiled_pattern=_PATTERN_SUD_FIELDS,
        base_confidence=_CONFIDENCE_HIGH_STRUCTURAL,
    ),
    # --- dbSNP rs-ID (genetic identifier, GINA + GDPR Art. 9) ---
    PhiPattern(
        entity_type="DBSNP_RS_ID",
        phi_category=PhiCategory.UNIQUE_ID,
        compiled_pattern=_PATTERN_DBSNP,
        base_confidence=_CONFIDENCE_HIGH_STRUCTURAL,
    ),
    # --- Ensembl gene ID ---
    PhiPattern(
        entity_type="ENSEMBL_GENE_ID",
        phi_category=PhiCategory.UNIQUE_ID,
        compiled_pattern=_PATTERN_ENSEMBL,
        base_confidence=_CONFIDENCE_HIGH_STRUCTURAL,
    ),
    # --- VCF-format genomic data (CHROM/POS/REF/ALT header) ---
    PhiPattern(
        entity_type="VCF_GENETIC_DATA",
        phi_category=PhiCategory.UNIQUE_ID,
        compiled_pattern=_PATTERN_VCF_DATA,
        base_confidence=_CONFIDENCE_HIGH_STRUCTURAL,
    ),
    # --- FDA UDI device identifier ---
    PhiPattern(
        entity_type="FDA_UDI",
        phi_category=PhiCategory.DEVICE,
        compiled_pattern=_PATTERN_FDA_UDI,
        base_confidence=_CONFIDENCE_HIGH_STRUCTURAL,
    ),
)

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _determine_confidence(line_text: str, phi_pattern: PhiPattern) -> float:
    """Return the effective confidence for a match on the given line.

    If the pattern has a context_pattern, the confidence is boosted to
    base_confidence when that pattern matches the line, and reduced to
    no_context_confidence when it does not.

    Args:
        line_text: The source line on which the match was found.
        phi_pattern: The PhiPattern that produced the match.

    Returns:
        Effective confidence float.
    """
    if phi_pattern.context_pattern is None:
        return phi_pattern.base_confidence
    context_found = phi_pattern.context_pattern.search(line_text) is not None
    if context_found:
        return phi_pattern.base_confidence
    if phi_pattern.no_context_confidence is not None:
        return phi_pattern.no_context_confidence
    return phi_pattern.base_confidence


def _build_finding(
    file_path: Path,
    line_number: int,
    line_text: str,
    matched_text: str,
    phi_pattern: PhiPattern,
    confidence: float,
) -> ScanFinding:
    """Construct a ScanFinding for one validated regex match.

    The raw matched_text is hashed immediately; only the hash is stored.
    code_context is the source line with the matched value replaced by
    CODE_CONTEXT_REDACTED_VALUE so raw PHI never flows through the model.

    Args:
        file_path: Path of the source file.
        line_number: 1-indexed source line number.
        line_text: Full text of the source line.
        matched_text: The exact matched string — hashed, then redacted from context.
        phi_pattern: The pattern that produced the match.
        confidence: Pre-computed confidence float.

    Returns:
        Immutable ScanFinding.
    """
    redacted_context = line_text.replace(matched_text, CODE_CONTEXT_REDACTED_VALUE).rstrip()
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=phi_pattern.entity_type,
        hipaa_category=phi_pattern.phi_category,
        confidence=confidence,
        detection_layer=DetectionLayer.REGEX,
        value_hash=compute_value_hash(matched_text),
        severity=severity_from_confidence(confidence),
        code_context=redacted_context,
        remediation_hint=HIPAA_REMEDIATION_GUIDANCE.get(phi_pattern.phi_category, ""),
    )


def _scan_line_for_pattern(
    line_text: str,
    line_number: int,
    file_path: Path,
    phi_pattern: PhiPattern,
) -> list[ScanFinding]:
    """Apply one PhiPattern to one source line.

    Runs the validator (if any) on each match and skips invalid matches.
    Confidence is determined from context-pattern presence on the same line.

    Args:
        line_text: The source line to scan.
        line_number: 1-indexed line number.
        file_path: Source file path for ScanFinding construction.
        phi_pattern: The pattern to apply.

    Returns:
        List of ScanFinding objects for this line and pattern (may be empty).
    """
    line_findings: list[ScanFinding] = []
    for regex_match in phi_pattern.compiled_pattern.finditer(line_text):
        matched_text = regex_match.group()
        if phi_pattern.validator is not None and not phi_pattern.validator(matched_text):
            continue
        confidence = _determine_confidence(line_text, phi_pattern)
        line_findings.append(
            _build_finding(file_path, line_number, line_text, matched_text, phi_pattern, confidence)
        )
    return line_findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_phi_with_regex(file_content: str, file_path: Path) -> list[ScanFinding]:
    """Scan file content line-by-line for PHI using the regex pattern registry.

    Layer 1 of the detection engine. Applies all patterns in _PATTERN_REGISTRY
    to each line. Post-match validators (Luhn, checksum, exclusion filters) are
    applied before creating a finding. Matched values are never stored — only
    their SHA-256 hashes (HIPAA audit requirement).

    Args:
        file_content: Full text content of the file to scan.
        file_path: Source path recorded in each ScanFinding for reporting.

    Returns:
        List of ScanFinding objects, one per validated match per pattern per line.
    """
    all_findings: list[ScanFinding] = []
    for line_number, line_text in enumerate(file_content.splitlines(), start=_LINE_NUMBER_START):
        for phi_pattern in _PATTERN_REGISTRY:
            all_findings.extend(
                _scan_line_for_pattern(line_text, line_number, file_path, phi_pattern)
            )
    return all_findings


def get_phi_pattern_registry() -> tuple[PhiPattern, ...]:
    """Return the compiled PHI pattern registry used by the regex detection layer.

    Provides read-only access to the registry for callers that need to iterate
    patterns directly — for example, the auto-fix engine (``phi_scan.fixer``)
    which must re-apply patterns to source lines to locate raw match spans and
    generate synthetic replacement values.

    Returns:
        Immutable tuple of all PhiPattern objects in detection order.
    """
    return _PATTERN_REGISTRY
