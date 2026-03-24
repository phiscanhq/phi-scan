"""Tests for phi_scan.constants — named constants, enums, and derived values."""

import pytest

from phi_scan.constants import (
    AI_LAYER_CONFIDENCE_ADJUSTMENT_MAX,
    AUDIT_RETENTION_DAYS,
    BYTES_PER_MEGABYTE,
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_LOW_FLOOR,
    CONFIDENCE_MEDIUM_FLOOR,
    CONFIDENCE_REGEX_MAX,
    CONFIDENCE_REGEX_MIN,
    CONFIDENCE_SCORE_MAXIMUM,
    DBSNP_RS_ID_MAX_DIGITS,
    DBSNP_RS_ID_MIN_DIGITS,
    DEA_NUMBER_DIGIT_COUNT,
    DEFAULT_CONFIDENCE_THRESHOLD,
    ENSEMBL_GENE_ID_DIGIT_COUNT,
    FICTIONAL_PHONE_EXCHANGE,
    FICTIONAL_PHONE_SUBSCRIBER_DISPLAY_PREFIX,
    FICTIONAL_PHONE_SUBSCRIBER_MAX,
    FICTIONAL_PHONE_SUBSCRIBER_MIN,
    HIPAA_AGE_RESTRICTION_THRESHOLD,
    HIPAA_REMEDIATION_GUIDANCE,
    KNOWN_BINARY_EXTENSIONS,
    MAX_FILE_SIZE_BYTES,
    MAX_FILE_SIZE_MB,
    MBI_ALLOWED_LETTERS,
    MBI_CHARACTER_COUNT,
    MINIMUM_QUASI_IDENTIFIER_COUNT,
    QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES,
    SSN_EXCLUDED_AREA_NUMBERS,
    SUD_FIELD_NAME_PATTERNS,
    VIN_CHARACTER_COUNT,
    ZIP_CODE_SAFE_HARBOR_POPULATION_MIN,
    OutputFormat,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)

# Cross-check: AUDIT_RETENTION_DAYS must equal the HIPAA-mandated 6-year minimum.
# 6 years worst-case: 4 standard years (365 days) + 2 leap years (366 days) = 2192 days.
# This concrete value is intentional — it guards against formula regressions.
_EXPECTED_HIPAA_RETENTION_DAYS: int = 2192


def test_max_file_size_bytes_equals_mb_times_bytes_per_megabyte() -> None:
    assert MAX_FILE_SIZE_BYTES == MAX_FILE_SIZE_MB * BYTES_PER_MEGABYTE


def test_audit_retention_days_equals_hipaa_six_year_minimum() -> None:
    assert AUDIT_RETENTION_DAYS == _EXPECTED_HIPAA_RETENTION_DAYS


def test_output_format_raises_value_error_for_unknown_string_value() -> None:
    # _missing_ returns None for unknown values; Python's enum machinery
    # then raises ValueError — callers should catch ValueError, not check None.
    with pytest.raises(ValueError):
        OutputFormat("unknown-format")


def test_output_format_raises_value_error_for_non_string_value() -> None:
    # _missing_ guard clause: non-string input returns None immediately,
    # causing Python's enum machinery to raise ValueError.
    with pytest.raises(ValueError):
        OutputFormat(42)  # type: ignore[arg-type]


def test_output_format_missing_matches_gitlab_sast_by_value() -> None:
    assert OutputFormat("gitlab-sast") is OutputFormat.GITLAB_SAST


def test_output_format_missing_is_case_insensitive() -> None:
    # StrEnum is case-sensitive by default: OutputFormat("TABLE") misses the
    # "table" member and falls through to _missing_, which calls lower() to match.
    assert OutputFormat("TABLE") is OutputFormat.TABLE


def test_hipaa_remediation_guidance_covers_every_phi_category() -> None:
    missing = [category for category in PhiCategory if category not in HIPAA_REMEDIATION_GUIDANCE]
    assert missing == [], f"Missing remediation guidance for: {missing}"


def test_known_binary_extensions_are_lowercase_dotted_strings() -> None:
    malformed = [
        ext for ext in KNOWN_BINARY_EXTENSIONS if not ext.startswith(".") or ext != ext.lower()
    ]
    assert malformed == [], f"Malformed extensions: {malformed}"


def test_known_binary_extensions_is_immutable() -> None:
    assert isinstance(KNOWN_BINARY_EXTENSIONS, frozenset)


def test_severity_level_resolves_high_by_value() -> None:
    assert SeverityLevel("high") is SeverityLevel.HIGH


def test_severity_level_resolves_info_by_value() -> None:
    assert SeverityLevel("info") is SeverityLevel.INFO


def test_risk_level_resolves_clean_by_value() -> None:
    assert RiskLevel("clean") is RiskLevel.CLEAN


def test_risk_level_resolves_critical_by_value() -> None:
    assert RiskLevel("critical") is RiskLevel.CRITICAL


def test_confidence_low_floor_is_below_default_threshold() -> None:
    assert CONFIDENCE_LOW_FLOOR < DEFAULT_CONFIDENCE_THRESHOLD


def test_default_confidence_threshold_is_below_medium_floor() -> None:
    assert DEFAULT_CONFIDENCE_THRESHOLD < CONFIDENCE_MEDIUM_FLOOR


def test_confidence_medium_floor_is_below_high_floor() -> None:
    assert CONFIDENCE_MEDIUM_FLOOR < CONFIDENCE_HIGH_FLOOR


def test_confidence_regex_max_equals_score_maximum() -> None:
    assert CONFIDENCE_REGEX_MAX == CONFIDENCE_SCORE_MAXIMUM


def test_confidence_regex_min_is_below_regex_max() -> None:
    assert CONFIDENCE_REGEX_MIN < CONFIDENCE_REGEX_MAX


def test_ai_layer_adjustment_max_is_below_high_floor() -> None:
    # Ensures the AI layer cannot push a LOW-confidence finding into HIGH territory
    # on its own — a delta this small requires a pre-existing high base score.
    assert AI_LAYER_CONFIDENCE_ADJUSTMENT_MAX < CONFIDENCE_HIGH_FLOOR


def test_phi_category_substance_use_disorder_resolves_by_value() -> None:
    assert PhiCategory("substance_use_disorder") is PhiCategory.SUBSTANCE_USE_DISORDER


def test_phi_category_quasi_identifier_combination_resolves_by_value() -> None:
    assert PhiCategory("quasi_identifier_combination") is PhiCategory.QUASI_IDENTIFIER_COMBINATION


def test_substance_use_disorder_is_not_unique_id() -> None:
    # 42 CFR Part 2 is a distinct regulatory category. Aliasing to UNIQUE_ID would
    # collapse two different statutes into one enum value and break compliance mapping.
    assert PhiCategory.SUBSTANCE_USE_DISORDER is not PhiCategory.UNIQUE_ID


def test_quasi_identifier_combination_is_not_unique_id() -> None:
    # Quasi-identifier combination risk is a distinct concept from HIPAA Safe Harbor
    # category #18 (unique identifying numbers). They must remain separate enum members.
    assert PhiCategory.QUASI_IDENTIFIER_COMBINATION is not PhiCategory.UNIQUE_ID


def test_quasi_identifier_proximity_window_lines_is_positive_int() -> None:
    # Guards against the constant being accidentally set to zero or negative, which
    # would disable combination detection entirely without raising an error.
    assert isinstance(QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES, int)
    assert QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES > 0


def test_minimum_quasi_identifier_count_is_at_least_two() -> None:
    # A count of 1 would flag every single-field finding as a combination —
    # the combination rule requires at least two distinct categories.
    assert isinstance(MINIMUM_QUASI_IDENTIFIER_COUNT, int)
    assert MINIMUM_QUASI_IDENTIFIER_COUNT >= 2


def test_hipaa_age_restriction_threshold_is_ninety() -> None:
    # HIPAA §164.514(b)(2)(i) restricts ages "over 90" — strictly greater than 90.
    # If this value drifts, detection logic using > HIPAA_AGE_RESTRICTION_THRESHOLD
    # would flag the wrong population. Pin the concrete value as a regression guard.
    assert HIPAA_AGE_RESTRICTION_THRESHOLD == 90


def test_mbi_character_count_is_eleven() -> None:
    # Medicare Beneficiary Identifier is a fixed 11-character alphanumeric string.
    # A change here would silently break the MBI regex pattern.
    assert MBI_CHARACTER_COUNT == 11


def test_dea_number_digit_count_is_seven() -> None:
    # DEA number structure: 2-letter prefix + exactly 7 digits + checksum on last digit.
    assert DEA_NUMBER_DIGIT_COUNT == 7


def test_vin_character_count_is_seventeen() -> None:
    # VIN is a fixed-length 17-character identifier per ISO 3779.
    assert VIN_CHARACTER_COUNT == 17


def test_dbsnp_rs_id_min_digits_is_below_max_digits() -> None:
    # Sanity: the minimum digit count must be less than the maximum.
    assert DBSNP_RS_ID_MIN_DIGITS < DBSNP_RS_ID_MAX_DIGITS


def test_dbsnp_rs_id_digit_bounds_are_positive() -> None:
    assert DBSNP_RS_ID_MIN_DIGITS > 0
    assert DBSNP_RS_ID_MAX_DIGITS > 0


def test_ensembl_gene_id_digit_count_is_eleven() -> None:
    # Ensembl gene IDs use the pattern ENSG + 11 zero-padded digits.
    assert ENSEMBL_GENE_ID_DIGIT_COUNT == 11


def test_fictional_phone_subscriber_min_is_below_max() -> None:
    # The FCC fictional subscriber range must be a valid non-empty interval.
    assert FICTIONAL_PHONE_SUBSCRIBER_MIN < FICTIONAL_PHONE_SUBSCRIBER_MAX


def test_fictional_phone_subscriber_display_prefix_is_single_zero() -> None:
    # NANP subscribers in the 555-0100–0199 range require a leading zero to pad
    # to 4 digits. A change here silently breaks synthetic phone number format.
    assert FICTIONAL_PHONE_SUBSCRIBER_DISPLAY_PREFIX == "0"


def test_fictional_phone_exchange_is_555() -> None:
    # FCC reserves exchange 555 for fictional use; this value is load-bearing
    # in both the exclusion regex and the synthetic data generator.
    assert FICTIONAL_PHONE_EXCHANGE == 555


def test_zip_code_safe_harbor_population_min_is_positive() -> None:
    # A value of zero would make every 3-digit ZIP prefix "safe" — defeating
    # the purpose of the constant entirely.
    assert isinstance(ZIP_CODE_SAFE_HARBOR_POPULATION_MIN, int)
    assert ZIP_CODE_SAFE_HARBOR_POPULATION_MIN > 0


def test_mbi_allowed_letters_is_nonempty_string() -> None:
    # MBI_ALLOWED_LETTERS encodes the CMS-approved character set; an empty string
    # would produce a regex that matches nothing and silently disables MBI detection.
    assert isinstance(MBI_ALLOWED_LETTERS, str)
    assert len(MBI_ALLOWED_LETTERS) > 0


def test_mbi_allowed_letters_excludes_cms_banned_characters() -> None:
    # CMS explicitly bans S, L, O, I, B, Z to prevent visual ambiguity with digits.
    # This test pins the exclusion — a drift here would cause false negatives on real MBIs.
    for banned_char in ("S", "L", "O", "I", "B", "Z"):
        assert banned_char not in MBI_ALLOWED_LETTERS, (
            f"Banned character {banned_char!r} found in MBI_ALLOWED_LETTERS"
        )


def test_ssn_excluded_area_numbers_is_immutable() -> None:
    assert isinstance(SSN_EXCLUDED_AREA_NUMBERS, frozenset)


def test_ssn_excluded_area_numbers_contains_666() -> None:
    # SSA area number 666 is permanently reserved and never assigned (§205.20).
    assert 666 in SSN_EXCLUDED_AREA_NUMBERS


def test_ssn_excluded_area_numbers_contains_full_900_to_999_range() -> None:
    # SSA area numbers 900–999 are permanently reserved. Any gap would allow a reserved
    # area number through the exclusion filter and produce false positives.
    for area_number in range(900, 1000):
        assert area_number in SSN_EXCLUDED_AREA_NUMBERS, (
            f"Area number {area_number} missing from SSN_EXCLUDED_AREA_NUMBERS"
        )


def test_ssn_excluded_area_numbers_does_not_contain_valid_area_numbers() -> None:
    # Spot-check that common valid area numbers are not accidentally excluded.
    for valid_area in (100, 200, 500, 750, 899):
        assert valid_area not in SSN_EXCLUDED_AREA_NUMBERS, (
            f"Valid area number {valid_area} incorrectly excluded"
        )


def test_sud_field_name_patterns_is_immutable() -> None:
    assert isinstance(SUD_FIELD_NAME_PATTERNS, frozenset)


def test_sud_field_name_patterns_contains_core_42_cfr_part2_terms() -> None:
    # These terms are the minimum set required for 42 CFR Part 2 SUD record detection.
    # A regression that removes any of them would silently reduce compliance coverage.
    required_terms = {"methadone", "buprenorphine", "naloxone", "substance_use"}
    missing = required_terms - SUD_FIELD_NAME_PATTERNS
    assert missing == set(), f"Required SUD terms missing: {missing}"


def test_sud_field_name_patterns_are_lowercase() -> None:
    # Detection logic lowercases the target before matching — all patterns must be
    # lowercase to guarantee matches, since "Methadone" != "methadone" at comparison time.
    malformed = [term for term in SUD_FIELD_NAME_PATTERNS if term != term.lower()]
    assert malformed == [], f"Non-lowercase SUD patterns: {malformed}"
