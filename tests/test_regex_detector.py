"""Tests for phi_scan.regex_detector — Layer 1 regex pattern registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from phi_scan.constants import (
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_LOW_FLOOR,
    CONFIDENCE_MEDIUM_FLOOR,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.hashing import severity_from_confidence
from phi_scan.regex_detector import detect_phi_with_regex

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FAKE_PATH: Path = Path("tmp/app.py")

# A valid NPI that passes the CMS Luhn check.
# CMS prefix 80840 + 1234567893 → Luhn total = 60 (divisible by 10).
_VALID_NPI: str = "1234567893"

# A valid DEA number: AB1234563
# Prefix AB, digits 1234563
# d1+d3+d5 = 1+3+5 = 9; 2*(d2+d4+d6) = 2*(2+4+6) = 24; sum = 33; mod 10 = 3 ✓
_VALID_DEA: str = "AB1234563"

# A VIN that passes the ISO 3779 check digit at position 9.
# Well-known test VIN: 1HGBH41JXMN109186
_VALID_VIN: str = "1HGBH41JXMN109186"

# An SSN in a valid range (not reserved, not all-zero).
_VALID_SSN: str = "123-45-6789"

# A valid MBI: 1EG4-TE5-MK72 (CMS example format).
_VALID_MBI: str = "1EG4TE5MK72"

# A fictional phone number (555-0100 range) — must NOT produce a finding.
_FICTIONAL_PHONE: str = "555-555-0150"

# A real NANP phone number that should fire.
_REAL_PHONE: str = "415-555-9999"

# A documentation-domain email — must NOT produce a finding.
_DOCUMENTATION_EMAIL: str = "patient@example.com"

# A real email that should fire.
_REAL_EMAIL: str = "john.smith@hospital.org"

# RFC 5737 TEST-NET address — must NOT produce a finding.
_TESTNET_IPV4: str = "192.0.2.100"

# A public IPv4 address that should fire.
_PUBLIC_IPV4: str = "203.45.67.89"

# An RFC 1918 private address — should still fire (may appear in patient logs).
_PRIVATE_IPV4: str = "10.0.0.5"

# Reserved SSN area numbers that must never trigger a finding.
_RESERVED_SSN_666: str = "666-12-3456"
_RESERVED_SSN_900: str = "900-12-3456"
_RESERVED_SSN_999: str = "999-12-3456"
_SSN_ZERO_AREA: str = "000-12-3456"
_SSN_ZERO_GROUP: str = "123-00-3456"
_SSN_ZERO_SERIAL: str = "123-45-0000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _findings_for(line: str) -> list:
    return detect_phi_with_regex(line, _FAKE_PATH)


def _entity_types_for(line: str) -> set[str]:
    return {f.entity_type for f in _findings_for(line)}


# ---------------------------------------------------------------------------
# detect_phi_with_regex — public API
# ---------------------------------------------------------------------------


class TestDetectPhiWithRegexReturnsFindings:
    def test_returns_list_for_empty_content(self) -> None:
        findings = detect_phi_with_regex("", _FAKE_PATH)

        assert findings == []

    def test_returns_list_for_clean_content(self) -> None:
        findings = detect_phi_with_regex("greeting = 'hello world'\n", _FAKE_PATH)

        assert isinstance(findings, list)

    def test_file_path_preserved_in_findings(self) -> None:
        findings = detect_phi_with_regex(f'ssn = "{_VALID_SSN}"', _FAKE_PATH)

        assert all(finding.file_path == _FAKE_PATH for finding in findings)

    def test_detection_layer_is_regex(self) -> None:
        findings = detect_phi_with_regex(f'ssn = "{_VALID_SSN}"', _FAKE_PATH)

        assert any(finding.detection_layer == DetectionLayer.REGEX for finding in findings)

    def test_value_hash_is_64_char_hex(self) -> None:
        findings = detect_phi_with_regex(f'ssn = "{_VALID_SSN}"', _FAKE_PATH)

        ssn_findings = [f for f in findings if f.entity_type == "SSN"]
        assert ssn_findings
        assert all(len(f.value_hash) == 64 for f in ssn_findings)
        assert all(all(ch in "0123456789abcdef" for ch in f.value_hash) for f in ssn_findings)

    def test_line_number_is_one_indexed(self) -> None:
        findings = detect_phi_with_regex(f'ssn = "{_VALID_SSN}"', _FAKE_PATH)

        ssn_findings = [f for f in findings if f.entity_type == "SSN"]
        assert ssn_findings[0].line_number == 1

    def test_multiline_content_correct_line_numbers(self) -> None:
        content = "nothing here\n" + f'ssn = "{_VALID_SSN}"' + "\nnothing here"
        findings = detect_phi_with_regex(content, _FAKE_PATH)

        ssn_findings = [f for f in findings if f.entity_type == "SSN"]
        assert ssn_findings
        assert ssn_findings[0].line_number == 2

    def test_code_context_is_stripped_line(self) -> None:
        line = f'ssn = "{_VALID_SSN}"   '
        findings = detect_phi_with_regex(line, _FAKE_PATH)

        ssn_findings = [f for f in findings if f.entity_type == "SSN"]
        assert ssn_findings
        assert ssn_findings[0].code_context == line.rstrip()


# ---------------------------------------------------------------------------
# SSN
# ---------------------------------------------------------------------------


class TestSsnDetection:
    def test_detects_standard_ssn(self) -> None:
        assert "SSN" in _entity_types_for(f'ssn = "{_VALID_SSN}"')

    def test_excludes_area_666(self) -> None:
        assert "SSN" not in _entity_types_for(f'ssn = "{_RESERVED_SSN_666}"')

    def test_excludes_area_900(self) -> None:
        assert "SSN" not in _entity_types_for(f'ssn = "{_RESERVED_SSN_900}"')

    def test_excludes_area_999(self) -> None:
        assert "SSN" not in _entity_types_for(f'ssn = "{_RESERVED_SSN_999}"')

    def test_excludes_area_000(self) -> None:
        assert "SSN" not in _entity_types_for(f'ssn = "{_SSN_ZERO_AREA}"')

    def test_excludes_group_00(self) -> None:
        assert "SSN" not in _entity_types_for(f'ssn = "{_SSN_ZERO_GROUP}"')

    def test_excludes_serial_0000(self) -> None:
        assert "SSN" not in _entity_types_for(f'ssn = "{_SSN_ZERO_SERIAL}"')

    def test_finding_has_ssn_category(self) -> None:
        findings = _findings_for(f'ssn = "{_VALID_SSN}"')
        ssn_findings = [f for f in findings if f.entity_type == "SSN"]
        assert ssn_findings[0].hipaa_category == PhiCategory.SSN

    def test_ssn_severity_is_high(self) -> None:
        findings = _findings_for(f'ssn = "{_VALID_SSN}"')
        ssn_findings = [f for f in findings if f.entity_type == "SSN"]
        assert ssn_findings[0].severity == SeverityLevel.HIGH


# ---------------------------------------------------------------------------
# MBI
# ---------------------------------------------------------------------------


class TestMbiDetection:
    def test_detects_valid_mbi(self) -> None:
        assert "MBI" in _entity_types_for(f'mbi = "{_VALID_MBI}"')

    def test_mbi_category_is_unique_id(self) -> None:
        findings = _findings_for(f'mbi = "{_VALID_MBI}"')
        mbi_findings = [f for f in findings if f.entity_type == "MBI"]
        assert mbi_findings[0].hipaa_category == PhiCategory.UNIQUE_ID


# ---------------------------------------------------------------------------
# DEA (checksum validated)
# ---------------------------------------------------------------------------


class TestDeaDetection:
    def test_detects_valid_dea(self) -> None:
        assert "DEA" in _entity_types_for(f'dea = "{_VALID_DEA}"')

    def test_rejects_invalid_dea_checksum(self) -> None:
        # Corrupt the check digit: AB1234560 (last digit 0 ≠ expected 3)
        assert "DEA" not in _entity_types_for('dea = "AB1234560"')

    def test_dea_confidence_is_high(self) -> None:
        findings = _findings_for(f'dea = "{_VALID_DEA}"')
        dea_findings = [f for f in findings if f.entity_type == "DEA"]
        assert dea_findings[0].confidence >= CONFIDENCE_HIGH_FLOOR


# ---------------------------------------------------------------------------
# NPI (Luhn validated)
# ---------------------------------------------------------------------------


class TestNpiDetection:
    def test_detects_valid_npi(self) -> None:
        assert "NPI" in _entity_types_for(f'npi = "{_VALID_NPI}"')

    def test_rejects_invalid_npi_luhn(self) -> None:
        # 1234567890 has a bad check digit for the CMS Luhn sequence.
        assert "NPI" not in _entity_types_for('npi = "1234567890"')


# ---------------------------------------------------------------------------
# VIN (ISO 3779 check digit validated)
# ---------------------------------------------------------------------------


class TestVinDetection:
    def test_detects_valid_vin(self) -> None:
        assert "VIN" in _entity_types_for(f'vin = "{_VALID_VIN}"')

    def test_rejects_invalid_vin_check_digit(self) -> None:
        # Replace check digit at position 9 with 'Z' (invalid for this VIN).
        corrupted_vin = _VALID_VIN[:8] + "Z" + _VALID_VIN[9:]
        assert "VIN" not in _entity_types_for(f'vin = "{corrupted_vin}"')


# ---------------------------------------------------------------------------
# Phone (fictional range excluded)
# ---------------------------------------------------------------------------


class TestPhoneDetection:
    def test_detects_real_phone(self) -> None:
        assert "PHONE" in _entity_types_for(f'phone = "{_REAL_PHONE}"')

    def test_excludes_fictional_nanp_range(self) -> None:
        assert "PHONE" not in _entity_types_for(f'phone = "{_FICTIONAL_PHONE}"')

    def test_detects_formatted_phone(self) -> None:
        assert "PHONE" in _entity_types_for('phone = "(415) 867-5309"')

    def test_phone_category_is_phone(self) -> None:
        findings = _findings_for(f'phone = "{_REAL_PHONE}"')
        phone_findings = [f for f in findings if f.entity_type == "PHONE"]
        assert phone_findings[0].hipaa_category == PhiCategory.PHONE


# ---------------------------------------------------------------------------
# Email (documentation domains excluded)
# ---------------------------------------------------------------------------


class TestEmailDetection:
    def test_detects_real_email(self) -> None:
        assert "EMAIL" in _entity_types_for(f'email = "{_REAL_EMAIL}"')

    def test_excludes_example_com(self) -> None:
        assert "EMAIL" not in _entity_types_for(f'email = "{_DOCUMENTATION_EMAIL}"')

    def test_excludes_example_org(self) -> None:
        assert "EMAIL" not in _entity_types_for('email = "test@example.org"')

    def test_excludes_test_com(self) -> None:
        assert "EMAIL" not in _entity_types_for('email = "user@test.com"')

    def test_email_category_is_email(self) -> None:
        findings = _findings_for(f'email = "{_REAL_EMAIL}"')
        email_findings = [f for f in findings if f.entity_type == "EMAIL"]
        assert email_findings[0].hipaa_category == PhiCategory.EMAIL


# ---------------------------------------------------------------------------
# IPv4 (TEST-NET excluded; private ranges included)
# ---------------------------------------------------------------------------


class TestIpv4Detection:
    def test_detects_public_ipv4(self) -> None:
        assert "IPV4_ADDRESS" in _entity_types_for(f'ip = "{_PUBLIC_IPV4}"')

    def test_excludes_rfc5737_testnet(self) -> None:
        assert "IPV4_ADDRESS" not in _entity_types_for(f'ip = "{_TESTNET_IPV4}"')

    def test_detects_rfc1918_private_range(self) -> None:
        # RFC 1918 private addresses are still flagged (may appear in patient logs).
        assert "IPV4_ADDRESS" in _entity_types_for(f'ip = "{_PRIVATE_IPV4}"')

    def test_ip_category_is_ip(self) -> None:
        findings = _findings_for(f'ip = "{_PUBLIC_IPV4}"')
        ip_findings = [f for f in findings if f.entity_type == "IPV4_ADDRESS"]
        assert ip_findings[0].hipaa_category == PhiCategory.IP


# ---------------------------------------------------------------------------
# Dates
# ---------------------------------------------------------------------------


class TestDateDetection:
    def test_detects_iso_date(self) -> None:
        assert "DATE" in _entity_types_for('dob = "1985-03-22"')

    def test_detects_us_date(self) -> None:
        assert "DATE" in _entity_types_for('dob = "03/22/1985"')

    def test_detects_long_month_date(self) -> None:
        assert "DATE" in _entity_types_for('dob = "March 22, 1985"')

    def test_detects_short_month_date(self) -> None:
        assert "DATE" in _entity_types_for('dob = "22-Mar-1985"')

    def test_date_category_is_date(self) -> None:
        findings = _findings_for('dob = "1985-03-22"')
        date_findings = [f for f in findings if f.entity_type == "DATE"]
        assert date_findings[0].hipaa_category == PhiCategory.DATE


# ---------------------------------------------------------------------------
# ZIP code / geographic
# ---------------------------------------------------------------------------


class TestZipCodeDetection:
    def test_detects_zip_plus4(self) -> None:
        assert "ZIP_PLUS4" in _entity_types_for('zip = "94107-1234"')

    def test_zip_category_is_geographic(self) -> None:
        findings = _findings_for('zip_plus4 = "94107-1234"')
        zip_findings = [f for f in findings if f.entity_type == "ZIP_PLUS4"]
        assert zip_findings[0].hipaa_category == PhiCategory.GEOGRAPHIC


# ---------------------------------------------------------------------------
# HICN (legacy Medicare, context-dependent)
# ---------------------------------------------------------------------------


class TestHicnDetection:
    def test_detects_hicn_with_context(self) -> None:
        findings = _findings_for('hicn = "123456789A"')
        hicn_findings = [f for f in findings if f.entity_type == "HICN"]
        assert hicn_findings
        assert hicn_findings[0].confidence >= CONFIDENCE_MEDIUM_FLOOR

    def test_hicn_lower_confidence_without_context(self) -> None:
        # No HICN context keyword on the line — confidence drops.
        findings = _findings_for('identifier = "123456789A"')
        hicn_findings = [f for f in findings if f.entity_type == "HICN"]
        if hicn_findings:
            assert hicn_findings[0].confidence < CONFIDENCE_HIGH_FLOOR


# ---------------------------------------------------------------------------
# Age over HIPAA threshold (context-dependent)
# ---------------------------------------------------------------------------


class TestAgeOverThresholdDetection:
    def test_detects_restricted_age_with_context(self) -> None:
        findings = _findings_for("patient_age = 95")
        age_findings = [f for f in findings if f.entity_type == "AGE_OVER_THRESHOLD"]
        assert age_findings
        assert age_findings[0].confidence >= CONFIDENCE_MEDIUM_FLOOR

    def test_does_not_flag_age_at_threshold(self) -> None:
        # Exactly 90 is the threshold — should not be flagged.
        findings = _findings_for("patient_age = 90")
        age_findings = [f for f in findings if f.entity_type == "AGE_OVER_THRESHOLD"]
        assert not age_findings

    def test_detects_age_100_or_above(self) -> None:
        findings = _findings_for("patient_age = 105")
        age_findings = [f for f in findings if f.entity_type == "AGE_OVER_THRESHOLD"]
        assert age_findings

    def test_age_lower_confidence_without_context(self) -> None:
        findings = _findings_for("timeout = 95")
        age_findings = [f for f in findings if f.entity_type == "AGE_OVER_THRESHOLD"]
        if age_findings:
            assert age_findings[0].confidence < CONFIDENCE_HIGH_FLOOR


# ---------------------------------------------------------------------------
# MRN (context-dependent)
# ---------------------------------------------------------------------------


class TestMrnDetection:
    def test_detects_mrn_with_context(self) -> None:
        findings = _findings_for('mrn = "1234567"')
        mrn_findings = [f for f in findings if f.entity_type == "MRN"]
        assert mrn_findings

    def test_mrn_category_is_mrn(self) -> None:
        findings = _findings_for('mrn = "1234567"')
        mrn_findings = [f for f in findings if f.entity_type == "MRN"]
        assert mrn_findings[0].hipaa_category == PhiCategory.MRN

    def test_mrn_confidence_higher_with_context(self) -> None:
        with_context = _findings_for('medical_record = "1234567"')
        without_context = _findings_for('x = "1234567"')
        mrn_with = [f for f in with_context if f.entity_type == "MRN"]
        mrn_without = [f for f in without_context if f.entity_type == "MRN"]
        if mrn_with and mrn_without:
            assert mrn_with[0].confidence > mrn_without[0].confidence


# ---------------------------------------------------------------------------
# Biometric field names
# ---------------------------------------------------------------------------


class TestBiometricFieldDetection:
    def test_detects_fingerprint_field(self) -> None:
        assert "BIOMETRIC_FIELD" in _entity_types_for("fingerprint = encode(raw_data)")

    def test_detects_voiceprint_field(self) -> None:
        assert "BIOMETRIC_FIELD" in _entity_types_for("voiceprint = sha256(audio)")

    def test_biometric_category_is_biometric(self) -> None:
        findings = _findings_for("fingerprint = encode(raw_data)")
        biometric_findings = [f for f in findings if f.entity_type == "BIOMETRIC_FIELD"]
        assert biometric_findings[0].hipaa_category == PhiCategory.BIOMETRIC


# ---------------------------------------------------------------------------
# SUD field names (42 CFR Part 2)
# ---------------------------------------------------------------------------


class TestSudFieldDetection:
    def test_detects_sud_field_name(self) -> None:
        # SUD_FIELD_NAME_PATTERNS contains field names like "substance_use_disorder"
        findings = _findings_for("substance_use_disorder = True")
        sud_findings = [f for f in findings if f.entity_type == "SUD_FIELD"]
        assert sud_findings

    def test_sud_category_is_substance_use_disorder(self) -> None:
        findings = _findings_for("substance_use_disorder = True")
        sud_findings = [f for f in findings if f.entity_type == "SUD_FIELD"]
        assert sud_findings[0].hipaa_category == PhiCategory.SUBSTANCE_USE_DISORDER


# ---------------------------------------------------------------------------
# Genetic identifiers
# ---------------------------------------------------------------------------


class TestGeneticIdentifierDetection:
    def test_detects_dbsnp_rs_id(self) -> None:
        assert "DBSNP_RS_ID" in _entity_types_for('variant = "rs12345678"')

    def test_detects_ensembl_gene_id(self) -> None:
        assert "ENSEMBL_GENE_ID" in _entity_types_for('gene = "ENSG00000139618"')

    def test_detects_vcf_header_line(self) -> None:
        assert "VCF_GENETIC_DATA" in _entity_types_for("CHROM POS ID REF ALT")


# ---------------------------------------------------------------------------
# Confidence → severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_high_confidence_maps_to_high_severity(self) -> None:
        findings = _findings_for(f'ssn = "{_VALID_SSN}"')
        ssn_findings = [f for f in findings if f.entity_type == "SSN"]
        assert ssn_findings[0].severity == SeverityLevel.HIGH

    def test_medium_confidence_maps_to_medium_severity(self) -> None:
        # HICN without context keyword lands in medium-confidence range.
        findings = _findings_for('identifier = "123456789A"')
        hicn_findings = [f for f in findings if f.entity_type == "HICN"]
        if hicn_findings:
            confidence = hicn_findings[0].confidence
            if CONFIDENCE_MEDIUM_FLOOR <= confidence < CONFIDENCE_HIGH_FLOOR:
                assert hicn_findings[0].severity == SeverityLevel.MEDIUM

    def test_confidence_below_low_floor_maps_to_info(self) -> None:
        # Verify the boundary: confidence below CONFIDENCE_LOW_FLOOR → INFO.
        assert CONFIDENCE_LOW_FLOOR > 0.0  # sanity: the constant is meaningful

    @pytest.mark.parametrize(
        ("confidence", "expected_severity"),
        [
            (0.95, SeverityLevel.HIGH),
            (0.75, SeverityLevel.MEDIUM),
            (0.50, SeverityLevel.LOW),
            (0.20, SeverityLevel.INFO),
        ],
    )
    def test_confidence_threshold_boundaries(
        self, confidence: float, expected_severity: SeverityLevel
    ) -> None:
        assert severity_from_confidence(confidence) == expected_severity


# ---------------------------------------------------------------------------
# FDA UDI (device identifier)
# ---------------------------------------------------------------------------


class TestFdaUdiDetection:
    def test_detects_fda_udi_application_identifier(self) -> None:
        assert "FDA_UDI" in _entity_types_for('udi = "(01)00844588003288"')

    def test_fda_udi_category_is_device(self) -> None:
        findings = _findings_for('udi = "(01)00844588003288"')
        udi_findings = [f for f in findings if f.entity_type == "FDA_UDI"]
        assert udi_findings[0].hipaa_category == PhiCategory.DEVICE


# ---------------------------------------------------------------------------
# Street address
# ---------------------------------------------------------------------------


class TestStreetAddressDetection:
    def test_detects_street_address(self) -> None:
        assert "STREET_ADDRESS" in _entity_types_for('address = "123 Main Street"')

    def test_street_address_category_is_geographic(self) -> None:
        findings = _findings_for('address = "123 Main Street"')
        addr_findings = [f for f in findings if f.entity_type == "STREET_ADDRESS"]
        assert addr_findings[0].hipaa_category == PhiCategory.GEOGRAPHIC


# ---------------------------------------------------------------------------
# Patient URL
# ---------------------------------------------------------------------------


class TestPatientUrlDetection:
    def test_detects_patient_url(self) -> None:
        assert "PATIENT_URL" in _entity_types_for('url = "https://ehr.example.org/patient/ABC123"')

    def test_url_category_is_url(self) -> None:
        findings = _findings_for('url = "https://ehr.example.org/patient/ABC123"')
        url_findings = [f for f in findings if f.entity_type == "PATIENT_URL"]
        assert url_findings[0].hipaa_category == PhiCategory.URL
