# Synthetic PHI fixture: Certificate and License Numbers, NPI
# Certificate, license, and NPI numbers are HIPAA identifiers.
# Expected findings: minimum 3 (LICENSE_NUMBER / NPI entity types)

# National Provider Identifier (10-digit — fictional, fails Luhn check)
provider_npi = "NPI-1234567890"
npi_raw = "1234567890"

# State medical license (fictional)
medical_license = "MD-IL-A12345"
nursing_license = "RN-CA-987654"

credentials = {
    "dea_registration": "AB1234563",
    "state_license": "MD-NY-B98765",
}
