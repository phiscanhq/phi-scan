# Synthetic PHI fixture: Medicare Identifiers — MBI, HICN, DEA Number
# MBI (Medicare Beneficiary Identifier): 11-character alphanumeric post-2019.
# HICN (Health Insurance Claim Number): legacy SSN-based format, lower confidence.
# DEA: 2-letter prefix + 7 digits with checksum validation.
# Expected findings: minimum 3 (MBI / HICN / DEA entity types)

# Medicare Beneficiary Identifier (fictional — CMS example format)
mbi = "1EG4-TE5-MK72"
mbi_nodash = "1EG4TE5MK72"

# Legacy HICN (SSN-based — lower confidence, may conflict with SSN detector)
hicn = "987-65-4321A"

# DEA Number: 2-letter prefix + 6-digit sequence + 1 check digit
dea_number = "AB1234563"
provider_dea = "BJ9876540"
