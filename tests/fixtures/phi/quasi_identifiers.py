# Synthetic PHI fixture: Quasi-Identifier Combinations
# A ZIP code + date of birth + biological sex combination achieves near-unique
# identification of individuals (Sweeney 2000 — 87% of US population uniquely
# identified by ZIP+DOB+sex). HIPAA requires treating these combinations as HIGH
# risk regardless of individual confidence scores.
# Expected findings: minimum 1 (QUASI_IDENTIFIER_COMBINATION entity type, HIGH severity)

patient_record = {
    "zip_code": "02139",
    "date_of_birth": "1978-11-23",
    "biological_sex": "female",
}

query = "SELECT * FROM patients WHERE zip = '02139' AND dob = '1978-11-23' AND sex = 'F'"
