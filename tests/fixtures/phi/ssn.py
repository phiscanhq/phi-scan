# Synthetic PHI fixture: Social Security Numbers
# All values are fictional and for scanner testing only.
# Expected findings: minimum 4 (SSN entity type)

patient_ssn = "321-54-9870"
legacy_format = "987-65-4321"
no_dashes = "123456789"

config = {
    "social_security_number": "456-78-9012",
    "backup_ssn": "555-43-2100",
}
