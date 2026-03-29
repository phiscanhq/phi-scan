# Synthetic PHI fixture: Social Security Numbers
# All values are fictional and for scanner testing only.
# SSA randomized assignment on 2011-06-25; all area numbers (first group) were
# valid before randomization but these specific area+group+serial combinations
# have no documented assignment. 987-65-4321 is the most widely documented
# fictional SSN (used by a 1938 wallet manufacturer and never reissued).
# None of these fall into the reserved non-assignable ranges in ssn_reserved.py.
# Expected findings: minimum 4 (SSN entity type)

patient_ssn = "321-54-9870"
legacy_format = "987-65-4321"
no_dashes = "123456789"

config = {
    "social_security_number": "456-78-9012",
    "backup_ssn": "555-43-2100",
}
