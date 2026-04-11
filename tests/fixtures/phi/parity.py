# Synthetic PHI fixture: parity test content for sequential vs parallel scan.
# Loaded as raw file text by tests/test_scanner.py to avoid embedding a raw
# SSN literal inside a test source file. Covered by the tests/fixtures/ entry
# in .phi-scanignore so self-scans do not flag it.
#
# 123-45-6789 uses area number 123, which the SSA has never assigned — it is
# a well-known synthetic test value and is not a real individual's SSN.
# Expected findings: minimum 1 (SSN entity type).

patient_ssn = "123-45-6789"
