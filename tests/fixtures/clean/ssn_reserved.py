# Synthetic clean fixture: SSN Reserved Ranges — must NOT produce findings
# HIPAA Safe Harbor requires SSNs to be flagged, but the following ranges are
# reserved by the SSA and never issued to real individuals. Flagging them causes
# false positives on synthetic/test data (Sweeney 2000, SSA publication 05-10120).
#
# Reserved ranges (per CLAUDE.md):
#   000-xx-xxxx  — group 000 never assigned
#   xxx-00-xxxx  — group number 00 never assigned
#   xxx-xx-0000  — serial 0000 never assigned
#   666-xx-xxxx  — group 666 explicitly reserved by SSA
#   900-999-xx-xxxx — ITIN range, not SSNs
#
# Expected findings: 0

# Group 000 — never issued
ssn_group_zero = "000-12-3456"
ssn_group_zero_compact = "000123456"

# Middle group 00 — never issued
ssn_mid_zero = "123-00-4567"
ssn_mid_zero_compact = "123004567"

# Serial 0000 — never issued
ssn_serial_zero = "123-45-0000"
ssn_serial_zero_compact = "123450000"

# Group 666 — explicitly reserved
ssn_group_666 = "666-12-3456"
ssn_group_666_compact = "666123456"

# ITIN range 900–999 — Individual Taxpayer Identification Numbers, not SSNs
itin_number = "912-34-5678"
itin_high = "999-88-7654"

RESERVED_SSN_EXAMPLES = [
    "000-12-3456",
    "123-00-4567",
    "123-45-0000",
    "666-12-3456",
    "912-34-5678",
]
