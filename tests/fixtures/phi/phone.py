# Synthetic PHI fixture: Phone and Fax Numbers
# NANP reserves the 555-0100 through 555-0199 subscriber block for fictional use.
# Correct format: (NXX) 555-01XX — area code is any valid NXX, exchange is 555,
# subscriber is 0100–0199. Exchange digits cannot start with 0 or 1 per NANP,
# so 555 (starting with 5) is a valid exchange; area codes below are documentary.
# Expected findings: minimum 4 (PHONE entity type)

patient_phone = "(212) 555-0150"
fax_number = "312-555-0175"
international = "+1-415-555-0101"

contact_info = {
    "mobile": "617.555.0123",
    "work_fax": "(213) 555-0199",
}
