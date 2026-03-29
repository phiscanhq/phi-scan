# Synthetic PHI fixture: Dates (non-year — HIPAA Safe Harbor requires removing
# all dates more specific than year for patients 90 years or younger).
# Expected findings: minimum 4 (DATE entity type)

date_of_birth = "1945-03-15"
admission_date = "03/15/2024"
discharge = "March 15, 2024"
last_visit = "15-Mar-2024"

patient_record = {
    "dob": "1972-07-04",
    "next_appointment": "2024-09-01",
}
