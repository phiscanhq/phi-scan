# Synthetic PHI fixture: Email Addresses
# All values use reserved/fictional domains (example.com, example.org per RFC 2606).
# Expected findings: minimum 3 (EMAIL entity type)

patient_email = "john.doe@example.com"
contact_address = "jane.smith@hospital-test.org"
notification_target = "patient.records@clinic.example"


def send_discharge_summary(recipient="patient.jones@example.net"): ...
