# Synthetic PHI fixture: IP Addresses and URLs
# IP addresses and patient-context URLs are HIPAA identifiers.
# Expected findings: minimum 4 (IP_ADDRESS / URL entity types)

patient_portal_url = "http://patient.hospital-test.example.com/records/john-doe"
direct_link = "https://portal.example.org/patients/123456/summary"

server_ip = "198.51.100.42"
workstation_ip = "198.51.100.105"
internal_range = "198.51.100.0/24"

audit_log = {
    "accessed_from": "198.51.100.77",
    "resource": "http://ehr.example.com/patients/987654",
}
