# Synthetic PHI fixture: Patient and Provider Names
# Uses well-known fictional name conventions.
# Expected findings: minimum 3 (NAME entity type — NLP layer, Phase 2B+)

patient_name = "John Doe"
provider = "Dr. Jane Smith, MD"
contact = "Robert Johnson"

record = {
    "patient_full_name": "Mary Elizabeth Williams",
    "attending_physician": "Dr. James Davis",
}
