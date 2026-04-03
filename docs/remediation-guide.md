# Remediation Guide

This guide explains how to remove PHI from your codebase after a PhiScan
finding, what to replace it with, and how to use PhiScan's tooling to
automate and verify remediation.

Use `phi-scan explain remediation` for a quick in-terminal reference.

---

## Recommended Workflow

```
1. phi-scan scan .                   Identify all PHI
2. phi-scan fix --dry-run            Preview synthetic replacements
3. phi-scan fix --apply              Apply replacements
4. phi-scan scan .                   Verify clean
5. phi-scan baseline create          Accept any acknowledged false positives
6. git commit                        Commit clean or baselined state
7. phi-scan scan . --baseline        CI only flags new findings going forward
```

---

## Automated Fix — `phi-scan fix`

PhiScan includes an auto-fix engine that replaces detected PHI with
**deterministic synthetic values**. Synthetic values are safe for tests,
realistic enough to validate formatting, and derived reproducibly from the
original value's hash.

```bash
# Preview what would change (no files modified)
phi-scan fix --dry-run

# Apply in place (overwrites files after confirmation prompt)
phi-scan fix --apply

# Write a git-compatible patch file
phi-scan fix --patch --report-path phi-scan-fix.patch
git apply phi-scan-fix.patch
```

### Synthetic Value Examples

| Entity Type | Original | Synthetic Replacement |
|---|---|---|
| SSN | `123-45-6789` | `000-00-4821` |
| MRN | `MRN-004821` | `MRN-000482` |
| Email | `jane.doe@hospital.org` | `user04821@example.com` |
| Phone | `555-867-5309` | `(555) 000-0482` |
| IP address | `192.168.1.100` | `192.0.2.100` |
| URL | `https://portal.hospital.org/patient/1234` | `https://example.com/resource/04821` |

Synthetic values use the first 8 hex characters of `SHA-256(original)` as a
seed, ensuring **referential integrity** — the same PHI value always produces
the same synthetic replacement throughout the codebase.

### Baseline + Fix Interaction

Lines with `# phi-scan:ignore` are never modified by `phi-scan fix`.

---

## Per-Category Remediation Playbook

### Names (Category: `name`)

Use fictional names or role-based placeholders.

```python
# Before
patient_name = "Jane Doe"
provider = "Dr. Alice Smith"

# After — fictional names safe for tests
patient_name = "Jane TestPatient"
provider = "Dr. Test Provider"

# After — role-based (preferred for fixture data)
patient_name = "TEST_PATIENT_NAME"
provider = "TEST_PROVIDER_NAME"
```

**In test fixtures**, use a shared constants module:
```python
# tests/conftest.py
TEST_PATIENT_NAME = "Jane TestPatient"
TEST_PROVIDER_NAME = "Dr. Test Provider"
```

---

### Geographic Data (Category: `geographic`)

Replace with clearly fictional or documentation-standard addresses.

```python
# Before
address = "123 Main Street, Springfield, IL 62701"
zip_code = "60601"

# After
address = "456 Test Avenue, Testville, IL 00000"
zip_code = "00000"   # ZIP 00000 is unassigned
```

For ZIP codes, use:
- `00000` — unassigned
- `99999` — unassigned
- Three-digit prefix only when the full ZIP is not needed

---

### Dates (Category: `date`)

Dates more specific than year are PHI. Replace with:
- A clearly fictional year-only date
- A static test date documented in your fixture README

```python
# Before
dob = "1985-03-15"
admission_date = "2024-03-15"

# After
dob = "1900-01-01"           # clearly fictional
admission_date = "2000-01-01"  # static test date

# Or use constants
from tests.constants import TEST_DOB, TEST_ADMISSION_DATE
```

---

### Phone and Fax Numbers (Category: `phone`, `fax`)

The FCC reserves 555-0100 through 555-0199 for fictional use.

```python
# Before
phone = "555-867-5309"
contact = "+1-312-555-9876"

# After — FCC fictional range
phone = "555-0100"
fax = "(555) 555-0199"
```

The regex engine excludes `555-01xx` from detection, so these values will
not be flagged.

---

### Email Addresses (Category: `email`)

RFC 2606 reserves `example.com`, `example.org`, and `example.net` for
documentation and testing.

```python
# Before
email = "jane.doe@hospital.org"
contact = "patient.smith@gmail.com"

# After — RFC 2606 safe domains (excluded from detection)
email = "testpatient@example.com"
contact = "test.user@example.org"
```

---

### Social Security Numbers (Category: `ssn`)

The SSA reserves area `000` for all-zero SSNs. The regex engine excludes
area `000` from detection.

```python
# Before
ssn = "123-45-6789"
social_security = "987654321"

# After — SSA-reserved, never issued
ssn = "000-00-0000"
```

---

### Medical Record Numbers (Category: `mrn`)

Replace with an MRN-format value using clearly test-only prefix.

```python
# Before
mrn = "MRN-004821"
patient_id = "1047832"

# After
mrn = "MRN-000000"
patient_id = "TEST-MRN-001"
```

---

### Health Plan Beneficiary Numbers (Category: `health_plan`)

Use test-format identifiers that do not match real patterns.

```python
# Before
member_id = "1EG4-TE5-MK72"   # real MBI format
beneficiary = "HMO-20481039"

# After
member_id = "TEST-MBI-0000"
beneficiary = "TEST-PLAN-0000"
```

---

### Account Numbers (Category: `account`)

```python
# Before
account_number = "4782039182"

# After
account_number = "0000000000"   # all-zero account
account_number = "TEST-ACCT-001"
```

---

### Certificate and License Numbers (Category: `certificate`)

```python
# Before
medical_license = "MD-123456"
dea_number = "AB1234563"

# After
medical_license = "MD-000000"
dea_number = "TEST-DEA-000"   # not a valid DEA format — won't be flagged
```

---

### Vehicle Identifiers (Category: `vehicle`)

VINs have a check-digit at position 9. Use a VIN with position 9 = `0`
and all other positions matching a non-real pattern.

```python
# Before
vin = "1HGBH41JXMN109186"

# After — clearly fictional, won't pass VIN validation
vin = "TESTVIN000TEST001"
```

---

### IP Addresses (Category: `ip`)

RFC 5737 reserves three TEST-NET ranges that are excluded from detection.

```python
# Before
patient_ip = "192.168.1.100"
log_entry = "10.0.0.45"

# After — RFC 5737 TEST-NET (excluded from detection)
test_ip = "192.0.2.1"
log_entry = "198.51.100.5"
```

---

### URLs (Category: `url`)

Replace patient-specific URL path segments with non-identifying paths.

```python
# Before
endpoint = "/api/patient/MRN-004821/records"
link = "https://portal.hospital.org/member/12345/summary"

# After
endpoint = "/api/patient/TEST-ID/records"
link = "https://example.com/member/0/summary"
```

---

### Biometric Identifiers (Category: `biometric`)

Biometric data is detected by field name. Rename fields in test fixtures
to non-PHI names, or remove the field entirely.

```python
# Before
fingerprint = "d41d8cd98f00b204e9800998ecf8427e"

# After — rename the field so it's not detected as biometric
mock_template_hash = "d41d8cd98f00b204e9800998ecf8427e"

# Or suppress if this is an acknowledged test fixture
fingerprint = "d41d8..."  # phi-scan:ignore[BIOMETRIC_FIELD]
```

---

### Substance Use Disorder Fields (Category: `substance_use_disorder`)

SUD field names are detected regardless of value. Remove SUD field names
from test fixtures or use clearly non-clinical naming.

```python
# Before
methadone = "20mg daily"
opioid_treatment = True

# After — rename to non-SUD terminology in test fixtures
mock_medication_dose = "20mg daily"
mock_treatment_active = True
```

---

### Genetic Identifiers (Category: `unique_id` with GINA controls)

```python
# Before
rs_id = "rs1234567"
vcf_variant = "CHROM\tPOS\tID\tREF\tALT"

# After
mock_variant_id = "rs-TESTONLY"
mock_vcf_header = "MOCK_CHROM\tMOCK_POS"
```

---

### Quasi-Identifier Combinations (Category: `quasi_identifier_combination`)

Quasi-identifier combinations are flagged when ≥ 2 PHI categories appear
within 50 lines of each other. Resolve by:

1. Separating the individual identifiers into separate fixtures
2. Using clearly fictional values for each
3. Using `phi-scan baseline create` if the combination is acknowledged and
   intentional (e.g., a well-documented test dataset)

```python
# Before — zip + dob combination within 50 lines
zip_code = "60601"           # line 10
dob = "1985-03-15"          # line 12  → QUASI_IDENTIFIER_COMBINATION flagged

# After — both replaced with fictional values
zip_code = "00000"           # unassigned ZIP
dob = "1900-01-01"          # clearly fictional DOB
```

---

## Suppression for Acknowledged False Positives

When a finding is a deliberate false positive (e.g., a documentation example,
a well-known test value, or a pattern-matched constant that contains no real
PHI), use inline suppression rather than removal.

```python
# Suppress a specific finding type on this line
TEST_SSN_FORMAT = "XXX-XX-XXXX"  # phi-scan:ignore[SSN]

# Suppress all findings on the next line
# phi-scan:ignore-next-line
EXAMPLE_PHONE = "555-867-5309"

# Suppress the entire file (must appear in first 5 lines)
# phi-scan:ignore-file
```

See `docs/ignore-patterns.md` for language-specific suppression syntax.

---

## Baseline Mode for Incremental Adoption

If you are adopting PhiScan in an existing codebase with known legacy
findings that cannot all be fixed immediately, use baseline mode:

```bash
# Step 1: Scan the current state
phi-scan scan .

# Step 2: Create a baseline accepting all current findings
phi-scan baseline create

# Step 3: From this point on, CI only fails on NEW findings
phi-scan scan . --baseline
```

Baseline entries expire after **90 days** — each quarter, the team must
review and either fix or re-acknowledge the remaining findings.

See the main README and `phi-scan baseline --help` for full baseline workflow.

---

## Verifying Remediation

After applying fixes:

```bash
# Full scan — should show clean
phi-scan scan .

# If using baseline mode — verify no new findings
phi-scan scan . --baseline

# Check baseline drift warning (> 20% new findings above baseline)
phi-scan baseline diff
```

A clean scan exits with code `0`. Any finding exits with code `1`.
