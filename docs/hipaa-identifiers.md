# HIPAA PHI Identifiers

HIPAA Safe Harbor de-identification (45 CFR §164.514(b)(2)) requires the
removal of 18 specific identifier categories before health information is
considered de-identified. PhiScan detects all 18 categories across its
detection layers, plus additional extended categories for expanded regulatory
coverage.

Use `phi-scan explain hipaa` for a quick in-terminal reference.

---

## The 18 Safe Harbor Categories

### A — Names

Any name related to an individual, their relatives, employers, or household
members. Includes patient names, provider names, and family member names.

**What PhiScan detects:**
- NLP layer: `PERSON` entity type via Presidio + spaCy
- FHIR layer: `Patient.name.family`, `Patient.name.given` fields

**Code examples that would be flagged:**
```python
patient_name = "Jane Doe"
family = "Smith"
```

---

### B — Geographic Subdivisions Smaller than State

Addresses, ZIP codes, and any geographic division smaller than a state.
The first three digits of ZIP codes are permitted except for those with
populations ≤ 20,000.

**What PhiScan detects:**
- `ZIP_CODE` (5-digit): entity type `ZIP_CODE`, confidence 0.88
- `ZIP_PLUS4` (ZIP+4 format): entity type `ZIP_PLUS4`, confidence 0.88
- `STREET_ADDRESS`: entity type `STREET_ADDRESS`, confidence 0.85
- NLP layer: `LOCATION`, `GPE` entity types
- FHIR layer: `Patient.address` fields

**Code examples:**
```python
zip_code = "90210"
address = "123 Main Street, Springfield, IL 62701"
```

---

### C — Dates (Except Year)

Dates more specific than the year for individuals older than 89. Includes
dates of birth, admission, discharge, and death.

**What PhiScan detects:**
- `DATE`: entity type, confidence 0.88
- FHIR layer: `Patient.birthDate` field
- NLP layer: `DATE_TIME` entity type

**Code examples:**
```python
dob = "1985-03-15"
admission_date = "03/15/2024"
```

---

### D — Telephone Numbers

All phone numbers including area code, country code, and extension.

**What PhiScan detects:**
- `PHONE`: entity type, confidence 0.88
- NANP format (10-digit), E.164 format (+1XXXXXXXXXX)
- 555-01xx fictional range is excluded from flagging (FCC-reserved)

**Code examples:**
```python
phone = "555-867-5309"
contact = "+1-312-555-0100"
```

---

### E — Fax Numbers

Fax numbers are treated identically to telephone numbers.

**What PhiScan detects:**
- `FAX`: entity type, confidence 0.88, same patterns as `PHONE`

**Code examples:**
```python
fax_number = "(312) 555-4321"
```

---

### F — Email Addresses

All email addresses. Documentation domains are excluded (example.com,
example.org, example.net, test.com).

**What PhiScan detects:**
- `EMAIL`: entity type, confidence 0.88
- NLP layer: Presidio `EMAIL_ADDRESS` entity

**Code examples:**
```python
email = "jane.doe@hospital.org"
contact_email = "patient.smith@gmail.com"
```

**Not flagged** (safe for test fixtures):
```python
test_email = "user@example.com"   # RFC 2606 example domain — excluded
```

---

### G — Social Security Numbers

Full 9-digit SSNs and partial SSNs when the pattern suggests the full
number is nearby.

**What PhiScan detects:**
- `SSN`: entity type, confidence 0.97
- Validates reserved ranges:
  - Area 000, 666, and 900–999 → excluded
  - Group 00 → excluded
  - Serial 0000 → excluded

**Code examples:**
```python
ssn = "123-45-6789"
social_security = "987654321"    # no dashes
```

**Not flagged:**
```python
test_ssn = "000-00-0000"   # Invalid SSA area — excluded
fake_ssn = "999-99-9999"   # Excluded range
```

---

### H — Medical Record Numbers

Medical Record Numbers and patient chart identifiers.

**What PhiScan detects:**
- `MRN`: entity type, confidence 0.88 with context, 0.65 without
- 6–10 digit numeric patterns confirmed by context keywords:
  `mrn`, `medical_record`, `patient_id`, `chart_number`, `chart_id`
- FHIR layer: `Patient.identifier` fields

**Code examples:**
```python
mrn = "MRN-004821"           # with context keyword in variable name
patient_id = "1047832"       # context in variable name
record = "4738291"           # no context → low confidence (0.65)
```

---

### I — Health Plan Beneficiary Numbers

Health insurance beneficiary IDs, member IDs, and policy numbers.

**What PhiScan detects:**
- `HEALTH_PLAN_NUMBER`: entity type, confidence 0.88
- `MBI` (Modern Medicare Beneficiary Identifier): 11-character pattern
  using letters C–Y (excluding S, L, O, I, B, Z), confidence 0.92
- `HICN` (legacy Medicare Health Insurance Claim Number): 9-digit base
  with 1–2 character suffix, confidence 0.88

**Code examples:**
```python
member_id = "1EG4-TE5-MK72"     # MBI format
hicn = "123456789A"              # HICN format
beneficiary = "HMO-20481039"     # generic health plan number
```

---

### J — Account Numbers

Financial account numbers linked to an individual.

**What PhiScan detects:**
- `ACCOUNT_NUMBER`: entity type, confidence 0.88 with context, 0.65 without
- 6–20 digit sequences confirmed by context keywords:
  `account`, `acct`, `account_number`, `account_id`, `account_no`, `bank_account`

**Code examples:**
```python
account_number = "4782039182"
acct = "987654321098"
```

---

### K — Certificate and License Numbers

Professional license, DEA registration, NPI, and other certificate numbers.

**What PhiScan detects:**
- `CERTIFICATE_NUMBER`: medical and professional license patterns, confidence 0.85
- `DEA`: DEA registration (2 letters + 7 digits with Luhn checksum), confidence 0.97
- `NPI`: National Provider Identifier (10 digits with Luhn, CMS prefix 80840), confidence 0.88

**Code examples:**
```python
dea_number = "AB1234563"        # DEA registration
medical_license = "MD-123456"
npi = "1234567893"              # NPI with valid Luhn check
```

---

### L — Vehicle Identifiers and Serial Numbers

Vehicle Identification Numbers (VINs) and vehicle-related serial numbers.

**What PhiScan detects:**
- `VIN`: 17-character VINs with position-9 check digit validation, confidence 0.97

**Code examples:**
```python
vin = "1HGBH41JXMN109186"
vehicle_id = "2T1BURHE0JC027392"
```

---

### M — Device Identifiers and Serial Numbers

Unique device identifiers (UDI) and equipment serial numbers.

**What PhiScan detects:**
- `FDA_UDI`: GS1 GTIN-14 format with optional lot/date extensions, confidence 0.88
- Field-name detection for device serial number patterns

**Code examples:**
```python
udi = "(01)00844588003288"       # UDI primary DI
device_serial = "SN-20481939"
```

---

### N — Web Universal Resource Locators (URLs)

Patient-specific URL paths that uniquely identify individuals in web applications.

**What PhiScan detects:**
- `PATIENT_URL`: entity type, confidence 0.88
- Path segments matching: `/patient/`, `/record/`, `/member/`, `/mrn/`

**Code examples:**
```python
endpoint = "/api/patient/MRN-004821/records"
link = "https://portal.hospital.org/member/12345/summary"
```

---

### O — Internet Protocol (IP) Address Numbers

IPv4 and IPv6 addresses that could identify a patient's device or location.

**What PhiScan detects:**
- `IPV4_ADDRESS`: entity type, confidence 0.88
- `IPV6_ADDRESS`: entity type, confidence 0.88
- RFC 5737 TEST-NET ranges excluded: 192.0.2.x, 198.51.100.x, 203.0.113.x

**Code examples:**
```python
patient_ip = "192.168.1.100"
server_log = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
```

**Not flagged:**
```python
test_ip = "192.0.2.1"        # RFC 5737 TEST-NET-1 — excluded
doc_ip = "203.0.113.10"      # RFC 5737 TEST-NET-3 — excluded
```

---

### P — Biometric Identifiers Including Finger and Voice Prints

Biometric data that uniquely identifies an individual.

**What PhiScan detects:**
- `BIOMETRIC_FIELD`: field-name pattern detection, confidence 0.88
- Detected field names: `fingerprint`, `iris_scan`, `retinal_scan`,
  `face_template`, `voiceprint`, `palm_print`, `gait_signature`,
  `dna_sequence`, `biometric_hash`

**Code examples:**
```python
fingerprint = "d41d8cd98f00b204e9800998ecf8427e"
biometric_hash = "a3f5c2..."
iris_scan = encode_biometric(scan_data)
```

---

### Q — Full-Face Photographs and Comparable Images

Photographic images that can identify an individual.

**What PhiScan detects:**
- Field-name and path-name pattern detection
- File paths or variable names containing: `photo`, `photograph`, `face_image`,
  `patient_photo`, `headshot`, `portrait`

**Code examples:**
```python
patient_photo = "photos/patient_001_face.jpg"
face_image_path = "/images/john_doe_headshot.png"
```

---

### R — Any Other Unique Identifying Number, Characteristic, or Code

Any other identifier not listed above that could uniquely identify an individual.

**What PhiScan detects:**
- `UNIQUE_ID`: entity type (catch-all for identifiers matching other patterns
  that don't fit a specific category)
- Includes Ensembl gene IDs, dbSNP rs-IDs (when not mapping to GINA category)

---

## Extended Categories

PhiScan detects categories beyond the 18 Safe Harbor identifiers for
comprehensive compliance coverage.

### Modern Medicare Beneficiary Identifier (MBI)

Post-2019 Medicare IDs replacing HICN. 11-character alphanumeric format
using only letters C–Y (with exclusions).

**Entity type:** `MBI` | **Category:** `health_plan` | **Confidence:** 0.92

### Legacy Medicare (HICN)

Pre-2019 Medicare Health Insurance Claim Numbers. 9-digit base + 1–2 suffix.

**Entity type:** `HICN` | **Category:** `health_plan` | **Confidence:** 0.88

### DEA Registration Numbers

Controlled substance prescriber registrations. 2 letters + 7 digits with
Luhn checksum validation.

**Entity type:** `DEA` | **Category:** `certificate` | **Confidence:** 0.97

### Age Over 90

HIPAA §164.514(b)(2)(i) requires converting ages over 89 to the category
"90 or older." A specific age over 90 in a healthcare context is a direct
Safe Harbor violation.

**Entity type:** `AGE_OVER_THRESHOLD` | **Category:** `date` | **Confidence:** 0.90

### Genetic Identifiers (GINA / GDPR Article 9)

Genetic data requiring special protection under GINA (employment) and
GDPR Article 9 (special category data).

| Entity Type | Pattern | Confidence |
|---|---|---|
| `DBSNP_RS_ID` | `rs` + 7–9 digits (dbSNP variant IDs) | 0.85 |
| `VCF_GENETIC_DATA` | VCF file `CHROM` column header | 0.85 |
| `ENSEMBL_GENE_ID` | `ENSG` + 11 digits | 0.85 |

### Substance Use Disorder Field Names (42 CFR Part 2)

SUD treatment records are governed by 42 CFR Part 2 (stricter than HIPAA).
PhiScan detects field names that indicate SUD-related data.

**Entity type:** `SUD_FIELD` | **Category:** `substance_use_disorder` | **Confidence:** 0.88

**Detected field names:** `substance_use`, `addiction_treatment`, `sud_diagnosis`,
`alcohol_abuse`, `opioid_treatment`, `methadone`, `buprenorphine`, `naloxone`,
`drug_treatment`, `detox_program`, `mat_program`

### Quasi-Identifier Combinations

Individual fields that are not PHI alone but create re-identification risk
in combination. Sweeney (2000) showed that ZIP code + date of birth + sex
uniquely identifies 87% of the US population.

**Category:** `quasi_identifier_combination` | **Confidence:** 0.90

| Combination | Re-identification Risk |
|---|---|
| ZIP + DOB | 87% of US population uniquely identified (Sweeney 2000) |
| NAME + DATE | Uniquely identifying in most populations |
| AGE > 90 + GEOGRAPHIC | HIPAA §164.514(b)(2)(i) direct violation |
| ≥ 2 PHI categories within 50 lines | Colocated identifier risk |

---

## Quick Reference

```bash
# See all 18 categories with detection notes
phi-scan explain hipaa

# Scan with verbose output showing which category triggered each finding
phi-scan scan . --verbose

# Filter to specific severity
phi-scan scan . --severity-threshold high
```
