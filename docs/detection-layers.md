# Detection Layers

PhiScan uses a four-layer detection architecture. Each layer is independently
useful but the layers work together — findings from one layer inform and
complement the others. All layers run on every scan; optional layers degrade
gracefully when their dependencies are not installed.

Use `phi-scan explain detection` for a quick in-terminal summary.

---

## Architecture Overview

```
File content
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1 — Regex                                                 │
│ 28 entity types, 0.85–1.0 confidence, no install required       │
│ Always runs. Covers all 18 HIPAA Safe Harbor categories.        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2 — NLP (Optional)                                        │
│ Presidio + spaCy, 0.50–0.90 confidence                          │
│ pip install "phi-scan[nlp]" && phi-scan setup                   │
│ Detects PERSON, LOCATION, DATE_TIME in free text                │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3 — Structured Formats (Optional)                         │
│ FHIR R4 field-name scanning + HL7 v2 segment parsing            │
│ 0.80–0.95 confidence                                            │
│ pip install "phi-scan[hl7]"                                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Variable-Name Context Boost                                     │
│ +0.15 when assignment LHS matches PHI-suggestive variable name  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4 — Quasi-Identifier Combination Detection                │
│ 0.90 confidence, always runs on prior findings                  │
│ ZIP+DOB, NAME+DATE, AGE>90+GEOGRAPHIC, colocated combinations   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Deduplication                                                   │
│ Keyed on (file_path, line_number, value_hash)                   │
│ Highest-confidence finding wins on conflict                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Layer 1 — Regex

**Confidence range: 0.85 – 1.0**
**Dependencies: none**
**Always active**

The regex layer is the primary detection engine. It covers all 18 HIPAA Safe
Harbor categories plus extended identifiers with carefully tuned patterns.

### What It Covers

| Entity Type | Category | Confidence | Validator |
|---|---|---|---|
| `SSN` | `ssn` | 0.97 | Reserved area/group/serial exclusion |
| `PHONE` | `phone` | 0.88 | NANP / E.164 format |
| `FAX` | `fax` | 0.88 | Same as phone |
| `EMAIL` | `email` | 0.88 | Excludes documentation domains |
| `MRN` | `mrn` | 0.88 / 0.65 | Context keyword required for high confidence |
| `DATE` | `date` | 0.88 | More specific than year only |
| `ZIP_CODE` | `geographic` | 0.88 | 5-digit US ZIP |
| `ZIP_PLUS4` | `geographic` | 0.88 | ZIP+4 format |
| `STREET_ADDRESS` | `geographic` | 0.85 | House number + street |
| `HEALTH_PLAN_NUMBER` | `health_plan` | 0.88 | Insurance ID / member ID |
| `MBI` | `health_plan` | 0.92 | CMS post-2019 format (11 chars) |
| `HICN` | `health_plan` | 0.88 | Legacy Medicare + suffix |
| `ACCOUNT_NUMBER` | `account` | 0.88 / 0.65 | Context keyword confirmation |
| `CERTIFICATE_NUMBER` | `certificate` | 0.85 | License number patterns |
| `DEA` | `certificate` | 0.97 | Luhn checksum |
| `NPI` | `unique_id` | 0.88 | Luhn validation, CMS prefix |
| `VIN` | `vehicle` | 0.97 | Position-9 check digit |
| `FDA_UDI` | `device` | 0.88 | GS1 GTIN-14 format |
| `PATIENT_URL` | `url` | 0.88 | Patient-specific path segments |
| `IPV4_ADDRESS` | `ip` | 0.88 | Excludes RFC 5737 TEST-NETs |
| `IPV6_ADDRESS` | `ip` | 0.88 | Full and compressed format |
| `BIOMETRIC_FIELD` | `biometric` | 0.88 | Field-name detection |
| `SUD_FIELD` | `substance_use_disorder` | 0.88 | Field-name list (42 CFR Part 2) |
| `DBSNP_RS_ID` | `unique_id` | 0.85 | rs + 7–9 digits |
| `VCF_GENETIC_DATA` | `unique_id` | 0.85 | CHROM column header |
| `AGE_OVER_THRESHOLD` | `date` | 0.90 | Age > 90 (HIPAA §164.514(b)(2)(i)) |
| `UNIQUE_ID` | `unique_id` | varies | Catch-all identifier patterns |

### How Context Works

Context-dependent patterns (MRN, Account, Health Plan) look for keyword
evidence on the same source line. When a keyword is found, confidence is
at the base level (0.88). When no keyword is found, confidence drops to 0.65.

```python
# HIGH confidence (0.88) — keyword "mrn" present on same line
mrn = "1047832"

# LOW confidence (0.65) — no corroborating context
x = "1047832"
```

### Exclusion Lists

PhiScan excludes known safe/fictional values to reduce false positives:

- **SSN**: Area 000, 666, 900–999; Group 00; Serial 0000
- **Phone**: 555-0100 through 555-0199 (FCC fictional range)
- **Email**: `example.com`, `example.org`, `example.net`, `test.com`
- **IP**: RFC 5737 TEST-NET ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)

---

## Layer 2 — NLP (Optional)

**Confidence range: 0.50 – 0.90**
**Dependencies: `phi-scan[nlp]`**
**Graceful degradation: empty findings + warning log**

The NLP layer uses **Microsoft Presidio** with **spaCy `en_core_web_lg`** to
detect PHI in unstructured free text. It excels at finding:

- Patient and provider names embedded in sentences
- Geographic locations described in prose
- Dates written in natural language

### Installation

```bash
pip install "phi-scan[nlp]"
phi-scan setup            # downloads en_core_web_lg (~550 MB)
```

### What It Detects

| spaCy / Presidio Entity | PhiScan Category |
|---|---|
| `PERSON` | `name` |
| `LOCATION` | `geographic` |
| `GPE` (geopolitical entity) | `geographic` |
| `DATE_TIME` | `date` |
| `EMAIL_ADDRESS` | `email` |

### Performance Notes

The NLP layer runs once per file, not once per pattern. The Presidio
`AnalyzerEngine` is a lazy singleton — it initialises on first call and
is reused for all subsequent files. Cold-start takes approximately 2–3
seconds; subsequent files are significantly faster.

For large codebases in CI, NLP detection adds 10–30% to scan time
depending on file count and content density.

---

## Layer 3 — Structured Formats (Optional)

**Confidence range: 0.80 – 0.95**

### FHIR R4 Scanning (Always Active)

PhiScan detects PHI in FHIR R4 JSON and XML without requiring the
`fhir.resources` library. The detection works on field-name patterns
rather than full FHIR resource parsing.

FHIR fields detected include:

| FHIR Field | PhiScan Category |
|---|---|
| `Patient.name.family`, `.given`, `.prefix` | `name` |
| `Patient.telecom` (phone/email/fax) | `phone`, `email`, `fax` |
| `Patient.address` | `geographic` |
| `Patient.birthDate` | `date` |
| `Patient.identifier`, `.value` | `unique_id`, `mrn`, `health_plan` |

### HL7 v2 Scanning (Optional)

```bash
pip install "phi-scan[hl7]"
```

HL7 v2 files are identified by the presence of the `MSH|^~\&|` message
header. The following segments are scanned:

| Segment | Content |
|---|---|
| `PID` | Patient Identification (name, DOB, SSN, address, MRN) |
| `NK1` | Next of Kin (name, address, phone) |
| `IN1` | Insurance (member ID, group number, company name) |

Each segment field index is mapped to a HIPAA category. Confidence is
`CONFIDENCE_HIGH_FLOOR` (0.90) for structured field matches.

---

## Variable-Name Context Boost

After all detection layers run, PhiScan applies a confidence boost when
the left-hand side of an assignment statement matches a PHI-suggestive
variable name pattern.

**Boost amount:** +0.15  
**Maximum score:** 1.0 (capped)

**Variable name patterns that trigger the boost:**
`address`, `beneficiary`, `birth`, `diagnosis`, `dob`, `email`,
`insurance`, `mrn`, `name`, `patient`, `phone`, `ssn`

The boost is a substring match — `patient_ssn`, `patient_phone_number`,
and `mrn_value` all qualify.

```python
# Without boost: MRN with no context → 0.65
record = "1047832"

# With boost: variable "mrn" contains boost keyword → 0.80
mrn = "1047832"
```

---

## Layer 4 — Quasi-Identifier Combination Detection

**Confidence: 0.90 (fixed)**
**Dependencies: none**
**Always runs (after other layers)**

Individual fields that do not meet Safe Harbor thresholds alone can create
re-identification risk when they appear together. Layer 4 analyses findings
from all previous layers and identifies dangerous combinations.

### Combination Rules

| Combination | Basis |
|---|---|
| ZIP code + Date of birth | Sweeney (2000): 87% of US population uniquely identified |
| Name + Date | Uniquely identifying in most populations |
| Age > 90 + Geographic data | HIPAA §164.514(b)(2)(i) direct violation |
| ≥ 2 distinct PHI categories within 50 lines | Colocated identifier risk |

### Proximity Window

Quasi-identifier combinations are evaluated within a sliding window of
**50 lines** (`QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES`). Two categories
found more than 50 lines apart are not considered a combination.

### Finding Representation

Each quasi-identifier combination produces a single representative finding
at the line of the first constituent finding:

```json
{
  "entity_type": "QUASI_IDENTIFIER_COMBINATION",
  "hipaa_category": "quasi_identifier_combination",
  "confidence": 0.90,
  "severity": "HIGH",
  "detection_layer": "combination",
  "code_context": "zip_code = '90210'  # [REDACTED: first constituent]"
}
```

---

## Deduplication

After all layers produce their findings, PhiScan deduplicates on:

```
(file_path, line_number, value_hash)
```

Where `value_hash` is the SHA-256 digest of the matched PHI value. If two
layers detect the same value at the same location, the finding with the
**higher confidence score** is kept.

This means that if the regex layer finds an SSN at line 42 with confidence
0.97 and the NLP layer also finds a name at the same line, both findings are
kept (different `value_hash`). But if both regex and NLP detect the same
email address on the same line, only the higher-confidence one is reported.

---

## PHI Redaction at the Detection Layer

Raw PHI values are **never stored**. The detection coordinator immediately
computes `SHA-256(matched_value)` and stores only the hash. The `code_context`
field stores the source line with the matched portion replaced by `[REDACTED]`.

```python
# Source line: mrn = "MRN-004821"
# Stored in ScanFinding:
#   value_hash = sha256("MRN-004821").hexdigest()
#   code_context = 'mrn = "[REDACTED]"'
```

This ensures that even if the audit database or a JSON report is exfiltrated,
no raw PHI values are exposed.

---

## Checking Layer Availability

```bash
# Check which optional layers are active
phi-scan explain detection

# Install all optional layers
pip install "phi-scan[full]"
phi-scan setup

# Run with verbose output to see which layer flagged each finding
phi-scan scan . --verbose
```
