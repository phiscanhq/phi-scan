---
name: hipaa-context
description: HIPAA PHI identifier definitions, confidence thresholds, and detection guidance — auto-loaded when working on scanner, detection, regex, or compliance code
user-invocable: false
---

## HIPAA 18 PHI Identifiers

All 18 must be detected. No exceptions.

| # | Identifier | Examples | Detection notes |
|---|-----------|---------|----------------|
| 1 | Names | Patient names, provider names | Full name, first/last separately |
| 2 | Geographic data | Street address, city, ZIP (5-digit OK, ZIP+4 is PHI) | Sub-state geographic subdivisions |
| 3 | Dates (except year) | DOB, admission date, discharge date, death date | All date formats: MM/DD/YYYY, ISO 8601, natural language |
| 4 | Phone numbers | Any phone/fax format | US and international formats |
| 5 | Fax numbers | Same patterns as phone | Often labelled `fax:` in code/data |
| 6 | Email addresses | Any RFC 5321 email | Including subaddressing (user+tag@domain) |
| 7 | Social Security Numbers | SSN, TIN | XXX-XX-XXXX and variants |
| 8 | Medical Record Numbers | MRN, chart number | Facility-specific — detect by field name context |
| 9 | Health plan beneficiary numbers | Insurance member ID | Policy number, group number |
| 10 | Account numbers | Bank, financial account | Context-dependent |
| 11 | Certificate / license numbers | Medical license, DEA number | Context-dependent |
| 12 | Vehicle identifiers | VIN, license plate | 17-char VIN pattern |
| 13 | Device identifiers | Serial numbers, implant IDs | UDI (Unique Device Identifier) |
| 14 | Web URLs | Any URL linked to an individual | URLs in patient records |
| 15 | IP addresses | IPv4 and IPv6 | In access logs linked to a patient |
| 16 | Biometric identifiers | Fingerprints, retinal scans, voiceprints | Usually field-name detection |
| 17 | Full-face photographs | Image file references | File path or base64 in code |
| 18 | Any other unique identifying number | NPI, provider ID, patient portal ID | Catch-all — use context |

## Safe Harbor Method

Under HIPAA Safe Harbor (45 CFR §164.514(b)), data is de-identified when ALL 18 identifiers
are removed or generalised. PhiScan scans for the presence of any of these identifiers in
source code, config files, test fixtures, and log output.

## FHIR R4 PHI-Bearing Fields

Field names in FHIR resources that always carry PHI:
`patient.name`, `patient.birthDate`, `patient.address`, `patient.telecom`,
`patient.identifier`, `patient.photo`, `practitioner.name`, `encounter.subject`,
`observation.subject`, `condition.subject`

## Confidence Scoring

| Confidence | Meaning | Action |
|-----------|---------|--------|
| HIGH ≥ 0.9 | Structural match (regex) — SSN, MRN format | Block immediately |
| MEDIUM 0.7–0.89 | NLP entity + context | Flag, allow override with suppression comment |
| LOW 0.4–0.69 | Heuristic / field-name match | Warn only, never block |
| INFO < 0.4 | Very low confidence signal | Log only, no user-facing warning |

## Severity Levels

| Severity | Identifiers | CI behaviour |
|----------|------------|-------------|
| CRITICAL | SSN, MRN, DOB, full name + DOB together | Fail CI, block merge |
| HIGH | Email, phone, address, health plan number | Fail CI, block merge |
| MEDIUM | IP address, URL, device ID | Warn, configurable block |
| LOW | Field name match, low-confidence NLP | Warn only |
