# De-identification Standards and Regulatory Scope

This document describes the regulatory scope of the PhiScan detection engine,
the de-identification methods it implements, and the limitations that must be
understood before relying on scan results for compliance purposes.

---

## HIPAA Safe Harbor — Implemented Standard

PhiScan implements **HIPAA Safe Harbor de-identification** as defined in
45 CFR §164.514(b)(2). Under Safe Harbor, data is considered de-identified
only when all 18 PHI identifier categories have been removed or transformed.

PhiScan's detection engine covers all 18 Safe Harbor categories across its
four detection layers (Regex, NLP, FHIR/HL7, AI). See `phi-scan explain hipaa`
for the full category list and confidence thresholds.

### Safe Harbor Categories Covered

| Category | Layer(s) | Notes |
|---|---|---|
| Names | Regex, NLP | Patient, provider, and family member names |
| Geographic data | Regex | ZIP codes, addresses smaller than state |
| Dates | Regex | More specific than year (DOB, admission, discharge) |
| Phone numbers | Regex | Including fictional-range exclusion (555-01xx) |
| Fax numbers | Regex | Treated identically to phone numbers |
| Email addresses | Regex | Documentation domains excluded (example.com, etc.) |
| SSN | Regex | Reserved ranges excluded (000-xx, 666-xx, 900-999-xx) |
| MRN | Regex, FHIR | Medical Record Numbers and FHIR identifier fields |
| Health plan numbers | Regex, FHIR | Beneficiary and member IDs including MBI/HICN |
| Account numbers | Regex | Financial account identifiers |
| Certificate/License numbers | Regex | Medical and professional license numbers |
| Vehicle identifiers | Regex | VINs with check-digit validation |
| Device identifiers | Regex | UDI, serial numbers |
| URLs | Regex | Patient-specific URL path segments |
| IP addresses | Regex | IPv4 and IPv6; TEST-NET ranges excluded |
| Biometric identifiers | Regex | Field-name pattern detection |
| Full-face photos | Regex | File-name and field-name detection |
| Unique IDs | Regex | Any other uniquely identifying number |

### Extended Categories Also Covered

| Category | Standard | Layer(s) |
|---|---|---|
| MBI | CMS post-2019 Medicare | Regex |
| HICN | Legacy Medicare (SSN-based) | Regex |
| DEA number | DEA registration | Regex (with checksum) |
| Age > 90 | HIPAA §164.514(b)(2)(i) | Regex |
| Genetic IDs (rs-IDs, VCF) | GINA, GDPR Art. 9 | Regex |
| SUD field names | 42 CFR Part 2 | Regex |
| Quasi-identifier combinations | HIPAA re-identification risk | Regex |

---

## Expert Determination — Not Implemented

**PhiScan implements Safe Harbor only.**

HIPAA provides two de-identification methods:

1. **Safe Harbor** (§164.514(b)(2)) — Remove all 18 identifier categories.
   PhiScan implements this method.

2. **Expert Determination** (§164.514(b)(1)) — A qualified statistician
   certifies that the risk of identifying an individual from the data is
   "very small." This requires professional judgment and statistical analysis
   that the tool alone cannot perform.

> **Limitation:** A clean PhiScan scan satisfies Safe Harbor only. It does
> **not** constitute Expert Determination certification. Organisations relying
> on Expert Determination must engage a qualified statistician separately.

---

## HITECH Act

The Health Information Technology for Economic and Clinical Health (HITECH)
Act (45 CFR §§164.400–414) extended HIPAA obligations to **business associates**
and established mandatory **breach notification thresholds**:

- Covered entities must notify affected individuals within 60 days of
  discovering a breach.
- Breaches affecting 500 or more individuals require notification to the
  Secretary of HHS and prominent media outlets.
- Business associates are directly liable for HIPAA compliance — not just
  the covered entity they serve.

PhiScan directly supports HITECH breach assessment by identifying what PHI
is present in a codebase. A scan report quantifies the categories of exposed
PHI, which determines the applicable breach notification requirements.

---

## 42 CFR Part 2 — Substance Use Disorder Records

Records relating to Substance Use Disorder (SUD) treatment are governed by
**42 CFR Part 2**, which is stricter than HIPAA in several key respects:

- Explicit patient **consent is required for any disclosure**, including
  disclosures for treatment, payment, and healthcare operations — categories
  that are broadly permitted under HIPAA.
- Re-disclosure of SUD records is prohibited without a new consent.
- The prohibition applies to records held by any federally assisted SUD
  treatment programme.

PhiScan detects SUD-related field names from `SUD_FIELD_NAME_PATTERNS`
(defined in `phi_scan/constants.py`) and maps them to the dedicated
`PhiCategory.SUBSTANCE_USE_DISORDER` category. This category is intentionally
separate from `PhiCategory.UNIQUE_ID` — SUD records fall under a different
statute with different consent requirements.

---

## GINA — Genetic Information Nondiscrimination Act

The Genetic Information Nondiscrimination Act (GINA) protects genetic
information from discrimination in health insurance and employment. Genetic
information includes:

- Genetic test results (individual or family members)
- Family health history used to predict future disease risk
- Participation in genetic services or clinical research

PhiScan's genetic identifier detection layer covers:

- dbSNP rs-IDs (`rs` followed by 1–12 digits)
- VCF-format variant data (chromosome, position, REF/ALT columns)
- Ensembl gene IDs (`ENSG` prefix)

These identifiers are also subject to **GDPR Article 9** (special category
data) in EU contexts.

> **Note:** GINA compliance mapping will be completed in Phase 4
> (`phi_scan/compliance.py`).

---

## NIST SP 800-122 — PII Confidentiality Guide

The NIST Special Publication 800-122 *Guide to Protecting the
Confidentiality of Personally Identifiable Information (PII)* defines PII
categories and recommends confidentiality safeguards.

PhiScan's PII detection layer aligns with NIST SP 800-122 across the
following categories:

| NIST SP 800-122 Category | PhiScan Category |
|---|---|
| Name | PhiCategory.NAME |
| Social Security Number | PhiCategory.SSN |
| Date of birth | PhiCategory.DATE |
| Home address | PhiCategory.GEOGRAPHIC |
| Phone number | PhiCategory.PHONE |
| Email address | PhiCategory.EMAIL |
| Financial account number | PhiCategory.ACCOUNT |
| Biometric identifiers | PhiCategory.BIOMETRIC |

> **Note:** Full NIST SP 800-122 compliance mapping will be completed in
> Phase 4 (`phi_scan/compliance.py`).

---

## Scope Boundaries

The following are **out of scope** for de-identification purposes:

- **Binary file formats** (PDF, DICOM, DOCX, XLSX) — see
  `docs/known-limitations.md` for details.
- **Expert Determination** — requires a qualified statistician; the tool
  alone cannot satisfy this standard.
- **Re-identification risk modelling** — Safe Harbor removes specific
  identifiers; it does not model residual re-identification risk from
  quasi-identifiers beyond the ZIP + DOB + sex combination.
- **Encryption at rest** — PhiScan detects exposed PHI in source code and
  test fixtures; it does not enforce encryption of stored data.
