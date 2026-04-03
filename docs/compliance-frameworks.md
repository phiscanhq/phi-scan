# Compliance Frameworks Reference

PhiScan annotates findings with applicable regulatory controls from 12
compliance frameworks. HIPAA is always active; all other frameworks are
opt-in via the `--framework` flag.

```bash
phi-scan scan . --framework gdpr,soc2,hitrust,nist
phi-scan explain frameworks   # quick in-terminal reference
```

---

## Framework Summary

> **Penalty figures are current as of April 2026.** HIPAA/HITECH penalty tiers
> were last updated by the HHS final rule effective October 2024 (adjusting
> the §1176(a)(1)(C) annual cap for inflation). Regulatory penalties change
> over time — verify current figures with official HHS/agency publications
> before relying on them for compliance decisions.

| Framework | Value | Enforcement Body | Key Penalty |
|---|---|---|---|
| HIPAA | `hipaa` | HHS OCR | $100–$50,000/violation; $1.9M annual cap |
| HITECH | `hitech` | HHS OCR + State AGs | $100–$50,000/violation; mandatory breach notification |
| SOC 2 Type II | `soc2` | AICPA | Loss of certification; contract breach |
| HITRUST CSF v11 | `hitrust` | HITRUST Alliance | Loss of certification |
| NIST SP 800-53 / SP 800-122 | `nist` | NIST / FISMA | Federal contract termination |
| GDPR | `gdpr` | EU DPAs | Up to €20M or 4% of global annual turnover |
| 42 CFR Part 2 | `42cfr2` | SAMHSA + HHS | Up to $500/violation (first offense) |
| GINA | `gina` | EEOC (employment); HHS OCR (health plans) | $50,000–$300,000/violation |
| California CMIA | `cmia` | California DOJ | Up to $250,000/violation |
| Illinois BIPA | `bipa` | Illinois AG | $1,000–$5,000/violation; private right of action |
| New York SHIELD Act | `shield` | New York AG | Up to $5,000/violation; $250,000/incident |
| Texas MRPA | `mrpa` | Texas AG | Up to $5,000/violation |

---

## HIPAA — Health Insurance Portability and Accountability Act

**Flag value:** `hipaa` (always active — cannot be disabled)  
**Enforcement body:** HHS Office for Civil Rights (OCR)  
**Penalty range:** $100–$50,000 per violation; $1.9M annual cap per violation category  
**Standard:** 45 CFR §§164.500–164.534 (Privacy Rule); 45 CFR §§164.302–164.318 (Security Rule)

HIPAA governs Protected Health Information (PHI) held or transmitted by
covered entities (healthcare providers, health plans, healthcare clearinghouses)
and their business associates. PHI includes any information that can be used
to identify an individual in connection with past, present, or future healthcare.

PhiScan implements the **Safe Harbor de-identification method** (45 CFR §164.514(b)(2)).
All 18 Safe Harbor identifier categories are always scanned regardless of which
frameworks are enabled.

### HIPAA Controls Mapped per Category

| PHI Category | Control ID | Control Name |
|---|---|---|
| All 18 categories | 45 CFR §164.514(b)(2)(i)(A–R) | Safe Harbor De-identification |
| Quasi-identifiers | 45 CFR §164.514(b) | Re-identification Risk |

### CI/CD Example

```bash
# HIPAA is always on — no flag needed
phi-scan scan . --output sarif --report-path results.sarif
```

---

## HITECH — Health Information Technology for Economic and Clinical Health Act

**Flag value:** `hitech`  
**Enforcement body:** HHS OCR + State Attorneys General  
**Penalty range:** $100–$50,000 per violation; mandatory breach notification  
**Standard:** 45 CFR §§164.400–414

HITECH extended HIPAA to business associates and established mandatory breach
notification thresholds. HIGH-confidence PhiScan findings represent "unsecured
PHI" under the HITECH definition and directly trigger breach notification
obligations.

### Breach Notification Thresholds

| Breach Size | Required Notification |
|---|---|
| Any size | Notify affected individuals within 60 days |
| 500+ individuals (45 CFR §164.406) | Notify HHS Secretary AND prominent media in affected area |
| < 500 individuals per state | Log in annual HHS report |

### Key Control

| Control ID | Control Name |
|---|---|
| 45 CFR §§164.400–414 | Breach Notification for Unsecured PHI |

### CI/CD Example

```bash
phi-scan scan . --framework hitech --output json | \
  jq '.findings[] | select(.severity == "high")'
```

HIGH-confidence findings are unsecured PHI — each one is a potential breach
notification trigger.

---

## SOC 2 Type II

**Flag value:** `soc2`  
**Enforcement body:** AICPA (American Institute of CPAs)  
**Penalty range:** Loss of SOC 2 certification; customer contract breach penalties  
**Standard:** AICPA Trust Services Criteria (CC6.x)

SOC 2 Type II audits service organisations against the AICPA Trust Services
Criteria. The CC6 criteria govern logical access and data protection. PHI
committed to source code is a direct CC6.6 violation.

### Controls Mapped

| Control ID | Control Name | Applicability |
|---|---|---|
| CC6.1 | Logical and Physical Access Controls | PHI outside access control boundaries |
| CC6.6 | Logical Access Security Measures | PHI accessible to all developers with repo access |
| CC6.7 | Data Transmission and Disposal | PHI retained in unauthorised location (source code) |

### CI/CD Example

```bash
# Fail CI if any SOC 2 control is violated
phi-scan scan . --framework soc2
```

---

## HITRUST CSF v11

**Flag value:** `hitrust`  
**Enforcement body:** HITRUST Alliance  
**Penalty range:** Loss of HITRUST certification; contractual penalties with covered entities  
**Standard:** HITRUST Common Security Framework v11

HITRUST CSF harmonises HIPAA, NIST SP 800-53, ISO 27001, and PCI-DSS into a
unified framework. Healthcare organisations pursuing HITRUST certification must
demonstrate controls across all mapped domains.

### Controls Mapped

| Control ID | Control Name | Applicability |
|---|---|---|
| 07.a | Asset Inventory | PHI in source code is an uncontrolled, unregistered asset |
| 09.s | Monitoring and Information Exchange | PHI committed without detection = monitoring gap |
| 01.v | Information Access Restriction | PHI accessible to all repo users (least-privilege violation) |
| 09.ab | Monitoring System Use | Data handling monitoring failed to prevent PHI commit |

### CI/CD Example

```bash
phi-scan scan . --framework hitrust --output pdf --report-path hitrust-audit.pdf
```

---

## NIST SP 800-53 Rev 5 / SP 800-122

**Flag value:** `nist`  
**Enforcement body:** NIST (advisory); federal agencies via FISMA  
**Penalty range:** Federal contract termination; FISMA non-compliance findings  
**Standards:** NIST SP 800-53 Rev 5 (security controls); NIST SP 800-122 (PII confidentiality)

NIST SP 800-53 Rev 5 provides the security control baseline for federal
information systems. NIST SP 800-122 guides PII confidentiality protection.
Together they cover both PHI (as a subset of PII) and the system security
controls that prevent PHI exposure.

### Controls Mapped

| Control ID | Control Name |
|---|---|
| SC-28 | Protection of Information at Rest |
| SI-1 | System and Information Integrity Policy |
| PM-22 | Personally Identifiable Information Quality Management |
| PT-2 | Authority to Process Personally Identifiable Information |
| PT-3 | Purposes of Personally Identifiable Information Processing |
| SP 800-122 §2.1 | Identify Personally Identifiable Information |
| SP 800-122 §2.2 | Minimise Personally Identifiable Information |

### CI/CD Example

```bash
# For federal contractors: scan + NIST annotations
phi-scan scan . --framework nist --output json --report-path nist-findings.json
```

---

## GDPR — EU General Data Protection Regulation

**Flag value:** `gdpr`  
**Enforcement body:** EU Data Protection Authorities (DPAs), one per member state  
**Penalty range:** Up to €20M or 4% of global annual turnover (whichever is higher)  
**Standard:** EU Regulation 2016/679

GDPR governs personal data of EU residents regardless of where the processing
organisation is located. Health data is a "special category" under Article 9
requiring explicit consent and stricter protections.

### Controls Mapped

| Control ID | Control Name | Applicability |
|---|---|---|
| GDPR Art. 4(1) | Personal Data Definition | Any finding = personal data under GDPR |
| GDPR Art. 4(15) | Health Data Definition | Health-related findings = special category |
| GDPR Art. 9 | Special Categories of Personal Data | Highest-risk GDPR category (explicit consent required) |
| GDPR Art. 25 | Data Protection by Design and by Default | PHI in source code = architectural failure |
| GDPR Art. 32 | Security of Processing | PHI lacks required access controls and encryption |

### Special Category Data (Article 9)

The following PhiScan categories trigger Article 9 annotations under GDPR:

| PhiScan Category | GDPR Basis |
|---|---|
| `name`, `date`, `phone`, `fax`, `mrn`, `device`, `biometric` | Health data (Art. 4(15)) |
| `biometric` | Biometric data for unique identification (Art. 9(1)) |
| Genetic identifiers | Genetic data (Art. 9(1)) |

### CI/CD Example

```bash
phi-scan scan . --framework gdpr
```

---

## 42 CFR Part 2 — Substance Use Disorder Records

**Flag value:** `42cfr2`  
**Enforcement body:** SAMHSA + HHS  
**Penalty range:** Up to $500 per violation (first offense); enhanced for repeat violations  
**Standard:** 42 CFR Part 2 (Confidentiality of Substance Use Disorder Patient Records)

42 CFR Part 2 is stricter than HIPAA. SUD treatment records may not be
disclosed without explicit written patient consent — even for treatment
referrals or internal healthcare operations. Re-disclosure is separately
prohibited.

PhiScan detects SUD-related field names (not values) that indicate the
presence of 42 CFR Part 2-protected data.

### Control Mapped

| Control ID | Control Name |
|---|---|
| 42 CFR Part 2 | SUD Patient Record Confidentiality |

### Detected Field Names

`substance_use`, `addiction_treatment`, `sud_diagnosis`, `alcohol_abuse`,
`opioid_treatment`, `methadone`, `buprenorphine`, `naloxone`,
`drug_treatment`, `detox_program`, `mat_program`

### Advisory Limitation

42 CFR Part 2 detection is **pattern-based** — a field named `methadone`
in source code is flagged, but the legal determination of whether a specific
dataset constitutes Part 2-protected records requires legal counsel.
See `docs/known-limitations.md`.

### CI/CD Example

```bash
phi-scan scan . --framework 42cfr2
```

---

## GINA — Genetic Information Nondiscrimination Act

**Flag value:** `gina`  
**Enforcement body:** EEOC (employment context); HHS OCR (health plan context)  
**Penalty range:** $50,000–$300,000 per violation (employment); civil penalties for health plans  
**Standard:** GINA Title II (employment); 45 CFR §164.514(b)(1) (HIPAA genetic provisions)

GINA prohibits the use of genetic information in employment decisions and
health insurance. Genetic identifiers in source code represent a genetic
information handling violation under GINA and GDPR Article 9.

### Controls Mapped

| Control ID | Control Name |
|---|---|
| GINA Title II | Genetic Information in Employment |
| 45 CFR §164.514(b)(1) | HIPAA Genetic Information Provisions |

### Detected Genetic Identifiers

| Entity Type | Description |
|---|---|
| `DBSNP_RS_ID` | dbSNP variant IDs (`rs` + 7–9 digits) |
| `VCF_GENETIC_DATA` | VCF file `CHROM` column header |
| `ENSEMBL_GENE_ID` | Ensembl gene IDs (`ENSG` + 11 digits) |

### CI/CD Example

```bash
phi-scan scan . --framework gina,gdpr   # genetic data triggers both
```

---

## California CMIA / SB 3 / AB 825

**Flag value:** `cmia`  
**Enforcement body:** California Department of Justice; private right of action  
**Penalty range:** Up to $250,000 per violation; private right of action  
**Standard:** California Confidentiality of Medical Information Act (Cal. Civ. Code §56);
SB 3 / AB 825 (genomic data extensions)

California CMIA is stricter than HIPAA for health apps and digital health
services. SB 3 / AB 825 extend protections to genomic data — genetic
identifiers require explicit written consent.

### Controls Mapped

| Control ID | Control Name |
|---|---|
| Cal. Civ. Code §56.10 | Confidentiality of Medical Information |
| Cal. Civ. Code §56.181 (SB 3 / AB 825) | Genomic Data Protections |

### CI/CD Example

```bash
phi-scan scan . --framework cmia
```

---

## Illinois BIPA — Biometric Information Privacy Act

**Flag value:** `bipa`  
**Enforcement body:** Illinois AG; private right of action  
**Penalty range:** $1,000 per negligent violation; $5,000 per intentional violation;
5-year statute of limitations; class actions common  
**Standard:** 740 ILCS 14/15

BIPA governs fingerprints, iris scans, face geometry, voiceprints, and other
biometric identifiers. Requires written notice and consent before collection.
No safe-harbour provision exists.

### Control Mapped

| Control ID | Control Name |
|---|---|
| 740 ILCS 14/15 | Biometric Identifier Collection and Retention |

### Applicability

BIPA applies to `PhiCategory.BIOMETRIC` findings. These are detected by
field-name patterns: `fingerprint`, `iris_scan`, `retinal_scan`,
`face_template`, `voiceprint`, `palm_print`.

### CI/CD Example

```bash
phi-scan scan . --framework bipa
```

---

## New York SHIELD Act

**Flag value:** `shield`  
**Enforcement body:** New York AG  
**Penalty range:** Up to $5,000 per violation; up to $250,000 per incident  
**Standard:** NY General Business Law §899-bb

The Stop Hacks and Improve Electronic Data Security (SHIELD) Act expands
New York's breach notification law to cover a broader definition of "private
information" than federal HIPAA. It applies to any entity that handles
New York residents' data, regardless of where the entity is located.

### Control Mapped

| Control ID | Control Name |
|---|---|
| NY Gen. Bus. Law §899-bb | Private Information — Reasonable Security |

### Applicability

SHIELD annotations apply to categories that constitute "private information"
under New York law: `name`, `geographic`, `date`, `phone`, `fax`, `email`,
`ssn`, `account`, `certificate`, `vehicle`, `url`, `ip`, `unique_id`.

### CI/CD Example

```bash
phi-scan scan . --framework shield
```

---

## Texas MRPA — Medical Records Privacy Act

**Flag value:** `mrpa`  
**Enforcement body:** Texas AG  
**Penalty range:** Up to $5,000 per violation  
**Standard:** Tex. Health & Safety Code §181.001–.205

Texas MRPA covers all identifiable health information, including information
not covered by HIPAA. It applies to healthcare facilities, physicians, and
electronic health record systems operating in Texas.

### Control Mapped

| Control ID | Control Name |
|---|---|
| Tex. Health & Safety Code §181.001–.205 | Identifiable Health Information |

### CI/CD Example

```bash
phi-scan scan . --framework mrpa
```

---

## Using Multiple Frameworks Together

Frameworks can be combined in a single scan:

```bash
# Full enterprise healthcare compliance stack
phi-scan scan . --framework hitech,soc2,hitrust,nist,gdpr

# California-specific stack
phi-scan scan . --framework hitech,cmia,gdpr,gina

# New York-based organisation
phi-scan scan . --framework hitech,shield,gdpr
```

HIPAA is always included regardless of which frameworks are specified.

### Generating a Multi-Framework Compliance Report

```bash
# PDF report with full compliance matrix
phi-scan scan . \
  --framework hitech,soc2,hitrust,nist,gdpr,42cfr2,gina,cmia,bipa,shield,mrpa \
  --output pdf \
  --report-path compliance-report-$(date +%Y%m%d).pdf
```

---

## Per-Category Framework Coverage Matrix

The following table shows which frameworks are triggered for each PHI category.
A `✓` means the framework's controls will be included when that framework is enabled.

| Category | HIPAA | HITECH | SOC 2 | HITRUST | NIST | GDPR | 42 CFR 2 | GINA | CMIA | BIPA | SHIELD | MRPA |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| name | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | — | ✓ | ✓ |
| geographic | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | — | ✓ | ✓ |
| date | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | — | ✓ | ✓ |
| phone | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | — | ✓ | ✓ |
| fax | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | — | ✓ | ✓ |
| email | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Art.4(1)) | — | — | ✓ | — | ✓ | ✓ |
| ssn | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Art.4(1)) | — | — | — | — | ✓ | — |
| mrn | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | — | — | ✓ |
| health_plan | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | — | — | ✓ |
| account | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Art.4(1)) | — | — | — | — | ✓ | — |
| certificate | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Art.4(1)) | — | — | — | — | ✓ | — |
| vehicle | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Art.4(1)) | — | — | — | — | ✓ | — |
| device | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | — | — | ✓ |
| url | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Art.4(1)) | — | — | — | — | ✓ | — |
| ip | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Art.4(1)) | — | — | — | — | ✓ | — |
| biometric | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ + Art.9 | — | ✓ | ✓ | ✓ | — | ✓ |
| photo | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ + Art.9 | — | — | ✓ | — | — | ✓ |
| unique_id | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Art.4(1)) | — | — | — | — | ✓ | — |
| substance_use_disorder | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | — | ✓ |
| quasi_identifier | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | — | ✓ | ✓ |

---

## Legal Advisory

Compliance annotations produced by PhiScan are **regulatory metadata** — they
map detected PHI patterns to applicable legal frameworks based on the category
of identifier found. They are **not legal opinions**.

- A BIPA annotation means the finding matches a pattern associated with
  biometric data under BIPA — it does not constitute a legal determination
  that your organisation is subject to BIPA.
- A 42 CFR Part 2 annotation means a SUD-related field name was detected —
  it does not determine whether the specific data constitutes Part 2-protected
  records under the legal definition.
- State law coverage is advisory. Consult legal counsel to determine
  applicability to your specific organisation and use case.

See `docs/known-limitations.md` for the full scope of advisory limitations.
