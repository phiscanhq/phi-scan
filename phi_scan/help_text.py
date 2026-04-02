"""Explain command content constants (Phase 2).

All explain topic text lives here. Each constant is the single source of truth
for that topic — the CLI explain commands render these constants; documentation
generation can import them directly rather than duplicating content.

Rich markup is used throughout: [bold], [cyan], [yellow], [red], [green].
"""

__all__ = [
    "EXPLAIN_CONFIDENCE_TEXT",
    "EXPLAIN_CONFIG_TEXT",
    "EXPLAIN_DEIDENTIFICATION_TEXT",
    "EXPLAIN_DETECTION_TEXT",
    "EXPLAIN_FRAMEWORKS_TEXT",
    "EXPLAIN_HIPAA_TEXT",
    "EXPLAIN_IGNORE_TEXT",
    "EXPLAIN_REMEDIATION_TEXT",
    "EXPLAIN_REPORTS_TEXT",
    "EXPLAIN_RISK_LEVELS_TEXT",
    "EXPLAIN_SEVERITY_TEXT",
]

# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------

EXPLAIN_CONFIDENCE_TEXT: str = """\
[bold cyan]Confidence Scores[/bold cyan]

Every finding carries a confidence score in [0.0, 1.0] that reflects how
certain PhiScan is that the detected value is real PHI.

[bold]Score ranges:[/bold]

  [red]0.90 – 1.00[/red]   HIGH   — Strong structural match (regex, checksum validation)
  [yellow]0.70 – 0.89[/yellow]   MEDIUM — Contextual match with some ambiguity (NLP / FHIR)
  [green]0.40 – 0.69[/green]   LOW    — Weak signal; may be a false positive
  0.00 – 0.39   INFO   — Very weak; logged but not reported by default

[bold]Default threshold:[/bold] 0.6
  Findings below this value are filtered from reports (but still logged to the
  audit database). Raise it in [cyan].phi-scanner.yml[/cyan] to reduce noise:

    [cyan]scan:
      confidence_threshold: 0.8[/cyan]

[bold]Per-layer ranges:[/bold]

  Layer 1 — Regex     0.85 – 1.00   Structured patterns are unambiguous
  Layer 2 — NLP       0.50 – 0.90   Context-dependent; model uncertainty applies
  Layer 3 — FHIR      0.80 – 0.95   Schema-based structural match
  Layer 4 — AI        ±0.15 delta   Refines an existing score; never standalone
"""

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

EXPLAIN_SEVERITY_TEXT: str = """\
[bold cyan]Severity Levels[/bold cyan]

Severity is derived directly from the confidence score.

  [red bold]HIGH[/red bold]     confidence ≥ 0.90   Treat as confirmed PHI. Block the PR.
  [yellow bold]MEDIUM[/yellow bold]   confidence ≥ 0.70   Likely PHI. Investigate before merge.
  [green bold]LOW[/green bold]      confidence ≥ 0.40   Possible PHI. Review for context.
  INFO     confidence < 0.40   Very weak signal. Logged only; not reported.

[bold]Severity threshold:[/bold]
  Set [cyan]scan.severity_threshold[/cyan] in [cyan].phi-scanner.yml[/cyan] to filter by severity.
  Default is [bold]low[/bold] — all findings with confidence ≥ 0.40 are reported.

  Example — report only HIGH and MEDIUM:
    [cyan]scan:
      severity_threshold: medium[/cyan]
"""

# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------

EXPLAIN_RISK_LEVELS_TEXT: str = """\
[bold cyan]Risk Levels[/bold cyan]

A scan's overall risk level summarises all findings into a single signal for
CI/CD gates and dashboards.

  [red bold]CRITICAL[/red bold]   One or more HIGH-severity findings. Block the PR immediately.
  [red]HIGH[/red]       One or more MEDIUM-severity findings; no HIGH findings.
  [yellow]MODERATE[/yellow]   One or more LOW-severity findings; no HIGH or MEDIUM.
  [green]LOW[/green]        Only INFO-level findings present.
  [bold green]CLEAN[/bold green]      Zero findings at or above the configured threshold.

[bold]Exit codes:[/bold]
  0   CLEAN — safe to proceed
  1   Any findings at or above the severity threshold
"""

# ---------------------------------------------------------------------------
# HIPAA identifiers
# ---------------------------------------------------------------------------

EXPLAIN_HIPAA_TEXT: str = """\
[bold cyan]HIPAA Safe Harbor — 18 PHI Identifier Categories[/bold cyan]

Under 45 CFR §164.514(b)(2), data is de-identified only when ALL 18 categories
are removed or transformed:

   1  [bold]Names[/bold]               Patient, provider, and family member names
   2  [bold]Geographic data[/bold]     Smaller than state; ZIP codes; addresses
   3  [bold]Dates[/bold]               More specific than year (DOB, admission, discharge)
   4  [bold]Phone numbers[/bold]       Including fax numbers
   5  [bold]Fax numbers[/bold]         Treated as phone numbers
   6  [bold]Email addresses[/bold]     Any email linked to a patient
   7  [bold]SSN[/bold]                 Social Security Numbers
   8  [bold]MRN[/bold]                 Medical Record Numbers
   9  [bold]Health plan numbers[/bold] Beneficiary and member IDs
  10  [bold]Account numbers[/bold]     Bank or financial account identifiers
  11  [bold]Cert/License numbers[/bold]Medical and professional license numbers
  12  [bold]Vehicle identifiers[/bold] VINs and registration plate numbers
  13  [bold]Device identifiers[/bold]  UDI, serial numbers, implant IDs
  14  [bold]URLs[/bold]                Web addresses encoding patient-specific paths
  15  [bold]IP addresses[/bold]        Addresses linkable to individual patients
  16  [bold]Biometric identifiers[/bold]Fingerprints, retinal scans, voiceprints
  17  [bold]Full-face photos[/bold]    Photographs and comparable images
  18  [bold]Unique IDs[/bold]          Any other uniquely identifying number

[bold]Extended categories also covered:[/bold]
  MBI / HICN     Medicare Beneficiary and legacy claim numbers
  DEA number     2-letter prefix + 7-digit checksum
  Age > 90       HIPAA §164.514(b)(2)(i) — must be generalised to "90 or older"
  Genetic IDs    dbSNP rs-IDs, VCF variants (GINA + GDPR Art. 9)
  SUD records    42 CFR Part 2 — stricter than HIPAA; explicit consent required
  Quasi-IDs      ZIP + DOB + sex combination → 87% re-identification risk

[bold]Regulatory scope:[/bold]

  [bold]HIPAA Safe Harbor[/bold]   45 CFR §164.514(b)(2) — primary standard implemented by
                      PhiScan. All 18 identifier categories are covered.

  [bold]HITECH Act[/bold]          45 CFR §§164.400–414 — extended HIPAA to
                      business associates; established mandatory
                      breach notification thresholds for covered entities.
                      PhiScan supports HITECH breach assessment by
                      identifying exposed PHI.

  [bold]42 CFR Part 2[/bold]       Substance Use Disorder records — stricter than HIPAA.
                      Explicit patient consent is required for any disclosure,
                      including disclosures for treatment purposes. SUD field
                      names are detected and mapped to a dedicated category.

  [bold]GINA[/bold]                Genetic Information Nondiscrimination Act — genetic
                      information (test results, family history, genomic data)
                      is a protected category. Covered by the genetic identifier
                      detection layer (dbSNP rs-IDs, VCF-format data, Ensembl
                      gene IDs). Also subject to GDPR Art. 9 in EU contexts.

  [bold]NIST SP 800-122[/bold]     PII Confidentiality Guide — the PII detection layer
                      (name, SSN, DOB, address, phone, email, financial account
                      numbers, biometrics) aligns with this standard.

[bold]Expert Determination limitation:[/bold]
  PhiScan implements [bold]Safe Harbor only[/bold]. Expert Determination (§164.514(b)(1))
  requires certification by a qualified statistician — the tool alone cannot
  satisfy that standard. See [cyan]docs/de-identification.md[/cyan] for details.
"""

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

EXPLAIN_DETECTION_TEXT: str = """\
[bold cyan]Detection Architecture — 4 Layers[/bold cyan]

PhiScan applies four detection layers in order. Each layer adds coverage
without replacing previous layers.

[bold]Layer 1 — Regex / Pattern Matching[/bold]
  Fast, zero false-negatives on structured PHI. Covers SSN, MBI, DEA, phone,
  email, IP, VIN, and other identifiers with fixed formats. Confidence: 0.85–1.00.

[bold]Layer 2 — NLP Named Entity Recognition[/bold]
  Context-aware detection via spaCy + Presidio. Catches names and locations
  embedded in code strings. Requires [cyan]pip install phi-scan[nlp][/cyan].
  Confidence: 0.50–0.90.

[bold]Layer 3 — Structured Healthcare Formats[/bold]
  FHIR R4 field-name scanning and HL7 v2 segment parsing (PID, NK1, IN1).
  Requires [cyan]pip install phi-scan[fhir][/cyan]. Confidence: 0.80–0.95.

[bold]Layer 4 — AI Augmentation (optional)[/bold]
  Claude API reduces false positives by re-scoring medium-confidence findings.
  PHI values are ALWAYS redacted before any API call — only code structure
  with [REDACTED] placeholders is sent. Confidence adjustment: ±0.15.
  Disabled by default. Enable with [cyan]ai.enable_claude_review: true[/cyan].
"""

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

EXPLAIN_CONFIG_TEXT: str = """\
[bold cyan].phi-scanner.yml — Configuration Reference[/bold cyan]

Run [cyan]phi-scan config init[/cyan] to generate a default file.

[bold]scan:[/bold]
  [cyan]confidence_threshold[/cyan]: 0.6      # Minimum confidence to report (0.0–1.0)
  [cyan]severity_threshold[/cyan]: low        # Minimum severity: info, low, medium, high
  [cyan]max_file_size_mb[/cyan]: 10           # Skip files larger than this
  [cyan]include_extensions[/cyan]: null       # null = all text files; or [".py", ".js"]
  [cyan]exclude_paths[/cyan]:                 # gitignore-style patterns
    - node_modules/
    - "*.min.js"
    - tests/fixtures/phi/

[bold]audit:[/bold]
  [cyan]database_path[/cyan]: ~/.phi-scanner/audit.db
  [cyan]retention_days[/cyan]: 2192           # HIPAA minimum is 6 years (2192 days)

[bold]ai:[/bold]
  [cyan]enable_claude_review[/cyan]: false    # Phase 7 — disabled by default
  [cyan]confidence_threshold[/cyan]: 0.8     # Only review findings below this

All values shown are defaults. Omit a key to use its default.
"""

# ---------------------------------------------------------------------------
# Ignore patterns
# ---------------------------------------------------------------------------

EXPLAIN_IGNORE_TEXT: str = """\
[bold cyan].phi-scanignore — Exclusion Patterns[/bold cyan]

Create a [cyan].phi-scanignore[/cyan] file in your project root (gitignore syntax).
PhiScan evaluates these patterns at every directory depth.

[bold]Example:[/bold]
  [cyan]# Exclude dependency directories
  node_modules/
  vendor/
  .venv/

  # Exclude minified files
  *.min.js
  *.min.css

  # Exclude test fixture corpus that contains intentional PHI patterns
  tests/fixtures/phi/[/cyan]

[bold]Pattern rules:[/bold]
  Patterns match using gitignore semantics (pathspec library).
  A trailing [cyan]/[/cyan] matches directories only.
  [cyan]**[/cyan] matches any number of path components.
  A leading [cyan]![/cyan] re-includes a previously excluded path.

[bold]Inline suppression (in source files):[/bold]
  [cyan]ssn = "123-45-6789"  # phi-scan:ignore[/cyan]
  [cyan]# phi-scan:ignore-next-line[/cyan]
  [cyan]ssn = "123-45-6789"[/cyan]
  [cyan]# phi-scan:ignore[SSN,MRN]    — suppress only specific types[/cyan]
  [cyan]# phi-scan:ignore-file        — suppress entire file (first 5 lines only)[/cyan]

Suppressed findings are still written to the audit log with [cyan]suppressed=True[/cyan].
"""

# ---------------------------------------------------------------------------
# Reports / output formats
# ---------------------------------------------------------------------------

EXPLAIN_REPORTS_TEXT: str = """\
[bold cyan]Output Formats[/bold cyan]

Select with [cyan]--output <format>[/cyan] or set [cyan]scan.output_format[/cyan] in config.

  [bold]table[/bold]         Rich terminal table. Default. Human-readable.
  [bold]json[/bold]          Machine-readable JSON. Pipe-friendly.
  [bold]sarif[/bold]         SARIF 2.1.0. GitHub Actions, Azure DevOps, Jenkins.
  [bold]csv[/bold]           Comma-separated. Spreadsheet import.
  [bold]junit[/bold]         JUnit XML. CircleCI test summary panels.
  [bold]codequality[/bold]   GitLab Code Quality artifact.
  [bold]gitlab-sast[/bold]   GitLab SAST artifact.
  [bold]pdf[/bold]           Enterprise PDF report.
                Requires [cyan]pip install phi-scan[reports][/cyan].
  [bold]html[/bold]          Interactive HTML report.
                Requires [cyan]pip install phi-scan[reports][/cyan].

[bold]CI/CD platform quick-reference:[/bold]
  GitHub Actions    → sarif   (upload with github/codeql-action/upload-sarif)
  GitLab CI         → codequality or gitlab-sast
  CircleCI          → junit
  Jenkins           → sarif   (Warnings NG plugin)
  Bitbucket         → sarif   (Code Insights)
  Azure DevOps      → sarif
  AWS CodeBuild     → sarif or asff (Security Hub)
"""

# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

EXPLAIN_REMEDIATION_TEXT: str = """\
[bold cyan]Remediation Playbook[/bold cyan]

[bold red]Names[/bold red]
  Replace with faker-generated names in test fixtures.
  Never commit real patient names to version control.

[bold red]Geographic data[/bold red]
  Replace ZIP codes and street addresses with safe placeholders.
  State abbreviations are generally safe under Safe Harbor.

[bold red]Dates[/bold red]
  Replace with synthetic dates or year-only values.
  Year-only is acceptable under the Safe Harbor method.

[bold red]Phone / Fax[/bold red]
  Use NANP reserved block: (NXX) 555-0100 through (NXX) 555-0199.
  These are never assigned to real subscribers.

[bold red]Email addresses[/bold red]
  Use [cyan]patient@example.com[/cyan]. The [cyan]example.com[/cyan] domain is
  RFC 2606 reserved and delivers to nobody.

[bold red]SSN[/bold red]
  Remove immediately. Use faker-generated values or [cyan]000-00-0000[/cyan]
  for test data. Never commit real SSNs.

[bold red]MRN / Health plan / Account numbers[/bold red]
  Replace with synthetic identifiers prefixed with [cyan]TEST-[/cyan]
  to make them self-evident.

[bold red]Certificate / License numbers[/bold red]
  Replace with synthetic values. These can impersonate practitioners.

[bold red]Vehicle identifiers (VIN)[/bold red]
  Use a VIN that intentionally fails the check digit. VINs link to
  registered owners via public databases.

[bold red]Device identifiers (UDI)[/bold red]
  Replace with synthetic UDIs. Device IDs can be traced to patients
  via medical records.

[bold red]URLs[/bold red]
  Remove patient-specific URL path segments. Replace with [cyan]/patients/TEST-ID[/cyan].

[bold red]IP addresses[/bold red]
  Use RFC 5737 documentation ranges:
  [cyan]192.0.2.x[/cyan], [cyan]198.51.100.x[/cyan], [cyan]203.0.113.x[/cyan].

[bold red]Biometric identifiers[/bold red]
  Remove entirely. These cannot be changed if exposed.

[bold red]Genetic identifiers (rs-IDs, VCF)[/bold red]
  Remove from source code. Covered by GINA + GDPR Art. 9 in addition to HIPAA.

[bold red]SUD records (42 CFR Part 2)[/bold red]
  Remove all SUD field names, diagnosis codes, and medication references.
  Disclosure without explicit patient consent violates federal law.

[bold red]Quasi-identifier combinations (ZIP + DOB + sex)[/bold red]
  Generalise at least one field: use 3-digit ZIP prefix, birth year only,
  or remove the combination entirely. Risk is in the combination, not any
  single field.
"""

# ---------------------------------------------------------------------------
# Compliance frameworks
# ---------------------------------------------------------------------------

EXPLAIN_FRAMEWORKS_TEXT: str = """\
[bold cyan]Compliance Frameworks[/bold cyan]

PhiScan annotates findings with applicable regulatory controls. Use the
[cyan]--framework[/cyan] flag to enable one or more frameworks:

  [cyan]phi-scan scan . --framework gdpr,soc2,hitrust[/cyan]

[bold]hipaa[/bold] — always active, no flag needed
  Enforcement: HHS Office for Civil Rights (OCR)
  Penalty: $100–$50,000 per violation; $1.9M annual cap per category
  Citation: 45 CFR §164.514(b)(2) Safe Harbor method — all 18 named identifiers
  must be removed before health information is considered de-identified.

[bold]hitech[/bold] — HITECH Act
  Enforcement: HHS OCR + State Attorneys General
  Penalty: $100–$50,000 per violation; mandatory breach notification
  Citation: 45 CFR §§164.400–414 — HIGH-confidence findings represent "unsecured
  PHI" and trigger mandatory breach notification obligations.

[bold]soc2[/bold] — SOC 2 Type II
  Enforcement: AICPA
  Penalty: Loss of certification; customer contract penalties
  Citation: Trust Services Criteria CC6.1 (access controls), CC6.6 (logical
  access security — PHI in code is a CC6.6 violation), CC6.7 (data disposal).

[bold]hitrust[/bold] — HITRUST CSF v11
  Enforcement: HITRUST Alliance
  Penalty: Loss of certification; contractual penalties with covered entities
  Citation: 07.a (asset inventory), 09.s (monitoring), 01.v (access restriction),
  09.ab (system use monitoring). PHI in source is an uncontrolled asset (07.a).

[bold]nist[/bold] — NIST SP 800-53 Rev 5 + SP 800-122
  Enforcement: NIST (advisory); federal agencies via FISMA
  Penalty: Federal contract termination; FISMA non-compliance
  Citation: SC-28 (protection at rest), PM-22 (PII quality), PT-2 (authority to
  process PII), PT-3 (purposes of processing), SP 800-122 §§2.1–4.1 (PII guide).

[bold]gdpr[/bold] — EU General Data Protection Regulation
  Enforcement: EU Data Protection Authorities (DPAs)
  Penalty: Up to €20M or 4% of global annual turnover (whichever is higher)
  Citation: Art. 4(1) personal data, Art. 4(15) health data, Art. 9 special
  categories (health/genetic/biometric — highest risk), Art. 25 data protection
  by design, Art. 32 security of processing.

[bold]42cfr2[/bold] — 42 CFR Part 2 (Substance Use Disorder records)
  Enforcement: SAMHSA + HHS
  Penalty: Up to $500 per violation (first offense)
  Citation: Stricter than HIPAA — prohibits SUD record disclosure without explicit
  written patient consent, even for treatment referrals. Re-disclosure prohibited.
  Applies only to SUBSTANCE_USE_DISORDER category findings.

[bold]gina[/bold] — Genetic Information Nondiscrimination Act
  Enforcement: EEOC (employment); HHS OCR (health plans)
  Penalty: $50,000–$300,000 per violation (employment context)
  Citation: GINA Title II + 45 CFR §164.514(b)(1). Applies to rs-IDs, VCF data,
  Ensembl gene IDs, and gene panel names.

[bold]cmia[/bold] — California CMIA / SB 3 / AB 825
  Enforcement: California DOJ; private right of action
  Penalty: Up to $250,000 per violation; private right of action
  Citation: Cal. Civ. Code §56.10 (medical information), §56.181 (genomic data).
  Stricter than HIPAA for health apps. Genomic data requires explicit consent.

[bold]bipa[/bold] — Illinois Biometric Information Privacy Act
  Enforcement: Illinois AG; private right of action
  Penalty: $1,000 per negligent violation; $5,000 per intentional violation
  Citation: 740 ILCS 14/15. Covers fingerprints, iris scans, face geometry,
  voiceprints. Written release required before collection. Applies to BIOMETRIC.

[bold]shield[/bold] — New York SHIELD Act
  Enforcement: New York AG
  Penalty: Up to $5,000 per violation; up to $250,000 per incident
  Citation: NY Gen. Bus. Law §899-bb. Broader definition of private information
  than HIPAA. Applies to any entity handling NY residents' data.

[bold]mrpa[/bold] — Texas Medical Records Privacy Act
  Enforcement: Texas AG
  Penalty: Up to $5,000 per violation
  Citation: Tex. Health & Safety Code §181.001–.205. Covers all identifiable
  health information including data not covered by HIPAA.

[bold]Example usage:[/bold]

  [cyan]phi-scan scan . --framework gdpr,soc2         [/cyan]  # federal + EU + SOC 2
  [cyan]phi-scan scan . --framework 42cfr2             [/cyan]  # SUD-specific annotation
  [cyan]phi-scan scan . --framework hipaa,hitech,nist  [/cyan]  # federal compliance stack
  [cyan]phi-scan scan . --framework bipa,cmia,shield   [/cyan]  # state privacy laws
  [cyan]phi-scan scan . -o pdf --framework gdpr,soc2 --report-path report.pdf[/cyan]

Framework annotations appear in the compliance matrix section of PDF and HTML
reports. The HIPAA column is always present.
"""

# ---------------------------------------------------------------------------
# De-identification methods
# ---------------------------------------------------------------------------

EXPLAIN_DEIDENTIFICATION_TEXT: str = """\
[bold cyan]De-identification Methods[/bold cyan]

HIPAA (45 CFR §164.514) defines two methods for de-identifying health information.
PhiScan implements the [bold]Safe Harbor[/bold] method.

[bold]Safe Harbor Method (§164.514(b)(2))[/bold]

  Remove all 18 named identifier categories listed in §164.514(b)(2)(i)(A)–(R):
  names, geographic subdivisions smaller than state, dates (except year), phone
  numbers, fax numbers, email addresses, SSNs, MRNs, health plan beneficiary
  numbers, account numbers, certificate/license numbers, vehicle identifiers,
  device identifiers, URLs, IP addresses, biometric identifiers, full-face
  photographs, and any other unique identifying number or code.

  Additionally (§164.514(b)(2)(ii)), the covered entity must have no actual
  knowledge that the information could identify an individual.

  PhiScan flags all 18 categories as defined by the Safe Harbor method.

[bold]Expert Determination Method (§164.514(b)(1))[/bold]

  A qualified statistician applies generally accepted statistical and scientific
  principles to certify that the risk of identifying an individual is very small.
  The expert's methods and results must be documented and retained.

  [yellow]PhiScan does NOT implement Expert Determination.[/yellow]
  Expert Determination requires a qualified statistician's sign-off. A scan tool
  alone cannot certify that the re-identification risk is "very small" under
  §164.514(b)(1) — that certification must come from a human expert.

[bold]Known Detection Gaps (Safe Harbor)[/bold]

  The following file types are currently skipped. PHI in these formats will not
  be detected by PhiScan and must be reviewed separately:

  [red]PDF documents (.pdf)[/red]
    PDFs may contain embedded forms, clinical notes, or scanned records with PHI.
    Archive inspection for PDF is not yet implemented. Review PDFs out-of-band.

  [red]DICOM files (.dcm)[/red]
    DICOM is the standard medical imaging format and embeds extensive patient
    metadata (patient name, DOB, MRN, study date). DICOM inspection is not yet
    implemented. Use a DICOM anonymisation tool (e.g. DicomCleaner, pydicom).

  [red]Office documents (.docx, .xlsx, .pptx, .doc, .xls, .ppt)[/red]
    Office formats may contain PHI in body text, headers, metadata, or embedded
    objects. Binary Office formats are currently skipped. Review these files
    manually or via a dedicated document scanner.

  [red]Compiled code (.class, .pyc, .exe, .dll, .so)[/red]
    Compiled artefacts may embed string literals from source code that contain
    PHI. PhiScan cannot decompile compiled code. Do not commit compiled
    artefacts that were built from PHI-containing source.

  [yellow]Java archives (.jar, .war)[/yellow]
    The archive scanner inspects .jar and .war files for scannable text resources
    (.properties, .xml, .yml, .json, .conf) but skips embedded .class files.
    PHI in class-level string constants may not be detected.

[bold]Quasi-identifier Re-identification Risk[/bold]

  The Sweeney (2000) study demonstrated that ZIP code + date of birth + sex
  uniquely re-identifies 87% of the US population, even when no single field
  is a named Safe Harbor identifier. PhiScan detects quasi-identifier combinations
  within a 50-line proximity window (Phase 2E.11).

  Generalise at least one field to break re-identification potential:
  use only the first 3 digits of a ZIP code, replace full date of birth
  with birth year only, or remove the combination from the codebase entirely.

[bold]Summary[/bold]

  PhiScan implements:    Safe Harbor (§164.514(b)(2)) — yes
  PhiScan implements:    Expert Determination (§164.514(b)(1)) — no
  Human sign-off needed: Expert Determination always requires a statistician.
  Known gaps:            PDF, DICOM, Office documents, compiled code.
"""
