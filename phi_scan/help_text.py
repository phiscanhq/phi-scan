"""Explain command content constants (Phase 2).

All explain topic text lives here. Each constant is the single source of truth
for that topic — the CLI explain commands render these constants; documentation
generation can import them directly rather than duplicating content.

Rich markup is used throughout: [bold], [cyan], [yellow], [red], [green].
"""

__all__ = [
    "EXPLAIN_CONFIDENCE_TEXT",
    "EXPLAIN_CONFIG_TEXT",
    "EXPLAIN_DETECTION_TEXT",
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
