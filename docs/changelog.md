# Changelog

All notable changes to PhiScan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Phase 4D test suite** — 163 tests covering PDF generation, HTML structure,
  chart PNG output, compliance control mapping, multi-framework annotation,
  executive summary accuracy, remediation coverage, and output format dispatch

---

## [0.4.0] — 2026-04-02 (Phase 4A–4C)

### Added

- **Multi-framework compliance mapping** (`phi_scan/compliance.py`)
  - 12 supported compliance frameworks: HIPAA, HITECH, SOC 2 Type II,
    HITRUST CSF v11, NIST SP 800-53 Rev 5 / SP 800-122, GDPR, 42 CFR Part 2,
    GINA, California CMIA, Illinois BIPA, New York SHIELD Act, Texas MRPA
  - Every `PhiCategory` finding is annotated with applicable controls from
    each enabled framework
  - `ComplianceControl` frozen dataclass: `framework`, `control_id`,
    `control_name`, `citation` — regulatory metadata only, no PHI stored
  - Module-level integrity assert: `FRAMEWORK_METADATA` must cover every
    `ComplianceFramework` member — fails loudly at import time if a new
    framework is added without metadata
- **`--framework` CLI flag** — opt-in compliance framework annotation:
  ```bash
  phi-scan scan . --framework gdpr,soc2,hitrust
  ```
  HIPAA is always active. All other frameworks are opt-in.
- **`phi-scan explain frameworks`** — new explain topic listing all 12
  supported frameworks with enforcement body, penalty ranges, and
  regulatory description
- **`phi-scan explain deidentification`** — Safe Harbor vs. Expert
  Determination methods; known detection gaps; recommended remediation
  workflow
- **PDF/HTML compliance matrix** — when `--framework` is used, reports
  include a per-finding compliance control matrix
- **`InvalidFrameworkError`** — domain-specific exception for unrecognised
  `--framework` tokens; subclasses `ValueError` for broad compatibility;
  caught precisely in CLI to avoid masking unrelated errors
- **Phase 4C documentation suite** (this release):
  - `docs/confidence-scoring.md` — confidence bands, per-layer ranges, tuning
  - `docs/hipaa-identifiers.md` — all 18 Safe Harbor categories with detection notes
  - `docs/detection-layers.md` — four-layer architecture with installation guide
  - `docs/output-formats.md` — all 9 formats with CI/CD integration examples
  - `docs/remediation-guide.md` — per-category playbook and `phi-scan fix` workflow
  - `docs/compliance-frameworks.md` — complete regulatory reference for all 12 frameworks
  - `docs/de-identification.md` — updated: Phase 4B compliance mapping complete
  - `docs/known-limitations.md` — updated: advisory scope, legal boundaries
  - `docs/plugin-developer-guide.md` — custom recognizer development guide
  - `CONTRIBUTING.md` — contribution standards, development setup, PR process

### Changed

- `ScanFinding` and audit output include `framework_annotations` when
  `--framework` is specified
- PDF and HTML reports include compliance matrix section when frameworks are enabled
- `phi-scan explain` topics updated to reference compliance framework documentation

### Security

- All compliance annotation operates on `PhiCategory` enum values and
  pre-built `ComplianceControl` constants — no raw PHI flows through the
  compliance mapping layer at any point

---

## [0.3.0] — 2026-03-30 (Phases 2–3C)

> **Note:** There is no `0.2.0` release. Phases 2 and 3 were developed
> incrementally on feature branches and shipped together as `0.3.0`.
> Version `0.1.0` was the initial scaffold; all detection engine, CLI,
> and output-format work accumulated in `0.3.0`.

### Added

- **Detection engine — 4 layers:**
  - Layer 1: Regex pattern registry covering all 18 HIPAA Safe Harbor
    identifiers plus MBI, HICN, DEA, genetic identifiers (rs-IDs, VCF,
    Ensembl), SUD field names, age > 90, quasi-identifier combinations
    (ZIP + DOB + sex), and NPI validation
  - Layer 2: NLP named entity recognition via Presidio + spaCy
    (`phi-scan[nlp]` optional extra)
  - Layer 3: FHIR R4 field-name scanning and HL7 v2 segment scanning
    (PID, NK1, IN1) via `phi-scan[hl7]` optional extra
  - Layer 4: Quasi-identifier combination detection (ZIP + DOB, NAME +
    DATE, AGE > 90 + GEOGRAPHIC, colocated combinations within 50 lines)
- **CLI commands:** `scan`, `scan --diff`, `scan --file`, `watch`, `report`,
  `history`, `init`, `setup`, `fix`, `explain`, `baseline`, `install-hook`,
  `uninstall-hook`, `config init`, `dashboard`, `plugins list`
- **Output formats:** `table`, `json`, `csv`, `sarif`, `junit`,
  `codequality`, `gitlab-sast`, `pdf`, `html`
- **Baseline management:** `phi-scan baseline create|show|clear|update|diff`
  — incremental adoption in existing codebases; baseline entries expire
  after 90 days for mandatory quarterly remediation reviews
- **Auto-fix engine:** `phi-scan fix --dry-run|--apply|--patch` —
  deterministic synthetic data replacement using SHA-256-seeded values;
  referential integrity preserved (same PHI → same replacement)
- **Inline suppression:** `# phi-scan:ignore`, `# phi-scan:ignore[TYPE]`,
  `# phi-scan:ignore-next-line`, `# phi-scan:ignore-file`
  — language-aware prefixes (Python `#`, JS `//`, SQL `--`, HTML `<!-- -->`)
- **SQLite audit log:** immutable HIPAA-compliant scan history at
  `~/.phi-scanner/audit.db`; SHA-256 hashes only, raw PHI values never stored;
  6-year retention per HIPAA §164.530(j)
- **Content-hash scan cache:** skips unchanged files on repeat scans;
  bypass with `--no-cache`
- **Pre-commit integration:** `.pre-commit-hooks.yaml` + `phi-scan install-hook`
- **Rich terminal UI:** progress bar, findings table with colour-coded
  severity, file tree, code context panels; auto-suppressed for piped output
- **PHI redaction at detection layer:** matched values hashed to SHA-256
  before `ScanFinding` is constructed — raw PHI never stored or displayed
- **Variable-name context boost:** +0.15 confidence when assignment LHS
  matches PHI-suggestive variable name (mrn, ssn, dob, patient, etc.)
- **Graceful degradation:** NLP, FHIR, HL7 layers each log a warning and
  return empty results when their optional dependency group is not installed

### Breaking Changes

None. This is the first public release.

---

## [0.1.0] — 2026-03-01 (Phase 1)

### Added

- Project scaffolding: `pyproject.toml`, CI workflows (lint, typecheck,
  test, release, Claude PR review), MIT license, `README.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`
- Typer CLI skeleton with Rich terminal UI and pyfiglet ASCII banner
- Structured logging (`--log-level`, `--log-file`)
- YAML configuration loading and validation (`.phi-scanner.yml`)
- Git diff file extraction (`--diff` mode)
- `.phi-scanignore` exclusion pattern support (gitignore-style via pathspec)

---

[Unreleased]: https://github.com/joeyessak/phi-scan/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/joeyessak/phi-scan/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/joeyessak/phi-scan/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/joeyessak/phi-scan/releases/tag/v0.1.0
