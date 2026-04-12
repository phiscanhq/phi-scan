# PhiScan

[![PyPI version](https://img.shields.io/pypi/v/phi-scan.svg)](https://pypi.org/project/phi-scan/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/joeyessak/phi-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/joeyessak/phi-scan/actions/workflows/ci.yml)

**HIPAA & FHIR compliant PHI/PII scanner for CI/CD pipelines. Local execution only — no PHI ever leaves your infrastructure (unless AI review is explicitly enabled).**

PhiScan scans source code, configuration files, and structured data for Protected Health Information (PHI) and Personally Identifiable Information (PII) before it reaches your main branch. It integrates into any CI/CD pipeline and blocks pull requests that expose patient data.

---

## Quick Start

```bash
# 1. Install
pipx install phi-scan

# 2. Scan your project
phi-scan scan ./src

# 3. Block commits automatically
phi-scan install-hook
```

PHI found → exit code 1 → commit blocked.

---

## Why PhiScan

- **Local execution only.** All scanning runs inside your pipeline runner or developer machine. No data is sent to any external service by default. The optional AI confidence review layer sends redacted code structure (never raw PHI values) to the configured AI provider only when explicitly enabled via `ai.enable_ai_review: true`.
- **4 detection layers.** Regex (all 18 HIPAA Safe Harbor categories), NLP named entity recognition, FHIR R4 field scanning, and HL7 v2 segment parsing work together.
- **Zero configuration required.** Sensible defaults work out of the box. Tune with a single YAML file.
- **Baseline mode.** Adopt incrementally in existing codebases — only new findings block CI.
- **9 output formats.** Table, JSON, SARIF, CSV, JUnit, GitLab Code Quality, GitLab SAST, PDF, and HTML enterprise reports.
- **Inline suppression.** `# phi-scan:ignore` comments let developers acknowledge false positives without disabling the scanner.
- **HIPAA audit trail.** Every scan is recorded in an immutable SQLite log. SHA-256 hashes only — raw PHI values are never stored.
- **Free forever.** All detection layers, output formats, CI integrations, compliance annotations, baseline mode, audit trail, and the plugin API ship in the MIT-licensed Community tier and will never be paywalled or intentionally degraded. See [docs/community-pro-cloud-matrix.md](docs/community-pro-cloud-matrix.md) for the full feature boundary.

---

## Installation

```bash
# Recommended: pipx (isolated environment)
pipx install phi-scan

# Or: uv
uv tool install phi-scan

# Or: pip
pip install phi-scan
```

**Optional detection layers:**

```bash
# NLP named entity recognition (Presidio + spaCy, ~550 MB)
pipx install "phi-scan[nlp]"
phi-scan setup           # downloads spaCy en_core_web_lg model

# HL7 v2 segment parsing
pipx install "phi-scan[hl7]"

# Everything
pipx install "phi-scan[full]"
```

---

## Commands

| Command | Description |
|---|---|
| `phi-scan scan [PATH]` | Scan a directory or file for PHI/PII |
| `phi-scan scan --diff HEAD~1` | Scan only files changed since a git ref |
| `phi-scan scan --file handler.py` | Scan a single file with detailed output |
| `phi-scan scan --output FORMAT` | Output as JSON, SARIF, CSV, JUnit, PDF, HTML, etc. |
| `phi-scan scan --framework gdpr,soc2` | Annotate findings with compliance framework controls |
| `phi-scan scan --baseline` | Only report NEW findings not in baseline |
| `phi-scan baseline create` | Snapshot current findings as accepted baseline |
| `phi-scan baseline show` | Display baseline statistics |
| `phi-scan baseline diff` | Show new vs. resolved findings against baseline |
| `phi-scan watch ./src` | Live file watcher — re-scans on every save |
| `phi-scan install-hook` | Install as git pre-commit hook |
| `phi-scan uninstall-hook` | Remove the pre-commit hook |
| `phi-scan config init` | Generate a default `.phi-scanner.yml` |
| `phi-scan explain hipaa` | Explain HIPAA Safe Harbor categories |
| `phi-scan explain frameworks` | List all 12 supported compliance frameworks |
| `phi-scan explain deidentification` | Safe Harbor vs Expert Determination methods |
| `phi-scan explain detection` | Explain detection layers and confidence scores |
| `phi-scan explain config` | Full configuration reference in the terminal |
| `phi-scan report` | Display last scan results from audit log |
| `phi-scan history --last 30d` | Query scan history |
| `phi-scan dashboard` | Real-time scan statistics dashboard |
| `phi-scan plugins list` | List all discovered recognizer plugins |

Run `phi-scan COMMAND --help` for full flag documentation.

---

## Output Formats

| Format | Flag | Use Case | CI/CD Platform |
|---|---|---|---|
| `table` | *(default)* | Rich terminal UI | Local development |
| `json` | `--output json` | Programmatic consumption | Any |
| `sarif` | `--output sarif` | Static analysis results | GitHub Code Scanning, Azure DevOps |
| `csv` | `--output csv` | Spreadsheet / audit reports | Excel, data warehouses |
| `junit` | `--output junit` | Test result summary | CircleCI, Jenkins, Azure Pipelines |
| `codequality` | `--output codequality` | MR inline annotations | GitLab |
| `gitlab-sast` | `--output gitlab-sast` | Security dashboard | GitLab |
| `pdf` | `--output pdf` | Enterprise compliance reports | Auditors, legal teams |
| `html` | `--output html` | Shareable browser-based reports | Stakeholder distribution |

Write to a file with `--report-path`:

```bash
phi-scan scan . --output sarif --report-path phi-scan-results.sarif
```

PDF and HTML reports include a compliance control matrix when `--framework` is specified.

---

## Compliance Framework Annotation

PhiScan maps every PHI finding to applicable regulatory controls using the
`--framework` flag. HIPAA is always active. All other frameworks are opt-in.

```bash
# Annotate with GDPR and SOC 2
phi-scan scan . --framework gdpr,soc2

# Full multi-framework compliance report (PDF)
phi-scan scan . --framework gdpr,soc2,hitrust,nist --output pdf --report-path report.pdf
```

**Supported frameworks:**

| Flag | Framework | Enforcement Body |
|---|---|---|
| `hipaa` | HIPAA Privacy & Security Rules | HHS Office for Civil Rights |
| `hitech` | HITECH Act | HHS / State AGs |
| `soc2` | SOC 2 Type II (CC6 controls) | AICPA |
| `hitrust` | HITRUST CSF v11 | HITRUST Alliance |
| `nist` | NIST SP 800-53 Rev 5 / SP 800-122 | NIST |
| `gdpr` | GDPR (EU) 2016/679 | EU Data Protection Authorities |
| `42cfr2` | 42 CFR Part 2 (SUD records) | SAMHSA |
| `gina` | Genetic Information Nondiscrimination Act | EEOC / HHS |
| `cmia` | California CMIA | California AG |
| `bipa` | Illinois BIPA | Illinois AG |
| `shield` | New York SHIELD Act | New York AG |
| `mrpa` | Texas Medical Records Privacy Act | Texas AG |

Run `phi-scan explain frameworks` for penalty ranges and full regulatory descriptions.
See [docs/compliance-frameworks.md](docs/compliance-frameworks.md) for the complete reference.

---

## Optional Extras

| Extra | Install | Adds |
|---|---|---|
| `nlp` | `pip install "phi-scan[nlp]"` | Presidio + spaCy NER — catches names and locations in free text |
| `fhir` | `pip install "phi-scan[fhir]"` | fhir.resources schema validation (FHIR R4 field scanning is always on) |
| `hl7` | `pip install "phi-scan[hl7]"` | HL7 v2 segment parsing (PID, NK1, IN1 segments) |
| `reports` | `pip install "phi-scan[reports]"` | PDF and HTML enterprise reports (Phase 4) |
| `full` | `pip install "phi-scan[full]"` | All of the above |

Missing extras degrade gracefully — PhiScan logs a one-time warning and continues scanning with the available layers.

---

## Configuration

Generate a config file:

```bash
phi-scan config init
```

Key options in `.phi-scanner.yml`:

```yaml
version: 1

scan:
  confidence_threshold: 0.7   # 0.0–1.0; findings below this score are suppressed
  severity_threshold: low      # info | low | medium | high
  max_file_size_mb: 10

audit:
  database_path: "~/.phi-scanner/audit.db"
  retention_days: 2192         # 6 years (HIPAA §164.530(j))
```

Full reference: [docs/configuration.md](docs/configuration.md)

---

## Suppressing False Positives

```python
patient_id = get_test_id()           # phi-scan:ignore
mrn = load_fixture_mrn()             # phi-scan:ignore[MRN]
```

```python
# phi-scan:ignore-next-line
SSN_REGEX_PATTERN = r"\d{3}-\d{2}-\d{4}"
```

Add `# phi-scan:ignore-file` in the first 5 lines to suppress an entire file.

Full syntax: [docs/ignore-patterns.md](docs/ignore-patterns.md)

---

## CI/CD Integration

**Pre-commit framework (teams):**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/joeyessak/phi-scan
    rev: v0.4.0
    hooks:
      - id: phi-scan
```

**GitHub Actions:**

```yaml
- name: Scan for PHI
  run: |
    pipx install phi-scan
    phi-scan scan --diff HEAD~1 --output sarif --report-path phi-scan.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: phi-scan.sarif
```

**GitHub Actions with compliance annotation:**

```yaml
- name: Scan for PHI (HIPAA + GDPR + SOC 2)
  run: |
    pipx install "phi-scan[reports]"
    phi-scan scan . --framework gdpr,soc2 --output pdf --report-path phi-scan-report.pdf

- name: Upload compliance report
  uses: actions/upload-artifact@v4
  with:
    name: phi-scan-compliance-report
    path: phi-scan-report.pdf
```

Copy-paste templates for all CI platforms: [docs/ci-cd-integration.md](docs/ci-cd-integration.md)

---

## Documentation

| Document | Description |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | Install, first scan, understanding output (5-minute guide) |
| [docs/configuration.md](docs/configuration.md) | Complete `.phi-scanner.yml` reference |
| [docs/hipaa-identifiers.md](docs/hipaa-identifiers.md) | All 18 HIPAA Safe Harbor categories with detection notes |
| [docs/detection-layers.md](docs/detection-layers.md) | Four-layer detection architecture and confidence scoring |
| [docs/confidence-scoring.md](docs/confidence-scoring.md) | Confidence bands, per-layer ranges, tuning guide |
| [docs/output-formats.md](docs/output-formats.md) | All 9 output formats with CI/CD integration examples |
| [docs/compliance-frameworks.md](docs/compliance-frameworks.md) | Complete regulatory reference for all 12 frameworks |
| [docs/remediation-guide.md](docs/remediation-guide.md) | Per-category PHI removal playbook and `phi-scan fix` workflow |
| [docs/de-identification.md](docs/de-identification.md) | Safe Harbor vs Expert Determination; regulatory scope |
| [docs/plugin-api-v1.md](docs/plugin-api-v1.md) | Plugin API v1 compatibility, deprecation policy, and authoring constraints |
| [docs/plugin-developer-guide.md](docs/plugin-developer-guide.md) | Custom recognizer development guide |
| [docs/plugin-hooks-v1_1-design.md](docs/plugin-hooks-v1_1-design.md) | Suppressor and output sink plugin hooks (v1.1 design) |
| [docs/ci-adapter-contract.md](docs/ci-adapter-contract.md) | CI adapter split interface contract and rollout plan |
| [docs/community-pro-cloud-matrix.md](docs/community-pro-cloud-matrix.md) | Community / Pro / Cloud feature boundary matrix |
| [docs/release-versioning-policy.md](docs/release-versioning-policy.md) | Release cadence, versioning scheme, and deprecation process |
| [docs/lts-eol-policy.md](docs/lts-eol-policy.md) | Long-term support and end-of-life policy |
| [docs/ignore-patterns.md](docs/ignore-patterns.md) | `.phi-scanignore` syntax, suppression comments |
| [docs/ci-cd-integration.md](docs/ci-cd-integration.md) | CI/CD platform copy-paste templates |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common issues, FAQ, debug tips |
| [docs/known-limitations.md](docs/known-limitations.md) | Binary formats, advisory scope boundaries |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, standards, PR process |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting policy |
| [docs/PROGRAM_SCORECARD.md](docs/PROGRAM_SCORECARD.md) | Public-repo quality scorecard (10/10 criteria and status) |

---

## Plugin Development

PhiScan supports third-party recognizer plugins that extend the scanner
with custom detection logic. Plugins register under the `phi_scan.plugins`
entry-point group and are discovered automatically at startup.

```bash
# List all installed plugins and their status
phi-scan plugins list
```

Plugins MUST declare `plugin_api_version = "1.0"` to match the current
host version. Incompatible or invalid plugins are skipped with a warning;
the core scanner continues functioning.

See [docs/plugin-api-v1.md](docs/plugin-api-v1.md) for the full
compatibility policy, deprecation rules, and a minimal plugin example.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings (or all findings covered by baseline) |
| `1` | Violation — PHI/PII detected |
| `2` | Error — invalid configuration or CLI argument |

---

## Contributing

- All changes arrive via pull request — no direct pushes to `main`
- CI must pass: lint (`ruff`), type check (`mypy`), tests (`pytest`) on Python 3.12 × ubuntu / macos / windows
- Every PR receives an automated Claude code review
- See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code standards, and PR process
- See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

## License

MIT — see [LICENSE](LICENSE)
