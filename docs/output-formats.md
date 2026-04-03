# Output Formats

PhiScan supports nine output formats to cover every use case from interactive
developer review to automated CI/CD pipeline integration.

Select a format with `--output <format>` on any `scan` command:

```bash
phi-scan scan . --output json
phi-scan scan . --output sarif --report-path results.sarif
```

Use `phi-scan explain reports` for a quick in-terminal summary.

---

## Format Overview

| Format | Flag | Best For | Writes to |
|---|---|---|---|
| `table` | (default) | Interactive developer review | Terminal (Rich) |
| `json` | `--output json` | API consumers, custom tooling | stdout or `--report-path` |
| `sarif` | `--output sarif` | GitHub Code Scanning, CI annotations | stdout or `--report-path` |
| `csv` | `--output csv` | Spreadsheet analysis, compliance exports | stdout or `--report-path` |
| `junit` | `--output junit` | Jenkins, CircleCI, TeamCity | stdout or `--report-path` |
| `codequality` | `--output codequality` | GitLab Code Quality artifact | stdout or `--report-path` |
| `gitlab-sast` | `--output gitlab-sast` | GitLab SAST artifact | stdout or `--report-path` |
| `pdf` | `--output pdf` | Compliance audits, executive reports | `--report-path` (required) |
| `html` | `--output html` | Self-contained browser reports | `--report-path` (required) |

---

## `table` — Rich Terminal (Default)

**When to use:** Interactive use, pull request review, local development.

The table format renders a full Rich terminal UI with:

- ASCII banner and scan header
- Live progress bar during scanning
- File tree showing affected directories
- Findings table with colour-coded severity badges
- Code context panels showing the flagged line with `[REDACTED]` markers
- Executive summary: risk level, severity counts, scan duration

The Rich UI is automatically suppressed when stdout is piped to another
process or when using a non-table output format.

```bash
# Default interactive output
phi-scan scan ./src

# Suppress banner and progress bar (still shows findings table)
phi-scan scan ./src --quiet
```

### Sample Output

```
  ██████╗ ██╗  ██╗██╗    ███████╗ ██████╗ █████╗ ███╗  ██╗
  ██╔══██╗██║  ██║██║    ██╔════╝██╔════╝██╔══██╗████╗ ██║
  ██████╔╝███████║██║    ███████╗██║     ███████║██╔██╗██║
  ██╔═══╝ ██╔══██║██║    ╚════██║██║     ██╔══██║██║╚████║
  ██║     ██║  ██║██║    ███████║╚██████╗██║  ██║██║ ╚███║
  ╚═╝     ╚═╝  ╚═╝╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝

 ┌────────────────────────────────────────────────────┐
 │  2 findings  │  CRITICAL risk  │  0.42s  │  14 files │
 └────────────────────────────────────────────────────┘

  File              Line  Entity  Severity   Confidence
  src/fixtures.py    42   SSN     ■ HIGH     0.97
  config/test.yml     8   PHONE   ■ MEDIUM   0.88
```

---

## `json` — Structured JSON

**When to use:** Custom tooling, dashboards, post-processing pipelines.

Outputs a single JSON object with the full scan result.

```bash
phi-scan scan . --output json | jq '.findings[].severity'
phi-scan scan . --output json --report-path scan-results.json
```

### Schema

```json
{
  "is_clean": false,
  "risk_level": "critical",
  "files_scanned": 14,
  "files_with_findings": 2,
  "scan_duration": 0.42,
  "severity_counts": {
    "high": 1,
    "medium": 1,
    "low": 0,
    "info": 0
  },
  "findings": [
    {
      "file_path": "src/fixtures.py",
      "line_number": 42,
      "entity_type": "SSN",
      "hipaa_category": "ssn",
      "confidence": 0.97,
      "severity": "high",
      "detection_layer": "regex",
      "value_hash": "b3d3e5f...",
      "code_context": "    test_ssn = \"[REDACTED]\"",
      "remediation_hint": "Replace with a synthetic value using phi-scan fix ..."
    }
  ]
}
```

### Notes

- `value_hash` is SHA-256 of the matched PHI value — raw values are never included
- `code_context` contains the source line with the PHI replaced by `[REDACTED]`
- `findings` is an empty array (not null) when the scan is clean

---

## `sarif` — Static Analysis Results Format 2.1

**When to use:** GitHub Advanced Security, Azure DevOps, any SARIF-compatible tool.

SARIF (Static Analysis Results Interchange Format v2.1) is the standard
format for static analysis tools. PhiScan produces fully valid SARIF output
that integrates with GitHub Code Scanning and Azure DevOps.

```bash
phi-scan scan . --output sarif --report-path phi-scan-results.sarif
```

### GitHub Actions Integration

```yaml
# .github/workflows/phi-scan.yml
- name: PHI Scan
  run: phi-scan scan . --output sarif --report-path phi-scan.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: phi-scan.sarif
  if: always()
```

Findings appear as inline annotations on pull request diffs in GitHub.

### SARIF Structure

Each finding maps to a SARIF `result` with:
- `ruleId`: entity type (e.g., `SSN`, `PHONE`)
- `level`: `error` (HIGH), `warning` (MEDIUM), `note` (LOW/INFO)
- `locations`: file path and line number
- `message.text`: remediation hint

---

## `csv` — Comma-Separated Values

**When to use:** Spreadsheet analysis, compliance reporting, data import.

```bash
phi-scan scan . --output csv > findings.csv
phi-scan scan . --output csv --report-path findings.csv
```

### CSV Columns

```
file_path,line_number,entity_type,hipaa_category,confidence,severity,detection_layer,value_hash,code_context,remediation_hint
src/fixtures.py,42,SSN,ssn,0.97,high,regex,b3d3e5f...,"    test_ssn = ""[REDACTED]""","Replace SSN with synthetic value..."
```

### Notes

- Fields containing commas or quotes are enclosed in double quotes per RFC 4180
- The header row is always included
- One row per finding; no summary rows

---

## `junit` — JUnit XML

**When to use:** Jenkins, CircleCI, TeamCity, or any CI system that parses
JUnit test results.

```bash
phi-scan scan . --output junit --report-path phi-scan-results.xml
```

Each finding is represented as a JUnit `<failure>` test case. A clean scan
produces a `<testsuite>` with zero failures. CI systems that parse JUnit
XML will show failed "tests" for each PHI finding.

### Jenkins Integration

```groovy
// Jenkinsfile
stage('PHI Scan') {
    steps {
        sh 'phi-scan scan . --output junit --report-path phi-scan.xml'
    }
    post {
        always {
            junit 'phi-scan.xml'
        }
    }
}
```

---

## `codequality` — GitLab Code Quality

**When to use:** GitLab Code Quality widget in merge requests.

```bash
phi-scan scan . --output codequality --report-path gl-code-quality-report.json
```

### GitLab CI Integration

```yaml
# .gitlab-ci.yml
phi-scan:
  script:
    - phi-scan scan . --output codequality --report-path gl-code-quality-report.json
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
```

Code Quality violations appear as inline comments on GitLab merge requests.

---

## `gitlab-sast` — GitLab SAST

**When to use:** GitLab Security Dashboard and vulnerability management.

```bash
phi-scan scan . --output gitlab-sast --report-path gl-sast-report.json
```

### GitLab CI Integration

```yaml
# .gitlab-ci.yml
phi-scan-sast:
  script:
    - phi-scan scan . --output gitlab-sast --report-path gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

Findings appear in the GitLab Security Dashboard and can be triaged,
assigned, and tracked through GitLab's vulnerability management workflow.

---

## `pdf` — Professional PDF Report

**When to use:** Compliance audits, security assessments, executive briefings,
regulator submissions.

`--report-path` is required for PDF output.

```bash
phi-scan scan . --output pdf --report-path phi-scan-report.pdf
```

### PDF Report Contents

1. **Cover page** — Scan target, timestamp, PhiScan version, HIPAA Safe Harbor badge
2. **Executive summary** — Risk level, finding counts by severity, scan coverage
3. **Visual charts** — Severity distribution pie chart, findings by category bar chart,
   historical trend line (from audit database)
4. **Findings table** — Paginated, colour-coded by severity, with file paths, line numbers,
   entity types, and confidence scores
5. **Compliance matrix** — When `--framework` is used, maps findings to applicable controls
6. **Remediation guidance** — Per-category playbook with recommended fixes

### Compliance Framework Annotations in PDF

```bash
phi-scan scan . --output pdf --report-path report.pdf --framework gdpr,hipaa,soc2
```

The PDF includes a compliance matrix section showing which frameworks are
violated by which categories of findings.

---

## `html` — Self-Contained HTML Report

**When to use:** Sharing reports via email or web, browser-based review,
documentation portals.

`--report-path` is required for HTML output.

```bash
phi-scan scan . --output html --report-path phi-scan-report.html
```

### HTML Report Features

- **Self-contained single file** — no external dependencies, no network calls
  required to view. All charts are embedded as base64 PNG
- **Responsive layout** — readable on desktop and tablet
- **Colour-coded severity badges** — HIGH (red), MEDIUM (yellow), LOW (green), INFO (grey)
- **Collapsible code context sections** — click to expand the source line for each finding
- **Print-friendly CSS** — suitable for printing or saving as PDF from the browser

---

## Writing Reports to File

All non-table formats can write to a file using `--report-path`:

```bash
phi-scan scan . --output json --report-path reports/$(date +%Y%m%d)-scan.json
```

For `table` format, the Rich terminal output can be captured with standard
shell redirection, but use `--output json` or `--output csv` for
machine-readable output instead.

---

## CI/CD: Choosing the Right Format

| CI Platform | Recommended Format |
|---|---|
| GitHub Actions | `sarif` (uploads to Code Scanning) or `junit` |
| GitLab CI | `codequality` or `gitlab-sast` |
| Jenkins | `junit` |
| CircleCI | `junit` |
| Azure DevOps | `sarif` or `junit` |
| Custom pipeline | `json` |
| Compliance audit | `pdf` |
| Executive report | `pdf` or `html` |

See `docs/ci-cd-integration.md` for complete pipeline configuration examples.
