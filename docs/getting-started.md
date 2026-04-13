# Getting Started with PhiScan

This guide gets you from zero to scanning in under 5 minutes.

---

## Prerequisites

- Python 3.12 or later
- A terminal (bash, zsh, or PowerShell)
- A git repository to scan

---

## 1. Install

The recommended install method is `pipx`, which isolates PhiScan from your project's
virtual environment:

```bash
pipx install phi-scan
```

Verify the install:

```bash
phi-scan --version
```

**Alternative install methods:**

```bash
# uv
uv tool install phi-scan

# pip (inside an activated virtual environment)
pip install phi-scan
```

### Optional detection layers

The base install covers all 18 HIPAA Safe Harbor identifiers plus MBI, DEA numbers,
genetic identifiers, and more — with zero additional dependencies.

Install optional extras for additional detection coverage:

```bash
# NLP named entity recognition (Presidio + spaCy) — catches names and locations in free text
pipx install "phi-scan[nlp]"
phi-scan setup    # downloads the spaCy en_core_web_lg model (~570 MB)

# HL7 v2 segment parsing (PID, NK1, IN1 segments)
pipx install "phi-scan[hl7]"

# All extras
pipx install "phi-scan[full]"
phi-scan setup
```

Missing extras degrade gracefully — PhiScan logs a one-time warning and continues
scanning with the available layers.

---

## 2. Your First Scan

Scan a directory:

```bash
phi-scan scan ./src
```

Scan only files changed since the last commit:

```bash
phi-scan scan --diff HEAD~1
```

Scan a single file with detailed output:

```bash
phi-scan scan --file path/to/patient_handler.py
```

### Reading the output

A clean scan:

```
PhiScan v0.5.0
Scanning: ./src (42 files)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

✓ No PHI/PII detected in 42 files.
```

A scan with findings:

```
PhiScan v0.5.0
Scanning: ./src (42 files)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

┌─────────────────────────────────────────────────────────────────────────┐
│ PHI/PII Findings                                                        │
├──────────────────────────┬──────────┬──────────┬────────────────────────┤
│ File                     │ Line     │ Severity │ Type                   │
├──────────────────────────┼──────────┼──────────┼────────────────────────┤
│ src/api/patient.py       │ 47       │ HIGH     │ SSN                    │
│ src/models/record.py     │ 12       │ MEDIUM   │ EMAIL_ADDRESS          │
└──────────────────────────┴──────────┴──────────┴────────────────────────┘

2 findings. Exit code: 1
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings |
| `1` | Violation — PHI/PII detected |
| `2` | Error — invalid configuration or CLI argument |

---

## 3. Configure PhiScan

Generate a configuration file with sensible defaults:

```bash
phi-scan config init
```

This writes `.phi-scanner.yml` to your working directory. Key settings:

```yaml
scan:
  confidence_threshold: 0.7   # suppress low-confidence pattern matches
  severity_threshold: low      # info | low | medium | high
  max_file_size_mb: 10

audit:
  database_path: "~/.phi-scanner/audit.db"
  retention_days: 2192         # 6 years (HIPAA §164.530(j))
```

PhiScan looks for `.phi-scanner.yml` in the current working directory. If not found,
it uses built-in defaults. Commit this file to your repository so all team members
use the same settings.

Full configuration reference: [configuration.md](configuration.md)

---

## 4. Exclude Files and Directories

Create `.phi-scanignore` in your repository root using gitignore-style patterns:

```
# Test fixtures that intentionally contain synthetic PHI
tests/fixtures/phi/

# Third-party vendor code
vendor/
node_modules/

# Build artifacts
dist/
build/
```

You can also suppress individual findings inline:

```python
patient_id = get_test_id()           # phi-scan:ignore
mrn = load_fixture_mrn()             # phi-scan:ignore[MRN]
```

```python
# phi-scan:ignore-next-line
SSN_REGEX_PATTERN = r"\d{3}-\d{2}-\d{4}"
```

Full suppression syntax: [ignore-patterns.md](ignore-patterns.md)

---

## 5. Block Commits Automatically

Install PhiScan as a git pre-commit hook so it runs on every commit:

```bash
phi-scan install-hook
```

PHI found → commit blocked. The hook runs `phi-scan scan --diff HEAD` so only
changed files are scanned, keeping commit times fast.

To uninstall:

```bash
phi-scan uninstall-hook
```

**For teams:** use the pre-commit framework instead so the hook configuration is
committed to the repository and shared automatically. See [ci-cd-integration.md](ci-cd-integration.md).

---

## 6. Adopt Incrementally with Baseline Mode

If your codebase already has findings you've accepted, baseline mode lets you adopt
PhiScan without blocking every existing CI run.

Snapshot current findings as the accepted baseline:

```bash
phi-scan baseline create
```

This writes `.phi-scanbaseline` to your working directory. Commit it.

Now run with baseline mode — only new findings block CI:

```bash
phi-scan scan --baseline
```

Existing findings are shown as dimmed in the output but do not affect the exit code.
New findings still produce exit code 1.

See baseline statistics:

```bash
phi-scan baseline show
phi-scan baseline diff      # new vs. resolved since baseline was created
```

---

## 7. Explore Detection Layers

PhiScan explains its own detection logic:

```bash
phi-scan explain hipaa       # all 18 HIPAA Safe Harbor categories
phi-scan explain detection   # how each layer works, confidence scoring
phi-scan explain config      # full configuration reference in the terminal
```

---

## Next Steps

| Document | Description |
|---|---|
| [configuration.md](configuration.md) | Complete `.phi-scanner.yml` reference |
| [ignore-patterns.md](ignore-patterns.md) | `.phi-scanignore` syntax and suppression comments |
| [ci-cd-integration.md](ci-cd-integration.md) | GitHub Actions, GitLab CI, Jenkins, and more |
| [troubleshooting.md](troubleshooting.md) | Common issues and debug tips |
| [security.md](security.md) | PHI protection model and audit log guarantees |
