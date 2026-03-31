# Troubleshooting

Common issues, error messages, and debug tips.

---

## False Positives

### "Too many findings in my own source code"

**Symptom:** PhiScan reports hundreds of `HEALTH_PLAN_NUMBER` or similar findings in
Python files, YAML configs, or documentation.

**Cause:** Broad patterns like `HEALTH_PLAN_NUMBER` match any 8–20 character alphanumeric
string when context keywords are absent. The default confidence floor for context-absent
matches (`0.65`) is below the default threshold of `0.7`, so they should be suppressed
automatically.

**Fix 1: Ensure your confidence threshold is 0.7 or higher**

```yaml
# .phi-scanner.yml
scan:
  confidence_threshold: 0.7
```

**Fix 2: Exclude scanner/infrastructure source directories**

If your repository contains PHI pattern strings as Python literals (e.g. a custom
scanner), add the source directory to `.phi-scanignore`:

```
# .phi-scanignore
phi_scan/
```

**Fix 3: Exclude documentation and CI configuration**

```
# .phi-scanignore
*.md
.github/
docs/
```

---

### "My test fixtures are flagged"

**Symptom:** `tests/fixtures/` produces findings even though the data is synthetic.

**Fix:** Add the fixture directory to `.phi-scanignore`:

```
# .phi-scanignore
tests/fixtures/phi/
```

Or suppress the entire fixture file in its first 5 lines:

```python
# phi-scan:ignore-file
# Synthetic PHI fixture — all values are fictional.
```

---

### "A pattern name in source code is flagged"

**Symptom:** A string like `"health_plan_number"` in a Python comment or variable name
triggers a finding.

**Fix:** Use an inline suppression on that line:

```python
HEALTH_PLAN_NUMBER_PATTERN = r"[A-Z0-9]{8,20}"  # phi-scan:ignore[HEALTH_PLAN_NUMBER]
```

---

## False Negatives

### "Real PHI was not detected"

**Symptom:** A file containing real PHI passes with exit code 0.

**Possible causes:**

1. **The file is excluded** — check `.phi-scanignore` and `exclude_paths` in
   `.phi-scanner.yml`. Run with `--verbose` to see which files are scanned.

2. **The confidence threshold is too high** — lower it:

   ```yaml
   scan:
     confidence_threshold: 0.5
   ```

3. **The severity threshold excludes the finding type** — lower it:

   ```yaml
   scan:
     severity_threshold: low
   ```

4. **The value is in a binary file** — PhiScan does not scan binary files (DICOM, PDF,
   DOCX, XLSX). See [known-limitations.md](known-limitations.md).

5. **The file exceeds `max_file_size_mb`** — increase the limit:

   ```yaml
   scan:
     max_file_size_mb: 50
   ```

6. **NLP layer not installed** — names and locations in free text require Presidio:

   ```bash
   pipx install "phi-scan[nlp]"
   phi-scan setup
   ```

---

## Exit Code Issues

### "Exit code 2 — configuration error"

PhiScan exited with code 2 and printed a `ConfigurationError`.

**Common causes:**

| Error message | Fix |
|---|---|
| `Unsupported config version` | Set `version: 1` in `.phi-scanner.yml` |
| `follow_symlinks must be false` | Set `follow_symlinks: false` |
| `output.format 'X' is not valid` | Use one of: `table`, `json`, `sarif`, `csv`, `junit`, `codequality`, `gitlab-sast` |
| `scan.severity_threshold 'X' is not valid` | Use one of: `low`, `medium`, `high` |
| `scan.confidence_threshold X is outside range` | Value must be between `0.0` and `1.0` |
| `Cannot read config file` | Check file path and permissions |

Run `phi-scan explain config` for the full configuration reference.

---

### "Exit code 1 on a clean repo"

**Symptom:** CI fails with exit code 1 but you believe no PHI exists.

**Debug steps:**

1. Run with JSON output to see the exact findings:

   ```bash
   phi-scan scan . --output json | python -m json.tool | less
   ```

2. Check if the confidence threshold is too low for your codebase type.

3. Use baseline mode to snapshot current accepted findings and only flag new ones:

   ```bash
   phi-scan baseline create
   phi-scan scan --baseline
   ```

---

## Installation Issues

### "`phi-scan: command not found`"

**Cause:** The `phi-scan` binary is not on your `PATH`.

**Fix for pipx:**

```bash
pipx ensurepath
source ~/.bashrc   # or ~/.zshrc
```

**Fix for pip:**

```bash
python -m phi_scan.cli --version
```

---

### "NLP layer warning at startup"

```
[phi-scan] NLP layer unavailable: presidio-analyzer is not installed.
Continuing with regex and structured layers only.
```

This is informational — the scan runs without NLP. To enable NLP:

```bash
pipx install "phi-scan[nlp]"
phi-scan setup
```

---

### "`phi-scan setup` fails with download error"

**Cause:** spaCy model download requires internet access.

**Fix for air-gapped environments:**

Download the model on a connected machine and transfer it:

```bash
python -m spacy download en_core_web_lg
# Package: en_core_web_lg-3.x.x.tar.gz in site-packages
```

Then install from the local archive:

```bash
pip install /path/to/en_core_web_lg-3.x.x.tar.gz
```

---

## `--diff` Mode Issues

### "`--diff` mode scans more files than expected"

**Cause:** Files in `.phi-scanignore` were not excluded from the diff set. This was
a bug in versions before `0.3.0`.

**Fix:** Upgrade to `0.3.0` or later:

```bash
pipx upgrade phi-scan
```

---

### "Error: not a git repository"

**Cause:** `--diff` requires the scan path to be inside a git repository.

**Fix:** Run from the repository root, or use a full directory scan instead:

```bash
phi-scan scan ./src
```

---

## Baseline Issues

### "Baseline not reducing findings"

**Cause:** The baseline file (`.phi-scanbaseline`) is not committed or is not in the
working directory.

**Fix:**

```bash
phi-scan baseline create    # creates .phi-scanbaseline
git add .phi-scanbaseline
git commit -m "Add phi-scan baseline"
phi-scan scan --baseline    # only new findings now
```

---

### "All findings show as new after a file rename"

**Cause:** Baseline entries are keyed by file path. Renaming a file produces new paths
not in the baseline.

**Fix:** Recreate the baseline after renames:

```bash
phi-scan baseline create
```

---

## Audit Log Issues

### "Cannot open audit database"

**Symptom:** `OperationalError: unable to open database file`

**Cause:** The directory for the audit database does not exist.

**Fix:**

```bash
mkdir -p ~/.phi-scanner
phi-scan scan .
```

Or change the path in `.phi-scanner.yml`:

```yaml
audit:
  database_path: "./phi-scanner-audit.db"
```

---

## Getting More Information

### Enable verbose output

```bash
phi-scan scan . --verbose
```

### Enable debug logging

```bash
phi-scan --log-level debug scan . 2>phi-scan-debug.log
cat phi-scan-debug.log
```

### Inspect the audit log

```bash
phi-scan report              # last scan
phi-scan history --last 7d   # last 7 days
```

### Run the explain commands

```bash
phi-scan explain hipaa       # HIPAA Safe Harbor categories
phi-scan explain detection   # detection layers and confidence scores
phi-scan explain config      # configuration reference
```

---

## Reporting a Bug

If you encounter a bug not covered here, open an issue at
[github.com/joeyessak/phi-scan/issues](https://github.com/joeyessak/phi-scan/issues)
and include:

- PhiScan version: `phi-scan --version`
- Python version: `python --version`
- Operating system
- The command you ran
- The full error output (with `--log-level debug` if possible)
- Whether the issue is reproducible with a minimal example
