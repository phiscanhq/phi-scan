# Configuration Reference

PhiScan reads its configuration from `.phi-scanner.yml` in the current working directory.
If the file does not exist, built-in defaults are used for every setting.

Generate a file with sensible defaults:

```bash
phi-scan config init
```

Commit `.phi-scanner.yml` to your repository so all team members use the same settings.

---

## Complete Reference

```yaml
version: 1

scan:
  confidence_threshold: 0.7
  severity_threshold: low
  max_file_size_mb: 10
  follow_symlinks: false
  include_extensions: null
  exclude_paths:
    - .git/
    - .venv/
    - node_modules/
    - dist/
    - build/
    - "*.egg-info/"
    - __pycache__/

output:
  format: table

audit:
  database_path: "~/.phi-scanner/audit.db"
  retention_days: 2192

ai:
  enable_claude_review: false
```

---

## `scan` Section

### `confidence_threshold`

**Type:** float
**Default:** `0.7`
**Range:** `0.0`–`1.0`

Findings with a confidence score below this value are suppressed from output and do
not contribute to the exit code.

PhiScan assigns confidence scores based on how certain the detection layer is that the
match represents actual PHI:

| Score range | Meaning |
|---|---|
| `0.95–1.0` | Structural patterns with checksum validation (SSN, DEA, NPI) |
| `0.88–0.94` | Pattern match confirmed by surrounding context keywords |
| `0.70–0.87` | Regex match without additional context |
| `0.65–0.69` | Broad pattern that may match non-PHI identifiers |
| `0.5–0.64` | NLP entity or ambiguous match |

**Guidance:**
- `0.7` — recommended for scanner/infrastructure codebases that contain clinical
  terminology in source code (pattern names, context keywords, category strings)
- `0.5`–`0.6` — recommended for clinical application codebases where names and
  locations appear in free text
- `0.0` — report everything (highest noise)

A `ConfigurationError` is raised if the value is outside `[0.0, 1.0]`.

---

### `severity_threshold`

**Type:** string
**Default:** `low`
**Accepted values:** `low`, `medium`, `high`

Findings below this severity level are suppressed from output and do not affect the
exit code.

PhiScan maps HIPAA identifier categories to severity levels:

| Severity | Examples |
|---|---|
| `high` | SSN, MRN, DEA number, MBI, full-face photo identifiers |
| `medium` | Email address, phone number, IP address, health plan number |
| `low` | Date (non-year), ZIP code (contextual), vehicle identifier |

A `ConfigurationError` is raised on any value not in the accepted set.

---

### `max_file_size_mb`

**Type:** integer
**Default:** `10`

Files larger than this limit are skipped and logged as a warning. Set to a higher
value if your repository contains large data files you need scanned.

---

### `follow_symlinks`

**Type:** boolean
**Default:** `false`
**Must remain:** `false`

Setting this to `true` raises a `ConfigurationError` and prevents the scan from
starting. Symlink traversal is disabled permanently — it creates a security boundary
violation that allows traversal outside the repository and causes infinite loops in
CI/CD environments.

---

### `include_extensions`

**Type:** list of strings, or `null`
**Default:** `null`

When `null`, all non-binary text files are scanned regardless of extension.

When set to a list, only files with matching extensions are scanned:

```yaml
scan:
  include_extensions: [".py", ".js", ".ts", ".yaml", ".yml", ".json"]
```

Extensions are matched case-insensitively. `.yaml` and `.yml` are equivalent.

---

### `exclude_paths`

**Type:** list of strings
**Default:** common build and cache directories (see generated config)

Gitignore-style patterns evaluated at every directory depth. A pattern like
`node_modules/` matches that directory at any nesting level.

```yaml
scan:
  exclude_paths:
    - .git/
    - .venv/
    - node_modules/
    - dist/
    - build/
    - "*.egg-info/"
    - __pycache__/
    - .mypy_cache/
    - .ruff_cache/
    - .pytest_cache/
    - htmlcov/
    - "*.pyc"
    - "*.pyo"
```

Patterns in `exclude_paths` are merged with patterns from `.phi-scanignore`. For
file-by-file exclusions and inline suppression, see [ignore-patterns.md](ignore-patterns.md).

---

## `output` Section

### `format`

**Type:** string
**Default:** `table`
**Accepted values:** `table`, `json`, `sarif`, `csv`, `junit`, `codequality`, `gitlab-sast`

Sets the default output format when `--output` is not passed on the CLI. The CLI
flag always takes precedence over this setting.

| Value | Use case | CI/CD platform |
|---|---|---|
| `table` | Rich terminal UI | Local development |
| `json` | Programmatic consumption | Any |
| `sarif` | Static analysis results | GitHub Code Scanning, Azure DevOps |
| `csv` | Spreadsheet / audit reports | Excel, data warehouses |
| `junit` | Test result summary | CircleCI, Jenkins, Azure Pipelines |
| `codequality` | MR inline annotations | GitLab |
| `gitlab-sast` | Security dashboard | GitLab |

A `ConfigurationError` is raised on any value not in the accepted set.

Note: `pdf` and `html` require the `reports` optional extra (`pip install "phi-scan[reports]"`).
These values will raise a `ConfigurationError` until that extra is installed.

---

## `audit` Section

### `database_path`

**Type:** string
**Default:** `~/.phi-scanner/audit.db`

Path to the SQLite audit database. Tilde (`~`) is expanded to the current user's home
directory at runtime via `Path.expanduser()` — not by the YAML parser.

Every scan appends an immutable record to this database. Records are never deleted or
updated — HIPAA 45 CFR §164.530(j) requires an immutable audit trail. Corrections are
new INSERT rows referencing the original entry.

The database is created automatically on first scan if it does not exist.

---

### `retention_days`

**Type:** integer
**Default:** `2192`

Audit records older than this many days are eligible for archival. The default of
2192 days equals exactly 6 years (the HIPAA minimum under 45 CFR §164.530(j)),
calculated as 4×365 + 2×366 to account for the maximum number of leap years in any
6-year span.

Do not reduce this value below 2192 in production environments subject to HIPAA.

---

## `ai` Section

### `enable_claude_review`

**Type:** boolean
**Default:** `false`

When `true`, PhiScan sends redacted code structure (never raw PHI values) to the
Claude API for medium-confidence finding review. This is optional — all 4 detection
layers operate fully locally when this is `false`.

**Important constraints when enabling:**
- Raw PHI values are always replaced with `[REDACTED]` before any API call
- Only findings with confidence below `0.8` are sent (high-confidence matches bypass Claude)
- The `ANTHROPIC_API_KEY` environment variable must be set (loaded from `.env` if present)
- Claude failures fall back gracefully to local-only scoring — they do not crash the scan

This setting is disabled by default because local scanning satisfies all HIPAA
requirements without any external API calls.

---

## CLI Flags That Override Config

These CLI flags take precedence over the corresponding config file settings:

| CLI flag | Overrides config field |
|---|---|
| `--output FORMAT` | `output.format` |
| `--confidence FLOAT` | `scan.confidence_threshold` |
| `--severity-threshold LEVEL` | `scan.severity_threshold` |
| `--quiet` | (no config equivalent — CLI only) |
| `--report-path PATH` | (no config equivalent — CLI only) |
| `--baseline` | (no config equivalent — CLI only) |

---

## Validation Errors

PhiScan raises `ConfigurationError` (exit code 2) for any of the following:

- `version` is missing or not `1`
- `follow_symlinks: true`
- `output.format` is not a recognized value
- `scan.severity_threshold` is not `low`, `medium`, or `high`
- `audit.database_path` is not a string
- `scan.confidence_threshold` is not a number or is outside `[0.0, 1.0]`
- The config file cannot be read or is not valid YAML

---

## Example Configurations

### Development (permissive)

Report all findings including low-confidence matches:

```yaml
version: 1
scan:
  confidence_threshold: 0.5
  severity_threshold: low
```

### Production CI (strict)

Only report high-confidence, medium+ severity findings and fail fast:

```yaml
version: 1
scan:
  confidence_threshold: 0.85
  severity_threshold: medium
output:
  format: sarif
```

### Infrastructure / scanner source repositories

Raise the confidence threshold to suppress broad context-absent patterns that
fire on clinical terminology in source code:

```yaml
version: 1
scan:
  confidence_threshold: 0.7
  severity_threshold: low
```

### Monorepo with many large files

```yaml
version: 1
scan:
  max_file_size_mb: 50
  exclude_paths:
    - .git/
    - .venv/
    - node_modules/
    - vendor/
    - "*.min.js"
    - "*.bundle.js"
```
