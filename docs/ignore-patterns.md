# Ignore Patterns and Suppression

PhiScan provides two mechanisms to suppress findings:

1. **`.phi-scanignore`** — exclude entire files or directories from scanning
2. **Inline suppression comments** — suppress individual findings inside source files

Both are always logged to the audit database with `suppressed=True` for HIPAA compliance.

---

## `.phi-scanignore` — File and Directory Exclusions

Create `.phi-scanignore` in your repository root. It uses the same gitignore-style
syntax as `.gitignore`, implemented via the Python `pathspec` library.

```
# .phi-scanignore

# Exclude test fixture directory
tests/fixtures/phi/

# Exclude vendor code
vendor/
node_modules/

# Exclude build artifacts
dist/
build/

# Exclude minified JS
*.min.js
```

### Syntax Rules

| Syntax | Meaning | Example |
|---|---|---|
| Lines starting with `#` | Comment — ignored | `# this is a comment` |
| Blank lines | Ignored | |
| Trailing `/` | Match directories only | `node_modules/` |
| `*` | Match anything except `/` | `*.pyc` |
| `**` | Match any number of directories | `**/test_data/` |
| `!` prefix | Negate (re-include a previously excluded pattern) | `!important.yml` |
| Leading `/` | Anchor to repository root | `/build/` matches only the root-level `build/` |
| No leading `/` | Match at any depth | `__pycache__/` matches at depth 1 or depth 10 |

### Where Patterns Are Evaluated

Patterns are evaluated against paths relative to the repository root (i.e., the
directory where you ran `phi-scan scan`). A pattern without a leading `/` matches
at every directory depth.

### Merging with `exclude_paths`

Patterns from `.phi-scanignore` are merged with `exclude_paths` in `.phi-scanner.yml`.
Both sources are applied together. If you have both files, there is no conflict —
their patterns union.

### What Is Not Excluded by Default

The default `.phi-scanignore` intentionally leaves these patterns out:

| Pattern | Reason |
|---|---|
| `*.log` | Log files are a primary PHI leak vector. Exclude only if you are certain your logs contain no PHI. |
| `.env` | `.env` files may contain hardcoded credentials or PHI. Add to `.gitignore` instead of suppressing. |
| `*.jar`, `*.war`, `*.zip` | Archives may bundle config files with PHI. Excluded as binary but not suppressed. |
| `*.tfstate` | Terraform state files may contain secrets and PHI. Leave unexcluded. |

---

## Inline Suppression Comments

Inline suppression directives let developers acknowledge false positives line-by-line
without disabling the scanner or excluding entire files.

PhiScan recognises suppression comments in 6 language comment syntaxes:

| Languages | Comment prefix |
|---|---|
| Python, Ruby, Shell, YAML, TOML | `#` |
| JavaScript, TypeScript, Java, Go, C, C++ | `//` |
| SQL, Haskell, Lua | `--` |
| HTML, XML | `<!-- -->` |
| LaTeX, Erlang | `%` |
| INI, Assembly, Lisp | `;` |

### Directives

#### `phi-scan:ignore` — suppress all findings on this line

```python
patient_id = get_test_id()     # phi-scan:ignore
```

```javascript
const token = config.testToken // phi-scan:ignore
```

```sql
SELECT * FROM patients WHERE mrn = '12345678'  -- phi-scan:ignore
```

Suppresses every finding on the line, regardless of entity type.

---

#### `phi-scan:ignore[TYPE,TYPE]` — suppress specific entity types

```python
mrn = load_fixture_mrn()    # phi-scan:ignore[MRN]
```

```python
record = {
    "email": SUPPORT_EMAIL,  # phi-scan:ignore[EMAIL_ADDRESS]
    "ssn": SYNTHETIC_SSN,    # phi-scan:ignore[SSN]
}
```

Only suppresses findings for the listed entity types. Other findings on the same line
are still reported. Type names are case-insensitive.

Common entity type names:

| Type name | Identifier |
|---|---|
| `SSN` | Social Security Number |
| `MRN` | Medical Record Number |
| `EMAIL_ADDRESS` | Email address |
| `PHONE_NUMBER` | Phone number |
| `DATE` | Date (non-year) |
| `IP_ADDRESS` | IP address |
| `HEALTH_PLAN_NUMBER` | Health plan / insurance number |
| `DEA_NUMBER` | DEA registration number |
| `NPI` | National Provider Identifier |
| `MBI` | Medicare Beneficiary Identifier |

Run `phi-scan explain hipaa` to see all entity type names.

---

#### `phi-scan:ignore-next-line` — suppress the following line

```python
# phi-scan:ignore-next-line
SSN_REGEX_PATTERN = r"\d{3}-\d{2}-\d{4}"
```

```javascript
// phi-scan:ignore-next-line
const EXAMPLE_MRN = "MRN-123456";
```

Suppresses all findings on the line immediately following the directive.
Only one line is suppressed. If the next line also needs suppression, add
another directive above it.

---

#### `phi-scan:ignore-file` — suppress the entire file

```python
# phi-scan:ignore-file
# Synthetic patient data fixture — all values are fictional.
```

The directive must appear in the **first 5 lines** of the file (lines 1–5).
All findings in the file are suppressed regardless of entity type.

This is appropriate for:
- Test fixture files that intentionally contain synthetic PHI-like values
- Generated code files where false positives are expected
- Configuration templates with placeholder patterns

For entire directories, use `.phi-scanignore` instead.

---

### HTML and XML

HTML and XML inline comments use the full comment block syntax:

```html
<input name="patient_id" value="TEST-001" <!-- phi-scan:ignore --> />
```

```xml
<!-- phi-scan:ignore-next-line -->
<SSN>123-45-6789</SSN>
```

---

### Audit Trail

All suppressed findings are written to the audit database with `suppressed=True`.
They appear in `phi-scan report` output and in `phi-scan history`, just with a
suppressed indicator. This ensures compliance teams can review all suppressions
without losing the audit trail.

Suppressed findings are shown as dimmed/grey in table output — they are not hidden.

---

## Choosing Between the Two Mechanisms

| Use case | Mechanism |
|---|---|
| Exclude a directory of test fixtures | `.phi-scanignore` |
| Exclude generated or vendor code | `.phi-scanignore` |
| Acknowledge a false positive in source code | Inline `# phi-scan:ignore` |
| Suppress a specific entity type (e.g. NPI) on one line | `# phi-scan:ignore[NPI]` |
| Suppress findings in a synthetic data file | `# phi-scan:ignore-file` in first 5 lines |
| Suppress everything in a large test directory | `.phi-scanignore` entry |
