# Security and PHI Protection Model

PhiScan is built on a single non-negotiable principle: **no PHI ever leaves your
infrastructure.** This document explains exactly how that guarantee is implemented
at every layer.

---

## Core Guarantee: Local Execution Only

All scanning executes inside your pipeline runner or developer machine. PhiScan
makes zero outbound network connections during a scan. There is no telemetry, no
cloud API, and no external service involved.

This is enforced structurally, not by configuration:

- The base install has no HTTP client used during scanning
- `httpx` is a listed dependency for future webhook notifications (Phase 5) — it is
  never called during the scan path
- AI-assisted confidence scoring (`ai.enable_ai_review`) is disabled by default
  and requires explicit opt-in. Even when enabled, only redacted code structure is
  sent — never raw PHI values

---

## How PHI Is Handled at Detection Time

### Redaction before storage

When PhiScan detects a PHI value, the raw value is **immediately discarded**. The
detection pipeline produces:

1. A SHA-256 hash of the raw value — stored in the audit log for deduplication
2. A redacted code snippet — `patient_name = [REDACTED]` — shown in output and logs

The raw matched string is never stored, never logged, and never displayed. This
applies to:

- The Rich terminal table output
- JSON, SARIF, CSV, JUnit, and all other output formats
- The SQLite audit database
- The scan cache
- The baseline file

### Regex detection

The regex detector extracts `match.start()` and `match.end()` span positions from
each match. It constructs the redacted context string as:

```
line_text[:match_start] + "[REDACTED]" + line_text[match_end:]
```

The matched substring is used only to compute its SHA-256 hash, then immediately
discarded.

### NLP detection

The NLP detector (Presidio + spaCy) returns entity spans as character offsets. The
span is used to:

1. Compute the SHA-256 hash of `file_content[span_start:span_end]`
2. Build the redacted line using intra-line offset arithmetic

The entity text is never stored in any variable beyond the hash computation.

---

## Audit Log Security

### Immutability (HIPAA 45 CFR §164.530(j))

The SQLite audit database is append-only. The schema uses no `UPDATE` or `DELETE`
statements. Corrections are new `INSERT` rows with a reference to the original entry.

HIPAA requires audit records to be retained for a minimum of 6 years (2192 days).
The default `retention_days: 2192` in `.phi-scanner.yml` matches this requirement.

### What is stored

Each scan record contains:

| Field | Value |
|---|---|
| `scan_id` | UUID for this scan run |
| `timestamp` | ISO 8601 UTC timestamp |
| `file_path` | Path of the scanned file |
| `entity_type` | E.g. `SSN`, `MRN`, `EMAIL_ADDRESS` |
| `line_number` | Line where the finding appeared |
| `value_hash` | SHA-256 of the raw matched value |
| `confidence` | Detection confidence score (0.0–1.0) |
| `severity` | `low`, `medium`, or `high` |
| `suppressed` | Whether an inline suppression covered this finding |
| `detection_layer` | Which layer found it: `REGEX`, `NLP`, `FHIR`, `HL7`, `AI` |

### What is NOT stored

- Raw PHI values
- Patient names, SSNs, MRNs, or any identifiable information
- File contents
- Code context (only `[REDACTED]` placeholder)

### Database location

Default: `~/.phi-scanner/audit.db`

The database is created in the user's home directory, outside the repository, so it
is never accidentally committed. Set a custom path in `.phi-scanner.yml`:

```yaml
audit:
  database_path: "/var/lib/phi-scanner/audit.db"
```

---

## AI Integration (Optional, Disabled by Default)

When `ai.enable_ai_review: true` is set in `.phi-scanner.yml`:

- Only medium-confidence findings (score < 0.8) are submitted for review
- High-confidence regex and structural matches bypass the AI provider entirely
- Before any API call, all matched values in the code snippet are replaced with
  `[REDACTED]` — the API receives only code structure
- Provider is inferred from the model name (default: `claude-sonnet-4-6` via Anthropic)
- AI provider failures fall back gracefully to local-only scoring — they never crash the scan

The API call looks like:

```
patient_name = [REDACTED]
mrn = [REDACTED]
```

Never:

```
patient_name = "John Smith"
mrn = "MRN-123456"
```

---

## Inline Suppression and Compliance

Inline suppression comments (`# phi-scan:ignore`) do not delete findings — they set
`suppressed=True` in the audit record. Compliance teams can query all suppressions:

```bash
phi-scan history --last 90d   # includes suppressed findings
phi-scan report               # last scan with suppression indicators
```

This ensures the audit trail remains complete even when developers suppress
false positives.

---

## Scan Cache

PhiScan caches scan results by content hash to skip unchanged files. The cache stores:

- The SHA-256 hash of the file content
- The list of `ScanFinding` objects (with `[REDACTED]` context, not raw values)
- The timestamp of the last scan

The cache is stored in `.phi-scanner/cache.db` (excluded from scanning by default).

---

## Supply Chain Security

- All dependencies are pinned to compatible-release versions (`~=`) in `pyproject.toml`
  to prevent unexpected upgrades
- The `uv.lock` lockfile is committed to the repository and verified in CI
- The Docker image (Phase 6) is signed and built from a pinned Alpine base

---

## Reporting a Vulnerability

If you discover a security vulnerability in PhiScan, please report it privately via
the GitHub Security Advisory process described in [SECURITY.md](../SECURITY.md).

Do not open a public issue for security vulnerabilities.

---

## Known Limitations

Binary file formats (PDF, DICOM, DOCX, XLSX) are skipped. See
[known-limitations.md](known-limitations.md) for the complete list and planned
remediation.
