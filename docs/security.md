# Security and PHI Protection Model

PhiScan is built on a single non-negotiable principle: **no PHI ever leaves your
infrastructure by default.** This document explains exactly how that guarantee is
implemented at every layer, and where opt-in features extend the boundary.

---

## Core Guarantee: Local Execution Only

All scanning executes inside your pipeline runner or developer machine. PhiScan
makes zero outbound network connections during a scan by default. There is no
telemetry, no cloud API, and no external service involved.

This is enforced structurally, not by configuration:

- The base install has no HTTP client used during scanning
- `httpx` is used only for webhook notifications and CI integrations — it is
  never called during the scan path itself
- AI-assisted confidence scoring (`ai.enable_ai_review`) is **disabled by default**
  and requires explicit opt-in. Even when enabled, only redacted code structure is
  sent — never raw PHI values. See [AI Integration](#ai-integration-optional-disabled-by-default) below.

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

## Archive Scanning Security

### Decompression Bomb Protection

PhiScan scans text members inside `.zip`, `.jar`, and `.war` files. Before reading
any archive member into memory, two independent guards are applied:

**1. Absolute size limit**

Each member's uncompressed size (from `ZipInfo.file_size`) is checked before
decompression. Members exceeding `ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES` (100 MB
by default) are skipped with a `WARNING` log. The scan continues with remaining
members.

**2. Compression ratio limit**

If the compression ratio (`uncompressed_size / compressed_size`) exceeds
`ARCHIVE_MAX_COMPRESSION_RATIO` (200:1 by default), the member is skipped with a
`WARNING` log. Classic ZIP bombs achieve ratios of 1000:1 or higher — the 200:1
ceiling blocks all known bomb payloads while accepting all legitimate source files.

Both limits are named constants in `constants.py` and can be tightened for
high-security environments by overriding them in a custom build.

ZIP-slip path traversal (members with `..` or absolute path components) is
rejected separately — those members are skipped at path validation before the
size check runs.

---

## Webhook Security

### SSRF Protection

Webhook URLs are validated before any HTTP request is made. Three checks are enforced
by default (when `is_private_webhook_url_allowed: false`):

**1. HTTPS scheme required**

`http://` URLs are rejected with a `NotificationError`. All webhook endpoints must
use TLS to prevent findings metadata from being transmitted in plaintext.

**2. Private IP block list**

Hostnames that are literal IP addresses are checked against a block list of
reserved and private ranges:

| Range | Block reason |
|---|---|
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC1918 private |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local / AWS & GCP metadata endpoint |
| `100.64.0.0/10` | CGNAT (RFC6598) |
| `::1/128`, `fc00::/7`, `fe80::/10` | IPv6 private/loopback/link-local |

Requests to these ranges are rejected with a `NotificationError` to prevent SSRF
attacks in CI environments where an attacker could influence the webhook URL via a
malicious PR.

**3. DNS resolution check**

Domain names that are not literal IPs are resolved via DNS before the request is
made. Every returned address is validated against the same block list above. This
closes the DNS rebinding bypass: a hostname like `internal.attacker.com` that
resolves to `169.254.169.254` is rejected even though the URL contains no literal IP.

If the hostname cannot be resolved at all, the request is also rejected — an
unresolvable hostname is not trusted.

**Opt-out for self-hosted targets**

If your webhook endpoint is on a private network (e.g., on-premise GitLab,
internal Jenkins), set:

```yaml
notifications:
  is_private_webhook_url_allowed: true
```

This disables both the IP block list check and the DNS resolution check while
keeping the HTTPS requirement in place.

> **Security note:** Enabling `is_private_webhook_url_allowed` on a system where
> webhook URLs can be influenced by untrusted input (e.g., a malicious PR setting
> an environment variable) removes SSRF protection entirely. Only enable it in
> environments with network-level egress controls (firewall rules, VPC policies)
> restricting access to metadata endpoints.

---

## Known Limitations

Binary file formats (PDF, DICOM, DOCX, XLSX) are skipped. See
[known-limitations.md](known-limitations.md) for the complete list and planned
remediation.
