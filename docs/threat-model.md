# PhiScan Threat Model

**Last reviewed:** 2026-04-12
**Scope:** PhiScan v1.x (the `phi-scan` CLI, the `phi_scan` Python package,
and the artifacts it produces).
**Audience:** security reviewers, auditors, and downstream integrators who
need to reason about what PhiScan defends against and what it does not.

This document is an operational threat model, not a marketing document.
Every P0/P1 row lists a specific mitigation location in the source and at
least one named test that fails if the mitigation regresses. Residual
risks are called out explicitly; a row whose residual risk is "none known"
is making a measurable claim, not hand-waving.

`docs/security.md` is the user-facing description of PhiScan's PHI
protection model and is intentionally kept separate. This document is for
auditors who want a threat-oriented view with concrete test citations.

---

## 1. Assumptions and Trust Boundaries

PhiScan's security posture is built on the following assumptions. If any
assumption is false in a given deployment, the corresponding mitigations
should be re-evaluated.

1. **The operator is trusted.** PhiScan is a CLI run by a developer, a CI
   job, or an automation account on infrastructure they control. Threats
   from a hostile operator (e.g. an insider intentionally exfiltrating
   PHI) are explicitly out of scope — PhiScan cannot protect data from
   the account running it.
2. **The local filesystem is trusted.** Files PhiScan reads are assumed
   to have been placed there by the operator or a trusted upstream
   process. PhiScan still defends against malformed inputs (ZIP bombs,
   symlinks, oversized files) but does not attempt to model a filesystem
   containing attacker-planted files unknown to the operator.
3. **External services are untrusted.** Every external endpoint PhiScan
   can talk to — AI review APIs, webhooks, SMTP servers, DNS, CI upload
   APIs — is treated as potentially hostile and is subject to explicit
   safety checks.
4. **The host OS resolves DNS.** PhiScan uses `socket.getaddrinfo` and
   accepts whatever the system resolver returns. We assume the resolver
   itself is not compromised (i.e. that DNSSEC, local hosts files, and
   upstream resolver policy are outside our scope). An adversary who can
   answer DNS queries for a given hostname can still influence the IPs
   PhiScan sees — the SSRF defenses are designed with that in mind.
5. **The Python runtime and stdlib are trusted.** Vulnerabilities in
   CPython or its standard library (including `ipaddress`, `zipfile`,
   `ssl`, `re`) are not modelled here. Dependency vulnerabilities are
   tracked separately (see scorecard S9 — pending `pip-audit` gate).

### Trust boundaries

```
                 ┌──────────────────────────────────────┐
                 │         Operator / CI runner         │
                 │                                      │
                 │  ┌──────────┐      ┌──────────────┐  │
Untrusted input ─┼─►│ phi-scan │      │ config files │  │
(files, archives)│  │   CLI    │◄─────┤ scan-config  │  │
                 │  └────┬─────┘      │  .yml        │  │
                 │       │            └──────────────┘  │
                 │       ▼                              │
                 │  ┌──────────┐      ┌──────────────┐  │
                 │  │ scanner  │─────►│ audit.sqlite │  │
                 │  │ + fixer  │      │ (local only) │  │
                 │  └────┬─────┘      └──────────────┘  │
                 │       │                              │
                 └───────┼──────────────────────────────┘
                         │ (per-operator opt-in)
                         ▼
            ┌────────────────────────────┐
            │   External trust boundary  │
            │                            │
            │   AI review providers      │
            │   Webhook receivers        │
            │   SMTP servers             │
            │   SARIF upload endpoints   │
            │                            │
            │   (all treated as hostile) │
            └────────────────────────────┘
```

The inner box is assumed trusted; everything crossing the outer boundary
is assumed hostile and requires an explicit, tested mitigation.

---

## 2. Severity Scale

| Level | Meaning |
|-------|---------|
| **P0** | Immediate exploitation risk with high blast radius (e.g. raw PHI exfiltration, remote command execution, silent data destruction). Must be mitigated with a named test before merging to `main`. |
| **P1** | Exploitable under realistic conditions with meaningful impact (SSRF, TOCTOU, symlink traversal, decompression bomb). Must be mitigated with a named test before shipping a release. |
| **P2** | Requires specific misconfiguration or low-likelihood adversary position. Should be mitigated; a regression test is strongly preferred but not strictly required. |
| **P3** | Hardening and defense-in-depth. Residual risks and mitigations are documented; tests may be aspirational. |

Per scorecard check **S8**, every P0 and P1 row in this document must
cite a specific test by name. If a row does not, it is a bug — file an
issue and block the next release on fixing it.

---

## 3. Threat Surface Inventory

The subsections below walk the attack surface from the outside in: raw
file ingestion first, then archive handling, then the network-facing
features (AI review, notifier, CI upload), then the local artifacts
PhiScan writes back (fixer output, audit log, cache).

### 3.1 Scanner ingestion

| # | Threat | Severity | Mitigation | Test(s) | Residual risk |
|---|--------|----------|------------|---------|---------------|
| I-1 | Symlink traversal: attacker-controlled symlink points outside the scan root to leak file contents into findings. | **P1** | `phi_scan.scanner._reject_symlinked_scan_root` rejects a symlinked root; `_should_skip_symlink_candidate` skips any symlink encountered during traversal (both directory and file symlinks). Never call `Path.resolve()` on untrusted input inside the traversal loop. | `test_scanner.py` (symlink-skip tests); `test_config.py::test_load_config_should_follow_symlinks_is_always_false`; `test_config.py::test_load_config_raises_configuration_error_when_follow_symlinks_is_true`; `test_models.py::test_scan_config_should_follow_symlinks_defaults_to_false`; `test_models.py::test_scan_config_raises_configuration_error_when_follow_symlinks_is_true`; `test_diff.py::test_is_safe_scannable_path_returns_false_for_symlink`; `test_diff.py::test_resolve_existing_paths_excludes_symlinked_file` | A symlink created _during_ traversal (between `os.walk` yielding a directory and the per-file check) is theoretically possible but requires local write access to the scan root, at which point the attacker is already inside the trust boundary. |
| I-2 | Oversized file used to exhaust memory or CPU via regex matching. | **P1** | `phi_scan.constants.MAX_FILE_SIZE_BYTES = 10 MB` caps per-file read size; files above the limit are skipped with a warning. Because the regex patterns operate on bounded input, worst-case runtime is also bounded. | `test_scanner.py` (max-file-size skip tests); `test_constants.py` pins the constant. | The limit is configurable via `scan.max_file_size_mb` in the YAML config — an operator who raises it to an unreasonable value reintroduces this risk. Configuration is trusted (assumption 1). |
| I-3 | Catastrophic regex backtracking (ReDoS) inside a detector pattern. | **P2** | Detector patterns are curated and bounded (no nested unbounded quantifiers). All input is capped by I-2 at 10 MB, making any linear-in-input regex runtime finite in practice. Patterns are compiled once at module load. | Coverage of each detector in `tests/test_regex_detector.py`. No dedicated ReDoS stress test exists today. | A future pattern that reintroduces a pathological structure would not be caught by existing tests. Tracked as a hardening item (scorecard `S?` — candidate for future round). Mitigation relies on pattern review at PR time. |
| I-4 | Path-traversal via `..` segments in config or CLI arguments to read files outside the intended scan root. | **P1** | `phi_scan.scanner` uses `Path.is_relative_to` / explicit root validation; `phi_scan.logging_config` rejects symlinked log paths even when the normalised form looks benign. | `test_logging_config.py::test_replace_logger_handlers_raises_phi_scan_logging_error_for_symlinked_log_path`; `test_logging_config.py::test_replace_logger_handlers_raises_phi_scan_logging_error_for_symlinked_parent_directory`; `test_logging_config.py::test_replace_logger_handlers_accepts_path_with_dotdot_when_no_symlink_in_normalized_form` | None known. |

### 3.2 Archive handling

| # | Threat | Severity | Mitigation | Test(s) | Residual risk |
|---|--------|----------|------------|---------|---------------|
| A-1 | ZIP decompression bomb: a small archive containing a member that expands to many GB. | **P1** | `phi_scan.scanner._passes_decompression_bomb_guards` applies two guards: (a) each member's `ZipInfo.file_size` is capped at `ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES` (100 MB); (b) if `compress_size > 0`, the ratio `file_size / compress_size` must not exceed `ARCHIVE_MAX_COMPRESSION_RATIO` (200). Members that violate either guard are skipped and logged, never read into memory. `ZipFile.extract` and `ZipFile.extractall` are never called — each member is read through an in-memory buffer. | `test_scanner.py::test_archive_member_size_accepts_small_member`; `test_scanner.py::test_archive_member_size_rejects_oversized_member`; `test_scanner.py::test_archive_member_size_rejects_high_compression_ratio`; `test_scanner.py::test_archive_member_size_accepts_zero_compress_size`; `test_scanner.py::test_archive_member_size_accepts_ratio_at_limit`; `test_scanner.py::test_scan_file_skips_bomb_member_in_real_zip` | Many small archives, each within the member-size limit, could collectively still use significant memory if scanned in parallel. The per-worker ceiling is `ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES × parallelism` which is bounded and documented. |
| A-2 | Zip slip (path traversal via `..` in archive member names). | **P1** | PhiScan never writes archive members to disk. Each member is read into memory via `ZipFile.read` and scanned in place. `ZipFile.extract` / `extractall` are explicitly not called anywhere in the codebase. | `test_scanner.py` archive-handling tests confirm reads happen via `ZipFile.read`; `test_module_structure.py` pins the module layout. Grep gate (CI-enforced by reviewer): `extractall(` must not appear outside docs. | None known. The mitigation is structural — no write path exists. |
| A-3 | Malformed archive crashes the scan. | **P2** | `zipfile.BadZipFile` is caught and the archive skipped with a warning; the scan continues. | `test_scanner.py` bad-archive tests. | None known. |

### 3.3 Regex and detector layer

| # | Threat | Severity | Mitigation | Test(s) | Residual risk |
|---|--------|----------|------------|---------|---------------|
| D-1 | `value_hash` computed inconsistently, allowing raw PHI to sneak into outputs via a field that was supposed to be hashed. | **P0** | `ScanFinding` validates `value_hash` at construction: must be 64 lowercase hex characters; a raw value would fail the hex check. `_redact_phi_from_context` in `ai_review.py` additionally enforces that `code_context` contains the redaction marker before any outbound call. | `test_models.py::test_scan_finding_stores_value_hash`; `test_models.py::test_scan_finding_raises_phi_detection_error_for_value_hash_too_short`; `test_models.py::test_scan_finding_raises_phi_detection_error_for_value_hash_too_long`; `test_models.py::test_scan_finding_raises_phi_detection_error_for_value_hash_with_non_hex_characters`; `test_models.py::test_scan_finding_raises_phi_detection_error_for_value_hash_with_uppercase_hex` | None known. |
| D-2 | `code_context` contains raw PHI that escapes into outputs or outbound API calls. | **P0** | The regex detector layer redacts the matched substring in `code_context` at construction (`test_regex_detector.py::test_code_context_redacts_matched_value`). The NLP detector does the same (`test_nlp_detector.py::test_code_context_redacts_matched_value`). AI review verifies the redaction marker is present before sending anything to a provider. | `test_regex_detector.py::test_code_context_redacts_matched_value`; `test_nlp_detector.py::test_code_context_redacts_matched_value`; `test_ai_review.py::test_code_context_is_redacted_at_construction`; `test_ai_review.py::test_value_hash_not_in_code_context`; `test_ai_review.py::test_raw_phi_construction_rejected` | A bug in the redaction function that emits the marker but leaves additional PHI outside the match span would not be caught by the marker check alone. Span-based redaction has its own invariants tested separately, but defense-in-depth would be a fuzzing layer — not yet implemented. |

### 3.4 Notifier — email and webhooks

This is the densest section because the notifier is the primary outbound
network boundary in a default install. Every mitigation below is tested
by the existing `tests/test_notifier.py` suite (happy path + first-order
SSRF rules) plus `tests/test_notifier_ssrf_adversarial.py` (added for
scorecard S5).

| # | Threat | Severity | Mitigation | Test(s) | Residual risk |
|---|--------|----------|------------|---------|---------------|
| N-1 | Webhook URL sent as `http://` in cleartext, exposing findings metadata in transit. | **P0** | `_validate_webhook_url` rejects any scheme other than `https`. The check runs even when `is_private_webhook_url_allowed=True`. | `test_notifier.py::test_validate_webhook_url_rejects_http_scheme`; `test_notifier.py::test_validate_webhook_url_still_rejects_http_when_opted_in` | None known. |
| N-2 | SMTP relay sent in plaintext, exposing findings metadata and credentials. | **P0** | `_deliver_via_smtp` raises `NotificationError` if `smtp_use_tls` is False. STARTTLS is required on the configured port. | `test_notifier.py` TLS enforcement tests (`_TLS_REQUIRED_ERROR`). | SMTP downgrade / STRIPTLS attacks at the network layer are outside scope; PhiScan relies on the stdlib `smtplib` STARTTLS implementation and its CA trust store. |
| N-3 | SSRF via literal private / loopback / metadata IP in the webhook URL. | **P1** | `_validate_webhook_url` parses the hostname as a literal IP. After normalisation by `_normalise_ip_address` (which unmaps IPv4-mapped IPv6), `_is_ip_address_blocked` rejects RFC1918, loopback, link-local, CGNAT, cloud metadata, multicast, unspecified, and reserved ranges. | `test_notifier.py::test_validate_webhook_url_rejects_rfc1918_class_c`; `::test_validate_webhook_url_rejects_loopback`; `::test_validate_webhook_url_rejects_metadata_endpoint`; `::test_validate_webhook_url_rejects_rfc1918_class_a`; `::test_validate_webhook_url_rejects_cgnat`; `test_notifier_ssrf_adversarial.py::TestValidateWebhookUrlRejectsLiteralIpv6`; `::TestValidateWebhookUrlRejectsSpecialRanges` | None known. |
| N-4 | SSRF via DNS-based redirect: hostname resolves to a private IP at validation time. | **P1** | `_resolve_hostname_addresses` calls `socket.getaddrinfo`, normalises IPv4-mapped IPv6, and returns every resolved address. `_reject_ssrf_resolved_addresses` calls `_is_ip_address_blocked` for each — if **any** resolved address is blocked, the entire hostname is rejected. This closes the "return [public, private]" bypass. | `test_notifier.py::test_validate_webhook_url_blocks_hostname_resolving_to_loopback`; `::test_validate_webhook_url_blocks_hostname_resolving_to_metadata_ip`; `::test_validate_webhook_url_blocks_hostname_resolving_to_rfc1918`; `test_notifier_ssrf_adversarial.py::TestValidateWebhookUrlMixedResolution` | None known. |
| N-5 | SSRF via IPv4-mapped IPv6 DNS record (e.g. `::ffff:127.0.0.1`). | **P1** | `_normalise_ip_address` unmaps IPv4-mapped IPv6 to its IPv4 form before the blocklist is consulted, so the `127.0.0.0/8` rule applies unchanged. Applied in both the literal-IP path and every resolved DNS address. | `test_notifier_ssrf_adversarial.py::TestNormaliseIpAddress`; `::TestValidateWebhookUrlRejectsIpv4MappedIpv6` | None known. Added in the same PR that introduced this document. |
| N-6 | DNS rebinding (TOCTOU): attacker flips the DNS record between the validation resolve and the delivery resolve. | **P1** | `_validate_webhook_url` returns the first validated IP as a pin. `_build_pinned_webhook_request` rewrites the outbound URL to connect to that IP directly and preserves the original hostname in the `Host` header for TLS SNI / virtual-host routing. The delivery path (`httpx.post`) therefore never issues a second DNS lookup. | `test_notifier.py::test_validate_webhook_url_returns_pinned_ip_for_domain`; `::test_rewrite_url_hostname_to_ip_substitutes_hostname`; `::test_build_pinned_webhook_request_sets_host_header`; `test_notifier_ssrf_adversarial.py::TestDnsRebindingTimeOfCheckTimeOfUse::test_rebind_between_validate_and_build_uses_first_ip`; `::test_rebind_host_header_preserves_original_hostname` | A malicious endpoint could still respond with an attacker-controlled certificate or a redirect pointing at a private IP. HTTPS validation defeats the former; httpx does not transparently follow redirects for webhook POSTs in our code path, so the latter is structurally prevented as long as the `_post_with_retry` loop continues to issue plain POSTs without `follow_redirects=True`. A regression that flips that flag would break this defense silently — reviewer discipline. |
| N-7 | Unresolvable hostname used to mask intent (side-channel via DNS-logging services, or exploiting unauthenticated DNS). | **P2** | `_resolve_hostname_addresses` raises `NotificationError` when `socket.gaierror` fires, hashing the hostname in the error message so logs never contain raw URL paths. | `test_notifier.py::test_validate_webhook_url_blocks_dns_resolution_failure`; `::test_validate_webhook_url_scheme_error_does_not_expose_raw_url`; `::test_validate_webhook_url_private_ip_error_does_not_expose_raw_url` | A legitimate webhook host that happens to be temporarily unresolvable fails closed — desired behaviour. |
| N-8 | HTML/JSON payload injection via operator-supplied `repository` or `branch` fields. | **P2** | `_build_email_html_body` and `_build_findings_table_html` call `html.escape` on every operator-supplied field before interpolation. JSON payloads are serialised via stdlib `json.dumps`, which escapes control characters and quotes by default. | `test_notifier.py` script-injection repro tests (`_SCRIPT_INJECTION_BRANCH`, `_SCRIPT_INJECTION_REPO`). | Rich-text clients that interpret HTML within attachment metadata are outside scope; any such client is expected to sandbox HTML content itself. |
| N-9 | Raw PHI leaked in an outbound webhook payload (e.g. via `finding.code_context` or an accidentally unhashed value). | **P0** | `_serialise_finding` emits only hashed metadata (`value_hash`, `hipaa_category`, `severity`, `confidence`, `file_path`, `line_number`, `entity_type`). `code_context` is never serialised into any payload. D-1 and D-2 additionally guarantee the source fields cannot contain raw PHI. | `test_notifier.py` payload-shape tests pin the exact keys emitted; `test_output_contracts.py::test_json_output_never_contains_raw_phi_value` pins the invariant at the output layer. | None known. |

### 3.5 AI review layer (opt-in)

| # | Threat | Severity | Mitigation | Test(s) | Residual risk |
|---|--------|----------|------------|---------|---------------|
| AI-1 | Raw PHI sent to an external AI provider. | **P0** | `_redact_phi_from_context` replaces every matched PHI span with `AI_REVIEW_REDACTED_PLACEHOLDER` before the prompt is built. A safety check (`_PHI_SAFETY_VIOLATION_ERROR`) raises `AIReviewError` if the placeholder is missing from the redacted context, preventing a silent regression in the redactor. | `test_ai_review.py::test_code_context_is_redacted_at_construction`; `::test_value_hash_not_in_code_context`; `::test_raw_phi_construction_rejected`; `::test_phi_redacted_in_outbound_prompt`; `::test_phi_redacted_in_provider_call` | The AI provider's response text is treated as untrusted — only `is_phi_risk` (boolean) is read, and free-text reasoning fields are not propagated back into findings or logs. Feature disabled by default; documented as opt-in throughout. |
| AI-2 | AI provider API key leaked in logs or error messages. | **P1** | `resolve_api_key` reads from environment variables only and is never included in structured log context. Provider errors are caught and re-raised as `AIReviewError` with the key stripped. | `test_ai_review.py` key-resolution tests. | An operator who runs with `PYTHONWARNINGS=error` or wraps `sys.exit` differently could capture the raw traceback — considered out of scope (assumption 1). |
| AI-3 | AI provider endpoint impersonation (TLS MITM, DNS rebind). | **P2** | HTTPS required; certificate validation delegated to `httpx` which uses the system CA trust store. The provider host is a constant (Anthropic / OpenAI / Google AI), so DNS rebinding is mitigated by the provider's own certificate chain. | No dedicated TLS-failure test today — relies on `httpx` defaults. | An enterprise that sets `SSL_CERT_FILE` to a corporate CA could be intercepted by that CA. Same trust model as every other HTTPS client; documented residual risk. |

### 3.6 Fixer — source rewriting

| # | Threat | Severity | Mitigation | Test(s) | Residual risk |
|---|--------|----------|------------|---------|---------------|
| F-1 | Fixer writes new PHI into source files when generating synthetic replacements. | **P1** | `generate_synthetic_value` uses `Faker` seeded deterministically from `value_hash`. Replacements are generated from formats that are documented as synthetic (e.g. `999-xx-xxxx` reserved SSN block). The fixer never echoes the original value. | `test_fixer.py` synthetic-generator tests. | Faker's seeded outputs are deterministic per `value_hash`, which means the same redacted value always maps to the same synthetic replacement — by design (stable diffs). An operator who leaks a single synthetic→real mapping leaks that row only. |
| F-2 | Fixer writes outside the intended file path. | **P1** | `apply_approved_replacements` only writes back to the file the replacement was collected from; no path argument is accepted from outside `collect_file_replacements`. Combined with I-1, this cannot escape the scan root. | `test_fixer.py` apply-replacement tests. | None known. |
| F-3 | Fixer executes attacker-controlled code (e.g. through a subprocess or eval). | **P0** | The fixer is pure Python text replacement. No subprocess, shell, `eval`, `exec`, or dynamic import occurs anywhere in `phi_scan/fixer.py`. | Structural: `grep -rn 'subprocess\|shell=True\|os.system\|eval(\|exec(' phi_scan/fixer.py` returns no matches. Grep gate: any future subprocess use in `fixer.py` must be reviewed explicitly. | None known. |

### 3.7 Output formats (JSON, CSV, SARIF, JUnit, Code-Quality, GitLab SAST, HTML, PDF)

| # | Threat | Severity | Mitigation | Test(s) | Residual risk |
|---|--------|----------|------------|---------|---------------|
| O-1 | Raw PHI leaks into a serialised output format. | **P0** | Every output serialiser reads from `ScanFinding`, which only exposes hashed and redacted fields. `format_sarif` in particular omits `code_context` entirely — the SARIF `message.text` is derived from entity type and hipaa category, not from the source line. | `test_output_contracts.py::test_json_output_never_contains_raw_phi_value`; `test_output.py::test_format_json_finding_value_hash_is_hex_digest_not_raw_phi`; `test_output_json.py::test_finding_value_hash_is_a_string`; `::test_finding_value_hash_is_64_characters`; `::test_finding_value_hash_is_lowercase_hex`; `test_output_goldens.py` byte-exact golden fixtures for all eight formats (any drift fails CI); `test_ci_integration_remaining.py::test_convert_findings_to_asff_excludes_full_value_hash` | None known for the tested formats. |
| O-2 | Path separator drift across OS renders non-deterministic finding fingerprints (security-relevant because fingerprints are used to deduplicate findings across runs and platforms). | **P2** | Every output serialiser calls `finding.file_path.as_posix()` instead of `str(finding.file_path)`. `_compute_finding_fingerprint` uses the POSIX form so the same finding produces identical bytes on Windows and Linux. | `test_output_goldens.py` golden fixtures (Windows CI regressed on 2026-04-11 before the fix); `test_output_csv.py` data-row oracle; `test_output_sarif.py` artifactLocation oracle. | None known. |
| O-3 | SARIF upload to a CI code-scanning endpoint exposes the file through an unauthorised path. | **P2** | `ci_integration.py` constructs upload URLs from documented API host constants; token handling is read from environment variables only. The upload payload is the SARIF document that has already passed O-1. | `test_ci_integration_remaining.py::test_upload_sarif_http_error_excludes_response_body` (error paths do not leak response bodies that might contain PHI). | A misconfigured CI runner that sets the wrong token will cause an auth failure, not a wrong-destination upload — desired behaviour. |

### 3.8 Local artifacts — audit log, cache, logging

| # | Threat | Severity | Mitigation | Test(s) | Residual risk |
|---|--------|----------|------------|---------|---------------|
| L-1 | Symlink plant attack against the audit DB or cache path (attacker pre-creates a symlink at the expected location pointing at a sensitive file). | **P1** | `audit._reject_symlink_database_path` and `cache._reject_symlinked_cache_path` reject symlinks on the entire database / cache path before any file handle is opened. `logging_config` applies the same rule to the log path and to its parent directory. | `test_audit.py::test_reject_symlink_database_path_raises_audit_log_error_for_symlink`; `::test_open_database_raises_audit_log_error_for_symlink_path`; `::test_create_audit_schema_raises_audit_log_error_for_symlink`; `::test_insert_scan_event_raises_audit_log_error_for_symlink`; `::test_query_recent_scans_raises_audit_log_error_for_symlink`; `::test_get_last_scan_raises_audit_log_error_for_symlink`; `::test_get_schema_version_raises_audit_log_error_for_symlink`; `::test_migrate_schema_raises_audit_log_error_for_symlink`; `test_audit_hardening.py::test_open_database_rejects_symlink`; `test_cache.py::test_raises_phi_scan_error_when_cache_path_is_symlink`; `test_logging_config.py::test_replace_logger_handlers_raises_phi_scan_logging_error_for_symlinked_log_path`; `::test_replace_logger_handlers_raises_phi_scan_logging_error_for_symlinked_parent_directory` | None known. |
| L-2 | SQL injection in audit log queries. | **P1** | Audit log uses parameterised queries (`sqlite3` `?` placeholders) exclusively; no string concatenation into SQL statements. | Coverage across `tests/test_audit.py` and `tests/test_audit_hardening.py`. | None known. |
| L-3 | Audit log accumulates PHI through `file_path` or finding metadata fields. | **P1** | `audit._serialize_findings` stores `value_hash` only — never raw values. File paths are the paths the operator asked PhiScan to scan (trusted). | `test_audit.py::test_serialize_findings_includes_value_hash` | If an operator scans a path that itself contains PHI in the filename, the audit log records the filename. This is a misconfiguration class issue, not a design gap — see assumption 1. |

### 3.9 CI integration adapters

| # | Threat | Severity | Mitigation | Test(s) | Residual risk |
|---|--------|----------|------------|---------|---------------|
| C-1 | CI token (GitHub, GitLab, Bitbucket) exfiltrated via logs or error messages. | **P1** | Tokens are read from environment variables; HTTP error paths explicitly exclude the request body and response body from exceptions. | `test_ci_integration_remaining.py::test_upload_sarif_http_error_excludes_response_body` | None known. |
| C-2 | CI upload host impersonation. | **P2** | HTTPS + stdlib CA trust store via `httpx`. Upload hosts are constants, not operator-supplied. | Inherited from `httpx` TLS defaults. | Same trust model as AI-3; residual risk is the same. |

---

## 4. Threats out of scope

The following threats are explicitly **not** part of PhiScan's threat
model. They are listed here so reviewers can see what has been
considered and deliberately excluded, rather than overlooked.

1. **Physical access to the host.** If an attacker has the disk, the
   audit log and cache are plaintext SQLite and they can read them. Use
   full-disk encryption.
2. **Compromised Python interpreter or stdlib.** Modelled as assumption 5.
3. **Malicious operator.** Modelled as assumption 1.
4. **Timing side channels on the hash function.** SHA-256 is used for
   fingerprinting and deduplication, not for secrecy. An attacker who
   can submit values and observe the hashes learns nothing beyond
   equality.
5. **Dependency supply-chain compromise.** Tracked under scorecard S9 /
   S10 / S11 (pending). When those gates are green, this row can move
   to scope.
6. **Denial of service via CPU exhaustion in the detection loop.** The
   10 MB file-size cap (I-2) bounds the per-file work; an operator
   asking PhiScan to scan millions of files accepts the aggregate cost
   by running the command.

---

## 5. Change management

- Any new outbound network call **must** add at least one row in
  section 3 and cite a named test. PR review should block otherwise.
- Any change to `_BLOCKED_IP_NETWORKS`, `_is_ip_address_blocked`, or
  `_normalise_ip_address` **must** update the N-3 through N-6 rows and
  add adversarial coverage in `tests/test_notifier_ssrf_adversarial.py`.
- The `Last reviewed` date at the top of this document should be
  updated whenever a row is added, removed, or materially changed. A
  reviewer should walk every P0 and P1 row at least once per release
  candidate.

---

## 6. Open items

- **S9 / S10 / S11**: dependency vulnerability scanning, SBOM, and
  artifact signing policy are tracked in the program scorecard and are
  not yet implemented. Until they ship, supply-chain compromise remains
  in the "out of scope" list above — with the understanding that it
  should move into scope as soon as those gates land.
- **D-3** (not enumerated above): fuzz coverage of the redaction
  functions would be defense-in-depth on top of the marker check.
  Candidate for a future `security/*` PR, not blocking v1.0.
