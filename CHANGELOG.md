# Changelog

All notable changes to PhiScan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_No changes yet._

## [0.7.0] - 2026-04-19

### Changed

- **v2 terminal renderer is now the default.** The redesigned grouped-output
  renderer (introduced behind `--report-format v2` in 0.6.x) is now the default
  `table` output. v2 aggregates findings by line, deduplicates remediation
  hints into a single playbook, and degrades cleanly under `NO_COLOR`, `CI=true`,
  and non-TTY (piped) environments — verified before release.
- **Non-breaking for CI pipelines.** This change is user-visible but non-breaking
  for anything parsing `--output json`, `--output sarif`, or exit codes. The
  `table` renderer's visual layout is not a stable contract and has never been;
  CI owners relying on structured output are safe.
- **Documentation:** Added an explicit "terminal output is not a stable
  interface" note to the README and `--report-format` help text, directing
  programmatic consumers to JSON or SARIF.

### Deprecated

- **`--report-format v1` is deprecated** and will be **removed in phi-scan
  0.8.0** (scheduled 2026-07). Passing `--report-format v1` continues to render
  the legacy output for one release but now prints a `DeprecationWarning` line
  to stderr pointing at `--output json` / `--output sarif` for stable
  machine-readable output. The `PHI_SCAN_REPORT_V2` environment variable has
  been removed — it was an opt-in for v2 during the flagged-preview period and
  is redundant now that v2 is the default.

## [0.6.2] - 2026-04-15

### Changed

- **README project description:** Softened compliance language throughout the
  README and the `pyproject.toml` short description. Removed the "HIPAA & FHIR
  compliant" phrasing from both the README tagline and the PyPI short
  description; replaced with language that describes PhiScan as designed for
  HIPAA-aligned and FHIR-based environments rather than claiming certification
  or guaranteed compliance. The "HIPAA audit trail" feature bullet is now
  "Audit trail designed for HIPAA-sensitive environments." No functional or
  API changes — PyPI long description and short summary will be refreshed on
  the next tagged release.

## [0.6.1] - 2026-04-15

### Fixed

- **Release workflow GitHub Release creation:** The `Create GitHub Release`
  step in `.github/workflows/release.yml` passed changelog content via
  `--notes "${{ steps.changelog.outputs.notes }}"`, which expanded multi-line
  text directly into the shell command before parsing. Tokens like
  `phi_scan.output.console:` were interpreted as shell commands, crashing the
  step. Fixed by writing notes to a temp file and using `--notes-file`. This
  caused the v0.6.0 GitHub Release to never be created (PyPI publish
  succeeded; Sigstore bundle was generated but never uploaded).

## [0.6.0] - 2026-04-15

_First S11-signed release. This section collects every change
shipped on `main` since `v0.5.0` (2026-04-04), including the public
Plugin API v1 / v1.1 surface that motivates the minor-version bump._

### Added

- **Plugin API v1 — recognizer surface (A1–A4):** Public, entry-point-based
  extension contract for custom PHI/PII recognizers. `BaseRecognizer`,
  `ScanContext`, `ScanFinding`, `PLUGIN_API_VERSION` are exported from
  `phi_scan`; plugins register via the `phi_scan.recognizers` entry-point
  group; `phi-scan plugins list` (with `--json`) enumerates discovered
  plugins. Per-plugin isolation boundary in
  `phi_scan.plugin_runtime._invoke_detect_with_isolation` documented in
  `CLAUDE.md`. Canonical contract: `docs/plugin-api-v1.md`.
- **Plugin API v1.1 — suppressor surface:** `BaseSuppressor.evaluate(finding,
  line) -> SuppressDecision`, entry-point group `phi_scan.suppressors`,
  deterministic `(distribution_name, entry_point_name)` ordering,
  first-`is_suppressed=True`-wins semantics. The suppressor stage runs in
  `_apply_post_scan_filters` after inline `phi-scan:ignore` and before the
  confidence/severity gates. Mirrors the recognizer isolation boundary.
  `phi-scan plugins list` now reports suppressors in both table and
  `--json` output (additive `suppressors` top-level key; existing
  `plugins` contract preserved byte-for-byte). Canonical contract:
  `docs/plugin-api-v1_1.md`.
- **Multi-provider AI support:** AI confidence review now supports Anthropic, OpenAI, and
  Google AI providers. Provider is inferred automatically from the model name:
  `claude-*` → Anthropic, `gpt-*`/`o1`/`o3`/`o4` → OpenAI, `gemini-*` → Google.
  Install the matching extra: `phi-scan[ai-anthropic]`, `phi-scan[ai-openai]`, or
  `phi-scan[ai-google]`. The existing `phi-scan[ai]` meta-extra continues to install Anthropic.
- **Provider-neutral configuration:** New `ai.enable_ai_review` key replaces the deprecated
  `ai.enable_claude_review`; new `ai.model` field selects the model and determines the provider.
  API keys are read from `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY` environment
  variables — storing keys in `.phi-scanner.yml` is explicitly rejected with a clear error.
- **AI token usage in audit log:** Each scan that uses AI review records `prompt_tokens`,
  `completion_tokens`, and `estimated_cost_usd` in the SQLite audit trail for cost tracking
  and compliance reporting.

### Security

- **Supply-chain gates (S9/S10/S11):** `pip-audit` dependency vulnerability
  gate in CI (S9); CycloneDX SBOM generated per release (S10); wheel and
  sdist signed with Sigstore keyless OIDC and bundles (`*.sigstore.json`)
  attached to each GitHub Release (S11). First release built with S11 is
  this one (`v0.6.0`).
- **ZIP decompression bomb protection:** Archive members are now validated against
  two guards before being read into memory: an absolute uncompressed size limit
  (`ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES`, 100 MB) and a compression ratio ceiling
  (`ARCHIVE_MAX_COMPRESSION_RATIO`, 200:1). Members that exceed either limit are
  skipped with a `WARNING` log; scanning continues with remaining members.
- **Webhook SSRF protection:** Webhook URLs are validated before any HTTP request.
  `http://` scheme is rejected (only `https://` permitted). Requests to RFC1918,
  loopback, link-local, CGNAT, and cloud metadata IP ranges are blocked by default.
  Set `notifications.is_private_webhook_url_allowed: true` to permit self-hosted targets
  on private networks.
- **HTML email escaping:** All dynamic fields in email notification templates
  (`repo`, `branch`, `file_path`, `category`, `severity`, `risk_level`) are now
  escaped with `html.escape()` before interpolation, preventing XSS via crafted
  branch or repository names.
- **Corrected security documentation:** README tagline and Why PhiScan section now
  accurately reflect that the "no external network calls" guarantee applies by
  default; the optional AI review layer is explicitly qualified as an opt-in
  exception.

### Deprecated

- **Top-level `phi_scan.cli_*` compatibility shims** (`cli_baseline`, `cli_config`,
  `cli_explain`, `cli_plugins`, `cli_report`, `cli_scan_config`, `cli_watch`) are
  deprecated. The canonical import paths are `phi_scan.cli.<name>`. The shims
  continue to work unchanged for the v1.x series and will be **removed in v2.0**.
  A runtime `DeprecationWarning` will be added in a later pre-v2.0 minor release.
  See `docs/lts-eol-policy.md` for the full deprecation timeline.

### Changed

- `ai.enable_claude_review` is deprecated — emits `DeprecationWarning`; still accepted for
  backward compatibility but will be removed in a future release.
- Per-provider token cost rates replace the single Anthropic rate. Cost estimates in the audit
  log now reflect the selected provider's published pricing.
- **`phi_scan/output/` package (7F.1):** `phi_scan/output.py` (2339 LOC) split into four
  focused submodules — `console.py` (Rich terminal UI), `serializers.py` (pure-data format
  functions), `dashboard.py` (live dashboard builders), `watch.py` (file-watcher event UI).
  All public symbols remain importable from `phi_scan.output` unchanged.
- **CI HTTP scaffolding deduplication (7F.2):** The `httpx → raise_for_status →
  HTTPStatusError → RequestError → CIIntegrationError` pattern that appeared verbatim 12
  times in `ci_integration.py` is replaced by a single `_execute_http_request` helper backed
  by `_HttpRequestConfig` and `_build_request_keyword_arguments`. No behaviour change.
- **Baseline CLI error handling deduplication (7F.3):** `_load_baseline_or_exit` and
  `_write_baseline_or_exit` helpers extracted from `cli.py`; replace repeated
  `try/except BaselineError → echo + raise typer.Exit` blocks in `baseline show`,
  `baseline diff`, `baseline create`, and `baseline update`.
- **`phi_scan/output/console/` sub-package (7G.3):** `phi_scan/output/console.py`
  (1307 LOC) split into five focused modules — `core.py` (console instance, progress,
  spinner), `findings.py` (findings table, file tree, code context, category breakdown),
  `summary.py` (banner, phase separators, scan header, clean/violation panels),
  `baseline.py` (baseline summary, diff, drift warning, scan notice). All public symbols
  remain importable from `phi_scan.output.console` unchanged. `_UNICODE_SUPPORTED` and
  `_resolve_symbol` remain in `__init__.py` to preserve `monkeypatch` compatibility in
  existing tests.
- **Security docs qualification (7H.1):** `SECURITY.md` "Local execution only" bullet
  qualified to reflect opt-in AI review — `ai.enable_ai_review` (disabled by default)
  sends redacted code structure only (never raw PHI) to the configured AI provider when
  explicitly enabled.
- **Notifier webhook payload model (7H.2):** Extracted `_WebhookScanSummary` frozen
  dataclass and `_build_webhook_scan_summary` factory from `notifier.py`. Slack, Teams,
  and generic payload builders each accept a single `_WebhookScanSummary`; the shared
  metadata (`is_clean`, `risk_level_label`, `findings_count`, `files_scanned`, etc.) is
  computed once per dispatch.
- **Shared structured-finding factory (7H.3):** Added `build_structured_finding` to
  `phi_scan/hashing.py`. FHIR and HL7 detection layers now delegate
  `compute_value_hash + severity_from_confidence + HIPAA_REMEDIATION_GUIDANCE.get` to
  this single function, eliminating the duplicated construction pattern.
- **CLI command-group split (7I):** `cli.py` (2328 LOC) reduced to 1976 LOC by
  extracting three sub-Typer apps: `cli_baseline.py` (`baseline` commands),
  `cli_config.py` (`config init`), `cli_explain.py` (11 `explain` topics). All CLI
  commands, help text, and exit codes are unchanged.

## [0.5.0] - 2026-04-04

### Added

- **CI/CD notifications:** `--post-comment` posts scan findings as a PR/MR comment;
  `--set-status` sets the commit status; `--upload-sarif` uploads SARIF to GitHub Code Scanning
  for inline PR diff annotations; auto-detects GitHub, GitLab, Azure DevOps, CircleCI, Bitbucket
- **Output formats:** `junit`, `codequality`, `gitlab-sast` added; all formats suppressed from
  stdout when `--report-path` is given
- **Enterprise reports:** PDF (`phi-scan[pdf]`) and HTML output formats with summary charts
- **Compliance frameworks:** `--framework gdpr,soc2,hitrust` annotates findings with applicable
  standards; HIPAA is always active
- **Docker image:** `ghcr.io/joeyessak/phi-scan` multi-arch (amd64/arm64) image published on
  every release
- **CI integrations:** GitHub Actions, GitLab CI, Azure Pipelines, Bitbucket Pipelines,
  CircleCI orb, AWS CodeBuild — each with native report group and annotation support
- **AI confidence review (BYOAK):** `phi-scan[ai]` optional extra; when `ANTHROPIC_API_KEY` is
  set, medium-confidence findings are re-scored by Claude to reduce false positives; PHI is
  always redacted before any API call; no raw PHI ever leaves the local machine
- **Scan history commands:** `phi-scan history show|diff|export` — query the SQLite audit log
  with `--repo` and `--violations-only` filters
- **GitHub Action:** `joeyessak/phi-scan-action` composite action — one-liner CI/CD integration
  for any repository; supports SARIF upload, PR comment, diff-only scanning, and AI review

### Changed

- Minimum Python version remains 3.12
- `--quiet` now suppresses the Rich banner and progress bar as well as the findings table

## [0.3.0] - 2026-03-30

### Added

- **Detection engine — 4 layers:**
  - Layer 1: Regex pattern registry covering all 18 HIPAA Safe Harbor identifiers plus MBI,
    HICN, DEA number, genetic identifiers (rs-IDs, VCF, Ensembl), SUD-related field names,
    age >90, quasi-identifier combinations (ZIP + DOB + sex), and NPI type distinction
  - Layer 2: NLP named entity recognition via Presidio + spaCy (`phi-scan[nlp]` optional extra)
  - Layer 3: FHIR R4 structured field scanning and HL7 v2 segment scanning (PID, NK1, IN1)
    via `phi-scan[fhir]` and `phi-scan[hl7]` optional extras
  - Layer 4: AI-assisted confidence scoring via Claude API (optional, disabled by default,
    PHI is always redacted before any API call)
- **CLI commands:** `scan`, `scan --diff`, `scan --file`, `watch`, `report`, `history`,
  `init`, `setup`, `fix`, `explain`, `baseline`, `install-hook`, `uninstall-hook`,
  `config init`, `dashboard`, `plugins list`
- **Output formats:** `table`, `json`, `csv`, `sarif`, `junit`, `codequality`, `gitlab-sast`
- **Baseline management:** `phi-scan baseline create|show|clear|update|diff` — adopt
  PhiScan incrementally in existing codebases; only new findings block CI
- **Auto-fix engine:** `phi-scan fix --dry-run|--apply|--patch` — replace PHI with
  deterministic synthetic data (requires `faker`)
- **Inline suppression:** `# phi-scan:ignore`, `# phi-scan:ignore[SSN,MRN]`,
  `# phi-scan:ignore-next-line`, `# phi-scan:ignore-file` with language-aware prefixes
- **SQLite audit log:** immutable HIPAA-compliant scan history; SHA-256 hashes only,
  raw PHI values never stored
- **Structured output cache:** content-hash based scan cache to skip unchanged files
- **Pre-commit framework integration:** `.pre-commit-hooks.yaml` registers phi-scan as a
  pre-commit hook; `phi-scan install-hook` installs a native git pre-commit hook
- **Rich terminal UI:** progress bar, findings table, file tree, code context panels,
  ASCII banner; suppressed automatically for piped/serialised output formats
- **Graceful degradation:** NLP, FHIR, HL7, and AI layers each degrade to a logged
  warning when their optional dependency group is not installed
- **PHI hygiene at detection layer:** matched PHI values are redacted to `[REDACTED]` in
  `code_context` before `ScanFinding` is constructed — raw values never stored or displayed
- **Rich markup safety:** user-derived strings (file paths, source lines) are escaped
  before Rich rendering to prevent `MarkupError` crashes on source containing `[` characters

### Changed

- Version bumped from `0.1.0` to `0.3.0` (Phases 1–3C complete per version table in PLAN.md)
- Dependency bounds narrowed to compatible-release pins (`~=`) for predictable installs

## [0.1.0] - 2026-03-01

### Added

- Project scaffolding: `pyproject.toml`, CI workflows (lint, typecheck, test, release,
  Claude PR review), MIT license, `README.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`
- Typer CLI skeleton with Rich terminal UI and pyfiglet ASCII banner
- Structured logging (`--log-level`, `--log-file`)
- YAML configuration loading and validation (`.phi-scanner.yml`)
- Git diff file extraction (`--diff` mode)
- `.phi-scanignore` exclusion pattern support (gitignore-style via pathspec)

[Unreleased]: https://github.com/phiscanhq/phi-scan/compare/v0.6.2...HEAD
[0.6.2]: https://github.com/phiscanhq/phi-scan/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/phiscanhq/phi-scan/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/phiscanhq/phi-scan/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/phiscanhq/phi-scan/compare/v0.3.0...v0.5.0
[0.3.0]: https://github.com/phiscanhq/phi-scan/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/phiscanhq/phi-scan/releases/tag/v0.1.0
