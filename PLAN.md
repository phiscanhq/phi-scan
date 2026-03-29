# PLAN.md — PhiScan Master Project Plan

**PHI/PII Scanner for CI/CD Pipelines**
Created: March 15, 2026 | Updated: March 27, 2026 | Python 3.12.3 | uv 0.10.9

---

## Versioning Strategy

PhiScan follows semantic versioning. The version stays at `0.x.y` throughout
development. Version `1.0.0` is reserved for the Phase 9 public launch when
all core features are production-ready and tested.

| Milestone        | Version | Trigger                           |
| ---------------- | ------- | --------------------------------- |
| Phase 1 complete | 0.1.0   | CLI shell installable             |
| Phase 2 complete | 0.2.0   | Detection engine working          |
| Phase 3 complete | 0.3.0   | Output formats + PyPI publish     |
| Phase 4 complete | 0.4.0   | Enterprise reports + docs         |
| Phase 5 complete | 0.5.0   | Notifications + audit hardening   |
| Phase 6 complete | 0.6.0   | CI/CD templates + Docker          |
| Phase 7 complete | 0.7.0   | AI enhancement (optional)         |
| Phase 8 complete | 0.8.0   | Pro tier + monetization           |
| Phase 9 (launch) | 1.0.0   | Hardening complete, public launch |

---

## Verified Development Environment

All tools confirmed installed and version-verified in WSL on March 15, 2026:

| Tool          | Version | Verified |
| ------------- | ------- | -------- |
| Python        | 3.12.3  | Yes      |
| uv            | 0.10.9  | Yes      |
| Ruff          | 0.15.6  | Yes      |
| Black         | 26.3.1  | Yes      |
| Rich          | 13.7.1  | Yes      |
| Typer         | 0.24.1  | Yes      |
| python-dotenv | 1.2.2   | Yes      |
| Make          | 4.3     | Yes      |
| Docker        | 29.3.0  | Yes      |
| SQLite3       | 3.45.1  | Yes      |
| pipx          | 1.4.3   | Yes      |
| gh CLI        | 2.45.0  | Yes      |
| Git           | 2.43.0  | Yes      |
| Anthropic SDK | 0.84.0  | Yes      |

---

## Current State (March 27, 2026)

**Phase 1A complete. Phase 1B complete. Phase 1C in progress.**

```
phi-scan/
├── .git/
├── .github/workflows/  ← ci.yml (lint, typecheck, test) + claude-review.yml
├── .gitignore          ← Python + PHI-risk entries
├── .phi-scanignore     ← exclusion patterns (gitignore-style)
├── .phi-scanner.yml    ← default scanner configuration
├── .python-version     ← 3.12
├── .venv/              ← uv sync, Python 3.12.3
├── CHANGELOG.md
├── CLAUDE.md
├── LICENSE             ← MIT
├── Makefile            ← install, lint, typecheck, test, scan, help
├── PLAN.md             ← this file
├── README.md           ← project overview, install, usage, CI badge
├── SECURITY.md
├── pyproject.toml      ← full metadata, all deps, entry point, ruff/pytest config
├── uv.lock
├── phi_scan/
│   ├── __init__.py         ← __version__ = "0.1.0", __app_name__ = "phi-scan"
│   ├── py.typed
│   ├── constants.py        ← all named constants and enums (complete)
│   ├── exceptions.py       ← PhiScanError hierarchy (complete)
│   ├── models.py           ← ScanFinding, ScanResult, ScanConfig (complete)
│   ├── logging_config.py   ← structured logging, Rich console handler (complete)
│   ├── config.py           ← YAML config loading and validation (complete)
│   ├── scanner.py          ← recursive traversal, Phase 2 detection stub (complete)
│   ├── diff.py             ← git diff file extraction (complete)
│   ├── audit.py            ← SQLite HIPAA-compliant audit logging (complete)
│   ├── output.py           ← formatters + Rich UI components (complete)
│   └── cli.py              ← Typer app with all Phase 1 commands (complete)
└── tests/
    ├── conftest.py
    ├── test_models.py      ← 71 tests, 100% models.py coverage
    └── ...                 ← additional test files per module
```

---

## Phase Dependencies

```
Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► Phase 6 ──┐
                                                                       │
                                                      Phase 7 (opt.) ◄─┤
                                                                       │
                                                      Phase 8 ◄────────┘
                                                        │
                                                      Phase 9
```

Every phase depends on the previous one being complete. Phase 7 (AI) is optional
and can be skipped — Phase 8 depends on Phase 6, not Phase 7. Phase 9 depends on Phase 8.

**Phase count changed from 8 → 9.** Phase 3 split into two (output + enterprise).
VS Code extension moved to its own phase within Phase 8. New Phase 9 for launch.

---

## Phase 1: Terminal CLI App (Weeks 1–4)

**Goal:** A fully installable CLI tool with core commands wired up, recursive file
traversal, Rich terminal UI, SQLite audit schema, config loading, structured logging,
and output formatting. Detection engine returns empty results — Phase 2 plugs in
detection. Suppression, caching, and explain content deferred to Phase 2.

**Exit Criteria:** `pipx install .` works, `phi-scan --help` shows all commands,
`phi-scan scan <path>` traverses files and exits cleanly, `make test` passes.

**Performance target:** CLI startup time < 500ms for non-scan commands (`--version`, `--help`,
`config init`). Lazy-import heavy modules (Rich progress, pyfiglet, watchdog) to avoid
import overhead on every invocation. Critical for pre-commit hook responsiveness.

**Estimated effort: 4 weeks** (reduced scope from original; suppression, cache,
and explain commands deferred to Phase 2).

### 1A — Project Scaffolding & Dependencies

- [x] **1A.1** Create `LICENSE` file — MIT license with copyright year and author name
- [x] **1A.2** Create `CHANGELOG.md` — initial entry: `## [Unreleased]` section
- [x] **1A.3** Create `SECURITY.md` — vulnerability reporting policy (email, response commitment, disclosure timeline)
- [x] **1A.4** Rewrite `pyproject.toml` — full metadata, all core dependencies, `[project.scripts]` entry point, version `0.1.0`
  - Include `[project.optional-dependencies]` groups: see Dependency Strategy section below
  - Include `[tool.ruff]` configuration
  - Include `[tool.pytest.ini_options]` configuration
  - Include `py.typed` marker in `[tool.setuptools.package-data]`
- [x] **1A.5** `uv add` core deps: `typer[all]`, `rich`, `pyyaml`, `python-dotenv`, `pyfiglet`, `watchdog`, `httpx`, `pathspec`
- [x] **1A.6** `uv add --dev` dev deps: `pytest`, `pytest-cov`, `ruff`, `mypy`
- [x] **1A.7** `uv sync` — generate `uv.lock` (commit it)
- [x] **1A.8** Delete `main.py` — replaced by `phi_scan/cli.py` entry point
- [x] **1A.9** Create `phi_scan/` package directory with all module files
- [x] **1A.10** Create `phi_scan/py.typed` — PEP 561 type checking marker file
- [x] **1A.11** Create `tests/` directory with `conftest.py`
- [x] **1A.12** Create `Makefile` — targets: `install`, `lint`, `typecheck`, `test`, `scan`, `help`
- [x] **1A.13** Create `.phi-scanner.yml` — default scanner configuration
- [x] **1A.14** Create `.phi-scanignore` — default exclusion patterns (see Ignore Format Spec below)
- [x] **1A.15** Update `.gitignore` — add `.env`, `*.db`, `*.sqlite3`, `.phi-scanner/`, `phi-report.json`, `dist/`, `*.egg-info`
- [x] **1A.16** Update `README.md` — project name, install instructions, basic usage, license badge
- [x] **1A.17** Create `.github/workflows/ci.yml` — PhiScan's own CI pipeline (see 1H below)

### 1B — Package Modules (`phi_scan/`)

- [x] **1B.1** `__init__.py` — `__version__ = "0.1.0"`, `__app_name__ = "phi-scan"`
- [x] **1B.2** `constants.py` — all named constants and enums
  - `DEFAULT_CONFIG_FILENAME`, `DEFAULT_IGNORE_FILENAME`
  - `KNOWN_BINARY_EXTENSIONS` — skip list (.png, .jpg, .gif, .ico, .wasm, .exe, .dll, .so, .dylib, .zip, .tar, .gz, .jar, .pyc, .pyo, .o, .a, .pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx, .mp3, .mp4, .mov, .avi, .wav, .ttf, .woff, .woff2, .eot)
  - `BINARY_CHECK_BYTE_COUNT = 8192` — read first 8KB to detect binary via null bytes
  - `DEFAULT_CONFIDENCE_THRESHOLD = 0.6`, `MAX_FILE_SIZE_MB = 10`
  - Confidence threshold constants:
    - `CONFIDENCE_HIGH_FLOOR = 0.90` — HIGH severity (almost certainly PHI)
    - `CONFIDENCE_MEDIUM_FLOOR = 0.70` — MEDIUM severity (likely PHI, possible false positive)
    - `CONFIDENCE_LOW_FLOOR = 0.40` — LOW severity (possible PHI, high FP risk)
    - Below 0.40 = INFO — very weak signal, logged but not flagged by default
  - Confidence ranges per detection layer:
    - Regex (Layer 1): 0.85–1.0 (structured patterns are unambiguous)
    - NLP/NER (Layer 2): 0.50–0.90 (context-dependent, model uncertainty)
    - FHIR (Layer 3): 0.80–0.95 (schema-based structural match)
    - AI (Layer 4): adjusts existing scores ±0.15 (second-opinion refinement)
  - `AUDIT_RETENTION_DAYS = 2192` (HIPAA 6-year minimum — 4×365 + 2×366, the mathematical maximum for a 6-year span; must match `.phi-scanner.yml` default)
  - `EXIT_CODE_CLEAN = 0`, `EXIT_CODE_VIOLATION = 1`
  - Enums: `OutputFormat` (TABLE, JSON, SARIF, CSV, PDF, HTML, JUNIT, CODEQUALITY, GITLAB_SAST), `SeverityLevel` (LOW, MEDIUM, HIGH)
  - Enum: `RiskLevel` (CRITICAL, HIGH, MODERATE, LOW, CLEAN)
  - Enum: `PhiCategory` — 18 HIPAA Safe Harbor members (NAME through UNIQUE_ID) plus two
    extended regulatory members that must be added here and not deferred:
    - `SUBSTANCE_USE_DISORDER = "substance_use_disorder"` — 42 CFR Part 2 scope; distinct
      statute with stricter consent rules; must not be aliased to UNIQUE_ID
    - `QUASI_IDENTIFIER_COMBINATION = "quasi_identifier_combination"` — re-identification
      risk from field combinations; not a Safe Harbor category; must not be aliased to UNIQUE_ID
    Both members must also have entries in `HIPAA_REMEDIATION_GUIDANCE` in this same task.
  - `QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES = 50` — module-level constant; referenced by
    `detect_quasi_identifier_combination()` in Phase 2E.11
  - `MINIMUM_QUASI_IDENTIFIER_COUNT = 2` — minimum distinct quasi-identifier categories
    required to trigger a combination finding; the literal `2` must never appear in logic code
  - `HIPAA_AGE_RESTRICTION_THRESHOLD = 90` — HIPAA §164.514(b)(2)(i) restricts ages "over
    90" (strictly greater than 90 = ages 91+); logic code uses `age > HIPAA_AGE_RESTRICTION_THRESHOLD`;
    the literal `90` must never appear in detection logic
  - Identifier structure constants (prevent magic values in regex pattern construction):
    - `MBI_CHARACTER_COUNT = 11` — fixed character count of a Medicare Beneficiary Identifier
    - `DEA_NUMBER_DIGIT_COUNT = 7` — digit count in a DEA number (2-letter prefix + 7 digits)
    - `VIN_CHARACTER_COUNT = 17` — fixed character count of a VIN (ISO 3779)
    - `DBSNP_RS_ID_MIN_DIGITS = 7` — minimum digit count in a dbSNP rs-ID
    - `DBSNP_RS_ID_MAX_DIGITS = 9` — maximum digit count in a dbSNP rs-ID
    - `ENSEMBL_GENE_ID_DIGIT_COUNT = 11` — digit count in an Ensembl gene ID (ENSG + 11 digits)
    - `FICTIONAL_PHONE_EXCHANGE = 555` — FCC-reserved fictional NANP exchange; exclude from
      real-phone detection; use for synthetic data generation in `phi-scan fix`
    - `FICTIONAL_PHONE_SUBSCRIBER_DISPLAY_PREFIX = "0"` — leading zero required to render
      4-digit NANP subscribers (100 → "0100"); must not appear as a bare `"0"` literal
    - `FICTIONAL_PHONE_SUBSCRIBER_MIN = 100` — start of FCC fictional subscriber range (0100)
    - `FICTIONAL_PHONE_SUBSCRIBER_MAX = 199` — end of FCC fictional subscriber range (0199)
    - `ZIP_CODE_SAFE_HARBOR_POPULATION_MIN = 20_000` — minimum census population for a 3-digit
      ZIP prefix to qualify as safe harbor under §164.514(b)(2)(i)
  - Regex pattern string constants (prevent magic string literals in detection logic):
    - `MBI_ALLOWED_LETTERS = "AC-HJ-KM-NP-RT-Y"` — CMS-approved letters for MBI positions
      2, 3, 5, 6, 8, 9 (excludes S, L, O, I, B, Z per CMS specification); used to build
      the MBI regex — never embed `AC-HJ-KM-NP-RT-Y` inline in any pattern string
    - `SSN_EXCLUDED_AREA_NUMBERS: frozenset[int]` — SSA area numbers never assigned per
      §205.20 regulations: `frozenset({666, *range(900, 1000)})`; used to build SSN exclusion
      regex — never embed `666`, `900`, or `999` as literals in pattern strings
    - `SUD_FIELD_NAME_PATTERNS: frozenset[str]` — 42 CFR Part 2 SUD-suggestive field names;
      detection logic iterates this set — never embed the strings inline in detection code
  - `HIPAA_REMEDIATION_GUIDANCE` — dict mapping each `PhiCategory` member to specific
    remediation text; must cover all members including the two extended ones above
  - `SCHEMA_VERSION = 1` — audit DB schema version for migration tracking
  - `CACHE_SCHEMA_VERSION = 1` — cache DB schema version
- [x] **1B.3** `exceptions.py` — `PhiScanError` (base), `ConfigurationError`, `TraversalError`, `AuditLogError`, `SchemaMigrationError`
- [x] **1B.4** `models.py` — dataclasses:
  - `ScanFinding` (file_path, line_number, entity_type, hipaa_category, confidence, detection_layer, value_hash, severity, code_context, remediation_hint)
  - `ScanResult` (findings, files_scanned, files_with_findings, scan_duration, is_clean, risk_level, severity_counts, category_counts)
  - `ScanConfig` (exclude_paths, severity_threshold, confidence_threshold, follow_symlinks, max_file_size_mb, include_extensions — optional allowlist filter, defaults to None meaning scan all text files)
- [x] **1B.5** `logging_config.py` — structured logging setup
  - Configure Python `logging` module with named logger `phi_scan`
  - Log levels: DEBUG, INFO, WARNING, ERROR
  - Console handler with Rich-formatted output (respects `--quiet` and `NO_COLOR`)
  - File handler: optional log file output to `~/.phi-scanner/phi-scan.log`
  - `--log-level` CLI flag: controls console verbosity (default: WARNING)
  - `--log-file` CLI flag: enable persistent file logging
  - All traversal events (symlink skip, permission error, binary skip) use structured logger
  - Log format: `[%(asctime)s] %(levelname)s %(name)s: %(message)s`
- [x] **1B.6** `config.py` — YAML config loading
  - `load_config(config_path)` → `ScanConfig`
  - `create_default_config(output_path)` — writes default `.phi-scanner.yml`
  - Validation raises `ConfigurationError` on invalid values — never silently fall back
  - Map `gitlab-sast` → `OutputFormat.GITLAB_SAST` explicitly (not via generic replace/upper)
  - Call `Path(database_path).expanduser()` before any file I/O — never pass raw `~` string
  - Raise `ConfigurationError` (not `ValueError`) if `follow_symlinks: true` is set;
    use `if scan_config.follow_symlinks:` (boolean check — no magic string `"true"` in logic)
- [x] **1B.7** `scanner.py` — recursive file traversal (NO detection yet)
  - `collect_scan_targets(root_path, excluded_patterns, config)` → `list[Path]` via `pathlib.rglob("*")`
  - `is_path_excluded(file_path, excluded_patterns)` → bool
  - `is_binary_file(file_path)` → bool — check `KNOWN_BINARY_EXTENSIONS` first, then read first 8KB for null bytes
  - `load_ignore_patterns(ignore_file_path)` → `list[str]`
  - `scan_file(file_path)` → `list[ScanFinding]` — **empty list placeholder** (Phase 2 fills this)
  - `execute_scan(scan_targets)` → `ScanResult` — iterates with per-file `PermissionError` isolation
  - Symlink skip + warning log, file size check against `max_file_size_mb`
  - Binary file skip + info log (scans ALL text files regardless of extension)
  - All warnings/info use `logging_config` logger (not print statements)
- [x] **1B.8** `diff.py` — git diff file extraction for `--diff` mode
  - `get_changed_files_from_diff(diff_ref)` → `list[Path]` — parse `git diff --name-only`
  - `get_staged_files()` → `list[Path]` — parse `git diff --cached --name-only`
  - Handle renamed files: `git diff --name-only --diff-filter=ACMR` (Added, Copied, Modified, Renamed)
  - Handle deleted files: exclude from scan targets (file no longer exists)
  - Guard: raise `TraversalError` with clear message when not inside a git repository
  - Guard: raise `TraversalError` when diff ref is invalid (e.g., `HEAD~1` with no commits)
  - Support formats: `HEAD~N`, `branch..branch`, `commit_sha`, `--staged`
- [x] **1B.9** `audit.py` — SQLite audit log (HIPAA-compliant immutable)
  - `create_audit_schema(database_path)` — CREATE TABLE IF NOT EXISTS with `schema_version` metadata table
  - `insert_scan_event(database_path, scan_result)` — INSERT only, never UPDATE/DELETE
  - `query_recent_scans(database_path, days)` → list of scan events
  - `get_last_scan(database_path)` → most recent scan event
  - `get_schema_version(database_path)` → int — read current schema version
  - `migrate_schema(database_path, from_version, to_version)` — apply sequential migrations
  - Table: `scan_events` (id, timestamp, scanner_version, repository, branch, files_scanned, findings_count, findings_json, is_clean, scan_duration)
  - Table: `schema_meta` (key, value) — stores `schema_version`, `created_at`
  - On startup: check schema version, migrate if needed, raise `SchemaMigrationError` on failure
- [x] **1B.10** `output.py` — formatters + Rich visual components
  - `format_table(scan_result)` — Rich table, color-coded rows (red=high, yellow=medium, green=low)
  - `format_json(scan_result)` — JSON serialization
  - `format_csv(scan_result)` — CSV string with headers
  - `format_sarif(scan_result)` — SARIF 2.1 JSON (GitHub Advanced Security)
  - `display_banner()` — pyfiglet ASCII art banner with Rich gradient styling
  - `display_scan_header(path, config)` — styled panel showing what's being scanned + config summary
  - `display_scan_progress(total_files)` — Rich Progress with multiple columns (spinner, bar, file count, file name, elapsed time)
  - `display_findings_table(findings)` — color-coded table with severity badges and code context
  - `display_file_tree(findings)` — Rich Tree showing affected files with finding counts per file
  - `display_summary_panel(scan_result)` — bordered summary: risk level badge, severity breakdown, file stats, scan time
  - `display_clean_result()` — large green checkmark with "No PHI/PII detected" celebration
  - `display_violation_alert(scan_result)` — red alert banner with finding count and risk level
  - `display_category_breakdown(scan_result)` — Rich table showing count per HIPAA category with bar-style column
- [x] **1B.11** `cli.py` — Typer app with all commands
  - `scan` — path arg, `--diff`, `--file`, `--output`, `--config`, `--severity-threshold`, `--log-level`, `--log-file`, `--quiet`, `--no-cache` (no-op until Phase 2)
  - `watch` — path arg, watchdog file monitoring + re-scan on change
    - **Phase 1 behavior:** traverses files and reports file count per change event
    - **Phase 2 behavior:** full detection on each re-scan
    - Watch mode displays a clear message: "Detection engine not active — install phi-scan[nlp] for full scanning"
  - `report` — display last scan from SQLite
  - `history` — `--last` period filter (e.g., `30d`)
  - `install-hook` — write `.git/hooks/pre-commit` script
  - `uninstall-hook` — remove phi-scan pre-commit hook
  - `init` — guided first-run wizard: creates `.phi-scanner.yml`, `.phi-scanignore`, installs git hook, downloads spaCy model (if [nlp] installed), runs first scan preview — all in one command
  - `config init` — interactive Typer prompts, generates `.phi-scanner.yml` only (subset of `init`)
  - `dashboard` — Rich Live real-time display
  - `setup` — downloads spaCy model and verifies dependencies (see Dependency Strategy)
  - `--version` callback
  - Every command and flag has a descriptive `help=` string in Typer
  - All `--help` output auto-generated by Typer with rich formatting
  - Respect `NO_COLOR` environment variable (per no-color.org standard)

### 1C — Rich Terminal UI & Visual Design

The terminal experience is the product's first impression. Every scan should feel
polished, informative, and visually striking. Users should enjoy running this tool.

#### 1C.1 — Scan Startup Visuals

- [x] **1C.1a** ASCII banner via pyfiglet — "PhiScan" rendered in a bold font (e.g., `slant` or `big`)
- [x] **1C.1b** Banner styled with Rich gradient coloring (cyan → blue → purple)
- [x] **1C.1c** Version + tagline below banner: `v0.1.0 — HIPAA-Compliant PHI/PII Scanner`
- [x] **1C.1d** `console.rule()` separator with styled title: `─── Initializing Scan ───`
- [x] **1C.1e** Scan header panel — bordered box showing:
  - Target path being scanned
  - Config file in use (or "defaults")
  - Severity threshold
  - Timestamp

#### 1C.2 — Live Scan Progress

- [x] **1C.2a** Rich Progress bar with multiple columns:
  - Animated spinner (dots style)
  - Progress bar with percentage `[████████░░░░░░░░] 52%`
  - File count: `1,247 / 2,390 files`
  - Current file name (truncated to fit): `src/api/handlers/patient.py`
  - Elapsed time: `[00:03.2s]`
- [x] **1C.2b** Phase separators between scan stages:
  - `─── Collecting Files ───`
  - `─── Scanning for PHI/PII ───`
  - `─── Writing Audit Log ───`
  - `─── Generating Report ───`
- [x] **1C.2c** File type summary after collection phase:
  - Mini table: `.py: 342 | .json: 128 | .yaml: 45 | .ts: 890 | other: 95`
- [x] **1C.2d** Spinner with status text during config load and audit log writes

#### 1C.3 — Clean Scan Result (Zero Findings)

- [x] **1C.3a** Large green shield/checkmark symbol: `✅` or ASCII art shield
- [x] **1C.3b** Bold green text: `CLEAN — No PHI or PII Detected`
- [x] **1C.3c** Summary panel with green border:
  ```
  ╭─────────────────── Scan Complete ───────────────────╮
  │  Status:        ✅ CLEAN                            │
  │  Files scanned: 2,390                               │
  │  Scan time:     4.2 seconds                         │
  │  Risk level:    CLEAN                               │
  ╰─────────────────────────────────────────────────────╯
  ```
- [x] **1C.3d** Exit with green-colored exit code message: `Exit code: 0 (clean)`

#### 1C.4 — Violation Result (Findings Detected)

- [x] **1C.4a** Red alert banner — full-width, bold:
  ```
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  ⚠  PHI/PII DETECTED — 12 findings in 4 files       ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
  ```
- [x] **1C.4b** Risk level badge — color-coded:
  - `[CRITICAL]` — bold red background, white text
  - `[HIGH]` — red text
  - `[MODERATE]` — yellow text
  - `[LOW]` — dim yellow text

- [x] **1C.4c** Severity breakdown — inline colored counters:

  ```
  🔴 HIGH: 4    🟡 MEDIUM: 5    🟢 LOW: 3
  ```

- [x] **1C.4d** HIPAA category breakdown table:

  ```
  ┌─────────────────────┬───────┬──────────────────────┐
  │ HIPAA Category      │ Count │ Distribution         │
  ├─────────────────────┼───────┼──────────────────────┤
  │ #7  SSN             │     4 │ ████████████░░░░ 33% │
  │ #1  Names           │     3 │ █████████░░░░░░░ 25% │
  │ #8  MRN             │     2 │ ██████░░░░░░░░░░ 17% │
  │ #6  Email Addresses │     2 │ ██████░░░░░░░░░░ 17% │
  │ #3  Dates           │     1 │ ███░░░░░░░░░░░░░  8% │
  └─────────────────────┴───────┴──────────────────────┘
  ```

- [x] **1C.4e** Affected files tree — Rich Tree view:

  ```
  📁 Affected Files (4 files, 12 findings)
  ├── 🔴 tests/fixtures/patient_data.json      (5 findings)
  ├── 🔴 src/api/handlers/patient.py           (3 findings)
  ├── 🟡 src/utils/seed_data.py                (2 findings)
  └── 🟡 config/test_database.yml              (2 findings)
  ```

- [x] **1C.4f** Detailed findings table — Rich Table with columns:

  ```
  ┌────┬──────────────────────────────────┬──────┬──────────┬────────┬────────────┐
  │  # │ File                             │ Line │ Type     │ HIPAA  │ Confidence │
  ├────┼──────────────────────────────────┼──────┼──────────┼────────┼────────────┤
  │  1 │ tests/fixtures/patient_data.json │   42 │ SSN      │ #7     │ ●●●●○ 0.98 │
  │  2 │ tests/fixtures/patient_data.json │   15 │ PERSON   │ #1     │ ●●●○○ 0.87 │
  │  3 │ src/api/handlers/patient.py      │  128 │ EMAIL    │ #6     │ ●●●●○ 0.94 │
  └────┴──────────────────────────────────┴──────┴──────────┴────────┴────────────┘
  ```

- [x] **1C.4g** Code context panel per finding — Rich Syntax with line numbers:

  ```
  ╭─── tests/fixtures/patient_data.json:42 ─── SSN (HIGH) ───╮
  │  40 │   "insurance": "Aetna",                             │
  │  41 │   "policy_number": "AET-29481",                     │
  │ ►42 │   "ssn": "[REDACTED]",              ← PHI DETECTED  │
  │  43 │   "primary_care": "Dr. Smith",                      │
  │  44 │   "pharmacy": "CVS #4521"                           │
  │                                                           │
  │  💡 Remediation: Replace with synthetic SSN (000-00-0000) │
  │     Use env vars or a secrets vault for test data.        │
  ╰───────────────────────────────────────────────────────────╯
  ```

- [x] **1C.4h** Summary panel with red/yellow border (matches risk level):
  ```
  ╭────────────────────── Scan Complete ──────────────────────╮
  │  Status:        ⚠  VIOLATION                             │
  │  Risk Level:    [CRITICAL]                               │
  │  Findings:      12  (🔴 4 HIGH  🟡 5 MED  🟢 3 LOW)     │
  │  Files:         4 of 2,390 contain PHI                   │
  │  Scan time:     4.2 seconds                              │
  │  Audit log:     ~/.phi-scanner/audit.db                  │
  │  Action:        Pipeline BLOCKED — exit code 1           │
  ╰──────────────────────────────────────────────────────────╯
  ```

#### 1C.5 — Dashboard Mode (`phi-scan dashboard`)

- [x] **1C.5a** Rich Live display — auto-refreshing terminal dashboard
- [x] **1C.5b** Dashboard layout panels:
  - Top: ASCII banner (compact) + scan status
  - Left: recent scan history (last 10 scans from audit log)
  - Right: HIPAA category totals across all scans
  - Bottom: live file watcher status (if watching)
- [x] **1C.5c** Color-coded scan history rows: green = clean, red = violation
- [x] **1C.5d** Auto-refresh interval: 2 seconds

#### 1C.6 — Watch Mode Visuals (`phi-scan watch`)

- [x] **1C.6a** Persistent header: "Watching: ./src — Press Ctrl+C to stop"
- [x] **1C.6b** File change detection notification: `[14:32:05] Changed: src/api/patient.py`
- [x] **1C.6c** Mini scan result inline after each re-scan: `✅ Clean` or `⚠ 2 findings detected`
- [x] **1C.6d** Rolling log of last 10 watch events
- [x] **1C.6e** Clear message when detection not active: "Detection engine not loaded — run `phi-scan setup` to enable full scanning"

#### 1C.7 — Color Theme & Consistency

- [x] **1C.7a** Consistent color palette across all output:
  - Severity HIGH: `red` / `bold red`
  - Severity MEDIUM: `yellow`
  - Severity LOW: `green` (informational, not alarming)
  - Clean/success: `bold green`
  - Headers/labels: `cyan` / `bold cyan`
  - Metadata/secondary: `dim` / `grey`
  - Banner accent: gradient `cyan → blue → magenta`
- [x] **1C.7b** Consistent Unicode symbols:
  - Clean: ✅ or ✔
  - Violation: ⚠ or 🚨
  - File: 📄
  - Folder: 📁
  - Severity dots: ● (filled) ○ (empty) for confidence visualization
  - Arrow: ► for highlighted line in code context
- [x] **1C.7c** Graceful fallback for terminals without Unicode — ASCII alternatives
- [x] **1C.7d** Respect `--quiet` flag — suppress all visual output, return only exit code
- [x] **1C.7e** Respect `NO_COLOR` environment variable (per no-color.org standard)

### 1D — Git Hook Integration

- [x] **1D.1** `install_hook` — write executable shell script to `.git/hooks/pre-commit`
- [x] **1D.2** `uninstall_hook` — detect and remove the phi-scan hook
- [x] **1D.3** Guard: check `.git/` exists, warn if not a git repo

### 1E — Makefile & Installability

- [x] **1E.1** Makefile targets: `install`, `lint`, `typecheck`, `test`, `scan`, `help`
- [x] **1E.2** `make typecheck` runs `mypy phi_scan/` — zero errors required
- [x] **1E.3** Verify `pipx install .` works — `phi-scan --version` returns version
- [x] **1E.4** Verify `phi-scan --help` shows all commands with descriptions

### 1F — Testing

- [x] **1F.1** `tests/conftest.py` — shared fixtures (tmp dirs with nested files, sample configs)
- [x] **1F.2** `tests/test_scanner.py` — `collect_scan_targets()`: multi-depth, binary detection, symlinks, excludes, PermissionError
  - Test: known binary extensions (.png, .exe, .zip) are skipped
  - Test: unknown binary files (null bytes in first 8KB) are skipped
  - Test: text files with unusual extensions (.conf, .cfg, .properties) are included
  - Test: files with no extension are scanned if text content detected
- [x] **1F.3** `tests/test_config.py` — loads valid YAML, defaults when missing, raises on invalid
  - `test_audit_retention_days_matches_config_default` — asserts `AUDIT_RETENTION_DAYS == 2192`
    to prevent silent drift between `constants.py` and `.phi-scanner.yml`
- [x] **1F.4** `tests/test_cli.py` — CLI smoke tests: `--version`, `scan <path>`, `--help`
- [x] **1F.5** `tests/test_ignore.py` — `.phi-scanignore` pattern matching at any depth (see Ignore Format Spec)
- [x] **1F.6** `tests/test_output.py` — visual output tests:
  - Table format produces Rich-renderable output with correct column count
  - JSON format is valid JSON
  - CSV format has correct headers
  - Clean scan triggers green success panel (no red/alert elements)
  - `--quiet` flag suppresses all Rich output
  - `NO_COLOR` env var produces uncolored output
- [x] **1F.7** `tests/test_audit.py` — schema creation, event insert, query, immutability, schema version check
- [x] **1F.8** `tests/test_diff.py` — git diff file extraction tests:
  - `--diff HEAD~1` returns correct changed files
  - `--diff --staged` returns staged files
  - Renamed files included with new name
  - Deleted files excluded from scan targets
  - Non-git directory raises `TraversalError` with clear message
  - Invalid ref raises `TraversalError`
- [x] **1F.9** `tests/test_integration.py` — end-to-end integration tests:
  - Scan → empty findings → clean output → audit log written → report reads it back
  - Scan → traversal with excludes → correct file count in audit log
  - Config load → scan with config → output respects config settings
  - Full CLI invocation via `CliRunner` → exit code 0 for clean scan
- [x] **1F.10** `tests/test_logging.py` — structured logging tests:
  - Default log level is WARNING (console)
  - `--log-level debug` produces debug output
  - `--quiet` suppresses log output to console
  - Symlink skip logged at WARNING level
  - Binary file skip logged at INFO level

### 1G — Cross-Platform Compatibility

- [x] **1G.1** Use `pathlib.Path` exclusively — never string concatenation for paths
- [x] **1G.2** No WSL-specific assumptions: no hardcoded `/mnt/`, no Windows path separators
- [x] **1G.3** Test path handling with forward slashes on all platforms
- [x] **1G.4** `.phi-scanignore` patterns use forward slashes (normalized internally on Windows)
- [x] **1G.5** All file I/O uses `encoding="utf-8"` explicitly — no platform-default encoding
- [x] **1G.6** SQLite paths use `pathlib.Path.home()` — no hardcoded `~` expansion

### 1H — PhiScan's Own CI Pipeline

This is the CI for the phiscan project itself, not the CI templates for users (Phase 6).

- [x] **1H.1** `.github/workflows/ci.yml` — runs on every push and PR:
  - Matrix: Python 3.12 on ubuntu-latest, macos-latest, windows-latest
  - Steps: checkout → uv sync → ruff lint → mypy typecheck → pytest with coverage
  - Upload coverage report as artifact
  - Fail PR if any step fails
- [x] **1H.2** `.github/workflows/release.yml` — runs on version tag push (`v*`):
  - Build sdist and wheel with `uv build`
  - Publish to PyPI with `uv publish` (using PyPI API token from GitHub secret)
  - Create GitHub Release with auto-generated changelog
- [x] **1H.3** Branch protection rules documented in README:
  - Require CI pass before merge
  - Require at least one review (when collaborators join)

### Phase 1 Verification Checklist

- [x] `uv sync` succeeds
- [x] `uv run phi-scan --version` → prints `0.1.0`
- [x] `uv run phi-scan --help` → lists all commands
- [x] `uv run phi-scan scan tests/` → traverses, Rich output, exit 0
- [x] `uv run phi-scan scan --diff HEAD~1` → scans only changed files
- [x] `uv run phi-scan config init` → wizard generates `.phi-scanner.yml`
- [x] `uv run phi-scan install-hook` → creates `.git/hooks/pre-commit`
- [x] `uv run phi-scan report` → reads last scan from SQLite
- [x] `uv run phi-scan setup` → reports dependency status
- [x] `make install` succeeds
- [x] `make lint` → zero Ruff errors
- [x] `make typecheck` → zero mypy errors
- [x] `make test` → all tests pass, >80% coverage
- [x] `pipx install .` → `phi-scan --version` works outside project dir
- [x] Nested dirs 5+ levels deep → all text files found
- [x] Binary files (.png, .exe, .zip) → skipped automatically
- [x] Unknown binary file (null bytes) → skipped via heuristic
- [x] Files with no extension → scanned if text, skipped if binary
- [x] .java, .go, .rb, .php, .ipynb files → scanned (not limited to allowlist)
- [x] Symlink in scan path → skipped with warning (in log, not stdout)
- [x] Unreadable file → scan completes without abort
- [x] `--log-level debug` → shows traversal detail
- [x] `--quiet` → no Rich output, only exit code
- [x] `NO_COLOR=1` → uncolored output
- [x] `phi-scan --version` responds in < 500ms (lazy imports verified)
- [x] `phi-scan --help` responds in < 500ms
- [x] `phi-scan init` creates config, ignore file, and installs hook in one guided wizard
- [x] CI pipeline passes on ubuntu, macos, windows
- [x] LICENSE file present and correct
- [x] CHANGELOG.md has `[Unreleased]` section
- [x] SECURITY.md has vulnerability reporting instructions

---

### Phase 1I — PHI Detection Fixture Corpus (pre-Phase-2 prerequisite)

**Goal:** Build a deterministic ground-truth benchmark corpus before writing any
detection code. Every detector added in Phase 2 must be validated against this
corpus — no detector ships without a fixture proving it fires on a known sample.

- [x] **1I.1** Create `tests/fixtures/phi/` — one synthetic PHI fixture file per HIPAA category
- [x] **1I.2** Create `tests/fixtures/clean/` — benign files that must never produce findings
- [x] **1I.3** Create `tests/fixtures/manifest.json` — ground-truth schema: entity types,
       minimum/maximum findings expected per file
- [x] **1I.4** Add `tests/fixtures/phi/` to `.phi-scanignore` — prevent false positives when
       scanning the repo itself
- [x] **1I.5** Write `tests/test_fixtures.py` — structural tests (manifest valid, all files
       exist, clean fixtures produce zero findings); detection assertion tests are
       added per-detector in Phase 2

---

## Phase 2: Detection Engine (Weeks 5–7)

**Goal:** Wire in the actual PHI/PII detection across all four layers. The CLI shell
from Phase 1 becomes a working scanner that finds real PHI. Also adds the deferred
Phase 1 features: suppression system, scan cache, and explain commands.

**Dependencies:** Phase 1 complete. `scan_file()` placeholder replaced with real detection.
`scan_file()`'s single responsibility is "return the PHI findings for a given file path."
Detection logic never lives directly in `scan_file()` — it delegates entirely to
`detect_phi_in_text_content()`.

**Version on completion: 0.2.0**

**New Dependencies to Install:**

- `presidio-analyzer` (2.x) — core PHI/PII detection
- `presidio-anonymizer` (2.x) — value anonymization
- `spacy` (3.7+) — NLP backbone
- `en_core_web_lg` — spaCy model (downloaded via `phi-scan setup` or `python -m spacy download`)
- `fhir.resources` (7.x) — FHIR R4 schema awareness
- `hl7` (0.4.x) — HL7 v2 message parsing (core, not a plugin — HL7 v2 is the dominant live transaction format in production hospital systems and must be detected natively)

### 2A — Deferred Phase 1 Features (Suppression, Cache, Explain)

These were removed from Phase 1 to reduce scope. They don't depend on detection
and can be wired in before or alongside the detection engine.

- [x] **2A.1** `suppression.py` — inline suppression comment system
  - Parse `# phi-scan:ignore` — suppress all findings on that line
  - Parse `# phi-scan:ignore[SSN,MRN]` — suppress only specific entity types
  - Parse `# phi-scan:ignore-next-line` — suppress all findings on the following line
  - Parse `# phi-scan:ignore-file` — suppress all findings in entire file (must appear in first 5 lines)
  - Language-aware comment prefixes: `#`, `//`, `/* */`, `--`, `<!-- -->`, `%`, `;`
  - `load_suppressions(file_lines)` → `dict[int, set[str]]` mapping line numbers to suppressed types
  - `is_finding_suppressed(finding, suppressions)` → bool
  - Suppressed findings still logged to audit (with `suppressed=True` flag) for compliance traceability
- [x] **2A.2** `cache.py` — content-hash scan cache for incremental scanning
  - Cache database: `~/.phi-scanner/cache.db` (SQLite) with `CACHE_SCHEMA_VERSION` tracking
  - Schema: `file_cache` (file_path, content_hash_sha256, last_scan_timestamp, findings_json, scanner_version)
  - `compute_file_hash(file_path)` → SHA-256 of file content
  - `get_cached_result(file_path, content_hash)` → `list[ScanFinding] | None`
  - `store_cached_result(file_path, content_hash, findings)` — upsert cache entry
  - `invalidate_cache()` — clear entire cache (scanner version change, config change)
  - `get_cache_stats()` → `CacheStats` dataclass (total_entries, hit_rate, cache_size_bytes)
  - Cache invalidated automatically when scanner version or config hash changes
  - `--no-cache` flag to force full re-scan
  - `--cache-stats` flag to display cache hit/miss ratio after scan
  - Cache DB also uses `schema_meta` table for migration support
- [x] **2A.3** `help_text.py` — all explain command content stored as named constants
  - One constant per explain topic (e.g., `EXPLAIN_CONFIDENCE_TEXT`, `EXPLAIN_HIPAA_TEXT`)
  - Formatted with Rich markup for terminal display (bold, colors, tables)
  - Single source of truth — same content used by CLI explain commands and docs generation
- [x] **2A.4** Wire `explain` command group into `cli.py`:
  - `phi-scan explain confidence` — what confidence scores mean, threshold ranges, per-layer breakdown
  - `phi-scan explain severity` — what HIGH/MEDIUM/LOW mean and how they map to confidence
  - `phi-scan explain risk-levels` — CRITICAL/HIGH/MODERATE/LOW/CLEAN risk assessment criteria
  - `phi-scan explain hipaa` — list all 18 HIPAA identifiers with descriptions
  - `phi-scan explain detection` — how the 4 detection layers work together
  - `phi-scan explain config` — annotated example `.phi-scanner.yml` with every option explained
  - `phi-scan explain ignore` — how `.phi-scanignore` patterns work with examples
  - `phi-scan explain reports` — available output formats and when to use each
  - `phi-scan explain remediation` — full remediation playbook for all 18 HIPAA categories

### 2A-T — Deferred Feature Tests

- [x] **2A-T.1** `tests/test_suppression.py` — inline suppression tests:
  - `# phi-scan:ignore` suppresses all findings on that line
  - `# phi-scan:ignore[SSN]` suppresses only SSN on that line
  - `# phi-scan:ignore-next-line` suppresses the following line
  - `# phi-scan:ignore-file` in first 5 lines suppresses entire file
  - Different comment syntax: `//`, `#`, `--`, `<!-- -->`
  - Suppressed findings still recorded in audit with `suppressed=True`
- [x] **2A-T.2** `tests/test_cache.py` — scan cache tests:
  - Cache miss on first scan, cache hit on unchanged file
  - Cache invalidated when file content changes
  - Cache invalidated when scanner version changes
  - `--no-cache` forces full re-scan
  - Cache stats report correct hit/miss ratio
  - Cache DB schema migration works on version bump

### 2B — Layer 1: Regex / Pattern Matching

- [x] **2B.1** Build regex pattern registry for all 18 HIPAA identifiers plus additional high-value
  healthcare identifiers. Precision requirements are listed per pattern — over-flagging causes
  alert fatigue; under-flagging is a HIPAA violation risk:
  - **SSN** (XXX-XX-XXXX) — must exclude reserved ranges to suppress false positives on order
    IDs and version strings (§205.20 SSA regulations; these area/group/serial combos are never
    assigned): area `000`, group `00`, serial `0000`, and all area numbers in
    `SSN_EXCLUDED_AREA_NUMBERS` (which contains 666 and the range 900–999). The exclusion
    regex must be constructed from `SSN_EXCLUDED_AREA_NUMBERS` — never embed `666`, `900`, or
    `999` as literals in pattern strings.
  - **MRN** — 6-10 digit numeric adjacent to MRN-suggestive variable names (`mrn`, `medical_record`,
    `patient_id`, `chart_number`); bare 6-10 digit strings without context are low-confidence only
  - **NPI** — 10-digit with Luhn check digit validation. **Type 1 (individual provider):** PHI when
    linked to a patient record — flag at medium confidence. **Type 2 (organization NPI):** public
    identifier, not PHI — do not flag when context is clearly organizational (e.g., assigned to a
    hospital object, not a patient record). Distinguish via surrounding variable/key name context.
  - **MBI (Medicare Beneficiary Identifier)** — `MBI_CHARACTER_COUNT`-character alphanumeric
    pattern built from `MBI_ALLOWED_LETTERS` (the CMS-approved letter set, excluding S, L, O,
    I, B, Z). The structural pattern is:
    `[1-9][{L}][{L}0-9][0-9][{L}][{L}0-9][0-9][{L}][{L}][0-9][0-9]` where `{L}` expands
    to `MBI_ALLOWED_LETTERS`. This is the primary Medicare identifier since 2019, replacing
    the SSN-based HICN. High-confidence when the pattern matches exactly.
    Neither `MBI_CHARACTER_COUNT` nor the character class string `AC-HJ-KM-NP-RT-Y` may
    appear as inline literals in detection logic — both must reference named constants.
  - **DEA number** — 2-letter prefix + `DEA_NUMBER_DIGIT_COUNT` digits with checksum:
    sum of digits 1+3+5 + 2×(2+4+6) must equal last digit mod 10. Validate checksum to
    eliminate false positives. Never use the literal `7` in the regex quantifier.
  - **HICN (legacy Medicare)** — 9-digit SSN base + 1-2 suffix characters (A, B, C, D, T, etc.);
    lower confidence than MBI; flag only in Medicare-suggestive variable context
  - **Phone numbers** — NANP `(NXX) NXX-XXXX`, dotted `NXX.NXX.XXXX`, dashed `NXX-NXX-XXXX`,
    E.164 `+1XXXXXXXXXX`, international `+[1-9][0-9]{6,14}`; exclude the FCC fictional NANP range
    where the exchange equals `FICTIONAL_PHONE_EXCHANGE` and the subscriber falls within
    `FICTIONAL_PHONE_SUBSCRIBER_MIN`–`FICTIONAL_PHONE_SUBSCRIBER_MAX` (inclusive). Never use
    the literals `555`, `100`, or `199` inline in exclusion logic.
  - **Fax numbers** — same patterns as phone; flag at same confidence level
  - **Email addresses** — RFC 5321 compliant; exclude documentation domains (`@example.com`,
    `@example.org`, `@example.net`, `@test.com`) per RFC 2606 as synthetic-safe
  - **IP addresses (v4)** — exclude RFC 5737 TEST-NET ranges (`192.0.2.x`, `198.51.100.x`,
    `203.0.113.x`) and RFC 1918 private ranges (`10.x`, `172.16–31.x`, `192.168.x`) as
    lower-confidence; public IPs in patient-context variables are high-confidence
  - **IP addresses (v6)** — full and compressed notation; exclude loopback (`::1`) and
    documentation ranges (`2001:db8::/32`)
  - **Dates** — DOB, admission date, discharge date, date of death patterns (`YYYY-MM-DD`,
    `MM/DD/YYYY`, `DD-Mon-YYYY`, `Month DD, YYYY`); bare year-only values are safe under
    HIPAA Safe Harbor (§164.514(b)(2)(i)) and must NOT be flagged; flag only dates with
    month and/or day precision
  - **Ages restricted by HIPAA** — numeric values strictly greater than `HIPAA_AGE_RESTRICTION_THRESHOLD`
    (i.e., ages 91 and above) adjacent to age-suggestive variable names (`patient_age`,
    `age_at_admission`, `age_in_years`, `years_old`, `dob_age`). HIPAA §164.514(b)(2)(i)
    requires ages "over 90" be generalized — "over 90" means strictly > 90, not ≥ 90.
    Detection logic must use `detected_age > HIPAA_AGE_RESTRICTION_THRESHOLD`; the literal
    `90` must not appear in logic code. Flag at medium confidence.
  - **ZIP codes** — 5-digit ZIP and ZIP+4 always flagged at medium confidence in patient
    context; 3-digit ZIP prefixes only flagged when the context is clearly patient-geographic
    (§164.514(b)(2)(i): 3-digit prefixes are safe only for areas with population
    > `ZIP_CODE_SAFE_HARBOR_POPULATION_MIN` — the scanner cannot verify population, so flag
    and let the user decide. Never use the literal `20000` or `20_000` in logic code.)
  - **Geographic sub-state data** — street addresses, city+state combinations, county names
    in patient-suggestive context; state abbreviations alone are NOT PHI under Safe Harbor
  - **URLs** — flag URLs containing path segments that encode patient identifiers
    (e.g., `/patient/12345`, `/record/mrn-67890`, `/member/abc123`)
  - **Account numbers** — patient account numbers, insurance member IDs, HSA/FSA account
    numbers adjacent to account-suggestive variable names
  - **Health plan numbers** — insurance subscriber IDs, group numbers, beneficiary IDs
  - **Certificate/license numbers** — medical license (state prefix + digits), nursing license,
    pharmacy license adjacent to license-suggestive variable names
  - **Vehicle identifiers (VIN)** — `VIN_CHARACTER_COUNT`-character ISO 3779 structure
    (WMI + VDS + VIS) with check digit validation (position 9); never contains I, O, or Q.
    Never use the literal `17` in the regex quantifier.
  - **Device identifiers** — FDA UDI format (device identifier + production identifier segments),
    GTIN-14 patterns in medical device context
  - **Biometric identifiers** — flag field names and JSON keys referencing:
    `fingerprint`, `iris_scan`, `retinal_scan`, `face_template`, `voiceprint`, `palm_print`,
    `gait_signature`, `dna_sequence`, `biometric_hash`; raw biometric data appears as large
    base64 or hex strings — flag high-entropy strings in biometric-named fields
  - **Genetic identifiers** — `rs{DBSNP_RS_ID_MIN_DIGITS` to `DBSNP_RS_ID_MAX_DIGITS` digits}`
    (dbSNP SNP IDs), `ENSG{ENSEMBL_GENE_ID_DIGIT_COUNT` digits}` (Ensembl gene IDs), VCF-format
    data (CHROM/POS/REF/ALT columns), gene panel names combined with patient identifiers;
    protected under GINA (federal) and GDPR Article 9 (EU). Never use the literals `7`, `9`,
    or `11` inline in regex quantifiers — build the pattern string from the named constants.
- [x] **2B.2** Implement confidence scoring for regex matches (high confidence for structured patterns)
- [x] **2B.3** Extract matched value, compute SHA-256 hash (never store raw value)
- [x] **2B.4** Implement `detect_phi_with_regex(file_content: str, file_path: Path) -> list[ScanFinding]`
  — the Layer 1 delegated function; scans line-by-line using the pattern registry from 2B.1

### 2C — Layer 2: NLP Named Entity Recognition

- [x] **2C.1** Initialize Presidio `AnalyzerEngine` with spaCy `en_core_web_lg`
- [x] **2C.2** Configure Presidio recognizers for: PERSON, GPE, DATE, ORG, LOCATION
- [x] **2C.3** Map Presidio entity types to HIPAA categories (Names → #1, Geographic → #2, etc.)
- [x] **2C.4** Set confidence thresholds — medium confidence findings flagged differently from high
- [x] **2C.5** Implement `detect_phi_with_nlp(file_content: str, file_path: Path) -> list[ScanFinding]`
  — the Layer 2 delegated function; runs after regex layer; applies Presidio NLP recognition
- [x] **2C.6** Graceful degradation: if spaCy model not installed, skip NLP layer with warning log and suggest `phi-scan setup`

### 2D — Layer 3: Structured Healthcare Formats (FHIR R4 + HL7 v2)

This layer detects PHI in structured healthcare data formats. FHIR R4 covers modern REST
APIs; HL7 v2 covers the legacy transaction format still dominant in live hospital integrations
(ADT feeds, lab results, pharmacy orders). Both must be supported natively — HL7 v2 is not
a plugin because it appears in production healthcare codebases at least as often as FHIR.

#### 2D-FHIR — FHIR R4 Schema Awareness

- [x] **2D.1** Create `fhir_recognizer.py` — custom FHIR R4 pattern detector; its detection logic
  is called from `detect_phi_in_structured_content(file_content: str, file_path: Path) -> list[ScanFinding]`,
  the Layer 3 delegated function that consolidates both FHIR and HL7 detection
- [x] **2D.2** Detect PHI-bearing FHIR field names in JSON/XML:
  - Patient: name, birthDate, address, telecom, identifier, photo, deceasedDateTime
  - Practitioner: name, identifier (NPI, DEA), telecom, address
  - RelatedPerson: name, birthDate, address, telecom, relationship
  - Observation: subject (Patient reference), performer, valueString, component
  - DiagnosticReport: subject, performer, result, presentedForm
  - Encounter: subject, participant, period, hospitalization
  - Coverage: beneficiary, subscriber, subscriberId, payor
  - Condition: subject, asserter, note (free-text diagnosis notes)
  - MedicationRequest: subject, requester, note
  - Procedure: subject, performer, note
  - AllergyIntolerance: patient, asserter, note
  - ImagingStudy: subject, referrer (DICOM metadata path — flag field presence, not binary)
- [x] **2D.3** Flag FHIR fields only when they contain non-synthetic/non-null values
- [x] **2D.4** Wire FHIR detection into `detect_phi_in_structured_content()` — the Layer 3
  delegated function attempts FHIR structure detection on content that does not match HL7 format
- [x] **2D.5** Detect FHIR Bundle resources — scan all `entry.resource` objects within a Bundle
  regardless of resource type; Bundles are the transport envelope for all FHIR operations

#### 2D-HL7 — HL7 v2 Message Segment Scanning

HL7 v2 is a pipe-delimited message format used in ADT feeds, lab orders, pharmacy messages,
and billing transactions. Nearly every hospital system generates HL7 v2 today. Files ending
in `.hl7`, `.msg`, or containing MSH segments in test fixtures are common sources of PHI.

- [x] **2D.6** Add `Hl7ScanContext` dataclass to `models.py` before implementing any HL7
  scanning functions. This dataclass is the pre-approved container for HL7 attribution
  context — it exists so `detect_phi_in_hl7_segment()` can accept attribution metadata
  as a single third argument without violating the 3-argument limit at the call site:
  ```python
  @dataclass(frozen=True)
  class Hl7ScanContext:
      file_path: Path        # source file the HL7 message was read from
      segment_index: int     # 0-based position of this segment in the message
  ```
  `frozen=True` enforces immutability — the context is read-only attribution data.
  This dataclass must be defined before 2D.7 is implemented. If `detect_phi_in_hl7_segment()`
  later requires attribution context, the signature becomes:
  `detect_phi_in_hl7_segment(segment, segment_field_categories, context: Hl7ScanContext)`
  — still 3 arguments and compliant. A fourth argument must never be added; add a field
  to `Hl7ScanContext` instead.
- [x] **2D.7** Detect HL7 v2 message files — identify by MSH segment header (`MSH|^~\&|`)
  in file content regardless of file extension (.hl7, .msg, .txt, .dat)
- [x] **2D.8** Implement HL7 v2 scanning functions in `scanner.py` (or a dedicated
  `hl7_scanner.py` module). All names must comply with the project naming standards — the
  plan proposes compliant names but does not grant exemptions from the standards:
  - `is_hl7_message_format(file_content: str) -> bool` — returns True when content
    contains a valid MSH segment header; used as the entry guard before HL7 parsing.
    Naming rules satisfied: (1) the `is_` prefix satisfies the boolean-naming rule;
    (2) the name reads as a predicate — "is [this content in] HL7 message format?" —
    which satisfies the verb-noun pair requirement because `is_` acts as the predicate
    verb and `hl7_message_format` is the noun phrase being tested. Both rules are met
    without conflict. Call sites may use it directly in a conditional
    (`if is_hl7_message_format(file_content):`) or store it
    (`is_hl7_format = is_hl7_message_format(file_content)`) — both are compliant.
    This function must be called only from within the HL7 detection delegated function,
    not from `scan_file()` or `detect_phi_in_text_content()` directly.
  - `detect_phi_in_hl7_segment(segment: hl7.Segment, segment_field_categories: Mapping[str, PhiCategory])
    -> list[ScanFinding]` — scans one parsed segment, returns findings; pure function,
    no side effects. `segment` is a parsed `hl7.Segment` instance, not a raw string.
    `segment_field_categories` is typed as `Mapping` (not `dict`) to enforce the read-only
    contract — the function must not mutate the lookup table it receives. The caller always
    passes a module-level constant defined in `hl7_scanner.py` (e.g. `_PID_FIELD_CATEGORIES`,
    `_NK1_FIELD_CATEGORIES`) — never a caller-constructed dict built at call time. These
    per-segment lookup tables are module-private constants and must follow `UPPER_SNAKE_CASE`
    with a leading underscore: `_PID_FIELD_CATEGORIES`, not `_pid_field_categories`. The
    leading underscore is mandatory; they must not appear in `__all__`; no other module
    may import them. The UPPER_SNAKE_CASE rule for module-level constants is not relaxed
    for module-private names — only the leading underscore signals private scope.
    **Attribution creep notice:** this signature is currently 2 arguments and compliant.
    If `file_path` or `line_number` attribution context is ever needed inside this function,
    a `@dataclass Hl7ScanContext` must be introduced before a third argument is added —
    the 3-argument limit would be reached immediately. Do not add a third positional argument;
    introduce the dataclass first.
  Parse and scan the following PHI-bearing segments using the `hl7` library:
  - **MSH** (Message Header) — MSH.4 (sending facility name can contain PHI in some systems)
  - **PID** (Patient Identification) — PID.3 (patient ID/MRN), PID.5 (patient name),
    PID.7 (date of birth), PID.8 (sex), PID.11 (address), PID.13/PID.14 (phone),
    PID.19 (SSN), PID.20 (driver's license)
  - **PD1** (Patient Additional Demographics) — PD1.3 (patient primary care provider name/NPI)
  - **NK1** (Next of Kin) — NK1.2 (name), NK1.4 (address), NK1.5 (phone)
  - **IN1/IN2** (Insurance) — IN1.2 (insurance plan ID), IN1.16 (insured name),
    IN2.1 (insured employee ID), IN2.8 (military ID), IN2.61 (mother's maiden name)
  - **OBX** (Observation) — OBX.5 (observation value — can contain lab result free text
    with patient context); flag only when OBX.3 observation identifier suggests PHI
  - **DG1** (Diagnosis) — DG1.3 (diagnosis code + description in patient context)
  - **GT1** (Guarantor) — GT1.3 (guarantor name), GT1.5 (address), GT1.6 (phone)
  - **AL1** (Allergy) — AL1.3 (allergy code/description in patient context)
- [x] **2D.9** Map HL7 v2 segment fields to HIPAA Safe Harbor categories:
  - PID.5 → PhiCategory.NAME; PID.7 → PhiCategory.DATE; PID.19 → PhiCategory.SSN
  - PID.11 → PhiCategory.GEOGRAPHIC; PID.13/14 → PhiCategory.PHONE; etc.
- [x] **2D.10** Wire HL7 v2 detection into `detect_phi_in_structured_content()` — the Layer 3
  delegated function calls `is_hl7_message_format()` internally to decide whether to parse
  as HL7; if True, it dispatches to the HL7 segment scanner; otherwise it attempts FHIR detection
- [x] **2D.11** Graceful degradation: if `hl7` library not installed, raise
  `MissingOptionalDependencyError` at the point of first use inside the function that
  needs the library. The import must be lazy (inside the function body), not at module
  level — a module-level `ImportError` causes the entire `hl7_scanner` module to fail
  to load and gives no function-level caller the chance to catch it.
  Implement a private helper that encapsulates the lazy import exactly once:
  ```python
  def _import_hl7_library() -> types.ModuleType:
      try:
          import hl7  # noqa: PLC0415 (intentional lazy import)
          return hl7
      except ImportError as import_error:
          raise MissingOptionalDependencyError(
              "hl7 is required for HL7 v2 scanning"
              " — install with: pip install phi-scan[hl7]"
          ) from import_error
  ```
  Each HL7 function that needs the library calls `hl7_lib = _import_hl7_library()`
  as its first statement. The caller of the HL7 detection delegated function catches
  `MissingOptionalDependencyError` specifically, logs a structured WARNING
  ("HL7 v2 scanning disabled — install phi-scan[hl7] to enable"), and continues with
  other detection layers. Never catch bare `Exception`; never use `except ImportError: pass`.
- [x] **2D.12** Add `hl7` to `[project.optional-dependencies]` in `pyproject.toml`:
  `hl7 = ["hl7>=0.4"]`; update `full` extra to include it

### 2E — Detection Integration

- [ ] **2E.1** Define a coordinator function `detect_phi_in_text_content(file_content: str,
  file_path: Path) -> list[ScanFinding]` that orchestrates all detection layers in order
  (regex → NLP → FHIR/HL7 → quasi-identifier combination) and deduplicates overlapping
  findings before returning. `file_path` is attribution metadata only — each returned
  `ScanFinding` records it as its source file. `detect_phi_in_text_content()` must not
  inspect `file_path` for any dispatch or routing decision.
  `scan_file()`'s single responsibility is "return the PHI findings for a given file path."
  The how — reading file bytes, decoding to text, calling `detect_phi_in_text_content()` —
  is implementation detail, not a second responsibility. The function must not dispatch by
  format (HL7 vs FHIR vs plain text) before calling the coordinator; doing so adds a
  second named responsibility that violates the single-responsibility rule.
  All format-detection gating lives inside each detection layer's
  delegated function: the HL7 delegated function calls `is_hl7_message_format()` internally;
  the FHIR delegated function examines content structure to decide whether to apply; the
  regex and NLP layers apply to all text content unconditionally.
  The layer implementation tasks (2B.4, 2C.5, 2D.4, 2D.10) produce the three
  delegated functions; all three wire into `detect_phi_in_text_content()` via the
  coordinator skeleton above, not directly into `scan_file()`.
  The body of `detect_phi_in_text_content()` must consist exclusively of delegated function
  calls. No pattern matching, entity recognition, or structural parsing logic may appear
  inline. The 30-line maximum applies — "only makes delegated calls" is not an exemption.
  The delegated layer functions (which must be named as specified here) are:
  - `detect_phi_with_regex(file_content: str, file_path: Path) -> list[ScanFinding]` — Layer 1
  - `detect_phi_with_nlp(file_content: str, file_path: Path) -> list[ScanFinding]` — Layer 2
  - `detect_phi_in_structured_content(file_content: str, file_path: Path) -> list[ScanFinding]`
    — Layer 3; internally calls `is_hl7_message_format()` and FHIR content detection to
    decide which structured-format path to apply; consolidates HL7 and FHIR into one delegated call
  The proposed body that verifies the 30-line claim (shown as a skeleton; docstring and
  type imports are additional lines but do not count toward the 30-line function body limit):
  ```python
  def detect_phi_in_text_content(
      file_content: str, file_path: Path
  ) -> list[ScanFinding]:
      all_findings: list[ScanFinding] = []
      all_findings.extend(detect_phi_with_regex(file_content, file_path))
      all_findings.extend(detect_phi_with_nlp(file_content, file_path))
      all_findings.extend(detect_phi_in_structured_content(file_content, file_path))
      all_findings.extend(detect_quasi_identifier_combination(all_findings))
      return deduplicate_overlapping_findings(all_findings)
  ```
  This skeleton is 7 body lines. The 30-line limit is met with significant headroom.
  If adding a future layer would exceed the limit, extract the `.extend()` accumulation
  pattern into a named helper rather than inlining more calls.
- [ ] **2E.2** Add `.phi-scanignore` support — patterns evaluated at every traversal depth
- [ ] **2E.3** Add content-aware scan strategy — detect file type from content/extension for optimal scanning:
  - Structured data (.json, .xml, .yaml) → parse structure + scan values
  - Code files (.py, .js, .java, .go, .rb, .cs, etc.) → line-by-line regex + NLP
  - Config/env files (.env, .ini, .conf, .properties) → key-value pattern scan
  - SQL files (.sql) → scan string literals and comments
  - Notebooks (.ipynb) → parse JSON, scan cell outputs and source
  - All other text files → full-text line-by-line scan
- [ ] **2E.4** Variable-name contextual boosting — boost confidence when value is assigned to a PHI-suggestive variable:
  - Pattern match variable names containing: `patient`, `ssn`, `mrn`, `dob`, `birth`, `name`, `address`, `phone`, `email`, `diagnosis`, `insurance`, `beneficiary`
  - Boost: +0.15 confidence when PHI-suggestive variable name + detected entity type align
  - Example: `patient_name = "John Smith"` → PERSON detection boosted from 0.72 → 0.87
  - Example: `x = "John Smith"` → no boost, relies on standard NLP confidence
  - Covers: Python (`=`), JS/TS (`=`, `:`), Java (`=`), JSON (key-value), YAML (key-value)
- [ ] **2E.5** Integrate suppression system from 2A.1 — apply inline `# phi-scan:ignore` before reporting findings
- [ ] **2E.6** Integrate scan cache from 2A.2 — skip unchanged files
- [ ] **2E.7** Tune confidence thresholds — benchmark recall vs false positive rate
- [ ] **2E.8** Target: >90% recall, <10% false positive rate on synthetic test dataset
- [ ] **2E.9** Archive inspection — scan embedded plaintext resources inside Java archives:
  - File types: .jar, .war, .zip (Python `zipfile` module — no external dependencies)
  - Scan embedded text resources only: .properties, .xml, .yaml, .yml, .json, .conf
  - Skip embedded .class files (compiled bytecode — opaque within archives)
  - SECURITY REQUIREMENT (must be a test criterion): extraction is in-memory only —
    never write extracted content to disk. PHI exposed to disk would violate the
    local-execution-only contract and could persist beyond the scan process.
  - Mandated pattern: use ZipFile.read(member) → BytesIO for in-memory access.
    Never use ZipFile.extract() or ZipFile.extractall() — both write to disk.
  - Test: assert no temporary files are created in tmp or the working directory
  - Graceful degradation: if zipfile extraction fails, log warning and skip the archive
  - Remove .jar and .war from KNOWN_BINARY_EXTENSIONS in constants.py when this ships
  - Update `.phi-scanignore` Format Specification in PLAN.md to note archive inspection live
- [ ] **2E.11** Quasi-identifier combination detection — implement as
  `detect_quasi_identifier_combination(findings: list[ScanFinding]) -> list[ScanFinding]`.
  Returns a list containing a single `PhiCategory.QUASI_IDENTIFIER_COMBINATION` finding when
  a combination rule fires, or an empty list when no combination risk is present. An empty
  list is the sentinel for "no match" — never return `None`. This return type is intentionally
  consistent with every other detection function, which allows the coordinator to accumulate
  results with `all_findings.extend(...)` without a None guard. Called at the end of
  `detect_phi_in_text_content()` after all layer findings are collected. Pure function —
  no side effects, no I/O. The proximity window must be read from
  `QUASI_IDENTIFIER_PROXIMITY_WINDOW_LINES` — a module-level `int` constant defined in
  `phi_scan/constants.py` and exported in its `__all__`; import it from `phi_scan.constants`.
  Never compare against the literal `50` directly.
  Each combination rule is a separate function delegated to from the coordinator — this keeps
  `detect_quasi_identifier_combination()` under 30 lines and gives each rule a testable name.
  Sub-evaluators use the same `list[ScanFinding]` return convention (empty = no match):
  - `evaluate_zip_dob_sex_combination(findings: list[ScanFinding]) -> list[ScanFinding]`
    ZIP code + date of birth + sex/gender → re-identification risk (Sweeney: 87% of US
    population uniquely identified by these three fields alone); return a finding at HIGH
    confidence even if each field alone would be MEDIUM or LOW
  - `evaluate_name_date_combination(findings: list[ScanFinding]) -> list[ScanFinding]`
    Name + any date → return a HIGH confidence finding regardless of individual scores
  - `evaluate_age_geographic_combination(findings: list[ScanFinding]) -> list[ScanFinding]`
    Age > `HIPAA_AGE_RESTRICTION_THRESHOLD` (ages 91+) + any geographic finding → HIGH.
    HIPAA §164.514(b)(2)(i) restricts ages "over 90" specifically because they re-identify
    when combined with geographic data. Never compare against the literal `90` — reference
    `HIPAA_AGE_RESTRICTION_THRESHOLD` and check with `>`, not `>=`.
  - `evaluate_colocated_identifier_combination(findings: list[ScanFinding]) -> list[ScanFinding]`
    ≥ `MINIMUM_QUASI_IDENTIFIER_COUNT` distinct identifier categories present in the same
    JSON object or data structure → elevated risk level. Never use the literal `2` — reference
    `MINIMUM_QUASI_IDENTIFIER_COUNT`.
  `detect_quasi_identifier_combination()` calls each evaluator in order, extends its result
  list, and returns. No combination rule logic may be implemented inline in the coordinator.
  The proposed body that verifies the 30-line claim:
  ```python
  def detect_quasi_identifier_combination(
      findings: list[ScanFinding],
  ) -> list[ScanFinding]:
      combination_findings: list[ScanFinding] = []
      combination_findings.extend(evaluate_zip_dob_sex_combination(findings))
      combination_findings.extend(evaluate_name_date_combination(findings))
      combination_findings.extend(evaluate_age_geographic_combination(findings))
      combination_findings.extend(evaluate_colocated_identifier_combination(findings))
      return combination_findings
  ```
  This skeleton is 7 body lines. The 30-line limit is met with significant headroom.
  Each returned finding must be `PhiCategory.QUASI_IDENTIFIER_COMBINATION` with a note
  listing which fields triggered the rule. Do not reuse `PhiCategory.UNIQUE_ID` — conflating
  the two breaks compliance mapping at Layer 4.

### 2F — Auto-Fix Engine (`phi-scan fix`)

The killer feature: don't just find PHI — replace it with synthetic data automatically.
Generate a git-applicable patch that developers can review and apply in seconds.

- [ ] **2F.1** `phi_scan/fixer.py` — synthetic data replacement engine
- [ ] **2F.2** Synthetic generators per HIPAA category (deterministic, seeded by original hash for consistency):
  - Names → faker `fake.name()` (seeded) — e.g., "Jane Thompson"
  - SSN → synthetic range `000-00-XXXX` (reserved non-real range)
  - MRN → synthetic `MRN-000001` through `MRN-999999`
  - Email → `user{N}@example.com` (RFC 2606 safe domain)
  - Phone → `{FICTIONAL_PHONE_EXCHANGE}-{FICTIONAL_PHONE_SUBSCRIBER_DISPLAY_PREFIX}{FICTIONAL_PHONE_SUBSCRIBER_MIN}`
    to `{FICTIONAL_PHONE_EXCHANGE}-{FICTIONAL_PHONE_SUBSCRIBER_DISPLAY_PREFIX}{FICTIONAL_PHONE_SUBSCRIBER_MAX}`
    (FCC reserved fictional range; the display prefix "0" pads the 4-digit subscriber
    representation and must not appear as a bare string literal "0" in generation code)
  - DOB/Dates → synthetic dates within plausible range (1950–2000)
  - Geographic → faker `fake.address()` (synthetic addresses)
  - IP address → RFC 5737 test range `192.0.2.X`, `198.51.100.X`
  - URL → `https://example.com/resource/{N}` (RFC 2606)
  - Account/plan numbers → synthetic `ACCT-000001`, `PLAN-000001`
  - Device/vehicle IDs → synthetic `DEV-000001`, `VIN-00000000000000000`
- [ ] **2F.3** `phi-scan fix --dry-run <path>` — show unified diff preview without modifying files
- [ ] **2F.4** `phi-scan fix --apply <path>` — apply replacements in-place after user confirmation
- [ ] **2F.5** `phi-scan fix --patch <path>` — write `.patch` file for `git apply`
- [ ] **2F.6** Deterministic replacements: same PHI value always maps to same synthetic value within a scan
  - Ensures referential integrity ("John Smith" on line 10 and line 50 both become "Jane Thompson")
- [ ] **2F.7** Respect suppressed lines — do not replace values on lines with `# phi-scan:ignore`
- [ ] **2F.8** Interactive mode: `phi-scan fix --interactive` — prompt per-finding: `Replace? [y/n/a(ll)/s(kip file)]`

**New Dependency:** `faker` (for synthetic data generation)

### 2G — Detection Testing

- [ ] **2G.1** Create synthetic test dataset — files with known PHI at various nesting depths
- [ ] **2G.2** Test each of 18 HIPAA identifiers detected correctly
- [ ] **2G.3** Test FHIR resource detection for all supported resource types
- [ ] **2G.4** Test false positive rate on clean code files
- [ ] **2G.5** Test confidence scoring produces correct severity levels
- [ ] **2G.6** Benchmark scan performance on a 1000-file synthetic repo
- [ ] **2G.7** Test variable-name boosting: `patient_name = "John"` scores higher than `x = "John"`
- [ ] **2G.8** Test auto-fix generates correct synthetic replacements for each HIPAA category
- [ ] **2G.9** Test `--dry-run` shows diff without modifying files
- [ ] **2G.10** Test `--apply` modifies files correctly
- [ ] **2G.11** Test deterministic replacement: same PHI value → same synthetic value across file
- [ ] **2G.12** Test suppressed lines are not replaced by auto-fix
- [ ] **2G.13** Test graceful degradation: NLP layer skipped when spaCy model not installed
- [ ] **2G.14** End-to-end integration: scan → detect → cache → re-scan (cache hit) → output → audit

### 2H — Compliance Scope & Known Limitations

These notes document the regulatory scope of the Phase 2 detection engine and must be
reflected in the Phase 4 documentation and compliance mapping.

#### 2H.1 — Regulatory Coverage

- [ ] **2H.1a** HIPAA Safe Harbor (§164.514(b)(2)) — primary standard; all 18 identifiers
  covered by Layers 1–3. The scanner implements Safe Harbor by design. Expert Determination
  (§164.514(b)(1)) requires a qualified statistician's certification — the tool alone cannot
  satisfy Expert Determination; document this limitation explicitly in `docs/de-identification.md`.
- [ ] **2H.1b** HITECH Act (45 CFR §§164.400–414) — the scanner directly supports HITECH
  breach assessment by identifying what PHI is exposed. Flag in `phi-scan explain hipaa` that
  HITECH extended HIPAA to business associates and established breach notification thresholds.
- [ ] **2H.1c** 42 CFR Part 2 (Substance Use Disorder) — stricter than HIPAA; requires
  explicit consent for disclosure even for treatment. The scanner must flag field names and
  data patterns defined in `SUD_FIELD_NAME_PATTERNS` (a `frozenset[str]` in `constants.py`
  containing: `substance_use`, `addiction_treatment`, `sud_diagnosis`, `alcohol_abuse`,
  `opioid_treatment`, `methadone`, `buprenorphine`, `naloxone`, and related treatment program
  keywords). Detection logic must iterate over `SUD_FIELD_NAME_PATTERNS` — never embed these
  strings as inline literals. Map detections to `PhiCategory.SUBSTANCE_USE_DISORDER`
  — a dedicated enum member added to `PhiCategory` in Phase 1B.2 (constants.py), not reused
  from an existing category. Do NOT map to `PhiCategory.UNIQUE_ID`; SUD records are a distinct
  regulatory category under a different statute with different consent requirements. Reusing
  UNIQUE_ID would cause a semantic collision that forces runtime disambiguation via free-text
  note fields — fragile and undetectable by the type checker.
- [ ] **2H.1d** GINA (Genetic Information Nondiscrimination Act) — genetic information
  (test results, family history, genomic data) is a protected category. Genetic identifier
  patterns from 2B.1 cover this; document GINA applicability in compliance mapping.
- [ ] **2H.1e** NIST SP 800-122 (PII Confidentiality Guide) — the PII side of the scanner
  (non-health personal information) aligns with this standard. PII categories covered include
  name, SSN, date of birth, address, phone, email, financial account numbers, and biometrics.
  Document alignment in Phase 4 compliance mapping.

#### 2H.2 — Known Detection Gaps (Must Be Documented)

The following file types contain PHI in healthcare codebases but are skipped as binary.
Document these gaps in `docs/de-identification.md` and `docs/known-limitations.md`:

- [ ] **2H.2a** **PDF files** — `.pdf` is in `KNOWN_BINARY_EXTENSIONS` and will be skipped.
  Lab results, discharge summaries, and medical records are often committed as PDFs.
  Phase 2 does not address this. A future phase should add `pdfminer.six` text extraction.
  Document limitation: "PDF files are not scanned. Use `phi-scan[pdf]` when available."
- [ ] **2H.2b** **DICOM files** — DICOM (`.dcm`) medical imaging files contain patient
  metadata in header tags (Patient Name, DOB, MRN, Physician). Not scanned in any phase.
  Document limitation and track as a post-1.0 feature.
- [ ] **2H.2c** **Office documents** — `.docx`, `.xlsx`, `.pptx` are in
  `KNOWN_BINARY_EXTENSIONS`. Clinical notes and patient rosters are often stored as Office
  files in test fixtures. Document as a known gap. Post-1.0 phase to add `python-docx` /
  `openpyxl` text extraction.
- [ ] **2H.2d** **Compiled code** — `.class`, `.pyc`, `.pyo` bytecode files are skipped.
  Hardcoded PHI in source code will be caught pre-compilation; post-compilation artifacts
  are out of scope by design. Document this as an intentional scope boundary.

### Phase 2 Verification Checklist

- [ ] `phi-scan scan tests/fixtures/` detects all planted PHI
- [ ] Each of 18 HIPAA identifier types has at least one test
- [ ] FHIR resources with PHI-bearing fields flagged correctly
- [ ] Clean code files produce zero false positives
- [ ] SHA-256 hash stored in findings, never raw PHI value
- [ ] Scan completes in <30 seconds on 1000-file repo
- [ ] Variable name `patient_ssn = "123-45-6789"` scores higher than `x = "123-45-6789"`
- [ ] `phi-scan fix --dry-run` shows unified diff with synthetic replacements
- [ ] `phi-scan fix --apply` replaces PHI with synthetic data in-place
- [ ] Deterministic: re-running fix produces identical synthetic values
- [ ] `# phi-scan:ignore` suppresses finding on that line
- [ ] `# phi-scan:ignore[SSN]` suppresses only SSN finding
- [ ] `# phi-scan:ignore-file` suppresses entire file when in first 5 lines
- [ ] Suppressed findings logged to audit with `suppressed=True`
- [ ] Second scan of unchanged files uses cache (faster completion)
- [ ] `--no-cache` forces full re-scan
- [ ] `phi-scan explain hipaa` renders all 18 identifiers in terminal
- [ ] NLP layer degrades gracefully without spaCy model
- [ ] HL7 v2 MSH-identified file → PID.5 name and PID.19 SSN detected
- [ ] HL7 v2 layer degrades gracefully when `hl7` library not installed
- [ ] MBI pattern matches valid MBI, rejects SSN-length strings
- [ ] SSN regex does not flag reserved ranges (000-XX-XXXX, 666-XX-XXXX, 900-XXX-XXXX)
- [ ] Age >90 detected adjacent to `patient_age`-style variable name
- [ ] ZIP+4 flagged; bare 3-digit prefix only flagged in patient-geographic context
- [ ] NPI Type 2 (org-context) not flagged; NPI Type 1 (patient-context) flagged
- [ ] DEA number checksum validation eliminates false positives
- [ ] Quasi-identifier combination: ZIP + DOB + sex in same file → HIGH combined confidence
- [ ] `phi-scan explain hipaa` mentions HITECH Act and 42 CFR Part 2
- [ ] SUD-related field names (`opioid_treatment`, `sud_diagnosis`) detected and mapped
- [ ] Genetic identifiers (`rs1234567`, VCF-format data) detected in patient context
- [ ] `make test` passes with all new detection tests
- [ ] `make typecheck` passes with all new modules

---

## Phase 3: CLI Polish, Output Formats & First PyPI Publish (Weeks 8–9)

**Goal:** Production-quality CLI with all output formats, verbose/debug modes,
baseline management, pre-commit integration, and published to PyPI. This is the
first public release — users can install and use PhiScan from PyPI.

**Dependencies:** Phase 2 complete. Scanner produces real findings to format.

**Version on completion: 0.3.0** (first PyPI release)

### 3A — Output Formats & Flags

- [ ] **3A.1** `--output json` — structured JSON findings report
- [ ] **3A.2** `--output sarif` — SARIF 2.1 for GitHub Advanced Security integration
- [ ] **3A.3** `--output csv` — CSV export with headers (all findings, one row per finding)
- [ ] **3A.4** `--output table` — default Rich table (already built in Phase 1)
- [ ] **3A.9** `--output junit` — JUnit XML format (each finding as a test failure, consumed by CircleCI Test Summary, Jenkins, Azure DevOps, and GitHub Actions test reporting)
- [ ] **3A.10** `--output codequality` — GitLab Code Quality JSON format (`gl-code-quality-report.json` schema, findings appear as inline MR annotations)
- [ ] **3A.11** `--output gitlab-sast` — GitLab SAST JSON format (`gl-sast-report.json` schema v15.0.0+, findings appear in GitLab Security Dashboard)
- [ ] **3A.5** `--verbose` flag — timestamped debug output showing each scan phase
- [ ] **3A.6** `--severity-threshold` flag — filter output by LOW, MEDIUM, HIGH
- [ ] **3A.7** `--quiet` flag — suppress Rich UI, output only exit code
- [ ] **3A.8** `--report-path` flag — write report file to specified path (default: `./phi-report.*`)

### 3B — Baseline Management (`phi-scan baseline`)

The #1 adoption blocker for security scanners in existing codebases is noise.
Baseline lets teams adopt PhiScan incrementally — acknowledge existing findings,
then enforce zero new PHI going forward.

- [ ] **3B.1** `phi_scan/baseline.py` — baseline snapshot management
- [ ] **3B.2** `phi-scan baseline create` — run full scan, save current findings as baseline
  - Baseline file: `.phi-scanbaseline` (committed to repo, tracks accepted findings)
  - Each entry: file_path + line_content_hash + entity_type + value_hash
  - Human-readable YAML format with comments explaining each entry
- [ ] **3B.3** `phi-scan baseline show` — display current baseline summary (count per category, age)
- [ ] **3B.4** `phi-scan baseline clear` — remove baseline (forces full enforcement)
- [ ] **3B.5** `phi-scan scan --baseline` — only report NEW findings not in baseline
  - Baselined findings shown as dimmed/grey in terminal output (not hidden entirely)
  - New findings shown in full color with `[NEW]` badge
  - Exit code based only on new findings (baselined findings don't fail the build)
- [ ] **3B.6** `phi-scan baseline update` — re-scan and update baseline with current findings
- [ ] **3B.7** `phi-scan baseline diff` — show what changed since last baseline (new, resolved, moved)
- [ ] **3B.8** Baseline drift detection: warn if baselined findings count increases significantly
- [ ] **3B.9** Baseline entries auto-expire: configurable `baseline_max_age_days` (default: 90)
  - After expiry, baselined finding becomes a regular finding again
  - Forces teams to actually remediate, not just baseline forever

### 3C — Pre-commit Framework Integration

- [ ] **3C.1** Create `.pre-commit-hooks.yaml` in repo root — defines phi-scan as a hook
  - Hook ID: `phi-scan`
  - Name: "PhiScan — PHI/PII Detection"
  - Entry: `phi-scan scan --diff`
  - Language: python
  - Types: [text]
  - Stages: [pre-commit, pre-push]
- [ ] **3C.2** Document usage in `.pre-commit-config.yaml`:
  ```yaml
  repos:
    - repo: https://github.com/your-org/phi-scan
      rev: v0.3.0
      hooks:
        - id: phi-scan
          args: ['--severity-threshold', 'medium']
  ```
- [ ] **3C.3** Test with `pre-commit run --all-files` and `pre-commit run --files <path>`
- [ ] **3C.4** Document in `docs/ci-cd-integration.md` alongside native git hook

### 3D — Package & First Publish

- [ ] **3D.1** Finalize `pyproject.toml` — `[project.scripts]` entry point, classifiers, license (MIT)
- [ ] **3D.2** Configure `pyproject.toml` build includes — ensure `.phi-scanner.yml` template, `py.typed`, and non-Python assets included in sdist/wheel
- [ ] **3D.3** Pin all dependency versions in `pyproject.toml`
- [ ] **3D.4** `uv build` — produce sdist and wheel
- [ ] **3D.5** Test `pipx install ./dist/phi_scan-0.3.0.tar.gz` end-to-end
- [ ] **3D.6** `uv publish` — publish to PyPI (triggered by `v0.3.0` tag via GitHub Actions release workflow)
- [ ] **3D.7** Verify `pipx install phi-scan` works from PyPI
- [ ] **3D.8** GitHub Release created automatically with changelog from `CHANGELOG.md`

### 3E — Documentation (Core Set)

- [ ] **3E.1** `README.md` — hero section, badges (PyPI version, Python version, license, CI status), quick start (3 steps), feature overview, command reference table, link to docs, license notice
- [ ] **3E.2** `docs/getting-started.md` — install, first scan, understanding output (5-minute quick start)
- [ ] **3E.3** `docs/configuration.md` — complete `.phi-scanner.yml` reference with every option annotated
- [ ] **3E.4** `docs/ignore-patterns.md` — `.phi-scanignore` syntax, examples, common patterns
- [ ] **3E.5** `docs/ci-cd-integration.md` — pre-commit hook setup, GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, Bitbucket Pipelines, and AWS CodeBuild pipeline examples with copy-paste templates
- [ ] **3E.6** `docs/troubleshooting.md` — common issues, FAQ, debug tips
- [ ] **3E.7** `docs/security.md` — how PHI is protected (hashing, no raw values, local-only scanning)
- [ ] **3E.8** `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1 (industry standard)
- [ ] **3E.9** `.github/ISSUE_TEMPLATE/bug_report.md` — structured bug report template (OS, Python version, phi-scan version, steps to reproduce)
- [ ] **3E.10** `.github/ISSUE_TEMPLATE/feature_request.md` — structured feature request template (use case, proposed solution, alternatives)
- [ ] **3E.11** `.github/PULL_REQUEST_TEMPLATE.md` — PR checklist (tests added, lint passes, docs updated, no PHI in test fixtures)
- [ ] **3E.12** Enable GitHub Discussions — categories: Q&A, Show & Tell, Ideas, Plugins

### 3F — Phase 3 Testing

- [ ] **3F.1** `tests/test_output_json.py` — JSON output validates against expected schema, all finding fields present
- [ ] **3F.2** `tests/test_output_sarif.py` — SARIF 2.1 output validates against official SARIF JSON schema
- [ ] **3F.3** `tests/test_output_csv.py` — CSV output parseable by Python `csv` module, headers match spec, special characters escaped
- [ ] **3F.4** `tests/test_baseline.py` — baseline create, baseline scan (new vs baselined), baseline expiry, baseline merge on conflict
- [ ] **3F.5** `tests/test_precommit.py` — `.pre-commit-hooks.yaml` integration: hook runs, blocks on finding, passes when clean
- [ ] **3F.6** `tests/test_cli_flags.py` — `--verbose`, `--severity-threshold`, `--report-path`, `--output` all behave correctly
- [ ] **3F.7** `tests/test_explain.py` — all 9 explain topics render without error, output contains expected content
- [ ] **3F.8** `tests/test_first_run.py` — first-run experience: no config file triggers setup prompt, error messages suggest next steps
- [ ] **3F.9** `tests/test_publish_package.py` — `uv build` produces valid wheel and sdist, package metadata correct

### Phase 3 Verification Checklist

- [ ] All four output formats produce valid, parseable output (table, json, csv, sarif)
- [ ] CSV imports cleanly into Excel/Google Sheets
- [ ] `--verbose` shows scan timing breakdown
- [ ] `--severity-threshold high` filters low/medium findings
- [ ] `--report-path` writes report to specified location
- [ ] Package installs from PyPI with `pipx install phi-scan`
- [ ] `phi-scan explain confidence` renders clear, formatted explanation in terminal
- [ ] All 9 explain topics render correctly with Rich formatting
- [ ] `docs/` folder contains all 7 core documentation files
- [ ] README.md has badges, quick start, command reference
- [ ] CODE_OF_CONDUCT.md merged to repo
- [ ] Bug report and feature request issue templates live on GitHub
- [ ] PR template with checklist live on GitHub
- [ ] GitHub Discussions enabled with categories
- [ ] `--output junit` produces valid JUnit XML consumable by CI test reporters
- [ ] `--output codequality` produces valid GitLab Code Quality JSON
- [ ] `--output gitlab-sast` produces valid GitLab SAST JSON v15+
- [ ] Error messages suggest next steps (not just "failed")
- [ ] First-run experience guides new user to `config init`
- [ ] `phi-scan baseline create` creates `.phi-scanbaseline` with current findings
- [ ] `phi-scan scan --baseline` only flags new findings, baselined shown as dimmed
- [ ] Baseline entries auto-expire after configured age
- [ ] `.pre-commit-hooks.yaml` works with `pre-commit run --all-files`
- [ ] GitHub Release published automatically on tag push
- [ ] CHANGELOG.md updated with 0.3.0 release notes

---

## Phase 4: Enterprise Reports, Compliance & Full Documentation (Weeks 10–11)

**Goal:** Enterprise-grade PDF and HTML reports with visual charts, remediation
playbooks, executive summaries, multi-framework compliance mapping, and complete
documentation suite. This phase upgrades PhiScan from "useful tool" to
"enterprise-ready compliance solution."

**Dependencies:** Phase 3 complete. Scanner produces real findings, output formats working.

**Version on completion: 0.4.0**

**New Dependencies to Install:**

- `fpdf2` — PDF report generation (lightweight, no external deps)
- `jinja2` — HTML report templating
- `matplotlib` — chart generation (bar charts, pie charts, trend lines)

### 4A — Enterprise Findings Report (`phi_scan/report.py`)

The full report is generated when PHI/PII is detected. It must be something a
compliance officer can hand directly to an auditor or executive.

#### 4A.1 — Executive Summary Section

- [ ] **4A.1a** Risk level assessment: CRITICAL / HIGH / MODERATE / LOW / CLEAN
  - CRITICAL: SSN, MRN, or health plan numbers found (>= 1 high-confidence)
  - HIGH: names + dates or geographic data found together
  - MODERATE: medium-confidence findings only
  - LOW: low-confidence findings or informational matches only
  - CLEAN: zero findings
- [ ] **4A.1b** Total findings count with severity breakdown (HIGH / MEDIUM / LOW)
- [ ] **4A.1c** Files scanned vs files with findings (e.g., "4 of 1,247 files contain PHI")
- [ ] **4A.1d** HIPAA category breakdown — count per category (e.g., "SSN: 4, Names: 3, MRN: 2")
- [ ] **4A.1e** Scan metadata: timestamp, repository, branch, scanner version, scan duration

#### 4A.2 — Detailed Findings Table

Each finding includes all of the following:

- [ ] **4A.2a** File path — full path from repository root
- [ ] **4A.2b** Line number — exact location in file
- [ ] **4A.2c** Entity type — SSN, PERSON, EMAIL, MRN, IP_ADDRESS, etc.
- [ ] **4A.2d** HIPAA category — which of the 18 identifiers (e.g., "#7 — Social Security Numbers")
- [ ] **4A.2e** Confidence score — 0.0 to 1.0
- [ ] **4A.2f** Severity level — HIGH (red), MEDIUM (yellow), LOW (green)
- [ ] **4A.2g** Detection layer — regex, NLP/NER, FHIR, AI
- [ ] **4A.2h** Code context — surrounding 3–5 lines with PHI value masked as `[REDACTED]`
- [ ] **4A.2i** Value hash — SHA-256 of detected value (for audit correlation, never raw PHI)

#### 4A.3 — Remediation Guidance Section

Grouped by HIPAA category. Each category gets a specific, actionable fix:

- [ ] **4A.3a** Build `HIPAA_REMEDIATION_GUIDANCE` dict mapping all 18 categories
- [ ] **4A.3b** Per-finding remediation hint — attached to each finding row
- [ ] **4A.3c** General remediation checklist at end of report

#### 4A.4 — Visual Summary Charts

- [ ] **4A.4a** Bar chart — findings count by HIPAA category (horizontal bar, sorted descending)
- [ ] **4A.4b** Severity distribution — pie/donut chart (HIGH vs MEDIUM vs LOW with counts)
- [ ] **4A.4c** Top 10 files with most findings — horizontal bar chart
- [ ] **4A.4d** Trend line — findings over time from audit log history (last 30/60/90 days)
- [ ] **4A.4e** Charts embedded in PDF and HTML reports as images (matplotlib → PNG → embed)

#### 4A.5 — Report Formats

- [ ] **4A.5a** **PDF report** (`fpdf2`) — professional, printable, letterhead-style:
  - Cover page: "PHI/PII Scan Report" + repo name + date + risk level badge
  - Executive summary page with charts
  - Detailed findings table (paginated)
  - Remediation guidance section
  - Appendix: scan configuration, scanner version, HIPAA reference
- [ ] **4A.5b** **HTML report** (`jinja2`) — shareable, self-contained single HTML file:
  - Responsive layout, works in any browser
  - Charts embedded as base64 PNG images
  - Clickable file paths (relative links)
  - Color-coded severity badges
  - Collapsible code context sections
  - Print-friendly CSS
- [ ] **4A.5c** Wire `--output pdf` and `--output html` flags into CLI

### 4B — Multi-Framework Compliance Mapping

HIPAA is primary, but healthcare orgs rarely care about HIPAA alone.

- [ ] **4B.1** `phi_scan/compliance.py` — compliance framework mapping engine
- [ ] **4B.2** Framework mappings (each finding tagged with applicable controls):
  - **HIPAA** — 45 CFR §164.514 (Safe Harbor de-identification, primary, always on);
    §164.530(j) (audit log retention); §164.312 (technical safeguards)
  - **HITECH Act** — 45 CFR §§164.400–414 (breach notification thresholds and BA obligations);
    findings from this scanner directly inform HITECH breach risk assessment. Map HIGH-confidence
    findings to HITECH "unsecured PHI" definition — these trigger breach notification obligations.
  - **SOC 2 Type II** — CC6.1 (logical and physical access controls), CC6.7 (data transmission
    and disposal), CC6.6 (logical access security measures — PHI in code is a CC6.6 violation)
  - **HITRUST CSF v11** — 09.s (monitoring system use and exchange of information),
    01.v (information access restriction), 07.a (inventory of assets — PHI in source is
    an uncontrolled asset), 09.ab (monitoring system use)
  - **NIST SP 800-53 Rev 5** — SC-28 (protection of information at rest), SI-1 (system and
    information integrity policy), AU-3 (content of audit records), AU-9 (protection of audit
    information — tamper-evident log required), AU-10 (non-repudiation),
    PM-22 (personally identifiable information quality management),
    PT-2 (authority to process PII), PT-3 (purposes of PII processing)
  - **NIST SP 800-122** — PII confidentiality guide; governs the PII detection side of the
    scanner (non-health personal information). Controls: 2.1 (identify PII), 2.2 (minimize
    PII), 4.1 (apply appropriate safeguards based on PII confidentiality impact level)
  - **GDPR** — Article 4(1) (personal data definition), Article 4(15) (health data definition),
    **Article 9** (special categories: health data, genetic data, biometric data used for unique
    identification — these require explicit consent and are the highest-risk GDPR category),
    Article 32 (security of processing), Article 25 (data protection by design and by default)
  - **42 CFR Part 2** — Substance Use Disorder record confidentiality (stricter than HIPAA;
    prohibits re-disclosure without explicit consent). Flag findings where SUD-related field
    names or patterns are detected with a `42 CFR Part 2` annotation and elevated risk level.
  - **GINA** — Genetic Information Nondiscrimination Act; genetic identifier findings
    (rs-IDs, VCF data, gene panel names) map to GINA Title II (employment) and HIPAA's
    genetic information provisions (45 CFR §164.514(b)(1))
  - **State Laws (configurable via `--framework` flag)**:
    - **California CMIA** — Confidentiality of Medical Information Act; stricter than HIPAA
      for health apps, digital health services; civil penalties up to $250,000 per violation
    - **California SB 3 / AB 825** — genomic data protections; genetic data requires
      explicit consent; flag all genetic identifier findings with CMIA annotation when enabled
    - **Illinois BIPA** — Biometric Information Privacy Act; private right of action;
      biometric identifier findings always flagged with BIPA annotation when `--framework bipa`
    - **New York SHIELD Act** — expanded breach notification; broader definition of private
      information than federal HIPAA
    - **Texas MRPA** — Medical Records Privacy Act; covers all identifiable health information
      including information not covered by HIPAA
- [ ] **4B.3** `--framework hipaa,soc2,hitrust,nist,gdpr,42cfr2,gina,cmia,bipa` flag —
  annotate findings with selected frameworks; `hipaa` always on; others opt-in
- [ ] **4B.4** Report includes compliance matrix: which frameworks are violated by each finding
- [ ] **4B.5** PDF/HTML reports include framework-specific sections when `--framework` is used
- [ ] **4B.6** `phi-scan explain frameworks` — new explain topic listing all supported frameworks
  with full regulatory citation, enforcement body, and penalty ranges
- [ ] **4B.7** `phi-scan explain deidentification` — explain HIPAA Safe Harbor vs Expert
  Determination methods; document that PhiScan implements Safe Harbor; document that Expert
  Determination requires a qualified statistician's sign-off that the tool alone cannot provide;
  document known detection gaps (PDF, DICOM, Office documents, compiled code)

### 4C — Full Documentation Suite

- [ ] **4C.1** `docs/confidence-scoring.md` — what confidence means, threshold ranges, per-layer breakdown, how to tune
- [ ] **4C.2** `docs/hipaa-identifiers.md` — all 18 HIPAA PHI identifiers with examples and regex patterns
- [ ] **4C.3** `docs/detection-layers.md` — how regex, NLP, FHIR, and AI layers work together
- [ ] **4C.4** `docs/output-formats.md` — table, json, csv, sarif, pdf, html — when to use each, examples
- [ ] **4C.5** `docs/remediation-guide.md` — per-category remediation playbook, synthetic data recommendations
- [ ] **4C.6** `docs/changelog.md` — version history with breaking changes noted
- [ ] **4C.7** `CONTRIBUTING.md` — how to contribute, code standards, PR process
- [ ] **4C.8** Update README.md — add terminal screenshots, enterprise report examples
- [ ] **4C.9** `docs/plugin-developer-guide.md` — how to build custom recognizers, register via entry points, test, and publish
- [ ] **4C.10** `docs/compliance-frameworks.md` — complete regulatory reference:
  - All supported frameworks with full citations (HIPAA, HITECH, NIST 800-53, NIST 800-122,
    GDPR, 42 CFR Part 2, GINA, SOC 2, HITRUST, state laws)
  - Per-framework control mappings table (which PhiScan findings violate which controls)
  - Penalty ranges per framework (HIPAA tiers $100–$50,000/violation; GDPR up to 4% global
    revenue; BIPA private right of action $1,000–$5,000/violation)
  - Enforcement bodies (OCR for HIPAA/HITECH, FTC for GINA, state AGs for state laws)
  - How to use `--framework` flag with CI/CD pipeline examples per framework
- [ ] **4C.11** `docs/de-identification.md` — HIPAA de-identification guide:
  - Safe Harbor method (§164.514(b)(2)) — what PhiScan covers and how
  - Expert Determination method (§164.514(b)(1)) — requires qualified statistician;
    PhiScan is a supporting tool, not a substitute for Expert Determination certification
  - Known detection gaps: PDF, DICOM, Office documents, compiled bytecode
  - Quasi-identifier re-identification risk (Sweeney research; ZIP+DOB+sex combination)
  - Recommended remediation workflow: scan → fix → verify → baseline → monitor
- [ ] **4C.12** `docs/known-limitations.md` — explicit documentation of detection boundaries:
  - File types not scanned (PDF, DICOM, DOCX, XLSX, PPTX, compiled bytecode)
  - Safe Harbor scope (not Expert Determination)
  - State law coverage is advisory — a finding annotated with CMIA is not a legal opinion
  - 42 CFR Part 2 detection is pattern-based — legal advice required for compliance decisions
  - PHI-in-context vs. PHI-in-isolation — the scanner flags identifiers, not legal PHI status

### 4D — Phase 4 Testing

- [ ] **4D.1** `tests/test_report_pdf.py` — PDF generates without error, page count > 0, contains expected sections (executive summary, findings table, remediation, charts)
- [ ] **4D.2** `tests/test_report_html.py` — HTML renders valid markup, contains chart images, code context sections, cross-links work
- [ ] **4D.3** `tests/test_executive_summary.py` — risk level calculation matches severity distribution, scan metadata accurate
- [ ] **4D.4** `tests/test_remediation.py` — every PHI type has remediation guidance, suggested code replacements are syntactically valid
- [ ] **4D.5** `tests/test_charts.py` — chart PNG generation succeeds, charts reflect actual findings data (severity pie, category bar, trend line)
- [ ] **4D.6** `tests/test_compliance_mapping.py` — each finding maps to correct HIPAA identifier, SOC 2 control, HITRUST requirement
- [ ] **4D.7** `tests/test_report_formats.py` — `--output pdf`, `--output html` produce valid files; filenames default correctly; `--report-path` respected
- [ ] **4D.8** `tests/test_multi_framework.py` — `--framework soc2`, `--framework hipaa+hitrust` produce correct combined compliance sections

### Phase 4 Verification Checklist

- [ ] PDF report opens correctly, contains charts, findings table, and remediation
- [ ] HTML report renders in browser, charts visible, code context expandable
- [ ] Executive summary risk level matches findings severity
- [ ] Every finding includes remediation guidance
- [ ] Charts accurately reflect findings data
- [ ] `--output pdf` and `--output html` produce valid files
- [ ] `--framework soc2` adds SOC 2 control mappings to findings
- [ ] `--framework gdpr` annotates health data findings with Article 9 (special categories)
- [ ] `--framework 42cfr2` annotates SUD-related findings with 42 CFR Part 2 notice
- [ ] `--framework gina` annotates genetic identifier findings with GINA protections
- [ ] `--framework bipa` annotates biometric findings with BIPA private right of action notice
- [ ] PDF/HTML reports include multi-framework compliance sections
- [ ] `phi-scan explain frameworks` lists all supported compliance frameworks with penalty ranges
- [ ] `phi-scan explain deidentification` documents Safe Harbor vs Expert Determination gap
- [ ] `docs/compliance-frameworks.md` complete with citations, controls, and penalties
- [ ] `docs/de-identification.md` complete with known gaps (PDF, DICOM, Office docs)
- [ ] `docs/known-limitations.md` complete and honest about detection boundaries
- [ ] All documentation files complete and cross-linked
- [ ] CONTRIBUTING.md merged to repo

---

## Phase 5: Notifications & Audit Log Hardening (Week 12)

**Goal:** Email and webhook notifications on PHI detection. Production-grade
SQLite audit log with HIPAA-compliant retention and immutability.

**Dependencies:** Phase 4 complete. Scanner produces findings to log and notify about.

**Version on completion: 0.5.0**

### 5A — Email Notifications

- [ ] **5A.1** Build `notifier.py` — email notification module
- [ ] **5A.2** SMTP support — configurable host, port, TLS, from address
- [ ] **5A.3** Configurable recipients from `.phi-scanner.yml` (secops, repo-owner, compliance)
- [ ] **5A.4** Rich-formatted email template — findings table, remediation hints
- [ ] **5A.5** Email fields: subject with repo/branch/PR#, committer info, scanner version
- [ ] **5A.6** TLS required for all SMTP connections — no plaintext email
- [ ] **5A.7** Attach PDF or HTML report to email when `fail_on_violation` triggers
- [ ] **5A.8** Email subject format: `[PHI ALERT] {risk_level} — {findings_count} findings in {repo}/{branch}`

### 5B — Webhook Notifications

- [ ] **5B.1** httpx async webhook client — POST findings JSON to configured URL
- [ ] **5B.2** Slack webhook support — formatted message with findings summary
- [ ] **5B.3** Microsoft Teams webhook support
- [ ] **5B.4** Generic webhook — POST JSON to any URL (PagerDuty, custom)
- [ ] **5B.5** Retry logic — configurable retry count on webhook failure

### 5C — Audit Log Hardening

- [ ] **5C.1** Finalize SQLite schema — `scan_events` table with full findings JSON
- [ ] **5C.2** Enforce immutability — application-level guards against UPDATE/DELETE
- [ ] **5C.3** Audit log entry schema matches PDF spec:
  - timestamp, scanner_version, event_type, repository, branch, pr_number
  - committer (name, email), pipeline, findings array, action_taken, notifications_sent
- [ ] **5C.4** Log rotation — retention policy respecting `AUDIT_RETENTION_DAYS` (2192 days / 6 years)
- [ ] **5C.5** `phi-scan history` command — query by date range, repo, violation-only filter
- [ ] **5C.6** `phi-scan report` command — display last scan with Rich formatting
- [ ] **5C.7** Trend analysis queries — supply data for trend charts (findings over time, by repo, by category)
- [ ] **5C.8** Hash chain tamper evidence — each `scan_events` row stores an HMAC-SHA256
  chain hash: `row_chain_hash = HMAC-SHA256(key=audit_secret, msg=prev_chain_hash + row_content)`.
  The first row uses a fixed genesis hash. On startup, `verify_audit_chain(database_path)`
  recomputes the chain and raises `AuditLogError` if any row hash does not match.
  Satisfies NIST SP 800-53 Rev 5 AU-9 (protection of audit information) and AU-10
  (non-repudiation). Without this, a database file can be silently modified at the OS level
  despite application-level INSERT-only guards — the chain detects retroactive tampering.
  - `audit_secret` stored in `~/.phi-scanner/audit.key` (generated on first run, never committed)
  - `phi-scan history --verify` runs chain verification and reports integrity status
  - Schema addition: `row_chain_hash TEXT NOT NULL` column in `scan_events`
- [ ] **5C.9** Audit log encryption at rest — encrypt `audit.db` using SQLCipher or
  file-level encryption (`cryptography` package, AES-256-GCM). Key stored separately from
  database. Document key management requirements in `docs/security.md`.

### 5D — Notification Testing

- [ ] **5D.1** Test email notification sends on PHI detection (mock SMTP)
- [ ] **5D.2** Test webhook POST with mock server
- [ ] **5D.3** Test audit log insert and query roundtrip
- [ ] **5D.4** Test retention policy does not delete within 6-year window
- [ ] **5D.5** Test immutability — verify UPDATE/DELETE raise errors

### Phase 5 Verification Checklist

- [ ] Email sent on PHI detection with correct subject and body
- [ ] Webhook fires to Slack/Teams/generic URL
- [ ] Audit log entries are immutable (no UPDATE/DELETE)
- [ ] `phi-scan history --last 30d` returns correct results
- [ ] `phi-scan report` displays last scan with Rich formatting
- [ ] Retention policy is HIPAA-compliant (6 years minimum)
- [ ] `phi-scan history --verify` recomputes chain hash and reports PASS or FAIL
- [ ] Tampered row detected: manually modifying a row causes `--verify` to fail with clear message
- [ ] Audit log encrypted at rest; unencrypted file not readable without key

---

## Phase 6: CI/CD Integration & Docker (Weeks 13–14)

**Goal:** Drop-in CI/CD templates for all major platforms. Docker container
for runners without Python. PR/MR comment posting via platform-native APIs.
First-class GitHub, GitLab, Jenkins, Azure DevOps, CircleCI, Bitbucket Pipelines, and AWS CodeBuild integration — all seven platforms are equally supported.

**Dependencies:** Phase 5 complete. Scanner, notifications, and audit log all production-ready.

**Version on completion: 0.6.0**

### 6A — CI/CD Templates

- [ ] **6A.1** GitHub Actions workflow — `.github/workflows/phi-scan.yml`
- [ ] **6A.2** GitLab CI job template — `.gitlab-ci.yml` snippet:
  - Scan stage with `phi-scan scan --diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME`
  - Code Quality artifact upload (findings as inline MR annotations)
  - SAST artifact upload (GitLab Security Dashboard integration)
  - Cache spaCy model between pipeline runs (`$HOME/.phi-scanner/` cache key)
  - Fail pipeline on violation via exit code
  - Works with GitLab.com and self-hosted GitLab instances
- [ ] **6A.3** Jenkins pipeline stage — `Jenkinsfile` snippet:
  - Declarative pipeline stage calling `phi-scan scan --diff origin/${env.CHANGE_TARGET}`
  - Publish Warnings NG report (`recordIssues tool: sarif(pattern: 'phi-report.sarif')`) for inline annotations
  - Archive JSON/SARIF/CSV artifacts via `archiveArtifacts`
  - Fail build on violation via exit code (`sh` step returns non-zero)
  - Shared library variant for org-wide reuse (`vars/phiScan.groovy`)
  - Support both Declarative and Scripted pipeline syntax
  - Works with Jenkins multibranch pipelines (auto-detect `CHANGE_ID`, `CHANGE_TARGET`)
  - Docker agent option: `agent { docker { image 'phi-scan:latest' } }`
- [ ] **6A.4** Azure DevOps YAML step — `azure-pipelines.yml`:
  - Task step calling `phi-scan scan --diff origin/$(System.PullRequest.TargetBranch)`
  - Publish SARIF via `PublishBuildArtifacts` task for traceability
  - PR thread comment via Azure DevOps REST API (`/pullrequests/{id}/threads`)
  - Pipeline status check integration — block PR completion on violation
  - Support both hosted and self-hosted agents
  - Cache spaCy model via `Cache@2` task (`~/.phi-scanner/` key)
  - Works with Azure Repos and GitHub repos connected to Azure Pipelines
- [ ] **6A.5** CircleCI job — `.circleci/config.yml`:
  - Docker executor job using `phi-scan:latest` image (or `pip install phi-scan`)
  - `phi-scan scan --diff origin/$CIRCLE_BRANCH` for PR-triggered builds
  - Store SARIF/JSON artifacts via `store_artifacts` step
  - Store test results via `store_test_results` (JUnit-style summary)
  - Fail job on violation via exit code
  - Cache spaCy model via CircleCI cache (`save_cache` / `restore_cache`)
  - GitHub/Bitbucket PR comment posting via platform API (auto-detect `CIRCLE_PULL_REQUEST`)
- [ ] **6A.6** Bitbucket Pipelines step — `bitbucket-pipelines.yml`:
  - Pipe step calling `phi-scan scan --diff origin/$BITBUCKET_PR_DESTINATION_BRANCH`
  - PR comment posting via Bitbucket REST API (`/pullrequests/{id}/comments`)
  - Build status reporting via Bitbucket Commit Status API
  - Store SARIF/JSON as Bitbucket Pipeline artifacts
  - Fail step on violation via exit code
  - Support Bitbucket Cloud and Bitbucket Data Center (Server)
  - Cache spaCy model via Bitbucket Pipelines `caches` definition
- [ ] **6A.7** AWS CodeBuild — `buildspec.yml`:
  - Build phase command calling `phi-scan scan --diff` against PR base branch
  - Upload SARIF/JSON to S3 artifacts bucket
  - CodeBuild report group integration — findings surfaced in AWS Console
  - GitHub/Bitbucket PR comment posting via platform API (detect `CODEBUILD_WEBHOOK_TRIGGER`)
  - Fail build on violation via exit code
  - Support CodePipeline orchestration (pass/fail gate between stages)
  - Cache spaCy model via CodeBuild local cache or S3 cache

### 6B — Docker Container

- [ ] **6B.1** Write `docker/Dockerfile` — Alpine-based, phi-scan pre-installed
- [ ] **6B.2** Write `docker/docker-compose.yml` — local testing setup
- [ ] **6B.3** Optimize image size — multi-stage build, minimal layers
- [ ] **6B.4** Pin base image version and verify checksums
- [ ] **6B.5** Multi-architecture build: `linux/amd64` and `linux/arm64` (Apple Silicon support)
- [ ] **6B.6** Test: `docker run phi-scan:latest scan /repo` works end-to-end

### 6C — PR / MR Integration

#### 6C-GH — GitHub PR Integration

- [ ] **6C.1** `gh` CLI integration — post PR comment with findings table
- [ ] **6C.2** Comment includes: file path, line number, entity type, confidence, remediation hint
- [ ] **6C.3** Set commit status — PASS/FAIL based on `fail_on_violation` config
- [ ] **6C.4** `--diff` mode — scan only changed files in PR (git diff extraction)
- [ ] **6C.5** GitHub inline annotations via SARIF upload:
  - Upload SARIF output to GitHub Code Scanning API (`/repos/{owner}/{repo}/code-scanning/sarifs`)
  - Each finding appears as an inline annotation on the exact line in the PR diff
  - Severity mapped to GitHub levels: `error` (HIGH), `warning` (MEDIUM), `note` (LOW)
  - Annotation message includes entity type, HIPAA category, confidence, and remediation hint
  - Works automatically with `--output sarif` in GitHub Actions

#### 6C-GL — GitLab MR Integration

- [ ] **6C.6** GitLab MR note (comment) posting via GitLab API:
  - Use `GITLAB_TOKEN` (CI_JOB_TOKEN or personal access token) for authentication
  - POST to `/api/v4/projects/:id/merge_requests/:iid/notes`
  - Comment includes: findings table, severity breakdown, remediation hints
  - Auto-detect GitLab context from `CI_PROJECT_ID` and `CI_MERGE_REQUEST_IID` env vars
  - Fallback: `--gitlab-project-id` and `--gitlab-mr-iid` flags for manual invocation
- [ ] **6C.7** GitLab Code Quality report support:
  - Generate Code Quality JSON format (`--output codequality`)
  - Upload as GitLab CI artifact (`gl-code-quality-report.json`) — findings appear as inline MR annotations
  - Each finding maps to: file path, line number, severity, description, fingerprint
- [ ] **6C.8** GitLab SAST report support:
  - Generate GitLab SAST JSON format (`--output gitlab-sast`)
  - Upload as GitLab CI artifact (`gl-sast-report.json`) — findings appear in Security Dashboard
  - Follows GitLab SAST report schema (version 15.0.0+)
  - Includes: vulnerability category, severity, location (file + line), identifiers (HIPAA ref)
- [ ] **6C.9** GitLab external status check integration:
  - Set pipeline status based on scan result (success/failed)
  - Works with GitLab merge request approval rules (require green pipeline)

#### 6C-JK — Jenkins PR Integration

- [ ] **6C.12** Jenkins Warnings NG plugin integration:
  - Generate SARIF output (`--output sarif`) consumed by Warnings NG `recordIssues`
  - Each finding appears as an inline annotation in Jenkins build results
  - Severity mapped to Warnings NG levels: `ERROR` (HIGH), `WARNING_NORMAL` (MEDIUM), `WARNING_LOW` (LOW)
  - Findings visible in Warnings NG trend charts across builds
- [ ] **6C.13** Jenkins Checks API integration (GitHub/Bitbucket PRs from Jenkins):
  - Post check run with findings summary when Jenkins builds a PR
  - Uses `publishChecks` step from Jenkins Checks API plugin
  - Annotations attached to specific file + line in PR diff
  - Works with GitHub Branch Source and Bitbucket Branch Source plugins
- [ ] **6C.14** Jenkins build description update:
  - Set build description to scan summary: "PhiScan: 3 findings (2 HIGH, 1 MED)" or "PhiScan: Clean"
  - Color-coded badge via Jenkins Badge plugin (optional)
- [ ] **6C.15** Jenkins pipeline shared library (`vars/phiScan.groovy`):
  - Reusable step: `phiScan(path: '.', severity: 'medium', failOnViolation: true)`
  - Encapsulates install, scan, artifact archive, and Warnings NG publish
  - Org-wide deployment via Jenkins Global Pipeline Libraries

#### 6C-ADO — Azure DevOps PR Integration

- [ ] **6C.16** Azure DevOps PR thread comment via REST API:
  - Use `SYSTEM_ACCESSTOKEN` (System.AccessToken) for authentication
  - POST to `/_apis/git/repositories/{repo}/pullRequests/{id}/threads`
  - Comment includes: findings table, severity breakdown, remediation hints
  - Auto-detect Azure DevOps context from `SYSTEM_TEAMFOUNDATIONCOLLECTIONURI`, `BUILD_REPOSITORY_ID`, `SYSTEM_PULLREQUEST_PULLREQUESTID` env vars
  - Support both status=active (new thread) and reply to existing PhiScan thread (update on re-run)
- [ ] **6C.17** Azure DevOps build tag and status:
  - Tag build with `phi-scan:clean` or `phi-scan:violations-found`
  - Set PR status policy via Azure DevOps Status API (`/statuses`)
  - Block PR completion when status is `failed` and branch policy requires it
- [ ] **6C.18** Azure Boards work-item linking (optional):
  - Create work item for HIGH severity findings if `azure_boards_integration: true`
  - Link work item to PR for tracking remediation

#### 6C-CI — CircleCI PR Integration

- [ ] **6C.19** CircleCI PR comment posting:
  - Auto-detect PR from `CIRCLE_PULL_REQUEST` env var (extract PR number)
  - Post comment via GitHub API or Bitbucket API depending on VCS provider
  - Comment includes: findings table, severity breakdown, remediation hints
  - Uses `GITHUB_TOKEN` or `BITBUCKET_TOKEN` depending on VCS
- [ ] **6C.20** CircleCI test summary integration:
  - Generate JUnit XML output (`--output junit`) — each finding becomes a test failure
  - CircleCI Test Summary tab shows findings with file, line, entity type
  - Trend tracking across builds via CircleCI Insights
- [ ] **6C.21** CircleCI orb packaging:
  - Publish reusable CircleCI orb `phi-scan/phi-scan` to CircleCI Orb Registry
  - Orb encapsulates: install, scan, comment, artifact upload
  - Configurable parameters: `severity_threshold`, `fail_on_violation`, `output_format`
  - Orb versioning follows PhiScan releases

#### 6C-BB — Bitbucket PR Integration

- [ ] **6C.22** Bitbucket PR comment posting via REST API:
  - Use `BITBUCKET_TOKEN` (Repository/Workspace access token) for authentication
  - POST to `/2.0/repositories/{workspace}/{repo}/pullrequests/{id}/comments`
  - Comment includes: findings table, severity breakdown, remediation hints
  - Auto-detect from `BITBUCKET_PR_ID`, `BITBUCKET_REPO_SLUG`, `BITBUCKET_WORKSPACE` env vars
  - Support both Bitbucket Cloud API and Bitbucket Data Center REST API
- [ ] **6C.23** Bitbucket Code Insights integration:
  - Report findings as Bitbucket Code Insights annotations (inline PR annotations)
  - POST to `/2.0/repositories/{workspace}/{repo}/commit/{hash}/reports/{reportId}/annotations`
  - Severity mapped: `HIGH` → HIGH, `MEDIUM` → MEDIUM, `LOW` → LOW
  - Report summary with total/new/resolved counts
- [ ] **6C.24** Bitbucket build status:
  - Set commit build status via Bitbucket Commit Status API
  - Block PR merge when build status is `FAILED` and merge check requires it

#### 6C-AWS — AWS CodeBuild PR Integration

- [ ] **6C.25** AWS CodeBuild PR comment posting:
  - Auto-detect PR from `CODEBUILD_WEBHOOK_TRIGGER` (e.g., `pr/123`)
  - Post comment via GitHub API or Bitbucket API depending on source provider
  - Uses `GITHUB_TOKEN` or Bitbucket app credentials from Secrets Manager / SSM
- [ ] **6C.26** AWS CodeBuild report group integration:
  - Create report group `phi-scan-findings` with SARIF format
  - Findings surfaced in AWS CodeBuild Console → Reports tab
  - Trend tracking across builds via CodeBuild report history
- [ ] **6C.27** AWS Security Hub integration (optional):
  - Convert findings to ASFF (AWS Security Finding Format)
  - Import findings to AWS Security Hub for centralized security view
  - Only enabled when `aws_security_hub: true` in config
  - Requires `securityhub:BatchImportFindings` IAM permission

#### 6C-Common — Shared PR/MR Features

- [ ] **6C.10** PR/MR comment includes baseline context:
  - "3 new findings | 7 baselined | 2 resolved since last scan"
  - New findings highlighted, baselined findings listed but dimmed
- [ ] **6C.11** Auto-detect platform: check `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`, `BUILD_ID`, `SYSTEM_TEAMFOUNDATIONCOLLECTIONURI`, `CIRCLECI`, `BITBUCKET_BUILD_NUMBER`, `CODEBUILD_BUILD_ID` env vars to select integration automatically

### 6D — CI/CD Testing

- [ ] **6D.1** End-to-end test: GitHub Actions workflow scans repo with synthetic PHI
- [ ] **6D.2** Docker container scan produces correct exit code (0 = clean, 1 = violation)
- [ ] **6D.3** GitHub PR comment posted correctly via `gh` CLI
- [ ] **6D.4** Pipeline blocks merge when `fail_on_violation: true` (all seven platforms)
- [ ] **6D.5** SARIF upload produces inline annotations on correct lines in GitHub PR
- [ ] **6D.6** Docker ARM image works on Apple Silicon
- [ ] **6D.7** GitLab MR note posted correctly via GitLab API (mock `CI_JOB_TOKEN`)
- [ ] **6D.8** GitLab Code Quality JSON (`gl-code-quality-report.json`) validates against GitLab schema
- [ ] **6D.9** GitLab SAST JSON (`gl-sast-report.json`) validates against GitLab SAST schema v15+
- [ ] **6D.10** Auto-detect: GitHub context uses `gh`, GitLab context uses GitLab API, Jenkins context uses Warnings NG, Azure DevOps context uses Azure API, CircleCI detects VCS, Bitbucket context uses Bitbucket API, CodeBuild detects source provider
- [ ] **6D.11** Jenkins Declarative pipeline Jenkinsfile runs scan and publishes Warnings NG report
- [ ] **6D.12** Jenkins SARIF output consumed by Warnings NG `recordIssues` with correct severity mapping
- [ ] **6D.13** Jenkins Checks API posts annotations to PR when building from GitHub Branch Source
- [ ] **6D.14** Azure DevOps `azure-pipelines.yml` runs scan and posts PR thread comment
- [ ] **6D.15** Azure DevOps PR status policy blocks completion when violation found
- [ ] **6D.16** Azure DevOps build tag set correctly (`phi-scan:clean` vs `phi-scan:violations-found`)
- [ ] **6D.17** CircleCI job runs scan, stores artifacts, and posts PR comment via GitHub API
- [ ] **6D.18** CircleCI JUnit XML output parsed correctly by CircleCI Test Summary
- [ ] **6D.19** CircleCI orb installs, scans, and reports correctly with default parameters
- [ ] **6D.20** Bitbucket Pipelines step runs scan and posts PR comment via Bitbucket API
- [ ] **6D.21** Bitbucket Code Insights annotations appear inline on correct PR lines
- [ ] **6D.22** Bitbucket build status blocks PR merge when merge check requires green build
- [ ] **6D.23** AWS CodeBuild `buildspec.yml` runs scan and uploads SARIF to report group
- [ ] **6D.24** AWS CodeBuild PR comment posted via GitHub API when source is GitHub
- [ ] **6D.25** AWS Security Hub ASFF import validates against Security Hub schema (when enabled)

### Phase 6 Verification Checklist

- [ ] GitHub Actions workflow runs and blocks PR on PHI detection
- [ ] GitLab CI pipeline runs and blocks MR on PHI detection
- [ ] Jenkins pipeline runs and blocks build on PHI detection
- [ ] Azure DevOps pipeline runs and blocks PR on PHI detection
- [ ] CircleCI job runs and blocks merge on PHI detection
- [ ] Bitbucket Pipelines step runs and blocks PR on PHI detection
- [ ] AWS CodeBuild build runs and blocks merge on PHI detection
- [ ] Docker image builds for amd64 and arm64, scans, and exits correctly
- [ ] GitHub PR comment appears with findings table via `gh` CLI
- [ ] GitLab MR comment appears with findings table via GitLab API
- [ ] Jenkins Warnings NG shows inline findings annotations
- [ ] Azure DevOps PR thread comment appears with findings table
- [ ] Azure DevOps PR status blocks completion when policy configured
- [ ] CircleCI PR comment posted via detected VCS provider API
- [ ] CircleCI JUnit test summary shows findings in Test Summary tab
- [ ] CircleCI orb published and installable from Orb Registry
- [ ] Bitbucket PR comment appears with findings table via Bitbucket API
- [ ] Bitbucket Code Insights annotations appear inline in PR diff
- [ ] Bitbucket build status blocks PR merge via merge check
- [ ] AWS CodeBuild report group shows findings in AWS Console
- [ ] AWS CodeBuild PR comment posted when source is GitHub/Bitbucket
- [ ] AWS Security Hub import validates when `aws_security_hub: true`
- [ ] `--diff HEAD~1` scans only changed files
- [ ] Exit code 1 blocks pipeline merge (all seven platforms)
- [ ] SARIF upload produces inline annotations in GitHub PR diff
- [ ] GitLab Code Quality report shows inline MR annotations
- [ ] GitLab SAST report appears in GitLab Security Dashboard
- [ ] Jenkins SARIF consumed by Warnings NG with correct severity levels
- [ ] Jenkins Checks API posts annotations on PR builds
- [ ] Auto-detection correctly identifies all seven CI/CD platforms from env vars
- [ ] `--output codequality` produces valid GitLab Code Quality JSON
- [ ] `--output gitlab-sast` produces valid GitLab SAST JSON

---

## Phase 7: AI Enhancement — Optional (Weeks 15–16)

**Goal:** Reduce false positives with Claude API confidence scoring on ambiguous
findings. Fine-tune spaCy NER for healthcare-specific entities. **Never send raw
PHI to any external API.**

**Dependencies:** Phase 6 complete. Optional phase — can be skipped entirely.

**Version on completion: 0.7.0**

**Critical Constraint:** All PHI values replaced with `[REDACTED]` before any API call.
Only code structure with redacted values sent to Claude. High-confidence and regex
matches bypass Claude entirely.

### 7A — Claude API Integration

- [ ] **7A.1** Integrate Anthropic SDK (already installed, v0.84.0)
- [ ] **7A.2** Build redaction layer — replace all detected PHI values with `[REDACTED]` before API call
- [ ] **7A.3** Send only redacted code context to Claude for confidence scoring
- [ ] **7A.4** Claude model: `claude-sonnet-4-6` — best balance of speed and accuracy
- [ ] **7A.5** Only call Claude for medium-confidence findings (confidence < 0.8 threshold)
- [ ] **7A.6** Parse Claude response: `{ "is_phi_risk": bool, "confidence": float, "reasoning": str }`
- [ ] **7A.7** Cost control — skip Claude for high-confidence regex matches entirely
- [ ] **7A.8** Config: `ai.enable_claude_review: false` by default in `.phi-scanner.yml`

### 7B — spaCy Fine-Tuning

- [ ] **7B.1** Generate synthetic training data — FHIR resources + annotated code with PHI
- [ ] **7B.2** Fine-tune spaCy NER (tok2vec + NER pipeline) on healthcare domain
- [ ] **7B.3** Target ~15-25% improvement over generic `en_core_web_lg` for healthcare entities
- [ ] **7B.4** Evaluate on held-out test set — precision, recall, F1

### 7C — AI Testing

- [ ] **7C.1** Verify no raw PHI values appear in any API request (packet-level test)
- [ ] **7C.2** A/B test: scanner with vs without AI — measure false positive reduction
- [ ] **7C.3** Test Claude API failure gracefully falls back to local-only scoring
- [ ] **7C.4** Test cost tracking — log token usage per scan

### Phase 7 Verification Checklist

- [ ] `[REDACTED]` appears in every Claude API request — zero raw PHI leaks
- [ ] False positive rate reduced measurably with AI enabled
- [ ] Claude failures don't crash the scanner — graceful fallback
- [ ] `ai.enable_claude_review: false` disables all API calls
- [ ] Fine-tuned spaCy model improves healthcare entity recall

---

## Phase 8: Pro Tier, Monetization & VS Code Extension (Weeks 17–20)

**Goal:** Define and build Pro features, license key system, plugin/extension
architecture, VS Code extension, billing integration, and marketplace listings.

**Dependencies:** Phase 6 complete (Phase 7 optional). Product is production-ready.

**Version on completion: 0.8.0**

### 8A — Pro Feature Set

- [ ] **8A.1** Define Pro vs Community feature matrix based on pilot feedback
- [ ] **8A.2** Community (Free): core CLI, 18 HIPAA patterns, terminal output, auto-fix, baseline, git hook, SQLite log, inline suppression, scan cache, pre-commit integration
- [ ] **8A.3** Pro ($29-49/dev/month): FHIR deep scan, AI confidence scoring, compliance PDF/HTML reports, multi-framework compliance mapping, email/Slack alerts, team dashboard, VS Code extension premium features, central policy server, priority support

**Pricing principle:** CI/CD templates and core scanning are always free. Paywalling pipeline templates would kill open-source adoption. The free tier must be genuinely useful in CI — Pro upsells on enterprise reporting, AI augmentation, and team features.

- [ ] **8A.4** Enterprise ($5,000-25,000/year): on-premise, custom EHR recognizers, SSO/SAML, SLA, plugin SDK, central policy server, org-wide dashboard

### 8B — Plugin / Extension System

- [ ] **8B.1** `phi_scan/plugin_api.py` — base classes and plugin loader
- [ ] **8B.2** `BaseRecognizer` abstract class — the interface all plugins implement:

  ```python
  class BaseRecognizer(ABC):
      name: str  # e.g., "epic-mrn"
      entity_types: list[str]  # e.g., ["EPIC_MRN", "EPIC_CSN"]

      @abstractmethod
      def detect(self, line: str, context: ScanContext) -> list[ScanFinding]: ...
  ```

- [ ] **8B.3** Plugin discovery via Python entry points:
  - Plugins register via `[project.entry-points."phi_scan.plugins"]` in their `pyproject.toml`
  - PhiScan discovers and loads all installed plugins at startup
  - `phi-scan plugins list` — show all installed plugins with version and entity types
- [ ] **8B.4** Plugin configuration in `.phi-scanner.yml`
- [ ] **8B.5** Example plugins (published separately as proof of concept):
  - `phi-scan-epic` — Epic EHR field patterns (MRN, CSN, MyChart IDs)
  - `phi-scan-cerner` — Cerner Millennium field patterns
  - `phi-scan-hl7` — HL7 v2 message segment scanning (PID, NK1, IN1)
- [ ] **8B.6** Plugin development guide in `docs/plugin-development.md`
- [ ] **8B.7** Plugin template repository — `cookiecutter` template for new plugins

### 8C — VS Code Extension (`phi-scan-vscode`)

This is a separate TypeScript project. It calls the `phi-scan` CLI under the hood.

- [ ] **8C.1** Create VS Code extension scaffold (TypeScript)
- [ ] **8C.2** Diagnostic provider — inline squiggly underlines on detected PHI:
  - Red underline for HIGH severity
  - Yellow underline for MEDIUM severity
  - Blue underline for LOW/INFO severity
  - Diagnostic message: "PHI Detected: SSN (#7) — confidence 0.98"
- [ ] **8C.3** Code action / quick-fix suggestions:
  - "Replace with synthetic data" — applies auto-fix inline
  - "Add phi-scan:ignore to this line" — inserts suppression comment
  - "Add phi-scan:ignore-file" — inserts file-level suppression
  - "View HIPAA category details" — opens explain panel
- [ ] **8C.4** Problem panel integration — all findings listed in VS Code Problems tab
- [ ] **8C.5** Status bar item: "🛡️ PhiScan: Clean" (green) or "⚠️ PhiScan: 3 findings" (red)
- [ ] **8C.6** Scan on save — configurable auto-scan when file is saved
- [ ] **8C.7** Command palette commands:
  - "PhiScan: Scan Current File"
  - "PhiScan: Scan Workspace"
  - "PhiScan: Fix Current File (Synthetic Replacement)"
  - "PhiScan: Show Dashboard"
  - "PhiScan: Create Baseline"
- [ ] **8C.8** Configuration via VS Code settings (maps to `.phi-scanner.yml` options)
- [ ] **8C.9** Hover tooltips on findings — show HIPAA category, confidence breakdown, remediation hint
- [ ] **8C.10** Extension calls `phi-scan` CLI under the hood (requires phi-scan installed)
- [ ] **8C.11** Publish to VS Code Marketplace

### 8D — License & Billing

- [ ] **8D.1** Build license key validation system — Pro features gated by valid key
- [ ] **8D.2** Stripe billing integration for Pro subscriptions
- [ ] **8D.3** License key delivery and rotation workflow

### 8E — Team Dashboard

- [ ] **8E.1** Build team compliance dashboard — web UI or Rich-based terminal dashboard
- [ ] **8E.2** Aggregate scan results across repos and team members
- [ ] **8E.3** Compliance report generation — PDF export

### 8F — Marketplace Listings

- [ ] **8F.1** Create `action.yml` — composite GitHub Action definition:
  - `uses: phi-scan/phi-scan-action@v1` with inputs: `severity_threshold`, `output_format`, `fail_on_violation`, `diff_ref`
  - Composite action: installs phi-scan, runs scan, uploads SARIF, posts PR comment
  - Publish to GitHub Marketplace as a verified action
- [ ] **8F.2** Submit to AWS Marketplace
- [ ] **8F.3** Submit to Azure Marketplace

### 8G — Community Growth & Marketing

_(Community infrastructure — issue templates, PR template, CODE_OF_CONDUCT, Discussions — is in Phase 3E and Phase 9E. This section covers growth content only.)_

- [ ] **8G.1** "Awesome PhiScan" curated list — community plugins, integrations, blog posts
- [ ] **8G.2** Example repositories:
  - `phi-scan-examples` — sample configs for Python/Node/Java/Go projects
  - `phi-scan-ci-examples` — working CI configs for every supported platform
  - `phi-scan-test-fixtures` — synthetic PHI test data for evaluating detection
- [ ] **8G.3** Blog post series / documentation:
  - "Why your CI pipeline needs a PHI scanner"
  - "HIPAA compliance for developers: a practical guide"
  - "Migrating from manual PHI audits to automated scanning"

### Phase 8 Verification Checklist

- [ ] Pro features locked without valid license key
- [ ] Stripe billing creates subscriptions and processes payments
- [ ] Team dashboard shows aggregated scan results
- [ ] Listed on at least one marketplace
- [ ] `phi-scan plugins list` shows installed plugins
- [ ] Custom plugin detects findings correctly and integrates with core output
- [ ] Plugin development guide enables third-party plugin creation
- [ ] Community starter pack (CONTRIBUTING, templates) merged to repo
- [ ] VS Code extension underlines PHI in editor with correct severity colors
- [ ] VS Code quick-fix applies synthetic replacement correctly
- [ ] VS Code status bar shows scan status
- [ ] Extension published to VS Code Marketplace

---

## Phase 9: Hardening, Enterprise & Public Launch (Weeks 21–23)

**Goal:** Security audit, performance optimization, enterprise features,
compliance documentation, and v1.0 public launch.

**Dependencies:** Phase 8 complete. Product is monetized and marketplace-listed.

**Version on completion: 1.0.0** — the first stable public release.

### 9A — Security Hardening

- [ ] **9A.1** Security audit — dependency scanning, supply chain verification
- [ ] **9A.2** Pin all dependency versions — verify checksums
- [ ] **9A.3** Sign Docker image
- [ ] **9A.4** Encrypt audit logs at rest — restrict access to SecOps roles
- [ ] **9A.5** Penetration test the scanner — ensure no PHI leaks in output or logs

### 9B — Performance

- [ ] **9B.1** Performance profiling — target <30 seconds for typical repos (5,000 files)
- [ ] **9B.2** Optimize traversal — lazy iteration with `rglob`, no pre-built lists
- [ ] **9B.3** Parallel file scanning with `concurrent.futures.ProcessPoolExecutor`:
  - Worker pool size = `os.cpu_count()` (configurable via `--workers N`)
  - Each worker scans files independently (read-only, no shared state)
  - Results collected and merged in main process
  - Progress bar updates from main process via queue
  - Fall back to sequential if `--workers 1` or single-file scan
- [ ] **9B.4** Scan cache integration (from 2A.2) — skip unchanged files for >10x speedup on re-scans
- [ ] **9B.5** Benchmark: first scan vs cached re-scan vs parallel scan on 5,000-file repo

### 9C — Enterprise Features

- [ ] **9C.1** Custom EHR recognizer templates — Epic, Cerner, Allscripts (now via plugin system from 8B)
- [ ] **9C.2** SSO/SAML support for Enterprise tier
- [ ] **9C.3** On-premise deployment documentation
- [ ] **9C.4** SLA and support tier definitions
- [ ] **9C.5** Central policy server — org-wide `.phi-scanner.yml` distributed to all repos:
  - Policy endpoint: `https://policies.example.com/phi-scan/config`
  - Config: `policy_server_url` in `.phi-scanner.yml`
  - Org policies override local config (enforced minimum thresholds, required frameworks)
  - Audit log forwarding to central compliance database

### 9D — Launch

- [ ] **9D.1** Write compliance documentation
- [ ] **9D.2** Final QA pass — all tests green, all output formats valid
- [ ] **9D.3** Cross-platform final verification: ubuntu, macos, windows
- [ ] **9D.4** Release v1.0.0 — public launch
- [ ] **9D.5** Post to Hacker News "Show HN", r/devops, r/healthcareit
- [ ] **9D.6** Identify 3-5 pilot enterprise customers

### 9E — Community & Contributor Infrastructure (Extended)

_(Core community files — CODE_OF_CONDUCT, issue templates, PR template, Discussions — ship in Phase 3E to support early adoption. This section covers the extended community program for launch.)_

- [ ] **9E.1** `.github/ISSUE_TEMPLATE/false_positive.md` — false positive report template (entity type, context snippet with PHI redacted, expected behavior)
- [ ] **9E.6** `docs/community.md` — contributor guide overview, plugin showcase, recognition (hall of fame)
- [ ] **9E.7** First-time contributor label (`good first issue`) on 10+ starter issues:
  - Add new regex pattern for a PHI type
  - Add CI template for a new platform
  - Improve error message for a specific failure mode
  - Add test coverage for edge case
  - Documentation improvement
- [ ] **9E.8** Automated welcome bot — greet first-time contributors, link to CONTRIBUTING.md
- [ ] **9E.9** Monthly community update — publish release notes, roadmap progress, contributor stats
- [ ] **9E.10** Plugin showcase page in docs — curated list of community plugins with install instructions

### Phase 9 Verification Checklist

- [ ] Zero critical vulnerabilities in dependency scan
- [ ] Scan completes in <30 seconds on 5,000-file repo
- [ ] Parallel scanning produces identical results to sequential
- [ ] Cached re-scan runs >10x faster than first scan
- [ ] Docker image signed and verifiable
- [ ] Audit logs encrypted at rest
- [ ] v1.0.0 tagged and published to PyPI
- [ ] At least one marketplace listing live
- [ ] CI passes on all three platforms (ubuntu, macos, windows)
- [ ] Issue templates (bug, feature, false positive) live on GitHub
- [ ] PR template with checklist live on GitHub
- [ ] GitHub Discussions enabled with categories _(core templates ship in Phase 3E; extended in 9E)_
- [ ] CODE*OF_CONDUCT.md merged *(ships in Phase 3E)\_
- [ ] 10+ issues labeled `good first issue`
- [ ] Plugin developer guide published in docs

---

## Dependency Strategy

PhiScan uses optional dependency groups to keep the base install lightweight.
CI runners that only need regex scanning can skip the ~500MB spaCy model entirely.

### Install Profiles

| Profile               | Command                         | Size   | Includes                                     |
| --------------------- | ------------------------------- | ------ | -------------------------------------------- |
| **Core (regex-only)** | `pip install phi-scan`          | ~15MB  | Typer, Rich, PyYAML, regex engine, audit log |
| **NLP**               | `pip install phi-scan[nlp]`     | ~550MB | + Presidio, spaCy, en_core_web_lg            |
| **FHIR**              | `pip install phi-scan[fhir]`    | ~20MB  | + fhir.resources                             |
| **Reports**           | `pip install phi-scan[reports]` | ~80MB  | + fpdf2, jinja2, matplotlib                  |
| **Full**              | `pip install phi-scan[full]`    | ~650MB | All of the above                             |
| **Dev**               | `pip install phi-scan[dev]`     | +50MB  | + pytest, ruff, mypy, faker                  |

### pyproject.toml Optional Dependencies

```toml
[project.optional-dependencies]
nlp = ["presidio-analyzer>=2.0", "presidio-anonymizer>=2.0", "spacy>=3.7"]
fhir = ["fhir.resources>=7.0"]
reports = ["fpdf2>=2.7", "jinja2>=3.1", "matplotlib>=3.8"]
full = ["phi-scan[nlp]", "phi-scan[fhir]", "phi-scan[reports]"]
dev = ["pytest>=8.0", "pytest-cov>=4.0", "ruff>=0.4", "mypy>=1.9", "faker>=24.0"]
```

### spaCy Model Management

The spaCy model (`en_core_web_lg`, ~500MB) is not bundled with any install profile.
It must be downloaded separately:

- **`phi-scan setup`** — CLI command that checks for and downloads the spaCy model
- **First-run detection:** if NLP layer is requested but model not found:
  1. Log warning: "spaCy model 'en_core_web_lg' not found"
  2. Print suggestion: "Run `phi-scan setup` to download the model (~500MB)"
  3. Continue scan with regex-only (graceful degradation, not a crash)
- **`make install`** — includes `python -m spacy download en_core_web_lg`
- **Docker image** — model pre-installed in the container
- **CI environments** — model cached between runs via pipeline cache key

### Graceful Degradation

When optional dependencies are not installed, PhiScan reduces capability rather
than crashing:

| Missing Dependency | Behavior                                                |
| ------------------ | ------------------------------------------------------- |
| spaCy / Presidio   | NLP layer disabled, regex-only scanning, warning logged |
| fhir.resources     | FHIR layer disabled, warning logged                     |
| fpdf2 / jinja2     | `--output pdf/html` returns error with install hint     |
| matplotlib         | Reports generated without charts, note in report        |
| faker              | `phi-scan fix` returns error with install hint          |

---

## `.phi-scanignore` Format Specification

The `.phi-scanignore` file uses **gitignore-style syntax** (not regex, not simple glob).
This makes it immediately familiar to every developer.

### Syntax Rules

1. **Lines starting with `#`** are comments
2. **Blank lines** are ignored
3. **Patterns match relative to the repository root**
4. **`/` at end** matches directories only: `node_modules/`
5. **`*`** matches anything except `/`: `*.pyc`
6. **`**`** matches any number of directories: `\*\*/test_data/`
7. **`!` prefix** negates a pattern (re-include): `!important_config.yml`
8. **Leading `/`** anchors to repo root: `/build/` matches only root-level build
9. **No leading `/`** matches at any depth: `__pycache__/` at depth 1 or depth 10

### Implementation

- Use Python `pathspec` library (gitignore-compatible pattern matching)
- Add `pathspec` to core dependencies
- Patterns evaluated at every directory level during `rglob` traversal
- Exclusion applied before file read (skip entire directory tree early)

### Default `.phi-scanignore`

```gitignore
# Dependencies
node_modules/
.venv/
venv/
__pycache__/
.tox/

# Build outputs
dist/
build/
*.egg-info/
target/

# IDE and editor
.idea/
.vscode/
*.swp
*.swo

# Version control
.git/

# PhiScan's own files
.phi-scanner/
*.db
*.sqlite3

# Common non-code directories
.terraform/
.serverless/
```

---

## `--diff` Mode Implementation Detail

The `--diff` flag scans only files changed relative to a git reference, making
CI scans fast by focusing on new/modified code.

### Supported Invocations

| Command                         | Behavior                                      |
| ------------------------------- | --------------------------------------------- |
| `phi-scan scan --diff HEAD~1`   | Files changed in last commit                  |
| `phi-scan scan --diff HEAD~3`   | Files changed in last 3 commits               |
| `phi-scan scan --diff main`     | Files changed between current branch and main |
| `phi-scan scan --diff abc123`   | Files changed since commit abc123             |
| `phi-scan scan --diff --staged` | Only staged files (pre-commit hook use case)  |

### Implementation (`phi_scan/diff.py`)

1. Run `git diff --name-only --diff-filter=ACMR <ref>` to get changed file list
2. Filter: Added (A), Copied (C), Modified (M), Renamed (R) — exclude Deleted (D)
3. For renamed files: use the new name (file exists at new path)
4. Resolve paths relative to git root (handle `phi-scan scan --diff` from subdirectory)
5. Apply `.phi-scanignore` to diff file list (same exclusion rules)
6. Pass filtered list to `execute_scan()` as scan targets

### Error Handling

- **Not a git repo:** `TraversalError("Not inside a git repository. --diff requires git.")`
- **Invalid ref:** `TraversalError("Invalid git reference: '{ref}'. Check that the commit or branch exists.")`
- **No changes:** Exit cleanly with message: "No files changed since {ref}"

---

## Data Migration Strategy

Both the audit database (`~/.phi-scanner/audit.db`) and cache database
(`~/.phi-scanner/cache.db`) will evolve across versions. Schema versioning
prevents silent data loss on upgrade.

### Schema Version Tracking

Each database has a `schema_meta` table:

```sql
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Initial entry:
INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1');
INSERT INTO schema_meta (key, value) VALUES ('created_at', '2026-03-16T00:00:00Z');
INSERT INTO schema_meta (key, value) VALUES ('last_migrated_at', '2026-03-16T00:00:00Z');
```

### Migration Flow (on startup)

1. Open database
2. Read `schema_version` from `schema_meta`
3. If version < current `SCHEMA_VERSION` constant → run sequential migrations
4. Each migration is a function: `migrate_v1_to_v2(connection)`, `migrate_v2_to_v3(connection)`
5. Migrations run in a transaction — rollback on failure
6. Update `schema_version` and `last_migrated_at` after success
7. If migration fails: raise `SchemaMigrationError` with instructions to back up and retry

### Rules

- Migrations are additive only (add columns, add tables) — never drop columns
- Audit DB: never DELETE or UPDATE existing rows (HIPAA immutability)
- Cache DB: safe to rebuild from scratch (it's just a cache)
- If cache DB migration fails: delete and recreate (no data loss)

---

## Files to Create (Phase 1)

```
phi_scan/
├── __init__.py         # package metadata (version 0.1.0)
├── py.typed            # PEP 561 type checking marker
├── constants.py        # all named constants, enums, remediation guidance
├── exceptions.py       # custom exception hierarchy
├── models.py           # ScanFinding, ScanResult, ScanConfig dataclasses
├── logging_config.py   # structured logging setup
├── config.py           # YAML config loading and validation
├── scanner.py          # recursive traversal, binary detection, placeholder detection
├── diff.py             # git diff file extraction for --diff mode
├── audit.py            # SQLite audit schema, insert, query, migration
├── output.py           # table, json, csv, sarif formatters + Rich UI
└── cli.py              # Typer app with all commands

tests/
├── conftest.py         # shared test fixtures
├── test_scanner.py     # traversal + binary detection tests
├── test_config.py      # config loading tests
├── test_cli.py         # CLI smoke tests
├── test_ignore.py      # ignore pattern tests
├── test_output.py      # output formatter tests
├── test_audit.py       # SQLite audit tests
├── test_diff.py        # git diff extraction tests
├── test_integration.py # end-to-end integration tests
└── test_logging.py     # structured logging tests

.github/
└── workflows/
    ├── ci.yml          # lint + typecheck + test on push/PR (3 platforms)
    └── release.yml     # build + publish to PyPI on version tag

Makefile                # task runner
.phi-scanner.yml        # default scanner configuration
.phi-scanignore         # default exclusion patterns
LICENSE                 # MIT license
CHANGELOG.md            # version history
SECURITY.md             # vulnerability reporting policy
```

## Files Added in Phase 2

```
phi_scan/
├── suppression.py      # inline phi-scan:ignore comment parser
├── cache.py            # content-hash scan cache for incremental scanning
├── help_text.py        # explain command content constants with Rich markup
├── fhir_recognizer.py  # FHIR R4 pattern detector
└── fixer.py            # auto-fix synthetic data replacement engine

tests/
├── test_suppression.py # inline suppression tests
└── test_cache.py       # scan cache tests
```

## Files to Modify (Phase 1)

- `pyproject.toml` — full rewrite: metadata, deps, optional deps, entry points, tool config
- `.gitignore` — add .env, \*.db, dist/, etc.
- `README.md` — project description, badges, quick start, usage

## Files to Delete (Phase 1)

- `main.py` — replaced by `phi_scan/cli.py` entry point

---

## Key Decisions

| Decision               | Choice                                            | Rationale                                                                |
| ---------------------- | ------------------------------------------------- | ------------------------------------------------------------------------ |
| Python version         | 3.12.3                                            | Stable, all deps have wheels, matches CI runners                         |
| Version strategy       | 0.x through dev, 1.0.0 at Phase 9 launch          | Avoids setting expectations; semver-compliant                            |
| File coverage          | All text files (binary detection, not allowlist)  | Scan every language/config/data file; skip only known binaries           |
| Binary detection       | Known-extension skip + null-byte heuristic        | Fast path for .png/.exe, fallback heuristic catches unknown binaries     |
| Detection in Phase 1   | No — deferred to Phase 2                          | Phase 1 is the CLI shell; detection plugs in later                       |
| Phase 1 deps           | No Presidio, spaCy, FHIR                          | Heavy deps not needed until Phase 2                                      |
| Optional deps          | `[nlp]`, `[fhir]`, `[reports]`, `[full]`, `[dev]` | Keeps base install ~15MB; CI runners can use regex-only                  |
| spaCy model            | Downloaded via `phi-scan setup`, not bundled      | 500MB model can't be a pip dependency; graceful degradation without it   |
| Ignore format          | gitignore-style via `pathspec` library            | Familiar to every developer; battle-tested pattern matching              |
| Report formats         | PDF, HTML, CSV, JSON, SARIF, table                | Enterprise needs printable PDF; dev teams need JSON/SARIF                |
| Report generation      | fpdf2 + jinja2 + matplotlib                       | Lightweight, no heavy deps; charts as PNG embedded in PDF/HTML           |
| Remediation guidance   | Per-finding + per-category playbook               | Actionable fixes, not just detection; compliance officers need specifics |
| Package name           | `phi_scan` (Python) / `phi-scan` (CLI/PyPI)       | Per CLAUDE.md                                                            |
| Audit DB path          | `~/.phi-scanner/audit.db`                         | Configurable via `.phi-scanner.yml`                                      |
| Schema migration       | Version-tracked, additive-only migrations         | Prevents silent data loss on upgrade; HIPAA audit immutability           |
| Logging                | Python `logging` + Rich console handler           | Structured, configurable, respects --quiet and NO_COLOR                  |
| Type checking          | mypy in CI + `py.typed` marker                    | Security tool needs type safety; PEP 561 for downstream users            |
| CI for PhiScan itself  | GitHub Actions: 3 platforms, lint+type+test       | Catches cross-platform issues; automates releases                        |
| Inline suppression     | `# phi-scan:ignore` comment syntax (Phase 2)      | Every mature scanner needs FP suppression; audit-traced                  |
| Scan caching           | Content-hash cache in SQLite (Phase 2)            | >10x speedup on re-scans; essential for CI performance                   |
| Auto-fix engine        | Synthetic data replacement via `faker`            | Killer feature — don't just find PHI, fix it automatically               |
| Baseline management    | `.phi-scanbaseline` YAML file                     | Critical for adopting in existing codebases without noise overload       |
| Pre-commit framework   | `.pre-commit-hooks.yaml`                          | De facto standard for git hooks; ecosystem compatibility                 |
| Multi-framework        | HIPAA + SOC 2 + HITRUST + NIST + GDPR             | Healthcare orgs need multi-framework evidence for auditors               |
| VS Code extension      | Separate TypeScript project in Phase 8            | Developers catch PHI in editor before commit; needs dedicated scope      |
| Plugin system          | Python entry points + BaseRecognizer              | Extensibility without forking; EHR-specific plugins by community         |
| Variable-name boosting | +0.15 confidence for PHI-suggestive var names     | `patient_ssn = "123"` is way more suspicious than `x = "123"`            |
| Cross-platform         | CI on ubuntu + macos + windows; pathlib only      | PyPI package must work everywhere; no WSL assumptions                    |

---

## What Makes PhiScan Different

This is not another secret scanner. Here's what no competitor offers:

| Differentiator                          | PhiScan | detect-secrets | git-secrets | Presidio | truffleHog |
| --------------------------------------- | ------- | -------------- | ----------- | -------- | ---------- |
| PHI-specific (not just secrets)         | ✅      | ❌             | ❌          | ✅       | ❌         |
| FHIR R4 schema awareness                | ✅      | ❌             | ❌          | ❌       | ❌         |
| 4-layer detection (regex+NLP+FHIR+AI)   | ✅      | ❌             | ❌          | Partial  | ❌         |
| Auto-fix with synthetic data            | ✅      | ❌             | ❌          | ❌       | ❌         |
| HIPAA 18-identifier coverage            | ✅      | ❌             | ❌          | Partial  | ❌         |
| Baseline management                     | ✅      | ✅             | ❌          | ❌       | ❌         |
| Inline suppression comments             | ✅      | ✅             | ❌          | ❌       | ❌         |
| Enterprise PDF/HTML reports             | ✅      | ❌             | ❌          | ❌       | ❌         |
| Multi-framework compliance              | ✅      | ❌             | ❌          | ❌       | ❌         |
| Local-only (no data leaves)             | ✅      | ✅             | ✅          | ✅       | ✅         |
| CI/CD pipeline blocking                 | ✅      | ✅             | ✅          | ❌       | ✅         |
| GitLab SAST + Code Quality native       | ✅      | ❌             | ❌          | ❌       | ❌         |
| Jenkins Warnings NG + Checks API        | ✅      | ❌             | ❌          | ❌       | ❌         |
| Azure DevOps PR threads + status policy | ✅      | ❌             | ❌          | ❌       | ❌         |
| CircleCI orb + Test Summary integration | ✅      | ❌             | ❌          | ❌       | ❌         |
| Bitbucket Code Insights (inline annot.) | ✅      | ❌             | ❌          | ❌       | ❌         |
| AWS Security Hub ASFF integration       | ✅      | ❌             | ❌          | ❌       | ❌         |
| 7 CI/CD platforms natively supported    | ✅      | ❌             | ❌          | ❌       | ❌         |
| Plugin/extension system                 | ✅      | ✅             | ❌          | ❌       | ❌         |
| VS Code extension                       | ✅      | ❌             | ❌          | ❌       | ❌         |
| Variable-name context boosting          | ✅      | ❌             | ❌          | ❌       | ❌         |
| Remediation playbook per finding        | ✅      | ❌             | ❌          | ❌       | ❌         |
| Lightweight install option (regex-only) | ✅      | ✅             | ✅          | ❌       | ✅         |
| Graceful degradation                    | ✅      | N/A            | N/A         | ❌       | N/A        |

**Core value proposition in one sentence:**

> PhiScan is the only tool that finds PHI in your code, tells you exactly which
> HIPAA rule it violates, shows you how to fix it, and can fix it for you — all
> without any data ever leaving your machine.

---

## Risk Register

Explicit risks, likelihood, impact, and mitigation strategies:

| #   | Risk                                                                        | Likelihood | Impact                            | Mitigation                                                                                                                                        |
| --- | --------------------------------------------------------------------------- | ---------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1  | spaCy model download fails in air-gapped / restricted environments          | Medium     | High — NLP layer unusable         | Graceful degradation to regex-only (Dependency Strategy); `phi-scan setup --offline <path>` for manual model install; Docker image bundles model  |
| R2  | Presidio false-positive rate too high for production use                    | Medium     | High — user trust eroded          | Variable-name context boosting (+0.15); confidence thresholds configurable; inline suppression system; baseline management for existing codebases |
| R3  | Docker image exceeds CI runner size limits (>2GB with spaCy model)          | Medium     | Medium — CI adoption blocked      | Multi-stage build; `phi-scan:slim` tag (regex-only, ~50MB); `phi-scan:full` tag (all layers, ~800MB); document image sizes per tag                |
| R4  | HIPAA audit log requirements conflict with user privacy expectations        | Low        | High — legal exposure             | Audit logs store SHA-256 hashes only, never raw PHI; encryption at rest; 6-year retention per 45 CFR §164.530(j); clear `docs/security.md`        |
| R5  | New Python version breaks spaCy/Presidio compatibility                      | Medium     | Medium — blocked upgrades         | Pin dependency versions in `uv.lock`; CI matrix tests Python 3.11 + 3.12 + 3.13; monitor upstream release notes                                   |
| R6  | Competitor ships PHI scanning before PhiScan 1.0                            | Low        | Medium — reduced adoption         | PhiScan's 4-layer detection + FHIR awareness + 7 CI/CD platforms is a defensible moat; ship Phase 3 (PyPI) early for market presence              |
| R7  | Claude API rate limits or pricing changes break AI layer                    | Low        | Low — AI layer is optional        | AI layer (Phase 7) is entirely optional; scanner works at full capability without it; no runtime dependency on any external API                   |
| R8  | Community plugin introduces security vulnerability                          | Medium     | High — supply chain risk          | Plugin sandboxing review in Phase 8B; plugins run in same process but can't access network; signed plugin registry (Phase 9)                      |
| R9  | SARIF/Code Quality schema changes break CI integrations                     | Low        | Medium — broken annotations       | Pin schema versions; schema validation in CI tests (6D.8, 6D.9); monitor GitLab/GitHub schema changelogs                                          |
| R10 | Enterprise customers require SOC 2 Type II certification for PhiScan itself | Medium     | Medium — enterprise sales blocked | Phase 9 security hardening addresses controls; compliance documentation in 9D.1; on-premise deployment option avoids SaaS audit scope             |

---

## Success Metrics & Adoption Targets

Measurable targets to track whether PhiScan achieves its adoption goals:

### Phase 3 (First PyPI Publish) — Month 2

| Metric                                     | Target                 | How to Measure                 |
| ------------------------------------------ | ---------------------- | ------------------------------ |
| PyPI downloads (first 30 days)             | 500+                   | PyPI Stats API / pypistats.org |
| GitHub stars                               | 50+                    | GitHub repo                    |
| Successful `pipx install phi-scan` reports | Zero open install bugs | GitHub Issues                  |
| README quick-start works first try         | >90% success           | User feedback / issue tracker  |

### Phase 6 (CI/CD Complete) — Month 3.5

| Metric                         | Target                               | How to Measure                                      |
| ------------------------------ | ------------------------------------ | --------------------------------------------------- |
| PyPI downloads (cumulative)    | 5,000+                               | pypistats.org                                       |
| GitHub stars                   | 300+                                 | GitHub repo                                         |
| CI/CD template adoption        | Templates used in 50+ external repos | GitHub code search for `phi-scan` in workflow files |
| Docker Hub pulls               | 1,000+                               | Docker Hub stats                                    |
| Community bug reports resolved | <48hr median response time           | GitHub Issues                                       |
| CI platforms verified working  | All 7 platforms                      | Integration test matrix                             |

### Phase 9 (v1.0 Launch) — Month 5.5

| Metric                           | Target              | How to Measure                                                  |
| -------------------------------- | ------------------- | --------------------------------------------------------------- |
| PyPI downloads (cumulative)      | 25,000+             | pypistats.org                                                   |
| GitHub stars                     | 1,000+              | GitHub repo                                                     |
| Enterprise pilot customers       | 3–5 healthcare orgs | Direct outreach / inbound                                       |
| Community plugins published      | 5+                  | Plugin registry / PyPI search                                   |
| VS Code extension installs       | 500+                | VS Code Marketplace                                             |
| Conference talks / blog mentions | 3+                  | Google Alerts / social                                          |
| Monthly active CI pipelines      | 200+                | Opt-in anonymous telemetry (privacy-first, disabled by default) |
| Contributor count                | 15+                 | GitHub contributors                                             |

### 12-Month Post-Launch Targets

| Metric                           | Target                               | How to Measure   |
| -------------------------------- | ------------------------------------ | ---------------- |
| PyPI downloads (cumulative)      | 100,000+                             | pypistats.org    |
| GitHub stars                     | 5,000+                               | GitHub repo      |
| Enterprise paying customers      | 15–25                                | Billing system   |
| Annual recurring revenue         | $50K–$150K                           | Stripe / billing |
| Healthcare org adoption          | Used by 10+ hospitals/health systems | Customer list    |
| HIPAA compliance audits assisted | 50+                                  | Customer surveys |

---

## Gap Resolution Tracker

All 35 gaps identified across reviews have been addressed:

| #   | Gap                                           | Resolution                                                                                                                                                                                                 |
| --- | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | No LICENSE file                               | Added to Phase 1A.1                                                                                                                                                                                        |
| 2   | Version mismatch (1.0.0)                      | New versioning strategy: 0.x until Phase 9 launch                                                                                                                                                          |
| 3   | spaCy model distribution                      | Dependency Strategy section + `phi-scan setup` + graceful degrade                                                                                                                                          |
| 4   | No CI/CD for PhiScan itself                   | Phase 1H: ci.yml (3-platform) + release.yml (auto-publish)                                                                                                                                                 |
| 5   | No cross-platform testing                     | Phase 1G + CI matrix (ubuntu, macos, windows)                                                                                                                                                              |
| 6   | No logging framework                          | Phase 1B.5: logging_config.py + --log-level + --log-file                                                                                                                                                   |
| 7   | Dependency weight                             | Dependency Strategy: optional groups, ~15MB base install                                                                                                                                                   |
| 8   | No --diff implementation detail               | diff.py (1B.8) + dedicated spec section + test_diff.py                                                                                                                                                     |
| 9   | Missing ignore format spec                    | `.phi-scanignore` Format Specification section (gitignore-style)                                                                                                                                           |
| 10  | No integration tests                          | Phase 1F.9: test_integration.py (scan→output→audit→report)                                                                                                                                                 |
| 11  | No data migration strategy                    | Data Migration Strategy section + schema_meta table + migrator                                                                                                                                             |
| 12  | Missing SECURITY.md                           | Added to Phase 1A.3                                                                                                                                                                                        |
| 13  | Phase 1 overloaded                            | Suppression, cache, explain deferred to Phase 2A; 3→4 week est                                                                                                                                             |
| 14  | Phase 3 overloaded                            | Split: Phase 3 (output+publish) + Phase 4 (enterprise+docs)                                                                                                                                                |
| 15  | VS Code extension premature                   | Moved from Phase 5 to Phase 8C (separate project scope)                                                                                                                                                    |
| 16  | No build include config                       | Phase 3D.2: pyproject.toml build includes for non-Python files                                                                                                                                             |
| 17  | No py.typed marker                            | Phase 1A.10: py.typed file + pyproject.toml package-data                                                                                                                                                   |
| 18  | No type checker                               | mypy added to dev deps (1A.6), make typecheck target (1E.2)                                                                                                                                                |
| 19  | No CHANGELOG.md                               | Added to Phase 1A.2                                                                                                                                                                                        |
| 20  | No GitHub Releases / automation               | Phase 1H.2: release.yml with auto-publish on tag                                                                                                                                                           |
| 21  | Watch mode hollow in Phase 1                  | 1B.11: watch shows file-count + degradation message until Phase 2                                                                                                                                          |
| 22  | No risk register                              | Risk Register section added — 10 risks with likelihood, impact, mitigation                                                                                                                                 |
| 23  | No success metrics                            | Success Metrics section added — targets for Phase 3, 6, 9, and 12-month post-launch                                                                                                                        |
| 24  | Phase 3/4 testing thin                        | 3F (9 test items) and 4D (8 test items) testing sub-sections added                                                                                                                                         |
| 25  | No contributor/community plan                 | Phase 9E added — issue templates, PR template, Discussions, CODE_OF_CONDUCT, plugin guide, good-first-issue program                                                                                        |
| 26  | Community infra duplicated (8G/9E)            | Deduplicated: core community files (COC, issue templates, PR template, Discussions) moved to Phase 3E for early adoption; Phase 8G refocused on growth content; Phase 9E covers extended community program |
| 27  | Community infra too late for adoption targets | Core community files ship in Phase 3E (month 2) alongside first PyPI publish, not Phase 8/9                                                                                                                |
| 28  | Dependency diagram wrong                      | Fixed: Phase 7 branches from Phase 6 only (not Phase 2); Phase 8 depends on Phase 6                                                                                                                        |
| 29  | `--output junit` undefined                    | Added to Phase 3A.9 and OutputFormat enum — JUnit XML for universal CI test reporting                                                                                                                      |
| 30  | `--output codequality/gitlab-sast` undefined  | Added to Phase 3A.10 and 3A.11 with schema references                                                                                                                                                      |
| 31  | `pathspec` missing from core deps             | Added to Phase 1A.5 core dependency list                                                                                                                                                                   |
| 32  | CI/CD templates paywalled (adoption killer)   | Pricing principle added: CI/CD templates always free; Pro upsells on reporting, AI, team features                                                                                                          |
| 33  | No `action.yml` for GitHub Marketplace        | Phase 8F.1 now creates composite `action.yml` with `uses: phi-scan/phi-scan-action@v1`                                                                                                                     |
| 34  | No `phi-scan init` one-step wizard            | Added `init` command to 1B.11 — creates config, ignore, hook, downloads model in one guided flow                                                                                                           |
| 35  | No CLI startup time target                    | Performance target added: < 500ms for non-scan commands; lazy imports required                                                                                                                             |
