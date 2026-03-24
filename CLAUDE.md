# CLAUDE.md — PhiScan

PHI/PII Scanner for CI/CD pipelines. HIPAA & FHIR compliant. Local execution only.
Project version: 0.1.0 (dev) | 1.0.0 reserved for public launch | Created: March 2026

---

## Project Overview

PhiScan is a terminal CLI tool that scans source code for Protected Health Information (PHI)
and Personally Identifiable Information (PII). It integrates into CI/CD pipelines to block
pull requests containing PHI before they are merged.

**Core Design Principle — Non-Negotiable:**
All scanning executes locally within the pipeline runner. No PHI or PII is ever transmitted
to an external API or third-party service. This constraint applies to every feature, every
layer, and every integration. If a feature would require sending raw PHI externally, it must
not be built.

---

## Project Identity

| Property       | Value                        |
| -------------- | ---------------------------- |
| Project name   | PhiScan                      |
| Folder         | phi-scan                     |
| Python package | phi_scan                     |
| CLI command    | phi-scan                     |
| PyPI package   | phi-scan                     |
| Version        | 0.1.0 (0.x through dev)      |
| Language       | Python 3.12.3 (WSL)          |
| Package mgr    | uv (replaces pip everywhere) |

---

## Build Order — Follow This Strictly

```
Phase 1: Terminal CLI App                    (Weeks 1–4)   ← START HERE
Phase 2: Detection Engine                    (Weeks 5–7)
Phase 3: CLI Polish, Output Formats & PyPI   (Weeks 8–9)
Phase 4: Enterprise Reports & Compliance     (Weeks 10–11)
Phase 5: Notifications & Audit Hardening     (Week 12)
Phase 6: CI/CD Integration & Docker          (Weeks 13–14)
Phase 7: AI Enhancement (optional)           (Weeks 15–16)
Phase 8: Pro Tier, Monetization & VS Code    (Weeks 17–20)
Phase 9: Hardening, Enterprise & Launch      (Weeks 21–23)
```

Every phase depends on the previous one being complete. Phase 7 (AI) is optional
and can be skipped — Phase 8 depends on Phase 6, not Phase 7. Phase 9 depends
on Phase 8. Version 1.0.0 is reserved for Phase 9 public launch.

Do not start Phase 2 until Phase 1 is complete and installable via `pipx install .`.

---

## Project Structure

```
phi-scan/
├── phi_scan/               # source package
│   ├── __init__.py         # __version__ = "0.1.0", __app_name__ = "phi-scan"
│   ├── py.typed            # PEP 561 type checking marker
│   ├── constants.py        # all named constants, enums, remediation guidance
│   ├── exceptions.py       # PhiScanError, ConfigurationError, TraversalError, etc.
│   ├── models.py           # ScanFinding, ScanResult, ScanConfig dataclasses
│   ├── logging_config.py   # structured logging setup (--log-level, --log-file)
│   ├── config.py           # YAML config loading and validation
│   ├── scanner.py          # recursive traversal + detection engine
│   ├── diff.py             # git diff file extraction for --diff mode
│   ├── output.py           # table, json, csv, sarif formatters + Rich UI
│   ├── audit.py            # SQLite audit logging (HIPAA-compliant immutable)
│   ├── cli.py              # Typer CLI entry point
│   ├── suppression.py      # inline phi-scan:ignore comment parser (Phase 2)
│   ├── cache.py            # content-hash scan cache (Phase 2)
│   ├── help_text.py        # explain command content constants (Phase 2)
│   ├── fhir_recognizer.py  # custom FHIR R4 patterns (Phase 2)
│   ├── fixer.py            # auto-fix synthetic data replacement (Phase 2)
│   ├── baseline.py         # baseline snapshot management (Phase 3)
│   ├── notifier.py         # email + webhook notifications (Phase 5)
│   ├── compliance.py       # multi-framework compliance mapping (Phase 4)
│   ├── report.py           # PDF/HTML enterprise reports (Phase 4)
│   └── plugin_api.py       # plugin system base classes (Phase 8)
├── tests/                  # pytest test suite
├── docs/                   # documentation suite (Phase 3+)
├── docker/                 # Dockerfile + compose (Phase 6)
├── .github/workflows/      # CI/CD workflows
├── pyproject.toml          # uv manages this
├── uv.lock                 # lockfile — commit this
├── Makefile                # task runner
├── .phi-scanner.yml        # scanner configuration
├── .phi-scanignore         # exclusion patterns (gitignore-style via pathspec)
├── .env                    # API keys — gitignored
├── LICENSE                 # MIT license
├── CHANGELOG.md            # version history
├── SECURITY.md             # vulnerability reporting policy
├── CODE_OF_CONDUCT.md      # Contributor Covenant v2.1 (Phase 3)
├── CONTRIBUTING.md         # contributor guide (Phase 4)
└── .pre-commit-hooks.yaml  # pre-commit framework integration (Phase 3)
```

---

## Technology Stack

### Core Dependencies (Phase 1 — ~15MB base install)

| Component       | Technology          | Version            |
| --------------- | ------------------- | ------------------ |
| Language        | Python              | 3.12.3 (WSL)       |
| Package manager | uv                  | 0.10.9             |
| CLI             | Typer[all]          | 0.24.1 (installed) |
| Terminal UI     | Rich                | 13.7.1 (installed) |
| Config          | PyYAML              | 6.x                |
| Env variables   | python-dotenv       | 1.2.2 (installed)  |
| Ignore patterns | pathspec            | latest             |
| ASCII banner    | pyfiglet            | latest             |
| File watching   | watchdog            | latest             |
| HTTP client     | httpx               | latest             |
| Audit database  | SQLite3             | 3.45.1 (installed) |
| Linting         | Ruff                | 0.15.6 (installed) |
| Type checking   | mypy                | latest (dev dep)   |
| Testing         | pytest + pytest-cov | latest (dev dep)   |
| Task runner     | Make                | 4.3 (installed)    |

### Optional Dependencies (install via extras)

| Group   | Command                         | Size   | Adds                                     |
| ------- | ------------------------------- | ------ | ---------------------------------------- |
| NLP     | `pip install phi-scan[nlp]`     | ~550MB | Presidio 2.x, spaCy 3.7+, en_core_web_lg |
| FHIR    | `pip install phi-scan[fhir]`    | ~20MB  | fhir.resources 7.x                       |
| Reports | `pip install phi-scan[reports]` | ~80MB  | fpdf2, jinja2, matplotlib                |
| Full    | `pip install phi-scan[full]`    | ~650MB | All of the above                         |
| Dev     | `pip install phi-scan[dev]`     | +50MB  | pytest, ruff, mypy, faker                |

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

### Other Tools

| Component      | Technology             | Version            |
| -------------- | ---------------------- | ------------------ |
| Container      | Docker + Alpine        | 29.3.0 (installed) |
| Notifications  | SMTP / httpx webhooks  | installed          |
| Synthetic data | faker                  | latest (dev dep)   |
| PDF reports    | fpdf2                  | 2.7+ (reports dep) |
| HTML reports   | jinja2                 | 3.1+ (reports dep) |
| Charts         | matplotlib             | 3.8+ (reports dep) |
| Optional AI    | Anthropic SDK + Claude | 0.84.0 (verified)  |

---

## CLI Commands

| Command         | Usage                           | Description                                                                 |
| --------------- | ------------------------------- | --------------------------------------------------------------------------- |
| scan            | phi-scan scan ./myapp           | Scan a directory or file for PHI/PII                                        |
| scan --diff     | phi-scan scan --diff HEAD~1     | Scan only files changed in last commit                                      |
| scan --file     | phi-scan scan --file handler.py | Scan a single file with detailed output                                     |
| scan --output   | phi-scan scan . --output json   | Output: table, json, sarif, csv, pdf, html, junit, codequality, gitlab-sast |
| scan --baseline | phi-scan scan --baseline        | Only report NEW findings not in baseline                                    |
| watch           | phi-scan watch ./src            | Live file watcher — re-scans on changes                                     |
| report          | phi-scan report                 | Display last scan results from SQLite                                       |
| history         | phi-scan history --last 30d     | Query audit log                                                             |
| init            | phi-scan init                   | Guided first-run wizard: config, ignore, hook, model download               |
| setup           | phi-scan setup                  | Download spaCy model and verify dependencies                                |
| fix             | phi-scan fix --dry-run ./myapp  | Auto-replace PHI with synthetic data (--dry-run, --apply, --patch)          |
| explain         | phi-scan explain hipaa          | Explain topics: confidence, severity, hipaa, detection, config, etc.        |
| baseline        | phi-scan baseline create        | Manage baseline: create, show, clear, update, diff                          |
| install-hook    | phi-scan install-hook           | Install as git pre-commit hook                                              |
| uninstall-hook  | phi-scan uninstall-hook         | Remove git pre-commit hook                                                  |
| config init     | phi-scan config init            | Interactive setup — generates .phi-scanner.yml only                         |
| dashboard       | phi-scan dashboard              | Rich Live real-time scan dashboard                                          |
| plugins list    | phi-scan plugins list           | Show all installed plugins with version and entity types                    |

---

## Detection Architecture (4 Layers)

| Layer   | Approach                              | Strength                                                      |
| ------- | ------------------------------------- | ------------------------------------------------------------- |
| Layer 1 | Regex / Pattern Matching              | Fast, zero false-negatives on structured PHI                  |
| Layer 2 | NLP Named Entity Recognition          | Context-aware, catches names/locations in code                |
| Layer 3 | Structured Healthcare Formats         | FHIR R4 field names + HL7 v2 segment scanning (PID, NK1, IN1) |
| Layer 4 | AI Augmentation (optional)            | Reduces false positives via confidence scoring                |

---

## File Traversal — Required Pattern

The scanner must reach every file at every depth level of any repository. Repos can have
unlimited nesting — subdirectories, sub-subdirectories, and files at every layer must all
be scanned without exception.

**Required traversal approach:**

- Always use `pathlib.rglob("*")` for directory scanning — never `os.listdir()`, never
  shallow reads, never hardcoded depth limits
- Every file matched by the configured `scan_extensions` list must be scanned regardless
  of how deeply nested it is
- `.phi-scanignore` exclusion rules must be evaluated at every directory level — a rule
  like `node_modules/` must exclude that folder whether it appears at depth 1 or depth 10
- Symlinks must not be followed — skip and log them to avoid infinite loop risk
- A `PermissionError` on any single file or folder must be caught, logged as a warning,
  and skipped — it must never abort the entire scan
- The Rich progress bar must update file-by-file as traversal proceeds so the user can
  see scan activity at all times

**What NOT to generate for traversal:**

- Do not use `os.listdir()` — it is shallow by default
- Do not hardcode a maximum directory depth
- Do not allow a single unreadable file to raise an unhandled exception
- Do not follow symlinks

---

## HIPAA 18 PHI Identifiers — All Must Be Covered

Names, Geographic data, Dates (except year), Phone numbers, Fax numbers, Email addresses,
SSN, MRN, Health plan numbers, Account numbers, Cert/License numbers, Vehicle identifiers,
Device identifiers, URLs, IP addresses, Biometric identifiers, Full-face photos, Unique IDs.

**Additional identifiers beyond the 18 Safe Harbor categories (also required):**

- MBI (Medicare Beneficiary Identifier) — post-2019 Medicare ID; 11-char alphanumeric
- HICN (legacy Medicare Health Insurance Claim Number) — SSN-based; lower confidence
- DEA number — 2-letter prefix + 7 digits with checksum validation
- Age >90 — HIPAA §164.514(b)(2)(i) requires ages over 90 to be generalized; flag explicitly
- ZIP codes — 5-digit and ZIP+4 always flagged; 3-digit prefix only in patient-geographic context
- Genetic identifiers — rs-IDs (dbSNP), VCF-format data, gene panel names (GINA + GDPR Art. 9)
- SUD-related field names — 42 CFR Part 2 scope (stricter than HIPAA)
- Quasi-identifier combinations — ZIP + DOB + sex together → HIGH risk regardless of individual scores

**SSN reserved ranges — do NOT flag (reduces false positives on version numbers):**
`000-XX-XXXX`, `XXX-00-XXXX`, `XXX-XX-0000`, `666-XX-XXXX`, `900-XX-XXXX` through `999-XX-XXXX`

**NPI distinction:**
- Type 1 (individual provider) — PHI in patient context; flag
- Type 2 (organization) — public identifier; do not flag

**Known detection gaps (document, do not silently skip):**
PDF, DICOM, DOCX/XLSX files are skipped as binary. Document this in `docs/known-limitations.md`.
The scanner implements HIPAA Safe Harbor only — Expert Determination requires a qualified
statistician and cannot be satisfied by the tool alone.

---

## AI Integration Rules

If Claude API integration is enabled (Phase 7, optional):

- **Never send raw PHI values to any external API**
- Send only code structure with values already redacted: `patient_name = [REDACTED]`
- Use `claude-sonnet-4-6` model
- Only call Claude for medium-confidence findings (confidence < 0.8 threshold)
- High-confidence and regex matches bypass Claude entirely
- PHI values are replaced with `[REDACTED]` before any API call
- Config: `ai.enable_claude_review: false` by default in `.phi-scanner.yml`
- Claude failures gracefully fall back to local-only scoring — never crash

---

## Makefile Targets

```
make install      # uv sync + spaCy model download
make lint         # ruff check . --fix && ruff format .
make typecheck    # mypy phi_scan/ — zero errors required
make test         # uv run pytest tests/ -v --cov=phi_scan
make scan         # uv run phi-scan scan --diff HEAD~1
make help         # list all available targets
```

---

## Code Standards

### Naming

- Variables and functions: `snake_case`
- Classes: `PascalCase` — nouns representing a real-world concept
- Constants: `UPPER_SNAKE_CASE`
- Booleans must start with `is_`, `has_`, `can_`, `should_`, or `was_`
- Function names must be verb-noun pairs: `calculate_tax_total`, not `process`
- Two approved patterns for functions whose body is a guard-clause raise:
  1. **`reject_<what_is_rejected>`** — used for domain invariant checkers where the
     noun names the invalid thing: `reject_negative_files_scanned`,
     `reject_clean_result_with_findings`, `reject_clean_flag_with_non_clean_risk_level`.
     Verb = reject (throw an error for), noun = the bad value or bad state.
  2. **`validate_<field_name>`** — used for single-field guards called from
     `__setattr__` or `__post_init__`: `validate_confidence_threshold`,
     `validate_max_file_size_mb`. Verb = validate, noun = the field name.
  Do **not** use `check_`, `assert_`, `raise_on_`, or plain `validate` (without a
  noun suffix) for these patterns — all were tried and rejected in earlier review
  cycles. The two patterns above are the only approved forms.
  **One guard clause = one function.** When two guard clauses together enforce a
  biconditional invariant (e.g. `is_clean=True → RiskLevel.CLEAN` and
  `is_clean=False → not RiskLevel.CLEAN`), each direction is a distinct bad state
  and gets its own `reject_<noun>` function. Do **not** merge them into a single
  function — merging creates a function body with two raises, two distinct
  conditions, and a name that cannot describe one bad state without "and".
- No abbreviations — write the full word. No: `usr`, `cfg`, `tmp`, `val`, `res`, `d`, `ts`
- Avoid class names ending in: `Manager`, `Handler`, `Processor`, `Helper`, `Util`
- The bigger the scope, the longer the name

### No Magic Values

- Zero numeric or string literals in logic code
- All literals go in named constants at module level or in a `constants.py` file
- Enums for any finite set of string values (status, role, event type)
- This rule applies to test code as well as production code

### Functions

- Maximum 30 lines per function
- Maximum 3 arguments — use a `@dataclass` for 4 or more
- Single responsibility: describe in one sentence with no "and"
- No side effects in functions named `get_*`, `is_*`, `has_*`, `calculate_*`
- Every line inside a function operates at one level of abstraction
- If a block needs a comment to explain what it does, extract it to its own function
- Guard clauses over nested conditionals — return early, keep the happy path flat

### Comments

- Comment the WHY, never the WHAT
- No commented-out code — use git
- Legal and compliance reasoning must be documented in comments
- All public functions require a docstring: `Args`, `Returns`, `Raises`
- TODO/FIXME comments must include an issue number and owner

### Error Handling

- Never catch bare `Exception` without re-raising
- Custom exceptions for domain errors: `PhiDetectionError`, not `RuntimeError`
- Error messages must include the bad value and what was expected
- Never silence errors with `pass` or empty `except` blocks

### Consistent Structure — Module Layout (top to bottom)

1. Module docstring
2. Standard library imports
3. Third-party library imports
4. Internal project imports
5. Constants and config
6. Exceptions
7. Data classes / models
8. Helper / utility functions (private)
9. Core public functions / classes
10. Entry point (`if __name__ == "__main__":`)

### Testing

- Test names describe the scenario and expected outcome:
  `test_scan_file_raises_phi_detection_error_when_ssn_found`
- AAA structure: Arrange, Act, Assert — with blank lines between each section
- Each test verifies exactly one behaviour
- No magic values in tests — use named constants or derive from constants
- Extract complex setup to fixtures — keep the test body clean

---

## Banned Patterns

- Magic numbers or strings in logic code
- Functions named: `handle`, `process`, `do`, `run`, `manage`, `data`, `info`
- Nested conditionals deeper than 2 levels — use guard clauses instead
- Mutable default arguments: `def f(items=[])` is always wrong
- Bare `except:` clauses
- Commented-out code anywhere in the codebase
- Double negatives in boolean expressions
- Vague variable names: `data`, `info`, `result`, `temp`, `value`, `obj`, `item`, `thing`
- Classes ending in: `Manager`, `Handler`, `Processor`, `Helper`, `Util`
- `os.listdir()` or any shallow directory read for scanner traversal
- Hardcoded directory depth limits
- Following symlinks during traversal

---

## What NOT to Generate

- Do not use magic numbers — every numeric literal must have a named constant
- Do not name variables: `data`, `info`, `result`, `temp`, `value`, `obj`, `item`, `thing`
- Do not create classes ending in: `Manager`, `Handler`, `Processor`, `Helper`, `Util`
- Do not write functions longer than 30 lines
- Do not use "and" in a function name — split into two functions
- Do not add error handling for scenarios that cannot happen in this context
- Do not add parameters for hypothetical future requirements
- Do not refactor code that was not requested
- Do not add docstrings or comments to code that was not modified
- Do not add features beyond what was explicitly requested
- Do not abstract prematurely — apply the Rule of Three first
- Do not send PHI values to any external API, ever
- Do not use `os.listdir()` or shallow reads for file traversal
- Do not hardcode a maximum directory traversal depth

---

## Security Constraints

| Risk                     | Mitigation                                                       |
| ------------------------ | ---------------------------------------------------------------- |
| PHI in scanner output    | Audit logs store SHA-256 hash of detected value, never raw value |
| Claude API receiving PHI | Redact all values before any API call; disable if unsure         |
| Log exposure             | Encrypt audit logs at rest; restrict access to SecOps only       |
| Supply chain attack      | Pin all dependency versions; sign Docker image                   |
| Scanner bypassed         | Require as required status check; protect branch rules           |
| Community plugin risk    | Plugin sandboxing review; signed plugin registry (Phase 9)       |
| Schema changes break CI  | Pin schema versions; schema validation in CI tests               |

HIPAA requires audit logs to be retained for a minimum of 6 years (45 CFR §164.530(j)).
Audit log entries must be immutable — never DELETE or UPDATE rows. Corrections are new
INSERT rows with a reference to the original entry.

---

## CI/CD Platform Support — 7 First-Class Platforms

PhiScan integrates natively with all major CI/CD platforms. CI/CD templates and
core scanning are always free — never paywalled.

| Platform            | PR/MR Comments | Inline Annotations    | Native Format              |
| ------------------- | -------------- | --------------------- | -------------------------- |
| GitHub Actions      | gh CLI         | SARIF upload          | SARIF                      |
| GitLab CI           | GitLab API     | Code Quality + SAST   | codequality, gitlab-sast   |
| Jenkins             | Checks API     | Warnings NG (SARIF)   | SARIF                      |
| Azure DevOps        | REST API       | SARIF artifacts       | SARIF                      |
| CircleCI            | GitHub/BB API  | JUnit Test Summary    | JUnit XML                  |
| Bitbucket Pipelines | Bitbucket API  | Code Insights         | SARIF                      |
| AWS CodeBuild       | GitHub/BB API  | Report Groups (SARIF) | SARIF, ASFF (Security Hub) |

Auto-detection: PhiScan checks env vars (`GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`,
`SYSTEM_TEAMFOUNDATIONCOLLECTIONURI`, `CIRCLECI`, `BITBUCKET_BUILD_NUMBER`,
`CODEBUILD_BUILD_ID`) to select the correct integration automatically.

---

## Inline Suppression System

Developers can suppress findings using inline comments (Phase 2):

- `# phi-scan:ignore` — suppress all findings on that line
- `# phi-scan:ignore[SSN,MRN]` — suppress only specific entity types
- `# phi-scan:ignore-next-line` — suppress all findings on the following line
- `# phi-scan:ignore-file` — suppress all findings in entire file (must appear in first 5 lines)
- Language-aware comment prefixes: `#`, `//`, `/* */`, `--`, `<!-- -->`, `%`, `;`
- Suppressed findings still logged to audit (with `suppressed=True` flag) for compliance

---

## Baseline Management

Baseline lets teams adopt PhiScan incrementally in existing codebases (Phase 3):

- `phi-scan baseline create` — snapshot current findings as accepted baseline
- `phi-scan scan --baseline` — only report NEW findings not in baseline
- Baseline file: `.phi-scanbaseline` (committed to repo, YAML format)
- Baselined findings shown as dimmed/grey in output (not hidden entirely)
- Exit code based only on new findings
- Baseline entries auto-expire after configurable `baseline_max_age_days` (default: 90)

---

## Auto-Fix Engine

Don't just find PHI — replace it with synthetic data automatically (Phase 2):

- `phi-scan fix --dry-run <path>` — show unified diff preview
- `phi-scan fix --apply <path>` — apply replacements in-place after confirmation
- `phi-scan fix --patch <path>` — write `.patch` file for `git apply`
- Deterministic: same PHI value always maps to same synthetic value within a scan
- Synthetic generators per HIPAA category (faker-based, seeded by original hash)

---

## Plugin / Extension System

Extensibility via Python entry points (Phase 8):

- `BaseRecognizer` abstract class — the interface all plugins implement
- Plugins register via `[project.entry-points."phi_scan.plugins"]` in their `pyproject.toml`
- `phi-scan plugins list` — show all installed plugins
- Example plugins: `phi-scan-epic` (Epic EHR), `phi-scan-cerner`, `phi-scan-hl7`

---

## Git Branching Strategy

**One long-lived branch: `main`.**

`main` is always releasable. No one pushes directly to `main`. Every change arrives via a
short-lived branch and a PR. Short-lived branches are deleted immediately after merge.

### Branch Types

| Type      | When to use                                              | Branches from |
| --------- | -------------------------------------------------------- | ------------- |
| `task/`   | Planned work from PLAN.md — the normal case              | `main`        |
| `hotfix/` | Urgent fix that cannot wait for the next planned task    | `main`        |
| `chore/`  | Maintenance with no PLAN.md task (dep bumps, docs, CI)   | `main`        |

### Branch Naming

```
task/<phase><section>-<task-number>-<short-description>
hotfix/<short-description>
chore/<short-description>
```

Examples:
- `task/1A-1-license-file`
- `task/1B-7-scanner-traversal`
- `hotfix/fix-ssn-regex-false-positive`
- `chore/bump-ruff-to-0-16`

### Branch Rules

- Always branch from `main` — never branch off another feature branch
- Never push directly to `main` — branch protection enforces this
- Keep branches short-lived — open the PR the same day you create the branch
- If `main` moves ahead while you are working, rebase: `git rebase main`
- Delete the branch immediately after the PR is merged

---

## Development Workflow — Non-Negotiable

Every single task in the build plan follows this exact workflow before the next task begins.
No exceptions. No skipping. No direct commits to main.

### PR-Per-Task Rule

**One task = one branch = one PR = one merge.**

Before moving to the next task:
1. Create a feature branch: `git checkout -b task/1A-1-license-file`
2. Complete the task
3. Run `make lint` → zero errors
4. Run `make typecheck` → zero mypy errors
5. Run `make test` → all tests pass
6. Push branch and open a PR on GitHub
7. GitHub Actions CI must pass (lint + typecheck + tests)
8. Claude automated code review must complete
9. Merge PR to `main`
10. Only then move to the next task

### PR Requirements

- PR title: `[Phase 1A.1] Create LICENSE file`
- PR body: reference the task number from PLAN.md, describe what was done, list any deviations
- PR must pass all CI checks before merge — no exceptions
- PR must receive Claude automated review before merge
- Squash merge preferred to keep `main` history clean

### Commit Message Rules

- Write a clear, concise commit message describing what changed and why
- No `Co-Authored-By:` tags — ever. The repository must remain clean of AI attribution metadata
- No `Co-Authored-By: Claude` or any Anthropic attribution in any commit or PR

### What CI Checks on Every PR

1. `ruff check .` — zero lint errors
2. `ruff format --check .` — zero formatting violations
3. `mypy phi_scan/` — zero type errors
4. `pytest tests/ -v --cov=phi_scan` — all tests pass
5. Matrix: Python 3.12 on ubuntu-latest, macos-latest, windows-latest

### Claude Automated Code Review

A GitHub Actions workflow calls the Anthropic API on every PR open/update.
Claude reviews the diff against the code standards in this file and posts a review comment.
The review is advisory — it does not block merge — but must be read and addressed.

---

## Development Environment

This project is developed entirely inside WSL (Windows Subsystem for Linux).

- All commands run in WSL terminal, never Windows CMD or PowerShell
- Use `uv` for all package management — never use `pip` directly
- Run tests with: `uv run pytest tests/ -v --cov=phi_scan`
- Lint before every commit: `uv run ruff check . --fix && uv run ruff format .`
- Python version: 3.12.3
