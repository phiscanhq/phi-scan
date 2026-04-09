# Contributing to PhiScan

Thank you for contributing to PhiScan. This document covers the development
setup, code standards, testing requirements, and pull request process.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Security and PHI Hygiene](#security-and-phi-hygiene)
- [Reporting Issues](#reporting-issues)

---

## Development Setup

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Clone and Install

```bash
git clone https://github.com/joeyessak/phi-scan.git
cd phi-scan
uv sync --extra nlp --extra hl7      # install with optional layers
phi-scan setup                        # download spaCy model
```

### Verify Setup

```bash
make test       # run test suite
make lint       # ruff check + ruff format --check
make typecheck  # mypy
make scan       # scan phi_scan/ itself
```

All four must pass before opening a PR.

### Available Make Targets

```
make install    Install in editable mode
make lint       ruff check + ruff format --check
make typecheck  mypy phi_scan/
make test       pytest with coverage
make scan       phi-scan scan phi_scan/
make help       Show all targets
```

---

## Codebase Overview

| Module | Purpose |
|---|---|
| `phi_scan/cli.py` | Typer CLI — all user-facing commands |
| `phi_scan/scanner.py` | File collection, binary detection, orchestration |
| `phi_scan/regex_detector.py` | Layer 1 — regex detection engine |
| `phi_scan/nlp_detector.py` | Layer 2 — Presidio/spaCy NLP (optional) |
| `phi_scan/fhir_recognizer.py` | Layer 3 — FHIR R4 field-name scanning |
| `phi_scan/hl7_scanner.py` | Layer 3 — HL7 v2 segment parsing (optional) |
| `phi_scan/detection_coordinator.py` | Combines layers, deduplicates findings |
| `phi_scan/output/console/` | Rich terminal UI — `display_*`, banner, progress (sub-package) |
| `phi_scan/output/console/__init__.py` | Constants, `_UNICODE_SUPPORTED`, `_resolve_symbol`; re-exports all public symbols |
| `phi_scan/output/console/core.py` | Shared infrastructure: `_rich_console`, `get_console()`, `create_scan_progress`, `display_status_spinner` |
| `phi_scan/output/console/findings.py` | Findings table, file tree, code context panel, category breakdown |
| `phi_scan/output/console/summary.py` | Banner, phase separators, scan header, clean/violation summary panels |
| `phi_scan/output/console/baseline.py` | Baseline summary, diff, drift warning, scan notice panels |
| `phi_scan/output/serializers.py` | Pure-data serialisers — JSON, CSV, SARIF, JUnit, GitLab |
| `phi_scan/output/dashboard.py` | Live dashboard layout builders |
| `phi_scan/output/watch.py` | File-watcher event UI |
| `phi_scan/output/__init__.py` | Re-exports all public output symbols |
| `phi_scan/ci_integration.py` | CI/CD platform integrations (GitHub, GitLab, Azure, Bitbucket) |
| `phi_scan/baseline.py` | Baseline snapshot create/load/diff |
| `phi_scan/audit.py` | SQLite audit log |
| `phi_scan/config.py` | `.phi-scanner.yml` configuration loading |
| `phi_scan/constants.py` | Enums, exit codes, shared constants |
| `phi_scan/models.py` | `ScanResult`, `ScanFinding` dataclasses |
| `phi_scan/exceptions.py` | Domain exception hierarchy |

### Where to Add Things

- **New output format** (JSON, SARIF, etc.): `phi_scan/output/serializers.py` → export from `phi_scan/output/__init__.py` → add to `OutputFormat` in `constants.py` → wire in `cli.py`
- **New terminal display function**: add to the appropriate `phi_scan/output/console/` sub-module (`findings.py`, `summary.py`, or `baseline.py`) → re-export from `phi_scan/output/console/__init__.py` using `name as name` syntax
- **New CI/CD platform**: `phi_scan/ci_integration.py` — add a `_HttpRequestConfig`-based call using `_execute_http_request`; wire into `post_pr_comment` and `set_commit_status` dispatch tables
- **New PHI pattern**: `phi_scan/regex_detector.py` — add pattern + validator; update `PhiCategory` in `constants.py` if a new HIPAA category
- **New CLI command**: `phi_scan/cli.py` — follow the existing Typer app/sub-app pattern

---

## Code Standards

These standards are enforced in code review. PRs that violate them will not
be merged.

### Naming

- **Functions**: `verb_noun` in `snake_case` (e.g., `compute_value_hash`,
  `resolve_scan_targets`). Banned verbs: `process`, `handle`, `manage`,
  `run`, `do`, `data`, `info` (use a more specific verb that names the
  operation, e.g., `parse_framework_flag` not `handle_framework`).
- **Boolean variables and fields**: `is_`, `has_`, `should_` prefix
  (e.g., `is_clean`, `should_use_baseline`, `has_findings`).
- **Constants**: `UPPER_SNAKE_CASE`. No abbreviations — spell out every word.
  `CONFIDENCE_HIGH_FLOOR`, not `CONF_HIGH` or `CONFIDENCE_HI_FLOOR`.
- **Private module constants**: `_UPPER_SNAKE_CASE`.
- **No abbreviations** in any identifier. `file_path` not `fp`. `findings`
  not `fndgs`. `enabled_frameworks` not `fw_set`. Regulatory acronyms
  (HIPAA, GDPR, NPI, SSN) used as proper names are accepted.
- **No banned variable names**: `result`, `data`, `item`, `value` — use
  a name that describes the content.

### Functions

- **30-line body limit**: function bodies must not exceed 30 lines (excluding
  docstring, blank lines, and comments). Extract helpers if needed.
- **Single responsibility**: describable in one sentence with no "and".
  If the description needs "and", split the function.
- **≤ 3 parameters** for regular functions. Use a frozen dataclass to
  group related parameters when more are needed.
- **`-> NoReturn`** on functions that always raise (e.g., functions that
  always raise `typer.Exit`). The type checker must be able to verify this.

### Classes and Dataclasses

- Domain dataclasses are `frozen=True` (immutable). Mutable configuration
  objects validate on `__setattr__`.
- Public module constants use `Mapping[K, V]` annotation (read-only contract)
  rather than `dict`.

### Exceptions

- Use domain-specific exceptions that subclass `PhiScanError` (from
  `phi_scan/exceptions.py`). Never raise bare `ValueError` or `RuntimeError`
  for domain errors.
- Catch the most specific exception type. Never `except Exception` in
  production paths.

### Magic Values

- No string or numeric literals in logic. Name every constant.
- String literals in display text (help strings, log messages) do not
  require naming.

### Imports and Type Annotations

- Use `from __future__ import annotations` at the top of every module.
- Heavy imports (Rich, matplotlib, fpdf2, spaCy) must be lazy-imported
  inside functions that use them. CLI startup time must remain under 500ms.
- Type-only imports go under `if TYPE_CHECKING:` to avoid circular imports.
- Use `Mapping` (from `collections.abc`) for read-only dict parameters and
  constants; use `dict` only for mutable local variables.

### PHI Safety

- **Never log, store, or return raw PHI values.** All matched PHI must be
  hashed with `compute_value_hash()` before any storage or further processing.
- **Never include PHI in exception messages.** Exception messages may contain
  file paths, line numbers, and entity types — not matched values.
- **`code_context` must be pre-redacted.** Matched PHI in source lines must
  be replaced with `[REDACTED]` before the string is stored in `ScanFinding`.

### Security

- No symlink following (`should_follow_symlinks` is always `False`).
- No external network calls from the scanner or detection layers.
- File paths in `ScanFinding` are always relative (never absolute).
- Rich markup user strings must be escaped with `rich.markup.escape()`
  before rendering.

---

## Testing

### Running Tests

```bash
make test
# or
uv run pytest
```

### Test Coverage Requirement

PRs must maintain or improve the test suite. New detection patterns require
tests in `tests/test_detection_*.py`. New CLI commands require integration
tests in `tests/test_integration.py`.

### Test Fixture PHI Policy

Test fixtures must not contain real PHI. Use:

- SSN: `000-00-0000` (SSA-reserved area)
- Phone: `555-0100` through `555-0199` (FCC fictional range)
- Email: `test@example.com` (RFC 2606 documentation domain)
- IP: `192.0.2.1` (RFC 5737 TEST-NET-1)
- Any other identifier: use clearly fictional values with `TEST-` prefix

Never commit real patient data, even in anonymised form, to the repository.

### Test Naming

```python
def test_<what>_<condition>_<expected>() -> None:
    """One-sentence description of what is being tested."""
```

Examples:
```python
def test_scan_finding_severity_matches_confidence_band() -> None: ...
def test_parse_framework_flag_rejects_unknown_token() -> None: ...
def test_annotate_findings_always_includes_hipaa() -> None: ...
```

### No Mocking the Database

Integration tests must use a real (temporary) SQLite database. Mocking
the database layer hides schema migration failures and real I/O errors.

---

## Pull Request Process

### Branch Naming

```
task/<phase>-<short-description>
fix/<issue-number>-<short-description>
docs/<scope>-<short-description>
```

Examples:
```
task/4C-documentation-suite
fix/80-self-heal-issues
docs/compliance-frameworks
```

### Before Opening a PR

1. `make lint` — passes
2. `make typecheck` — passes (pre-existing mypy errors in `hl7_scanner.py`
   and `nlp_detector.py` are accepted; do not add new ones)
3. `make test` — all tests pass
4. `make scan` — `phi_scan/` itself is clean
5. Update `CHANGELOG.md` under `[Unreleased]`

### Commit Message Style

Use imperative mood, 72-character subject line:

```
feat: add --framework flag for compliance annotation
fix: handle empty frozenset in annotate_findings
docs: add confidence-scoring.md
refactor: split _emit_report_phase into display + emit
```

### PR Description

Every PR must include:
- **What**: one-paragraph summary of the change
- **Why**: the motivation or issue it addresses
- **Testing**: how the change was tested
- **Breaking changes**: any API or CLI changes that are not backwards-compatible

### Squash-Merge Policy

All PRs are squash-merged. Individual commits in the branch do not need to
be perfectly structured — the squash commit message is what matters.

---

## Security and PHI Hygiene

### Reporting Security Vulnerabilities

Do not open a public GitHub issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for the private disclosure process.

### PHI in Test Data

If you discover real PHI in the repository (committed accidentally), follow
the incident response process in `SECURITY.md`. Do not attempt to scrub git
history unilaterally — coordinate with the maintainer.

---

## Reporting Issues

- **Bug reports**: open a GitHub issue with reproduction steps, expected
  behaviour, actual behaviour, and output of `phi-scan --version`.
- **Feature requests**: open a GitHub issue describing the use case.
- **False positives / false negatives**: open an issue with the entity type,
  the pattern that triggered (or didn't trigger), and a minimal reproduction.
  Do not include real PHI in issue reports.
