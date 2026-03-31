# Changelog

All notable changes to PhiScan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/joeyessak/phi-scan/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/joeyessak/phi-scan/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/joeyessak/phi-scan/releases/tag/v0.1.0
