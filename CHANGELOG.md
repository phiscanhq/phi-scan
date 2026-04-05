# Changelog

All notable changes to PhiScan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Multi-provider AI support (7D):** AI confidence review now supports Anthropic, OpenAI, and
  Google AI providers. Provider is inferred automatically from the model name:
  `claude-*` → Anthropic, `gpt-*`/`o1`/`o3`/`o4` → OpenAI, `gemini-*` → Google.
  Install the matching extra: `phi-scan[ai-anthropic]`, `phi-scan[ai-openai]`, or
  `phi-scan[ai-google]`. The existing `phi-scan[ai]` meta-extra continues to install Anthropic.
- **Provider-neutral configuration:** New `ai.enable_ai_review` key replaces the deprecated
  `ai.enable_claude_review`; new `ai.model` field selects the model and determines the provider.
  API keys are read from `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY` environment
  variables — storing keys in `.phi-scanner.yml` is explicitly rejected with a clear error.

### Changed

- `ai.enable_claude_review` is deprecated — emits `DeprecationWarning`; still accepted for
  backward compatibility but will be removed in a future release.
- Per-provider token cost rates replace the single Anthropic rate. Cost estimates in the audit
  log now reflect the selected provider's published pricing.

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

[Unreleased]: https://github.com/joeyessak/phi-scan/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/joeyessak/phi-scan/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/joeyessak/phi-scan/releases/tag/v0.1.0
