# PhiScan Roadmap

PhiScan is a HIPAA-compliant PHI/PII scanner for CI/CD pipelines. All scanning
runs locally by default — no PHI leaves your infrastructure. The optional AI
confidence review layer sends only redacted code structure (never raw PHI values)
to the configured AI provider when explicitly enabled.

This roadmap tracks what has been built, what is in progress, and what is planned.
All core scanning and CI/CD integration is and will remain free and open source.

---

## Version Strategy

PhiScan follows semantic versioning. The `0.x` series is active development.
Version `1.0.0` marks the production-ready public launch.

| Version | Milestone                        |
| ------- | -------------------------------- |
| 0.1.0   | CLI shell installable            |
| 0.2.0   | Detection engine working         |
| 0.3.0   | Output formats + first PyPI publish |
| 0.4.0   | Enterprise reports + compliance  |
| 0.5.0   | Notifications + audit hardening  |
| 0.6.0   | CI/CD templates + Docker         |
| 0.7.0   | AI enhancement (optional)        |
| 0.8.0   | Pro tier + VS Code extension     |
| 1.0.0   | Public launch                    |

---

## Phase 1 — Terminal CLI App ✅ `v0.1.0`

Fully installable CLI with Rich terminal UI, recursive file traversal, SQLite audit
logging, YAML config, structured logging, and all command stubs wired up.

- Installable via `pipx install phi-scan`
- `phi-scan scan`, `watch`, `report`, `history`, `explain`, `fix`, `baseline`, `init`, `dashboard`
- `.phi-scanignore` exclusion patterns (gitignore-style via pathspec)
- HIPAA-compliant SQLite audit log — hashes only, never raw PHI
- Rich progress bar, coloured severity output, summary table

---

## Phase 2 — Detection Engine ✅ `v0.2.0`

Four-layer PHI/PII detection covering all 18 HIPAA Safe Harbor identifiers plus
extended regulatory categories.

- **Layer 1 — Regex:** SSN, MRN, DOB, phone, email, IP, NPI, DEA, MBI, HICN, VIN,
  genetic rs-IDs, ZIP codes, health plan numbers, and more
- **Layer 2 — NLP/NER:** spaCy + Presidio named entity recognition for names,
  locations, and context-aware detection (optional install)
- **Layer 3 — Structured Formats:** FHIR R4 field name recognition, HL7 v2 segment
  scanning (PID, NK1, IN1)
- **Layer 4 — AI Scoring:** AI provider confidence adjustment for ambiguous findings
  (optional; Anthropic, OpenAI, or Google; values redacted before any API call)
- Inline suppression: `# phi-scan:ignore`, `# phi-scan:ignore[SSN,MRN]`,
  `# phi-scan:ignore-next-line`, `# phi-scan:ignore-file`
- Content-hash scan cache — skip unchanged files
- Auto-fix engine: replace PHI with synthetic data (`--dry-run`, `--apply`, `--patch`)
- `phi-scan explain` — human-readable explanations of confidence, severity, HIPAA categories

---

## Phase 3 — CLI Polish, Output Formats & First Publish ✅ `v0.3.0`

Production-quality output and first public PyPI release.

- Output formats: `table`, `json`, `sarif`, `csv`, `junit`, `codequality`, `gitlab-sast`
- Baseline management: `phi-scan baseline create/show/clear/diff` + `--baseline` scan flag
- Pre-commit framework integration (`.pre-commit-hooks.yaml`)
- Published to PyPI: `pip install phi-scan`
- Core documentation: getting started, configuration, CI/CD integration, ignore patterns,
  known limitations, security, troubleshooting
- Community files: `CODE_OF_CONDUCT.md`, issue templates, PR template

---

## Phase 4 — Enterprise Reports & Compliance ✅ `v0.5.0`

Enterprise-grade PDF and HTML reports with charts, and multi-framework compliance mapping.

- PDF and HTML reports with executive summary, severity charts, findings table,
  remediation guidance, and trend chart from audit history
- Multi-framework compliance mapping: HIPAA, GDPR, SOC 2, HITRUST, NIST SP 800-53,
  42 CFR Part 2, GINA, CCPA, BIPA, SHIELD Act, MRPA — each finding annotated with
  applicable regulatory controls
- Full documentation suite: confidence scoring, detection layers, output formats,
  remediation guide, compliance frameworks, de-identification guide
- 163-test suite covering PDF/HTML output, compliance mapping, and multi-framework annotation

---

## Phase 5 — Notifications & Audit Hardening ✅ `v0.5.0`

Alerting when PHI is detected and hardened audit infrastructure.

- CI/CD notifications: `--post-comment` (PR/MR comment), `--set-status` (commit status),
  `--upload-sarif` (GitHub Code Scanning inline annotations)
- Auto-detects GitHub, GitLab, Azure DevOps, CircleCI, Bitbucket
- Output formats: `junit`, `codequality`, `gitlab-sast`
- `phi-scan history show|diff|export` with `--repo` and `--violations-only` filters

---

## Phase 6 — CI/CD Integration & Docker ✅ `v0.5.0`

Drop-in CI/CD templates for all major platforms and a production Docker image.

- Native templates: GitHub Actions, GitLab CI, Azure Pipelines, Bitbucket Pipelines,
  CircleCI orb, AWS CodeBuild — each with native report group and annotation support
- `joeyessak/phi-scan-action` composite action — one-liner GitHub CI/CD integration
  with SARIF upload, PR comment, diff-only scanning, and AI review support
- Multi-arch Docker image (`ghcr.io/joeyessak/phi-scan`, amd64/arm64)

---

## Phase 7 — AI Enhancement _(Optional)_ ✅ `v0.7.0`

Reduce false positives using AI confidence scoring. Fully optional — the scanner
operates at full capability without this phase.

- ✅ AI confidence review layer — medium-confidence findings re-scored by an AI provider
- ✅ Multi-provider support: Anthropic (`claude-*`), OpenAI (`gpt-*`/`o1`/`o3`/`o4`),
  Google (`gemini-*`) — provider inferred from model name, no new mandatory dependencies
- ✅ PHI always redacted before any API call — raw values never leave the machine
- ✅ Graceful fallback to local-only scoring if API is unavailable
- ✅ AI token usage logged in audit trail (`prompt_tokens`, `completion_tokens`, `estimated_cost_usd`)
- ✅ Disabled by default; opt-in via `ai.enable_ai_review: true` in `.phi-scanner.yml`

> **Note:** GitHub Marketplace publication of
> [`phi-scan-action`](https://github.com/joeyessak/phi-scan-action) is deferred
> until the GitHub org migration is complete. The composite action is fully
> functional; only the Marketplace listing is pending.

---

## Phase 8 — Plugin Ecosystem, Pro Tier & IDE Integration 🔄 In Progress `→ v0.8.0`

Plugin ecosystem, pro features, and IDE integration.

**Shipped:**

- ✅ Plugin API v1: `BaseRecognizer` abstract class, `ScanContext`/`ScanFinding`
  dataclasses, `PLUGIN_API_VERSION = "1.0"` with exact-match enforcement
- ✅ Plugin discovery via `phi_scan.plugins` entry-point group with fail-safe
  validation and skip-on-error semantics
- ✅ `phi-scan plugins list` command with Rich table and `--json` output
- ✅ Plugin API compatibility and deprecation policy documented
  ([docs/plugin-api-v1.md](docs/plugin-api-v1.md))
- ✅ Suppressor and output-sink plugin hooks designed
  ([docs/plugin-hooks-v1_1-design.md](docs/plugin-hooks-v1_1-design.md))
- ✅ CI adapter split: `ci_integration.py` decomposed into `phi_scan/ci/` package
  with per-platform adapters, shared `BaseCIAdapter` interface, and backward-
  compatible re-exports ([docs/ci-adapter-contract.md](docs/ci-adapter-contract.md))

**Remaining:**

- Example plugins: `phi-scan-epic`, `phi-scan-cerner`, `phi-scan-hl7`
- VS Code extension with inline highlighting and quick-fix suggestions
- Pro license key system (compliance report watermarking, audit export, SLA support)

---

## Phase 9 — Hardening & Public Launch 🔄 In Progress `→ v1.0.0`

Security audit, performance hardening, enterprise features, and public launch.

**Shipped:**

- ✅ Performance benchmark suite: synthetic small/medium/large corpora with
  per-size runtime and throughput thresholds enforced in CI
- ✅ Supply-chain hardening: `pip-audit` CI gate with policy-enforced ignore list,
  CycloneDX SBOM generated at release time, keyless Sigstore signing of
  wheel + sdist artifacts
- ✅ Full-surface threat model documented ([docs/threat-model.md](docs/threat-model.md))
  with every P0/P1 threat mapped to a named test
- ✅ SSRF adversarial test suite: 50 tests covering IPv4-mapped IPv6, DNS rebind
  TOCTOU, multicast, mixed-resolution, and reserved IP ranges

**Remaining:**

- Independent security audit
- Performance optimisation (target: 10k files/sec)
- Enterprise SSO and audit log API
- Signed plugin registry
- Public launch: ProductHunt, Hacker News, security community outreach

---

## Contributing

PhiScan is open source under the MIT license. Contributions are welcome.
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines (available Phase 4+).

**Core principle — non-negotiable:** All scanning executes locally by default.
No raw PHI or PII is ever transmitted externally. The optional AI confidence
review layer sends only redacted code structure to the configured AI provider
when explicitly enabled via `ai.enable_ai_review: true`.
