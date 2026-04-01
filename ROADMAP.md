# PhiScan Roadmap

PhiScan is a HIPAA-compliant PHI/PII scanner for CI/CD pipelines. It runs entirely
locally — no PHI is ever transmitted to an external service.

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
- **Layer 4 — AI Scoring:** Claude API confidence adjustment for ambiguous findings
  (optional; values redacted before any API call)
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

## Phase 4 — Enterprise Reports & Compliance 🔄 In Progress `→ v0.4.0`

Enterprise-grade PDF and HTML reports with charts, and multi-framework compliance mapping.

- [x] **4A** — PDF and HTML reports with executive summary, severity charts, findings
  table, remediation guidance, and trend chart from audit history
- [ ] **4B** — Multi-framework compliance mapping: HIPAA, GDPR, SOC 2, PCI-DSS, CCPA,
  HITRUST — each finding mapped to the applicable regulatory controls
- [ ] **4C** — Full documentation suite: architecture, plugin authoring, compliance
  reference, de-identification guide
- [ ] **4D** — Phase 4 test coverage

---

## Phase 5 — Notifications & Audit Hardening 📋 Planned `→ v0.5.0`

Alerting when PHI is detected and hardened audit infrastructure.

- Email notifications (SMTP) on scan findings above configurable threshold
- Webhook notifications (Slack, Teams, PagerDuty, generic HTTP)
- Audit log encryption at rest
- Structured audit query API for downstream integrations
- `phi-scan history` improvements: date filters, severity filters, export

---

## Phase 6 — CI/CD Integration & Docker 📋 Planned `→ v0.6.0`

Drop-in CI/CD templates for all major platforms and a production Docker image.

- Native templates: GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI,
  Bitbucket Pipelines, AWS CodeBuild
- PR/MR inline annotations and comments on each platform
- GitHub Marketplace action (`phi-scan/phi-scan-action`)
- Official Docker image on Docker Hub (`phi-scan/phi-scan`)
- `phi-scan init` auto-detects CI platform and generates the correct template

---

## Phase 7 — AI Enhancement _(Optional)_ 📋 Planned `→ v0.7.0`

Reduce false positives using Claude API confidence scoring. Fully optional — the
scanner operates at full capability without this phase.

- Claude reviews medium-confidence findings only (`confidence < 0.8`)
- PHI values are redacted before any API call — raw values never leave the machine
- Graceful fallback to local-only scoring if API is unavailable
- Disabled by default; opt-in via `.phi-scanner.yml`

---

## Phase 8 — Pro Tier & VS Code Extension 📋 Planned `→ v0.8.0`

Pro features, plugin ecosystem, and IDE integration.

- Plugin system: `BaseRecognizer` interface + entry-point registration
- Example plugins: `phi-scan-epic`, `phi-scan-cerner`, `phi-scan-hl7`
- VS Code extension with inline highlighting and quick-fix suggestions
- Pro license key system (compliance report watermarking, audit export, SLA support)
- GitHub Marketplace listing

---

## Phase 9 — Hardening & Public Launch 📋 Planned `→ v1.0.0`

Security audit, performance hardening, enterprise features, and public launch.

- Independent security audit
- Performance benchmarks and optimisation (target: 10k files/sec)
- Enterprise SSO and audit log API
- Signed plugin registry
- Public launch: ProductHunt, Hacker News, security community outreach

---

## Contributing

PhiScan is open source under the MIT license. Contributions are welcome.
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines (available Phase 4+).

**Core principle — non-negotiable:** All scanning executes locally. No PHI or PII
is ever transmitted to an external API or third-party service.
