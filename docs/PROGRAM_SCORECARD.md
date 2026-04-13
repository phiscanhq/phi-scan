# PhiScan Public Repo Program Scorecard

Tracks progress toward 10/10 public-repo quality across four categories.
Each check has a binary pass/fail state. All checks must pass before the repo
is declared production-ready for v1.0.

**Last updated:** 2026-04-15

---

## How to Read This Document

- **PASS** — criterion is met, tested, and enforced.
- **FAIL** — criterion is not yet met.
- **PARTIAL** — partially implemented; gaps are documented in the Notes column.
- Status in the [Weekly Log](#weekly-log) reflects the snapshot at each review date.

---

## Category 1 — Technical Maturity

| # | Check | Status | Notes |
|---|-------|--------|-------|
| T1 | `uv run ruff check` exits 0 on every merge to `main` | PASS | Enforced by CI |
| T2 | `uv run mypy phi_scan/` exits 0 on every merge to `main` | PASS | Enforced by CI |
| T3 | Test suite coverage ≥ 80% enforced as a CI gate | PASS | `pytest --cov` gate active |
| T4 | `--workers N` parallel scan implemented with `ThreadPoolExecutor` | PASS | Shipped in [8F-ext.1] via `run_parallel_scan` |
| T5 | Sequential and parallel modes produce identical finding sets and identical output ordering | PASS | Parity tests in `tests/test_scanner.py` cover workers=1 vs workers>1 |
| T6 | Golden contract tests exist for JSON, SARIF, CSV, and JUnit output formats | PASS | 16 byte-exact goldens under `tests/fixtures/goldens/` driven by `tests/test_output_goldens.py` |
| T7 | Golden contract tests are a required CI gate (failures block merge) | PASS | `test_output_goldens.py` runs in the standard pytest CI job; any drift fails the merge gate |
| T8 | Performance benchmark fixtures exist (small / medium / large corpus) | PASS | 10/100/500-file synthetic corpora generated at test time in `tests/test_performance_benchmarks.py` |
| T9 | CI enforces per-benchmark runtime and files-per-second thresholds | PASS | Per-size `max_elapsed_seconds` and `min_files_per_second` asserted in the standard pytest CI job on Linux |

**Passing: 9 / 9**

---

## Category 2 — Security Posture

| # | Check | Status | Notes |
|---|-------|--------|-------|
| S1 | No unresolved P0 or P1 security issues | PASS | No known open issues |
| S2 | Webhook `http://` scheme rejected at validation time | PASS | Enforced in `notifier.py` since 7E |
| S3 | Webhook SSRF: RFC1918, loopback, link-local, CGNAT, metadata IPs blocked by default | PASS | DNS resolution + IP range check since 7G.2 |
| S4 | DNS rebinding (TOCTOU) window closed: validated IP pinned to TCP connection | PASS | `_rewrite_url_hostname_to_ip` + `_PinnedWebhookRequest` since 7J |
| S5 | SSRF controls validated with adversarial tests (rebind, mixed-resolution, IPv6) | PASS | Adversarial coverage in `tests/test_notifier_ssrf_adversarial.py` (50 tests) covers IPv4-mapped IPv6, unspecified, multicast, reserved, literal IPv6, mixed-resolution, and deterministic DNS rebind simulation. Notifier unmapping + built-in-property checks added in same PR. |
| S6 | ZIP decompression bomb protection implemented and tested | PASS | Size + ratio guards since 7E |
| S7 | `docs/threat-model.md` exists with threat → mitigation → test → residual risk table | PASS | Full-attack-surface threat model in `docs/threat-model.md` covering scanner ingestion, archive handling, detectors, notifier, AI review, fixer, output, local artifacts, CI adapters. |
| S8 | All P0/P1 threats in the threat model map to a named test | PASS | Every P0 and P1 row in `docs/threat-model.md` cites specific test names; all 61 citations verified via `pytest --collect-only`. |
| S9 | Dependency vulnerability scanning runs in CI (e.g. `pip-audit` or `safety`) | PASS | `dependency-audit` job in `.github/workflows/ci.yml` runs `pip-audit` on every PR and push to `main` via `.github/scripts/pip_audit_runner.py`. Policy-enforced ignore list at `.pip-audit-ignore.toml` (required `id`/`reason`/`tracking`, advisory-ID regex, optional future-dated `expires`, no wildcards). Zero active ignores; baseline CVEs cleared via direct pin bumps (`cryptography>=46.0.7`, `pygments>=2.20.0`). Documented in `docs/supply-chain.md`. |
| S10 | SBOM generation policy documented | PASS | CycloneDX 1.4 SBOM generated at release time via `.github/scripts/sbom_generator.py`, attached to every GitHub Release as `sbom.cyclonedx.json`. Dev dependencies excluded. Policy and local regeneration command documented in `docs/supply-chain.md`. |
| S11 | Artifact signing policy documented (or explicitly out of scope with rationale) | PASS | Keyless Sigstore signing via `sigstore/gh-action-sigstore-python@v3.0.0` wired into `release.yml`; per-artifact `<input>.sigstore.json` bundles attached to each GitHub Release alongside wheel, sdist, and SBOM. Verification workflow and workload-identity policy documented in `docs/supply-chain.md`. |

**Passing: 11 / 11**

---

## Category 3 — Architecture Scalability

| # | Check | Status | Notes |
|---|-------|--------|-------|
| A1 | Plugin API v1 interface defined with explicit version constant | PASS | `PLUGIN_API_VERSION = "1.0"` in `phi_scan/plugin_api.py`; exact-match enforced by loader. Shipped in PR #124. |
| A2 | `BaseRecognizer` abstract class published with stable method signatures | PASS | ABC with `detect(line, context)` method, `ScanContext`/`ScanFinding` frozen dataclasses. Shipped in PR #124. |
| A3 | Plugin discovery via Python entry points implemented and tested | PASS | Entry-point discovery via `phi_scan.plugins` group, fail-safe validation, 30 tests at 100% coverage. Shipped in PR #124. |
| A4 | `phi-scan plugins list` command implemented with metadata validation tests | PASS | Rich table + `--json` output, 19 tests at 100% coverage. Shipped in PR #125. |
| A5 | Plugin API compatibility and deprecation policy documented | PASS | `docs/plugin-api-v1.md` covers version contract, compatibility surface, deprecation process (2-minor-release window), failure semantics, authoring constraints. |
| A6 | Suppressor and output-sink plugin hooks designed (v1.1 shape documented, not implemented) | PASS | `docs/plugin-hooks-v1_1-design.md` covers `BaseSuppressor`, `BaseOutputSink` draft interfaces, execution pipeline, PHI safety model, performance budget, config shape, and open questions. |
| A7 | Parallel scan determinism validated across `workers=1` and `workers>1` | PASS | Parity tests in `tests/test_scanner.py` validate identical findings and ordering |
| A8 | `ci_integration.py` adapter split implemented with per-platform interface contract | PASS | Shipped in PR #130. `phi_scan/ci/` package with 7 per-platform adapters, shared `BaseCIAdapter` interface, capability flags, shared transport/error model. Design doc at `docs/ci-adapter-contract.md`. |
| A9 | Plugin runtime execution integrated into scan path with deterministic ordering and error isolation | PASS | Plugin findings flow through existing filter/output/audit path; per-line plugin errors isolated; plugin registry loaded once per scan. |

**Passing: 9 / 9**

---

## Category 4 — Commercial Readiness

| # | Check | Status | Notes |
|---|-------|--------|-------|
| C1 | `CONTRIBUTING.md` exists with development setup, standards, and PR process | PASS | Present in repo |
| C2 | `SECURITY.md` exists with vulnerability reporting policy | PASS | Present in repo |
| C3 | Community / Pro / Cloud feature boundary matrix published in docs | PASS | `docs/community-pro-cloud-matrix.md` covers 8 feature categories across Community/Pro/Cloud tiers with guiding principles and "what stays free forever" guarantees. |
| C4 | "What stays free forever" messaging is explicit in `README.md` | PASS | "Free forever" bullet in Why PhiScan section with link to full boundary matrix. Explicit guarantee that Community capabilities will never be paywalled or degraded. |
| C5 | Release cadence and versioning policy documented | PASS | `docs/release-versioning-policy.md` covers semver scheme, patch/minor/major cadence, breaking-change definition, release process, and deprecation cross-reference. |
| C6 | Long-term support (LTS) and end-of-life policy documented | PASS | `docs/lts-eol-policy.md` covers 12-month LTS window, security backport SLA, EOL process with 90-day notice, LTS overlap, and Python version support policy. |
| C7 | `docs/PROGRAM_SCORECARD.md` linked from `README.md` | PASS | Added in same PR as scorecard |

**Passing: 7 / 7**

---

## Overall Status

| Category | Passing | Total | % |
|----------|---------|-------|---|
| Technical Maturity | 9 | 9 | 100% |
| Security Posture | 11 | 11 | 100% |
| Architecture Scalability | 9 | 9 | 100% |
| Commercial Readiness | 7 | 7 | 100% |
| **Total** | **36** | **36** | **100%** |

**Target:** 36 / 36 checks passing.

---

## Weekly Log

| Date | Tech | Security | Architecture | Commercial | Notes |
|------|------|----------|--------------|------------|-------|
| 2026-04-11 | 7/9 | 5/11 | 1/8 | 3/7 | Scorecard created. 7J merged (DNS TOCTOU fix). README link added. Reconciled T4/T5/A7 for shipped parallel scan work ([8F-ext.1]). T6/T7 shipped: byte-exact golden contract tests for JSON/SARIF/CSV/JUnit. |
| 2026-04-12 | 9/9 | 5/11 | 1/8 | 3/7 | T8/T9 shipped: synthetic small/medium/large corpora and per-size runtime + throughput thresholds enforced in the Linux pytest job. Technical Maturity category now at 100%. |
| 2026-04-13 | 9/9 | 8/11 | 1/8 | 3/7 | S5/S7/S8 shipped: 50 adversarial SSRF tests (IPv4-mapped IPv6, unspecified, multicast, mixed-resolution, DNS rebind TOCTOU), full-surface threat model at `docs/threat-model.md`, notifier SSRF fix (unmap IPv4-mapped IPv6 + built-in-property checks). Security category now at 73%. |
| 2026-04-14 | 9/9 | 11/11 | 1/8 | 3/7 | S9/S10/S11 shipped: pip-audit CI gate with policy-enforced `.pip-audit-ignore.toml`, release-time CycloneDX SBOM via `.github/scripts/sbom_generator.py`, keyless Sigstore signing of wheel+sdist. Baseline CVEs cleared via direct pin bumps (cryptography 46.0.7, pygments 2.20.0). Full supply-chain policy at `docs/supply-chain.md`. Security category at 100%; overall 69%. |
| 2026-04-15 | 9/9 | 11/11 | 6/9 | 3/7 | A1–A5 shipped: Plugin API v1 core (`BaseRecognizer` ABC, `ScanContext`/`ScanFinding` dataclasses, `PLUGIN_API_VERSION`) in PR #124. `phi-scan plugins list` command with Rich table and `--json` output in PR #125. Plugin compatibility and deprecation policy at `docs/plugin-api-v1.md`. Architecture category at 6/9; overall 29/36. |
| 2026-04-16 | 9/9 | 11/11 | 8/9 | 7/7 | A6/A8 shipped: `docs/plugin-hooks-v1_1-design.md` (suppressor + output sink v1.1 design) and A8 CI adapter split implemented in PR #130 (`phi_scan/ci/` package with `BaseCIAdapter` interface and per-platform adapters); contract documented in `docs/ci-adapter-contract.md`. C3/C4 shipped: `docs/community-pro-cloud-matrix.md` (feature boundary matrix across 8 categories) and "Free forever" messaging in README. C5/C6 shipped: `docs/release-versioning-policy.md` (semver, cadence, breaking-change rules) and `docs/lts-eol-policy.md` (12-month LTS, 90-day EOL notice). Architecture 8/9 (A9 pending); overall 35/36. |
| 2026-04-17 | 9/9 | 11/11 | 9/9 | 7/7 | A9 shipped (PR #136): plugin runtime execution integrated into scan path (`phi_scan/plugin_runtime.py`). Per-line plugin pass runs in `phi_scan.scanner` after the built-in detection coordinator returns; plugin findings flow through the existing filter/suppression/baseline/output pipeline. Per-line exception isolation (documented carve-out in `docs/plugin-api-v1.md`), rate-limited warnings (5 per recognizer + summary), deterministic ordering, and worker-parity validated. Registry cached once per `execute_scan` invocation. **Architecture 9/9; overall 36/36 — scorecard complete.** |
| 2026-04-18 | 9/9 | 11/11 | 9/9 | 7/7 | Truth-sync pass: scanner / detection-coordinator docstrings state that built-in layers live in `detection_coordinator` and the plugin runtime pass runs in `scanner`; `docs/ci-adapter-contract.md` corrected to match the shipped state of `ci_integration.py` (no `DeprecationWarning` emitted today; extras migration is a Phase 3 prerequisite to shim removal); scorecard log reordered chronologically and A9 narrative deduplicated. No behavior changes. Totals unchanged at 36/36. |

---

## Execution Order

Checks are addressed in this sequence:

1. **T4, T5, A7** — Parallel scan + parity tests (single PR) ✓ Done — shipped in [8F-ext.1]
2. **T6, T7, T8, T9** — Output contract golden tests + performance gates
    - T6, T7 ✓ Done — byte-exact golden tests for JSON/SARIF/CSV/JUnit
    - T8, T9 ✓ Done — synthetic corpora + runtime/throughput CI thresholds
3. **S5, S7, S8** ✓ Done — SSRF adversarial tests + threat model doc
4. **S9, S10, S11** ✓ Done — Supply-chain security gates (pip-audit CI gate, CycloneDX SBOM, Sigstore signing)
5. **A1–A5** ✓ Done — Plugin API v1 core (PR #124), `plugins list` command (PR #125), compatibility/deprecation policy doc
6. **A6** ✓ Done — Suppressor + output-sink v1.1 design doc (`docs/plugin-hooks-v1_1-design.md`)
7. **A8** ✓ Done — CI adapter split implemented in PR #130; contract documented in `docs/ci-adapter-contract.md`.
8. **C3, C4** ✓ Done — Feature boundary matrix (`docs/community-pro-cloud-matrix.md`), "Free forever" README messaging
9. **C5, C6** ✓ Done — Release cadence/versioning policy (`docs/release-versioning-policy.md`), LTS/EOL policy (`docs/lts-eol-policy.md`)
