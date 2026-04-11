# PhiScan Public Repo Program Scorecard

Tracks progress toward 10/10 public-repo quality across four categories.
Each check has a binary pass/fail state. All checks must pass before the repo
is declared production-ready for v1.0.

**Last updated:** 2026-04-12

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
| S5 | SSRF controls validated with adversarial tests (rebind, mixed-resolution, IPv6) | PARTIAL | Basic pin tests present; mixed-resolution and rebind simulation tests missing |
| S6 | ZIP decompression bomb protection implemented and tested | PASS | Size + ratio guards since 7E |
| S7 | `docs/threat-model.md` exists with threat → mitigation → test → residual risk table | FAIL | Not yet written |
| S8 | All P0/P1 threats in the threat model map to a named test | FAIL | Blocked by S7 |
| S9 | Dependency vulnerability scanning runs in CI (e.g. `pip-audit` or `safety`) | FAIL | Not yet implemented |
| S10 | SBOM generation policy documented | FAIL | Not yet documented |
| S11 | Artifact signing policy documented (or explicitly out of scope with rationale) | FAIL | Not yet documented |

**Passing: 5 / 11 (1 partial)**

---

## Category 3 — Architecture Scalability

| # | Check | Status | Notes |
|---|-------|--------|-------|
| A1 | Plugin API v1 interface defined with explicit version constant | FAIL | `plugin_api.py` is a stub |
| A2 | `BaseRecognizer` abstract class published with stable method signatures | FAIL | Not yet implemented |
| A3 | Plugin discovery via Python entry points implemented and tested | FAIL | Not yet implemented |
| A4 | `phi-scan plugins list` command implemented with metadata validation tests | FAIL | Not yet implemented |
| A5 | Plugin API compatibility and deprecation policy documented | FAIL | Not yet documented |
| A6 | Suppressor and output-sink plugin hooks designed (v1.1 shape documented, not implemented) | FAIL | Deferred to v1.1; design not yet written |
| A7 | Parallel scan determinism validated across `workers=1` and `workers>1` | PASS | Parity tests in `tests/test_scanner.py` validate identical findings and ordering |
| A8 | `ci_integration.py` adapter split planned with per-platform interface contract documented | FAIL | Planned in roadmap (8F-ext.2); not yet designed |

**Passing: 1 / 8**

---

## Category 4 — Commercial Readiness

| # | Check | Status | Notes |
|---|-------|--------|-------|
| C1 | `CONTRIBUTING.md` exists with development setup, standards, and PR process | PASS | Present in repo |
| C2 | `SECURITY.md` exists with vulnerability reporting policy | PASS | Present in repo |
| C3 | Community / Pro / Cloud feature boundary matrix published in docs | FAIL | Not yet written |
| C4 | "What stays free forever" messaging is explicit in `README.md` | FAIL | Not present |
| C5 | Release cadence and versioning policy documented | FAIL | Not yet documented |
| C6 | Long-term support (LTS) and end-of-life policy documented | FAIL | Not yet documented |
| C7 | `docs/PROGRAM_SCORECARD.md` linked from `README.md` | PASS | Added in same PR as scorecard |

**Passing: 3 / 7**

---

## Overall Status

| Category | Passing | Total | % |
|----------|---------|-------|---|
| Technical Maturity | 9 | 9 | 100% |
| Security Posture | 5 | 11 | 45% |
| Architecture Scalability | 1 | 8 | 13% |
| Commercial Readiness | 3 | 7 | 43% |
| **Total** | **18** | **35** | **51%** |

**Target:** 35 / 35 checks passing.

---

## Weekly Log

| Date | Tech | Security | Architecture | Commercial | Notes |
|------|------|----------|--------------|------------|-------|
| 2026-04-11 | 7/9 | 5/11 | 1/8 | 3/7 | Scorecard created. 7J merged (DNS TOCTOU fix). README link added. Reconciled T4/T5/A7 for shipped parallel scan work ([8F-ext.1]). T6/T7 shipped: byte-exact golden contract tests for JSON/SARIF/CSV/JUnit. |
| 2026-04-12 | 9/9 | 5/11 | 1/8 | 3/7 | T8/T9 shipped: synthetic small/medium/large corpora and per-size runtime + throughput thresholds enforced in the Linux pytest job. Technical Maturity category now at 100%. |

---

## Execution Order

Checks are addressed in this sequence:

1. **T4, T5, A7** — Parallel scan + parity tests (single PR) ✓ Done — shipped in [8F-ext.1]
2. **T6, T7, T8, T9** — Output contract golden tests + performance gates
    - T6, T7 ✓ Done — byte-exact golden tests for JSON/SARIF/CSV/JUnit
    - T8, T9 ✓ Done — synthetic corpora + runtime/throughput CI thresholds
3. **S5, S7, S8** — SSRF adversarial tests + threat model doc
4. **S9, S10, S11** — Supply-chain security gates
5. **A1–A5** — Plugin API v1 implementation
6. **A6** — Suppressor + output-sink design doc (v1.1 shape)
7. **A8** — CI adapter split design doc
8. **C3–C6** — Boundary docs, release policy, governance
