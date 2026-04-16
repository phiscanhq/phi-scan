# Org Migration Pre-flight Report — `joeyessak/*` → `phiscanhq/*`

**Date:** 2026-04-18
**Scope:** Section 1 (Pre-flight) of `docs/org-migration-checklist.md`.
**Status:** Pre-flight only. No transfer executed. No repo config changed.
No URL flips applied. No releases published.

This report captures the current state of `joeyessak/phi-scan` so the
transfer described in `docs/org-migration-checklist.md` can be executed
against a known-good baseline. It enumerates every hardcoded
`joeyessak/` reference in the tree, classifies each by migration
priority, and lists the exact post-transfer patches that will need to
be applied in a follow-up PR (after maintainer "migration go" approval).

`phi-scan-action` lives in a separate repository and is out of scope
for this pre-flight beyond consumer-facing references in this repo.

---

## 1. Repo cleanliness (§1.1)

| Check | Result |
|-------|--------|
| Open pull requests on `joeyessak/phi-scan` | **None** |
| In-progress CI runs | **None** (last run 2026-04-12 completed `success`) |
| `main` green on latest commit | **Yes** (most recent push: CI `success`) |
| Draft releases or in-flight publish jobs | **None observed** via `gh run list` |
| Release branch parked or merged | **N/A** — no release branch in play |

Source: `gh pr list --repo joeyessak/phi-scan --state open`,
`gh run list --repo joeyessak/phi-scan --limit 5`.

---

## 2. Hardcoded organisation-reference sweep (§1.2)

Command used:

```bash
grep -rn "joeyessak\|JoeyEssak" --include="*.md" --include="*.yml" \
  --include="*.yaml" --include="*.toml" --include="*.py" .
```

Classification:

- **P0** — Transfer-blocker if not handled: breaks the release or CI
  path at transfer time.
- **P1** — Must flip within the 48-hour observation window: canonical
  URLs consumers see (README, `pyproject.toml` project URLs, release
  verification commands, CI `uses:` references).
- **P2** — Cosmetic or historical: documentation that references the
  old path but does not affect publish, install, or signing paths.
  Update opportunistically.

### 2.1 P0 — Transfer-blockers

**None.** Every hardcoded reference either resolves via the GitHub
redirect or is rebuildable post-transfer. No workflow file depends on
an unredirectable `joeyessak/` identity (e.g. no `permissions:` scoped
to the old owner, no hardcoded OIDC subject inside a workflow).

### 2.2 P1 — Flip within 48h after transfer

Format: `<file>:<line> -> current -> intended post-transfer`.

- `README.md:6 -> https://github.com/joeyessak/phi-scan/actions/workflows/ci.yml/badge.svg -> https://github.com/phiscanhq/phi-scan/actions/workflows/ci.yml/badge.svg`
- `README.md:6 -> https://github.com/joeyessak/phi-scan/actions/workflows/ci.yml -> https://github.com/phiscanhq/phi-scan/actions/workflows/ci.yml`
- `README.md:229 -> repo: https://github.com/joeyessak/phi-scan -> repo: https://github.com/phiscanhq/phi-scan`
- `README.md:266 -> https://github.com/joeyessak/phi-scan-action -> https://github.com/phiscanhq/phi-scan-action`
- `pyproject.toml:43 -> Homepage = "https://github.com/joeyessak/phi-scan" -> Homepage = "https://github.com/phiscanhq/phi-scan"`
- `pyproject.toml:44 -> Repository = "https://github.com/joeyessak/phi-scan" -> Repository = "https://github.com/phiscanhq/phi-scan"`
- `pyproject.toml:45 -> Issues = "https://github.com/joeyessak/phi-scan/issues" -> Issues = "https://github.com/phiscanhq/phi-scan/issues"`
- `pyproject.toml:46 -> Changelog = "https://github.com/joeyessak/phi-scan/blob/main/CHANGELOG.md" -> Changelog = "https://github.com/phiscanhq/phi-scan/blob/main/CHANGELOG.md"`
- `.pre-commit-hooks.yaml:7 -> - repo: https://github.com/joeyessak/phi-scan -> - repo: https://github.com/phiscanhq/phi-scan`
- `.github/workflows/ci.yml:96 -> uses: joeyessak/phi-scan-action@<sha>  # v0.1.0 -> uses: phiscanhq/phi-scan-action@<sha>  # v0.1.0` *(SHA-pinned; redirect expected to work, but flip to canonical path)*
- `docs/ci-cd-integration.md:50 -> - repo: https://github.com/joeyessak/phi-scan -> - repo: https://github.com/phiscanhq/phi-scan`
- `docs/ci-cd-integration.md:73 -> - repo: https://github.com/joeyessak/phi-scan -> - repo: https://github.com/phiscanhq/phi-scan`
- `docs/troubleshooting.md:344 -> [github.com/joeyessak/phi-scan/issues](https://github.com/joeyessak/phi-scan/issues) -> [github.com/phiscanhq/phi-scan/issues](https://github.com/phiscanhq/phi-scan/issues)`
- `docs/supply-chain.md:239 -> gh release download v<version> --repo joeyessak/phi-scan -> gh release download v<version> --repo phiscanhq/phi-scan`
- `docs/supply-chain.md:246 -> --cert-identity "https://github.com/joeyessak/phi-scan/.github/workflows/release.yml@refs/tags/v<version>" -> --cert-identity "https://github.com/phiscanhq/phi-scan/.github/workflows/release.yml@refs/tags/v<version>"`

### 2.3 P2 — Cosmetic / historical

- `CONTRIBUTING.md:29 -> git clone https://github.com/joeyessak/phi-scan.git -> git clone https://github.com/phiscanhq/phi-scan.git`
- `CHANGELOG.md:102,111,173,174,175,176` — historical release entries
  and GitHub compare links. **Decision: retain old URLs in historical
  entries** to preserve truth of the record at release time; add a
  new changelog entry at migration time announcing the move and using
  the new URLs going forward.
- `ROADMAP.md:113,115,133,188` — forward-looking references. The 2.3
  fix PR SHOULD update `:113/:115/:133` to the new canonical paths;
  `:188` is the migration-intent line itself and will be updated after
  the migration completes.
- `docs/org-migration-checklist.md` — references `joeyessak/` are
  intentional (this is the migration runbook). Leave as-is.

### 2.4 Intentional references (no action)

- `docs/org-migration-checklist.md` (entire file)
- `docs/org-migration-preflight-report.md` (this document)

---

## 3. Current-state snapshot (§1.3)

Captured via `gh api` against `joeyessak/phi-scan` on 2026-04-18.
**No secret values were fetched or stored.**

### 3.1 Branch-protection ruleset

- **Ruleset id/name:** `14041817` / `Protect main`
- **Enforcement:** `active`
- **Target refs:** `refs/heads/main`
- **Rules:**
    - `deletion` (blocked)
    - `non_fast_forward` (blocked)
    - `pull_request` — `required_approving_review_count: 0`;
      `dismiss_stale_reviews_on_push: false`;
      `require_code_owner_review: false`;
      `require_last_push_approval: false`;
      `required_review_thread_resolution: false`;
      `allowed_merge_methods: [merge, squash, rebase]`
    - `required_status_checks` —
      `strict_required_status_checks_policy: false`;
      `do_not_enforce_on_create: false`;
      required: `Python 3.12 on ubuntu-latest` (integration_id `15368` = GitHub Actions)
- **Bypass actors:** none. `current_user_can_bypass: never`.

This matches the "Protect main" profile in §1.3 of the checklist.

### 3.2 Actions secrets (names only)

| Name | Purpose |
|------|---------|
| `ANTHROPIC_API_KEY` | AI review workflow |
| `PYPI_API_TOKEN` | Release publish (`UV_PUBLISH_TOKEN`) |

Total: 2. No org-level or environment-level secrets observed.

### 3.3 Actions variables

None (`total_count: 0`).

### 3.4 Environments

None (`total_count: 0`).

### 3.5 Webhooks

None.

### 3.6 Collaborators and teams

Only collaborator: `joeyessak` (admin). No teams. No `CODEOWNERS` file
(`CODEOWNERS` and `.github/CODEOWNERS` both absent). Nothing to update
on the owners side at transfer time beyond org membership.

### 3.7 Pages / deployment configuration

Not in use.

---

## 4. External dependency inventory (§1.4)

### 4.1 PyPI (public metadata only)

Source: `https://pypi.org/pypi/phi-scan/json` on 2026-04-18.

| Item | Value |
|------|-------|
| Project name | `phi-scan` |
| Latest version | `0.5.0` |
| Historical releases on PyPI | `0.3.0`, `0.5.0` |
| Maintainer email (metadata) | `joey.essak@gmail.com` |
| `Homepage` / `Repository` | `https://github.com/joeyessak/phi-scan` |
| `Issues` | `https://github.com/joeyessak/phi-scan/issues` |
| `Changelog` | `https://github.com/joeyessak/phi-scan/blob/main/CHANGELOG.md` |

Observation: the `project_urls` block on PyPI is baked into the
published wheels and cannot be updated for `0.5.0`. The next release
after `pyproject.toml` is flipped (§2.2) will carry the new URLs.
**2FA status** is not exposed on the public JSON endpoint and must be
confirmed by the maintainer out-of-band (maintainer-run check).

### 4.2 GHCR — **Deferred (post-migration hardening)**

> **Deferred — out-of-scope for migration-go.** PyPI is the only
> required distribution channel for the transfer. GHCR container
> publication is not a migration-go blocker. The commands below remain
> useful for the later post-migration hardening track but must not
> gate migration-go. See
> [`docs/org-migration-status.md`](org-migration-status.md).

- Current canonical image path per docs: `ghcr.io/joeyessak/phi-scan`.
- Live image manifest verification is deferred to the maintainer to
  avoid assuming authenticated `ghcr.io` context in this pre-flight.
  Commands the maintainer should run prior to transfer:

  ```bash
  # Requires ghcr authentication
  docker pull ghcr.io/joeyessak/phi-scan:latest
  docker inspect ghcr.io/joeyessak/phi-scan:latest --format '{{.RepoDigests}}'
  ```

### 4.3 Sigstore / OIDC subject (maintainer-run for verification)

- Current signing subject derived from OIDC claim issued to workflow
  runs: `repo:joeyessak/phi-scan:…`.
- Verification command per `docs/supply-chain.md` line 246. Note:
  `v0.5.0` was built before the S11 Sigstore signing step was added
  (PR #123, 2026-04-11) and therefore has no `.sigstore.json` bundle.
  This command must be run against the first release ≥ v0.6.0 whose
  workflow run executed the `Sign wheel and sdist with Sigstore (S11)`
  step and whose GitHub Release assets include the bundle:

  ```bash
  cosign verify-blob \
    --cert-identity "https://github.com/joeyessak/phi-scan/.github/workflows/release.yml@refs/tags/v<version>" \
    --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
    --bundle phi_scan-<version>-py3-none-any.whl.sigstore.json \
    phi_scan-<version>-py3-none-any.whl
  ```

- Post-transfer, re-verification MUST use the new subject
  (`repo:phiscanhq/phi-scan:…`) — see §2.4 of the checklist.

### 4.4 Downstream consumers

- `phi-scan-action` is referenced at `joeyessak/phi-scan-action@<sha>`
  in `.github/workflows/ci.yml:96`. SHA-pinned; GitHub redirect will
  resolve the action repo after its own transfer.
- Pre-commit users referencing `joeyessak/phi-scan` are expected to
  continue resolving via GitHub's repo-redirect. A smoke test of this
  is listed in §2.7 of the checklist.

---

## 5. Go / no-go readiness matrix

| # | Gate | Status | Notes |
|---|------|--------|-------|
| 1 | Repo clean (no open PRs, no in-flight runs, `main` green) | **READY** | §1 of this report |
| 2 | Hardcoded-reference sweep complete with plan | **READY** | §2; patch list in §2.2, cosmetic in §2.3; no P0 blockers |
| 3 | Branch-protection ruleset captured for re-creation | **READY** | §3.1 |
| 4 | Actions secrets enumerated | **READY** | §3.2 (2 secrets: `ANTHROPIC_API_KEY`, `PYPI_API_TOKEN`) |
| 5 | Variables / environments / webhooks enumerated | **READY** | §3.3–3.5 — all empty |
| 6 | Collaborators / teams / `CODEOWNERS` enumerated | **READY** | §3.6 — solo admin, no `CODEOWNERS` |
| 7 | PyPI owner + 2FA confirmed | **PENDING MAINTAINER** | Owner email confirmed via public API; 2FA status needs out-of-band check |
| 8 | GHCR manifest reachable and current | **DEFERRED** | Out-of-scope for migration-go — see [`docs/org-migration-status.md`](org-migration-status.md). Post-migration hardening only. |
| 9 | Sigstore bundle verifies under current subject | **DONE** | `v0.6.1` wheel + sdist verified 2026-04-15 via `cosign verify-blob` → `Verified OK`. Evidence in `docs/migration/maintainer-checklist.md §3`. |
| 10 | Draft migration notice prepared | **DONE** | [`docs/migration/communication-draft.md §1`](migration/communication-draft.md) |
| 11 | Draft release-notes entry prepared | **DONE** | [`docs/migration/communication-draft.md §2`](migration/communication-draft.md) |
| 12 | Migration ticket opened | **NOT STARTED** | §1.6 of checklist |
| 13 | Maintainer "migration go" approval | **NOT GIVEN** | §1.6 of checklist — requested after this report is merged |

**Overall:** No P0 blockers found. Six automated gates READY;
PyPI 2FA cleared 2026-04-14; the Sigstore gate is **pending-until-
signed-release** (bound to the first release ≥ v0.6.0 — see row 9 /
§4.3); GHCR is **deferred** as out-of-scope for migration-go;
drafts (rows 10, 11) are complete; the remaining operational tasks
(rows 12, 13) are executed during §1.5–§1.6 of the checklist. Live
status tracked in [`docs/org-migration-status.md`](org-migration-status.md).

---

## 6. Required post-transfer patch files

No edits are applied in this PR. After maintainer "migration go" and
completion of the GitHub transfer, a single follow-up PR should apply
the P1 list below verbatim. The P2 list may be folded into the same
PR or a subsequent docs-only PR at the maintainer's discretion.

- **P1 patch set** — see §2.2 of this report. 15 hunks across 9 files.
- **P2 patch set** — see §2.3 of this report. 5 entries in `CONTRIBUTING.md`
  (1) and `ROADMAP.md` (3 with one deferred). `CHANGELOG.md` historical
  entries are intentionally not rewritten.

---

## 7. Blockers (classification)

**None found at P0, P1, or P2.**

If any of the maintainer-run checks (go/no-go rows 7, 8, 9) surface a
problem, classify at discovery time:

- **P0** — signing or publish cannot proceed on the new org. Example:
  PyPI 2FA lockout, ghcr image cannot be pushed to the new org. Fix
  **before** initiating transfer.
- **P1** — signing or publish succeeds on the new org but downstream
  verification fails (e.g. `cosign verify-blob` fails against a fresh
  bundle). Fix within the 48-hour observation window; gate any
  release cut during that window.
- **P2** — cosmetic doc drift or historical-link rot. Fix in a
  follow-up docs PR.

No migration step should proceed until rows 1–9 of the readiness
matrix are all READY.

---

## 8. Out of scope for this pre-flight

- Any `phi-scan-action` repository internals (separate repo,
  separate pre-flight).
- `phi-scan-pro` — does not exist; explicitly excluded by checklist §
  Scope.
- Marketplace publication of the GitHub Action.
- Pro-tier feature work.

---

## 9. Next action

Pre-flight report merges first. Maintainer then gives explicit
"migration go" approval in writing (per §1.6 of the checklist) before
any transfer command is run.
