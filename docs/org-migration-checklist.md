# Org Migration Checklist — `joeyessak/*` → `phiscanhq/*`

Status: **PLANNED — NOT STARTED.** No transfer actions are authorised
until every repo-pristine blocker is merged and the maintainer gives an
explicit "migration go" approval. This document is the operational
runbook for that future transfer.

Pre-flight execution is recorded in
[`docs/org-migration-preflight-report.md`](org-migration-preflight-report.md),
which captures the §1 snapshot, the hardcoded-reference sweep, the
external-dependency inventory, and the go/no-go readiness matrix.

Operational status (live) is tracked in
[`docs/org-migration-status.md`](org-migration-status.md). That page is
the single source of truth for "what is left before migration-go".

**GHCR scope:** PyPI is the only required distribution channel for
migration-go. GHCR container publication is deferred to a
post-migration hardening track and is **not a transfer blocker**. GHCR
items below are retained for post-migration reference and are marked
**Deferred**.

## Scope

- `joeyessak/phi-scan` → `phiscanhq/phi-scan`
- `joeyessak/phi-scan-action` → `phiscanhq/phi-scan-action`

Out of scope for this phase: `phi-scan-pro` (does not yet exist and is
explicitly excluded from this runbook).

## Transfer order

1. `phi-scan` first. Validate end-to-end (CI, release dry-run, PyPI token
   continuity, Sigstore signing, ghcr push) before moving to step 2.
2. `phi-scan-action` second. Its canonical reference paths depend on the
   post-migration state of `phi-scan`, so it moves after validation.

---

## 1. Pre-flight

Complete every item before initiating any transfer.

### 1.1 Repo cleanliness

- [ ] No open draft release or in-flight publish job on `joeyessak/phi-scan`.
- [ ] No open pull requests mid-merge; no in-progress CI runs.
- [ ] `main` is green on the most recent commit.
- [ ] Release branch (if any) is either merged or explicitly parked.

### 1.2 Hardcoded organisation references

Grep for hardcoded `joeyessak/` references that must be updated
post-transfer. Items here need a plan (update now, update post-transfer,
or rely on GitHub redirect) before proceeding.

- [ ] `.github/workflows/**/*.yml` — action refs, OIDC subjects, artifact
      URLs, `gh` CLI calls.
- [ ] `.github/scripts/**` — any scripted `joeyessak/` URLs.
- [ ] `docs/**/*.md` — install instructions, CI snippets, badge URLs.
- [ ] `README.md` — install instructions, badge URLs, action references.
- [ ] `pyproject.toml` — project URLs (`Homepage`, `Source`, `Issues`).
- [ ] `.pre-commit-hooks.yaml` and any consumer-facing
      `.pre-commit-config.yaml` example.
- [ ] ~~Docker image references in docs and workflows
      (`ghcr.io/joeyessak/phi-scan`).~~ **Deferred — post-migration
      hardening (out-of-scope for migration-go).**

Command reference (run locally, not blocking):

```bash
grep -rn "joeyessak" --include="*.md" --include="*.yml" --include="*.yaml" --include="*.toml" --include="*.py" .
```

### 1.3 Current-state snapshot

Capture the current configuration so it can be recreated exactly on the
new org.

- [ ] **Branch protection / rulesets** (current `joeyessak/phi-scan`):
    - Ruleset name: `Protect main`.
    - Rules enforced: `deletion` (blocked), `non_fast_forward` (blocked),
      `pull_request` (required; 0 approving reviews; merge/squash/rebase
      all allowed), `required_status_checks`
      (`Python 3.12 on ubuntu-latest`).
    - Capture UI screenshot and attach to migration ticket (do not paste
      raw JSON into this document).
- [ ] **Actions secrets** (current repo-level):
    - `ANTHROPIC_API_KEY` — AI review workflow.
    - `PYPI_API_TOKEN` — release publish workflow.
    - Document any additional org-level or environment-level secrets
      added after this snapshot.
- [ ] **Actions variables** — capture any non-secret variables in use.
- [ ] **Environments** — list names and protection rules, if any.
- [ ] **Webhooks** — enumerate destinations and events.
- [ ] **Collaborators and teams** — record current direct collaborators.
- [ ] **Pages / deployment configuration** — if in use.
- [ ] `CODEOWNERS` — confirm file accurately reflects reviewers; update
      any `@joeyessak` references if a team is preferred on the new org.

### 1.4 External dependency inventory

- [ ] PyPI project `phi-scan` — owner currently `joeyessak`; confirm
      maintainer email and 2FA status.
- [ ] ~~ghcr.io — current image path `ghcr.io/joeyessak/phi-scan`.~~
      **Deferred — post-migration hardening (out-of-scope for
      migration-go).**
- [ ] Sigstore signing — currently keyless OIDC with workload subject
      `repo:joeyessak/phi-scan:…`.
- [ ] `phi-scan-action` — consumers reference via `joeyessak/phi-scan-action@v1`.
- [ ] Downstream pre-commit users — reference `joeyessak/phi-scan`; redirect
      is expected to work.

### 1.5 Communication

- [ ] Draft (do not publish yet) a migration notice covering: new canonical
      paths, redirect continuity, action required by consumers (none
      expected), rollback window.
- [ ] Prepare release-notes entry for the next patch release announcing
      the move.

### 1.6 Go / no-go

- [ ] All pristine blockers merged.
- [ ] Maintainer has given explicit "migration go" approval in writing.
- [ ] Migration ticket tracks the checklist execution.

---

## 2. Transfer — `phi-scan`

### 2.1 Execute transfer

- [ ] Initiate GitHub repo transfer from `joeyessak/phi-scan` to
      `phiscanhq/phi-scan`.
- [ ] Accept transfer on the `phiscanhq` side.

### 2.2 Re-apply repo configuration

- [ ] Recreate the `Protect main` ruleset on the new repo with the same
      enforced rules (deletion blocked, non-fast-forward blocked, PR
      required with 0 approvals, required check `Python 3.12 on
      ubuntu-latest`). Verify the ruleset is `enforcement: active`.
- [ ] Recreate Actions secrets on `phiscanhq/phi-scan`:
    - [ ] `ANTHROPIC_API_KEY` — same value (rotate later if routine).
    - [ ] `PYPI_API_TOKEN` — see §2.3 for rotation policy.
- [ ] Recreate any Actions variables from the pre-flight snapshot.
- [ ] Recreate environments and their protection rules.
- [ ] Recreate webhooks.
- [ ] Reconfirm `CODEOWNERS` resolves on the new org (teams, if used,
      must exist on `phiscanhq`).

### 2.3 PyPI token rotation

Current publish model uses a repo Actions secret `PYPI_API_TOKEN`, read
by the release workflow as `UV_PUBLISH_TOKEN`. Transfer does NOT invalidate
the token, but the old token is scoped under the old organisational
identity and must be rotated.

- [ ] Generate a new PyPI API token scoped to the `phi-scan` project.
- [ ] Store the new token as `PYPI_API_TOKEN` on `phiscanhq/phi-scan`.
- [ ] Run a release dry-run (or a patch release to TestPyPI if configured)
      to confirm the new token works.
- [ ] Revoke the old token on PyPI once the new token is validated in a
      real publish.

### 2.4 Sigstore / OIDC workload identity

Release artifacts are signed keyless with Sigstore. The OIDC subject
encodes the repo path and will change at transfer time from
`repo:joeyessak/phi-scan:…` to `repo:phiscanhq/phi-scan:…`.

- [ ] Run the release workflow against a tagged pre-release (or a
      dry-run signing job) on the new repo.
- [ ] Download the produced `.sigstore.json` bundle.
- [ ] Verify the bundle: confirm the embedded certificate's OIDC subject
      is `repo:phiscanhq/phi-scan:…` and that `cosign verify-blob` (or
      `sigstore-python verify`) accepts the new subject.
- [ ] Update `docs/supply-chain.md` verification example to reference the
      new subject.

### 2.5 GHCR container continuity — **Deferred (post-migration hardening)**

> **Deferred — out-of-scope for migration-go.** GHCR container
> publication is not required for the PyPI-focused transfer. The steps
> below are retained for a later post-migration hardening PR and must
> not gate migration-go. See
> [`docs/org-migration-status.md`](org-migration-status.md).

- [ ] Build and push the image to `ghcr.io/phiscanhq/phi-scan` tagged
      with the current release version and `latest`.
- [ ] Keep `ghcr.io/joeyessak/phi-scan` in place for the observation
      window so existing pull commands succeed via redirect.
- [ ] Update docs and workflows that reference the image path to the
      new canonical path. Retain a one-line note pointing users to the
      new path.

### 2.6 Hardcoded reference sweep (round 2)

- [ ] Re-run the `joeyessak/` grep from §1.2 on the new repo.
- [ ] Open a small follow-up PR updating docs, badges, and workflow
      references to `phiscanhq/`. Rely on GitHub redirect for external
      consumers but clean up canonical documentation.

### 2.7 End-to-end validation

- [ ] CI passes on a no-op PR against the new `main`.
- [ ] Release workflow dry-run (or patch release) succeeds end-to-end:
      PyPI publish, SBOM generation, Sigstore signing, ghcr push.
- [ ] `pip install phi-scan==<version>` from PyPI works and matches the
      new SBOM.
- [ ] Sigstore bundle verification passes against the new OIDC subject.
- [ ] Third-party `.pre-commit-config.yaml` pinning `joeyessak/phi-scan`
      still resolves via redirect (manual smoke test).

---

## 3. Transfer — `phi-scan-action`

Execute only after §2.7 passes cleanly.

- [ ] Initiate and accept transfer `joeyessak/phi-scan-action` →
      `phiscanhq/phi-scan-action`.
- [ ] Recreate secrets, rulesets, and environments as in §2.2.
- [ ] Update canonical usage examples in docs and README to
      `phiscanhq/phi-scan-action@v1`.
- [ ] Publish a deprecation note on the old path (release notes +
      README banner) pointing consumers to the new canonical path.
      Redirect is expected to work; the note exists for trust and clarity.
- [ ] Smoke-test the action from a consumer workflow pinned to the new
      canonical path.

---

## 4. Post-flight

### 4.1 Announce

- [ ] Publish the migration notice drafted in §1.5 (release notes +
      repo README banner if desired).
- [ ] Update `docs/supply-chain.md` and any other operational docs to
      reference the new OIDC subject and image path.

### 4.2 Observation window — 48 hours

During the first 48 hours after `phi-scan` transfer:

- [ ] Freeze new releases unless required for an emergency fix. If an
      emergency release is cut, re-verify Sigstore subject and PyPI
      publish as a sentinel.
- [ ] Monitor issues for redirect failures, pre-commit resolution errors,
      or signing verification failures.
- [ ] Monitor CI on `main` daily.
- [ ] ~~Track ghcr pull counts on both old and new image paths to detect
      stale references.~~ **Deferred — GHCR is out-of-scope for
      migration-go; revisit in post-migration hardening.**

### 4.3 Cleanup (after 48h clean)

- [ ] Revoke old PyPI token (if not already done in §2.3).
- [ ] Close the migration ticket with a summary and post-mortem note.
- [ ] ~~Schedule removal of the legacy ghcr image path for a later minor
      release, with notice.~~ **Deferred — handled in post-migration
      hardening track.**

---

## 5. Rollback

If a critical break is detected within the 48-hour observation window
(CI broken on `main` with no forward-fix in sight, PyPI publish blocked,
Sigstore verification broken for released artifacts, or widespread
redirect failure), execute rollback:

### 5.1 Immediate freeze

- [ ] Freeze all releases on the new org.
- [ ] Post a brief incident notice on the repo indicating rollback is in
      progress.

### 5.2 Transfer back

- [ ] Transfer `phiscanhq/phi-scan` back to `joeyessak/phi-scan` via the
      GitHub transfer flow.
- [ ] If already transferred, transfer `phi-scan-action` back as well.
- [ ] Recreate rulesets, secrets, environments on the restored repo from
      the pre-flight snapshot (§1.3).

### 5.3 Artifact continuity during rollback

- [ ] Re-validate PyPI token on the restored repo; rotate if the new
      token was already published.
- [ ] Re-validate Sigstore subject reverts to
      `repo:joeyessak/phi-scan:…` for subsequent signing runs.
- [ ] ~~Revert ghcr image path in docs/workflows; keep any `phiscanhq/`
      images in place for historical access.~~ **Deferred — GHCR was
      out-of-scope for migration-go; no ghcr changes to revert.**

### 5.4 Post-rollback

- [ ] Open a post-mortem documenting root cause, blast radius, and
      remediation required before a second attempt.
- [ ] Update this checklist with any gaps identified.
- [ ] Maintainer explicitly re-approves any subsequent migration attempt.

---

## Appendix A — Reference snapshot

This appendix captures state as of the pre-flight date so that future
readers can verify the runbook against what existed at the time it was
written. Refresh this section immediately before execution.

| Item | Value (as of writing) |
|------|----------------------|
| Source org/repo | `joeyessak/phi-scan` |
| Target org/repo | `phiscanhq/phi-scan` |
| Secondary repo | `joeyessak/phi-scan-action` → `phiscanhq/phi-scan-action` |
| Ruleset name | `Protect main` |
| Required status check | `Python 3.12 on ubuntu-latest` |
| Actions secrets | `ANTHROPIC_API_KEY`, `PYPI_API_TOKEN` |
| PyPI project | `phi-scan` |
| Container image | `ghcr.io/joeyessak/phi-scan` → `ghcr.io/phiscanhq/phi-scan` *(Deferred — post-migration hardening)* |
| Sigstore OIDC subject | `repo:joeyessak/phi-scan:…` → `repo:phiscanhq/phi-scan:…` |
| Observation window | 48 hours post-transfer |
