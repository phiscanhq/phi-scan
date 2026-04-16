# Post-Transfer Canonical Patch Pack (draft)

**Purpose.** One deterministic list of every hardcoded `joeyessak/*`
reference that must flip to `phiscanhq/*` **after** the GitHub
repository transfer completes. This file is a runbook artifact only:
no edits below are applied on `main` pre-transfer. GitHub redirects
from the old owner will keep everything functional during the 48-hour
observation window; the patch pack is the planned cleanup PR that
runs inside that window.

**Applied when.** After `docs/org-migration-checklist.md §2.7`
("transfer complete") passes and the smoke tests in §2.8 succeed.
Not before.

**Not in scope (explicit carve-outs).**
- **GHCR image paths** — `ghcr.io/joeyessak/phi-scan` is
  **deferred** to the post-migration hardening track; no flips in
  this pack. See [`docs/org-migration-status.md`](../org-migration-status.md)
  "Scope decision — GHCR deferred".
- **Historical CHANGELOG entries** — bullets under released-version
  sections (e.g. `## [0.5.0]`) that describe the URLs published *at
  that version* remain unchanged. Flipping them would rewrite
  release history.
- **Migration runbook docs** (`docs/org-migration-*`,
  `docs/migration/*`) — these deliberately record both sides of the
  flip; they are reclassified (not rewritten) in the closeout PR
  under `docs/org-migration-checklist.md §4`.
- **Sigstore OIDC subject flip in `docs/supply-chain.md`** — the
  documented `--cert-identity` URL flips to the new org for
  releases cut **after** transfer, but bundles signed before
  transfer still verify against `repo:joeyessak/phi-scan:…`. The
  patch below annotates this explicitly rather than a blind flip.
- **Version pins (`rev: v0.5.0`) in README and docs** — orthogonal
  to the owner flip; tracked separately against the next release
  publish.

---

## 1. Project metadata — `pyproject.toml`

| Line | Current | Replacement |
|------|---------|-------------|
| 43 | `Homepage = "https://github.com/joeyessak/phi-scan"` | `Homepage = "https://github.com/phiscanhq/phi-scan"` |
| 44 | `Repository = "https://github.com/joeyessak/phi-scan"` | `Repository = "https://github.com/phiscanhq/phi-scan"` |
| 45 | `Issues = "https://github.com/joeyessak/phi-scan/issues"` | `Issues = "https://github.com/phiscanhq/phi-scan/issues"` |
| 46 | `Changelog = "https://github.com/joeyessak/phi-scan/blob/main/CHANGELOG.md"` | `Changelog = "https://github.com/phiscanhq/phi-scan/blob/main/CHANGELOG.md"` |

Rebuild + re-lock after edit:

```bash
uv sync
```

---

## 2. README badges and links — `README.md`

| Line | Current | Replacement |
|------|---------|-------------|
| 6 | `[![CI](https://github.com/joeyessak/phi-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/joeyessak/phi-scan/actions/workflows/ci.yml)` | `[![CI](https://github.com/phiscanhq/phi-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/phiscanhq/phi-scan/actions/workflows/ci.yml)` |
| 229 | `  - repo: https://github.com/joeyessak/phi-scan` (pre-commit block) | `  - repo: https://github.com/phiscanhq/phi-scan` |
| 266 | `> **GitHub Action:** The [`phi-scan-action`](https://github.com/joeyessak/phi-scan-action) …` | `> **GitHub Action:** The [`phi-scan-action`](https://github.com/phiscanhq/phi-scan-action) …` |

---

## 3. Workflow `uses:` references — `.github/workflows/`

| File | Line | Current | Replacement |
|------|------|---------|-------------|
| `ci.yml` | 96 | `uses: joeyessak/phi-scan-action@b17418799d4cf730cf57676b49d4828a579930ed  # v0.1.0` | `uses: phiscanhq/phi-scan-action@b17418799d4cf730cf57676b49d4828a579930ed  # v0.1.0` |

`release.yml` and `claude-review.yml` contain no `joeyessak/*`
references (verified by grep) and need no changes.

**Note on the action path.** This flip depends on
`docs/org-migration-checklist.md §3` (transfer of
`joeyessak/phi-scan-action` → `phiscanhq/phi-scan-action`) also
having completed. Apply this line change only after the action repo
transfer is confirmed.

---

## 4. Pre-commit hooks metadata — `.pre-commit-hooks.yaml`

| Line | Current | Replacement |
|------|---------|-------------|
| 7 | `#     - repo: https://github.com/joeyessak/phi-scan` (doc comment) | `#     - repo: https://github.com/phiscanhq/phi-scan` |

---

## 5. Contributor guide — `CONTRIBUTING.md`

| Line | Current | Replacement |
|------|---------|-------------|
| 29 | `git clone https://github.com/joeyessak/phi-scan.git` | `git clone https://github.com/phiscanhq/phi-scan.git` |

---

## 6. CI/CD integration docs — `docs/ci-cd-integration.md`

| Line | Current | Replacement |
|------|---------|-------------|
| 50 | `  - repo: https://github.com/joeyessak/phi-scan` (pre-commit sample) | `  - repo: https://github.com/phiscanhq/phi-scan` |
| 73 | `  - repo: https://github.com/joeyessak/phi-scan` (second pre-commit sample) | `  - repo: https://github.com/phiscanhq/phi-scan` |

---

## 7. Supply-chain docs — `docs/supply-chain.md`

| Line | Current | Replacement | Notes |
|------|---------|-------------|-------|
| 239 | `gh release download v<version> --repo joeyessak/phi-scan \` | `gh release download v<version> --repo phiscanhq/phi-scan \` | Flip for releases cut **after** transfer |
| 246 | `    --cert-identity "https://github.com/joeyessak/phi-scan/.github/workflows/release.yml@refs/tags/v<version>" \` | `    --cert-identity "https://github.com/phiscanhq/phi-scan/.github/workflows/release.yml@refs/tags/v<version>" \` | **Subject pinning: verifying a pre-transfer signed bundle still requires the old `repo:joeyessak/phi-scan:…` identity.** Add an inline note in the same block explaining that releases ≤ the transfer cutover verify under the old subject and releases > cutover verify under the new. |

Suggested additional prose block to add above the flipped command
(not a single-line replacement, so apply by hand):

```
> Sigstore bundles signed before the repository transfer verify under
> `repo:joeyessak/phi-scan:…`; bundles signed after transfer verify
> under `repo:phiscanhq/phi-scan:…`. Use the identity that matches the
> release tag you are verifying.
```

---

## 8. Troubleshooting — `docs/troubleshooting.md`

| Line | Current | Replacement |
|------|---------|-------------|
| 344 | `[github.com/joeyessak/phi-scan/issues](https://github.com/joeyessak/phi-scan/issues)` | `[github.com/phiscanhq/phi-scan/issues](https://github.com/phiscanhq/phi-scan/issues)` |

---

## 9. Roadmap — `ROADMAP.md`

| Line | Current | Replacement |
|------|---------|-------------|
| 113 | `- \`joeyessak/phi-scan-action\` composite action — one-liner GitHub CI/CD integration` | `- \`phiscanhq/phi-scan-action\` composite action — one-liner GitHub CI/CD integration` |
| 133 | `> [\`phi-scan-action\`](https://github.com/joeyessak/phi-scan-action) is deferred` | `> [\`phi-scan-action\`](https://github.com/phiscanhq/phi-scan-action) is deferred` |

| Line | Current | Leave as-is |
|------|---------|--------------|
| 115 | ``- Multi-arch Docker image (`ghcr.io/joeyessak/phi-scan`, amd64/arm64)`` | Leave — GHCR deferred per §0 |
| 188 | `- Organisation migration from \`joeyessak/*\` to \`phiscanhq/*\` — planned,` | Leave pre-transfer; the closeout PR (post-48h observation) reclassifies this bullet to historical. |

---

## 10. CHANGELOG link references — `CHANGELOG.md`

The compare-URL footer at the bottom of the file is rewritten; the
release-note bullets under `[0.5.0]` describing `ghcr.io/joeyessak/…`
and the `joeyessak/phi-scan-action` composite action are historical
and **not flipped**.

| Line | Current | Replacement |
|------|---------|-------------|
| 213 | `[Unreleased]: https://github.com/joeyessak/phi-scan/compare/v0.5.0...HEAD` | `[Unreleased]: https://github.com/phiscanhq/phi-scan/compare/v0.5.0...HEAD` (update the base tag to whatever is current at apply time) |
| 214 | `[0.5.0]: https://github.com/joeyessak/phi-scan/compare/v0.3.0...v0.5.0` | `[0.5.0]: https://github.com/phiscanhq/phi-scan/compare/v0.3.0...v0.5.0` |
| 215 | `[0.3.0]: https://github.com/joeyessak/phi-scan/compare/v0.1.0...v0.3.0` | `[0.3.0]: https://github.com/phiscanhq/phi-scan/compare/v0.1.0...v0.3.0` |
| 216 | `[0.1.0]: https://github.com/joeyessak/phi-scan/releases/tag/v0.1.0` | `[0.1.0]: https://github.com/phiscanhq/phi-scan/releases/tag/v0.1.0` |

| Line | Current | Leave as-is |
|------|---------|--------------|
| 142 | `- **Docker image:** \`ghcr.io/joeyessak/phi-scan\` …` under `## [0.5.0]` | Historical — release-time URL |
| 151 | `- **GitHub Action:** \`joeyessak/phi-scan-action\` …` under `## [0.5.0]` | Historical — release-time URL |

If a new release (e.g. `v0.6.0`) is cut between the transfer and the
apply time, update its compare URL entry identically.

---

## 11. Apply-in-one-PR checklist

The post-transfer cleanup PR is a single squash commit. Suggested
title:

```
docs(transfer): flip canonical URLs from joeyessak/* to phiscanhq/*
```

Steps inside the PR:

1. Apply every replacement in §§ 1–10 above as written.
2. Leave all rows explicitly marked "Leave as-is".
3. Run:

   ```bash
   uv run ruff check .
   uv run mypy phi_scan
   uv run pytest -q
   ```

4. Verify no unintended `joeyessak` residue:

   ```bash
   grep -rn "joeyessak" \
     --include="*.md" --include="*.yml" --include="*.yaml" \
     --include="*.toml" --include="*.py" \
     --exclude-dir=docs/migration --exclude-dir=docs/org-migration* \
     --exclude=CHANGELOG.md \
     .
   ```

   Expected hits after the flip: **zero**. Any remaining hits in the
   excluded paths must be walked manually in the closeout PR
   (`docs/org-migration-checklist.md §4`).

5. Run the smoke from `docs/org-migration-checklist.md §2.8` to
   confirm the flipped URLs resolve.

6. Open PR against the new canonical repo
   (`phiscanhq/phi-scan`) — redirects from the old path work for
   pushes but the PR UI should live under the new org.

---

## 12. Acceptance criteria for this patch pack (pre-apply review)

- [ ] Every `joeyessak/*` hit found by the §11 grep command has a
      corresponding row above — either a **Replacement** or an
      explicit **Leave as-is** with a reason.
- [ ] GHCR paths carry no replacement rows (deferred scope).
- [ ] Historical CHANGELOG bullets under released-version sections
      carry no replacement rows.
- [ ] `docs/supply-chain.md §7` adds the dual-subject note, not just
      a blind URL swap.
- [ ] The `phi-scan-action` `uses:` flip in §3 is explicitly gated
      on the action-repo transfer (`docs/org-migration-checklist.md §3`).
