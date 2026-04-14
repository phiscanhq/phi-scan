# Migration Communication Drafts

Drafts only — **do not publish** until the transfer has completed and the
48-hour observation window described in `docs/org-migration-checklist.md`
§4.2 has started.

---

## 1. Migration notice (README banner + release notes prelude)

```
> **Notice — repository moved.** `phi-scan` has transferred from
> `github.com/joeyessak/phi-scan` to `github.com/phiscanhq/phi-scan`.
> GitHub redirects from the old path continue to work, but the new
> canonical URL is https://github.com/phiscanhq/phi-scan.
>
> No action is required by existing users. `pip install phi-scan` still
> installs the same package from PyPI. Container image publication to
> the new canonical path is handled separately as a post-migration
> hardening step and is not part of this transfer; existing
> `ghcr.io/joeyessak/phi-scan` tags remain resolvable.
>
> If you sign-verify releases with Sigstore / cosign, update the
> `--cert-identity` flag from
> `https://github.com/joeyessak/phi-scan/.github/workflows/release.yml@refs/tags/v<version>`
> to
> `https://github.com/phiscanhq/phi-scan/.github/workflows/release.yml@refs/tags/v<version>`
> for releases cut after the transfer date.
```

---

## 2. Release-notes entry (next patch release after transfer)

```markdown
## Repository migration — `joeyessak/phi-scan` → `phiscanhq/phi-scan`

This release is the first one cut from the `phiscanhq/phi-scan` repository.
Installation, pinning, and pre-commit behaviour are unchanged. Sigstore
verification commands must reference the new OIDC subject
`repo:phiscanhq/phi-scan:…` for releases from this version onward; the
published `docs/supply-chain.md` example command has been updated.

Old GitHub URLs redirect automatically. Container image publication to
the new canonical path is deferred to a post-migration hardening track
and is not part of this release; `ghcr.io/joeyessak/phi-scan` remains
resolvable.
```

---

## 3. `phi-scan-action` consumer notice

For the separately transferred `phi-scan-action` repository, once §3 of the
runbook completes:

```markdown
### Action path change

The canonical path for the PhiScan GitHub Action is now
`phiscanhq/phi-scan-action@v1`. Existing workflow pins that reference
`joeyessak/phi-scan-action@<ref>` continue to resolve through GitHub's
redirect, but updating the `uses:` line to the new canonical path is
recommended for clarity.
```

---

## 4. Rollback notice template

**Only publish if §5 of the runbook is executed (critical break within
the 48-hour window).**

```markdown
### Migration rolled back

An issue detected during the post-migration observation window has been
rolled back. The canonical repository is temporarily
`github.com/joeyessak/phi-scan` again while the root cause is
investigated. Existing installations, workflow pins, and container tags
continue to resolve. A post-mortem will be published before any second
migration attempt.
```
