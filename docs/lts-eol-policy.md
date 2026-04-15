# Long-Term Support (LTS) and End-of-Life (EOL) Policy

This document defines which PhiScan releases receive long-term
security support, how long that support lasts, and how end-of-life
transitions are communicated.

**Last updated:** 2026-04-16

---

## LTS Designation

Not every minor release is an LTS release. The maintainers designate
specific minor releases as LTS based on stability, feature
completeness, and community adoption.

| Property | LTS release | Standard release |
|----------|------------|-----------------|
| Security patches | 12 months from release date | Until the next minor release |
| Critical bug fixes | 12 months from release date | Until the next minor release |
| New features | No | Yes |
| Recommended for production | Yes | Yes (but LTS preferred for regulated environments) |

### LTS Selection Criteria

A minor release is designated as LTS when:

1. It has been stable for at least 30 days after the final release
   (no critical regressions reported).
2. All scorecard checks are passing at the time of designation.
3. The maintainers judge it suitable for long-term production use in
   regulated (HIPAA, HITRUST) environments.

LTS designation is announced in the GitHub Release notes and in
`CHANGELOG.md`. The announcement includes the support end date.

### LTS Support Scope

During the 12-month LTS window, the designated release line receives:

- **Security patches**: vulnerabilities in PhiScan code or direct
  dependencies, rated HIGH or CRITICAL, are backported within 7 days
  of confirmation. MEDIUM and LOW vulnerabilities are backported on a
  best-effort basis.
- **Critical bug fixes**: bugs that cause data loss, incorrect scan
  results (false negatives on known PHI patterns), or crashes on
  supported platforms are backported.
- **Dependency updates**: only security-driven dependency bumps are
  backported. Feature-driven dependency updates are not backported.

LTS releases do NOT receive:

- New features or detection categories.
- Performance improvements (unless they fix a critical regression).
- Support for new CI/CD platforms.
- Plugin API additions.

---

## Support Timeline

```
Release 1.2.0 (LTS)
  │
  ├─── Active support (0–12 months)
  │      Security patches, critical bug fixes
  │
  ├─── EOL notice issued (at 9 months, 90 days before EOL)
  │
  └─── End of life (12 months)
         No further patches; users must upgrade
```

### Overlap Between LTS Lines

When a new LTS release is designated, the previous LTS release
continues to receive support for the remainder of its 12-month window.
There is no early termination of an LTS line when a newer LTS is
designated.

Example timeline:

```
v1.2.0 LTS ──────────────────────────────────── EOL
              v1.4.0 LTS ─────────────────────────────── EOL
                            v2.0.0 LTS ─────────────────────── EOL
```

---

## End-of-Life (EOL) Process

1. **EOL notice** (90 days before): the maintainers publish a notice
   in the GitHub Release notes, `CHANGELOG.md`, and the project
   README (if the release is the current recommended version). The
   notice includes:
   - The exact EOL date.
   - The recommended upgrade target (typically the latest LTS).
   - A summary of breaking changes between the EOL release and the
     upgrade target.
   - A link to any migration guide.

2. **Final patch** (at or before EOL): a final patch release is
   published for the EOL line that includes all pending security
   backports. This is the last release on that line.

3. **EOL date**: after the EOL date, the release line receives no
   further patches, security or otherwise. The branch remains
   available in git history but is not maintained.

4. **PyPI availability**: EOL releases remain available on PyPI
   indefinitely. They are not yanked unless a critical security
   vulnerability with no workaround is discovered. Yanking is a last
   resort and is announced with at least 14 days notice.

---

## Current LTS Releases

| Release | LTS designated | Support ends | Status |
|---------|---------------|-------------|--------|
| *(none yet — first LTS will be designated after v1.0 stabilizes)* | — | — | — |

This table will be updated as LTS releases are designated.

---

## Supported Python Versions

Each PhiScan release declares its supported Python versions in
`pyproject.toml` (`requires-python`). The current minimum is
Python 3.12.

Python version support follows this policy:

- PhiScan supports all Python versions that are in active support
  (receiving security updates) per the
  [Python release schedule](https://devguide.python.org/versions/).
- When a Python version reaches end of life, PhiScan drops support
  in the next MINOR release. Dropping a Python version is a MINOR
  change, not a MAJOR change, because it does not affect the
  behavior of the tool for users on supported Python versions.
- LTS releases maintain their declared Python version support for the
  full 12-month LTS window, even if a Python version reaches EOL
  during that window.

---

## Deprecation Timelines

Public API deprecations that have a scheduled removal target are recorded
here so consumers can plan upgrades against a known horizon.

| Deprecated surface | Deprecated in | Removal target | Canonical replacement |
|--------------------|--------------|----------------|----------------------|
| Top-level `phi_scan.cli_*` compatibility shims (`cli_baseline`, `cli_config`, `cli_explain`, `cli_plugins`, `cli_report`, `cli_scan_config`, `cli_watch`) | v1.x (see `CHANGELOG.md` Unreleased) | **v2.0** | `phi_scan.cli.<name>` |

A runtime `DeprecationWarning` for the above shims is deferred to a
pre-v2.0 minor release so that v1.x consumers do not experience a
silent behavior change mid-series.

---

## Version History

| Date | Change |
|------|--------|
| 2026-04-16 | Initial LTS and EOL policy for C6 scorecard check |
| 2026-04-14 | Added deprecation timeline for `phi_scan.cli_*` shims (removal v2.0) |
