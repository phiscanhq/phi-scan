# Release Cadence and Versioning Policy

This document defines how PhiScan versions are numbered, how often
releases are published, and what stability guarantees each release
type carries.

**Last updated:** 2026-04-16

---

## Versioning Scheme

PhiScan follows [Semantic Versioning 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH
```

| Component | Incremented when | Example |
|-----------|-----------------|---------|
| **MAJOR** | Incompatible changes to the public CLI interface, configuration schema, output format structure, or Plugin API stable surface | `1.0.0` → `2.0.0` |
| **MINOR** | New features, new detection categories, new output formats, new CLI commands, or Plugin API additions that are backwards-compatible | `1.0.0` → `1.1.0` |
| **PATCH** | Bug fixes, security patches, documentation corrections, dependency updates with no user-facing behavior change | `1.0.1` → `1.0.2` |

### Pre-release and Build Metadata

- Pre-release versions use the format `X.Y.Z-alpha.N` or `X.Y.Z-rc.N`.
- Pre-release versions are published to PyPI with the appropriate
  PEP 440 suffix (e.g. `1.1.0a1`, `1.1.0rc1`).
- Pre-release versions carry no stability guarantees and SHOULD NOT be
  used in production CI/CD pipelines.

---

## Release Cadence

| Release type | Target cadence | Trigger |
|-------------|---------------|---------|
| **Patch** | As needed (typically monthly) | Security vulnerability, bug fix, or dependency update |
| **Minor** | Target quarterly | Accumulated feature work, new detection categories, or Plugin API additions |
| **Major** | As needed (no fixed cadence) | Breaking changes that cannot be delivered as backwards-compatible additions |

### Cadence Commitments

- **Security patches** are released within 7 days of a confirmed
  vulnerability in PhiScan code or a direct dependency. This timeline
  applies to vulnerabilities rated HIGH or CRITICAL by the maintainers.
  MEDIUM and LOW vulnerabilities are addressed in the next scheduled
  patch or minor release.
- **Quarterly minor releases** are a target, not a guarantee. A minor
  release may be delayed if the feature set is incomplete or quality
  gates are not met. The project will not ship a minor release solely
  to meet a calendar deadline.
- **Major releases** are rare and planned well in advance. A major
  release is preceded by at least one release candidate (`X.0.0-rc.N`)
  published at least 30 days before the final release.

---

## What Constitutes a Breaking Change

The following are considered breaking changes and require a MAJOR
version increment:

| Surface | Breaking change example |
|---------|----------------------|
| CLI interface | Removing a command or flag, changing default behavior of an existing flag |
| Configuration schema | Removing a config key, changing the type or semantics of an existing key |
| Output formats | Changing the JSON schema, SARIF structure, or CSV column order of an existing format |
| Exit codes | Changing the meaning of exit code 0, 1, or 2 |
| Plugin API | Removing a stable export, changing `detect()` signature, renaming the entry-point group |

The following are NOT breaking changes:

| Surface | Non-breaking change example |
|---------|---------------------------|
| CLI interface | Adding a new command or flag with a sensible default |
| Configuration schema | Adding a new config key (unknown keys are ignored) |
| Output formats | Adding a new field to JSON output (consumers SHOULD ignore unknown fields) |
| Detection | Adding a new entity type or detection category (may produce new findings on existing code) |
| Plugin API | Adding a new export, adding a new optional attribute with a default value |

### New Findings as a Non-Breaking Change

Adding new detection categories or improving existing recognizers may
cause PhiScan to report findings that were not reported in a previous
version. This is explicitly NOT a breaking change. Teams that need
stable finding sets across upgrades SHOULD use baseline mode
(`--baseline`) to isolate new findings from previously accepted ones.

---

## Release Process

1. **Feature freeze**: all feature work for the release is merged to
   `main`. No new features are merged after the freeze.
2. **Release candidate** (minor/major only): a tagged RC is published
   to PyPI for community testing. The RC period lasts at least 7 days
   for minor releases and 30 days for major releases.
3. **Final release**: the RC is promoted to a final release if no
   blocking issues are found. The release is tagged in git, published
   to PyPI, and a GitHub Release is created with:
   - Wheel and sdist artifacts.
   - CycloneDX SBOM (`sbom.cyclonedx.json`).
   - Sigstore signature bundles (`.sigstore.json`).
4. **Release notes**: published on the GitHub Release page and in
   `CHANGELOG.md`. Notes include: new features, bug fixes, breaking
   changes (major only), deprecation notices, migration guidance, and
   security fixes.

---

## Deprecation Process

Deprecations within a MAJOR version line follow the policy defined in
[plugin-api-v1.md](plugin-api-v1.md):

- Deprecated features are announced in release notes with a migration
  path and the earliest removal version.
- Deprecated features emit `DeprecationWarning` at runtime.
- Deprecated features are maintained for a minimum of 2 minor releases
  after the announcement.
- Removal is documented in the release notes of the version that
  removes the feature.

This policy applies to all public surfaces: CLI flags, configuration
keys, output format fields, and Plugin API exports.

---

## Version History

| Date | Change |
|------|--------|
| 2026-04-16 | Initial release cadence and versioning policy for C5 scorecard check |
