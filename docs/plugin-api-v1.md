# Plugin API v1 — Compatibility and Deprecation Policy

> **Suppressor plugins (v1.1):** the suppressor hook under the
> `phi_scan.suppressors` entry-point group is documented separately in
> [`plugin-api-v1_1.md`](plugin-api-v1_1.md). The recognizer contract
> below is unchanged.

This document defines the compatibility contract, deprecation rules, and
authoring constraints for third-party recognizer plugins that register
under the `phi_scan.plugins` entry-point group.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this
document are to be interpreted as described in
[RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

---

## API Version Contract

The host declares its plugin API version as the string constant
`PLUGIN_API_VERSION` (currently `"1.0"`).

Every recognizer plugin MUST declare the same version string on its
`plugin_api_version` class attribute. The loader enforces an **exact
match**: if the declared version does not equal the host version, the
plugin is skipped with a WARNING and the scan continues without it.

```
Host: PLUGIN_API_VERSION = "1.0"
Plugin: plugin_api_version = "1.0"   # exact match required
```

The exact-match rule is deliberate for v1. Semver-range negotiation MAY
be added in a future API version once the deprecation process described
below is in place.

---

## Compatibility Policy

### Stable v1 Surface

The following names are the stable public contract for the 1.x line.
They MUST NOT be removed, renamed, or have their signatures changed
in any 1.x release:

| Name | Module | Kind |
|------|--------|------|
| `BaseRecognizer` | `phi_scan.plugin_api` | Abstract base class |
| `ScanContext` | `phi_scan.plugin_api` | Frozen dataclass |
| `ScanFinding` | `phi_scan.plugin_api` | Frozen dataclass |
| `PLUGIN_API_VERSION` | `phi_scan.plugin_api` | String constant |

All four names are re-exported at the `phi_scan` package root for
convenience. Both import paths are supported and stable:

```python
# Either import path is stable across the 1.x line:
from phi_scan.plugin_api import BaseRecognizer, ScanContext, ScanFinding
from phi_scan import BaseRecognizer, ScanContext, ScanFinding
```

### Stable Entry-Point Group

Plugins register under the entry-point group `phi_scan.plugins`. This
group name MUST NOT change within the 1.x line.

### Internal / Private Surface

Any name prefixed with `_` (single underscore) is private and MAY
change without notice in any release. Plugin authors MUST NOT import
or depend on private names.

The following public names in `phi_scan.plugin_api` are implementation
details used by the loader. They are importable but are NOT part of the
stable plugin-author contract and MAY be relocated or renamed in a
future 1.x release:

- `RECOGNIZER_NAME_PATTERN`
- `ENTITY_TYPE_PATTERN`
- `MIN_CONFIDENCE_SCORE` / `MAX_CONFIDENCE_SCORE`
- `MIN_START_OFFSET`
- `MIN_LINE_NUMBER`

Plugin authors SHOULD NOT reference these constants directly. The
loader validates recognizer metadata; plugins do not need to duplicate
those checks.

---

## Deprecation Policy

When a stable v1 surface element is scheduled for removal or
incompatible change, the following process MUST be followed:

1. **Announce** the deprecation in release notes and in this document.
   The announcement MUST include the earliest version in which the
   removal will take effect and a migration path.

2. **Maintain** the deprecated element for a minimum of **2 minor
   releases** after the announcement. For example, if deprecation is
   announced in v1.3.0, the element MUST remain functional through
   v1.4.x and MUST NOT be removed before v1.5.0.

3. **Emit** a `DeprecationWarning` at runtime when the deprecated
   element is used, starting from the announcement release.

4. **Remove** the element no earlier than the version stated in the
   announcement. The removal MUST be documented in the release notes
   with a final migration reminder.

Breaking changes to the stable surface (removing `BaseRecognizer`,
changing `detect()` signature, renaming the entry-point group) MUST
NOT occur in any 1.x release. Such changes require a new major API
version (`PLUGIN_API_VERSION = "2.0"`) with its own compatibility
policy.

---

## Failure Semantics and Safety

### Invalid or Incompatible Plugins

A plugin that fails any validation check is **skipped with a WARNING**.
The scanner continues functioning with all remaining valid plugins. A
scan with zero valid plugins is indistinguishable from a scan with no
plugins installed — both produce an empty plugin list.

Validation checks that trigger skipping:

| Check | Reason |
|-------|--------|
| `plugin_api_version` does not match host | Version incompatibility |
| `name` missing or does not match pattern | Invalid metadata |
| `entity_types` missing, empty, or malformed | Invalid metadata |
| Entry-point target is not a `BaseRecognizer` subclass | Structural incompatibility |
| Entry-point import fails (`ImportError`, `AttributeError`) | Broken package metadata |
| Constructor raises an exception | Runtime failure |

### Name Collision Rule

Plugin names MUST be unique across all installed distributions. When
two plugins declare the same `name`, the loader applies a
**deterministic first-wins** rule: plugins are sorted by
`(distribution_name, entry_point_name)` and the first occurrence is
loaded. All subsequent duplicates are skipped with a WARNING that
identifies the collision.

### Constructor Error Safety

Plugin constructor exceptions are caught and converted to skip entries.
Only the exception **type name** is recorded in the skip reason — the
raw error message is intentionally dropped because a constructor MAY
have read values from the environment that could incidentally contain
PHI. `BaseException` subclasses (`SystemExit`, `KeyboardInterrupt`)
are NOT caught.

### Plugin Detection Exception Isolation (Runtime Carve-out)

Exceptions raised from `detect()` during a scan are caught at the
per-line plugin invocation boundary so that one faulty plugin cannot
abort the scan or starve other plugins of their chance to run. This is
the single designated exemption to the project-wide rule that bare
`Exception` MUST NOT be caught without re-raising.

The carve-out applies **only** under all of the following conditions:

1. **Single-invocation scope.** The `try`/`except` wraps exactly one
   call to third-party plugin code (one `recognizer.detect(...)`
   invocation against one line). It MUST NOT span multiple plugins,
   multiple lines, or any host logic.
2. **`BaseException` still propagates.** Only `Exception` is caught;
   `SystemExit`, `KeyboardInterrupt`, and other `BaseException`
   subclasses continue to abort the scan as normal.
3. **Warning is logged.** The exception type and message are recorded
   through the rate-limited `_RecognizerWarningBudget` so operators
   can diagnose misbehaving plugins without log spam.
4. **Inline justification.** The catch site carries
   `# noqa: BLE001` with a short comment pointing to the docstring
   that explains the isolation contract.
5. **Dedicated test coverage.** Tests MUST prove that (a) a raising
   plugin produces a warning instead of propagating, (b) the scan
   continues to completion, and (c) findings from other plugins on the
   same line are still emitted.

The canonical — and currently only — site is
`phi_scan.plugin_runtime._invoke_detect_with_isolation`. Any new
exemption site MUST be reviewed against the conditions above and
documented here.

---

## Authoring Constraints (v1)

### Required Class Attributes

Every `BaseRecognizer` subclass MUST declare:

| Attribute | Type | Constraint |
|-----------|------|------------|
| `name` | `str` | Matches `^[a-z][a-z0-9_]*$` (lowercase snake_case) |
| `entity_types` | `tuple[str, ...]` or `list[str]` | Non-empty; each element matches `^[A-Z][A-Z0-9_]*$`; no duplicates |
| `plugin_api_version` | `str` | Must equal host `PLUGIN_API_VERSION` (`"1.0"`) |

Optional attributes with defaults:

| Attribute | Type | Default |
|-----------|------|---------|
| `version` | `str` | `"0.0.0"` |
| `description` | `str` | `""` |

### Constructor

The host calls `RecognizerClass()` with **no arguments**. Plugin
constructors MUST accept zero positional or keyword arguments.

### `detect()` Method

```python
def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
    ...
```

- `line`: Full text of the line being scanned, without trailing newline.
- `context`: A `ScanContext` with `file_path`, `line_number`, and
  `file_extension`.
- Return a **freshly constructed** `list` of zero or more `ScanFinding`
  objects on every call. MUST NOT reuse a shared mutable list across
  invocations.
- Raising from `detect()` is permitted; the host catches the exception
  and drops findings for that line with a WARNING.

### `ScanFinding` Fields

| Field | Type | Constraint |
|-------|------|------------|
| `entity_type` | `str` | MUST appear in the recognizer's `entity_types` list |
| `start_offset` | `int` | 0-indexed column; MUST be >= 0 |
| `end_offset` | `int` | Exclusive; MUST be > `start_offset` |
| `confidence` | `float` | MUST be in [0.0, 1.0] |

The host derives severity and computes the value hash from the matched
line slice. Plugins MUST NOT attempt to set severity or include raw PHI
values in any `ScanFinding`.

### Prohibited Actions

Plugin authors MUST NOT:

- Open, read, stat, or follow symlinks at `context.file_path` — it is
  provided for language-gating and logging only. PhiScan never follows
  symlinks during directory traversal and plugins MUST NOT circumvent
  that guarantee.
- Include raw PHI values in any `ScanFinding` or log output.
- Send data to any remote service — PhiScan is an offline scanner and
  plugins inherit that guarantee.

---

## Minimal Plugin Example

### Recognizer Class

```python
from phi_scan import BaseRecognizer, PLUGIN_API_VERSION, ScanContext, ScanFinding

ENTITY_TYPE_INTERNAL_ID: str = "INTERNAL_ID"
MARKER_PREFIX: str = "PATIENT-"
SUFFIX_LENGTH: int = 6  # digits after the PATIENT- prefix
MATCH_CONFIDENCE: float = 0.9
PYTHON_EXTENSION: str = ".py"


class InternalIdRecognizer(BaseRecognizer):
    name = "internal_id"
    entity_types = [ENTITY_TYPE_INTERNAL_ID]
    plugin_api_version = PLUGIN_API_VERSION
    version = "0.1.0"
    description = "Detects internal patient identifiers."

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        if context.file_extension != PYTHON_EXTENSION:
            return []

        findings: list[ScanFinding] = []
        search_start = 0
        while True:
            position = line.find(MARKER_PREFIX, search_start)
            if position < 0:
                break
            match_end = position + len(MARKER_PREFIX) + SUFFIX_LENGTH
            # Guard: end_offset must not exceed the line length
            if match_end > len(line):
                search_start = position + 1
                continue
            findings.append(
                ScanFinding(
                    entity_type=ENTITY_TYPE_INTERNAL_ID,
                    start_offset=position,
                    end_offset=match_end,
                    confidence=MATCH_CONFIDENCE,
                )
            )
            search_start = position + 1
        return findings
```

### Entry-Point Registration (`pyproject.toml`)

```toml
[project.entry-points."phi_scan.plugins"]
internal_id = "my_package.recognizers:InternalIdRecognizer"
```

### Verify Installation

```bash
phi-scan plugins list
```

The recognizer appears as `loaded` if metadata is valid, or
`skipped-invalid` with a reason if any check fails.

---

## Inspecting Installed Plugins

The `phi-scan plugins list` command discovers all installed recognizer
plugins and displays their status:

```bash
# Rich table (default)
phi-scan plugins list

# Machine-readable JSON
phi-scan plugins list --json
```

Loaded plugins display name, version, API version, entity types, and
a `loaded` status. Skipped plugins display the entry-point name and
the validation failure reason.

---

## Version History

| API Version | Host Version | Status |
|-------------|-------------|--------|
| `1.0` | v0.5.0+ | **Current** — exact match enforced |
