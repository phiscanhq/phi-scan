# Plugin API v1.1 — Suppressor Hook

This document defines the contract for third-party **suppressor**
plugins that register under the `phi_scan.suppressors` entry-point
group. It extends the v1.0 contract (`docs/plugin-api-v1.md`) with a
second hook type; the v1.0 recognizer contract is unchanged.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this
document are to be interpreted as described in
[RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

---

## API Version Contract

The host declares its suppressor API version as the string constant
`SUPPRESSOR_API_VERSION` (currently `"1.1"`).

Every suppressor plugin MUST declare the same version string on its
`plugin_api_version` class attribute. The loader enforces an **exact
match**: a mismatch causes the plugin to be skipped with a WARNING
and the scan continues without it.

```
Host: SUPPRESSOR_API_VERSION = "1.1"
Plugin: plugin_api_version = "1.1"   # exact match required
```

The v1.0 recognizer `PLUGIN_API_VERSION` and the v1.1 suppressor
`SUPPRESSOR_API_VERSION` are **independent** version axes. A
distribution may ship a v1.0 recognizer and a v1.1 suppressor in the
same package.

---

## Public Surface

Exported from `phi_scan.plugin_api`:

```python
from phi_scan.plugin_api import (
    SUPPRESSOR_API_VERSION,
    BaseSuppressor,
    SuppressDecision,
    SuppressorFindingView,
)
```

### `SuppressorFindingView`

Frozen dataclass passed to `evaluate` — a plugin-stable projection of
the host finding. Host-internal fields (`value_hash`, `code_context`,
`detection_layer`) are deliberately withheld so the API stays stable
across future host refactors.

| Field | Type | Description |
|-------|------|-------------|
| `entity_type` | `str` | Uppercase entity-type string of the finding. |
| `confidence` | `float` | Host-computed confidence in `[0.0, 1.0]`. |
| `line_number` | `int` | 1-indexed line number of the finding. |
| `file_path` | `pathlib.Path` | Path of the scanned file (language-gating + logging only). |
| `file_extension` | `str` | File extension including the leading dot; empty when absent. |

### `SuppressDecision`

Frozen dataclass returned by `evaluate`.

| Field | Type | Description |
|-------|------|-------------|
| `is_suppressed` | `bool` | `True` drops the finding before the confidence/severity gates. |
| `reason` | `str` | Short human-readable rationale. MUST NOT contain raw PHI. |

### `BaseSuppressor`

Abstract base class. Subclasses declare:

- `name` — lowercase snake_case identifier matching
  `[a-z][a-z0-9_]*`.
- `plugin_api_version` — must equal `SUPPRESSOR_API_VERSION`.
- `version`, `description` — informational.

The single abstract method:

```python
def evaluate(
    self,
    finding: SuppressorFindingView,
    line: str,
) -> SuppressDecision: ...
```

`line` is the full text of the source line containing the finding,
without the trailing newline. It is the empty string when the line
cannot be reconstructed.

---

## Pipeline Position

Suppressor plugins run in `_apply_post_scan_filters` between the
inline `phi-scan:ignore` filter and the confidence/severity
thresholds:

```
detection
   │
   ▼
inline `phi-scan:ignore` directives   (v0.3 — unchanged)
   │
   ▼
suppressor plugins                    (v1.1 — new)
   │
   ▼
confidence threshold
   │
   ▼
severity threshold
   │
   ▼
emitted findings
```

A finding dropped by a suppressor **never** reaches the
confidence/severity gates, the audit log, or any output formatter.

---

## Execution Order

Loaded suppressors are consulted in deterministic
`(distribution_name, entry_point_name)` order, identical to the
recognizer ordering rule in v1.0.

For each surviving finding the host iterates the suppressor list and
**short-circuits on the first `SuppressDecision` with
`is_suppressed=True`** — later suppressors are not consulted for that
finding.

---

## Isolation and Failure Semantics

Third-party suppressor code runs at a documented isolation boundary.
Any exception raised by `evaluate` is caught, logged at WARNING level
through a per-suppressor rate-limited budget (default: 5 per scan
plus one end-of-scan summary line), and the finding is treated as
**not suppressed by that plugin** for that one call. Other
suppressors and the surrounding scan proceed unaffected.
`BaseException` (`KeyboardInterrupt`, `SystemExit`) is deliberately
not caught.

A return value that is not an instance of `SuppressDecision` is
handled the same way: WARNING-logged, treated as pass-through.

This mirrors the recognizer-side boundary in
`phi_scan.plugin_runtime._invoke_detect_with_isolation`.

---

## Author Constraints

Plugin authors MUST NOT:

- Open, stat, or mutate `finding.file_path`.
- Send any data to a remote service.
- Mutate the passed `SuppressorFindingView` or `line` string.
- Include raw PHI in `SuppressDecision.reason`.

Plugin authors MAY:

- Gate on `finding.file_extension` to skip languages the suppressor
  does not understand.
- Consult `finding.entity_type` and `finding.confidence` to implement
  per-entity or per-confidence allowlists.

---

## Configuration

v1.1 ships with **no** user-facing configuration flag. All discovered
suppressors are loaded and executed. A `plugins.suppressors.enabled`
config key is reserved for a follow-up release; see
`docs/plugin-hooks-v1_1-backlog.md`.

---

## Minimal Example

```python
from phi_scan.plugin_api import (
    SUPPRESSOR_API_VERSION,
    BaseSuppressor,
    SuppressDecision,
    SuppressorFindingView,
)


class TestFixtureSuppressor(BaseSuppressor):
    """Suppress findings in files under test-fixture directories."""

    name = "test_fixture_suppressor"
    plugin_api_version = SUPPRESSOR_API_VERSION
    version = "0.1.0"
    description = "Drop findings in tests/fixtures/**."

    def evaluate(
        self,
        finding: SuppressorFindingView,
        line: str,
    ) -> SuppressDecision:
        is_fixture = "tests/fixtures" in str(finding.file_path)
        return SuppressDecision(
            is_suppressed=is_fixture,
            reason="file under tests/fixtures" if is_fixture else "not a fixture",
        )
```

Register it via the publishing distribution's `pyproject.toml`:

```toml
[project.entry-points."phi_scan.suppressors"]
test_fixture_suppressor = "my_package.suppressors:TestFixtureSuppressor"
```

Verify discovery:

```
$ phi-scan plugins list
```

The command prints a dedicated "Installed Suppressor Plugins" table
and, with `--json`, a top-level `suppressors` array alongside the
existing `plugins` array.

---

## Compatibility With v1.0

- v1.0 recognizer plugins are unaffected. A host that discovers zero
  suppressors behaves identically to the pre-v1.1 host.
- The v1.0 `phi_scan.plugins` entry-point group and
  `PLUGIN_API_VERSION = "1.0"` are unchanged.
- Existing `phi-scan plugins list` output for recognizers is
  preserved byte-for-byte when no suppressors are installed, apart
  from a new one-line "No suppressor plugins discovered." footer.
