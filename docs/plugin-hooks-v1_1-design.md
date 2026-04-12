# Plugin Hooks v1.1 — Suppressor and Output Sink Design

Status: **DRAFT** — design document for discussion. No implementation yet.

This document describes two new plugin extension points planned for
Plugin API v1.1: **suppressors** (filter findings before output) and
**output sinks** (consume finalized findings for external delivery).
Neither hook exists in v1.0. Both are additive — existing v1.0
recognizer plugins will continue to work unchanged.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this
document are to be interpreted as described in
[RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

---

## Motivation

PhiScan v1.0 ships three built-in escape hatches for false positives:

1. `# phi-scan:ignore` inline comments.
2. `.phi-scanignore` file-level exclusions.
3. Baseline mode (`--baseline`).

These cover the common cases, but teams with domain-specific suppression
logic (e.g. "findings inside `test_fixtures/` with confidence below 0.6
are always false positives") cannot express that today without forking
the scanner. Similarly, teams that need to push findings to a
ticketing system, SIEM, or dashboard must parse the output formats
themselves.

Suppressors and output sinks solve these two problems as first-class
plugin hooks.

---

## Execution Pipeline

The current v1.0 pipeline and the proposed v1.1 additions:

```
  Files
    │
    ▼
  ┌──────────────────────┐
  │  Recognizer plugins   │  ← v1.0 (BaseRecognizer.detect)
  │  + built-in layers    │
  └──────────┬───────────┘
             │ raw findings
             ▼
  ┌──────────────────────┐
  │  Suppressor plugins   │  ← v1.1 NEW
  │  (BaseSuppressor)     │
  └──────────┬───────────┘
             │ filtered findings
             ▼
  ┌──────────────────────┐
  │  Severity / scoring   │  (host-internal)
  └──────────┬───────────┘
             │ scored findings
             ▼
  ┌──────────────────────┐
  │  Built-in formatters  │  (JSON, SARIF, CSV, …)
  │  + Output sink plugins│  ← v1.1 NEW
  │  (BaseOutputSink)     │
  └──────────────────────┘
```

### Ordering Guarantees

1. **Recognizers** run first. All built-in detection layers and all
   loaded `BaseRecognizer` plugins execute before any suppressor is
   consulted.
2. **Suppressors** run in deterministic order: sorted by
   `(distribution_name, entry_point_name)`, same as recognizers. Each
   suppressor sees the output of the previous one (pipeline, not
   fan-out). A finding removed by an earlier suppressor is not visible
   to later suppressors.
3. **Output sinks** run after severity scoring and built-in formatting.
   Sinks receive the final, immutable finding list. Sink execution order
   is deterministic (same sort key) but sinks MUST NOT depend on
   execution order — they receive the same input and MUST NOT mutate it.

---

## `BaseSuppressor` — Draft Interface

```python
from phi_scan.plugin_api import ScanContext, ScanFinding

class SuppressDecision:
    """Returned by a suppressor for each finding."""
    # True  → suppress (drop the finding from results)
    # False → keep (finding passes through unchanged)
    is_suppressed: bool
    reason: str  # human-readable, logged at DEBUG level

class BaseSuppressor(ABC):
    """Abstract base class for suppressor plugins."""

    name: str                          # same naming rules as BaseRecognizer
    plugin_api_version: str = PLUGIN_API_VERSION
    version: str = "0.0.0"
    description: str = ""

    @abstractmethod
    def evaluate(
        self, finding: ScanFinding, context: ScanContext, line: str,
    ) -> SuppressDecision:
        """Decide whether to suppress a single finding.

        Args:
            finding: The candidate finding to evaluate.
            context: Same ScanContext the recognizer received.
            line: The full text of the line (without trailing newline).

        Returns:
            A SuppressDecision indicating whether to suppress.
        """
```

### Design Decisions

| Decision | Rationale |
|----------|-----------|
| Per-finding evaluation (not batch) | Keeps the interface simple and stateless. Batch filtering can be layered on top via internal buffering in a future API version if profiling shows a need. |
| `SuppressDecision` dataclass (not bare `bool`) | Captures the reason for audit-trail logging. A suppressed finding with no reason is hard to debug in compliance reviews. |
| Receives `line` text | Suppressors MAY need linguistic context (e.g. "this line is a comment in language X"). Passing the line avoids suppressors reading the file directly, preserving the no-file-access contract. |
| No access to other findings | Suppressors see one finding at a time. Cross-finding correlation (e.g. "suppress if another finding on the same line has higher confidence") is intentionally out of scope for v1.1. |

### Prohibited Actions

Suppressor plugins inherit all prohibitions from `BaseRecognizer`
plugins (see `docs/plugin-api-v1.md`):

- MUST NOT open, read, or stat files at `context.file_path`.
- MUST NOT include raw PHI values in `SuppressDecision.reason` or log
  output.
- MUST NOT send data to any remote service.

### Constructor

Same as recognizers: `SuppressorClass()` with **no arguments**.

---

## `BaseOutputSink` — Draft Interface

```python
from pathlib import Path
from phi_scan.plugin_api import ScanFinding, ScanContext

@dataclass(frozen=True)
class FinalizedFinding:
    """A scored, post-suppression finding delivered to output sinks."""
    finding: ScanFinding
    context: ScanContext
    severity: str          # "info" | "low" | "medium" | "high"
    value_hash: str        # SHA-256 hex digest — never raw PHI

class BaseOutputSink(ABC):
    """Abstract base class for output sink plugins."""

    name: str
    plugin_api_version: str = PLUGIN_API_VERSION
    version: str = "0.0.0"
    description: str = ""

    @abstractmethod
    def deliver(
        self,
        findings: Sequence[FinalizedFinding],
        scan_root: Path,
    ) -> None:
        """Deliver the finalized finding set to an external destination.

        Args:
            findings: Immutable sequence of all findings that survived
                suppression and met the confidence/severity thresholds.
                Plugins MUST NOT mutate this sequence.
            scan_root: The root directory that was scanned. Plugins MAY
                use this to compute relative paths for display.

        Raises:
            Any exception raised is caught by the host and logged at
            WARNING level. A failing sink does not affect other sinks
            or the scan exit code.
        """
```

### Design Decisions

| Decision | Rationale |
|----------|-----------|
| `FinalizedFinding` wrapper | Exposes severity and value_hash (both host-computed) without leaking internal `Finding` model fields. Plugins never see raw PHI — only the hash. |
| `deliver()` receives full batch | Output sinks typically need the complete finding set (to POST a summary, write a file, update a dashboard). Per-finding delivery would force plugins to buffer internally. |
| `scan_root` argument | Sinks that generate reports need to compute relative paths. Passing the root avoids sinks guessing or reading config. |
| Failure isolation | A broken sink MUST NOT block the scan or suppress built-in output. The host catches `Exception` (not `BaseException`) and logs a WARNING. |

### PHI Safety

Output sinks receive `FinalizedFinding` objects that contain:

- `value_hash` (SHA-256 hex) — **never** raw PHI.
- `context.file_path` — the file path, which is metadata, not PHI.
- `finding.start_offset` / `finding.end_offset` — column offsets only.
- `severity` — a classification label.

Sinks MUST NOT attempt to reconstruct the original PHI value from the
hash or from the file path + offsets. The host does not pass the line
text to sinks — this is a deliberate omission to prevent accidental PHI
exfiltration by a sink that forwards findings to a remote service.

### Remote Communication

Unlike recognizers and suppressors, output sinks MAY communicate with
remote services (that is their purpose). However:

- Sinks MUST NOT include raw PHI in any outbound payload. The
  `FinalizedFinding` contract enforces this by design: no line text,
  no raw values.
- Sinks SHOULD document which remote service they communicate with and
  what data they send.
- Sinks SHOULD respect `HTTPS_PROXY` / `HTTP_PROXY` environment
  variables.

---

## Entry-Point Groups

| Hook type | Entry-point group | API version |
|-----------|-------------------|-------------|
| Recognizer | `phi_scan.plugins` | `1.0` (current) |
| Suppressor | `phi_scan.suppressors` | `1.1` (planned) |
| Output sink | `phi_scan.output_sinks` | `1.1` (planned) |

Each hook type uses a separate entry-point group to avoid ambiguity in
the loader. A single distribution MAY register plugins in all three
groups.

---

## Performance Budget

| Hook | Budget per invocation | Rationale |
|------|----------------------|-----------|
| `BaseSuppressor.evaluate()` | < 1 ms per finding | Called once per finding per suppressor. At 10,000 findings × 3 suppressors = 30,000 calls. Budget prevents suppressors from dominating scan time. |
| `BaseOutputSink.deliver()` | < 30 s total | Called once per scan with the full batch. Network I/O is expected; 30 s accommodates slow endpoints without blocking the CLI indefinitely. |

The host MAY enforce these budgets via timeouts in a future release.
v1.1 will document the budgets as SHOULD-level guidance; enforcement
is deferred to v1.2 pending real-world profiling data.

---

## Configuration Shape

Suppressors and output sinks will be configurable in `.phi-scanner.yml`:

```yaml
version: 1

plugins:
  suppressors:
    enabled: true                   # default: true
    # Per-suppressor overrides:
    # my_custom_suppressor:
    #   enabled: false

  output_sinks:
    enabled: true                   # default: true
    # Per-sink overrides:
    # jira_sink:
    #   enabled: false
```

The `plugins` key is new in v1.1. Unrecognized keys under `plugins`
are ignored with a WARNING (forward-compatibility).

---

## Discovery and Validation

Suppressor and output sink discovery follows the same pattern as
recognizer discovery:

1. Enumerate entry points in the relevant group.
2. Sort deterministically by `(distribution_name, entry_point_name)`.
3. Validate class attributes (name, plugin_api_version, entity_types
   where applicable).
4. Instantiate with no arguments.
5. Skip with WARNING on any validation or instantiation failure.

The `PluginRegistry` dataclass will be extended with `suppressors` and
`output_sinks` tuples. The `phi-scan plugins list` command will display
all three hook types.

---

## Migration and Compatibility

- v1.1 is a **pure addition** to v1.0. No existing recognizer plugins
  need changes.
- `PLUGIN_API_VERSION` remains `"1.0"` for recognizer plugins. A new
  constant `SUPPRESSOR_API_VERSION = "1.1"` and
  `OUTPUT_SINK_API_VERSION = "1.1"` will be introduced for the new
  hook types.
- The `docs/plugin-api-v1.md` compatibility surface (4 stable exports +
  entry-point group) is unaffected. New exports for v1.1 will be
  documented in a separate `docs/plugin-api-v1_1.md` addendum.
- The 2-minor-release deprecation policy from `docs/plugin-api-v1.md`
  applies to all v1.1 additions once they ship.

---

## Open Questions

| # | Question | Leaning | Status |
|---|----------|---------|--------|
| 1 | Should suppressors receive the full `Finding` (internal model) or only `ScanFinding` (plugin API model)? | `ScanFinding` — keeps the plugin surface minimal and avoids coupling to internal fields. | Tentative |
| 2 | Should output sinks receive line text for context-rich reporting? | No — PHI safety outweighs convenience. Sinks that need context can read the file themselves (they already have `file_path` + offsets). | Tentative |
| 3 | Should suppressor ordering be configurable? | Deferred to v1.2. Deterministic sort is sufficient for v1.1. | Deferred |
| 4 | Should the host enforce performance budgets via hard timeouts? | Deferred to v1.2 pending profiling data. v1.1 documents budgets as guidance. | Deferred |
| 5 | Should `FinalizedFinding` include the recognizer name that produced it? | Likely yes — useful for sink-side filtering ("only send NLP findings to SIEM"). Needs API surface review. | Open |

---

## Version History

| Document version | Date | Change |
|-----------------|------|--------|
| Draft 1 | 2026-04-16 | Initial design for A6 scorecard check |
