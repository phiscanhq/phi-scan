# Plugin Hooks v1.1 — Implementation Backlog

**Status:** BACKLOG — not scheduled to a release.
**Companion design doc:** `docs/plugin-hooks-v1_1-design.md` (preserves
historical context; this backlog is the execution-oriented artifact).

v1.1 extends the Plugin API beyond `BaseRecognizer` with two new
entry-point-loaded hooks:

- `BaseSuppressor` — plug-in suppression/filtering of findings before
  serialisation.
- `BaseOutputSink` — plug-in destinations for scan results (custom
  reporters, SIEM forwarders, third-party dashboards).

Both hooks ship in the same minor release. Until shipped, no plugin-side
implementation should assume their presence. See
`docs/plugin-api-v1.md` for the v1.0 contract that v1.1 extends without
breaking.

---

## Ticket — H1: `BaseSuppressor` hook

### Scope

- One new abstract class `BaseSuppressor` in `phi_scan/plugin_api.py`.
- One new entry-point group `phi_scan.suppressors_v1`.
- Runtime loader and invocation boundary in `phi_scan/plugin_runtime.py`
  modelled on the existing `BaseRecognizer` isolation helper.
- Suppression plugins see an immutable `ScanFinding` and return one of
  `Keep` / `Suppress(reason: str)`.

### Responsibilities

1. Define `BaseSuppressor` with an abstract
   `should_suppress(finding: ScanFinding, context: ScanContext) -> SuppressDecision`.
2. Add `SuppressDecision` as a frozen union (`Keep` sentinel,
   `Suppress(reason: str)` dataclass).
3. Load suppressor plugins at scan start with the same registry cache
   semantics as recognizers.
4. Apply the suppressor chain in `phi_scan.scanner._apply_post_scan_filters`
   **after** built-in suppression (`is_finding_suppressed`) and **before**
   confidence / severity filters. Order must be deterministic.
5. Record each suppression decision in the audit log at DEBUG level with
   plugin name and reason (never the raw finding value).

### Rollout sequence

1. **R1:** Land `BaseSuppressor` + `SuppressDecision` types behind the
   existing `PLUGIN_API_VERSION` bump to `1.1`.
2. **R2:** Land the loader and runtime helper
   `_invoke_suppressor_with_isolation` matching the recognizer isolation
   boundary contract documented in `CLAUDE.md`.
3. **R3:** Wire the suppressor chain into `_apply_post_scan_filters`.
4. **R4:** Document in `docs/plugin-developer-guide.md` with a worked
   example suppressor.
5. **R5:** Publish `docs/plugin-api-v1_1.md` as the canonical contract.

### Test strategy

- Unit tests for `BaseSuppressor` signature and `SuppressDecision` types.
- Isolation test: a suppressor raising `Exception` emits a rate-limited
  warning, the scan continues, other suppressors still run.
- Order test: with three suppressors [A, B, C], if B suppresses a
  finding, A's decision is visible in the audit log but C is not
  invoked for that finding.
- Audit-log test: suppression reason is recorded; the raw value and the
  `value_hash` of the suppressed finding are never written into the
  reason field by the framework.
- Deterministic-ordering test: same suppressors + same input file
  produces byte-identical audit output across runs.

### Compatibility / migration notes

- v1.0 plugins continue to load. The loader tolerates entry points that
  do not advertise a suppressor.
- No change to any built-in suppression behaviour — suppressors run
  after `is_finding_suppressed` by contract.
- `PLUGIN_API_VERSION` bumps from `"1.0"` to `"1.1"`; v1.0 plugins do
  not fail on this.

### Dependencies / blockers

- Depends on the existing `phi_scan.plugin_runtime` isolation helper
  (already present).
- No external dependencies.

---

## Ticket — H2: `BaseOutputSink` hook

### Scope

- One new abstract class `BaseOutputSink` in `phi_scan/plugin_api.py`.
- One new entry-point group `phi_scan.output_sinks_v1`.
- Runtime dispatch in `phi_scan/output/` (current serializers live at
  `phi_scan/output/serializers.py`).
- Sink plugins receive the final `ScanResult` and an immutable
  configuration dict; they emit their output side-effectfully.

### Responsibilities

1. Define `BaseOutputSink` with abstract `name: str` property and
   `emit(scan_result: ScanResult, config: SinkConfig) -> None`.
2. Add `SinkConfig` as a frozen dataclass with fields appropriate to a
   first-party example sink (`target_path: Path | None`,
   `endpoint_url: str | None`, `extra: MappingProxyType[str, str]`).
3. Load sink plugins at scan end with the same registry cache semantics
   as recognizers.
4. Dispatch to each registered sink **after** the built-in serializers
   complete, in deterministic order.
5. Isolate failures per sink — a raising sink does not abort emission to
   the remaining sinks, and the main scan exit code is unaffected by
   sink failures unless the user opts into `--strict-sinks`.

### Rollout sequence

1. **R1:** Land `BaseOutputSink` + `SinkConfig` types under the v1.1
   protocol bump.
2. **R2:** Land the loader and runtime helper
   `_invoke_sink_with_isolation`.
3. **R3:** Add CLI flag `--strict-sinks` (default off) to propagate sink
   failures to the exit code.
4. **R4:** Document in `docs/plugin-developer-guide.md` with a worked
   example sink (file writer or HTTP POST).
5. **R5:** Append the sink contract to `docs/plugin-api-v1_1.md`.

### Test strategy

- Unit tests for `BaseOutputSink` signature and `SinkConfig` frozen-ness.
- Isolation test: a sink raising `Exception` emits a warning, other
  sinks still emit, scan exit code stays 0 unless `--strict-sinks` is
  set.
- `--strict-sinks` test: exit code is non-zero iff at least one sink
  raised.
- PHI-sentinel test: the `ScanResult` handed to a sink never contains a
  raw value; `value_hash` is present, `code_context` is redacted. This
  mirrors the existing sentinel test in `tests/test_ci_adapters.py`.
- Deterministic-ordering test: sinks emit in the order the entry points
  were discovered, sorted by `name` for ties.

### Compatibility / migration notes

- v1.0 plugins continue to load.
- No change to built-in serializers (`phi_scan/output/serializers.py`);
  sinks run **after** them.
- `SinkConfig` is designed to be forward-compatible: it carries an
  `extra: MappingProxyType[str, str]` field so new sink types can read
  additional configuration without requiring an API bump.

### Dependencies / blockers

- Depends on H1 being merged (shares the v1.1 version bump commit).
- No external dependencies.

---

## Shared rollout contract (applies to H1 and H2)

### Single `PLUGIN_API_VERSION` bump

`PLUGIN_API_VERSION` transitions `"1.0" → "1.1"` in one commit that
lands both `BaseSuppressor` and `BaseOutputSink`. Do not bump the
version twice.

### CLI discovery flag

Add `phi-scan plugins list` support (already implemented for recognizers)
to display suppressors and sinks. No new CLI command — extend the existing
output.

### Deprecation policy

Matches `docs/plugin-api-v1.md`: no deprecation needed because v1.1 is
strictly additive. v1.0 stays supported for at least two subsequent minor
releases.

### Security contract

All three existing invariants from v1.0 continue to apply:

1. Plugins receive redacted `ScanFinding` objects — raw values are never
   exposed.
2. Errors from plugins are caught at the isolation boundary and never
   abort the scan.
3. No plugin can read or write files outside the explicit paths passed
   through the documented APIs — built-in safeguards in
   `phi_scan.scanner` (symlink rejection, archive bomb guards) are not
   reachable from plugin code.

---

## Non-goals in v1.1

- Third-party **CI adapter** pluggability. Tracked separately in
  `docs/ci-adapter-contract.md` Deferred Enhancements; that requires a
  different rollout because adapters run against external services and
  would need a stricter sandboxing model.
- Rewriting the recognizer contract. v1.0 stays unchanged.
- Marketplace / plugin discovery UI. The Python entry-point mechanism is
  the only advertised discovery path in v1.1.
