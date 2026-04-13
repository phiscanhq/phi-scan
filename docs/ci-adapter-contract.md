# CI Adapter Split — Interface Contract and Rollout Plan

Status: **IMPLEMENTED** — shipped in PR #130. The `phi_scan/ci/` package
contains per-platform adapters matching this contract. `ci_integration.py`
is retained as the backward-compatible entry point: it dispatches to the
per-platform adapters in `phi_scan.ci` and still hosts the orchestration
helpers (comment-body formatting) and the platform-specific extras
(SARIF upload, Bitbucket Code Insights, Azure build tags / PR statuses /
Boards work items, AWS Security Hub ASFF import) that have not yet been
migrated into their adapters. No runtime deprecation warning is emitted
today; migration and shim removal are deferred (see Phase 3 below).

---

## Background and Motivation

`phi_scan/ci_integration.py` was a 1,960-line module covering seven CI
platforms (GitHub, GitLab, Azure DevOps, CircleCI, Bitbucket, AWS
CodeBuild, Jenkins). It handled:

1. Platform auto-detection from environment variables.
2. PR/MR context extraction per platform.
3. PR comment posting per platform.
4. Commit status reporting per platform.
5. Platform-specific extras: GitHub SARIF upload, Azure build tags,
   Azure PR status, Azure Boards work items, Bitbucket Code Insights,
   AWS Security Hub ASFF import.

All seven platforms shared the same outbound interface
(`post_pull_request_comment`, `set_commit_status`) but diverged
significantly in transport, auth, and API shape. The single-module design
caused:

- **Merge conflicts**: every CI-platform change touched the same file.
- **Test isolation**: platform-specific fixtures crowded one test module.
- **Cognitive load**: contributors modifying GitHub support had to read
  past Azure, Bitbucket, and CodeBuild code.

PR #130 decomposed the module into a per-platform adapter package with
the shared interface contract documented below.

---

## Current Module Layout

```
phi_scan/
  ci/
    __init__.py           # re-exports detect_platform, get_pull_request_context,
                          #   post_pull_request_comment, set_commit_status
    _base.py              # BaseCIAdapter ABC, PullRequestContext, UnsupportedOperation
    _transport.py         # shared _HttpRequestConfig, _execute_http_request
    _detect.py            # detect_platform(), CIPlatform enum
    _env.py               # fetch_environment_variable() — safe env-var accessor
                          #   shared by detection and adapter auth lookups
    github.py             # GitHubAdapter
    gitlab.py             # GitLabAdapter
    azure.py              # AzureAdapter
    circleci.py           # CircleCIAdapter
    bitbucket.py          # BitbucketAdapter
    codebuild.py          # CodeBuildAdapter
    jenkins.py            # JenkinsAdapter
  exceptions.py           # CIIntegrationError — shared across the codebase

tests/
  test_ci_adapters.py     # consolidated adapter test suite
  test_ci_integration.py  # legacy entry-point coverage via the shim
  test_ci_integration_remaining.py  # migration-holdover coverage
```

`phi_scan/ci/__init__.py` re-exports the public API so that callers can
migrate with a single import-path change
(`from phi_scan.ci import post_pull_request_comment`). The legacy
`phi_scan/ci_integration.py` module continues to expose the original
public names (re-dispatching orchestration calls through the
`phi_scan.ci` adapter registry) and still hosts the platform-specific
extras listed in Phase 3. It does not currently raise a
`DeprecationWarning` on import; adding one is an explicit prerequisite
for shim removal and is tracked under Phase 3.

`CIIntegrationError` lives in `phi_scan/exceptions.py` (imported by
`_base.py` and every adapter), not in `_base.py` itself — this matches the
project's "custom exceptions in one module" convention.

---

## Adapter Interface

```python
from abc import ABC, abstractmethod
from phi_scan.models import ScanResult


class BaseCIAdapter(ABC):
    """Per-platform CI adapter.

    Each adapter encapsulates the platform-specific logic for posting
    PR comments, setting commit statuses, and any platform-specific
    extras (SARIF upload, build tags, etc.).
    """

    @abstractmethod
    def post_pull_request_comment(
        self,
        comment_body: str,
        pull_request_context: PullRequestContext,
    ) -> None:
        """Post a comment on the PR/MR associated with this build.

        Raises:
            CIIntegrationError: On any HTTP or auth failure.
        """

    @abstractmethod
    def set_commit_status(
        self,
        scan_result: ScanResult,
        pull_request_context: PullRequestContext,
    ) -> None:
        """Report pass/fail status on the commit that triggered the build.

        Raises:
            CIIntegrationError: On any HTTP or auth failure.
        """

    @property
    def can_upload_sarif_report(self) -> bool:
        """Whether this platform supports native SARIF ingestion."""
        return False

    @property
    def can_annotate_code_findings(self) -> bool:
        """Whether this platform supports inline code annotations."""
        return False

    @property
    def can_create_work_item_from_findings(self) -> bool:
        """Whether this platform supports creating work items from findings."""
        return False
```

### Capability Flags

Platform-specific extras are exposed via boolean capability properties
rather than optional methods. This avoids `hasattr` checks and makes
each adapter's capabilities inspectable.

| Capability | GitHub | GitLab | Azure | CircleCI | Bitbucket | CodeBuild | Jenkins |
|-----------|--------|--------|-------|----------|-----------|-----------|---------|
| `post_pull_request_comment` | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| `set_commit_status` | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| `can_upload_sarif_report` | Yes | No | No | No | No | No | No |
| `can_annotate_code_findings` | No | No | No | No | Yes | No | No |
| `can_create_work_item_from_findings` | No | No | Yes | No | No | No | No |
| `can_import_findings_to_security_hub` | No | No | No | No | No | Yes | No |

Platforms that support an extra implement the corresponding method on
their adapter (e.g. `upload_sarif_report()` on `GitHubAdapter`). The base
class provides a default that raises `CIIntegrationError` — the domain
exception — rather than the built-in `NotImplementedError`, matching the
project's custom-exception-for-domain-errors convention.

---

## Shared Transport

`_transport.py` holds the `_HttpRequestConfig` dataclass and
`_execute_http_request` function used by every adapter:

- **Consistent error wrapping.** HTTP failures raise `CIIntegrationError`
  with status code and reason phrase only. Response bodies are never
  included in the error message because they may echo back request
  content containing finding metadata.
- **Consistent timeout handling.** Every request has a configurable
  timeout with a safe default.
- **Consistent proxy support.** `HTTPS_PROXY` / `HTTP_PROXY` environment
  variables are respected.

---

## Error Model

All adapter methods raise `CIIntegrationError` on failure. The error
message MUST include:

- The platform name.
- The HTTP status code and reason phrase (for HTTP failures).
- The operation that failed (e.g. "post PR comment", "set commit status").

The error message MUST NOT include:

- The HTTP response body (may echo back finding metadata).
- Authentication tokens or credentials.
- Raw PHI values.

This matches the existing security contract and is enforced by sentinel
tests in `tests/test_ci_adapters.py`.

---

## Test Strategy

Adapter tests currently live in a consolidated suite at
`tests/test_ci_adapters.py`. Each platform's test block follows the same
pattern:

1. **Monkeypatch environment variables** for the platform under test.
2. **Mock `_execute_http_request`** to avoid real HTTP calls.
3. **Assert outbound request shape**: URL, headers, body structure.
4. **Assert error wrapping**: HTTP failures produce `CIIntegrationError`
   with safe messages.
5. **Sentinel tests**: error messages never contain response body text.

Shared transport tests and platform-detection tests live in the same
file alongside the per-platform blocks. Legacy coverage still runs
through `tests/test_ci_integration.py` and
`tests/test_ci_integration_remaining.py` via the re-export shim.

### Coverage

Each adapter block maintains >= 90% line coverage over its platform's
module. `_transport.py` is security-critical and retains 100% coverage.

---

## Rollout Plan

### Phase 1 — Extract and Shim ✅ Done

Shipped in PR #130. `phi_scan/ci/` package created with `_base.py`,
`_transport.py`, `_detect.py`, and `_env.py`. Platform detection and
shared HTTP logic moved out of the monolith. `ci_integration.py` retained
as the backward-compatible entry point — orchestration calls dispatch
through `phi_scan.ci`, and the module still hosts the platform-specific
extras scheduled for migration in Phase 3. No runtime deprecation warning
is emitted today.

### Phase 2 — Per-Platform Adapters ✅ Done

Shipped in PR #130. Each platform's functions were extracted into its
adapter class (`github.py`, `gitlab.py`, `azure.py`, `circleci.py`,
`bitbucket.py`, `codebuild.py`, `jenkins.py`), each implementing
`BaseCIAdapter`. `phi_scan/ci/__init__.py` dispatches
`post_pull_request_comment` and `set_commit_status` via the adapter
registry.

### Phase 3 — Migrate Extras and Remove Shim ⏳ Deferred follow-up

Not scheduled to a specific release. The platform-specific extras
(SARIF upload, Bitbucket Code Insights, Azure build tags / PR statuses /
Boards work items, AWS Security Hub ASFF import) still live in
`ci_integration.py` and will be moved onto their respective adapters
before the shim is retired. Before removal:

1. Migrate the remaining platform-specific extras from
   `ci_integration.py` onto their adapters in `phi_scan.ci`.
2. Add a `DeprecationWarning` to `phi_scan.ci_integration` import so
   external callers observe it for at least one minor-release cycle,
   per the deprecation policy in `docs/plugin-api-v1.md`.
3. Migrate any remaining internal callers to `phi_scan.ci`.
4. Remove `ci_integration.py` in a subsequent minor release; release
   notes call out the removal.

Verification at removal time: `ruff check` confirms no remaining imports
of the old module path inside the repo.

---

## Deferred Enhancements

The following improvements are optional follow-ups. None block pristine
signoff.

- **Per-platform test file split.** The consolidated
  `tests/test_ci_adapters.py` can be decomposed into `tests/ci/` with one
  file per platform once the suite grows large enough to justify it. The
  test patterns described above already map cleanly onto a per-file
  layout.
- **Adapter registry pluggability.** Exposing a public registration hook
  would let third-party CI adapters ship as plugins. This lands under a
  future plugin-hooks v1.1 revision (see
  [docs/plugin-hooks-v1_1-design.md](plugin-hooks-v1_1-design.md)).

---

## Risk and Rollback

| Risk | Mitigation |
|------|-----------|
| Import path breakage for downstream consumers | The shim preserves the old import path; a deprecation warning will be added before removal and maintained through the 2-minor-release deprecation window. |
| Behavior regression in platform-specific logic | Each adapter was extracted as a mechanical refactor with no logic changes; existing tests were moved rather than rewritten. |
| Test coverage regression | Per-platform >= 90% coverage gate; `_transport.py` at 100%. |

### Rollback

If a regression is discovered that cannot be fixed forward, revert PR #130
and fall back to the pre-split monolith. The shim means downstream callers
are unaffected either way.

---

## Version History

| Document version | Date | Change |
|-----------------|------|--------|
| Draft 1 | 2026-04-16 | Initial design for A8 scorecard check |
| Draft 2 | 2026-04-17 | Rewrite to current-state wording: Phase 1/2 marked done, Phase 3 marked deferred, module layout and test strategy updated to reflect shipped reality, `_env.py` and `exceptions.py` corrections applied |
| Draft 3 | 2026-04-18 | Truth-sync: remove claims that `ci_integration.py` is a thin re-export shim emitting `DeprecationWarning` on import. Shim still hosts orchestration helpers and platform-specific extras; no deprecation warning is currently raised. Phase 3 expanded to cover extras migration as a prerequisite to shim removal. |
