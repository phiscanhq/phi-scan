# CI Adapter Split — Interface Contract and Rollout Plan

Status: **DRAFT** — design document for discussion. No implementation yet.

This document describes the planned decomposition of
`phi_scan/ci_integration.py` (1,960 lines, 7 CI platforms) into a
per-platform adapter package with a shared interface contract.

---

## Problem Statement

`ci_integration.py` is the largest module in the codebase. It handles:

1. Platform auto-detection from environment variables.
2. PR/MR context extraction (7 platform-specific builders).
3. PR comment posting (7 platform-specific HTTP calls).
4. Commit status reporting (7 platform-specific HTTP calls).
5. Platform-specific extras: GitHub SARIF upload, Azure build tags,
   Azure PR status, Azure Boards work items, Bitbucket Code Insights,
   AWS Security Hub ASFF import.

All 7 platforms share the same outbound interface (`post_pr_comment`,
`set_commit_status`) but diverge significantly in transport, auth, and
API shape. The single-module design causes:

- **Merge conflicts**: any CI platform change touches the same file.
- **Test isolation**: platform-specific test fixtures crowd a single
  test module (currently `tests/test_ci_integration.py` +
  `tests/test_ci_integration_remaining.py`).
- **Cognitive load**: contributors modifying GitHub support must read
  past Azure, Bitbucket, and CodeBuild code.

---

## Target Module Layout

```
phi_scan/
  ci/
    __init__.py           # re-exports detect_platform, get_pr_context,
                          #   post_pr_comment, set_commit_status
    _base.py              # BaseCIAdapter ABC, PRContext, CIIntegrationError
    _transport.py         # shared _HttpRequestConfig, _execute_http_request
    _detect.py            # detect_platform(), CIPlatform enum
    github.py             # GitHubAdapter
    gitlab.py             # GitLabAdapter
    azure.py              # AzureAdapter
    circleci.py           # CircleCIAdapter
    bitbucket.py          # BitbucketAdapter
    codebuild.py          # CodeBuildAdapter
    jenkins.py            # JenkinsAdapter

tests/
  ci/
    __init__.py
    test_github.py
    test_gitlab.py
    test_azure.py
    test_circleci.py
    test_bitbucket.py
    test_codebuild.py
    test_jenkins.py
    test_detect.py
    test_transport.py
```

The top-level `phi_scan/ci/__init__.py` re-exports the public API so
existing callers (`from phi_scan.ci_integration import post_pr_comment`)
can migrate with a single import-path change. The old
`ci_integration.py` module will be retained as a thin re-export shim
during the deprecation window (see Phase 1 below).

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
    def post_pr_comment(
        self, comment_body: str, pr_context: PRContext,
    ) -> None:
        """Post a comment on the PR/MR associated with this build.

        Raises:
            CIIntegrationError: On any HTTP or auth failure.
        """

    @abstractmethod
    def set_commit_status(
        self, scan_result: ScanResult, pr_context: PRContext,
    ) -> None:
        """Report pass/fail status on the commit that triggered the build.

        Raises:
            CIIntegrationError: On any HTTP or auth failure.
        """

    @property
    def supports_sarif_upload(self) -> bool:
        """Whether this platform supports native SARIF ingestion."""
        return False

    @property
    def supports_code_insights(self) -> bool:
        """Whether this platform supports inline code annotations."""
        return False

    @property
    def supports_work_item_creation(self) -> bool:
        """Whether this platform supports creating work items from findings."""
        return False
```

### Capability Flags

Platform-specific extras are exposed via boolean capability properties
rather than optional methods. This avoids `hasattr` checks and makes
the adapter's capabilities inspectable:

| Capability | GitHub | GitLab | Azure | CircleCI | Bitbucket | CodeBuild | Jenkins |
|-----------|--------|--------|-------|----------|-----------|-----------|---------|
| `post_pr_comment` | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| `set_commit_status` | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| `supports_sarif_upload` | Yes | No | No | No | No | No | No |
| `supports_code_insights` | No | No | No | No | Yes | No | No |
| `supports_work_item_creation` | No | No | Yes | No | No | No | No |
| `supports_security_hub` | No | No | No | No | No | Yes | No |

Platforms that support an extra MUST implement the corresponding method
(e.g. `upload_sarif()` on `GitHubAdapter`). The base class provides a
default that raises `CIIntegrationError` (the domain exception) for
each extra — not `NotImplementedError`, which is a built-in and does
not conform to the project's custom-exception-for-domain-errors rule.

---

## Shared Transport

The `_transport.py` module extracts the existing `_HttpRequestConfig`
dataclass and `_execute_http_request` function. All adapters use this
shared transport layer:

- Consistent error wrapping: HTTP failures always raise
  `CIIntegrationError` with status code and reason phrase only (never
  response body — see security audit in current `ci_integration.py`).
- Consistent timeout handling: configurable per-request timeout with a
  sensible default.
- Consistent proxy support: `HTTPS_PROXY` / `HTTP_PROXY` environment
  variables respected.

---

## Error Model

All adapter methods raise `CIIntegrationError` on failure. The error
message MUST include:

- The platform name.
- The HTTP status code and reason phrase (for HTTP failures).
- The operation that failed (e.g. "post PR comment", "set commit
  status").

The error message MUST NOT include:

- The HTTP response body (may echo back request content containing
  finding metadata).
- Authentication tokens or credentials.
- Raw PHI values.

This matches the existing security contract in `ci_integration.py` and
is enforced by sentinel tests.

---

## Test Strategy

Each adapter module gets a dedicated test file. Tests follow the
existing pattern:

1. **Monkeypatch environment variables** for the platform under test.
2. **Mock `_execute_http_request`** to avoid real HTTP calls.
3. **Assert outbound request shape**: URL, headers, body structure.
4. **Assert error wrapping**: HTTP failures produce
   `CIIntegrationError` with safe messages.
5. **Sentinel tests**: error messages never contain response body text.

Shared transport tests go in `test_transport.py`. Platform detection
tests go in `test_detect.py`.

### Coverage Target

Each adapter module MUST maintain >= 90% line coverage. The shared
transport module MUST maintain 100% coverage (it is security-critical).

---

## Rollout Plan

### Phase 1 — Extract and Shim (non-breaking)

1. Create `phi_scan/ci/` package with `_base.py`, `_transport.py`,
   `_detect.py`.
2. Move platform detection logic to `_detect.py`.
3. Move shared HTTP logic to `_transport.py`.
4. Keep `ci_integration.py` as a thin re-export shim with explicit
   named imports (no wildcard `import *`):
   ```python
   # phi_scan/ci_integration.py — deprecated, will be removed in v1.3
   from phi_scan.ci import (  # noqa: F401
       CIIntegrationError,
       CIPlatform,
       PRContext,
       detect_platform,
       get_pr_context,
       post_pr_comment,
       set_commit_status,
   )
   ```
5. Emit `DeprecationWarning` on import of the old module path.

**Verification**: all existing tests pass without modification.

### Phase 2 — Per-Platform Adapters

1. Extract each platform's functions into its adapter class
   (`github.py`, `gitlab.py`, etc.).
2. Implement `BaseCIAdapter` interface on each adapter.
3. Update `phi_scan/ci/__init__.py` to dispatch `post_pr_comment` and
   `set_commit_status` via the adapter registry.
4. Split test files into per-platform modules.

**Verification**: full test suite passes, no behavior changes, coverage
>= 90% per adapter.

### Phase 3 — Remove Shim

1. Remove `ci_integration.py` after the 2-minor-release deprecation
   window (per `docs/plugin-api-v1.md` deprecation policy).
2. Update all internal imports to `phi_scan.ci`.
3. Document the migration in release notes.

**Verification**: `ruff check` confirms no remaining imports of the
old module path.

---

## Risk and Rollback

| Risk | Mitigation |
|------|-----------|
| Import path breakage for downstream consumers | Phase 1 shim preserves the old import path with a deprecation warning. 2-minor-release window before removal. |
| Behavior regression in platform-specific logic | Each adapter is extracted as a mechanical refactor with no logic changes. Existing tests are moved (not rewritten) in Phase 2. |
| Test coverage regression | Per-adapter 90% coverage gate prevents merging undertested adapters. |
| Merge conflicts during phased rollout | Phase 1 (non-breaking) ships first. Phase 2 can be done one platform at a time as independent PRs. |

### Rollback

If Phase 2 introduces regressions, revert the per-platform extraction
PRs and fall back to Phase 1 (shim + monolith). The shim ensures
callers are unaffected.

---

## Version History

| Document version | Date | Change |
|-----------------|------|--------|
| Draft 1 | 2026-04-16 | Initial design for A8 scorecard check |
