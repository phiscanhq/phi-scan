# CI Adapter Phase 3 Migration Plan

**Status:** PLAN — no migration work is executed here.
**Scope:** Move every remaining platform-specific extra in
`phi_scan/ci_integration.py` onto its adapter under `phi_scan/ci/`, then
add a `DeprecationWarning` on `phi_scan.ci_integration` import, then
remove the shim in a subsequent minor release.

See `docs/ci-adapter-contract.md` for the Phase 1/2 context.

## 1. Current inventory of `ci_integration.py`

Size: 871 lines. Contents fall into three buckets.

### 1.1 Already dispatches through adapters (stays in shim, zero-risk)

| Function | Notes |
|---|---|
| `post_pr_comment` | Orchestration entry; dispatches to per-platform adapter. |
| `set_commit_status` | Same. |
| `build_comment_body` | Comment-body formatting — platform-agnostic. |
| `build_comment_body_with_baseline` | Wraps `build_comment_body` with baseline context. |
| `_insert_baseline_context_into_comment` | Private helper to the above. |
| `BaselineComparison` (dataclass) | Shared type; platform-agnostic. |
| `_env` | Environment-variable accessor; already duplicated as `phi_scan.ci._env.fetch_environment_variable`. |

### 1.2 Platform-specific extras that still live here (scheduled for move)

| Function | Current home | Target adapter | Risk |
|---|---|---|---|
| `_verify_sarif_excludes_code_snippets` | `ci_integration.py:412` | `phi_scan/ci/github.py` (new private helper) | Low — pure string check; sentinel tested. |
| `_gzip_compress_sarif` | `:439` | `phi_scan/ci/github.py` | Trivial. |
| `_base64_encode_bytes` | `:443` | `phi_scan/ci/_transport.py` (shared) | Trivial. |
| `upload_sarif_to_github` | `:447` | `phi_scan/ci/github.py` as `GitHubAdapter.upload_sarif_report` | **Medium** — must preserve PHI-sentinel check order. Feature gated by `can_upload_sarif_report`. |
| `post_bitbucket_code_insights` | `:494` | `phi_scan/ci/bitbucket.py` as `BitbucketAdapter.annotate_code_findings` | Medium — large HTTP payload shape; full-request golden test required. |
| `set_azure_build_tag` | `:592` | `phi_scan/ci/azure.py` as `AzureAdapter.set_build_tag` | Low. |
| `set_azure_pr_status` | `:629` | `phi_scan/ci/azure.py` as `AzureAdapter.set_pr_status` | Low. |
| `create_azure_boards_work_item` | `:686` | `phi_scan/ci/azure.py` as `AzureAdapter.create_work_item_from_findings` | **Medium** — work-item payload structure is externally observable; add golden test. |
| `convert_findings_to_asff` | `:757` | `phi_scan/ci/codebuild.py` as `CodeBuildAdapter._convert_findings_to_asff` (private helper) | Low — pure transform; existing tests move with it. |
| `import_findings_to_security_hub` | `:828` | `phi_scan/ci/codebuild.py` as `CodeBuildAdapter.import_findings_to_security_hub` | Medium — boto3 client call; preserve existing mocking surface. |

### 1.3 Already moved (documented here for completeness)

- Platform detection → `phi_scan/ci/_detect.py`
- Shared HTTP transport → `phi_scan/ci/_transport.py`
- `CIIntegrationError` → `phi_scan/exceptions.py`
- Per-platform `post_pull_request_comment` and `set_commit_status`
  implementations → `phi_scan/ci/{github,gitlab,azure,circleci,bitbucket,codebuild,jenkins}.py`

## 2. Recommended extraction order

Grouped by adapter so each slice is atomic and reviewable on its own.

1. **Trivial-shared slice** — move `_base64_encode_bytes` into
   `_transport.py`. One-line import update in every caller. Zero risk.
2. **GitHub SARIF slice** — move `_verify_sarif_excludes_code_snippets`,
   `_gzip_compress_sarif`, `upload_sarif_to_github` into
   `phi_scan/ci/github.py`. Add `GitHubAdapter.upload_sarif_report`
   method; existing callers reach it via the adapter registry. Preserve
   the PHI-sentinel test at its new location.
3. **Azure slice** — move `set_azure_build_tag`, `set_azure_pr_status`,
   `create_azure_boards_work_item` onto `AzureAdapter`. Three methods,
   one commit. Golden test for work-item payload required.
4. **Bitbucket slice** — move `post_bitbucket_code_insights` onto
   `BitbucketAdapter.annotate_code_findings`. Snapshot the HTTP payload
   in a golden fixture before and after.
5. **AWS CodeBuild slice** — move `convert_findings_to_asff` and
   `import_findings_to_security_hub` onto `CodeBuildAdapter`. The ASFF
   transformation is pure; test it with a fixture. The
   `import_findings_to_security_hub` call retains its existing boto3
   mock surface.
6. **Shim deprecation** — once every extra has moved, add a
   `DeprecationWarning` at the top of `phi_scan/ci_integration.py` that
   fires on import. Ship in one minor release.
7. **Shim removal** — in the next minor release, delete
   `phi_scan/ci_integration.py`. Release notes call out the removal.
   Verification: `ruff check` confirms no remaining internal imports of
   the old path.

## 3. Gates for each slice

Each extraction slice must satisfy all of:

- [ ] `uv run ruff check .` clean.
- [ ] `uv run mypy phi_scan` clean.
- [ ] `uv run pytest tests/test_ci_adapters.py tests/test_ci_integration.py tests/test_ci_integration_remaining.py -q` passes.
- [ ] For SARIF: PHI-sentinel assertion (response body never contains raw
      PHI, error messages never echo request body) runs at the new
      location.
- [ ] For Bitbucket / Azure work-item: a request-payload golden fixture
      captures the full HTTP body before the move and is asserted
      byte-identical after.
- [ ] No public import breaks: every name currently importable from
      `phi_scan.ci_integration` remains importable until the deprecation
      window closes.

## 4. Non-goals in Phase 3

- Do not rename `CIIntegrationError` or any public function in this phase.
- Do not change the adapter capability flags in
  `docs/ci-adapter-contract.md` beyond adding the ones that correspond to
  newly migrated methods.
- Do not introduce new platforms.
- Do not rewrite the shared transport.

## 5. Out of scope

- Marketplace publication of any GitHub Action.
- Moving adapter tests into a `tests/ci/` subdirectory — deferred to a
  separate pass once the adapter set stabilises.
- Third-party adapter pluggability — tracked under
  `docs/plugin-hooks-v1_1-backlog.md`.
