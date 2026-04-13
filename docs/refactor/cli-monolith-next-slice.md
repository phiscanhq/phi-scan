# `phi_scan/cli/__init__.py` — next-slice split plan

**Status:** PLANNED — deferred from the pristine-closure pass.
**Module size:** ~1490 lines (the former `phi_scan/cli.py`, now
`phi_scan/cli/__init__.py`).

The pristine-closure pass absorbed the seven satellite `cli_*.py` modules
into `phi_scan/cli/` and preserved import compatibility via top-level
shims. The large legacy body of `cli.py` now lives in `cli/__init__.py`
and is the next decomposition slice.

## Recommended split

```
phi_scan/cli/
    __init__.py          # thin dispatcher: construct app, register
                         # sub-apps, expose `app` for the pyproject entry
                         # point (pyproject.toml: phi-scan = "phi_scan.cli:app")
    _shared.py           # _ScanTargetOptions, _ScanPhaseOptions,
                         # _ScanExecutionOptions, _ProgressScanContext,
                         # _configure_logging, _load_combined_ignore_patterns,
                         # _resolve_scan_targets, _normalize_diff_path,
                         # _truncate_filename_for_progress,
                         # _validate_worker_count, _echo_version,
                         # _reject_hook_path_with_symlinked_component,
                         # _reject_missing_git_directory
    scan.py              # _run_sequential_scan_with_progress,
                         # _run_parallel_scan_with_progress,
                         # _run_scan_with_progress,
                         # _execute_scan_with_progress,
                         # _resolve_framework_flag, _prepare_scan_phase,
                         # _dispatch_notifications,
                         # _write_audit_record, _persist_audit_record,
                         # _display_audit_phase_header,
                         # _run_ci_integration, _call_ci_integration,
                         # @app.command("scan") → scan()
    fix.py               # _collect_target_files, _print_fix_result,
                         # _run_interactive_fix,
                         # @app.command("fix") → fix_command()
    history.py           # _parse_lookback_days, _display_scan_event_row,
                         # _display_scan_history,
                         # @app.command("history") → display_history(),
                         # @app.command("report") → display_last_scan()
    dashboard.py         # _aggregate_category_totals,
                         # @app.command("dashboard") → display_dashboard()
    hooks.py             # @app.command("install-hook") → install_hook(),
                         # @app.command("uninstall-hook") → uninstall_hook(),
                         # @app.command("init") → initialize_project(),
                         # @app.command("setup") → download_models()
```

## Extraction order (recommended)

1. `_shared.py` — leaf helpers with no Typer registrations. Zero risk.
2. `fix.py` — self-contained block already (three helpers + one command).
3. `hooks.py` — four trivial command registrations.
4. `history.py` — moderately coupled to scan-event rendering.
5. `dashboard.py` — one helper + one command.
6. `scan.py` — the largest and most coupled; do last once `_shared.py` is
   stable.

## Shim strategy

After each slice is extracted, the imported symbol must still be reachable
through `phi_scan.cli.<command_module>` **and** through the historical
`phi_scan.cli` surface (because existing tests import
`from phi_scan.cli import _normalize_diff_path`, etc.).

`phi_scan/cli/__init__.py` stays the canonical `app` object home; it
re-exports private helpers for test compatibility via explicit
`from phi_scan.cli._shared import _normalize_diff_path` + `__all__`
additions. Do not change test imports in this pass.

## Gates

- [ ] `uv run pytest tests/test_cli.py tests/test_cli_flags.py tests/test_cli_plugins.py` passes.
- [ ] `phi-scan --help` produces byte-identical output before/after.
- [ ] `pyproject.toml` entry point `phi_scan.cli:app` resolves.
- [ ] No test's golden output regresses.

## Non-goals

- Do not rename any Typer command (names are user-facing contract).
- Do not change help strings or option names.
- Do not reorganise the suppression, config, or baseline sub-apps (they
  are already their own modules).
