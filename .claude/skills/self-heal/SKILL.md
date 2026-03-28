---
name: self-heal
description: Autonomous PhiScan codebase health review and self-healing cycle. Spawns parallel subagents reviewing performance, DRY, Python FP patterns, documentation, tests, code quality, and HIPAA compliance — then plans, implements, and validates fixes. Also auto-resolves open PR review feedback with loop detection and auto-squash-merge. Invoke manually or runs twice daily via cron. Requires --dangerously-skip-permissions for full automation.
---

# /self-heal

Autonomous health and PR resolution cycle for PhiScan. Selects mode based on current repo state.

**Current branch:**
!`git branch --show-current`

**Open PRs:**
!`gh pr list --state open --json number,title,headRefName,reviewDecision,statusCheckRollup`

**Uncommitted changes:**
!`git status --short`

---

## Phase 0 — Pre-Run Checks

Run these before anything else. They prevent wasted spend on a healthy codebase or an
over-budget week.

### 0.1 Read run history

```bash
cat .self-heal/history.json 2>/dev/null || echo "[]"
```

Parse the JSON array. Each entry is one prior run. Store as `history`.

### 0.2 Circuit breaker — weekly spend cap

Sum `cost_usd_estimated` for all entries in `history` where `timestamp_utc` falls in the
current calendar week (Monday 00:00 UTC through Sunday 23:59 UTC).

```
WEEKLY_BUDGET_CAP = 30.00
weekly_spend = sum(r.cost_usd_estimated for r in history if r is this week and not r.skipped)
```

If `weekly_spend >= WEEKLY_BUDGET_CAP`:
1. Append a skip entry to history (see Phase C format, set `skipped=true`, `skip_reason="weekly_budget_cap"`, `cost_usd_estimated=0`)
2. Commit history
3. Send skip alert email if Gmail MCP is available (see Phase C)
4. **Stop. Do not proceed.**

### 0.3 Smart skip — consecutive clean runs

From `history`, take the last 3 entries where `skipped=false`.

If all 3 exist AND all 3 have `is_clean=true` AND all 3 have `cost_usd_estimated < 1.00`:
1. Append a skip entry (`skipped=true`, `skip_reason="consecutive_clean_runs"`, `cost_usd_estimated=0`)
2. Commit history
3. Send one-liner skip email if Gmail MCP is available (see Phase C)
4. **Stop. Do not proceed.**

### 0.4 Proceed

Neither gate triggered. Record `run_start_utc = current UTC timestamp`. Continue to Mode Selection.

---

## Mode Selection

- **Open PR with review feedback** → enter **Phase A — PR Feedback Resolution** first
- **Clean main, no open PRs** → enter **Phase B — Codebase Health**
- **Both** → run Phase A first, then Phase B on a new branch

---

## Phase A — PR Feedback Resolution Mode

### A1. Read all review feedback

```bash
gh pr view <number> --comments
gh api repos/{owner}/{repo}/pulls/<number>/reviews
gh api repos/{owner}/{repo}/pulls/<number>/comments
```

For each piece of feedback, record:
- File path and line number (if available)
- Issue description
- Severity — **CRITICAL** (logic error, PHI leakage, security, broken tests) | **WARNING** (CLAUDE.md violation, naming, style) | **INFO** (suggestion)
- Issue fingerprint: first 60 chars of description + file path — used to detect loops

### A2. Check prior fix history

```bash
git log --oneline -20
```

Skip any issue where the git log shows a fix commit targeting the same file and description.

### A3. Classify and prioritise

Fix order:
1. CRITICAL — always fix
2. WARNING — fix if the solution is unambiguous
3. INFO — fix only if trivial (under 5 lines)

Do not fix items that would introduce new features, new files, or break existing behaviour.

### A4. Implement fixes

For each item:
1. Read the file at the flagged location
2. Implement following CLAUDE.md exactly:
   - No magic values — all literals in named constants
   - No banned variable names: `data`, `info`, `result`, `temp`, `value`, `obj`, `item`, `thing`
   - Functions max 30 lines, max 3 arguments
   - Guard clauses over nested conditionals
   - `reject_<noun>` for domain invariant guards, `validate_<field_name>` for `__setattr__` guards
   - PHI values must never appear in exception messages — omit value, log only length or type
   - No `Co-Authored-By` in any commit message

### A5. Validate

```bash
uv run ruff check . --fix && uv run ruff format .
uv run mypy phi_scan/
uv run pytest tests/ -v --cov=phi_scan 2>&1 | tee /tmp/pytest_output.txt
```

Capture the coverage percentage from pytest output. Look for the line:
`TOTAL ... XX%` — extract the percentage as `test_coverage_pct`.

If any check fails: fix first. If unfixable after 2 attempts, revert only that file:
```bash
git checkout -- <file>
```

### A6. Commit and push

```bash
git add <specific files>
git commit -m "fix: resolve PR review feedback — <brief description>"
git push origin <branch>
```

### A7. Wait for CI

```bash
gh pr checks <number> --watch
```

### A8. Loop detection

- Same fingerprint appearing 3 consecutive times → confirmed false positive, skip it
- Track total cycle counter

| Cycle | Action |
|-------|--------|
| 1–4 | Fix all CRITICAL + WARNING, push, wait for CI + re-review |
| 5 (final) | False positives only or clean → proceed to A9 |
| 5 (final) | New CRITICAL issues exist → post human-review comment, stop |

If stopping at cycle 5:
```
Auto-resolution reached the 5-cycle limit. Unresolved critical issues require human review.
```

### A9. Auto-squash-merge

When CI is green and no CRITICAL/WARNING issues remain:

```bash
gh pr merge <number> --squash --subject "<PR title>"
git checkout main && git pull
```

After merge, proceed to **Phase C** with `mode="Phase A"`.

---

## Phase B — Codebase Health Mode

### B0. Create working branch

```bash
git checkout main && git pull
git checkout -b chore/self-heal-$(date +%Y%m%d-%H%M)
```

### B1. Parallel Review — 7 Subagents

Spawn all 7 using the Agent tool **in parallel** (single message, 7 Agent tool calls).
Each returns **1–2 highest-priority findings** with: file path, line number, issue description,
suggested fix, risk level (low / medium / high), and estimated tokens used.

**Every subagent prompt must include:**
- CLAUDE.md naming and structure rules
- Stack: Python 3.12, uv, Typer, Rich, SQLite, pytest, ruff, mypy, pathlib
- PHI safety constraint: no raw values in error messages, hash-only storage
- Banned patterns list from CLAUDE.md
- Instruction: suggest fixes only — no new features, no new files

---

**Subagent 1 — Performance**

Look for: regex patterns compiled inside functions instead of at module scope, SQLite queries
missing indexes, expensive operations in traversal hot paths, redundant file reads,
`pathlib.rglob` results collected into memory when streaming is possible, repeated
`isinstance` chains that could be a dispatch dict.

---

**Subagent 2 — DRY**

Look for: duplicated validation logic across modules, repeated error message string patterns
that should be a shared constant, similar `__post_init__` guard sequences that could share
a utility, copy-pasted test setup that should be a fixture.

---

**Subagent 3 — Python FP Patterns**

Look for: `for` loops that mutate an accumulator where a comprehension fits, functions named
`get_*`/`calculate_*`/`is_*`/`has_*` that contain side effects or mutations, dataclasses
missing `frozen=True` where immutability is the intent, in-place list mutation where a new
list should be returned, `global` or `nonlocal` usage outside justified scope.

---

**Subagent 4 — Documentation**

Look for: public functions missing Google-style docstrings (`Args:`, `Returns:`, `Raises:`),
docstrings that no longer match the function signature, complex logic blocks with no WHY
comment, missing type annotations on public API boundaries, `TODO`/`FIXME` without an issue
number and owner.

---

**Subagent 5 — Test Quality**

Look for: missing coverage for CRITICAL paths (PHI detection, audit log immutability, config
validation, symlink rejection), tests not following AAA structure, magic values in test code,
tests asserting implementation details instead of behaviour, missing edge cases for boundary
values (empty list, None, zero, max threshold).

---

**Subagent 6 — Code Quality + CLAUDE.md Standards**

Look for: functions exceeding 30 lines, functions with more than 3 arguments, banned variable
names (`data`/`info`/`result`/`temp`/`value`/`obj`/`item`/`thing`), classes ending in
`Manager`/`Handler`/`Processor`/`Helper`/`Util`, magic literals in logic code, nested
conditionals deeper than 2 levels, bare `except:` clauses, double negatives, commented-out
code.

---

**Subagent 7 — HIPAA / Compliance**

Look for: exception messages including raw field values where PHI could appear, missing
SHA-256 format validation on hash fields, `os.listdir()` or non-`rglob` traversal, symlink
traversal without a guard, unbounded fields that could store PHI (`code_context`,
`remediation_hint`, `entity_type`), numeric detection thresholds as literals, audit log
functions that allow UPDATE or DELETE.

---

### B2. Prioritise

Select top 3–5 findings ranked by:
1. PHI / security risk
2. Bug or regression risk
3. Maintainability impact
4. Fix confidence — prefer unambiguous, low-risk changes

For medium-risk items too complex for this cycle, leave a TODO comment and file a GitHub
issue with the `self-heal` label:

```bash
gh issue create \
  --title "self-heal: <issue title>" \
  --body "<description and rationale>" \
  --label "self-heal"
```

Record deferred items for the run report.

### B3. Plan

Spawn a single **Plan subagent** with the prioritised findings. Specify per fix:
- Exact files and line numbers
- Old code → new code
- Why this improves the codebase
- How to verify with tests

### B4. Implement

Spawn a single **general-purpose subagent** to execute the plan exactly. Prompt must include:
- The full plan from B3
- CLAUDE.md standards (naming, 30-line limit, no magic values, PHI safety)
- Constraint: only planned changes — no new features, no new files

### B5. Validate

Run in the **main conversation**:

```bash
uv run ruff check . --fix && uv run ruff format .
uv run mypy phi_scan/
uv run pytest tests/ -v --cov=phi_scan 2>&1 | tee /tmp/pytest_output.txt
```

Extract coverage: look for `TOTAL ... XX%` in pytest output. Store as `test_coverage_pct`.

If validation fails:
1. Spawn a fix subagent with the full error output
2. Re-validate
3. After 2 failed attempts on a file, revert it: `git checkout -- <file>`
4. Commit whatever subset passes

### B6. Review

Spawn a single **general-purpose review subagent** with the plan and `git diff HEAD` output.

Checklist: plan adherence, CLAUDE.md compliance, PHI safety, type safety, edge cases, coverage.
Return: **APPROVE** or **REQUEST_CHANGES**.

If `REQUEST_CHANGES`: fix → re-validate → re-review. Max 2 review-fix loops.

### B7. Commit

```bash
git add <specific files>
git commit -m "$(cat <<'EOF'
refactor: <description of what was improved and why>

- <change 1>
- <change 2>
EOF
)"
```

No `Co-Authored-By` tags. No Anthropic attribution.

### B8. Open PR

```bash
gh pr create \
  --title "chore: self-heal — <brief description>" \
  --body "$(cat <<'EOF'
## Summary
- <what was found>
- <what was fixed>

## Test coverage
All existing tests pass. Coverage unchanged or improved.
EOF
)"
```

The PR triggers the Claude review workflow automatically. Phase A handles feedback and merge.

After opening the PR, proceed to **Phase C** with `mode="Phase B"`.

### B9. Expand scope (if fewer than 3 code changes)

```bash
grep -rn "TODO\|FIXME" phi_scan/ --include="*.py"
gh issue list --state open --label "self-heal"
uv pip list --outdated
```

Create GitHub issues with `self-heal` label for anything found. Always produce output.

---

## Phase C — Post-Run Record and Report

Run this after every execution path including skips.

### C1. Collect run metrics

Gather:
- `timestamp_utc` — current UTC time (ISO 8601)
- `mode` — "Phase A", "Phase B", "Both", or "skipped"
- `is_clean` — true if nothing was found or fixed
- `skipped` — true if Phase 0 halted execution
- `skip_reason` — "weekly_budget_cap" | "consecutive_clean_runs" | null
- `issues_found` — total count across all subagents
- `issues_fixed` — count of issues actually fixed this run
- `issues_deferred` — count of GitHub issues created for later
- `cost_usd_estimated` — estimated total using $3/MTok input, $15/MTok output
- `turns_used` — approximate tool call count
- `test_coverage_pct` — from pytest output, or null if not run
- `files_changed` — list of files modified, or []
- `fix_cycles` — number of A/B fix loops used
- `pr_number` — PR number if Phase A resolved a PR, else null
- `subagent_findings` — dict with finding count per subagent (Phase B only):
  ```json
  {
    "performance": 0, "dry": 1, "python_fp": 0,
    "documentation": 1, "test_quality": 0,
    "code_quality": 0, "hipaa_compliance": 0
  }
  ```
- `validation` — `{"ruff": "pass"|"fail", "mypy": "pass"|"fail", "pytest": "pass"|"fail"}` or null

### C2. Append to history

Read `.self-heal/history.json`, append the new run record, write back.

Keep the full history — do not truncate. The weekly digest reads from it.

```bash
# Commit the updated history file
git add .self-heal/history.json
git commit -m "chore(self-heal): record run $(date +%Y%m%d-%H%M)"
git push origin main 2>/dev/null || git push origin $(git branch --show-current)
```

### C3. Build trend data for email

From `history`, compute:
- Last 5 non-skipped runs: cost and outcome
- Weekly spend so far (current week)
- Most active subagent (highest total findings across all runs)
- Least active subagent (zero or lowest findings — candidate for removal)
- Coverage trend: last 3 runs with coverage data

### C4. Send run report email (if Gmail MCP is available)

If Gmail MCP is connected, send to **joey.essak@gmail.com**.

**Subject:**
- Clean run: `PhiScan Self-Heal — CLEAN — <date> <time MT>`
- Issues fixed: `PhiScan Self-Heal — <N> issues fixed — <date> <time MT>`
- Skipped (budget): `PhiScan Self-Heal — SKIPPED (weekly budget cap reached) — <date>`
- Skipped (clean): `PhiScan Self-Heal — SKIPPED (3 consecutive clean runs) — <date>`

**Body:**

```
PHISCAN SELF-HEAL RUN REPORT
<date and time in Mountain Time>
Mode:    <Phase A / Phase B / Both / Skipped>
Outcome: <CLEAN / X issues found and fixed / X issues found, Y fixed, Z deferred / Skipped>

COST BREAKDOWN (estimated)
------------------------------------------------------------
Review Subagent 1 — Performance:      $X.XX  (<finding or 'nothing found'>)
Review Subagent 2 — DRY:              $X.XX  (<finding or 'nothing found'>)
Review Subagent 3 — Python FP:        $X.XX  (<finding or 'nothing found'>)
Review Subagent 4 — Documentation:    $X.XX  (<finding or 'nothing found'>)
Review Subagent 5 — Test Quality:     $X.XX  (<finding or 'nothing found'>)
Review Subagent 6 — Code Quality:     $X.XX  (<finding or 'nothing found'>)
Review Subagent 7 — HIPAA/Compliance: $X.XX  (<finding or 'nothing found'>)
Planning Agent:                       $X.XX
Implementation Agent:                 $X.XX  (<files changed or 'no changes'>)
Validation:                           $X.XX  (ruff: <P/F> | mypy: <P/F> | pytest: <P/F>)
Review Agent:                         $X.XX  (<APPROVE / REQUEST_CHANGES / N/A>)
------------------------------------------------------------
TOTAL THIS RUN:                       $X.XX
Weekly spend so far:                  $X.XX / $30.00 cap
Turns used:                           <N> / 50
Test coverage:                        <XX.X%>  (<↑/↓/→> from last run)

FILES CHANGED
<list each file and one-line description, or 'No files changed'>

ISSUES FIXED
<numbered list, or 'None — codebase was clean'>

ISSUES DEFERRED (GitHub backlog)
<list with issue numbers, or 'None'>

FIX CYCLES
<N of 5 used, or 'N/A — Phase B health run'>

RUN HISTORY (last 5 runs)
<timestamp>:  $X.XX  |  <N issues fixed or CLEAN>
<timestamp>:  $X.XX  |  <N issues fixed or CLEAN>
...

SUBAGENT EFFICIENCY
Most active:   <subagent name> (<N total findings this week>)
Least active:  <subagent name> (<N total findings — consider disabling if 0 for 2+ weeks>)

COST TREND GUIDANCE
< $1.00:  Codebase is clean. Consider reducing to once-daily.
$1–$3:    Normal active-dev range. Current schedule is right.
$3–$8:    Meaningful work done. Review what was fixed.
> $8:     High activity. Review issues and consider adjusting scope.
```

If Gmail MCP is not available (local/GH Actions run), skip the email silently.

---

## Invocation

**Manual:**
```bash
claude --dangerously-skip-permissions /self-heal
```

**Cron (twice daily via remote scheduler):**
Managed at https://claude.ai/code/scheduled/trig_014U49QKyTbbUXBknqKGgeY6

**GitHub Actions (PR feedback loop):**
Triggered automatically on `pull_request_review` events via `auto-resolve-pr-feedback.yml`.
Uses `self_heal_runner.py` with `bypassPermissions` mode, $15 budget cap, 50-turn limit.

`--dangerously-skip-permissions` is required for local automated invocations. Without it the
agent stalls waiting for permission prompts.
