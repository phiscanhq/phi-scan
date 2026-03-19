---
name: complete-task
description: Complete the current PhiScan task — runs lint, typecheck, tests, commits, pushes, and opens a PR
disable-model-invocation: true
allowed-tools: Bash, Read, Edit
---

## /complete-task

Finish the current task and open a PR. Run every step in order. Stop and report if any step fails.

**Current branch:**
!`git branch --show-current`

**Uncommitted changes:**
!`git status --short`

### Steps

1. **Lint**
   ```
   uv run ruff check . --fix && uv run ruff format .
   ```
   Fix any issues before continuing.

2. **Type check**
   ```
   uv run mypy phi_scan/
   ```
   Zero errors required. Fix all mypy errors before continuing.

3. **Tests**
   ```
   uv run pytest tests/ -v --cov=phi_scan
   ```
   All tests must pass. Fix failures before continuing.

4. **Commit** — stage specific files by name, never `git add .`
   ```
   git add <specific files>
   git commit -m "<clear description of what changed and why>"
   ```
   - No `Co-Authored-By:` tags — ever
   - No Anthropic attribution in any commit message

5. **Push**
   ```
   git push origin <current-branch>
   ```

6. **Open PR**
   ```
   gh pr create \
     --title "[Phase X.Y] <task title>" \
     --body "..."
   ```
   PR body must include:
   - Task reference from PLAN.md
   - What was built
   - Any deviations from the plan
   - Test coverage note

7. **Wait for CI to pass**
   ```
   gh pr checks --watch
   ```
   All three platform checks (ubuntu, macos, windows) must be green before proceeding.

8. **Wait for Claude automated review** to post its comment. Read it. Address any issues
   before merging.

9. **Confirm with user** — paste the PR URL. Only merge after the user approves.

The task is not complete until CI is green, Claude review has been read, and the user has approved.
