---
name: task-status
description: Show the current PhiScan task position — what was last merged, what is in progress, and what comes next according to PLAN.md
disable-model-invocation: true
allowed-tools: Bash, Read
---

## /task-status

Report the current state of work by cross-referencing git history, open PRs, and PLAN.md.
This gives a definitive answer on what was last completed and what comes next — even if the
user is unsure or does not remember.

**Merged task branches on main:**
!`git log main --merges --oneline --format="%s" 2>/dev/null | grep -o 'task/[^ ]*' | head -20 || echo "none"`

**Current branch:**
!`git branch --show-current`

**Uncommitted changes:**
!`git status --short`

**Open PRs:**
!`gh pr list --state open --json number,title,headRefName 2>/dev/null || echo "none"`

**CI status (current branch PR):**
!`gh pr checks 2>/dev/null || echo "no open PR on this branch"`

### Steps

1. **Read PLAN.md** — parse every task reference (e.g. `1A-1`, `1A-2`, `1B-7`) and its
   title in phase order.

2. **Determine last completed task** — map each merged branch name above back to a task
   reference in PLAN.md. The highest task reference found = last completed task.

3. **Determine current in-progress task** — check open PRs for a `task/*` branch.

4. **Determine next task** — first task in PLAN.md order with no merged branch and no open PR.

5. **Flag any gaps** — if a task appears to have been skipped, say so explicitly.

### Output format

**Last completed task**
- Task reference, title, branch merged, date if available

**Currently in progress** (if any)
- Branch, PR link, CI status

**Next task to start**
- Task reference and title from PLAN.md
- Branch name to create
- Key files that will be created or modified

**Uncommitted local changes** (if any)
