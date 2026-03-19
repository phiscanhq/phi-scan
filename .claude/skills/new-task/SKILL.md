---
name: new-task
description: Start a new PhiScan PLAN.md task — verifies current position, creates the correct branch from main, and confirms what to build before writing any code
disable-model-invocation: true
allowed-tools: Bash, Read, Glob
---

## /new-task

Start a new task. Always verify position in PLAN.md before creating a branch so we never
skip a task or start one out of order.

**Current git state:**
!`git log main --merges --oneline --format="%s" | head -10`

**Open PRs:**
!`gh pr list --state open 2>/dev/null || echo "none"`

### Steps

1. **Verify current position** by cross-referencing the git merge history above with PLAN.md:
   - Parse merged task branches to identify the last completed task
   - Find the next incomplete task in PLAN.md order
   - If the user specified a task reference, confirm it matches the next task in order
   - If it does not match, warn the user and ask them to confirm before proceeding

2. **Confirm we are on main and up to date**
   ```
   git checkout main && git pull origin main
   ```

3. **Determine branch name** from the task reference and a short description:
   - Planned PLAN.md work → `task/<phase><section>-<task-number>-<short-description>`
   - Urgent fix → `hotfix/<short-description>`
   - Maintenance → `chore/<short-description>`

4. **Create and push the branch**
   ```
   git checkout -b task/1A-2-gitignore-file
   git push -u origin task/1A-2-gitignore-file
   ```

5. **Read the task definition from PLAN.md** and present a confirmation summary:
   - Task reference and title
   - Branch name created
   - Files that will be created or modified
   - Acceptance criteria from PLAN.md

6. **Wait for user confirmation** before writing any code.

Do not write any code until the user confirms the summary is correct.
