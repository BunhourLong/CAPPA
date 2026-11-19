---
name: task
description: Orchestrate CyberSIEM tasks end to end through the locked mixed-model pipeline (plan/brief, write+tests, check/gates, review, fix, close, push), or plan a phase's backlog.
disable-model-invocation: true
argument-hint: "[T-NNN | Pn | empty for the next task]"
---

Target: $ARGUMENTS

- Empty: read `docs/STATE.md` and take its next task. If it has no file yet, create it from `docs/tasks/_TEMPLATE.md` and its row in plan.md §5.
- `T-NNN`: run that task.
- `Pn`: plan that phase (last section), not a task.

You orchestrate and decide. Workers do the work. Stay cheap: give workers short, self-contained briefs, and read their replies, not their transcripts. Follow `.claude/workflow-locked.md` and `.claude/run-task.md` verbatim.

## Pick the tier first
- **High risk:** touches auth, sessions, enforcement, scoring, client IP, proxy config, request or log parsing, or audit. Runs in two halves (plan + `/goal` approval, then execute).
- **Medium risk:** feature, API, engine, or database work outside the high-risk list.
- **Low risk:** docs, config, tests of existing behaviour, small UI tweaks, Docker/CI chores, and mechanical refactors.

**Active routing (TEMPORARY OpenCode Go override until Go resets ~2026-12-02; see `.claude/workflow-locked.md`):**

| Step | Low risk | Medium risk | High risk |
|---|---|---|---|
| Orchestrate, plan, check, gates | `antigravity` / `gemini-4-neon` (`thinking_level: low`) | `antigravity` / `gemini-4-neon` (`thinking_level: medium`) | `antigravity` / `gemini-4-neon` (`thinking_level: medium`) |
| Read-only search & research | **TEMP** `claudeAgent_2` / `claude-haiku-5-5` (`effort: high` if accepted) | same | same |
| Write code, tests, fixes | **TEMP** `claudeAgent_2` / `claude-haiku-5-5` (`effort: high` if accepted) | `codex` / `gpt-6.2-sol` (`reasoningEffort: high`) | `antigravity` / `gemini-4-neon` (`thinking_level: medium`) |
| Run tests, scans, eval | `task brief -- check` | same | same |
| Review (1 fresh-context reviewer) | **TEMP** `claudeAgent_2` / `claude-sonnet-5-5` (`effort: high`) | **TEMP** `claudeAgent_2` / `claude-sonnet-5-5` (`effort: high`) | `codex` / `gpt-6.2-sol` (`reasoningEffort: high`) |

Dispatch, brief, isolation, review, mutation-check and Limit/pause rules live in `.claude/run-task.md` and `.claude/workflow-locked.md`:
- Always use T3 `delegate_task`; never Claude native `Agent`, launcher scripts, CLI or API. Always set Codex `reasoningEffort: high` explicitly.
- Writer and reviewer stay different models; one fresh-context reviewer per task.
- Every Antigravity (`gemini-4-neon`) brief explicitly reminds the worker to follow ponytail `ultra`, read the matching `.claude/rules/` files (`python.md`, `frontend.md`, `infra.md`), and run any project graph/query tool or read matching gotchas files if present.
- **Limit rule:** if a worker hits a ChatGPT Plus, Claude Pro or OpenCode Go usage limit, stage nothing new, record `Paused: <Plus|Claude|Go> limit`, the task id, what is finished and the brief path in `docs/STATE.md`, and stop. Never take over its work or switch model, provider or plan. (A search limit means the main session searches itself.)

## Pipeline
1. **Load.** Read the task file (`docs/tasks/T-NNN.md`). Search `docs/tasks/` for prior `## Learned` sections touching the same modules. If a `🔒` item is undecided, record it in `docs/STATE.md` and skip to the next unblocked task; stop if there's none. Don't guess a `🔒` decision.
2. **Branch** from up-to-date `main`: `git switch -c t-NNN-short-name`.
3. **High-risk Half 1 (high-risk tasks only).** Confirm mechanism at `path:line`, races, transaction boundaries, failure cases, red test shape and mutation checks; save a one-page plan at `.delegate/<date>-T-NNN.md` and end the turn with a standalone `/goal` prompt for the user. Wait for the user to send it back before writing code.
4. **Write code + tests** through the tier's writer (`delegate_task`): put the goal, exact `path:line` context, red test, acceptance checks, invariants, ponytail `ultra`, matching `.claude/rules/` and out-of-scope list in the brief (saved in `.delegate/T-NNN-writer.md`).
5. **Check & gates (main session).** Read the whole diff (new files included) against the requirements. Confirm the red test fails without the code, and revert each new guard/branch by hand to confirm a test goes red, then restore it. Run `task brief -- check`, plus `task brief -- eval` if detection or scoring changed, plus any `task brief -- security:<name>` that `/verify` lists. Send defects back to the same writer (max 2 rounds, then `BLOCKED` in `docs/STATE.md`). Never fix writer code yourself.
6. **Review (1 fresh-context reviewer).** Freeze the full diff under `.delegate/T-NNN.diff` and send to the tier's reviewer (skip only for a one-file fix with an obvious test). Reviewer checks requirements, edge cases, regression tests, invariants/races/transaction boundaries, and security (using `security-audit` for auth, sessions, enforcement, client IP or proxy diffs; save any private security findings in `docs/security/T-NNN.md`, never in commits).
7. **Fix:** judge every finding yourself. Real → send back to the same writer with a regression test, re-run step 5 and re-review. False → note why (in `docs/security/T-NNN.md` if security-related). Max 2 fix rounds, then stop and record `BLOCKED` in `docs/STATE.md`, with nothing pushed.
8. **Close:** tick the task's checks, set `Status: done`, fill in `Learned` and `Follow-ups` in `docs/tasks/T-NNN.md`, and rewrite `docs/STATE.md` (under 40 lines, naming the next task and its risk).
9. **Commit and push:** stage by explicit path, commit with a Conventional Commit ending in `(T-NNN)`, then `task ship`. No AI attribution.
10. **Land:** watch the branch's CI (`gh run watch --exit-status`). When `check`, `secrets`, `rules`, `code` and `workflows` are green, `git switch main && git pull --ff-only && git merge --ff-only <branch> && git push` and delete the branch. On red, treat it as a test failure in step 5. Scanner results outside this diff become follow-ups (T-021), not blockers.

Never push with an open High security finding, a failing required check, or a skipped review. Never force-push or rewrite history.

## Then
Stop after every task, once it's landed, paused or blocked. Summarize it, name the next task and its risk, and tell the user to start a fresh session: `/clear`, then `delikit run-task`. Don't start the next task, even if it looks small.

## Plan a phase
1. Run the previous phase's exit criteria from plan.md §5. If any fails, report it and stop.
2. Read this phase's rows and only the sections they need. Create one `docs/tasks/T-NNN.md` per row from the template. Keep each session-sized, mark each low, medium or high risk, and make the last task prove the exit criteria.
3. Mark `🔒` anything expensive to reverse.
4. Update `docs/STATE.md`, show the user the list and wait for OK.
