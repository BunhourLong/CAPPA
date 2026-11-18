---
name: task
description: Orchestrate CyberSIEM tasks end to end through the mixed-model pipeline (code, review, tests, pentest, fixes, push), or plan a phase's backlog.
disable-model-invocation: true
argument-hint: "[T-NNN | Pn | empty for the next task]"
---

Target: $ARGUMENTS

- Empty: read `docs/STATE.md` and take its next task. If it has no file yet, create it from `docs/tasks/_TEMPLATE.md` and its row in plan.md §5.
- `T-NNN`: run that task.
- `Pn`: plan that phase (last section), not a task.

You orchestrate and decide. Workers do the work. Stay cheap: give workers short, self-contained briefs, and read their replies, not their transcripts.

## Pick the tier first
**High risk:** the diff touches auth, sessions, enforcement, scoring, client IP, proxy config, request or log parsing, or audit. **Low risk:** everything else, such as docs, tests of existing behaviour, UI, Docker, CI, and mechanical refactors.

| Step | Low risk | High risk |
|---|---|---|
| Find code | `delegate_task`: `research`, DeepSeek V4.1 Flash | same |
| Write code | `delegate_task`: `implementation`, DeepSeek V4.1 Flash | same |
| Review | `delegate_task`: `review`, MiniMax M3 | same, then Codex GPT-6 Astra `review`, plus Go Kimi K3 |
| Write tests | `delegate_task`: `test`, Claude Haiku 5.5 | same |
| Run tests | `task brief -- check` | same |
| Pentest | `delegate_task`: `review`, MiniMax M3, with an attacker brief | same, then Codex GPT-6.2 Astra `review` |

Dispatch, isolation, review and report rules are in `.claude/run-task.md`.
Briefs and frozen diffs go in `.delegate/` (ignored). Pass the brief's text in
`task`, because a worktree child cannot see ignored files. Go workers always
run with `isolation: "worktree"`, so restate the requirements in the brief:
they never see `docs/tasks/` or `docs/security/`. Commit the task branch before
each dispatch. The child gets its own checkout, so **read its whole diff and
run the checks yourself before trusting either**, because tests execute what
was written. One job per brief, under about 400 words, with a word limit
stated. Never put `docs/security/` or customer data in one: a fix brief states
the behaviour required, not the exploit. On a Go failure, retry once through
the same provider with `opencode-go/claude-haiku-5-5` for writing, review and
attack, or `opencode-go/deepseek-v4.1-flash` for tests. If Go is at its usage
limit, go straight to the Codex worker routed in `.claude/run-task.md`. Never switch
models silently.

## Pipeline
1. **Load.** Read the task file. `rg --no-ignore -l '<module>' docs/tasks`, then read only those files' "Learned" sections. If a 🔒 item is undecided, record it in `docs/STATE.md` and skip to the next unblocked task; stop if there's none. Don't guess a 🔒 decision.
2. **Branch** from up-to-date `main`: `git switch -c t-NNN-short-name`.
3. **Write code** through a Go writer: put the goal, files, first failing test, acceptance checks and out-of-scope list in the brief. Read its diff, and confirm the test fails without the code. If it's wrong, delegate again with what to do differently; don't rewrite it yourself.
4. **Review,** by tier, against the task's checks. Every reviewer gets the checks in its brief; a shared-checkout Codex reviewer may also read the task file. On blocking findings, delegate the fix with the findings, then review again.
5. **Write tests** through `delegate_task` (`test`, Claude Haiku 5.5). Read every test before running it: reject any that can't fail, only exercise mocks, or assert too little. A real failing test is a bug: send it to the code's writer, not back to the test.
6. **Test:** `task brief -- check`, plus `task brief -- eval` if detection or scoring changed, plus any `task brief -- security:<name>` that `/verify` lists.
7. **Pentest**, by tier. Save the report to `docs/security/T-NNN.md` (private). Docs-only changes skip this step and step 5, and config-only changes skip step 5 unless the task says otherwise. Review is never skipped.
8. **Fix:** judge every finding yourself. Outside models can be wrong, and never apply one blindly. Real → send it to the writer, add a regression test, rerun steps 4 and 6. False → note why in the private report. Max 2 fix rounds across the task, then stop and write it up in `docs/STATE.md`, with nothing pushed.
9. **Close:** tick the task's checks, set `Status: done`, fill in "Learned" and "Follow-ups", and rewrite `docs/STATE.md` (under 40 lines).
10. **Commit and push:** commit with a Conventional Commit ending in `(T-NNN)`, then `task ship`. The message states what changed, not how to exploit what it fixes. No AI attribution.
11. **Land:** watch the branch's CI (`gh run watch --exit-status`). When `check`, `secrets`, `rules`, `code` and `workflows` are green, then `git switch main && git pull --ff-only && git merge --ff-only <branch> && git push`. On red, treat it as a test failure in step 6. Scanner results that fail outside this diff become follow-ups (T-021), not blockers.

Never push with an open High pentest finding, a failing required check, or a skipped review. Never force-push or rewrite history.

## Then
Stop after every task, once it's landed or blocked. Summarize it, name the next task, and tell me to start a fresh session: `/clear`, then `/task`. Don't start the next task, even if it looks small. Also stop on a 🔒 with nothing else unblocked, a failed fix round, or a change you'd want me to look at first.

## Plan a phase
1. Run the previous phase's exit criteria from plan.md §5. If any fails, report it and stop.
2. Read this phase's rows and only the sections they need. Create one `docs/tasks/T-NNN.md` per row from the template. Keep each session-sized, mark each low or high risk, and make the last task prove the exit criteria.
3. Mark 🔒 anything expensive to reverse.
4. Update `docs/STATE.md`, show me the list and wait for my OK.
