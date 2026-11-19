# CyberSIEM task configuration

Project configuration for the global `delikit` skill, and the dispatch rules
`/task` follows. It wins where it differs from that skill.

- Plan and next task: `docs/STATE.md`; the task file is `docs/tasks/T-NNN.md`.
- Flow: the pipeline in `.claude/skills/task/SKILL.md` (tier, code, review, tests, test, pentest, fix, close, push, land). `/task` and `/delikit run-task` both follow it step for step. Review is never skipped.
- Gates: `task brief -- check`, plus `task brief -- eval` when detection or scoring changed and the `/verify` scans the change needs.
- Constraints: `AGENTS.md`; ponytail ultra, restated in every OpenCode and Antigravity brief because those workers run without the plugin. No Codex or GPT models; for Gemini models, only `gemini-4-neon` at `thinking_level: "high"`.
- High risk: the diff touches auth, sessions, enforcement, scoring, client IP, proxy config, request or log parsing, or audit.
- Review: every code change, by tier (routing below). The pentest follows the task skill.
- Scratch: `.delegate/` (ignored) for briefs, frozen diffs and final reports. Read the report, not the transcript.
- Git: commit the task branch before each dispatch; commit, push and land as the task skill says. No AI attribution.
- Close: the task file and `docs/STATE.md`; stop after one task.

## Worker routing

Workers start only through T3's native `delegate_task`: no dispatch script, CLI
integration or new service. Call `orchestrator_capabilities` once per session
before the first one. The tiers and backups are in `AGENTS.md` "Model routing".
Delegate file reading, searching and basic scraping to `glm-5.3-flash` instead
of spending orchestrator tokens reading large files directly.

| Job | `role` | `target` |
|---|---|---|
| Read, find code, basic scraping | `research` | `opencode`, `opencode-go/glm-5.3-flash`, `options: {variant: "max"}` |
| Write code, chores, apply fixes | `implementation` | `opencode`, `opencode-go/deepseek-v4.1-flash`, `options: {variant: "max"}` |
| Complex / stuck high-risk fixes | `implementation` | enabled Claude instance, `claude-sonnet-5-5`, `options: {effort: "high"}` |
| Write tests | `test` | `opencode`, `opencode-go/claude-haiku-5-5`, `options: {variant: "max"}` |
| Review the diff | `review` | `opencode`, `opencode-go/glm-5.3-flash`, `options: {variant: "max"}` |
| Attack the change | `review` | same |
| High-risk second review | `review` | enabled Claude instance, `claude-sonnet-5-5`, `options: {effort: "high"}` |
| High-risk attack | `review` | enabled Claude instance, `claude-sonnet-5-5`, `options: {effort: "high"}` |
| High-risk Go second opinion | `review` | `opencode`, `opencode-go/glm-5.3`, `options: {variant: "max"}` |

For Claude, take the enabled instance's id and option names from
`orchestrator_capabilities` (for example `claudeAgent_2`), never a guess. Never
use Codex or GPT models; for Gemini models, only `antigravity` `gemini-4-neon`
with `options: {thinking_level: "high"}`. These are routing defaults, not
guarantees of access: if a model is unavailable, report it and ask for a routing
change instead of substituting silently.

## Briefs

Delegate scouting to `glm-5.3-flash` before reading, then write a self-contained brief in `.delegate/` with
five headings: Goal, Context, Do, Don't, Done when. Give exact `path:line`,
numbered requirements, the cases and commands that prove it, the project
invariants that apply, and the report format below. Workers get no conversation
history and must not pick another task or delegate further. Pass the brief's
text in `task`, not its path: a worktree child cannot see ignored files. Keep it
under about 400 words and never include `docs/security/`, customer data or an
exploit recipe; a fix brief states the behaviour required, not the attack.

Workers have no approval channel in a background run: grant no permission
bypass, set no `runtimeMode` above the session's, and tell scouts and reviewers
not to edit files. The Claude role checklists in `.claude/agents/` stay for
Claude Code sessions; a T3 brief restates what it needs, because `delegate_task`
does not select an agent profile.

## Isolation

Go workers always use `isolation: "worktree"`: Go keeps requests for 30 days, so
a Go worker sees only the public committed checkout, never `plan.md`,
`docs/STATE.md`, `docs/tasks/` or `docs/security/`. Commit the task branch
before each dispatch; a worktree starts from the committed HEAD and drops
uncommitted edits. Claude and Antigravity workers may use `isolation: "shared"` on a checkout
with no unrelated changes. Parallel writers always get separate worktrees. If
the checkout contains user work you must not touch, stop and ask before applying
or committing anything.

## Read, review, confirm

1. **Read, then run.** Find the child's checkout (`git worktree list`, or
   `t3_worktree_list` with its `childThreadId`) and read the whole change before
   running anything, untracked new files included (`git status --short`): tests
   execute what the worker wrote. Run the brief's checks yourself. Send a
   failure back with the failing command and the expected result. At most two
   failed repair rounds, then report the unresolved issue; no silent model
   fallback. Each repair or review round is a new `delegate_task`, with the
   earlier findings in its brief.
2. **Freeze and review.** Apply only this task's change to a clean task
   checkout and commit it on the task branch. Freeze it under `.delegate/`,
   untracked new files included, without staging the user's work. In the child
   checkout:
   `git add -A && git diff --cached --binary HEAD > <repo>/.delegate/<task>.diff`,
   then `git reset`. Send it to a different model for independent review:
   GLM-5.3-Flash on every change, and on high risk then Claude Sonnet 5.5 plus Go
   GLM-5.3 (`AGENTS.md` "Model routing"). A
   shared-checkout reviewer gets the frozen diff; a worktree reviewer reads
   `git diff <base>...HEAD` from the committed task branch, so name the base
   ref. Scouts and reviewers never edit files.
3. **Confirm.** Judge every finding against a real case; a confirmed bug gets a
   regression test and a fix, a false one is dropped with the reason. Run the
   gates after the last fix, read the final diff, and report results.

Reports: a writer returns `STATUS: DONE | PARTIAL | BLOCKED`, `CHANGED`, `RAN`,
`RESULT` and `OPEN`; a scout `ANSWER` and `EVIDENCE` with `path:line`; a
reviewer `VERDICT: PASS | FINDINGS`, then each finding with `path:line`, the
failing case and a proposed regression check.
