<!--
USER-SET WORKFLOW. DO NOT REWORD, REORDER, SHORTEN OR "IMPROVE". Only the user may change it, in-session.
Agents: copy rows into other files verbatim; never paraphrase the model names or options.
-->

# Locked workflow (set by the user)

## Main orchestrator (CyberSIEM exception: Gemini 4 Neon)
- `antigravity` / `gemini-4-neon`, `thinking_level: low` on low tasks, `thinking_level: medium` on medium and high-risk tasks (never `high` or `xhigh`), for plan, briefs, diff check, gates, mutation checks and commits on every task.
- The main orchestrator and the high-risk writer are both `antigravity` / `gemini-4-neon`, and only those two. The orchestrator never works alone: the writer, reviewer and search rows below still go to their subagents through `delegate_task`.
- Gemini 4 Neon is the only Gemini model allowed in this project.
- Because Antigravity skips `.claude/settings.json` hooks and `.claude/rules/`, every Antigravity brief must explicitly remind the worker to follow ponytail `ultra`, read the matching `.claude/rules/` files (`python.md`, `frontend.md`, `infra.md`), and run the project's graph/query tool and read matching gotchas files if this project has them.

## Standing routing
| Job | Provider and model | Options |
| --- | --- | --- |
| Implementation, tests, fixes of high-risk tasks | `antigravity` / `gemini-4-neon` | `thinking_level: medium` |
| Review of high-risk tasks | `codex` / `gpt-6.2-sol` | `reasoningEffort: high` |
| Implementation, tests, fixes of medium tasks | `codex` / `gpt-6.2-sol` | `reasoningEffort: high` |
| Implementation, tests, fixes of low tasks | `opencode` / `opencode-go/deepseek-v4.1-flash` | `variant: max` |
| Review of medium and low tasks | `opencode` / `opencode-go/glm-5.3-flash` | `variant: max` |
| Read-only codebase search and basic research | `opencode` / `opencode-go/deepseek-v4.1-flash` (or `opencode-go/glm-5.3-flash`) | `variant: max` |

## TEMPORARY OVERRIDE: OpenCode Go exhausted (user, 2026-11-19)
The user's OpenCode Go monthly allowance is nearly spent (about 5% left, resets ~2026-12-02; the user will say when it has reset). While it lasts, these three rows replace the three OpenCode Go rows above. All other rows are unchanged.

| Job | Provider and model | Options |
| --- | --- | --- |
| Implementation, tests, fixes of low tasks | `claudeAgent_2` / `claude-haiku-5-5` | `effort: high` if the model accepts it |
| Review of medium and low tasks | `claudeAgent_2` / `claude-sonnet-5-5` | `effort: high` |
| Read-only codebase search and basic research | `claudeAgent_2` / `claude-haiku-5-5` | `effort: high` if the model accepts it |

- Writer and reviewer stay different models (Haiku writes low tasks, Sonnet reviews medium/low; `gemini-4-neon` writes high-risk tasks, `gpt-6.2-sol` reviews high-risk).
- Haiku 5.5 and Sonnet 5.5 are allowed only under this override. When the user says OpenCode Go has reset, delete this section and the Standing routing applies again.
- Always set Codex `reasoningEffort: high` explicitly (T3 defaults to `low`).
- One fresh-context reviewer per task; subagents only via T3 `delegate_task`.
- No other substitutes. Never OpenCode models while this override is active, never any Gemini model other than Gemini 4 Neon (and never `high`/`xhigh`), never GPT-6 Luna, GPT-6 Astra, GPT-6.2 Astra, GPT-6.1-*, OpenCode free models, Claude native `Agent` tool or launcher scripts.
- A ChatGPT Plus or Claude Pro limit (or OpenCode Go limit under standing routing) pauses the task per the Limit rule in `.claude/run-task.md`; nothing takes over and no model, provider or plan is switched.
