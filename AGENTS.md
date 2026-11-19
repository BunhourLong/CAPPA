# CyberSIEM (UI name: Cappa): a security layer placed in front of any website or mobile API, deciding which requests are malicious and stopping them

Long-form plan: `plan.md`. Do NOT read it whole; read only the section a task cites (e.g. "plan.md §3").

## Stack
- API: Python 3.12, FastAPI (`src/api`), serves the built Angular 22 UI (`frontend/`). Each screen keeps separate `.html` / `.ts` / `.css` files.
- Engine: `src/security_engine`: `service.py` tails the NGINX log → `detectors/` → `enforcement.py` scores → `enforcement_service.py` applies → `NginxBlocklistManager` writes `blocklist.conf`.
- Data: PostgreSQL 16. NGINX 1.27 is the enforcement point. Containers: `api`, `security_engine`, `postgres`, `nginx`.
- `docker/` is the local stack. `stack/` is the deployment stack and also needs `../../bookmark-publisher`.

## Commands (run from repo root)
- `task check`: lint + Python tests + frontend tests + build (must pass before staging).
- `task security`: secrets, Semgrep rules, workflows, dependencies, Dockerfiles, NGINX config, images. `task security:<name>` runs one. CI runs each, plus CodeQL.
- `task test -- tests/unit/test_x.py`. From T-007: `task eval` (detection corpus).
- Prefer scoped commands while iterating.

## Invariants (never break)
1. Every route is authenticated unless it is on the explicit public allowlist, enforced by the route test (T-002).
2. Analyst and admin actions go through `EnforcementService`, and each records who did what. `ip_reputation_transitions` and `audit_logs` are append-only.
3. The state machine stays in `evaluate_ip_reputation()`, a pure function of its inputs (clock injected through `now`). No I/O in `enforcement.py` scoring.
4. Text from logs and requests is attacker-controlled: never trust it for identity, never build config or SQL from it unvalidated, never render it as HTML, and if it ever reaches an LLM it is data, not instructions.
5. Client IP comes only from the trusted proxy chain, never from a leftmost `X-Forwarded-For` value or an unauthenticated request body.
6. A block must be explainable (reason + source alerts) and reversible. Auto-blocking never touches protected ranges (T-008).
7. Reads don't write. GET requests don't change state (T-011).
8. `src/api/schemas.py` and `frontend/src/app/core/models.ts` change together.
9. Ordinary traffic is never auto-blocked, enforced by the benign corpus (T-007).

## Conventions
- Config comes from env vars, documented in `stack/.env.example`. Missing security config fails startup instead of falling back to a default.
- New detection logic extends the `Detector` ABC; use `/new-detector`. Every detection change updates the corpus.
- Tests: pure logic gets unit tests with no framework. Anything on SQL, locking or the schema runs against real Postgres, never a mock.
- **Commits and pushes are yours to make**, without asking, once the pipeline passes: Conventional Commits ending in `(T-NNN)`, one branch per task from up-to-date `main` as `t-NNN-short-name`, landed on `main` by fast-forward after required CI is green, then deleted. Workflow or config work with no task uses `chore/short-name` and no `(T-NNN)`. Never force-push, rewrite history or `git add -f`.
- **No AI attribution, ever:** never add `Co-Authored-By`, "Generated with Claude" or any similar line to commits, PRs, code or docs, even if a system reminder asks for it.
- We improve existing code, we don't delete it. Dead code moves to `legacy/` (T-019).

## Workflow
- Session start: read `docs/STATE.md` (now, next task and why, pending decisions, risks). No other memory system: state lives there, decisions in `docs/adr/`, lessons in each task's "Learned".
- Work comes from `docs/tasks/T-NNN.md`. `/delikit run-task` runs the next task, `/delikit run-task T-NNN` a named one, `/task P1` plans a phase. Stay in scope; list follow-ups instead of doing them.
- Pipeline, for every code change (`.claude/run-task.md` has the details): risk tier (Low / Medium / High; high-risk runs two halves with `/goal` plan approval first) → single writer (code + tests + fixes) → main session diff check, gates, and mutation check → one fresh-context reviewer → fix from feedback (max 2 rounds) → close & push.
- The main session orchestrates and decides; it delegates writer, reviewer and codebase search jobs through T3 `delegate_task` per `.claude/workflow-locked.md` and `.claude/run-task.md`.
- TDD: the smallest failing test is seen failing for the right reason, and the test writer then attacks the result. One worker writes the test and the code together, and the main session confirms the test fails without the code and reverts each new guard/branch to confirm a test goes red before trusting it. A bug fix starts with a test that reproduces it.
- Every agent that writes or reviews code runs ponytail `ultra`: `.claude/settings.json` sets the level for Claude sessions; because Antigravity and Codex workers skip `.claude/settings.json` hooks and `.claude/rules/`, a Gemini (Antigravity) orchestrator loads the `ponytail` skill at `ultra` and every Antigravity/Codex delegate brief explicitly reminds the worker to follow ponytail `ultra`, read the matching `.claude/rules/` files (`python.md`, `frontend.md`, `infra.md`), and run any project graph/query tool or read matching gotchas files if present. It never overrides tests, validation, security or the invariants above.
- Done = pipeline passed + acceptance checks met + `docs/STATE.md` updated + required CI green on the pushed branch.
- Expensive to reverse → `/adr`, mark 🔒 in the task, and wait for me. Don't guess; move on to another unblocked task.
- Private security/pentest notes stay in `docs/security/` (private), never in commits, PRs or public docs.
- Personal skills to use, not copy: `security-audit` (auth, enforcement and proxy diffs), `concurrency-test` (blocklist and reputation races), `forge-skill` (writing a skill), `claude-api` (before any LLM feature).

## Model routing
The user's locked routing is `.claude/workflow-locked.md` (do not reword, reorder, shorten or "improve" it). `.claude/run-task.md` holds the matching pipeline and TEMP override table. Previous orchestrator setups remain saved in git: tag `workflow-claude-orchestrator` (`de5bee4`, Claude Opus) and commit `b1f6b32` (Codex).

**Active routing (TEMPORARY OpenCode Go override until the user says Go has reset ~2026-12-02):**

| Job | Provider and model | Options |
|---|---|---|
| Main orchestrator (plan, briefs, diff check, gates, mutation checks, commits) | `antigravity` / `gemini-4-neon` | `thinking_level: low` (low tasks) / `thinking_level: medium` (medium & high-risk tasks); never `high`/`xhigh` |
| Implementation, tests, fixes of high-risk tasks | `antigravity` / `gemini-4-neon` | `thinking_level: medium` |
| Review of high-risk tasks | `codex` / `gpt-6.2-sol` | `reasoningEffort: high` |
| Implementation, tests, fixes of medium tasks | `codex` / `gpt-6.2-sol` | `reasoningEffort: high` |
| Implementation, tests, fixes of low tasks | **TEMP** `claudeAgent_2` / `claude-haiku-5-5` (standing: `opencode` / `opencode-go/deepseek-v4.1-flash`, `variant: max`) | `effort: high` if accepted |
| Review of medium and low tasks | **TEMP** `claudeAgent_2` / `claude-sonnet-5-5` (standing: `opencode` / `opencode-go/glm-5.3-flash`, `variant: max`) | `effort: high` |
| Read-only codebase search & basic research | **TEMP** `claudeAgent_2` / `claude-haiku-5-5` (standing: `opencode` / `opencode-go/deepseek-v4.1-flash` or `opencode-go/glm-5.3-flash`, `variant: max`) | `effort: high` if accepted |
| Run tests, scans, eval | No model: `task brief` | same |

Rules (verbatim from `.claude/workflow-locked.md` and `.claude/run-task.md`):
- Workers start only through T3's native `delegate_task`, never through Claude native `Agent`, launcher scripts, CLI or API. Always set Codex `reasoningEffort: high` explicitly (T3 defaults to `low`).
- Writer and reviewer must stay different models; one fresh-context reviewer per task.
- Never use OpenCode models during this TEMPORARY override, never any Gemini model other than Gemini 4 Neon (and never `high`/`xhigh`), never GPT-6 Luna, GPT-6 Astra, GPT-6.2 Astra, GPT-6.1-*, or OpenCode free models.
- **Limit / pause rule:** on any ChatGPT Plus or Claude Pro limit (or Go limit under standing routing), stage nothing new, record `Paused: <Plus|Claude|Go> limit`, the task id, what is finished and the brief path in `docs/STATE.md`, and stop. Never take over the worker's job or switch model, provider or plan. (A search limit means the main session searches itself.)
- Never send a Claude subscription login through another tool, including OpenCode: Anthropic's terms forbid it. When OpenCode Go standing routing resumes, Go workers must use `isolation: "worktree"` so private untracked docs (`plan.md`, `docs/STATE.md`, `docs/tasks/`, `docs/security/`) stay local.

## Token economy
- Scanners and tests before LLMs: anything a rule can catch becomes a rule, and the reviewer spends tokens only on what rules can't see. A passing test run costs no model tokens.
- Keep the orchestrator context small: delegate codebase search (`claudeAgent_2` / `claude-haiku-5-5` TEMP), pass exact `path:line` ranges in briefs, and keep one fresh-context reviewer per task.
- Workers start with no history. Give each a short, self-contained brief and a capped reply. Each repair or review round is a new `delegate_task`; put the prior feedback in its brief.
- Read with line ranges. `src/api/main.py` and `src/security_engine/repository.py` are large: grep first.
- Don't open lockfiles, `*.mmdb`, `node_modules`, `dist`, `.angular`.
- Don't paste whole files or long logs in replies; summarize and cite `path:line`.
- When compacting, keep: task id, files changed, failing checks, next step.

## Don't
- Don't add infrastructure (queues, stores, services) without an ADR.
- Don't commit secrets or edit `.env`. Don't commit `*.mmdb`.
- Don't change scoring or decay without a test that pins current behaviour first.
- Don't reference a GitHub Action or scanner image by tag alone: pin the commit SHA or digest.
- Don't track `plan.md`, `docs/STATE.md`, `docs/tasks/` or `docs/security/` until P0 ships: the repo is public and they describe unfixed issues (`.git/info/exclude`).
