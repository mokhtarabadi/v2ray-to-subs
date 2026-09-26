# v2ray-to-subs — Project Context Hub

## Project Overview

Python CLI tool that downloads V2Ray subscription links, parses share-link
proxy formats (vmess, vless, trojan, ss, hysteria/hy2, tuic, socks), and
generates ready-to-run `clash_config.yaml` (mihomo) and `singbox_config.json`
(sing-box) with TUN, Fake-IP DNS, Iran/CN bypass routing, and url-test /
load-balance / fallback proxy groups. Live config is refreshed every 6h by a
systemd user timer (`v2ray-to-subs-refresh.timer` → `refresh.sh`) into
`~/.config/mihomo-subs/`. Stack: Python 3.8+ stdlib plus PyYAML; bash
wrappers (`manager.sh`, `refresh.sh`).

## Setup & Dev Commands

- Install: `pip install -r requirements.txt` (or use `.venv/bin/python`)
- Generate: `./manager.sh generate` or `python3 proxy_converter.py`
- Validate: `./manager.sh check` (`mihomo -t` + `sing-box check`)
- Refresh live: `./refresh.sh [url]` (uses converter default when omitted)
- Test: no repo test suite; `mihomo -t -f <config>` is the applicable gate
- Lint (tasks): `lint_task_file` on the active task file

## Actionable Guardrails (Do's & Don'ts)

- **Don't** read `context-reports/` markdown files yourself.
  -> **Do** generate them using the MCP server — context reports via `custom_context_read_source_files`, tree reports via `custom_context_create_tree_report` ("create a tree of the project") — and hand the file path to the Manager.
- **Don't** execute Git commands like `git add`, `git commit`, or `git push` autonomously or try to guess when to stage code.
  -> **Do** execute Git commands ONLY when explicitly instructed by an Orchestrator task block. Otherwise, rely on the `custom_context_stage_and_inject_diff` MCP tool.
  -> **Exception:** `git mv` is permitted autonomously for moving task files between Kanban directories (or plain `mv` when the file is untracked).
- **Don't** guess blindly when facing complex bugs, deadlocks, or silent timeouts.
  -> **Do** utilize the `debug-instrumentation` skill to inject strategic logs and trace the runtime execution path.
- **Don't** write bash scripts without strict mode or mask errors with `2>/dev/null` on data commands.
  -> **Do** follow the Defensive Shell Protocol: `set -euo pipefail`, ban error masking, sidecar isolation for Docker backups. See `docs/conventions.md`.
- **Don't** perform financial mutations without snapshotting the prior state or allow nulls in monetary aggregations.
  -> **Do** follow the Universal Financial Ledger Standard: snapshot-on-write, `$ifNull` precedence, discrepancy alerting, deep config merging. See `docs/conventions.md`. (No financial logic exists in this project today; the rule binds if any is added.)
- **Don't** leave task numbers in visible prompt prose, section headings, or skill instructions.
  -> **Do** keep task-number references in code comments, CHANGELOG entries, task files, history archives, and HTML comments only. See `docs/conventions.md`.
- **Don't** carry over assumptions, partial results, or architectural hypotheses from a previous task.
  -> **Do** flush context and treat every task as contextually independent (Buffer Isolation directive in validation-phase).
- **Don't** execute raw, informal, or non-English prompts directly.
  -> **Do** load the `prompt-refactor` skill to translate and expand the intent into an elite English spec first. (Note: If you receive a standard XML task block, skip this and execute normally).
- **Don't** attempt to resolve cross-disciplinary ambiguity within a single persona.
  -> **Do** trigger the Multi-Agent Brainstorming Loop if the Manager explicitly requests brainstorming or a task exhibits cross-disciplinary ambiguity. Interpret the `<brainstorming_session>` results in backlog tasks as non-functional guidelines that govern execution.
- **Don't** emit YAML values that Go-YAML can misread (e.g. REALITY `short-id: 2e00` parses as float 2.0).
  -> **Do** force double-quoted scalars for hex/opaque strings in generated Clash configs (see `_QuotedStr` in `proxy_converter.py`).

## Documentation Sync Rules

When modifying this repository, you must keep these files synchronized:

1. Active task file in `tasks/` (single source of truth for current work items)
2. `CHANGELOG.md` (Keep a Changelog format)
3. `DESIGN.md` (absent — no frontend in this project; UI/UX rule below does not apply)
4. `docs/conventions.md` (syntax rules, datetime standard, SOLID guidelines)
5. Relevant `SKILL.md` files (if structural patterns were altered)

## 🛑 GATEKEEPER VALIDATION (HALT PROTOCOL)

You (the Hands) are the final gatekeeper. Before executing any implementation task, you MUST evaluate the Orchestrator's instructions against this file and any referenced specs (`docs/architecture.md`, `docs/data_model.md`, etc.). If the instructions violate project rules, ignore them. HALT immediately and output a `⚠️ RULE VIOLATION WARNING` back to the Manager explaining exactly what the Orchestrator got wrong, forcing it to self-correct.

## 🛑 CORE FILE LOCATIONS

You MUST strictly adhere to these exact paths. Do not create duplicates elsewhere:

- **Global Rules:** `AGENTS.md` (Root)
- **UI/UX Specs:** `DESIGN.md` (Root — absent; this project has no frontend, noted per Absent-File Policy)
- **Conventions:** `docs/conventions.md`
- **Active Tasks:** `tasks/backlog/<task-number>-<name>.md` (backlog), `tasks/in-progress/`, `tasks/qa/`, `tasks/completed/`, `tasks/archive/`

## 🛑 SKILL LOADING RULES

You MUST follow these skill loading rules in every session:

- **Task-Generator Skill:** Before creating any new task file, you MUST load the `task-generator` skill using the `skill` tool to ensure the correct template format with `<!-- BEGIN_GIT_DIFF -->` / `<!-- END_GIT_DIFF -->` markers.
- **Project Skills:** Before implementing any task, you MUST load every available skill matching the project's tech stack. This project is plain Python (stdlib plus PyYAML) with bash wrappers — no roster skill matches, so none is required unless the stack changes.

## 🛑 CONTEXT BOOTSTRAPPING

At the start of every task, you MUST call `search_memory` or `list_namespaces` to load any hidden project quirks relevant to your domain before implementing.

## 🛑 TASK MANAGEMENT & OPENCODE RULES

- **Decentralized Task Management:** Use decentralized, individual task files in the Kanban directories as the single source of truth.
- **No Monolithic State:** Creating `TODO.md` or `STATE.md` is strictly forbidden.
- **Zero-Autonomous-Commit:** Never execute `git add`, `git commit`, or `git push` autonomously; only on explicit Orchestrator/Manager instruction via the approved MCP commit path. **Exception:** `git mv` for task-file Kanban moves.
- **Explicit Staging Contract (F5):** Always pass an explicit `modified_files` list to `stage_and_inject_diff` — blind `git add -A .` is banned.
- **MCP Report Generation:** Generate context/tree reports via the MCP server and hand the file path to the Manager instead of reading report files inline.

## 🛑 MANDATORY END-OF-TASK SEQUENCE

When finishing a task, you MUST execute these exact steps in order:

1. **Update Changelog:** You MUST insert a formal entry into CHANGELOG.md logging your modifications.
2. **Write your Summary:** Manually write your architectural reasoning, local TODO checks, and execution notes into the active `tasks/XX-task.md` file under "Execution Log & Reasoning".
3. **Call MCP Tool & QA Transition:** Call the `custom_context_stage_and_inject_diff` MCP tool. After injection, you MUST move the task file to `tasks/qa/` via `git mv` before notifying the Manager (implementation tasks only — discovery tasks stay in place). DO NOT execute any `git commit` commands. Closure to `tasks/completed/` happens ONLY after the Manager explicitly says "Approved for closure" or "Close task".
4. **Kanban Metadata Synchronization (mandatory after ANY authorized `git mv`):** After the move, update the task file's `**File:**` metadata header to the new path. If the move happened AFTER staging, re-run `lint_task_file` and call `custom_context_stage_and_inject_diff` AGAIN with the NEW task path and the full `modified_files` array before notifying the Manager — the re-stage keeps the injected diff and staging state in sync with the final path. Never notify the Manager with a stale `**File:**` header.
5. **Notify Manager:** Output exactly: "Task ready. Manager, please copy the contents of `tasks/XX-task.md` and send it back to the Orchestrator Brain for review."
