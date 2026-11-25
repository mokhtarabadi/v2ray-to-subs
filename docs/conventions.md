# Conventions

This document defines syntax rules, naming conventions, file boundaries, and automation patterns for this project.

## Universal DateTime Standard

All projects in this ecosystem MUST follow these datetime rules:

1. **UTC at Rest** — All databases and caches store datetimes in UTC with `TIMESTAMP WITH TIME ZONE`. Banned: naive or local-time storage.
2. **ISO-8601 with Offset / Epoch ms at API Boundaries** — APIs transmit datetimes as Unix Epoch milliseconds (int64) or ISO-8601 with offset (e.g., `2026-07-23T14:30:00+00:00`). Banned: timezone-naive strings.
3. **Clock Injection** — All current-time access must go through an injectable `Clock` abstraction. Banned: direct `new Date()`, `datetime.now()`, `time.Now()` in business logic.
4. **Dual-Representation for Future Events** — Calendar events expose both `event_start_local` (with timezone) and `event_start_epoch_ms` (absolute).
5. **`TZ=UTC` Infrastructure** — All environments run with `TZ=UTC`. Timezone display is a client-layer responsibility only.

## SOLID Programming Guidelines

Enforce these SOLID principles and pragmatic guardrails in every implementation:

1. **SRP** — One reason to change per module. Split merged concerns.
2. **OCP** — Open for extension, closed for modification. Use composition over inheritance.
3. **LSP** — Subtypes must be substitutable. Ban `NotImplementedError` overrides.
4. **ISP** — Small role-specific interfaces. Ban monolithic god-interfaces.
5. **DIP** — Depend on abstractions, not concretions. Core layer must not import adapters.

**Pragmatic Guardrails:** No abstraction for <3 trivial operations. Only extract interfaces with 2+ implementations. Apply YAGNI strictly. Prefer simpler designs unless a measurable requirement forces complexity.

## Universal Financial Ledger Standard

All financial, transactional, and countable data operations MUST enforce these mandates:

1. **Snapshot-on-Write for Mutable Totals:** Whenever a financial amount, inventory count, or balance is mutated, persist a read-only snapshot of the preceding state in the same transaction (sidecar table, audit log, or WAL). Banned: mutating without preserving the prior value.
2. **Mandatory `$ifNull` Precedence:** All aggregation queries on monetary fields MUST use explicit null-handling (`COALESCE`, `ISNULL`, `$ifNull`). Banned: passing nullable columns into mathematical operators.
3. **Observability Alerting on Discrepancies:** If a computed total diverges from its line-item sum by more than 0.01, emit a high-severity alert and prevent finalization.
4. **Deep Config Merging for Financial Settings:** Financial configuration updates MUST deeply merge nested properties. Banned: shallow object spread on financial config objects.

## Defensive Shell Protocol (DSP)

When writing or reviewing bash scripts, cron jobs, or container orchestration commands:

1. **Mandatory Strict Mode:** All scripts MUST start with `set -euo pipefail`.
2. **Banned Error Masking:** `2>/dev/null` is STRICTLY FORBIDDEN on data-generation, backup, archive, or database commands.
3. **No Post-Redirect Status Checks:** Never use `command > file; if [ $? -eq 0 ]` — the shell creates the file before running the command, masking failures.
4. **Sidecar Isolation for Hostless Backups:** Never rely on host file staging for Docker volume backups. Always use ephemeral containers (`docker run --rm -v volume:/data:ro alpine tar...`) with read-only mounts.

## Edit Tool Discipline

File edits use ONLY native file-editing tools (`edit` for replacements, file-write tools for new files). Using python, shell, heredoc, `sed -i`, or any script to create or modify files is strictly forbidden — scripted edits fail silently (replace-all on non-unique anchors, quoting and encoding mangling) while native tools fail loudly on a non-unique anchor.

1. **Default native only:** one replacement, one location, exact unique anchor. A no-match or multi-match error is a signal, never a retry hint.
2. **No scripted edits:** python, shell, heredoc, and `sed -i` are banned for creating or modifying files. Shell stays read-only for file content (e.g. `grep`, `cat`, `diff`, `ls`, `git status`).
3. **Verify always:** `grep`/`diff` after every edit.

## Task-Number Reference Discipline

Task numbers are provenance for humans, not reasoning material for the model. A bare task number in visible prompt prose invites hallucination: the model treats it as load-bearing context it cannot resolve.

1. **Allowed Homes (only):** code comments (`#`, `//`), `CHANGELOG.md` entries, task files, history archives, and HTML-comment markers (`<!-- -->`).
2. **Forbidden Homes:** visible prose in prompt fragments, agent instruction files, skill instructions, registry lines, section headings, and any Markdown the Brain or Hands reads as operating instructions.
3. **Authoring Rule:** when writing or editing prompt-facing Markdown, strip task-number parentheticals. Record provenance in the task file and CHANGELOG instead — never in the prompt text itself.

## Living Folder Docs Standard

All component and script directories in this repository MUST maintain colocated documentation and decision records:

1. **Folder Colocation** — Every component or script directory (e.g. `scripts/`, `tests/`) must contain:
   - `README.md` — core duties, directory layout, owned files, critical invariants and risks.
   - `DECISIONS.md` — chronological dated Architectural Decision Records. Each entry documents Context, Decision, Consequences, and Rollback strategy.
2. **One-Line Code Pointer Standard** — primary source files include a top-line comment pointing at the sibling docs:
   - Python/Shell: `# Sibling Docs: <relative-path>/README.md | Decisions: <relative-path>/DECISIONS.md`
3. **Synchronization Invariant** — whenever source code inside a component directory changes behavior or data contract, the sibling `README.md` and `DECISIONS.md` MUST be inspected and updated within the same task. Silent overrides of existing architectural decisions are forbidden.

> Current repository state: the root holds a single converter file (`proxy_converter.py`) and no component subdirectories, so no slice README/DECISIONS pairs apply. This standard binds if a component directory is introduced.

## Agent Operational Rules (Cross-Reference)

The operational rules below are normative for this project and are defined in full in `AGENTS.md` (kept there to avoid duplication). This section exists so `docs/conventions.md` documents them as required by the governance audit.

1. **Decentralized Task Management** — Use individual task files in `tasks/backlog`, `tasks/in-progress`, `tasks/qa`, `tasks/completed`, `tasks/archive` as the single source of truth. See `AGENTS.md` "TASK MANAGEMENT & OPENCODE RULES".
2. **No Monolithic State** — Creating `TODO.md` or `STATE.md` is strictly forbidden.
3. **Zero-Autonomous-Commit (ZAC)** — Never execute `git add`, `git commit`, or `git push` autonomously; only on explicit Orchestrator/Manager instruction via the approved MCP commit path. Exception: `git mv` for task-file Kanban moves.
4. **Mandatory End-Of-Task Sequence** — 1) Update `CHANGELOG.md`. 2) Write reasoning in the active task file. 3) Call `custom_context_qa_transition` once with the active task path and explicit `modified_files`. 4) Notify the Manager that QA/review will be chained via `brain_turn`. 5) Do not commit or close without explicit approval.
5. **Gatekeeper Validation (Halt Protocol)** — Evaluate tasks against project rules and HALT with a warning if the Orchestrator provides non-compliant instructions.
6. **Context Bootstrapping** — At the start of every task, call `search_memory` or `list_namespaces` to load hidden project quirks.
7. **Buffer Isolation** — Treat every task as contextually independent; flush working assumptions between tasks.
8. **Context Map Before Brain Calls** — Produce a verified `context_paths` manifest and record a `Context-Map:` line before any planning/verdict `brain_turn`.
9. **Deprecated-Section Purge Rule** — Purge deprecated sections (`## Manager Decisions`, `## Admin Decision`, etc.) from `AGENTS.md` and task files; never recreate them.
10. **Lite Mode Removal** — Lite Mode is a deprecated bypass; every task traverses the full workflow with no bypass.
11. **Runtime-State gitignore** — `.gitignore` must cover per-project runtime state (`tasks/.sessions/`, `.opencode/goals/`, etc.) but never deliberate config like `.opencode/smart-compact.jsonc`.
12. **Project Skills Table** — Scan local skill dirs on every audit and (re)build the Project Skills table in `AGENTS.md`.
13. **MCP Report Generation** — Generate context/tree reports via the MCP server and hand the file path to the Manager; never read `context-reports/` inline.
14. **Explicit Staging Contract (F5)** — Always pass an explicit `modified_files` list to `stage_and_inject_diff`; blind `git add -A .` is banned.
15. **Parallel Index Isolation** — Use `custom_context_unstage_files` (index-only) + `stage_and_inject_diff` with `skip_add=True` for shared files; `git commit`/`git checkout`/`git push` stay forbidden.
