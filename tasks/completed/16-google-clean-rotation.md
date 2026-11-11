# Task 16: Google-clean rotation gate for the balancer

**File:** `tasks/qa/16-google-clean-rotation.md`
**Source:** manager
**Type:** feature
**Status:** in-progress
**Submitted:** 2026-11-11T12:14:24Z

## Goal

Stop the balancer from selecting exit nodes whose Google Search answers the
`/sorry` anti-abuse page. Every rotation candidate must return HTTP 200 for
`https://www.google.com/search?q=test` before it becomes the active node;
302 (`/sorry`) candidates are quarantined with a `google` cause.

## Manager's Notes

Manager context (paraphrased): Spotify and YouTube Music intermittently report
"not available in your country"; the server IP geolocates inconsistently and
Google sometimes blocks it. Manager asked whether mihomo itself could filter
based on which exits have a working Google Search, and to implement, redeploy
and test it in this repo.

Measurement first (2026-11-11): a 40-node sweep through mihomo's delay API
showed 27/40 nodes alive on gstatic and 27/40 passing the Google Search check
(no gstatic-only survivors). The active PROXY selection at the time
(`vless-0c0b9e2377bd`) answered 302 `/sorry`, which is the failure this gate
prevents.

## Key Finding (pre-implementation)

Google Search is the only cheap discriminator. `generate_204`, `gen_204` and
the autocomplete endpoints answer identically (204/200) on blocked and clean
IPs; only `/search` redirects flagged exits to `/sorry` (302, ~400 bytes)
while clean exits return 200 (~94 KB). The gate therefore costs one search
request per candidate rotation, not per node per interval.

**mihomo's `/delay` endpoint cannot see the block**: it follows the 302 to
`/sorry` and reports the final 200, so `expected=200` passes on a blocked
exit. Verified live — `expected=200` returned `{"delay":363}` for a node that
answered 302 through the same selector. The gate therefore reads Google
through the live mixed-port with redirects disabled.

The live PROXY group is a `Selector` driven by `scripts/rr_balancer.py`
(rotate every few minutes), so mihomo's own `url-test` health check on the
`Auto` group does not control the active path. The gate belongs in the
balancer's rotation decision.

## Design

- `ClashAPI.delay()` gains an optional `expected` status passed to mihomo's
  `/proxies/{name}/delay` endpoint (kept for callers that want it).
- `probe_status_via_proxy(url, proxy, timeout)` reads the URL through the
  mihomo mixed-port with `_NoRedirect`, returning the real 302/200.
- `google_clean(api, group, name, ...)` selects the candidate and probes it
  through the live selector, so the check matches what a client sees.
- `google_reachable_direct(url)` probes the same URL from the host without a
  proxy. If it fails, the gate is skipped for that run so a Google outage
  cannot quarantine the whole pool (infra guard).
- `cmd_rotate` walks the pool in the existing preference order
  (uses → quota_fails → delay), rejects up to `--google-attempts` candidates
  for `/sorry`, records them with `_mark_failed(..., "google")` (24 h
  quarantine, new `google_fails` counter), and fails open to the best
  candidate if every attempt is blocked.
- New flags on `rotate` / `skip` / `next`: `--google-url`,
  `--google-timeout-ms`, `--google-attempts`, `--no-google-check`.
- Schema: `google_fails` column plus an idempotent migration for existing DBs.
- `retest` is unchanged: the gate runs at rotation time to keep bandwidth
  flat (one ~94 KB request per candidate instead of a 500-node sweep).

## Local TODOs

- [x] Add `expected` support to the delay probe
- [x] Add `google_clean` + direct-reachability guard
- [x] Add `google` failure cause, counter, schema column and migration
- [x] Gate `cmd_rotate` with bounded attempts and fail-open
- [x] Add CLI flags and validation
- [x] Add unit tests (skip blocked, fail open)
- [x] Full test suite green
- [x] Live rotation verified against a blocked node
- [x] Stage + QA transition

## Acceptance Criteria

- [x] A blocked candidate is quarantined with `last_fail_cause='google'`
- [x] Rotation selects a Google-clean candidate when one exists
- [x] All-blocked pool fails open instead of selecting nothing
- [x] `--no-google-check` restores the previous behavior
- [x] Full test suite passes
- [x] Live `curl` through mihomo returns 200 for Google Search after rotation

## Definition of Done

- [x] Rotation skips and quarantines `/sorry` exits with cause `google`
- [x] Clean candidate is selected and verified live (200)
- [x] Fail-open path covered by a unit test
- [x] Full test suite green (58 passed)
- [x] CHANGELOG, README, schema and task docs updated
- [x] Sibling slice docs (`scripts/README.md`, `scripts/DECISIONS.md`) added
- [ ] Manager commit/push

## Verification Evidence

- **Format command:** `.venv/bin/black --check scripts/rr_balancer.py tests/test_rr_balancer.py`
- **Expected result:** both files already formatted
- **Actual result:** `2 files would be left unchanged` (after fixing the drift noted below)
- **Exit code:** 0

- **Test command:** `rtk test .venv/bin/python -m pytest tests/ -q`
- **Expected result:** full suite green with preserved exit code
- **Actual result:** `58 passed in 0.67s`
- **Exit code:** 0

- **Test command:** `.venv/bin/python -m pytest tests/test_rr_balancer.py -q`
- **Expected result:** all balancer tests pass, including the two new gate tests
- **Actual result:** 36 passed
- **Exit code:** 0

- **Test command:** `.venv/bin/python -m pytest tests/ -q`
- **Expected result:** full suite green
- **Actual result:** 58 passed
- **Exit code:** 0

- **Test command:** `.venv/bin/python -m py_compile scripts/rr_balancer.py`
- **Expected result:** compiles
- **Actual result:** COMPILE_OK
- **Exit code:** 0

- **Live check before:** `curl -x 127.0.0.1:7890 https://www.google.com/search?q=test`
- **Expected result:** 302 (active node `vless-0c0b9e2377bd` blocked)
- **Actual result:** 302, location `https://www.google.com/sorry/index?...`
- **Exit code:** 0

- **Live rotation:** `scripts/rr_balancer.py next --reason google`
- **Expected result:** blocked node quarantined, a clean candidate selected
- **Actual result:** `skip: marked vless-0c0b9e2377bd failed (google, quarantined 24h)` → `rotate: selected hysteria2-95535cec6abf (delay 15ms)`
- **Exit code:** 0

- **Live check after:** `curl -x 127.0.0.1:7890 https://www.google.com/search?q=test`
- **Expected result:** 200
- **Actual result:** 200
- **Exit code:** 0

- **Gate discrimination:** `probe_status_via_proxy` against each node
- **Expected result:** blocked 302, clean 200
- **Actual result:** `vless-0c0b9e2377bd → 302`, `hysteria2-95535cec6abf → 200`
- **Exit code:** 0

- **DB state:** `SELECT name,status,last_fail_cause,google_fails FROM nodes WHERE google_fails>0`
- **Expected result:** both rejected nodes recorded with cause `google`
- **Actual result:** `vless-0c0b9e2377bd failed google 1`, `hysteria2-f069184d3bd9 failed google 1`
- **Exit code:** 0

## Risk & Rollback

- **Brief flapping during probing**: the gate selects a candidate to probe it, so a rejected node carries traffic for ~0.3s before the next candidate is tried. Bounded by `--google-attempts` (5).
- **Google outage**: `google_reachable_direct` fails first and the gate is skipped for that run, so a Google-side incident cannot quarantine the pool.
- **Cost**: one search request per candidate (~94 KB on a pass, ~0.4 KB on a block); at normal rotation rates this is negligible.
- **Rollback**: `--no-google-check` disables the gate instantly; the new `google_fails` column is additive and old code ignores it, so reverting the script alone is safe.

## Execution Log & Reasoning

- The gate lives in `cmd_rotate` rather than a mihomo `url-test` group because
  the live path is a `Selector` rotated by this script; changing the `Auto`
  group would not affect it.
- `/search` is the only endpoint that distinguishes `/sorry`, so the probe is
  intentionally heavier than the gstatic liveness check. Running it once per
  rotation keeps total traffic low.
- Fail-open on an all-blocked pool preserves availability; the alternative
  (no-op) would leave the client without a proxy.
- Correction after the first live attempt: mihomo's `/delay?expected=200`
  returned success for a node that answered 302 to real traffic, because the
  probe follows the `/sorry` redirect to a 200 page. The probe was moved to
  the live mixed-port with redirects disabled; the API path is kept only for
  callers that still want it.
- QA-gate pass: `black --check` failed on the two changed files (black is the
  project's configured formatter) because the new `order_pool` signature and
  the patch context-manager blocks were not in black's shape. Fixed with native
  edits; the formatter now reports both files unchanged. The remaining `ruff`
  findings are pre-existing in this file (baseline at `HEAD` reports 66, the
  categories `UP006`/`UP031`/`BLE001` exist throughout) and ruff is not part of
  this project's documented gate, so no style rewrite was attempted.
- Added `scripts/README.md` and `scripts/DECISIONS.md` (with the Google-gate
  ADR) plus a code-pointer line in the script, per the Living Folder Docs
  standard. `AGENTS.md`, `docs/conventions.md`, and `.gitignore` were audited
  in the same session; they are staged alongside this task's files and listed
  in the injected diff, because the Manager asked for the audit and the task
  work in one instruction.
- Live evidence still stands as recorded: the blocked node
  (`vless-0c0b9e2377bd`) quarantined with cause `google`, the clean candidate
  (`hysteria2-95535cec6abf`) selected, and `curl` through `127.0.0.1:7890`
  returning 200 after rotation. No re-run was needed for this gate pass.
- Lane note: the file already sat in `tasks/qa/`, so `custom_context_qa_transition`
  (which requires `tasks/in-progress/`) was not applicable; staging and diff
  injection ran through `custom_context_stage_and_inject_diff` with the explicit
  file list instead.

### QA Round — QA Engineer: QA_PASSED

- Verdict `QA_PASSED`, no blocking findings. Confirmed: idempotent migration
  (fresh CREATE plus ALTER-if-missing both carry `google_fails`), attempts
  bounded by `max(1, google_attempts)` with fail-open to `ordered[0]`, the
  direct-reachability guard preventing mass quarantine, 302 surfaced on both
  the normal response and the `HTTPError` path, and CLI validation rejecting
  `--google-timeout-ms < 500` and `--google-attempts < 1`.
- Risks accepted: a transport `None` counts as blocked, which is safe because
  the direct guard already proved Google reachable (so the failure is
  node-specific); `skip` accepts the Google flags without consuming them while
  `next` forwards them to `rotate`.
- Follow-up (non-blocking, not implemented): a unit test for the
  direct-unreachable skip path. Recommended for a later task so the reviewed
  diff is not changed after the QA verdict.

### Review Round — Code Reviewer: APPROVED (PO_REVIEW_PENDING)

- Verdict `APPROVED`, no blocking defects. Confirmed: gate placed in
  `cmd_rotate` as designed, probe through the live mixed-port with redirects
  disabled, direct-reachability guard, bounded attempts with fail-open,
  additive idempotent schema migration, consistent CLI surface with
  validation, two meaningful unit tests that keep the rest network-free, and
  CHANGELOG/README/`scripts` docs matching the code.
- Notes accepted as low severity: `skip` accepts the Google flags without
  consuming them (parser uniformity, `next` forwards them), `--google-proxy`
  is a fifth flag beyond the four named in Design (documented in CHANGELOG),
  and the direct probe uses `urlopen` so host proxy env vars would apply (none
  set here). Recommendations: add the direct-unreachable unit test in a later
  task and keep this diff stable.
- State: `PO_REVIEW_PENDING`. Awaiting the Manager's explicit closure word.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/.gitignore b/.gitignore
index 66d4164..2444c59 100644
--- a/.gitignore
+++ b/.gitignore
@@ -51,6 +51,13 @@ context-reports/
 # Brain session transcripts (per-project runtime state)
 tasks/.sessions/
 
+# Goal plugin runtime state (per-session scratch, never project truth)
+.opencode/goals/
+.opencode/goal-state.json
+.opencode/goal-evidence.json
+.opencode/STOP_GOAL
+STOP_GOAL
+
 # External balancer runtime state (SQLite, rebuilt by retest)
 data/*.db
 data/*.db-journal
diff --git a/AGENTS.md b/AGENTS.md
index 70c5e9f..2c87f7c 100644
--- a/AGENTS.md
+++ b/AGENTS.md
@@ -75,7 +75,7 @@ You MUST strictly adhere to these exact paths. Do not create duplicates elsewher
 
 You MUST follow these skill loading rules in every session:
 
-- **Task-Generator Skill:** Before creating any new task file, you MUST load the `task-generator` skill using the `skill` tool to ensure the correct template format with `<!-- BEGIN_GIT_DIFF -->` / `<!-- END_GIT_DIFF -->` markers.
+- **Task-Generator Skill:** Before creating any new task file, you MUST load the `kanban-lifecycle` skill using the `skill` tool to ensure the correct template format with `<!-- BEGIN_GIT_DIFF -->` / `<!-- END_GIT_DIFF -->` markers.
 - **Project Skills:** Before implementing any task, you MUST load every available skill matching the project's tech stack. This project is plain Python (stdlib plus PyYAML) with bash wrappers — no roster skill matches, so none is required unless the stack changes.
 
 ## 🛑 CONTEXT BOOTSTRAPPING
@@ -88,6 +88,9 @@ At the start of every task, you MUST call `search_memory` or `list_namespaces` t
 - **No Monolithic State:** Creating `TODO.md` or `STATE.md` is strictly forbidden.
 - **Zero-Autonomous-Commit:** Never execute `git add`, `git commit`, or `git push` autonomously; only on explicit Orchestrator/Manager instruction via the approved MCP commit path. **Exception:** `git mv` for task-file Kanban moves.
 - **Explicit Staging Contract (F5):** Always pass an explicit `modified_files` list to `stage_and_inject_diff` — blind `git add -A .` is banned.
+- **Parallel Index Isolation:** When two tasks run in parallel and share files, touch only your own task's files. If foreign hunks land in your staged diff, call `custom_context_unstage_files` with exactly those files (index-only), redo your hunk-level staging, then call `custom_context_stage_and_inject_diff` with `skip_add=True`. `git commit`, `git checkout`, and `git push` stay forbidden everywhere.
+- **Edit Tool Discipline:** File edits use ONLY native file-editing tools (`edit` for replacements, file-write tools for new files). Using python, shell, heredoc, or `sed -i` to create or modify files is forbidden; shell stays read-only for file content (`grep`, `cat`, `diff`, `ls`, `git status`). A non-unique anchor must fail loudly and be widened, never forced. See `docs/conventions.md`.
+- **Living Folder Docs Inspection:** Before modifying code inside a component or script directory, read the sibling `README.md` and `DECISIONS.md`, and update them when domain contracts or architectural decisions change.
 - **MCP Report Generation:** Generate context/tree reports via the MCP server and hand the file path to the Manager instead of reading report files inline.
 
 ## 🛑 MANDATORY END-OF-TASK SEQUENCE
@@ -96,10 +99,6 @@ When finishing a task, you MUST execute these exact steps in order:
 
 1. **Update Changelog:** You MUST insert a formal entry into CHANGELOG.md logging your modifications.
 2. **Write your Summary:** Manually write your architectural reasoning, local TODO checks, and execution notes into the active `tasks/XX-task.md` file under "Execution Log & Reasoning".
-3. **Call MCP Tool & QA Transition:** Call the `custom_context_stage_and_inject_diff` MCP tool. After injection, you MUST move the task file to `tasks/qa/` via `git mv` before notifying the Manager (implementation tasks only — discovery tasks stay in place). DO NOT execute any `git commit` commands. Closure to `tasks/completed/` happens ONLY after the Manager explicitly says "Approved for closure" or "Close task".
-4. **Kanban Metadata Synchronization (mandatory after ANY authorized `git mv`):** After the move, update the task file's `**File:**` metadata header to the new path. If the move happened AFTER staging, re-run `lint_task_file` and call `custom_context_stage_and_inject_diff` AGAIN with the NEW task path and the full `modified_files` array before notifying the Manager — the re-stage keeps the injected diff and staging state in sync with the final path. Never notify the Manager with a stale `**File:**` header.
-5. **Notify Manager:** Output exactly: "Task ready. Manager, please copy the contents of `tasks/XX-task.md` and send it back to the Orchestrator Brain for review."
-
-## 🛑 LITE MODE PROTOCOL (`<lite_mode_protocol>`)
-
-When a change is eligible — single file, no security or financial impact, obvious simplicity — the full production line may be bypassed: record a `[LITE]` justification with the eligibility reason in the task file's `## Execution Log & Reasoning` section and proceed. Escalation to Full Mode is mandatory if hidden complexity is discovered mid-task.
+3. **Call MCP Tool & QA Transition:** Call `custom_context_qa_transition` once with the active task path and an explicit `modified_files` list. It atomically moves the task to `tasks/qa/`, synchronizes the `**File:**` header, stages the changes, and injects the diff. Do not run a separate task move, header edit, or re-stage. DO NOT execute any `git commit` commands. Closure to `tasks/completed/` happens ONLY after the Manager explicitly says "Approved for closure" or "Close task".
+4. **Kanban Metadata Sync:** `custom_context_qa_transition` already keeps the `**File:**` header and the injected diff in sync. If an authorized `git mv` happened outside that tool, update the header, re-run `lint_task_file`, and re-stage with the NEW task path and the full `modified_files` array before notifying the Manager. Never notify the Manager with a stale `**File:**` header.
+5. **Notify Manager:** Report that the task is in `tasks/qa/` and that QA/review will be chained directly through `brain_turn`. Never ask the Manager to copy, paste, or relay task contents.
diff --git a/CHANGELOG.md b/CHANGELOG.md
index ab7bca5..5b1003a 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -23,6 +23,12 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 - Upstream parity fixes (task 12): emit vless `encryption` to Clash only for values mihomo accepts (`mlkem768x25519plus…`), drop unusable values like `aes-128-gcm` that fail validation.
 - Stable identity-hash node naming (task 13): converter emits `{proto}-{12hex}` names derived from protocol + normalized host + port (SHA-256), replacing provider remarks that reshuffled or collided each refresh; deterministic sort-then-suffix collision fallback; Clash keeps the original remark in a `remark` key while sing-box omits it (schema rejects unknown fields); balancer history (delay/fails/uses/quarantine) now survives feed refreshes; `tests/test_stable_hash_naming.py` (10 tests).
 - Geo-block failure cause (`region`): balancer `--reason` accepts `region` and counts it separately (`region_fails` column via idempotent migration, old DBs self-upgrade); the OpenCode rescue plugin now detects `RegionError` ("model is not available in your country/region") model-independently and rotates the exit with the same 2s rescue; exits refused by a provider's country check quarantine 24h like other causes.
+- Google-clean rotation gate: `scripts/rr_balancer.py` probes each rotation candidate's Google Search through the live mihomo mixed-port with redirects disabled; exits answering 302 `/sorry` are quarantined with a new `google` cause and `google_fails` counter (idempotent schema migration). Bounded by `--google-attempts` with fail-open on an all-blocked pool and a direct-reachability infrastructure guard; `--no-google-check` restores the previous behavior. New flags: `--google-url`, `--google-timeout-ms`, `--google-proxy`, `--google-attempts`, `--no-google-check`; `tests/test_rr_balancer.py` covers skip and fail-open.
+- Balancer slice docs: `scripts/README.md` (duties, invariants, risks) and `scripts/DECISIONS.md` (dated ADRs for the Google-clean gate, identity-hash naming, and the `region` cause) with a code-pointer line in `scripts/rr_balancer.py`.
+
+### Changed
+
+- `AGENTS.md` brought in line with the audit criteria: the lite-mode bypass removed so every task runs the full workflow, the task-generator reference corrected to `kanban-lifecycle`, the QA transition routed through `custom_context_qa_transition`, and Edit Tool Discipline, Parallel Index Isolation, and Living Folder Docs Inspection rules added. `docs/conventions.md` gained the Edit Tool Discipline and Living Folder Docs Standard sections; `.gitignore` now covers goal-plugin runtime state.
 
 ### Fixed
 - Hysteria2 links carrying `fp=` now emit `client-fingerprint`; mihomo rejects a uTLS name under `fingerprint` (that key is a TLS certificate pin) and aborts the whole `mihomo -t` run.
diff --git a/README.md b/README.md
index d1925b3..e9c1e10 100644
--- a/README.md
+++ b/README.md
@@ -164,7 +164,8 @@ when a target rate-limits an exit IP, the crawler reports the cause
 and the balancer moves traffic to the next best node automatically:
 
 - **Rotate**: manual only — bare `rr` skips the current node and picks least-used + fastest (`rr-rotate.timer` is intentionally disabled)
-- **Failure causes**: `rr next --reason quota|transport|region` (default `manual`) records per-cause counters; selection order is least-used, then fewest quota fails, then fastest — exits that hit crawl rate limits sink in priority without being deleted; `region` (geo-blocked from a provider country check) is tracked separately and quarantined like the others
+- **Failure causes**: `rr next --reason quota|transport|region|google` (default `manual`) records per-cause counters; selection order is least-used, then fewest quota fails, then fastest — exits that hit crawl rate limits sink in priority without being deleted; `region` (geo-blocked from a provider country check) is tracked separately and quarantined like the others
+- **Google-clean gate**: before selecting a node, rotation reads `https://www.google.com/search?q=test` through the candidate (live mixed-port, redirects disabled). Exits answering 302 `/sorry` are quarantined with cause `google` (24h, `google_fails` counter). A node that passes stays selected; up to `--google-attempts` candidates are rejected, then the best remaining is used so the client never goes dark. `--no-google-check` disables it; the check is skipped when Google is unreachable directly (infra guard)
 - **Retest**: 500 oldest controller-present nodes every 30 minutes (`rr-retest.timer`), dead nodes readmitted on recovery
 - **Freshness**: nodes unchecked for over 2h sit out until rechecked
 - **Stable names**: nodes are named by identity hash (`{proto}-{12hex}` from server + port), so balancer history survives every feed refresh; the provider remark is kept in the Clash `remark` field for humans
diff --git a/data/balancer_state.schema.sql b/data/balancer_state.schema.sql
index a444dfb..4b5f59f 100644
--- a/data/balancer_state.schema.sql
+++ b/data/balancer_state.schema.sql
@@ -9,7 +9,8 @@ CREATE TABLE IF NOT EXISTS nodes (
   last_fail_cause TEXT NOT NULL DEFAULT '',
   quota_fails INTEGER NOT NULL DEFAULT 0,
   transport_fails INTEGER NOT NULL DEFAULT 0,
-  region_fails INTEGER NOT NULL DEFAULT 0
+  region_fails INTEGER NOT NULL DEFAULT 0,
+  google_fails INTEGER NOT NULL DEFAULT 0
 );
 
 CREATE TABLE IF NOT EXISTS rotation_state (
diff --git a/docs/conventions.md b/docs/conventions.md
index f8a8fe2..9e1f4b5 100644
--- a/docs/conventions.md
+++ b/docs/conventions.md
@@ -42,6 +42,25 @@ When writing or reviewing bash scripts, cron jobs, or container orchestration co
 3. **No Post-Redirect Status Checks:** Never use `command > file; if [ $? -eq 0 ]` — the shell creates the file before running the command, masking failures.
 4. **Sidecar Isolation for Hostless Backups:** Never rely on host file staging for Docker volume backups. Always use ephemeral containers (`docker run --rm -v volume:/data:ro alpine tar...`) with read-only mounts.
 
+## Edit Tool Discipline
+
+File edits use ONLY native file-editing tools (`edit` for replacements, file-write tools for new files). Using python, shell, heredoc, `sed -i`, or any script to create or modify files is strictly forbidden — scripted edits fail silently (replace-all on non-unique anchors, quoting and encoding mangling) while native tools fail loudly on a non-unique anchor.
+
+1. **Default native only:** one replacement, one location, exact unique anchor. A no-match or multi-match error is a signal, never a retry hint.
+2. **No scripted edits:** python, shell, heredoc, and `sed -i` are banned for creating or modifying files. Shell stays read-only for file content (e.g. `grep`, `cat`, `diff`, `ls`, `git status`).
+3. **Verify always:** `grep`/`diff` after every edit.
+
+## Living Folder Docs Standard
+
+All component and script directories in this repository MUST maintain colocated documentation and decision records:
+
+1. **Folder Colocation** — Every component or script directory (e.g. `scripts/`, `tests/`) must contain:
+   - `README.md` — core duties, directory layout, owned files, critical invariants and risks.
+   - `DECISIONS.md` — chronological dated Architectural Decision Records. Each entry documents Context, Decision, Consequences, and Rollback strategy.
+2. **One-Line Code Pointer Standard** — primary source files include a top-line comment pointing at the sibling docs:
+   - Python/Shell: `# Sibling Docs: <relative-path>/README.md | Decisions: <relative-path>/DECISIONS.md`
+3. **Synchronization Invariant** — whenever source code inside a component directory changes behavior or data contract, the sibling `README.md` and `DECISIONS.md` MUST be inspected and updated within the same task. Silent overrides of existing architectural decisions are forbidden.
+
 ## Task-Number Reference Discipline
 
 Task numbers are provenance for humans, not reasoning material for the model. A bare task number in visible prompt prose invites hallucination: the model treats it as load-bearing context it cannot resolve.
diff --git a/scripts/DECISIONS.md b/scripts/DECISIONS.md
new file mode 100644
index 0000000..3998b95
--- /dev/null
+++ b/scripts/DECISIONS.md
@@ -0,0 +1,60 @@
+# scripts/ — Architecture Decision Records
+
+Chronological. Each entry: Context, Decision, Consequences, Rollback.
+
+## 2026-11-11 — Google Search status is the anti-abuse discriminator
+
+**Context.** Exit nodes used by crawl and media traffic get flagged by
+Google; flagged IPs answer `https://www.google.com/search?q=test` with a 302
+to `/sorry`, and clients see "not available in your country" on some
+services. Lightweight Google endpoints (`generate_204`, suggest) answer
+identically on flagged and clean IPs, so they cannot discriminate.
+mihomo's own `/delay?expected=200` follows the redirect and reports the final
+200, so it also cannot see the block.
+
+**Decision.** The balancer gates rotation on a real HTTP status read of
+`/search` taken through the live mixed-port (`127.0.0.1:7890`) with
+redirects disabled. A 302 quarantines the candidate with cause `google`
+(24 h) and increments `google_fails`; rotation then tries the next candidate
+up to `--google-attempts`, and fails open to the best remaining node when
+every attempt is blocked. The gate is skipped when a direct host probe of the
+same URL fails, so a Google-side outage cannot quarantine the pool.
+`--no-google-check` disables the gate per run.
+
+**Consequences.** One ~94 KB request per rotation on a pass and ~0.4 KB on a
+block. The `google_fails` column is additive and migrated idempotently, so old
+databases self-upgrade. `retest` stays un-gated: gating it would cost a
+per-node search request every interval.
+
+**Rollback.** Pass `--no-google-check`, or revert the script; the extra
+column is ignored by older code.
+
+## 2026-11-09 — Node identity is a hash, not the provider remark
+
+**Context.** Provider remarks reshuffle or collide between refreshes, which
+wiped learned delay/failure history and made quarantine inconsistent.
+
+**Decision.** Names are `{proto}-{12hex}` from protocol + normalized host +
+port (SHA-256), sorted deterministically with a suffix on collision. The
+provider remark is kept in Clash's `remark` field for humans; sing-box omits
+it because the schema rejects unknown fields.
+
+**Consequences.** History survives every feed refresh. Humans read remarks
+in Clash, not in the node name.
+
+**Rollback.** Revert naming in the converter; balancer history resets once.
+
+## 2026-11-08 — Separate `region` failure cause
+
+**Context.** Provider country checks (geo-blocks) are a distinct failure from
+rate limits and transport faults, and treating them as generic failures
+diluted the quota signal used for crawl traffic.
+
+**Decision.** `skip` / `next` accept `--reason region`, count it in a
+dedicated `region_fails` column, and quarantine like other causes.
+
+**Consequences.** Exit selection correctly demotes geo-blocked IPs without
+deleting them; the column migrated idempotently.
+
+**Rollback.** Revert the enum and column; unknown reasons fall back to
+`manual`.
diff --git a/scripts/README.md b/scripts/README.md
new file mode 100644
index 0000000..face195
--- /dev/null
+++ b/scripts/README.md
@@ -0,0 +1,48 @@
+# scripts/ — external mihomo balancer
+
+Automation that runs beside mihomo and owns things mihomo cannot decide on
+its own: which subscription node carries traffic right now, and when a node
+should sit out.
+
+## Layout
+
+| File              | Duty                                                                 |
+| ----------------- | -------------------------------------------------------------------- |
+| `rr_balancer.py`  | Clash-API + SQLite round-robin balancer (`rotate`, `skip`, `next`, `retest`) |
+
+State lives in `data/balancer_state.db` (schema in
+`data/balancer_state.schema.sql`, git-ignored). Run `python3 scripts/rr_balancer.py --help`
+for the full CLI.
+
+## Duties
+
+- **Liveness + delay**: probes every pool node through mihomo's
+  `/proxies/{name}/delay` endpoint and stores delay or failure.
+- **Selection**: `rotate` picks the lowest `(uses, quota_fails, delay_ms)`
+  row among alive, fresh, non-quarantined nodes and selects it in the
+  `PROXY` group.
+- **Failure causes**: `skip` / `next --reason quota|transport|region|google|manual`
+  increments the per-cause counter and quarantines the node for 24 h.
+- **Google-clean gate**: `rotate` reads `https://www.google.com/search?q=test`
+  through the live mixed-port with redirects disabled. A 302 to `/sorry`
+  means the exit IP is anti-abuse flagged, so the candidate is quarantined
+  with cause `google` and the next candidate is tried. `--no-google-check`
+  restores the pre-gate behavior; the gate is skipped when Google is
+  unreachable directly (infrastructure guard).
+- **Retest**: rechecks the oldest batch so dead nodes rejoin on recovery.
+
+## Invariants
+
+1. Node names are identity hashes (`{proto}-{12hex}` from server + port), so
+   learned rows survive every subscription refresh.
+2. Never delete learned rows on a refresh — only never-tested rows are pruned.
+3. Selection order is deterministic: `uses` → `quota_fails` → `delay_ms`.
+4. Rotation always leaves the group pointing at a node. An all-blocked pool
+   fails open to the best candidate instead of going dark.
+
+## Risks
+
+- The Google gate selects a candidate in order to probe it, so a rejected
+  node carries traffic for roughly `GOOGLE_SETTLE_SECONDS` before the next
+  candidate is tried. Bounded by `--google-attempts`.
+- `data/balancer_state.db` is runtime state. Losing it only loses history.
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index 3513fbb..683c10c 100755
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -1,4 +1,5 @@
 #!/usr/bin/env python3
+# Sibling Docs: scripts/README.md | Decisions: scripts/DECISIONS.md
 """External round-robin balancer for mihomo (Clash API + SQLite state).
 
 Owns the PROXY group's selection from outside mihomo: tests each node
@@ -33,6 +34,13 @@ SCHEMA_PATH = os.path.join(REPO_ROOT, "data", "balancer_state.schema.sql")
 DEFAULT_DB = os.path.join(REPO_ROOT, "data", "balancer_state.db")
 DEFAULT_SECRET_FILE = os.path.expanduser("~/.config/mihomo-subs/.controller_secret")
 
+# Google Search is the discriminator: flagged exits answer 302 -> /sorry,
+# clean exits answer 200. Lightweight Google endpoints (generate_204,
+# suggest) answer identically on blocked IPs, so they cannot be used.
+DEFAULT_GOOGLE_URL = "https://www.google.com/search?q=test"
+DEFAULT_PROXY_URL = "http://127.0.0.1:7890"
+GOOGLE_SETTLE_SECONDS = 0.3
+
 # Group members that are selectors themselves, plus mihomo builtins:
 # never enter the rotation pool.
 META_NAMES = {"Auto", "Load Balance", "Fallback", "DIRECT", "REJECT", "PASS"}
@@ -96,8 +104,17 @@ class ClashAPI:
         if status != 204:
             raise RuntimeError("PUT selection %r failed with HTTP %s" % (name, status))
 
-    def delay(self, name: str, test_url: str, timeout_ms: int) -> Optional[int]:
-        qs = urllib.parse.urlencode({"timeout": timeout_ms, "url": test_url})
+    def delay(
+        self,
+        name: str,
+        test_url: str,
+        timeout_ms: int,
+        expected: Optional[int] = None,
+    ) -> Optional[int]:
+        query = {"timeout": timeout_ms, "url": test_url}
+        if expected is not None:
+            query["expected"] = expected
+        qs = urllib.parse.urlencode(query)
         path = "/proxies/%s/delay?%s" % (urllib.parse.quote(name), qs)
         try:
             status, payload = self._request("GET", path)
@@ -189,6 +206,7 @@ def connect_db(db_path: str) -> sqlite3.Connection:
             "quota_fails INTEGER NOT NULL DEFAULT 0",
             "transport_fails INTEGER NOT NULL DEFAULT 0",
             "region_fails INTEGER NOT NULL DEFAULT 0",
+            "google_fails INTEGER NOT NULL DEFAULT 0",
         ):
             col = coldef.split()[0]
             if col not in cols:
@@ -255,11 +273,85 @@ def alive_pool(
     return cur.fetchall()
 
 
+def order_pool(
+    pool: List[Tuple[str, int, int, int]],
+) -> List[Tuple[str, int, int, int]]:
+    """Least-used first, fewest quota fails next, fastest delay last."""
+    return sorted(pool, key=lambda row: (row[1], row[2], row[3]))
+
+
 def pick_next(pool: List[Tuple[str, int, int, int]]) -> Optional[str]:
     """Least-used first, fewest quota fails next, fastest delay last."""
     if not pool:
         return None
-    return sorted(pool, key=lambda row: (row[1], row[2], row[3]))[0][0]
+    return order_pool(pool)[0][0]
+
+
+def google_clean(
+    api: ClashAPI,
+    group: str,
+    name: str,
+    url: str,
+    timeout_ms: int,
+    proxy_url: str = DEFAULT_PROXY_URL,
+) -> bool:
+    """Select the node, then read Google Search through it without redirects.
+
+    mihomo's /delay endpoint follows the 302 to /sorry and reports the final
+    200, so it cannot see the block. This probes the live selector instead:
+    a blocked exit returns 302, a clean exit returns 200.
+
+    The node stays selected; rotation keeps it when it passes and moves on
+    when it does not, so no extra switch is needed.
+    """
+    api.select(group, name)
+    if GOOGLE_SETTLE_SECONDS:
+        time.sleep(GOOGLE_SETTLE_SECONDS)
+    return probe_status_via_proxy(url, proxy_url, timeout_ms / 1000.0) == 200
+
+
+def probe_status_via_proxy(url: str, proxy_url: str, timeout_s: float) -> Optional[int]:
+    """HTTP status for url through proxy_url, redirects NOT followed.
+
+    Returns None on transport errors. The body is not read, so a clean
+    candidate costs one request and a blocked one only its 302 headers.
+    """
+    opener = urllib.request.build_opener(
+        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
+        _NoRedirect,
+    )
+    req = urllib.request.Request(
+        url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131"}
+    )
+    try:
+        with opener.open(req, timeout=timeout_s) as resp:
+            return resp.status
+    except urllib.error.HTTPError as exc:
+        return exc.code
+    except Exception:
+        return None
+
+
+class _NoRedirect(urllib.request.HTTPRedirectHandler):
+    """Turn 3xx into an HTTPError so the status is visible to the caller."""
+
+    def redirect_request(self, req, fp, code, msg, headers, newurl):
+        return None
+
+
+def google_reachable_direct(url: str, timeout_s: float = 8.0) -> bool:
+    """Guard against quarantining the whole pool during a Google outage.
+
+    Probes the same URL from the host without a proxy. If this fails, the
+    per-node Google gate is skipped for this run instead of marking every
+    node blocked (infra failure, not node failure).
+    """
+    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
+    try:
+        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
+            return resp.status == 200
+    except Exception:
+        return False
 
 
 def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
@@ -268,8 +360,8 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
     pool_names, current = api.group_members(args.group)
     seed_names(conn, pool_names)
     pool = alive_pool(conn, now, args.stale_after, allowed=set(pool_names))
-    name = pick_next(pool)
-    if name is None:
+    ordered = order_pool(pool)
+    if not ordered:
         conn.execute(
             "INSERT INTO rotation_log (ts, node, reason) VALUES (?, '', 'noop-empty-pool')",
             (now,),
@@ -277,8 +369,44 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
         conn.commit()
         print("rotate: empty alive pool, no-op (group untouched)")
         return 0
-    delay = next(d for n, _u, _q, d in pool if n == name)
-    api.select(args.group, name)
+    name = None
+    delay = None
+    attempts = 0
+    enforce_google = not getattr(args, "no_google_check", False)
+    google_url = getattr(args, "google_url", DEFAULT_GOOGLE_URL)
+    google_timeout = getattr(args, "google_timeout_ms", 8000)
+    google_proxy = getattr(args, "google_proxy", DEFAULT_PROXY_URL)
+    max_attempts = max(1, getattr(args, "google_attempts", 5))
+    if enforce_google and not google_reachable_direct(google_url):
+        print("rotate: google unreachable directly, skipping google gate")
+        enforce_google = False
+    selected_by_probe = False
+    for candidate in ordered:
+        if enforce_google and attempts < max_attempts:
+            attempts += 1
+            if google_clean(
+                api, args.group, candidate[0], google_url, google_timeout, google_proxy
+            ):
+                name, delay = candidate[0], candidate[3]
+                selected_by_probe = True
+                break
+            _mark_failed(
+                conn,
+                candidate[0],
+                getattr(args, "max_fails", 3),
+                now,
+                "google",
+            )
+            continue
+        name, delay = candidate[0], candidate[3]
+        break
+    if name is None:
+        # Every checked candidate answered 302 /sorry: fail open to the best
+        # one so the client keeps working instead of going dark.
+        name, delay = ordered[0][0], ordered[0][3]
+        print("rotate: all candidates google-blocked, failing open to %s" % name)
+    if not selected_by_probe:
+        api.select(args.group, name)
     if current and current != name:
         try:
             closed, failed = close_stale_connections(api, current)
@@ -321,10 +449,10 @@ def _mark_failed(
 ) -> None:
     """Mark one node failed and quarantine it for 24h (retest readmits after expiry).
 
-    The failure cause (quota/transport/region/manual) is recorded per cause
-    so rotation can prefer nodes with a clean record for crawl traffic and
-    provider-side counters stay separable (region = geo-blocked from the
-    provider's country check, unrelated to rate limiting).
+    The failure cause (quota/transport/region/google/manual) is recorded per
+    cause so rotation can prefer nodes with a clean record for crawl traffic
+    and provider-side counters stay separable (region = geo-blocked from the
+    provider's country check; google = Google Search answers /sorry).
     """
     cur = conn.cursor()
     row = cur.execute("SELECT status FROM nodes WHERE name = ?", (name,)).fetchone()
@@ -336,7 +464,8 @@ def _mark_failed(
             "quarantined_until = ?, last_fail_cause = ?, "
             "quota_fails = quota_fails + ?, "
             "transport_fails = transport_fails + ?, "
-            "region_fails = region_fails + ? WHERE name = ?",
+            "region_fails = region_fails + ?, "
+            "google_fails = google_fails + ? WHERE name = ?",
             (
                 max_fails,
                 now,
@@ -345,6 +474,7 @@ def _mark_failed(
                 1 if reason == "quota" else 0,
                 1 if reason == "transport" else 0,
                 1 if reason == "region" else 0,
+                1 if reason == "google" else 0,
                 name,
             ),
         )
@@ -487,6 +617,32 @@ def load_secret(secret_file: str) -> str:
     return ""
 
 
+def add_google_args(parser: argparse.ArgumentParser) -> None:
+    """Google-clean gate flags shared by rotate/skip/next."""
+    parser.add_argument(
+        "--google-url",
+        default=DEFAULT_GOOGLE_URL,
+        help="URL that must answer 200; flagged exits answer 302 /sorry",
+    )
+    parser.add_argument("--google-timeout-ms", type=int, default=8000)
+    parser.add_argument(
+        "--google-proxy",
+        default=DEFAULT_PROXY_URL,
+        help="mihomo mixed-port used to read Google through the live selector",
+    )
+    parser.add_argument(
+        "--google-attempts",
+        type=int,
+        default=5,
+        help="max candidates to reject for /sorry before failing open",
+    )
+    parser.add_argument(
+        "--no-google-check",
+        action="store_true",
+        help="disable the Google-clean gate for this run",
+    )
+
+
 def build_parser() -> argparse.ArgumentParser:
     ap = argparse.ArgumentParser(description=__doc__)
     ap.add_argument("--controller", default="http://127.0.0.1:9090")
@@ -497,6 +653,7 @@ def build_parser() -> argparse.ArgumentParser:
 
     rot = sub.add_parser("rotate", help="select next alive node")
     rot.add_argument("--stale-after", type=int, default=7200)
+    add_google_args(rot)
 
     ret = sub.add_parser("retest", help="check oldest batch of nodes")
     ret.add_argument("--batch", type=int, default=500)
@@ -513,20 +670,22 @@ def build_parser() -> argparse.ArgumentParser:
     skp.add_argument("--max-fails", type=int, default=3)
     skp.add_argument(
         "--reason",
-        choices=("quota", "transport", "region", "manual"),
+        choices=("quota", "transport", "region", "google", "manual"),
         default="manual",
         help="failure cause recorded for smart selection",
     )
+    add_google_args(skp)
 
     nxt = sub.add_parser("next", help="skip the current node and rotate now")
     nxt.add_argument("--stale-after", type=int, default=7200)
     nxt.add_argument("--max-fails", type=int, default=3)
     nxt.add_argument(
         "--reason",
-        choices=("quota", "transport", "region", "manual"),
+        choices=("quota", "transport", "region", "google", "manual"),
         default="manual",
         help="failure cause recorded for smart selection",
     )
+    add_google_args(nxt)
     return ap
 
 
@@ -544,6 +703,11 @@ def validate_args(args: argparse.Namespace) -> Optional[str]:
             return "--timeout-ms must be >= 500"
     if args.cmd in ("rotate", "skip", "next") and args.stale_after < 60:
         return "--stale-after must be >= 60"
+    if args.cmd in ("rotate", "skip", "next"):
+        if args.google_timeout_ms < 500:
+            return "--google-timeout-ms must be >= 500"
+        if args.google_attempts < 1:
+            return "--google-attempts must be >= 1"
     return None
 
 
diff --git a/tests/test_rr_balancer.py b/tests/test_rr_balancer.py
index b870977..0626d68 100644
--- a/tests/test_rr_balancer.py
+++ b/tests/test_rr_balancer.py
@@ -6,6 +6,7 @@ import sys
 import tempfile
 import time
 import unittest
+import unittest.mock
 
 sys.path.insert(
     0,
@@ -18,10 +19,14 @@ import rr_balancer
 
 
 class FakeAPI:
-    """Stub ClashAPI: delays dict maps name -> delay_ms or None (dead)."""
+    """Stub ClashAPI: delays dict maps name -> delay_ms or None (dead).
 
-    def __init__(self, delays, group="PROXY"):
+    google_blocked names answer /sorry (302) on the expected=200 probe.
+    """
+
+    def __init__(self, delays, group="PROXY", google_blocked=None):
         self.delays = delays
+        self.google_blocked = set(google_blocked or ())
         self.group = group
         self.selected = []
         self.members = list(delays) + ["Auto", "Load Balance", "Fallback"]
@@ -36,7 +41,9 @@ class FakeAPI:
     def select(self, group, name):
         self.selected.append((group, name))
 
-    def delay(self, name, test_url, timeout_ms):
+    def delay(self, name, test_url, timeout_ms, expected=None):
+        if expected == 200 and name in self.google_blocked:
+            return None
         return self.delays.get(name)
 
     def get_connections(self):
@@ -80,6 +87,12 @@ class Args:
                 max_fails=3,
                 test_url="https://www.gstatic.com/generate_204",
                 timeout_ms=3000,
+                # Keep unit tests network-free; the google-gate test opts in
+                # and patches the direct reachability probe.
+                no_google_check=True,
+                google_url=rr_balancer.DEFAULT_GOOGLE_URL,
+                google_timeout_ms=8000,
+                google_attempts=5,
             )
         )
         self.__dict__.update(kw)
@@ -100,6 +113,53 @@ class RotateTest(unittest.TestCase):
         uses = conn.execute("SELECT uses FROM nodes WHERE name='fast'").fetchone()[0]
         self.assertEqual(uses, 1)
 
+    def test_rotate_skips_google_blocked(self):
+        conn, path = make_db()
+        now = int(time.time())
+        # "blocked" is faster and unused, so only the gate can reject it.
+        mark(conn, "blocked", "alive", delay=50, uses=0, last_check=now)
+        mark(conn, "clean", "alive", delay=200, uses=0, last_check=now)
+        api = FakeAPI({"blocked": 50, "clean": 200}, google_blocked={"blocked"})
+        args = Args(db=path, no_google_check=False)
+
+        def fake_probe(url, proxy, timeout):
+            return 302 if api.selected[-1][1] in api.google_blocked else 200
+
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", side_effect=fake_probe
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "clean"))
+        row = conn.execute(
+            "SELECT status, last_fail_cause, google_fails FROM nodes "
+            "WHERE name='blocked'"
+        ).fetchone()
+        self.assertEqual(row, ("failed", "google", 1))
+
+    def test_rotate_fails_open_when_all_blocked(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "a", "alive", delay=50, uses=0, last_check=now)
+        api = FakeAPI({"a": 50}, google_blocked={"a"})
+        args = Args(db=path, no_google_check=False, google_attempts=1)
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", return_value=302
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "a"))
+
     def test_second_rotate_moves_on(self):
         conn, path = make_db()
         now = int(time.time())
```
<!-- END_GIT_DIFF -->
