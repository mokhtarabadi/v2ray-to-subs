# Task [09]: Close stale connections on proxy switch

**File:** `tasks/completed/09-close-stale-connections-on-switch.md`
**Source:** manager
**Type:** improvement
**Status:** closed

## Goal

When the balancer switches the PROXY selection, close connections still pinned to the old node so traffic moves to the new proxy immediately, in both manual (`rr` / `skip`) and automatic (timer `rotate`) paths.

## Manager's Notes

Manager message (verbatim, Persian):

> خب این کار رو بکن وقتی پروکسی عوض میشه کانکشن های قدیمی رو ببند هم حالت rr و هم حالت خودکار این رو تسکش کن و انجامش بده خودکار

English: do this — when the proxy changes, close the old connections, both in rr mode and automatic mode; task it and do it automatically.

Context: verified live that `GET /connections` works on the controller; per-connection entries carry chains metadata; `DELETE /connections` (all) and `DELETE /connections/:id` (single) are the documented close endpoints. DELETE was never executed to avoid disturbing live traffic.

## Local TODOs

- [x] Add connection-close step to the balancer switch path in `scripts/rr_balancer.py` (surgical per-id close of old-node connections preferred over close-all)
- [x] Cover both manual (`rr` / `skip` → `cmd_rotate`) and timer (`rotate`) paths (single shared code path)
- [x] Tests for the close step (unit with stubbed API, incl. failure tolerance: close must never break the switch)
- [x] Live verify: rotate, confirm old-node connections drop and traffic follows the new node

## Acceptance Criteria

- [x] After every successful selection change, connections chained to the previous node are closed
- [x] Manual and timer paths share the same close logic (no duplication)
- [x] A failing close call never breaks the rotation (logged, non-fatal)
- [x] Live evidence: rotate changes `now`, old connections gone, traffic works on new exit

## Verification Evidence

- **Test command:** ./.venv/bin/python -m unittest discover -s tests (incl. 3 new CloseStaleTest, TDD RED then GREEN)
- **Expected result:** all tests pass; rotate closes only old-node connections; close failures never raise
- **Actual result:** 18 tests OK, exit 0; py_compile exit 0
- **Exit code:** 0

- **Test command:** live — background slow download via proxy (conn pinned to CA-26582), then `./scripts/rr_balancer.py rotate`
- **Expected result:** rotate selects a new node, prints close count, old connection gone, traffic works on new exit
- **Actual result:** "closed 1 stale connections of CA-26582 after switch to CA-29374"; `now` confirms CA-29374; old conn ID absent; exit 152.67.210.234, example.com 200
- **Exit code:** 0

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** closing all connections causes a brief traffic blip; surgical per-id close limits blast radius
- **Rollback plan:** revert the balancer change; connections then drain naturally as before

---

## Execution Log & Reasoning

- Implementation: `ClashAPI.get_connections()` + `close_connection(id)` (True on 204/200/404, never raises) + module-level `close_stale_connections(api, prev)` filtering connections whose `chains` contain the previous node; hooked into `cmd_rotate` right after `api.select()` — captures `current` before select, skips when empty/unchanged, wrapped in try/except so failures only print. `skip`/`next` delegate to `cmd_rotate`, so one shared path covers manual and timer modes.
- Deviation from plan: S3 implemented as a module function (not a ClashAPI method) so the FakeAPI stub needs no new methods; file has no logger, so the hook uses print like the rest of the script.
- TDD: 3 CloseStaleTest methods written first (filter-selectivity, unchanged-selection no-op, close-failure tolerance); RED run showed 1 failure (missing helper); GREEN after implementation — 18 tests OK.
- Live verify: slow download pinned conn 8c262652… to CA-26582; `rotate` printed "closed 1 stale connections of CA-26582 after switch to CA-29374"; controller `now` = CA-29374; old conn ID absent; fresh traffic exit 152.67.210.234, example.com 200.

- Bridge-QA re-run with fed-context excerpts (task_id 09): VERDICT QA_PASSED. F1 GET-failure [] path safe; F2 missing chains/id skipped; F3 per-id/outer exception guards keep bookkeeping alive; F4 unchanged-selection never closes; F5 theoretical only (string chains, quote safe default). Missing tests M1-M3 non-blocking (live run covers). Routed to Code Reviewer.

- Code Review (bridge, task_id 09, fed-context): APPROVED technically, status PO_REVIEW_PENDING. F1-F4 strengths (single hook, safe GET, never-raise DELETE, per-id isolation); F5 Low (substring match if chains were a string — controller returns lists; R1/R2 optional hardening deferred). Relayed to Manager; file stays in tasks/qa pending exact closure words.
- Closure: Approved for closure received, moving to completed.

- Code Review final (bridge, task_id 09, fed-context, staging still broken so diff judged via excerpts): APPROVED, PO_REVIEW_PENDING. F1-F4 strengths; F5 Low (chains list-guard optional, deferred R1/R2). Manager chained order included 'approved for closure' — proceeding to closure commit attempt.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->

_(Git diff will be automatically injected here by the MCP tool. Do not edit this block manually)_

<!-- END_GIT_DIFF -->

## Planning Gate Log

- Seat Check: Python backend + Clash REST API → Software Architect single seat (explicit trigger-word miss on all seats; no UX surface, no failure signatures). Brainstorm: not required — single-domain additive reversible change.
- Brain round 1 (task_id 09): returned discovery task (XML_EXTRACTED), no plan. Deviation logged: discovery subagents unavailable this session (prior precedent); executing discovery directly via targeted reads and feeding back under same task_id.

## Planning Gate Log (continued)

- Brain round 2 (task_id 09, fed-context with verified rr_balancer.py lines 51-105/172-204/233/249): grounded REPORT plan received — S1-S5 (get_connections + close_connection + close_stale_connections helpers, hook in cmd_rotate after select, non-fatal logging), T1-T3 tests, R1-R2 risks. Auditable line: Brainstorm: not required — single-domain additive reversible change. Presenting for approval; no implementation before approval.
