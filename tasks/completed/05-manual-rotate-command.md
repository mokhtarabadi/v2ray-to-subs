# Task [05]: Manual rotate command for flagged proxies

**File:** `tasks/completed/05-manual-rotate-command.md`
**Source:** manager
**Type:** feature
**Status:** closed

## Goal

Give the manager a one-shot command to force-rotate to the next alive node when the current proxy gets flagged (e.g. Cloudflare 429), and resolve the report of a proxy named `PROXY` appearing selected.

## Manager's Notes

Manager message (verbatim):

> there is minor bug i used this systsem for a tool that the tool use cf, the cf has rate limit over ips. so it works when we rotated and balanced., but some of nodes already flaged as 429, i think if you can implemment a simple thing for me a api or someting even a command helper when i see a bad proxy or already flaged i run command it roated manually to next.
>
> also i see in balaner a proxy with named `PROXY` selected what is it? it a bug? crate task and handle both of them

## Local TODOs

- [x] Add manual rotate entrypoint (`skip <name>` marks failed + advances via `cmd_rotate`)
- [x] Add `next` subcommand + global `rr` launcher: rotates whatever node is currently active, no name needed
- [x] Verify manual run selects a different node than current and traffic follows
- [x] Confirm the `PROXY` sighting is the group name, not a node (evidence below)

## Acceptance Criteria

- [x] One command rotates to the next alive node on demand (no waiting for the 5-min timer)
- [x] One command marks a named node failed so rotation skips it until retest readmits it
- [x] Bare `rr` rotates the currently active node (auto-detected via controller) with zero arguments
- [x] `PROXY` question answered with evidence: no node named PROXY exists in DB or controller

## Verification Evidence

- **Test command:** ./.venv/bin/python -m unittest discover -s tests (includes 2 new skip tests, TDD RED then GREEN)
- **Expected result:** all tests pass
- **Actual result:** 13 tests OK, exit 0; py_compile exit 0
- **Exit code:** 0

- **Test command:** ./.venv/bin/python -m unittest discover -s tests (includes 2 new `next` tests, TDD RED then GREEN)
- **Expected result:** all tests pass
- **Actual result:** 15 tests OK, exit 0; py_compile exit 0
- **Exit code:** 0

- **Test command:** `rr` with no arguments (live; active node was NL-12614)
- **Expected result:** current node marked failed, controller `now` moves to a different alive node, traffic exit IP changes
- **Actual result:** skipped NL-12614, rotated to NL-12363 (5ms); controller now confirms NL-12363; traffic works, exit 104.168.76.144, example.com 200
- **Exit code:** 0

- **Test command:** ./scripts/rr_balancer.py skip "[OpenRay] 🇺🇸 US-27076" (live, manager rate-limited on this node)
- **Expected result:** node marked failed, controller `now` moves to a different alive node, traffic exit IP changes
- **Actual result:** rotated to US-24409 (11ms); controller now confirms US-24409; traffic works, exit 107.174.131.32, example.com 200
- **Exit code:** 0

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** manual `skip` could drain the alive pool if overused; rotation no-ops on empty pool by design
- **Rollback plan:** no config change involved; pool state self-heals via the 30-min retest loop

---

## Execution Log & Reasoning

- Triage: `nodes` has 0 rows named PROXY and `rotation_log` has 0 rows with node PROXY; controller `GET /proxies/PROXY` reports `type: Selector`, `now: [OpenRay] US-22853` (a real node, matching the latest rotation row), 7233 members. Conclusion: `PROXY` is the select-group's own name as shown by the manager's external tool, not a balancer node — not a bug.
- Design intent: manual rotate reuses `cmd_rotate` (index advance modulo alive pool, PUT 204, log reason `manual`); `skip` sets status failed + fails bump then calls rotate.
- Implementation: `skip NAME` subcommand added to `scripts/rr_balancer.py` — marks node `failed` with `fails = max_fails` + fresh `last_check`, then delegates to `cmd_rotate`; relabels the newest log row reason to `manual-skip` only when rotate logged `rotate`. Parser args: `name`, `--stale-after`, `--max-fails`; `validate_args` extended; main dispatch added.
- TDD: wrote 2 new skip tests first, confirmed RED (AttributeError on missing subcommand + FAIL), then implemented; suite GREEN, 13 tests OK.
- Live run (manager rate-limited on US-27076): `skip` marked it failed and rotated to US-24409 (11ms); controller `now` confirms; traffic verified with fresh exit IP. Manager unblocked without waiting for the timer.
- Follow-up (manager: install globally so bare `rr` auto-rotates the current active node): added `next` subcommand — refactored the skip body into `_mark_failed` + `_relabel_latest` helpers reused by both; `cmd_next` reads the current selection via `group_members`, marks it failed (or rotates anyway with reason `manual-next` when none reported); parser/dispatch/`validate_args` extended. TDD: 2 new tests RED first (AttributeError + errors), then GREEN — 15 tests OK. Installed `~/.local/bin/rr` wrapper (execs repo script, defaults to `next`; script made executable for its `python3` shebang). Live bare-`rr` run: skipped NL-12614, rotated to NL-12363 (5ms); controller confirms; traffic works with fresh exit IP. Note: the wrapper lives outside the repo (home dir) and is not committed; repo side is the `next` subcommand itself.

- Bridge-QA (task_id 05, include_diff): VERDICT QA_PASSED. F1 SQL injection blocked (parameterized queries); F2 unknown node warns + rotates; F3 empty controller selection rotates; F4 bad numerics rejected; F5 empty rotation_log relabel is zero-row no-op. Non-blocking: M1 unknown-skip untested (delegates to tested rotate), M2 rotate-failure-after-mark untested (relabel correctly skipped on nonzero rc), M3 home launcher outside repo. Live evidence confirmed (skip US-27076->US-24409, next NL-12614->NL-12363, traffic OK). Routed to Code Reviewer per verdict.

- Code Review (bridge, task_id 05): APPROVED technically, status PO_REVIEW_PENDING. No blocking issues; A1 (context-manager DB use, test placement) deferred to next touch, no change required now. Relayed to Manager; file stays in tasks/qa pending exact closure words.
- Closure approved, moving to completed via single issuance. Manager accept quote: "Approved for closure".
- Closure executed: file moved qa to completed, CHANGELOG entries confirmed present (skip + next, no duplication), all TODOs/AC/DoD boxes checked against recorded evidence. No source changes in closure, only this file relocation.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `295887528dbc3c15df97f78390a3699ee2903601`
<!-- END_GIT_DIFF -->
