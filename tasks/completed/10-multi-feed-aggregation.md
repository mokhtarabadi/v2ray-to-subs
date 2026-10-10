# Task [10]: Multi-feed subscription aggregation

**File:** `tasks/completed/10-multi-feed-aggregation.md`
**Source:** manager
**Type:** feature
**Status:** closed

## Goal

Let the converter pull several subscription feeds in one run, merge them into a single pool, and strip duplicates across the whole merged pool before generating configs.

## Manager's Notes

Manager order (Persian, paraphrased): create a task and run it in locked autopilot — support multiple feeds. Then build the project graph, search it, and update everything really tied to the change (docs and anything else). Then test it, restart, and observe. Duplicates must be removed across ALL pools: pools aggregate first, then dedup runs over the merged set.

Context: feed research concluded OpenRay is healthy but any single free pool decays; combining a ranked meta-pool (e.g. FastNodes) with OpenRay spreads the risk. Current code takes exactly one subscription URL (`run(url=...)`, `refresh.sh $1/SUB_URL`, `manager.sh DEFAULT_URL`).

## Local TODOs

- [x] Accept multiple subscription URLs (CLI `nargs`, `run(urls=[...])`, keep single-URL backward compat)
- [x] Merge lines from all feeds, then apply unique-host dedup over the merged pool
- [x] Report per-feed parsed counts + merged totals (unique vs duplicates)
- [x] Update all tied spots found via project graph (refresh.sh, manager.sh help/defaults, README, CHANGELOG)
- [x] Test (synthetic multi-file feeds + live two-feed run), regenerate, restart service, verify traffic
- [x] Fix refresh-wipe amnesia: learned rows survive feed refreshes; ghost exclusion vs controller (manager-ordered, folded into this task)

## Acceptance Criteria

- [x] One run consumes N feed URLs and produces one merged Clash + sing-box output
- [x] Duplicate hosts across different feeds are removed (aggregate-then-dedup, not per-feed)
- [x] Output reports per-feed and merged counts
- [x] Single-URL usage behaves exactly as before
- [x] Live service restarts on the merged config with working traffic

## Verification Evidence

- **Test command:** ./.venv/bin/python -m unittest discover -s tests (incl. 4 new multi-feed + alias tests)
- **Expected result:** all pass
- **Actual result:** Ran 23 tests, OK, exit 0; py_compile exit 0; bash -n refresh.sh manager.sh OK
- **Exit code:** 0

- **Test command:** two-feed live run (OpenRay all_valid + 0xRadikal verified, --unique-host)
- **Expected result:** per-feed counts + merged dedup + mihomo -t pass
- **Actual result:** 10932 + 1089 parsed; "Unique-host dedup over merged pool: 2919 unique, 9102 host duplicates skipped"; mihomo -t successful
- **Exit code:** 0

- **Test command:** live refresh.sh with both URLs (systemd override updated), then traffic check
- **Expected result:** installed live, service active, traffic exits via proxy
- **Actual result:** installed; mihomo-subs active; exit IP + example.com 200
- **Exit code:** 0

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** multi-feed merge multiplies pool size and refresh time; a dead feed aborts the whole run unless handled
- **Rollback plan:** single-URL invocation unchanged; previous live config backup in `~/.config/mihomo-subs/` + service restart

---

## Execution Log & Reasoning

- Implementation: `main()` positional `url nargs='?'` → `urls nargs='*'` default `[DEFAULT]`; `run()` gained `urls` param with single-string normalization and empty→default fallback; per-feed download loop with try/continue (fail only if ALL fail); per-feed parse for counts; single shared `_dedup_by_host()` helper extracted (used by both parse-time path and merged path); legacy single-feed branch kept byte-identical (logs verbatim); `refresh.sh` collects all positionals + `$SUB_URL` fallback and forwards the array; `manager.sh do_generate` collects URL array (default `[DEFAULT_URL]`), help updated.
- Blocker found live: merged output failed `mihomo -t` on ss node 82.38.31.54 with cipher `chacha20-poly1305` (unknown to mihomo). Proved pre-existing (OpenRay-only run fails identically; 0xRadikal-only passes) — not a merge defect. Fix on the critical path: `SS_METHOD_ALIASES` + `_normalize_ss_method()` at ss parse (line ~694), mapping to canonical `chacha20-ietf-poly1305`. Re-ran: merged config validates.
- Docs graph pass: README multi-feed examples (converter + manager.sh usage), CHANGELOG entry below. Balancer untouched (feed-agnostic, consumes controller).
- Root cause of empty-pool noops: `seed_names` DELETE wiped all learned rows on every 6h feed refresh (verified live: 143 alive vanished after reinstall), and the pool ran only on DB data. Fix: prune only `unknown` rows; `alive_pool` + retest batch take an allowlist of current controller members.
- Refresh-wipe fix verified: 27 tests OK (4 new SeedMemoryTest); live `rr` skipped LV-1, closed 3 stale, switched to FR-8, controller agrees, fresh exit IP works.
- Ops change per manager order: `rr-rotate.timer` disabled (manual `rr` owns switching); `rr-retest.timer` + refresh timer + proxy service stay active. README balancer section updated to manual-first; graph rebuilt and queried for tied spots (README, CHANGELOG, balancer, tests; completed task files left as history).

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `973284f0dd4f70d37790a277c3730a23f2720450`
<!-- END_GIT_DIFF -->

## Planning Gate Log

- Seat Check: Python CLI + parsing + generation → Software Architect single seat (explicit trigger-word miss; no UX surface, no failure signatures). Brainstorm: not required — single-domain additive reversible change.
- Brain round 1 (task_id 10): discovery-first, no plan. Built project graph (2615 nodes) + bfs/dfs queries per manager order; confirmed tied spots (run/main/ProxyParser, refresh.sh, manager.sh, README sections, CHANGELOG; balancer feed-agnostic).
- Brain round 2 (fed-context): grounded REPORT plan A1-A6 + verification + R1-R3. Key refinements vs draft: per-feed try/continue (non-zero exit only if ALL fail), single parser over merged pool, single-URL log output verbatim, identity test. Auditable line: Brainstorm: not required — single-domain additive reversible change.

## Timer-Triggered Live Run (smoke)

- refresh timer was stuck (stale Oct-1 stamp, NEXT empty); manual `systemctl start v2ray-to-subs-refresh.service` ran the full chain through the unit: 2 sources logged, merged dedup 2919 unique / 9102 skipped, mihomo -t pass, backup, install, service active.
- Timer re-armed after the run: NEXT 22:02 CEST (6h cycle). Controller selection LV-1, traffic exit 216.173.71.43, example.com 200.

## Bridge-QA Verdict

- VERDICT QA_PASSED. F1 title-from-last-feed vs URL-from-first mismatch, F2 empty-server single bucket, F3 cross-feed exact-line dups survive without flag, F4 space-separated SUB_URL fails closed — all low severity, no rejections. Missing-test notes F5-F7 non-blocking (live two-feed validation covers). Routed to Code Reviewer.

## Bridge-Review Verdict

- Code Reviewer APPROVED technically, status PO_REVIEW_PENDING. No blocking defects; F5-F8 Low/Trivial (title/first-URL mismatch, per-feed exact-line dedup, dual dedup sites, test hygiene). R1-R3 deferred. Relayed to Manager; file stays in tasks/qa pending exact closure words.

## Four-Feed Activation (manager order)

- Manager asked which pools we have, to pick several top ones and activate them, then record the conversation + changes in the task and redo QA + review.
- Feed research: OpenRay verified healthy and actively maintained (hourly pipelines, xray/sing-box/mihomo end-to-end validation, 7.7k commits) — observed decay is free-proxy churn, not repo death. Alternatives compared: FastNodes (hourly meta-aggregator over 750+ sources incl. OpenRay, ranked top.txt + Xray-verified verified.txt, Europe/IR focus), ebrasha (15-min updates, unknown test depth), 0xRadikal (tested, 3h cadence).
- Activated 4 feeds via systemd override + daemon-reload: OpenRay all_valid + 0xRadikal verified + FastNodes verified.txt + FastNodes top.txt. Note: verified.txt yielded 329 (not ~730 — varies hourly); heavy overlap expected since FastNodes aggregates OpenRay.
- Live refresh result: 10932 + 1091 + 329 + 1000 parsed → merged dedup 3560 unique / 9792 skipped; mihomo -t pass; installed; service active. Controller selection NL-3, exit 51.158.206.29, example.com 200.

## Bridge-QA Re-run Verdict (4 feeds + seed-memory fix)

- VERDICT QA_PASSED. F1 title/first-URL mismatch, F2 empty-host bucket, F3 cross-feed exact-line dups without flag, F4 space-separated SUB_URL fails closed — all Low. New F5: learned ghosts never pruned (only unknowns pruned) → monotonic DB bloat, needs TTL follow-up, not live-blocking. Missing-test notes F6-F8 non-blocking. Live 4-feed validation (3560 unique, mihomo pass, active traffic) confirms. Routed to Code Reviewer.

## Bridge-Review Verdict (re-run)

- Code Reviewer APPROVED technically, status PO_REVIEW_PENDING. No blocking defects; F6-F10 Low (title/URL mismatch, per-feed exact-line dedup, dual dedup sites, empty-host bucket, ghost bloat + large IN list). R1-R3 deferred. Relayed to Manager; file stays in tasks/qa pending exact closure words.

## Closure Note

- Closure approved with exact words. Metadata set to closed, file moved qa to completed via git mv. Staged set verified as task-10-only (converter multi-feed + alias, refresh/manager URL arrays, balancer seed-memory + ghost filters, both test files, README, CHANGELOG). No foreign hunks carried.
