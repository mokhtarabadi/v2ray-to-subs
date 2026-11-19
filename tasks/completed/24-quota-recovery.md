# Task 24: Proxy and Quarantine Recovery

**File:** `tasks/completed/24-quota-recovery.md`
**Source:** manager
**Type:** bug
**Status:** closed
**Started:** 2026-11-19T17:19:36Z
**Submitted:** 2026-11-19T08:19:24Z
**Finished:** 2026-11-19T17:05:17Z

## Goal

Repair the broken mihomo data path and clear the false quota quarantines after
a global free-tier 429 exhausted the balancer pool.

## Manager's Notes

Approved S1-S5: back up the DB, align the selected node UUID with the mihomo
Vision config, clear only `quota`-caused quarantines, and verify without chat
requests. Retry-After is 57403s (~16h); inference must wait.

## Local TODOs

- [x] Back up balancer_state.db and record counts
- [x] Repair selected node / subscription UUID mismatch
- [x] Clear quota-caused quarantines only
- [x] Verify proxy trace, /health, /v1/models without inference
- [x] Update CHANGELOG and finalize

## Acceptance Criteria

- [x] Timestamped DB backup exists
- [x] Proxy trace through localhost:7890 succeeds
- [x] `last_fail_cause='quota'` rows cleared; transport rows retained
- [x] No chat completions sent during verification

## Verification Evidence

- **Test command:** curl -x http://127.0.0.1:7890 https://www.cloudflare.com/cdn-cgi/trace
- **Expected result:** exit 0 with ip/loc lines
- **Actual result:** `ip=79.182.39.40 loc=NL` (also GB and PL on earlier passes), exit 0
- **Exit code:** 0
- **DB backup:** `data/balancer_state.db.bak-20261119T081335Z`
- **Counts before:** 10672 nodes, 580 alive, 7763 quarantined, 106 quota-caused; after cleanup 0 quota rows, 682 alive, remaining causes google 12, manual 2, youtube 1
- **Bridge gate:** `/health` ok, 12 models, gate open; no chat completions sent after approval
- **Dead node:** `vless-ffb5bf6e64c3` reported delay 35ms but carried no traffic; `rr skip` quarantined it and rotation restored egress

## Definition of Done

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes
- [x] `CHANGELOG.md` updated
- [x] evidence recorded

## Risk & Rollback

DB backup allows restore. No service restart without approval.

---

## Execution Log & Reasoning

Diagnosis: direct upstream POST returned HTTP 429 `FreeUsageLimitError` with `Retry-After: 57403` (~16h), proving account-wide quota. Through the mihomo proxy the bridge returned HTTP 500 ECONNRESET, and even a plain Cloudflare trace through localhost:7890 failed, proving a separate local data-path fault. Plugin metrics showed 10 successful `rr --reason quota` rescues followed by 10 capped transport rescues; the balancer had quarantined 106 nodes for quota.

S1: copied the SQLite DB to a timestamped backup before mutation and recorded counts. S2: the journal's `unknown UUID` was not a config mismatch — the selected node existed with a valid UUID in `~/.config/mihomo-subs/config.yaml:60797`; its 35ms delay was misleading. Rotating to another node restored the proxy trace (`ip=141.98.101.179 loc=GB`), and the dead node was marked failed with cause `manual`. S3: a guarded UPDATE cleared only `last_fail_cause='quota'` rows, preserving google/manual/youtube quarantines. Two more quota rows appeared from an external caller afterward and were cleared again. S5: verified proxy trace, `/health`, `/v1/models`, and service state without sending inference.

Docs: root README now warns that delay_ms is not proof of a live node; CHANGELOG records the recovery. ZAC held: no git add, commit, checkout, or push.

Closure note: the code for this task was committed earlier as `3236fa1` (fix: restore proxy egress and clear false quota quarantines). Task file was closed via bookkeeping on 2026-11-19 after Manager approval: moved to tasks/completed/, Status set closed, Finished stamp added, diff block replaced with the commit hash reference.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `b24886003c49cd37cc8231e0e0d69ef1e065c9c7`
<!-- END_GIT_DIFF -->
