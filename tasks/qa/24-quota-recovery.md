# Task 24: Proxy and Quarantine Recovery

**File:** `tasks/qa/24-quota-recovery.md`
**Source:** manager
**Type:** bug
**Status:** open
**Submitted:** 2026-11-19T08:19:24Z

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

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index e49dc9a..4900ea4 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -10,6 +10,7 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 
 - Restored the `quota` failure cause for the active rate-limit-rescue plugin: `rotate`/`skip`/`next --reason quota` quarantines the current exit for 24h, and `rr --reason quota` parks the spent node before rotating with fail-open when no other candidate exists. No per-cause counter was restored. `transport` and `region` stay retired.
 - `rr` launcher forwards flag-only calls to `rotate` with gates off, so the rescue plugin's `rr --reason quota` reaches argparse as `rotate --reason quota`; explicit subcommands still pass through unchanged.
+- Recovery after the global free-tier 429: cleared 106 false `quota` quarantines from the balancer DB plus 2 more re-quarantined rows from a later external caller (backup retained), quarantined the dead selectable node with cause `manual`, and restored proxy egress by rotating to a working exit. Delay probes had reported the dead node healthy.
 
 ### Added
 
diff --git a/README.md b/README.md
index 60b3676..61735ee 100644
--- a/README.md
+++ b/README.md
@@ -172,7 +172,7 @@ and the balancer moves traffic to the next best node automatically:
 - **Tailscale exit**: peer traffic goes direct (server IP) — steering removed; the setup/teardown scripts and boot unit remain in the tree, disabled, as the documented rollback path. See `scripts/README.md`
 - **Failure causes**: `rr next --reason google|youtube|spotify|gemini|country|manual|quota` (default `manual`) records the cause and quarantines 24h; each probe cause increments its own counter. `quota` is restored for the active rescue plugin: `rr --reason quota` parks the current exit for 24h before rotating, and fails open when no other candidate is alive. Quota has no counter — the 24h quarantine is the whole mechanism. `transport` and `region` remain retired
 - **Country**: `rr country --batch 40` reads `https://www.cloudflare.com/cdn-cgi/trace` through each selected node and stores the observed exit country (`country`, `country_checked`); unreadable traces are stored as unknown, never as failures. `rr report` prints coverage (checked/total) and per-country counts
-- **Country lock**: `--require-country CC` keeps rotation inside one observed country when passed explicitly; bare `rr` and the timer use no lock. When no candidate matches, the current node is kept rather than switching country
+- **Country lock**: `--require-country CC` keeps rotation inside one observed country when passed explicitly; bare `rr` and the timer use no lock. When no candidate matches, the current node is kept rather than switching country. A low delay_ms is not proof a node carries traffic: an actual `cdn-cgi/trace` through the mixed-port is the authority; quarantine a dead selectable node with `rr skip NAME`
 - **One maintenance unit**: `v2ray-to-subs.timer` → `v2ray-to-subs-maintain.service` runs `scripts/maintain.sh` every 30 minutes: retest 1000, then a country batch of 40, then a refresh only when the live config is older than 6 hours. Rotation is manual-only (`rr`). This replaces the former refresh/retest/country timers — the project now owns two units, `mihomo-subs.service` and this pair
 - **Multi-service clean gate**: before selecting a node, rotation probes Google Search, the YouTube backend, the Spotify API, and Gemini through the candidate (live mixed-port, redirects disabled). The first flagged service quarantines with its own cause (24h, per-cause counter). Up to the shared attempt budget candidates are rejected, then the best remaining is used so the client never goes dark. Per-service `--no-*-check` flags disable gates; the battery is skipped when Google is unreachable directly (infra guard)
 - **Retest**: 1000 oldest controller-present nodes on every maintenance tick, dead nodes readmitted on recovery
```
<!-- END_GIT_DIFF -->
