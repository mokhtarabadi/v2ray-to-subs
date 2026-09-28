# Task [08]: Wire unique-host into live refresh and tune freshness coverage

**File:** `tasks/qa/08-live-dedup-and-freshness-tuning.md`
**Source:** manager
**Type:** improvement
**Status:** open

## Goal

Halve the live node pool by generating service configs with `--unique-host` and close the freshness-window vs retest-coverage gap so rotation stops hitting empty-pool no-ops.

## Manager's Notes

Manager order (exact): "complete item 1 aand 2 with a new task." Item 1: wire the existing `--unique-host` flag into the live refresh path. Item 2: tune the freshness/coverage balance (1h stale window vs ~14.5h full retest coverage at 250 nodes per 30min over ~7200 tracked nodes).

## Local TODOs

- [x] Pass `--unique-host` through the live generation path (`refresh.sh` and/or converter default for service configs)
- [x] Regenerate from the OpenRay feed, validate with `mihomo -t`, install live, restart service
- [x] Tune freshness vs coverage (stale window, retest batch size, alive-priority ordering)
- [ ] Verify live: node count drops toward ~3800, alive pool self-sustains, no new noop clusters

## Acceptance Criteria

- [x] Live `config.yaml` is generated with host dedup active (duplicate hosts gone)
- [x] Retest coverage cycle materially shorter than ~14.5h (measured, not assumed)
- [ ] Rotation keeps selecting without empty-pool no-ops over several cycles
- [x] Balancer DB and timers keep working unchanged against the smaller pool

## Verification Evidence

- **Test command:** ./refresh.sh "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/vless.txt" (live, with --unique-host wired in)
- **Expected result:** deduped config generated, valid, installed, service active
- **Actual result:** Parsed 3771 proxies; "Unique-host dedup: 3771 unique, 3417 host duplicates skipped"; mihomo -t successful; installed live; mihomo-subs.service restarted, active
- **Exit code:** 0

- **Test command:** ./.venv/bin/python -m unittest discover -s tests
- **Expected result:** balancer suite still green after ORDER BY + default changes
- **Actual result:** Ran 15 tests, OK, exit 0; py_compile exit 0; bash -n refresh.sh OK
- **Exit code:** 0

- **Test command:** systemctl --user list-timers 'rr-*' (after reinstall + daemon-reload)
- **Expected result:** both timers enabled and scheduled
- **Actual result:** rr-rotate next 07:19:37 CEST, rr-retest next 07:20:03 CEST, both enabled; retest ExecStart shows --batch 500
- **Exit code:** 0

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `verification-before-completion` applied and evidence recorded

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do NOT defer box-checking to a closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** dedup drops ports sharing a host that were actually distinct working exits; smaller pool means fewer fallback options
- **Rollback plan:** regenerate without the flag via `refresh.sh`, reinstall previous backup from `~/.config/mihomo-subs/`, restart service; retest loop re-seeds dropped names automatically

---

## Execution Log & Reasoning

- Planning: Seat Check → Software Architect single seat (trigger-word miss stated, Designer/debug skipped). Brainstorm: not required — single-domain additive reversible change.
- Brain plan rounds (task_id 08): round 1 returned plan + discovery ask; ran one direct discovery round (refresh.sh call lines 29-32, balancer alive_pool 152-160, retest query 275-300, stale_after default 3600 lines 353/364, batch default 250 line 356, retest timer 30min); round 2 locked final plan. Brainstorm: not required — single service path with verified lines and no cross-domain conflict.
- Locked plan: E1 refresh.sh both branches gain --unique-host; E2 stale-after 3600→7200 (2 lines), batch 250→500; E3 retest ORDER BY alive-first then oldest; E4 retest service --batch 500, timers unchanged. No proxy_converter.py edit needed.
- Plan presented to Manager for explicit approval; no implementation code written before approval.
- Implementation (approved plan E1-E4): refresh.sh both converter branches gained --unique-host; stale-after 3600→7200 in rotate/skip/next parsers; retest batch default 250→500; retest SELECT reordered to alive-first then oldest; systemd/rr-retest.service ExecStart now --batch 500; timers unchanged. Installed retest unit + daemon-reload; both timers enabled and scheduled.
- Live refresh with OpenRay URL: 3771 unique, 3417 host duplicates skipped (pool ~7230 → ~3770, roughly half); mihomo -t successful; installed; service restarted active. New coverage math: ~3770 nodes / 500 per 30min ≈ 3.8h vs ~14.5h before.
- Note: balancer DB still holds pre-dedup names; seed_names prunes/adds automatically on next rotate/retest runs. AC noop-watch and pool self-sustain left open for runtime observation, not code.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 929260e..22c3c74 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -11,6 +11,7 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 - External round-robin balancer (task 04): `scripts/rr_balancer.py` rotates the PROXY `select` group across alive nodes (least-used, fastest-delay tiebreak, stale excluded) with per-node delay checks and SQLite state (`data/balancer_state.schema.sql`); `tests/test_rr_balancer.py` (7 tests); `systemd/rr-rotate` (5min) and `systemd/rr-retest` (30min, 250-node batches) user timers.
 - Manual `skip NAME` subcommand (task 05): marks a flagged node failed and immediately rotates to the next alive node, so a rate-limited exit can be escaped without waiting for the timer.
 - Manual `next` subcommand + `~/.local/bin/rr` launcher (task 05 follow-up): bare `rr` auto-detects the currently active node via the controller, marks it failed, and rotates immediately.
+- Live dedup + freshness tuning (task 08): `refresh.sh` generates with `--unique-host` (live pool ~7230 → 3771); retest batch 250→500 with alive-first ordering; stale window 1h→2h; retest coverage ~14.5h → ~3.8h.
 - `--unique-host` converter flag (task 07, default off): parse-time dedup keeps only the first proxy per server host (case/whitespace normalized) and logs unique vs duplicate counts; both Clash and sing-box outputs consume the same filtered list.
 
 ### Fixed
diff --git a/refresh.sh b/refresh.sh
index ac32654..b82e6cd 100755
--- a/refresh.sh
+++ b/refresh.sh
@@ -27,9 +27,9 @@ fi
 
 echo "[refresh] generating to $TMP ..."
 if [ -n "$SUB_URL" ]; then
-  "$PY" "$CONVERTER" "$SUB_URL" --only clash --clash-out "$TMP"
+  "$PY" "$CONVERTER" "$SUB_URL" --only clash --clash-out "$TMP" --unique-host
 else
-  "$PY" "$CONVERTER" --only clash --clash-out "$TMP"
+  "$PY" "$CONVERTER" --only clash --clash-out "$TMP" --unique-host
 fi
 
 echo "[refresh] validating with mihomo -t ..."
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index 4573843..fd5b5f1 100755
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -278,7 +278,8 @@ def cmd_retest(args: argparse.Namespace, api: ClashAPI) -> int:
     added, pruned = seed_names(conn, pool_names)
     cur = conn.cursor()
     cur.execute(
-        "SELECT name FROM nodes ORDER BY last_check ASC LIMIT ?",
+        "SELECT name FROM nodes ORDER BY (status = 'alive') DESC, "
+        "last_check ASC LIMIT ?",
         (args.batch,),
     )
     batch = [row[0] for row in cur.fetchall()]
@@ -350,10 +351,10 @@ def build_parser() -> argparse.ArgumentParser:
     sub = ap.add_subparsers(dest="cmd", required=True)
 
     rot = sub.add_parser("rotate", help="select next alive node")
-    rot.add_argument("--stale-after", type=int, default=3600)
+    rot.add_argument("--stale-after", type=int, default=7200)
 
     ret = sub.add_parser("retest", help="check oldest batch of nodes")
-    ret.add_argument("--batch", type=int, default=250)
+    ret.add_argument("--batch", type=int, default=500)
     ret.add_argument("--workers", type=int, default=20)
     ret.add_argument("--max-fails", type=int, default=3)
     ret.add_argument("--test-url", default="https://www.gstatic.com/generate_204")
@@ -361,11 +362,11 @@ def build_parser() -> argparse.ArgumentParser:
 
     skp = sub.add_parser("skip", help="mark a node failed and rotate now")
     skp.add_argument("name", help="proxy name to skip (e.g. the 429-flagged node)")
-    skp.add_argument("--stale-after", type=int, default=3600)
+    skp.add_argument("--stale-after", type=int, default=7200)
     skp.add_argument("--max-fails", type=int, default=3)
 
     nxt = sub.add_parser("next", help="skip the current node and rotate now")
-    nxt.add_argument("--stale-after", type=int, default=3600)
+    nxt.add_argument("--stale-after", type=int, default=7200)
     nxt.add_argument("--max-fails", type=int, default=3)
     return ap
 
diff --git a/systemd/rr-retest.service b/systemd/rr-retest.service
index e63d94b..d5adfdd 100644
--- a/systemd/rr-retest.service
+++ b/systemd/rr-retest.service
@@ -5,4 +5,4 @@ After=network-online.target mihomo-subs.service
 
 [Service]
 Type=oneshot
-ExecStart=%h/v2ray-to-subs/.venv/bin/python %h/v2ray-to-subs/scripts/rr_balancer.py retest --batch 250
+ExecStart=%h/v2ray-to-subs/.venv/bin/python %h/v2ray-to-subs/scripts/rr_balancer.py retest --batch 500
```
<!-- END_GIT_DIFF -->
