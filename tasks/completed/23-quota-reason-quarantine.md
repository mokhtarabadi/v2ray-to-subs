# Task 23: Restore quota reason with 24-hour node quarantine

**File:** `tasks/qa/23-quota-reason-quarantine.md`
**Source:** manager
**Type:** improvement
**Status:** open
**Submitted:** 2026-11-18T13:04:18Z

## Goal

Accept `--reason quota` in the `rr` balancer and make `rotate --reason quota`
quarantine the currently selected node for 24 hours before rotating to the next
alive node. A node that hits the free-tier quota is not reused inside that day.

## Source Context

`scripts/DECISIONS.md` records that the `quota`, `transport` and `region` causes
were removed when the old rescue plugin was retired. The plugin is active again,
so the `quota` cause is restored here. `QUARANTINE_SECONDS` is already 24h and
`alive_pool()` excludes quarantined nodes.

## Manager's Notes

Assumptions:
- A1: `rr --reason quota` (bare launcher = `rotate`) quarantines the current
  node for 24h and rotates onward.
- A2: no per-cause counter or selection weighting is restored; quarantine alone
  satisfies the requirement.
- A3: the rescue-plugin half lives in the paired task in the other repo.
- A4: both repos stay uncommitted for Manager review; ZAC holds.

## Local TODOs

- [x] Add quota to --reason choices and add --reason to rotate
- [x] Quarantine current node on rotate --reason quota, then rotate; fail open when empty
- [x] Add unit tests for quota quarantine and rotate logging
- [x] Update scripts/DECISIONS.md ADR, scripts/README.md, root README.md, CHANGELOG.md
- [x] Run the balancer unit suite and record evidence
- [x] Finalize the task file

## Acceptance Criteria

- [x] `rr rotate --reason quota` sets `last_fail_cause=quota` and `quarantined_until=now+86400` on the current node
- [x] A different alive node is selected; with no other candidate the current node is kept and reported
- [x] `skip --reason quota` and `next --reason quota` are accepted
- [x] The new rotation is logged with reason `quota`
- [x] Balancer unit tests pass with exit code 0
- [x] `lint_task_file` passes

## Verification Evidence

- **Test command:** python3 -m unittest tests.test_rr_balancer
- **Expected result:** all balancer tests pass (exit 0)
- **Actual result:** `OK` (all `tests.test_rr_balancer` cases pass, including the 3 new QuotaReasonTest cases)
- **Exit code:** 0
- **Syntax command:** `python3 -m py_compile scripts/rr_balancer.py` → exit 0
- **CLI parse check:** `python3 scripts/rr_balancer.py --help` exit 0; `python3 scripts/rr_balancer.py rotate --reason quota --help` exit 0
- **Red phase:** before the implementation, QuotaReasonTest ran with 2 failures and 1 error (`cause '' != 'quota'`, argparse rejecting `quota`), then passed after the change
- **Full-suite note:** `python3 -m unittest discover -s tests -p 'test_*.py'` exits 1 with 2 failures in `tests/test_proxy_converter.py` (Clash/Sing-box REJECT rule shape). That file is untouched by this task; the failures are pre-existing and unrelated to the balancer.
- **Strict Tooling Gate:** plain Python stdlib CLI, no framework or stack skill matches; base gate is `py_compile` + balancer unit tests + `lint_task_file`

## Definition of Done

The task is NOT done unless ALL of the following are true:

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `testing-verification` applied and evidence recorded

## Risk & Rollback

- **Risk:** a 429 burst across many nodes quarantines a large part of the pool
  for a day; fail-open keeps the service alive when the pool is exhausted.
- **Rollback plan:** revert the rotate branch and argparse hunks from the staged
  diff; existing `skip`/`next` behavior is unchanged.

---

## Execution Log & Reasoning

The Manager ordered a different response to a free-tier 429: do not switch models, pass `--reason quota` to `rr` and quarantine the spent exit for 24h. Typo corrections: quota, reason, quarantine, hours, inside. A1: `rr --reason quota` means the bare launcher (= `rotate`) parks the current node then picks the next alive one. Historical context from `scripts/DECISIONS.md`: the `quota` cause was removed with the old rescue plugin; this task restores only that cause, not `transport` or `region`.

Step 1 — Tests first. Added `QuotaReasonTest` to `tests/test_rr_balancer.py`: quarantine current and select the next node with rotation reason `quota`; fail open to the current node with reason `quota-failopen` when it is the only candidate; argparse accepts quota on rotate/skip/next. Before implementation the focused run had 2 failures and 1 error.

Step 2 — Balancer. Added `--reason` to the `rotate` parser and `quota` to the `skip`/`next` choices. In `cmd_rotate`, when the reason is `quota` and a current selection exists, `_mark_failed()` sets `last_fail_cause=quota`, `status=failed`, `fails=max_fails` and `quarantined_until=now+QUARANTINE_SECONDS` (24h). The current node is removed from this run's ordered candidates. With no candidates left, the current node is reselected, a `quota-failopen` log line is written, and the function returns 0. The normal rotation INSERT now logs `log_reason` (`quota` for this path, `rotate` otherwise), replacing the hardcoded literal. `_mark_failed`'s docstring was updated to describe the restored cause and the absence of a counter.

Step 3 — Verification. Focused suite and full balancer suite exit 0; `py_compile` and CLI help checks exit 0. The full repo suite still has 2 pre-existing failures in `test_proxy_converter.py` about REJECT rules; that file is not in this task's diff.

Step 4 — Docs. Added a reversal ADR to `scripts/DECISIONS.md`, updated both READMEs' failure-cause bullets, and added one Unreleased/Changed entry to CHANGELOG. ZAC held: no `git add`, `git commit`, `git checkout`, or `git push`; both repos remain uncommitted for Manager review.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 92ec5f5..0980824 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -6,6 +6,10 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 
 ## [Unreleased]
 
+### Changed
+
+- Restored the `quota` failure cause for the active rate-limit-rescue plugin: `rotate`/`skip`/`next --reason quota` quarantines the current exit for 24h, and `rr --reason quota` parks the spent node before rotating with fail-open when no other candidate exists. No per-cause counter was restored. `transport` and `region` stay retired.
+
 ### Added
 
 - External round-robin balancer (task 04): `scripts/rr_balancer.py` rotates the PROXY `select` group across alive nodes (least-used, fastest-delay tiebreak, stale excluded) with per-node delay checks and SQLite state (`data/balancer_state.schema.sql`); `tests/test_rr_balancer.py` (7 tests); `systemd/rr-rotate` (5min) and `systemd/rr-retest` (30min, 250-node batches) user timers.
diff --git a/README.md b/README.md
index cce2208..ec18813 100644
--- a/README.md
+++ b/README.md
@@ -170,7 +170,7 @@ and the balancer moves traffic to the next best node automatically:
 - **Rotate**: manual only — bare `rr` picks the lowest `(uses, delay_ms)` alive node with no gates and no country lock. Gate flags (`--google-url`, `--youtube-url`, etc.) and `--require-country` still work when passed explicitly; `--keep-if-clean` keeps a clean incumbent without switching
 - **Speed pick**: `rr fastest [--require-country CC]` takes the top 3 gate-clean finalists, downloads a capped 3MB file through each (~15s each), and selects the fastest. Slowness alone never quarantines anyone. On-demand only — the timer stays on retest plus refresh
 - **Tailscale exit**: peer traffic goes direct (server IP) — steering removed; the setup/teardown scripts and boot unit remain in the tree, disabled, as the documented rollback path. See `scripts/README.md`
-- **Failure causes**: `rr next --reason google|youtube|spotify|gemini|country|manual` (default `manual`) records the cause and quarantines 24h; each probe cause increments its own counter. The old `quota`/`transport`/`region` causes belonged to the retired rate-limit-rescue plugin and are gone
+- **Failure causes**: `rr next --reason google|youtube|spotify|gemini|country|manual|quota` (default `manual`) records the cause and quarantines 24h; each probe cause increments its own counter. `quota` is restored for the active rescue plugin: `rr --reason quota` parks the current exit for 24h before rotating, and fails open when no other candidate is alive. `transport` and `region` remain retired
 - **Country**: `rr country --batch 40` reads `https://www.cloudflare.com/cdn-cgi/trace` through each selected node and stores the observed exit country (`country`, `country_checked`); unreadable traces are stored as unknown, never as failures. `rr report` prints coverage (checked/total) and per-country counts
 - **Country lock**: `--require-country CC` keeps rotation inside one observed country when passed explicitly; bare `rr` and the timer use no lock. When no candidate matches, the current node is kept rather than switching country
 - **One maintenance unit**: `v2ray-to-subs.timer` → `v2ray-to-subs-maintain.service` runs `scripts/maintain.sh` every 30 minutes: retest 1000, then a country batch of 40, then a refresh only when the live config is older than 6 hours. Rotation is manual-only (`rr`). This replaces the former refresh/retest/country timers — the project now owns two units, `mihomo-subs.service` and this pair
diff --git a/scripts/DECISIONS.md b/scripts/DECISIONS.md
index a1110a3..6f60769 100644
--- a/scripts/DECISIONS.md
+++ b/scripts/DECISIONS.md
@@ -207,3 +207,26 @@ deleting them; the column migrated idempotently.
 **Consequences.** `rr` picks least-used/fastest-delay alive node, any country; dead nodes still quarantine via retest. No auto-switching of any kind.
 
 **Rollback.** Re-add the rotate line with a lock; re-enable the tailnet unit; re-add `--tun`.
+
+## 2026-11-18 — Restore the quota failure cause for the active rescue plugin
+
+**Context.** An earlier cleanup removed the `quota`, `transport` and `region`
+causes together with the retired rate-limit-rescue plugin. The plugin is active
+again and now reports a free-tier 429 as `rr --reason quota`. In the observed
+burst, ten distinct nodes were rotated in 41 seconds and every one returned
+429, so plain rotation could not escape a spent allowance.
+
+**Decision.** Re-add `quota` to the `--reason` choices for `skip` and `next`,
+and add `--reason` to `rotate`. `rotate --reason quota` marks the current exit
+with `last_fail_cause=quota` and the existing 24h `quarantined_until`, removes
+it from this run's candidates, then continues normal selection. With no other
+candidate it keeps the current node and logs `quota-failopen` rather than going
+dark. No per-cause counter or selection weighting is restored: the quarantine
+alone keeps a spent exit out of rotation for a day.
+
+**Consequences.** A quota burst can quarantine many exits for 24h, but fail-open
+keeps the proxy usable when the alive pool is exhausted. Transport and region
+causes stay retired; the plugin only sends a reason for quota.
+
+**Rollback.** Remove `quota` from the argparse choices and the quarantine branch
+in `cmd_rotate`; existing rows keep their cause strings.
diff --git a/scripts/README.md b/scripts/README.md
index a5152ab..e095cd5 100644
--- a/scripts/README.md
+++ b/scripts/README.md
@@ -49,9 +49,12 @@ The feed list the old refresh drop-in used is embedded in the script.
   (default 3MB, 30s cap) and selects the fastest. Slow losers keep
   their standing — throughput is a signal, never a quarantine verdict.
   Manual only, never on the timer.
-- **Failure causes**: `skip` / `next --reason google|youtube|spotify|gemini|country|manual`
+- **Failure causes**: `skip` / `next --reason google|youtube|spotify|gemini|country|manual|quota`
   quarantines the node for 24 h. Each probe cause increments its own
   counter (`google_fails`, `youtube_fails`, `spotify_fails`, `gemini_fails`).
+  `quota` has no counter: `rotate --reason quota` parks the current exit for
+  24 h before picking the next one, and fails open to it when no other
+  candidate is alive. The rescue plugin sends this reason on a free-tier 429.
 - **Multi-service clean gate**: `rotate` probes each candidate through the
   live mixed-port with redirects disabled, all-must-pass in order Google
   (`search?q=test`: 200 clean, 302 `/sorry` flagged) → YouTube backend
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index ec504db..3ebe8e3 100755
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -626,6 +626,31 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
     seed_names(conn, pool_names)
     pool = alive_pool(conn, now, args.stale_after, allowed=set(pool_names))
     ordered = order_pool(pool)
+
+    # A quota 429 means the exit itself spent its free-tier allowance, not that
+    # the route is slow or dirty. Park it for 24h so the next rotation cannot
+    # pick the same spent exit, then fall through to the normal selection.
+    # With no other candidate, keep the current node: going dark is worse than
+    # retrying an already-limited exit.
+    reason = getattr(args, "reason", None)
+    log_reason = "rotate"
+    if reason == "quota" and current:
+        _mark_failed(conn, current, getattr(args, "max_fails", 3), now, "quota")
+        ordered = [row for row in ordered if row[0] != current]
+        log_reason = "quota"
+        if not ordered:
+            conn.execute(
+                "INSERT INTO rotation_log (ts, node, reason) VALUES (?, ?, 'quota-failopen')",
+                (now, current),
+            )
+            conn.commit()
+            print(
+                "rotate: quota node %s quarantined, no other candidate, failing open"
+                % current
+            )
+            api.select(args.group, current)
+            return 0
+
     require_country = getattr(args, "require_country", None)
     if require_country:
         require_country = require_country.strip().upper()
@@ -759,8 +784,8 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
     cur.execute("UPDATE nodes SET uses = uses + 1 WHERE name = ?", (name,))
     cur.execute(
         "INSERT INTO rotation_log (ts, node, delay_ms, reason) "
-        "VALUES (?, ?, ?, 'rotate')",
-        (now, name, None if delay >= 999999 else delay),
+        "VALUES (?, ?, ?, ?)",
+        (now, name, None if delay >= 999999 else delay, log_reason),
     )
     cur.execute(
         "INSERT OR REPLACE INTO rotation_state (id, position, updated_at) "
@@ -785,10 +810,12 @@ def _mark_failed(
     Causes are the ones this balancer actually acts on: google (Search
     answers /sorry), youtube (oEmbed answers 403), spotify (API edge
     answers HTML 403), gemini (app answers 403), country (exit does not
-    match the required country), and manual (an operator skipped it).
-    Each probe cause increments its own counter; the retired
-    quota/transport/region causes belonged to the rate-limit-rescue
-    plugin and were removed with their columns.
+    match the required country), quota (the free-tier allowance on this
+    exit is spent), and manual (an operator skipped it).
+    Each probe cause increments its own counter. Quota is stored on
+    ``last_fail_cause`` only: its 24h quarantine is enough to keep a
+    spent exit out of rotation, and no per-cause counter was restored.
+    Transport and region causes remain retired with their columns.
     """
     cur = conn.cursor()
     row = cur.execute("SELECT status FROM nodes WHERE name = ?", (name,)).fetchone()
@@ -1279,6 +1306,12 @@ def build_parser() -> argparse.ArgumentParser:
 
     rot = sub.add_parser("rotate", help="select next alive node")
     rot.add_argument("--stale-after", type=int, default=7200)
+    rot.add_argument(
+        "--reason",
+        choices=("google", "youtube", "spotify", "gemini", "country", "manual", "quota"),
+        default="manual",
+        help="failure cause; quota quarantines the current exit for 24h before rotating",
+    )
     rot.add_argument(
         "--keep-if-clean",
         action="store_true",
@@ -1306,7 +1339,7 @@ def build_parser() -> argparse.ArgumentParser:
     skp.add_argument("--max-fails", type=int, default=3)
     skp.add_argument(
         "--reason",
-        choices=("google", "youtube", "spotify", "gemini", "country", "manual"),
+        choices=("google", "youtube", "spotify", "gemini", "country", "manual", "quota"),
         default="manual",
         help="failure cause recorded for the node",
     )
@@ -1321,7 +1354,7 @@ def build_parser() -> argparse.ArgumentParser:
     nxt.add_argument("--max-fails", type=int, default=3)
     nxt.add_argument(
         "--reason",
-        choices=("google", "youtube", "spotify", "gemini", "country", "manual"),
+        choices=("google", "youtube", "spotify", "gemini", "country", "manual", "quota"),
         default="manual",
         help="failure cause recorded for the node",
     )
diff --git a/tests/test_rr_balancer.py b/tests/test_rr_balancer.py
index 6f69fe5..b384472 100644
--- a/tests/test_rr_balancer.py
+++ b/tests/test_rr_balancer.py
@@ -1324,5 +1324,56 @@ class CountryArgsTest(unittest.TestCase):
         )
 
 
+class QuotaReasonTest(unittest.TestCase):
+    """A quota 429 quarantines the spent exit for 24h instead of reusing it."""
+
+    def test_rotate_quota_reason_quarantines_current_and_switches(self):
+        conn, path = make_db()
+        api = FakeAPI({"cur": 50, "n2": 5})
+        api.group_members = lambda group: (["cur", "n2"], "cur")
+        mark(conn, "cur", "alive", delay=50, uses=3)
+        mark(conn, "n2", "alive", delay=5, uses=0)
+        conn.close()
+        rc = rr_balancer.cmd_rotate(Args(cmd="rotate", db=path, reason="quota"), api)
+        self.assertEqual(rc, 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "n2"))
+        conn = sqlite3.connect(path)
+        cause, until = conn.execute(
+            "SELECT last_fail_cause, quarantined_until FROM nodes WHERE name='cur'"
+        ).fetchone()
+        self.assertEqual(cause, "quota")
+        self.assertGreater(until, int(time.time()))
+        reason = conn.execute(
+            "SELECT reason FROM rotation_log ORDER BY id DESC LIMIT 1"
+        ).fetchone()[0]
+        self.assertEqual(reason, "quota")
+        conn.close()
+
+    def test_rotate_quota_reason_fails_open_when_no_other_candidate(self):
+        conn, path = make_db()
+        api = FakeAPI({"cur": 50})
+        api.group_members = lambda group: (["cur"], "cur")
+        mark(conn, "cur", "alive", delay=50, uses=3)
+        conn.close()
+        rc = rr_balancer.cmd_rotate(Args(cmd="rotate", db=path, reason="quota"), api)
+        self.assertEqual(rc, 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "cur"))
+        conn = sqlite3.connect(path)
+        reason = conn.execute(
+            "SELECT reason FROM rotation_log ORDER BY id DESC LIMIT 1"
+        ).fetchone()[0]
+        self.assertEqual(reason, "quota-failopen")
+        conn.close()
+
+    def test_quota_reason_is_accepted_by_rotate_skip_and_next(self):
+        parser = rr_balancer.build_parser()
+        for argv in (
+            ["rotate", "--reason", "quota"],
+            ["skip", "n1", "--reason", "quota"],
+            ["next", "--reason", "quota"],
+        ):
+            self.assertEqual(parser.parse_args(argv).reason, "quota", argv)
+
+
 if __name__ == "__main__":
     unittest.main()
```
<!-- END_GIT_DIFF -->
