# Task [05]: Manual rotate command for flagged proxies

**File:** `tasks/qa/05-manual-rotate-command.md`
**Source:** manager
**Type:** feature
**Status:** open

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

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index e4442e6..b9eb4ac 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -9,6 +9,7 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 ### Added
 
 - External round-robin balancer (task 04): `scripts/rr_balancer.py` rotates the PROXY `select` group across alive nodes (least-used, fastest-delay tiebreak, stale excluded) with per-node delay checks and SQLite state (`data/balancer_state.schema.sql`); `tests/test_rr_balancer.py` (7 tests); `systemd/rr-rotate` (5min) and `systemd/rr-retest` (30min, 250-node batches) user timers.
+- Manual `skip NAME` subcommand (task 05): marks a flagged node failed and immediately rotates to the next alive node, so a rate-limited exit can be escaped without waiting for the timer.
 
 ### Fixed
 - Review hotfix: balancer clock seam, DB parent makedirs, group_members annotation, WAL sidecar ignores.
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index e31e561..2ba6737 100644
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -204,6 +204,39 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
     return 0
 
 
+def cmd_skip(args: argparse.Namespace, api: ClashAPI) -> int:
+    """Mark a flagged node failed, then rotate to the next alive node."""
+    now = utc_now_epoch()
+    conn = connect_db(args.db)
+    pool_names, _ = api.group_members(args.group)
+    seed_names(conn, pool_names)
+    cur = conn.cursor()
+    row = cur.execute(
+        "SELECT status FROM nodes WHERE name = ?", (args.name,)
+    ).fetchone()
+    if row is None:
+        print("skip: unknown node %r, rotating anyway" % args.name)
+    else:
+        cur.execute(
+            "UPDATE nodes SET status = 'failed', fails = ?, last_check = ? "
+            "WHERE name = ?",
+            (args.max_fails, now, args.name),
+        )
+        conn.commit()
+        print("skip: marked %s failed (retest readmits it if alive)" % args.name)
+    conn.close()
+    rc = cmd_rotate(args, api)
+    if rc == 0:
+        conn = connect_db(args.db)
+        conn.execute(
+            "UPDATE rotation_log SET reason = 'manual-skip' "
+            "WHERE id = (SELECT MAX(id) FROM rotation_log) AND reason = 'rotate'"
+        )
+        conn.commit()
+        conn.close()
+    return rc
+
+
 def check_one(
     api: ClashAPI, name: str, test_url: str, timeout_ms: int
 ) -> Tuple[str, Optional[int]]:
@@ -297,21 +330,27 @@ def build_parser() -> argparse.ArgumentParser:
     ret.add_argument("--max-fails", type=int, default=3)
     ret.add_argument("--test-url", default="https://www.gstatic.com/generate_204")
     ret.add_argument("--timeout-ms", type=int, default=3000)
+
+    skp = sub.add_parser("skip", help="mark a node failed and rotate now")
+    skp.add_argument("name", help="proxy name to skip (e.g. the 429-flagged node)")
+    skp.add_argument("--stale-after", type=int, default=3600)
+    skp.add_argument("--max-fails", type=int, default=3)
     return ap
 
 
 def validate_args(args: argparse.Namespace) -> Optional[str]:
     """Reject numeric CLI values that crash or misbehave. Returns error or None."""
+    if args.cmd in ("retest", "skip"):
+        if args.max_fails < 1:
+            return "--max-fails must be >= 1"
     if args.cmd == "retest":
         if args.batch < 1:
             return "--batch must be >= 1"
         if args.workers < 1:
             return "--workers must be >= 1"
-        if args.max_fails < 1:
-            return "--max-fails must be >= 1"
         if args.timeout_ms < 500:
             return "--timeout-ms must be >= 500"
-    if args.cmd == "rotate" and args.stale_after < 60:
+    if args.cmd in ("rotate", "skip") and args.stale_after < 60:
         return "--stale-after must be >= 60"
     return None
 
@@ -329,6 +368,8 @@ def main(argv: Optional[List[str]] = None) -> int:
     api = ClashAPI(args.controller, secret)
     if args.cmd == "rotate":
         return cmd_rotate(args, api)
+    if args.cmd == "skip":
+        return cmd_skip(args, api)
     return cmd_retest(args, api)
 
 
diff --git a/tests/test_rr_balancer.py b/tests/test_rr_balancer.py
index fdbad25..ecde032 100644
--- a/tests/test_rr_balancer.py
+++ b/tests/test_rr_balancer.py
@@ -194,6 +194,30 @@ class ValidateArgsTest(unittest.TestCase):
         args = Args(cmd="rotate")
         self.assertIsNone(rr_balancer.validate_args(args))
 
+    def test_skip_marks_failed_and_advances(self):
+        conn, path = make_db()
+        api = FakeAPI({"n1": 2, "n2": 5})
+        mark(conn, "n1", "alive", delay=2, uses=0)
+        mark(conn, "n2", "alive", delay=5, uses=0)
+        conn.close()
+        rc = rr_balancer.cmd_skip(Args(cmd="skip", name="n1", db=path), api)
+        self.assertEqual(rc, 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "n2"))
+        conn = sqlite3.connect(path)
+        st = conn.execute("SELECT status FROM nodes WHERE name='n1'").fetchone()[0]
+        self.assertEqual(st, "failed")
+        reason = conn.execute(
+            "SELECT reason FROM rotation_log ORDER BY id DESC LIMIT 1"
+        ).fetchone()[0]
+        self.assertEqual(reason, "manual-skip")
+        conn.close()
+
+    def test_rejects_bad_skip_numbers(self):
+        args = Args(cmd="skip", name="n1", stale_after=59)
+        self.assertIsNotNone(rr_balancer.validate_args(args))
+        args = Args(cmd="skip", name="n1", max_fails=0)
+        self.assertIsNotNone(rr_balancer.validate_args(args))
+
 
 class ConnectDbTest(unittest.TestCase):
     def test_wal_and_busy_timeout(self):
```
<!-- END_GIT_DIFF -->
