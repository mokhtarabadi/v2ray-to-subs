# Task [11]: 24h quarantine for failed nodes

**File:** `tasks/qa/11-failed-node-quarantine.md`
**Source:** manager
**Type:** feature
**Status:** open

## Goal

Nodes marked failed (manual `rr`/`skip`, OpenCode auto-trigger on 429, or retest failures) stay out of rotation for 24 hours before becoming eligible again, so the balancer never reconnects to a recently rate-limited exit.

## Manager's Notes

Manager order (Persian, paraphrased): define a new task, complete it, deploy it, restart, with Brain autopilot locked. Goal is 100%: today a failed node can return within ~30min via retest readmission; every failed node must wait 24h before reuse. Follow-up finding: the OpenCode auto-trigger already exists and runs `rr` itself on 429s (recent rotations were OpenCode's, not manual).

## Local TODOs

- [x] Add quarantine timestamp to failed nodes (failed_until = failed_at + 24h)
- [x] Exclude quarantined nodes from the rotation pool until expiry
- [x] Exclude quarantined nodes from retest batches until expiry (no wasted checks)
- [x] Expired quarantine readmits automatically (retest reconfirms liveness)
- [x] Tests for quarantine set/expiry/exclusion; migrate + deploy + restart + verify live

## Acceptance Criteria

- [x] A node failed by any path is unselectable for 24h
- [x] Retest skips quarantined nodes (no probe waste, no early readmit)
- [x] After expiry the node re-enters via normal retest confirmation
- [x] Live verify: fail a node, confirm 24h exclusion, traffic stays healthy

## Verification Evidence

- **Test command:** ./.venv/bin/python -m unittest discover -s tests (incl. 5 new QuarantineTest, TDD RED then GREEN)
- **Expected result:** all pass
- **Actual result:** 32 tests OK, exit 0; py_compile exit 0
- **Exit code:** 0

- **Test command:** migration dry-run on live DB copy (/tmp/opencode/mig-test.db)
- **Expected result:** column added, all rows preserved with default 0, idempotent reopen
- **Actual result:** quarantined_until present, rows 3560/3560, defaults 3560, reopen OK
- **Exit code:** 0

- **Test command:** live `rr` (skips current node, rate-limited era)
- **Expected result:** node marked failed with +24h quarantine, rotation advances, traffic healthy
- **Actual result:** E18483 quarantined until 2026-10-11 21:06:26; rotated to FCDE3D (14ms); DB shows failed + quarantined; exit IP + example.com 200
- **Exit code:** 0

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** schema change on live DB (new column); pool shrinks if many nodes quarantined at once
- **Rollback plan:** revert script + restore DB from pre-deploy copy; rotation falls back to current behavior

---

## Execution Log & Reasoning

- Autopilot locked for task 11 on manager order (Persian): new task, complete, deploy, restart, Brain autopilot locked, goal 100%.
- Brain bridge absent from this environment's tool catalog (verified twice via search); proceeded with direct plan from repo knowledge + supervised approval gate per AGENTS.md. Plan approved verbatim by manager.
- Implementation: `QUARANTINE_SECONDS = 24*3600`; `nodes.quarantined_until` column (schema.sql + idempotent ALTER in connect_db); `_mark_failed` + retest-failure transition set now+24h; success resets to 0; `alive_pool` + retest batch exclude future-quarantined rows; old failed rows (0) stay immediately eligible.
- Deploy note: migration runs inside connect_db on next timer/manual run; live DB backup at /tmp/opencode/balancer_state.pre11.db; no service restart needed (timers invoke the script fresh). Observed: OpenCode auto-trigger rotates on its own (controller moved past my manual pick) — system working as designed.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index d0bef15..91dcc92 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -15,6 +15,7 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 - `--unique-host` converter flag (task 07, default off): parse-time dedup keeps only the first proxy per server host (case/whitespace normalized) and logs unique vs duplicate counts; both Clash and sing-box outputs consume the same filtered list.
 - Multi-feed aggregation (task 10): converter/`manager.sh`/`refresh.sh` accept N subscription URLs, merge into one pool, dedup across the merged set with per-feed + merged counts; ss cipher alias `chacha20-poly1305` normalized to `chacha20-ietf-poly1305`.
 - Balancer seed memory (task 10 follow-up): learned rows survive feed refreshes (only never-tested rows pruned); pool and retest batch exclude controller ghosts; auto-rotate timer disabled, manual `rr` owns switching.
+- 24h quarantine for failed nodes (task 11): failed nodes stay out of rotation and retest for 24h, then readmit via normal retest confirmation.
 - Close stale connections on proxy switch (task 09): after every successful selection change the balancer closes connections still chained to the previous node (surgical per-id close, non-fatal); shared path covers manual (`rr`/`skip`) and timer (`rotate`) modes.
 
 ### Fixed
diff --git a/data/balancer_state.schema.sql b/data/balancer_state.schema.sql
index 98d49b6..a241da6 100644
--- a/data/balancer_state.schema.sql
+++ b/data/balancer_state.schema.sql
@@ -4,7 +4,8 @@ CREATE TABLE IF NOT EXISTS nodes (
   delay_ms   INTEGER,
   last_check INTEGER NOT NULL DEFAULT 0,
   fails      INTEGER NOT NULL DEFAULT 0,
-  uses       INTEGER NOT NULL DEFAULT 0
+  uses       INTEGER NOT NULL DEFAULT 0,
+  quarantined_until INTEGER NOT NULL DEFAULT 0
 );
 
 CREATE TABLE IF NOT EXISTS rotation_state (
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index 19544af..84b3e3f 100755
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -37,6 +37,10 @@ DEFAULT_SECRET_FILE = os.path.expanduser("~/.config/mihomo-subs/.controller_secr
 # never enter the rotation pool.
 META_NAMES = {"Auto", "Load Balance", "Fallback", "DIRECT", "REJECT", "PASS"}
 
+# Failed nodes stay out of rotation and retest for this long, so a
+# rate-limited exit cannot come back minutes later.
+QUARANTINE_SECONDS = 24 * 3600
+
 
 def utc_now_epoch() -> int:
     """Current UTC time as epoch seconds. Single clock seam for tests.
@@ -176,6 +180,15 @@ def connect_db(db_path: str) -> sqlite3.Connection:
     if fresh:
         with open(SCHEMA_PATH, encoding="utf-8") as fh:
             conn.executescript(fh.read())
+    else:
+        # Idempotent migration for DBs created before quarantine support.
+        cols = [row[1] for row in conn.execute("PRAGMA table_info(nodes)")]
+        if "quarantined_until" not in cols:
+            conn.execute(
+                "ALTER TABLE nodes ADD COLUMN quarantined_until "
+                "INTEGER NOT NULL DEFAULT 0"
+            )
+            conn.commit()
     return conn
 
 
@@ -217,13 +230,15 @@ def alive_pool(
 
     When allowed is given, only names present in the controller's current
     member list are returned, so ghosts from older feeds are never picked.
+    Quarantined nodes (failed less than 24h ago) are always excluded.
     """
     cur = conn.cursor()
     query = (
         "SELECT name, uses, COALESCE(delay_ms, 999999) FROM nodes "
-        "WHERE status = 'alive' AND (? - last_check) <= ?"
+        "WHERE status = 'alive' AND (? - last_check) <= ? "
+        "AND quarantined_until <= ?"
     )
-    params: List[Any] = [now, stale_after]
+    params: List[Any] = [now, stale_after, now]
     if allowed is not None:
         allowed = list(allowed)
         if not allowed:
@@ -292,19 +307,19 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
 
 
 def _mark_failed(conn: sqlite3.Connection, name: str, max_fails: int, now: int) -> None:
-    """Mark one node failed (retest readmits it if alive)."""
+    """Mark one node failed and quarantine it for 24h (retest readmits after expiry)."""
     cur = conn.cursor()
     row = cur.execute("SELECT status FROM nodes WHERE name = ?", (name,)).fetchone()
     if row is None:
         print("skip: unknown node %r, rotating anyway" % name)
     else:
         cur.execute(
-            "UPDATE nodes SET status = 'failed', fails = ?, last_check = ? "
-            "WHERE name = ?",
-            (max_fails, now, name),
+            "UPDATE nodes SET status = 'failed', fails = ?, last_check = ?, "
+            "quarantined_until = ? WHERE name = ?",
+            (max_fails, now, now + QUARANTINE_SECONDS, name),
         )
         conn.commit()
-        print("skip: marked %s failed (retest readmits it if alive)" % name)
+        print("skip: marked %s failed (quarantined 24h, retest readmits after)" % name)
 
 
 def _relabel_latest(conn: sqlite3.Connection, reason: str) -> None:
@@ -369,9 +384,10 @@ def cmd_retest(args: argparse.Namespace, api: ClashAPI) -> int:
     else:
         cur.execute(
             "SELECT name FROM nodes WHERE name IN (%s) "
+            "AND quarantined_until <= ? "
             "ORDER BY (status = 'alive') DESC, last_check ASC LIMIT ?"
             % ",".join("?" * len(pool_names)),
-            (*pool_names, args.batch),
+            (*pool_names, now, args.batch),
         )
         batch = [row[0] for row in cur.fetchall()]
     if not batch:
@@ -406,7 +422,7 @@ def cmd_retest(args: argparse.Namespace, api: ClashAPI) -> int:
         if delay is not None:
             cur.execute(
                 "UPDATE nodes SET status='alive', delay_ms=?, "
-                "last_check=?, fails=0 WHERE name=?",
+                "last_check=?, fails=0, quarantined_until=0 WHERE name=?",
                 (delay, now, name),
             )
             alive += 1
@@ -414,8 +430,10 @@ def cmd_retest(args: argparse.Namespace, api: ClashAPI) -> int:
             cur.execute(
                 "UPDATE nodes SET fails=fails+1, last_check=?, "
                 "status=CASE WHEN fails+1 >= ? THEN 'failed' "
-                "ELSE status END WHERE name=?",
-                (now, args.max_fails, name),
+                "ELSE status END, "
+                "quarantined_until=CASE WHEN fails+1 >= ? THEN ? "
+                "ELSE quarantined_until END WHERE name=?",
+                (now, args.max_fails, args.max_fails, now + QUARANTINE_SECONDS, name),
             )
             failed += 1
     conn.commit()
diff --git a/tests/test_rr_balancer.py b/tests/test_rr_balancer.py
index 8d23413..450b894 100644
--- a/tests/test_rr_balancer.py
+++ b/tests/test_rr_balancer.py
@@ -369,5 +369,93 @@ class SeedMemoryTest(unittest.TestCase):
         conn.close()
 
 
+class QuarantineTest(unittest.TestCase):
+    def test_mark_failed_sets_24h_quarantine(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "n1", "alive", delay=10, uses=0, last_check=now)
+        conn.close()
+        conn = rr_balancer.connect_db(path)
+        rr_balancer._mark_failed(conn, "n1", 3, now)
+        row = conn.execute(
+            "SELECT status, quarantined_until FROM nodes WHERE name='n1'"
+        ).fetchone()
+        self.assertEqual(row[0], "failed")
+        self.assertEqual(row[1], now + 24 * 3600)
+        conn.close()
+
+    def test_pool_excludes_quarantined(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "q", "failed", last_check=now)
+        mark(conn, "ok", "alive", delay=10, uses=0, last_check=now)
+        conn.execute(
+            "UPDATE nodes SET quarantined_until=? WHERE name='q'", (now + 3600,)
+        )
+        conn.commit()
+        pool = rr_balancer.alive_pool(conn, now, 7200, allowed={"q", "ok"})
+        # q is failed so pool holds only ok regardless; force alive to isolate filter
+        conn.execute("UPDATE nodes SET status='alive' WHERE name='q'")
+        conn.commit()
+        pool = rr_balancer.alive_pool(conn, now, 7200, allowed={"q", "ok"})
+        self.assertEqual([n for n, _, _ in pool], ["ok"])
+        conn.close()
+
+    def test_expired_quarantine_readmits(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "old", "alive", delay=10, uses=0, last_check=now)
+        conn.execute(
+            "UPDATE nodes SET quarantined_until=? WHERE name='old'", (now - 1,)
+        )
+        conn.commit()
+        pool = rr_balancer.alive_pool(conn, now, 7200, allowed={"old"})
+        self.assertEqual([n for n, _, _ in pool], ["old"])
+        conn.close()
+
+    def test_retest_skips_quarantined(self):
+        conn, path = make_db()
+        api = FakeAPI({"n1": 10})
+        api.group_members = lambda group: (["n1", "q"], "old-node")
+        mark(conn, "q", "failed", last_check=100)
+        mark(conn, "n1", "unknown", last_check=100)
+        conn.execute(
+            "UPDATE nodes SET quarantined_until=? WHERE name='q'",
+            (int(time.time()) + 3600,),
+        )
+        conn.commit()
+        conn.close()
+        rc = rr_balancer.cmd_retest(Args(cmd="retest", db=path, batch=10), api)
+        self.assertEqual(rc, 0)
+        conn = sqlite3.connect(path)
+        q_check = conn.execute(
+            "SELECT last_check FROM nodes WHERE name='q'"
+        ).fetchone()[0]
+        self.assertEqual(q_check, 100)
+        conn.close()
+
+    def test_migration_adds_column_idempotently(self):
+        fd, path = tempfile.mkstemp(suffix=".db")
+        os.close(fd)
+        os.unlink(path)
+        conn = sqlite3.connect(path)
+        conn.execute(
+            "CREATE TABLE nodes (name TEXT PRIMARY KEY, status TEXT NOT NULL "
+            "DEFAULT 'unknown', delay_ms INTEGER, last_check INTEGER NOT NULL "
+            "DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, "
+            "uses INTEGER NOT NULL DEFAULT 0)"
+        )
+        conn.commit()
+        conn.close()
+        conn = rr_balancer.connect_db(path)
+        cols = [r[1] for r in conn.execute("PRAGMA table_info(nodes)").fetchall()]
+        self.assertIn("quarantined_until", cols)
+        conn.close()
+        conn = rr_balancer.connect_db(path)
+        cols = [r[1] for r in conn.execute("PRAGMA table_info(nodes)").fetchall()]
+        self.assertIn("quarantined_until", cols)
+        conn.close()
+
+
 if __name__ == "__main__":
     unittest.main()
```
<!-- END_GIT_DIFF -->
