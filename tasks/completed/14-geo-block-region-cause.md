# Task [14]: Geo-block failure cause for rotation and rescue

**File:** `tasks/completed/14-geo-block-region-cause.md`
**Source:** manager
**Type:** feature
**Status:** closed

## Goal

Handle provider region blocks (`RegionError`, model not available in the exit's country) as a first-class rotation cause so geo-blocked exits quarantine like other failures and the rescue loop rotates away from them.

## Manager's Notes

Manager context (paraphrased): OpenCode failed with a region error for the model in the current exit country. Asked to handle this error class too. Approved a 3-step plan (balancer reason, plugin detector, verification) as a quick fix without Kanban tracking, then ordered the finished changes formalized into a task and run through the Brain pipeline on autopilot.

## Key Finding (pre-implementation)

Region blocks are provider-side country refusals, unrelated to rate limiting or network faults, but `rr` rotation (new exit country) fixes them the same way. The balancer already records per-cause counters (`quota_fails`, `transport_fails`) with 24h quarantine, so a parallel `region_fails` counter fits without design change. The rescue plugin's retry hook is model-gated for quota but region blocks hit paid and free models alike, so the detector is model-independent. Plugin files live outside this repo (`~/.config/opencode/plugins/rate-limit-rescue/`) and are a companion change, not part of this diff.

## Design

- `scripts/rr_balancer.py`: `--reason` accepts `region` on `skip` and `next`; `_mark_failed` increments `region_fails` and quarantines 24h like other causes.
- `data/balancer_state.schema.sql`: `region_fails` column added; existing DBs self-upgrade through the idempotent migration in `connect_db` (no reseed).
- `tests/test_rr_balancer.py`: per-cause test mirroring the quota/transport cases.
- Companion (separate repo, already has region support): rescue plugin source of truth is the private GitHub repo `mokhtarabadi/opencode-rate-limit-rescue`, installed as `github:mokhtarabadi/opencode-rate-limit-rescue`; it detects `RegionError` / country-unavailable text model-independently, runs `rr next --reason region`, tags metrics `kind: "region"`. The old `~/.config/opencode/plugins/rate-limit-rescue/` path is not source — never edit it.

## Local TODOs

- [x] Add `region` reason to balancer CLI, counter, schema, and migration
- [x] Add per-cause unit test
- [x] Migrate live DB and verify argparse accepts/rejects correctly
- [x] Run full repo test suite
- [ ] Brain QA adversarial testing on the staged diff
- [ ] Brain reviewer final review
- [ ] Stage, move to qa lane, report verdict

## Acceptance Criteria

- [x] `rr next --reason region` marks a node failed with `region_fails=1` and 24h quarantine
- [x] Old DBs gain the column automatically on next run
- [x] Full test suite green
- [ ] Brain QA passes on the diff
- [ ] Brain reviewer approves

## Verification Evidence

- **Test command:** rtk test .venv/bin/python -m pytest tests/test_rr_balancer.py -q
- **Expected result:** all balancer tests pass including the new region case
- **Actual result:** 32 passed
- **Exit code:** 0

- **Test command:** rtk test .venv/bin/python -m pytest tests/ -q
- **Expected result:** full suite green
- **Actual result:** 53 passed
- **Exit code:** 0

- **Test command:** python3 -m py_compile scripts/rr_balancer.py
- **Expected result:** compiles
- **Actual result:** COMPILE-OK
- **Exit code:** 0

- **Test command:** .venv/bin/python scripts/rr_balancer.py --db /tmp/x-region-test.db --secret-file /dev/null next --reason region (argparse smoke)
- **Expected result:** reason accepted (fails later only on missing secret, unrelated)
- **Actual result:** `--reason region` accepted; `--reason bogus` rejected with invalid choice
- **Exit code:** 0

- **Test command:** live DB migration via connect_db + PRAGMA table_info
- **Expected result:** region_fails present, old rows intact
- **Actual result:** True, cols [fails, quota_fails, transport_fails, region_fails]
- **Exit code:** 0

- **Tooling gate skip record:** root marker scan list [go.mod, build.gradle.kts, Package.swift, pyproject.toml, package.json, vite.config, nuxt.config, nest-cli.json]; matched skills []; repo root /home/mohammad/v2ray-to-subs; reason: plain Python (stdlib + PyYAML) + bash, no stack marker match.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [ ] Build/Test/Lint pass with exit code 0
- [ ] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append
- [ ] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** per-cause column added to a live table; a bad migration could lock or corrupt balancer state
- **Rollback plan:** snapshot the DB file before migration (`cp data/balancer_state.db /tmp/opencode/`); restore the file if anything fails (migration is additive-only, verified on the live DB already)

---

## Execution Log & Reasoning

- Mode: autopilot locked for this task on manager order to run the finished quick fix through the Brain pipeline.
- Seat Check: single-domain backend change (balancer CLI + counter + migration + test) → QA Engineer for the QA turn, then Code Reviewer; Designer/Architect/Planner skipped (no UI, no new schema design beyond one additive column mirroring existing ones, no sprint scope). Brainstorm: not required — additive change following the established per-cause pattern, already implemented and green.
- Implementation: already complete in worktree (quick-fix phase, uncommitted): `scripts/rr_balancer.py`, `data/balancer_state.schema.sql`, `tests/test_rr_balancer.py`, `README.md`, `CHANGELOG.md`. No further code planned unless QA or review demands fixes.
- CHANGELOG already carries the region entry under Unreleased/Added (Parse-Then-Append, no header duplication).

### Bridge rounds

- QA turn 1: QA_PASSED with test-only advisories (reverse isolation, quarantine assert, retest readmission for region rows).
- Closed F5/F6 in the same session: extended the region test with failed-status plus quarantine asserts and added a reverse-isolation test (quota leaves `region_fails` at 0). Full suite now 52 passed. F7 (cause-specific retest readmission) rides on the generic expiry path already covered by the quarantine tests.
- Reviewer turn: APPROVED (technical) → PO_REVIEW_PENDING. Reviewer advisories F1 (test name over-promises) and F2 (no next-path region test) closed the same session: test renamed to `test_other_causes_leave_region_fails_at_zero` covering quota/transport/manual, plus new `test_next_reason_region_records_cause`. Full suite now 53 passed. F3 (region in selection ranking) left as-is intentionally, matching transport behavior.
- PO gate: PO_REVIEW_PENDING relayed to manager; manager approval quote, exact: "Approved for closure".

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index b2076b6..95343d7 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -22,6 +22,7 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 - Upstream parity fixes (task 12): ss SIP003 trailing-slash parse crash fixed; v2ray-plugin `mode` defaults to websocket (required by mihomo); vless `encryption` emitted only for mihomo-accepted values.
 - Upstream parity fixes (task 12): emit vless `encryption` to Clash only for values mihomo accepts (`mlkem768x25519plus…`), drop unusable values like `aes-128-gcm` that fail validation.
 - Stable identity-hash node naming (task 13): converter emits `{proto}-{12hex}` names derived from protocol + normalized host + port (SHA-256), replacing provider remarks that reshuffled or collided each refresh; deterministic sort-then-suffix collision fallback; Clash keeps the original remark in a `remark` key while sing-box omits it (schema rejects unknown fields); balancer history (delay/fails/uses/quarantine) now survives feed refreshes; `tests/test_stable_hash_naming.py` (10 tests).
+- Geo-block failure cause (`region`): balancer `--reason` accepts `region` and counts it separately (`region_fails` column via idempotent migration, old DBs self-upgrade); the OpenCode rescue plugin now detects `RegionError` ("model is not available in your country/region") model-independently and rotates the exit with the same 2s rescue; exits refused by a provider's country check quarantine 24h like other causes.
 
 ### Fixed
 - Review hotfix: balancer clock seam, DB parent makedirs, group_members annotation, WAL sidecar ignores.
diff --git a/README.md b/README.md
index fb01252..d1925b3 100644
--- a/README.md
+++ b/README.md
@@ -164,7 +164,7 @@ when a target rate-limits an exit IP, the crawler reports the cause
 and the balancer moves traffic to the next best node automatically:
 
 - **Rotate**: manual only — bare `rr` skips the current node and picks least-used + fastest (`rr-rotate.timer` is intentionally disabled)
-- **Failure causes**: `rr next --reason quota|transport` (default `manual`) records per-cause counters; selection order is least-used, then fewest quota fails, then fastest — exits that hit crawl rate limits sink in priority without being deleted
+- **Failure causes**: `rr next --reason quota|transport|region` (default `manual`) records per-cause counters; selection order is least-used, then fewest quota fails, then fastest — exits that hit crawl rate limits sink in priority without being deleted; `region` (geo-blocked from a provider country check) is tracked separately and quarantined like the others
 - **Retest**: 500 oldest controller-present nodes every 30 minutes (`rr-retest.timer`), dead nodes readmitted on recovery
 - **Freshness**: nodes unchecked for over 2h sit out until rechecked
 - **Stable names**: nodes are named by identity hash (`{proto}-{12hex}` from server + port), so balancer history survives every feed refresh; the provider remark is kept in the Clash `remark` field for humans
diff --git a/data/balancer_state.schema.sql b/data/balancer_state.schema.sql
index b7c48c3..a444dfb 100644
--- a/data/balancer_state.schema.sql
+++ b/data/balancer_state.schema.sql
@@ -8,7 +8,8 @@ CREATE TABLE IF NOT EXISTS nodes (
   quarantined_until INTEGER NOT NULL DEFAULT 0,
   last_fail_cause TEXT NOT NULL DEFAULT '',
   quota_fails INTEGER NOT NULL DEFAULT 0,
-  transport_fails INTEGER NOT NULL DEFAULT 0
+  transport_fails INTEGER NOT NULL DEFAULT 0,
+  region_fails INTEGER NOT NULL DEFAULT 0
 );
 
 CREATE TABLE IF NOT EXISTS rotation_state (
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index ab53a48..3513fbb 100755
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -188,6 +188,7 @@ def connect_db(db_path: str) -> sqlite3.Connection:
             "last_fail_cause TEXT NOT NULL DEFAULT ''",
             "quota_fails INTEGER NOT NULL DEFAULT 0",
             "transport_fails INTEGER NOT NULL DEFAULT 0",
+            "region_fails INTEGER NOT NULL DEFAULT 0",
         ):
             col = coldef.split()[0]
             if col not in cols:
@@ -320,8 +321,10 @@ def _mark_failed(
 ) -> None:
     """Mark one node failed and quarantine it for 24h (retest readmits after expiry).
 
-    The failure cause (quota/transport/manual) is recorded per cause so
-    rotation can prefer nodes with a clean record for crawl traffic.
+    The failure cause (quota/transport/region/manual) is recorded per cause
+    so rotation can prefer nodes with a clean record for crawl traffic and
+    provider-side counters stay separable (region = geo-blocked from the
+    provider's country check, unrelated to rate limiting).
     """
     cur = conn.cursor()
     row = cur.execute("SELECT status FROM nodes WHERE name = ?", (name,)).fetchone()
@@ -332,7 +335,8 @@ def _mark_failed(
             "UPDATE nodes SET status = 'failed', fails = ?, last_check = ?, "
             "quarantined_until = ?, last_fail_cause = ?, "
             "quota_fails = quota_fails + ?, "
-            "transport_fails = transport_fails + ? WHERE name = ?",
+            "transport_fails = transport_fails + ?, "
+            "region_fails = region_fails + ? WHERE name = ?",
             (
                 max_fails,
                 now,
@@ -340,6 +344,7 @@ def _mark_failed(
                 reason,
                 1 if reason == "quota" else 0,
                 1 if reason == "transport" else 0,
+                1 if reason == "region" else 0,
                 name,
             ),
         )
@@ -508,7 +513,7 @@ def build_parser() -> argparse.ArgumentParser:
     skp.add_argument("--max-fails", type=int, default=3)
     skp.add_argument(
         "--reason",
-        choices=("quota", "transport", "manual"),
+        choices=("quota", "transport", "region", "manual"),
         default="manual",
         help="failure cause recorded for smart selection",
     )
@@ -518,7 +523,7 @@ def build_parser() -> argparse.ArgumentParser:
     nxt.add_argument("--max-fails", type=int, default=3)
     nxt.add_argument(
         "--reason",
-        choices=("quota", "transport", "manual"),
+        choices=("quota", "transport", "region", "manual"),
         default="manual",
         help="failure cause recorded for smart selection",
     )
diff --git a/tests/test_rr_balancer.py b/tests/test_rr_balancer.py
index a1138da..b870977 100644
--- a/tests/test_rr_balancer.py
+++ b/tests/test_rr_balancer.py
@@ -494,6 +494,70 @@ class QuotaCauseTest(unittest.TestCase):
         self.assertEqual(row, (0, 1, "transport"))
         conn.close()
 
+    def test_skip_reason_region_records_cause(self):
+        # Geo-blocked exits (provider region check) get their own counter so
+        # they stay separable from rate-limit and network failures.
+        conn, path = make_db()
+        api = FakeAPI({"n1": 2, "n2": 5})
+        mark(conn, "n1", "alive", delay=2, uses=0)
+        mark(conn, "n2", "alive", delay=5, uses=0)
+        conn.close()
+        rc = rr_balancer.cmd_skip(
+            Args(cmd="skip", name="n1", reason="region", db=path), api
+        )
+        self.assertEqual(rc, 0)
+        conn = sqlite3.connect(path)
+        row = conn.execute(
+            "SELECT quota_fails, transport_fails, region_fails, last_fail_cause "
+            "FROM nodes WHERE name='n1'"
+        ).fetchone()
+        self.assertEqual(row, (0, 0, 1, "region"))
+        # Quarantine parity: region failures quarantine exactly like other causes.
+        row = conn.execute(
+            "SELECT status, quarantined_until, last_check FROM nodes WHERE name='n1'"
+        ).fetchone()
+        self.assertEqual(row[0], "failed")
+        self.assertGreater(row[1], row[2])
+        conn.close()
+
+    def test_other_causes_leave_region_fails_at_zero(self):
+        # Reverse isolation: quota, transport, and manual marks must never
+        # touch the region counter.
+        for cause in ("quota", "transport", "manual"):
+            conn, path = make_db()
+            api = FakeAPI({"n1": 2, "n2": 5})
+            mark(conn, "n1", "alive", delay=2, uses=0)
+            mark(conn, "n2", "alive", delay=5, uses=0)
+            conn.close()
+            rc = rr_balancer.cmd_skip(
+                Args(cmd="skip", name="n1", reason=cause, db=path), api
+            )
+            self.assertEqual(rc, 0)
+            conn = sqlite3.connect(path)
+            row = conn.execute(
+                "SELECT region_fails FROM nodes WHERE name='n1'"
+            ).fetchone()
+            self.assertEqual(row, (0,), cause)
+            conn.close()
+
+    def test_next_reason_region_records_cause(self):
+        # The next path shares the same mark-failed helper as skip, so a
+        # region rotation must record region_fails on the current node.
+        conn, path = make_db()
+        api = FakeAPI({"cur": 50, "n2": 5})
+        api.group_members = lambda group: (["cur", "n2"], "cur")
+        mark(conn, "cur", "alive", delay=50, uses=3)
+        mark(conn, "n2", "alive", delay=5, uses=0)
+        conn.close()
+        rc = rr_balancer.cmd_next(Args(cmd="next", reason="region", db=path), api)
+        self.assertEqual(rc, 0)
+        conn = sqlite3.connect(path)
+        row = conn.execute(
+            "SELECT region_fails, last_fail_cause, status FROM nodes WHERE name='cur'"
+        ).fetchone()
+        self.assertEqual(row, (1, "region", "failed"))
+        conn.close()
+
     def test_fewer_quota_fails_beats_faster_delay(self):
         conn, path = make_db()
         api = FakeAPI({"burned": 5, "clean": 500})
```
<!-- END_GIT_DIFF -->
