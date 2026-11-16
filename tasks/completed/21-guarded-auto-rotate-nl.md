# Task 21: Guarded auto-rotate with NL lock

**File:** `tasks/qa/21-guarded-auto-rotate-nl.md`
**Source:** manager
**Type:** feature
**Status:** in-progress
**Submitted:** 2026-11-16T12:48:27Z
**Started:** 2026-11-16T12:42:38Z

## Goal

Land the working-tree NL switch and guarded auto-rotation: triple-feed pool, doubled tick batches, Netherlands exit with a fully gate-tested selection, `rotate --keep-if-clean` wired into the maintenance tick, and the `rr` launcher default flipped to NL.

## Manager's Notes

Direct orders from the live session, implemented in the tree and awaiting QA-to-closure: drop OpenRay for a combination of the top-starred feeds (barry-far All_Configs_Sub, 0xRadikal all/configs.txt, MatinGhanbari all_sub.txt); double tick batches (retest 1000, country 40); switch the live exit to the Netherlands with every probe verified; add `rotate --keep-if-clean` so the timer holds the best gate-tested NL node and moves only when dirty; flip the `rr` launcher default from US to NL so manual runs agree with the timer.

## Local TODOs

- [x] Verify triple-feed refresh: 9254 + 11517 + 3955 parsed, 7636 unique hosts, `mihomo -t` passes, service restarts clean
- [x] Verify NL exit: gate battery green on Google/YouTube/Spotify (Gemini 302 → unknown-kept), `loc=NL`
- [x] Verify `--keep-if-clean`: keeps clean incumbent without churn, quarantines dirty incumbent with cause and moves on, honors the country lock, handles no-current gracefully
- [x] Verify suite: 59 unittest green, new keep tests plus tri-state gate tests
- [x] Verify timer wiring: guarded rotate in `maintain.sh` with NL lock, fail-soft like the other tick jobs
- [x] Verify docs: root README, scripts README, DECISIONS ADR, CHANGELOG entry, launcher default

## Acceptance Criteria

- [x] Live config holds 7000+ proxies from the three feeds with validation passing
- [x] Active exit is NL and gate-clean on Google, YouTube, and Spotify
- [x] A tick with a clean incumbent performs zero switches; a dirty incumbent is quarantined with cause and replaced
- [x] Manual `rr` and the timer agree on the NL default (`RR_COUNTRY` still overrides)
- [x] All 59 tests pass; docs describe the guarded rotation and NL default

## Verification Evidence

- **Test command:** rtk test .venv/bin/python -m unittest tests.test_rr_balancer (pytest is not installed in this env; the stdlib runner covers the same tests)
- **Expected result:** all 59 tests pass including keep-if-clean keeps/rotates/no-current cases
- **Actual result:** Ran 59 tests in 0.326s, OK, via the RTK wrapper. Live: 7646 proxies (vless/vmess/trojan/ss/hysteria2/socks5/tuic), `mihomo -t` pass, exit NL 51.158.206.34 with Google 200 + YouTube/Spotify clean + Gemini 302 unknown-kept, guarded rotate kept incumbent with zero switches. Correction to plan: SUB_URLS lives in `scripts/maintain.sh` (no `refresh-sub.py` exists; `refresh.sh` takes feed URLs as args).
- **Exit code:** 0

> Verification runner rule: `.venv/bin/python -m unittest tests.test_rr_balancer` is the complete underlying test command. The first verification run MUST use the `rtk test` prefix; record the exact prefixed command above. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `testing-verification` applied and evidence recorded
- Stack-skill skip recorded: no roster stack skill matches this plain-Python balancer task; general workflow skills only.

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do not defer box-checking to a closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** Auto-rotate on the timer moves live traffic without an operator watching; a gate false-positive could quarantine a working exit.
- **Rollback plan:** Remove the rotate line from `maintain.sh`; flip the launcher default back to US; `--keep-if-clean` stays inert unless passed; live config `.bak` files restore the previous pool.

---

## Execution Log & Reasoning

Working-tree state at task creation (8 modified files, verified live before filing): triple-feed refresh green (7634 proxies, mihomo -t pass), NL exit 51.158.206.34 with G/Y/S clean and Gemini 302→unknown-kept, `--keep-if-clean` implemented with 3 new tests (59 total green), timer wiring syntax-checked, launcher default NL, docs synced. Plan approval (verbatim Manager answer): "Approved" on the plan-approval question covering S1-S7 with seat routing and R1-R3. Routing back through the Brain for the Senior Programmer verification XML.
Reviewer verdict: technical APPROVAL with PO_REVIEW_PENDING. File stays in tasks/qa/ pending the explicit closure word. Non-blocking follow-ups recorded: R1 log fail-open selections with a distinct rotation-log reason; R2 refresh last_check on keep or document retest ownership; R3 add a non-NL-incumbent lock+keep interaction test.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index cf86b7f..72bcde3 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -36,6 +36,7 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 - Proxy-everything routing in both generators: the ads `REJECT` block, the ~90-domain foreign-service pin list, and the `geosite:category-ads-all` DNS policy are deleted; rules are now private/LAN `DIRECT` → `MATCH,PROXY` (Clash) and sniff/hijack-dns/`ip_is_private` → final auto (sing-box). `allow-lan` defaults to true with mixed-port 7890, so scheduled refreshes serve LAN clients; TUN stays opt-in. `refresh.sh` and `manager.sh deploy` pass `--allow-lan` explicitly; checked-in samples regenerated via the converter.
 - `AGENTS.md` brought in line with the audit criteria: the lite-mode bypass removed so every task runs the full workflow, the task-generator reference corrected to `kanban-lifecycle`, the QA transition routed through `custom_context_qa_transition`, and Edit Tool Discipline, Parallel Index Isolation, and Living Folder Docs Inspection rules added. `docs/conventions.md` gained the Edit Tool Discipline and Living Folder Docs Standard sections; `.gitignore` now covers goal-plugin runtime state.
 - Multi-service clean gate in `rr_balancer.py`: rotation probes all-must-pass Google → YouTube (oEmbed 403 discriminator) → Spotify API (401-JSON clean vs HTML-403 edge block) → Gemini spare, with distinct `youtube`/`spotify`/`gemini` quarantine causes and counters, per-service `--url`/`--timeout-ms`/`--attempts`/`--no-*-check` flags, one shared attempt budget, and fail-open on all-dirty pools. Inconclusive new-probe measurements never quarantine. `tests/test_rr_balancer.py` covers per-cause rejection, unknown-keeps, and the Spotify shape classifier.
+- Guarded auto-rotate with NL lock: `rotate --keep-if-clean` gate-tests the current exit and keeps it when clean (no churn), rotating only on a dirty verdict; `maintain.sh` runs it with `--require-country NL` every tick, and the `rr` launcher default flips US to NL (`RR_COUNTRY` overrides). Retest batch 500→1000 and country batch 20→40 per tick.
 
 ### Fixed
 - Hysteria2 links carrying `fp=` now emit `client-fingerprint`; mihomo rejects a uTLS name under `fingerprint` (that key is a TLS certificate pin) and aborts the whole `mihomo -t` run.
diff --git a/README.md b/README.md
index b8741f9..2bcd2d2 100644
--- a/README.md
+++ b/README.md
@@ -167,13 +167,13 @@ It exists to keep high-volume crawling workloads on working exits:
 when a target rate-limits an exit IP, the crawler reports the cause
 and the balancer moves traffic to the next best node automatically:
 
-- **Rotate**: manual only — bare `rr` rotates to a Google-clean **US** exit (`RR_COUNTRY=DE` overrides, `RR_COUNTRY=` disables the lock); the balancer picks least-used + fastest inside that country (`rr-rotate.timer` is gone, rotation stays manual)
-- **Failure causes**: `rr next --reason google|country|manual` (default `manual`) records the cause and quarantines 24h; `google` also increments `google_fails`. The old `quota`/`transport`/`region` causes belonged to the retired rate-limit-rescue plugin and are gone
-- **Country**: `rr country --batch 20` reads `https://www.cloudflare.com/cdn-cgi/trace` through each selected node and stores the observed exit country (`country`, `country_checked`); unreadable traces are stored as unknown, never as failures. `rr report` prints coverage (checked/total) and per-country counts
-- **Country lock**: `--require-country US` keeps rotation inside one observed country; when no candidate matches, the current node is kept rather than switching country
-- **One maintenance unit**: `v2ray-to-subs.timer` → `v2ray-to-subs-maintain.service` runs `scripts/maintain.sh` every 30 minutes: retest, then a country batch, then a refresh only when the live config is older than 6 hours. This replaces the former refresh/retest/country timers — the project now owns two units, `mihomo-subs.service` and this pair
-- **Google-clean gate**: before selecting a node, rotation reads `https://www.google.com/search?q=test` through the candidate (live mixed-port, redirects disabled). Exits answering 302 `/sorry` are quarantined with cause `google` (24h, `google_fails` counter). A node that passes stays selected; up to `--google-attempts` candidates are rejected, then the best remaining is used so the client never goes dark. `--no-google-check` disables it; the check is skipped when Google is unreachable directly (infra guard)
-- **Retest**: 500 oldest controller-present nodes on every maintenance tick, dead nodes readmitted on recovery
+- **Rotate**: guarded auto-rotate plus manual escape. Every maintenance tick runs `rotate --require-country NL --keep-if-clean`: the current exit is gate-tested, kept when clean, and moved only when dirty — no churn on healthy exits. Bare `rr` does the same rotation manually with the NL default (`RR_COUNTRY=US` overrides, `RR_COUNTRY=` empty disables the lock); the balancer picks least-used + fastest inside that country
+- **Failure causes**: `rr next --reason google|youtube|spotify|gemini|country|manual` (default `manual`) records the cause and quarantines 24h; each probe cause increments its own counter. The old `quota`/`transport`/`region` causes belonged to the retired rate-limit-rescue plugin and are gone
+- **Country**: `rr country --batch 40` reads `https://www.cloudflare.com/cdn-cgi/trace` through each selected node and stores the observed exit country (`country`, `country_checked`); unreadable traces are stored as unknown, never as failures. `rr report` prints coverage (checked/total) and per-country counts
+- **Country lock**: `--require-country NL` keeps rotation inside one observed country; when no candidate matches, the current node is kept rather than switching country
+- **One maintenance unit**: `v2ray-to-subs.timer` → `v2ray-to-subs-maintain.service` runs `scripts/maintain.sh` every 30 minutes: retest, then a country batch, then a guarded rotate (NL lock, keep-if-clean), then a refresh only when the live config is older than 6 hours. This replaces the former refresh/retest/country timers — the project now owns two units, `mihomo-subs.service` and this pair
+- **Multi-service clean gate**: before selecting a node, rotation probes Google Search, the YouTube backend, the Spotify API, and Gemini through the candidate (live mixed-port, redirects disabled). The first flagged service quarantines with its own cause (24h, per-cause counter). Up to the shared attempt budget candidates are rejected, then the best remaining is used so the client never goes dark. Per-service `--no-*-check` flags disable gates; the battery is skipped when Google is unreachable directly (infra guard)
+- **Retest**: 1000 oldest controller-present nodes on every maintenance tick, dead nodes readmitted on recovery
 - **Freshness**: nodes unchecked for over 2h sit out until rechecked
 - **Stable names**: nodes are named by identity hash (`{proto}-{12hex}` from server + port), so balancer history survives every feed refresh; the provider remark is kept in the Clash `remark` field for humans
 - **Memory**: learned rows (alive/failed with delay, uses) survive feed refreshes; only never-tested rows are pruned; pool and retest batch exclude names gone from the controller
diff --git a/scripts/DECISIONS.md b/scripts/DECISIONS.md
index d1fb625..1804ec5 100644
--- a/scripts/DECISIONS.md
+++ b/scripts/DECISIONS.md
@@ -147,3 +147,13 @@ deleting them; the column migrated idempotently.
 **Consequences.** Selection rejects exits that pass Google but fail reputation-sensitive apps; a fully-flagged pool serves the least-bad candidate instead of going dark. First live run quarantined two US nodes (`youtube`, `gemini`) and fail-opened to the best remaining.
 
 **Rollback.** Per-service `--no-*-check` flags; `git checkout` the balancer to restore the Google-only gate.
+
+## 2026-11-16 — Guarded auto-rotate with NL lock (`--keep-if-clean`)
+
+**Context.** US exits kept flapping (repeated manual `rr` runs in one day) while the NL bench measured deeper and cleaner. Manual-only rotation also meant a dirty exit stayed until an operator noticed. But naive auto-rotate re-picks least-used every tick and would flap healthy exits.
+
+**Decision.** `rotate` gains `--keep-if-clean`: the current exit is gate-tested first and kept (uses+1, `keep-clean` log) when clean or inconclusive; rotation proceeds only on a dirty verdict, with the dirty current quarantined under its cause. `maintain.sh` runs `rotate --require-country NL --keep-if-clean` every tick after the country batch. The `rr` launcher default flips US to NL (`RR_COUNTRY` still overrides, empty still disables).
+
+**Consequences.** The pool holds the best gate-tested NL exit on its own and moves only on real dirt — no churn, no manual watching. Manual `rr` and the timer now agree on NL.
+
+**Rollback.** Remove the rotate line from `maintain.sh`; flip the launcher default back to US; `--keep-if-clean` stays inert unless passed.
diff --git a/scripts/README.md b/scripts/README.md
index 3704c85..1a7ff5f 100644
--- a/scripts/README.md
+++ b/scripts/README.md
@@ -37,6 +37,10 @@ The feed list the old refresh drop-in used is embedded in the script.
   counts, so the decision to enable a country lock is data-driven.
 - **Selection**: `rotate` picks the lowest `(uses, delay_ms)` row among alive,
   fresh, non-quarantined nodes and selects it in the `PROXY` group.
+  With `--keep-if-clean` the current exit is gate-tested first and kept
+  when clean, so healthy exits never flap; rotation moves only on a
+  dirty verdict. The maintenance tick runs this guarded rotate with the
+  NL lock, so the pool self-heals without manual runs.
 - **Failure causes**: `skip` / `next --reason google|youtube|spotify|gemini|country|manual`
   quarantines the node for 24 h. Each probe cause increments its own
   counter (`google_fails`, `youtube_fails`, `spotify_fails`, `gemini_fails`).
diff --git a/scripts/maintain.sh b/scripts/maintain.sh
index cade215..5e63fcb 100755
--- a/scripts/maintain.sh
+++ b/scripts/maintain.sh
@@ -23,20 +23,29 @@ REFRESH_AFTER_SEC=21600
 # that this dispatcher replaces. Without these the converter falls back to its
 # built-in default feed, which would silently swap the pool.
 SUB_URLS=(
-	"https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt"
+	"https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt"
+	"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt"
+	"https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/base64/all_sub.txt"
 )
 
 echo "maintain: tick start"
 
 # A failing job must not abort the tick: retest and country both touch the
 # live selector, so one bad batch should never block the refresh check.
-if ! "$PY" "$BALANCER" retest --batch 500; then
+if ! "$PY" "$BALANCER" retest --batch 1000; then
 	echo "maintain: retest warned (continuing)"
 fi
-if ! "$PY" "$BALANCER" country --batch 20; then
+if ! "$PY" "$BALANCER" country --batch 40; then
 	echo "maintain: country warned (continuing)"
 fi
 
+# Guarded auto-rotate: keep the best gate-tested NL exit without churn.
+# --keep-if-clean only moves when the current exit is dirty; a healthy
+# exit is kept untouched, so stable connections never flap.
+if ! "$PY" "$BALANCER" rotate --require-country NL --keep-if-clean; then
+	echo "maintain: rotate warned (continuing)"
+fi
+
 NEED_REFRESH=0
 if [[ ! -f "$LIVE" ]]; then
 	NEED_REFRESH=1
diff --git a/scripts/rr b/scripts/rr
index d8c7695..7c9ecc9 100755
--- a/scripts/rr
+++ b/scripts/rr
@@ -11,7 +11,7 @@ if [[ $# -eq 0 ]]; then
   if [[ -n "${RR_COUNTRY+set}" && -z "$RR_COUNTRY" ]]; then
     exec "$DIR/rr_balancer.py" rotate
   else
-    exec "$DIR/rr_balancer.py" rotate --require-country "${RR_COUNTRY:-US}"
+    exec "$DIR/rr_balancer.py" rotate --require-country "${RR_COUNTRY:-NL}"
   fi
 fi
 
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index bd4c7ea..22e790f 100755
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -620,17 +620,6 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
     seed_names(conn, pool_names)
     pool = alive_pool(conn, now, args.stale_after, allowed=set(pool_names))
     ordered = order_pool(pool)
-    if not ordered:
-        conn.execute(
-            "INSERT INTO rotation_log (ts, node, reason) VALUES (?, '', 'noop-empty-pool')",
-            (now,),
-        )
-        conn.commit()
-        print("rotate: empty alive pool, no-op (group untouched)")
-        return 0
-    name = None
-    delay = None
-    attempts = 0
     require_country = getattr(args, "require_country", None)
     if require_country:
         require_country = require_country.strip().upper()
@@ -642,6 +631,61 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
             )
             return 0
         ordered = locked
+    if getattr(args, "keep_if_clean", False) and current:
+        alive_names = set(row[0] for row in ordered)
+        if current in alive_names:
+            keep_cause = multi_gate_cause(api, args.group, current, args)
+            if keep_cause is None or keep_cause == "unknown":
+                if keep_cause == "unknown":
+                    print(
+                        "rotate: current %s probe inconclusive, keeping without quarantine"
+                        % current
+                    )
+                else:
+                    print("rotate: current %s still clean, keeping" % current)
+                cur = conn.cursor()
+                cur.execute(
+                    "UPDATE nodes SET uses = uses + 1 WHERE name = ?", (current,)
+                )
+                cur.execute(
+                    "INSERT INTO rotation_log (ts, node, delay_ms, reason) "
+                    "VALUES (?, ?, ?, 'keep-clean')",
+                    (now, current, None),
+                )
+                cur.execute(
+                    "INSERT OR REPLACE INTO rotation_state (id, position, updated_at) "
+                    "VALUES (1, (SELECT COALESCE(position, 0) FROM rotation_state "
+                    "WHERE id = 1) + 1, ?)",
+                    (now,),
+                )
+                conn.commit()
+                return 0
+            _mark_failed(
+                conn,
+                current,
+                getattr(args, "max_fails", 3),
+                now,
+                keep_cause,
+            )
+            ordered = [row for row in ordered if row[0] != current]
+            if not ordered:
+                print(
+                    "rotate: current %s dirty and no other candidates, "
+                    "failing open to current" % current
+                )
+                api.select(args.group, current)
+                return 0
+    if not ordered:
+        conn.execute(
+            "INSERT INTO rotation_log (ts, node, reason) VALUES (?, '', 'noop-empty-pool')",
+            (now,),
+        )
+        conn.commit()
+        print("rotate: empty alive pool, no-op (group untouched)")
+        return 0
+    name = None
+    delay = None
+    attempts = 0
     gates_on = [
         svc
         for svc in ("google", "youtube", "spotify", "gemini")
@@ -1093,6 +1137,12 @@ def build_parser() -> argparse.ArgumentParser:
 
     rot = sub.add_parser("rotate", help="select next alive node")
     rot.add_argument("--stale-after", type=int, default=7200)
+    rot.add_argument(
+        "--keep-if-clean",
+        action="store_true",
+        help="gate the current node first and keep it when clean; "
+        "rotate only when it is dirty",
+    )
     add_google_args(rot)
     add_youtube_args(rot)
     add_spotify_args(rot)
diff --git a/tests/test_rr_balancer.py b/tests/test_rr_balancer.py
index ddc3975..d47a23e 100644
--- a/tests/test_rr_balancer.py
+++ b/tests/test_rr_balancer.py
@@ -28,10 +28,11 @@ class FakeAPI:
     google_blocked names answer /sorry (302) on the expected=200 probe.
     """
 
-    def __init__(self, delays, group="PROXY", google_blocked=None):
+    def __init__(self, delays, group="PROXY", google_blocked=None, current="old-node"):
         self.delays = delays
         self.google_blocked = set(google_blocked or ())
         self.group = group
+        self.current = current
         self.selected = []
         self.members = list(delays) + ["Auto", "Load Balance", "Fallback"]
         self.connections = []
@@ -40,7 +41,7 @@ class FakeAPI:
 
     def group_members(self, group):
         pool = [m for m in self.members if m not in rr_balancer.META_NAMES]
-        return pool, "old-node"
+        return pool, self.current
 
     def select(self, group, name):
         self.selected.append((group, name))
@@ -109,6 +110,7 @@ class Args:
                 gemini_url=rr_balancer.DEFAULT_GEMINI_URL,
                 gemini_timeout_ms=8000,
                 gemini_attempts=5,
+                keep_if_clean=False,
                 # Country fields default to the lock being off.
                 require_country=None,
                 trace_url=rr_balancer.DEFAULT_TRACE_URL,
@@ -258,6 +260,111 @@ class RotateTest(unittest.TestCase):
         ).fetchone()
         self.assertEqual(row, ("failed", "spotify", 1))
 
+    def test_keep_if_clean_keeps_current(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "incumbent", "alive", delay=200, uses=3, last_check=now)
+        mark(conn, "challenger", "alive", delay=50, uses=0, last_check=now)
+        api = FakeAPI({"incumbent": 200, "challenger": 50}, current="incumbent")
+        args = Args(
+            db=path,
+            keep_if_clean=True,
+            no_google_check=False,
+            no_youtube_check=False,
+            no_spotify_check=False,
+            no_gemini_check=False,
+        )
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", return_value=200
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_spotify_clean", return_value=True
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        # Challenger is faster and unused, but the clean incumbent stays.
+        self.assertEqual(api.selected[-1], ("PROXY", "incumbent"))
+        row = conn.execute(
+            "SELECT status, uses FROM nodes WHERE name='incumbent'"
+        ).fetchone()
+        self.assertEqual(row, ("alive", 4))
+        log = conn.execute(
+            "SELECT reason FROM rotation_log ORDER BY id DESC LIMIT 1"
+        ).fetchone()
+        self.assertEqual(log, ("keep-clean",))
+
+    def test_keep_if_clean_rotates_when_dirty(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "incumbent", "alive", delay=200, uses=3, last_check=now)
+        mark(conn, "challenger", "alive", delay=50, uses=0, last_check=now)
+        api = FakeAPI({"incumbent": 200, "challenger": 50}, current="incumbent")
+        args = Args(
+            db=path,
+            keep_if_clean=True,
+            no_google_check=False,
+            no_youtube_check=False,
+            no_spotify_check=False,
+            no_gemini_check=False,
+        )
+
+        def fake_status(url, proxy, timeout):
+            if "youtube.com" in url and api.selected[-1][1] == "incumbent":
+                return 403
+            return 200
+
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", side_effect=fake_status
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_spotify_clean", return_value=True
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "challenger"))
+        row = conn.execute(
+            "SELECT status, last_fail_cause FROM nodes WHERE name='incumbent'"
+        ).fetchone()
+        self.assertEqual(row, ("failed", "youtube"))
+
+    def test_keep_if_clean_without_current_rotates_normally(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "a", "alive", delay=50, uses=0, last_check=now)
+        api = FakeAPI({"a": 50}, current=None)
+        args = Args(
+            db=path,
+            keep_if_clean=True,
+            no_google_check=False,
+            no_youtube_check=False,
+            no_spotify_check=False,
+            no_gemini_check=False,
+        )
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", return_value=200
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_spotify_clean", return_value=True
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "a"))
+
     def test_rotate_youtube_unknown_keeps_without_quarantine(self):
         conn, path = make_db()
         now = int(time.time())
```
<!-- END_GIT_DIFF -->
