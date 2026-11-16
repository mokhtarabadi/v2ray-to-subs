# Task 22: On-demand speed pick with DE hold, TUN retired

**File:** `tasks/qa/22-speed-pick-de-hold-no-tun.md`
**Source:** manager
**Type:** feature
**Status:** in-progress
**Submitted:** 2026-11-16T13:27:11Z
**Started:** 2026-11-16T13:20:05Z

## Goal

Land the working-tree speed and hold changes: proxy-only stack (TUN retired), on-demand `fastest` speed pick, DE hold across timer and launcher, with tests and docs.

## Manager's Notes

Direct orders from the live session, implemented in the tree and awaiting QA-to-closure: the selected node was too slow (delay says nothing about throughput — 28ms exits delivered 48–196 KB/s), so disable TUN and restart proxy-only, then build the proportionate fix (bounded finalist speed test, not full speedtest-cli per node). Flip the hold country NL→DE across `maintain.sh` and the `rr` launcher so both agree.

## Local TODOs

- [x] Verify TUN retired: no TUN device, direct egress on server default IP, proxy exits still gate-clean
- [x] Verify triple-feed refresh still validates (`mihomo -t` pass, service restarts clean)
- [x] Verify `fastest`: gates finalists with the full battery, quarantines flagged with cause, picks the quickest of top 3, never quarantines on slowness alone
- [x] Verify DE hold: timer and launcher agree on DE, keep-if-clean keeps healthy exits with zero switches
- [x] Verify suite: 63 unittest green including keep-if-clean and fastest tests
- [x] Verify docs: root README, scripts README, DECISIONS ADRs, CHANGELOG entries

## Acceptance Criteria

- [x] Live stack is proxy-only: no TUN device, direct traffic on the server default IP
- [x] Active exit is DE and gate-clean, selected as the fastest of tested finalists
- [x] Slowness alone never quarantines any node (verified by test + live run)
- [x] Timer and manual `rr` agree on the DE default (`RR_COUNTRY` still overrides)
- [x] All 63 tests pass; docs describe the speed pick, DE hold, and proxy-only stack

## Verification Evidence

- **Test command:** rtk test .venv/bin/python -m unittest tests.test_rr_balancer (pytest is not installed in this env; the stdlib runner covers the same tests)
- **Expected result:** all 63 tests pass including fastest picks/flags/no-quarantine cases
- **Actual result:** Ran 63 tests in 0.299s, OK, via the RTK wrapper. Live: proxy-only stack verified (no TUN device, `tun.enable: false`, direct FR default); 7718 live proxies, `mihomo -t` pass; exit DE 76.164.202.162 gate-clean on Google/YouTube/Spotify (Gemini 302 unknown-kept); guarded rotate kept the incumbent with zero switches; then the fastest-picked node died mid-session (dial EOF) and the guard quarantined it (google) and moved back to the verified DE exit — the auto-heal loop demonstrated live. Correction to plan: SUB_URLS lives in `scripts/maintain.sh`, `refresh.sh` is at repo root (no `refresh-sub.py` exists).
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

- **Risk:** A speed pick moves live traffic to an untested-for-stability node; a bad finalist pool picks the least-bad slow exit.
- **Rollback plan:** `rr rotate --require-country DE` reselects by delay order; remove the `fastest` subcommand without touching `rotate`; restore live config from `.bak`.

---

## Execution Log & Reasoning

Working-tree state at task filing (9 modified files, verified live): TUN device absent with `tun.enable: false`, direct egress on the server default (FR), proxy exit DE 185.255.115.181 gate-clean on all four probes, `fastest` picked 190KB/s over 150KB/s finalists live, keep-if-clean holds DE with zero switches, 63 tests green. Plan approval (verbatim Manager answer): "Approved" on the plan-approval question covering S1-S7 with seat routing and R1-R3. Routing back through the Brain for the Senior Programmer verification XML.
Reviewer verdict: technical APPROVAL with PO_REVIEW_PENDING. File stays in tasks/qa/ pending the explicit closure word. Non-blocking follow-ups recorded: R1 add fastest to the stale-after floor 60 for consistency; R2 simplify the redundant elif branch; R3 annotate the prior NL ADR as superseded; plus QA notes (no try around mid-loop select, fastest lacks last_check refresh, no lock-miss test).

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 72bcde3..da9cf4a 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -37,6 +37,8 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 - `AGENTS.md` brought in line with the audit criteria: the lite-mode bypass removed so every task runs the full workflow, the task-generator reference corrected to `kanban-lifecycle`, the QA transition routed through `custom_context_qa_transition`, and Edit Tool Discipline, Parallel Index Isolation, and Living Folder Docs Inspection rules added. `docs/conventions.md` gained the Edit Tool Discipline and Living Folder Docs Standard sections; `.gitignore` now covers goal-plugin runtime state.
 - Multi-service clean gate in `rr_balancer.py`: rotation probes all-must-pass Google → YouTube (oEmbed 403 discriminator) → Spotify API (401-JSON clean vs HTML-403 edge block) → Gemini spare, with distinct `youtube`/`spotify`/`gemini` quarantine causes and counters, per-service `--url`/`--timeout-ms`/`--attempts`/`--no-*-check` flags, one shared attempt budget, and fail-open on all-dirty pools. Inconclusive new-probe measurements never quarantine. `tests/test_rr_balancer.py` covers per-cause rejection, unknown-keeps, and the Spotify shape classifier.
 - Guarded auto-rotate with NL lock: `rotate --keep-if-clean` gate-tests the current exit and keeps it when clean (no churn), rotating only on a dirty verdict; `maintain.sh` runs it with `--require-country NL` every tick, and the `rr` launcher default flips US to NL (`RR_COUNTRY` overrides). Retest batch 500→1000 and country batch 20→40 per tick.
+- On-demand speed pick: `rr fastest` gates the ordered pool with the same battery, downloads a capped 3MB file through the top 3 clean finalists, and selects the fastest. Slowness alone never quarantines; manual only, never on the timer.
+- Hold country flipped NL→DE and TUN retired: the live stack is proxy-only again (mixed-port 7890 + allow-lan, no TUN device), and the timer plus `rr` default hold the best gate-tested DE exit.
 
 ### Fixed
 - Hysteria2 links carrying `fp=` now emit `client-fingerprint`; mihomo rejects a uTLS name under `fingerprint` (that key is a TLS certificate pin) and aborts the whole `mihomo -t` run.
diff --git a/README.md b/README.md
index 2bcd2d2..bea6d2a 100644
--- a/README.md
+++ b/README.md
@@ -167,11 +167,12 @@ It exists to keep high-volume crawling workloads on working exits:
 when a target rate-limits an exit IP, the crawler reports the cause
 and the balancer moves traffic to the next best node automatically:
 
-- **Rotate**: guarded auto-rotate plus manual escape. Every maintenance tick runs `rotate --require-country NL --keep-if-clean`: the current exit is gate-tested, kept when clean, and moved only when dirty — no churn on healthy exits. Bare `rr` does the same rotation manually with the NL default (`RR_COUNTRY=US` overrides, `RR_COUNTRY=` empty disables the lock); the balancer picks least-used + fastest inside that country
+- **Rotate**: guarded auto-rotate plus manual escape. Every maintenance tick runs `rotate --require-country DE --keep-if-clean`: the current exit is gate-tested, kept when clean, and moved only when dirty — no churn on healthy exits. Bare `rr` does the same rotation manually with the DE default (`RR_COUNTRY=US` overrides, `RR_COUNTRY=` empty disables the lock); the balancer picks least-used + fastest inside that country
+- **Speed pick**: `rr fastest [--require-country DE]` takes the top 3 gate-clean finalists, downloads a capped 3MB file through each (~15s each), and selects the fastest. Slowness alone never quarantines anyone. On-demand only — the timer stays on cleanliness gates
 - **Failure causes**: `rr next --reason google|youtube|spotify|gemini|country|manual` (default `manual`) records the cause and quarantines 24h; each probe cause increments its own counter. The old `quota`/`transport`/`region` causes belonged to the retired rate-limit-rescue plugin and are gone
 - **Country**: `rr country --batch 40` reads `https://www.cloudflare.com/cdn-cgi/trace` through each selected node and stores the observed exit country (`country`, `country_checked`); unreadable traces are stored as unknown, never as failures. `rr report` prints coverage (checked/total) and per-country counts
-- **Country lock**: `--require-country NL` keeps rotation inside one observed country; when no candidate matches, the current node is kept rather than switching country
-- **One maintenance unit**: `v2ray-to-subs.timer` → `v2ray-to-subs-maintain.service` runs `scripts/maintain.sh` every 30 minutes: retest, then a country batch, then a guarded rotate (NL lock, keep-if-clean), then a refresh only when the live config is older than 6 hours. This replaces the former refresh/retest/country timers — the project now owns two units, `mihomo-subs.service` and this pair
+- **Country lock**: `--require-country DE` keeps rotation inside one observed country; when no candidate matches, the current node is kept rather than switching country
+- **One maintenance unit**: `v2ray-to-subs.timer` → `v2ray-to-subs-maintain.service` runs `scripts/maintain.sh` every 30 minutes: retest, then a country batch, then a guarded rotate (DE lock, keep-if-clean), then a refresh only when the live config is older than 6 hours. This replaces the former refresh/retest/country timers — the project now owns two units, `mihomo-subs.service` and this pair
 - **Multi-service clean gate**: before selecting a node, rotation probes Google Search, the YouTube backend, the Spotify API, and Gemini through the candidate (live mixed-port, redirects disabled). The first flagged service quarantines with its own cause (24h, per-cause counter). Up to the shared attempt budget candidates are rejected, then the best remaining is used so the client never goes dark. Per-service `--no-*-check` flags disable gates; the battery is skipped when Google is unreachable directly (infra guard)
 - **Retest**: 1000 oldest controller-present nodes on every maintenance tick, dead nodes readmitted on recovery
 - **Freshness**: nodes unchecked for over 2h sit out until rechecked
diff --git a/refresh.sh b/refresh.sh
index e662131..eba1589 100755
--- a/refresh.sh
+++ b/refresh.sh
@@ -31,7 +31,7 @@ else
 fi
 
 echo "[refresh] generating to $TMP ..."
-"$PY" "$CONVERTER" "${URLS[@]}" --only clash --clash-out "$TMP" --unique-host --allow-lan --tun
+"$PY" "$CONVERTER" "${URLS[@]}" --only clash --clash-out "$TMP" --unique-host --allow-lan
 
 echo "[refresh] validating with mihomo -t ..."
 MIHOMO_BIN="$(command -v mihomo || true)"
diff --git a/scripts/DECISIONS.md b/scripts/DECISIONS.md
index 1804ec5..8764fda 100644
--- a/scripts/DECISIONS.md
+++ b/scripts/DECISIONS.md
@@ -157,3 +157,23 @@ deleting them; the column migrated idempotently.
 **Consequences.** The pool holds the best gate-tested NL exit on its own and moves only on real dirt — no churn, no manual watching. Manual `rr` and the timer now agree on NL.
 
 **Rollback.** Remove the rotate line from `maintain.sh`; flip the launcher default back to US; `--keep-if-clean` stays inert unless passed.
+
+## 2026-11-16 — Hold country flipped NL to DE
+
+**Context.** The NL exit stayed clean but the operator asked for a German hold: the DE bench is deep and the current DE exit tests clean on all four probes.
+
+**Decision.** Default lock flipped NL to DE in `maintain.sh` and the `rr` launcher (`RR_COUNTRY` still overrides, empty still disables). Nothing else changes: same keep-if-clean guard, same battery, same fail-open.
+
+**Consequences.** Every tick holds the best gate-tested DE exit; manual `rr` agrees.
+
+**Rollback.** Flip both lines back to NL.
+
+## 2026-11-16 — On-demand speed pick (`fastest`)
+
+**Context.** Delay (HTTP 204 round-trip) says nothing about throughput: 28ms exits delivered 48–196 KB/s. Full speedtest-cli per node is over-engineering (60s+, ~100MB per candidate, abusive to free nodes, and it 502s through exits).
+
+**Decision.** New manual-only `fastest` subcommand: gate the ordered pool (flagged quarantine with cause, same battery), speed-test the first `--top` (default 3) clean finalists with a bounded exact-byte download (default 3MB, 30s cap each), select the fastest. Slow losers are never quarantined; nobody clean loses standing. Not wired to the timer.
+
+**Consequences.** Operator can escape a clean-but-slow exit in about a minute without disturbing the pool's learned state.
+
+**Rollback.** Remove the subcommand; `rotate` behavior unchanged.
diff --git a/scripts/README.md b/scripts/README.md
index 1a7ff5f..c8f8d40 100644
--- a/scripts/README.md
+++ b/scripts/README.md
@@ -40,7 +40,12 @@ The feed list the old refresh drop-in used is embedded in the script.
   With `--keep-if-clean` the current exit is gate-tested first and kept
   when clean, so healthy exits never flap; rotation moves only on a
   dirty verdict. The maintenance tick runs this guarded rotate with the
-  NL lock, so the pool self-heals without manual runs.
+  DE lock, so the pool self-heals without manual runs.
+- **Speed pick**: `fastest` speed-tests the top `--top` gate-clean
+  finalists (default 3) with a bounded exact-byte download each
+  (default 3MB, 30s cap) and selects the fastest. Slow losers keep
+  their standing — throughput is a signal, never a quarantine verdict.
+  Manual only, never on the timer.
 - **Failure causes**: `skip` / `next --reason google|youtube|spotify|gemini|country|manual`
   quarantines the node for 24 h. Each probe cause increments its own
   counter (`google_fails`, `youtube_fails`, `spotify_fails`, `gemini_fails`).
diff --git a/scripts/maintain.sh b/scripts/maintain.sh
index 5e63fcb..5eb4cc9 100755
--- a/scripts/maintain.sh
+++ b/scripts/maintain.sh
@@ -39,10 +39,10 @@ if ! "$PY" "$BALANCER" country --batch 40; then
 	echo "maintain: country warned (continuing)"
 fi
 
-# Guarded auto-rotate: keep the best gate-tested NL exit without churn.
+# Guarded auto-rotate: keep the best gate-tested DE exit without churn.
 # --keep-if-clean only moves when the current exit is dirty; a healthy
 # exit is kept untouched, so stable connections never flap.
-if ! "$PY" "$BALANCER" rotate --require-country NL --keep-if-clean; then
+if ! "$PY" "$BALANCER" rotate --require-country DE --keep-if-clean; then
 	echo "maintain: rotate warned (continuing)"
 fi
 
diff --git a/scripts/rr b/scripts/rr
index 7c9ecc9..c9396ee 100755
--- a/scripts/rr
+++ b/scripts/rr
@@ -11,7 +11,7 @@ if [[ $# -eq 0 ]]; then
   if [[ -n "${RR_COUNTRY+set}" && -z "$RR_COUNTRY" ]]; then
     exec "$DIR/rr_balancer.py" rotate
   else
-    exec "$DIR/rr_balancer.py" rotate --require-country "${RR_COUNTRY:-NL}"
+    exec "$DIR/rr_balancer.py" rotate --require-country "${RR_COUNTRY:-DE}"
   fi
 fi
 
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index 22e790f..ec504db 100755
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -62,6 +62,12 @@ DEFAULT_SPOTIFY_URL = "https://api.spotify.com/v1/search?q=test&type=track"
 # that pass Search, so a Gemini-clean exit is clean everywhere measured.
 DEFAULT_GEMINI_URL = "https://gemini.google.com/"
 
+# Throughput probe: Cloudflare serves an exact byte count, so the test is
+# bounded by construction. Big enough to separate throttled exits from
+# healthy ones, small enough to stay polite to free nodes.
+DEFAULT_SPEED_URL = "https://speed.cloudflare.com/__down?bytes=3000000"
+DEFAULT_SPEED_BYTES = 3000000
+
 # Cloudflare's trace endpoint reports the country Cloudflare sees for the
 # connection ("loc=XX"). Read through a candidate exit it is the observed
 # country of that exit, which is what a geo-locked client actually gets --
@@ -861,6 +867,142 @@ def cmd_next(args: argparse.Namespace, api: ClashAPI) -> int:
     return rc
 
 
+def probe_throughput(
+    url: str, proxy_url: str, max_bytes: int, timeout_s: float
+) -> Optional[float]:
+    """Download up to max_bytes through the live selector, return bytes/sec.
+
+    One bounded read: slow or failing exits cost at most timeout_s, never
+    a stall. Returns None on any transport failure. Slowness is a signal,
+    never a quarantine verdict — callers must not fail nodes on it.
+    """
+    opener = urllib.request.build_opener(
+        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
+        _NoRedirect,
+    )
+    req = urllib.request.Request(
+        url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131"}
+    )
+    if max_bytes < 65536:
+        max_bytes = 65536
+    start = time.monotonic()
+    deadline = start + timeout_s
+    total = 0
+    try:
+        with opener.open(req, timeout=timeout_s) as resp:
+            if resp.status != 200:
+                return None
+            while total < max_bytes:
+                if time.monotonic() >= deadline:
+                    break
+                chunk = resp.read(min(65536, max_bytes - total))
+                if not chunk:
+                    break
+                total += len(chunk)
+    except Exception:
+        return None
+    elapsed = time.monotonic() - start
+    if total <= 0 or elapsed <= 0:
+        return None
+    return total / elapsed
+
+
+def cmd_fastest(args: argparse.Namespace, api: ClashAPI) -> int:
+    """Pick the fastest of the top gate-clean finalists, on demand only.
+
+    Gates the ordered pool like rotate (flagged candidates quarantine
+    with cause), speed-tests the first --top clean finalists with a
+    bounded download each, and selects the fastest. Slow losers are
+    never quarantined. Never runs on the timer: speed costs traffic
+    and time, so this stays a manual decision.
+    """
+    now = utc_now_epoch()
+    conn = connect_db(args.db)
+    pool_names, current = api.group_members(args.group)
+    seed_names(conn, pool_names)
+    pool = alive_pool(conn, now, args.stale_after, allowed=set(pool_names))
+    ordered = order_pool(pool)
+    require_country = getattr(args, "require_country", None)
+    if require_country:
+        require_country = require_country.strip().upper()
+        locked = [row for row in ordered if (row[3] or "").upper() == require_country]
+        if not locked:
+            print(
+                "fastest: no %s candidates in the alive pool, keeping current %s"
+                % (require_country, current or "selection")
+            )
+            return 0
+        ordered = locked
+    max_attempts = max(
+        1,
+        max(
+            getattr(args, "%s_attempts" % svc, 5)
+            for svc in ("google", "youtube", "spotify", "gemini")
+        ),
+    )
+    proxy_url = getattr(args, "google_proxy", DEFAULT_PROXY_URL)
+    speed_url = getattr(args, "speed_url", DEFAULT_SPEED_URL)
+    speed_bytes = max(65536, getattr(args, "speed_bytes", DEFAULT_SPEED_BYTES))
+    speed_timeout = getattr(args, "speed_timeout_ms", 30000) / 1000.0
+    top_n = max(1, getattr(args, "top", 3))
+    attempts = 0
+    finalists = []
+    for candidate in ordered:
+        if len(finalists) >= top_n or attempts >= max_attempts:
+            break
+        attempts += 1
+        cause = multi_gate_cause(api, args.group, candidate[0], args)
+        if cause is None or cause == "unknown":
+            finalists.append(candidate[0])
+        elif cause != "unknown":
+            _mark_failed(conn, candidate[0], getattr(args, "max_fails", 3), now, cause)
+    if not finalists:
+        print("fastest: no clean finalists, keeping current selection")
+        return 0
+    results = []
+    for name in finalists:
+        api.select(args.group, name)
+        if GOOGLE_SETTLE_SECONDS:
+            time.sleep(GOOGLE_SETTLE_SECONDS)
+        rate = probe_throughput(speed_url, proxy_url, speed_bytes, speed_timeout)
+        print("fastest: %s %.0f B/s" % (name, rate if rate is not None else -1))
+        results.append((name, rate if rate is not None else -1))
+    results.sort(key=lambda row: row[1], reverse=True)
+    winner = results[0][0]
+    api.select(args.group, winner)
+    if current and current != winner:
+        try:
+            closed, failed = close_stale_connections(api, current)
+        except Exception as exc:
+            print("close stale after switch to %s failed: %s" % (winner, exc))
+        else:
+            print(
+                "closed %d stale connections of %s after switch to %s%s"
+                % (
+                    closed,
+                    current,
+                    winner,
+                    (" (failed ids: %s)" % ",".join(failed)) if failed else "",
+                )
+            )
+    cur = conn.cursor()
+    cur.execute("UPDATE nodes SET uses = uses + 1 WHERE name = ?", (winner,))
+    cur.execute(
+        "INSERT INTO rotation_log (ts, node, delay_ms, reason) "
+        "VALUES (?, ?, ?, 'fastest')",
+        (now, winner, None),
+    )
+    cur.execute(
+        "INSERT OR REPLACE INTO rotation_state (id, position, updated_at) "
+        "VALUES (1, (SELECT COALESCE(position, 0) FROM rotation_state "
+        "WHERE id = 1) + 1, ?)",
+        (now,),
+    )
+    conn.commit()
+    print("fastest: selected %s" % winner)
+    return 0
+
+
 def check_one(
     api: ClashAPI, name: str, test_url: str, timeout_ms: int
 ) -> Tuple[str, Optional[int]]:
@@ -1189,6 +1331,30 @@ def build_parser() -> argparse.ArgumentParser:
     add_gemini_args(nxt)
     add_country_lock_arg(nxt)
 
+    fst = sub.add_parser(
+        "fastest", help="pick the fastest of the top gate-clean finalists"
+    )
+    fst.add_argument("--stale-after", type=int, default=7200)
+    fst.add_argument(
+        "--top",
+        type=int,
+        default=3,
+        help="gate-clean finalists to speed-test before picking",
+    )
+    fst.add_argument(
+        "--speed-url",
+        default=DEFAULT_SPEED_URL,
+        help="exact-byte download read through each finalist",
+    )
+    fst.add_argument("--speed-bytes", type=int, default=DEFAULT_SPEED_BYTES)
+    fst.add_argument("--speed-timeout-ms", type=int, default=30000)
+    fst.add_argument("--max-fails", type=int, default=3)
+    add_google_args(fst)
+    add_youtube_args(fst)
+    add_spotify_args(fst)
+    add_gemini_args(fst)
+    add_country_lock_arg(fst)
+
     cty = sub.add_parser("country", help="fill observed exit countries for a batch")
     cty.add_argument("--batch", type=int, default=20)
     cty.add_argument("--trace-url", default=DEFAULT_TRACE_URL)
@@ -1222,7 +1388,7 @@ def validate_args(args: argparse.Namespace) -> Optional[str]:
             return "--trace-timeout-ms must be >= 500"
     if args.cmd in ("rotate", "skip", "next") and args.stale_after < 60:
         return "--stale-after must be >= 60"
-    if args.cmd in ("rotate", "skip", "next"):
+    if args.cmd in ("rotate", "skip", "next", "fastest"):
         if args.google_timeout_ms < 500:
             return "--google-timeout-ms must be >= 500"
         if args.google_attempts < 1:
@@ -1243,6 +1409,11 @@ def validate_args(args: argparse.Namespace) -> Optional[str]:
             cc = args.require_country.strip()
             if len(cc) != 2 or not cc.isalpha():
                 return "--require-country must be a two-letter country code"
+    if args.cmd == "fastest":
+        if args.top < 1:
+            return "--top must be >= 1"
+        if args.speed_timeout_ms < 1000:
+            return "--speed-timeout-ms must be >= 1000"
     return None
 
 
@@ -1265,6 +1436,8 @@ def main(argv: Optional[List[str]] = None) -> int:
         return cmd_skip(args, api)
     if args.cmd == "next":
         return cmd_next(args, api)
+    if args.cmd == "fastest":
+        return cmd_fastest(args, api)
     if args.cmd == "country":
         return cmd_country(args, api)
     return cmd_retest(args, api)
diff --git a/tests/test_rr_balancer.py b/tests/test_rr_balancer.py
index d47a23e..6f69fe5 100644
--- a/tests/test_rr_balancer.py
+++ b/tests/test_rr_balancer.py
@@ -111,6 +111,10 @@ class Args:
                 gemini_timeout_ms=8000,
                 gemini_attempts=5,
                 keep_if_clean=False,
+                top=3,
+                speed_url=rr_balancer.DEFAULT_SPEED_URL,
+                speed_bytes=rr_balancer.DEFAULT_SPEED_BYTES,
+                speed_timeout_ms=30000,
                 # Country fields default to the lock being off.
                 require_country=None,
                 trace_url=rr_balancer.DEFAULT_TRACE_URL,
@@ -365,6 +369,95 @@ class RotateTest(unittest.TestCase):
             self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
         self.assertEqual(api.selected[-1], ("PROXY", "a"))
 
+    def test_fastest_picks_quickest_clean_finalist(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "slow", "alive", delay=50, uses=0, last_check=now)
+        mark(conn, "mid", "alive", delay=60, uses=0, last_check=now)
+        mark(conn, "fast", "alive", delay=70, uses=0, last_check=now)
+        api = FakeAPI({"slow": 50, "mid": 60, "fast": 70})
+        args = Args(cmd="fastest", db=path, top=3)
+        speeds = {"slow": 100000.0, "mid": 500000.0, "fast": 2000000.0}
+
+        def fake_throughput(url, proxy, max_bytes, timeout):
+            return speeds[api.selected[-1][1]]
+
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "multi_gate_cause", return_value=None
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_throughput", side_effect=fake_throughput
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_fastest(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "fast"))
+        for name in ("slow", "mid", "fast"):
+            row = conn.execute(
+                "SELECT status FROM nodes WHERE name=?", (name,)
+            ).fetchone()
+            self.assertEqual(row, ("alive",))
+
+    def test_fastest_skips_gate_flagged_candidate(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "dirty", "alive", delay=50, uses=0, last_check=now)
+        mark(conn, "clean", "alive", delay=200, uses=0, last_check=now)
+        api = FakeAPI({"dirty": 50, "clean": 200})
+        args = Args(cmd="fastest", db=path, top=3)
+
+        def fake_gate(api_, group, name, args_):
+            return "youtube" if name == "dirty" else None
+
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "multi_gate_cause", side_effect=fake_gate
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_throughput", return_value=1000000.0
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_fastest(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "clean"))
+        row = conn.execute(
+            "SELECT status, last_fail_cause FROM nodes WHERE name='dirty'"
+        ).fetchone()
+        self.assertEqual(row, ("failed", "youtube"))
+
+    def test_fastest_all_unmeasured_keeps_first_without_quarantine(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "a", "alive", delay=50, uses=0, last_check=now)
+        mark(conn, "b", "alive", delay=60, uses=0, last_check=now)
+        api = FakeAPI({"a": 50, "b": 60})
+        args = Args(cmd="fastest", db=path, top=3)
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "multi_gate_cause", return_value=None
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_throughput", return_value=None
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_fastest(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "a"))
+        rows = conn.execute(
+            "SELECT status FROM nodes WHERE name IN ('a', 'b')"
+        ).fetchall()
+        self.assertEqual(rows, [("alive",), ("alive",)])
+
+    def test_rejects_bad_fastest_numbers(self):
+        for kw in (
+            {"cmd": "fastest", "top": 0},
+            {"cmd": "fastest", "speed_timeout_ms": 999},
+        ):
+            args = Args(**kw)
+            args.cmd = kw["cmd"]
+            self.assertIsNotNone(rr_balancer.validate_args(args), kw)
+
     def test_rotate_youtube_unknown_keeps_without_quarantine(self):
         conn, path = make_db()
         now = int(time.time())
```
<!-- END_GIT_DIFF -->
