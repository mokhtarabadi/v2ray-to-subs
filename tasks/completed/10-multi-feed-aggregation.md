# Task [10]: Multi-feed subscription aggregation

**File:** `tasks/qa/10-multi-feed-aggregation.md`
**Source:** manager
**Type:** feature
**Status:** open

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
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index a60c6af..d0bef15 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -13,6 +13,8 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 - Manual `next` subcommand + `~/.local/bin/rr` launcher (task 05 follow-up): bare `rr` auto-detects the currently active node via the controller, marks it failed, and rotates immediately.
 - Live dedup + freshness tuning (task 08): `refresh.sh` generates with `--unique-host` (live pool ~7230 → 3771); retest batch 250→500 with alive-first ordering; stale window 1h→2h; retest coverage ~14.5h → ~3.8h.
 - `--unique-host` converter flag (task 07, default off): parse-time dedup keeps only the first proxy per server host (case/whitespace normalized) and logs unique vs duplicate counts; both Clash and sing-box outputs consume the same filtered list.
+- Multi-feed aggregation (task 10): converter/`manager.sh`/`refresh.sh` accept N subscription URLs, merge into one pool, dedup across the merged set with per-feed + merged counts; ss cipher alias `chacha20-poly1305` normalized to `chacha20-ietf-poly1305`.
+- Balancer seed memory (task 10 follow-up): learned rows survive feed refreshes (only never-tested rows pruned); pool and retest batch exclude controller ghosts; auto-rotate timer disabled, manual `rr` owns switching.
 - Close stale connections on proxy switch (task 09): after every successful selection change the balancer closes connections still chained to the previous node (surgical per-id close, non-fatal); shared path covers manual (`rr`/`skip`) and timer (`rotate`) modes.
 
 ### Fixed
diff --git a/README.md b/README.md
index 8628e5e..4dc0c3a 100644
--- a/README.md
+++ b/README.md
@@ -160,9 +160,10 @@ sing-box check -c singbox_config.json
 Balancing is done by the external balancer (`scripts/rr_balancer.py` with
 SQLite state), not by mihomo groups — PROXY stays in `select` mode:
 
-- **Rotate**: least-used + fastest node every 30 minutes (`rr-rotate.timer`)
-- **Retest**: 500 oldest nodes every 30 minutes (`rr-retest.timer`), dead nodes readmitted on recovery
+- **Rotate**: manual only — bare `rr` skips the current node and picks least-used + fastest (`rr-rotate.timer` is intentionally disabled)
+- **Retest**: 500 oldest controller-present nodes every 30 minutes (`rr-retest.timer`), dead nodes readmitted on recovery
 - **Freshness**: nodes unchecked for over 2h sit out until rechecked
+- **Memory**: learned rows (alive/failed with delay, uses) survive feed refreshes; only never-tested rows are pruned; pool and retest batch exclude names gone from the controller
 - **Manual escape**: bare `rr` skips the current node immediately (`skip NAME` targets one)
 - **Subscription refresh**: OpenRay feed regenerated every 6h (`v2ray-to-subs-refresh.timer`)
 
@@ -186,6 +187,16 @@ https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Proto
 https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt
 ```
 
+Multiple feeds can be combined in one run — each is downloaded and
+counted separately, then merged and deduped as a single pool:
+
+```bash
+python proxy_converter.py \
+  "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt" \
+  "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt" \
+  --unique-host
+```
+
 ## manager.sh (easy use)
 
 The repo ships a `manager.sh` wrapper (same style as `~/Desktop/mihomo/manager.sh`).
@@ -196,6 +207,7 @@ It defaults to the Patterniha subscription above, loopback-only bindings, TUN of
 ./manager.sh generate --tun                            # + TUN inbound
 ./manager.sh generate --tun --allow-lan                # + LAN clients
 ./manager.sh tun "https://example.com/sub#MyProfile"   # TUN + custom sub
+./manager.sh generate "https://a.example/sub" "https://b.example/sub"  # merge feeds
 ./manager.sh clash | ./manager.sh singbox              # single output
 ./manager.sh check                                     # mihomo -t + sing-box check
 ./manager.sh deploy --tun                              # regenerate + install to ~/Desktop/mihomo
diff --git a/manager.sh b/manager.sh
index 674ea6a..b1e3a6f 100755
--- a/manager.sh
+++ b/manager.sh
@@ -38,9 +38,10 @@ find_singbox() {
   if command -v sing-box >/dev/null 2>&1; then command -v sing-box; else echo ""; fi
 }
 
-# generate [url] [--tun] [--allow-lan] [--only clash|singbox|both] [-v]
+# generate [url...] [--tun] [--allow-lan] [--only clash|singbox|both] [-v]
 do_generate() {
-  local url="$DEFAULT_URL" only="both" tun="" lan="" verbose=""
+  local only="both" tun="" lan="" verbose=""
+  local -a urls=()
   while [[ $# -gt 0 ]]; do
     case "$1" in
       --tun) tun="--tun"; shift ;;
@@ -50,18 +51,21 @@ do_generate() {
       -v|--verbose) verbose="-v"; shift ;;
       -h|--help) show_help; exit 0 ;;
       -*) warn "unknown flag ignored: $1"; shift ;;
-      *) url="$1"; shift ;;
+      *) urls+=("$1"); shift ;;
     esac
   done
+  if [[ ${#urls[@]} -eq 0 ]]; then
+    urls=("$DEFAULT_URL")
+  fi
   case "$only" in
     clash|singbox|both) ;;
     *) err "bad --only value: $only (want clash|singbox|both)"; exit 1 ;;
   esac
 
-  info "source: $url"
+  info "sources: ${urls[*]}"
   info "outputs: $only | tun: ${tun:-off} | lan: ${lan:-off}"
   # shellcheck disable=SC2086
-  "$(pick_python)" "$CONVERTER" "$url" \
+  "$(pick_python)" "$CONVERTER" "${urls[@]}" \
     --clash-out "$CLASH_OUT" --singbox-out "$SB_OUT" \
     --only "$only" $tun $lan $verbose
   ok "generated: $CLASH_OUT + $SB_OUT (as selected)"
@@ -115,7 +119,7 @@ Default subscription: $DEFAULT_URL
 Usage: $(basename "$0") <command> [url] [flags]
 
 Commands:
-  generate [url] [--tun] [--allow-lan] [--only clash|singbox|both] [-v]
+  generate [url...] [--tun] [--allow-lan] [--only clash|singbox|both] [-v]
       Regenerate configs (defaults: Patterniha URL, TUN off, loopback-only)
   clash [url] [flags]     Same as generate --only clash
   singbox [url] [flags]   Same as generate --only singbox
@@ -128,6 +132,7 @@ Examples:
   ./manager.sh generate
   ./manager.sh generate --tun
   ./manager.sh tun "https://example.com/sub#MyProfile"
+  ./manager.sh generate "https://a.example/sub" "https://b.example/sub"  # merge feeds
   ./manager.sh clash --only clash
   ./manager.sh check
   ./manager.sh deploy --tun
diff --git a/proxy_converter.py b/proxy_converter.py
index 6edb91b..b4ca374 100644
--- a/proxy_converter.py
+++ b/proxy_converter.py
@@ -206,6 +206,22 @@ def _parse_bool(value: Optional[str]) -> bool:
     return str(value or "").strip().lower() in ("1", "true", "yes", "on")
 
 
+# Cipher names some feeds emit that mihomo/sing-box do not recognize,
+# mapped to their canonical equivalents.
+SS_METHOD_ALIASES = {
+    "chacha20-poly1305": "chacha20-ietf-poly1305",
+}
+
+
+def _normalize_ss_method(method: str) -> str:
+    """Map known ss cipher aliases to canonical mihomo-accepted names."""
+    key = (method or "").strip().lower()
+    if key in SS_METHOD_ALIASES:
+        logger.debug("ss cipher alias %r -> %r", method, SS_METHOD_ALIASES[key])
+        return SS_METHOD_ALIASES[key]
+    return method
+
+
 def _ws_early_data(
     path: Optional[str],
 ) -> Tuple[Optional[str], Optional[int], Optional[str]]:
@@ -384,6 +400,27 @@ class SubscriptionDownloader:
             raise
 
 
+def _dedup_by_host(
+    proxies: List[ProxyConfig],
+) -> Tuple[List[ProxyConfig], int]:
+    """Keep the first proxy per server host (case/whitespace normalized).
+
+    Shared by single-feed parse and multi-feed merge so both paths apply
+    identical first-wins semantics. Returns (unique, duplicate_count).
+    """
+    seen: set = set()
+    unique: List[ProxyConfig] = []
+    dups = 0
+    for proxy in proxies:
+        key = (proxy.server or "").strip().lower()
+        if key in seen:
+            dups += 1
+            continue
+        seen.add(key)
+        unique.append(proxy)
+    return unique, dups
+
+
 class ProxyParser:
     """Parses share-link formats (v2rayNG / v2rayN / Xray conventions)."""
 
@@ -670,7 +707,7 @@ class ProxyParser:
             server=server,
             port=port,
             protocol="shadowsocks",
-            method=urllib.parse.unquote(method),
+            method=_normalize_ss_method(urllib.parse.unquote(method)),
             password=urllib.parse.unquote(password),
             plugin=plugin,
             plugin_opts=plugin_opts,
@@ -1926,6 +1963,7 @@ def _parse_plugin_opts(opts: str) -> Dict[str, Any]:
 
 def run(
     url: str = DEFAULT_SUBSCRIPTION_URL,
+    urls: Optional[List[str]] = None,
     clash_out: str = "clash_config.yaml",
     singbox_out: str = "singbox_config.json",
     outputs: str = "both",
@@ -1934,22 +1972,70 @@ def run(
     controller_secret: str = "",
     unique_host: bool = False,
 ) -> int:
+    if urls is None:
+        urls = [url]
+    elif isinstance(urls, str):
+        urls = [urls]
+    if not urls:
+        urls = [DEFAULT_SUBSCRIPTION_URL]
+
     downloader = SubscriptionDownloader()
-    content = downloader.download_subscription(url)
-    title = downloader.last_title
-    logger.info("Subscription title: %s", title or "(none)")
-
-    parser = ProxyParser(unique_host=unique_host)
-    proxies = parser.parse_subscription_content(content)
-    if not proxies:
-        logger.error("No proxies parsed from subscription")
+    feed_contents: List[Tuple[str, str]] = []
+    for feed_url in urls:
+        try:
+            feed_contents.append((feed_url, downloader.download_subscription(feed_url)))
+        except Exception as exc:
+            logger.warning("Skipping failed feed %s: %s", feed_url, exc)
+    if not feed_contents:
+        logger.error("No subscriptions could be downloaded")
         return 1
-    if unique_host:
-        logger.info(
-            "Unique-host dedup: %d unique, %d host duplicates skipped",
-            len(proxies),
-            parser.host_dup,
-        )
+
+    if len(feed_contents) == 1:
+        # Legacy single-feed path: behavior and logs byte-identical.
+        url, content = feed_contents[0]
+        title = downloader.last_title
+        logger.info("Subscription title: %s", title or "(none)")
+
+        parser = ProxyParser(unique_host=unique_host)
+        proxies = parser.parse_subscription_content(content)
+        if not proxies:
+            logger.error("No proxies parsed from subscription")
+            return 1
+        if unique_host:
+            logger.info(
+                "Unique-host dedup: %d unique, %d host duplicates skipped",
+                len(proxies),
+                parser.host_dup,
+            )
+    else:
+        # Multi-feed path: parse per feed for counts, then aggregate and
+        # dedup over the merged pool (never per-feed).
+        per_feed: List[Tuple[str, int, int]] = []
+        merged: List[ProxyConfig] = []
+        for feed_url, content in feed_contents:
+            feed_parser = ProxyParser(unique_host=False)
+            parsed = feed_parser.parse_subscription_content(content)
+            per_feed.append((feed_url, len(content), len(parsed)))
+            merged.extend(parsed)
+        for feed_url, nbytes, nparsed in per_feed:
+            logger.info("Feed %s: %d bytes, %d parsed", feed_url, nbytes, nparsed)
+        proxies = merged
+        if unique_host:
+            proxies, host_dup = _dedup_by_host(merged)
+            logger.info(
+                "Unique-host dedup over merged pool: %d unique, "
+                "%d host duplicates skipped",
+                len(proxies),
+                host_dup,
+            )
+        else:
+            logger.info("Merged %d feeds: %d proxies", len(feed_contents), len(proxies))
+        if not proxies:
+            logger.error("No proxies parsed from subscriptions")
+            return 1
+        title = downloader.last_title
+        logger.info("Subscription title: %s", title or "(none)")
+        url = feed_contents[0][0]
 
     generator = ConfigGenerator(
         tun_enabled=tun_enabled,
@@ -2000,10 +2086,10 @@ def main() -> None:
         description="Parse V2Ray subscription links into Clash (mihomo) / sing-box configs"
     )
     ap.add_argument(
-        "url",
-        nargs="?",
-        default=DEFAULT_SUBSCRIPTION_URL,
-        help="Subscription URL (fragment #Name becomes profile title)",
+        "urls",
+        nargs="*",
+        default=[DEFAULT_SUBSCRIPTION_URL],
+        help="Subscription URL(s) (fragment #Name becomes profile title)",
     )
     ap.add_argument("--clash-out", default="clash_config.yaml")
     ap.add_argument("--singbox-out", default="singbox_config.json")
@@ -2042,7 +2128,7 @@ def main() -> None:
 
     raise SystemExit(
         run(
-            url=args.url,
+            urls=args.urls,
             clash_out=args.clash_out,
             singbox_out=args.singbox_out,
             outputs=args.only,
diff --git a/refresh.sh b/refresh.sh
index b82e6cd..827cfed 100755
--- a/refresh.sh
+++ b/refresh.sh
@@ -16,21 +16,22 @@ trap cleanup EXIT
 # Controller secret lives in a chmod-600 file, never in git.
 export MIHOMO_CONTROLLER_SECRET="$(cat "$CONF_DIR/.controller_secret")"
 
-# Subscription source: $1 or $SUB_URL wins, else converter default.
-# Lets the systemd unit pin a custom sub without editing code.
-SUB_URL="${1:-${SUB_URL:-}}"
-if [ -n "$SUB_URL" ]; then
-  echo "[refresh] source: $SUB_URL"
+# Subscription sources: all positional args win, else $SUB_URL, else converter default.
+# Lets the systemd unit pin one or several subs without editing code.
+URLS=()
+if [[ $# -gt 0 ]]; then
+  URLS=("$@")
+elif [ -n "${SUB_URL:-}" ]; then
+  URLS=("$SUB_URL")
+fi
+if [[ ${#URLS[@]} -gt 0 ]]; then
+  echo "[refresh] sources: ${URLS[*]}"
 else
   echo "[refresh] source: converter default"
 fi
 
 echo "[refresh] generating to $TMP ..."
-if [ -n "$SUB_URL" ]; then
-  "$PY" "$CONVERTER" "$SUB_URL" --only clash --clash-out "$TMP" --unique-host
-else
-  "$PY" "$CONVERTER" --only clash --clash-out "$TMP" --unique-host
-fi
+"$PY" "$CONVERTER" "${URLS[@]}" --only clash --clash-out "$TMP" --unique-host
 
 echo "[refresh] validating with mihomo -t ..."
 mihomo -t -f "$TMP"
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index 5d364de..19544af 100755
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -26,7 +26,7 @@ import time
 import urllib.parse
 import urllib.request
 from concurrent.futures import ThreadPoolExecutor
-from typing import Any, Dict, List, Optional, Tuple
+from typing import Any, Collection, Dict, List, Optional, Tuple
 
 REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
 SCHEMA_PATH = os.path.join(REPO_ROOT, "data", "balancer_state.schema.sql")
@@ -180,7 +180,13 @@ def connect_db(db_path: str) -> sqlite3.Connection:
 
 
 def seed_names(conn: sqlite3.Connection, names: List[str]) -> Tuple[int, int]:
-    """Insert unknown names; prune names gone from the controller."""
+    """Insert unknown names; prune only unknowns gone from the controller.
+
+    Learned rows (alive/failed with delay, uses, fails) survive feed
+    refreshes so rotation keeps working across config regenerations;
+    recurring names resume with their stats intact. Unknown rows carry
+    no knowledge, so dropping them is free and bounds table growth.
+    """
     cur = conn.cursor()
     cur.execute("SELECT name FROM nodes")
     known = {row[0] for row in cur.fetchall()}
@@ -189,25 +195,42 @@ def seed_names(conn: sqlite3.Connection, names: List[str]) -> Tuple[int, int]:
         if name not in known:
             cur.execute("INSERT INTO nodes (name) VALUES (?)", (name,))
             added += 1
-    cur.execute(
-        "DELETE FROM nodes WHERE name NOT IN (%s)" % ",".join("?" * len(names)),
-        names,
-    ) if names else None
-    pruned = cur.rowcount if names else 0
+    pruned = 0
+    if names:
+        cur.execute(
+            "DELETE FROM nodes WHERE status = 'unknown' AND name NOT IN (%s)"
+            % ",".join("?" * len(names)),
+            names,
+        )
+        pruned = cur.rowcount
     conn.commit()
     return added, pruned
 
 
 def alive_pool(
-    conn: sqlite3.Connection, now: int, stale_after: int
+    conn: sqlite3.Connection,
+    now: int,
+    stale_after: int,
+    allowed: Optional[Collection[str]] = None,
 ) -> List[Tuple[str, int, int]]:
-    """Alive AND freshly checked nodes as (name, uses, delay_ms)."""
+    """Alive AND freshly checked nodes as (name, uses, delay_ms).
+
+    When allowed is given, only names present in the controller's current
+    member list are returned, so ghosts from older feeds are never picked.
+    """
     cur = conn.cursor()
-    cur.execute(
+    query = (
         "SELECT name, uses, COALESCE(delay_ms, 999999) FROM nodes "
-        "WHERE status = 'alive' AND (? - last_check) <= ?",
-        (now, stale_after),
+        "WHERE status = 'alive' AND (? - last_check) <= ?"
     )
+    params: List[Any] = [now, stale_after]
+    if allowed is not None:
+        allowed = list(allowed)
+        if not allowed:
+            return []
+        query += " AND name IN (%s)" % ",".join("?" * len(allowed))
+        params.extend(allowed)
+    cur.execute(query, params)
     return cur.fetchall()
 
 
@@ -223,7 +246,7 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
     conn = connect_db(args.db)
     pool_names, current = api.group_members(args.group)
     seed_names(conn, pool_names)
-    pool = alive_pool(conn, now, args.stale_after)
+    pool = alive_pool(conn, now, args.stale_after, allowed=set(pool_names))
     name = pick_next(pool)
     if name is None:
         conn.execute(
@@ -341,12 +364,16 @@ def cmd_retest(args: argparse.Namespace, api: ClashAPI) -> int:
     pool_names, _ = api.group_members(args.group)
     added, pruned = seed_names(conn, pool_names)
     cur = conn.cursor()
-    cur.execute(
-        "SELECT name FROM nodes ORDER BY (status = 'alive') DESC, "
-        "last_check ASC LIMIT ?",
-        (args.batch,),
-    )
-    batch = [row[0] for row in cur.fetchall()]
+    if not pool_names:
+        batch = []
+    else:
+        cur.execute(
+            "SELECT name FROM nodes WHERE name IN (%s) "
+            "ORDER BY (status = 'alive') DESC, last_check ASC LIMIT ?"
+            % ",".join("?" * len(pool_names)),
+            (*pool_names, args.batch),
+        )
+        batch = [row[0] for row in cur.fetchall()]
     if not batch:
         print("retest: no nodes to check")
         return 0
diff --git a/tests/test_proxy_converter.py b/tests/test_proxy_converter.py
new file mode 100644
index 0000000..add4f3f
--- /dev/null
+++ b/tests/test_proxy_converter.py
@@ -0,0 +1,111 @@
+"""Tests for multi-feed aggregation in proxy_converter.py.
+
+Offline only: feeds are file:// URLs, no network access.
+"""
+
+import base64
+import json
+import os
+import sys
+import tempfile
+import unittest
+
+sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
+
+import proxy_converter
+from proxy_converter import _dedup_by_host, run
+
+FEED_A = [
+    "vless://11111111-1111-4111-8111-111111111111@shared.example:443?encryption=none#n1",
+    "vless://22222222-2222-4222-8222-222222222222@solo-a.example:443?encryption=none#n2",
+]
+
+FEED_B = [
+    "trojan://pass@SHARED.EXAMPLE:443?sni=x.com#n3",
+    "vless://33333333-3333-4333-8333-333333333333@solo-b.example:443?encryption=none#n4",
+]
+
+
+def write_feed(lines):
+    fd, path = tempfile.mkstemp(suffix=".txt")
+    with os.fdopen(fd, "w", encoding="utf-8") as fh:
+        fh.write("\n".join(lines) + "\n")
+    return "file://" + path
+
+
+class DedupHelperTest(unittest.TestCase):
+    def test_first_wins_case_insensitive(self):
+        parsed = proxy_converter.ProxyParser().parse_subscription_content(
+            "\n".join(FEED_A + FEED_B)
+        )
+        unique, dups = _dedup_by_host(parsed)
+        self.assertEqual(len(unique), 3)
+        self.assertEqual(dups, 1)
+        self.assertEqual(unique[0].name, "n1")
+
+
+class MultiFeedRunTest(unittest.TestCase):
+    def _run(self, **kw):
+        tmp = tempfile.mkdtemp()
+        clash = os.path.join(tmp, "c.yaml")
+        singbox = os.path.join(tmp, "s.json")
+        rc = run(
+            clash_out=clash,
+            singbox_out=singbox,
+            outputs="both",
+            **kw,
+        )
+        return rc, clash, singbox
+
+    def test_cross_feed_dedup(self):
+        url_a = write_feed(FEED_A)
+        url_b = write_feed(FEED_B)
+        rc, clash, _ = self._run(urls=[url_a, url_b], unique_host=True)
+        self.assertEqual(rc, 0)
+        import yaml
+
+        proxies = yaml.safe_load(open(clash, encoding="utf-8"))["proxies"]
+        hosts = sorted(p["server"] for p in proxies)
+        self.assertEqual(hosts, ["shared.example", "solo-a.example", "solo-b.example"])
+
+    def test_per_feed_counts_logged(self):
+        url_a = write_feed(FEED_A)
+        url_b = write_feed(FEED_B)
+        with self.assertLogs(proxy_converter.logger, level="INFO") as logs:
+            rc, _, _ = self._run(urls=[url_a, url_b], unique_host=True)
+        self.assertEqual(rc, 0)
+        out = "\n".join(logs.output)
+        self.assertIn("Feed", out)
+        self.assertIn(
+            "Unique-host dedup over merged pool: 3 unique, 1 host duplicates skipped",
+            out,
+        )
+
+    def test_single_url_identity(self):
+        url_a = write_feed(FEED_A + FEED_B)
+        _, clash_old, singbox_old = self._run(url=url_a)
+        _, clash_old, singbox_old = self._run(url=url_a)
+        _, clash_new, singbox_new = self._run(urls=[url_a])
+        with open(clash_old, encoding="utf-8") as fh:
+            old_yaml = fh.read()
+        with open(clash_new, encoding="utf-8") as fh:
+            new_yaml = fh.read()
+        self.assertEqual(old_yaml, new_yaml)
+        with open(singbox_old, encoding="utf-8") as fh:
+            old_json = json.load(fh)
+        with open(singbox_new, encoding="utf-8") as fh:
+            new_json = json.load(fh)
+        self.assertEqual(old_json, new_json)
+
+    def test_ss_cipher_alias_normalized(self):
+        link = (
+            "ss://"
+            + base64.urlsafe_b64encode(b"chacha20-poly1305:x").decode().rstrip("=")
+            + "@h.example:1#n"
+        )
+        proxy = proxy_converter.ProxyParser().parse_shadowsocks(link)
+        self.assertEqual(proxy.method, "chacha20-ietf-poly1305")
+
+
+if __name__ == "__main__":
+    unittest.main()
diff --git a/tests/test_rr_balancer.py b/tests/test_rr_balancer.py
index 3334623..8d23413 100644
--- a/tests/test_rr_balancer.py
+++ b/tests/test_rr_balancer.py
@@ -92,7 +92,7 @@ class RotateTest(unittest.TestCase):
         mark(conn, "slow", "alive", delay=900, uses=0, last_check=now)
         mark(conn, "fast", "alive", delay=120, uses=0, last_check=now)
         mark(conn, "used", "alive", delay=50, uses=5, last_check=now)
-        api = FakeAPI({})
+        api = FakeAPI({"slow": 900, "fast": 120, "used": 50})
         args = Args(db=path)
         self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
         # fast wins the 0-use tie over slow despite used being quicker
@@ -105,7 +105,7 @@ class RotateTest(unittest.TestCase):
         now = int(time.time())
         mark(conn, "a", "alive", delay=100, uses=0, last_check=now)
         mark(conn, "b", "alive", delay=200, uses=0, last_check=now)
-        api = FakeAPI({})
+        api = FakeAPI({"a": 100, "b": 200})
         args = Args(db=path)
         rr_balancer.cmd_rotate(args, api)
         rr_balancer.cmd_rotate(args, api)
@@ -315,5 +315,59 @@ class CloseStaleTest(unittest.TestCase):
         conn.close()
 
 
+class SeedMemoryTest(unittest.TestCase):
+    def test_reseed_keeps_learned_rows(self):
+        conn, path = make_db()
+        mark(conn, "a1", "alive", delay=10, uses=5)
+        mark(conn, "u1", "unknown")
+        rr_balancer.seed_names(conn, ["u1", "new1"])
+        row = conn.execute(
+            "SELECT status, uses, delay_ms FROM nodes WHERE name='a1'"
+        ).fetchone()
+        self.assertEqual(row, ("alive", 5, 10))
+        self.assertIsNotNone(
+            conn.execute("SELECT 1 FROM nodes WHERE name='new1'").fetchone()
+        )
+        conn.close()
+
+    def test_unknown_absent_rows_pruned(self):
+        conn, path = make_db()
+        mark(conn, "u2", "unknown")
+        mark(conn, "u1", "unknown")
+        rr_balancer.seed_names(conn, ["u1"])
+        self.assertIsNone(
+            conn.execute("SELECT 1 FROM nodes WHERE name='u2'").fetchone()
+        )
+        self.assertIsNotNone(
+            conn.execute("SELECT 1 FROM nodes WHERE name='u1'").fetchone()
+        )
+        conn.close()
+
+    def test_alive_pool_excludes_controller_ghosts(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "ghost", "alive", delay=5, uses=0, last_check=now)
+        mark(conn, "real", "alive", delay=50, uses=0, last_check=now)
+        pool = rr_balancer.alive_pool(conn, now, 3600, allowed={"real", "other"})
+        self.assertEqual([n for n, _, _ in pool], ["real"])
+        conn.close()
+
+    def test_retest_batch_skips_ghosts(self):
+        conn, path = make_db()
+        api = FakeAPI({"n1": 10})
+        api.group_members = lambda group: (["n1"], "old-node")
+        mark(conn, "ghost", "alive", delay=5, uses=0, last_check=100)
+        mark(conn, "n1", "unknown", last_check=100)
+        conn.close()
+        rc = rr_balancer.cmd_retest(Args(cmd="retest", db=path, batch=10), api)
+        self.assertEqual(rc, 0)
+        conn = sqlite3.connect(path)
+        ghost_check = conn.execute(
+            "SELECT last_check FROM nodes WHERE name='ghost'"
+        ).fetchone()[0]
+        self.assertEqual(ghost_check, 100)
+        conn.close()
+
+
 if __name__ == "__main__":
     unittest.main()
```
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
