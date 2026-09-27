# Task [07]: Unique host/IP dedup option for conversion

**File:** `tasks/qa/07-dedup-by-host.md`
**Source:** manager
**Type:** feature
**Status:** open

## Goal

Add a CLI argument to the converter so that, when enabled, subscription parsing registers each server host/IP only once — duplicates never reach the generated service configs — and the run reports duplicate vs unique counts.

## Manager's Notes

Manager request (Persian, paraphrased): many OpenRay subscription proxies are duplicates by host/IP (credentials may differ, but host/IP is the same); since unique IP matters, dedup fires. Add a new argument to the converter: when the unique-host/unique-IP option is active, parsing must never register a duplicate host or domain (the parser knows the host/IP at parse time). Output must report how many duplicates vs how many unique came out. Our own service generation must never contain duplicates when it generates a new file. Manager order: create the task and run the autopilot stages including Brain QA and Brain reviewer.

## Local TODOs

- [x] Add unique-host CLI argument to `proxy_converter.py` (off by default)
- [x] Dedup parsed proxies by server host at parse time when enabled
- [x] Log duplicate vs unique counts on every run
- [x] Verify generated configs contain no duplicate hosts
- [x] Verify balancer rotation wraps to the start after the last alive node (folded in per manager order: usage-ordered pick re-covers from min-uses; confirm + fix here if broken)
- [ ] Run bridge-QA and bridge-review

## Acceptance Criteria

- [x] New argument exists, off by default, documented in help text
- [x] With the flag on, no server host appears twice in generated outputs
- [x] Run output reports duplicate count and unique count
- [x] Default behavior (flag off) unchanged

## Verification Evidence

- **Test command:** synthetic 4-node feed through ProxyParser (shared host across vless/vless/trojan + mixed case), flag off then on
- **Expected result:** off=4 proxies (parity), on=2 unique (n1 + other) with host_dup=2
- **Actual result:** off=4, on=2 unique + 2 host duplicates skipped
- **Exit code:** 0

- **Test command:** end-to-end run() on file:// feed with unique_host=True (clash + singbox outputs)
- **Expected result:** rc=0, both outputs shrink equally, no host twice
- **Actual result:** rc=0, clash 2 proxies + sing-box 2 proxy outbounds
- **Exit code:** 0

- **Test command:** balancer suite (wrap-around regression) + py_compile + --help
- **Expected result:** 15 tests OK, compile clean, flag documented
- **Actual result:** 15 tests OK, py_compile exit 0, --unique-host in --help
- **Exit code:** 0

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** distinct nodes sharing a host (different ports/credentials) get dropped when the flag is on
- **Rollback plan:** flag defaults off; rerun without it restores full output

---

## Execution Log & Reasoning

- Autopilot locked for task 07 on manager order (Persian): task it, run autopilot incl. Brain QA + reviewer.
- Goal created (active). Memory bootstrap: no namespaces. Decision sync: personal repo dirty, push is manager-owned. Autopilot norms replayed from stored rulings (drive end-to-end, no ferrying).
- Manager follow-up (Persian, paraphrased): continue; also verify rotation wraps from the last alive node back to the first, fixing inside this same task since it is small. Added as a TODO above (balancer-side check).
- Implementation (per approved Architect plan): `ProxyParser.__init__(unique_host=False)` + `host_dup` counter; `seen_hosts` check after server/port validation, normalized strip().lower() key, first wins; `run()` plumbs `unique_host` + logs "Unique-host dedup: %d unique, %d host duplicates skipped"; `main()` adds `--unique-host` store_true. Wrap check: balancer `pick_next` re-sorts by (uses, delay) every run — no end-of-list index exists, wrap-around inherent, no fix needed (balancer suite 15 tests OK confirms).
- Verification: synthetic 4-node feed off=4 (parity) / on=2 unique + 2 dups; end-to-end file:// run rc=0, clash 2 proxies + sing-box 2 outbounds (equal shrink); py_compile OK; --help shows flag.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 2e9a5a5..929260e 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -11,6 +11,7 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 - External round-robin balancer (task 04): `scripts/rr_balancer.py` rotates the PROXY `select` group across alive nodes (least-used, fastest-delay tiebreak, stale excluded) with per-node delay checks and SQLite state (`data/balancer_state.schema.sql`); `tests/test_rr_balancer.py` (7 tests); `systemd/rr-rotate` (5min) and `systemd/rr-retest` (30min, 250-node batches) user timers.
 - Manual `skip NAME` subcommand (task 05): marks a flagged node failed and immediately rotates to the next alive node, so a rate-limited exit can be escaped without waiting for the timer.
 - Manual `next` subcommand + `~/.local/bin/rr` launcher (task 05 follow-up): bare `rr` auto-detects the currently active node via the controller, marks it failed, and rotates immediately.
+- `--unique-host` converter flag (task 07, default off): parse-time dedup keeps only the first proxy per server host (case/whitespace normalized) and logs unique vs duplicate counts; both Clash and sing-box outputs consume the same filtered list.
 
 ### Fixed
 - Review hotfix: balancer clock seam, DB parent makedirs, group_members annotation, WAL sidecar ignores.
diff --git a/proxy_converter.py b/proxy_converter.py
index 45391a1..6edb91b 100644
--- a/proxy_converter.py
+++ b/proxy_converter.py
@@ -21,12 +21,12 @@ from typing import Any, Dict, List, Optional, Tuple
 
 import yaml
 
-logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
+logging.basicConfig(
+    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
+)
 logger = logging.getLogger(__name__)
 
-DEFAULT_SUBSCRIPTION_URL = (
-    "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt#Patterniha-F"
-)
+DEFAULT_SUBSCRIPTION_URL = "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt#Patterniha-F"
 
 # ---------------------------------------------------------------------------
 # Shared bypass policy.
@@ -206,7 +206,9 @@ def _parse_bool(value: Optional[str]) -> bool:
     return str(value or "").strip().lower() in ("1", "true", "yes", "on")
 
 
-def _ws_early_data(path: Optional[str]) -> Tuple[Optional[str], Optional[int], Optional[str]]:
+def _ws_early_data(
+    path: Optional[str],
+) -> Tuple[Optional[str], Optional[int], Optional[str]]:
     """Split WebSocket path early-data (?ed=) and early-data header (?eh=).
 
     Returns (clean_path, max_early_data, early_data_header_name).
@@ -385,6 +387,10 @@ class SubscriptionDownloader:
 class ProxyParser:
     """Parses share-link formats (v2rayNG / v2rayN / Xray conventions)."""
 
+    def __init__(self, unique_host: bool = False) -> None:
+        self.unique_host = unique_host
+        self.host_dup = 0
+
     SCHEMES = (
         "vmess://",
         "vless://",
@@ -426,7 +432,9 @@ class ProxyParser:
         return content
 
     @staticmethod
-    def _name_from(parsed: urllib.parse.ParseResult, default: str, params: Dict[str, List[str]]) -> str:
+    def _name_from(
+        parsed: urllib.parse.ParseResult, default: str, params: Dict[str, List[str]]
+    ) -> str:
         frag = _unquote(parsed.fragment)
         if frag:
             return frag
@@ -534,13 +542,15 @@ class ProxyParser:
             host=str(data.get("host") or "") or None,
             path=str(data.get("path") or "") or None,
             service_name=str(data.get("path") or "") or None if net == "grpc" else None,
-            security="tls" if str(data.get("tls") or "").lower().endswith("tls") else (
-                "reality" if str(data.get("tls") or "").lower() == "reality" else ""
-            ),
+            security="tls"
+            if str(data.get("tls") or "").lower().endswith("tls")
+            else ("reality" if str(data.get("tls") or "").lower() == "reality" else ""),
             sni=str(data.get("sni") or "") or None,
             alpn=str(data.get("alpn") or "") or None,
             fp=str(data.get("fp") or "") or None,
-            insecure=_parse_bool(str(data.get("insecure") or data.get("allowInsecure") or "")),
+            insecure=_parse_bool(
+                str(data.get("insecure") or data.get("allowInsecure") or "")
+            ),
             pbk=str(data.get("pbk") or "") or None,
             sid=str(data.get("sid") or "") or None,
         )
@@ -580,8 +590,10 @@ class ProxyParser:
         ProxyParser._apply_common(cfg, params)
         security = (params.get("security") or ["tls"])[0].lower()
         if security in ("tls", "reality", "xtls", "none"):
-            cfg.security = "none" if security == "none" else (
-                "reality" if security == "reality" else "tls"
+            cfg.security = (
+                "none"
+                if security == "none"
+                else ("reality" if security == "reality" else "tls")
             )
         return cfg
 
@@ -756,7 +768,9 @@ class ProxyParser:
             vals = params.get(key)
             return _unquote(vals[0]) if vals else None
 
-        cfg.congestion_control = get("congestion_control") or get("congestion-control") or "cubic"
+        cfg.congestion_control = (
+            get("congestion_control") or get("congestion-control") or "cubic"
+        )
         cfg.udp_relay_mode = get("udp_relay_mode") or get("udp-relay-mode") or "native"
         cfg.heartbeat = get("heartbeat") or get("heartbeat-interval")
         if not cfg.password and get("password"):
@@ -805,6 +819,8 @@ class ProxyParser:
         content = self.decode_base64_content(content)
         proxies: List[ProxyConfig] = []
         seen_raw: set = set()
+        seen_hosts: set = set()
+        self.host_dup = 0
 
         for raw_line in content.splitlines():
             line = raw_line.strip().strip("\r").strip()
@@ -839,6 +855,12 @@ class ProxyParser:
                 if proxy and proxy.server and proxy.port:
                     if not proxy.name:
                         proxy.name = f"{proxy.protocol}-{len(proxies)}"
+                    if self.unique_host:
+                        key = proxy.server.strip().lower()
+                        if key in seen_hosts:
+                            self.host_dup += 1
+                            continue
+                        seen_hosts.add(key)
                     proxies.append(proxy)
             except Exception as exc:
                 logger.error("Failed to parse proxy line: %s (%s)", exc, line[:80])
@@ -1000,7 +1022,9 @@ class ConfigGenerator:
             return out
 
         if network in ("kcp", "mkcp", "quic"):
-            logger.debug("Transport %s not supported by mihomo export; using tcp", network)
+            logger.debug(
+                "Transport %s not supported by mihomo export; using tcp", network
+            )
             return out
 
         # tcp / default: omit network key
@@ -1219,7 +1243,9 @@ class ConfigGenerator:
                 ]
             )
         else:
-            proxy_groups.append({"name": "PROXY", "type": "select", "proxies": ["DIRECT"]})
+            proxy_groups.append(
+                {"name": "PROXY", "type": "select", "proxies": ["DIRECT"]}
+            )
 
         rules = self._clash_rules()
 
@@ -1560,7 +1586,9 @@ class ConfigGenerator:
             return None
         return None
 
-    def _singbox_outbound(self, proxy: ProxyConfig, tag: str) -> Optional[Dict[str, Any]]:
+    def _singbox_outbound(
+        self, proxy: ProxyConfig, tag: str
+    ) -> Optional[Dict[str, Any]]:
         outbound: Dict[str, Any] = {
             "tag": tag,
             "server": proxy.server,
@@ -1575,7 +1603,9 @@ class ConfigGenerator:
             if proxy.packet_encoding:
                 pe = proxy.packet_encoding.lower()
                 if pe in ("xudp", "packetaddr", "packet"):
-                    outbound["packet_encoding"] = "xudp" if pe == "xudp" else "packetaddr"
+                    outbound["packet_encoding"] = (
+                        "xudp" if pe == "xudp" else "packetaddr"
+                    )
         elif isinstance(proxy, VLESSConfig):
             outbound["type"] = "vless"
             outbound["uuid"] = proxy.uuid
@@ -1601,12 +1631,18 @@ class ConfigGenerator:
         elif isinstance(proxy, Hysteria2Config):
             outbound["type"] = "hysteria2"
             outbound["password"] = proxy.password
-            tls = self._singbox_tls(proxy) or {"enabled": True, "server_name": proxy.sni or proxy.server}
+            tls = self._singbox_tls(proxy) or {
+                "enabled": True,
+                "server_name": proxy.sni or proxy.server,
+            }
             if proxy.insecure:
                 tls["insecure"] = True
             outbound["tls"] = tls
             if proxy.obfs:
-                outbound["obfs"] = {"type": proxy.obfs, "password": proxy.obfs_password or ""}
+                outbound["obfs"] = {
+                    "type": proxy.obfs,
+                    "password": proxy.obfs_password or "",
+                }
             if proxy.up:
                 outbound["up_mbps"] = _mbps(proxy.up)
             if proxy.down:
@@ -1624,7 +1660,10 @@ class ConfigGenerator:
                     outbound["auth_str"] = proxy.auth
             outbound["up_mbps"] = _mbps(proxy.up) or 100
             outbound["down_mbps"] = _mbps(proxy.down) or 100
-            tls = self._singbox_tls(proxy) or {"enabled": True, "server_name": proxy.sni or proxy.server}
+            tls = self._singbox_tls(proxy) or {
+                "enabled": True,
+                "server_name": proxy.sni or proxy.server,
+            }
             if proxy.insecure:
                 tls["insecure"] = True
             if proxy.obfs:
@@ -1642,7 +1681,10 @@ class ConfigGenerator:
                 outbound["password"] = proxy.password
             outbound["congestion_control"] = proxy.congestion_control
             outbound["udp_relay_mode"] = proxy.udp_relay_mode
-            tls = self._singbox_tls(proxy) or {"enabled": True, "server_name": proxy.sni or proxy.server}
+            tls = self._singbox_tls(proxy) or {
+                "enabled": True,
+                "server_name": proxy.sni or proxy.server,
+            }
             if proxy.insecure:
                 tls["insecure"] = True
             alpn = _split_alpn(proxy.alpn)
@@ -1890,17 +1932,24 @@ def run(
     tun_enabled: bool = False,
     allow_lan: bool = False,
     controller_secret: str = "",
+    unique_host: bool = False,
 ) -> int:
     downloader = SubscriptionDownloader()
     content = downloader.download_subscription(url)
     title = downloader.last_title
     logger.info("Subscription title: %s", title or "(none)")
 
-    parser = ProxyParser()
+    parser = ProxyParser(unique_host=unique_host)
     proxies = parser.parse_subscription_content(content)
     if not proxies:
         logger.error("No proxies parsed from subscription")
         return 1
+    if unique_host:
+        logger.info(
+            "Unique-host dedup: %d unique, %d host duplicates skipped",
+            len(proxies),
+            parser.host_dup,
+        )
 
     generator = ConfigGenerator(
         tun_enabled=tun_enabled,
@@ -1980,6 +2029,12 @@ def main() -> None:
         help="mihomo external-controller secret (or set MIHOMO_CONTROLLER_SECRET env). Empty = no auth (default).",
     )
     ap.add_argument("-v", "--verbose", action="store_true")
+    ap.add_argument(
+        "--unique-host",
+        action="store_true",
+        default=False,
+        help="Keep only the first proxy per server host.",
+    )
     args = ap.parse_args()
 
     if args.verbose:
@@ -1994,6 +2049,7 @@ def main() -> None:
             tun_enabled=args.tun,
             allow_lan=args.allow_lan,
             controller_secret=args.controller_secret,
+            unique_host=args.unique_host,
         )
     )
```
<!-- END_GIT_DIFF -->
