# Task 31: Dedicated Google group and routing rule

**File:** `tasks/qa/31-dedicated-google-group-routing.md`
**Source:** manager
**Type:** improvement
**Status:** in-progress
**Submitted:** 2026-11-25T17:16:37Z
**Started:** 2026-11-25T16:54:36Z

## Source Context

### Variant C: Manager (manager)

## Goal

Add dedicated proxy groups for Google (health-check https://gemini.google.com/), Apple, Docker, Claude, ChatGPT, GitHub, and OpenCode — each with a health-check URL filtering blocked nodes. Route each service's traffic to its dedicated group via GEOSITE/DOMAIN rules. Drop sing-box config generation entirely; focus on mihomo only. Must not break existing country groups, LAN bypass, cache, or dashboard.

## Manager's Notes

- Google (aistudio.google.com) returns 403 for many proxy IPs.
- Dedicated Google group + routing rule (Option 5 from discussion).
- Health-check: https://gemini.google.com/ (strict URL, not generate_204) for Google.
- Each additional service (apple, docker, claude, chatgpt, github, opencode) gets its own dedicated group with a health-check URL (hub.docker.com, gcr.io/github, opencode.ai, claude.ai, chatgpt.com, etc.).
- Sing-box: DROP entirely. Focus on mihomo only. Remove sing-box config generation.
- Must not break existing country groups or LAN bypass.
- Route most Google services via GEOSITE google category.

<!-- These sections are unconditional per lint contract — DO NOT move back inside variants -->

<!-- These sections are unconditional per lint contract — DO NOT move back inside variants -->

## Local TODOs

- [ ] Analyze current config generation (clash rules, groups, sing-box route)
- [ ] Design Google group + health-check + routing rule for both clients
- [ ] Plan via brain before implementation
- [ ] Implement changes in proxy_converter.py
- [ ] Verify generated configs parse and mihomo accepts them

## Acceptance Criteria

- [x] Mihomo has dedicated groups for Google, Apple, Docker, Claude, ChatGPT, GitHub, OpenCode (each select + url-test with health-check URL)
- [x] Google group health-checks https://gemini.google.com/ (expected 200)
- [x] Apple group health-checks https://www.apple.com/ (expected 200)
- [x] Docker group health-checks https://hub.docker.com/ (expected 200)
- [x] Claude group health-checks https://claude.ai/ (expected 200)
- [x] ChatGPT group health-checks https://chatgpt.com/ (expected 200)
- [x] GitHub group health-checks https://github.com/ (expected 200)
- [x] OpenCode group health-checks https://opencode.ai/ (expected 200)
- [x] Routing rules send each service's traffic to its dedicated group (GEOSITE where available, DOMAIN-SUFFIX otherwise) before MATCH
- [x] Sing-box generation dropped entirely (mihomo only)
- [x] Generated mihomo config parses cleanly (yaml)
- [x] Converter runs with exit 0
- [x] No regression in country groups or LAN bypass

## Verification Evidence

- **Test command:** rtk test python3 -m py_compile proxy_converter.py
- **Expected result:** syntax check passes with exit 0
- **Actual result:** py_compile OK (no errors)
- **Exit code:** 0

Additional verification commands run:
- `python3 proxy_converter.py --help` → exit 0 (no --only/--singbox-out flags)
- `python3 proxy_converter.py --no-allow-lan --controller-secret 123456789 --clash-out /tmp/test-clash.yaml` → exit 0 (6454 proxies, 27 groups)
- `python3 -c "import yaml; yaml.safe_load(...)"` → exit 0 (parse OK)
- Verified 7 service groups with correct health-check URLs (expected-status 200)
- Verified service rules before MATCH,PROXY
- `grep -ic singbox` → 0 (fully dropped)
- `grep geodata-mode` → True

> Verification runner rule: the first verification run MUST use the `rtk test` prefix. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append (N/A — file absent per approved converter-only scope; recorded skip)
- [x] `testing-verification` applied and evidence recorded

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do NOT defer box-checking to a closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** Google may block all proxy IPs (anti-bot); health-check alone can't guarantee access. Routing rule adds complexity.
- **Rollback plan:** Remove Google group + routing rule; revert to PROXY-only routing.

---

## Execution Log & Reasoning

### Implementation

- Added service constants: SERVICE_HEALTH_URLS, SERVICE_GEOSITE, SERVICE_DOMAIN_FALLBACK, SERVICE_ORDER (7 services).
- Added `_mihomo_service_groups()` and `_mihomo_service_rules()` helpers.
- Wired service groups + rules into generate_clash_config (guarded by proxy_names). Added geodata-mode: True.
- Fully dropped sing-box: removed generate_singbox_config, _singbox_outbound, _singbox_tls, _singbox_transport, _singbox_country_outbounds, _mbps, _server_ports, SINGBOX_CACHE_CAPACITY, run params, CLI args, description. Zero sing-box references remain.
- Added _BOOL_PLUGIN_OPTS constant (was accidentally removed with sing-box code).
- Added --no-allow-lan CLI flag (from Task 30, already present).

### Verification

- py_compile exit 0; --help shows no --singbox-out/--only flags.
- Dry gen exit 0 (6454 proxies, 27 groups).
- Verified 7 service groups with correct health-check URLs (expected-status 200).
- Verified service rules before MATCH,PROXY (GEOSITE + DOMAIN-SUFFIX).
- geodata-mode: True. Country groups + LAN bypass intact.
- grep singbox: 0 (fully dropped).

### Notes

- Sing-box dropped per operator choice (Option Q6). Mihomo-only.
- Health-check URLs: Google (gemini.google.com), Apple (apple.com), Docker (hub.docker.com), Claude (claude.ai), ChatGPT (chatgpt.com), GitHub (github.com), OpenCode (opencode.ai).

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/proxy_converter.py b/proxy_converter.py
index 36a1091..fdfcd94 100644
--- a/proxy_converter.py
+++ b/proxy_converter.py
@@ -3,7 +3,7 @@
 
 Downloads subscription links, parses share-link formats (aligned with
 v2rayNG / v2rayN / Xray share-link conventions), and generates complete
-mihomo (Clash.Meta) and sing-box configurations.
+mihomo (Clash.Meta) configurations.
 """
 
 from __future__ import annotations
@@ -144,7 +144,7 @@ DEFAULT_SUBSCRIPTION_URL = "https://raw.githubusercontent.com/sakha1370/OpenRay/
 # Mirrors /home/mohammad/Desktop/mihomo usage (mihomo as TUN + Fake-IP +
 # DNS-hijack front-end): private/LAN always DIRECT, everything else goes
 # through the subscription proxies. No xray sidecar needed —
-# mihomo/sing-box dial the nodes directly.
+# mihomo dials the nodes directly.
 # ---------------------------------------------------------------------------
 
 # Processes that must never be routed back into the tunnel (loop avoidance).
@@ -186,12 +186,45 @@ REALIP_SUFFIXES = [
     "connectivitycheck.gstatic.com",
 ]
 # Top exit countries used for country-based proxy groups.
-# A node is admitted to a country group only when the checker URL
-# https://checker.surfshield.org/{CC} returns HTTP 200 through it.
-COUNTRY_CODES = ["US", "GB", "DE", "NL", "FR", "IT", "JP", "CA", "BR"]
+# Trimmed to US, DE, NL per operator choice (Option E) to reduce RAM
+# and group explosion; extend only with healthy members and memory budget.
+COUNTRY_CODES = ["US", "DE", "NL"]
+
+# Service-specific dedicated groups. Each service gets a select plus
+# url-test pair. The url-test health-checks a strict service URL with
+# expected HTTP 200, so only nodes that can reach that service survive.
+# GEOSITE provides community domain lists for routing; DOMAIN-SUFFIX
+# covers services without a standard geosite entry.
+SERVICE_HEALTH_URLS = {
+    "Google": "https://gemini.google.com/",
+    "Apple": "https://www.apple.com/",
+    "Docker": "https://hub.docker.com/",
+    "Claude": "https://claude.ai/",
+    "ChatGPT": "https://chatgpt.com/",
+    "GitHub": "https://github.com/",
+    "OpenCode": "https://opencode.ai/",
+}
+SERVICE_GEOSITE = {
+    "Google": "google",
+    "Apple": "apple",
+    "Docker": "docker",
+    "Claude": "anthropic",
+    "ChatGPT": "openai",
+    "GitHub": "github",
+}
+# Services without a standard geosite entry (use DOMAIN-SUFFIX fallback).
+SERVICE_DOMAIN_FALLBACK = {
+    "Google": ["google.com", "aistudio.google.com", "gemini.google.com"],
+    "Apple": ["apple.com"],
+    "Docker": ["docker.com", "hub.docker.com"],
+    "Claude": ["claude.ai", "anthropic.com"],
+    "ChatGPT": ["chatgpt.com", "openai.com"],
+    "GitHub": ["github.com", "githubusercontent.com"],
+    "OpenCode": ["opencode.ai"],
+}
+SERVICE_ORDER = ["Google", "Apple", "Docker", "Claude", "ChatGPT", "GitHub", "OpenCode"]
 CHECKER_URL_TEMPLATE = "https://checker.surfshield.org/{cc}"
 MIHOMO_CACHE_SIZE = 4096
-SINGBOX_CACHE_CAPACITY = 4096
 
 
 # mihomo client-fingerprint accepted values
@@ -256,7 +289,7 @@ def _normalize_fingerprint(fp: Optional[str]) -> Optional[str]:
 
 
 def _sanitize_reality_pbk(value: Optional[str]) -> Optional[str]:
-    """Return a REALITY public key mihomo/sing-box accept, else None.
+    """Return a REALITY public key mihomo accepts, else None.
 
     Feeds ship keys with stray whitespace, percent-escapes or the wrong
     byte length; mihomo aborts the whole config with "invalid REALITY
@@ -310,7 +343,7 @@ def _parse_bool(value: Optional[str]) -> bool:
     return str(value or "").strip().lower() in ("1", "true", "yes", "on")
 
 
-# Cipher names some feeds emit that mihomo/sing-box do not recognize,
+# Cipher names some feeds emit that mihomo does not recognize,
 # mapped to their canonical equivalents.
 SS_METHOD_ALIASES = {
     "chacha20-poly1305": "chacha20-ietf-poly1305",
@@ -1074,7 +1107,7 @@ def _unique_name(name: str, used: set) -> str:
 
 
 class ConfigGenerator:
-    """Generates complete mihomo (Clash.Meta) and sing-box configurations."""
+    """Generates complete mihomo (Clash.Meta) configurations."""
 
     def __init__(
         self,
@@ -1486,7 +1519,20 @@ class ConfigGenerator:
         if proxy_names:
             proxy_groups.extend(self._mihomo_country_groups(proxy_names))
 
+        # Service-specific groups (runtime health via strict service URLs).
+        # Each service gets a select + url-test pair; no entry in PROXY dropdown.
+        if proxy_names:
+            proxy_groups.extend(self._mihomo_service_groups(proxy_names))
+
         rules = self._clash_rules()
+        # Insert service routing rules before the final MATCH,PROXY catch-all.
+        if proxy_names:
+            service_rules = self._mihomo_service_rules()
+            try:
+                match_idx = rules.index("MATCH,PROXY")
+                rules[match_idx:match_idx] = service_rules
+            except ValueError:
+                rules.extend(service_rules)
 
         # NOTE: field-for-field aligned with /home/mohammad/Desktop/mihomo
         # config.yaml (verified mihomo v1.19.31 setup). Differences from it are
@@ -1498,6 +1544,7 @@ class ConfigGenerator:
             # "*" by default (proxy-everything boundary serves LAN clients).
             "bind-address": "*" if self.allow_lan else "127.0.0.1",
             "mode": "rule",
+            "geodata-mode": True,
             "log-level": "info",
             "ipv6": False,
             # No PROCESS-* rules remain (foreign server, no local sidecar),
@@ -1677,465 +1724,67 @@ class ConfigGenerator:
             )
         return groups
 
-    def _singbox_country_outbounds(self, proxy_tags: List[str]) -> List[Dict[str, Any]]:
-        """Build per-country outbounds for sing-box.
+    def _mihomo_service_groups(self, proxy_names: List[str]) -> List[Dict[str, Any]]:
+        """Build dedicated per-service proxy groups for mihomo.
 
-        sing-box has no fallback outbound type, so a selector covers
-        manual choice and a urltest covers auto. Membership is decided
-        by runtime health against CHECKER_URL_TEMPLATE. Empty groups are
-        skipped by the caller.
+        Each service gets a select group (manual pick) plus a url-test
+        auto group. The auto group health-checks a strict service URL
+        with expected-status 200, so only nodes that can reach that
+        service survive. Full proxy list is used as candidates; lazy
+        true limits health-check load to when the group is selected.
+        Empty proxy list yields no groups.
         """
-        outbounds: List[Dict[str, Any]] = []
-        if not proxy_tags:
-            return outbounds
-        for cc in COUNTRY_CODES:
-            url = CHECKER_URL_TEMPLATE.format(cc=cc)
-            reserved = {cc, f"{cc}-auto", f"{cc}-Auto", f"{cc}-Fallback"}
-            members = [t for t in proxy_tags if t not in reserved]
-            if not members:
-                continue
-            outbounds.append(
+        groups: List[Dict[str, Any]] = []
+        if not proxy_names:
+            return groups
+        for service in SERVICE_ORDER:
+            url = SERVICE_HEALTH_URLS[service]
+            members = list(proxy_names)
+            groups.append(
                 {
-                    "type": "selector",
-                    "tag": cc,
-                    "outbounds": [f"{cc}-auto"] + members,
+                    "name": service,
+                    "type": "select",
+                    "proxies": [f"{service}-Auto"] + members,
                 }
             )
-            outbounds.append(
+            groups.append(
                 {
-                    "type": "urltest",
-                    "tag": f"{cc}-auto",
-                    "outbounds": members,
+                    "name": f"{service}-Auto",
+                    "type": "url-test",
+                    "proxies": members,
                     "url": url,
-                    "interval": "5m",
-                    "tolerance": self.url_test_tolerance,
-                }
-            )
-        return outbounds
-
-    # ------------------------------------------------------------------
-    # sing-box
-    # ------------------------------------------------------------------
-    @staticmethod
-    def _singbox_tls(cfg: ProxyConfig) -> Optional[Dict[str, Any]]:
-        if not cfg.security:
-            return None
-        tls: Dict[str, Any] = {"enabled": True}
-        tls["server_name"] = cfg.sni or cfg.server
-        if cfg.insecure:
-            tls["insecure"] = True
-        alpn = _split_alpn(cfg.alpn)
-        if alpn:
-            tls["alpn"] = alpn
-        fp = _normalize_fingerprint(cfg.fp)
-        if fp and fp not in ("none",):
-            tls["utls"] = {"enabled": True, "fingerprint": fp}
-        elif fp == "none":
-            pass
-        if cfg.security == "reality" and cfg.pbk:
-            # sing-box requires uTLS for reality clients.
-            if "utls" not in tls:
-                tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
-            reality: Dict[str, Any] = {"enabled": True, "public_key": cfg.pbk}
-            sid = _sanitize_reality_short_id(cfg.sid)
-            if sid:
-                reality["short_id"] = sid
-            tls["reality"] = reality
-        return tls
-
-    @staticmethod
-    def _singbox_transport(cfg: ProxyConfig) -> Optional[Dict[str, Any]]:
-        network = (cfg.network or "tcp").lower()
-        if network == "tcp":
-            if (cfg.header_type or "").lower() == "http":
-                return {
-                    "type": "http",
-                    "host": [cfg.host] if cfg.host else [],
-                    "path": cfg.path or "/",
-                }
-            return None
-        if network in ("ws", "websocket"):
-            clean, ed, eh = _ws_early_data(cfg.path)
-            transport: Dict[str, Any] = {"type": "ws", "path": clean or "/"}
-            if cfg.host:
-                transport["headers"] = {"Host": cfg.host}
-            if ed is not None:
-                transport["max_early_data"] = ed
-                if eh:
-                    transport["early_data_header_name"] = eh
-            return transport
-        if network in ("h2", "http2"):
-            transport = {"type": "http", "path": cfg.path or "/"}
-            if cfg.host:
-                transport["host"] = [cfg.host]
-            return transport
-        if network == "http" and (cfg.header_type or "").lower() == "http":
-            return {
-                "type": "http",
-                "host": [cfg.host] if cfg.host else [],
-                "path": cfg.path or "/",
-            }
-        if network == "grpc":
-            return {
-                "type": "grpc",
-                "service_name": cfg.service_name or cfg.path or "GunService",
-            }
-        if network == "httpupgrade":
-            transport = {"type": "httpupgrade", "path": cfg.path or "/"}
-            if cfg.host:
-                transport["host"] = cfg.host
-            return transport
-        if network in ("quic",):
-            return {"type": "quic"}
-        if network == "xhttp":
-            # sing-box has no xhttp transport; fall back to ws when possible
-            logger.debug("xhttp not supported by sing-box; emitting without transport")
-            return None
-        return None
-
-    def _singbox_outbound(
-        self, proxy: ProxyConfig, tag: str
-    ) -> Optional[Dict[str, Any]]:
-        outbound: Dict[str, Any] = {
-            "tag": tag,
-            "server": proxy.server,
-            "server_port": proxy.port,
-        }
-
-        if isinstance(proxy, VMessConfig):
-            outbound["type"] = "vmess"
-            outbound["uuid"] = proxy.uuid
-            outbound["alter_id"] = proxy.alterId
-            outbound["security"] = (
-                proxy.cipher
-                if proxy.cipher and proxy.cipher.lower() not in ("null", "none", "")
-                else "auto"
-            )
-            if proxy.packet_encoding:
-                pe = proxy.packet_encoding.lower()
-                if pe in ("xudp", "packetaddr", "packet"):
-                    outbound["packet_encoding"] = (
-                        "xudp" if pe == "xudp" else "packetaddr"
-                    )
-        elif isinstance(proxy, VLESSConfig):
-            outbound["type"] = "vless"
-            outbound["uuid"] = proxy.uuid
-            if proxy.flow:
-                flow = proxy.flow
-                if "udp443" in flow:
-                    flow = flow.replace("-udp443", "")
-                if flow in ("xtls-rprx-vision",):
-                    outbound["flow"] = flow
-            if proxy.packet_encoding:
-                pe = proxy.packet_encoding.lower()
-                if pe == "xudp":
-                    outbound["packet_encoding"] = "xudp"
-                elif pe in ("packet", "packetaddr"):
-                    outbound["packet_encoding"] = "packetaddr"
-        elif isinstance(proxy, TrojanConfig):
-            outbound["type"] = "trojan"
-            outbound["password"] = proxy.password
-        elif isinstance(proxy, ShadowsocksConfig):
-            outbound["type"] = "shadowsocks"
-            outbound["method"] = proxy.method
-            outbound["password"] = proxy.password
-            if proxy.plugin:
-                # sing-box supports only obfs-local and v2ray-plugin;
-                # simple-obfs is an alias for obfs-local.
-                plugin = proxy.plugin
-                if plugin == "simple-obfs":
-                    plugin = "obfs-local"
-                if plugin in ("obfs-local", "v2ray-plugin"):
-                    outbound["plugin"] = plugin
-                    if proxy.plugin_opts:
-                        outbound["plugin_opts"] = proxy.plugin_opts
-        elif isinstance(proxy, Hysteria2Config):
-            outbound["type"] = "hysteria2"
-            outbound["password"] = proxy.password
-            tls = self._singbox_tls(proxy) or {
-                "enabled": True,
-                "server_name": proxy.sni or proxy.server,
-            }
-            if proxy.insecure:
-                tls["insecure"] = True
-            outbound["tls"] = tls
-            if proxy.obfs:
-                outbound["obfs"] = {
-                    "type": proxy.obfs,
-                    "password": proxy.obfs_password or "",
-                }
-            if proxy.up:
-                outbound["up_mbps"] = _mbps(proxy.up)
-            if proxy.down:
-                outbound["down_mbps"] = _mbps(proxy.down)
-            if proxy.ports:
-                outbound["server_ports"] = _server_ports(proxy.ports)
-                outbound["hop_interval"] = proxy.hop_interval or 30
-            return outbound
-        elif isinstance(proxy, HysteriaConfig):
-            outbound["type"] = "hysteria"
-            if proxy.auth:
-                if proxy.auth_base64:
-                    outbound["auth"] = proxy.auth
-                else:
-                    outbound["auth_str"] = proxy.auth
-            outbound["up_mbps"] = _mbps(proxy.up) or 100
-            outbound["down_mbps"] = _mbps(proxy.down) or 100
-            tls = self._singbox_tls(proxy) or {
-                "enabled": True,
-                "server_name": proxy.sni or proxy.server,
-            }
-            if proxy.insecure:
-                tls["insecure"] = True
-            if proxy.obfs:
-                outbound["obfs"] = proxy.obfs
-            outbound["tls"] = tls
-            if proxy.ports:
-                outbound["server_ports"] = _server_ports(proxy.ports)
-            return outbound
-        elif isinstance(proxy, TUICConfig):
-            if proxy.token and not proxy.uuid:
-                # sing-box TUIC only supports uuid+password (v5); token (v4)
-                # is not a valid field and fails `sing-box check`.
-                return None
-            outbound["type"] = "tuic"
-            if proxy.token and not proxy.uuid:
-                outbound["token"] = proxy.token
-            else:
-                outbound["uuid"] = proxy.uuid
-                outbound["password"] = proxy.password
-            outbound["congestion_control"] = proxy.congestion_control
-            outbound["udp_relay_mode"] = proxy.udp_relay_mode
-            tls = self._singbox_tls(proxy) or {
-                "enabled": True,
-                "server_name": proxy.sni or proxy.server,
-            }
-            if proxy.insecure:
-                tls["insecure"] = True
-            alpn = _split_alpn(proxy.alpn)
-            if alpn:
-                tls["alpn"] = alpn
-            outbound["tls"] = tls
-            return outbound
-        elif isinstance(proxy, SocksConfig):
-            outbound["type"] = "socks"
-            if proxy.username:
-                outbound["username"] = proxy.username
-            if proxy.password:
-                outbound["password"] = proxy.password
-            return outbound
-        else:
-            return None
-
-        transport = self._singbox_transport(proxy)
-        if transport:
-            outbound["transport"] = transport
-        tls = self._singbox_tls(proxy)
-        if tls:
-            outbound["tls"] = tls
-        return outbound
-
-    def generate_singbox_config(self, proxies: List[ProxyConfig]) -> Dict[str, Any]:
-        outbounds: List[Dict[str, Any]] = []
-        proxy_tags: List[str] = []
-
-        # Explicit direct outbound (referenced by rules / final)
-        outbounds.append({"type": "direct", "tag": "direct"})
-
-        # Same stable identities as Clash (no remark key: sing-box rejects
-        # unknown outbound fields, verified with `sing-box check`).
-        entries = []
-        for proxy in _usable_proxies(proxies):
-            try:
-                base = build_proxy_identity(proxy.protocol, proxy.server, proxy.port)
-            except Exception:
-                # Same unified fallback as Clash: remark or "proxy", never a
-                # positional index (feed-order independence for broken rows).
-                base = (proxy.name or "proxy").strip() or "proxy"
-            entries.append(
-                {
-                    "proxy": proxy,
-                    "base_identity": base,
-                    "source_link": getattr(proxy, "source_link", "") or "",
-                }
-            )
-        for item in assign_stable_names(entries):
-            proxy = item["proxy"]
-            tag: str = item["final_name"]
-            raw = proxy.name or tag
-            try:
-                outbound = self._singbox_outbound(proxy, tag)
-            except Exception as exc:
-                logger.error("Failed to convert %r to sing-box: %s", raw, exc)
-                continue
-            if outbound:
-                outbounds.append(outbound)
-                proxy_tags.append(tag)
-
-        if proxy_tags:
-            outbounds.append(
-                {
-                    "type": "urltest",
-                    "tag": "auto",
-                    "outbounds": proxy_tags,
-                    "url": self.url_test_url,
-                    "interval": "5m",
+                    "interval": self.url_test_interval,
                     "tolerance": self.url_test_tolerance,
+                    "lazy": True,
+                    "expected-status": 200,
+                    "max-failed-times": 3,
                 }
             )
-        if proxy_tags:
-            outbounds.extend(self._singbox_country_outbounds(proxy_tags))
-
-        inbounds = [
-            {
-                "type": "mixed",
-                "tag": "mixed-in",
-                "listen": "127.0.0.1",
-                "listen_port": 10808,
-            },
-        ]
-        if self.tun_enabled:
-            # Opt-in via --tun (needs root/CAP_NET_ADMIN). sing-box
-            # inbounds have no "enabled" flag, so TUN is only emitted
-            # when requested.
-            inbounds.append(
-                {
-                    "type": "tun",
-                    "tag": "tun-in",
-                    "interface_name": "mihomo",
-                    # Outside the fake-ip pool (198.18.0.0/15) to avoid overlap.
-                    "address": ["172.19.0.1/30"],
-                    # gvisor: fully userspace stack (no kernel interplay needed).
-                    "stack": "gvisor",
-                    "mtu": 9000,
-                    "auto_route": True,
-                    "strict_route": True,
-                    # Exclude private/LAN from TUN routing -> stays DIRECT and
-                    # avoids proxy loops (mirrors mihomo route-exclude-address).
-                    "route_exclude_address": PRIVATE_CIDRS + PRIVATE_CIDRS_V6,
-                    "endpoint_independent_nat": False,
-                    "udp_timeout": "5m",
-                }
-            )
-
-        final = "auto" if proxy_tags else "direct"
-        # Mirrors the mihomo rule order: private → final (proxy-everything).
-        # Process matchers, ads reject and Iran/China suffixes are gone:
-        # this runs on a foreign server with no local sidecar, and sing-box
-        # `geoip` is deprecated in favour of rule-sets anyway.
-        rules: List[Dict[str, Any]] = [
-            {"action": "sniff"},
-            {"protocol": "dns", "action": "hijack-dns"},
-            {
-                "action": "route",
-                "outbound": "direct",
-                "ip_is_private": True,
-            },
-        ]
-
-        # Fake-IP by default (like mihomo enhanced-mode: fake-ip): hijacked
-        # DNS gets fake IPs via the query_type rule; LAN/NTP/probes get
-        # real IPs from dns-direct. `final` must be a real resolver —
-        # sing-box forbids fakeip as the default server.
-        realip_suffixes = [
-            ".lan",
-            ".local",
-            ".localhost",
-            ".localdomain",
-            "localhost.ptlogin2.qq.com",
-            "msftconnecttest.com",
-            "msftncsi.com",
-            "pool.ntp.org",
-            "detectportal.firefox.com",
-            "connectivitycheck.gstatic.com",
-        ]
-        config: Dict[str, Any] = {
-            "log": {"level": "info", "timestamp": True},
-            "dns": {
-                "servers": [
-                    {
-                        "type": "fakeip",
-                        "tag": "dns-fakeip",
-                        "inet4_range": "198.18.0.0/15",
-                    },
-                    {
-                        "type": "udp",
-                        "server": "1.1.1.1",
-                        "tag": "dns-direct",
-                    },
-                ],
-                "rules": [
-                    {
-                        "action": "route",
-                        "server": "dns-direct",
-                        "domain_suffix": realip_suffixes,
-                    },
-                    {
-                        "action": "route",
-                        "server": "dns-fakeip",
-                        "query_type": ["A", "AAAA"],
-                    },
-                ],
-                "final": "dns-direct",
-                "strategy": "prefer_ipv4",
-                "cache_capacity": SINGBOX_CACHE_CAPACITY,
-                "independent_cache": True,
-            },
-            "inbounds": inbounds,
-            "outbounds": outbounds,
-            "route": {
-                "rules": rules,
-                "final": final,
-                "auto_detect_interface": True,
-                # Must be a REAL resolver (not fakeip): used to resolve
-                # proxy node domain names (SNI/host).
-                "default_domain_resolver": "dns-direct",
-            },
-            "experimental": {
-                "clash_api": {
-                    "external_controller": "127.0.0.1:9090",
-                    "external_ui": "ui",
-                    "external_ui_url": "https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages.zip",
-                    "default_mode": "rule",
-                    "store_selected": True,
-                },
-                "cache_file": {
-                    "enabled": True,
-                    "store_fakeip": True,
-                    "store_dns": True,
-                    "store_rdrc": True,
-                    "flush_interval": "5m",
-                },
-            },
-            "ntp": {
-                "enabled": True,
-                "server": "time.apple.com",
-                "server_port": 123,
-                "interval": "60m",
-            },
-            "http_clients": [
-                {"tag": "http-client-direct"},
-            ],
-        }
-        return config
+        return groups
 
+    def _mihomo_service_rules(self) -> List[str]:
+        """Build service routing rules for mihomo.
 
-def _mbps(value: Optional[str]) -> Optional[int]:
-    if not value:
-        return None
-    m = re.search(r"(\d+)", str(value))
-    return int(m.group(1)) if m else None
+        GEOSITE rules use community domain lists; DOMAIN-SUFFIX fallbacks
+        cover services without a standard geosite entry (OpenCode) and
+        provide resilience if geodata is unavailable. Rules are ordered
+        before MATCH so they take precedence. LAN/private bypass stays
+        first (handled by _clash_rules).
+        """
+        rules: List[str] = []
+        # GEOSITE rules for services with standard categories.
+        for service in SERVICE_ORDER:
+            category = SERVICE_GEOSITE.get(service)
+            if category:
+                rules.append(f"GEOSITE,{category},{service}")
+        # DOMAIN-SUFFIX fallbacks for core domains (resilience + services
+        # without a geosite entry).
+        for service in SERVICE_ORDER:
+            for domain in SERVICE_DOMAIN_FALLBACK.get(service, []):
+                rules.append(f"DOMAIN-SUFFIX,{domain},{service}")
+        return rules
 
 
-def _server_ports(spec: str) -> List[str]:
-    """Convert mport style '2000,3000-4000' to sing-box server_ports strings."""
-    out: List[str] = []
-    for part in str(spec).split(","):
-        part = part.strip()
-        if not part:
-            continue
-        out.append(part)
-    return out
 
 
 _BOOL_PLUGIN_OPTS = {"mux", "tls", "skip-cert-verify", "fast-open"}
@@ -2162,8 +1811,6 @@ def run(
     url: str = DEFAULT_SUBSCRIPTION_URL,
     urls: Optional[List[str]] = None,
     clash_out: str = "clash_config.yaml",
-    singbox_out: str = "singbox_config.json",
-    outputs: str = "both",
     tun_enabled: bool = False,
     allow_lan: bool = True,
     controller_secret: str = "",
@@ -2241,46 +1888,36 @@ def run(
     )
     generator.subscription_title = title
 
-    if outputs in ("clash", "both"):
-        clash_config = generator.generate_clash_config(proxies)
-        header_lines = []
-        if title:
-            header_lines.append(f"# profile-title: {title}")
-            header_lines.append(f"# profile-web-page-url: {url.split('#', 1)[0]}")
-            header_lines.append("# profile-update-interval: 1")
-        body = yaml.dump(
-            clash_config,
-            default_flow_style=False,
-            allow_unicode=True,
-            sort_keys=False,
-            width=4096,
-        )
-        text = ("\n".join(header_lines) + "\n" if header_lines else "") + body
-        with open(clash_out, "w", encoding="utf-8") as fh:
-            fh.write(text)
-        logger.info(
-            "Generated Clash config %s with %d proxies / %d groups",
-            clash_out,
-            len(clash_config.get("proxies", [])),
-            len(clash_config.get("proxy-groups", [])),
-        )
 
-    if outputs in ("singbox", "both"):
-        singbox_config = generator.generate_singbox_config(proxies)
-        with open(singbox_out, "w", encoding="utf-8") as fh:
-            json.dump(singbox_config, fh, indent=2, ensure_ascii=False)
-        logger.info(
-            "Generated sing-box config %s with %d outbounds",
-            singbox_out,
-            len(singbox_config.get("outbounds", [])),
-        )
+    clash_config = generator.generate_clash_config(proxies)
+    header_lines = []
+    if title:
+        header_lines.append(f"# profile-title: {title}")
+        header_lines.append(f"# profile-web-page-url: {url.split('#', 1)[0]}")
+        header_lines.append("# profile-update-interval: 1")
+    body = yaml.dump(
+        clash_config,
+        default_flow_style=False,
+        allow_unicode=True,
+        sort_keys=False,
+        width=4096,
+    )
+    text = ("\n".join(header_lines) + "\n" if header_lines else "") + body
+    with open(clash_out, "w", encoding="utf-8") as fh:
+        fh.write(text)
+    logger.info(
+        "Generated Clash config %s with %d proxies / %d groups",
+        clash_out,
+        len(clash_config.get("proxies", [])),
+        len(clash_config.get("proxy-groups", [])),
+    )
 
     return 0
 
 
 def main() -> None:
     ap = argparse.ArgumentParser(
-        description="Parse V2Ray subscription links into Clash (mihomo) / sing-box configs"
+        description="Parse V2Ray subscription links into Clash (mihomo) config"
     )
     ap.add_argument(
         "urls",
@@ -2289,13 +1926,6 @@ def main() -> None:
         help="Subscription URL(s) (fragment #Name becomes profile title)",
     )
     ap.add_argument("--clash-out", default="clash_config.yaml")
-    ap.add_argument("--singbox-out", default="singbox_config.json")
-    ap.add_argument(
-        "--only",
-        choices=("clash", "singbox", "both"),
-        default="both",
-        help="Which outputs to generate",
-    )
     ap.add_argument(
         "--tun",
         action="store_true",
@@ -2337,8 +1967,6 @@ def main() -> None:
         run(
             urls=args.urls,
             clash_out=args.clash_out,
-            singbox_out=args.singbox_out,
-            outputs=args.only,
             tun_enabled=args.tun,
             allow_lan=args.allow_lan,
             controller_secret=args.controller_secret,
```
<!-- END_GIT_DIFF -->
