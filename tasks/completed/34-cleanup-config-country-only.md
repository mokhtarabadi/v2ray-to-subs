# Task 34: Cleanup config — remove service groups, cloudflare, geo; keep countries only

**File:** `tasks/qa/34-cleanup-config-country-only.md`
**Source:** manager
**Type:** improvement
**Status:** in-progress
**Submitted:** 2026-11-25T18:59:40Z
**Started:** 2026-11-25T18:53:55Z

## Source Context

### Variant C: Manager (manager)

## Goal

Clean up the generated mihomo config:
- Remove ALL dedicated service groups (Google, Apple, Docker, Claude, ChatGPT, GitHub, OpenCode, OpenRouter).
- Remove Cloudflare IP-CIDR rules (fetched ranges).
- Remove geoip/geosite references (geodata-mode, geox-url).
- Keep ONLY country groups: IT, GB, JP, HK.
- PROXY group defaults to Auto.
- Remove the fetch helper, service constants, and related code.

## Manager's Notes

- User wants a lean config: only country groups + LAN bypass + MATCH,PROXY.
- Countries: IT, GB, JP, HK (4 countries).
- No external dedicated service groups.
- Remove all geoip/geosite.
- PROXY by default uses Auto.
- Cloudflare rules removed.
- Do all in one cleanup task.

<!-- These sections are unconditional per lint contract — DO NOT move back inside variants -->

## Local TODOs

- [ ] Update COUNTRY_CODES to IT, GB, JP, HK
- [ ] Remove service groups, constants, and helpers
- [ ] Remove Cloudflare fetch and IP-CIDR rules
- [ ] Remove geodata-mode and geo references
- [ ] Set PROXY default to Auto
- [ ] Remove unused imports (ipaddress, urllib if unused)
- [ ] Verify generated config

## Acceptance Criteria

- [x] COUNTRY_CODES = IT, GB, JP, HK (4 countries)
- [x] No service groups (Google, Apple, Docker, Claude, ChatGPT, GitHub, OpenCode, OpenRouter) in config
- [x] No Cloudflare IP-CIDR rules in config
- [x] No geoip/geosite/geodata-mode references in config
- [x] PROXY group defaults to Auto
- [x] Country groups: IT, GB, JP, HK (each select + url-test + fallback)
- [x] Generated config parses cleanly (yaml)
- [x] Converter runs with exit 0
- [x] No regression in LAN bypass

## Verification Evidence

- **Test command:** rtk test python3 -m py_compile proxy_converter.py
- **Expected result:** syntax check passes with exit 0
- **Actual result:** py_compile OK (no errors)
- **Exit code:** 0

Additional verification commands run:
- `python3 proxy_converter.py --no-allow-lan --unique-host --controller-secret 123456789 --clash-out /tmp/test-clash.yaml` → exit 0 (2978 proxies, 16 groups)
- `python3 -c "import yaml; yaml.safe_load(...)"` → exit 0 (parse OK)
- Verified 4 country groups (IT, GB, JP, HK) with select + url-test + fallback
- Verified PROXY default-selected: Auto
- Verified no service groups, no Cloudflare rules, no geodata-mode
- Verified LAN/private DIRECT rules present
- Verified MATCH,PROXY last
- `grep -ic singbox` → 0 (fully dropped)
- `grep -c "checker.surfshield.org"` → 4 (country groups only)

> Verification runner rule: the first verification run MUST use the `rtk test` prefix. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append (N/A — file absent per approved converter-only scope; recorded skip)
- [x] `testing-verification` applied and evidence recorded

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do NOT defer box-checking to a separate closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** Removing service groups means users lose per-service node selection. Cloudflare sites go through PROXY.
- **Rollback plan:** Re-add service groups and Cloudflare rules from git history.

---

## Execution Log & Reasoning

### Implementation

- COUNTRY_CODES → IT, GB, JP, HK (4 countries).
- Removed all service constants (SERVICE_HEALTH_URLS, SERVICE_GEOSITE, SERVICE_DOMAIN_FALLBACK, SERVICE_ORDER).
- Removed _mihomo_service_groups and _mihomo_service_rules methods.
- Removed service groups wiring and service rules splice from generate_clash_config.
- Removed Cloudflare constants, _fetch_cloudflare_ranges helper, and Cloudflare IP-CIDR wiring.
- Removed geodata-mode: True.
- Added default-selected: "Auto" to PROXY select group.
- Inlined checker URL (f-string) in _mihomo_country_groups.
- Removed CHECKER_URL_TEMPLATE constant.
- Removed import ipaddress (no longer used).
- urllib still used (urllib.parse, urllib.request in SubscriptionDownloader).

### Verification

- py_compile exit 0; dry gen exit 0 (2978 proxies, 16 groups).
- Verified 4 country groups (IT, GB, JP, HK) with select + url-test + fallback.
- Verified PROXY default-selected: Auto.
- Verified no service groups, no Cloudflare rules, no geodata-mode.
- Verified LAN/private DIRECT rules present.
- Verified MATCH,PROXY last.
- grep singbox: 0 (fully dropped).
- grep checker.surfshield: 4 (country groups only).

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/proxy_converter.py b/proxy_converter.py
index 71369f5..e302ce1 100644
--- a/proxy_converter.py
+++ b/proxy_converter.py
@@ -17,7 +17,6 @@ import os
 import re
 import urllib.parse
 import urllib.request
-import ipaddress
 from dataclasses import dataclass
 from typing import Any, Dict, List, Optional, Tuple
 
@@ -139,12 +138,6 @@ def assign_stable_names(entries: list) -> list:
 
 DEFAULT_SUBSCRIPTION_URL = "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt"
 
-# Cloudflare official IP range endpoints (plain text, one CIDR per line).
-# Fetched fresh at generation time so ranges are always up-to-date.
-CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
-CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6"
-CLOUDFLARE_FETCH_TIMEOUT = 5  # seconds; short to avoid generation hangs
-
 # ---------------------------------------------------------------------------
 # Shared bypass policy.
 #
@@ -193,48 +186,12 @@ REALIP_SUFFIXES = [
     "connectivitycheck.gstatic.com",
 ]
 # Top exit countries used for country-based proxy groups.
-# Expanded to US, DE, NL, FR, BR, CA per operator choice (Task 32).
-COUNTRY_CODES = ["US", "DE", "NL", "FR", "BR", "CA"]
+# Lean set: IT, GB, JP, HK per operator choice (Task 34).
+COUNTRY_CODES = ["IT", "GB", "JP", "HK"]
 
 # Country health-check uses checker.surfshield.org which returns 200 for
 # matching country exit IP and 403 otherwise. expected-status filters nodes.
-CHECKER_URL_TEMPLATE = "https://checker.surfshield.org/{cc}"
-
-# Service-specific dedicated groups. Each service gets a select plus
-# url-test pair. The url-test health-checks a strict service URL with
-# expected HTTP 200, so only nodes that can reach that service survive.
-# GEOSITE provides community domain lists for routing; DOMAIN-SUFFIX
-# covers services without a standard geosite entry.
-SERVICE_HEALTH_URLS = {
-    "Google": "https://aistudio.google.com/",
-    "Apple": "https://www.apple.com/",
-    "Docker": "https://hub.docker.com/",
-    "Claude": "https://claude.ai/",
-    "ChatGPT": "https://chatgpt.com/",
-    "GitHub": "https://github.com/",
-    "OpenCode": "https://opencode.ai/",
-    "OpenRouter": "https://openrouter.ai/",
-}
-SERVICE_GEOSITE = {
-    "Google": "google",
-    "Apple": "apple",
-    "Docker": "docker",
-    "Claude": "anthropic",
-    "ChatGPT": "openai",
-    "GitHub": "github",
-}
-# Services without a standard geosite entry (use DOMAIN-SUFFIX fallback).
-SERVICE_DOMAIN_FALLBACK = {
-    "Google": ["google.com", "aistudio.google.com", "gemini.google.com"],
-    "Apple": ["apple.com"],
-    "Docker": ["docker.com", "hub.docker.com"],
-    "Claude": ["claude.ai", "anthropic.com"],
-    "ChatGPT": ["chatgpt.com", "openai.com"],
-    "GitHub": ["github.com", "githubusercontent.com"],
-    "OpenCode": ["opencode.ai"],
-    "OpenRouter": ["openrouter.ai"],
-}
-SERVICE_ORDER = ["Google", "Apple", "Docker", "Claude", "ChatGPT", "GitHub", "OpenCode", "OpenRouter"]
+
 MIHOMO_CACHE_SIZE = 4096
 
 
@@ -1479,6 +1436,7 @@ class ConfigGenerator:
                         "proxies": ["Auto", "Load Balance", "Fallback"]
                         + country_group_names
                         + proxy_names,
+                        "default-selected": "Auto",
                     },
                     {
                         "name": "Auto",
@@ -1530,32 +1488,7 @@ class ConfigGenerator:
         if proxy_names:
             proxy_groups.extend(self._mihomo_country_groups(proxy_names))
 
-        # Service-specific groups (runtime health via strict service URLs).
-        # Each service gets a select + url-test pair; no entry in PROXY dropdown.
-        if proxy_names:
-            proxy_groups.extend(self._mihomo_service_groups(proxy_names))
-
         rules = self._clash_rules()
-        # Insert service routing rules before the final MATCH,PROXY catch-all.
-        if proxy_names:
-            service_rules = self._mihomo_service_rules()
-            try:
-                match_idx = rules.index("MATCH,PROXY")
-                rules[match_idx:match_idx] = service_rules
-            except ValueError:
-                rules.extend(service_rules)
-        # Insert Cloudflare IP ranges before MATCH (after services/countries).
-        # Fetches fresh from official source; graceful fallback on failure.
-        cf_v4 = self._fetch_cloudflare_ranges(CLOUDFLARE_IPV4_URL, CLOUDFLARE_FETCH_TIMEOUT)
-        cf_v6 = self._fetch_cloudflare_ranges(CLOUDFLARE_IPV6_URL, CLOUDFLARE_FETCH_TIMEOUT)
-        cf_rules = [f"IP-CIDR,{c},DIRECT,no-resolve" for c in cf_v4]
-        cf_rules += [f"IP-CIDR6,{c},DIRECT,no-resolve" for c in cf_v6]
-        if cf_rules:
-            try:
-                match_idx = rules.index("MATCH,PROXY")
-                rules[match_idx:match_idx] = cf_rules
-            except ValueError:
-                rules.extend(cf_rules)
 
         # NOTE: field-for-field aligned with /home/mohammad/Desktop/mihomo
         # config.yaml (verified mihomo v1.19.31 setup). Differences from it are
@@ -1567,7 +1500,6 @@ class ConfigGenerator:
             # "*" by default (proxy-everything boundary serves LAN clients).
             "bind-address": "*" if self.allow_lan else "127.0.0.1",
             "mode": "rule",
-            "geodata-mode": True,
             "log-level": "info",
             "ipv6": False,
             # No PROCESS-* rules remain (foreign server, no local sidecar),
@@ -1669,37 +1601,6 @@ class ConfigGenerator:
         }
         return config
 
-    @staticmethod
-    def _fetch_cloudflare_ranges(url: str, timeout: int = 5) -> List[str]:
-        """Fetch and validate Cloudflare IP CIDR ranges from official source.
-
-        Downloads a plain-text list (one CIDR per line) with a short
-        timeout. Returns an empty list on any network/decode/validation
-        failure so generation never crashes. Invalid lines are dropped.
-        """
-        ranges: List[str] = []
-        try:
-            # Short timeout prevents generation from hanging on slow endpoints.
-            req = urllib.request.Request(url, headers={"User-Agent": "mihomo-config-generator/1.0"})
-            with urllib.request.urlopen(req, timeout=timeout) as resp:
-                text = resp.read().decode("utf-8", errors="ignore")
-        except Exception as exc:
-            # Graceful fallback: log warning, return empty (no Cloudflare rules).
-            print(f"Warning: Cloudflare range fetch failed for {url}: {exc}")
-            return ranges
-        for raw_line in text.splitlines():
-            line = raw_line.strip()
-            # Skip empty lines and comments.
-            if not line or line.startswith("#"):
-                continue
-            try:
-                # Validate CIDR; drop invalid entries silently.
-                net = ipaddress.ip_network(line, strict=False)
-                ranges.append(str(net))
-            except ValueError:
-                continue
-        return ranges
-
     @classmethod
     def _clash_rules(cls) -> List[str]:
         # First match wins — proxy-everything shape:
@@ -1728,7 +1629,7 @@ class ConfigGenerator:
 
         Each country gets a select group plus url-test and fallback
         variants. The health-check URL is templated per country via
-        CHECKER_URL_TEMPLATE (checker.surfshield.org returns 200 for
+        checker.surfshield.org (returns 200 for
         matching country exit IP, 403 otherwise). expected-status filters
         nodes. Runtime health decides membership.
         """
@@ -1736,7 +1637,7 @@ class ConfigGenerator:
         if not proxy_names:
             return groups
         for cc in COUNTRY_CODES:
-            url = CHECKER_URL_TEMPLATE.format(cc=cc)
+            url = f"https://checker.surfshield.org/{cc}"
             # Collision guard: a proxy literally named like a group tag
             # must not shadow the group itself.
             reserved = {cc, f"{cc}-Auto", f"{cc}-Fallback", f"{cc}-auto"}
@@ -1777,68 +1678,6 @@ class ConfigGenerator:
             )
         return groups
 
-    def _mihomo_service_groups(self, proxy_names: List[str]) -> List[Dict[str, Any]]:
-        """Build dedicated per-service proxy groups for mihomo.
-
-        Each service gets a select group (manual pick) plus a url-test
-        auto group. The auto group health-checks a strict service URL
-        with expected-status 200, so only nodes that can reach that
-        service survive. Full proxy list is used as candidates; lazy
-        true limits health-check load to when the group is selected.
-        Empty proxy list yields no groups.
-        """
-        groups: List[Dict[str, Any]] = []
-        if not proxy_names:
-            return groups
-        for service in SERVICE_ORDER:
-            url = SERVICE_HEALTH_URLS[service]
-            members = list(proxy_names)
-            groups.append(
-                {
-                    "name": service,
-                    "type": "select",
-                    "proxies": [f"{service}-Auto"] + members,
-                }
-            )
-            auto_group: Dict[str, Any] = {
-                "name": f"{service}-Auto",
-                "type": "url-test",
-                "proxies": members,
-                "url": url,
-                "interval": self.url_test_interval,
-                "tolerance": self.url_test_tolerance,
-                "lazy": True,
-                "expected-status": 200,
-                "max-failed-times": 3,
-            }
-            groups.append(auto_group)
-        return groups
-
-    def _mihomo_service_rules(self) -> List[str]:
-        """Build service routing rules for mihomo.
-
-        GEOSITE rules use community domain lists; DOMAIN-SUFFIX fallbacks
-        cover services without a standard geosite entry (OpenCode) and
-        provide resilience if geodata is unavailable. Rules are ordered
-        before MATCH so they take precedence. LAN/private bypass stays
-        first (handled by _clash_rules).
-        """
-        rules: List[str] = []
-        # GEOSITE rules for services with standard categories.
-        for service in SERVICE_ORDER:
-            category = SERVICE_GEOSITE.get(service)
-            if category:
-                rules.append(f"GEOSITE,{category},{service}")
-        # DOMAIN-SUFFIX fallbacks for core domains (resilience + services
-        # without a geosite entry).
-        for service in SERVICE_ORDER:
-            for domain in SERVICE_DOMAIN_FALLBACK.get(service, []):
-                rules.append(f"DOMAIN-SUFFIX,{domain},{service}")
-        return rules
-
-
-
-
 _BOOL_PLUGIN_OPTS = {"mux", "tls", "skip-cert-verify", "fast-open"}
```
<!-- END_GIT_DIFF -->
