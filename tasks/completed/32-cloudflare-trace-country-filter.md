# Task 32: Cloudflare trace per-country filtering and expand countries

**File:** `tasks/qa/32-cloudflare-trace-country-filter.md`
**Source:** manager
**Type:** improvement
**Status:** in-progress
**Submitted:** 2026-11-25T17:52:45Z
**Started:** 2026-11-25T17:42:23Z

## Source Context

### Variant C: Manager (manager)

## Goal

Switch country health-checks from checker.surfshield.org (status-only) to Cloudflare trace endpoint (body-based `loc=XX` matching) using mihomo's `expected-body`/`exclude-body` support. Add FR, BR, CA back to the country list. This enables per-country filtering by checking the actual exit-country code in the response body, which is more reliable than status codes alone.

## Manager's Notes

- mihomo v1.19.34 supports `expected-body` and `exclude-body` in url-test (PR #3297, merged).
- Cloudflare trace endpoint: https://www.cloudflare.com/cdn-cgi/trace returns `loc=XX` in body.
- Use `expected-body: "loc=US"` (etc.) for each country group instead of checker.surfshield.org.
- Add FR, BR, CA to COUNTRY_CODES (currently US, DE, NL).
- Google group: keep https://gemini.google.com/ with exclude-body for "isn't currently supported in your country".
- Verify each service URL with curl to find block indicators (done in Task 31).

<!-- These sections are unconditional per lint contract — DO NOT move back inside variants -->

## Local TODOs

- [ ] Verify Cloudflare trace endpoint returns correct country for current proxy
- [ ] Update COUNTRY_CODES to include US, DE, NL, FR, BR, CA
- [ ] Change country health-check URLs to Cloudflare trace with expected-body: loc=XX
- [ ] Update task file and plan via brain
- [ ] Implement and verify

## Acceptance Criteria

- [x] COUNTRY_CODES includes US, DE, NL, FR, BR, CA (6 countries)
- [x] Country health-checks use https://www.cloudflare.com/cdn-cgi/trace with expected-body: loc=XX
- [x] Google group uses exclude-body for country block message
- [x] 8 service groups (Google, Apple, Docker, Claude, ChatGPT, GitHub, OpenCode, OpenRouter) with strict health URLs
- [x] Each service group health-checks its service URL with expected-status 200
- [x] Google uses exclude-body for "isn't currently supported in your country"
- [x] Routing rules use GEOSITE where available + DOMAIN-SUFFIX fallback before MATCH
- [x] Generated config parses cleanly (yaml)
- [x] Converter runs with exit 0
- [x] No regression in country groups, LAN bypass, cache, dashboard

## Verification Evidence

- **Test command:** rtk test python3 -m py_compile proxy_converter.py
- **Expected result:** syntax check passes with exit 0
- **Actual result:** py_compile OK (no errors)
- **Exit code:** 0

Additional verification commands run:
- `python3 proxy_converter.py --no-allow-lan --unique-host --controller-secret 123456789 --clash-out /tmp/test-clash.yaml` → exit 0 (2978 proxies, 38 groups)
- `python3 -c "import yaml; yaml.safe_load(...)"` → exit 0 (parse OK)
- Verified 6 country groups use Cloudflare trace URL with expected-body: loc=XX
- Verified 8 service groups with strict health URLs; only Google has exclude-body
- Verified service + country rules before MATCH,PROXY
- `grep -c singbox` → 0 (fully dropped)
- `grep geodata-mode` → True
- `grep checker.surfshield.org` → 0 (removed)

> Verification runner rule: the first verification run MUST use the `rtk test` prefix. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append (N/A — file absent per approved converter-only scope; recorded skip)
- [x] `testing-verification` applied and evidence recorded

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do NOT defer box-checking to a closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** Cloudflare trace endpoint may be blocked by some proxies; expected-body matching depends on mihomo v1.19.34+.
- **Rollback plan:** Revert health-check URLs to checker.surfshield.org; remove expected-body fields.

---

## Execution Log & Reasoning

### Implementation

- Updated COUNTRY_CODES: US, DE, NL, FR, BR, CA (6 countries).
- Replaced CHECKER_URL_TEMPLATE with CLOUDFLARE_TRACE_URL (https://www.cloudflare.com/cdn-cgi/trace).
- Added SERVICE_EXCLUDE_BODY dict (Google: "isn't currently supported in your country").
- Updated _mihomo_country_groups: fixed trace URL + expected-body: loc=XX per country.
- Updated _mihomo_service_groups: added exclude-body for Google only.
- Removed CHECKER_URL_TEMPLATE constant (no longer used).

### Verification

- py_compile exit 0; dry gen exit 0 (2978 proxies, 38 groups).
- Verified 6 country groups: trace URL + expected-body loc=XX (US, DE, NL, FR, BR, CA).
- Verified 8 service groups with strict health URLs; only Google has exclude-body.
- Verified service + country rules before MATCH,PROXY.
- grep singbox: 0 (fully dropped). grep checker.surfshield: 0 (removed).
- geodata-mode: True. Country groups + LAN bypass + cache + dashboard intact.

### Curl findings (Task 32)

- Cloudflare trace: returns loc=XX matching exit country (NL tested).
- Google (gemini.google.com): 200 but body contains "isn't currently supported in your country" when blocked → exclude-body.
- Apple, Docker, ChatGPT, GitHub, OpenCode, OpenRouter: clean 200, no block indicator → status-only.
- Claude: 403 (Cloudflare challenge) → status filter handles it.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/proxy_converter.py b/proxy_converter.py
index fdfcd94..3f371e9 100644
--- a/proxy_converter.py
+++ b/proxy_converter.py
@@ -186,9 +186,19 @@ REALIP_SUFFIXES = [
     "connectivitycheck.gstatic.com",
 ]
 # Top exit countries used for country-based proxy groups.
-# Trimmed to US, DE, NL per operator choice (Option E) to reduce RAM
-# and group explosion; extend only with healthy members and memory budget.
-COUNTRY_CODES = ["US", "DE", "NL"]
+# Expanded to US, DE, NL, FR, BR, CA per operator choice (Task 32).
+# Cloudflare trace endpoint provides per-country filtering via body matching.
+COUNTRY_CODES = ["US", "DE", "NL", "FR", "BR", "CA"]
+
+# Cloudflare trace endpoint returns loc=XX in the response body, enabling
+# per-country filtering via expected-body. More reliable than status-only
+# checkers.
+CLOUDFLARE_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
+# Body text that marks a node as failed when present (Google returns 200
+# with this message when the service is blocked for the exit country).
+SERVICE_EXCLUDE_BODY = {
+    "Google": "isn't currently supported in your country",
+}
 
 # Service-specific dedicated groups. Each service gets a select plus
 # url-test pair. The url-test health-checks a strict service URL with
@@ -203,6 +213,7 @@ SERVICE_HEALTH_URLS = {
     "ChatGPT": "https://chatgpt.com/",
     "GitHub": "https://github.com/",
     "OpenCode": "https://opencode.ai/",
+    "OpenRouter": "https://openrouter.ai/",
 }
 SERVICE_GEOSITE = {
     "Google": "google",
@@ -221,9 +232,9 @@ SERVICE_DOMAIN_FALLBACK = {
     "ChatGPT": ["chatgpt.com", "openai.com"],
     "GitHub": ["github.com", "githubusercontent.com"],
     "OpenCode": ["opencode.ai"],
+    "OpenRouter": ["openrouter.ai"],
 }
-SERVICE_ORDER = ["Google", "Apple", "Docker", "Claude", "ChatGPT", "GitHub", "OpenCode"]
-CHECKER_URL_TEMPLATE = "https://checker.surfshield.org/{cc}"
+SERVICE_ORDER = ["Google", "Apple", "Docker", "Claude", "ChatGPT", "GitHub", "OpenCode", "OpenRouter"]
 MIHOMO_CACHE_SIZE = 4096
 
 
@@ -1673,19 +1684,20 @@ class ConfigGenerator:
         """Build per-country proxy groups for mihomo.
 
         Each country gets a select group plus url-test and fallback
-        variants. The health-check URL is templated per country via
-        CHECKER_URL_TEMPLATE; a node is kept only when the checker
-        returns HTTP 200. Runtime health (not build-time probing) decides
-        membership, so all usable nodes are emitted as candidates and
-        url-test filters dead ones. Empty country groups are skipped.
+        variants. The health-check URL is the Cloudflare trace endpoint
+        (returns loc=XX in body), so a node is kept only when the trace
+        confirms the exit country matches. Runtime health decides
+        membership; all usable nodes are emitted as candidates and
+        url-test filters non-matching ones. Empty country groups skipped.
         """
         groups: List[Dict[str, Any]] = []
         if not proxy_names:
             return groups
         for cc in COUNTRY_CODES:
-            url = CHECKER_URL_TEMPLATE.format(cc=cc)
+            # Fixed Cloudflare trace URL returns loc=XX in body.
+            url = CLOUDFLARE_TRACE_URL
             # Collision guard: a proxy literally named like a group tag
-            # (e.g. "US" or "US-Auto") must not shadow the group itself.
+            # must not shadow the group itself.
             reserved = {cc, f"{cc}-Auto", f"{cc}-Fallback", f"{cc}-auto"}
             members = [n for n in proxy_names if n not in reserved]
             if not members:
@@ -1703,6 +1715,8 @@ class ConfigGenerator:
                     "type": "url-test",
                     "proxies": members,
                     "url": url,
+                    # loc=XX in trace body confirms exit country.
+                    "expected-body": f"loc={cc}",
                     "interval": self.url_test_interval,
                     "tolerance": self.url_test_tolerance,
                     "lazy": True,
@@ -1747,19 +1761,23 @@ class ConfigGenerator:
                     "proxies": [f"{service}-Auto"] + members,
                 }
             )
-            groups.append(
-                {
-                    "name": f"{service}-Auto",
-                    "type": "url-test",
-                    "proxies": members,
-                    "url": url,
-                    "interval": self.url_test_interval,
-                    "tolerance": self.url_test_tolerance,
-                    "lazy": True,
-                    "expected-status": 200,
-                    "max-failed-times": 3,
-                }
-            )
+            auto_group: Dict[str, Any] = {
+                "name": f"{service}-Auto",
+                "type": "url-test",
+                "proxies": members,
+                "url": url,
+                "interval": self.url_test_interval,
+                "tolerance": self.url_test_tolerance,
+                "lazy": True,
+                "expected-status": 200,
+                "max-failed-times": 3,
+            }
+            # Google returns 200 with a country-block message in the body;
+            # exclude nodes whose body contains that message. Other services
+            # return clean 200 or a non-200 status, so no body filter needed.
+            if service in SERVICE_EXCLUDE_BODY:
+                auto_group["exclude-body"] = SERVICE_EXCLUDE_BODY[service]
+            groups.append(auto_group)
         return groups
 
     def _mihomo_service_rules(self) -> List[str]:
```
<!-- END_GIT_DIFF -->
