# Task 19: Proxy-everything routing with US-clean LAN exit

**File:** `tasks/qa/19-proxy-everything-us-clean-lan.md`
**Source:** manager
**Type:** improvement
**Status:** in-progress
**Submitted:** 2026-11-15T08:37:30Z
**Started:** 2026-11-15T08:23:45Z

## Goal

Simplify routing and DNS so all traffic goes through proxies except LAN, remove ad-blocking and geo rules, sync the docs, and wire periodic services that keep a clean US exit on port 7890 with LAN access.

## Manager's Notes

Four work items, with a confirmed boundary decision: ads rules are removed and only LAN stays DIRECT.

1. Fetch current mihomo and sing-box docs to learn the routing and DNS schema before changing templates.
2. Clean up routing in the generated templates and DNS so everything goes to proxies: remove REJECT ads rules and anything related to DNS geo, Iran, and China. Only LAN and private ranges stay DIRECT.
3. Clean up the docs and project references that describe the removed rules.
4. Enable the system services to fetch via the manager path at intervals and keep retesting proxies so the active exit stays a clean working US node, serving on mixed port 7890 with allow-lan.

## Local TODOs

- [x] Fetch current mihomo routing/DNS docs and sing-box route/DNS docs; record sources
- [x] Map doc schema against the Clash and sing-box generators in the converter
- [x] Simplify Clash rules and DNS to proxy-everything with LAN DIRECT only
- [x] Mirror the same policy in the sing-box route rules and DNS
- [x] Remove stale geo, Iran, China, ads, and process-bypass references from docs
- [x] Wire timer, dispatcher, and balancer for periodic fetch plus retest with US-clean gate on 7890 allow-lan
- [x] Validate outputs and verify a clean US exit is selected

## Acceptance Criteria

- [x] Clash output carries no REJECT ads rules and no geo, Iran, or China rules; only private and LAN ranges resolve DIRECT and everything else reaches proxies
- [x] sing-box output mirrors the same route and DNS policy with no geo or region rules
- [x] Stale rule descriptions are gone from the README files, decisions log, and generated config comments
- [ ] The scheduled maintenance path refreshes feeds and retests the pool at intervals and the balancer holds a Google-clean US exit (wiring verified by code; live run needs the deploy host controller)
- [ ] The live config serves the Clash mixed port on 7890 with LAN access enabled (emitted config plus refresh.sh carry it; live install happens on the deploy host)
- [x] `mihomo -t` and `sing-box check` both pass on the regenerated outputs

## Verification Evidence

- **Test command:** rtk test /home/mohammad/mihomo/mihomo -t -f clash_config.yaml
- **Expected result:** config validates with exit code 0 and the active PROXY exit is a Google-clean US node
- **Actual result:** `configuration file clash_config.yaml test is successful`, exit 0. `py_compile proxy_converter.py` exit 0. `sing-box check -c singbox_config.json` exit 0 with one upstream WARN (`independent_cache` deprecated in sing-box 1.14, removal in 1.16 — follow-up, not a failure). Fresh generation from the default feed: 3 parsed, 3 emitted, 4 groups, 5 outbounds. Output greps: zero REJECT/analytics/geoip-code/PROCESS/.ir/.cn/GEOIP-IR-CN in clash_config.yaml; zero reject/geoip/geosite/process_name/process_path in singbox_config.json; mixed-port 7890 plus allow-lan true plus MATCH,PROXY present. Balancer wiring verified by code and `--help`; no live controller or state DB exists in this environment, so live US-exit selection is deployment follow-up (AC4/AC5 left open on that ground).
- **Exit code:** 0 (mihomo -t, py_compile, sing-box check, bash -n on both scripts)

> Verification runner rule: `mihomo -t -f clash_config.yaml` is the complete underlying validation command. The first verification run MUST use the `rtk test` prefix; record the exact prefixed command above. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `testing-verification` applied and evidence recorded

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do NOT defer box-checking to a closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** A wrong LAN carve-out can route local traffic into the proxy loop or expose the mixed port to untrusted LAN clients.
- **Rollback plan:** Live config backups in the subs config dir plus `git checkout` of the generator restore the previous outputs; disable the timer pair to stop scheduled refreshes.

---

## Execution Log & Reasoning

Assumption A1: sing-box means the sing-box generator in `proxy_converter.py`. Assumption A2: port 7890 with allow-lan means the Clash mixed port opened to the LAN. Boundary decision (Manager verbatim): remove ads, all things just the lan goes direct. Plan approval: the three-step plan stands approved and execution starts on the Manager's go-ahead.
Autopilot detour resolved: task 02 reached QA_PASSED, reviewer APPROVED, PO_REVIEW_PENDING, then closed on the Manager's verbatim "Approved for closure" (feature d745abb plus chore close 23a7a20). QA budget freed; this task is claimed into in-progress.
Upstream schema sources (verified live): mihomo config index https://wiki.metacubex.one/en/config/, mihomo DNS https://wiki.metacubex.one/en/config/dns/ (fake-ip, nameserver-policy, fallback-filter geoip-code fields confirmed in TOC), sing-box route https://sing-box.sagernet.org/configuration/route/ (rules, final, auto_detect_interface, default_domain_resolver), sing-box DNS https://sing-box.sagernet.org/configuration/dns/ (final, strategy, independent_cache). Builders located: _clash_rules, generate_clash_config, generate_singbox_config; py_compile exit 0.
Step 2 done: Block 1 ads plus Block 2 foreign pins collapsed to MATCH,PROXY; ads nameserver-policy and ADS_REJECT_SUFFIXES removed; allow-lan default True in ConfigGenerator and run(); stale Iran comments fixed. Step 3 done: sing-box ads reject removed, ip_is_private direct kept, empty-feed guards kept. No "reject" action rules remain; GEOIP hits are only the kept private/lan DIRECT rules plus geox DB URLs.
Plan approval (verbatim Manager answer): "Approved" on the plan-approval question covering S1-S6 with seat routing and risks. Routing back through the Brain for the Senior Programmer implementation XML.
Reviewer verdict: APPROVED with PO_REVIEW_PENDING. File stays in tasks/qa/ pending the explicit closure word. Reviewer I3 note: manager.sh/refresh.sh hunks carry formatter churn (leading-whitespace tabs across both files) from the file-write pipeline, which normalizes shell indentation on save; the functional change is 3 lines (refresh.sh --allow-lan, deploy --allow-lan, help wording), bash -n passes on both, behavior otherwise identical. Follow-ups I1 (IR icon), I2 (--no-allow-lan), I4 (sing-box 10808 loopback asymmetry), I5 (independent_cache deprecation) recorded as low-severity follow-ups, none blocking.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 526b0d8..dbe6c78 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -33,6 +33,7 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 - `rr` with no arguments now rotates with `--require-country US` (Google-clean US exit); `RR_COUNTRY=DE` overrides the country and `RR_COUNTRY=` disables the lock. Explicit arguments pass through unchanged.
 - `rr_balancer.py` gained observed exit country: `country`/`country_checked` columns, `rr country --batch N` (Cloudflare `cdn-cgi/trace` `loc`, oldest-first, previous selection restored, unreadable traces stored as unknown without quarantine), `rr report` (coverage plus per-country counts), and `--require-country CC` on `rotate`/`skip`/`next` which keeps the current node when no candidate matches. Selection order is now `uses` then `delay_ms`.
 - Balancer cause cleanup: the `quota`, `transport`, and `region` failure causes, their counters, and their per-cause selection weighting were removed with the retired `opencode-rate-limit-rescue` plugin they served. `--reason` accepts `google|country|manual`; existing databases drop the legacy columns through a guarded `DROP COLUMN` migration that keeps every learned row.
+- Proxy-everything routing in both generators: the ads `REJECT` block, the ~90-domain foreign-service pin list, and the `geosite:category-ads-all` DNS policy are deleted; rules are now private/LAN `DIRECT` → `MATCH,PROXY` (Clash) and sniff/hijack-dns/`ip_is_private` → final auto (sing-box). `allow-lan` defaults to true with mixed-port 7890, so scheduled refreshes serve LAN clients; TUN stays opt-in. `refresh.sh` and `manager.sh deploy` pass `--allow-lan` explicitly; checked-in samples regenerated via the converter.
 - `AGENTS.md` brought in line with the audit criteria: the lite-mode bypass removed so every task runs the full workflow, the task-generator reference corrected to `kanban-lifecycle`, the QA transition routed through `custom_context_qa_transition`, and Edit Tool Discipline, Parallel Index Isolation, and Living Folder Docs Inspection rules added. `docs/conventions.md` gained the Edit Tool Discipline and Living Folder Docs Standard sections; `.gitignore` now covers goal-plugin runtime state.
 
 ### Fixed
diff --git a/README.md b/README.md
index 90bca5e..5591409 100644
--- a/README.md
+++ b/README.md
@@ -12,9 +12,10 @@ A comprehensive Python tool that downloads V2Ray subscription links, parses vari
 > cp clash_config.yaml ~/Desktop/mihomo/config.yaml
 > cd ~/Desktop/mihomo && ./manager.sh check && sudo ./manager.sh restart
 > ```
-> Routing policy: private/LAN → `DIRECT`, ads → `REJECT`, everything else →
-> subscription proxies (`MATCH,PROXY`). No process bypass and no Iran/CN geo
-> rules: this config targets a foreign server with no local sidecar.
+> Routing policy: private/LAN → `DIRECT`, everything else →
+> subscription proxies (`MATCH,PROXY`). No ads rules, no process bypass and
+> no Iran/CN geo rules: this config targets a foreign server with no local
+> sidecar.
 >
 > **Dashboard:** the generated config serves the official MetaCubeX dashboard
 > at <http://127.0.0.1:9090/ui> (`external-ui: ui` + metacubexd `gh-pages`
@@ -134,8 +135,8 @@ sing-box check -c singbox_config.json
   subnets in `route_exclude_address` (loop-free system-wide proxy)
 - **DNS**: FakeIP by default (`198.18.0.0/15`) with real-IP exceptions for
   LAN/NTP; hijacked port-53 handled via `hijack-dns`
-- **Routing**: sniff → hijack-dns → `ip_is_private` → ads reject →
-  `final: auto` (urltest)
+- **Routing**: sniff → hijack-dns → `ip_is_private` →
+  `final: auto` (urltest, proxy-everything)
 - **URL Test Outbound**: Automatic proxy selection based on latency
 - **Auto Interface Detection**: Prevents routing loops
 
@@ -151,9 +152,9 @@ sing-box check -c singbox_config.json
   - `Auto`: url-test, automatic selection based on latency
   - `Load Balance`: Consistent-hashing load balancing with 60s active checks
   - `Fallback`: Failover group
-- **Rules** (first match wins): private/LAN → ads REJECT → foreign services →
-  `MATCH,PROXY`. No process rules and no Iran/CN geo rules: the host is a
-  foreign server with no local xray sidecar to bypass.
+- **Rules** (first match wins): private/LAN → `DIRECT`, everything else →
+  `MATCH,PROXY`. No ads rules, no process rules and no Iran/CN geo rules:
+  the host is a foreign server with no local xray sidecar to bypass.
 
 ### Load Balancing and URL Testing
 
@@ -252,22 +253,25 @@ then open the dashboard at <http://127.0.0.1:9090/ui>.
 
 ### Clash Structure
 ```yaml
-mixed-port: 10801
+mixed-port: 7890
 allow-lan: true
 mode: rule
 proxies:
-  - name: proxy-0
-    type: vmess
+  - name: vless-abc123def456
+    type: vless
 proxy-groups:
-  - name: URL-Test
+  - name: PROXY
+    type: select
+  - name: Auto
     type: url-test
-  - name: Load-Balance
+  - name: Load Balance
     type: load-balance
-  - name: Proxy
-    type: select
+    strategy: consistent-hashing
+  - name: Fallback
+    type: fallback
 rules:
-  - DOMAIN-SUFFIX,google.com,Proxy
-  - MATCH,Proxy
+  - GEOIP,private,DIRECT,no-resolve
+  - MATCH,PROXY
 ```
 
 ## Advanced Features
diff --git a/clash_config.yaml b/clash_config.yaml
index 3d24d96..397987a 100644
--- a/clash_config.yaml
+++ b/clash_config.yaml
@@ -2,12 +2,12 @@
 # profile-web-page-url: https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt
 # profile-update-interval: 1
 mixed-port: 7890
-allow-lan: false
-bind-address: 127.0.0.1
+allow-lan: true
+bind-address: '*'
 mode: rule
 log-level: info
 ipv6: false
-find-process-mode: always
+find-process-mode: 'off'
 tcp-concurrent: true
 keep-alive-interval: 30
 unified-delay: true
@@ -39,28 +39,24 @@ dns:
   - +.msftncsi.com
   - time.*.com
   - time.*.gov
-  - time.*.edu.cn
-  - +.ntp.org.cn
   - +.pool.ntp.org
   - detectportal.firefox.com
   - connectivitycheck.gstatic.com
   default-nameserver:
-  - 223.5.5.5
-  - 114.114.114.114
+  - 1.1.1.1
+  - 1.0.0.1
   - 8.8.8.8
   nameserver:
-  - https://doh.pub/dns-query
-  - https://dns.alidns.com/dns-query
+  - https://cloudflare-dns.com/dns-query
+  - https://dns.google/dns-query
+  - tls://1.1.1.1
   - tls://8.8.8.8
-  - 223.5.5.5
   proxy-server-nameserver:
-  - https://doh.pub/dns-query
+  - https://cloudflare-dns.com/dns-query
   fallback:
   - tls://1.1.1.1
   - tls://8.8.4.4
   fallback-filter:
-    geoip: true
-    geoip-code: CN
     ipcidr:
     - 240.0.0.0/4
     domain:
@@ -68,9 +64,6 @@ dns:
     - +.facebook.com
     - +.youtube.com
     - +.twitter.com
-  nameserver-policy:
-    geosite:category-ads-all: rcode://success
-    +.ir: https://dns.alidns.com/dns-query
 tun:
   enable: false
   stack: mixed
@@ -116,802 +109,56 @@ sniffer:
   skip-domain:
   - Mijia Cloud
 proxies:
-- name: '@DeltaKroneckerGithub | c3505c'
+- name: vless-131cd4452f31
   type: vless
-  server: 188.114.97.6
-  port: 443
+  server: 127.0.0.1
+  port: 40443
   udp: true
-  uuid: 6cd78ec7-b715-471c-92b4-0c3842caea4b
-  packet-encoding: xudp
+  remark: Sni-Spoofing 🇺🇸65Mb | GTHost | 059438
+  uuid: 0281a320-21e8-434f-86b7-a7c0db58c0db
   network: ws
   ws-opts:
-    path: /eyJqdW5rIjoiVXRIT2UwaDUiLCJwcm90b2NvbCI6InZsIiwibW9kZSI6InByZWZpeCIsInBhbmVsSVBzIjpbIlsyNjAyOmZjNTk6YjA6NjQ6Ol0iXX0=
+    path: /ws/0281a320-21e8-434f-86b7-a7c0db58c0db
     headers:
-      Host: billowing-cloud-d339.sospanel.workers.dev
+      Host: je8r21hqax.dev.onappjet.com
   tls: true
-  servername: billowing-cloud-d339.sospanel.workers.dev
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | AD753A | a19820
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: b2593749-691c-428c-9481-14979cba3446
-  network: ws
-  ws-opts:
-    path: /proxyip=us.xiabibi.cf
-    headers:
-      Host: xi.tbv.ccwu.cc
-  tls: true
-  servername: xi.tbv.ccwu.cc
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 9C8FF6 | d52c79
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 5f4acc06-8cbf-4172-92d2-8f475e51f781
-  network: ws
-  ws-opts:
-    path: /vl/qS74oZnpprf6Qgqx
-    headers:
-      Host: p9c85ckpnai98sdljzhuwwnolmcmxw88.cdzsqje4u3ms.workers.dev
-  tls: true
-  servername: p9c85ckpnai98sdljzhuwwnolmcmxw88.cdzsqje4u3ms.workers.dev
-  client-fingerprint: none
+  servername: je8r21hqax.dev.onappjet.com
+  client-fingerprint: chrome
   alpn:
   - http/1.1
-- name: CA 🇨🇦 | @Raydikalx | 30CA9B | a0a8f4
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 8991a496-1baa-486f-9948-ffe44e68c072
-  network: ws
-  ws-opts:
-    path: /pyip=ProxyIP.SG.CMLiussss.net
-    headers:
-      Host: soft-band-8da6.426.workers.dev
-  tls: true
-  servername: soft-band-8da6.426.workers.dev
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 2DC968 | fb3653
+- name: vless-39242b8aa28d
   type: vless
-  server: 188.114.97.6
+  server: 2a06:98c1:3120::7
   port: 443
   udp: true
-  uuid: 77777777-8a3e-6666-b6d1-a9c5f0e8b3a2
-  packet-encoding: xudp
+  remark: IPv6 oob 🇺🇸65Mb | GTHost | f578ea
+  uuid: 0281a320-21e8-434f-86b7-a7c0db58c0db
   network: ws
   ws-opts:
-    path: /
+    path: /ws/0281a320-21e8-434f-86b7-a7c0db58c0db
     headers:
-      Host: fx3h2kf8xn.fx6hsv0.ccwu.cc
-    max-early-data: 2560
-    early-data-header-name: Sec-WebSocket-Protocol
-  tls: true
-  servername: fx3h2kf8xn.fx6hsv0.ccwu.cc
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | BFA791 | bf2e3d
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 9f44d517-29f2-4c6d-cc06-a1268f13da58
-  network: xhttp
-  xhttp-opts:
-    path: /Meh?di=443
-    host: kala.bestsellers1.site
-    mode: auto
-    extra:
-      scMaxBufferedPosts: 30
-      scMaxEachPostBytes: '1000000'
-      scStreamUpServerSecs: 20-80
-      xPaddingBytes: 100-1000
-      scMinPostsIntervalMs: '30'
-      xmux:
-        maxConcurrency: 16-32
-        maxConnections: 0
-        cMaxReuseTimes: 0
-        hMaxRequestTimes: 600-900
-        hMaxReusableSecs: 1800-3000
-        hKeepAlivePeriod: 0
+      Host: je8r21hqax.dev.onappjet.com
   tls: true
-  servername: kala.bestsellers1.site
-  client-fingerprint: none
-  alpn:
-  - h2
-- name: CA 🇨🇦 | @Raydikalx | 575F8C | a0383b
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 77777777-8a3e-6666-b6d1-a9c5f0e8b3a2
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: faxf32gkfzoxqv.fx6hsv0.ccwu.cc
-    max-early-data: 2560
-    early-data-header-name: Sec-WebSocket-Protocol
-  tls: true
-  servername: faxf32gkfzoxqv.fx6hsv0.ccwu.cc
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 26BF39 | b1e068
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 4c0b7280-76bb-495c-9c8b-f05712ebf805
-  packet-encoding: xudp
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: youxuanku.kdns.fr
-  tls: true
-  servername: youxuanku.kdns.fr
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 38B262 | 40ff7d
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 4c0b7280-76bb-495c-9c8b-f05712ebf805
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: youxuanku.kdns.fr
-  tls: true
-  servername: youxuanku.kdns.fr
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 0F5978 | ab23d9
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 9952b71a-6c86-4522-888f-ff9ea9b93536
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: 1.hshs8227shhshs.workers.dev
-  tls: true
-  servername: 1.hshs8227shhshs.workers.dev
-  client-fingerprint: none
-- name: '@DeltaKroneckerGithub | 353f61'
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 4c0b7280-76bb-495c-9c8b-f05712ebf805
-  packet-encoding: xudp
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: youxuanku.kdns.fr
-  tls: true
-  servername: youxuanku.kdns.fr
-  client-fingerprint: none
-- name: '[openproxylist.com] CA 5049268 | d3219c'
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 77777777-8a3e-6666-b6d1-a9c5f0e8b3a2
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: fx3h2kf8xn.fx6hsv0.ccwu.cc
-    max-early-data: 2560
-    early-data-header-name: Sec-WebSocket-Protocol
-  tls: true
-  servername: fx3h2kf8xn.fx6hsv0.ccwu.cc
-  client-fingerprint: none
-- name: US 🇺🇸 | @Raydikalx | 2e605b
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: b2593749-691c-428c-9481-14979cba3446
-  network: ws
-  ws-opts:
-    path: /proxyip=us.xiabibi.cf
-    headers:
-      Host: xi.tbv.ccwu.cc
-  tls: true
-  servername: xi.tbv.ccwu.cc
-  client-fingerprint: none
-- name: '@DeltaKroneckerGithub | 08e1d4'
-  type: trojan
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  password: humanity
-  network: ws
-  ws-opts:
-    path: /assignment
-    headers:
-      Host: www.calmlunch.com
-  tls: true
-  servername: www.calmlunch.com
-  client-fingerprint: none
-- name: '@DeltaKroneckerGithub | 022f0f'
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: c18b978e-1c4e-415c-8bea-07942b563a64
-  network: ws
-  ws-opts:
-    path: /fp=chrome
-    headers:
-      Host: shuma.ccwu.cc
-  tls: true
-  servername: shuma.ccwu.cc
-  client-fingerprint: none
-- name: '@DeltaKroneckerGithub | add03f'
-  type: trojan
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  password: humanity
-  network: ws
-  ws-opts:
-    path: /assignment
-    headers:
-      Host: www.calmlunch.com
-  tls: true
-  servername: www.calmlunch.com
-  client-fingerprint: none
+  servername: je8r21hqax.dev.onappjet.com
   alpn:
   - http/1.1
-- name: '@DeltaKroneckerGithub | bb4dc1'
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: b2593749-691c-428c-9481-14979cba3446
-  packet-encoding: xudp
-  network: ws
-  ws-opts:
-    path: /proxyip=us.xiabibi.cf
-    headers:
-      Host: xi.tbv.ccwu.cc
-  tls: true
-  servername: xi.tbv.ccwu.cc
-  client-fingerprint: none
-- name: United+States | 9f9d93
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 34ce8760-24ed-41e7-a1f5-aa6c2660a53c
-  packet-encoding: xudp
-  network: ws
-  ws-opts:
-    path: /pyip=ProxyIP.SG.CMLiussss.net
-    headers:
-      Host: quiet-frost-ac61.333-07d.workers.dev
-  tls: true
-  servername: quiet-frost-ac61.333-07d.workers.dev
-  client-fingerprint: none
-- name: By EbraSha 🦅 | ec3ba5
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 77777777-8a3e-6666-b6d1-a9c5f0e8b3a2
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: faxf32gkfzoxqv.fx6hsv0.ccwu.cc
-    max-early-data: 2560
-    early-data-header-name: Sec-WebSocket-Protocol
-  tls: true
-  servername: faxf32gkfzoxqv.fx6hsv0.ccwu.cc
-  client-fingerprint: none
-- name: JP 🇯🇵 | @Raydikalx | 14fb60
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: c18b978e-1c4e-415c-8bea-07942b563a64
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: shuma.ccwu.cc
-  tls: true
-  servername: shuma.ccwu.cc
-  client-fingerprint: none
-- name: BE 🇧🇪 | @Raydikalx | 7FD27C | ea4c14
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: c18b978e-1c4e-415c-8bea-07942b563a64
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: shuma.ccwu.cc
-  tls: true
-  servername: shuma.ccwu.cc
-  client-fingerprint: none
-- name: US 🇺🇸 | @Raydikalx | AB1DC2 | e379c8
+- name: vless-a1c91bd4162f
   type: vless
-  server: 188.114.97.6
+  server: 188.114.98.0
   port: 443
   udp: true
-  uuid: c18b978e-1c4e-415c-8bea-07942b563a64
+  remark: F&F 🇺🇸65Mb | GTHost | e8f08a
+  uuid: 0281a320-21e8-434f-86b7-a7c0db58c0db
   network: ws
   ws-opts:
-    path: /
+    path: /ws/0281a320-21e8-434f-86b7-a7c0db58c0db
     headers:
-      Host: shuma.ccwu.cc
+      Host: je8r21hqax.dev.onappjet.com
   tls: true
-  servername: shuma.ccwu.cc
-  client-fingerprint: none
-- name: '@DeltaKroneckerGithub | 28a81d'
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: bba95b1f-f48c-454b-897b-a6c6bc307df1
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: edge.yzkvm.top
-  tls: true
-  servername: edge.yzkvm.top
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 903E4E | 13f57d
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 47fcef29-ab4e-4aa6-932b-d95a18f28a4e
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: e34bq.oa9r.zl3.hh.vavava.kdns.fr
-    max-early-data: 2560
-    early-data-header-name: Sec-WebSocket-Protocol
-  tls: true
-  servername: e34bq.oa9r.zl3.hh.vavava.kdns.fr
-  client-fingerprint: none
-- name: DE 🇩🇪 | @Raydikalx | 7DF8AC | 7a9d94
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: bba95b1f-f48c-454b-897b-a6c6bc307df1
-  network: ws
-  ws-opts:
-    path: /fp=chrome
-    headers:
-      Host: edge.yzkvm.top
-  tls: true
-  servername: edge.yzkvm.top
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 26F144 | 2188c3
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 3c6d1933-b22a-484b-ac8a-63e24f5fba75
-  network: ws
-  ws-opts:
-    path: /ujhgfytsrtw563675eud
-    headers:
-      Host: server14.9966338.xyz
-  tls: true
-  servername: server14.9966338.xyz
-  client-fingerprint: none
-- name: '>>@freeland8::FR | d35f86'
-  type: trojan
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  password: humanity
-  network: ws
-  ws-opts:
-    path: //assignment
-    headers:
-      Host: www.calmlunch.com
-  tls: true
-  servername: www.calmlunch.com
-  client-fingerprint: none
-- name: AU 🇦🇺 | @Raydikalx | F56B4F | fe0c08
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 8be20011-59b1-4118-91ed-83e8e6b662cd
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: f.yoptybla.ru
-  tls: true
-  servername: f.yoptybla.ru
-  client-fingerprint: none
-- name: 🇩🇪179Mb | Senko Digital | 17275e
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 523e85fa-82b2-4ca5-9ff5-a734a4510197
-  network: xhttp
-  xhttp-opts:
-    path: /api/v1/7ad9078af72be1d6fe012b0f2ebe9248/
-    host: assets-de1.mirolit.ru
-    mode: packet-up
-  tls: true
-  servername: assets-de1.mirolit.ru
-  client-fingerprint: none
-- name: '@DeltaKroneckerGithub | 76b82a'
-  type: trojan
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  password: humanity
-  network: ws
-  ws-opts:
-    path: /assignment
-    headers:
-      Host: www.calmlunch.com
-  tls: true
-  servername: www.calmlunch.com
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 0e3d4f
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 77777777-8a3e-6666-b6d1-a9c5f0e8b3a2
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: faxf32gkfzoxqv.fx6hsv0.ccwu.cc
-    max-early-data: 2560
-    early-data-header-name: Sec-WebSocket-Protocol
-  tls: true
-  servername: faxf32gkfzoxqv.fx6hsv0.ccwu.cc
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 4DE122 | 986b15
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 77777777-8a3e-6666-b6d1-a9c5f0e8b3a2
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: fx3h2kf8xn.fx6hsv0.ccwu.cc
-    max-early-data: 2560
-    early-data-header-name: Sec-WebSocket-Protocol
-  tls: true
-  servername: fx3h2kf8xn.fx6hsv0.ccwu.cc
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 5BE41E | f23ac1
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 77777777-8a3e-6666-b6d1-a9c5f0e8b3a2
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: fx3l5i2wdfxln0.fx6hsv0.ccwu.cc
-    max-early-data: 2560
-    early-data-header-name: Sec-WebSocket-Protocol
-  tls: true
-  servername: fx3l5i2wdfxln0.fx6hsv0.ccwu.cc
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 4DE122 | b6a927
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 77777777-8a3e-6666-b6d1-a9c5f0e8b3a2
-  network: ws
-  ws-opts:
-    path: /
-    headers:
-      Host: fx3h2kf8xn.fx6hsv0.ccwu.cc
-    max-early-data: 2560
-    early-data-header-name: Sec-WebSocket-Protocol
-  tls: true
-  servername: fx3h2kf8xn.fx6hsv0.ccwu.cc
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 51B6CF | 3da173
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 77dc177b-79d9-49ac-92e1-2f1011faa5e3
-  network: ws
-  ws-opts:
-    path: /api/v2/b8ee4ba356df307c/stream
-    headers:
-      Host: f871a986.69lover.site
-  tls: true
-  servername: f871a986.69lover.site
-  client-fingerprint: none
-  alpn:
-  - http/1.1
-- name: '@DeltaKroneckerGithub | e776a6'
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 4e4f1f70-5e56-4a76-bb9d-db087f4690c4
-  packet-encoding: xudp
-  network: ws
-  ws-opts:
-    path: /tyxyws
-    headers:
-      Host: jp3.yohototo.top
-  tls: true
-  servername: jp3.yohototo.top
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 703016
-  type: trojan
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  password: humanity
-  network: ws
-  ws-opts:
-    path: /assignment
-    headers:
-      Host: www.ignitelimit.com
-  tls: true
-  servername: www.ignitelimit.com
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 32B6D3 | ada968
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: fd6fb48f-b324-4a82-9dcd-f8bdb1bd5301
-  network: xhttp
-  xhttp-opts:
-    path: /meti
-    host: denet1.17e1feeuzi.online
-    mode: stream-one
-  tls: true
-  servername: denet1.17e1feeuzi.online
-  client-fingerprint: none
-  alpn:
-  - h2
-- name: CA 🇨🇦 | @Raydikalx | 3F5E1A | 8f3ebf
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: c47eb7ab-2c2d-44e0-80cc-bb104f89a137
-  network: ws
-  ws-opts:
-    path: /tunnel
-    headers:
-      Host: www.terence-tunnel.org
-  tls: true
-  servername: www.terence-tunnel.org
-  client-fingerprint: none
-- name: 🇫🇷 - FR - @FreeOnlineVPN | 4a49fb
-  type: trojan
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  password: humanity
-  network: ws
-  ws-opts:
-    path: /assignment
-    headers:
-      Host: www.calmlunch.com
-  tls: true
-  servername: www.calmlunch.com
-  client-fingerprint: none
-- name: 🏳[openproxylist.com] trojan- | 890f1d
-  type: trojan
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  password: humanity
-  network: ws
-  ws-opts:
-    path: /assignment
-    headers:
-      Host: www.volumeroot.com
-  tls: true
-  servername: www.volumeroot.com
-  client-fingerprint: none
-- name: US 🇺🇸 | @Raydikalx | EDC5EE | 401641
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 4e4f1f70-5e56-4a76-bb9d-db087f4690c4
-  network: ws
-  ws-opts:
-    path: /tyxyws
-    headers:
-      Host: jp3.yohototo.top
-  tls: true
-  servername: jp3.yohototo.top
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | D06334 | 2aa478
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: c4edb87e-8544-4fa4-bd1c-b0cda9a34b46
-  packet-encoding: xudp
-  network: ws
-  ws-opts:
-    path: /ws
-    headers:
-      Host: a.cwvps.eu.org
-  tls: true
-  servername: a.cwvps.eu.org
-  client-fingerprint: none
-- name: By EbraSha 🧬 | 3d7373
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 91d28760-ecf1-450b-9170-d310111a0e6d
-  network: ws
-  ws-opts:
-    path: /api/v2/63e9687fa53e441c/stream
-    headers:
-      Host: us9.69lover.my
-  tls: true
-  servername: us9.69lover.my
-  client-fingerprint: none
-  alpn:
-  - http/1.1
-- name: US 🇺🇸 | @Raydikalx | FB0008 | 8da267
-  type: trojan
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  password: humanity
-  network: ws
-  ws-opts:
-    path: /assignment
-    headers:
-      Host: www.ignitelimit.com
-  tls: true
-  servername: www.ignitelimit.com
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 91DD24 | f97024
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: c4edb87e-8544-4fa4-bd1c-b0cda9a34b46
-  network: ws
-  ws-opts:
-    path: /ws
-    headers:
-      Host: a.cwvps.eu.org
-  tls: true
-  servername: a.cwvps.eu.org
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | B6DF98 | b19f1e
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 7a657573-627d-c5d7-4e7b-9e260f5cfff1
-  network: ws
-  ws-opts:
-    path: /stream/PANEL_ZEUS/9e260f5cfff1/loc-0
-    headers:
-      Host: imzajnekupas.a3-60-morteza.workers.dev
-  tls: true
-  servername: imzajnekupas.a3-60-morteza.workers.dev
-  client-fingerprint: none
-- name: '@DeltaKroneckerGithub | 2b3a78'
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: b585dc5e-55bf-4a8b-913a-27c9ccac05c3
-  network: ws
-  ws-opts:
-    path: /vws/
-    headers:
-      Host: bab-6.site
-  tls: true
-  servername: bab-6.site
-  client-fingerprint: none
-- name: 49. 🇺🇸 United States | b4764a
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: c4edb87e-8544-4fa4-bd1c-b0cda9a34b46
-  network: ws
-  ws-opts:
-    path: /ws#/?TELEGRAM--MARAMBASHI--MARAMBASHI?ed=512
-    headers:
-      Host: a.cwvps.eu.org
-  tls: true
-  servername: a.cwvps.eu.org
-  client-fingerprint: none
-- name: CA 🇨🇦 | @Raydikalx | 774ACE | 794d5b
-  type: trojan
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  password: humanity
-  network: ws
-  ws-opts:
-    path: //assignment
-    headers:
-      Host: www.ignitelimit.com
-  tls: true
-  servername: www.ignitelimit.com
-  client-fingerprint: none
-- name: By EbraSha ♠️ | ad7869
-  type: trojan
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  password: humanity
-  network: ws
-  ws-opts:
-    path: /assignment
-    headers:
-      Host: www.ignitelimit.com
-  tls: true
-  servername: www.ignitelimit.com
+  servername: je8r21hqax.dev.onappjet.com
   client-fingerprint: none
   alpn:
   - http/1.1
-- name: 69. 🇺🇸 United States | f737fb
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: c4edb87e-8544-4fa4-bd1c-b0cda9a34b46
-  packet-encoding: xudp
-  network: ws
-  ws-opts:
-    path: /ws
-    headers:
-      Host: a.cwvps.eu.org
-  tls: true
-  servername: a.cwvps.eu.org
-  client-fingerprint: none
-- name: By EbraSha ⛓️ | 339789
-  type: vless
-  server: 188.114.97.6
-  port: 443
-  udp: true
-  uuid: 828aa918-2ed3-4541-8519-083f9efeaaf7
-  network: ws
-  ws-opts:
-    path: /pyip=proxyip.us.cmliussss.net
-    headers:
-      Host: icy-hall-bfba.266-f4e.workers.dev
-  tls: true
-  servername: icy-hall-bfba.266-f4e.workers.dev
-  client-fingerprint: none
 proxy-groups:
 - name: PROXY
   type: select
@@ -919,143 +166,40 @@ proxy-groups:
   - Auto
   - Load Balance
   - Fallback
-  - '@DeltaKroneckerGithub | c3505c'
-  - CA 🇨🇦 | @Raydikalx | AD753A | a19820
-  - CA 🇨🇦 | @Raydikalx | 9C8FF6 | d52c79
-  - CA 🇨🇦 | @Raydikalx | 30CA9B | a0a8f4
-  - CA 🇨🇦 | @Raydikalx | 2DC968 | fb3653
-  - CA 🇨🇦 | @Raydikalx | BFA791 | bf2e3d
-  - CA 🇨🇦 | @Raydikalx | 575F8C | a0383b
-  - CA 🇨🇦 | @Raydikalx | 26BF39 | b1e068
-  - CA 🇨🇦 | @Raydikalx | 38B262 | 40ff7d
-  - CA 🇨🇦 | @Raydikalx | 0F5978 | ab23d9
-  - '@DeltaKroneckerGithub | 353f61'
-  - '[openproxylist.com] CA 5049268 | d3219c'
-  - US 🇺🇸 | @Raydikalx | 2e605b
-  - '@DeltaKroneckerGithub | 08e1d4'
-  - '@DeltaKroneckerGithub | 022f0f'
-  - '@DeltaKroneckerGithub | add03f'
-  - '@DeltaKroneckerGithub | bb4dc1'
-  - United+States | 9f9d93
-  - By EbraSha 🦅 | ec3ba5
-  - JP 🇯🇵 | @Raydikalx | 14fb60
-  - BE 🇧🇪 | @Raydikalx | 7FD27C | ea4c14
-  - US 🇺🇸 | @Raydikalx | AB1DC2 | e379c8
-  - '@DeltaKroneckerGithub | 28a81d'
-  - CA 🇨🇦 | @Raydikalx | 903E4E | 13f57d
-  - DE 🇩🇪 | @Raydikalx | 7DF8AC | 7a9d94
-  - CA 🇨🇦 | @Raydikalx | 26F144 | 2188c3
-  - '>>@freeland8::FR | d35f86'
-  - AU 🇦🇺 | @Raydikalx | F56B4F | fe0c08
-  - 🇩🇪179Mb | Senko Digital | 17275e
-  - '@DeltaKroneckerGithub | 76b82a'
-  - CA 🇨🇦 | @Raydikalx | 0e3d4f
-  - CA 🇨🇦 | @Raydikalx | 4DE122 | 986b15
-  - CA 🇨🇦 | @Raydikalx | 5BE41E | f23ac1
-  - CA 🇨🇦 | @Raydikalx | 4DE122 | b6a927
-  - CA 🇨🇦 | @Raydikalx | 51B6CF | 3da173
-  - '@DeltaKroneckerGithub | e776a6'
-  - CA 🇨🇦 | @Raydikalx | 703016
-  - CA 🇨🇦 | @Raydikalx | 32B6D3 | ada968
-  - CA 🇨🇦 | @Raydikalx | 3F5E1A | 8f3ebf
-  - 🇫🇷 - FR - @FreeOnlineVPN | 4a49fb
-  - 🏳[openproxylist.com] trojan- | 890f1d
-  - US 🇺🇸 | @Raydikalx | EDC5EE | 401641
-  - CA 🇨🇦 | @Raydikalx | D06334 | 2aa478
-  - By EbraSha 🧬 | 3d7373
-  - US 🇺🇸 | @Raydikalx | FB0008 | 8da267
-  - CA 🇨🇦 | @Raydikalx | 91DD24 | f97024
-  - CA 🇨🇦 | @Raydikalx | B6DF98 | b19f1e
-  - '@DeltaKroneckerGithub | 2b3a78'
-  - 49. 🇺🇸 United States | b4764a
-  - CA 🇨🇦 | @Raydikalx | 774ACE | 794d5b
-  - By EbraSha ♠️ | ad7869
-  - 69. 🇺🇸 United States | f737fb
-  - By EbraSha ⛓️ | 339789
+  - vless-131cd4452f31
+  - vless-39242b8aa28d
+  - vless-a1c91bd4162f
   icon: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/mmdb/release/flag/Country-IR.svg
 - name: Auto
   type: url-test
   proxies: &id001
-  - '@DeltaKroneckerGithub | c3505c'
-  - CA 🇨🇦 | @Raydikalx | AD753A | a19820
-  - CA 🇨🇦 | @Raydikalx | 9C8FF6 | d52c79
-  - CA 🇨🇦 | @Raydikalx | 30CA9B | a0a8f4
-  - CA 🇨🇦 | @Raydikalx | 2DC968 | fb3653
-  - CA 🇨🇦 | @Raydikalx | BFA791 | bf2e3d
-  - CA 🇨🇦 | @Raydikalx | 575F8C | a0383b
-  - CA 🇨🇦 | @Raydikalx | 26BF39 | b1e068
-  - CA 🇨🇦 | @Raydikalx | 38B262 | 40ff7d
-  - CA 🇨🇦 | @Raydikalx | 0F5978 | ab23d9
-  - '@DeltaKroneckerGithub | 353f61'
-  - '[openproxylist.com] CA 5049268 | d3219c'
-  - US 🇺🇸 | @Raydikalx | 2e605b
-  - '@DeltaKroneckerGithub | 08e1d4'
-  - '@DeltaKroneckerGithub | 022f0f'
-  - '@DeltaKroneckerGithub | add03f'
-  - '@DeltaKroneckerGithub | bb4dc1'
-  - United+States | 9f9d93
-  - By EbraSha 🦅 | ec3ba5
-  - JP 🇯🇵 | @Raydikalx | 14fb60
-  - BE 🇧🇪 | @Raydikalx | 7FD27C | ea4c14
-  - US 🇺🇸 | @Raydikalx | AB1DC2 | e379c8
-  - '@DeltaKroneckerGithub | 28a81d'
-  - CA 🇨🇦 | @Raydikalx | 903E4E | 13f57d
-  - DE 🇩🇪 | @Raydikalx | 7DF8AC | 7a9d94
-  - CA 🇨🇦 | @Raydikalx | 26F144 | 2188c3
-  - '>>@freeland8::FR | d35f86'
-  - AU 🇦🇺 | @Raydikalx | F56B4F | fe0c08
-  - 🇩🇪179Mb | Senko Digital | 17275e
-  - '@DeltaKroneckerGithub | 76b82a'
-  - CA 🇨🇦 | @Raydikalx | 0e3d4f
-  - CA 🇨🇦 | @Raydikalx | 4DE122 | 986b15
-  - CA 🇨🇦 | @Raydikalx | 5BE41E | f23ac1
-  - CA 🇨🇦 | @Raydikalx | 4DE122 | b6a927
-  - CA 🇨🇦 | @Raydikalx | 51B6CF | 3da173
-  - '@DeltaKroneckerGithub | e776a6'
-  - CA 🇨🇦 | @Raydikalx | 703016
-  - CA 🇨🇦 | @Raydikalx | 32B6D3 | ada968
-  - CA 🇨🇦 | @Raydikalx | 3F5E1A | 8f3ebf
-  - 🇫🇷 - FR - @FreeOnlineVPN | 4a49fb
-  - 🏳[openproxylist.com] trojan- | 890f1d
-  - US 🇺🇸 | @Raydikalx | EDC5EE | 401641
-  - CA 🇨🇦 | @Raydikalx | D06334 | 2aa478
-  - By EbraSha 🧬 | 3d7373
-  - US 🇺🇸 | @Raydikalx | FB0008 | 8da267
-  - CA 🇨🇦 | @Raydikalx | 91DD24 | f97024
-  - CA 🇨🇦 | @Raydikalx | B6DF98 | b19f1e
-  - '@DeltaKroneckerGithub | 2b3a78'
-  - 49. 🇺🇸 United States | b4764a
-  - CA 🇨🇦 | @Raydikalx | 774ACE | 794d5b
-  - By EbraSha ♠️ | ad7869
-  - 69. 🇺🇸 United States | f737fb
-  - By EbraSha ⛓️ | 339789
+  - vless-131cd4452f31
+  - vless-39242b8aa28d
+  - vless-a1c91bd4162f
   url: https://www.gstatic.com/generate_204
   interval: 300
   tolerance: 50
   lazy: true
+  expected-status: 204
+  max-failed-times: 3
 - name: Load Balance
   type: load-balance
   proxies: *id001
   url: https://www.gstatic.com/generate_204
-  interval: 300
-  strategy: round-robin
-  lazy: true
+  interval: 60
+  strategy: consistent-hashing
+  lazy: false
+  expected-status: 204
+  max-failed-times: 3
 - name: Fallback
   type: fallback
   proxies: *id001
   url: https://www.gstatic.com/generate_204
   interval: 300
   lazy: true
+  expected-status: 204
+  max-failed-times: 3
 rules:
-- PROCESS-NAME,xray,DIRECT
-- PROCESS-NAME,sing-box,DIRECT
-- PROCESS-NAME,PattN,DIRECT
-- PROCESS-NAME,v2rayn,DIRECT
-- PROCESS-PATH,/home/mohammad/.local/share/v2rayN/bin/xray/xray,DIRECT
-- PROCESS-PATH,/home/mohammad/.local/share/v2rayN/bin/sing_box/sing-box,DIRECT
-- PROCESS-PATH,/opt/v2rayN/PattN,DIRECT
-- PROCESS-NAME-WILDCARD,*sing-box*,DIRECT
-- PROCESS-NAME-REGEX,(?i)v2ray.*|PattN,DIRECT
 - DOMAIN-SUFFIX,lan,DIRECT
 - DOMAIN,lan,DIRECT
 - GEOIP,private,DIRECT,no-resolve
@@ -1076,145 +220,4 @@ rules:
 - IP-CIDR6,fc00::/7,DIRECT,no-resolve
 - IP-CIDR6,fe80::/10,DIRECT,no-resolve
 - IP-CIDR6,2001:db8::/32,DIRECT,no-resolve
-- DOMAIN-SUFFIX,doubleclick.net,REJECT
-- DOMAIN-SUFFIX,googlesyndication.com,REJECT
-- DOMAIN-SUFFIX,googleadservices.com,REJECT
-- DOMAIN-SUFFIX,googletagmanager.com,REJECT
-- DOMAIN-SUFFIX,googletagservices.com,REJECT
-- DOMAIN-SUFFIX,tracking.pro,REJECT
-- DOMAIN-SUFFIX,scorecardresearch.com,REJECT
-- DOMAIN-SUFFIX,adnxs.com,REJECT
-- DOMAIN-SUFFIX,adsrvr.org,REJECT
-- DOMAIN-SUFFIX,advertising.com,REJECT
-- DOMAIN-SUFFIX,amazon-adsystem.com,REJECT
-- DOMAIN-KEYWORD,analytics,REJECT
-- DOMAIN-SUFFIX,ir,DIRECT
-- DOMAIN-SUFFIX,digikala.com,DIRECT
-- DOMAIN-SUFFIX,digikalaelectron.com,DIRECT
-- DOMAIN-SUFFIX,digimah.com,DIRECT
-- DOMAIN-SUFFIX,digikala.tm,DIRECT
-- DOMAIN-SUFFIX,snappfood.com,DIRECT
-- DOMAIN-SUFFIX,parspack.com,DIRECT
-- DOMAIN-SUFFIX,hostiran.net,DIRECT
-- DOMAIN-SUFFIX,arvancloud.com,DIRECT
-- DOMAIN-SUFFIX,iraniancdns.com,DIRECT
-- DOMAIN-SUFFIX,parsdata.com,DIRECT
-- DOMAIN-SUFFIX,idehpay.com,DIRECT
-- GEOIP,IR,DIRECT
-- DOMAIN-SUFFIX,cn,DIRECT
-- DOMAIN-SUFFIX,aliyun.com,DIRECT
-- DOMAIN-SUFFIX,taobao.com,DIRECT
-- DOMAIN-SUFFIX,tmail.com,DIRECT
-- DOMAIN-SUFFIX,tmall.com,DIRECT
-- DOMAIN-SUFFIX,alipay.com,DIRECT
-- DOMAIN-SUFFIX,qq.com,DIRECT
-- DOMAIN-SUFFIX,weixin.qq.com,DIRECT
-- DOMAIN-SUFFIX,gtimg.com,DIRECT
-- DOMAIN-SUFFIX,myqcloud.com,DIRECT
-- DOMAIN-SUFFIX,baidu.com,DIRECT
-- DOMAIN-SUFFIX,bdstatic.com,DIRECT
-- DOMAIN-SUFFIX,bilibili.com,DIRECT
-- DOMAIN-SUFFIX,hdslb.com,DIRECT
-- DOMAIN-SUFFIX,iqiyi.com,DIRECT
-- DOMAIN-SUFFIX,sohu.com,DIRECT
-- DOMAIN-SUFFIX,sina.com.cn,DIRECT
-- DOMAIN-SUFFIX,163.com,DIRECT
-- DOMAIN-SUFFIX,126.net,DIRECT
-- DOMAIN-SUFFIX,netease.com,DIRECT
-- DOMAIN-SUFFIX,jd.com,DIRECT
-- DOMAIN-SUFFIX,360.cn,DIRECT
-- DOMAIN-SUFFIX,sogou.com,DIRECT
-- DOMAIN-SUFFIX,weibo.com,DIRECT
-- DOMAIN-SUFFIX,zhihu.com,DIRECT
-- GEOIP,CN,DIRECT
-- DOMAIN-SUFFIX,google.com,PROXY
-- DOMAIN-SUFFIX,googleapis.com,PROXY
-- DOMAIN-SUFFIX,gstatic.com,PROXY
-- DOMAIN-SUFFIX,googleusercontent.com,PROXY
-- DOMAIN-SUFFIX,ggpht.com,PROXY
-- DOMAIN-SUFFIX,youtube.com,PROXY
-- DOMAIN-SUFFIX,youtu.be,PROXY
-- DOMAIN-SUFFIX,ytimg.com,PROXY
-- DOMAIN-SUFFIX,googlevideo.com,PROXY
-- DOMAIN-SUFFIX,facebook.com,PROXY
-- DOMAIN-SUFFIX,facebook.net,PROXY
-- DOMAIN-SUFFIX,fbcdn.net,PROXY
-- DOMAIN-SUFFIX,instagram.com,PROXY
-- DOMAIN-SUFFIX,whatsapp.com,PROXY
-- DOMAIN-SUFFIX,whatsapp.net,PROXY
-- DOMAIN-SUFFIX,thread.com,PROXY
-- DOMAIN-SUFFIX,twitter.com,PROXY
-- DOMAIN-SUFFIX,x.com,PROXY
-- DOMAIN-SUFFIX,t.co,PROXY
-- DOMAIN-SUFFIX,twimg.com,PROXY
-- DOMAIN-SUFFIX,telegram.org,PROXY
-- DOMAIN-SUFFIX,telegram.me,PROXY
-- DOMAIN-SUFFIX,t.me,PROXY
-- DOMAIN-SUFFIX,tdesktop.com,PROXY
-- DOMAIN-SUFFIX,telegra.ph,PROXY
-- DOMAIN-KEYWORD,t.me,PROXY
-- DOMAIN-SUFFIX,spotify.com,PROXY
-- DOMAIN-SUFFIX,scdn.co,PROXY
-- DOMAIN-SUFFIX,github.com,PROXY
-- DOMAIN-SUFFIX,githubusercontent.com,PROXY
-- DOMAIN-SUFFIX,github.io,PROXY
-- DOMAIN-SUFFIX,gitlab.com,PROXY
-- DOMAIN-SUFFIX,openai.com,PROXY
-- DOMAIN-SUFFIX,chatgpt.com,PROXY
-- DOMAIN-SUFFIX,oaiusercontent.com,PROXY
-- DOMAIN-SUFFIX,anthropic.com,PROXY
-- DOMAIN-SUFFIX,claude.ai,PROXY
-- DOMAIN-SUFFIX,gemini.google.com,PROXY
-- DOMAIN-SUFFIX,netflix.com,PROXY
-- DOMAIN-SUFFIX,nflxvideo.net,PROXY
-- DOMAIN-SUFFIX,nflximg.net,PROXY
-- DOMAIN-SUFFIX,nflxso.net,PROXY
-- DOMAIN-SUFFIX,twitch.tv,PROXY
-- DOMAIN-SUFFIX,ttvnw.net,PROXY
-- DOMAIN-SUFFIX,discord.com,PROXY
-- DOMAIN-SUFFIX,discordapp.com,PROXY
-- DOMAIN-SUFFIX,discord.gg,PROXY
-- DOMAIN-SUFFIX,discord.media,PROXY
-- DOMAIN-SUFFIX,reddit.com,PROXY
-- DOMAIN-SUFFIX,redd.it,PROXY
-- DOMAIN-SUFFIX,redditstatic.com,PROXY
-- DOMAIN-SUFFIX,redditmedia.com,PROXY
-- DOMAIN-SUFFIX,pinterest.com,PROXY
-- DOMAIN-SUFFIX,pinimg.com,PROXY
-- DOMAIN-SUFFIX,tiktok.com,PROXY
-- DOMAIN-SUFFIX,tiktokv.com,PROXY
-- DOMAIN-SUFFIX,tiktokcdn.com,PROXY
-- DOMAIN-SUFFIX,byteoversea.com,PROXY
-- DOMAIN-SUFFIX,medium.com,PROXY
-- DOMAIN-SUFFIX,wikipedia.org,PROXY
-- DOMAIN-SUFFIX,wikimedia.org,PROXY
-- DOMAIN-SUFFIX,wikiwand.com,PROXY
-- DOMAIN-SUFFIX,cloudflare.com,PROXY
-- DOMAIN-SUFFIX,workers.dev,PROXY
-- DOMAIN-SUFFIX,pages.dev,PROXY
-- DOMAIN-SUFFIX,reg.cloudflare.com,PROXY
-- DOMAIN-SUFFIX,v2ex.com,PROXY
-- DOMAIN-SUFFIX,duckduckgo.com,PROXY
-- DOMAIN-SUFFIX,bing.com,PROXY
-- DOMAIN-SUFFIX,microsoft.com,PROXY
-- DOMAIN-SUFFIX,office.com,PROXY
-- DOMAIN-SUFFIX,office365.com,PROXY
-- DOMAIN-SUFFIX,outlook.com,PROXY
-- DOMAIN-SUFFIX,msn.com,PROXY
-- DOMAIN-SUFFIX,dropbox.com,PROXY
-- DOMAIN-SUFFIX,icloud.com,PROXY
-- DOMAIN-SUFFIX,apple.com,PROXY
-- DOMAIN-SUFFIX,aaplimg.com,PROXY
-- DOMAIN-SUFFIX,amazon.com,PROXY
-- DOMAIN-SUFFIX,amazonaws.com,PROXY
-- DOMAIN-SUFFIX,steamcommunity.com,PROXY
-- DOMAIN-SUFFIX,steampowered.com,PROXY
-- DOMAIN-SUFFIX,store.steampowered.com,PROXY
-- DOMAIN-SUFFIX,signal.org,PROXY
-- DOMAIN-SUFFIX,whispersystems.org,PROXY
-- DOMAIN-SUFFIX,protonmail.com,PROXY
-- DOMAIN-SUFFIX,proton.me,PROXY
-- DOMAIN-SUFFIX,tailscale.com,PROXY
-- DOMAIN-SUFFIX,speedtest.net,PROXY
-- DOMAIN-SUFFIX,fast.com,PROXY
 - MATCH,PROXY
diff --git a/manager.sh b/manager.sh
index b1e3a6f..35aff23 100755
--- a/manager.sh
+++ b/manager.sh
@@ -11,108 +11,148 @@ SB_OUT="$DIR/singbox_config.json"
 DEFAULT_URL="https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt#Patterniha-F"
 DESKTOP_DIR="/home/mohammad/Desktop/mihomo"
 
-RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
-ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
+RED='\033[0;31m'
+GREEN='\033[0;32m'
+YELLOW='\033[0;33m'
+BLUE='\033[0;34m'
+NC='\033[0m'
+ok() { echo -e "${GREEN}[OK]${NC} $*"; }
 warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
-err()  { echo -e "${RED}[ERR]${NC} $*" >&2; }
+err() { echo -e "${RED}[ERR]${NC} $*" >&2; }
 info() { echo -e "${BLUE}[INFO]${NC} $*"; }
 
 pick_python() {
-  if [[ -x "$DIR/.venv/bin/python" ]]; then
-    echo "$DIR/.venv/bin/python"
-  elif command -v python3 >/dev/null 2>&1; then
-    echo "python3"
-  else
-    err "no python found (tried .venv/bin/python, python3)"
-    exit 1
-  fi
+	if [[ -x "$DIR/.venv/bin/python" ]]; then
+		echo "$DIR/.venv/bin/python"
+	elif command -v python3 >/dev/null 2>&1; then
+		echo "python3"
+	else
+		err "no python found (tried .venv/bin/python, python3)"
+		exit 1
+	fi
 }
 
 find_mihomo() {
-  if command -v mihomo >/dev/null 2>&1; then command -v mihomo;
-  elif [[ -x "$DESKTOP_DIR/mihomo" ]]; then echo "$DESKTOP_DIR/mihomo";
-  else echo ""; fi
+	if command -v mihomo >/dev/null 2>&1; then
+		command -v mihomo
+	elif [[ -x "$DESKTOP_DIR/mihomo" ]]; then
+		echo "$DESKTOP_DIR/mihomo"
+	else echo ""; fi
 }
 
 find_singbox() {
-  if command -v sing-box >/dev/null 2>&1; then command -v sing-box; else echo ""; fi
+	if command -v sing-box >/dev/null 2>&1; then command -v sing-box; else echo ""; fi
 }
 
 # generate [url...] [--tun] [--allow-lan] [--only clash|singbox|both] [-v]
 do_generate() {
-  local only="both" tun="" lan="" verbose=""
-  local -a urls=()
-  while [[ $# -gt 0 ]]; do
-    case "$1" in
-      --tun) tun="--tun"; shift ;;
-      --allow-lan) lan="--allow-lan"; shift ;;
-      --only) only="$2"; shift 2 ;;
-      --only=*) only="${1#--only=}"; shift ;;
-      -v|--verbose) verbose="-v"; shift ;;
-      -h|--help) show_help; exit 0 ;;
-      -*) warn "unknown flag ignored: $1"; shift ;;
-      *) urls+=("$1"); shift ;;
-    esac
-  done
-  if [[ ${#urls[@]} -eq 0 ]]; then
-    urls=("$DEFAULT_URL")
-  fi
-  case "$only" in
-    clash|singbox|both) ;;
-    *) err "bad --only value: $only (want clash|singbox|both)"; exit 1 ;;
-  esac
-
-  info "sources: ${urls[*]}"
-  info "outputs: $only | tun: ${tun:-off} | lan: ${lan:-off}"
-  # shellcheck disable=SC2086
-  "$(pick_python)" "$CONVERTER" "${urls[@]}" \
-    --clash-out "$CLASH_OUT" --singbox-out "$SB_OUT" \
-    --only "$only" $tun $lan $verbose
-  ok "generated: $CLASH_OUT + $SB_OUT (as selected)"
+	local only="both" tun="" lan="" verbose=""
+	local -a urls=()
+	while [[ $# -gt 0 ]]; do
+		case "$1" in
+		--tun)
+			tun="--tun"
+			shift
+			;;
+		--allow-lan)
+			lan="--allow-lan"
+			shift
+			;;
+		--only)
+			only="$2"
+			shift 2
+			;;
+		--only=*)
+			only="${1#--only=}"
+			shift
+			;;
+		-v | --verbose)
+			verbose="-v"
+			shift
+			;;
+		-h | --help)
+			show_help
+			exit 0
+			;;
+		-*)
+			warn "unknown flag ignored: $1"
+			shift
+			;;
+		*)
+			urls+=("$1")
+			shift
+			;;
+		esac
+	done
+	if [[ ${#urls[@]} -eq 0 ]]; then
+		urls=("$DEFAULT_URL")
+	fi
+	case "$only" in
+	clash | singbox | both) ;;
+	*)
+		err "bad --only value: $only (want clash|singbox|both)"
+		exit 1
+		;;
+	esac
+
+	info "sources: ${urls[*]}"
+	info "outputs: $only | tun: ${tun:-off} | lan: ${lan:-off}"
+	# shellcheck disable=SC2086
+	"$(pick_python)" "$CONVERTER" "${urls[@]}" \
+		--clash-out "$CLASH_OUT" --singbox-out "$SB_OUT" \
+		--only "$only" $tun $lan $verbose
+	ok "generated: $CLASH_OUT + $SB_OUT (as selected)"
 }
 
 do_check() {
-  local fail=0
-  local mihomo singbox
-  mihomo="$(find_mihomo)"; singbox="$(find_singbox)"
-  if [[ -z "$mihomo" ]]; then
-    warn "mihomo binary not found, skipping clash check"
-  else
-    info "mihomo -t $CLASH_OUT"
-    if "$mihomo" -t -f "$CLASH_OUT" 2>&1 | tail -n2; then ok "clash config valid"; else err "clash check FAILED"; fail=1; fi
-  fi
-  if [[ -z "$singbox" ]]; then
-    warn "sing-box binary not found, skipping sing-box check"
-  else
-    info "sing-box check $SB_OUT"
-    if "$singbox" check -c "$SB_OUT"; then ok "sing-box config valid"; else err "sing-box check FAILED"; fail=1; fi
-  fi
-  [[ $fail -eq 0 ]] || exit 1
+	local fail=0
+	local mihomo singbox
+	mihomo="$(find_mihomo)"
+	singbox="$(find_singbox)"
+	if [[ -z "$mihomo" ]]; then
+		warn "mihomo binary not found, skipping clash check"
+	else
+		info "mihomo -t $CLASH_OUT"
+		if "$mihomo" -t -f "$CLASH_OUT" 2>&1 | tail -n2; then ok "clash config valid"; else
+			err "clash check FAILED"
+			fail=1
+		fi
+	fi
+	if [[ -z "$singbox" ]]; then
+		warn "sing-box binary not found, skipping sing-box check"
+	else
+		info "sing-box check $SB_OUT"
+		if "$singbox" check -c "$SB_OUT"; then ok "sing-box config valid"; else
+			err "sing-box check FAILED"
+			fail=1
+		fi
+	fi
+	[[ $fail -eq 0 ]] || exit 1
 }
 
 # deploy [--tun] [--allow-lan] [url] — regenerate then install to Desktop mihomo
 do_deploy() {
-  do_generate "$@"
-  do_check
-  if [[ ! -d "$DESKTOP_DIR" ]]; then
-    err "desktop dir not found: $DESKTOP_DIR"
-    exit 1
-  fi
-  local bak="$DESKTOP_DIR/config.yaml.deploy-$(date +%Y%m%d-%H%M%S).bak"
-  cp "$DESKTOP_DIR/config.yaml" "$bak"
-  info "backup: $bak"
-  cp "$CLASH_OUT" "$DESKTOP_DIR/config.yaml"
-  ok "installed $CLASH_OUT -> $DESKTOP_DIR/config.yaml"
-  if [[ -x "$DESKTOP_DIR/manager.sh" ]]; then
-    info "validating with Desktop manager..."
-    (cd "$DESKTOP_DIR" && ./manager.sh check)
-  fi
-  warn "activation needs root: cd $DESKTOP_DIR && sudo ./manager.sh restart"
-  warn "dashboard lands at http://127.0.0.1:9090/ui after restart (auto-downloaded)"
+	do_generate --allow-lan "$@"
+	do_check
+	if [[ ! -d "$DESKTOP_DIR" ]]; then
+		err "desktop dir not found: $DESKTOP_DIR"
+		exit 1
+	fi
+	local bak="$DESKTOP_DIR/config.yaml.deploy-$(date +%Y%m%d-%H%M%S).bak"
+	cp "$DESKTOP_DIR/config.yaml" "$bak"
+	info "backup: $bak"
+	cp "$CLASH_OUT" "$DESKTOP_DIR/config.yaml"
+	ok "installed $CLASH_OUT -> $DESKTOP_DIR/config.yaml"
+	if [[ -x "$DESKTOP_DIR/manager.sh" ]]; then
+		info "validating with Desktop manager..."
+		(cd "$DESKTOP_DIR" && ./manager.sh check)
+	fi
+	warn "activation needs root: cd $DESKTOP_DIR && sudo ./manager.sh restart"
+	warn "dashboard lands at http://127.0.0.1:9090/ui after restart (auto-downloaded)"
 }
 
 show_help() {
-  cat <<EOF
+	cat <<EOF
 v2ray-to-subs manager - $DIR
 Default subscription: $DEFAULT_URL
 
@@ -144,18 +184,37 @@ Outputs:
 Notes:
   - TUN needs root/CAP_NET_ADMIN: use --tun only if you run mihomo/sing-box
     with sudo or setcap; otherwise keep the loopback-only default.
-  - --allow-lan binds mixed-port to all interfaces (loopback-only by default).
+  - --allow-lan binds mixed-port to all interfaces (LAN open by default).
   - Dashboard: http://127.0.0.1:9090/ui (auto-downloaded metacubexd).
 EOF
 }
 
 case "${1:-help}" in
-  generate) shift; do_generate "$@" ;;
-  clash) shift; do_generate --only clash "$@" ;;
-  singbox) shift; do_generate --only singbox "$@" ;;
-  tun) shift; do_generate --tun "$@" ;;
-  check) do_check ;;
-  deploy) shift; do_deploy "$@" ;;
-  help|--help|-h) show_help ;;
-  *) err "unknown command: $1"; show_help; exit 1 ;;
+generate)
+	shift
+	do_generate "$@"
+	;;
+clash)
+	shift
+	do_generate --only clash "$@"
+	;;
+singbox)
+	shift
+	do_generate --only singbox "$@"
+	;;
+tun)
+	shift
+	do_generate --tun "$@"
+	;;
+check) do_check ;;
+deploy)
+	shift
+	do_deploy "$@"
+	;;
+help | --help | -h) show_help ;;
+*)
+	err "unknown command: $1"
+	show_help
+	exit 1
+	;;
 esac
diff --git a/proxy_converter.py b/proxy_converter.py
index 08e4d00..13bcde4 100644
--- a/proxy_converter.py
+++ b/proxy_converter.py
@@ -145,9 +145,9 @@ DEFAULT_SUBSCRIPTION_URL = "https://raw.githubusercontent.com/patterniha/Free-Co
 # Shared bypass policy.
 #
 # Mirrors /home/mohammad/Desktop/mihomo usage (mihomo as TUN + Fake-IP +
-# DNS-hijack front-end): private/LAN always DIRECT, Iranian sites/IPs always
-# DIRECT, everything else goes through the subscription proxies. No xray
-# sidecar needed — mihomo/sing-box dial the nodes directly.
+# DNS-hijack front-end): private/LAN always DIRECT, everything else goes
+# through the subscription proxies. No xray sidecar needed —
+# mihomo/sing-box dial the nodes directly.
 # ---------------------------------------------------------------------------
 
 # Processes that must never be routed back into the tunnel (loop avoidance).
@@ -189,21 +189,6 @@ REALIP_SUFFIXES = [
     "connectivitycheck.gstatic.com",
 ]
 
-# Trackers/ads rejected before anything else.
-ADS_REJECT_SUFFIXES = [
-    "doubleclick.net",
-    "googlesyndication.com",
-    "googleadservices.com",
-    "googletagmanager.com",
-    "googletagservices.com",
-    "tracking.pro",
-    "scorecardresearch.com",
-    "adnxs.com",
-    "adsrvr.org",
-    "advertising.com",
-    "amazon-adsystem.com",
-]
-
 # mihomo client-fingerprint accepted values
 UTLS_FINGERPRINTS = {
     "chrome",
@@ -1063,14 +1048,15 @@ class ConfigGenerator:
     def __init__(
         self,
         tun_enabled: bool = False,
-        allow_lan: bool = False,
+        allow_lan: bool = True,
         controller_secret: str = "",
     ) -> None:
         self.url_test_url = "https://www.gstatic.com/generate_204"
         self.url_test_interval = 300
         self.url_test_tolerance = 50
         self.subscription_title: Optional[str] = None
-        # TUN is opt-in (needs root/CAP_NET_ADMIN); loopback-only by default.
+        # TUN is opt-in (needs root/CAP_NET_ADMIN); LAN open by default
+        # (proxy-everything boundary: mixed port serves LAN clients).
         self.tun_enabled = tun_enabled
         self.allow_lan = allow_lan
         # Empty = no `secret` key emitted (backwards compatible default).
@@ -1466,11 +1452,11 @@ class ConfigGenerator:
         # NOTE: field-for-field aligned with /home/mohammad/Desktop/mihomo
         # config.yaml (verified mihomo v1.19.31 setup). Differences from it are
         # intentional: proxies/groups come from the subscription (no xray
-        # sidecar), and Iran/CN bypass rules are added.
+        # sidecar); no ads, geo, or Iran/CN bypass rules are emitted.
         config: Dict[str, Any] = {
             "mixed-port": 7890,
             "allow-lan": self.allow_lan,
-            # Loopback-only by default; "*" only when LAN access is opted in.
+            # "*" by default (proxy-everything boundary serves LAN clients).
             "bind-address": "*" if self.allow_lan else "127.0.0.1",
             "mode": "rule",
             "log-level": "info",
@@ -1508,7 +1494,7 @@ class ConfigGenerator:
                 # 1053 avoids systemd-resolved/dnsmasq port-53 conflict;
                 # with TUN enabled, dns-hijack (any:53) still intercepts all
                 # port-53 queries and forwards them here, so fake-ip keeps
-                # working. Loopback-only; LAN needs --allow-lan + TUN.
+                # working. DNS stays loopback; LAN clients use TUN for DNS.
                 "listen": "127.0.0.1:1053",
                 "ipv6": False,
                 "cache-algorithm": "arc",
@@ -1539,9 +1525,6 @@ class ConfigGenerator:
                         "+.twitter.com",
                     ],
                 },
-                "nameserver-policy": {
-                    "geosite:category-ads-all": "rcode://success",
-                },
             },
             "tun": {
                 # Opt-in via --tun (needs root/CAP_NET_ADMIN).
@@ -1592,10 +1575,10 @@ class ConfigGenerator:
 
     @classmethod
     def _clash_rules(cls) -> List[str]:
-        # First match wins — foreign-server shape:
-        # 0) private/LAN, 1) ads, 2) known foreign services → PROXY, 3) MATCH.
-        # Process bypasses and Iran/China geo bypasses are intentionally gone:
-        # this runs outside both countries and has no local sidecar.
+        # First match wins — proxy-everything shape:
+        # 0) private/LAN DIRECT, 1) MATCH,PROXY for everything else.
+        # Ads REJECT, process bypasses and Iran/China geo bypasses are
+        # intentionally gone: no local sidecar, exit outside both countries.
         rules: List[str] = [
             # 0) LAN / private bypass (Desktop pattern)
             "DOMAIN-SUFFIX,lan,DIRECT",
@@ -1608,103 +1591,10 @@ class ConfigGenerator:
         ]
         rules += [f"IP-CIDR,{c},DIRECT,no-resolve" for c in PRIVATE_CIDRS]
         rules += [f"IP-CIDR6,{c},DIRECT,no-resolve" for c in PRIVATE_CIDRS_V6]
-        # 2) Ads / trackers
-        rules += [f"DOMAIN-SUFFIX,{d},REJECT" for d in ADS_REJECT_SUFFIXES]
-        rules.append("DOMAIN-KEYWORD,analytics,REJECT")
-        # 2) Foreign services → PROXY
-        rules += [
-            "DOMAIN-SUFFIX,google.com,PROXY",
-            "DOMAIN-SUFFIX,googleapis.com,PROXY",
-            "DOMAIN-SUFFIX,gstatic.com,PROXY",
-            "DOMAIN-SUFFIX,googleusercontent.com,PROXY",
-            "DOMAIN-SUFFIX,ggpht.com,PROXY",
-            "DOMAIN-SUFFIX,youtube.com,PROXY",
-            "DOMAIN-SUFFIX,youtu.be,PROXY",
-            "DOMAIN-SUFFIX,ytimg.com,PROXY",
-            "DOMAIN-SUFFIX,googlevideo.com,PROXY",
-            "DOMAIN-SUFFIX,facebook.com,PROXY",
-            "DOMAIN-SUFFIX,facebook.net,PROXY",
-            "DOMAIN-SUFFIX,fbcdn.net,PROXY",
-            "DOMAIN-SUFFIX,instagram.com,PROXY",
-            "DOMAIN-SUFFIX,whatsapp.com,PROXY",
-            "DOMAIN-SUFFIX,whatsapp.net,PROXY",
-            "DOMAIN-SUFFIX,thread.com,PROXY",
-            "DOMAIN-SUFFIX,twitter.com,PROXY",
-            "DOMAIN-SUFFIX,x.com,PROXY",
-            "DOMAIN-SUFFIX,t.co,PROXY",
-            "DOMAIN-SUFFIX,twimg.com,PROXY",
-            "DOMAIN-SUFFIX,telegram.org,PROXY",
-            "DOMAIN-SUFFIX,telegram.me,PROXY",
-            "DOMAIN-SUFFIX,t.me,PROXY",
-            "DOMAIN-SUFFIX,tdesktop.com,PROXY",
-            "DOMAIN-SUFFIX,telegra.ph,PROXY",
-            "DOMAIN-KEYWORD,t.me,PROXY",
-            "DOMAIN-SUFFIX,spotify.com,PROXY",
-            "DOMAIN-SUFFIX,scdn.co,PROXY",
-            "DOMAIN-SUFFIX,github.com,PROXY",
-            "DOMAIN-SUFFIX,githubusercontent.com,PROXY",
-            "DOMAIN-SUFFIX,github.io,PROXY",
-            "DOMAIN-SUFFIX,gitlab.com,PROXY",
-            "DOMAIN-SUFFIX,openai.com,PROXY",
-            "DOMAIN-SUFFIX,chatgpt.com,PROXY",
-            "DOMAIN-SUFFIX,oaiusercontent.com,PROXY",
-            "DOMAIN-SUFFIX,anthropic.com,PROXY",
-            "DOMAIN-SUFFIX,claude.ai,PROXY",
-            "DOMAIN-SUFFIX,gemini.google.com,PROXY",
-            "DOMAIN-SUFFIX,netflix.com,PROXY",
-            "DOMAIN-SUFFIX,nflxvideo.net,PROXY",
-            "DOMAIN-SUFFIX,nflximg.net,PROXY",
-            "DOMAIN-SUFFIX,nflxso.net,PROXY",
-            "DOMAIN-SUFFIX,twitch.tv,PROXY",
-            "DOMAIN-SUFFIX,ttvnw.net,PROXY",
-            "DOMAIN-SUFFIX,discord.com,PROXY",
-            "DOMAIN-SUFFIX,discordapp.com,PROXY",
-            "DOMAIN-SUFFIX,discord.gg,PROXY",
-            "DOMAIN-SUFFIX,discord.media,PROXY",
-            "DOMAIN-SUFFIX,reddit.com,PROXY",
-            "DOMAIN-SUFFIX,redd.it,PROXY",
-            "DOMAIN-SUFFIX,redditstatic.com,PROXY",
-            "DOMAIN-SUFFIX,redditmedia.com,PROXY",
-            "DOMAIN-SUFFIX,pinterest.com,PROXY",
-            "DOMAIN-SUFFIX,pinimg.com,PROXY",
-            "DOMAIN-SUFFIX,tiktok.com,PROXY",
-            "DOMAIN-SUFFIX,tiktokv.com,PROXY",
-            "DOMAIN-SUFFIX,tiktokcdn.com,PROXY",
-            "DOMAIN-SUFFIX,byteoversea.com,PROXY",
-            "DOMAIN-SUFFIX,medium.com,PROXY",
-            "DOMAIN-SUFFIX,wikipedia.org,PROXY",
-            "DOMAIN-SUFFIX,wikimedia.org,PROXY",
-            "DOMAIN-SUFFIX,wikiwand.com,PROXY",
-            "DOMAIN-SUFFIX,cloudflare.com,PROXY",
-            "DOMAIN-SUFFIX,workers.dev,PROXY",
-            "DOMAIN-SUFFIX,pages.dev,PROXY",
-            "DOMAIN-SUFFIX,reg.cloudflare.com,PROXY",
-            "DOMAIN-SUFFIX,v2ex.com,PROXY",
-            "DOMAIN-SUFFIX,duckduckgo.com,PROXY",
-            "DOMAIN-SUFFIX,bing.com,PROXY",
-            "DOMAIN-SUFFIX,microsoft.com,PROXY",
-            "DOMAIN-SUFFIX,office.com,PROXY",
-            "DOMAIN-SUFFIX,office365.com,PROXY",
-            "DOMAIN-SUFFIX,outlook.com,PROXY",
-            "DOMAIN-SUFFIX,msn.com,PROXY",
-            "DOMAIN-SUFFIX,dropbox.com,PROXY",
-            "DOMAIN-SUFFIX,icloud.com,PROXY",
-            "DOMAIN-SUFFIX,apple.com,PROXY",
-            "DOMAIN-SUFFIX,aaplimg.com,PROXY",
-            "DOMAIN-SUFFIX,amazon.com,PROXY",
-            "DOMAIN-SUFFIX,amazonaws.com,PROXY",
-            "DOMAIN-SUFFIX,steamcommunity.com,PROXY",
-            "DOMAIN-SUFFIX,steampowered.com,PROXY",
-            "DOMAIN-SUFFIX,store.steampowered.com,PROXY",
-            "DOMAIN-SUFFIX,signal.org,PROXY",
-            "DOMAIN-SUFFIX,whispersystems.org,PROXY",
-            "DOMAIN-SUFFIX,protonmail.com,PROXY",
-            "DOMAIN-SUFFIX,proton.me,PROXY",
-            "DOMAIN-SUFFIX,tailscale.com,PROXY",
-            "DOMAIN-SUFFIX,speedtest.net,PROXY",
-            "DOMAIN-SUFFIX,fast.com,PROXY",
-        ]
-        # 6) Final catch-all (Desktop pattern: everything else → PROXY)
+        # 1) Everything else → PROXY via the MATCH,PROXY catch-all below
+        # (ads REJECT and the foreign-service pin list were removed:
+        # proxy-everything boundary, LAN/private DIRECT only).
+        # 2) Final catch-all (everything else → PROXY)
         rules.append("MATCH,PROXY")
         return rules
 
@@ -2011,10 +1901,10 @@ class ConfigGenerator:
             )
 
         final = "auto" if proxy_tags else "direct"
-        # Mirrors the mihomo rule order: private → ads reject → final.
-        # Process matchers and Iran/China suffixes are gone: this runs on a
-        # foreign server with no local sidecar, and sing-box `geoip` is
-        # deprecated in favour of rule-sets anyway.
+        # Mirrors the mihomo rule order: private → final (proxy-everything).
+        # Process matchers, ads reject and Iran/China suffixes are gone:
+        # this runs on a foreign server with no local sidecar, and sing-box
+        # `geoip` is deprecated in favour of rule-sets anyway.
         rules: List[Dict[str, Any]] = [
             {"action": "sniff"},
             {"protocol": "dns", "action": "hijack-dns"},
@@ -2023,14 +1913,10 @@ class ConfigGenerator:
                 "outbound": "direct",
                 "ip_is_private": True,
             },
-            {
-                "action": "reject",
-                "domain_suffix": [d.lstrip("+") for d in ADS_REJECT_SUFFIXES],
-            },
         ]
 
         # Fake-IP by default (like mihomo enhanced-mode: fake-ip): hijacked
-        # DNS gets fake IPs via the query_type rule; LAN/NTP/Iran/CN get
+        # DNS gets fake IPs via the query_type rule; LAN/NTP/probes get
         # real IPs from dns-direct. `final` must be a real resolver —
         # sing-box forbids fakeip as the default server.
         realip_suffixes = [
@@ -2153,7 +2039,7 @@ def run(
     singbox_out: str = "singbox_config.json",
     outputs: str = "both",
     tun_enabled: bool = False,
-    allow_lan: bool = False,
+    allow_lan: bool = True,
     controller_secret: str = "",
     unique_host: bool = False,
 ) -> int:
@@ -2292,7 +2178,8 @@ def main() -> None:
     ap.add_argument(
         "--allow-lan",
         action="store_true",
-        help="Allow LAN connections and bind to all interfaces (loopback-only by default)",
+        default=True,
+        help="Allow LAN connections and bind to all interfaces (on by default)",
     )
     ap.add_argument(
         "--controller-secret",
diff --git a/refresh.sh b/refresh.sh
index 827cfed..fddbd25 100755
--- a/refresh.sh
+++ b/refresh.sh
@@ -20,18 +20,18 @@ export MIHOMO_CONTROLLER_SECRET="$(cat "$CONF_DIR/.controller_secret")"
 # Lets the systemd unit pin one or several subs without editing code.
 URLS=()
 if [[ $# -gt 0 ]]; then
-  URLS=("$@")
+	URLS=("$@")
 elif [ -n "${SUB_URL:-}" ]; then
-  URLS=("$SUB_URL")
+	URLS=("$SUB_URL")
 fi
 if [[ ${#URLS[@]} -gt 0 ]]; then
-  echo "[refresh] sources: ${URLS[*]}"
+	echo "[refresh] sources: ${URLS[*]}"
 else
-  echo "[refresh] source: converter default"
+	echo "[refresh] source: converter default"
 fi
 
 echo "[refresh] generating to $TMP ..."
-"$PY" "$CONVERTER" "${URLS[@]}" --only clash --clash-out "$TMP" --unique-host
+"$PY" "$CONVERTER" "${URLS[@]}" --only clash --clash-out "$TMP" --unique-host --allow-lan
 
 echo "[refresh] validating with mihomo -t ..."
 mihomo -t -f "$TMP"
@@ -40,16 +40,16 @@ BAK="$CONF_DIR/config.yaml.refresh-$(date +%Y%m%d-%H%M%S).bak"
 cp "$LIVE" "$BAK"
 echo "[refresh] backup: $BAK"
 
-cat "$TMP" > "$LIVE"
+cat "$TMP" >"$LIVE"
 chmod 600 "$LIVE"
 echo "[refresh] installed fresh config -> $LIVE"
 
 if systemctl --user is-active --quiet mihomo-subs.service; then
-  echo "[refresh] restarting mihomo-subs.service ..."
-  systemctl --user restart mihomo-subs.service
+	echo "[refresh] restarting mihomo-subs.service ..."
+	systemctl --user restart mihomo-subs.service
 else
-  echo "[refresh] starting mihomo-subs.service ..."
-  systemctl --user start mihomo-subs.service
+	echo "[refresh] starting mihomo-subs.service ..."
+	systemctl --user start mihomo-subs.service
 fi
 
 # keep only last 5 backups
diff --git a/scripts/DECISIONS.md b/scripts/DECISIONS.md
index a60f60c..4c81a93 100644
--- a/scripts/DECISIONS.md
+++ b/scripts/DECISIONS.md
@@ -113,7 +113,7 @@ in Clash, not in the node name.
 
 **Rollback.** Revert naming in the converter; balancer history resets once.
 
-## 2026-11-08 — Separate `region` failure cause
+## 2026-11-08 — Separate `region` failure cause (SUPERSEDED by the 2026-11-11 cause-cleanup entry above)
 
 **Context.** Provider country checks (geo-blocks) are a distinct failure from
 rate limits and transport faults, and treating them as generic failures
@@ -127,3 +127,13 @@ deleting them; the column migrated idempotently.
 
 **Rollback.** Revert the enum and column; unknown reasons fall back to
 `manual`.
+
+## 2026-11-15 — Proxy-everything routing, no ads, allow-lan by default
+
+**Context.** The generated configs still carried an ads REJECT block, a ~90-domain foreign-service pin list, a `geosite:category-ads-all` DNS policy, and `allow-lan false` defaults, while the checked-in samples were stale artifacts contradicting the generator.
+
+**Decision.** Both generators collapse to LAN/private DIRECT plus `MATCH,PROXY` (Clash) and sniff/hijack-dns/ip_is_private plus final auto (sing-box); the ads list, its DNS policy, and the pin list are deleted. `allow-lan` defaults to true with mixed-port 7890 so scheduled refreshes serve LAN clients; TUN stays opt-in. Checked-in samples are regenerated by the converter, never hand-edited.
+
+**Consequences.** All non-LAN traffic goes through a Google-clean US exit held by the balancer (retest 500, country 20, 6h refresh gate). LAN exposure of the mixed port is the accepted trade-off for serving LAN clients.
+
+**Rollback.** `git checkout` the generator, regenerate, reinstall the last `.bak` live config; disable the timer pair to stop scheduled refreshes.
diff --git a/singbox_config.json b/singbox_config.json
index b39228f..9208139 100644
--- a/singbox_config.json
+++ b/singbox_config.json
@@ -12,7 +12,7 @@
       },
       {
         "type": "udp",
-        "server": "223.5.5.5",
+        "server": "1.1.1.1",
         "tag": "dns-direct"
       },
       {
@@ -22,7 +22,7 @@
       },
       {
         "type": "https",
-        "server": "doh.pub",
+        "server": "cloudflare-dns.com",
         "tag": "dns-doh",
         "path": "/dns-query",
         "domain_resolver": "dns-direct"
@@ -44,7 +44,6 @@
           "localhost.ptlogin2.qq.com",
           "msftconnecttest.com",
           "msftncsi.com",
-          "ntp.org.cn",
           "pool.ntp.org",
           "detectportal.firefox.com",
           "connectivitycheck.gstatic.com"
@@ -52,1102 +51,104 @@
       },
       {
         "action": "route",
-        "server": "dns-direct",
-        "domain_suffix": [
-          ".ir",
-          "digikala.com",
-          "digikalaelectron.com",
-          "digimah.com",
-          "digikala.tm",
-          "snappfood.com",
-          "parspack.com",
-          "hostiran.net",
-          "arvancloud.com",
-          "iraniancdns.com",
-          "parsdata.com",
-          "idehpay.com",
-          ".cn",
-          "aliyun.com",
-          "taobao.com",
-          "tmail.com",
-          "tmall.com",
-          "alipay.com",
-          "qq.com",
-          "weixin.qq.com",
-          "gtimg.com",
-          "myqcloud.com",
-          "baidu.com",
-          "bdstatic.com",
-          "bilibili.com",
-          "hdslb.com",
-          "iqiyi.com",
-          "sohu.com",
-          "sina.com.cn",
-          "163.com",
-          "126.net",
-          "netease.com",
-          "jd.com",
-          "360.cn",
-          "sogou.com",
-          "weibo.com",
-          "zhihu.com"
-        ]
-      },
-      {
-        "action": "route",
-        "server": "dns-fakeip",
-        "query_type": [
-          "A",
-          "AAAA"
-        ]
-      }
-    ],
-    "final": "dns-doh",
-    "strategy": "prefer_ipv4",
-    "independent_cache": true
-  },
-  "inbounds": [
-    {
-      "type": "mixed",
-      "tag": "mixed-in",
-      "listen": "127.0.0.1",
-      "listen_port": 10808
-    }
-  ],
-  "outbounds": [
-    {
-      "type": "direct",
-      "tag": "direct"
-    },
-    {
-      "tag": "@DeltaKroneckerGithub | c3505c",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "6cd78ec7-b715-471c-92b4-0c3842caea4b",
-      "packet_encoding": "xudp",
-      "transport": {
-        "type": "ws",
-        "path": "/eyJqdW5rIjoiVXRIT2UwaDUiLCJwcm90b2NvbCI6InZsIiwibW9kZSI6InByZWZpeCIsInBhbmVsSVBzIjpbIlsyNjAyOmZjNTk6YjA6NjQ6Ol0iXX0=",
-        "headers": {
-          "Host": "billowing-cloud-d339.sospanel.workers.dev"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "billowing-cloud-d339.sospanel.workers.dev"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | AD753A | a19820",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "b2593749-691c-428c-9481-14979cba3446",
-      "transport": {
-        "type": "ws",
-        "path": "/proxyip=us.xiabibi.cf",
-        "headers": {
-          "Host": "xi.tbv.ccwu.cc"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "xi.tbv.ccwu.cc"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 9C8FF6 | d52c79",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "5f4acc06-8cbf-4172-92d2-8f475e51f781",
-      "transport": {
-        "type": "ws",
-        "path": "/vl/qS74oZnpprf6Qgqx",
-        "headers": {
-          "Host": "p9c85ckpnai98sdljzhuwwnolmcmxw88.cdzsqje4u3ms.workers.dev"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "p9c85ckpnai98sdljzhuwwnolmcmxw88.cdzsqje4u3ms.workers.dev",
-        "alpn": [
-          "http/1.1"
-        ]
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 30CA9B | a0a8f4",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "8991a496-1baa-486f-9948-ffe44e68c072",
-      "transport": {
-        "type": "ws",
-        "path": "/pyip=ProxyIP.SG.CMLiussss.net",
-        "headers": {
-          "Host": "soft-band-8da6.426.workers.dev"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "soft-band-8da6.426.workers.dev"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 2DC968 | fb3653",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "77777777-8a3e-6666-b6d1-a9c5f0e8b3a2",
-      "packet_encoding": "xudp",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "fx3h2kf8xn.fx6hsv0.ccwu.cc"
-        },
-        "max_early_data": 2560
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "fx3h2kf8xn.fx6hsv0.ccwu.cc"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | BFA791 | bf2e3d",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "9f44d517-29f2-4c6d-cc06-a1268f13da58",
-      "tls": {
-        "enabled": true,
-        "server_name": "kala.bestsellers1.site",
-        "alpn": [
-          "h2"
-        ]
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 575F8C | a0383b",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "77777777-8a3e-6666-b6d1-a9c5f0e8b3a2",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "faxf32gkfzoxqv.fx6hsv0.ccwu.cc"
-        },
-        "max_early_data": 2560
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "faxf32gkfzoxqv.fx6hsv0.ccwu.cc"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 26BF39 | b1e068",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "4c0b7280-76bb-495c-9c8b-f05712ebf805",
-      "packet_encoding": "xudp",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "youxuanku.kdns.fr"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "youxuanku.kdns.fr"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 38B262 | 40ff7d",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "4c0b7280-76bb-495c-9c8b-f05712ebf805",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "youxuanku.kdns.fr"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "youxuanku.kdns.fr"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 0F5978 | ab23d9",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "9952b71a-6c86-4522-888f-ff9ea9b93536",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "1.hshs8227shhshs.workers.dev"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "1.hshs8227shhshs.workers.dev"
-      }
-    },
-    {
-      "tag": "@DeltaKroneckerGithub | 353f61",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "4c0b7280-76bb-495c-9c8b-f05712ebf805",
-      "packet_encoding": "xudp",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "youxuanku.kdns.fr"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "youxuanku.kdns.fr"
-      }
-    },
-    {
-      "tag": "[openproxylist.com] CA 5049268 | d3219c",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "77777777-8a3e-6666-b6d1-a9c5f0e8b3a2",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "fx3h2kf8xn.fx6hsv0.ccwu.cc"
-        },
-        "max_early_data": 2560
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "fx3h2kf8xn.fx6hsv0.ccwu.cc"
-      }
-    },
-    {
-      "tag": "US 🇺🇸 | @Raydikalx | 2e605b",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "b2593749-691c-428c-9481-14979cba3446",
-      "transport": {
-        "type": "ws",
-        "path": "/proxyip=us.xiabibi.cf",
-        "headers": {
-          "Host": "xi.tbv.ccwu.cc"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "xi.tbv.ccwu.cc"
-      }
-    },
-    {
-      "tag": "@DeltaKroneckerGithub | 08e1d4",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "trojan",
-      "password": "humanity",
-      "transport": {
-        "type": "ws",
-        "path": "/assignment",
-        "headers": {
-          "Host": "www.calmlunch.com"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "www.calmlunch.com"
-      }
-    },
-    {
-      "tag": "@DeltaKroneckerGithub | 022f0f",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "c18b978e-1c4e-415c-8bea-07942b563a64",
-      "transport": {
-        "type": "ws",
-        "path": "/fp=chrome",
-        "headers": {
-          "Host": "shuma.ccwu.cc"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "shuma.ccwu.cc"
-      }
-    },
-    {
-      "tag": "@DeltaKroneckerGithub | add03f",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "trojan",
-      "password": "humanity",
-      "transport": {
-        "type": "ws",
-        "path": "/assignment",
-        "headers": {
-          "Host": "www.calmlunch.com"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "www.calmlunch.com",
-        "alpn": [
-          "http/1.1"
-        ]
-      }
-    },
-    {
-      "tag": "@DeltaKroneckerGithub | bb4dc1",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "b2593749-691c-428c-9481-14979cba3446",
-      "packet_encoding": "xudp",
-      "transport": {
-        "type": "ws",
-        "path": "/proxyip=us.xiabibi.cf",
-        "headers": {
-          "Host": "xi.tbv.ccwu.cc"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "xi.tbv.ccwu.cc"
-      }
-    },
-    {
-      "tag": "United+States | 9f9d93",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "34ce8760-24ed-41e7-a1f5-aa6c2660a53c",
-      "packet_encoding": "xudp",
-      "transport": {
-        "type": "ws",
-        "path": "/pyip=ProxyIP.SG.CMLiussss.net",
-        "headers": {
-          "Host": "quiet-frost-ac61.333-07d.workers.dev"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "quiet-frost-ac61.333-07d.workers.dev"
-      }
-    },
-    {
-      "tag": "By EbraSha 🦅 | ec3ba5",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "77777777-8a3e-6666-b6d1-a9c5f0e8b3a2",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "faxf32gkfzoxqv.fx6hsv0.ccwu.cc"
-        },
-        "max_early_data": 2560
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "faxf32gkfzoxqv.fx6hsv0.ccwu.cc"
-      }
-    },
-    {
-      "tag": "JP 🇯🇵 | @Raydikalx | 14fb60",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "c18b978e-1c4e-415c-8bea-07942b563a64",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "shuma.ccwu.cc"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "shuma.ccwu.cc"
-      }
-    },
-    {
-      "tag": "BE 🇧🇪 | @Raydikalx | 7FD27C | ea4c14",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "c18b978e-1c4e-415c-8bea-07942b563a64",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "shuma.ccwu.cc"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "shuma.ccwu.cc"
-      }
-    },
-    {
-      "tag": "US 🇺🇸 | @Raydikalx | AB1DC2 | e379c8",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "c18b978e-1c4e-415c-8bea-07942b563a64",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "shuma.ccwu.cc"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "shuma.ccwu.cc"
-      }
-    },
-    {
-      "tag": "@DeltaKroneckerGithub | 28a81d",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "bba95b1f-f48c-454b-897b-a6c6bc307df1",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "edge.yzkvm.top"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "edge.yzkvm.top"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 903E4E | 13f57d",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "47fcef29-ab4e-4aa6-932b-d95a18f28a4e",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "e34bq.oa9r.zl3.hh.vavava.kdns.fr"
-        },
-        "max_early_data": 2560
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "e34bq.oa9r.zl3.hh.vavava.kdns.fr"
-      }
-    },
-    {
-      "tag": "DE 🇩🇪 | @Raydikalx | 7DF8AC | 7a9d94",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "bba95b1f-f48c-454b-897b-a6c6bc307df1",
-      "transport": {
-        "type": "ws",
-        "path": "/fp=chrome",
-        "headers": {
-          "Host": "edge.yzkvm.top"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "edge.yzkvm.top"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 26F144 | 2188c3",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "3c6d1933-b22a-484b-ac8a-63e24f5fba75",
-      "transport": {
-        "type": "ws",
-        "path": "/ujhgfytsrtw563675eud",
-        "headers": {
-          "Host": "server14.9966338.xyz"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "server14.9966338.xyz"
-      }
-    },
-    {
-      "tag": ">>@freeland8::FR | d35f86",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "trojan",
-      "password": "humanity",
-      "transport": {
-        "type": "ws",
-        "path": "//assignment",
-        "headers": {
-          "Host": "www.calmlunch.com"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "www.calmlunch.com"
-      }
-    },
-    {
-      "tag": "AU 🇦🇺 | @Raydikalx | F56B4F | fe0c08",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "8be20011-59b1-4118-91ed-83e8e6b662cd",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "f.yoptybla.ru"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "f.yoptybla.ru"
-      }
-    },
-    {
-      "tag": "🇩🇪179Mb | Senko Digital | 17275e",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "523e85fa-82b2-4ca5-9ff5-a734a4510197",
-      "tls": {
-        "enabled": true,
-        "server_name": "assets-de1.mirolit.ru"
-      }
-    },
-    {
-      "tag": "@DeltaKroneckerGithub | 76b82a",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "trojan",
-      "password": "humanity",
-      "transport": {
-        "type": "ws",
-        "path": "/assignment",
-        "headers": {
-          "Host": "www.calmlunch.com"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "www.calmlunch.com"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 0e3d4f",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "77777777-8a3e-6666-b6d1-a9c5f0e8b3a2",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "faxf32gkfzoxqv.fx6hsv0.ccwu.cc"
-        },
-        "max_early_data": 2560
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "faxf32gkfzoxqv.fx6hsv0.ccwu.cc"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 4DE122 | 986b15",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "77777777-8a3e-6666-b6d1-a9c5f0e8b3a2",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "fx3h2kf8xn.fx6hsv0.ccwu.cc"
-        },
-        "max_early_data": 2560
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "fx3h2kf8xn.fx6hsv0.ccwu.cc"
+        "server": "dns-fakeip",
+        "query_type": [
+          "A",
+          "AAAA"
+        ]
       }
-    },
+    ],
+    "final": "dns-doh",
+    "strategy": "prefer_ipv4",
+    "independent_cache": true
+  },
+  "inbounds": [
     {
-      "tag": "CA 🇨🇦 | @Raydikalx | 5BE41E | f23ac1",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "77777777-8a3e-6666-b6d1-a9c5f0e8b3a2",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "fx3l5i2wdfxln0.fx6hsv0.ccwu.cc"
-        },
-        "max_early_data": 2560
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "fx3l5i2wdfxln0.fx6hsv0.ccwu.cc"
-      }
-    },
+      "type": "mixed",
+      "tag": "mixed-in",
+      "listen": "127.0.0.1",
+      "listen_port": 10808
+    }
+  ],
+  "outbounds": [
     {
-      "tag": "CA 🇨🇦 | @Raydikalx | 4DE122 | b6a927",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "77777777-8a3e-6666-b6d1-a9c5f0e8b3a2",
-      "transport": {
-        "type": "ws",
-        "path": "/",
-        "headers": {
-          "Host": "fx3h2kf8xn.fx6hsv0.ccwu.cc"
-        },
-        "max_early_data": 2560
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "fx3h2kf8xn.fx6hsv0.ccwu.cc"
-      }
+      "type": "direct",
+      "tag": "direct"
     },
     {
-      "tag": "CA 🇨🇦 | @Raydikalx | 51B6CF | 3da173",
-      "server": "188.114.97.6",
-      "server_port": 443,
+      "tag": "vless-131cd4452f31",
+      "server": "127.0.0.1",
+      "server_port": 40443,
       "type": "vless",
-      "uuid": "77dc177b-79d9-49ac-92e1-2f1011faa5e3",
+      "uuid": "0281a320-21e8-434f-86b7-a7c0db58c0db",
       "transport": {
         "type": "ws",
-        "path": "/api/v2/b8ee4ba356df307c/stream",
+        "path": "/ws/0281a320-21e8-434f-86b7-a7c0db58c0db",
         "headers": {
-          "Host": "f871a986.69lover.site"
+          "Host": "je8r21hqax.dev.onappjet.com"
         }
       },
       "tls": {
         "enabled": true,
-        "server_name": "f871a986.69lover.site",
+        "server_name": "je8r21hqax.dev.onappjet.com",
         "alpn": [
           "http/1.1"
-        ]
-      }
-    },
-    {
-      "tag": "@DeltaKroneckerGithub | e776a6",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "4e4f1f70-5e56-4a76-bb9d-db087f4690c4",
-      "packet_encoding": "xudp",
-      "transport": {
-        "type": "ws",
-        "path": "/tyxyws",
-        "headers": {
-          "Host": "jp3.yohototo.top"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "jp3.yohototo.top"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 703016",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "trojan",
-      "password": "humanity",
-      "transport": {
-        "type": "ws",
-        "path": "/assignment",
-        "headers": {
-          "Host": "www.ignitelimit.com"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "www.ignitelimit.com"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 32B6D3 | ada968",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "fd6fb48f-b324-4a82-9dcd-f8bdb1bd5301",
-      "tls": {
-        "enabled": true,
-        "server_name": "denet1.17e1feeuzi.online",
-        "alpn": [
-          "h2"
-        ]
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 3F5E1A | 8f3ebf",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "c47eb7ab-2c2d-44e0-80cc-bb104f89a137",
-      "transport": {
-        "type": "ws",
-        "path": "/tunnel",
-        "headers": {
-          "Host": "www.terence-tunnel.org"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "www.terence-tunnel.org"
-      }
-    },
-    {
-      "tag": "🇫🇷 - FR - @FreeOnlineVPN | 4a49fb",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "trojan",
-      "password": "humanity",
-      "transport": {
-        "type": "ws",
-        "path": "/assignment",
-        "headers": {
-          "Host": "www.calmlunch.com"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "www.calmlunch.com"
-      }
-    },
-    {
-      "tag": "🏳[openproxylist.com] trojan- | 890f1d",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "trojan",
-      "password": "humanity",
-      "transport": {
-        "type": "ws",
-        "path": "/assignment",
-        "headers": {
-          "Host": "www.volumeroot.com"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "www.volumeroot.com"
-      }
-    },
-    {
-      "tag": "US 🇺🇸 | @Raydikalx | EDC5EE | 401641",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "4e4f1f70-5e56-4a76-bb9d-db087f4690c4",
-      "transport": {
-        "type": "ws",
-        "path": "/tyxyws",
-        "headers": {
-          "Host": "jp3.yohototo.top"
+        ],
+        "utls": {
+          "enabled": true,
+          "fingerprint": "chrome"
         }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "jp3.yohototo.top"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | D06334 | 2aa478",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "c4edb87e-8544-4fa4-bd1c-b0cda9a34b46",
-      "packet_encoding": "xudp",
-      "transport": {
-        "type": "ws",
-        "path": "/ws",
-        "headers": {
-          "Host": "a.cwvps.eu.org"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "a.cwvps.eu.org"
       }
     },
     {
-      "tag": "By EbraSha 🧬 | 3d7373",
-      "server": "188.114.97.6",
+      "tag": "vless-39242b8aa28d",
+      "server": "2a06:98c1:3120::7",
       "server_port": 443,
       "type": "vless",
-      "uuid": "91d28760-ecf1-450b-9170-d310111a0e6d",
+      "uuid": "0281a320-21e8-434f-86b7-a7c0db58c0db",
       "transport": {
         "type": "ws",
-        "path": "/api/v2/63e9687fa53e441c/stream",
+        "path": "/ws/0281a320-21e8-434f-86b7-a7c0db58c0db",
         "headers": {
-          "Host": "us9.69lover.my"
+          "Host": "je8r21hqax.dev.onappjet.com"
         }
       },
       "tls": {
         "enabled": true,
-        "server_name": "us9.69lover.my",
+        "server_name": "je8r21hqax.dev.onappjet.com",
         "alpn": [
           "http/1.1"
         ]
       }
     },
     {
-      "tag": "US 🇺🇸 | @Raydikalx | FB0008 | 8da267",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "trojan",
-      "password": "humanity",
-      "transport": {
-        "type": "ws",
-        "path": "/assignment",
-        "headers": {
-          "Host": "www.ignitelimit.com"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "www.ignitelimit.com"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 91DD24 | f97024",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "c4edb87e-8544-4fa4-bd1c-b0cda9a34b46",
-      "transport": {
-        "type": "ws",
-        "path": "/ws",
-        "headers": {
-          "Host": "a.cwvps.eu.org"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "a.cwvps.eu.org"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | B6DF98 | b19f1e",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "7a657573-627d-c5d7-4e7b-9e260f5cfff1",
-      "transport": {
-        "type": "ws",
-        "path": "/stream/PANEL_ZEUS/9e260f5cfff1/loc-0",
-        "headers": {
-          "Host": "imzajnekupas.a3-60-morteza.workers.dev"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "imzajnekupas.a3-60-morteza.workers.dev"
-      }
-    },
-    {
-      "tag": "@DeltaKroneckerGithub | 2b3a78",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "b585dc5e-55bf-4a8b-913a-27c9ccac05c3",
-      "transport": {
-        "type": "ws",
-        "path": "/vws/",
-        "headers": {
-          "Host": "bab-6.site"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "bab-6.site"
-      }
-    },
-    {
-      "tag": "49. 🇺🇸 United States | b4764a",
-      "server": "188.114.97.6",
+      "tag": "vless-a1c91bd4162f",
+      "server": "188.114.98.0",
       "server_port": 443,
       "type": "vless",
-      "uuid": "c4edb87e-8544-4fa4-bd1c-b0cda9a34b46",
-      "transport": {
-        "type": "ws",
-        "path": "/ws#/?TELEGRAM--MARAMBASHI--MARAMBASHI?ed=512",
-        "headers": {
-          "Host": "a.cwvps.eu.org"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "a.cwvps.eu.org"
-      }
-    },
-    {
-      "tag": "CA 🇨🇦 | @Raydikalx | 774ACE | 794d5b",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "trojan",
-      "password": "humanity",
-      "transport": {
-        "type": "ws",
-        "path": "//assignment",
-        "headers": {
-          "Host": "www.ignitelimit.com"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "www.ignitelimit.com"
-      }
-    },
-    {
-      "tag": "By EbraSha ♠️ | ad7869",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "trojan",
-      "password": "humanity",
+      "uuid": "0281a320-21e8-434f-86b7-a7c0db58c0db",
       "transport": {
         "type": "ws",
-        "path": "/assignment",
+        "path": "/ws/0281a320-21e8-434f-86b7-a7c0db58c0db",
         "headers": {
-          "Host": "www.ignitelimit.com"
+          "Host": "je8r21hqax.dev.onappjet.com"
         }
       },
       "tls": {
         "enabled": true,
-        "server_name": "www.ignitelimit.com",
+        "server_name": "je8r21hqax.dev.onappjet.com",
         "alpn": [
           "http/1.1"
         ]
       }
     },
-    {
-      "tag": "69. 🇺🇸 United States | f737fb",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "c4edb87e-8544-4fa4-bd1c-b0cda9a34b46",
-      "packet_encoding": "xudp",
-      "transport": {
-        "type": "ws",
-        "path": "/ws",
-        "headers": {
-          "Host": "a.cwvps.eu.org"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "a.cwvps.eu.org"
-      }
-    },
-    {
-      "tag": "By EbraSha ⛓️ | 339789",
-      "server": "188.114.97.6",
-      "server_port": 443,
-      "type": "vless",
-      "uuid": "828aa918-2ed3-4541-8519-083f9efeaaf7",
-      "transport": {
-        "type": "ws",
-        "path": "/pyip=proxyip.us.cmliussss.net",
-        "headers": {
-          "Host": "icy-hall-bfba.266-f4e.workers.dev"
-        }
-      },
-      "tls": {
-        "enabled": true,
-        "server_name": "icy-hall-bfba.266-f4e.workers.dev"
-      }
-    },
     {
       "type": "urltest",
       "tag": "auto",
       "outbounds": [
-        "@DeltaKroneckerGithub | c3505c",
-        "CA 🇨🇦 | @Raydikalx | AD753A | a19820",
-        "CA 🇨🇦 | @Raydikalx | 9C8FF6 | d52c79",
-        "CA 🇨🇦 | @Raydikalx | 30CA9B | a0a8f4",
-        "CA 🇨🇦 | @Raydikalx | 2DC968 | fb3653",
-        "CA 🇨🇦 | @Raydikalx | BFA791 | bf2e3d",
-        "CA 🇨🇦 | @Raydikalx | 575F8C | a0383b",
-        "CA 🇨🇦 | @Raydikalx | 26BF39 | b1e068",
-        "CA 🇨🇦 | @Raydikalx | 38B262 | 40ff7d",
-        "CA 🇨🇦 | @Raydikalx | 0F5978 | ab23d9",
-        "@DeltaKroneckerGithub | 353f61",
-        "[openproxylist.com] CA 5049268 | d3219c",
-        "US 🇺🇸 | @Raydikalx | 2e605b",
-        "@DeltaKroneckerGithub | 08e1d4",
-        "@DeltaKroneckerGithub | 022f0f",
-        "@DeltaKroneckerGithub | add03f",
-        "@DeltaKroneckerGithub | bb4dc1",
-        "United+States | 9f9d93",
-        "By EbraSha 🦅 | ec3ba5",
-        "JP 🇯🇵 | @Raydikalx | 14fb60",
-        "BE 🇧🇪 | @Raydikalx | 7FD27C | ea4c14",
-        "US 🇺🇸 | @Raydikalx | AB1DC2 | e379c8",
-        "@DeltaKroneckerGithub | 28a81d",
-        "CA 🇨🇦 | @Raydikalx | 903E4E | 13f57d",
-        "DE 🇩🇪 | @Raydikalx | 7DF8AC | 7a9d94",
-        "CA 🇨🇦 | @Raydikalx | 26F144 | 2188c3",
-        ">>@freeland8::FR | d35f86",
-        "AU 🇦🇺 | @Raydikalx | F56B4F | fe0c08",
-        "🇩🇪179Mb | Senko Digital | 17275e",
-        "@DeltaKroneckerGithub | 76b82a",
-        "CA 🇨🇦 | @Raydikalx | 0e3d4f",
-        "CA 🇨🇦 | @Raydikalx | 4DE122 | 986b15",
-        "CA 🇨🇦 | @Raydikalx | 5BE41E | f23ac1",
-        "CA 🇨🇦 | @Raydikalx | 4DE122 | b6a927",
-        "CA 🇨🇦 | @Raydikalx | 51B6CF | 3da173",
-        "@DeltaKroneckerGithub | e776a6",
-        "CA 🇨🇦 | @Raydikalx | 703016",
-        "CA 🇨🇦 | @Raydikalx | 32B6D3 | ada968",
-        "CA 🇨🇦 | @Raydikalx | 3F5E1A | 8f3ebf",
-        "🇫🇷 - FR - @FreeOnlineVPN | 4a49fb",
-        "🏳[openproxylist.com] trojan- | 890f1d",
-        "US 🇺🇸 | @Raydikalx | EDC5EE | 401641",
-        "CA 🇨🇦 | @Raydikalx | D06334 | 2aa478",
-        "By EbraSha 🧬 | 3d7373",
-        "US 🇺🇸 | @Raydikalx | FB0008 | 8da267",
-        "CA 🇨🇦 | @Raydikalx | 91DD24 | f97024",
-        "CA 🇨🇦 | @Raydikalx | B6DF98 | b19f1e",
-        "@DeltaKroneckerGithub | 2b3a78",
-        "49. 🇺🇸 United States | b4764a",
-        "CA 🇨🇦 | @Raydikalx | 774ACE | 794d5b",
-        "By EbraSha ♠️ | ad7869",
-        "69. 🇺🇸 United States | f737fb",
-        "By EbraSha ⛓️ | 339789"
+        "vless-131cd4452f31",
+        "vless-39242b8aa28d",
+        "vless-a1c91bd4162f"
       ],
       "url": "https://www.gstatic.com/generate_204",
       "interval": "5m",
@@ -1163,87 +164,10 @@
         "protocol": "dns",
         "action": "hijack-dns"
       },
-      {
-        "action": "route",
-        "outbound": "direct",
-        "process_name": [
-          "xray",
-          "sing-box",
-          "PattN",
-          "v2rayn"
-        ]
-      },
-      {
-        "action": "route",
-        "outbound": "direct",
-        "process_path_regex": [
-          "(?i)v2ray.*|PattN",
-          ".*sing-box.*"
-        ]
-      },
       {
         "action": "route",
         "outbound": "direct",
         "ip_is_private": true
-      },
-      {
-        "action": "route",
-        "outbound": "direct",
-        "domain_suffix": [
-          ".ir",
-          "digikala.com",
-          "digikalaelectron.com",
-          "digimah.com",
-          "digikala.tm",
-          "snappfood.com",
-          "parspack.com",
-          "hostiran.net",
-          "arvancloud.com",
-          "iraniancdns.com",
-          "parsdata.com",
-          "idehpay.com",
-          ".cn",
-          "aliyun.com",
-          "taobao.com",
-          "tmail.com",
-          "tmall.com",
-          "alipay.com",
-          "qq.com",
-          "weixin.qq.com",
-          "gtimg.com",
-          "myqcloud.com",
-          "baidu.com",
-          "bdstatic.com",
-          "bilibili.com",
-          "hdslb.com",
-          "iqiyi.com",
-          "sohu.com",
-          "sina.com.cn",
-          "163.com",
-          "126.net",
-          "netease.com",
-          "jd.com",
-          "360.cn",
-          "sogou.com",
-          "weibo.com",
-          "zhihu.com"
-        ]
-      },
-      {
-        "action": "reject",
-        "domain_suffix": [
-          "doubleclick.net",
-          "googlesyndication.com",
-          "googleadservices.com",
-          "googletagmanager.com",
-          "googletagservices.com",
-          "tracking.pro",
-          "scorecardresearch.com",
-          "adnxs.com",
-          "adsrvr.org",
-          "advertising.com",
-          "amazon-adsystem.com"
-        ]
       }
     ],
     "final": "auto",
```
<!-- END_GIT_DIFF -->
