# Task 31: Dedicated Google group and routing rule

**File:** `tasks/completed/31-dedicated-google-group-routing.md`
**Source:** manager
**Type:** improvement
**Status:** closed
**Finished:** 2026-11-25T17:21:16Z
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

### Review
- QA Engineer verdict: QA_PASSED (no blocking defects; F1-F4 residual low).
- Code Reviewer verdict: PO_REVIEW_PENDING (technical approval; strengths F1-F3; low issues F4-F5; recommendations A1-A2).
- Manager closure accept quote (verbatim): "Approved for closure".

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `c7891bf58f75b56974815d89625fc6a4d5de46c0`
<!-- END_GIT_DIFF -->
