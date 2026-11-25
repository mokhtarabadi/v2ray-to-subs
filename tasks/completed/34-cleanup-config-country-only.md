# Task 34: Cleanup config — remove service groups, cloudflare, geo; keep countries only

**File:** `tasks/completed/34-cleanup-config-country-only.md`
**Source:** manager
**Type:** improvement
**Status:** closed
**Finished:** 2026-11-25T19:01:28Z
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

### Review
- QA Engineer verdict: QA_PASSED (no blocking defects; V1-V3 residual low).
- Code Reviewer verdict: PO_REVIEW_PENDING (technical approval; strengths F1-F5; no blocking issues; recommendation A1).
- Manager closure accept quote (verbatim): "Approved for closure".

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `56b74f936263245a32a936dfef1feebf076a217f`
<!-- END_GIT_DIFF -->
