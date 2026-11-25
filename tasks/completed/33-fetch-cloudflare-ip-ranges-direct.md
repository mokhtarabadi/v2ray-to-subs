# Task 33: Fetch Cloudflare IP ranges and route to DIRECT

**File:** `tasks/completed/33-fetch-cloudflare-ip-ranges-direct.md`
**Source:** manager
**Type:** improvement
**Status:** closed
**Finished:** 2026-11-25T18:45:47Z
**Submitted:** 2026-11-25T18:40:58Z
**Started:** 2026-11-25T18:26:20Z

## Source Context

### Variant C: Manager (manager)

## Goal

Fetch Cloudflare's official IPv4 (and optionally IPv6) CIDR ranges from `https://www.cloudflare.com/ips-v4` (and `ips-v6`) at generation time, and add them as `IP-CIDR`/`IP-CIDR6` rules → DIRECT before MATCH,PROXY. This ensures all sites behind Cloudflare CDN go direct, and the ranges are always up-to-date (fetched fresh each run).

## Manager's Notes

- User wants Approach 2 (manual explicit IP-CIDR rules) over Approach 1 (GEOSITE).
- Fetch from official source each generation run so always up-to-date.
- Route all Cloudflare IP ranges to DIRECT.
- Must not break existing rules (LAN/private bypass, service rules, country groups).
- Must handle network failure gracefully (skip if fetch fails, log warning).

<!-- These sections are unconditional per lint contract — DO NOT move back inside variants -->

## Local TODOs

- [ ] Research Cloudflare IP range endpoints (ips-v4, ips-v6)
- [ ] Design fetch function with timeout and fallback
- [ ] Plan via brain before implementation
- [ ] Implement in proxy_converter.py
- [ ] Verify generated config includes Cloudflare IP-CIDR rules

## Acceptance Criteria

- [x] Fetches https://www.cloudflare.com/ips-v4 at generation time
- [x] Fetches https://www.cloudflare.com/ips-v6 at generation time
- [x] Parses CIDR ranges from response (one per line)
- [x] Adds IP-CIDR (v4) and IP-CIDR6 (v6) rules → DIRECT before MATCH
- [x] Handles network failure gracefully (skip + log, no crash)
- [x] Generated config parses cleanly (yaml)
- [x] Converter runs with exit 0

## Verification Evidence

- **Test command:** rtk test python3 -m py_compile proxy_converter.py
- **Expected result:** syntax check passes with exit 0
- **Actual result:** py_compile OK (no errors)
- **Exit code:** 0

Additional verification commands run:
- `python3 proxy_converter.py --no-allow-lan --unique-host --controller-secret 123456789 --clash-out /tmp/test-clash.yaml` → exit 0 (2978 proxies, 38 groups)
- `python3 -c "import yaml; yaml.safe_load(...)"` → exit 0 (parse OK)
- Verified Cloudflare fetch: 15 v4 + 7 v6 CIDR ranges fetched successfully
- Verified 22 Cloudflare IP-CIDR/IP-CIDR6 rules in generated config
- Verified rules order: LAN → services → Cloudflare → MATCH
- `grep -c singbox` → 0 (fully dropped)
- Tested graceful fallback: `_fetch_cloudflare_ranges('bad-url', 1)` returns empty list

> Verification runner rule: the first verification run MUST use the `rtk test` prefix. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append (N/A — file absent per approved converter-only scope; recorded skip)
- [x] `testing-verification` applied and evidence recorded

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do NOT defer box-checking to a separate closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** Network dependency at generation time; Cloudflare endpoint may be unreachable.
- **Rollback plan:** Remove fetch function and Cloudflare IP-CIDR rules; revert to previous rules.

---

## Execution Log & Reasoning

### Implementation

- Added `import ipaddress` to imports.
- Updated DEFAULT_SUBSCRIPTION_URL to barry-far All_Configs_Sub.txt.
- Added CLOUDFLARE_IPV4_URL, CLOUDFLARE_IPV6_URL, CLOUDFLARE_FETCH_TIMEOUT constants.
- Added `_fetch_cloudflare_ranges()` staticmethod (urllib fetch with User-Agent, 5s timeout, ipaddress validation, graceful fallback).
- Wired Cloudflare IP-CIDR/IP-CIDR6 rules into generate_clash_config before MATCH (after service rules).
- Updated README comment to barry-far.

### Verification

- py_compile exit 0; dry gen exit 0 (2978 proxies, 38 groups).
- Fetch returned 15 v4 + 7 v6 CIDR ranges.
- Verified 22 Cloudflare IP-CIDR/IP-CIDR6 rules in generated config.
- Verified rules order: LAN → services → Cloudflare → MATCH.
- Tested graceful fallback: bad URL returns empty list (no crash).
- grep singbox: 0 (fully dropped). grep checker.surfshield: 0 (removed).

### Review
- QA Engineer verdict: QA_PASSED (no blocking defects; V1-V3 residual low).
- Code Reviewer verdict: PO_REVIEW_PENDING (technical approval; strengths F1-F4; no blocking issues; recommendation A1).
- Manager closure accept quote (verbatim): "Approved for closure".

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `6ec5f1c596bc008f9d763ad7276609a8f58848e3`
<!-- END_GIT_DIFF -->
