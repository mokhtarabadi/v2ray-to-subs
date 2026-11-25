# Task 32: Cloudflare trace per-country filtering and expand countries

**File:** `tasks/completed/32-cloudflare-trace-country-filter.md`
**Source:** manager
**Type:** improvement
**Status:** closed
**Finished:** 2026-11-25T17:55:39Z
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

### Review
- QA Engineer verdict: QA_PASSED (no blocking defects; V1-V3 residual low).
- Code Reviewer verdict: PO_REVIEW_PENDING (technical approval; strengths F1-F4; no blocking issues; recommendation A1).
- Manager closure accept quote (verbatim): "Approved for closure".

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `805b859a6226c4c1175dbe9a1539ac02adc60212`
<!-- END_GIT_DIFF -->
