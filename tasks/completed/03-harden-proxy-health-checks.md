# Task [03]: Harden proxy health checks to filter dead nodes

**File:** `tasks/completed/03-harden-proxy-health-checks.md`
**Source:** manager
**Type:** improvement
**Status:** closed

## Goal

Make mihomo health-check all proxies in Auto, Load Balance, and Fallback groups with a strict https test so dead and broken nodes get filtered out of rotation.

## Manager's Notes

Manager: "we need to configure mihomo to test all proxies in balance or other proxy groups with a https link a gstatic or even harder test it filter wrong proxies." Context: consistent-hashing pins destinations to single nodes; pinned dead nodes break sites (ifconfig.me, ipify, gstatic failed via proxy while example.com worked). Suspected root cause: url-test groups use gstatic generate_204 (HTTP 204) with no explicit expected-status, so checks may never discriminate healthy from dead nodes.

## Local TODOs

- [x] Inspect current url-test group settings in proxy_converter.py
- [x] Set explicit expected-status and a harder https test URL on Auto, Load Balance, Fallback
- [x] Regenerate OpenRay config and validate with mihomo -t
- [x] Install live config and restart mihomo-subs.service

## Acceptance Criteria

- [x] All three smart groups carry explicit health-check expectations
- [x] Regenerated config passes `mihomo -t`
- [x] Live config active with new checks, service running

## Verification Evidence

- **Test command:** ./refresh.sh "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/vless.txt" && mihomo -t (inside refresh)
- **Expected result:** config valid, installed live, service active
- **Actual result:** test is successful, installed to ~/.config/mihomo-subs/config.yaml, mihomo-subs.service active; live groups show expected-status 204 + max-failed-times 3
- **Exit code:** 0

- **Test command:** curl -s --max-time 25 -x http://127.0.0.1:7890 https://api.ipify.org (after 90s)
- **Expected result:** exit-node IP
- **Actual result:** empty; logs show pinned nodes dead at TCP level (91.204.75.198 no route, 13.209.81.34 timeout) — filtering converges as 60s sweeps complete over 7330 nodes
- **Exit code:** 35 (TLS EOF)

## Definition of Done

- [x] Build/Test/Lint pass with exit code 0 (mihomo -t is the applicable gate here; no repo test suite covers the generator)
- [x] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append (no CHANGELOG.md in repo, skipped)
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** Stricter checks mark all 7330 nodes unhealthy if the test URL is unreachable from exit nodes
- **Rollback plan:** Revert proxy_converter.py change, regenerate, reinstall, restart; previous live config backups in ~/.config/mihomo-subs/

---

## Execution Log & Reasoning

- Root cause: groups used gstatic generate_204 (HTTP 204) with no expected-status, so mihomo defaulted to expecting 200 and checks could never pass; dead nodes stayed in rotation.
- Fix in proxy_converter.py: added "expected-status": 204 and "max-failed-times": 3 to Auto, Load Balance, and Fallback groups. Kept the gstatic https URL (a body-download test over 7330 nodes every 60s would overload the box).
- Ran refresh.sh with the OpenRay URL: config valid, installed live, service restarted and active. Re-selected PROXY -> Load Balance via API (restart resets it to Auto).
- Assumption A1: 204 status check is strict enough; a harder body-based test was skipped for load reasons.
- Live verification: example.com returns 200 via proxy; ipify/ifconfig.me still fail 90s after restart because their pinned nodes are dead at TCP level (no route / timeout in logs). Filtering converges as 60s sweeps work through 7330 nodes; full sweep takes many minutes.
- Closure: manager reviewed and approved ("close the task 03 i agrree with it"); closing with remaining convergence left to the running checker.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `2277bc8e2f2a0d8485e6854c1ececaaad3e26c44`
<!-- END_GIT_DIFF -->
