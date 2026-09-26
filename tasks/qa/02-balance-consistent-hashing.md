# Task [02]: Balance across all proxies with consistent-hashing

**File:** `tasks/qa/02-balance-consistent-hashing.md`
**Source:** manager
**Type:** improvement
**Status:** open

## Goal

Spread traffic across all healthy proxies instead of only the top few by switching the Load Balance group to consistent-hashing with active health checks.

## Manager's Notes

Manager reported ~5000 active proxies but only the top ones used by the balance proxy. Approved plan: consistent-hashing plus active health checks. Quick fix, no Kanban tracking during implementation; task file created retroactively for closure ("Task it and close").

## Local TODOs

- [x] Switch Load Balance strategy round-robin to consistent-hashing
- [x] Turn off lazy checks, shorten interval to 60s
- [x] Regenerate via refresh.sh, validate, restart mihomo-subs

## Acceptance Criteria

- [x] Load Balance group uses consistent-hashing with 60s active checks
- [x] Fresh OpenRay config passes `mihomo -t`
- [x] mihomo-subs.service restarted and active on the new config

## Verification Evidence

- **Test command:** ./refresh.sh "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/vless.txt" (runs mihomo -t internally) + systemctl --user is-active mihomo-subs.service
- **Expected result:** config test successful, service active
- **Actual result:** configuration file test is successful, 7330 proxies, Load Balance consistent-hashing interval 60 lazy False, service active
- **Exit code:** 0

## Definition of Done

- [x] Build/Test/Lint pass with exit code 0
- [ ] `lint_task_file` passes on the active task file (no lint tool in this environment, template followed)
- [ ] `CHANGELOG.md` updated via Parse-Then-Append (no CHANGELOG.md in repo, skipped)
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** Active checks over 7330 nodes every 60s add probe load (~120/s)
- **Rollback plan:** Revert proxy_converter.py Load Balance block to round-robin/lazy, regenerate, restart

---

## Execution Log & Reasoning

- proxy_converter.py Load Balance group: strategy round-robin to consistent-hashing, interval 300 to 60, lazy True to False. Auto and Fallback groups untouched.
- refresh.sh regenerated from the OpenRay feed (7330 proxies), mihomo -t passed, live config installed, mihomo-subs.service restarted to active.
- Assumption A1: complaint describes the Load Balance group, not Fallback (fallback uses top-first by design).

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->

_(Git diff will be automatically injected here by the MCP tool. Do not edit this block manually)_

<!-- END_GIT_DIFF -->
