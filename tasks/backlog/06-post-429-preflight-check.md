# Task [06]: POST-based 429 pre-flight check for rotation

**File:** `tasks/backlog/06-post-429-preflight-check.md`
**Source:** manager
**Type:** feature
**Status:** open

## Goal

Stop rotation from landing on Cloudflare rate-limited exits by verifying each candidate node with the manager's real POST request before selecting it, and lengthen the rotation interval so clean IPs are kept longer.

## Manager's Notes

Manager context (paraphrased from Persian): background 5-min rotation swaps away good clean IPs; the next IP may already be 429-limited, killing access until several manual `rr` runs find a clean one. Key new fact: the 429 triggers only on one specific POST request — plain GET works fine on the same endpoint.

## Key Finding (pre-implementation)

Mihomo's delay/health-check API and url-test groups only issue GET requests (URL + timeout parameters, no method/body support). So neither the built-in checks nor the delay endpoint can reproduce a POST-triggered 429 — the pre-flight check cannot live inside mihomo.

Feasible design: do it in our external script (`scripts/rr_balancer.py`), which is plain Python and can send any POST. Rotation becomes select-then-verify: pick candidate → select it in the PROXY group → send the manager's POST through the mixed port → 429 means mark failed and try the next candidate; clean means stay. Each bad candidate costs seconds of traffic flip, which rotation already does anyway.

Requires from manager: the exact POST details (URL, body, headers, what counts as limited vs clean). These must be configurable and toggleable, never hardcoded: an env flag (e.g. pre-flight off by default) plus env or local config-file settings for URL/body/headers, stored outside the repo (local config file or env, like the controller secret) since they describe the manager's private tool.

Manager order: do NOT implement now — keep parked in backlog with the configurability requirement recorded.

## Local TODOs

- [ ] Collect POST details (URL, body, headers, clean-vs-limited criteria) from manager
- [ ] Pre-flight must be configurable and toggleable (env flag, off by default; URL/body/headers via env or local config file, never hardcoded, never committed)
- [ ] Add pre-flight POST check to rotation path in `scripts/rr_balancer.py`
- [ ] Lengthen rotate timer (proposed 30-60 min) once pre-flight lands
- [ ] Verify live: rotation never settles on a 429 node; clean node kept across cycles

## Acceptance Criteria

- [ ] Rotation verifies each candidate with the real POST before settling
- [ ] A 429 candidate is marked failed and skipped automatically
- [ ] Clean IPs survive across rotation cycles for the full interval
- [ ] POST details stored outside the repo (no private tool data committed)

## Verification Evidence

- **Test command:** _(fill during execution)_
- **Expected result:** _(fill during execution)_
- **Actual result:** _(not yet executed — task parked pending manager decision)_
- **Exit code:** _(not yet executed — task parked pending manager decision)_

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [ ] Build/Test/Lint pass with exit code 0
- [ ] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append
- [ ] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** select-then-verify briefly flips live traffic onto each bad candidate (seconds per candidate)
- **Rollback plan:** disable pre-flight flag; rotation falls back to current delay-based behavior

---

## Execution Log & Reasoning

_(Parked on creation — awaiting manager decision on the select-then-verify design and POST details.)_

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->

_(Git diff will be automatically injected here by the MCP tool. Do not edit this block manually)_

<!-- END_GIT_DIFF -->
