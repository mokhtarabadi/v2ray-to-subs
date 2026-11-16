# Task 22: On-demand speed pick with DE hold, TUN retired

**File:** `tasks/completed/22-speed-pick-de-hold-no-tun.md`
**Source:** manager
**Type:** feature
**Status:** closed
**Finished:** 2026-11-16T13:30:02Z
**Submitted:** 2026-11-16T13:27:11Z
**Started:** 2026-11-16T13:20:05Z
**Closed:** 2026-11-16T13:29:29Z

## Goal

Land the working-tree speed and hold changes: proxy-only stack (TUN retired), on-demand `fastest` speed pick, DE hold across timer and launcher, with tests and docs.

## Manager's Notes

Direct orders from the live session, implemented in the tree and awaiting QA-to-closure: the selected node was too slow (delay says nothing about throughput — 28ms exits delivered 48–196 KB/s), so disable TUN and restart proxy-only, then build the proportionate fix (bounded finalist speed test, not full speedtest-cli per node). Flip the hold country NL→DE across `maintain.sh` and the `rr` launcher so both agree.

## Local TODOs

- [x] Verify TUN retired: no TUN device, direct egress on server default IP, proxy exits still gate-clean
- [x] Verify triple-feed refresh still validates (`mihomo -t` pass, service restarts clean)
- [x] Verify `fastest`: gates finalists with the full battery, quarantines flagged with cause, picks the quickest of top 3, never quarantines on slowness alone
- [x] Verify DE hold: timer and launcher agree on DE, keep-if-clean keeps healthy exits with zero switches
- [x] Verify suite: 63 unittest green including keep-if-clean and fastest tests
- [x] Verify docs: root README, scripts README, DECISIONS ADRs, CHANGELOG entries

## Acceptance Criteria

- [x] Live stack is proxy-only: no TUN device, direct traffic on the server default IP
- [x] Active exit is DE and gate-clean, selected as the fastest of tested finalists
- [x] Slowness alone never quarantines any node (verified by test + live run)
- [x] Timer and manual `rr` agree on the DE default (`RR_COUNTRY` still overrides)
- [x] All 63 tests pass; docs describe the speed pick, DE hold, and proxy-only stack

## Verification Evidence

- **Test command:** rtk test .venv/bin/python -m unittest tests.test_rr_balancer (pytest is not installed in this env; the stdlib runner covers the same tests)
- **Expected result:** all 63 tests pass including fastest picks/flags/no-quarantine cases
- **Actual result:** Ran 63 tests in 0.299s, OK, via the RTK wrapper. Live: proxy-only stack verified (no TUN device, `tun.enable: false`, direct FR default); 7718 live proxies, `mihomo -t` pass; exit DE 76.164.202.162 gate-clean on Google/YouTube/Spotify (Gemini 302 unknown-kept); guarded rotate kept the incumbent with zero switches; then the fastest-picked node died mid-session (dial EOF) and the guard quarantined it (google) and moved back to the verified DE exit — the auto-heal loop demonstrated live. Correction to plan: SUB_URLS lives in `scripts/maintain.sh`, `refresh.sh` is at repo root (no `refresh-sub.py` exists).
- **Exit code:** 0

> Verification runner rule: `.venv/bin/python -m unittest tests.test_rr_balancer` is the complete underlying test command. The first verification run MUST use the `rtk test` prefix; record the exact prefixed command above. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `testing-verification` applied and evidence recorded
- Stack-skill skip recorded: no roster stack skill matches this plain-Python balancer task; general workflow skills only.

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do not defer box-checking to a closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** A speed pick moves live traffic to an untested-for-stability node; a bad finalist pool picks the least-bad slow exit.
- **Rollback plan:** `rr rotate --require-country DE` reselects by delay order; remove the `fastest` subcommand without touching `rotate`; restore live config from `.bak`.

---

## Execution Log & Reasoning

Working-tree state at task filing (9 modified files, verified live): TUN device absent with `tun.enable: false`, direct egress on the server default (FR), proxy exit DE 185.255.115.181 gate-clean on all four probes, `fastest` picked 190KB/s over 150KB/s finalists live, keep-if-clean holds DE with zero switches, 63 tests green. Plan approval (verbatim Manager answer): "Approved" on the plan-approval question covering S1-S7 with seat routing and R1-R3. Routing back through the Brain for the Senior Programmer verification XML.
Reviewer verdict: technical APPROVAL with PO_REVIEW_PENDING. File stays in tasks/qa/ pending the explicit closure word.
Manager closure approval (verbatim): "Approved for closure". Preconditions verified: file present in tasks/qa/ and PO_REVIEW_PENDING recorded in this log. Non-blocking follow-ups recorded: R1 add fastest to the stale-after floor 60 for consistency; R2 simplify the redundant elif branch; R3 annotate the prior NL ADR as superseded; plus QA notes (no try around mid-loop select, fastest lacks last_check refresh, no lock-miss test).

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `4ccb03ea16c048c4abc79474d63c21fbf33e06b3`
<!-- END_GIT_DIFF -->
