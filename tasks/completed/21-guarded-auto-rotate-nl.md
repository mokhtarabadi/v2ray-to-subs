# Task 21: Guarded auto-rotate with NL lock

**File:** `tasks/completed/21-guarded-auto-rotate-nl.md`
**Source:** manager
**Type:** feature
**Status:** closed
**Finished:** 2026-11-16T12:53:09Z
**Submitted:** 2026-11-16T12:48:27Z
**Started:** 2026-11-16T12:42:38Z
**Closed:** 2026-11-16T12:52:27Z

## Goal

Land the working-tree NL switch and guarded auto-rotation: triple-feed pool, doubled tick batches, Netherlands exit with a fully gate-tested selection, `rotate --keep-if-clean` wired into the maintenance tick, and the `rr` launcher default flipped to NL.

## Manager's Notes

Direct orders from the live session, implemented in the tree and awaiting QA-to-closure: drop OpenRay for a combination of the top-starred feeds (barry-far All_Configs_Sub, 0xRadikal all/configs.txt, MatinGhanbari all_sub.txt); double tick batches (retest 1000, country 40); switch the live exit to the Netherlands with every probe verified; add `rotate --keep-if-clean` so the timer holds the best gate-tested NL node and moves only when dirty; flip the `rr` launcher default from US to NL so manual runs agree with the timer.

## Local TODOs

- [x] Verify triple-feed refresh: 9254 + 11517 + 3955 parsed, 7636 unique hosts, `mihomo -t` passes, service restarts clean
- [x] Verify NL exit: gate battery green on Google/YouTube/Spotify (Gemini 302 → unknown-kept), `loc=NL`
- [x] Verify `--keep-if-clean`: keeps clean incumbent without churn, quarantines dirty incumbent with cause and moves on, honors the country lock, handles no-current gracefully
- [x] Verify suite: 59 unittest green, new keep tests plus tri-state gate tests
- [x] Verify timer wiring: guarded rotate in `maintain.sh` with NL lock, fail-soft like the other tick jobs
- [x] Verify docs: root README, scripts README, DECISIONS ADR, CHANGELOG entry, launcher default

## Acceptance Criteria

- [x] Live config holds 7000+ proxies from the three feeds with validation passing
- [x] Active exit is NL and gate-clean on Google, YouTube, and Spotify
- [x] A tick with a clean incumbent performs zero switches; a dirty incumbent is quarantined with cause and replaced
- [x] Manual `rr` and the timer agree on the NL default (`RR_COUNTRY` still overrides)
- [x] All 59 tests pass; docs describe the guarded rotation and NL default

## Verification Evidence

- **Test command:** rtk test .venv/bin/python -m unittest tests.test_rr_balancer (pytest is not installed in this env; the stdlib runner covers the same tests)
- **Expected result:** all 59 tests pass including keep-if-clean keeps/rotates/no-current cases
- **Actual result:** Ran 59 tests in 0.326s, OK, via the RTK wrapper. Live: 7646 proxies (vless/vmess/trojan/ss/hysteria2/socks5/tuic), `mihomo -t` pass, exit NL 51.158.206.34 with Google 200 + YouTube/Spotify clean + Gemini 302 unknown-kept, guarded rotate kept incumbent with zero switches. Correction to plan: SUB_URLS lives in `scripts/maintain.sh` (no `refresh-sub.py` exists; `refresh.sh` takes feed URLs as args).
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

- **Risk:** Auto-rotate on the timer moves live traffic without an operator watching; a gate false-positive could quarantine a working exit.
- **Rollback plan:** Remove the rotate line from `maintain.sh`; flip the launcher default back to US; `--keep-if-clean` stays inert unless passed; live config `.bak` files restore the previous pool.

---

## Execution Log & Reasoning

Working-tree state at task creation (8 modified files, verified live before filing): triple-feed refresh green (7634 proxies, mihomo -t pass), NL exit 51.158.206.34 with G/Y/S clean and Gemini 302→unknown-kept, `--keep-if-clean` implemented with 3 new tests (59 total green), timer wiring syntax-checked, launcher default NL, docs synced. Plan approval (verbatim Manager answer): "Approved" on the plan-approval question covering S1-S7 with seat routing and R1-R3. Routing back through the Brain for the Senior Programmer verification XML.
Reviewer verdict: technical APPROVAL with PO_REVIEW_PENDING. File stays in tasks/qa/ pending the explicit closure word.
Manager closure approval (verbatim): "Approved for closure". Preconditions verified: file present in tasks/qa/ and PO_REVIEW_PENDING recorded in this log. Non-blocking follow-ups recorded: R1 log fail-open selections with a distinct rotation-log reason; R2 refresh last_check on keep or document retest ownership; R3 add a non-NL-incumbent lock+keep interaction test.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `f8b417745b35d2bae7c407faf6f10cc26fa79d27`
<!-- END_GIT_DIFF -->
