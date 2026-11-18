# Task 23: Restore quota reason with 24-hour node quarantine

**File:** `tasks/completed/23-quota-reason-quarantine.md`
**Source:** manager
**Type:** improvement
**Status:** closed
**Finished:** 2026-11-18T13:22:14Z
**Submitted:** 2026-11-18T13:04:18Z

## Goal

Accept `--reason quota` in the `rr` balancer and make `rotate --reason quota`
quarantine the currently selected node for 24 hours before rotating to the next
alive node. A node that hits the free-tier quota is not reused inside that day.

## Source Context

`scripts/DECISIONS.md` records that the `quota`, `transport` and `region` causes
were removed when the old rescue plugin was retired. The plugin is active again,
so the `quota` cause is restored here. `QUARANTINE_SECONDS` is already 24h and
`alive_pool()` excludes quarantined nodes.

## Manager's Notes

Assumptions:
- A1: `rr --reason quota` (bare launcher = `rotate`) quarantines the current
  node for 24h and rotates onward.
- A2: no per-cause counter or selection weighting is restored; quarantine alone
  satisfies the requirement.
- A3: the rescue-plugin half lives in the paired task in the other repo.
- A4: both repos stay uncommitted for Manager review; ZAC holds.

## Local TODOs

- [x] Add quota to --reason choices and add --reason to rotate
- [x] Quarantine current node on rotate --reason quota, then rotate; fail open when empty
- [x] Add unit tests for quota quarantine and rotate logging
- [x] Update scripts/DECISIONS.md ADR, scripts/README.md, root README.md, CHANGELOG.md
- [x] Run the balancer unit suite and record evidence
- [x] Finalize the task file

## Acceptance Criteria

- [x] `rr rotate --reason quota` sets `last_fail_cause=quota` and `quarantined_until=now+86400` on the current node
- [x] A different alive node is selected; with no other candidate the current node is kept and reported
- [x] `skip --reason quota` and `next --reason quota` are accepted
- [x] The new rotation is logged with reason `quota`
- [x] Balancer unit tests pass with exit code 0
- [x] `lint_task_file` passes

## Verification Evidence

- **Test command:** python3 -m unittest tests.test_rr_balancer
- **Expected result:** all balancer tests pass (exit 0)
- **Actual result:** `OK` (all `tests.test_rr_balancer` cases pass, including the 3 new QuotaReasonTest cases)
- **Exit code:** 0
- **Syntax command:** `python3 -m py_compile scripts/rr_balancer.py` → exit 0
- **CLI parse check:** `python3 scripts/rr_balancer.py --help` exit 0; `python3 scripts/rr_balancer.py rotate --reason quota --help` exit 0
- **Red phase:** before the implementation, QuotaReasonTest ran with 2 failures and 1 error (`cause '' != 'quota'`, argparse rejecting `quota`), then passed after the change
- **Full-suite note:** `python3 -m unittest discover -s tests -p 'test_*.py'` exits 1 with 2 failures in `tests/test_proxy_converter.py` (Clash/Sing-box REJECT rule shape). That file is untouched by this task; the failures are pre-existing and unrelated to the balancer.
- **Strict Tooling Gate:** plain Python stdlib CLI, no framework or stack skill matches; base gate is `py_compile` + balancer unit tests + `lint_task_file`

## Definition of Done

The task is NOT done unless ALL of the following are true:

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `testing-verification` applied and evidence recorded

## Risk & Rollback

- **Risk:** a 429 burst across many nodes quarantines a large part of the pool
  for a day; fail-open keeps the service alive when the pool is exhausted.
- **Rollback plan:** revert the rotate branch and argparse hunks from the staged
  diff; existing `skip`/`next` behavior is unchanged.

---

## Execution Log & Reasoning

The Manager ordered a different response to a free-tier 429: do not switch models, pass `--reason quota` to `rr` and quarantine the spent exit for 24h. Typo corrections: quota, reason, quarantine, hours, inside. A1: `rr --reason quota` means the bare launcher (= `rotate`) parks the current node then picks the next alive one. Historical context from `scripts/DECISIONS.md`: the `quota` cause was removed with the old rescue plugin; this task restores only that cause, not `transport` or `region`.

Step 1 — Tests first. Added `QuotaReasonTest` to `tests/test_rr_balancer.py`: quarantine current and select the next node with rotation reason `quota`; fail open to the current node with reason `quota-failopen` when it is the only candidate; argparse accepts quota on rotate/skip/next. Before implementation the focused run had 2 failures and 1 error.

Step 2 — Balancer. Added `--reason` to the `rotate` parser and `quota` to the `skip`/`next` choices. In `cmd_rotate`, when the reason is `quota` and a current selection exists, `_mark_failed()` sets `last_fail_cause=quota`, `status=failed`, `fails=max_fails` and `quarantined_until=now+QUARANTINE_SECONDS` (24h). The current node is removed from this run's ordered candidates. With no candidates left, the current node is reselected, a `quota-failopen` log line is written, and the function returns 0. The normal rotation INSERT now logs `log_reason` (`quota` for this path, `rotate` otherwise), replacing the hardcoded literal. `_mark_failed`'s docstring was updated to describe the restored cause and the absence of a counter.

Step 3 — Verification. Focused suite and full balancer suite exit 0; `py_compile` and CLI help checks exit 0. The full repo suite still has 2 pre-existing failures in `test_proxy_converter.py` about REJECT rules; that file is not in this task's diff.

Step 4 — Docs. Added a reversal ADR to `scripts/DECISIONS.md`, updated both READMEs' failure-cause bullets, and added one Unreleased/Changed entry to CHANGELOG. ZAC held: no `git add`, `git commit`, `git checkout`, or `git push`; both repos remain uncommitted for Manager review.

Review chain: `[QA Engineer]` returned `QA_PASSED` with V1-V5 and three advisory missing-test notes. `[Code Reviewer]` returned `PO_REVIEW_PENDING` — technically approved, three low-severity clarity notes. One was applied afterward: the root README now states that quota has no counter and the 24h quarantine is the whole mechanism. The reviewer's launcher question was verified: `~/.local/bin/rr` forwards all arguments to `rr_balancer.py`, so `rr --reason quota` reaches `rotate`. Verdict relayed to the Manager.

Manager closure instruction (verbatim): "close both tasks".

Closure honoured 2026-11-18: QA_PASSED and PO_REVIEW_PENDING verified, this repo's task moved to tasks/completed/.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `9a9bb3c3543fb7bcd0e8a8d188bd651664ad646b`
<!-- END_GIT_DIFF -->
