# Task [11]: 24h quarantine for failed nodes

**File:** `tasks/completed/11-failed-node-quarantine.md`
**Source:** manager
**Type:** feature
**Status:** closed

## Goal

Nodes marked failed (manual `rr`/`skip`, OpenCode auto-trigger on 429, or retest failures) stay out of rotation for 24 hours before becoming eligible again, so the balancer never reconnects to a recently rate-limited exit.

## Manager's Notes

Manager order (Persian, paraphrased): define a new task, complete it, deploy it, restart, with Brain autopilot locked. Goal is 100%: today a failed node can return within ~30min via retest readmission; every failed node must wait 24h before reuse. Follow-up finding: the OpenCode auto-trigger already exists and runs `rr` itself on 429s (recent rotations were OpenCode's, not manual).

## Local TODOs

- [x] Add quarantine timestamp to failed nodes (failed_until = failed_at + 24h)
- [x] Exclude quarantined nodes from the rotation pool until expiry
- [x] Exclude quarantined nodes from retest batches until expiry (no wasted checks)
- [x] Expired quarantine readmits automatically (retest reconfirms liveness)
- [x] Tests for quarantine set/expiry/exclusion; migrate + deploy + restart + verify live

## Acceptance Criteria

- [x] A node failed by any path is unselectable for 24h
- [x] Retest skips quarantined nodes (no probe waste, no early readmit)
- [x] After expiry the node re-enters via normal retest confirmation
- [x] Live verify: fail a node, confirm 24h exclusion, traffic stays healthy

## Verification Evidence

- **Test command:** ./.venv/bin/python -m unittest discover -s tests (incl. 5 new QuarantineTest, TDD RED then GREEN)
- **Expected result:** all pass
- **Actual result:** 32 tests OK, exit 0; py_compile exit 0
- **Exit code:** 0

- **Test command:** migration dry-run on live DB copy (/tmp/opencode/mig-test.db)
- **Expected result:** column added, all rows preserved with default 0, idempotent reopen
- **Actual result:** quarantined_until present, rows 3560/3560, defaults 3560, reopen OK
- **Exit code:** 0

- **Test command:** live `rr` (skips current node, rate-limited era)
- **Expected result:** node marked failed with +24h quarantine, rotation advances, traffic healthy
- **Actual result:** E18483 quarantined until 2026-10-11 21:06:26; rotated to FCDE3D (14ms); DB shows failed + quarantined; exit IP + example.com 200
- **Exit code:** 0

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** schema change on live DB (new column); pool shrinks if many nodes quarantined at once
- **Rollback plan:** revert script + restore DB from pre-deploy copy; rotation falls back to current behavior

---

## Execution Log & Reasoning

- Autopilot locked for task 11 on manager order (Persian): new task, complete, deploy, restart, Brain autopilot locked, goal 100%.
- Brain bridge absent from this environment's tool catalog (verified twice via search); proceeded with direct plan from repo knowledge + supervised approval gate per AGENTS.md. Plan approved verbatim by manager.
- Implementation: `QUARANTINE_SECONDS = 24*3600`; `nodes.quarantined_until` column (schema.sql + idempotent ALTER in connect_db); `_mark_failed` + retest-failure transition set now+24h; success resets to 0; `alive_pool` + retest batch exclude future-quarantined rows; old failed rows (0) stay immediately eligible.
- Deploy note: migration runs inside connect_db on next timer/manual run; live DB backup at /tmp/opencode/balancer_state.pre11.db; no service restart needed (timers invoke the script fresh). Observed: OpenCode auto-trigger rotates on its own (controller moved past my manual pick) — system working as designed.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `8e701700bcbf192225327bebff2ca7bb035b0436`
<!-- END_GIT_DIFF -->

## Locked-Mode QA Verdict (self-review, Brain bridge absent from tool catalog)

- VERDICT QA_PASSED. Adversarial review of the staged diff (schema, connect_db migration, _mark_failed, alive_pool, retest batch/success/failure paths):
- F1 exact-24h boundary (quarantined_until == now eligible) — correct, no off-by-one harm.
- F2 failed nodes re-failing after expiry get a fresh 24h window — intended.
- F3 clock jumps backward only lengthen quarantine — acceptable, fail-safe direction.
- F4 success path resets quarantine to 0 — harmless (batch excludes quarantined anyway).
- F5 pre-existing failed rows (quarantined_until=0) stay immediately eligible — intended migration behavior.
- No blocking defects. Suite 32/32 green + live skip proof on record.

## Review Gate

- Code Review verdict: APPROVED technically, status PO_REVIEW_PENDING. Manager accept quote: "Approved for closure".
