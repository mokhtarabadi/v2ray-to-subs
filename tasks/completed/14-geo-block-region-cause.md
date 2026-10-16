# Task [14]: Geo-block failure cause for rotation and rescue

**File:** `tasks/completed/14-geo-block-region-cause.md`
**Source:** manager
**Type:** feature
**Status:** closed

## Goal

Handle provider region blocks (`RegionError`, model not available in the exit's country) as a first-class rotation cause so geo-blocked exits quarantine like other failures and the rescue loop rotates away from them.

## Manager's Notes

Manager context (paraphrased): OpenCode failed with a region error for the model in the current exit country. Asked to handle this error class too. Approved a 3-step plan (balancer reason, plugin detector, verification) as a quick fix without Kanban tracking, then ordered the finished changes formalized into a task and run through the Brain pipeline on autopilot.

## Key Finding (pre-implementation)

Region blocks are provider-side country refusals, unrelated to rate limiting or network faults, but `rr` rotation (new exit country) fixes them the same way. The balancer already records per-cause counters (`quota_fails`, `transport_fails`) with 24h quarantine, so a parallel `region_fails` counter fits without design change. The rescue plugin's retry hook is model-gated for quota but region blocks hit paid and free models alike, so the detector is model-independent. Plugin files live outside this repo (`~/.config/opencode/plugins/rate-limit-rescue/`) and are a companion change, not part of this diff.

## Design

- `scripts/rr_balancer.py`: `--reason` accepts `region` on `skip` and `next`; `_mark_failed` increments `region_fails` and quarantines 24h like other causes.
- `data/balancer_state.schema.sql`: `region_fails` column added; existing DBs self-upgrade through the idempotent migration in `connect_db` (no reseed).
- `tests/test_rr_balancer.py`: per-cause test mirroring the quota/transport cases.
- Companion (separate repo, already has region support): rescue plugin source of truth is the private GitHub repo `mokhtarabadi/opencode-rate-limit-rescue`, installed as `github:mokhtarabadi/opencode-rate-limit-rescue`; it detects `RegionError` / country-unavailable text model-independently, runs `rr next --reason region`, tags metrics `kind: "region"`. The old `~/.config/opencode/plugins/rate-limit-rescue/` path is not source — never edit it.

## Local TODOs

- [x] Add `region` reason to balancer CLI, counter, schema, and migration
- [x] Add per-cause unit test
- [x] Migrate live DB and verify argparse accepts/rejects correctly
- [x] Run full repo test suite
- [ ] Brain QA adversarial testing on the staged diff
- [ ] Brain reviewer final review
- [ ] Stage, move to qa lane, report verdict

## Acceptance Criteria

- [x] `rr next --reason region` marks a node failed with `region_fails=1` and 24h quarantine
- [x] Old DBs gain the column automatically on next run
- [x] Full test suite green
- [ ] Brain QA passes on the diff
- [ ] Brain reviewer approves

## Verification Evidence

- **Test command:** rtk test .venv/bin/python -m pytest tests/test_rr_balancer.py -q
- **Expected result:** all balancer tests pass including the new region case
- **Actual result:** 32 passed
- **Exit code:** 0

- **Test command:** rtk test .venv/bin/python -m pytest tests/ -q
- **Expected result:** full suite green
- **Actual result:** 53 passed
- **Exit code:** 0

- **Test command:** python3 -m py_compile scripts/rr_balancer.py
- **Expected result:** compiles
- **Actual result:** COMPILE-OK
- **Exit code:** 0

- **Test command:** .venv/bin/python scripts/rr_balancer.py --db /tmp/x-region-test.db --secret-file /dev/null next --reason region (argparse smoke)
- **Expected result:** reason accepted (fails later only on missing secret, unrelated)
- **Actual result:** `--reason region` accepted; `--reason bogus` rejected with invalid choice
- **Exit code:** 0

- **Test command:** live DB migration via connect_db + PRAGMA table_info
- **Expected result:** region_fails present, old rows intact
- **Actual result:** True, cols [fails, quota_fails, transport_fails, region_fails]
- **Exit code:** 0

- **Tooling gate skip record:** root marker scan list [go.mod, build.gradle.kts, Package.swift, pyproject.toml, package.json, vite.config, nuxt.config, nest-cli.json]; matched skills []; repo root /home/mohammad/v2ray-to-subs; reason: plain Python (stdlib + PyYAML) + bash, no stack marker match.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [ ] Build/Test/Lint pass with exit code 0
- [ ] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append
- [ ] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** per-cause column added to a live table; a bad migration could lock or corrupt balancer state
- **Rollback plan:** snapshot the DB file before migration (`cp data/balancer_state.db /tmp/opencode/`); restore the file if anything fails (migration is additive-only, verified on the live DB already)

---

## Execution Log & Reasoning

- Mode: autopilot locked for this task on manager order to run the finished quick fix through the Brain pipeline.
- Seat Check: single-domain backend change (balancer CLI + counter + migration + test) → QA Engineer for the QA turn, then Code Reviewer; Designer/Architect/Planner skipped (no UI, no new schema design beyond one additive column mirroring existing ones, no sprint scope). Brainstorm: not required — additive change following the established per-cause pattern, already implemented and green.
- Implementation: already complete in worktree (quick-fix phase, uncommitted): `scripts/rr_balancer.py`, `data/balancer_state.schema.sql`, `tests/test_rr_balancer.py`, `README.md`, `CHANGELOG.md`. No further code planned unless QA or review demands fixes.
- CHANGELOG already carries the region entry under Unreleased/Added (Parse-Then-Append, no header duplication).

### Bridge rounds

- QA turn 1: QA_PASSED with test-only advisories (reverse isolation, quarantine assert, retest readmission for region rows).
- Closed F5/F6 in the same session: extended the region test with failed-status plus quarantine asserts and added a reverse-isolation test (quota leaves `region_fails` at 0). Full suite now 52 passed. F7 (cause-specific retest readmission) rides on the generic expiry path already covered by the quarantine tests.
- Reviewer turn: APPROVED (technical) → PO_REVIEW_PENDING. Reviewer advisories F1 (test name over-promises) and F2 (no next-path region test) closed the same session: test renamed to `test_other_causes_leave_region_fails_at_zero` covering quota/transport/manual, plus new `test_next_reason_region_records_cause`. Full suite now 53 passed. F3 (region in selection ranking) left as-is intentionally, matching transport behavior.
- PO gate: PO_REVIEW_PENDING relayed to manager; manager approval quote, exact: "Approved for closure".

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `7d00fea7239eb4b2658bed395b2108d0ff2d82ed`
<!-- END_GIT_DIFF -->
