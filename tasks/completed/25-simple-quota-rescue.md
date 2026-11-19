# Task 25: Simple Quota Rescue and Background opencode.ai Probe

**File:** `tasks/completed/25-simple-quota-rescue.md`
**Source:** manager
**Type:** improvement
**Status:** closed
**Submitted:** 2026-11-19T17:06:07Z
**Started:** 2026-11-19T17:05:49Z
**Finished:** 2026-11-19T17:19:02Z

## Goal

Simplify the v2ray-to-subs rescue path and make a quota event pick a genuinely
working exit. Five changes, approved by the Manager as one scope:

1. Make the quarantine duration configurable (env/CLI) and run with 12h.
2. Add a background real-HTTPS probe against `https://opencode.ai` (via the
   mixed port), modeled on `cmd_country`, persisted to the balancer DB.
3. Trim the redundant tests and fix the two failing ones, without losing
   coverage of rotation, quarantine, reason=quota, fail-open, or parsing.
4. Repair the failing `v2ray-to-subs-maintain.service` (invalid REALITY short
   ID at `mihomo -t`), so the 30-minute tick works.
5. Deploy both projects and restart services so the Manager can test together.

## Manager's Notes

- Manager chose "Do all five" from the assessment. Autopilot locked; ZAC holds.
- Seat Check: domain = Python backend + shell/systemd; trigger `quota` →
  Software Architect (owns DevOps); no UI/race/deadlock/performance triggers.
  Single-seat. Brainstorm not required: hard to reverse but not cross-disciplinary.
- Assumption A1: "cleaner / less complex" means the concrete five steps listed,
  not a wholesale rewrite of `proxy_converter.py` (2220 lines) or deleting the
  gate/country/keep-if-clean features, which are ADR-protected.
- Assumption A2: "12 hours" is a default set for this deployment via env, not
  a removal of the 24h default from the code.
- Assumption A3 (confirmed at plan approval): the Manager chose "No, bridge
  path is enough". A bare `rr` stays IP-only; this task does NOT make it POST
  `/api/session/rotate`. The quota path already clears session then calls rr.
- Plan-gate decisions (Manager, at approval):
  - 12h quarantine via BOTH a systemd drop-in `Environment=RR_QUARANTINE_SECONDS=43200`
    on `v2ray-to-subs-maintain.service` AND an `export RR_QUARANTINE_SECONDS=43200`
    in `scripts/maintain.sh`.
  - opencode.ai probe ON by default with a small batch of 20.
  - Plan approved; proceed to Senior Programmer implementation XML.

## Relevant Code Context

- `scripts/rr_balancer.py:84` `QUARANTINE_SECONDS = 24 * 3600` (hardcoded). Used
  at `:835` (`_mark_failed`) and `:1100` (`retest`). Text "24h" at `:302,631,808,816,845,1313`.
- `rr --reason quota` already quarantines current, removes it, picks next-best
  `(uses, delay_ms)` (`order_pool` `:324-328`), selects, fails open (`:630-652`).
- `cmd_country` `:1111-1166` is the select-probe-restore-in-finally pattern.
- `DEFAULT_PROXY_URL = "http://127.0.0.1:7890"` (`:46`); `probe_status_via_proxy`
  `:531-550`. No `opencode.ai` string exists anywhere in the repo.
- `scripts/maintain.sh:35,38` runs `retest --batch 1000`, `country --batch 40`,
  refresh if age > 21600s. Timer every 30 min (`systemd/v2ray-to-subs.timer`).
- `maintain.service` currently FAILED: `proxy 4328: invalid REALITY short ID`
  at `mihomo -t` validation (`refresh.sh:43`).
- Tests: 94 total, 3 files; `test_rr_balancer.py:1379`, `test_proxy_converter.py:261`,
  `test_stable_hash_naming.py:146`. Runner: `.venv/bin/python -m unittest discover
  -s tests -p 'test_*.py'` (pytest not installed). Current: `FAILED (failures=2)`
  — stale REJECT assertions at `test_proxy_converter.py:230,256`.
- `~/.local/bin/rr` is a symlink to `scripts/rr` — repo edits affect live command.

## Local TODOs

- [x] Plan approval via Brain + Manager (non-trivial, autopilot)
- [x] Get implementation XML from Senior Programmer via brain_turn
- [x] Configurable quarantine (env/CLI) with 12h deployment default
- [ ] Background opencode.ai HTTPS probe + DB persistence (cmd implemented; hook in next step)
- [ ] Trim/merge redundant tests and fix the two failing ones
- [ ] Repair REALITY short-ID validation failure
- [ ] Update sibling README.md / DECISIONS.md (living-folder docs)
- [ ] Run verification gates and record evidence
- [ ] Finalize task, chain QA/review, close on approval
- [ ] Deploy both projects, restart services, verify health

## Acceptance Criteria

- [x] Quarantine duration configurable, bounded by tests (12h runtime effective post-closure)
- [x] A real HTTPS request to `https://opencode.ai` runs in the background via
  the mixed port, verdict persisted, selection restored in `finally`
- [x] Test suite passes (0 failures); 17 new tests added, 1 stub removed, all
  five protected coverage areas intact (merges skipped to protect them)
- [ ] `v2ray-to-subs-maintain.service` runs without the REALITY short-ID failure (post-closure restart)
- [x] Sibling `README.md` and dated `DECISIONS.md` ADR updated
- [x] `python -m unittest discover` exits 0; `mihomo -t` on generated config exits 0
- [ ] Both projects deployed, services active, bridge health ok, opencode.ai probe recorded (post-closure)

## Verification Evidence

- **Test command:** .venv/bin/python -m unittest discover -s tests -p 'test_*.py'
- **Expected result:** OK, 0 failures
- **Actual result:** baseline (before edits) `Ran 94 tests ... FAILED (failures=2)` (the two stale REJECT assertions). After all edits `Ran 110 tests ... OK`, exit 0. Count rose from 94 because 17 new tests were added (11 probe + 6 sanitizer) and 1 stub-only test removed; the assessment's duplicate merges were deliberately skipped to avoid risking the protected coverage areas (recorded in Execution Log).
- **Exit code:** 0
- **Focused new suites:** `tests.test_opencode_probe` 11 pass; `tests.test_reality_short_id` 6 pass; both exit 0.
- **Mutation check (finally-restore):** disabling the `finally` restore in `cmd_opencode_probe` made `test_probe_persists_verdict_and_restores_selection_on_failure` fail; restored and re-passed.
- **REALITY sanitizer proof:** generating a fresh config from the three live feeds hit `invalid REALITY short-id '5596a94e2228791'` (15 chars, odd), sanitizer emitted empty with a warning, and `~/mihomo/mihomo -t -f <generated>` reported "configuration file ... test is successful" with exit 0. This is the exact validation that was failing in the maintain service.
- **Quarantine resolver checks:** default 86400, env 43200, CLI over env, empty env default, non-positive and non-integer rejected — all PASS (inline python assertions, exit 0).
- **DB migration checks:** fresh DB + existing old-schema DB + idempotent rerun all contain `opencode_ok/opencode_checked/opencode_delay_ms` — PASS.
- **Syntax checks:** `.venv/bin/python -m py_compile scripts/rr_balancer.py` exit 0; `.venv/bin/python -m py_compile proxy_converter.py` exit 0; `bash -n scripts/maintain.sh` exit 0.
- **Stack-skill skip:** repo root `/home/mohammad/v2ray-to-subs`; marker scan = `pyproject.toml`, `requirements.txt` (stdlib + PyYAML only), no Flask/FastAPI/NestJS/Next.js markers; matched skills = none; reason = plain Python scripts + shell + systemd, no framework blueprint. Used `testing-verification` discipline only.
- **Post-closure (not yet done):** deploy drop-in + restart maintain service + bridge, verify 12h effective at runtime, probe row recorded, bridge health ok.

QA round 1 (REJECTED) fixes — F1 fixed, F2 disputed:
- F1 (real): parser defined `--timeout-ms` with implicit dest `timeout_ms`, but
  cmd reads `args.opencode_timeout_ms`, so a real CLI run raised AttributeError
  inside the per-node try and every node recorded failure with no HTTPS request.
  Fixed by `dest="opencode_timeout_ms"` (scripts/rr_balancer.py). Added
  ProbeParserRoundTripTest (5 tests) that parses real argv. Mutation reverting
  the dest reproduced the AttributeError; restored and re-passed.
- F2 (disputed with evidence): QA claimed RR_OPENCODE_PROBE_ENABLED=0 is ignored.
  Exhaustive check: env UNSET -> enabled True, env=0 -> False, env=1 -> True;
  explicit `--enabled` -> True, `--no-probe` -> False. The QA-suggested
  `set_defaults` change would risk overriding explicit flags, so it was NOT
  applied (fix only what reproduces). Covered by 3 new parser tests.
- F3 (test-count 94->115, not the ~78 target): scope deviation, deliberately
  chosen to protect the five coverage areas; needs Manager waiver, not a code fix.
- F4 (log hours floor): cosmetic, non-blocking; not changed.
- M2 (overlong even-hex short-id): speculative; repo's own docs/singbox/changelog.md
  line 3166 records "Remove length limit on short_id", so no cap was added.
- Final full suite: `Ran 115 tests ... OK`, exit 0; py_compile and bash -n exit 0.

Review chain (chained directly via brain_turn under this session): `[QA Engineer]` first returned `QA_REJECTED` (F1 real parser dest bug, F2 false positive). F1 fixed and mutation-proven; F2 disproved with exhaustive env evidence; re-review returned `QA_PASSED`. `[Code Reviewer]` returned technical approval / `PO_REVIEW_PENDING` with S1-S4 strengths and I1 (test-count 94->115 waiver needed), I2 (shared-dest flag fragility, low/advisory, do not block), I3 (cosmetic hour floor, non-blocking). Verdict notice: "Code approved technically. PO, please review business logic and the test count waiver. Reply Approved for closure to commit and finish."

I1 waiver rationale: the suite grew because 22 new tests were added (11 probe + 6 sanitizer + 5 parser round-trip) and 1 stub removed; the assessment's duplicate merges were skipped to protect the five covered areas the Manager explicitly said to keep. Coverage is strictly greater, not weaker.

## Definition of Done

The task is NOT done unless ALL of the following are true:

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `testing-verification` applied and evidence recorded

## Risk & Rollback

- **Risk:** a background probe that selects/restores nodes could disturb the live
  PROXY selector. Mitigate with the `cmd_country` finally-restore pattern and a
  config flag defaulting the probe off until verified.
- **Risk:** trimming tests could drop quota/fail-open guards. Mitigate by keeping
  every protected test named in the assessment and re-running the full suite.
- **Rollback:** revert staged hunks in both projects. No commits without the
  explicit Manager closure word.

---

## Execution Log & Reasoning

Seat Check: domain Python backend + shell/systemd; trigger `quota` -> Software
Architect single seat; no UI/race/deadlock/performance triggers; brainstorm not
required (hard to reverse but not cross-disciplinary). Manager approved "Do all
five"; decisions: 12h via BOTH drop-in and maintain.sh export, probe ON by
default batch 20, bare `rr` stays IP-only (bridge path is enough).

Step 2 RED: baseline suite `Ran 94 tests ... FAILED (failures=2)` — the two stale
REJECT assertions in test_proxy_converter.py, as predicted.

Step 3 quarantine: added resolve_quarantine_seconds (CLI > RR_QUARANTINE_SECONDS
> 24h default, reject non-positive/non-integer), added --quarantine-seconds to
build_parser, resolved in main() with a loud error, threaded the effective value
into _mark_failed (new optional param) and retest (module global), and replaced
24h log strings with computed hours. os was already imported.

Step 4 DB: added opencode_ok/opencode_checked/opencode_delay_ms to the nodes
schema and to the idempotent connect_db migration; verified on fresh DB, an old
schema DB, and a repeat connect.

Step 5 probe: added probe_opencode_via_proxy (200-only, redirects off, returns
(ok, delay_ms)) and cmd_opencode_probe modeled on cmd_country — select, real
HTTPS GET via 127.0.0.1:7890, persist verdict, restore prior selection in
finally. Added opencode-probe subcommand with RR_OPENCODE_URL / RR_OPENCODE_PROBE_ENABLED
defaults. Per-node probe exceptions are caught so one failure cannot abort the
sweep. Mutation check: removing the finally restore failed the restore test.

Step 6 maintain.sh: exported RR_QUARANTINE_SECONDS=43200 after strict mode and
hooked `opencode-probe --batch 20` between retest and country. Created repo
drop-in systemd/v2ray-to-subs-maintain.service.d/quarantine.conf with
Environment=RR_QUARANTINE_SECONDS=43200. No service restarted or reloaded.

Step 7 REALITY: added _sanitize_reality_short_id (even-length hex or empty, warn
on invalid) and wired it into both Clash and sing-box emitters. Regenerating from
the live feeds hit a real 15-char odd short-id; the sanitizer emitted empty and
`mihomo -t` passed — the exact validation that broke the maintain service.

Step 8 tests: fixed the two stale REJECT assertions to the current no-REJECT
rule set (ADR 2026-11-15), removed the stub-only test_meta_members_never_in_pool,
added 17 new tests for new behavior. Did NOT force the assessment's duplicate
merges: each carried distinct mock scaffolding and assertions, and merging them
risked silently dropping protected coverage (rotation, quarantine timing,
reason=quota, fail-open, config parsing) which the Manager said to keep. Net
suite 94 -> 110 tests, all green. This trades the literal "fewer tests" target
for the higher-priority "no loss of protected coverage" requirement, logged here
rather than hidden.

Step 9 docs: scripts/README.md invariants 6-7 + background probe section,
scripts/DECISIONS.md dated ADR, CHANGELOG.md Added/Changed entries via
Parse-Then-Append.

ZAC held: no git add/commit/push, no systemctl restart or daemon-reload. Deploy
and restart are post-closure. Living-folder docs updated in the same task.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `43d32c44ce47a61262429d5e9b482f33c062fa8f`
<!-- END_GIT_DIFF -->
