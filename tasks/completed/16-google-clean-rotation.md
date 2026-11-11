# Task 16: Google-clean rotation gate for the balancer

**File:** `tasks/completed/16-google-clean-rotation.md`
**Source:** manager
**Type:** feature
**Status:** closed
**Finished:** 2026-11-11T12:29:35Z
**Submitted:** 2026-11-11T12:14:24Z

## Goal

Stop the balancer from selecting exit nodes whose Google Search answers the
`/sorry` anti-abuse page. Every rotation candidate must return HTTP 200 for
`https://www.google.com/search?q=test` before it becomes the active node;
302 (`/sorry`) candidates are quarantined with a `google` cause.

## Manager's Notes

Manager context (paraphrased): Spotify and YouTube Music intermittently report
"not available in your country"; the server IP geolocates inconsistently and
Google sometimes blocks it. Manager asked whether mihomo itself could filter
based on which exits have a working Google Search, and to implement, redeploy
and test it in this repo.

Measurement first (2026-11-11): a 40-node sweep through mihomo's delay API
showed 27/40 nodes alive on gstatic and 27/40 passing the Google Search check
(no gstatic-only survivors). The active PROXY selection at the time
(`vless-0c0b9e2377bd`) answered 302 `/sorry`, which is the failure this gate
prevents.

## Key Finding (pre-implementation)

Google Search is the only cheap discriminator. `generate_204`, `gen_204` and
the autocomplete endpoints answer identically (204/200) on blocked and clean
IPs; only `/search` redirects flagged exits to `/sorry` (302, ~400 bytes)
while clean exits return 200 (~94 KB). The gate therefore costs one search
request per candidate rotation, not per node per interval.

**mihomo's `/delay` endpoint cannot see the block**: it follows the 302 to
`/sorry` and reports the final 200, so `expected=200` passes on a blocked
exit. Verified live — `expected=200` returned `{"delay":363}` for a node that
answered 302 through the same selector. The gate therefore reads Google
through the live mixed-port with redirects disabled.

The live PROXY group is a `Selector` driven by `scripts/rr_balancer.py`
(rotate every few minutes), so mihomo's own `url-test` health check on the
`Auto` group does not control the active path. The gate belongs in the
balancer's rotation decision.

## Design

- `ClashAPI.delay()` gains an optional `expected` status passed to mihomo's
  `/proxies/{name}/delay` endpoint (kept for callers that want it).
- `probe_status_via_proxy(url, proxy, timeout)` reads the URL through the
  mihomo mixed-port with `_NoRedirect`, returning the real 302/200.
- `google_clean(api, group, name, ...)` selects the candidate and probes it
  through the live selector, so the check matches what a client sees.
- `google_reachable_direct(url)` probes the same URL from the host without a
  proxy. If it fails, the gate is skipped for that run so a Google outage
  cannot quarantine the whole pool (infra guard).
- `cmd_rotate` walks the pool in the existing preference order
  (uses → quota_fails → delay), rejects up to `--google-attempts` candidates
  for `/sorry`, records them with `_mark_failed(..., "google")` (24 h
  quarantine, new `google_fails` counter), and fails open to the best
  candidate if every attempt is blocked.
- New flags on `rotate` / `skip` / `next`: `--google-url`,
  `--google-timeout-ms`, `--google-attempts`, `--no-google-check`.
- Schema: `google_fails` column plus an idempotent migration for existing DBs.
- `retest` is unchanged: the gate runs at rotation time to keep bandwidth
  flat (one ~94 KB request per candidate instead of a 500-node sweep).

## Local TODOs

- [x] Add `expected` support to the delay probe
- [x] Add `google_clean` + direct-reachability guard
- [x] Add `google` failure cause, counter, schema column and migration
- [x] Gate `cmd_rotate` with bounded attempts and fail-open
- [x] Add CLI flags and validation
- [x] Add unit tests (skip blocked, fail open)
- [x] Full test suite green
- [x] Live rotation verified against a blocked node
- [x] Stage + QA transition

## Acceptance Criteria

- [x] A blocked candidate is quarantined with `last_fail_cause='google'`
- [x] Rotation selects a Google-clean candidate when one exists
- [x] All-blocked pool fails open instead of selecting nothing
- [x] `--no-google-check` restores the previous behavior
- [x] Full test suite passes
- [x] Live `curl` through mihomo returns 200 for Google Search after rotation

## Definition of Done

- [x] Rotation skips and quarantines `/sorry` exits with cause `google`
- [x] Clean candidate is selected and verified live (200)
- [x] Fail-open path covered by a unit test
- [x] Full test suite green (58 passed)
- [x] CHANGELOG, README, schema and task docs updated
- [x] Sibling slice docs (`scripts/README.md`, `scripts/DECISIONS.md`) added
- [ ] Manager commit/push

## Verification Evidence

- **Format command:** `.venv/bin/black --check scripts/rr_balancer.py tests/test_rr_balancer.py`
- **Expected result:** both files already formatted
- **Actual result:** `2 files would be left unchanged` (after fixing the drift noted below)
- **Exit code:** 0

- **Test command:** `rtk test .venv/bin/python -m pytest tests/ -q`
- **Expected result:** full suite green with preserved exit code
- **Actual result:** `58 passed in 0.67s`
- **Exit code:** 0

- **Test command:** `.venv/bin/python -m pytest tests/test_rr_balancer.py -q`
- **Expected result:** all balancer tests pass, including the two new gate tests
- **Actual result:** 36 passed
- **Exit code:** 0

- **Test command:** `.venv/bin/python -m pytest tests/ -q`
- **Expected result:** full suite green
- **Actual result:** 58 passed
- **Exit code:** 0

- **Test command:** `.venv/bin/python -m py_compile scripts/rr_balancer.py`
- **Expected result:** compiles
- **Actual result:** COMPILE_OK
- **Exit code:** 0

- **Live check before:** `curl -x 127.0.0.1:7890 https://www.google.com/search?q=test`
- **Expected result:** 302 (active node `vless-0c0b9e2377bd` blocked)
- **Actual result:** 302, location `https://www.google.com/sorry/index?...`
- **Exit code:** 0

- **Live rotation:** `scripts/rr_balancer.py next --reason google`
- **Expected result:** blocked node quarantined, a clean candidate selected
- **Actual result:** `skip: marked vless-0c0b9e2377bd failed (google, quarantined 24h)` → `rotate: selected hysteria2-95535cec6abf (delay 15ms)`
- **Exit code:** 0

- **Live check after:** `curl -x 127.0.0.1:7890 https://www.google.com/search?q=test`
- **Expected result:** 200
- **Actual result:** 200
- **Exit code:** 0

- **Gate discrimination:** `probe_status_via_proxy` against each node
- **Expected result:** blocked 302, clean 200
- **Actual result:** `vless-0c0b9e2377bd → 302`, `hysteria2-95535cec6abf → 200`
- **Exit code:** 0

- **DB state:** `SELECT name,status,last_fail_cause,google_fails FROM nodes WHERE google_fails>0`
- **Expected result:** both rejected nodes recorded with cause `google`
- **Actual result:** `vless-0c0b9e2377bd failed google 1`, `hysteria2-f069184d3bd9 failed google 1`
- **Exit code:** 0

## Risk & Rollback

- **Brief flapping during probing**: the gate selects a candidate to probe it, so a rejected node carries traffic for ~0.3s before the next candidate is tried. Bounded by `--google-attempts` (5).
- **Google outage**: `google_reachable_direct` fails first and the gate is skipped for that run, so a Google-side incident cannot quarantine the pool.
- **Cost**: one search request per candidate (~94 KB on a pass, ~0.4 KB on a block); at normal rotation rates this is negligible.
- **Rollback**: `--no-google-check` disables the gate instantly; the new `google_fails` column is additive and old code ignores it, so reverting the script alone is safe.

## Execution Log & Reasoning

- The gate lives in `cmd_rotate` rather than a mihomo `url-test` group because
  the live path is a `Selector` rotated by this script; changing the `Auto`
  group would not affect it.
- `/search` is the only endpoint that distinguishes `/sorry`, so the probe is
  intentionally heavier than the gstatic liveness check. Running it once per
  rotation keeps total traffic low.
- Fail-open on an all-blocked pool preserves availability; the alternative
  (no-op) would leave the client without a proxy.
- Correction after the first live attempt: mihomo's `/delay?expected=200`
  returned success for a node that answered 302 to real traffic, because the
  probe follows the `/sorry` redirect to a 200 page. The probe was moved to
  the live mixed-port with redirects disabled; the API path is kept only for
  callers that still want it.
- QA-gate pass: `black --check` failed on the two changed files (black is the
  project's configured formatter) because the new `order_pool` signature and
  the patch context-manager blocks were not in black's shape. Fixed with native
  edits; the formatter now reports both files unchanged. The remaining `ruff`
  findings are pre-existing in this file (baseline at `HEAD` reports 66, the
  categories `UP006`/`UP031`/`BLE001` exist throughout) and ruff is not part of
  this project's documented gate, so no style rewrite was attempted.
- Added `scripts/README.md` and `scripts/DECISIONS.md` (with the Google-gate
  ADR) plus a code-pointer line in the script, per the Living Folder Docs
  standard. `AGENTS.md`, `docs/conventions.md`, and `.gitignore` were audited
  in the same session; they are staged alongside this task's files and listed
  in the injected diff, because the Manager asked for the audit and the task
  work in one instruction.
- Live evidence still stands as recorded: the blocked node
  (`vless-0c0b9e2377bd`) quarantined with cause `google`, the clean candidate
  (`hysteria2-95535cec6abf`) selected, and `curl` through `127.0.0.1:7890`
  returning 200 after rotation. No re-run was needed for this gate pass.
- Lane note: the file already sat in `tasks/qa/`, so `custom_context_qa_transition`
  (which requires `tasks/in-progress/`) was not applicable; staging and diff
  injection ran through `custom_context_stage_and_inject_diff` with the explicit
  file list instead.

### QA Round — QA Engineer: QA_PASSED

- Verdict `QA_PASSED`, no blocking findings. Confirmed: idempotent migration
  (fresh CREATE plus ALTER-if-missing both carry `google_fails`), attempts
  bounded by `max(1, google_attempts)` with fail-open to `ordered[0]`, the
  direct-reachability guard preventing mass quarantine, 302 surfaced on both
  the normal response and the `HTTPError` path, and CLI validation rejecting
  `--google-timeout-ms < 500` and `--google-attempts < 1`.
- Risks accepted: a transport `None` counts as blocked, which is safe because
  the direct guard already proved Google reachable (so the failure is
  node-specific); `skip` accepts the Google flags without consuming them while
  `next` forwards them to `rotate`.
- Follow-up (non-blocking, not implemented): a unit test for the
  direct-unreachable skip path. Recommended for a later task so the reviewed
  diff is not changed after the QA verdict.

### Review Round — Code Reviewer: APPROVED (PO_REVIEW_PENDING)

- Verdict `APPROVED`, no blocking defects. Confirmed: gate placed in
  `cmd_rotate` as designed, probe through the live mixed-port with redirects
  disabled, direct-reachability guard, bounded attempts with fail-open,
  additive idempotent schema migration, consistent CLI surface with
  validation, two meaningful unit tests that keep the rest network-free, and
  CHANGELOG/README/`scripts` docs matching the code.
- Notes accepted as low severity: `skip` accepts the Google flags without
  consuming them (parser uniformity, `next` forwards them), `--google-proxy`
  is a fifth flag beyond the four named in Design (documented in CHANGELOG),
  and the direct probe uses `urlopen` so host proxy env vars would apply (none
  set here). Recommendations: add the direct-unreachable unit test in a later
  task and keep this diff stable.
- State: `PO_REVIEW_PENDING`. Awaiting the Manager's explicit closure word.

### Closure

- Manager answered `Approved for closure` to the closure gate.
- File moved to `tasks/completed/16-google-clean-rotation.md`, status set to
  `closed`, `**File:**` header synced.
- Commit runs through `custom_context_commit_and_clean_task`; `git push` stays
  with the Manager.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `7f1746282f0dfbf0c9a186a7b9f59637e152ef32`
<!-- END_GIT_DIFF -->
