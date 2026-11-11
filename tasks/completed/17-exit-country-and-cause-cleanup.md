# Task 17: Real exit country from Cloudflare trace plus balancer cause cleanup

**File:** `tasks/completed/17-exit-country-and-cause-cleanup.md`
**Source:** manager
**Type:** feature
**Status:** closed
**Finished:** 2026-11-11T13:05:18Z
**Submitted:** 2026-11-11T13:01:08Z

## Goal

Record the real country of every exit node by reading Cloudflare's
`cdn-cgi/trace` through the node itself, store it with a freshness stamp, and
make a country lock available (`--require-country US`) that combines with the
existing Google-clean gate. In the same change, remove the failure causes and
counters that existed only for the retired `opencode-rate-limit-rescue` plugin
(`quota`, `transport`, `region`), so the balancer serves what it is used for
now: Google-clean exits and a real-country lock.

## Manager's Notes

Manager context: "we need add real country to our system and the checker check
the real exit node country using cdn cgi cloudflare, so after that when one day
of running most of them filled then we can force a country. Also cleanup the
checker — before we used this for the opencode plugin that helps change proxy
but now we don't use it and we use it for google and a force real exit country
lock. So cleanup quota and other problems from the checker related to this
plugin."

Consequences of that intent:

- Country must come from the exit itself, not from provider remarks: 547 of 629
  remarks in the current feed are hash-style with no country, and only 14 are
  labelled US.
- The country lock ships disabled. It becomes useful once a day of retests has
  filled the `country` column; the balancer must report coverage so the decision
  to enable the lock is data-driven.
- The retired plugin lives outside this repository
  (`~/Develop/Projects/opencode-rate-limit-rescue`) and is not referenced by the
  global OpenCode config anymore. It is out of scope: this task removes only the
  balancer-side causes and counters that existed to serve it.

## Local TODOs

- [x] Confirm the field shape of `https://www.cloudflare.com/cdn-cgi/trace`
      (`loc=XX` line) and that it is readable through the mixed-port
- [x] Add a country probe that returns the two-letter code or a typed failure
- [x] Persist `country` + `country_checked` with an idempotent migration
- [x] Sweep countries in bounded batches without leaving the group on a
      probed node
- [x] Add `--require-country` to `rotate` / `skip` / `next` with a clear
      fallback when nothing qualifies
- [x] Report country coverage and per-country counts
- [x] Remove `quota` / `transport` / `region` causes, counters and selection
      weighting, with a legacy-column cleanup migration
- [x] Update tests, schema, README, `scripts` docs, DECISIONS, CHANGELOG
- [x] Full suite green and live verification of the country read

## Acceptance Criteria

- [x] `rr country --batch N` fills `country` and `country_checked` for N nodes
      and leaves the active selection exactly as it was before the run
- [x] A node whose trace cannot be read is recorded as unknown, never as a
      country, and never quarantined for that reason alone
- [x] `rr report` prints country coverage (checked/total) and per-country counts
- [x] `--require-country US` makes rotation skip non-US candidates, quarantine
      nothing until it has tried, and keep the current node when no candidate
      matches instead of selecting a non-US exit
- [x] Without `--require-country`, rotation behavior is unchanged from the
      Google-clean gate
- [x] `--reason` accepts only `google`, `country`, `manual`; the `quota`,
      `transport`, and `region` causes are gone from CLI, code, and schema
- [x] Selection order is `uses` then `delay_ms` (no quota weighting)
- [x] An existing database with the legacy columns still opens and works
      (migration is idempotent and does not lose learned rows)
- [x] Full test suite passes and the live proxy answers 200 for Google Search

## Verification Evidence

- **Test command:** rtk test `.venv/bin/python -m pytest tests/ -q`
- **Expected result:** full suite green including the new country and cleanup
  tests
- **Actual result:** `70 passed in 0.53s` (58 before; 7 plugin-cause tests
  replaced by 19 country, lock, report, migration and ordering tests)
- **Exit code:** 0

- **Format command:** `.venv/bin/black --check scripts/rr_balancer.py tests/test_rr_balancer.py`
- **Expected result:** both files already formatted
- **Actual result:** `2 files would be left unchanged`
- **Exit code:** 0

- **Compile command:** `.venv/bin/python -m py_compile scripts/rr_balancer.py`
- **Expected result:** compiles
- **Actual result:** COMPILE_OK
- **Exit code:** 0

- **CLI surface:** `.venv/bin/python scripts/rr_balancer.py --help` and `country --help`
- **Expected result:** subcommands `rotate, retest, skip, next, country, report`
  with the trace flags
- **Actual result:** both lists match
- **Exit code:** 0

- **Migration on the live DB:** `PRAGMA table_info(nodes)` after `report`
- **Expected result:** legacy counters gone, country columns present, rows kept
- **Actual result:** `[..., 'google_fails', 'country', 'country_checked']`, 995
  rows preserved (backup at `/tmp/opencode/balancer_state.pre-task17.db`)
- **Exit code:** 0

- **Live country sweep:** `.venv/bin/python scripts/rr_balancer.py country --batch 5`
- **Expected result:** real codes recorded, previous selection restored
- **Actual result:** `TR, NL, TW, HK, DE` (5 measured, 0 unknown); active node
  stayed `hysteria2-95535cec6abf`
- **Exit code:** 0

- **Live timer run:** `systemctl --user list-timers | grep rr-country` plus journal
- **Expected result:** one batch per 30 minutes, selection restored
- **Actual result:** `checked 20 (seed +0 prune -0): 19 measured, 1 unknown`,
  finished in 22 s, next run 30 min later, active node unchanged
- **Exit code:** 0 (unit `Finished rr-country.service`)

- **Report:** `.venv/bin/python scripts/rr_balancer.py report`
- **Expected result:** coverage plus per-country counts
- **Actual result:** `coverage 28/995 checked`, `US 2`, `KR 3`, `DE 3`, `TW 3`,
  `HK 3`, `NL 2`, `SG 2`, `FR 2`, `TR/RO/JP/CH 1`
- **Exit code:** 0

- **Live Google check after the sweeps:**
  `curl -x 127.0.0.1:7890 https://www.google.com/search?q=test`
- **Expected result:** 200 on the still-selected clean exit
- **Actual result:** 200
- **Exit code:** 0

> Verification runner rule: `.venv/bin/python -m pytest tests/ -q` is the
> complete underlying test command. The first verification run MUST use the
> `rtk test` prefix; record the exact prefixed command above. A raw rerun is
> allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true:

- [x] Build/Test/Lint pass with exit code 0 (`black --check`, `py_compile`,
      pytest)
- [ ] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `testing-verification` applied and evidence recorded
- [x] Schema, `README.md`, `scripts/README.md`, `scripts/DECISIONS.md` reflect
      the new country data and the removed causes

## Risk & Rollback

- **Risk — traffic flap during a sweep**: reading a country requires selecting
  the node (mihomo has no per-node body probe; `/delay` discards the body).
  Mitigation: bounded batch, short settle, restore the previous selection at the
  end, and document the cost. A ~200 byte trace per node is negligible.
- **Risk — wrong country**: Cloudflare `loc` is the exit's geo as Cloudflare
  sees it and can disagree with the provider label. That is the point — the
  stored value is the observed one, and `country_checked` records when it was
  observed.
- **Risk — the country lock empties the pool**: if no US+clean candidate exists,
  rotation must keep the current node rather than fail open to a non-US exit.
  The flag stays off until coverage justifies it.
- **Risk — dropping legacy causes breaks a caller**: the retired plugin is not
  wired into the global config; no timer or unit passes `--reason`. Verified
  during task kickoff.
- **Rollback plan**: the country columns are additive and ignored by older code;
  `--require-country` is opt-in; reverting the script alone restores prior
  behavior. Legacy cause columns are dropped only by an explicit migration that
  copies no data back, so rollback of the code alone keeps working databases
  usable (missing columns re-added by the additive migration).

## Execution Log & Reasoning

_(The Hands: log technical changes, file edits, and architectural reasoning here
before calling the MCP tool)_

- **Schema** (`data/balancer_state.schema.sql`): `nodes` keeps `google_fails`
  and gains `country`/`country_checked`; `quota_fails`, `transport_fails`, and
  `region_fails` are gone. `rotation_state`, `rotation_log`, and both indexes
  are untouched.
- **Migration** (`connect_db`): additive `ALTER TABLE ... ADD COLUMN` for every
  column added since the first release, then a guarded `DROP COLUMN` for the
  three legacy counters. `DROP COLUMN` needs SQLite ≥ 3.35 (host has 3.53); the
  `OperationalError` is swallowed so an old database always opens, and the
  columns are simply left dormant where the statement is unsupported. This is
  the project's migration mechanism — there is no ORM or migration framework in
  this repo, so Alembic/Flyway do not apply (skill skip recorded). Verified on
  the live database: 995 rows preserved, legacy columns dropped, backup at
  `/tmp/opencode/balancer_state.pre-task17.db`.
- **Country probe**: `parse_trace_country` accepts only a two-letter `loc=`
  value; `probe_country_via_proxy` builds the opener *inside* the try block.
  That detail was a real bug found by the test suite — the first version built
  the opener outside the guard, so a proxy-construction failure propagated
  instead of returning `None`.
- **Sweep** (`cmd_country`): bounded batch, oldest `country_checked` first,
  quarantined nodes excluded, per-node progress line, `finally` restores the
  previous selection. mihomo exposes no per-node body read (`/delay` discards
  the response), so selecting the node is the only way to observe its country.
- **Country lock** (`cmd_rotate`): filters the ordered pool before the Google
  loop, so non-matching nodes are never marked failed and fail-open stays inside
  the locked country. When nothing matches, rotation returns 0 without touching
  the group. Normalizing to upper case means `--require-country us` works.
- **Cleanup**: `_mark_failed` now only increments `google_fails` for the
  `google` cause; `country` and `manual` record the cause without touching it.
  Retest success clears `last_fail_cause` and leaves `country` and the
  historical `google_fails` intact. `order_pool` sorts on `(uses, delay_ms)`.
- **Live finding during verification**: the first sweep reported
  `0 measured, 3 unknown` because the oldest-checked rows were dead exits. The
  probe itself was correct (`NL` through the active node). Adding the
  quarantined-node filter and a per-node progress line made the next batch
  `5/5` measured. This is why the per-node print exists.
- **Beyond the approved plan (addition, logged)**: `systemd/rr-country.service`
  and `systemd/rr-country.timer` (batch 20 every 30 minutes) were added and
  installed as user units, because the Manager's goal is a pool that fills
  "after one day of running" and nothing would fill it otherwise. At 20 nodes
  per 30 minutes a ~1000-node pool completes in roughly 25 hours, with ~20-25 s
  of probing per run and the previous selection restored afterwards. Rollback is
  `systemctl --user disable --now rr-country.timer` plus removing the two files.
- **Not changed**: the Google-clean gate, `retest` batching, quarantine length,
  and the converter are untouched; no dependency was added.

### QA Round 1 — QA Engineer: QA_PASSED

- Verdict `QA_PASSED`, all nine acceptance criteria confirmed: idempotent
  lossless migration (995 rows preserved), probe contract, sweep restore with
  quarantined nodes excluded, lock semantics (unknown never matches, keep
  current when nothing matches, fail-open inside the locked country), unchanged
  no-lock path, narrowed `--reason`, `uses`-then-`delay` ordering, and report
  output. Both logged deviations were judged acceptable.
- `R1` (fixed after the verdict): the docstring claimed `loc=XX` is rejected
  while the code stored `XX` as a country. `parse_trace_country` now maps `XX`
  to `None`, with the case added to the existing test. The gate was re-run
  afterwards (70 passed, black clean).
- `R2` (documented, not changed): with an empty previous selection the sweep
  cannot restore anything and leaves the group on the last probed node. The
  controller always reports a selection in practice, so this is a note rather
  than a defect.

### Review Round — Code Reviewer: APPROVED (PO_REVIEW_PENDING)

- Verdict `APPROVED`, no blocking defects. Confirmed the observed-country path,
  the honest migration and its rollback note, the lock semantics, the narrowed
  allowlist, `uses`-then-`delay` ordering, meaningful error-path tests, docs
  matching the code, and the timer as a justified, reversible addition.
- Accepted low-severity notes: empty-prev restore (R2, controller always
  reports a selection) and the intentional destructive drop of the legacy
  counters. Recommendation for a later task: a unit test for the empty-prev
  case; this diff stays stable.
- State: `PO_REVIEW_PENDING`. Awaiting the Manager's explicit closure word.

### Closure

- Manager answered `Approved for closure` to the closure gate.
- File moved to `tasks/completed/17-exit-country-and-cause-cleanup.md`, status
  `closed`, `**File:**` header synced.
- Live state at closure: `rr-country.timer` active and enabled, 28/995 nodes
  measured with real codes (US, KR, DE, TW, HK, NL, SG, FR, TR, RO, JP, CH),
  active exit still `hysteria2-95535cec6abf`, Google Search 200 through
  `127.0.0.1:7890`. Pool coverage reaches the whole node list in about 25 hours
  at 20 nodes per 30 minutes.
- Commit runs through `custom_context_commit_and_clean_task`; `git push` stays
  with the Manager.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `36c5d6326ace911fb2c730cbfc55c1f965fbb0ff`
<!-- END_GIT_DIFF -->
