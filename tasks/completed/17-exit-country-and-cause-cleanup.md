# Task 17: Real exit country from Cloudflare trace plus balancer cause cleanup

**File:** `tasks/completed/17-exit-country-and-cause-cleanup.md`
**Source:** manager
**Type:** feature
**Status:** closed
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
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 5b1003a..49638d9 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -28,6 +28,8 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 
 ### Changed
 
+- `rr_balancer.py` gained observed exit country: `country`/`country_checked` columns, `rr country --batch N` (Cloudflare `cdn-cgi/trace` `loc`, oldest-first, previous selection restored, unreadable traces stored as unknown without quarantine), `rr report` (coverage plus per-country counts), and `--require-country CC` on `rotate`/`skip`/`next` which keeps the current node when no candidate matches. Selection order is now `uses` then `delay_ms`.
+- Balancer cause cleanup: the `quota`, `transport`, and `region` failure causes, their counters, and their per-cause selection weighting were removed with the retired `opencode-rate-limit-rescue` plugin they served. `--reason` accepts `google|country|manual`; existing databases drop the legacy columns through a guarded `DROP COLUMN` migration that keeps every learned row.
 - `AGENTS.md` brought in line with the audit criteria: the lite-mode bypass removed so every task runs the full workflow, the task-generator reference corrected to `kanban-lifecycle`, the QA transition routed through `custom_context_qa_transition`, and Edit Tool Discipline, Parallel Index Isolation, and Living Folder Docs Inspection rules added. `docs/conventions.md` gained the Edit Tool Discipline and Living Folder Docs Standard sections; `.gitignore` now covers goal-plugin runtime state.
 
 ### Fixed
diff --git a/README.md b/README.md
index e9c1e10..0871bd9 100644
--- a/README.md
+++ b/README.md
@@ -164,7 +164,9 @@ when a target rate-limits an exit IP, the crawler reports the cause
 and the balancer moves traffic to the next best node automatically:
 
 - **Rotate**: manual only — bare `rr` skips the current node and picks least-used + fastest (`rr-rotate.timer` is intentionally disabled)
-- **Failure causes**: `rr next --reason quota|transport|region|google` (default `manual`) records per-cause counters; selection order is least-used, then fewest quota fails, then fastest — exits that hit crawl rate limits sink in priority without being deleted; `region` (geo-blocked from a provider country check) is tracked separately and quarantined like the others
+- **Failure causes**: `rr next --reason google|country|manual` (default `manual`) records the cause and quarantines 24h; `google` also increments `google_fails`. The old `quota`/`transport`/`region` causes belonged to the retired rate-limit-rescue plugin and are gone
+- **Country**: `rr country --batch 20` reads `https://www.cloudflare.com/cdn-cgi/trace` through each selected node and stores the observed exit country (`country`, `country_checked`); unreadable traces are stored as unknown, never as failures. `rr report` prints coverage (checked/total) and per-country counts. `rr-country.timer` runs one batch every 30 minutes, so a ~1000-node pool fills in about a day (~25 s of probing per run, selection restored afterwards)
+- **Country lock**: `--require-country US` keeps rotation inside one observed country; when no candidate matches, the current node is kept rather than switching country. Opt-in until `rr report` shows coverage
 - **Google-clean gate**: before selecting a node, rotation reads `https://www.google.com/search?q=test` through the candidate (live mixed-port, redirects disabled). Exits answering 302 `/sorry` are quarantined with cause `google` (24h, `google_fails` counter). A node that passes stays selected; up to `--google-attempts` candidates are rejected, then the best remaining is used so the client never goes dark. `--no-google-check` disables it; the check is skipped when Google is unreachable directly (infra guard)
 - **Retest**: 500 oldest controller-present nodes every 30 minutes (`rr-retest.timer`), dead nodes readmitted on recovery
 - **Freshness**: nodes unchecked for over 2h sit out until rechecked
diff --git a/data/balancer_state.schema.sql b/data/balancer_state.schema.sql
index 4b5f59f..4d1c663 100644
--- a/data/balancer_state.schema.sql
+++ b/data/balancer_state.schema.sql
@@ -7,10 +7,9 @@ CREATE TABLE IF NOT EXISTS nodes (
   uses       INTEGER NOT NULL DEFAULT 0,
   quarantined_until INTEGER NOT NULL DEFAULT 0,
   last_fail_cause TEXT NOT NULL DEFAULT '',
-  quota_fails INTEGER NOT NULL DEFAULT 0,
-  transport_fails INTEGER NOT NULL DEFAULT 0,
-  region_fails INTEGER NOT NULL DEFAULT 0,
-  google_fails INTEGER NOT NULL DEFAULT 0
+  google_fails INTEGER NOT NULL DEFAULT 0,
+  country TEXT NOT NULL DEFAULT '',
+  country_checked INTEGER NOT NULL DEFAULT 0
 );
 
 CREATE TABLE IF NOT EXISTS rotation_state (
diff --git a/scripts/DECISIONS.md b/scripts/DECISIONS.md
index 3998b95..c7388e5 100644
--- a/scripts/DECISIONS.md
+++ b/scripts/DECISIONS.md
@@ -2,6 +2,40 @@
 
 Chronological. Each entry: Context, Decision, Consequences, Rollback.
 
+## 2026-11-11 — Observed exit country, and removal of the plugin-era causes
+
+**Context.** A country lock cannot be built from provider remarks: in the live
+feed 547 of 629 remarks are hash-style names with no country, and only 14 are
+labelled US. The balancer also carried `quota`, `transport`, and `region`
+failure causes plus their counters, which existed to serve the retired
+`opencode-rate-limit-rescue` plugin and now measure nothing that the Google
+gate or a country lock acts on.
+
+**Decision.** `country` and `country_checked` columns store the country that
+Cloudflare reports for a node's connection (`cdn-cgi/trace`, `loc=XX`), read
+through the live mixed-port because mihomo's `/delay` endpoint discards the
+response body. `rr country --batch N` fills the columns oldest-first, restores
+the previous selection in a `finally` block, and records an unreadable trace as
+unknown without quarantining. `rr report` prints coverage and per-country
+counts. `rotate`/`skip`/`next` accept `--require-country CC`: candidates with
+no measurement never match, and when nothing matches the current node is kept
+so the client never lands in the wrong country. The three plugin-era causes and
+their columns are removed (guarded `DROP COLUMN`; a failure leaves them
+dormant), and selection is `uses` → `delay_ms` with no per-cause weighting.
+
+**Consequences.** A sweep briefly carries traffic through each probed node
+(`TRACE_SETTLE_SECONDS` each, bounded batch), so it is a background job, not a
+per-rotation cost. The country lock stays off until coverage is high; enabling
+it early would freeze rotation on an empty column. Dropping the legacy counters
+is destructive by design and intentional — they were never read by anything
+after this change.
+
+**Rollback.** The country columns are additive and ignored by older code;
+`--require-country` is opt-in. Reverting the script restores the previous
+behavior, and the additive migration re-creates the legacy columns empty if an
+older build is run against an upgraded database (their values are not restorable,
+which is accepted because nothing consumes them).
+
 ## 2026-11-11 — Google Search status is the anti-abuse discriminator
 
 **Context.** Exit nodes used by crawl and media traffic get flagged by
diff --git a/scripts/README.md b/scripts/README.md
index face195..18ddc94 100644
--- a/scripts/README.md
+++ b/scripts/README.md
@@ -8,7 +8,7 @@ should sit out.
 
 | File              | Duty                                                                 |
 | ----------------- | -------------------------------------------------------------------- |
-| `rr_balancer.py`  | Clash-API + SQLite round-robin balancer (`rotate`, `skip`, `next`, `retest`) |
+| `rr_balancer.py`  | Clash-API + SQLite balancer (`rotate`, `retest`, `country`, `report`, `skip`, `next`) |
 
 State lives in `data/balancer_state.db` (schema in
 `data/balancer_state.schema.sql`, git-ignored). Run `python3 scripts/rr_balancer.py --help`
@@ -18,17 +18,28 @@ for the full CLI.
 
 - **Liveness + delay**: probes every pool node through mihomo's
   `/proxies/{name}/delay` endpoint and stores delay or failure.
-- **Selection**: `rotate` picks the lowest `(uses, quota_fails, delay_ms)`
-  row among alive, fresh, non-quarantined nodes and selects it in the
-  `PROXY` group.
-- **Failure causes**: `skip` / `next --reason quota|transport|region|google|manual`
-  increments the per-cause counter and quarantines the node for 24 h.
+- **Country**: `country --batch N` selects each node briefly, reads
+  `https://www.cloudflare.com/cdn-cgi/trace` through the live mixed-port, and
+  stores the observed two-letter code with a freshness stamp
+  (`country`, `country_checked`). Unreadable traces are stored as unknown, never
+  as a country and never as a failure. The previous selection is restored at the
+  end of the batch.
+- **Report**: `report` prints country coverage (checked/total) and per-country
+  counts, so the decision to enable a country lock is data-driven.
+- **Selection**: `rotate` picks the lowest `(uses, delay_ms)` row among alive,
+  fresh, non-quarantined nodes and selects it in the `PROXY` group.
+- **Failure causes**: `skip` / `next --reason google|country|manual`
+  quarantines the node for 24 h. `google` also increments `google_fails`.
 - **Google-clean gate**: `rotate` reads `https://www.google.com/search?q=test`
   through the live mixed-port with redirects disabled. A 302 to `/sorry`
   means the exit IP is anti-abuse flagged, so the candidate is quarantined
   with cause `google` and the next candidate is tried. `--no-google-check`
   restores the pre-gate behavior; the gate is skipped when Google is
   unreachable directly (infrastructure guard).
+- **Country lock**: `--require-country CC` (on `rotate`, `skip`, `next`) keeps
+  rotation inside one observed country. Candidates with no measurement never
+  match, and when nothing matches the current node is kept instead of falling
+  back to another country. The lock is opt-in until `report` shows coverage.
 - **Retest**: rechecks the oldest batch so dead nodes rejoin on recovery.
 
 ## Invariants
@@ -36,9 +47,12 @@ for the full CLI.
 1. Node names are identity hashes (`{proto}-{12hex}` from server + port), so
    learned rows survive every subscription refresh.
 2. Never delete learned rows on a refresh — only never-tested rows are pruned.
-3. Selection order is deterministic: `uses` → `quota_fails` → `delay_ms`.
+3. Selection order is deterministic: `uses` → `delay_ms`, with no per-cause
+   weighting.
 4. Rotation always leaves the group pointing at a node. An all-blocked pool
-   fails open to the best candidate instead of going dark.
+   fails open to the best candidate, and with a country lock that failure stays
+   inside the locked country.
+5. An unreadable country trace is a measurement gap, never a node verdict.
 
 ## Risks
 
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index 683c10c..50911cc 100755
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -9,10 +9,15 @@ selected node among alive ones, and retests dead nodes until they revive.
 Subcommands:
   rotate   pick next node (least-used, fastest first) and select it
   retest   check a batch of nodes (oldest-checked first) and update state
+  country  record the observed exit country for a batch of nodes
+  report   print country coverage and per-country counts
+  skip     mark one node failed and rotate now
+  next     mark the current node failed and rotate now
 
 Selection policy (fastest + fresh + fair):
   - pool = status 'alive' AND checked within STALE_AFTER seconds
   - pick lowest (uses, delay_ms): equal load first, fastest wins ties
+  - optional --require-country CC keeps rotation inside one observed country
   - empty pool = logged no-op, never touches the group (no Auto fallback)
 """
 
@@ -41,6 +46,13 @@ DEFAULT_GOOGLE_URL = "https://www.google.com/search?q=test"
 DEFAULT_PROXY_URL = "http://127.0.0.1:7890"
 GOOGLE_SETTLE_SECONDS = 0.3
 
+# Cloudflare's trace endpoint reports the country Cloudflare sees for the
+# connection ("loc=XX"). Read through a candidate exit it is the observed
+# country of that exit, which is what a geo-locked client actually gets --
+# provider remarks are unreliable (most feeds carry hash-style names).
+DEFAULT_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
+TRACE_SETTLE_SECONDS = 0.3
+
 # Group members that are selectors themselves, plus mihomo builtins:
 # never enter the rotation pool.
 META_NAMES = {"Auto", "Load Balance", "Fallback", "DIRECT", "REJECT", "PASS"}
@@ -203,14 +215,23 @@ def connect_db(db_path: str) -> sqlite3.Connection:
         for coldef in (
             "quarantined_until INTEGER NOT NULL DEFAULT 0",
             "last_fail_cause TEXT NOT NULL DEFAULT ''",
-            "quota_fails INTEGER NOT NULL DEFAULT 0",
-            "transport_fails INTEGER NOT NULL DEFAULT 0",
-            "region_fails INTEGER NOT NULL DEFAULT 0",
             "google_fails INTEGER NOT NULL DEFAULT 0",
+            "country TEXT NOT NULL DEFAULT ''",
+            "country_checked INTEGER NOT NULL DEFAULT 0",
         ):
             col = coldef.split()[0]
             if col not in cols:
                 conn.execute("ALTER TABLE nodes ADD COLUMN %s" % coldef)
+        # Legacy counters that existed only for the retired rate-limit-rescue
+        # plugin. DROP COLUMN needs SQLite >= 3.35; the failure is swallowed
+        # so an old database always opens even where the statement is
+        # unsupported (the columns are simply left dormant).
+        for legacy in ("quota_fails", "transport_fails", "region_fails"):
+            if legacy in cols:
+                try:
+                    conn.execute("ALTER TABLE nodes DROP COLUMN %s" % legacy)
+                except sqlite3.OperationalError:
+                    pass
         conn.commit()
     return conn
 
@@ -248,17 +269,19 @@ def alive_pool(
     now: int,
     stale_after: int,
     allowed: Optional[Collection[str]] = None,
-) -> List[Tuple[str, int, int, int]]:
-    """Alive AND freshly checked nodes as (name, uses, quota_fails, delay_ms).
+) -> List[Tuple[str, int, int, str]]:
+    """Alive AND freshly checked nodes as (name, uses, delay_ms, country).
 
     When allowed is given, only names present in the controller's current
     member list are returned, so ghosts from older feeds are never picked.
     Quarantined nodes (failed less than 24h ago) are always excluded.
+    country is the last observed exit country ("" when never measured), so
+    a country lock can filter the pool without another probe.
     """
     cur = conn.cursor()
     query = (
-        "SELECT name, uses, COALESCE(quota_fails, 0), "
-        "COALESCE(delay_ms, 999999) FROM nodes "
+        "SELECT name, uses, COALESCE(delay_ms, 999999), "
+        "COALESCE(country, '') FROM nodes "
         "WHERE status = 'alive' AND (? - last_check) <= ? "
         "AND quarantined_until <= ?"
     )
@@ -274,14 +297,14 @@ def alive_pool(
 
 
 def order_pool(
-    pool: List[Tuple[str, int, int, int]],
-) -> List[Tuple[str, int, int, int]]:
-    """Least-used first, fewest quota fails next, fastest delay last."""
-    return sorted(pool, key=lambda row: (row[1], row[2], row[3]))
+    pool: List[Tuple[str, int, int, str]],
+) -> List[Tuple[str, int, int, str]]:
+    """Least-used first, then fastest delay; no per-cause weighting."""
+    return sorted(pool, key=lambda row: (row[1], row[2]))
 
 
-def pick_next(pool: List[Tuple[str, int, int, int]]) -> Optional[str]:
-    """Least-used first, fewest quota fails next, fastest delay last."""
+def pick_next(pool: List[Tuple[str, int, int, str]]) -> Optional[str]:
+    """Least-used first, then fastest delay; no per-cause weighting."""
     if not pool:
         return None
     return order_pool(pool)[0][0]
@@ -339,6 +362,53 @@ class _NoRedirect(urllib.request.HTTPRedirectHandler):
         return None
 
 
+def parse_trace_country(body: str) -> Optional[str]:
+    """Country code from a Cloudflare cdn-cgi/trace body.
+
+    The body is line-oriented ("loc=US"). Only a real two-letter code is
+    accepted; "XX" (Cloudflare's unknown/Tor marker), a missing line, or
+    anything else returns None so callers store "unknown" instead of
+    inventing a country.
+    """
+    for line in body.splitlines():
+        if line.startswith("loc="):
+            code = line[4:].strip().upper()
+            if code == "XX":
+                return None
+            if len(code) == 2 and code.isalpha():
+                return code
+            return None
+    return None
+
+
+def probe_country_via_proxy(
+    trace_url: str,
+    proxy_url: str = DEFAULT_PROXY_URL,
+    timeout_s: float = 8.0,
+) -> Optional[str]:
+    """Observed exit country for trace_url read through proxy_url.
+
+    Returns a two-letter code, or None when the trace is unreachable or
+    unparseable. None is a measurement failure, never a verdict about the
+    node, so callers must not quarantine on it.
+    """
+    req = urllib.request.Request(
+        trace_url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131"}
+    )
+    try:
+        opener = urllib.request.build_opener(
+            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
+            _NoRedirect,
+        )
+        with opener.open(req, timeout=timeout_s) as resp:
+            if resp.status != 200:
+                return None
+            body = resp.read().decode("utf-8", errors="replace")
+    except Exception:
+        return None
+    return parse_trace_country(body)
+
+
 def google_reachable_direct(url: str, timeout_s: float = 8.0) -> bool:
     """Guard against quarantining the whole pool during a Google outage.
 
@@ -372,6 +442,17 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
     name = None
     delay = None
     attempts = 0
+    require_country = getattr(args, "require_country", None)
+    if require_country:
+        require_country = require_country.strip().upper()
+        locked = [row for row in ordered if (row[3] or "").upper() == require_country]
+        if not locked:
+            print(
+                "rotate: no %s candidates in the alive pool, keeping current %s"
+                % (require_country, current or "selection")
+            )
+            return 0
+        ordered = locked
     enforce_google = not getattr(args, "no_google_check", False)
     google_url = getattr(args, "google_url", DEFAULT_GOOGLE_URL)
     google_timeout = getattr(args, "google_timeout_ms", 8000)
@@ -387,7 +468,7 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
             if google_clean(
                 api, args.group, candidate[0], google_url, google_timeout, google_proxy
             ):
-                name, delay = candidate[0], candidate[3]
+                name, delay = candidate[0], candidate[2]
                 selected_by_probe = True
                 break
             _mark_failed(
@@ -398,12 +479,13 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
                 "google",
             )
             continue
-        name, delay = candidate[0], candidate[3]
+        name, delay = candidate[0], candidate[2]
         break
     if name is None:
         # Every checked candidate answered 302 /sorry: fail open to the best
-        # one so the client keeps working instead of going dark.
-        name, delay = ordered[0][0], ordered[0][3]
+        # one so the client keeps working instead of going dark. When a
+        # country lock is active, this stays inside the locked subset.
+        name, delay = ordered[0][0], ordered[0][2]
         print("rotate: all candidates google-blocked, failing open to %s" % name)
     if not selected_by_probe:
         api.select(args.group, name)
@@ -449,10 +531,11 @@ def _mark_failed(
 ) -> None:
     """Mark one node failed and quarantine it for 24h (retest readmits after expiry).
 
-    The failure cause (quota/transport/region/google/manual) is recorded per
-    cause so rotation can prefer nodes with a clean record for crawl traffic
-    and provider-side counters stay separable (region = geo-blocked from the
-    provider's country check; google = Google Search answers /sorry).
+    Causes are the ones this balancer actually acts on: google (Search
+    answers /sorry), country (exit does not match the required country),
+    and manual (an operator skipped it). Only google increments its
+    counter; the retired quota/transport/region causes belonged to the
+    rate-limit-rescue plugin and were removed with their columns.
     """
     cur = conn.cursor()
     row = cur.execute("SELECT status FROM nodes WHERE name = ?", (name,)).fetchone()
@@ -462,18 +545,12 @@ def _mark_failed(
         cur.execute(
             "UPDATE nodes SET status = 'failed', fails = ?, last_check = ?, "
             "quarantined_until = ?, last_fail_cause = ?, "
-            "quota_fails = quota_fails + ?, "
-            "transport_fails = transport_fails + ?, "
-            "region_fails = region_fails + ?, "
             "google_fails = google_fails + ? WHERE name = ?",
             (
                 max_fails,
                 now,
                 now + QUARANTINE_SECONDS,
                 reason,
-                1 if reason == "quota" else 0,
-                1 if reason == "transport" else 0,
-                1 if reason == "region" else 0,
                 1 if reason == "google" else 0,
                 name,
             ),
@@ -587,8 +664,7 @@ def cmd_retest(args: argparse.Namespace, api: ClashAPI) -> int:
             cur.execute(
                 "UPDATE nodes SET status='alive', delay_ms=?, "
                 "last_check=?, fails=0, quarantined_until=0, "
-                "last_fail_cause='', quota_fails=0, transport_fails=0 "
-                "WHERE name=?",
+                "last_fail_cause='' WHERE name=?",
                 (delay, now, name),
             )
             alive += 1
@@ -610,6 +686,83 @@ def cmd_retest(args: argparse.Namespace, api: ClashAPI) -> int:
     return 0
 
 
+def cmd_country(args: argparse.Namespace, api: ClashAPI) -> int:
+    """Fill the observed country for a bounded batch of nodes.
+
+    mihomo's /delay endpoint returns only a latency, so an exit's country
+    can be read only by selecting that node and requesting the trace
+    through the live mixed-port. The batch is therefore bounded, oldest
+    measurement first, and the previous selection is restored in a
+    finally block so a sweep never leaves traffic on a probed node.
+    A node whose trace cannot be read is stored as unknown with a fresh
+    country_checked stamp; it is never quarantined for that reason.
+    """
+    now = utc_now_epoch()
+    conn = connect_db(args.db)
+    pool_names, prev = api.group_members(args.group)
+    added, pruned = seed_names(conn, pool_names)
+    cur = conn.cursor()
+    batch = []
+    checked = 0
+    measured = 0
+    try:
+        if pool_names:
+            cur.execute(
+                "SELECT name FROM nodes WHERE name IN (%s) "
+                "AND quarantined_until <= ? "
+                "ORDER BY country_checked ASC, last_check ASC LIMIT ?"
+                % ",".join("?" * len(pool_names)),
+                (*pool_names, now, args.batch),
+            )
+            batch = [row[0] for row in cur.fetchall()]
+        for name in batch:
+            api.select(args.group, name)
+            if TRACE_SETTLE_SECONDS:
+                time.sleep(TRACE_SETTLE_SECONDS)
+            code = probe_country_via_proxy(
+                args.trace_url, args.trace_proxy, args.trace_timeout_ms / 1000.0
+            )
+            cur.execute(
+                "UPDATE nodes SET country = ?, country_checked = ? WHERE name = ?",
+                (code or "", now, name),
+            )
+            conn.commit()
+            checked += 1
+            if code:
+                measured += 1
+            print("country: %s -> %s" % (name, code or "unknown"))
+    finally:
+        if prev:
+            try:
+                api.select(args.group, prev)
+            except Exception as exc:
+                print("country: could not restore %s: %s" % (prev, exc))
+    print(
+        "country: checked %d (seed +%d prune -%d): %d measured, %d unknown"
+        % (len(batch), added, pruned, measured, checked - measured)
+    )
+    return 0
+
+
+def cmd_report(args: argparse.Namespace) -> int:
+    """Print country coverage and per-country counts (no controller needed)."""
+    conn = connect_db(args.db)
+    cur = conn.cursor()
+    total = cur.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
+    checked = cur.execute(
+        "SELECT COUNT(*) FROM nodes WHERE country_checked > 0"
+    ).fetchone()[0]
+    rows = cur.execute(
+        "SELECT CASE WHEN country = '' THEN 'unknown' ELSE country END, "
+        "COUNT(*), SUM(CASE WHEN status = 'alive' THEN 1 ELSE 0 END) "
+        "FROM nodes GROUP BY 1 ORDER BY 2 DESC"
+    ).fetchall()
+    print("report: country coverage %d/%d checked" % (checked, total))
+    for country, count, alive in rows:
+        print("  %-8s %5d total %5d alive" % (country, count, alive or 0))
+    return 0
+
+
 def load_secret(secret_file: str) -> str:
     if os.path.exists(secret_file):
         with open(secret_file, encoding="utf-8") as fh:
@@ -643,6 +796,21 @@ def add_google_args(parser: argparse.ArgumentParser) -> None:
     )
 
 
+def add_country_lock_arg(parser: argparse.ArgumentParser) -> None:
+    """Country lock shared by rotate/skip/next.
+
+    Opt-in by design: the alarm is only useful once `country` coverage is
+    high, and a lock on an empty country column would freeze rotation.
+    """
+    parser.add_argument(
+        "--require-country",
+        default=None,
+        metavar="CC",
+        help="only rotate to exits whose observed country is CC (e.g. US); "
+        "keeps the current node when no candidate matches",
+    )
+
+
 def build_parser() -> argparse.ArgumentParser:
     ap = argparse.ArgumentParser(description=__doc__)
     ap.add_argument("--controller", default="http://127.0.0.1:9090")
@@ -654,6 +822,7 @@ def build_parser() -> argparse.ArgumentParser:
     rot = sub.add_parser("rotate", help="select next alive node")
     rot.add_argument("--stale-after", type=int, default=7200)
     add_google_args(rot)
+    add_country_lock_arg(rot)
 
     ret = sub.add_parser("retest", help="check oldest batch of nodes")
     ret.add_argument("--batch", type=int, default=500)
@@ -670,22 +839,36 @@ def build_parser() -> argparse.ArgumentParser:
     skp.add_argument("--max-fails", type=int, default=3)
     skp.add_argument(
         "--reason",
-        choices=("quota", "transport", "region", "google", "manual"),
+        choices=("google", "country", "manual"),
         default="manual",
-        help="failure cause recorded for smart selection",
+        help="failure cause recorded for the node",
     )
     add_google_args(skp)
+    add_country_lock_arg(skp)
 
     nxt = sub.add_parser("next", help="skip the current node and rotate now")
     nxt.add_argument("--stale-after", type=int, default=7200)
     nxt.add_argument("--max-fails", type=int, default=3)
     nxt.add_argument(
         "--reason",
-        choices=("quota", "transport", "region", "google", "manual"),
+        choices=("google", "country", "manual"),
         default="manual",
-        help="failure cause recorded for smart selection",
+        help="failure cause recorded for the node",
     )
     add_google_args(nxt)
+    add_country_lock_arg(nxt)
+
+    cty = sub.add_parser("country", help="fill observed exit countries for a batch")
+    cty.add_argument("--batch", type=int, default=20)
+    cty.add_argument("--trace-url", default=DEFAULT_TRACE_URL)
+    cty.add_argument("--trace-timeout-ms", type=int, default=8000)
+    cty.add_argument(
+        "--trace-proxy",
+        default=DEFAULT_PROXY_URL,
+        help="mihomo mixed-port used to read the trace through each candidate",
+    )
+
+    sub.add_parser("report", help="print country coverage and per-country counts")
     return ap
 
 
@@ -701,6 +884,11 @@ def validate_args(args: argparse.Namespace) -> Optional[str]:
             return "--workers must be >= 1"
         if args.timeout_ms < 500:
             return "--timeout-ms must be >= 500"
+    if args.cmd == "country":
+        if args.batch < 1:
+            return "--batch must be >= 1"
+        if args.trace_timeout_ms < 500:
+            return "--trace-timeout-ms must be >= 500"
     if args.cmd in ("rotate", "skip", "next") and args.stale_after < 60:
         return "--stale-after must be >= 60"
     if args.cmd in ("rotate", "skip", "next"):
@@ -708,6 +896,10 @@ def validate_args(args: argparse.Namespace) -> Optional[str]:
             return "--google-timeout-ms must be >= 500"
         if args.google_attempts < 1:
             return "--google-attempts must be >= 1"
+        if args.require_country is not None:
+            cc = args.require_country.strip()
+            if len(cc) != 2 or not cc.isalpha():
+                return "--require-country must be a two-letter country code"
     return None
 
 
@@ -717,6 +909,8 @@ def main(argv: Optional[List[str]] = None) -> int:
     if err:
         print("error: %s" % err, file=sys.stderr)
         return 2
+    if args.cmd == "report":
+        return cmd_report(args)
     secret = os.environ.get("MIHOMO_CONTROLLER_SECRET") or load_secret(args.secret_file)
     if not secret:
         print("error: no controller secret (env or --secret-file)", file=sys.stderr)
@@ -728,6 +922,8 @@ def main(argv: Optional[List[str]] = None) -> int:
         return cmd_skip(args, api)
     if args.cmd == "next":
         return cmd_next(args, api)
+    if args.cmd == "country":
+        return cmd_country(args, api)
     return cmd_retest(args, api)
 
 
diff --git a/systemd/rr-country.service b/systemd/rr-country.service
new file mode 100644
index 0000000..2641d36
--- /dev/null
+++ b/systemd/rr-country.service
@@ -0,0 +1,8 @@
+[Unit]
+Description=Fill observed exit countries for mihomo proxy pool (external balancer)
+Wants=network-online.target
+After=network-online.target mihomo-subs.service
+
+[Service]
+Type=oneshot
+ExecStart=%h/v2ray-to-subs/.venv/bin/python %h/v2ray-to-subs/scripts/rr_balancer.py country --batch 20
diff --git a/systemd/rr-country.timer b/systemd/rr-country.timer
new file mode 100644
index 0000000..61dbfb1
--- /dev/null
+++ b/systemd/rr-country.timer
@@ -0,0 +1,11 @@
+[Unit]
+Description=Fill observed exit countries for the mihomo pool every 30 minutes
+
+[Timer]
+OnBootSec=10min
+OnUnitActiveSec=30min
+Persistent=true
+Unit=rr-country.service
+
+[Install]
+WantedBy=timers.target
diff --git a/tests/test_rr_balancer.py b/tests/test_rr_balancer.py
index 0626d68..a1c6603 100644
--- a/tests/test_rr_balancer.py
+++ b/tests/test_rr_balancer.py
@@ -1,5 +1,7 @@
 """Unit tests for scripts/rr_balancer.py (stdlib unittest, no network)."""
 
+import contextlib
+import io
 import os
 import sqlite3
 import sys
@@ -64,13 +66,13 @@ def make_db():
     return conn, path
 
 
-def mark(conn, name, status, delay=None, uses=0, last_check=None):
+def mark(conn, name, status, delay=None, uses=0, last_check=None, country=""):
     if last_check is None:
         last_check = int(time.time())
     conn.execute(
-        "INSERT INTO nodes (name, status, delay_ms, last_check, uses) "
-        "VALUES (?, ?, ?, ?, ?)",
-        (name, status, delay, last_check, uses),
+        "INSERT INTO nodes (name, status, delay_ms, last_check, uses, country) "
+        "VALUES (?, ?, ?, ?, ?, ?)",
+        (name, status, delay, last_check, uses, country),
     )
     conn.commit()
 
@@ -93,6 +95,11 @@ class Args:
                 google_url=rr_balancer.DEFAULT_GOOGLE_URL,
                 google_timeout_ms=8000,
                 google_attempts=5,
+                # Country fields default to the lock being off.
+                require_country=None,
+                trace_url=rr_balancer.DEFAULT_TRACE_URL,
+                trace_timeout_ms=8000,
+                trace_proxy=rr_balancer.DEFAULT_PROXY_URL,
             )
         )
         self.__dict__.update(kw)
@@ -510,148 +517,307 @@ class QuarantineTest(unittest.TestCase):
         conn = rr_balancer.connect_db(path)
         cols = [r[1] for r in conn.execute("PRAGMA table_info(nodes)").fetchall()]
         self.assertIn("quarantined_until", cols)
+        self.assertIn("country", cols)
+        self.assertIn("country_checked", cols)
         conn.close()
         conn = rr_balancer.connect_db(path)
         cols = [r[1] for r in conn.execute("PRAGMA table_info(nodes)").fetchall()]
-        self.assertIn("quarantined_until", cols)
+        self.assertIn("country", cols)
+        self.assertNotIn("quota_fails", cols)
         conn.close()
 
 
-class QuotaCauseTest(unittest.TestCase):
-    def test_skip_reason_quota_records_cause(self):
+class CauseCleanupTest(unittest.TestCase):
+    """Only the causes this balancer acts on survive the plugin cleanup."""
+
+    def test_fresh_schema_has_no_plugin_counters(self):
+        conn, path = make_db()
+        cols = [r[1] for r in conn.execute("PRAGMA table_info(nodes)").fetchall()]
+        for legacy in ("quota_fails", "transport_fails", "region_fails"):
+            self.assertNotIn(legacy, cols)
+        self.assertIn("google_fails", cols)
+        self.assertIn("country", cols)
+        self.assertIn("country_checked", cols)
+        conn.close()
+
+    def test_skip_reason_google_records_cause_and_quarantines(self):
         conn, path = make_db()
         api = FakeAPI({"n1": 2, "n2": 5})
         mark(conn, "n1", "alive", delay=2, uses=0)
         mark(conn, "n2", "alive", delay=5, uses=0)
         conn.close()
         rc = rr_balancer.cmd_skip(
-            Args(cmd="skip", name="n1", reason="quota", db=path), api
+            Args(cmd="skip", name="n1", reason="google", db=path), api
         )
         self.assertEqual(rc, 0)
         conn = sqlite3.connect(path)
         row = conn.execute(
-            "SELECT quota_fails, transport_fails, last_fail_cause "
-            "FROM nodes WHERE name='n1'"
+            "SELECT google_fails, last_fail_cause, status, quarantined_until, "
+            "last_check FROM nodes WHERE name='n1'"
         ).fetchone()
-        self.assertEqual(row, (1, 0, "quota"))
+        self.assertEqual(row[:3], (1, "google", "failed"))
+        self.assertGreater(row[3], row[4])
         conn.close()
 
-    def test_skip_reason_transport_records_cause(self):
+    def test_country_and_manual_causes_leave_google_counter_alone(self):
         conn, path = make_db()
         api = FakeAPI({"n1": 2, "n2": 5})
         mark(conn, "n1", "alive", delay=2, uses=0)
         mark(conn, "n2", "alive", delay=5, uses=0)
         conn.close()
-        rc = rr_balancer.cmd_skip(
-            Args(cmd="skip", name="n1", reason="transport", db=path), api
+        rr_balancer.cmd_skip(
+            Args(cmd="skip", name="n1", reason="country", db=path), api
         )
-        self.assertEqual(rc, 0)
+        rr_balancer.cmd_skip(Args(cmd="skip", name="n2", reason="manual", db=path), api)
+        conn = sqlite3.connect(path)
+        rows = conn.execute(
+            "SELECT name, google_fails, last_fail_cause FROM nodes ORDER BY name"
+        ).fetchall()
+        self.assertEqual(rows, [("n1", 0, "country"), ("n2", 0, "manual")])
+        conn.close()
+
+    def test_legacy_counters_dropped_while_rows_survive(self):
+        fd, path = tempfile.mkstemp(suffix=".db")
+        os.close(fd)
+        os.unlink(path)
         conn = sqlite3.connect(path)
+        conn.execute(
+            "CREATE TABLE nodes (name TEXT PRIMARY KEY, status TEXT NOT NULL "
+            "DEFAULT 'unknown', delay_ms INTEGER, last_check INTEGER NOT NULL "
+            "DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, "
+            "uses INTEGER NOT NULL DEFAULT 0, quarantined_until INTEGER NOT NULL "
+            "DEFAULT 0, last_fail_cause TEXT NOT NULL DEFAULT '', "
+            "quota_fails INTEGER NOT NULL DEFAULT 0, transport_fails INTEGER "
+            "NOT NULL DEFAULT 0, region_fails INTEGER NOT NULL DEFAULT 0, "
+            "google_fails INTEGER NOT NULL DEFAULT 0)"
+        )
+        conn.execute(
+            "INSERT INTO nodes (name, status, uses) VALUES ('kept', 'alive', 7)"
+        )
+        conn.commit()
+        conn.close()
+        conn = rr_balancer.connect_db(path)
+        cols = [r[1] for r in conn.execute("PRAGMA table_info(nodes)").fetchall()]
+        for legacy in ("quota_fails", "transport_fails", "region_fails"):
+            self.assertNotIn(legacy, cols)
         row = conn.execute(
-            "SELECT quota_fails, transport_fails, last_fail_cause "
-            "FROM nodes WHERE name='n1'"
+            "SELECT status, uses FROM nodes WHERE name='kept'"
         ).fetchone()
-        self.assertEqual(row, (0, 1, "transport"))
+        self.assertEqual(row, ("alive", 7))
         conn.close()
 
-    def test_skip_reason_region_records_cause(self):
-        # Geo-blocked exits (provider region check) get their own counter so
-        # they stay separable from rate-limit and network failures.
+    def test_order_pool_uses_then_delay_only(self):
+        pool = [
+            ("slow", 0, 500, "US"),
+            ("fast", 0, 5, "DE"),
+            ("used", 1, 1, "US"),
+        ]
+        self.assertEqual(
+            [row[0] for row in rr_balancer.order_pool(pool)],
+            ["fast", "slow", "used"],
+        )
+
+    def test_retest_success_clears_cause_but_keeps_country(self):
         conn, path = make_db()
-        api = FakeAPI({"n1": 2, "n2": 5})
-        mark(conn, "n1", "alive", delay=2, uses=0)
-        mark(conn, "n2", "alive", delay=5, uses=0)
-        conn.close()
-        rc = rr_balancer.cmd_skip(
-            Args(cmd="skip", name="n1", reason="region", db=path), api
+        api = FakeAPI({"n1": 10})
+        api.group_members = lambda group: (["n1"], "old-node")
+        mark(conn, "n1", "unknown", last_check=100, country="US")
+        conn.execute(
+            "UPDATE nodes SET google_fails=2, last_fail_cause='google' WHERE name='n1'"
         )
+        conn.commit()
+        conn.close()
+        rc = rr_balancer.cmd_retest(Args(cmd="retest", db=path, batch=10), api)
         self.assertEqual(rc, 0)
         conn = sqlite3.connect(path)
         row = conn.execute(
-            "SELECT quota_fails, transport_fails, region_fails, last_fail_cause "
-            "FROM nodes WHERE name='n1'"
+            "SELECT google_fails, last_fail_cause, country FROM nodes WHERE name='n1'"
         ).fetchone()
-        self.assertEqual(row, (0, 0, 1, "region"))
-        # Quarantine parity: region failures quarantine exactly like other causes.
-        row = conn.execute(
-            "SELECT status, quarantined_until, last_check FROM nodes WHERE name='n1'"
-        ).fetchone()
-        self.assertEqual(row[0], "failed")
-        self.assertGreater(row[1], row[2])
-        conn.close()
-
-    def test_other_causes_leave_region_fails_at_zero(self):
-        # Reverse isolation: quota, transport, and manual marks must never
-        # touch the region counter.
-        for cause in ("quota", "transport", "manual"):
-            conn, path = make_db()
-            api = FakeAPI({"n1": 2, "n2": 5})
-            mark(conn, "n1", "alive", delay=2, uses=0)
-            mark(conn, "n2", "alive", delay=5, uses=0)
-            conn.close()
-            rc = rr_balancer.cmd_skip(
-                Args(cmd="skip", name="n1", reason=cause, db=path), api
+        self.assertEqual(row, (2, "", "US"))
+        conn.close()
+
+
+class CountryTest(unittest.TestCase):
+    def test_parse_trace_country_reads_loc(self):
+        body = "fl=123abc\nh=www.cloudflare.com\nip=1.2.3.4\nts=1\nloc=us\n"
+        self.assertEqual(rr_balancer.parse_trace_country(body), "US")
+
+    def test_parse_trace_country_rejects_unknown_shapes(self):
+        self.assertIsNone(rr_balancer.parse_trace_country("ip=1.2.3.4\n"))
+        self.assertIsNone(rr_balancer.parse_trace_country("loc=\n"))
+        self.assertIsNone(rr_balancer.parse_trace_country("loc=USA\n"))
+        self.assertIsNone(rr_balancer.parse_trace_country("loc=T1\n"))
+        # Cloudflare reports loc=XX when it cannot place the exit (Tor, etc.).
+        self.assertIsNone(rr_balancer.parse_trace_country("loc=XX\n"))
+        self.assertIsNone(rr_balancer.parse_trace_country(""))
+
+    def test_probe_country_parses_body(self):
+        class _Resp:
+            status = 200
+
+            def read(self):
+                return b"h=www.cloudflare.com\nloc=DE\nts=1\n"
+
+            def __enter__(self):
+                return self
+
+            def __exit__(self, *exc):
+                return False
+
+        class _Opener:
+            def open(self, req, timeout=None):
+                return _Resp()
+
+        with unittest.mock.patch.object(
+            rr_balancer.urllib.request, "build_opener", return_value=_Opener()
+        ):
+            self.assertEqual(
+                rr_balancer.probe_country_via_proxy(
+                    rr_balancer.DEFAULT_TRACE_URL, rr_balancer.DEFAULT_PROXY_URL, 5.0
+                ),
+                "DE",
             )
-            self.assertEqual(rc, 0)
-            conn = sqlite3.connect(path)
-            row = conn.execute(
-                "SELECT region_fails FROM nodes WHERE name='n1'"
-            ).fetchone()
-            self.assertEqual(row, (0,), cause)
-            conn.close()
-
-    def test_next_reason_region_records_cause(self):
-        # The next path shares the same mark-failed helper as skip, so a
-        # region rotation must record region_fails on the current node.
+
+    def test_probe_country_returns_none_on_transport_error(self):
+        with unittest.mock.patch.object(
+            rr_balancer.urllib.request,
+            "build_opener",
+            side_effect=OSError("proxy down"),
+        ):
+            self.assertIsNone(
+                rr_balancer.probe_country_via_proxy(
+                    rr_balancer.DEFAULT_TRACE_URL, rr_balancer.DEFAULT_PROXY_URL, 1.0
+                )
+            )
+
+    def test_cmd_country_fills_batch_and_restores_selection(self):
         conn, path = make_db()
-        api = FakeAPI({"cur": 50, "n2": 5})
-        api.group_members = lambda group: (["cur", "n2"], "cur")
-        mark(conn, "cur", "alive", delay=50, uses=3)
-        mark(conn, "n2", "alive", delay=5, uses=0)
+        now = int(time.time())
+        mark(conn, "a", "alive", delay=10, uses=0, last_check=now)
+        mark(conn, "b", "alive", delay=20, uses=0, last_check=now)
+        api = FakeAPI({"a": 10, "b": 20})
+        api.group_members = lambda group: (["a", "b"], "prev")
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "probe_country_via_proxy", side_effect=["US", "DE"]
+            ),
+            unittest.mock.patch.object(rr_balancer, "TRACE_SETTLE_SECONDS", 0),
+        ):
+            rc = rr_balancer.cmd_country(Args(cmd="country", db=path, batch=10), api)
+        self.assertEqual(rc, 0)
         conn.close()
-        rc = rr_balancer.cmd_next(Args(cmd="next", reason="region", db=path), api)
+        conn = sqlite3.connect(path)
+        rows = conn.execute(
+            "SELECT name, country, country_checked FROM nodes ORDER BY name"
+        ).fetchall()
+        self.assertEqual([(r[0], r[1]) for r in rows], [("a", "US"), ("b", "DE")])
+        self.assertTrue(all(row[2] > 0 for row in rows))
+        self.assertEqual(api.selected[-1], ("PROXY", "prev"))
+        conn.close()
+
+    def test_cmd_country_unknown_never_quarantines(self):
+        conn, path = make_db()
+        mark(conn, "a", "alive", delay=10, uses=0)
+        api = FakeAPI({"a": 10})
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "probe_country_via_proxy", return_value=None
+            ),
+            unittest.mock.patch.object(rr_balancer, "TRACE_SETTLE_SECONDS", 0),
+        ):
+            rc = rr_balancer.cmd_country(Args(cmd="country", db=path, batch=5), api)
         self.assertEqual(rc, 0)
+        conn.close()
         conn = sqlite3.connect(path)
         row = conn.execute(
-            "SELECT region_fails, last_fail_cause, status FROM nodes WHERE name='cur'"
+            "SELECT country, country_checked, status, quarantined_until, fails "
+            "FROM nodes WHERE name='a'"
         ).fetchone()
-        self.assertEqual(row, (1, "region", "failed"))
+        self.assertEqual(row[0], "")
+        self.assertGreater(row[1], 0)
+        self.assertEqual(row[2:], ("alive", 0, 0))
         conn.close()
 
-    def test_fewer_quota_fails_beats_faster_delay(self):
+
+class CountryLockTest(unittest.TestCase):
+    def test_require_country_filters_to_matching_exit(self):
         conn, path = make_db()
-        api = FakeAPI({"burned": 5, "clean": 500})
-        mark(conn, "burned", "alive", delay=5, uses=0)
-        mark(conn, "clean", "alive", delay=500, uses=0)
-        conn.execute(
-            "UPDATE nodes SET quota_fails=2, last_fail_cause='quota' "
-            "WHERE name='burned'"
-        )
-        conn.commit()
+        now = int(time.time())
+        mark(conn, "us", "alive", delay=500, uses=0, last_check=now, country="US")
+        mark(conn, "de", "alive", delay=10, uses=0, last_check=now, country="DE")
+        api = FakeAPI({"us": 500, "de": 10})
+        # Lowercase input must normalize, and the slower US exit must win.
+        rc = rr_balancer.cmd_rotate(Args(db=path, require_country="us"), api)
+        self.assertEqual(rc, 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "us"))
         conn.close()
-        rc = rr_balancer.cmd_rotate(Args(cmd="rotate", db=path), api)
+
+    def test_require_country_without_match_keeps_current_selection(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "de", "alive", delay=10, uses=0, last_check=now, country="DE")
+        mark(conn, "unmeasured", "alive", delay=5, uses=0, last_check=now)
+        api = FakeAPI({"de": 10, "unmeasured": 5})
+        rc = rr_balancer.cmd_rotate(Args(db=path, require_country="US"), api)
         self.assertEqual(rc, 0)
-        self.assertEqual(api.selected[-1], ("PROXY", "clean"))
+        self.assertEqual(api.selected, [])
+        conn.close()
 
-    def test_success_resets_cause_counters(self):
+    def test_skip_with_country_reason_still_respects_lock(self):
         conn, path = make_db()
-        api = FakeAPI({"n1": 10})
-        api.group_members = lambda group: (["n1"], "old-node")
-        mark(conn, "n1", "unknown", last_check=100)
-        conn.execute(
-            "UPDATE nodes SET quota_fails=2, last_fail_cause='quota' WHERE name='n1'"
+        api = FakeAPI({"n1": 2, "n2": 5})
+        mark(conn, "n1", "alive", delay=2, uses=0, country="US")
+        mark(conn, "n2", "alive", delay=5, uses=0, country="US")
+        conn.close()
+        rc = rr_balancer.cmd_skip(
+            Args(
+                cmd="skip", name="n1", reason="country", db=path, require_country="US"
+            ),
+            api,
         )
+        self.assertEqual(rc, 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "n2"))
+
+
+class ReportTest(unittest.TestCase):
+    def test_report_prints_coverage_and_country_counts(self):
+        conn, path = make_db()
+        mark(conn, "a", "alive", delay=10, country="US")
+        mark(conn, "b", "alive", delay=20, country="US")
+        mark(conn, "c", "failed", delay=30, country="DE")
+        mark(conn, "d", "unknown")
+        conn.execute("UPDATE nodes SET country_checked=1 WHERE name IN ('a','b','c')")
         conn.commit()
         conn.close()
-        rc = rr_balancer.cmd_retest(Args(cmd="retest", db=path, batch=10), api)
+        buf = io.StringIO()
+        with contextlib.redirect_stdout(buf):
+            rc = rr_balancer.cmd_report(Args(cmd="report", db=path))
+        out = buf.getvalue()
         self.assertEqual(rc, 0)
-        conn = sqlite3.connect(path)
-        row = conn.execute(
-            "SELECT quota_fails, transport_fails, last_fail_cause "
-            "FROM nodes WHERE name='n1'"
-        ).fetchone()
-        self.assertEqual(row, (0, 0, ""))
-        conn.close()
+        self.assertIn("coverage 3/4 checked", out)
+        self.assertIn("US", out)
+        self.assertIn("DE", out)
+        self.assertIn("unknown", out)
+
+
+class CountryArgsTest(unittest.TestCase):
+    def test_rejects_bad_require_country(self):
+        for bad in ("USA", "1A", ""):
+            self.assertIsNotNone(
+                rr_balancer.validate_args(Args(cmd="rotate", require_country=bad)), bad
+            )
+
+    def test_rejects_bad_country_batch_numbers(self):
+        self.assertIsNotNone(rr_balancer.validate_args(Args(cmd="country", batch=0)))
+        self.assertIsNotNone(
+            rr_balancer.validate_args(Args(cmd="country", trace_timeout_ms=100))
+        )
+
+    def test_accepts_sane_country_args(self):
+        self.assertIsNone(rr_balancer.validate_args(Args(cmd="country")))
+        self.assertIsNone(
+            rr_balancer.validate_args(Args(cmd="rotate", require_country="us"))
+        )
 
 
 if __name__ == "__main__":
```
<!-- END_GIT_DIFF -->
