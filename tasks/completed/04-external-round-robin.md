# Task [04]: External round-robin balancer via Clash API plus SQLite

**File:** `tasks/completed/04-external-round-robin.md`
**Source:** manager
**Type:** feature
**Status:** closed

## Goal

Build an external Python script that does true round-robin plus hash-weighted load balancing over alive proxies using the Clash API and its own SQLite state, keeping the PROXY group in select mode.

## Manager's Notes

Manager's original message (Persian, verbatim):

> ببین می‌تونی این قابلیت و توسعه بدی؟ خب؟ این‌جوری. از کلاً حالت سلکت میهومو یا همون کلش استفاده کنیم، خب؟ کاری با حالت اتوبالانس و این مواردش نداشته باشیم. بعد یک اسکریپت پایتون بنویسی با ای‌پی‌آی کلش. بعد یه دیتابیس لوکال اس‌کی‌لایت هم داشته باشی ترک کنی پروکسی‌ها رو بر اساس نیمشون، اینا یونیک‌ان. ببین الان مثلاً، ببین می‌شه، نمی‌دونم می‌شه یا نه. پروکسی‌ها رو تست کنی؟ نه، نمی‌شه. این‌جوری هی باید عوض کنی، تست کنی این خودش داستان داره. اگر یه قابلیت داشته باشی که پروکسی رو دقیقاً همون پروکسی رو از طریق خود کلش تست کنی، یعنی به کلش بگی پروکسی شماره ۵ رو تست کن، اگر کار کرد پینگش رو مثلاً خودت ذخیره کنی. بعد پروکسی‌هایی که کار نمی‌کنن رو. بعد اون‌ها رو هم بدونی یعنی خودت سیستم رو کلاً جدا از کلش باشه. بعد ای‌پی‌آی کلش به‌صورت اکسترنال بهش وصل بشه. هدف اینه: مثلاً هر، نمی‌دونم، چند ثانیه یه بار خودم، یعنی خودت به‌صورت ران‌روبین واقعاً ترافیک رو روی پروکسی‌هایی که واقعاً کار می‌کنن و پینگ دارن بالانس کنی. کاری به ای‌پی‌آی خود کلش نداشته باشی. بعد نسبت به مقداری که ازشون استفاده شده دقیقاً بار رو سعی کنی روی همه‌شون به‌صورت یکسان هندل کنی. و اگر یکی از پروکسی‌ها هم از بین رفت، تو می‌دونی دیگه، توی حالت سلکتی که انجام می‌دی، اون پروکسی دیگه اونو انتخاب نمی‌کنی. یعنی پروکسی مرد. و پروکسی‌های مرده هم هر چند وقت یک‌بار، یک‌بار دیگه هم تست بشن، اگر زنده شده باشن دوباره بهشون برگردونی به سیستم. یعنی این نواقصی که خود کلش داره بتونی با ای‌پی‌آیی که داره و یک اسکریپت پایتونی که به‌صورت اینتروالی اجرا می‌شه، هندل کنیم. یک ران‌روبین واقعی که ترو ران‌روبین به‌اضافه‌ی یک هش‌ویت لود بالانس تور می‌خوام که دقیقاً دیتات هم باید توی اس‌کی‌لایت ذخیره کنی. که بر اساس دیتای خودمون هندل کنیم، نه دیتای کلش. کلاً حالا یه چیزایی گفتم نسبت به ای‌پی‌آیی که کلش داره بهم بگو قابل پیاده‌سازی هست یا نه.

English summary: keep PROXY group in select mode, ignore mihomo auto-balance modes. Write a Python script using the Clash API plus a local SQLite database keyed by unique proxy names. Test each proxy through Clash itself (per-node delay check), store the delay for alive nodes, track dead nodes separately. The script owns the system state externally: every N seconds rotate the selected proxy round-robin among alive nodes, equalize load by tracked usage counts, skip dead nodes, and retest dead nodes on a slower loop to readmit revived ones. True round-robin plus hash-weighted balancing driven by our own data, not Clash internals. Manager asked whether this is implementable via the Clash API. Task parked on manager order: "just task it not need to handle it now".

## Local TODOs

- [x] Confirm feasibility against Clash API surface (proxies list, per-node delay, switch now)
- [x] Design SQLite schema (proxy name unique, delay, alive state, usage counts)
- [x] Implement per-node test loop via Clash delay API
- [x] Implement round-robin rotation with usage equalization
- [x] Implement dead-node slower retest loop and readmission
- [x] Wire interval execution (systemd timer or loop)
- [x] Verify against live config

## Acceptance Criteria

- [x] PROXY group stays in select mode; script owns selection
- [x] Per-node liveness and delay stored in SQLite keyed by proxy name
- [x] Rotation spreads traffic evenly across alive nodes by usage counts
- [x] Dead nodes skipped and retested on slower loop, readmitted when alive

## Verification Evidence

- **Test command:** `.venv/bin/python -m unittest discover -s tests -v` (7 tests, FakeAPI stub)
- **Expected result:** all pass
- **Actual result:** 7 tests OK (round-robin order, empty-pool no-op, fail counting, readmission, usage equalization, meta exclusion, stale exclusion)
- **Exit code:** 0

- **Test command:** `.venv/bin/python scripts/rr_balancer.py retest --batch 25` (live controller)
- **Expected result:** batch tested, DB seeded
- **Actual result:** 23 alive / 2 failed, 7193 node names seeded, exit 0
- **Exit code:** 0

- **Test command:** `.venv/bin/python scripts/rr_balancer.py rotate` (live controller)
- **Expected result:** fastest alive node selected, PUT 204, GET confirms
- **Actual result:** selected fastest alive node (2ms), PUT 204, GET `now` matches, exit 0
- **Exit code:** 0

- **Test command:** `curl via mixed port 7890 after rotate (api.ipify.org + example.com)`
- **Expected result:** traffic exits through rotated node, HTTP 200
- **Actual result:** exit IP returned, example.com 200
- **Exit code:** 0

- **Test command:** `systemctl --user status rr-rotate.service rr-retest.service` after install + enable
- **Expected result:** both oneshots exit 0, timers scheduled
- **Actual result:** rotate selected fastest node (3ms) exit 0; retest batch 250 exit 0; next cycles 07:24 / 07:49
- **Exit code:** 0

- **Test command:** `rtk test .venv/bin/python -m unittest discover -s tests -v` (QA hotfix round: 7 existing + 4 new)
- **Expected result:** 11 tests pass, exit 0
- **Actual result:** Ran 11 tests, OK (all-fail guard, arg validation accept/reject, WAL pragmas)
- **Exit code:** 0

- **Test command:** `.venv/bin/python -m py_compile scripts/rr_balancer.py`
- **Expected result:** compiles clean
- **Actual result:** compile OK
- **Exit code:** 0

- **Test command:** `MIHOMO_CONTROLLER_SECRET=dummy .venv/bin/python scripts/rr_balancer.py --db /tmp/dummy.db retest --workers 0` (no live secrets)
- **Expected result:** exit 2 with clear stderr message
- **Actual result:** `error: --workers must be >= 1`
- **Exit code:** 2

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** per-node delay checks against 7000+ nodes are slow; rotation interval must account for check throughput
- **Rollback plan:** stop the script/timer; selection stays wherever it was last set, mihomo keeps working in select mode

---

## Execution Log & Reasoning

Autopilot locked for task 04 ("start auto pilot for task 04"). Manager plan approval (exact): "Approved. make sure we always connect to fastest nodes. and fresh, and gool balancer." Implemented accordingly.

### Implementation (2026-09-27)

- `scripts/rr_balancer.py` (new, stdlib only): `ClashAPI` (GET /proxies, PUT selection expecting 204, per-node delay check); `META_NAMES` excludes Auto/Load Balance/Fallback/DIRECT/REJECT/PASS; secret via `MIHOMO_CONTROLLER_SECRET` env or `~/.config/mihomo-subs/.controller_secret` file, never in repo. `rotate`: advance index modulo alive pool, PUT selection, log row; empty pool = logged no-op, never falls back. `retest --batch N`: oldest-checked-first batch, 3 consecutive fails → failed, success readmits.
- Selection policy per manager order: least-used node wins, fastest-delay tiebreak; nodes unchecked for >3600s are stale and excluded from the pool.
- `data/balancer_state.schema.sql` (new): `nodes(name PK, status, delay_ms, last_check, fails, uses)`, `rotation_state`, `rotation_log` + indexes. Runtime `data/balancer_state.db` gitignored.
- `tests/test_rr_balancer.py` (new): 7 unittest cases with FakeAPI stub (seeded order, empty-pool no-op, fail counting, readmission, usage equalization, meta exclusion, stale exclusion). Initial 2 failures came from fixed `last_check=1.7e9` fixtures vs real clock; fixed helper default and bodies to `int(time.time())` → 7 OK. Schema dry-run confirmed tables.
- `systemd/rr-rotate.{service,timer}` (5min) + `systemd/rr-retest.{service,timer}` (30min, batch 250 → ~15h full coverage). Installed to `~/.config/systemd/user/`, daemon-reload, both timers enabled; first timer-triggered runs both exit 0 (rotate picked fastest 3ms node; retest batch 250 done).
- Live fix during verification: controller `all` is a string list, not objects — fixed `group_members`.
- Assumption: controller at 127.0.0.1:9090 with Bearer secret (outside repo, redacted in all logs).
- Incident: one diagnostic shell command dumped process env including provider keys into tool output — values redacted everywhere, never reproduced; script reads the secret file directly so keys never pass through shell output.
- Brainstorm: not required — single domain backend task with verified API and no cross disciplinary ambiguity.

### QA hotfix round (2026-09-27, QA_REJECTED → fixed)

- V1 infra guard: `cmd_retest` now detects a full batch (≥5) with zero successes and only bumps `last_check`, printing `retest: all N failed, likely infra outage, fails not incremented`. Nodes are never blamed for infra outages, so rotation cannot wedge into a permanent no-op.
- V2 arg validation: new `validate_args` called from `main` after parse; rejects `retest --batch/--workers/--max-fails < 1`, `--timeout-ms < 500`, and `rotate --stale-after < 60` with `error: <msg>` on stderr and exit 2. Previously `--workers 0` raised `ValueError` and `--batch -1` became `LIMIT -1` (full-table scan).
- V3 overlap protection: `connect_db` opens with `timeout=10.0` plus `PRAGMA journal_mode=WAL / busy_timeout=10000 / synchronous=NORMAL` (best-effort inside try/except, fresh-schema behavior unchanged) so the 5min rotate and 30min retest oneshots share the DB.
- TDD order followed: 3 new tests written first and confirmed failing (2 failures + 2 errors), then code, then green. Tooling gate note: `root=. markers=[requirements.txt, proxy_converter.py] matched=[] reason=no stack skill matches this stdlib-only repo, base suite plus lint used`.

### Autopilot planning round 1 (2026-09-27)

- Seat Check: domains = Python backend + SQLite + Clash REST API + systemd. TITLE+BODY matched `schema` → Software Architect requested. Skipped UI/UX Designer (no user-visible surface) and debug consult (no failure signatures). Single-seat call.
- Brainstorm: not required — single-domain, additive new files, fully reversible (stop-script rollback).
- prompt-refactor skipped: input is an existing structured task file, not a raw prompt.
- Brain verdict: discovery task (no grounded plan yet). Memory bootstrap: no memory namespaces exist; decision sync clean. Replayed autopilot norms from stored rulings (drive end-to-end, no ferrying).
- Deviations from Brain XML logged: no memory store (project strict auto-save criteria requires an explicit manager-stated rule); no database-migration skill (no migration tooling in this stdlib-only project, new SQLite file); task-ID validation skipped (04 file already exists and is the active file).

- Re-QA (bridge, task_id 04): VERDICT QA_PASSED. V1/V2/V3 confirmed fixed in diff; residuals non-blocking: F1 fresh clone without data/ dir fails loud (reviewer may add makedirs), F2 manual batch<5 under total outage still increments fails (default 250 covered), F3 .gitignore lacks db-wal/db-shm (status noise only). Missing-tests M1-M3 non-blocking (all fail loud). Routed to Code Reviewer.

- Review hotfix (Code Reviewer APPROVED_WITH_CHANGES, I1-I4): added utc_now_epoch() clock seam (used in cmd_rotate/cmd_retest), connect_db now makedirs the parent dir (fresh-clone fix), group_members annotation fixed to Tuple[List[str], Optional[str]], .gitignore extended with data/*.db-wal + data/*.db-shm. No policy/interval/pool/secret changes.
- Evidence: `rtk test .venv/bin/python -m unittest discover -s tests` -> 11 tests OK exit 0; `py_compile scripts/rr_balancer.py` -> exit 0; `grep int(time.time())` -> exactly 1 match (line 48, inside utc_now_epoch); makedirs inline check -> makedirs-ok exit 0. Tooling gate skip record: root=. markers=[package.json, requirements.txt] matched=[] reason=no stack skill for stdlib-only repo (unittest is the gate).

- Re-review (bridge, task_id 04, include_diff): Code Reviewer APPROVED technically, status PO_REVIEW_PENDING. All four hotfix points (I1 makedirs, I2 annotation, I3 clock seam, I4 gitignore) confirmed closed in diff; rotation policy, guards, and live behavior intact. Non-blocking R1/R2 confirmations for Manager. Relayed to Manager verbatim; awaiting 'Approved for closure'.

- Closure: Manager approved with exact words "Approved for closure". File moved from qa to completed, header synced, ready for commit tool. No source changes in this turn.
- Closure evidence: `git mv tasks/qa/04-external-round-robin.md tasks/completed/04-external-round-robin.md` -> exit 0; `ls tasks/completed/04-external-round-robin.md` -> exit 0; header grep confirms completed path + closed status. Tooling gate skip record: root=. markers=[package.json, requirements.txt] matched=[] reason=no stack skill for stdlib-only repo.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `f4dcfafabae6d5f651654de04c77fdb4e957060d`
<!-- END_GIT_DIFF -->
