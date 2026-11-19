# Task 25: Simple Quota Rescue and Background opencode.ai Probe

**File:** `tasks/qa/25-simple-quota-rescue.md`
**Source:** manager
**Type:** improvement
**Status:** in-progress
**Submitted:** 2026-11-19T17:06:07Z
**Started:** 2026-11-19T17:05:49Z

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
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 4900ea4..098eb15 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -14,6 +14,13 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 
 ### Added
 
+- Simple quota rescue (task 25): `rr_balancer.py opencode-probe --batch 20` opens `https://opencode.ai` through the mixed port for a bounded batch, records `opencode_ok`/`opencode_checked`/`opencode_delay_ms`, and restores the previous selector in a `finally` block; on by default in `maintain.sh`, disabled with `RR_OPENCODE_PROBE_ENABLED=0`, URL overridable with `RR_OPENCODE_URL`. Added `tests/test_opencode_probe.py` (11 tests) and `tests/test_reality_short_id.py` (6 tests).
+- Configurable quarantine (task 25): `RR_QUARANTINE_SECONDS` env and `--quarantine-seconds` CLI override the 24h code default; this host sets 12h via a systemd drop-in and a `maintain.sh` export.
+
+### Changed
+
+- REALITY short-ids are sanitized at generation (task 25): only even-length hex is emitted, so a single odd-length or non-hex feed value can no longer abort the whole config at `mihomo -t` (the cause of the failing maintain service). `tests/test_proxy_converter.py` REJECT-rule assertions were corrected to the current no-REJECT rule set and the stub-only balancer test was removed.
+
 - External round-robin balancer (task 04): `scripts/rr_balancer.py` rotates the PROXY `select` group across alive nodes (least-used, fastest-delay tiebreak, stale excluded) with per-node delay checks and SQLite state (`data/balancer_state.schema.sql`); `tests/test_rr_balancer.py` (7 tests); `systemd/rr-rotate` (5min) and `systemd/rr-retest` (30min, 250-node batches) user timers.
 - Manual `skip NAME` subcommand (task 05): marks a flagged node failed and immediately rotates to the next alive node, so a rate-limited exit can be escaped without waiting for the timer.
 - Manual `next` subcommand + `~/.local/bin/rr` launcher (task 05 follow-up): bare `rr` auto-detects the currently active node via the controller, marks it failed, and rotates immediately.
diff --git a/data/balancer_state.schema.sql b/data/balancer_state.schema.sql
index 9274db0..60bd73a 100644
--- a/data/balancer_state.schema.sql
+++ b/data/balancer_state.schema.sql
@@ -12,7 +12,10 @@ CREATE TABLE IF NOT EXISTS nodes (
   spotify_fails INTEGER NOT NULL DEFAULT 0,
   gemini_fails INTEGER NOT NULL DEFAULT 0,
   country TEXT NOT NULL DEFAULT '',
-  country_checked INTEGER NOT NULL DEFAULT 0
+  country_checked INTEGER NOT NULL DEFAULT 0,
+  opencode_ok INTEGER NOT NULL DEFAULT 0,
+  opencode_checked INTEGER NOT NULL DEFAULT 0,
+  opencode_delay_ms INTEGER
 );
 
 CREATE TABLE IF NOT EXISTS rotation_state (
diff --git a/proxy_converter.py b/proxy_converter.py
index d6d3c5c..8719ce2 100644
--- a/proxy_converter.py
+++ b/proxy_converter.py
@@ -270,6 +270,32 @@ def _sanitize_reality_pbk(value: Optional[str]) -> Optional[str]:
     return key if len(raw) == 32 else None
 
 
+def _sanitize_reality_short_id(value: Optional[str]) -> str:
+    """Return a REALITY short-id mihomo accepts, or "" for an invalid one.
+
+    mihomo aborts the *entire* generated config with "invalid REALITY short
+    ID" when a node carries an odd-length or non-hex short-id. A single bad
+    feed entry therefore breaks every proxy for the host. The sanitizer
+    normalises the value and substitutes "" (which mihomo treats as "no short
+    id") for anything invalid, logging a warning so the source is visible.
+
+    Accepted: None/empty -> ""; "0xDEADbeef" -> "deadbeef" (even-length hex);
+    a bare even-length hex string -> lowercased. Rejected: odd-length hex and
+    any string containing non-hex characters -> "" with a warning.
+    """
+    if value is None:
+        return ""
+    text = "".join(str(value).split()).lower()
+    if text.startswith("0x"):
+        text = text[2:]
+    if text == "":
+        return ""
+    if len(text) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", text):
+        return text
+    logging.warning("invalid REALITY short-id %r; emitting empty short-id", value)
+    return ""
+
+
 def _usable_proxies(proxies: List[ProxyConfig]) -> List[ProxyConfig]:
     """Drop nodes that can never establish a session (bad REALITY key)."""
     return [p for p in proxies if not (p.security == "reality" and not p.pbk)]
@@ -1087,8 +1113,10 @@ class ConfigGenerator:
             block["alpn"] = alpn
         if cfg.security == "reality" and cfg.pbk:
             reality: Dict[str, Any] = {"public-key": _QuotedStr(cfg.pbk)}
-            if cfg.sid is not None:
-                reality["short-id"] = _QuotedStr(cfg.sid)
+            sid = _sanitize_reality_short_id(cfg.sid)
+            if sid:
+                # Quote so Go-YAML never reads a hex value like "2e00" as a float.
+                reality["short-id"] = _QuotedStr(sid)
             block["reality-opts"] = reality
         return block
 
@@ -1627,8 +1655,9 @@ class ConfigGenerator:
             if "utls" not in tls:
                 tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
             reality: Dict[str, Any] = {"enabled": True, "public_key": cfg.pbk}
-            if cfg.sid is not None:
-                reality["short_id"] = cfg.sid
+            sid = _sanitize_reality_short_id(cfg.sid)
+            if sid:
+                reality["short_id"] = sid
             tls["reality"] = reality
         return tls
 
diff --git a/scripts/DECISIONS.md b/scripts/DECISIONS.md
index 6f60769..4ebfe54 100644
--- a/scripts/DECISIONS.md
+++ b/scripts/DECISIONS.md
@@ -230,3 +230,37 @@ causes stay retired; the plugin only sends a reason for quota.
 
 **Rollback.** Remove `quota` from the argparse choices and the quarantine branch
 in `cmd_rotate`; existing rows keep their cause strings.
+
+## 2026-11-19 — Simple quota rescue: configurable quarantine, real HTTPS probe, REALITY sanitizer
+
+**Context.** The Manager asked to make quota rescue simpler and ensure the next
+exit actually works. Three concrete problems: the quarantine was hardcoded 24h;
+mihomo `/delay` reported a low latency for a node that carried no traffic (task
+24 measured 35ms with no data); and a single odd-length REALITY short-id from a
+feed aborted the whole generated config at `mihomo -t` (the failing maintain
+service on 2026-11-19). The Manager chose 12h via both a systemd drop-in and a
+`maintain.sh` export, the probe on by default with a small batch, and confirmed
+bare `rr` stays IP-only because the bridge already clears its session in its own
+quota path.
+
+**Decision.**
+- Quarantine length is resolved CLI > `RR_QUARANTINE_SECONDS` > 24h code default
+  in `resolve_quarantine_seconds`, threaded through `_mark_failed` and `retest`;
+  this host sets 12h in two places so every caller agrees.
+- New `opencode-probe` subcommand opens `https://opencode.ai` through the mixed
+  port for a bounded batch, persists `opencode_ok`/`opencode_checked`/
+  `opencode_delay_ms`, and restores the prior selector in `finally`. It is a
+  measurement only, never a quarantine. `maintain.sh` runs it each tick, on by
+  default.
+- `_sanitize_reality_short_id` emits only even-length hex (or empty) so one bad
+  feed entry cannot break every proxy. The 24h cause string and fail-open
+  behavior from the 2026-11-18 ADR are unchanged.
+
+**Consequences.** Quarantine is now operator-tunable without a code edit. The
+probe adds a bounded 20-request HTTPS check per 30-minute tick and slightly
+longer maintain runs. Invalid short-ids are dropped with a warning instead of
+failing config validation. No gate/country/keep-if-clean behavior was removed.
+
+**Rollback.** Remove the `opencode-probe` dispatch and its DB columns, revert
+`_mark_failed`/`retest` to the constant, and delete the sanitizer; existing DB
+rows keep their extra columns harmlessly.
diff --git a/scripts/README.md b/scripts/README.md
index e095cd5..d78cbd6 100644
--- a/scripts/README.md
+++ b/scripts/README.md
@@ -85,6 +85,22 @@ The feed list the old refresh drop-in used is embedded in the script.
    fails open to the best candidate, and with a country lock that failure stays
    inside the locked country.
 5. An unreadable country trace is a measurement gap, never a node verdict.
+6. A spent exit is quarantined for a configurable window (code default 24h,
+   this host sets 12h via `RR_QUARANTINE_SECONDS`); rotation picks the
+   least-used, then fastest, non-quarantined node and never goes dark.
+7. A node's REALITY short-id is sanitized at generation: only even-length hex
+   is emitted, so one bad feed entry cannot abort the whole mihomo config.
+
+## Background opencode.ai probe
+
+`rr_balancer.py opencode-probe --batch 20` opens `https://opencode.ai`
+through the mixed port for a small batch, records `opencode_ok`,
+`opencode_checked` (epoch seconds) and `opencode_delay_ms` on each node, and
+restores the previous PROXY selection in a `finally` block. A low mihomo
+`/delay` is not proof the exit carries traffic, so this is the real-HTTPS
+verdict that a quota rotation can trust. `maintain.sh` runs it every tick,
+on by default (`RR_OPENCODE_PROBE_ENABLED=0` disables, `RR_OPENCODE_URL`
+overrides the URL). A probe failure is a measurement, never a quarantine.
 
 ## Risks
 
diff --git a/scripts/maintain.sh b/scripts/maintain.sh
index da6eb4f..7342806 100755
--- a/scripts/maintain.sh
+++ b/scripts/maintain.sh
@@ -12,6 +12,11 @@
 # without a proxy.
 set -euo pipefail
 
+# A spent free-tier exit is quarantined for 12h in this deployment (code
+# default remains 24h). Exported so every subscript in this tick, including
+# both rr invocations below, inherits the same window.
+export RR_QUARANTINE_SECONDS=43200
+
 REPO="$HOME/v2ray-to-subs"
 PY="$REPO/.venv/bin/python"
 BALANCER="$REPO/scripts/rr_balancer.py"
@@ -35,6 +40,13 @@ echo "maintain: tick start"
 if ! "$PY" "$BALANCER" retest --batch 1000; then
 	echo "maintain: retest warned (continuing)"
 fi
+# Real-HTTPS verdict: verify a small batch actually reaches opencode.ai through
+# the mixed-port (a low mihomo delay alone does not prove the exit carries
+# traffic). On by default with a small batch; the command restores the previous
+# selector in its finally block, so one bad probe never strands the group.
+if ! "$PY" "$BALANCER" opencode-probe --batch 20; then
+	echo "maintain: opencode-probe warned (continuing)"
+fi
 if ! "$PY" "$BALANCER" country --batch 40; then
 	echo "maintain: country warned (continuing)"
 fi
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index 3ebe8e3..e7e8a84 100755
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -80,9 +80,47 @@ TRACE_SETTLE_SECONDS = 0.3
 META_NAMES = {"Auto", "Load Balance", "Fallback", "DIRECT", "REJECT", "PASS"}
 
 # Failed nodes stay out of rotation and retest for this long, so a
-# rate-limited exit cannot come back minutes later.
+# rate-limited exit cannot come back minutes later. This is the *code default*;
+# the effective value for a process is resolved from CLI > env > this default.
 QUARANTINE_SECONDS = 24 * 3600
 
+# Effective quarantine window for this process. ``main()`` resolves it once
+# from --quarantine-seconds / RR_QUARANTINE_SECONDS; direct function callers and
+# unit tests that never enter main() keep the 24h default.
+_quarantine_seconds: int = QUARANTINE_SECONDS
+
+
+def resolve_quarantine_seconds(cli_value: Optional[int] = None) -> int:
+    """Resolve the quarantine window: CLI, then env, then the 24h default.
+
+    Why: the operator may want a shorter window (e.g. 12h) without editing code,
+    while unit tests must stay deterministic with no environment configured.
+
+    Args:
+        cli_value: value of ``--quarantine-seconds`` when supplied, else None.
+
+    Returns:
+        Positive integer number of seconds to quarantine a failed node.
+
+    Edge cases: an empty env string counts as unset; a non-integer or
+    non-positive value raises ValueError so callers fail loudly rather than
+    parking nodes for a nonsensical interval.
+    """
+    if cli_value is not None:
+        seconds = int(cli_value)
+        if seconds <= 0:
+            raise ValueError("quarantine seconds must be positive, got %r" % (cli_value,))
+        return seconds
+    env_value = os.environ.get("RR_QUARANTINE_SECONDS")
+    if env_value is not None and env_value.strip() != "":
+        seconds = int(env_value)
+        if seconds <= 0:
+            raise ValueError(
+                "RR_QUARANTINE_SECONDS must be positive, got %r" % (env_value,)
+            )
+        return seconds
+    return QUARANTINE_SECONDS
+
 
 def utc_now_epoch() -> int:
     """Current UTC time as epoch seconds. Single clock seam for tests.
@@ -243,6 +281,9 @@ def connect_db(db_path: str) -> sqlite3.Connection:
             "gemini_fails INTEGER NOT NULL DEFAULT 0",
             "country TEXT NOT NULL DEFAULT ''",
             "country_checked INTEGER NOT NULL DEFAULT 0",
+            "opencode_ok INTEGER NOT NULL DEFAULT 0",
+            "opencode_checked INTEGER NOT NULL DEFAULT 0",
+            "opencode_delay_ms INTEGER",
         ):
             col = coldef.split()[0]
             if col not in cols:
@@ -299,7 +340,7 @@ def alive_pool(
 
     When allowed is given, only names present in the controller's current
     member list are returned, so ghosts from older feeds are never picked.
-    Quarantined nodes (failed less than 24h ago) are always excluded.
+    Quarantined nodes (still inside their configurable window) are always excluded.
     country is the last observed exit country ("" when never measured), so
     a country lock can filter the pool without another probe.
     """
@@ -604,6 +645,48 @@ def probe_country_via_proxy(
     return parse_trace_country(body)
 
 
+def probe_opencode_via_proxy(
+    url: str,
+    proxy_url: str = DEFAULT_PROXY_URL,
+    timeout_s: float = 8.0,
+) -> Tuple[bool, Optional[int]]:
+    """Real-HTTPS verdict for ``url`` read through the mihomo mixed-port.
+
+    Why: mihomo's /delay only proves a TCP/TLS handshake, not that the exit can
+    actually carry a request to opencode.ai (task 24 measured a node with a
+    35ms delay that carried no traffic). This opens the URL through
+    ``proxy_url`` with redirects disabled and classifies the response.
+
+    Returns ``(ok, delay_ms)``. ``ok`` is True only for HTTP 200; 429 (quota or
+    gate), 4xx/5xx and any transport failure are False. ``delay_ms`` is the
+    round trip in integer milliseconds, or None when the request failed.
+
+    Edge cases: non-200 is a normal failure verdict, not an exception; a
+    timeout or malformed URL yields ``(False, None)``; redirects are not
+    followed so a gate redirect is not mistaken for success.
+    """
+    started = time.monotonic()
+    req = urllib.request.Request(
+        url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131"}
+    )
+    try:
+        opener = urllib.request.build_opener(
+            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
+            _NoRedirect,
+        )
+        with opener.open(req, timeout=timeout_s) as resp:
+            status = resp.status
+            resp.read()  # drain so the connection closes cleanly
+        elapsed_ms = int(round((time.monotonic() - started) * 1000))
+        return (status == 200, elapsed_ms)
+    except urllib.error.HTTPError as exc:
+        # A non-2xx is a real network answer but not a working exit.
+        elapsed_ms = int(round((time.monotonic() - started) * 1000))
+        return (False, elapsed_ms)
+    except Exception:
+        return (False, None)
+
+
 def google_reachable_direct(url: str, timeout_s: float = 8.0) -> bool:
     """Guard against quarantining the whole pool during a Google outage.
 
@@ -628,8 +711,8 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
     ordered = order_pool(pool)
 
     # A quota 429 means the exit itself spent its free-tier allowance, not that
-    # the route is slow or dirty. Park it for 24h so the next rotation cannot
-    # pick the same spent exit, then fall through to the normal selection.
+    # the route is slow or dirty. Park it for the configured window so the next
+    # rotation cannot pick the same spent exit, then fall through to selection.
     # With no other candidate, keep the current node: going dark is worse than
     # retrying an already-limited exit.
     reason = getattr(args, "reason", None)
@@ -804,8 +887,13 @@ def _mark_failed(
     max_fails: int,
     now: int,
     reason: str = "manual",
+    quarantine_seconds: Optional[int] = None,
 ) -> None:
-    """Mark one node failed and quarantine it for 24h (retest readmits after expiry).
+    """Mark one node failed and quarantine it (retest readmits after expiry).
+
+    The quarantine length is the process-wide effective value resolved by
+    ``resolve_quarantine_seconds``; callers may override it explicitly. The
+    default of ``None`` keeps direct callers and unit tests deterministic.
 
     Causes are the ones this balancer actually acts on: google (Search
     answers /sorry), youtube (oEmbed answers 403), spotify (API edge
@@ -813,10 +901,13 @@ def _mark_failed(
     match the required country), quota (the free-tier allowance on this
     exit is spent), and manual (an operator skipped it).
     Each probe cause increments its own counter. Quota is stored on
-    ``last_fail_cause`` only: its 24h quarantine is enough to keep a
-    spent exit out of rotation, and no per-cause counter was restored.
+    ``last_fail_cause`` only: its quarantine is enough to keep a spent exit
+    out of rotation, and no per-cause counter was restored.
     Transport and region causes remain retired with their columns.
     """
+    if quarantine_seconds is None:
+        quarantine_seconds = _quarantine_seconds
+
     cur = conn.cursor()
     row = cur.execute("SELECT status FROM nodes WHERE name = ?", (name,)).fetchone()
     if row is None:
@@ -832,7 +923,7 @@ def _mark_failed(
             (
                 max_fails,
                 now,
-                now + QUARANTINE_SECONDS,
+                now + quarantine_seconds,
                 reason,
                 1 if reason == "google" else 0,
                 1 if reason == "youtube" else 0,
@@ -842,7 +933,10 @@ def _mark_failed(
             ),
         )
         conn.commit()
-        print("skip: marked %s failed (%s, quarantined 24h)" % (name, reason))
+        print(
+            "skip: marked %s failed (%s, quarantined %sh)"
+            % (name, reason, quarantine_seconds // 3600)
+        )
 
 
 def _relabel_latest(conn: sqlite3.Connection, reason: str) -> None:
@@ -1097,7 +1191,13 @@ def cmd_retest(args: argparse.Namespace, api: ClashAPI) -> int:
                 "ELSE status END, "
                 "quarantined_until=CASE WHEN fails+1 >= ? THEN ? "
                 "ELSE quarantined_until END WHERE name=?",
-                (now, args.max_fails, args.max_fails, now + QUARANTINE_SECONDS, name),
+                (
+                    now,
+                    args.max_fails,
+                    args.max_fails,
+                    now + _quarantine_seconds,
+                    name,
+                ),
             )
             failed += 1
     conn.commit()
@@ -1166,6 +1266,76 @@ def cmd_country(args: argparse.Namespace, api: ClashAPI) -> int:
     return 0
 
 
+def cmd_opencode_probe(args: argparse.Namespace, api: ClashAPI) -> int:
+    """Verify through a real HTTPS request that bounded nodes reach opencode.ai.
+
+    A low mihomo /delay is not proof a node carries traffic (task 24). This
+    selects each node briefly, opens ``args.opencode_url`` through the mixed
+    port, records a 200-only verdict plus delay, and restores the previous
+    PROXY selection in a ``finally`` block so a sweep never strands traffic on
+    a probed node. A failed probe is a measurement, never a quarantine.
+
+    Gated by ``args.opencode_enabled`` (env RR_OPENCODE_PROBE_ENABLED); off
+    means a no-op so operators can disable a noisy probe without editing units.
+    """
+    if not getattr(args, "opencode_enabled", True):
+        print("opencode-probe: disabled (RR_OPENCODE_PROBE_ENABLED=0)")
+        return 0
+    now = utc_now_epoch()  # epoch seconds, consistent with other stamps
+    conn = connect_db(args.db)
+    pool_names, prev = api.group_members(args.group)
+    added, pruned = seed_names(conn, pool_names)
+    cur = conn.cursor()
+    batch = []
+    working = 0
+    try:
+        if pool_names:
+            cur.execute(
+                "SELECT name FROM nodes WHERE name IN (%s) "
+                "AND quarantined_until <= ? "
+                "ORDER BY opencode_checked ASC, last_check ASC LIMIT ?"
+                % ",".join("?" * len(pool_names)),
+                (*pool_names, now, args.batch),
+            )
+            batch = [row[0] for row in cur.fetchall()]
+        for name in batch:
+            api.select(args.group, name)
+            if TRACE_SETTLE_SECONDS:
+                time.sleep(TRACE_SETTLE_SECONDS)
+            # A probe exception is a failed measurement for this node, never a
+            # reason to abort the sweep or strand the selector on a probed exit.
+            try:
+                ok, delay_ms = probe_opencode_via_proxy(
+                    args.opencode_url,
+                    args.opencode_proxy,
+                    args.opencode_timeout_ms / 1000.0,
+                )
+            except Exception as exc:
+                print("opencode-probe: %s probe error: %s" % (name, exc))
+                ok, delay_ms = False, None
+            cur.execute(
+                "UPDATE nodes SET opencode_ok = ?, opencode_checked = ?, "
+                "opencode_delay_ms = ? WHERE name = ?",
+                (1 if ok else 0, now, delay_ms, name),
+            )
+            conn.commit()
+            if ok:
+                working += 1
+            print("opencode-probe: %s -> %s" % (name, "ok" if ok else "failed"))
+    finally:
+        # Always put the selector back, even on a probe exception.
+        if prev:
+            try:
+                api.select(args.group, prev)
+            except Exception as exc:
+                print("opencode-probe: could not restore %s: %s" % (prev, exc))
+    print(
+        "opencode-probe: checked %d (seed +%d prune -%d): %d working, %d failed"
+        % (len(batch), added, pruned, working, len(batch) - working)
+    )
+    return 0
+
+
 def cmd_report(args: argparse.Namespace) -> int:
     """Print country coverage and per-country counts (no controller needed)."""
     conn = connect_db(args.db)
@@ -1302,6 +1472,12 @@ def build_parser() -> argparse.ArgumentParser:
     ap.add_argument("--secret-file", default=DEFAULT_SECRET_FILE)
     ap.add_argument("--db", default=DEFAULT_DB)
     ap.add_argument("--group", default="PROXY")
+    ap.add_argument(
+        "--quarantine-seconds",
+        type=int,
+        default=None,
+        help="failed-node quarantine window in seconds (overrides RR_QUARANTINE_SECONDS; default 86400)",
+    )
     sub = ap.add_subparsers(dest="cmd", required=True)
 
     rot = sub.add_parser("rotate", help="select next alive node")
@@ -1310,7 +1486,7 @@ def build_parser() -> argparse.ArgumentParser:
         "--reason",
         choices=("google", "youtube", "spotify", "gemini", "country", "manual", "quota"),
         default="manual",
-        help="failure cause; quota quarantines the current exit for 24h before rotating",
+        help="failure cause; quota quarantines the current exit before rotating",
     )
     rot.add_argument(
         "--keep-if-clean",
@@ -1398,6 +1574,42 @@ def build_parser() -> argparse.ArgumentParser:
         help="mihomo mixed-port used to read the trace through each candidate",
     )
 
+    ocp = sub.add_parser(
+        "opencode-probe",
+        help="verify via real HTTPS that a batch of exits reaches opencode.ai",
+    )
+    ocp.add_argument("--batch", type=int, default=20)
+    ocp.add_argument(
+        "--url",
+        dest="opencode_url",
+        default=os.environ.get("RR_OPENCODE_URL", "https://opencode.ai"),
+        help="URL opened through the proxy; override with RR_OPENCODE_URL",
+    )
+    # dest must match what cmd_opencode_probe reads (args.opencode_timeout_ms);
+    # a bare --timeout-ms would expose args.timeout_ms and silently skip probes.
+    ocp.add_argument(
+        "--timeout-ms", dest="opencode_timeout_ms", type=int, default=8000
+    )
+    ocp.add_argument(
+        "--proxy",
+        dest="opencode_proxy",
+        default=DEFAULT_PROXY_URL,
+        help="mihomo mixed-port used to open the URL through each candidate",
+    )
+    ocp.add_argument(
+        "--enabled",
+        dest="opencode_enabled",
+        default=os.environ.get("RR_OPENCODE_PROBE_ENABLED", "1") != "0",
+        action="store_true",
+        help="enable the probe (default on; RR_OPENCODE_PROBE_ENABLED=0 disables)",
+    )
+    ocp.add_argument(
+        "--no-probe",
+        dest="opencode_enabled",
+        action="store_false",
+        help="disable this probe run regardless of env",
+    )
+
     sub.add_parser("report", help="print country coverage and per-country counts")
     return ap
 
@@ -1456,6 +1668,14 @@ def main(argv: Optional[List[str]] = None) -> int:
     if err:
         print("error: %s" % err, file=sys.stderr)
         return 2
+    global _quarantine_seconds
+    try:
+        _quarantine_seconds = resolve_quarantine_seconds(
+            getattr(args, "quarantine_seconds", None)
+        )
+    except (ValueError, TypeError) as exc:
+        print("error: invalid quarantine configuration: %s" % exc, file=sys.stderr)
+        return 2
     if args.cmd == "report":
         return cmd_report(args)
     secret = os.environ.get("MIHOMO_CONTROLLER_SECRET") or load_secret(args.secret_file)
@@ -1473,6 +1693,8 @@ def main(argv: Optional[List[str]] = None) -> int:
         return cmd_fastest(args, api)
     if args.cmd == "country":
         return cmd_country(args, api)
+    if args.cmd == "opencode-probe":
+        return cmd_opencode_probe(args, api)
     return cmd_retest(args, api)
 
 
diff --git a/systemd/v2ray-to-subs-maintain.service.d/quarantine.conf b/systemd/v2ray-to-subs-maintain.service.d/quarantine.conf
new file mode 100644
index 0000000..4661762
--- /dev/null
+++ b/systemd/v2ray-to-subs-maintain.service.d/quarantine.conf
@@ -0,0 +1,7 @@
+# A spent free-tier exit is quarantined for 12h in this deployment.
+# The rr_balancer.py code default stays 24h; this drop-in (together with the
+# export in scripts/maintain.sh) sets the effective window for this host.
+# Install to ~/.config/systemd/user/v2ray-to-subs-maintain.service.d/ and run
+# `systemctl --user daemon-reload` at deploy time, never during a task.
+[Service]
+Environment=RR_QUARANTINE_SECONDS=43200
diff --git a/tests/test_opencode_probe.py b/tests/test_opencode_probe.py
new file mode 100644
index 0000000..343e0a8
--- /dev/null
+++ b/tests/test_opencode_probe.py
@@ -0,0 +1,256 @@
+"""Tests for the background opencode.ai HTTPS probe and configurable quarantine.
+
+Offline: urllib and the Clash controller are patched; no live network or mihomo.
+"""
+import argparse
+import os
+import sys
+import tempfile
+import unittest
+import unittest.mock
+
+sys.path.insert(
+    0,
+    os.path.join(
+        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
+    ),
+)
+import rr_balancer
+
+
+class FakeAPI:
+    """Minimal ClashAPI stand-in: remembers selection and records restores."""
+
+    def __init__(self, members, current):
+        self.members = members
+        self.current = current
+        self.selected = []
+
+    def group_members(self, group):
+        return self.members, self.current
+
+    def select(self, group, name):
+        self.selected.append(name)
+        self.current = name
+
+
+class ProbeVerdictTest(unittest.TestCase):
+    def test_probe_returns_ok_only_on_200(self):
+        class _Resp:
+            status = 200
+
+            def read(self):
+                return b"ok"
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
+            ok, delay = rr_balancer.probe_opencode_via_proxy(
+                "https://opencode.ai", rr_balancer.DEFAULT_PROXY_URL, 5.0
+            )
+        self.assertTrue(ok)
+        self.assertIsInstance(delay, int)
+
+    def test_probe_429_is_failure_not_success(self):
+        class _Opener:
+            def open(self, req, timeout=None):
+                raise rr_balancer.urllib.error.HTTPError(
+                    req.full_url, 429, "rate limited", None, None
+                )
+
+        with unittest.mock.patch.object(
+            rr_balancer.urllib.request, "build_opener", return_value=_Opener()
+        ):
+            ok, _ = rr_balancer.probe_opencode_via_proxy(
+                "https://opencode.ai", rr_balancer.DEFAULT_PROXY_URL, 5.0
+            )
+        self.assertFalse(ok)
+
+    def test_probe_transport_error_is_failure(self):
+        with unittest.mock.patch.object(
+            rr_balancer.urllib.request,
+            "build_opener",
+            side_effect=OSError("proxy down"),
+        ):
+            ok, delay = rr_balancer.probe_opencode_via_proxy(
+                "https://opencode.ai", rr_balancer.DEFAULT_PROXY_URL, 1.0
+            )
+        self.assertFalse(ok)
+        self.assertIsNone(delay)
+
+
+class QuarantineConfigTest(unittest.TestCase):
+    def setUp(self):
+        self.saved = os.environ.pop("RR_QUARANTINE_SECONDS", None)
+
+    def tearDown(self):
+        if self.saved is not None:
+            os.environ["RR_QUARANTINE_SECONDS"] = self.saved
+
+    def test_default_is_24h(self):
+        self.assertEqual(rr_balancer.resolve_quarantine_seconds(), 24 * 3600)
+
+    def test_env_override(self):
+        os.environ["RR_QUARANTINE_SECONDS"] = "43200"
+        self.assertEqual(rr_balancer.resolve_quarantine_seconds(), 43200)
+
+    def test_cli_overrides_env(self):
+        os.environ["RR_QUARANTINE_SECONDS"] = "43200"
+        self.assertEqual(rr_balancer.resolve_quarantine_seconds(7200), 7200)
+
+    def test_empty_env_uses_default(self):
+        os.environ["RR_QUARANTINE_SECONDS"] = ""
+        self.assertEqual(rr_balancer.resolve_quarantine_seconds(), 24 * 3600)
+
+    def test_nonpositive_rejected(self):
+        with self.assertRaises(ValueError):
+            rr_balancer.resolve_quarantine_seconds(0)
+        os.environ["RR_QUARANTINE_SECONDS"] = "-5"
+        with self.assertRaises(ValueError):
+            rr_balancer.resolve_quarantine_seconds()
+
+    def test_noninteger_rejected(self):
+        os.environ["RR_QUARANTINE_SECONDS"] = "abc"
+        with self.assertRaises(ValueError):
+            rr_balancer.resolve_quarantine_seconds()
+
+
+class ProbeParserRoundTripTest(unittest.TestCase):
+    """Guard the CLI wiring so the probe actually runs from the real command line.
+
+    Manual-Namespace tests missed F1 (dest mismatch) and would have missed any
+    regression where the parser exposes a different attribute than the command
+    reads. Parsing the real argv here closes that gap.
+    """
+
+    def setUp(self):
+        self.saved = os.environ.pop("RR_OPENCODE_PROBE_ENABLED", None)
+
+    def tearDown(self):
+        if self.saved is not None:
+            os.environ["RR_OPENCODE_PROBE_ENABLED"] = self.saved
+
+    def test_parser_exposes_the_timeout_attribute_the_command_reads(self):
+        args = rr_balancer.build_parser().parse_args(
+            ["opencode-probe", "--batch", "20"]
+        )
+        # cmd_opencode_probe reads args.opencode_timeout_ms; a bare --timeout-ms
+        # would expose args.timeout_ms instead and silently skip every probe.
+        self.assertEqual(args.opencode_timeout_ms, 8000)
+        self.assertEqual(args.batch, 20)
+        self.assertTrue(hasattr(args, "opencode_proxy"))
+
+    def test_parser_defaults_to_enabled_with_clean_env(self):
+        args = rr_balancer.build_parser().parse_args(["opencode-probe"])
+        self.assertTrue(args.opencode_enabled)
+
+    def test_env_zero_disables_by_default(self):
+        os.environ["RR_OPENCODE_PROBE_ENABLED"] = "0"
+        args = rr_balancer.build_parser().parse_args(["opencode-probe"])
+        self.assertFalse(args.opencode_enabled)
+
+    def test_explicit_flags_override_env_default(self):
+        os.environ["RR_OPENCODE_PROBE_ENABLED"] = "0"
+        args_on = rr_balancer.build_parser().parse_args(
+            ["opencode-probe", "--enabled"]
+        )
+        self.assertTrue(args_on.opencode_enabled)
+        args_off = rr_balancer.build_parser().parse_args(
+            ["opencode-probe", "--no-probe"]
+        )
+        self.assertFalse(args_off.opencode_enabled)
+
+    def test_command_uses_parsed_timeout_without_attribute_error(self):
+        # Parse real argv, then feed the Namespace to the command with a mocked
+        # probe; a dest mismatch would surface here as an AttributeError.
+        args = rr_balancer.build_parser().parse_args(
+            ["opencode-probe", "--batch", "20", "--timeout-ms", "3000"]
+        )
+        conn_path = tempfile.mktemp(suffix=".db")
+        try:
+            args.db = conn_path
+            conn = rr_balancer.connect_db(conn_path)
+            conn.execute(
+                "INSERT INTO nodes (name, status, quarantined_until) "
+                "VALUES ('n1','alive',0)"
+            )
+            conn.commit()
+            conn.close()
+            api = FakeAPI(["n1"], "original")
+            with unittest.mock.patch.object(
+                rr_balancer, "probe_opencode_via_proxy", return_value=(True, 5)
+            ) as probe:
+                rr_balancer.cmd_opencode_probe(args, api)
+            self.assertTrue(probe.called)
+            self.assertEqual(probe.call_args[0][2], 3.0)
+        finally:
+            if os.path.exists(conn_path):
+                os.unlink(conn_path)
+
+
+class OpencodeProbeCommandTest(unittest.TestCase):
+    def make_db(self):
+        fd, path = tempfile.mkstemp(suffix=".db")
+        os.close(fd)
+        os.unlink(path)
+        return path
+
+    def make_args(self, db, **overrides):
+        defaults = dict(
+            cmd="opencode-probe",
+            db=db,
+            group="PROXY",
+            batch=20,
+            opencode_url="https://opencode.ai",
+            opencode_proxy=rr_balancer.DEFAULT_PROXY_URL,
+            opencode_timeout_ms=8000,
+            opencode_enabled=True,
+        )
+        defaults.update(overrides)
+        return argparse.Namespace(**defaults)
+
+    def test_probe_persists_verdict_and_restores_selection_on_failure(self):
+        db = self.make_db()
+        conn = rr_balancer.connect_db(db)
+        conn.execute(
+            "INSERT INTO nodes (name, status, quarantined_until) VALUES ('n1','alive',0)"
+        )
+        conn.commit()
+        conn.close()
+        api = FakeAPI(["n1"], "original")
+        args = self.make_args(db)
+        args.opencode_enabled = True
+        with unittest.mock.patch.object(
+            rr_balancer, "probe_opencode_via_proxy", side_effect=OSError("boom")
+        ):
+            rr_balancer.cmd_opencode_probe(args, api)
+        # Finally restored the original selection even though the probe raised.
+        self.assertEqual(api.selected[-1], "original")
+        conn = rr_balancer.connect_db(db)
+        row = conn.execute(
+            "SELECT opencode_ok, opencode_checked FROM nodes WHERE name='n1'"
+        ).fetchone()
+        conn.close()
+        self.assertEqual(row[0], 0)
+        self.assertGreater(row[1], 0)
+
+    def test_disabled_probe_is_noop(self):
+        db = self.make_db()
+        api = FakeAPI(["n1"], "original")
+        args = self.make_args(db, opencode_enabled=False)
+        rr_balancer.cmd_opencode_probe(args, api)
+        self.assertEqual(api.selected, [])
+
+
+if __name__ == "__main__":
+    unittest.main()
diff --git a/tests/test_proxy_converter.py b/tests/test_proxy_converter.py
index 79fecba..f0e5965 100644
--- a/tests/test_proxy_converter.py
+++ b/tests/test_proxy_converter.py
@@ -227,7 +227,10 @@ class RuleShapeTest(unittest.TestCase):
         rules = self.gen.generate_clash_config(self.proxies)["rules"]
         self.assertIn("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", rules)
         self.assertIn("DOMAIN-SUFFIX,localhost,DIRECT", rules)
-        self.assertTrue([r for r in rules if r.endswith(",REJECT")])
+        # Ads REJECT rules were intentionally removed (ADR 2026-11-15): the
+        # host is a foreign server with no local sidecar to bypass. The final
+        # catch-all still routes everything else through PROXY.
+        self.assertFalse([r for r in rules if r.endswith(",REJECT")])
         self.assertEqual(rules[-1], "MATCH,PROXY")
 
     def test_clash_process_lookup_is_off(self):
@@ -253,7 +256,9 @@ class RuleShapeTest(unittest.TestCase):
     def test_singbox_rules_keep_private_and_reject(self):
         rules = self.gen.generate_singbox_config(self.proxies)["route"]["rules"]
         self.assertTrue([r for r in rules if r.get("ip_is_private")])
-        self.assertTrue([r for r in rules if r.get("action") == "reject"])
+        # REJECT rules were intentionally removed (ADR 2026-11-15); sniff stays
+        # first and private LAN traffic is routed DIRECT.
+        self.assertFalse([r for r in rules if r.get("action") == "reject"])
         self.assertEqual(rules[0], {"action": "sniff"})
 
 
diff --git a/tests/test_reality_short_id.py b/tests/test_reality_short_id.py
new file mode 100644
index 0000000..11ed6c3
--- /dev/null
+++ b/tests/test_reality_short_id.py
@@ -0,0 +1,46 @@
+"""Tests for REALITY short-id sanitization (mihomo -t must never abort a config).
+
+Offline: pure helper, no network or mihomo needed.
+"""
+import os
+import sys
+import unittest
+
+sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
+import proxy_converter
+
+
+class RealityShortIdTest(unittest.TestCase):
+    def test_none_and_empty_become_empty(self):
+        self.assertEqual(proxy_converter._sanitize_reality_short_id(None), "")
+        self.assertEqual(proxy_converter._sanitize_reality_short_id(""), "")
+        self.assertEqual(proxy_converter._sanitize_reality_short_id("   "), "")
+
+    def test_valid_even_hex_is_normalized(self):
+        self.assertEqual(proxy_converter._sanitize_reality_short_id("DEADbeef"), "deadbeef")
+        self.assertEqual(proxy_converter._sanitize_reality_short_id("2e00"), "2e00")
+
+    def test_0x_prefix_is_stripped(self):
+        self.assertEqual(
+            proxy_converter._sanitize_reality_short_id(" 0xDEADbeef "), "deadbeef"
+        )
+
+    def test_odd_length_hex_becomes_empty(self):
+        self.assertEqual(proxy_converter._sanitize_reality_short_id("abc"), "")
+
+    def test_non_hex_becomes_empty(self):
+        self.assertEqual(proxy_converter._sanitize_reality_short_id("zzzz"), "")
+        self.assertEqual(proxy_converter._sanitize_reality_short_id("hello!"), "")
+
+    def test_emitted_short_id_is_even_hex_or_absent(self):
+        # The emitter uses _QuotedStr for non-empty ids; assert the helper output
+        # is always something mihomo accepts before it reaches the emitter.
+        for value in ("abc", "zzzz", "0x0011", "2e00", None):
+            result = proxy_converter._sanitize_reality_short_id(value)
+            if result:
+                self.assertEqual(len(result) % 2, 0)
+                self.assertTrue(all(c in "0123456789abcdef" for c in result))
+
+
+if __name__ == "__main__":
+    unittest.main()
diff --git a/tests/test_rr_balancer.py b/tests/test_rr_balancer.py
index b384472..2900e4f 100644
--- a/tests/test_rr_balancer.py
+++ b/tests/test_rr_balancer.py
@@ -704,10 +704,6 @@ class RotateTest(unittest.TestCase):
         pool = rr_balancer.alive_pool(conn, 1_700_000_000, 3600)
         self.assertEqual([n for n, _, _, _ in pool], ["fresh"])
 
-    def test_meta_members_never_in_pool(self):
-        api = FakeAPI({"real": 100})
-        pool, _ = api.group_members("PROXY")
-        self.assertEqual(pool, ["real"])
 
 
 class RetestTest(unittest.TestCase):
```
<!-- END_GIT_DIFF -->
