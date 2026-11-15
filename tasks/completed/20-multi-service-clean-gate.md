# Task 20: Multi-service clean-gate for exit selection

**File:** `tasks/qa/20-multi-service-clean-gate.md`
**Source:** manager
**Type:** feature
**Status:** in-progress
**Submitted:** 2026-11-15T12:06:26Z
**Started:** 2026-11-15T11:47:10Z

## Goal

Extend the balancer's clean-exit check beyond the Google search probe so a selected US exit is verified against reputation-sensitive services (YouTube Music, Spotify) before traffic is moved onto it.

## Manager's Notes

Today the cleanliness gate is a single Google search read (`/search?q=test` with redirects disabled: 302 to `/sorry` means flagged). That proved insufficient: exits pass Google yet fail YouTube Music and Spotify apps. Refactor the check to probe several services at once and only accept an exit that is clean everywhere. Research first: find curl-able or Python-probeable endpoints for each service (landing pages are too weak — a 200 on `music.youtube.com/` does not mean the app works), then implement the multi-probe gate in `scripts/rr_balancer.py` next to the existing Google gate.

## Local TODOs

- [x] Research probe endpoints: Google search (existing baseline), YouTube backend (oEmbed discriminator — music.youtube.com pages are 200-weak), Spotify API edge-block (HTML 403 vs documented JSON 401), plus Gemini spare (strict 403, user-confirmed)
- [x] Document each probe: URL, method, clean vs flagged response shape, timeout budget (table below)
- [x] Design the multi-probe gate: all-must-pass G→Y→S→X via a new `multi_gate_cause()` helper (returns None when clean, else the cause), per-service quarantine causes, shared attempt budget so rotation never stalls
- [x] Implement in `scripts/rr_balancer.py` reusing the live mixed-port proxy path and the redirect-disabled fetch pattern
- [x] Extend `tests/test_rr_balancer.py` for the new gate (clean pass, single-service fail, all-fail fail-open)
- [x] Validate live: rotate onto a dirty exit on purpose, confirm the gate rejects it with the right cause
- [x] Sync docs (`scripts/README.md` gate section, `scripts/DECISIONS.md` ADR) and CHANGELOG

## Live Validation Evidence (Step 6)

- Read-only probes through the live mixed port on exit 45.138.100.248: Google 200, YouTube oEmbed blocked, Gemini blocked, Spotify edge-blocked — battery works end-to-end.
- Live `rotate --require-country US`: quarantined `vless-720dd080bf04` with cause `gemini` (it passed Google+YouTube+Spotify first — battery depth proven), quarantined `vless-25808bdc16aa` with cause `youtube`, then fail-open to `vless-69cb76cd5252` (itself youtube-dirty: every US candidate failed at least one probe, so R1 materialized and fail-open kept the client online). Per-cause counters verified in DB: youtube_fails=1 on two nodes, gemini_fails=1 on one.
- Post-rotate exit verified: `loc=US`, Google search 200. User traffic uninterrupted (fail-open + stale-connection close).

## Acceptance Criteria

- [x] Balancer probes Google plus at least YouTube Music and Spotify before selecting an exit
- [x] A service-specific failure quarantines with a distinct cause (no silent lumping into `google`)
- [x] Rotation still fails open to the best remaining node when every candidate is dirty
- [x] Probe budget per rotation stays bounded (no multi-minute stall on a dead pool)
- [x] Docs describe each probe and its clean/blocked signatures

## Verification Evidence

- **Test command:** rtk test .venv/bin/python -m unittest tests.test_rr_balancer (pytest is not installed in this env; the suite is stdlib unittest so the runner covers the same tests)
- **Expected result:** all 52 tests pass including new gate tests (youtube reject, spotify reject, unknown-keeps, spotify shape)
- **Actual result:** first RTK run collapsed output; unpiped rerun EXIT=1 with 7 failures caused by the new flags missing from the test Args helper and one bad test URL. Fixed the helper (gates-off defaults keep tests network-free; gate tests opt in) and the test URL. Final: Ran 52 tests, OK, 0.166s, EXIT=0
- **Exit code:** 0 (final unpiped run; intermediate failing run EXIT=1 recorded above)

- **Hotfix round (QA_REJECTED → fixed):** QA proved `youtube_clean`/`gemini_clean` returned bool, collapsing transport-None and 429/404 into flagged quarantines against the documented inconclusive-never-quarantines invariant. Fixed both to tri-state Optional (200 clean / 403 flagged / else None→unknown-keep); `google_clean` stays legacy-strict; `multi_gate_cause` unknown branch now live for all three new probes. Added 4 regression tests (youtube-unknown-keep, gemini-reject, gemini-unknown-keep, all-dirty fail-open with youtube causes). Docs needed no change (README/ADR already promise unknown-keeps); CHANGELOG wording unchanged. Final: Ran 56 tests, OK, EXIT=0.

> Verification runner rule: `python3 -m pytest tests/test_rr_balancer.py -q` is the complete underlying test command. The first verification run MUST use the `rtk test` prefix; record the exact prefixed command above. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `testing-verification` applied and evidence recorded

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do not defer box-checking to a closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** Stricter gate rejects the whole pool in regions where every exit is flagged for at least one service, leaving rotation stuck on fail-open.
- **Rollback plan:** `--no-google-check`-style opt-out flag for the new probes; revert `scripts/rr_balancer.py` to the Google-only gate.

---

## Execution Log & Reasoning

Carry-forward from the live session: today's exits pass Google (`HTTP 200`) yet fail the YouTube Music and Spotify apps, so landing-page 200s are proven insufficient as cleanliness signals. The current gate lives in `google_clean()` / `probe_status_via_proxy()` in `scripts/rr_balancer.py` with the `_NoRedirect` fetch pattern and `--google-attempts` bound; mirror that shape for new probes. Assumption A1: probes run through the live mixed port (127.0.0.1:7890) like the existing gate.

### Probe battery (research result, 2026-11-15, exit 45.138.100.248 US Google-clean via 127.0.0.1:7890)

Upstream `blowsh` searches for Spotify/YouTube-Music probe guidance timed out twice (recorded, not retried — live experiments substituted as primary evidence). Public Gemini reports corroborate aggressive datacenter-IP 403s.

| # | Service | Probe URL (GET, UA Chrome/131) | Clean shape | Flagged shape | Verdict |
|---|---------|-------------------------------|-------------|---------------|---------|
| G | Google search | `https://www.google.com/search?q=test`, redirects disabled | 200 | 302 to `/sorry` | keep (baseline) |
| Y | YouTube backend | `https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=aqz-KE-bpKQ`, redirects disabled | 200 JSON (public-embed design; blocking is the anomaly) | 403 observed live | adopt; `music.youtube.com/` and `/watch` both 200-weak, documented as rejected |
| S | Spotify API | `https://api.spotify.com/v1/search?q=test&type=track`, redirects disabled, body sniff | 401 JSON `{"error":...}` = edge reached auth evaluation (documented no-token behavior) | 403 HTML `Error: Forbidden` observed live = edge IP block before auth | adopt with status+body shape check |
| X | Gemini (spare) | `https://gemini.google.com/`, redirects disabled | 200 (service works for normal users; user-confirmed 403 is the anomaly) | 403 observed live, twice | adopt as spare only |

Timeout budget: 8000ms per probe, mirroring `google-timeout-ms`. Order cheapest-first: G (one request, existing infra guard) → Y → S → X. Stack-skill skip recorded: no roster stack skill matches this plain-Python balancer task; general workflow skills only.

### Gate design (Step 3 result)

D1: promotion is all-must-pass Google → YouTube → Spotify → Gemini(spare), evaluated by a new `multi_gate_cause(api, group, name, args)` helper that returns None when clean or the failing cause string. Google stays first so the existing `google_reachable_direct` infra guard keeps its meaning (skip whole battery on egress failure).
D2: first flagged service stops the candidate and quarantines with its own cause (`youtube`, `spotify`, `gemini`), via the existing `_mark_failed` path extended with per-cause counters; never lumped into `google`. `--reason` choices for skip/next gain the three causes.
D3: probes run cheapest and most discriminating first (G, Y, S, X); one `GOOGLE_SETTLE_SECONDS`-style settle after select, not per probe.
D4: one shared `attempts` counter per rotation, cap = max of the four `--*-attempts` flags (default 5 each, mirroring `google-attempts`); per-probe timeout 8000ms each, mirroring `google-timeout-ms`; all-dirty still fail-opens to `ordered[0]` inside the country lock. Schema gains `youtube_fails`, `spotify_fails`, `gemini_fails` (schema.sql + idempotent migration tuple + `_mark_failed` increment map).

Live probe battery on exit 45.138.100.248 (US, Google-clean) via 127.0.0.1:7890, 2026-11-15: `gemini.google.com/` 403 (flagged — user-confirmed, stricter than Search); `youtube.com/oembed?url=...` 403 (flagged — discriminates where `youtube.com/` 200 does not); `open.spotify.com/embed/...` 200 (not discriminating); `api.spotify.com/v1/` 403 (ambiguous without a clean baseline — Spotify's no-token answer needs research); `netflix.com/title/80018499` 200; `music.apple.com/us/browse` 301 (locale redirect, weak); `google.com/search?q=test` 200 (clean baseline). So the current exit is the perfect motivating case: Google-clean yet Gemini/YouTube-flagged. Gemini 403-on-datacenter behavior is corroborated by public reports (aggressive datacenter-IP detection, regional 403s even for paid tiers).
Plan approval (verbatim Manager answer): "Approved" on the plan-approval question covering S1-S7 with seat routing and R1-R4. Routing back through the Brain for the Senior Programmer implementation XML.
Reviewer verdict: technical APPROVAL with PO_REVIEW_PENDING. File stays in tasks/qa/ pending the explicit closure word. Non-blocking follow-ups recorded: I1 continue probing after unknown instead of returning early; I2 tighter per-probe timeout/early abort; I3 dedicated Spotify unknown-keeps test.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index dbe6c78..cf86b7f 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -35,6 +35,7 @@ The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
 - Balancer cause cleanup: the `quota`, `transport`, and `region` failure causes, their counters, and their per-cause selection weighting were removed with the retired `opencode-rate-limit-rescue` plugin they served. `--reason` accepts `google|country|manual`; existing databases drop the legacy columns through a guarded `DROP COLUMN` migration that keeps every learned row.
 - Proxy-everything routing in both generators: the ads `REJECT` block, the ~90-domain foreign-service pin list, and the `geosite:category-ads-all` DNS policy are deleted; rules are now private/LAN `DIRECT` → `MATCH,PROXY` (Clash) and sniff/hijack-dns/`ip_is_private` → final auto (sing-box). `allow-lan` defaults to true with mixed-port 7890, so scheduled refreshes serve LAN clients; TUN stays opt-in. `refresh.sh` and `manager.sh deploy` pass `--allow-lan` explicitly; checked-in samples regenerated via the converter.
 - `AGENTS.md` brought in line with the audit criteria: the lite-mode bypass removed so every task runs the full workflow, the task-generator reference corrected to `kanban-lifecycle`, the QA transition routed through `custom_context_qa_transition`, and Edit Tool Discipline, Parallel Index Isolation, and Living Folder Docs Inspection rules added. `docs/conventions.md` gained the Edit Tool Discipline and Living Folder Docs Standard sections; `.gitignore` now covers goal-plugin runtime state.
+- Multi-service clean gate in `rr_balancer.py`: rotation probes all-must-pass Google → YouTube (oEmbed 403 discriminator) → Spotify API (401-JSON clean vs HTML-403 edge block) → Gemini spare, with distinct `youtube`/`spotify`/`gemini` quarantine causes and counters, per-service `--url`/`--timeout-ms`/`--attempts`/`--no-*-check` flags, one shared attempt budget, and fail-open on all-dirty pools. Inconclusive new-probe measurements never quarantine. `tests/test_rr_balancer.py` covers per-cause rejection, unknown-keeps, and the Spotify shape classifier.
 
 ### Fixed
 - Hysteria2 links carrying `fp=` now emit `client-fingerprint`; mihomo rejects a uTLS name under `fingerprint` (that key is a TLS certificate pin) and aborts the whole `mihomo -t` run.
diff --git a/data/balancer_state.schema.sql b/data/balancer_state.schema.sql
index 4d1c663..9274db0 100644
--- a/data/balancer_state.schema.sql
+++ b/data/balancer_state.schema.sql
@@ -8,6 +8,9 @@ CREATE TABLE IF NOT EXISTS nodes (
   quarantined_until INTEGER NOT NULL DEFAULT 0,
   last_fail_cause TEXT NOT NULL DEFAULT '',
   google_fails INTEGER NOT NULL DEFAULT 0,
+  youtube_fails INTEGER NOT NULL DEFAULT 0,
+  spotify_fails INTEGER NOT NULL DEFAULT 0,
+  gemini_fails INTEGER NOT NULL DEFAULT 0,
   country TEXT NOT NULL DEFAULT '',
   country_checked INTEGER NOT NULL DEFAULT 0
 );
diff --git a/scripts/DECISIONS.md b/scripts/DECISIONS.md
index 4c81a93..d1fb625 100644
--- a/scripts/DECISIONS.md
+++ b/scripts/DECISIONS.md
@@ -137,3 +137,13 @@ deleting them; the column migrated idempotently.
 **Consequences.** All non-LAN traffic goes through a Google-clean US exit held by the balancer (retest 500, country 20, 6h refresh gate). LAN exposure of the mixed port is the accepted trade-off for serving LAN clients.
 
 **Rollback.** `git checkout` the generator, regenerate, reinstall the last `.bak` live config; disable the timer pair to stop scheduled refreshes.
+
+## 2026-11-15 — Multi-service clean gate (YouTube, Spotify, Gemini)
+
+**Context.** Google-clean exits still failed the YouTube Music and Spotify apps: Search answers 200 while the YouTube oEmbed backend answers 403, the Spotify API edge answers HTML 403, and Gemini answers 403. Landing pages (`youtube.com/`, `music.youtube.com/`, `open.spotify.com/`) stay 200 on flagged exits, so they cannot discriminate. Live battery on a US exit confirmed the shapes (research searches timed out; experiments substituted).
+
+**Decision.** Rotation probes all-must-pass Google → YouTube → Spotify → Gemini(spare) via `multi_gate_cause()`, reusing the redirect-disabled mixed-port pattern. First-flagged service quarantines 24h with its own cause and counter (`youtube_fails`, `spotify_fails`, `gemini_fails` via idempotent migration); inconclusive new-probe measurements never quarantine. One shared attempt budget (max of the four `--*-attempts`, default 5); per-service `--no-*-check` flags; all-dirty still fail-opens.
+
+**Consequences.** Selection rejects exits that pass Google but fail reputation-sensitive apps; a fully-flagged pool serves the least-bad candidate instead of going dark. First live run quarantined two US nodes (`youtube`, `gemini`) and fail-opened to the best remaining.
+
+**Rollback.** Per-service `--no-*-check` flags; `git checkout` the balancer to restore the Google-only gate.
diff --git a/scripts/README.md b/scripts/README.md
index 2f0d5ba..3704c85 100644
--- a/scripts/README.md
+++ b/scripts/README.md
@@ -37,14 +37,22 @@ The feed list the old refresh drop-in used is embedded in the script.
   counts, so the decision to enable a country lock is data-driven.
 - **Selection**: `rotate` picks the lowest `(uses, delay_ms)` row among alive,
   fresh, non-quarantined nodes and selects it in the `PROXY` group.
-- **Failure causes**: `skip` / `next --reason google|country|manual`
-  quarantines the node for 24 h. `google` also increments `google_fails`.
-- **Google-clean gate**: `rotate` reads `https://www.google.com/search?q=test`
-  through the live mixed-port with redirects disabled. A 302 to `/sorry`
-  means the exit IP is anti-abuse flagged, so the candidate is quarantined
-  with cause `google` and the next candidate is tried. `--no-google-check`
-  restores the pre-gate behavior; the gate is skipped when Google is
-  unreachable directly (infrastructure guard).
+- **Failure causes**: `skip` / `next --reason google|youtube|spotify|gemini|country|manual`
+  quarantines the node for 24 h. Each probe cause increments its own
+  counter (`google_fails`, `youtube_fails`, `spotify_fails`, `gemini_fails`).
+- **Multi-service clean gate**: `rotate` probes each candidate through the
+  live mixed-port with redirects disabled, all-must-pass in order Google
+  (`search?q=test`: 200 clean, 302 `/sorry` flagged) → YouTube backend
+  (`oembed`: 200 clean, 403 flagged; landing pages are 200-weak and unused)
+  → Spotify API (401 JSON clean = edge reached auth, 403 HTML flagged =
+  edge IP block) → Gemini spare (200 clean, 403 flagged). The first
+  flagged service quarantines with its cause and the next candidate is
+  tried; an inconclusive new-probe measurement keeps the candidate
+  without quarantine. Per-service `--no-*-check` flags restore fewer
+  gates; the battery is skipped when Google is unreachable directly
+  (infrastructure guard). One shared attempt budget (max of the four
+  `--*-attempts`, default 5) bounds the run; an all-dirty pool fails
+  open to the best candidate.
 - **Country lock**: `--require-country CC` (on `rotate`, `skip`, `next`) keeps
   rotation inside one observed country. Candidates with no measurement never
   match, and when nothing matches the current node is kept instead of falling
@@ -65,7 +73,11 @@ The feed list the old refresh drop-in used is embedded in the script.
 
 ## Risks
 
-- The Google gate selects a candidate in order to probe it, so a rejected
-  node carries traffic for roughly `GOOGLE_SETTLE_SECONDS` before the next
-  candidate is tried. Bounded by `--google-attempts`.
+- The probe gates select a candidate in order to probe it, so a rejected
+  node carries traffic for roughly `GOOGLE_SETTLE_SECONDS` per probe
+  before the next candidate is tried. Bounded by the shared attempt
+  budget (max of the four `--*-attempts`, default 5).
+- A stricter battery can reject the whole pool where every exit is
+  flagged for at least one service; fail-open then serves the least-bad
+  candidate instead of going dark.
 - `data/balancer_state.db` is runtime state. Losing it only loses history.
diff --git a/scripts/rr_balancer.py b/scripts/rr_balancer.py
index 50911cc..bd4c7ea 100755
--- a/scripts/rr_balancer.py
+++ b/scripts/rr_balancer.py
@@ -46,6 +46,22 @@ DEFAULT_GOOGLE_URL = "https://www.google.com/search?q=test"
 DEFAULT_PROXY_URL = "http://127.0.0.1:7890"
 GOOGLE_SETTLE_SECONDS = 0.3
 
+# YouTube backend is the app-relevant discriminator: flagged exits answer
+# 403 on oEmbed metadata while youtube.com/ and music.youtube.com/ still
+# answer 200, so landing pages cannot be used. Clean exits answer 200 JSON.
+DEFAULT_YOUTUBE_URL = (
+    "https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=aqz-KE-bpKQ"
+)
+
+# Spotify API edge block is an HTML 403 before auth evaluation; a clean
+# exit reaches auth evaluation and answers 401 JSON ("no token"). So the
+# probe classifies by status AND body shape, not status alone.
+DEFAULT_SPOTIFY_URL = "https://api.spotify.com/v1/search?q=test&type=track"
+
+# Gemini is the strict spare: Google's datacenter-IP detection 403s exits
+# that pass Search, so a Gemini-clean exit is clean everywhere measured.
+DEFAULT_GEMINI_URL = "https://gemini.google.com/"
+
 # Cloudflare's trace endpoint reports the country Cloudflare sees for the
 # connection ("loc=XX"). Read through a candidate exit it is the observed
 # country of that exit, which is what a geo-locked client actually gets --
@@ -216,6 +232,9 @@ def connect_db(db_path: str) -> sqlite3.Connection:
             "quarantined_until INTEGER NOT NULL DEFAULT 0",
             "last_fail_cause TEXT NOT NULL DEFAULT ''",
             "google_fails INTEGER NOT NULL DEFAULT 0",
+            "youtube_fails INTEGER NOT NULL DEFAULT 0",
+            "spotify_fails INTEGER NOT NULL DEFAULT 0",
+            "gemini_fails INTEGER NOT NULL DEFAULT 0",
             "country TEXT NOT NULL DEFAULT ''",
             "country_checked INTEGER NOT NULL DEFAULT 0",
         ):
@@ -333,6 +352,176 @@ def google_clean(
     return probe_status_via_proxy(url, proxy_url, timeout_ms / 1000.0) == 200
 
 
+def youtube_clean(
+    api: ClashAPI,
+    group: str,
+    name: str,
+    url: str,
+    timeout_ms: int,
+    proxy_url: str = DEFAULT_PROXY_URL,
+) -> Optional[bool]:
+    """Same select-settle shape as google_clean, tri-state YouTube verdict.
+
+    200 is clean, 403 is flagged, anything else (transport error,
+    rate-limit, removed video) is unknown and never a verdict.
+    """
+    api.select(group, name)
+    if GOOGLE_SETTLE_SECONDS:
+        time.sleep(GOOGLE_SETTLE_SECONDS)
+    status = probe_status_via_proxy(url, proxy_url, timeout_ms / 1000.0)
+    if status is None:
+        return None
+    if status == 200:
+        return True
+    if status == 403:
+        return False
+    return None
+
+
+def gemini_clean(
+    api: ClashAPI,
+    group: str,
+    name: str,
+    url: str,
+    timeout_ms: int,
+    proxy_url: str = DEFAULT_PROXY_URL,
+) -> Optional[bool]:
+    """Same select-settle shape as google_clean, tri-state Gemini verdict.
+
+    200 is clean, 403 is flagged, anything else is unknown and never
+    a verdict.
+    """
+    api.select(group, name)
+    if GOOGLE_SETTLE_SECONDS:
+        time.sleep(GOOGLE_SETTLE_SECONDS)
+    status = probe_status_via_proxy(url, proxy_url, timeout_ms / 1000.0)
+    if status is None:
+        return None
+    if status == 200:
+        return True
+    if status == 403:
+        return False
+    return None
+
+
+def probe_spotify_clean(url: str, proxy_url: str, timeout_s: float) -> Optional[bool]:
+    """Classify a Spotify API read: True clean, False flagged, None unknown.
+
+    The edge answers 401 JSON once the request reaches auth evaluation
+    (documented no-token behavior) and 403 HTML when the exit IP is
+    blocked before auth. Anything else (rate-limit, transport error) is
+    unknown, and unknown is never a verdict.
+    """
+    opener = urllib.request.build_opener(
+        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
+        _NoRedirect,
+    )
+    req = urllib.request.Request(
+        url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131"}
+    )
+    try:
+        with opener.open(req, timeout=timeout_s) as resp:
+            status, body = resp.status, resp.read(512)
+    except urllib.error.HTTPError as exc:
+        status = exc.code
+        try:
+            body = exc.read(512)
+        except Exception:
+            body = b""
+    except Exception:
+        return None
+    if status == 401 and b'"error"' in body:
+        return True
+    if status == 403:
+        return False
+    return None
+
+
+def spotify_clean(
+    api: ClashAPI,
+    group: str,
+    name: str,
+    url: str,
+    timeout_ms: int,
+    proxy_url: str = DEFAULT_PROXY_URL,
+) -> Optional[bool]:
+    """Select, settle, then classify the Spotify API shape (None = unknown)."""
+    api.select(group, name)
+    if GOOGLE_SETTLE_SECONDS:
+        time.sleep(GOOGLE_SETTLE_SECONDS)
+    return probe_spotify_clean(url, proxy_url, timeout_ms / 1000.0)
+
+
+def multi_gate_cause(
+    api: ClashAPI, group: str, name: str, args: argparse.Namespace
+) -> Optional[str]:
+    """First-flagged cause across the probe battery, or None when clean.
+
+    Order is Google, YouTube, Spotify, Gemini(spare): cheapest and most
+    discriminating first. "unknown" means a new-probe measurement failed
+    (transport or unexpected shape) and must not quarantine anyone;
+    legacy Google keeps its strict None-is-flagged shape. No gate
+    enabled returns None.
+    """
+    battery = []
+    if not getattr(args, "no_google_check", False):
+        battery.append(
+            (
+                "google",
+                getattr(args, "google_url", DEFAULT_GOOGLE_URL),
+                getattr(args, "google_timeout_ms", 8000),
+            )
+        )
+    if not getattr(args, "no_youtube_check", False):
+        battery.append(
+            (
+                "youtube",
+                getattr(args, "youtube_url", DEFAULT_YOUTUBE_URL),
+                getattr(args, "youtube_timeout_ms", 8000),
+            )
+        )
+    if not getattr(args, "no_spotify_check", False):
+        battery.append(
+            (
+                "spotify",
+                getattr(args, "spotify_url", DEFAULT_SPOTIFY_URL),
+                getattr(args, "spotify_timeout_ms", 8000),
+            )
+        )
+    if not getattr(args, "no_gemini_check", False):
+        battery.append(
+            (
+                "gemini",
+                getattr(args, "gemini_url", DEFAULT_GEMINI_URL),
+                getattr(args, "gemini_timeout_ms", 8000),
+            )
+        )
+    if not battery:
+        return None
+    # All probes share the live mixed-port; google_proxy names that port.
+    proxy_url = getattr(args, "google_proxy", DEFAULT_PROXY_URL)
+    for cause, url, timeout_ms in battery:
+        if cause == "spotify":
+            verdict = spotify_clean(api, group, name, url, timeout_ms, proxy_url)
+            if verdict is True:
+                continue
+            return "unknown" if verdict is None else cause
+        if cause == "youtube":
+            passed = youtube_clean(api, group, name, url, timeout_ms, proxy_url)
+        elif cause == "gemini":
+            passed = gemini_clean(api, group, name, url, timeout_ms, proxy_url)
+        else:
+            passed = google_clean(api, group, name, url, timeout_ms, proxy_url)
+        if cause == "google":
+            if not passed:
+                return cause
+        elif passed is None:
+            return "unknown"
+        elif not passed:
+            return cause
+    return None
+
+
 def probe_status_via_proxy(url: str, proxy_url: str, timeout_s: float) -> Optional[int]:
     """HTTP status for url through proxy_url, redirects NOT followed.
 
@@ -453,21 +642,33 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
             )
             return 0
         ordered = locked
-    enforce_google = not getattr(args, "no_google_check", False)
+    gates_on = [
+        svc
+        for svc in ("google", "youtube", "spotify", "gemini")
+        if not getattr(args, "no_%s_check" % svc, False)
+    ]
     google_url = getattr(args, "google_url", DEFAULT_GOOGLE_URL)
-    google_timeout = getattr(args, "google_timeout_ms", 8000)
-    google_proxy = getattr(args, "google_proxy", DEFAULT_PROXY_URL)
-    max_attempts = max(1, getattr(args, "google_attempts", 5))
-    if enforce_google and not google_reachable_direct(google_url):
-        print("rotate: google unreachable directly, skipping google gate")
-        enforce_google = False
+    max_attempts = max(
+        1,
+        max(
+            getattr(args, "%s_attempts" % svc, 5)
+            for svc in ("google", "youtube", "spotify", "gemini")
+        ),
+    )
+    if gates_on and not google_reachable_direct(google_url):
+        print("rotate: google unreachable directly, skipping probe gates")
+        gates_on = []
     selected_by_probe = False
     for candidate in ordered:
-        if enforce_google and attempts < max_attempts:
+        if gates_on and attempts < max_attempts:
             attempts += 1
-            if google_clean(
-                api, args.group, candidate[0], google_url, google_timeout, google_proxy
-            ):
+            cause = multi_gate_cause(api, args.group, candidate[0], args)
+            if cause is None or cause == "unknown":
+                if cause == "unknown":
+                    print(
+                        "rotate: probe inconclusive for %s, keeping without quarantine"
+                        % candidate[0]
+                    )
                 name, delay = candidate[0], candidate[2]
                 selected_by_probe = True
                 break
@@ -476,7 +677,7 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
                 candidate[0],
                 getattr(args, "max_fails", 3),
                 now,
-                "google",
+                cause,
             )
             continue
         name, delay = candidate[0], candidate[2]
@@ -486,7 +687,7 @@ def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
         # one so the client keeps working instead of going dark. When a
         # country lock is active, this stays inside the locked subset.
         name, delay = ordered[0][0], ordered[0][2]
-        print("rotate: all candidates google-blocked, failing open to %s" % name)
+        print("rotate: all candidates gate-blocked, failing open to %s" % name)
     if not selected_by_probe:
         api.select(args.group, name)
     if current and current != name:
@@ -532,10 +733,12 @@ def _mark_failed(
     """Mark one node failed and quarantine it for 24h (retest readmits after expiry).
 
     Causes are the ones this balancer actually acts on: google (Search
-    answers /sorry), country (exit does not match the required country),
-    and manual (an operator skipped it). Only google increments its
-    counter; the retired quota/transport/region causes belonged to the
-    rate-limit-rescue plugin and were removed with their columns.
+    answers /sorry), youtube (oEmbed answers 403), spotify (API edge
+    answers HTML 403), gemini (app answers 403), country (exit does not
+    match the required country), and manual (an operator skipped it).
+    Each probe cause increments its own counter; the retired
+    quota/transport/region causes belonged to the rate-limit-rescue
+    plugin and were removed with their columns.
     """
     cur = conn.cursor()
     row = cur.execute("SELECT status FROM nodes WHERE name = ?", (name,)).fetchone()
@@ -545,13 +748,19 @@ def _mark_failed(
         cur.execute(
             "UPDATE nodes SET status = 'failed', fails = ?, last_check = ?, "
             "quarantined_until = ?, last_fail_cause = ?, "
-            "google_fails = google_fails + ? WHERE name = ?",
+            "google_fails = google_fails + ?, "
+            "youtube_fails = youtube_fails + ?, "
+            "spotify_fails = spotify_fails + ?, "
+            "gemini_fails = gemini_fails + ? WHERE name = ?",
             (
                 max_fails,
                 now,
                 now + QUARANTINE_SECONDS,
                 reason,
                 1 if reason == "google" else 0,
+                1 if reason == "youtube" else 0,
+                1 if reason == "spotify" else 0,
+                1 if reason == "gemini" else 0,
                 name,
             ),
         )
@@ -796,6 +1005,69 @@ def add_google_args(parser: argparse.ArgumentParser) -> None:
     )
 
 
+def add_youtube_args(parser: argparse.ArgumentParser) -> None:
+    """YouTube-backend gate flags shared by rotate/skip/next."""
+    parser.add_argument(
+        "--youtube-url",
+        default=DEFAULT_YOUTUBE_URL,
+        help="URL that must answer 200; flagged exits answer 403",
+    )
+    parser.add_argument("--youtube-timeout-ms", type=int, default=8000)
+    parser.add_argument(
+        "--youtube-attempts",
+        type=int,
+        default=5,
+        help="max gated candidates before failing open (shared budget)",
+    )
+    parser.add_argument(
+        "--no-youtube-check",
+        action="store_true",
+        help="disable the YouTube-clean gate for this run",
+    )
+
+
+def add_spotify_args(parser: argparse.ArgumentParser) -> None:
+    """Spotify-API gate flags shared by rotate/skip/next."""
+    parser.add_argument(
+        "--spotify-url",
+        default=DEFAULT_SPOTIFY_URL,
+        help="URL that must answer 401 JSON; flagged exits answer HTML 403",
+    )
+    parser.add_argument("--spotify-timeout-ms", type=int, default=8000)
+    parser.add_argument(
+        "--spotify-attempts",
+        type=int,
+        default=5,
+        help="max gated candidates before failing open (shared budget)",
+    )
+    parser.add_argument(
+        "--no-spotify-check",
+        action="store_true",
+        help="disable the Spotify-clean gate for this run",
+    )
+
+
+def add_gemini_args(parser: argparse.ArgumentParser) -> None:
+    """Gemini spare-gate flags shared by rotate/skip/next."""
+    parser.add_argument(
+        "--gemini-url",
+        default=DEFAULT_GEMINI_URL,
+        help="URL that must answer 200; flagged exits answer 403",
+    )
+    parser.add_argument("--gemini-timeout-ms", type=int, default=8000)
+    parser.add_argument(
+        "--gemini-attempts",
+        type=int,
+        default=5,
+        help="max gated candidates before failing open (shared budget)",
+    )
+    parser.add_argument(
+        "--no-gemini-check",
+        action="store_true",
+        help="disable the Gemini-clean gate for this run",
+    )
+
+
 def add_country_lock_arg(parser: argparse.ArgumentParser) -> None:
     """Country lock shared by rotate/skip/next.
 
@@ -822,6 +1094,9 @@ def build_parser() -> argparse.ArgumentParser:
     rot = sub.add_parser("rotate", help="select next alive node")
     rot.add_argument("--stale-after", type=int, default=7200)
     add_google_args(rot)
+    add_youtube_args(rot)
+    add_spotify_args(rot)
+    add_gemini_args(rot)
     add_country_lock_arg(rot)
 
     ret = sub.add_parser("retest", help="check oldest batch of nodes")
@@ -839,11 +1114,14 @@ def build_parser() -> argparse.ArgumentParser:
     skp.add_argument("--max-fails", type=int, default=3)
     skp.add_argument(
         "--reason",
-        choices=("google", "country", "manual"),
+        choices=("google", "youtube", "spotify", "gemini", "country", "manual"),
         default="manual",
         help="failure cause recorded for the node",
     )
     add_google_args(skp)
+    add_youtube_args(skp)
+    add_spotify_args(skp)
+    add_gemini_args(skp)
     add_country_lock_arg(skp)
 
     nxt = sub.add_parser("next", help="skip the current node and rotate now")
@@ -851,11 +1129,14 @@ def build_parser() -> argparse.ArgumentParser:
     nxt.add_argument("--max-fails", type=int, default=3)
     nxt.add_argument(
         "--reason",
-        choices=("google", "country", "manual"),
+        choices=("google", "youtube", "spotify", "gemini", "country", "manual"),
         default="manual",
         help="failure cause recorded for the node",
     )
     add_google_args(nxt)
+    add_youtube_args(nxt)
+    add_spotify_args(nxt)
+    add_gemini_args(nxt)
     add_country_lock_arg(nxt)
 
     cty = sub.add_parser("country", help="fill observed exit countries for a batch")
@@ -896,6 +1177,18 @@ def validate_args(args: argparse.Namespace) -> Optional[str]:
             return "--google-timeout-ms must be >= 500"
         if args.google_attempts < 1:
             return "--google-attempts must be >= 1"
+        if args.youtube_timeout_ms < 500:
+            return "--youtube-timeout-ms must be >= 500"
+        if args.youtube_attempts < 1:
+            return "--youtube-attempts must be >= 1"
+        if args.spotify_timeout_ms < 500:
+            return "--spotify-timeout-ms must be >= 500"
+        if args.spotify_attempts < 1:
+            return "--spotify-attempts must be >= 1"
+        if args.gemini_timeout_ms < 500:
+            return "--gemini-timeout-ms must be >= 500"
+        if args.gemini_attempts < 1:
+            return "--gemini-attempts must be >= 1"
         if args.require_country is not None:
             cc = args.require_country.strip()
             if len(cc) != 2 or not cc.isalpha():
diff --git a/tests/test_rr_balancer.py b/tests/test_rr_balancer.py
index a1c6603..ddc3975 100644
--- a/tests/test_rr_balancer.py
+++ b/tests/test_rr_balancer.py
@@ -9,6 +9,8 @@ import tempfile
 import time
 import unittest
 import unittest.mock
+import urllib.error
+import urllib.request
 
 sys.path.insert(
     0,
@@ -89,12 +91,24 @@ class Args:
                 max_fails=3,
                 test_url="https://www.gstatic.com/generate_204",
                 timeout_ms=3000,
-                # Keep unit tests network-free; the google-gate test opts in
-                # and patches the direct reachability probe.
+                # Keep unit tests network-free; gate tests opt in and patch
+                # all probes. Production CLI defaults are gates-on.
                 no_google_check=True,
+                no_youtube_check=True,
+                no_spotify_check=True,
+                no_gemini_check=True,
                 google_url=rr_balancer.DEFAULT_GOOGLE_URL,
                 google_timeout_ms=8000,
                 google_attempts=5,
+                youtube_url=rr_balancer.DEFAULT_YOUTUBE_URL,
+                youtube_timeout_ms=8000,
+                youtube_attempts=5,
+                spotify_url=rr_balancer.DEFAULT_SPOTIFY_URL,
+                spotify_timeout_ms=8000,
+                spotify_attempts=5,
+                gemini_url=rr_balancer.DEFAULT_GEMINI_URL,
+                gemini_timeout_ms=8000,
+                gemini_attempts=5,
                 # Country fields default to the lock being off.
                 require_country=None,
                 trace_url=rr_balancer.DEFAULT_TRACE_URL,
@@ -167,6 +181,296 @@ class RotateTest(unittest.TestCase):
             self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
         self.assertEqual(api.selected[-1], ("PROXY", "a"))
 
+    def test_rotate_rejects_youtube_flagged(self):
+        conn, path = make_db()
+        now = int(time.time())
+        # "blocked" passes Google but answers 403 on the YouTube backend.
+        mark(conn, "blocked", "alive", delay=50, uses=0, last_check=now)
+        mark(conn, "clean", "alive", delay=200, uses=0, last_check=now)
+        api = FakeAPI({"blocked": 50, "clean": 200})
+        args = Args(
+            db=path,
+            no_google_check=False,
+            no_youtube_check=False,
+            no_spotify_check=False,
+            no_gemini_check=False,
+        )
+
+        def fake_status(url, proxy, timeout):
+            if "youtube.com" in url and api.selected[-1][1] == "blocked":
+                return 403
+            return 200
+
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", side_effect=fake_status
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_spotify_clean", return_value=True
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "clean"))
+        row = conn.execute(
+            "SELECT status, last_fail_cause, youtube_fails, google_fails FROM nodes "
+            "WHERE name='blocked'"
+        ).fetchone()
+        self.assertEqual(row, ("failed", "youtube", 1, 0))
+
+    def test_rotate_rejects_spotify_flagged(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "blocked", "alive", delay=50, uses=0, last_check=now)
+        mark(conn, "clean", "alive", delay=200, uses=0, last_check=now)
+        api = FakeAPI({"blocked": 50, "clean": 200})
+        args = Args(
+            db=path,
+            no_google_check=False,
+            no_youtube_check=False,
+            no_spotify_check=False,
+            no_gemini_check=False,
+        )
+
+        def fake_spotify(url, proxy, timeout):
+            return api.selected[-1][1] != "blocked"
+
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", return_value=200
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_spotify_clean", side_effect=fake_spotify
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "clean"))
+        row = conn.execute(
+            "SELECT status, last_fail_cause, spotify_fails FROM nodes "
+            "WHERE name='blocked'"
+        ).fetchone()
+        self.assertEqual(row, ("failed", "spotify", 1))
+
+    def test_rotate_youtube_unknown_keeps_without_quarantine(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "lonely", "alive", delay=50, uses=0, last_check=now)
+        api = FakeAPI({"lonely": 50})
+        args = Args(
+            db=path,
+            no_google_check=False,
+            no_youtube_check=False,
+            no_spotify_check=False,
+            no_gemini_check=False,
+        )
+
+        def fake_status(url, proxy, timeout):
+            if "youtube.com" in url:
+                return None
+            return 200
+
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", side_effect=fake_status
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_spotify_clean", return_value=True
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "lonely"))
+        row = conn.execute(
+            "SELECT status, youtube_fails FROM nodes WHERE name='lonely'"
+        ).fetchone()
+        self.assertEqual(row, ("alive", 0))
+
+    def test_rotate_rejects_gemini_flagged(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "blocked", "alive", delay=50, uses=0, last_check=now)
+        mark(conn, "clean", "alive", delay=200, uses=0, last_check=now)
+        api = FakeAPI({"blocked": 50, "clean": 200})
+        args = Args(
+            db=path,
+            no_google_check=False,
+            no_youtube_check=False,
+            no_spotify_check=False,
+            no_gemini_check=False,
+        )
+
+        def fake_status(url, proxy, timeout):
+            if "gemini.google.com" in url and api.selected[-1][1] == "blocked":
+                return 403
+            return 200
+
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", side_effect=fake_status
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_spotify_clean", return_value=True
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "clean"))
+        row = conn.execute(
+            "SELECT status, last_fail_cause, gemini_fails FROM nodes "
+            "WHERE name='blocked'"
+        ).fetchone()
+        self.assertEqual(row, ("failed", "gemini", 1))
+
+    def test_rotate_gemini_unknown_keeps(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "lonely", "alive", delay=50, uses=0, last_check=now)
+        api = FakeAPI({"lonely": 50})
+        args = Args(
+            db=path,
+            no_google_check=False,
+            no_youtube_check=False,
+            no_spotify_check=False,
+            no_gemini_check=False,
+        )
+
+        def fake_status(url, proxy, timeout):
+            if "gemini.google.com" in url:
+                return 429
+            return 200
+
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", side_effect=fake_status
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_spotify_clean", return_value=True
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        self.assertEqual(api.selected[-1], ("PROXY", "lonely"))
+        row = conn.execute(
+            "SELECT status, gemini_fails FROM nodes WHERE name='lonely'"
+        ).fetchone()
+        self.assertEqual(row, ("alive", 0))
+
+    def test_rotate_all_dirty_fail_open_youtube(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "a", "alive", delay=50, uses=0, last_check=now)
+        mark(conn, "b", "alive", delay=60, uses=0, last_check=now)
+        api = FakeAPI({"a": 50, "b": 60})
+        args = Args(
+            db=path,
+            no_google_check=False,
+            no_youtube_check=False,
+            no_spotify_check=False,
+            no_gemini_check=False,
+        )
+
+        def fake_status(url, proxy, timeout):
+            if "youtube.com" in url:
+                return 403
+            return 200
+
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", side_effect=fake_status
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_spotify_clean", return_value=True
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        # Both quarantined with youtube, fail-open keeps the best first.
+        self.assertEqual(api.selected[-1], ("PROXY", "a"))
+        rows = conn.execute(
+            "SELECT name, status, last_fail_cause FROM nodes ORDER BY name"
+        ).fetchall()
+        self.assertEqual(rows, [("a", "failed", "youtube"), ("b", "failed", "youtube")])
+
+    def test_rotate_unknown_probe_keeps_without_quarantine(self):
+        conn, path = make_db()
+        now = int(time.time())
+        mark(conn, "flaky", "alive", delay=50, uses=0, last_check=now)
+        api = FakeAPI({"flaky": 50})
+        args = Args(db=path, no_google_check=False)
+
+        with (
+            unittest.mock.patch.object(
+                rr_balancer, "google_reachable_direct", return_value=True
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_status_via_proxy", return_value=None
+            ),
+            unittest.mock.patch.object(
+                rr_balancer, "probe_spotify_clean", return_value=None
+            ),
+            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
+        ):
+            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
+        # Google is legacy-strict (None counts as flagged); a single-node
+        # pool then fail-opens to it, quarantined as google like before.
+        self.assertEqual(api.selected[-1], ("PROXY", "flaky"))
+
+    def test_spotify_shape_clean_flagged_unknown(self):
+        opener_status = {}
+
+        class FakeResp:
+            def __init__(self, status, body):
+                self.status = status
+                self._body = body
+
+            def read(self, n=-1):
+                return self._body
+
+            def __enter__(self):
+                return self
+
+            def __exit__(self, *exc):
+                return False
+
+        class FakeOpener:
+            def open(self, req, timeout=None):
+                status, body = opener_status["next"]
+                if status >= 400:
+                    err = urllib.error.HTTPError(req.full_url, status, "x", {}, None)
+                    err.read = lambda n=-1: body
+                    raise err
+                return FakeResp(status, body)
+
+        with unittest.mock.patch.object(
+            urllib.request, "build_opener", return_value=FakeOpener()
+        ):
+            url = "https://api.spotify.example/v1/search?q=test&type=track"
+            opener_status["next"] = (401, b'{"error":{"status":401}}')
+            self.assertTrue(rr_balancer.probe_spotify_clean(url, "p", 1))
+            opener_status["next"] = (403, b"<html>Forbidden</html>")
+            self.assertFalse(rr_balancer.probe_spotify_clean(url, "p", 1))
+            opener_status["next"] = (429, b"rate limited")
+            self.assertIsNone(rr_balancer.probe_spotify_clean(url, "p", 1))
+
     def test_second_rotate_moves_on(self):
         conn, path = make_db()
         now = int(time.time())
```
<!-- END_GIT_DIFF -->
