# Task 20: Multi-service clean-gate for exit selection

**File:** `tasks/completed/20-multi-service-clean-gate.md`
**Source:** manager
**Type:** feature
**Status:** closed
**Finished:** 2026-11-15T12:13:27Z
**Submitted:** 2026-11-15T12:06:26Z
**Started:** 2026-11-15T11:47:10Z
**Closed:** 2026-11-15T12:12:26Z

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
Manager closure approval (verbatim): "Approved for closure". Preconditions verified: file present in tasks/qa/ and PO_REVIEW_PENDING recorded in this log.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `8ee2f19606d108e7e08afdbf747e0562fcb3f1fc`
<!-- END_GIT_DIFF -->
