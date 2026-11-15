# Task 20: Multi-service clean-gate for exit selection

**File:** `tasks/backlog/20-multi-service-clean-gate.md`
**Source:** manager
**Type:** feature
**Status:** open

## Goal

Extend the balancer's clean-exit check beyond the Google search probe so a selected US exit is verified against reputation-sensitive services (YouTube Music, Spotify) before traffic is moved onto it.

## Manager's Notes

Today the cleanliness gate is a single Google search read (`/search?q=test` with redirects disabled: 302 to `/sorry` means flagged). That proved insufficient: exits pass Google yet fail YouTube Music and Spotify apps. Refactor the check to probe several services at once and only accept an exit that is clean everywhere. Research first: find curl-able or Python-probeable endpoints for each service (landing pages are too weak — a 200 on `music.youtube.com/` does not mean the app works), then implement the multi-probe gate in `scripts/rr_balancer.py` next to the existing Google gate.

## Local TODOs

- [ ] Research probe endpoints: Google search (existing baseline), YouTube Music (app-level, not landing page), Spotify (unauthenticated endpoint), plus one spare candidate
- [ ] Document each probe: URL, method, clean vs flagged response shape, timeout budget
- [ ] Design the multi-probe gate: all-must-pass vs scored, per-service quarantine causes, attempt bounds so rotation never stalls
- [ ] Implement in `scripts/rr_balancer.py` reusing the live mixed-port proxy path and the redirect-disabled fetch pattern
- [ ] Extend `tests/test_rr_balancer.py` for the new gate (clean pass, single-service fail, all-fail fail-open)
- [ ] Validate live: rotate onto a dirty exit on purpose, confirm the gate rejects it with the right cause
- [ ] Sync docs (`scripts/README.md` gate section, `scripts/DECISIONS.md` ADR) and CHANGELOG

## Acceptance Criteria

- [ ] Balancer probes Google plus at least YouTube Music and Spotify before selecting an exit
- [ ] A service-specific failure quarantines with a distinct cause (no silent lumping into `google`)
- [ ] Rotation still fails open to the best remaining node when every candidate is dirty
- [ ] Probe budget per rotation stays bounded (no multi-minute stall on a dead pool)
- [ ] Docs describe each probe and its clean/blocked signatures

## Verification Evidence

- **Test command:** rtk test python3 -m pytest tests/test_rr_balancer.py -q
- **Expected result:** all tests pass including new gate tests (clean pass, single-service fail, all-fail fail-open)
- **Actual result:** _(The Hands fill this during execution)_
- **Exit code:** _(The Hands fill this during execution)_

> Verification runner rule: `python3 -m pytest tests/test_rr_balancer.py -q` is the complete underlying test command. The first verification run MUST use the `rtk test` prefix; record the exact prefixed command above. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [ ] Build/Test/Lint pass with exit code 0
- [ ] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append
- [ ] `testing-verification` applied and evidence recorded

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do not defer box-checking to a closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** Stricter gate rejects the whole pool in regions where every exit is flagged for at least one service, leaving rotation stuck on fail-open.
- **Rollback plan:** `--no-google-check`-style opt-out flag for the new probes; revert `scripts/rr_balancer.py` to the Google-only gate.

---

## Execution Log & Reasoning

Carry-forward from the live session: today's exits pass Google (`HTTP 200`) yet fail the YouTube Music and Spotify apps, so landing-page 200s are proven insufficient as cleanliness signals. The current gate lives in `google_clean()` / `probe_status_via_proxy()` in `scripts/rr_balancer.py` with the `_NoRedirect` fetch pattern and `--google-attempts` bound; mirror that shape for new probes. Assumption A1: probes run through the live mixed port (127.0.0.1:7890) like the existing gate.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->

_(Git diff will be automatically injected here by the MCP tool. Do not edit this block manually)_

<!-- END_GIT_DIFF -->
