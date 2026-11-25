# Task 29: Create user systemd units for config generation and mihomo

**File:** `tasks/archive/29-create-user-systemd-units.md`
**Source:** manager
**Type:** feature
**Status:** superseded
**Superseded-By:** `30-systemd-units-research-and-creation`
**Superseded-At:** `2026-11-25 16:14 UTC`
**Depends on:** 28

## Source Context

### Variant C: Manager (manager)

## Goal

Create two per-user (systemd --user) units:
1. A timer + service that internally calls proxy_converter.py to generate both sing-box and mihomo configs (TUN off, disable LAN listen) every 6 hours.
2. A mihomo service unit that starts the generated mihomo config, with dashboard password 123456789, bound locally and safely.

User already has mihomo installed at a path. Units must be installed per-user, not system-wide. Config generation must disable LAN listen and TUN.

## Manager's Notes

- Config generation: TUN off, disable LAN listen (bind 127.0.0.1, allow-lan false).
- Generation cadence: every 6 hours (systemd timer).
- Mihomo unit: starts generated clash_config.yaml; dashboard secret 123456789; local-only (127.0.0.1:9090), safe.
- User already has mihomo binary at a path (to be confirmed during discovery).
- Per-user install: ~/.config/systemd/user/.
- Soft config reload preferred where supported (SIGHUP) to avoid restarts.

<!-- These sections are unconditional per lint contract — DO NOT move back inside variants -->

## Local TODOs

- [ ] Confirm discovery (Task 28) findings
- [ ] Confirm mihomo binary path
- [ ] Create config-generation service + timer units
- [ ] Create mihomo service unit
- [ ] Install units per-user and enable timer
- [ ] Verify units with systemd-analyze and dry-run

## Acceptance Criteria

- [ ] Config-generation service unit created (calls proxy_converter.py, TUN off, LAN off)
- [ ] Timer unit created (every 6 hours)
- [ ] Mihomo service unit created (starts generated config, dashboard secret 123456789, local-only)
- [ ] Units installed under ~/.config/systemd/user/
- [ ] systemd-analyze verify passes for all units
- [ ] No system-wide (root) installation

## Verification Evidence

- **Test command:** rtk test systemd-analyze verify ~/.config/systemd/user/*.service ~/.config/systemd/user/*.timer
- **Expected result:** all units verify with exit 0
- **Actual result:** _(The Hands fill this during execution)_
- **Exit code:** _(The Hands fill this during execution)_

> Verification runner rule: the first verification run MUST use the `rtk test` prefix. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [ ] Build/Test/Lint pass with exit code 0
- [ ] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append (N/A — file absent per approved converter-only scope; recorded skip)
- [ ] `testing-verification` applied and evidence recorded

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do NOT defer box-checking to a closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** Per-user units require login session or lingering enabled (loginctl enable-linger); mihomo path may differ.
- **Rollback plan:** Remove unit files from ~/.config/systemd/user/ and run systemctl --user daemon-reload.

---

> **Superseded:** This task was bundled into META task `30-systemd-units-research-and-creation` and archived on 2026-11-25 16:14 UTC. See `tasks/backlog/30-systemd-units-research-and-creation.md` (or its Kanban successor) for the unified execution. History preserved via `git log --follow -- tasks/archive/29-create-user-systemd-units.md`.

## Execution Log & Reasoning

_(The Hands: Manually log your changes, file edits, and architectural reasoning here)_

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->

_(Git diff will be automatically injected here by the MCP tool. Do not edit this block manually)_

<!-- END_GIT_DIFF -->
