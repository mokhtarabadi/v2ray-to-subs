# Task 28: Research mihomo and sing-box systemd units and deb links

**File:** `tasks/archive/28-research-mihomo-singbox-systemd-deb.md`
**Source:** manager
**Type:** discovery
**Status:** superseded
**Superseded-By:** `30-systemd-units-research-and-creation`
**Superseded-At:** `2026-11-25 16:14 UTC`

## Source Context

### Variant C: Manager (manager)

## Goal

Research and collect authoritative information before implementing user-level systemd units:
1. Official mihomo and sing-box systemd unit examples (user and system).
2. Actual .deb download links for mihomo and sing-box (latest stable).
3. Sing-box and mihomo soft-reload behavior (SIGHUP, hot reload) and cache persistence of last selected group across restarts.
4. Per-user (systemd --user) installation conventions and requirements.

## Manager's Notes

- User has mihomo already installed at a path (to be confirmed).
- Units must be per-user (systemd --user), not system-wide.
- Need actual deb download links for reproducible installs.
- Answer: mihomo and sing-box persist last selected group via store-selected/cache_file (enabled in our configs); soft reload via SIGHUP/API for mihomo, SIGHUP for sing-box.

<!-- These sections are unconditional per lint contract — DO NOT move back inside variants -->

## Local TODOs

- [ ] Search web for official mihomo systemd unit examples
- [ ] Search web for official sing-box systemd unit examples
- [ ] Find actual .deb download links for mihomo (latest stable)
- [ ] Find actual .deb download links for sing-box (latest stable)
- [ ] Document soft-reload and cache-persistence behavior for both
- [ ] Record findings in task Execution Log

## Acceptance Criteria

- [ ] Mihomo systemd unit example collected with source link
- [ ] Sing-box systemd unit example collected with source link
- [ ] Mihomo .deb download link recorded
- [ ] Sing-box .deb download link recorded
- [ ] Soft-reload and cache-persistence behavior documented
- [ ] Per-user installation steps documented

## Verification Evidence

- **Test command:** rtk test python3 -m py_compile proxy_converter.py
- **Expected result:** n/a (discovery task, no code change)
- **Actual result:** _(The Hands fill this during execution)_
- **Exit code:** _(The Hands fill this during execution)_

> Verification runner rule: discovery tasks do not require code verification; record any commands run.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [ ] Research findings recorded in Execution Log
- [ ] `lint_task_file` passes on the active task file
- [ ] Source links cited for all collected facts

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence` — do NOT defer box-checking to a closure task. See `<hands_protocols>` for the authoritative instruction.

## Risk & Rollback

- **Risk:** Deb links may change between versions; document version + date.
- **Rollback plan:** N/A (discovery only, no code changes).

---

> **Superseded:** This task was bundled into META task `30-systemd-units-research-and-creation` and archived on 2026-11-25 16:14 UTC. See `tasks/backlog/30-systemd-units-research-and-creation.md` (or its Kanban successor) for the unified execution. History preserved via `git log --follow -- tasks/archive/28-research-mihomo-singbox-systemd-deb.md`.

## Execution Log & Reasoning

_(The Hands: Manually log your research findings, sources, and notes here)_

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->

_(Discovery task: no code changes, no diff injected)_

<!-- END_GIT_DIFF -->
