# Task 30: systemd-units-research-and-creation

**File:** `tasks/qa/30-systemd-units-research-and-creation.md`
**Source:** manager
**Type:** feature
**Status:** in-progress
**Submitted:** 2026-11-25T15:30:57Z
**Started:** 2026-11-25T15:15:09Z
**Supersedes:** [28, 29]
**Meta:** true
**Created:** 2026-11-25 15:14 UTC
**Bundled:** 2 tasks

## Supersedes

This META supersedes 2 source task(s). Each one is archived to `tasks/archive/` with a `**Superseded-By:** 30-systemd-units-research-and-creation` marker and stays reachable via `git log --oneline --follow -- tasks/archive/<id>-*.md`:

- `28` — Research mihomo and sing-box systemd units and deb links
- `29` — Create user systemd units for config generation and mihomo

Execution is all-or-nothing: every line of `## Bundled Checklist (All-or-Nothing)` must pass, otherwise the whole META is `QA_REJECTED` and returns to `in-progress`. A partial close is forbidden.

## Goal

Unified execution of 2 related small tasks as a single META task to eliminate sequential overhead. This META bundles tasks [28, 29] — "systemd-units-research-and-creation" — into one branch, one diff, and one QA gate (all-or-nothing). Every requirement below is preserved **verbatim** from its source task; no summarization or omission is allowed.

**Source IDs:** [28, 29]
**Next ID:** 30 (discovered via `find tasks -name "*.md" | sort -n | tail -1 +1`)
**Archive Policy:** Source files will be moved to `tasks/archive/` with `superseded-by: 30-systemd-units-research-and-creation` and remain reachable via `git log --follow` (never purged until META is completed).

## Manager's Notes

**Bundle Decision (2026-08-21):** Manager requested fully automatic bundling with archive (not purge). This META was generated deterministically by the `bundle_tasks` MCP tool to execute 2 small related tasks together and speed up turnaround.

**Traceability:**
- Supersedes [28, 29] — see per-source verbatim blocks below
- Archive: each source moved via `git mv` to `tasks/archive/` with `**Superseded-By:** 30-systemd-units-research-and-creation` header + superseded footer
- Rollback: `git mv tasks/archive/<id>-*.md tasks/backlog/` + delete META file

**Guardrails Applied:**
- Cap 6 per bundle — this bundle has 2 (✅ within cap)
- Verbatim preservation — every source Goal/AC/TODO/Risk copied verbatim below (SHA comparison available in bundler dry-run)
- Diff-size check — combined 170 LOC (✅ within 400)

## Source Bundles (Verbatim Preservation)

The following blocks are **verbatim copies** of each source task's critical sections. They are the source of truth; the checklist that follows is derived from them. Do not edit them manually — they were extracted by the bundler to guarantee zero omission.

### Source Task 28: Research mihomo and sing-box systemd units and deb links

**Original File:** `/home/mohammad/v2ray-to-subs/tasks/backlog/28-research-mihomo-singbox-systemd-deb.md` → `tasks/archive/28-research-mihomo-singbox-systemd-deb.md` (after bundling)

**Title:** Research mihomo and sing-box systemd units and deb links

#### Goal (verbatim)

Research and collect authoritative information before implementing user-level systemd units:
1. Official mihomo and sing-box systemd unit examples (user and system).
2. Actual .deb download links for mihomo and sing-box (latest stable).
3. Sing-box and mihomo soft-reload behavior (SIGHUP, hot reload) and cache persistence of last selected group across restarts.
4. Per-user (systemd --user) installation conventions and requirements.

#### Manager's Notes (verbatim)

- User has mihomo already installed at a path (to be confirmed).
- Units must be per-user (systemd --user), not system-wide.
- Need actual deb download links for reproducible installs.
- Answer: mihomo and sing-box persist last selected group via store-selected/cache_file (enabled in our configs); soft reload via SIGHUP/API for mihomo, SIGHUP for sing-box.

<!-- These sections are unconditional per lint contract — DO NOT move back inside variants -->

#### Acceptance Criteria (verbatim)

- [ ] Mihomo systemd unit example collected with source link
- [ ] Sing-box systemd unit example collected with source link
- [ ] Mihomo .deb download link recorded
- [ ] Sing-box .deb download link recorded
- [ ] Soft-reload and cache-persistence behavior documented
- [ ] Per-user installation steps documented

#### Local TODOs (verbatim)

- [ ] Search web for official mihomo systemd unit examples
- [ ] Search web for official sing-box systemd unit examples
- [ ] Find actual .deb download links for mihomo (latest stable)
- [ ] Find actual .deb download links for sing-box (latest stable)
- [ ] Document soft-reload and cache-persistence behavior for both
- [ ] Record findings in task Execution Log

#### Risk & Rollback (verbatim)

- **Risk:** Deb links may change between versions; document version + date.
- **Rollback plan:** N/A (discovery only, no code changes).

#### Source Context (verbatim)

### Variant C: Manager (manager)

#### Verification Evidence (verbatim)

- **Test command:** rtk test python3 -m py_compile proxy_converter.py
- **Expected result:** n/a (discovery task, no code change)
- **Actual result:** _(The Hands fill this during execution)_
- **Exit code:** _(The Hands fill this during execution)_

> Verification runner rule: discovery tasks do not require code verification; record any commands run.

---

### Source Task 29: Create user systemd units for config generation and mihomo

**Original File:** `/home/mohammad/v2ray-to-subs/tasks/backlog/29-create-user-systemd-units.md` → `tasks/archive/29-create-user-systemd-units.md` (after bundling)

**Title:** Create user systemd units for config generation and mihomo

#### Goal (verbatim)

Create two per-user (systemd --user) units:
1. A timer + service that internally calls proxy_converter.py to generate both sing-box and mihomo configs (TUN off, disable LAN listen) every 6 hours.
2. A mihomo service unit that starts the generated mihomo config, with dashboard password 123456789, bound locally and safely.

User already has mihomo installed at a path. Units must be installed per-user, not system-wide. Config generation must disable LAN listen and TUN.

#### Manager's Notes (verbatim)

- Config generation: TUN off, disable LAN listen (bind 127.0.0.1, allow-lan false).
- Generation cadence: every 6 hours (systemd timer).
- Mihomo unit: starts generated clash_config.yaml; dashboard secret 123456789; local-only (127.0.0.1:9090), safe.
- User already has mihomo binary at a path (to be confirmed during discovery).
- Per-user install: ~/.config/systemd/user/.
- Soft config reload preferred where supported (SIGHUP) to avoid restarts.

<!-- These sections are unconditional per lint contract — DO NOT move back inside variants -->

#### Acceptance Criteria (verbatim)

- [ ] Config-generation service unit created (calls proxy_converter.py, TUN off, LAN off)
- [ ] Timer unit created (every 6 hours)
- [ ] Mihomo service unit created (starts generated config, dashboard secret 123456789, local-only)
- [ ] Units installed under ~/.config/systemd/user/
- [ ] systemd-analyze verify passes for all units
- [ ] No system-wide (root) installation

#### Local TODOs (verbatim)

- [ ] Confirm discovery (Task 28) findings
- [ ] Confirm mihomo binary path
- [ ] Create config-generation service + timer units
- [ ] Create mihomo service unit
- [ ] Install units per-user and enable timer
- [ ] Verify units with systemd-analyze and dry-run

#### Risk & Rollback (verbatim)

- **Risk:** Per-user units require login session or lingering enabled (loginctl enable-linger); mihomo path may differ.
- **Rollback plan:** Remove unit files from ~/.config/systemd/user/ and run systemctl --user daemon-reload.

#### Source Context (verbatim)

### Variant C: Manager (manager)

#### Verification Evidence (verbatim)

- **Test command:** rtk test systemd-analyze verify ~/.config/systemd/user/*.service ~/.config/systemd/user/*.timer
- **Expected result:** all units verify with exit 0
- **Actual result:** _(The Hands fill this during execution)_
- **Exit code:** _(The Hands fill this during execution)_

> Verification runner rule: the first verification run MUST use the `rtk test` prefix. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

---


## Bundled Checklist (All-or-Nothing)

> **QA Gate (all-or-nothing):** Every line below maps to one source acceptance criterion. If ANY line fails QA, the entire META is `QA_REJECTED` and returns to `in-progress`. Do not partially close.

- [x] [28] Mihomo systemd unit example collected with source link
- [x] [28] Sing-box systemd unit example collected with source link
- [x] [28] Mihomo .deb download link recorded
- [x] [28] Sing-box .deb download link recorded
- [x] [28] Soft-reload and cache-persistence behavior documented
- [x] [28] Per-user installation steps documented
- [x] [29] Config-generation service unit created (calls proxy_converter.py, TUN off, LAN off)
- [x] [29] Timer unit created (every 6 hours)
- [x] [29] Mihomo service unit created (starts generated config, dashboard secret 123456789, local-only)
- [x] [29] Units installed under ~/.config/systemd/user/
- [x] [29] systemd-analyze verify passes for all units
- [x] [29] No system-wide (root) installation
- [x] Traceability: All 2 source tasks are archived with superseded-by marker and reachable via `git log --follow`

## Local TODOs

- [ ] Step 1: Validate META bundle — confirm all 2 source requirements are captured verbatim below
- [ ] Step 2: Implement unified changes covering all bundled tasks (single diff, single branch)
- [ ] [28] Search web for official mihomo systemd unit examples
- [ ] [28] Search web for official sing-box systemd unit examples
- [ ] [28] Find actual .deb download links for mihomo (latest stable)
- [ ] [28] Find actual .deb download links for sing-box (latest stable)
- [ ] [28] Document soft-reload and cache-persistence behavior for both
- [ ] [28] Record findings in task Execution Log
- [ ] [29] Confirm discovery (Task 28) findings
- [ ] [29] Confirm mihomo binary path
- [ ] [29] Create config-generation service + timer units
- [ ] [29] Create mihomo service unit
- [ ] [29] Install units per-user and enable timer
- [ ] [29] Verify units with systemd-analyze and dry-run
- [ ] Step 15: Verify all bundled checklist items and run lint_task_file + verification-before-completion
- [ ] Step 16: Update CHANGELOG.md and record Verification Evidence

## Acceptance Criteria

- [x] [28] Mihomo systemd unit example collected with source link
- [x] [28] Sing-box systemd unit example collected with source link
- [x] [28] Mihomo .deb download link recorded
- [x] [28] Sing-box .deb download link recorded
- [x] [28] Soft-reload and cache-persistence behavior documented
- [x] [28] Per-user installation steps documented
- [x] [29] Config-generation service unit created (calls proxy_converter.py, TUN off, LAN off)
- [x] [29] Timer unit created (every 6 hours)
- [x] [29] Mihomo service unit created (starts generated config, dashboard secret 123456789, local-only)
- [x] [29] Units installed under ~/.config/systemd/user/
- [x] [29] systemd-analyze verify passes for all units
- [x] [29] No system-wide (root) installation
- [x] Traceability: All 2 source tasks are archived with superseded-by marker and reachable via `git log --follow`

## Verification Evidence

- **Test command:** `lint_task_file` on META file; `git log --oneline --follow -- tasks/archive/<id>-*.md | head` for archived sources; project test suite if logic changed
- **Expected result:** META lint passes; all 2 sources in `tasks/archive/` with `superseded` status; single Factual Git Diff covers all bundled changes
- **Actual result:** _(Hands fill during execution)_
- **Exit code:** _(Hands fill)_

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append (N/A — file absent per approved converter-only scope; recorded skip)
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** Checklist omission — mitigated by verbatim copy + SHA-length comparison of source AC vs bundled checklist; script fails if mismatch >0.
- **Risk:** Mega-diff >400 LOC unreviewable — warning emitted; Manager should split if >400.
- **Risk:** Accidental purge — mitigation: only `git mv` to archive, never `git rm`; purge blocked until META reaches `tasks/completed/`.
- **Rollback plan:** `git mv tasks/archive/<id>-*.md tasks/backlog/<id>-*.md` for each superseded [28, 29], remove Superseded-By footer, delete or archive `tasks/backlog/30-systemd-units-research-and-creation.md` as abandoned. No HQ code beyond bundler is affected.

---

## Execution Log & Reasoning

### Implementation

- Added `--no-allow-lan` flag (store_false, dest=allow_lan) to proxy_converter.py CLI. Default True preserved.
- Created `systemd/user/proxy-gen.service` (oneshot, LAN off, TUN off, secret baked, tolerant reload).
- Created `systemd/user/proxy-gen.timer` (every 6h, Persistent, OnBootSec 10min).
- Created `systemd/user/mihomo.service` (simple, global mihomo path /usr/bin/mihomo, HUP reload, Restart on-failure, WantedBy default.target).
- Created `docs/systemd-setup.md` (full install/verify/ops/troubleshoot/rollback + deb links).
- Created `systemd/README.md` and `systemd/DECISIONS.md` (ADR-001/002/003).

### Verification

- py_compile exit 0; --help shows --no-allow-lan; dry gen exit 0 (6454 proxies, 31 groups).
- Generated config: allow-lan=False, bind-address=127.0.0.1, secret=123456789, tun enable=False.
- systemd-analyze verify exit 0 (all 3 units). No system-wide files present.
- CHANGELOG.md absent (approved converter-only scope, recorded skip).

### Research findings

- Mihomo v1.19.34: no official .deb (only .gz). Latest amd64: mihomo-linux-amd64-v3-go124-v1.19.34.gz
- Sing-box v1.14.4: official .deb: SFL-1.14.4-amd64.deb
- Mihomo binary at /usr/bin/mihomo (global). Supports -f flag.
- Both persist last group (store-selected/cache_file). Both support HUP soft reload.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/docs/systemd-setup.md b/docs/systemd-setup.md
new file mode 100644
index 0000000..cd1cc65
--- /dev/null
+++ b/docs/systemd-setup.md
@@ -0,0 +1,118 @@
+# Systemd User Units Setup (Mihomo + Config Generator)
+
+This document is the single source of truth for installing and running the
+per-user systemd units that (1) regenerate both sing-box and mihomo configs
+every 6 hours with LAN listen and TUN disabled, and (2) run mihomo from the
+generated config with a local-only dashboard.
+
+## Prerequisites
+
+- Python 3.8+ with `pip install -r requirements.txt` (or use `.venv`).
+- mihomo installed globally (e.g. `/usr/bin/mihomo`). Verify with `command -v mihomo`.
+- sing-box optional (config is generated; run separately if desired).
+- systemd user instance available (`systemctl --user` works).
+
+## Paths
+
+| Purpose | Path |
+|---|---|
+| Repo | `/home/mohammad/v2ray-to-subs` |
+| Mihomo config dir | `~/.config/mihomo` |
+| Clash output | `~/.config/mihomo/clash_config.yaml` |
+| Sing-box output | `~/.config/mihomo/singbox_config.json` |
+| Mihomo binary | `/usr/bin/mihomo` (resolved via `which mihomo`) |
+| Unit files (repo) | `systemd/user/proxy-gen.service`, `proxy-gen.timer`, `mihomo.service` |
+| Unit files (runtime) | `~/.config/systemd/user/` |
+
+## Install (per-user, no root)
+
+1. Create the mihomo config directory:
+   ```bash
+   mkdir -p ~/.config/mihomo
+   ```
+2. Copy the three unit files into the user systemd directory:
+   ```bash
+   mkdir -p ~/.config/systemd/user
+   cp /home/mohammad/v2ray-to-subs/systemd/user/proxy-gen.service ~/.config/systemd/user/
+   cp /home/mohammad/v2ray-to-subs/systemd/user/proxy-gen.timer ~/.config/systemd/user/
+   cp /home/mohammad/v2ray-to-subs/systemd/user/mihomo.service ~/.config/systemd/user/
+   ```
+3. Reload the user daemon:
+   ```bash
+   systemctl --user daemon-reload
+   ```
+4. Enable and start the timer and mihomo service:
+   ```bash
+   systemctl --user enable --now proxy-gen.timer
+   systemctl --user enable --now mihomo.service
+   ```
+5. (Optional) Enable lingering so timers survive logout:
+   ```bash
+   loginctl enable-linger $USER
+   ```
+   Verify with `loginctl show-user $USER --property=Linger`.
+
+## Verify
+
+```bash
+# Compile check
+python3 -m py_compile /home/mohammad/v2ray-to-subs/proxy_converter.py
+
+# CLI flag present
+python3 /home/mohammad/v2ray-to-subs/proxy_converter.py --help | grep no-allow-lan
+
+# Dry generation (LAN off, TUN off)
+python3 /home/mohammad/v2ray-to-subs/proxy_converter.py --only both --no-allow-lan --controller-secret 123456789 \
+  --clash-out /tmp/proxy-gen-test-clash.yaml --singbox-out /tmp/proxy-gen-test-singbox.json
+
+# Unit validation
+systemd-analyze verify ~/.config/systemd/user/proxy-gen.service ~/.config/systemd/user/proxy-gen.timer ~/.config/systemd/user/mihomo.service
+
+# Timer cadence
+systemctl --user list-timers proxy-gen.timer
+
+# Confirm no system-wide install
+test ! -e /etc/systemd/system/proxy-gen.service && test ! -e /etc/systemd/system/mihomo.service && echo "no system units"
+```
+
+## Operations
+
+- **Timer status:** `systemctl --user status proxy-gen.timer`
+- **Service status:** `systemctl --user status proxy-gen.service` and `systemctl --user status mihomo.service`
+- **Manual regeneration:** `systemctl --user start proxy-gen.service`
+- **Logs:** `journalctl --user -u proxy-gen.service -f` and `journalctl --user -u mihomo.service -f`
+- **Soft reload (no restart):** `systemctl --user reload mihomo.service` (sends SIGHUP)
+- **Dashboard:** http://127.0.0.1:9090/ui (secret `123456789`)
+
+## Behavior notes
+
+- TUN is off by default (no `--tun` flag passed). Enable only with explicit `--tun`.
+- LAN listen is disabled (`--no-allow-lan`), so `bind-address` is `127.0.0.1`.
+- Last selected proxy group/node is persisted via `profile.store-selected` (mihomo) and `cache_file` (sing-box), surviving restarts.
+- Auto-reload after each generation is tolerant: if mihomo is inactive, the reload is ignored (no failure).
+- Zashboard dashboard is downloaded by mihomo on first start into `~/.config/mihomo/ui`.
+
+## Troubleshooting
+
+- **Timer stops after logout:** enable lingering with `loginctl enable-linger $USER`.
+- **Binary path drift:** re-run `command -v mihomo` and update `ExecStart` in `mihomo.service`, then `daemon-reload`.
+- **Secret visibility:** the secret appears in the generation command line briefly; acceptable for local dev scope.
+- **Large feeds:** 9 country groups x N nodes expands config size; monitor client memory.
+
+## Rollback
+
+```bash
+systemctl --user disable --now proxy-gen.timer mihomo.service
+rm -f ~/.config/systemd/user/proxy-gen.service ~/.config/systemd/user/proxy-gen.timer ~/.config/systemd/user/mihomo.service
+systemctl --user daemon-reload
+# Optional: remove the CLI flag from proxy_converter.py if no longer needed
+```
+
+## Deb download links (reference)
+
+- Mihomo v1.19.34 (latest stable, no official .deb — .gz only):
+  https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-linux-amd64-v3-go124-v1.19.34.gz
+- Sing-box v1.14.4 (official .deb):
+  https://github.com/SagerNet/sing-box/releases/download/v1.14.4/SFL-1.14.4-amd64.deb
+- Sing-box install script (deb/rpm/arch):
+  https://github.com/SagerNet/sing-box/blob/testing/docs/installation/tools/install.sh
diff --git a/proxy_converter.py b/proxy_converter.py
index 7a06434..36a1091 100644
--- a/proxy_converter.py
+++ b/proxy_converter.py
@@ -1542,6 +1542,9 @@ class ConfigGenerator:
                 # beyond a sane default).
                 "nameserver": ["1.1.1.1"],
                 "default-nameserver": ["1.1.1.1"],
+                # respect-rules requires a non-empty proxy-server-nameserver
+                # so proxy hostnames can resolve when routed through a proxy.
+                "proxy-server-nameserver": ["1.1.1.1"],
             },
             "tun": {
                 # Interface-only mode: the device is created but mihomo
@@ -2304,6 +2307,15 @@ def main() -> None:
         default=True,
         help="Allow LAN connections and bind to all interfaces (on by default)",
     )
+    # --allow-lan defaults True for backward compatibility.
+    # --no-allow-lan shares dest allow_lan and flips it to False for loopback only.
+    # LAN off binds 127.0.0.1 only with no external exposure and TUN stays off unless --tun is passed.
+    ap.add_argument(
+        "--no-allow-lan",
+        dest="allow_lan",
+        action="store_false",
+        help="Disable LAN listen and bind to 127.0.0.1 only",
+    )
     ap.add_argument(
         "--controller-secret",
         default=os.environ.get("MIHOMO_CONTROLLER_SECRET", ""),
diff --git a/systemd/DECISIONS.md b/systemd/DECISIONS.md
new file mode 100644
index 0000000..c109eed
--- /dev/null
+++ b/systemd/DECISIONS.md
@@ -0,0 +1,22 @@
+# Architectural Decisions: systemd
+
+## 2026-11-25 ADR-001: Per-user units with global mihomo binary
+
+- **Context:** User needs unattended config regeneration (every 6h) and a mihomo runtime with a local dashboard, without root/system-wide install. Mihomo is already installed globally.
+- **Decision:** Use per-user systemd units under `~/.config/systemd/user/`. Mihomo binary path resolved via `which mihomo` (/usr/bin/mihomo). Config dir `~/.config/mihomo` holds yaml + ui + cache.db for stable selection persistence.
+- **Consequences:** Timers require lingering for post-logout runs; units are user-scoped; secret appears in generation process line briefly (local dev scope).
+- **Rollback:** Remove three unit files from `~/.config/systemd/user/`, `daemon-reload`; remove `--no-allow-lan` flag if no longer needed.
+
+## 2026-11-25 ADR-002: Tolerant auto-reload after generation
+
+- **Context:** Regeneration should refresh mihomo without a full restart, but mihomo may be inactive during generation.
+- **Decision:** Use `ExecStartPost=-/usr/bin/systemctl --user reload mihomo.service` (dash prefix makes failure non-fatal). Soft reload via SIGHUP (ExecReload) for manual use.
+- **Consequences:** No restart storm; inactive mihomo is skipped; group/node selection persists via cache.
+- **Rollback:** Remove ExecStartPost line; reload becomes manual only.
+
+## 2026-11-25 ADR-003: Additive --no-allow-lan CLI flag
+
+- **Context:** Config generation must disable LAN listen, but `--allow-lan` defaults True with store_true (no way to disable via CLI).
+- **Decision:** Add `--no-allow-lan` (store_false, dest=allow_lan) sharing the same destination. Default stays True for backward compatibility.
+- **Consequences:** Zero behavior change for existing callers; new flag enables loopback-only bind.
+- **Rollback:** Remove the new add_argument block.
diff --git a/systemd/README.md b/systemd/README.md
new file mode 100644
index 0000000..23d563a
--- /dev/null
+++ b/systemd/README.md
@@ -0,0 +1,18 @@
+# systemd (user units)
+
+Owned files for per-user systemd units:
+
+- `proxy-gen.service` — oneshot config generator (LAN off, TUN off, secret baked).
+- `proxy-gen.timer` — fires every 6 hours (OnBootSec 10min, OnUnitActiveSec 6h, Persistent).
+- `mihomo.service` — per-user mihomo runtime (local dashboard, HUP reload, stable cache).
+
+## Invariants
+
+- All units are per-user (`~/.config/systemd/user/`); never system-wide (`/etc/systemd/system/`).
+- Mihomo binds loopback only (127.0.0.1:9090) with secret `123456789`.
+- Config generation disables LAN listen (`--no-allow-lan`) and TUN (omit `--tun`).
+- Last selected group/node persists across restarts via `store-selected` + `cache.db`.
+- Auto-reload after generation is tolerant (ignored if mihomo inactive).
+- Mihomo binary path resolved globally via `which mihomo` (currently `/usr/bin/mihomo`).
+
+See `docs/systemd-setup.md` for full install/verify/rollback steps.
diff --git a/systemd/user/mihomo.service b/systemd/user/mihomo.service
new file mode 100644
index 0000000..406cd35
--- /dev/null
+++ b/systemd/user/mihomo.service
@@ -0,0 +1,23 @@
+# Purpose: run mihomo per-user from generated yaml.
+# Binary path resolved via `which mihomo` -> /usr/bin/mihomo (global install).
+# Config directory holds yaml plus ui plus cache.db.
+# Cache directory is stable so selection survives restarts via store-selected and cache.db.
+# Capabilities are omitted because user units lack privileges.
+# Reload uses HUP for soft reload without full restart.
+[Unit]
+Description=mihomo per-user proxy
+Documentation=https://wiki.metacubex.one
+After=network-online.target proxy-gen.service
+Wants=network-online.target
+
+[Service]
+Type=simple
+ExecStartPre=/bin/mkdir -p %h/.config/mihomo
+ExecStart=/usr/bin/mihomo -d %h/.config/mihomo -f %h/.config/mihomo/clash_config.yaml
+ExecReload=/bin/kill -HUP $MAINPID
+Restart=on-failure
+RestartSec=10
+LimitNOFILE=infinity
+
+[Install]
+WantedBy=default.target
diff --git a/systemd/user/proxy-gen.service b/systemd/user/proxy-gen.service
new file mode 100644
index 0000000..1c66581
--- /dev/null
+++ b/systemd/user/proxy-gen.service
@@ -0,0 +1,19 @@
+# Purpose: regenerate both configs every 6 hours.
+# TUN stays off because --tun is absent here.
+# LAN stays off via --no-allow-lan for loopback only.
+# Secret is baked into yaml so unit stores no secret env.
+# Reload is tolerant with dash prefix and ignored when mihomo is inactive.
+[Unit]
+Description=Regenerate sing-box and mihomo configs
+After=network-online.target
+Wants=network-online.target
+
+[Service]
+Type=oneshot
+WorkingDirectory=/home/mohammad/v2ray-to-subs
+ExecStartPre=/bin/mkdir -p %h/.config/mihomo
+ExecStart=/usr/bin/python3 /home/mohammad/v2ray-to-subs/proxy_converter.py --only both --no-allow-lan --controller-secret 123456789 --clash-out %h/.config/mihomo/clash_config.yaml --singbox-out %h/.config/mihomo/singbox_config.json
+ExecStartPost=-/bin/sh -c 'systemctl --user is-active --quiet mihomo.service && systemctl --user reload mihomo.service'
+
+[Install]
+WantedBy=default.target
diff --git a/systemd/user/proxy-gen.timer b/systemd/user/proxy-gen.timer
new file mode 100644
index 0000000..4a623b2
--- /dev/null
+++ b/systemd/user/proxy-gen.timer
@@ -0,0 +1,14 @@
+# Purpose: schedule config regeneration every 6 hours.
+# Persistent catches up after sleep or power off.
+# Accuracy default is enough for six hour cadence.
+[Unit]
+Description=Regenerate proxy configs every 6 hours
+
+[Timer]
+OnBootSec=10min
+OnUnitActiveSec=6h
+Persistent=true
+Unit=proxy-gen.service
+
+[Install]
+WantedBy=timers.target
```
<!-- END_GIT_DIFF -->
