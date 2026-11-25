# Architectural Decisions: systemd

## 2026-11-25 ADR-001: Per-user units with global mihomo binary

- **Context:** User needs unattended config regeneration (every 6h) and a mihomo runtime with a local dashboard, without root/system-wide install. Mihomo is already installed globally.
- **Decision:** Use per-user systemd units under `~/.config/systemd/user/`. Mihomo binary path resolved via `which mihomo` (/usr/bin/mihomo). Config dir `~/.config/mihomo` holds yaml + ui + cache.db for stable selection persistence.
- **Consequences:** Timers require lingering for post-logout runs; units are user-scoped; secret appears in generation process line briefly (local dev scope).
- **Rollback:** Remove three unit files from `~/.config/systemd/user/`, `daemon-reload`; remove `--no-allow-lan` flag if no longer needed.

## 2026-11-25 ADR-002: Tolerant auto-reload after generation

- **Context:** Regeneration should refresh mihomo without a full restart, but mihomo may be inactive during generation.
- **Decision:** Use `ExecStartPost=-/usr/bin/systemctl --user reload mihomo.service` (dash prefix makes failure non-fatal). Soft reload via SIGHUP (ExecReload) for manual use.
- **Consequences:** No restart storm; inactive mihomo is skipped; group/node selection persists via cache.
- **Rollback:** Remove ExecStartPost line; reload becomes manual only.

## 2026-11-25 ADR-003: Additive --no-allow-lan CLI flag

- **Context:** Config generation must disable LAN listen, but `--allow-lan` defaults True with store_true (no way to disable via CLI).
- **Decision:** Add `--no-allow-lan` (store_false, dest=allow_lan) sharing the same destination. Default stays True for backward compatibility.
- **Consequences:** Zero behavior change for existing callers; new flag enables loopback-only bind.
- **Rollback:** Remove the new add_argument block.
