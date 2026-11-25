# Systemd User Units Setup (Mihomo + Config Generator)

This document is the single source of truth for installing and running the
per-user systemd units that (1) regenerate both sing-box and mihomo configs
every 6 hours with LAN listen and TUN disabled, and (2) run mihomo from the
generated config with a local-only dashboard.

## Prerequisites

- Python 3.8+ with `pip install -r requirements.txt` (or use `.venv`).
- mihomo installed globally (e.g. `/usr/bin/mihomo`). Verify with `command -v mihomo`.
- sing-box optional (config is generated; run separately if desired).
- systemd user instance available (`systemctl --user` works).

## Paths

| Purpose | Path |
|---|---|
| Repo | `$HOME/v2ray-to-subs` |
| Mihomo config dir | `~/.config/mihomo` |
| Clash output | `~/.config/mihomo/clash_config.yaml` |
| Sing-box output | `~/.config/mihomo/singbox_config.json` |
| Mihomo binary | `/usr/bin/mihomo` (resolved via `which mihomo`) |
| Unit files (repo) | `systemd/user/proxy-gen.service`, `proxy-gen.timer`, `mihomo.service` |
| Unit files (runtime) | `~/.config/systemd/user/` |

## Install (per-user, no root)

1. Create the mihomo config directory:
   ```bash
   mkdir -p ~/.config/mihomo
   ```
2. Copy the three unit files into the user systemd directory:
   ```bash
   mkdir -p ~/.config/systemd/user
   cp $HOME/v2ray-to-subs/systemd/user/proxy-gen.service ~/.config/systemd/user/
   cp $HOME/v2ray-to-subs/systemd/user/proxy-gen.timer ~/.config/systemd/user/
   cp $HOME/v2ray-to-subs/systemd/user/mihomo.service ~/.config/systemd/user/
   ```
3. Reload the user daemon:
   ```bash
   systemctl --user daemon-reload
   ```
4. Enable and start the timer and mihomo service:
   ```bash
   systemctl --user enable --now proxy-gen.timer
   systemctl --user enable --now mihomo.service
   ```
5. (Optional) Enable lingering so timers survive logout:
   ```bash
   loginctl enable-linger $USER
   ```
   Verify with `loginctl show-user $USER --property=Linger`.

## Verify

```bash
# Compile check
python3 -m py_compile $HOME/v2ray-to-subs/proxy_converter.py

# CLI flag present
python3 $HOME/v2ray-to-subs/proxy_converter.py --help | grep no-allow-lan

# Dry generation (LAN off, TUN off)
python3 $HOME/v2ray-to-subs/proxy_converter.py --controller-secret 123456789 \
  --clash-out /tmp/proxy-gen-test-clash.yaml

# Unit validation
systemd-analyze verify ~/.config/systemd/user/proxy-gen.service ~/.config/systemd/user/proxy-gen.timer ~/.config/systemd/user/mihomo.service

# Timer cadence
systemctl --user list-timers proxy-gen.timer

# Confirm no system-wide install
test ! -e /etc/systemd/system/proxy-gen.service && test ! -e /etc/systemd/system/mihomo.service && echo "no system units"
```

## Operations

- **Timer status:** `systemctl --user status proxy-gen.timer`
- **Service status:** `systemctl --user status proxy-gen.service` and `systemctl --user status mihomo.service`
- **Manual regeneration:** `systemctl --user start proxy-gen.service`
- **Logs:** `journalctl --user -u proxy-gen.service -f` and `journalctl --user -u mihomo.service -f`
- **Soft reload (no restart):** `systemctl --user reload mihomo.service` (sends SIGHUP)
- **Dashboard:** http://127.0.0.1:9090/ui (secret `123456789`)

## Behavior notes

- TUN is off by default (no `--tun` flag passed). Enable only with explicit `--tun`.
- LAN listen is enabled (default `--allow-lan`), so `bind-address` is `*` and the mixed port (8118) serves LAN clients.
- Last selected proxy group/node is persisted via `profile.store-selected` (mihomo) and `cache_file` (sing-box), surviving restarts.
- Auto-reload after each generation is tolerant: if mihomo is inactive, the reload is ignored (no failure).
- Zashboard dashboard is downloaded by mihomo on first start into `~/.config/mihomo/ui`.

## Troubleshooting

- **Timer stops after logout:** enable lingering with `loginctl enable-linger $USER`.
- **Binary path drift:** re-run `command -v mihomo` and update `ExecStart` in `mihomo.service`, then `daemon-reload`.
- **Secret visibility:** the secret appears in the generation command line briefly; acceptable for local dev scope.
- **Large feeds:** 9 country groups x N nodes expands config size; monitor client memory.

## Rollback

```bash
systemctl --user disable --now proxy-gen.timer mihomo.service
rm -f ~/.config/systemd/user/proxy-gen.service ~/.config/systemd/user/proxy-gen.timer ~/.config/systemd/user/mihomo.service
systemctl --user daemon-reload
# Optional: remove the CLI flag from proxy_converter.py if no longer needed
```

## Deb download links (reference)

- Mihomo v1.19.34 (latest stable, no official .deb — .gz only):
  https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-linux-amd64-v3-go124-v1.19.34.gz
- Sing-box v1.14.4 (official .deb):
  https://github.com/SagerNet/sing-box/releases/download/v1.14.4/SFL-1.14.4-amd64.deb
- Sing-box install script (deb/rpm/arch):
  https://github.com/SagerNet/sing-box/blob/testing/docs/installation/tools/install.sh
