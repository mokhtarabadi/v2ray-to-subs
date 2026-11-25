# systemd (user units)

Owned files for per-user systemd units:

- `proxy-gen.service` — oneshot config generator (LAN off, TUN off, secret baked).
- `proxy-gen.timer` — fires every 6 hours (OnBootSec 10min, OnUnitActiveSec 6h, Persistent).
- `mihomo.service` — per-user mihomo runtime (local dashboard, HUP reload, stable cache).

## Invariants

- All units are per-user (`~/.config/systemd/user/`); never system-wide (`/etc/systemd/system/`).
- Mihomo binds loopback only (127.0.0.1:9090) with secret `123456789`.
- Config generation enables LAN listen (default `--allow-lan`) and TUN stays off (omit `--tun`).
- Last selected group/node persists across restarts via `store-selected` + `cache.db`.
- Auto-reload after generation is tolerant (ignored if mihomo inactive).
- Mihomo binary path resolved globally via `which mihomo` (currently `/usr/bin/mihomo`).

See `docs/systemd-setup.md` for full install/verify/rollback steps.
