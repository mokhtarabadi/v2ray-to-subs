# Fresh-host install runbook

How to bring up the live proxy stack on a new host from this repo.
Runtime state lives outside git (`~/.config/mihomo-subs/`, `~/.config/systemd/user/`);
the repo holds only the generator, scripts, and unit definitions.

## 0. Prerequisites

- Python 3.8+ with `pip install -r requirements.txt` (or `.venv/bin/python`)
- A `mihomo` binary reachable as `mihomo` on `PATH` or at `~/mihomo/mihomo`
  (`refresh.sh` resolves both; it fails closed if neither exists)
- `systemd --user` with linger enabled (`loginctl show-user $USER -p Linger`)

## 1. Controller secret

```bash
mkdir -p ~/.config/mihomo-subs
openssl rand -hex 32 > ~/.config/mihomo-subs/.controller_secret
chmod 600 ~/.config/mihomo-subs/.controller_secret
```

The balancer reads the same file, so API auth works on both sides.

## 2. Install the units

```bash
mkdir -p ~/.config/systemd/user
ln -sf ~/v2ray-to-subs/systemd/v2ray-to-subs.timer \
       ~/v2ray-to-subs/systemd/v2ray-to-subs-maintain.service \
       ~/.config/systemd/user/
```

Create `~/.config/systemd/user/mihomo-subs.service`:

```ini
[Unit]
Description=mihomo subscription proxy (generated config)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/mohammad/.config/mihomo-subs
ExecStart=/home/mohammad/mihomo/mihomo -f /home/mohammad/.config/mihomo-subs/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Then reload and enable:

```bash
systemctl --user daemon-reload
systemctl --user enable --now v2ray-to-subs.timer mihomo-subs.service
```

What you get: `mihomo-subs.service` serves the live config (mixed port
7890, allow-lan, dashboard on `127.0.0.1:9090`), and
`v2ray-to-subs.timer` fires `maintain.sh` every 30 minutes
(retest 500 → country batch 20 → refresh only when the live config is
older than 6h).

## 3. Seed the first live config

```bash
touch ~/.config/mihomo-subs/config.yaml
chmod 600 ~/.config/mihomo-subs/config.yaml
./refresh.sh "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt"
```

This generates, validates with `mihomo -t`, backs up, installs, and
(starts the service). To change provider later, run the same command
with a new URL and update `SUB_URLS` in `scripts/maintain.sh` so
scheduled refreshes follow it.

## 4. Verify

```bash
systemctl --user is-active mihomo-subs.service v2ray-to-subs.timer
curl -s -o /dev/null -w "dashboard HTTP %{http_code}\n" http://127.0.0.1:9090/ui/
https_proxy=http://127.0.0.1:7890 curl -s https://www.cloudflare.com/cdn-cgi/trace | grep ^loc=
https_proxy=http://127.0.0.1:7890 curl -s -D - -o /dev/null https://www.google.com/search?q=test | grep -iE "^HTTP/2|location"
```

Expect: both units active, dashboard 200, `loc=US`, Google 200 with no
`/sorry` redirect. If the exit is not US-clean, rotate explicitly:

```bash
.venv/bin/python scripts/rr_balancer.py retest --batch 500
.venv/bin/python scripts/rr_balancer.py country --batch 20
.venv/bin/python scripts/rr_balancer.py rotate --require-country US
```

## 5. Notes

- Feeds are pinned in `scripts/maintain.sh` (`SUB_URLS`); the converter
  default is only a fallback.
- Rollback: live backups in `~/.config/mihomo-subs/config.yaml.refresh-*.bak`
  (last 5 kept); `git checkout` the generator; `systemctl --user disable --now`
  the timer to stop scheduled refreshes.
- Generated outputs (`clash_config.yaml`, `singbox_config.json`) are
  git-ignored build artifacts — never hand-edit, regenerate instead.
- Only the mixed port (7890) binds all interfaces; controller, DNS, and
  sing-box inbound stay on loopback. Keep the perimeter closed except SSH.
