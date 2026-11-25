# V2Ray Subscription Parser — Clash (Mihomo) & SingBox Config Generator

A lightweight Python CLI that turns V2Ray subscription links into ready-to-run proxy configurations. It is a **V2Ray subscription parser**, **Clash Mihomo config generator**, and **SingBox config generator** in one standard-library tool. Feed it one or more subscription URLs and it downloads, decodes, deduplicates, and converts proxy share links into `clash_config.yaml` and `singbox_config.json`.

Supported protocols: **VMess, VLESS, Trojan, Shadowsocks, Hysteria / Hysteria2, TUIC**, and SOCKS. It handles V2RayN, DuckSoft, SS-Android, and base64-encoded subscription formats, plus transports TCP, WebSocket, HTTP, gRPC, and HTTPUpgrade with TLS, Reality, ECH, and uTLS fingerprinting.

## Why use this converter

- **Pure converter, no sidecar.** No balancer service, systemd timer, external checker, or dashboard plugin. It generates config files and exits.
- **Stable node names.** Proxies are named by an identity hash of protocol + host + port, so names stay constant when a feed reshuffles its remarks.
- **Safe YAML output.** Hex and opaque scalars such as REALITY `short-id` are double-quoted so Go-YAML does not misread them as floats.
- **TUN is off by default.** Loopback-only unless you opt in with `--tun`.

## Installation

Requires Python 3.8 or newer.

```bash
git clone <repository-url>
cd v2ray-to-subs
pip install -r requirements.txt
```

Dependencies: `requests`, `PyYAML`, `urllib3`, and optionally `cryptography`.

## Usage

```bash
# Default subscription (barry-far All_Configs_Sub) -> both config files
python3 proxy_converter.py

# One or more subscription URLs; fragment #Name becomes the profile title
python3 proxy_converter.py "https://example.com/sub#MyProfile"
python3 proxy_converter.py "https://a.example/sub" "https://b.example/sub"

# Choose output
python3 proxy_converter.py --only clash
python3 proxy_converter.py --only singbox -v

# Write to custom paths
python3 proxy_converter.py --clash-out out.yaml --singbox-out out.json

# System-wide routing (needs root / CAP_NET_ADMIN) and LAN access
python3 proxy_converter.py --tun --allow-lan

# Keep only the first proxy per server host
python3 proxy_converter.py --unique-host

# Protect the mihomo controller (flag or MIHOMO_CONTROLLER_SECRET env)
python3 proxy_converter.py --controller-secret "YOUR-SECRET"
```

### CLI options

| Option | Meaning |
| --- | --- |
| `urls` | Subscription URL(s); `#Name` fragment sets the profile title |
| `--clash-out PATH` | Clash output path (default `clash_config.yaml`) |
| `--singbox-out PATH` | SingBox output path (default `singbox_config.json`) |
| `--only {clash,singbox,both}` | Which config to generate (default `both`) |
| `--tun` | Enable TUN inbound; **off by default** |
| `--allow-lan` | Allow LAN clients and bind to all interfaces (on by default) |
| `--controller-secret SECRET` | mihomo controller secret, or set `MIHOMO_CONTROLLER_SECRET` |
| `-v`, `--verbose` | Verbose logging |
| `--unique-host` | Keep only the first proxy per server host |

Run `python3 proxy_converter.py --help` for the authoritative flag list.

## Generated configuration structure

### Clash / Mihomo (`clash_config.yaml`)

- Mixed HTTP/SOCKS proxy on port `8118`, Fake-IP DNS on `0.0.0.0:1053`.
- Optional TUN (`stack: mixed`, DNS hijack on `any:53`) enabled only with `--tun`.
- Proxy groups: **PROXY** (manual `select`), **Auto** (url-test), **Load Balance** (consistent hashing), and **Fallback** — PROXY contains `Auto`, `Load Balance`, `Fallback`, then the individual nodes.
- DNS resolvers are Cloudflare (`1.1.1.1`, `1.0.0.1`, `cloudflare-dns.com`); no Google resolvers.
- Rules: private/LAN ranges go `DIRECT`, everything else matches `PROXY`.

### SingBox (`singbox_config.json`)

- Mixed inbound plus optional TUN inbound, FakeIP DNS with a real-IP `dns-direct` resolver.
- One outbound per proxy plus a `urltest` group tagged `auto`, with `final: auto` when proxies exist.
- Routing: sniff → hijack-dns → `ip_is_private` → `final: auto`.

### Validate before deploying

```bash
mihomo -t -f clash_config.yaml
sing-box check -c singbox_config.json
```

## TUN mode

TUN is disabled by default. Pass `--tun` to create the TUN inbound; it needs root or `CAP_NET_ADMIN`. Without it, the converter emits loopback-only inbounds and does not change the host default route.

## Proxy groups and balancing

Generated Clash configs include four groups: `PROXY` (manual selection), `Auto` (latency-based url-test), `Load Balance` (consistent-hashing load balancing), and `Fallback`. These are standard mihomo proxy groups embedded in the YAML — no external balancer, database, or timer is installed with this tool. Select a group in your client to switch behavior.

## Deduplication and multiple feeds

The converter accepts one or more subscription URLs as positional arguments. Each feed is downloaded separately; a feed that fails to download is skipped with a warning, and generation continues with the feeds that succeeded. Successful feeds are parsed into one merged pool and written to a single pair of output files. A single feed keeps the same behavior as before.

Two kinds of duplicates are removed:

- **Exact duplicates are always removed.** Identical raw share links are skipped with a `seen` set, so the same link appearing twice in a feed is emitted once.
- **Same-host duplicates are optional.** Pass `--unique-host` to keep only the first proxy per server host. With one feed this is applied during parsing; with multiple feeds it is applied to the merged pool after all feeds are parsed, so a host repeated across different feeds is also reduced to one entry.

Node names are identity hashes of protocol + host + port, so even without `--unique-host` multiple links pointing at the same server share a stable name.

```bash
# Merge two feeds and drop repeated hosts across both
python3 proxy_converter.py \
  "https://a.example/sub#FeedA" \
  "https://b.example/sub#FeedB" \
  --unique-host
```

## FAQ

**Does it need xray or a local sidecar?** No. The generated Clash config carries the subscription nodes directly and uses TUN + Fake-IP DNS. There is no Iran/CN geo bypass or process bypass.

**Can I merge feeds?** Yes. Pass multiple URLs on the command line; they are downloaded separately, merged, and deduplicated.

**Why do node names look like hashes?** Names are `{proto}-{12hex}` derived from server + port so they remain stable across feed refreshes; the provider remark is retained for humans.

**Where do the configs go?** By default to `clash_config.yaml` and `singbox_config.json` in the current directory. Override with `--clash-out` / `--singbox-out`.

**Is there a dashboard?** The generated Clash config exposes the standard mihomo external controller; set a secret before exposing it on a network.

## License

MIT — see [LICENSE](LICENSE).
