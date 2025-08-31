# v2ray Subscription to Clash Meta & Singbox Config Generator

This Python project converts a v2rayNG-style subscription link (vmess/vless/ss/trojan/socks) directly to two config
formats:

- A Clash Meta YAML config (`config.yaml` style)
- A Singbox JSON config (`signbox.json` style)

Both outputs retain advanced template features (DNS, rules, anti-DNS-hijack, groups) as provided in your base configs.

## Features

- Parses all links in a v2ray subscription (vmess, vless, trojan, ss, socks)
- Injects nodes into both configs per your template structure
- Preserves all routing, geoip, dns, and proxy group tricks (Iran/anti-hijack optimized)
- Outputs ready-to-use configs for both Clash Meta and Singbox

## Requirements

Setup and usage is simple:

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```
python sub2clash_singbox.py <subs_url> config.yaml singbox.json result_clash.yaml result_singbox.json
```

Where:

- `subs_url` is the HTTP/HTTPS v2ray subscription (
  e.g. https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/iran_top100_checked.txt)
- `config.yaml` is your base Clash Meta template
- `singbox.json` is your base Singbox template
- Outputs are written to result_clash.yaml and result_singbox.json respectively

## Notes

- All existing template proxies are replaced; proxy groups, rules, and DNS remain as in your base config.
- If your template has hardcoded outbounds (e.g. "warp", "us") they will appear in Singbox unless removed from the
  template.
- Fully robust to mix of protocols or large sub lists (tested on 100+ node links).

## License

MIT
