# V2Ray Subscription Link Parser and Configuration Generator

A comprehensive Python tool that downloads V2Ray subscription links, parses various proxy formats, and generates optimized configurations for SingBox and Clash with automatic URL testing and load balancing.

> **Direct-mihomo mode (no xray needed):** the generated `clash_config.yaml`
> carries the subscription nodes itself and mirrors the TUN + Fake-IP +
> DNS-hijack setup from `~/Desktop/mihomo` (mixed `:7890`, TUN `stack: mixed`
> with `dns-hijack: any:53`, DNS on `:1053`, `find-process-mode: always`,
> PROCESS + private/LAN bypass). Copy it over the Desktop config and restart:
> ```bash
> python3 proxy_converter.py
> cp clash_config.yaml ~/Desktop/mihomo/config.yaml
> cd ~/Desktop/mihomo && ./manager.sh check && sudo ./manager.sh restart
> ```
> Routing policy: proxy/helper processes + private/LAN → `DIRECT`,
> Iranian sites (`*.ir`, …) and IPs (`GEOIP,IR`) → `DIRECT`, everything
> else → subscription proxies (`MATCH,PROXY`).
>
> **Dashboard:** the generated config serves the official MetaCubeX dashboard
> at <http://127.0.0.1:9090/ui> (`external-ui: ui` + metacubexd `gh-pages`
> zip, auto-downloaded by mihomo on first start into `./ui/`, git-ignored).
> No secret is set, so the same-origin UI connects without auth.

## Features

- **Multi-Protocol Support**: VMess, VLESS, Trojan, Shadowsocks, Hysteria, TUIC
- **Multiple Link Formats**: V2RayN, DuckSoft, SS-Android, and base64 encoded formats
- **Configuration Generation**: SingBox JSON and Clash YAML configurations
- **Load Balancing**: URL testing with automatic failover
- **Enhanced Routing**: Mixed inbound and TUN inbound for system-wide proxy
- **Comprehensive Documentation**: Based on official SingBox and Clash specifications

## Supported Protocols

### Proxy Protocols
- ✅ **VMess** - Multiple formats (Standard, V2RayN, DuckSoft)
- ✅ **VLESS** - With flow control and Reality support
- ✅ **Trojan** - Password-based with TLS
- ✅ **Shadowsocks** - SS-Android and V2RayN formats
- ✅ **Hysteria** - Both v1 and v2 (hy2) protocols
- ✅ **TUIC** - v5 protocol with congestion control

### Transport Layers
- TCP, WebSocket (WS), HTTP, gRPC, HTTPUpgrade
- TLS with SNI, ALPN, certificate verification
- Reality, ECH, uTLS fingerprinting support

## Installation

### Requirements
- Python 3.8 or higher
- Required packages listed in `requirements.txt`

### Setup
```bash
# Clone the repository
git clone <repository-url>
cd v2ray-to-subs

# Install dependencies
pip install -r requirements.txt

# Run the tool
python proxy_converter.py
```

## Usage

### Basic Usage
```python
from proxy_converter import SubscriptionDownloader, ProxyParser, ConfigGenerator

# Download subscription
downloader = SubscriptionDownloader()
content = downloader.download_subscription("https://example.com/subscription")

# Parse proxies
parser = ProxyParser()
proxies = parser.parse_subscription_content(content)

# Generate configurations
generator = ConfigGenerator()

# SingBox configuration
singbox_config = generator.generate_singbox_config(proxies)
with open('singbox_config.json', 'w') as f:
    json.dump(singbox_config, f, indent=2)

# Clash configuration
clash_config = generator.generate_clash_config(proxies)
with open('clash_config.yaml', 'w') as f:
    yaml.dump(clash_config, f, default_flow_style=False)
```

### Command Line Usage
```bash
# Default: Patterniha Free-Configs subscription → clash_config.yaml + singbox_config.json
python proxy_converter.py

# Custom subscription URL (fragment #Name becomes the profile title)
python proxy_converter.py "https://example.com/sub#MyProfile"

# Only Clash / only sing-box
python proxy_converter.py --only clash
python proxy_converter.py --only singbox -v

# Defaults: TUN off, loopback-only (allow-lan false, 127.0.0.1 bindings).
# Opt in when you need system-wide routing or LAN access:
python proxy_converter.py --tun
python proxy_converter.py --tun --allow-lan

# Validate outputs
mihomo -t -f clash_config.yaml
sing-box check -c singbox_config.json
```

## Configuration Features

### SingBox Configuration
- **Mixed Inbound**: HTTP/SOCKS5 proxy on `127.0.0.1:10808`
- **TUN Inbound**: `stack: mixed`, `mtu: 9000`, `strict-route`, private
  subnets in `route_exclude_address` (loop-free system-wide proxy)
- **DNS**: FakeIP by default (`198.18.0.0/15`) with real-IP exceptions for
  LAN/NTP/Iran/CN; hijacked port-53 handled via `hijack-dns`
- **Routing**: sniff → hijack-dns → process bypass (xray/sing-box/PattN) →
  `ip_is_private` → Iran/CN suffixes → `final: auto` (urltest)
- **URL Test Outbound**: Automatic proxy selection based on latency
- **Auto Interface Detection**: Prevents routing loops

### Clash Configuration
- **Mixed Port**: HTTP/SOCKS5 proxy on port 7890 (matches `~/Desktop/mihomo`)
- **TUN**: `stack: mixed`, `device: mihomo`, `dns-hijack: [any:53, tcp://any:53]`,
  `route-exclude-address` for private/LAN (mirrors Desktop setup)
- **DNS**: Fake-IP on `0.0.0.0:1053`, DoH/DoT resolvers, fallback + filter
  (mirrors Desktop setup)
- **Sniffer**: TLS/HTTP/QUIC with Desktop ports and skip lists
- **Proxy Groups**:
  - `PROXY`: Manual selection group
  - `Auto`: url-test, automatic selection based on latency
  - `Load Balance`: Round-robin load balancing
  - `Fallback`: Failover group
- **Rules** (first match wins): PROCESS bypass → private/LAN → ads REJECT →
  Iran bypass (sites + `GEOIP,IR`) → CN bypass (sites + `GEOIP,CN`) →
  foreign services → `MATCH,PROXY`

### Load Balancing and URL Testing
- **Test URL**: `https://www.gstatic.com/generate_204`
- **Test Interval**: 3 minutes
- **Tolerance**: 50ms
- **Failover**: Automatic switching to faster proxies
- **Load Distribution**: Consistent hashing algorithm

## Subscription Link Formats

### Supported Sources
The tool can parse subscription links from various sources:
- Base64 encoded subscription files
- Plain text proxy lists
- V2RayN format configurations
- DuckSoft format links

### Example Subscription URLs
```bash
# Default subscription (also the manager.sh default)
https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt#Patterniha-F

# Other public subscriptions (fragment #Name becomes the profile title)
https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt
https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt
https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt
```

## manager.sh (easy use)

The repo ships a `manager.sh` wrapper (same style as `~/Desktop/mihomo/manager.sh`).
It defaults to the Patterniha subscription above, loopback-only bindings, TUN off:

```bash
./manager.sh generate                                  # both configs, defaults
./manager.sh generate --tun                            # + TUN inbound
./manager.sh generate --tun --allow-lan                # + LAN clients
./manager.sh tun "https://example.com/sub#MyProfile"   # TUN + custom sub
./manager.sh clash | ./manager.sh singbox              # single output
./manager.sh check                                     # mihomo -t + sing-box check
./manager.sh deploy --tun                              # regenerate + install to ~/Desktop/mihomo
./manager.sh help                                      # full usage
```

`deploy` backs up `~/Desktop/mihomo/config.yaml`, installs the fresh
`clash_config.yaml`, and runs its `check`. Activate with:
```bash
cd ~/Desktop/mihomo && sudo ./manager.sh restart
```
then open the dashboard at <http://127.0.0.1:9090/ui>.

## Generated Configuration Structure

### SingBox Structure
```json
{
  "log": { "level": "info" },
  "dns": { "servers": [...] },
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in" },
    { "type": "tun", "tag": "tun-in" }
  ],
  "outbounds": [
    { "type": "vmess", "tag": "proxy-0" },
    { "type": "vless", "tag": "proxy-1" },
    { "type": "urltest", "tag": "url-test" }
  ],
  "route": { "rules": [...] }
}
```

### Clash Structure
```yaml
mixed-port: 10801
allow-lan: true
mode: rule
proxies:
  - name: proxy-0
    type: vmess
proxy-groups:
  - name: URL-Test
    type: url-test
  - name: Load-Balance
    type: load-balance
  - name: Proxy
    type: select
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - MATCH,Proxy
```

## Advanced Features

### Protocol-Specific Optimizations
- **VMES/VLESS**: Flow control, Reality, ECH support
- **Trojan**: TLS optimization, header manipulation
- **Shadowsocks**: Plugin support, UDP over TCP
- **Hysteria**: QUIC protocol, bandwidth control
- **TUIC**: Congestion control, UDP relay modes

### Security Features
- **TLS Verification**: Certificate validation options
- **SNI Support**: Custom server name indication
- **uTLS Fingerprinting**: Anti-detection capabilities
- **Reality Protocol**: Advanced obfuscation

### Performance Optimizations
- **Connection Multiplexing**: Reduce connection overhead
- **Smart Routing**: Domain-based rule matching
- **DNS Optimization**: Custom DNS servers
- **Auto Interface Detection**: Prevent routing issues

## Error Handling

The tool includes comprehensive error handling:
- **Network Errors**: Timeout and connection failure handling
- **Parse Errors**: Graceful handling of malformed links
- **Configuration Validation**: Output format validation
- **Logging**: Detailed error messages and warnings

## Logging

Configure logging levels for debugging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Log levels:
- `INFO`: General operation messages
- `WARNING`: Non-critical issues
- `ERROR`: Parsing or configuration errors
- `DEBUG`: Detailed debugging information

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- **SingBox Documentation**: Configuration format specifications
- **Clash Documentation**: Proxy configuration standards
- **NekoBox Analysis**: Protocol format references
- **V2Ray Community**: Protocol specifications and examples

## Support

For issues and questions:
1. Check the generated configuration files
2. Review the log output for errors
3. Verify subscription link accessibility
4. Test individual proxy configurations

## Changelog

### v1.0.0
- Initial release
- Support for VMess, VLESS, Trojan, Shadowsocks, Hysteria, TUIC
- SingBox and Clash configuration generation
- URL testing and load balancing
- Mixed and TUN inbound support
- Comprehensive error handling and logging
