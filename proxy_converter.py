#!/usr/bin/env python3
"""V2Ray Subscription Link Parser and Configuration Generator.

Downloads subscription links, parses share-link formats (aligned with
v2rayNG / v2rayN / Xray share-link conventions), and generates complete
mihomo (Clash.Meta) configurations.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import yaml

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Stable proxy identity naming.
#
# Provider remarks reshuffle on every feed refresh (positional indexes like
# "US-1" or colliding labels needing feed-order suffixes), so these helpers
# derive a deterministic identity from protocol + normalized host + port.
# The same server always maps to the same node name across refreshes.
# ---------------------------------------------------------------------------


def normalize_host(host: str) -> str:
    """Normalize a proxy host for stable identity hashing.

    Lowercases the host, strips surrounding IPv6 brackets, strips a
    trailing FQDN dot, and strips surrounding whitespace. Returns an empty
    string for None input so callers never crash on missing hosts.
    """
    # Defensive: parsers may pass None for malformed links; coerce first.
    h = (host or "").strip().lower()
    # Strip surrounding IPv6 brackets: "[::1]" and "::1" must hash alike.
    if len(h) >= 2 and h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
        # Re-strip in case of "[ ::1 ]" style padding inside brackets.
        h = h.strip().lower()
    # Strip a trailing FQDN dot: "example.com." and "example.com" are one host.
    if h.endswith("."):
        h = h.rstrip(".")
    return h


def build_proxy_identity(proto: str, host: str, port: int) -> str:
    """Build a stable proxy identity as ``{proto}-{12 hex chars}``.

    Normalizes the protocol to lowercase, normalizes the host via
    :func:`normalize_host`, and coerces the port to int so ``"443"`` and
    ``443`` hash alike. The ``proto|host|port`` key is hashed with SHA-256
    and truncated to 12 hex chars (48 bits): for a 10k-node pool the
    expected collision count is far below one, and any residual collision
    is resolved deterministically by :func:`assign_stable_names`.
    """
    # Normalize protocol: "VLESS" and "vless" must yield the same identity.
    p = (proto or "").strip().lower()
    # Normalize host so case/bracket/dot variants map to one identity.
    norm = normalize_host(host)
    # Guard: empty proto or host must fall back to the remark path, never
    # hash to a trusted-looking name that could mask a broken entry.
    if not p:
        raise ValueError("proto required for stable identity")
    if not norm:
        raise ValueError("host required for stable identity")
    # Coerce port to int so string and int ports hash alike; raises on garbage.
    port_int = int(str(port).strip())
    # Pipe-joined key keeps the three fields unambiguous ("a|b|c" framing).
    key = f"{p}|{norm}|{port_int}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"{p}-{digest}"


def assign_stable_names(entries: list) -> list:
    """Assign deterministic stable names to converter entries.

    Sorts a copy of ``entries`` by base identity then source link, so the
    output no longer depends on feed order. Entries with a unique base
    identity keep it unchanged; colliding identities gain sorted suffixes
    (``base``, ``base-2``, ``base-3``, ...). Each entry must expose
    ``base_identity`` and ``source_link`` as attributes or dict keys; the
    final name is written to ``final_name``. Returns the entries in sorted
    emission order.
    """

    # Accessors tolerate both dataclass-style entries and plain dicts.
    def get_base(e):
        return e.get("base_identity") if isinstance(e, dict) else e.base_identity

    def get_link(e):
        return (
            e.get("source_link", "")
            if isinstance(e, dict)
            else getattr(e, "source_link", "")
        )

    def set_final(e, v):
        if isinstance(e, dict):
            e["final_name"] = v
        else:
            e.final_name = v

    # Sort by (identity, link): identical identities get a stable link order.
    ordered = sorted(list(entries), key=lambda e: (get_base(e), get_link(e)))
    # Count first so unique identities pass through untouched (no "-1").
    counts: dict = {}
    for e in ordered:
        counts[get_base(e)] = counts.get(get_base(e), 0) + 1
    # Second pass assigns: first of a colliding group keeps the base name.
    seen: dict = {}
    for e in ordered:
        b = get_base(e)
        if counts[b] == 1:
            set_final(e, b)
        else:
            seen[b] = seen.get(b, 0) + 1
            n = seen[b]
            if n == 1:
                set_final(e, b)
            else:
                set_final(e, f"{b}-{n}")
    return ordered


DEFAULT_SUBSCRIPTION_URL = "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt"

# ---------------------------------------------------------------------------
# Shared bypass policy.
#
# Mirrors /home/mohammad/Desktop/mihomo usage (mihomo as TUN + Fake-IP +
# DNS-hijack front-end): private/LAN always DIRECT, everything else goes
# through the subscription proxies. No xray sidecar needed —
# mihomo dials the nodes directly.
# ---------------------------------------------------------------------------

# Processes that must never be routed back into the tunnel (loop avoidance).
# Retired: this runs on a foreign server with no local xray/PattN sidecar, so
# process matching was removed along with the PROCESS-* rules it fed.
# Subnets excluded from TUN routing AND forced DIRECT at rule level.
PRIVATE_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "198.18.0.0/15",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
]
PRIVATE_CIDRS_V6 = [
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "2001:db8::/32",
]

# Iranian and Chinese direct-bypass lists were removed: the exit is outside
# both countries, so those suffixes only stole traffic from the proxy.

# Domains that must resolve to real IPs (never fake-ip): LAN + NTP + probes.
REALIP_SUFFIXES = [
    "*.lan",
    "*.local",
    "localhost.ptlogin2.qq.com",
    "+.msftconnecttest.com",
    "+.msftncsi.com",
    "time.*.com",
    "time.*.gov",
    "+.pool.ntp.org",
    "detectportal.firefox.com",
    "connectivitycheck.gstatic.com",
]
# Top exit countries used for country-based proxy groups.
# Trimmed to US, DE, NL per operator choice (Option E) to reduce RAM
# and group explosion; extend only with healthy members and memory budget.
COUNTRY_CODES = ["US", "DE", "NL"]

# Service-specific dedicated groups. Each service gets a select plus
# url-test pair. The url-test health-checks a strict service URL with
# expected HTTP 200, so only nodes that can reach that service survive.
# GEOSITE provides community domain lists for routing; DOMAIN-SUFFIX
# covers services without a standard geosite entry.
SERVICE_HEALTH_URLS = {
    "Google": "https://gemini.google.com/",
    "Apple": "https://www.apple.com/",
    "Docker": "https://hub.docker.com/",
    "Claude": "https://claude.ai/",
    "ChatGPT": "https://chatgpt.com/",
    "GitHub": "https://github.com/",
    "OpenCode": "https://opencode.ai/",
}
SERVICE_GEOSITE = {
    "Google": "google",
    "Apple": "apple",
    "Docker": "docker",
    "Claude": "anthropic",
    "ChatGPT": "openai",
    "GitHub": "github",
}
# Services without a standard geosite entry (use DOMAIN-SUFFIX fallback).
SERVICE_DOMAIN_FALLBACK = {
    "Google": ["google.com", "aistudio.google.com", "gemini.google.com"],
    "Apple": ["apple.com"],
    "Docker": ["docker.com", "hub.docker.com"],
    "Claude": ["claude.ai", "anthropic.com"],
    "ChatGPT": ["chatgpt.com", "openai.com"],
    "GitHub": ["github.com", "githubusercontent.com"],
    "OpenCode": ["opencode.ai"],
}
SERVICE_ORDER = ["Google", "Apple", "Docker", "Claude", "ChatGPT", "GitHub", "OpenCode"]
CHECKER_URL_TEMPLATE = "https://checker.surfshield.org/{cc}"
MIHOMO_CACHE_SIZE = 4096


# mihomo client-fingerprint accepted values
UTLS_FINGERPRINTS = {
    "chrome",
    "firefox",
    "safari",
    "ios",
    "random",
    "none",
    "edge",
    "360",
    "qq",
    "uou",
    "tugatu",
}


class _QuotedStr(str):
    """A string that PyYAML always emits double-quoted.

    Needed for REALITY public-key / short-id: values like "2e00" are
    valid hex but dump unquoted by PyYAML while Go-YAML (mihomo) reads
    them as float 2.0, failing with "invalid REALITY short ID".
    """


def _quoted_str_representer(dumper: yaml.Dumper, data: _QuotedStr):  # type: ignore[type-arg]
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style='"')


yaml.add_representer(_QuotedStr, _quoted_str_representer)
try:
    yaml.SafeDumper.add_representer(_QuotedStr, _quoted_str_representer)  # type: ignore[attr-defined]
except Exception:
    pass


def _unquote(value: Optional[str]) -> str:
    if not value:
        return ""
    return urllib.parse.unquote(value)


def _split_alpn(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    parts = re.split(r"[,:]", value)
    alpn = [p.strip() for p in parts if p.strip()]
    return alpn or None


def _normalize_fingerprint(fp: Optional[str]) -> Optional[str]:
    if not fp:
        return None
    fp = fp.strip().lower()
    if fp in ("unsafe", ""):
        return "none"
    if fp in UTLS_FINGERPRINTS:
        return fp
    return None


def _sanitize_reality_pbk(value: Optional[str]) -> Optional[str]:
    """Return a REALITY public key mihomo accepts, else None.

    Feeds ship keys with stray whitespace, percent-escapes or the wrong
    byte length; mihomo aborts the whole config with "invalid REALITY
    public key" instead of skipping the node. A REALITY node without a
    usable key can never connect, so callers drop it.
    """
    if not value:
        return None
    key = "".join(str(value).split())
    if not re.fullmatch(r"[A-Za-z0-9_\-]+={0,2}", key):
        return None
    try:
        raw = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
    except Exception:
        return None
    return key if len(raw) == 32 else None


def _sanitize_reality_short_id(value: Optional[str]) -> str:
    """Return a REALITY short-id mihomo accepts, or "" for an invalid one.

    mihomo aborts the *entire* generated config with "invalid REALITY short
    ID" when a node carries an odd-length or non-hex short-id. A single bad
    feed entry therefore breaks every proxy for the host. The sanitizer
    normalises the value and substitutes "" (which mihomo treats as "no short
    id") for anything invalid, logging a warning so the source is visible.

    Accepted: None/empty -> ""; "0xDEADbeef" -> "deadbeef" (even-length hex);
    a bare even-length hex string -> lowercased. Rejected: odd-length hex and
    any string containing non-hex characters -> "" with a warning.
    """
    if value is None:
        return ""
    text = "".join(str(value).split()).lower()
    if text.startswith("0x"):
        text = text[2:]
    if text == "":
        return ""
    if len(text) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", text):
        return text
    logging.warning("invalid REALITY short-id %r; emitting empty short-id", value)
    return ""


def _usable_proxies(proxies: List[ProxyConfig]) -> List[ProxyConfig]:
    """Drop nodes that can never establish a session (bad REALITY key)."""
    return [p for p in proxies if not (p.security == "reality" and not p.pbk)]


def _parse_bool(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


# Cipher names some feeds emit that mihomo does not recognize,
# mapped to their canonical equivalents.
SS_METHOD_ALIASES = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
}

# Shadowsocks ciphers mihomo actually accepts. Anything else (garbage from
# mislabeled links, base64-decoded UUIDs, etc.) would fail `mihomo -t` with
# "unknown method", so drop the proxy at parse time instead.
SS_VALID_METHODS = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "chacha20",
    "chacha20-ietf",
    "xchacha20",
    "rc4-md5",
    "rc4",
    "table",
    "none",
    "plain",
    "auto",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}


def _normalize_ss_method(method: str) -> str:
    """Map known ss cipher aliases to canonical mihomo-accepted names."""
    key = (method or "").strip().lower()
    if key in SS_METHOD_ALIASES:
        logger.debug("ss cipher alias %r -> %r", method, SS_METHOD_ALIASES[key])
        return SS_METHOD_ALIASES[key]
    return method


def _valid_ss_method(method: str) -> bool:
    return (method or "").strip().lower() in SS_VALID_METHODS


def _ws_early_data(
    path: Optional[str],
) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """Split WebSocket path early-data (?ed=) and early-data header (?eh=).

    Returns (clean_path, max_early_data, early_data_header_name).
    """
    if not path:
        return path, None, None
    try:
        parsed = urllib.parse.urlsplit(path)
    except ValueError:
        return path, None, None
    if not parsed.query and not parsed.fragment:
        return path, None, None
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    ed = None
    eh = None
    if "ed" in qs:
        try:
            ed = int(qs["ed"][0])
        except (ValueError, IndexError):
            ed = None
    if "eh" in qs and qs["eh"][0]:
        eh = qs["eh"][0]
    if ed is None and eh is None and not qs:
        return path, None, None
    remaining = {k: v for k, v in qs.items() if k not in ("ed", "eh")}
    query = urllib.parse.urlencode(remaining, doseq=True)
    clean = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", query, parsed.fragment)
    )
    if parsed.query and not remaining and ed is None and eh is None:
        return path, None, None
    return clean, ed, eh


@dataclass
class ProxyConfig:
    """Base proxy configuration with common stream/TLS fields."""

    name: str
    server: str
    port: int
    protocol: str

    network: str = "tcp"
    header_type: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None
    service_name: Optional[str] = None
    mode: Optional[str] = None
    extra: Optional[str] = None

    security: str = ""  # "", "tls", "reality"
    sni: Optional[str] = None
    alpn: Optional[str] = None
    fp: Optional[str] = None
    insecure: bool = False
    flow: Optional[str] = None
    pbk: Optional[str] = None
    sid: Optional[str] = None
    spx: Optional[str] = None
    packet_encoding: Optional[str] = None
    # Raw subscription line this entry was parsed from. Used only as a
    # deterministic tiebreak in assign_stable_names; never emitted.
    source_link: str = ""


@dataclass
class VMessConfig(ProxyConfig):
    uuid: str = ""
    alterId: int = 0
    cipher: str = "auto"


@dataclass
class VLESSConfig(ProxyConfig):
    uuid: str = ""
    encryption: str = "none"


@dataclass
class TrojanConfig(ProxyConfig):
    password: str = ""


@dataclass
class ShadowsocksConfig(ProxyConfig):
    method: str = ""
    password: str = ""
    plugin: Optional[str] = None
    plugin_opts: Optional[str] = None


@dataclass
class HysteriaConfig(ProxyConfig):
    auth: Optional[str] = None
    auth_base64: bool = False
    up: Optional[str] = None
    down: Optional[str] = None
    obfs: Optional[str] = None
    ports: Optional[str] = None


@dataclass
class Hysteria2Config(ProxyConfig):
    password: str = ""
    obfs: Optional[str] = None
    obfs_password: Optional[str] = None
    up: Optional[str] = None
    down: Optional[str] = None
    ports: Optional[str] = None
    hop_interval: Optional[int] = None


@dataclass
class TUICConfig(ProxyConfig):
    uuid: str = ""
    password: str = ""
    token: Optional[str] = None
    congestion_control: str = "cubic"
    udp_relay_mode: str = "native"
    heartbeat: Optional[str] = None


@dataclass
class SocksConfig(ProxyConfig):
    username: Optional[str] = None
    password: Optional[str] = None


class SubscriptionDownloader:
    """Downloads subscription content; captures URL fragment as title."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.last_title: Optional[str] = None
        self.last_update_interval: Optional[str] = None

    def download_subscription(self, url: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        self.last_title = _unquote(parsed.fragment) or None

        request_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")
        )
        headers = {
            "User-Agent": "v2rayNG/1.10.0",
            "Accept": "*/*",
            "Connection": "close",
        }
        try:
            req = urllib.request.Request(request_url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read()
                interval = response.headers.get("Profile-Update-Interval")
                if interval:
                    self.last_update_interval = interval.strip()
                title = response.headers.get("Profile-Title") or response.headers.get(
                    "content-profile-title"
                )
                if title:
                    self.last_title = title.strip().strip('"')

                for encoding in ("utf-8", "utf-8-sig", "latin-1"):
                    try:
                        content = raw.decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    content = raw.decode("utf-8", errors="replace")

                logger.info("Downloaded subscription from %s (%d bytes)", url, len(raw))
                return content
        except Exception as exc:
            logger.error("Failed to download subscription from %s: %s", url, exc)
            raise


def _dedup_by_host(
    proxies: List[ProxyConfig],
) -> Tuple[List[ProxyConfig], int]:
    """Keep the first proxy per server host (case/whitespace normalized).

    Shared by single-feed parse and multi-feed merge so both paths apply
    identical first-wins semantics. Returns (unique, duplicate_count).
    """
    seen: set = set()
    unique: List[ProxyConfig] = []
    dups = 0
    for proxy in proxies:
        key = (proxy.server or "").strip().lower()
        if key in seen:
            dups += 1
            continue
        seen.add(key)
        unique.append(proxy)
    return unique, dups


class ProxyParser:
    """Parses share-link formats (v2rayNG / v2rayN / Xray conventions)."""

    def __init__(self, unique_host: bool = False) -> None:
        self.unique_host = unique_host
        self.host_dup = 0

    SCHEMES = (
        "vmess://",
        "vless://",
        "trojan://",
        "ss://",
        "ssr://",
        "hysteria2://",
        "hy2://",
        "hysteria://",
        "tuic://",
        "socks://",
        "socks5://",
        "socks4://",
        "wireguard://",
    )

    @staticmethod
    def decode_base64_content(content: str) -> str:
        stripped = content.strip()
        if not stripped:
            return content
        if any(stripped.startswith(s) for s in ProxyParser.SCHEMES):
            return content
        if re.match(r"^[A-Za-z0-9+/=\s]+$", stripped) and not stripped.startswith("#"):
            for decoder in (
                lambda s: base64.b64decode(s, validate=False),
                lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)),
            ):
                try:
                    decoded = decoder(re.sub(r"\s+", "", stripped)).decode("utf-8")
                    if any(
                        line.startswith(s)
                        for line in decoded.splitlines()
                        for s in ProxyParser.SCHEMES
                    ):
                        return decoded
                except Exception:
                    continue
        return content

    @staticmethod
    def _name_from(
        parsed: urllib.parse.ParseResult, default: str, params: Dict[str, List[str]]
    ) -> str:
        frag = _unquote(parsed.fragment)
        if frag:
            return frag
        for key in ("remark", "remarks", "name", "tag"):
            if params.get(key):
                return _unquote(params[key][0])
        return default

    @staticmethod
    def _apply_common(cfg: ProxyConfig, params: Dict[str, List[str]]) -> None:
        def get(key: str) -> Optional[str]:
            vals = params.get(key)
            return _unquote(vals[0]) if vals else None

        network = (get("type") or "tcp").lower()
        if network in ("h2", "http2"):
            network = "h2"
        if network in ("httpupgrade", "http-upgrade"):
            network = "httpupgrade"
        if network == "xhttp":
            network = "xhttp"
        if network == "splithttp":
            network = "xhttp"
        cfg.network = network or "tcp"
        cfg.header_type = get("headerType") or get("header-type")
        cfg.host = get("host")
        cfg.path = get("path")
        cfg.service_name = get("serviceName") or get("service-name")
        cfg.mode = get("mode")
        cfg.extra = get("extra")
        cfg.sni = get("sni") or get("servername") or get("serverName")
        cfg.alpn = get("alpn")
        cfg.fp = get("fp") or get("fingerprint")
        cfg.flow = get("flow")
        cfg.pbk = _sanitize_reality_pbk(
            get("pbk") or get("publicKey") or get("public-key")
        )
        cfg.sid = get("sid") or get("shortId") or get("short-id")
        cfg.spx = get("spx") or get("spiderX")
        cfg.packet_encoding = get("packetEncoding") or get("packet-encoding")

        security = (get("security") or "").lower()
        if security in ("tls", "reality", "xtls"):
            cfg.security = "reality" if security == "reality" else "tls"
        elif cfg.protocol in ("trojan", "hysteria", "hysteria2", "tuic"):
            cfg.security = cfg.security or "tls"

        for key in ("insecure", "allowInsecure", "allow_insecure"):
            if key in params:
                cfg.insecure = _parse_bool(params[key][0])
                break
        if get("allowInsecure") is not None and "allowInsecure" not in params:
            cfg.insecure = _parse_bool(get("allowInsecure"))

    @staticmethod
    def parse_vmess(link: str) -> VMessConfig:
        content = link[len("vmess://") :]
        # Standard URI form: vmess://uuid@host:port?query#name
        if "@" in content.split("#", 1)[0].split("?", 1)[0]:
            parsed = urllib.parse.urlparse(link)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            cfg = VMessConfig(
                name=ProxyParser._name_from(parsed, "VMess", params),
                server=parsed.hostname or "",
                port=parsed.port or 443,
                protocol="vmess",
                uuid=_unquote(parsed.username) or "",
            )
            ProxyParser._apply_common(cfg, params)
            scy = params.get("scy") or params.get("encryption")
            if scy:
                cfg.cipher = scy[0]
            return cfg

        raw = _unquote(content) if "%" in content else content
        try:
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
        except Exception:
            decoded = raw
        try:
            data = json.loads(decoded)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid vmess JSON payload: {exc}") from exc

        if not data.get("add") or not data.get("id"):
            raise ValueError("vmess payload missing add/id")

        net = (str(data.get("net") or "tcp")).lower()
        if net in ("h2", "http2"):
            net = "h2"
        if data.get("type") == "http" and net == "tcp":
            # HTTP header obfuscation over TCP in legacy vmess JSON
            header_type = "http"
        else:
            header_type = str(data.get("type") or "") or None

        cfg = VMessConfig(
            name=str(data.get("ps") or data.get("remark") or "VMess"),
            server=str(data.get("add") or ""),
            port=int(data.get("port") or 443),
            protocol="vmess",
            uuid=str(data.get("id") or ""),
            alterId=int(data.get("aid") or 0),
            cipher=str(data.get("scy") or data.get("encryption") or "auto") or "auto",
            network=net or "tcp",
            header_type=header_type,
            host=str(data.get("host") or "") or None,
            path=str(data.get("path") or "") or None,
            service_name=str(data.get("path") or "") or None if net == "grpc" else None,
            security=(
                "tls"
                if str(data.get("tls") or "").lower().endswith("tls")
                else (
                    "reality" if str(data.get("tls") or "").lower() == "reality" else ""
                )
            ),
            sni=str(data.get("sni") or "") or None,
            alpn=str(data.get("alpn") or "") or None,
            fp=str(data.get("fp") or "") or None,
            insecure=_parse_bool(
                str(data.get("insecure") or data.get("allowInsecure") or "")
            ),
            pbk=_sanitize_reality_pbk(str(data.get("pbk") or "") or None),
            sid=str(data.get("sid") or "") or None,
        )
        if net == "grpc" and not cfg.service_name:
            cfg.service_name = cfg.path or "GunService"
        return cfg

    @staticmethod
    def parse_vless(link: str) -> VLESSConfig:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not parsed.query:
            raise ValueError("vless link missing query string")
        cfg = VLESSConfig(
            name=ProxyParser._name_from(parsed, "VLESS", params),
            server=parsed.hostname or "",
            port=parsed.port or 443,
            protocol="vless",
            uuid=_unquote(parsed.username) or "",
            encryption=(params.get("encryption") or ["none"])[0],
        )
        ProxyParser._apply_common(cfg, params)
        return cfg

    @staticmethod
    def parse_trojan(link: str) -> TrojanConfig:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        cfg = TrojanConfig(
            name=ProxyParser._name_from(parsed, "Trojan", params),
            server=parsed.hostname or "",
            port=parsed.port or 443,
            protocol="trojan",
            password=_unquote(parsed.password or parsed.username or ""),
            security="tls",
        )
        ProxyParser._apply_common(cfg, params)
        security = (params.get("security") or ["tls"])[0].lower()
        if security in ("tls", "reality", "xtls", "none"):
            cfg.security = (
                "none"
                if security == "none"
                else ("reality" if security == "reality" else "tls")
            )
        return cfg

    @staticmethod
    def parse_shadowsocks(link: str) -> ShadowsocksConfig:
        body = link[len("ss://") :]
        fragment = ""
        if "#" in body:
            body, fragment = body.split("#", 1)
        query = ""
        if "?" in body:
            body, query = body.split("?", 1)
        params = urllib.parse.parse_qs(query, keep_blank_values=True)

        userinfo = ""
        hostport = body
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
        if not userinfo:
            try:
                pad = "=" * (-len(hostport) % 4)
                decoded = base64.urlsafe_b64decode(hostport + pad).decode("utf-8")
                if "@" in decoded:
                    userinfo, hostport = decoded.rsplit("@", 1)
                elif ":" in decoded:
                    # legacy full-base64 without @ split failed; try userinfo only
                    userinfo = decoded
                    hostport = ""
            except Exception as exc:
                raise ValueError(f"invalid ss payload: {exc}") from exc

        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            pad = "=" * (-len(userinfo) % 4)
            try:
                decoded = base64.urlsafe_b64decode(userinfo + pad).decode("utf-8")
                method, password = decoded.split(":", 1)
            except Exception as exc:
                raise ValueError(f"invalid ss userinfo: {exc}") from exc

        hostport = urllib.parse.unquote(hostport).rstrip("/")
        if hostport.count(":") == 1:
            server, port_s = hostport.split(":")
        else:
            # IPv6 [::1]:port
            m = re.match(r"^\[([^\]]+)\]:(\d+)$", hostport) or re.match(
                r"^(.*):(\d+)$", hostport
            )
            if not m:
                raise ValueError(f"invalid ss host:port {hostport!r}")
            server, port_s = m.group(1), m.group(2)
        server = server.strip("[]")
        port = int(port_s)

        name = _unquote(fragment) or "Shadowsocks"
        for key in ("name", "remark", "remarks"):
            if params.get(key):
                name = _unquote(params[key][0])
                break

        plugin = None
        plugin_opts = None
        plugin_raw = (params.get("plugin") or [""])[0]
        if plugin_raw:
            # SIP003: plugin;key=value;key=value
            bits = plugin_raw.split(";")
            plugin = _unquote(bits[0])
            if len(bits) > 1:
                plugin_opts = ";".join(bits[1:])

        method = _normalize_ss_method(urllib.parse.unquote(method))
        if not _valid_ss_method(method):
            raise ValueError(f"unknown ss cipher: {method!r}")
        return ShadowsocksConfig(
            name=name,
            server=server,
            port=port,
            protocol="shadowsocks",
            method=method,
            password=urllib.parse.unquote(password),
            plugin=plugin,
            plugin_opts=plugin_opts,
        )

    @staticmethod
    def parse_hysteria2(link: str, scheme: str = "hysteria2") -> Hysteria2Config:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        cfg = Hysteria2Config(
            name=ProxyParser._name_from(parsed, "Hysteria2", params),
            server=parsed.hostname or "",
            port=parsed.port or 443,
            protocol="hysteria2",
            password=_unquote(parsed.password or parsed.username or ""),
            security="tls",
        )
        ProxyParser._apply_common(cfg, params)

        def get(key: str) -> Optional[str]:
            vals = params.get(key)
            return _unquote(vals[0]) if vals else None

        obfs = get("obfs")
        cfg.obfs = obfs
        cfg.obfs_password = get("obfs-password") or get("obfs_password")
        mport = get("mport") or get("ports")
        cfg.ports = mport
        up = get("up") or get("upmbps") or get("up_mbps")
        down = get("down") or get("downmbps") or get("down_mbps")
        if up:
            cfg.up = up if not up.isdigit() else f"{up} Mbps"
        if down:
            cfg.down = down if not down.isdigit() else f"{down} Mbps"
        interval = get("_interval") or get("hop-interval")
        if interval and str(interval).isdigit():
            cfg.hop_interval = int(interval)
        return cfg

    @staticmethod
    def parse_hysteria(link: str) -> HysteriaConfig:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        cfg = HysteriaConfig(
            name=ProxyParser._name_from(parsed, "Hysteria", params),
            server=parsed.hostname or "",
            port=parsed.port or 443,
            protocol="hysteria",
            auth=_unquote(parsed.password or parsed.username or "") or None,
            security="tls",
        )
        ProxyParser._apply_common(cfg, params)

        def get(key: str) -> Optional[str]:
            vals = params.get(key)
            return _unquote(vals[0]) if vals else None

        up = get("upmbps") or get("up")
        down = get("downmbps") or get("down")
        if up:
            cfg.up = up if not str(up).isdigit() else f"{up} Mbps"
        if down:
            cfg.down = down if not str(down).isdigit() else f"{down} Mbps"
        cfg.obfs = get("obfs")
        cfg.ports = get("mport") or get("ports")
        cfg.auth_base64 = bool(get("auth"))
        return cfg

    @staticmethod
    def parse_tuic(link: str) -> TUICConfig:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        userinfo = _unquote(parsed.username or "")
        uuid = ""
        password = ""
        token = None
        if ":" in userinfo:
            uuid, password = userinfo.split(":", 1)
        elif userinfo:
            # v4 token style tuic://token@ or password-only
            token = userinfo
        cfg = TUICConfig(
            name=ProxyParser._name_from(parsed, "TUIC", params),
            server=parsed.hostname or "",
            port=parsed.port or 443,
            protocol="tuic",
            uuid=uuid,
            password=password,
            token=token,
            security="tls",
        )
        ProxyParser._apply_common(cfg, params)

        def get(key: str) -> Optional[str]:
            vals = params.get(key)
            return _unquote(vals[0]) if vals else None

        cfg.congestion_control = (
            get("congestion_control") or get("congestion-control") or "cubic"
        )
        cfg.udp_relay_mode = get("udp_relay_mode") or get("udp-relay-mode") or "native"
        cfg.heartbeat = get("heartbeat") or get("heartbeat-interval")
        if not cfg.password and get("password"):
            cfg.password = get("password")
        if not cfg.uuid and get("uuid"):
            cfg.uuid = get("uuid")
        if not cfg.token and get("token"):
            cfg.token = get("token")
        return cfg

    @staticmethod
    def parse_socks(link: str) -> SocksConfig:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        username = _unquote(parsed.username) or None
        password = _unquote(parsed.password) or None
        if username and ":" in username and password is None:
            # base64 userinfo
            try:
                pad = "=" * (-len(username) % 4)
                decoded = base64.urlsafe_b64decode(username + pad).decode("utf-8")
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
            except Exception:
                pass
        return SocksConfig(
            name=ProxyParser._name_from(parsed, "SOCKS5", params),
            server=parsed.hostname or "",
            port=parsed.port or 1080,
            protocol="socks",
            username=username,
            password=password,
        )

    @staticmethod
    def _skip_line(line: str) -> bool:
        if not line:
            return True
        if line.startswith("#") or line.startswith("//"):
            return True
        if line.lower().startswith(("profile-", "#profile")):
            return True
        return False

    def parse_subscription_content(self, content: str) -> List[ProxyConfig]:
        content = self.decode_base64_content(content)
        proxies: List[ProxyConfig] = []
        seen_raw: set = set()
        seen_hosts: set = set()
        self.host_dup = 0

        for raw_line in content.splitlines():
            line = raw_line.strip().strip("\r").strip()
            if self._skip_line(line):
                continue
            if line in seen_raw:
                continue
            seen_raw.add(line)

            try:
                lower = line.lower()
                if lower.startswith("vmess://"):
                    proxy: Optional[ProxyConfig] = self.parse_vmess(line)
                elif lower.startswith("vless://"):
                    proxy = self.parse_vless(line)
                elif lower.startswith("trojan://"):
                    proxy = self.parse_trojan(line)
                elif lower.startswith("ss://"):
                    proxy = self.parse_shadowsocks(line)
                elif lower.startswith(("hysteria2://", "hy2://")):
                    proxy = self.parse_hysteria2(line)
                elif lower.startswith("hysteria://"):
                    proxy = self.parse_hysteria(line)
                elif lower.startswith("tuic://"):
                    proxy = self.parse_tuic(line)
                elif lower.startswith(("socks://", "socks5://", "socks4://")):
                    proxy = self.parse_socks(line)
                else:
                    logger.debug("Unsupported line skipped: %s", line[:60])
                    continue

                if proxy and proxy.server and proxy.port:
                    if not proxy.name:
                        proxy.name = f"{proxy.protocol}-{len(proxies)}"
                    # Record the raw line for deterministic naming tiebreaks.
                    if not proxy.source_link:
                        proxy.source_link = line
                    if self.unique_host:
                        # Normalized key (same rules as identity hashing:
                        # lowercase, bracket strip, trailing-dot strip) so
                        # dedup and identity always agree on host equality.
                        key = normalize_host(proxy.server)
                        if key in seen_hosts:
                            self.host_dup += 1
                            continue
                        seen_hosts.add(key)
                    proxies.append(proxy)
            except Exception as exc:
                logger.error("Failed to parse proxy line: %s (%s)", exc, line[:80])

        logger.info("Parsed %d proxy configurations", len(proxies))
        return proxies


def _unique_name(name: str, used: set) -> str:
    name = (name or "").strip() or "proxy"
    # Clash/mihomo allows unicode names; keep emojis
    candidate = name
    idx = 1
    while candidate in used:
        idx += 1
        candidate = f"{name} ({idx})"
    used.add(candidate)
    return candidate


class ConfigGenerator:
    """Generates complete mihomo (Clash.Meta) configurations."""

    def __init__(
        self,
        tun_enabled: bool = False,
        allow_lan: bool = True,
        controller_secret: str = "",
    ) -> None:
        self.url_test_url = "https://www.gstatic.com/generate_204"
        self.url_test_interval = 300
        self.url_test_tolerance = 50
        self.subscription_title: Optional[str] = None
        # TUN is opt-in (needs root/CAP_NET_ADMIN); LAN open by default
        # (proxy-everything boundary: mixed port serves LAN clients).
        self.tun_enabled = tun_enabled
        self.allow_lan = allow_lan
        # Empty = no `secret` key emitted (backwards compatible default).
        self.controller_secret = controller_secret or ""

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _tls_block(cfg: ProxyConfig) -> Optional[Dict[str, Any]]:
        """mihomo TLS fields for a stream proxy (flat keys)."""
        if not cfg.security:
            return None
        block: Dict[str, Any] = {"tls": True}
        sni = cfg.sni or (cfg.host if cfg.security != "reality" else None) or None
        if cfg.sni:
            block["servername"] = cfg.sni
        elif cfg.security == "tls" and cfg.host and cfg.protocol != "vmess":
            # many workers nodes rely on Host as SNI when sni missing
            pass
        if cfg.insecure:
            block["skip-cert-verify"] = True
        fp = _normalize_fingerprint(cfg.fp)
        if fp:
            block["client-fingerprint"] = fp
        alpn = _split_alpn(cfg.alpn)
        if alpn:
            block["alpn"] = alpn
        if cfg.security == "reality" and cfg.pbk:
            reality: Dict[str, Any] = {"public-key": _QuotedStr(cfg.pbk)}
            sid = _sanitize_reality_short_id(cfg.sid)
            if sid:
                # Quote so Go-YAML never reads a hex value like "2e00" as a float.
                reality["short-id"] = _QuotedStr(sid)
            block["reality-opts"] = reality
        return block

    @staticmethod
    def _transport_fields(cfg: ProxyConfig) -> Dict[str, Any]:
        """mihomo network + transport option fields."""
        out: Dict[str, Any] = {}
        network = (cfg.network or "tcp").lower()
        header_type = (cfg.header_type or "").lower()

        # Legacy vmess TCP HTTP header obfuscation
        if network == "tcp" and header_type == "http":
            network = "http"

        if network in ("h2", "http2"):
            out["network"] = "h2"
            h2: Dict[str, Any] = {}
            if cfg.path:
                h2["path"] = [cfg.path]
            if cfg.host:
                h2["host"] = [cfg.host]
            if h2:
                out["h2-opts"] = h2
            return out

        if network == "httpupgrade":
            out["network"] = "ws"
            clean, ed, eh = _ws_early_data(cfg.path)
            ws: Dict[str, Any] = {"path": clean or "/"}
            headers: Dict[str, Any] = {}
            if cfg.host:
                headers["Host"] = cfg.host
            if headers:
                ws["headers"] = headers
            ws["v2ray-http-upgrade"] = True
            if ed is not None:
                ws["v2ray-http-upgrade-fast-open"] = True
            out["ws-opts"] = ws
            return out

        if network in ("ws", "websocket"):
            out["network"] = "ws"
            clean, ed, eh = _ws_early_data(cfg.path)
            ws = {"path": clean if clean is not None else "/"}
            if not ws["path"]:
                ws["path"] = "/"
            headers = {}
            if cfg.host:
                headers["Host"] = cfg.host
            if headers:
                ws["headers"] = headers
            if ed is not None:
                ws["max-early-data"] = ed
                ws["early-data-header-name"] = eh or "Sec-WebSocket-Protocol"
            elif eh:
                ws["early-data-header-name"] = eh
            out["ws-opts"] = ws
            return out

        if network == "grpc":
            out["network"] = "grpc"
            service = cfg.service_name or cfg.path or "GunService"
            out["grpc-opts"] = {"grpc-service-name": service}
            return out

        if network == "xhttp":
            out["network"] = "xhttp"
            opts: Dict[str, Any] = {}
            if cfg.path:
                opts["path"] = cfg.path
            if cfg.host:
                opts["host"] = cfg.host
            if cfg.mode:
                opts["mode"] = cfg.mode
            if cfg.extra:
                try:
                    opts["extra"] = json.loads(cfg.extra)
                except (json.JSONDecodeError, TypeError):
                    pass
            if opts:
                out["xhttp-opts"] = opts
            return out

        if network == "http":
            out["network"] = "http"
            http_opts: Dict[str, Any] = {"path": [cfg.path or "/"]}
            headers = {}
            if cfg.host:
                headers["Host"] = [cfg.host]
            if headers:
                http_opts["headers"] = headers
            out["http-opts"] = http_opts
            return out

        if network in ("kcp", "mkcp", "quic"):
            logger.debug(
                "Transport %s not supported by mihomo export; using tcp", network
            )
            return out

        # tcp / default: omit network key
        return out

    # ------------------------------------------------------------------
    # Clash / mihomo
    # ------------------------------------------------------------------
    def _clash_proxy(self, proxy: ProxyConfig, name: str) -> Optional[Dict[str, Any]]:
        base: Dict[str, Any] = {
            "name": name,
            "type": proxy.protocol,
            "server": proxy.server,
            "port": proxy.port,
            "udp": True,
        }
        # Keep the provider remark for humans: mihomo ignores unknown proxy
        # keys (verified with `mihomo -t`), so this never affects validation.
        if proxy.name and proxy.name != name:
            base["remark"] = proxy.name

        if isinstance(proxy, VMessConfig):
            base["type"] = "vmess"
            base["uuid"] = proxy.uuid
            base["alterId"] = proxy.alterId
            base["cipher"] = (
                proxy.cipher
                if proxy.cipher and proxy.cipher.lower() not in ("null", "none", "")
                else "auto"
            )
            if proxy.packet_encoding:
                pe = proxy.packet_encoding.lower()
                if pe == "packetaddr":
                    base["packet-encoding"] = "packetaddr"
                elif pe == "packet":
                    base["packet-encoding"] = "packetaddr"
                elif pe == "xudp":
                    base["packet-encoding"] = "xudp"
                # none → omit
        elif isinstance(proxy, VLESSConfig):
            base["type"] = "vless"
            base["uuid"] = proxy.uuid
            if proxy.flow:
                base["flow"] = proxy.flow
            # mihomo only accepts "" / "none" (omitted) or mlkem768x25519plus
            # key strings here; anything else (e.g. aes-128-gcm seen in the
            # wild) fails `mihomo -t`, so only mlkem values are emitted.
            if proxy.encryption and proxy.encryption.startswith("mlkem768"):
                base["encryption"] = proxy.encryption
            if proxy.packet_encoding:
                pe = proxy.packet_encoding.lower()
                if pe in ("packet", "packetaddr"):
                    base["packet-encoding"] = "packetaddr"
                elif pe == "xudp":
                    base["packet-encoding"] = "xudp"
        elif isinstance(proxy, TrojanConfig):
            base["type"] = "trojan"
            base["password"] = proxy.password
        elif isinstance(proxy, ShadowsocksConfig):
            base["type"] = "ss"
            base["cipher"] = proxy.method
            base["password"] = proxy.password
            if proxy.plugin:
                base["plugin"] = proxy.plugin
                if proxy.plugin_opts:
                    opts = _parse_plugin_opts(proxy.plugin_opts)
                    # mihomo requires v2ray-plugin mode; the plugin's own
                    # default is websocket when the link omits it.
                    if proxy.plugin == "v2ray-plugin" and "mode" not in opts:
                        opts["mode"] = "websocket"
                    base["plugin-opts"] = opts
        elif isinstance(proxy, Hysteria2Config):
            base["type"] = "hysteria2"
            base["password"] = proxy.password
            if proxy.ports:
                base["ports"] = proxy.ports
            if proxy.obfs:
                base["obfs"] = proxy.obfs
                base["obfs-password"] = proxy.obfs_password or ""
            if proxy.up:
                base["up"] = proxy.up
            if proxy.down:
                base["down"] = proxy.down
            if proxy.hop_interval:
                base["hop-interval"] = proxy.hop_interval
            if proxy.sni:
                base["sni"] = proxy.sni
            if proxy.insecure:
                base["skip-cert-verify"] = True
            alpn = _split_alpn(proxy.alpn)
            if alpn:
                base["alpn"] = alpn
            fp = _normalize_fingerprint(proxy.fp)
            if fp and fp != "none":
                # mihomo rejects a uTLS name under `fingerprint` (that key is
                # a TLS cert pin); browser fingerprints go to client-fingerprint.
                base["client-fingerprint"] = fp
            return base
        elif isinstance(proxy, HysteriaConfig):
            base["type"] = "hysteria"
            if proxy.auth:
                if proxy.auth_base64:
                    base["auth"] = proxy.auth
                else:
                    base["auth-str"] = proxy.auth
            if proxy.ports:
                base["ports"] = proxy.ports
            if proxy.obfs:
                base["obfs"] = proxy.obfs
            if proxy.up:
                base["up"] = proxy.up
            if proxy.down:
                base["down"] = proxy.down
            if proxy.sni:
                base["sni"] = proxy.sni
            if proxy.insecure:
                base["skip-cert-verify"] = True
            alpn = _split_alpn(proxy.alpn)
            if alpn:
                base["alpn"] = alpn
            return base
        elif isinstance(proxy, TUICConfig):
            base["type"] = "tuic"
            if proxy.token and not proxy.uuid:
                base["token"] = proxy.token
            else:
                base["uuid"] = proxy.uuid
                base["password"] = proxy.password
            base["congestion-controller"] = proxy.congestion_control
            base["udp-relay-mode"] = proxy.udp_relay_mode
            if proxy.heartbeat:
                try:
                    base["heartbeat-interval"] = int(proxy.heartbeat)
                except ValueError:
                    pass
            alpn = _split_alpn(proxy.alpn) or ["h3"]
            base["alpn"] = alpn
            if proxy.sni:
                base["sni"] = proxy.sni
            if proxy.insecure:
                base["skip-cert-verify"] = True
            return base
        elif isinstance(proxy, SocksConfig):
            base["type"] = "socks5"
            if proxy.username:
                base["username"] = proxy.username
            if proxy.password:
                base["password"] = proxy.password
            return base
        else:
            return None

        # Common transport + TLS for stream protocols
        base.update(self._transport_fields(proxy))
        tls = self._tls_block(proxy)
        if tls:
            base.update(tls)
            if proxy.protocol in ("vmess", "vless") and proxy.security:
                # servername fallback: SNI param already handled
                if "servername" not in base and proxy.sni:
                    base["servername"] = proxy.sni

        # Reality requires client-fingerprint
        if proxy.security == "reality" and "client-fingerprint" not in base:
            base["client-fingerprint"] = "chrome"

        return base

    def generate_clash_config(self, proxies: List[ProxyConfig]) -> Dict[str, Any]:
        clash_proxies: List[Dict[str, Any]] = []
        proxy_names: List[str] = []
        # Stable identity names: same proto/host/port always yields the same
        # node name across refreshes. Sorted emission makes output independent
        # of feed order.
        entries = []
        for proxy in _usable_proxies(proxies):
            try:
                base = build_proxy_identity(proxy.protocol, proxy.server, proxy.port)
            except Exception:
                # Broken entries fall back to remark or "proxy" with NO
                # positional index, so names never depend on feed order;
                # assign_stable_names sorts by source_link on collision.
                base = (proxy.name or "proxy").strip() or "proxy"
            entries.append(
                {
                    "proxy": proxy,
                    "base_identity": base,
                    "source_link": getattr(proxy, "source_link", "") or "",
                }
            )
        for item in assign_stable_names(entries):
            proxy = item["proxy"]
            name: str = item["final_name"]
            raw_name = proxy.name or name
            try:
                entry = self._clash_proxy(proxy, name)
            except Exception as exc:
                logger.error("Failed to convert proxy %r to clash: %s", raw_name, exc)
                continue
            if entry:
                clash_proxies.append(entry)
                proxy_names.append(name)

        proxy_groups: List[Dict[str, Any]] = []
        if proxy_names:
            auto_members = list(proxy_names)
            country_group_names = [cc for cc in COUNTRY_CODES]
            proxy_groups.extend(
                [
                    {
                        "name": "PROXY",
                        "type": "select",
                        "proxies": ["Auto", "Load Balance", "Fallback"]
                        + country_group_names
                        + proxy_names,
                    },
                    {
                        "name": "Auto",
                        "type": "url-test",
                        "proxies": auto_members,
                        "url": self.url_test_url,
                        "interval": self.url_test_interval,
                        "tolerance": self.url_test_tolerance,
                        "lazy": True,
                        # gstatic answers 204; without this mihomo expects
                        # 200, so checks can never pass and dead nodes stay
                        # in rotation. Drop nodes after 3 straight failures.
                        "expected-status": 204,
                        "max-failed-times": 3,
                    },
                    {
                        "name": "Load Balance",
                        "type": "load-balance",
                        "proxies": auto_members,
                        "url": self.url_test_url,
                        # 60s active checks over ~7k nodes: dead nodes drop
                        # out fast; consistent-hashing spreads destinations
                        # across all healthy nodes instead of rotating one
                        # connection stream through the top few.
                        "interval": 60,
                        "strategy": "consistent-hashing",
                        "lazy": False,
                        "expected-status": 204,
                        "max-failed-times": 3,
                    },
                    {
                        "name": "Fallback",
                        "type": "fallback",
                        "proxies": auto_members,
                        "url": self.url_test_url,
                        "interval": self.url_test_interval,
                        "lazy": True,
                        "expected-status": 204,
                        "max-failed-times": 3,
                    },
                ]
            )
        else:
            proxy_groups.append(
                {"name": "PROXY", "type": "select", "proxies": ["DIRECT"]}
            )

        # Country-based exit groups (runtime health via checker URL).
        if proxy_names:
            proxy_groups.extend(self._mihomo_country_groups(proxy_names))

        # Service-specific groups (runtime health via strict service URLs).
        # Each service gets a select + url-test pair; no entry in PROXY dropdown.
        if proxy_names:
            proxy_groups.extend(self._mihomo_service_groups(proxy_names))

        rules = self._clash_rules()
        # Insert service routing rules before the final MATCH,PROXY catch-all.
        if proxy_names:
            service_rules = self._mihomo_service_rules()
            try:
                match_idx = rules.index("MATCH,PROXY")
                rules[match_idx:match_idx] = service_rules
            except ValueError:
                rules.extend(service_rules)

        # NOTE: field-for-field aligned with /home/mohammad/Desktop/mihomo
        # config.yaml (verified mihomo v1.19.31 setup). Differences from it are
        # intentional: proxies/groups come from the subscription (no xray
        # sidecar); no ads, geo, or Iran/CN bypass rules are emitted.
        config: Dict[str, Any] = {
            "mixed-port": 7890,
            "allow-lan": self.allow_lan,
            # "*" by default (proxy-everything boundary serves LAN clients).
            "bind-address": "*" if self.allow_lan else "127.0.0.1",
            "mode": "rule",
            "geodata-mode": True,
            "log-level": "info",
            "ipv6": False,
            # No PROCESS-* rules remain (foreign server, no local sidecar),
            # so process lookup is off entirely instead of "always".
            "find-process-mode": "off",
            "tcp-concurrent": True,
            "keep-alive-interval": 30,
            "unified-delay": True,
            "external-controller": "127.0.0.1:9090",
            # Controller auth: emitted only when a secret is provided
            # (--controller-secret / MIHOMO_CONTROLLER_SECRET). Empty default
            # keeps the old no-auth behaviour.
            **({"secret": self.controller_secret} if self.controller_secret else {}),
            # Official Zashboard dashboard: served by mihomo itself at
            # http://127.0.0.1:9090/ui . "ui" is relative to the mihomo
            # working dir (mihomo -d <dir>); the zip below is fetched
            # automatically on first start into that folder.
            "external-ui": "ui",
            "external-ui-url": "https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages.zip",
            "profile": {
                "store-selected": True,
                "store-fake-ip": True,
            },
            "dns": {
                "enable": True,
                # 1053 avoids systemd-resolved/dnsmasq port-53 conflict;
                # with TUN enabled, dns-hijack (any:53) still intercepts all
                # port-53 queries and forwards them here, so fake-ip keeps
                # working. DNS stays loopback; LAN clients use TUN for DNS.
                "listen": "127.0.0.1:1053",
                "ipv6": False,
                "cache-algorithm": "arc",
                "cache-size": MIHOMO_CACHE_SIZE,
                "enhanced-mode": "fake-ip",
                "fake-ip-range": "198.18.0.1/16",
                "fake-ip-filter-mode": "blacklist",
                "fake-ip-filter": ["*.lan", "*.local", "localhost"],
                "respect-rules": True,
                "prefer-h3": False,
                # Minimal upstream: a single plain IP avoids DoH bootstrap
                # loops and keeps the "no custom DNS" intent (no resolvers
                # beyond a sane default).
                "nameserver": ["1.1.1.1"],
                "default-nameserver": ["1.1.1.1"],
                # respect-rules requires a non-empty proxy-server-nameserver
                # so proxy hostnames can resolve when routed through a proxy.
                "proxy-server-nameserver": ["1.1.1.1"],
            },
            "tun": {
                # Interface-only mode: the device is created but mihomo
                # injects NO routes (auto-route false), so the host default
                # route and local traffic stay untouched. Peer traffic is
                # steered into this device by external policy routing
                # (nft mark + ip rule, see tailnet setup scripts).
                "enable": self.tun_enabled,
                # mips: mihomo's own stack (upstream default/recommended);
                # fully userspace, no kernel interplay for routed-in packets.
                # Fallback is gvisor if mips ever misbehaves.
                "stack": "mips",
                "device": "mihomo",
                "auto-route": False,
                # Linux iptables/nftables auto redirect; keep false —
                # steering is done by our own nft+rule, not mihomo.
                "auto-redirect": False,
                "auto-detect-interface": True,
                "dns-hijack": ["any:53", "tcp://any:53"],
                "mtu": 1500,
                "gso": True,
                "gso-max-size": 65536,
                "strict-route": True,
                "endpoint-independent-nat": False,
                # Exclude private/LAN from TUN routing -> stays DIRECT and
                # avoids proxy loops (covers local upstream ports too).
                "route-exclude-address": [
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "224.0.0.0/4",
                    "240.0.0.0/4",
                ],
            },
            "sniffer": {
                "enable": True,
                "parse-pure-ip": True,
                "override-destination": False,
                "sniff": {
                    "TLS": {"ports": [443, 8443]},
                    "HTTP": {"ports": [80, "8080-8880"], "override-destination": True},
                    "QUIC": {"ports": [443]},
                },
                "force-domain": ["+.v2ex.com"],
                "skip-domain": ["Mijia Cloud"],
            },
            "proxies": clash_proxies,
            "proxy-groups": proxy_groups,
            "rules": rules,
        }
        return config

    @classmethod
    def _clash_rules(cls) -> List[str]:
        # First match wins — proxy-everything shape:
        # 0) private/LAN DIRECT, 1) MATCH,PROXY for everything else.
        # Ads REJECT, process bypasses and Iran/China geo bypasses are
        # intentionally gone: no local sidecar, exit outside both countries.
        rules: List[str] = [
            # 0) LAN / private bypass (Desktop pattern)
            "DOMAIN-SUFFIX,lan,DIRECT",
            "DOMAIN,lan,DIRECT",
            "DOMAIN-SUFFIX,local,DIRECT",
            "DOMAIN-SUFFIX,localhost,DIRECT",
            "DOMAIN-SUFFIX,localdomain,DIRECT",
        ]
        rules += [f"IP-CIDR,{c},DIRECT,no-resolve" for c in PRIVATE_CIDRS]
        rules += [f"IP-CIDR6,{c},DIRECT,no-resolve" for c in PRIVATE_CIDRS_V6]
        # 1) Everything else → PROXY via the MATCH,PROXY catch-all below
        # (ads REJECT and the foreign-service pin list were removed:
        # proxy-everything boundary, LAN/private DIRECT only).
        # 2) Final catch-all (everything else → PROXY)
        rules.append("MATCH,PROXY")
        return rules

    def _mihomo_country_groups(self, proxy_names: List[str]) -> List[Dict[str, Any]]:
        """Build per-country proxy groups for mihomo.

        Each country gets a select group plus url-test and fallback
        variants. The health-check URL is templated per country via
        CHECKER_URL_TEMPLATE; a node is kept only when the checker
        returns HTTP 200. Runtime health (not build-time probing) decides
        membership, so all usable nodes are emitted as candidates and
        url-test filters dead ones. Empty country groups are skipped.
        """
        groups: List[Dict[str, Any]] = []
        if not proxy_names:
            return groups
        for cc in COUNTRY_CODES:
            url = CHECKER_URL_TEMPLATE.format(cc=cc)
            # Collision guard: a proxy literally named like a group tag
            # (e.g. "US" or "US-Auto") must not shadow the group itself.
            reserved = {cc, f"{cc}-Auto", f"{cc}-Fallback", f"{cc}-auto"}
            members = [n for n in proxy_names if n not in reserved]
            if not members:
                continue
            groups.append(
                {
                    "name": cc,
                    "type": "select",
                    "proxies": [f"{cc}-Auto", f"{cc}-Fallback"] + members,
                }
            )
            groups.append(
                {
                    "name": f"{cc}-Auto",
                    "type": "url-test",
                    "proxies": members,
                    "url": url,
                    "interval": self.url_test_interval,
                    "tolerance": self.url_test_tolerance,
                    "lazy": True,
                    "expected-status": 200,
                    "max-failed-times": 3,
                }
            )
            groups.append(
                {
                    "name": f"{cc}-Fallback",
                    "type": "fallback",
                    "proxies": members,
                    "url": url,
                    "interval": self.url_test_interval,
                    "lazy": True,
                    "expected-status": 200,
                    "max-failed-times": 3,
                }
            )
        return groups

    def _mihomo_service_groups(self, proxy_names: List[str]) -> List[Dict[str, Any]]:
        """Build dedicated per-service proxy groups for mihomo.

        Each service gets a select group (manual pick) plus a url-test
        auto group. The auto group health-checks a strict service URL
        with expected-status 200, so only nodes that can reach that
        service survive. Full proxy list is used as candidates; lazy
        true limits health-check load to when the group is selected.
        Empty proxy list yields no groups.
        """
        groups: List[Dict[str, Any]] = []
        if not proxy_names:
            return groups
        for service in SERVICE_ORDER:
            url = SERVICE_HEALTH_URLS[service]
            members = list(proxy_names)
            groups.append(
                {
                    "name": service,
                    "type": "select",
                    "proxies": [f"{service}-Auto"] + members,
                }
            )
            groups.append(
                {
                    "name": f"{service}-Auto",
                    "type": "url-test",
                    "proxies": members,
                    "url": url,
                    "interval": self.url_test_interval,
                    "tolerance": self.url_test_tolerance,
                    "lazy": True,
                    "expected-status": 200,
                    "max-failed-times": 3,
                }
            )
        return groups

    def _mihomo_service_rules(self) -> List[str]:
        """Build service routing rules for mihomo.

        GEOSITE rules use community domain lists; DOMAIN-SUFFIX fallbacks
        cover services without a standard geosite entry (OpenCode) and
        provide resilience if geodata is unavailable. Rules are ordered
        before MATCH so they take precedence. LAN/private bypass stays
        first (handled by _clash_rules).
        """
        rules: List[str] = []
        # GEOSITE rules for services with standard categories.
        for service in SERVICE_ORDER:
            category = SERVICE_GEOSITE.get(service)
            if category:
                rules.append(f"GEOSITE,{category},{service}")
        # DOMAIN-SUFFIX fallbacks for core domains (resilience + services
        # without a geosite entry).
        for service in SERVICE_ORDER:
            for domain in SERVICE_DOMAIN_FALLBACK.get(service, []):
                rules.append(f"DOMAIN-SUFFIX,{domain},{service}")
        return rules




_BOOL_PLUGIN_OPTS = {"mux", "tls", "skip-cert-verify", "fast-open"}


def _parse_plugin_opts(opts: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for bit in opts.split(";"):
        if not bit:
            continue
        if "=" in bit:
            k, v = bit.split("=", 1)
            key = k.strip()
            val = v.strip()
            if key in _BOOL_PLUGIN_OPTS:
                val = val.lower() in ("1", "true", "yes", "on")
            result[key] = val
        else:
            result[bit.strip()] = True
    return result


def run(
    url: str = DEFAULT_SUBSCRIPTION_URL,
    urls: Optional[List[str]] = None,
    clash_out: str = "clash_config.yaml",
    tun_enabled: bool = False,
    allow_lan: bool = True,
    controller_secret: str = "",
    unique_host: bool = False,
) -> int:
    if urls is None:
        urls = [url]
    elif isinstance(urls, str):
        urls = [urls]
    if not urls:
        urls = [DEFAULT_SUBSCRIPTION_URL]

    downloader = SubscriptionDownloader()
    feed_contents: List[Tuple[str, str]] = []
    for feed_url in urls:
        try:
            feed_contents.append((feed_url, downloader.download_subscription(feed_url)))
        except Exception as exc:
            logger.warning("Skipping failed feed %s: %s", feed_url, exc)
    if not feed_contents:
        logger.error("No subscriptions could be downloaded")
        return 1

    if len(feed_contents) == 1:
        # Legacy single-feed path: behavior and logs byte-identical.
        url, content = feed_contents[0]
        title = downloader.last_title
        logger.info("Subscription title: %s", title or "(none)")

        parser = ProxyParser(unique_host=unique_host)
        proxies = parser.parse_subscription_content(content)
        if not proxies:
            logger.error("No proxies parsed from subscription")
            return 1
        if unique_host:
            logger.info(
                "Unique-host dedup: %d unique, %d host duplicates skipped",
                len(proxies),
                parser.host_dup,
            )
    else:
        # Multi-feed path: parse per feed for counts, then aggregate and
        # dedup over the merged pool (never per-feed).
        per_feed: List[Tuple[str, int, int]] = []
        merged: List[ProxyConfig] = []
        for feed_url, content in feed_contents:
            feed_parser = ProxyParser(unique_host=False)
            parsed = feed_parser.parse_subscription_content(content)
            per_feed.append((feed_url, len(content), len(parsed)))
            merged.extend(parsed)
        for feed_url, nbytes, nparsed in per_feed:
            logger.info("Feed %s: %d bytes, %d parsed", feed_url, nbytes, nparsed)
        proxies = merged
        if unique_host:
            proxies, host_dup = _dedup_by_host(merged)
            logger.info(
                "Unique-host dedup over merged pool: %d unique, "
                "%d host duplicates skipped",
                len(proxies),
                host_dup,
            )
        else:
            logger.info("Merged %d feeds: %d proxies", len(feed_contents), len(proxies))
        if not proxies:
            logger.error("No proxies parsed from subscriptions")
            return 1
        title = downloader.last_title
        logger.info("Subscription title: %s", title or "(none)")
        url = feed_contents[0][0]

    generator = ConfigGenerator(
        tun_enabled=tun_enabled,
        allow_lan=allow_lan,
        controller_secret=controller_secret,
    )
    generator.subscription_title = title


    clash_config = generator.generate_clash_config(proxies)
    header_lines = []
    if title:
        header_lines.append(f"# profile-title: {title}")
        header_lines.append(f"# profile-web-page-url: {url.split('#', 1)[0]}")
        header_lines.append("# profile-update-interval: 1")
    body = yaml.dump(
        clash_config,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=4096,
    )
    text = ("\n".join(header_lines) + "\n" if header_lines else "") + body
    with open(clash_out, "w", encoding="utf-8") as fh:
        fh.write(text)
    logger.info(
        "Generated Clash config %s with %d proxies / %d groups",
        clash_out,
        len(clash_config.get("proxies", [])),
        len(clash_config.get("proxy-groups", [])),
    )

    return 0


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Parse V2Ray subscription links into Clash (mihomo) config"
    )
    ap.add_argument(
        "urls",
        nargs="*",
        default=[DEFAULT_SUBSCRIPTION_URL],
        help="Subscription URL(s) (fragment #Name becomes profile title)",
    )
    ap.add_argument("--clash-out", default="clash_config.yaml")
    ap.add_argument(
        "--tun",
        action="store_true",
        help="Enable TUN inbound (needs root/CAP_NET_ADMIN; off by default)",
    )
    ap.add_argument(
        "--allow-lan",
        action="store_true",
        default=True,
        help="Allow LAN connections and bind to all interfaces (on by default)",
    )
    # --allow-lan defaults True for backward compatibility.
    # --no-allow-lan shares dest allow_lan and flips it to False for loopback only.
    # LAN off binds 127.0.0.1 only with no external exposure and TUN stays off unless --tun is passed.
    ap.add_argument(
        "--no-allow-lan",
        dest="allow_lan",
        action="store_false",
        help="Disable LAN listen and bind to 127.0.0.1 only",
    )
    ap.add_argument(
        "--controller-secret",
        default=os.environ.get("MIHOMO_CONTROLLER_SECRET", ""),
        help="mihomo external-controller secret (or set MIHOMO_CONTROLLER_SECRET env). Empty = no auth (default).",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument(
        "--unique-host",
        action="store_true",
        default=False,
        help="Keep only the first proxy per server host.",
    )
    args = ap.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    raise SystemExit(
        run(
            urls=args.urls,
            clash_out=args.clash_out,
            tun_enabled=args.tun,
            allow_lan=args.allow_lan,
            controller_secret=args.controller_secret,
            unique_host=args.unique_host,
        )
    )


if __name__ == "__main__":
    main()
