#!/usr/bin/env python3
"""V2Ray Subscription Link Parser and Configuration Generator.

Downloads subscription links, parses share-link formats (aligned with
v2rayNG / v2rayN / Xray share-link conventions), and generates complete
mihomo (Clash.Meta) and sing-box configurations.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_SUBSCRIPTION_URL = (
    "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt#Patterniha-F"
)

# ---------------------------------------------------------------------------
# Shared bypass policy.
#
# Mirrors /home/mohammad/Desktop/mihomo usage (mihomo as TUN + Fake-IP +
# DNS-hijack front-end): private/LAN always DIRECT, Iranian sites/IPs always
# DIRECT, everything else goes through the subscription proxies. No xray
# sidecar needed — mihomo/sing-box dial the nodes directly.
# ---------------------------------------------------------------------------

# Processes that must never be routed back into the tunnel (loop avoidance).
# Covers the legacy xray/PattN sidecar if still running, plus our own cores.
LOOPBACK_PROCESS_NAMES = ["xray", "sing-box", "PattN", "v2rayn"]
LOOPBACK_PROCESS_PATHS = [
    "/home/mohammad/.local/share/v2rayN/bin/xray/xray",
    "/home/mohammad/.local/share/v2rayN/bin/sing_box/sing-box",
    "/opt/v2rayN/PattN",
]

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

# Iranian infrastructure that must bypass the proxy (domain suffixes).
IRAN_DIRECT_SUFFIXES = [
    ".ir",
    "digikala.com",
    "digikalaelectron.com",
    "digimah.com",
    "digikala.tm",
    "snappfood.com",
    "parspack.com",
    "hostiran.net",
    "arvancloud.com",
    "iraniancdns.com",
    "parsdata.com",
    "idehpay.com",
]

# Chinese infrastructure that must bypass the proxy.
CN_DIRECT_SUFFIXES = [
    ".cn",
    "aliyun.com",
    "taobao.com",
    "tmail.com",
    "tmall.com",
    "alipay.com",
    "qq.com",
    "weixin.qq.com",
    "gtimg.com",
    "myqcloud.com",
    "baidu.com",
    "bdstatic.com",
    "bilibili.com",
    "hdslb.com",
    "iqiyi.com",
    "sohu.com",
    "sina.com.cn",
    "163.com",
    "126.net",
    "netease.com",
    "jd.com",
    "360.cn",
    "sogou.com",
    "weibo.com",
    "zhihu.com",
]

# Domains that must resolve to real IPs (never fake-ip): LAN + NTP + probes.
REALIP_SUFFIXES = [
    "*.lan",
    "*.local",
    "localhost.ptlogin2.qq.com",
    "+.msftconnecttest.com",
    "+.msftncsi.com",
    "time.*.com",
    "time.*.gov",
    "time.*.edu.cn",
    "+.ntp.org.cn",
    "+.pool.ntp.org",
    "detectportal.firefox.com",
    "connectivitycheck.gstatic.com",
]

# Trackers/ads rejected before anything else.
ADS_REJECT_SUFFIXES = [
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "googletagmanager.com",
    "googletagservices.com",
    "tracking.pro",
    "scorecardresearch.com",
    "adnxs.com",
    "adsrvr.org",
    "advertising.com",
    "amazon-adsystem.com",
]

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


def _parse_bool(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _ws_early_data(path: Optional[str]) -> Tuple[Optional[str], Optional[int], Optional[str]]:
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


class ProxyParser:
    """Parses share-link formats (v2rayNG / v2rayN / Xray conventions)."""

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
    def _name_from(parsed: urllib.parse.ParseResult, default: str, params: Dict[str, List[str]]) -> str:
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
        cfg.pbk = get("pbk") or get("publicKey") or get("public-key")
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
            security="tls" if str(data.get("tls") or "").lower().endswith("tls") else (
                "reality" if str(data.get("tls") or "").lower() == "reality" else ""
            ),
            sni=str(data.get("sni") or "") or None,
            alpn=str(data.get("alpn") or "") or None,
            fp=str(data.get("fp") or "") or None,
            insecure=_parse_bool(str(data.get("insecure") or data.get("allowInsecure") or "")),
            pbk=str(data.get("pbk") or "") or None,
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
            cfg.security = "none" if security == "none" else (
                "reality" if security == "reality" else "tls"
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

        hostport = urllib.parse.unquote(hostport)
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

        return ShadowsocksConfig(
            name=name,
            server=server,
            port=port,
            protocol="shadowsocks",
            method=urllib.parse.unquote(method),
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

        cfg.congestion_control = get("congestion_control") or get("congestion-control") or "cubic"
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
    """Generates complete mihomo (Clash.Meta) and sing-box configurations."""

    def __init__(
        self,
        tun_enabled: bool = False,
        allow_lan: bool = False,
        controller_secret: str = "",
    ) -> None:
        self.url_test_url = "https://www.gstatic.com/generate_204"
        self.url_test_interval = 300
        self.url_test_tolerance = 50
        self.subscription_title: Optional[str] = None
        # TUN is opt-in (needs root/CAP_NET_ADMIN); loopback-only by default.
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
            if cfg.sid is not None:
                reality["short-id"] = _QuotedStr(cfg.sid)
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
            logger.debug("Transport %s not supported by mihomo export; using tcp", network)
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

        if isinstance(proxy, VMessConfig):
            base["type"] = "vmess"
            base["uuid"] = proxy.uuid
            base["alterId"] = proxy.alterId
            base["cipher"] = proxy.cipher or "auto"
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
                    base["plugin-opts"] = _parse_plugin_opts(proxy.plugin_opts)
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
                base["fingerprint"] = fp
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
        used: set = set()

        for i, proxy in enumerate(proxies):
            raw_name = proxy.name or f"{proxy.protocol}-{i}"
            name = _unique_name(raw_name, used)
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
            proxy_groups.extend(
                [
                    {
                        "name": "PROXY",
                        "type": "select",
                        "proxies": ["Auto", "Load Balance", "Fallback"] + proxy_names,
                        "icon": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/mmdb/release/flag/Country-IR.svg",
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
            proxy_groups.append({"name": "PROXY", "type": "select", "proxies": ["DIRECT"]})

        rules = self._clash_rules()

        # NOTE: field-for-field aligned with /home/mohammad/Desktop/mihomo
        # config.yaml (verified mihomo v1.19.31 setup). Differences from it are
        # intentional: proxies/groups come from the subscription (no xray
        # sidecar), and Iran/CN bypass rules are added.
        config: Dict[str, Any] = {
            "mixed-port": 7890,
            "allow-lan": self.allow_lan,
            # Loopback-only by default; "*" only when LAN access is opted in.
            "bind-address": "*" if self.allow_lan else "127.0.0.1",
            "mode": "rule",
            "log-level": "info",
            "ipv6": False,
            # "always" is required for PROCESS-NAME/PATH rules; strict may
            # skip them, off disables them entirely.
            "find-process-mode": "always",
            "tcp-concurrent": True,
            "keep-alive-interval": 30,
            "unified-delay": True,
            "external-controller": "127.0.0.1:9090",
            # Controller auth: emitted only when a secret is provided
            # (--controller-secret / MIHOMO_CONTROLLER_SECRET). Empty default
            # keeps the old no-auth behaviour.
            **({"secret": self.controller_secret} if self.controller_secret else {}),
            # Official MetaCubeX dashboard (metacubexd): served by mihomo
            # itself at http://127.0.0.1:9090/ui . "ui" is relative to the
            # mihomo working dir (mihomo -d <dir>); the zip below is fetched
            # automatically on first start into that folder.
            "external-ui": "ui",
            "external-ui-url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
            "geox-url": {
                "geoip": "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
                "geosite": "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
                "mmdb": "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb",
            },
            "geo-auto-update": True,
            "geo-update-interval": 24,
            "profile": {
                "store-selected": True,
                "store-fake-ip": True,
            },
            "dns": {
                "enable": True,
                # 1053 avoids systemd-resolved/dnsmasq port-53 conflict;
                # with TUN enabled, dns-hijack (any:53) still intercepts all
                # port-53 queries and forwards them here, so fake-ip keeps
                # working. Loopback-only; LAN needs --allow-lan + TUN.
                "listen": "127.0.0.1:1053",
                "ipv6": False,
                "cache-algorithm": "arc",
                "enhanced-mode": "fake-ip",
                "fake-ip-range": "198.18.0.1/16",
                "fake-ip-filter-mode": "blacklist",
                "fake-ip-filter": list(REALIP_SUFFIXES),
                # Plain IPs only: used to resolve DoH/DoT hostnames themselves.
                "default-nameserver": ["223.5.5.5", "114.114.114.114", "8.8.8.8"],
                "nameserver": [
                    "https://doh.pub/dns-query",
                    "https://dns.alidns.com/dns-query",
                    "tls://8.8.8.8",
                    "223.5.5.5",
                ],
                "proxy-server-nameserver": ["https://doh.pub/dns-query"],
                "fallback": ["tls://1.1.1.1", "tls://8.8.4.4"],
                "fallback-filter": {
                    "geoip": True,
                    "geoip-code": "CN",
                    "ipcidr": ["240.0.0.0/4"],
                    "domain": [
                        "+.google.com",
                        "+.facebook.com",
                        "+.youtube.com",
                        "+.twitter.com",
                    ],
                },
                "nameserver-policy": {
                    "geosite:category-ads-all": "rcode://success",
                    "+.ir": "https://dns.alidns.com/dns-query",
                },
            },
            "tun": {
                # Opt-in via --tun (needs root/CAP_NET_ADMIN).
                "enable": self.tun_enabled,
                # mixed: TCP via system stack, UDP via gvisor (recommended).
                "stack": "mixed",
                "device": "mihomo",
                "auto-route": True,
                # Linux iptables/nftables auto redirect; keep false on a
                # desktop (auto-route alone is enough), true on routers.
                "auto-redirect": False,
                "auto-detect-interface": True,
                "dns-hijack": ["any:53", "tcp://any:53"],
                "mtu": 9000,
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
        # First match wins — order mirrors Desktop/mihomo usage:
        # 0) loop avoidance, 1) private/LAN, 2) ads, 3) Iran bypass,
        # 4) CN bypass, 5) foreign → PROXY, 6) geo fallbacks, 7) MATCH.
        rules: List[str] = [
            # 0) Bypass proxy/helper processes to avoid routing loops.
            # (Covers the legacy xray/PattN sidecar if still running, and
            # our own cores. Requires find-process-mode: always.)
            "PROCESS-NAME,xray,DIRECT",
            "PROCESS-NAME,sing-box,DIRECT",
            "PROCESS-NAME,PattN,DIRECT",
            "PROCESS-NAME,v2rayn,DIRECT",
            "PROCESS-PATH,/home/mohammad/.local/share/v2rayN/bin/xray/xray,DIRECT",
            "PROCESS-PATH,/home/mohammad/.local/share/v2rayN/bin/sing_box/sing-box,DIRECT",
            "PROCESS-PATH,/opt/v2rayN/PattN,DIRECT",
            "PROCESS-NAME-WILDCARD,*sing-box*,DIRECT",
            "PROCESS-NAME-REGEX,(?i)v2ray.*|PattN,DIRECT",
            # 1) LAN / private bypass (Desktop pattern)
            "DOMAIN-SUFFIX,lan,DIRECT",
            "DOMAIN,lan,DIRECT",
            "GEOIP,private,DIRECT,no-resolve",
            "GEOIP,lan,DIRECT,no-resolve",
            "DOMAIN-SUFFIX,local,DIRECT",
            "DOMAIN-SUFFIX,localhost,DIRECT",
            "DOMAIN-SUFFIX,localdomain,DIRECT",
        ]
        rules += [f"IP-CIDR,{c},DIRECT,no-resolve" for c in PRIVATE_CIDRS]
        rules += [f"IP-CIDR6,{c},DIRECT,no-resolve" for c in PRIVATE_CIDRS_V6]
        # 2) Ads / trackers
        rules += [f"DOMAIN-SUFFIX,{d},REJECT" for d in ADS_REJECT_SUFFIXES]
        rules.append("DOMAIN-KEYWORD,analytics,REJECT")
        # 3) Iran bypass: sites + IPs
        rules += [f"DOMAIN-SUFFIX,{d.lstrip('.')},DIRECT" for d in IRAN_DIRECT_SUFFIXES]
        rules.append("GEOIP,IR,DIRECT")
        # 4) China bypass: sites + IPs
        rules += [f"DOMAIN-SUFFIX,{d.lstrip('.')},DIRECT" for d in CN_DIRECT_SUFFIXES]
        rules.append("GEOIP,CN,DIRECT")
        # 5) Foreign services → PROXY
        rules += [
            "DOMAIN-SUFFIX,google.com,PROXY",
            "DOMAIN-SUFFIX,googleapis.com,PROXY",
            "DOMAIN-SUFFIX,gstatic.com,PROXY",
            "DOMAIN-SUFFIX,googleusercontent.com,PROXY",
            "DOMAIN-SUFFIX,ggpht.com,PROXY",
            "DOMAIN-SUFFIX,youtube.com,PROXY",
            "DOMAIN-SUFFIX,youtu.be,PROXY",
            "DOMAIN-SUFFIX,ytimg.com,PROXY",
            "DOMAIN-SUFFIX,googlevideo.com,PROXY",
            "DOMAIN-SUFFIX,facebook.com,PROXY",
            "DOMAIN-SUFFIX,facebook.net,PROXY",
            "DOMAIN-SUFFIX,fbcdn.net,PROXY",
            "DOMAIN-SUFFIX,instagram.com,PROXY",
            "DOMAIN-SUFFIX,whatsapp.com,PROXY",
            "DOMAIN-SUFFIX,whatsapp.net,PROXY",
            "DOMAIN-SUFFIX,thread.com,PROXY",
            "DOMAIN-SUFFIX,twitter.com,PROXY",
            "DOMAIN-SUFFIX,x.com,PROXY",
            "DOMAIN-SUFFIX,t.co,PROXY",
            "DOMAIN-SUFFIX,twimg.com,PROXY",
            "DOMAIN-SUFFIX,telegram.org,PROXY",
            "DOMAIN-SUFFIX,telegram.me,PROXY",
            "DOMAIN-SUFFIX,t.me,PROXY",
            "DOMAIN-SUFFIX,tdesktop.com,PROXY",
            "DOMAIN-SUFFIX,telegra.ph,PROXY",
            "DOMAIN-KEYWORD,t.me,PROXY",
            "DOMAIN-SUFFIX,spotify.com,PROXY",
            "DOMAIN-SUFFIX,scdn.co,PROXY",
            "DOMAIN-SUFFIX,github.com,PROXY",
            "DOMAIN-SUFFIX,githubusercontent.com,PROXY",
            "DOMAIN-SUFFIX,github.io,PROXY",
            "DOMAIN-SUFFIX,gitlab.com,PROXY",
            "DOMAIN-SUFFIX,openai.com,PROXY",
            "DOMAIN-SUFFIX,chatgpt.com,PROXY",
            "DOMAIN-SUFFIX,oaiusercontent.com,PROXY",
            "DOMAIN-SUFFIX,anthropic.com,PROXY",
            "DOMAIN-SUFFIX,claude.ai,PROXY",
            "DOMAIN-SUFFIX,gemini.google.com,PROXY",
            "DOMAIN-SUFFIX,netflix.com,PROXY",
            "DOMAIN-SUFFIX,nflxvideo.net,PROXY",
            "DOMAIN-SUFFIX,nflximg.net,PROXY",
            "DOMAIN-SUFFIX,nflxso.net,PROXY",
            "DOMAIN-SUFFIX,twitch.tv,PROXY",
            "DOMAIN-SUFFIX,ttvnw.net,PROXY",
            "DOMAIN-SUFFIX,discord.com,PROXY",
            "DOMAIN-SUFFIX,discordapp.com,PROXY",
            "DOMAIN-SUFFIX,discord.gg,PROXY",
            "DOMAIN-SUFFIX,discord.media,PROXY",
            "DOMAIN-SUFFIX,reddit.com,PROXY",
            "DOMAIN-SUFFIX,redd.it,PROXY",
            "DOMAIN-SUFFIX,redditstatic.com,PROXY",
            "DOMAIN-SUFFIX,redditmedia.com,PROXY",
            "DOMAIN-SUFFIX,pinterest.com,PROXY",
            "DOMAIN-SUFFIX,pinimg.com,PROXY",
            "DOMAIN-SUFFIX,tiktok.com,PROXY",
            "DOMAIN-SUFFIX,tiktokv.com,PROXY",
            "DOMAIN-SUFFIX,tiktokcdn.com,PROXY",
            "DOMAIN-SUFFIX,byteoversea.com,PROXY",
            "DOMAIN-SUFFIX,medium.com,PROXY",
            "DOMAIN-SUFFIX,wikipedia.org,PROXY",
            "DOMAIN-SUFFIX,wikimedia.org,PROXY",
            "DOMAIN-SUFFIX,wikiwand.com,PROXY",
            "DOMAIN-SUFFIX,cloudflare.com,PROXY",
            "DOMAIN-SUFFIX,workers.dev,PROXY",
            "DOMAIN-SUFFIX,pages.dev,PROXY",
            "DOMAIN-SUFFIX,reg.cloudflare.com,PROXY",
            "DOMAIN-SUFFIX,v2ex.com,PROXY",
            "DOMAIN-SUFFIX,duckduckgo.com,PROXY",
            "DOMAIN-SUFFIX,bing.com,PROXY",
            "DOMAIN-SUFFIX,microsoft.com,PROXY",
            "DOMAIN-SUFFIX,office.com,PROXY",
            "DOMAIN-SUFFIX,office365.com,PROXY",
            "DOMAIN-SUFFIX,outlook.com,PROXY",
            "DOMAIN-SUFFIX,msn.com,PROXY",
            "DOMAIN-SUFFIX,dropbox.com,PROXY",
            "DOMAIN-SUFFIX,icloud.com,PROXY",
            "DOMAIN-SUFFIX,apple.com,PROXY",
            "DOMAIN-SUFFIX,aaplimg.com,PROXY",
            "DOMAIN-SUFFIX,amazon.com,PROXY",
            "DOMAIN-SUFFIX,amazonaws.com,PROXY",
            "DOMAIN-SUFFIX,steamcommunity.com,PROXY",
            "DOMAIN-SUFFIX,steampowered.com,PROXY",
            "DOMAIN-SUFFIX,store.steampowered.com,PROXY",
            "DOMAIN-SUFFIX,signal.org,PROXY",
            "DOMAIN-SUFFIX,whispersystems.org,PROXY",
            "DOMAIN-SUFFIX,protonmail.com,PROXY",
            "DOMAIN-SUFFIX,proton.me,PROXY",
            "DOMAIN-SUFFIX,tailscale.com,PROXY",
            "DOMAIN-SUFFIX,speedtest.net,PROXY",
            "DOMAIN-SUFFIX,fast.com,PROXY",
        ]
        # 6) Final catch-all (Desktop pattern: everything else → PROXY)
        rules.append("MATCH,PROXY")
        return rules

    # ------------------------------------------------------------------
    # sing-box
    # ------------------------------------------------------------------
    @staticmethod
    def _singbox_tls(cfg: ProxyConfig) -> Optional[Dict[str, Any]]:
        if not cfg.security:
            return None
        tls: Dict[str, Any] = {"enabled": True}
        tls["server_name"] = cfg.sni or cfg.server
        if cfg.insecure:
            tls["insecure"] = True
        alpn = _split_alpn(cfg.alpn)
        if alpn:
            tls["alpn"] = alpn
        fp = _normalize_fingerprint(cfg.fp)
        if fp and fp not in ("none",):
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        elif fp == "none":
            pass
        if cfg.security == "reality" and cfg.pbk:
            reality: Dict[str, Any] = {"enabled": True, "public_key": cfg.pbk}
            if cfg.sid is not None:
                reality["short_id"] = cfg.sid
            tls["reality"] = reality
        return tls

    @staticmethod
    def _singbox_transport(cfg: ProxyConfig) -> Optional[Dict[str, Any]]:
        network = (cfg.network or "tcp").lower()
        if network == "tcp":
            if (cfg.header_type or "").lower() == "http":
                return {
                    "type": "http",
                    "host": [cfg.host] if cfg.host else [],
                    "path": cfg.path or "/",
                }
            return None
        if network in ("ws", "websocket"):
            clean, ed, eh = _ws_early_data(cfg.path)
            transport: Dict[str, Any] = {"type": "ws", "path": clean or "/"}
            if cfg.host:
                transport["headers"] = {"Host": cfg.host}
            if ed is not None:
                transport["max_early_data"] = ed
                if eh:
                    transport["early_data_header_name"] = eh
            return transport
        if network in ("h2", "http2"):
            transport = {"type": "http", "path": cfg.path or "/"}
            if cfg.host:
                transport["host"] = [cfg.host]
            return transport
        if network == "http" and (cfg.header_type or "").lower() == "http":
            return {
                "type": "http",
                "host": [cfg.host] if cfg.host else [],
                "path": cfg.path or "/",
            }
        if network == "grpc":
            return {
                "type": "grpc",
                "service_name": cfg.service_name or cfg.path or "GunService",
            }
        if network == "httpupgrade":
            transport = {"type": "httpupgrade", "path": cfg.path or "/"}
            if cfg.host:
                transport["host"] = cfg.host
            return transport
        if network in ("quic",):
            return {"type": "quic"}
        if network == "xhttp":
            # sing-box has no xhttp transport; fall back to ws when possible
            logger.debug("xhttp not supported by sing-box; emitting without transport")
            return None
        return None

    def _singbox_outbound(self, proxy: ProxyConfig, tag: str) -> Optional[Dict[str, Any]]:
        outbound: Dict[str, Any] = {
            "tag": tag,
            "server": proxy.server,
            "server_port": proxy.port,
        }

        if isinstance(proxy, VMessConfig):
            outbound["type"] = "vmess"
            outbound["uuid"] = proxy.uuid
            outbound["alter_id"] = proxy.alterId
            outbound["security"] = proxy.cipher or "auto"
            if proxy.packet_encoding:
                pe = proxy.packet_encoding.lower()
                if pe in ("xudp", "packetaddr", "packet"):
                    outbound["packet_encoding"] = "xudp" if pe == "xudp" else "packetaddr"
        elif isinstance(proxy, VLESSConfig):
            outbound["type"] = "vless"
            outbound["uuid"] = proxy.uuid
            if proxy.flow:
                outbound["flow"] = proxy.flow
            if proxy.packet_encoding:
                pe = proxy.packet_encoding.lower()
                if pe == "xudp":
                    outbound["packet_encoding"] = "xudp"
                elif pe in ("packet", "packetaddr"):
                    outbound["packet_encoding"] = "packetaddr"
        elif isinstance(proxy, TrojanConfig):
            outbound["type"] = "trojan"
            outbound["password"] = proxy.password
        elif isinstance(proxy, ShadowsocksConfig):
            outbound["type"] = "shadowsocks"
            outbound["method"] = proxy.method
            outbound["password"] = proxy.password
            if proxy.plugin:
                outbound["plugin"] = proxy.plugin
                if proxy.plugin_opts:
                    outbound["plugin_opts"] = proxy.plugin_opts
        elif isinstance(proxy, Hysteria2Config):
            outbound["type"] = "hysteria2"
            outbound["password"] = proxy.password
            tls = self._singbox_tls(proxy) or {"enabled": True, "server_name": proxy.sni or proxy.server}
            if proxy.insecure:
                tls["insecure"] = True
            outbound["tls"] = tls
            if proxy.obfs:
                outbound["obfs"] = {"type": proxy.obfs, "password": proxy.obfs_password or ""}
            if proxy.up:
                outbound["up_mbps"] = _mbps(proxy.up)
            if proxy.down:
                outbound["down_mbps"] = _mbps(proxy.down)
            if proxy.ports:
                outbound["server_ports"] = _server_ports(proxy.ports)
                outbound["hop_interval"] = proxy.hop_interval or 30
            return outbound
        elif isinstance(proxy, HysteriaConfig):
            outbound["type"] = "hysteria"
            if proxy.auth:
                if proxy.auth_base64:
                    outbound["auth"] = proxy.auth
                else:
                    outbound["auth_str"] = proxy.auth
            outbound["up_mbps"] = _mbps(proxy.up) or 100
            outbound["down_mbps"] = _mbps(proxy.down) or 100
            tls = self._singbox_tls(proxy) or {"enabled": True, "server_name": proxy.sni or proxy.server}
            if proxy.insecure:
                tls["insecure"] = True
            if proxy.obfs:
                outbound["obfs"] = proxy.obfs
            outbound["tls"] = tls
            if proxy.ports:
                outbound["server_ports"] = _server_ports(proxy.ports)
            return outbound
        elif isinstance(proxy, TUICConfig):
            outbound["type"] = "tuic"
            if proxy.token and not proxy.uuid:
                outbound["token"] = proxy.token
            else:
                outbound["uuid"] = proxy.uuid
                outbound["password"] = proxy.password
            outbound["congestion_control"] = proxy.congestion_control
            outbound["udp_relay_mode"] = proxy.udp_relay_mode
            tls = self._singbox_tls(proxy) or {"enabled": True, "server_name": proxy.sni or proxy.server}
            if proxy.insecure:
                tls["insecure"] = True
            alpn = _split_alpn(proxy.alpn)
            if alpn:
                tls["alpn"] = alpn
            outbound["tls"] = tls
            return outbound
        elif isinstance(proxy, SocksConfig):
            outbound["type"] = "socks"
            if proxy.username:
                outbound["username"] = proxy.username
            if proxy.password:
                outbound["password"] = proxy.password
            return outbound
        else:
            return None

        transport = self._singbox_transport(proxy)
        if transport:
            outbound["transport"] = transport
        tls = self._singbox_tls(proxy)
        if tls:
            outbound["tls"] = tls
        return outbound

    def generate_singbox_config(self, proxies: List[ProxyConfig]) -> Dict[str, Any]:
        outbounds: List[Dict[str, Any]] = []
        proxy_tags: List[str] = []
        used: set = set()

        # Explicit direct outbound (referenced by rules / final)
        outbounds.append({"type": "direct", "tag": "direct"})

        for i, proxy in enumerate(proxies):
            raw = proxy.name or f"proxy-{i}"
            tag = _unique_name(raw, used)
            try:
                outbound = self._singbox_outbound(proxy, tag)
            except Exception as exc:
                logger.error("Failed to convert %r to sing-box: %s", raw, exc)
                continue
            if outbound:
                outbounds.append(outbound)
                proxy_tags.append(tag)

        if proxy_tags:
            outbounds.append(
                {
                    "type": "urltest",
                    "tag": "auto",
                    "outbounds": proxy_tags,
                    "url": self.url_test_url,
                    "interval": "5m",
                    "tolerance": self.url_test_tolerance,
                }
            )

        inbounds = [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 10808,
            },
        ]
        if self.tun_enabled:
            # Opt-in via --tun (needs root/CAP_NET_ADMIN). sing-box
            # inbounds have no "enabled" flag, so TUN is only emitted
            # when requested.
            inbounds.append(
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "mihomo",
                    # Outside the fake-ip pool (198.18.0.0/15) to avoid overlap.
                    "address": ["172.19.0.1/30"],
                    # mixed: TCP via system stack, UDP via gvisor (recommended).
                    "stack": "mixed",
                    "mtu": 9000,
                    "auto_route": True,
                    "strict_route": True,
                    # Exclude private/LAN from TUN routing -> stays DIRECT and
                    # avoids proxy loops (mirrors mihomo route-exclude-address).
                    "route_exclude_address": PRIVATE_CIDRS + PRIVATE_CIDRS_V6,
                    "endpoint_independent_nat": False,
                    "udp_timeout": "5m",
                }
            )

        final = "auto" if proxy_tags else "direct"
        # Mirrors the mihomo rule order: loop avoidance → private →
        # Iran bypass → MATCH (final). sing-box `geoip` is deprecated in
        # favor of rule-sets, so Iran/IP bypass here is domain_suffix +
        # ip_is_private based (no downloads needed).
        rules: List[Dict[str, Any]] = [
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
            {
                "action": "route",
                "outbound": "direct",
                "process_name": LOOPBACK_PROCESS_NAMES,
            },
            {
                "action": "route",
                "outbound": "direct",
                "process_path_regex": ["(?i)v2ray.*|PattN", ".*sing-box.*"],
            },
            {
                "action": "route",
                "outbound": "direct",
                "ip_is_private": True,
            },
            {
                "action": "route",
                "outbound": "direct",
                "domain_suffix": IRAN_DIRECT_SUFFIXES + CN_DIRECT_SUFFIXES,
            },
            {
                "action": "reject",
                "domain_suffix": [d.lstrip("+") for d in ADS_REJECT_SUFFIXES],
            },
        ]

        # Fake-IP by default (like mihomo enhanced-mode: fake-ip): hijacked
        # DNS gets fake IPs via the query_type rule; LAN/NTP/Iran/CN get
        # real IPs from dns-direct. `final` must be a real resolver —
        # sing-box forbids fakeip as the default server.
        realip_suffixes = [
            ".lan",
            ".local",
            ".localhost",
            ".localdomain",
            "localhost.ptlogin2.qq.com",
            "msftconnecttest.com",
            "msftncsi.com",
            "ntp.org.cn",
            "pool.ntp.org",
            "detectportal.firefox.com",
            "connectivitycheck.gstatic.com",
        ]
        config: Dict[str, Any] = {
            "log": {"level": "info", "timestamp": True},
            "dns": {
                "servers": [
                    {
                        "type": "fakeip",
                        "tag": "dns-fakeip",
                        "inet4_range": "198.18.0.0/15",
                    },
                    {
                        "type": "udp",
                        "server": "223.5.5.5",
                        "tag": "dns-direct",
                    },
                    {
                        "type": "tls",
                        "server": "8.8.8.8",
                        "tag": "dns-remote",
                    },
                    {
                        "type": "https",
                        "server": "doh.pub",
                        "tag": "dns-doh",
                        "path": "/dns-query",
                        # DoH hostname itself must resolve via a plain-IP
                        # server (mirrors mihomo default-nameserver).
                        "domain_resolver": "dns-direct",
                    },
                    {
                        "type": "local",
                        "tag": "dns-local",
                    },
                ],
                "rules": [
                    {
                        "action": "route",
                        "server": "dns-direct",
                        "domain_suffix": realip_suffixes,
                    },
                    {
                        "action": "route",
                        "server": "dns-direct",
                        "domain_suffix": IRAN_DIRECT_SUFFIXES + CN_DIRECT_SUFFIXES,
                    },
                    {
                        "action": "route",
                        "server": "dns-fakeip",
                        "query_type": ["A", "AAAA"],
                    },
                ],
                "final": "dns-doh",
                "strategy": "prefer_ipv4",
                "independent_cache": True,
            },
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {
                "rules": rules,
                "final": final,
                "auto_detect_interface": True,
                # Must be a REAL resolver (not fakeip): used to resolve
                # proxy node domain names (SNI/host).
                "default_domain_resolver": "dns-direct",
            },
        }
        return config


def _mbps(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    m = re.search(r"(\d+)", str(value))
    return int(m.group(1)) if m else None


def _server_ports(spec: str) -> List[str]:
    """Convert mport style '2000,3000-4000' to sing-box server_ports strings."""
    out: List[str] = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        out.append(part)
    return out


def _parse_plugin_opts(opts: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for bit in opts.split(";"):
        if not bit:
            continue
        if "=" in bit:
            k, v = bit.split("=", 1)
            result[k.strip()] = v.strip()
        else:
            result[bit.strip()] = True
    return result


def run(
    url: str = DEFAULT_SUBSCRIPTION_URL,
    clash_out: str = "clash_config.yaml",
    singbox_out: str = "singbox_config.json",
    outputs: str = "both",
    tun_enabled: bool = False,
    allow_lan: bool = False,
    controller_secret: str = "",
) -> int:
    downloader = SubscriptionDownloader()
    content = downloader.download_subscription(url)
    title = downloader.last_title
    logger.info("Subscription title: %s", title or "(none)")

    parser = ProxyParser()
    proxies = parser.parse_subscription_content(content)
    if not proxies:
        logger.error("No proxies parsed from subscription")
        return 1

    generator = ConfigGenerator(
        tun_enabled=tun_enabled,
        allow_lan=allow_lan,
        controller_secret=controller_secret,
    )
    generator.subscription_title = title

    if outputs in ("clash", "both"):
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

    if outputs in ("singbox", "both"):
        singbox_config = generator.generate_singbox_config(proxies)
        with open(singbox_out, "w", encoding="utf-8") as fh:
            json.dump(singbox_config, fh, indent=2, ensure_ascii=False)
        logger.info(
            "Generated sing-box config %s with %d outbounds",
            singbox_out,
            len(singbox_config.get("outbounds", [])),
        )

    return 0


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Parse V2Ray subscription links into Clash (mihomo) / sing-box configs"
    )
    ap.add_argument(
        "url",
        nargs="?",
        default=DEFAULT_SUBSCRIPTION_URL,
        help="Subscription URL (fragment #Name becomes profile title)",
    )
    ap.add_argument("--clash-out", default="clash_config.yaml")
    ap.add_argument("--singbox-out", default="singbox_config.json")
    ap.add_argument(
        "--only",
        choices=("clash", "singbox", "both"),
        default="both",
        help="Which outputs to generate",
    )
    ap.add_argument(
        "--tun",
        action="store_true",
        help="Enable TUN inbound (needs root/CAP_NET_ADMIN; off by default)",
    )
    ap.add_argument(
        "--allow-lan",
        action="store_true",
        help="Allow LAN connections and bind to all interfaces (loopback-only by default)",
    )
    ap.add_argument(
        "--controller-secret",
        default=os.environ.get("MIHOMO_CONTROLLER_SECRET", ""),
        help="mihomo external-controller secret (or set MIHOMO_CONTROLLER_SECRET env). Empty = no auth (default).",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    raise SystemExit(
        run(
            url=args.url,
            clash_out=args.clash_out,
            singbox_out=args.singbox_out,
            outputs=args.only,
            tun_enabled=args.tun,
            allow_lan=args.allow_lan,
            controller_secret=args.controller_secret,
        )
    )


if __name__ == "__main__":
    main()
