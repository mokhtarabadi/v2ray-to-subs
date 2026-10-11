"""Tests for multi-feed aggregation in proxy_converter.py.

Offline only: feeds are file:// URLs, no network access.
"""

import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import proxy_converter
from proxy_converter import _dedup_by_host, run

FEED_A = [
    "vless://11111111-1111-4111-8111-111111111111@shared.example:443?encryption=none#n1",
    "vless://22222222-2222-4222-8222-222222222222@solo-a.example:443?encryption=none#n2",
]

FEED_B = [
    "trojan://pass@SHARED.EXAMPLE:443?sni=x.com#n3",
    "vless://33333333-3333-4333-8333-333333333333@solo-b.example:443?encryption=none#n4",
]


def write_feed(lines):
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return "file://" + path


class DedupHelperTest(unittest.TestCase):
    def test_first_wins_case_insensitive(self):
        parsed = proxy_converter.ProxyParser().parse_subscription_content(
            "\n".join(FEED_A + FEED_B)
        )
        unique, dups = _dedup_by_host(parsed)
        self.assertEqual(len(unique), 3)
        self.assertEqual(dups, 1)
        self.assertEqual(unique[0].name, "n1")


class VlessEncryptionEmitTest(unittest.TestCase):
    def test_unusable_encryption_dropped(self):
        # mihomo only accepts "" / "none" (omitted) or mlkem768x25519plus
        # key strings; aes-128-gcm seen in the wild fails `mihomo -t`.
        parsed = proxy_converter.ProxyParser().parse_subscription_content(
            "vless://11111111-1111-4111-8111-111111111111@enc.example:443"
            "?encryption=aes-128-gcm#enc1"
        )
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].encryption, "aes-128-gcm")
        gen = proxy_converter.ConfigGenerator()
        clash = gen.generate_clash_config(parsed)["proxies"]
        self.assertEqual(len(clash), 1)
        self.assertNotIn("encryption", clash[0])

    def test_none_encryption_omitted(self):
        parsed = proxy_converter.ProxyParser().parse_subscription_content(
            "vless://11111111-1111-4111-8111-111111111111@plain.example:443"
            "?encryption=none#plain1"
        )
        gen = proxy_converter.ConfigGenerator()
        clash = gen.generate_clash_config(parsed)["proxies"]
        self.assertNotIn("encryption", clash[0])


class MultiFeedRunTest(unittest.TestCase):
    def _run(self, **kw):
        tmp = tempfile.mkdtemp()
        clash = os.path.join(tmp, "c.yaml")
        singbox = os.path.join(tmp, "s.json")
        rc = run(
            clash_out=clash,
            singbox_out=singbox,
            outputs="both",
            **kw,
        )
        return rc, clash, singbox

    def test_cross_feed_dedup(self):
        url_a = write_feed(FEED_A)
        url_b = write_feed(FEED_B)
        rc, clash, _ = self._run(urls=[url_a, url_b], unique_host=True)
        self.assertEqual(rc, 0)
        import yaml

        proxies = yaml.safe_load(open(clash, encoding="utf-8"))["proxies"]
        hosts = sorted(p["server"] for p in proxies)
        self.assertEqual(hosts, ["shared.example", "solo-a.example", "solo-b.example"])

    def test_per_feed_counts_logged(self):
        url_a = write_feed(FEED_A)
        url_b = write_feed(FEED_B)
        with self.assertLogs(proxy_converter.logger, level="INFO") as logs:
            rc, _, _ = self._run(urls=[url_a, url_b], unique_host=True)
        self.assertEqual(rc, 0)
        out = "\n".join(logs.output)
        self.assertIn("Feed", out)
        self.assertIn(
            "Unique-host dedup over merged pool: 3 unique, 1 host duplicates skipped",
            out,
        )

    def test_single_url_identity(self):
        url_a = write_feed(FEED_A + FEED_B)
        _, clash_old, singbox_old = self._run(url=url_a)
        _, clash_old, singbox_old = self._run(url=url_a)
        _, clash_new, singbox_new = self._run(urls=[url_a])
        with open(clash_old, encoding="utf-8") as fh:
            old_yaml = fh.read()
        with open(clash_new, encoding="utf-8") as fh:
            new_yaml = fh.read()
        self.assertEqual(old_yaml, new_yaml)
        with open(singbox_old, encoding="utf-8") as fh:
            old_json = json.load(fh)
        with open(singbox_new, encoding="utf-8") as fh:
            new_json = json.load(fh)
        self.assertEqual(old_json, new_json)

    def test_ss_cipher_alias_normalized(self):
        link = (
            "ss://"
            + base64.urlsafe_b64encode(b"chacha20-poly1305:x").decode().rstrip("=")
            + "@h.example:1#n"
        )
        proxy = proxy_converter.ProxyParser().parse_shadowsocks(link)
        self.assertEqual(proxy.method, "chacha20-ietf-poly1305")

    def test_ss_sip003_trailing_slash(self):
        # SIP003 links often carry a trailing slash before ?plugin=
        proxy = proxy_converter.ProxyParser().parse_shadowsocks(
            "ss://YWVzLTI1Ni1nY206cGFzcw@h.com:8388/"
            "?plugin=v2ray-plugin%3Btls%3Bhost%3Dh.com#ss2"
        )
        self.assertEqual(proxy.server, "h.com")
        self.assertEqual(proxy.port, 8388)
        self.assertEqual(proxy.plugin, "v2ray-plugin")
        self.assertIn("tls", proxy.plugin_opts or "")

    def test_ss_v2ray_plugin_mode_default(self):
        # mihomo rejects v2ray-plugin without mode; the plugin default is websocket
        parsed = proxy_converter.ProxyParser().parse_subscription_content(
            "ss://YWVzLTI1Ni1nY206cGFzcw@h.com:8388/"
            "?plugin=v2ray-plugin%3Btls%3Bhost%3Dh.com#ss2"
        )
        gen = proxy_converter.ConfigGenerator()
        clash = gen.generate_clash_config(parsed)["proxies"]
        self.assertEqual(clash[0]["plugin-opts"].get("mode"), "websocket")


if __name__ == "__main__":
    unittest.main()
