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


if __name__ == "__main__":
    unittest.main()
