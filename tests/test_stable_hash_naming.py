"""Tests for stable identity-hash proxy naming (feed-refresh persistence).

Offline only: synthetic links and helper-level cases, no network access.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy_converter import (
    ConfigGenerator,
    assign_stable_names,
    build_proxy_identity,
    normalize_host,
)


class NormalizeHostTest(unittest.TestCase):
    def test_normalization_uppercase_brackets_trailing_dot(self):
        self.assertEqual(normalize_host("Example.COM."), "example.com")
        self.assertEqual(normalize_host("[::1]"), "::1")
        self.assertEqual(normalize_host("  HOST.Example  "), "host.example")
        self.assertEqual(normalize_host(None), "")


class IdentityFormatTest(unittest.TestCase):
    def test_generated_name_format_proto_12hex(self):
        ident = build_proxy_identity("VLESS", "example.com", 443)
        self.assertRegex(ident, r"^[a-z0-9]+-[0-9a-f]{12}$")
        self.assertTrue(ident.startswith("vless-"))

    def test_stability_same_link_same_name(self):
        first = build_proxy_identity("vless", "example.com", 443)
        second = build_proxy_identity("vless", "example.com", 443)
        self.assertEqual(first, second)

    def test_case_and_port_form_insensitive(self):
        self.assertEqual(
            build_proxy_identity("VLESS", "Example.COM.", 443),
            build_proxy_identity("vless", "example.com", "443"),
        )

    def test_uniqueness_different_host_or_port(self):
        base = build_proxy_identity("vless", "a.example", 443)
        self.assertNotEqual(base, build_proxy_identity("vless", "b.example", 443))
        self.assertNotEqual(base, build_proxy_identity("vless", "a.example", 8443))
        self.assertNotEqual(base, build_proxy_identity("vmess", "a.example", 443))

    def test_empty_host_and_proto_raise(self):
        """Empty or missing proto/host must raise so callers fall back.

        A hashed empty string would look like a legitimate identity and
        mask a broken entry; the builders must refuse instead.
        """
        for bad_host in ("", None, "   ", "[   ]"):
            with self.assertRaises(ValueError):
                build_proxy_identity("vless", bad_host, 443)
        for bad_proto in ("", None, " "):
            with self.assertRaises(ValueError):
                build_proxy_identity(bad_proto, "example.com", 443)


class CollisionFallbackTest(unittest.TestCase):
    def test_collision_sorted_suffix_order_independent(self):
        batch_a = [
            {"base_identity": "vless-abc123", "source_link": "link-2"},
            {"base_identity": "vless-abc123", "source_link": "link-1"},
            {"base_identity": "vless-zzz999", "source_link": "link-3"},
        ]
        batch_b = list(reversed(batch_a))
        out_a = [e["final_name"] for e in assign_stable_names(batch_a)]
        out_b = [e["final_name"] for e in assign_stable_names(batch_b)]
        self.assertEqual(out_a, out_b)
        self.assertEqual(out_a[0], "vless-abc123")
        self.assertEqual(out_a[1], "vless-abc123-2")
        self.assertEqual(out_a[2], "vless-zzz999")


class GeneratorNamingTest(unittest.TestCase):
    def test_clash_names_are_stable_and_unique(self):
        gen = ConfigGenerator()
        links = [
            "vless://11111111-1111-4111-8111-111111111111@b.example:443?encryption=none#r2",
            "vless://11111111-1111-4111-8111-111111111111@a.example:443?encryption=none#r1",
        ]
        from proxy_converter import ProxyParser

        proxies = ProxyParser().parse_subscription_content("\n".join(links))
        first = [p["name"] for p in gen.generate_clash_config(proxies)["proxies"]]
        second = [
            p["name"]
            for p in gen.generate_clash_config(list(reversed(proxies)))["proxies"]
        ]
        self.assertEqual(first, second)
        self.assertEqual(len(set(first)), 2)
        for name in first:
            self.assertRegex(name, r"^vless-[0-9a-f]{12}$")

    def test_singbox_tags_are_stable_and_unique(self):
        """sing-box tags must be as stable as Clash names across runs.

        Mirrors the Clash stability test on the sing-box path: two parses,
        reversed input order, identical tag lists, unique, correct format.
        """
        gen = ConfigGenerator()
        links = [
            "vless://11111111-1111-4111-8111-111111111111@b.example:443?encryption=none#r2",
            "vless://11111111-1111-4111-8111-111111111111@a.example:443?encryption=none#r1",
        ]
        from proxy_converter import ProxyParser

        proxies = ProxyParser().parse_subscription_content("\n".join(links))
        cfg1 = gen.generate_singbox_config(proxies)
        tags1 = [o["tag"] for o in cfg1["outbounds"] if o.get("server")]
        cfg2 = gen.generate_singbox_config(list(reversed(proxies)))
        tags2 = [o["tag"] for o in cfg2["outbounds"] if o.get("server")]
        self.assertEqual(tags1, tags2)
        self.assertEqual(len(set(tags1)), 2)
        for tag in tags1:
            self.assertRegex(tag, r"^vless-[0-9a-f]{12}$")
        # No remark leakage: sing-box rejects unknown outbound fields.
        for outbound in cfg1["outbounds"]:
            if outbound.get("server"):
                self.assertNotIn("remark", outbound)

    def test_same_host_port_different_link_suffixes(self):
        """Same host+port with different links must get sorted suffixes.

        Two entries sharing a base identity are ordered by source_link and
        receive base, base-2 independently of input order.
        """
        batch = [
            {"base_identity": "vless-shared123", "source_link": "z-link"},
            {"base_identity": "vless-shared123", "source_link": "a-link"},
        ]
        forward = [e["final_name"] for e in assign_stable_names(list(batch))]
        backward = [e["final_name"] for e in assign_stable_names(list(reversed(batch)))]
        self.assertEqual(forward, backward)
        self.assertEqual(forward, ["vless-shared123", "vless-shared123-2"])


if __name__ == "__main__":
    unittest.main()
