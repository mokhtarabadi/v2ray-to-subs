"""Tests for REALITY short-id sanitization (mihomo -t must never abort a config).

Offline: pure helper, no network or mihomo needed.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import proxy_converter


class RealityShortIdTest(unittest.TestCase):
    def test_none_and_empty_become_empty(self):
        self.assertEqual(proxy_converter._sanitize_reality_short_id(None), "")
        self.assertEqual(proxy_converter._sanitize_reality_short_id(""), "")
        self.assertEqual(proxy_converter._sanitize_reality_short_id("   "), "")

    def test_valid_even_hex_is_normalized(self):
        self.assertEqual(proxy_converter._sanitize_reality_short_id("DEADbeef"), "deadbeef")
        self.assertEqual(proxy_converter._sanitize_reality_short_id("2e00"), "2e00")

    def test_0x_prefix_is_stripped(self):
        self.assertEqual(
            proxy_converter._sanitize_reality_short_id(" 0xDEADbeef "), "deadbeef"
        )

    def test_odd_length_hex_becomes_empty(self):
        self.assertEqual(proxy_converter._sanitize_reality_short_id("abc"), "")

    def test_non_hex_becomes_empty(self):
        self.assertEqual(proxy_converter._sanitize_reality_short_id("zzzz"), "")
        self.assertEqual(proxy_converter._sanitize_reality_short_id("hello!"), "")

    def test_emitted_short_id_is_even_hex_or_absent(self):
        # The emitter uses _QuotedStr for non-empty ids; assert the helper output
        # is always something mihomo accepts before it reaches the emitter.
        for value in ("abc", "zzzz", "0x0011", "2e00", None):
            result = proxy_converter._sanitize_reality_short_id(value)
            if result:
                self.assertEqual(len(result) % 2, 0)
                self.assertTrue(all(c in "0123456789abcdef" for c in result))


if __name__ == "__main__":
    unittest.main()
