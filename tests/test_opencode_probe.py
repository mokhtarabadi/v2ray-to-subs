"""Tests for the background opencode.ai HTTPS probe and configurable quarantine.

Offline: urllib and the Clash controller are patched; no live network or mihomo.
"""
import argparse
import os
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
    ),
)
import rr_balancer


class FakeAPI:
    """Minimal ClashAPI stand-in: remembers selection and records restores."""

    def __init__(self, members, current):
        self.members = members
        self.current = current
        self.selected = []

    def group_members(self, group):
        return self.members, self.current

    def select(self, group, name):
        self.selected.append(name)
        self.current = name


class ProbeVerdictTest(unittest.TestCase):
    def test_probe_returns_ok_only_on_200(self):
        class _Resp:
            status = 200

            def read(self):
                return b"ok"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        class _Opener:
            def open(self, req, timeout=None):
                return _Resp()

        with unittest.mock.patch.object(
            rr_balancer.urllib.request, "build_opener", return_value=_Opener()
        ):
            ok, delay = rr_balancer.probe_opencode_via_proxy(
                "https://opencode.ai", rr_balancer.DEFAULT_PROXY_URL, 5.0
            )
        self.assertTrue(ok)
        self.assertIsInstance(delay, int)

    def test_probe_429_is_failure_not_success(self):
        class _Opener:
            def open(self, req, timeout=None):
                raise rr_balancer.urllib.error.HTTPError(
                    req.full_url, 429, "rate limited", None, None
                )

        with unittest.mock.patch.object(
            rr_balancer.urllib.request, "build_opener", return_value=_Opener()
        ):
            ok, _ = rr_balancer.probe_opencode_via_proxy(
                "https://opencode.ai", rr_balancer.DEFAULT_PROXY_URL, 5.0
            )
        self.assertFalse(ok)

    def test_probe_transport_error_is_failure(self):
        with unittest.mock.patch.object(
            rr_balancer.urllib.request,
            "build_opener",
            side_effect=OSError("proxy down"),
        ):
            ok, delay = rr_balancer.probe_opencode_via_proxy(
                "https://opencode.ai", rr_balancer.DEFAULT_PROXY_URL, 1.0
            )
        self.assertFalse(ok)
        self.assertIsNone(delay)


class QuarantineConfigTest(unittest.TestCase):
    def setUp(self):
        self.saved = os.environ.pop("RR_QUARANTINE_SECONDS", None)

    def tearDown(self):
        if self.saved is not None:
            os.environ["RR_QUARANTINE_SECONDS"] = self.saved

    def test_default_is_24h(self):
        self.assertEqual(rr_balancer.resolve_quarantine_seconds(), 24 * 3600)

    def test_env_override(self):
        os.environ["RR_QUARANTINE_SECONDS"] = "43200"
        self.assertEqual(rr_balancer.resolve_quarantine_seconds(), 43200)

    def test_cli_overrides_env(self):
        os.environ["RR_QUARANTINE_SECONDS"] = "43200"
        self.assertEqual(rr_balancer.resolve_quarantine_seconds(7200), 7200)

    def test_empty_env_uses_default(self):
        os.environ["RR_QUARANTINE_SECONDS"] = ""
        self.assertEqual(rr_balancer.resolve_quarantine_seconds(), 24 * 3600)

    def test_nonpositive_rejected(self):
        with self.assertRaises(ValueError):
            rr_balancer.resolve_quarantine_seconds(0)
        os.environ["RR_QUARANTINE_SECONDS"] = "-5"
        with self.assertRaises(ValueError):
            rr_balancer.resolve_quarantine_seconds()

    def test_noninteger_rejected(self):
        os.environ["RR_QUARANTINE_SECONDS"] = "abc"
        with self.assertRaises(ValueError):
            rr_balancer.resolve_quarantine_seconds()


class ProbeParserRoundTripTest(unittest.TestCase):
    """Guard the CLI wiring so the probe actually runs from the real command line.

    Manual-Namespace tests missed F1 (dest mismatch) and would have missed any
    regression where the parser exposes a different attribute than the command
    reads. Parsing the real argv here closes that gap.
    """

    def setUp(self):
        self.saved = os.environ.pop("RR_OPENCODE_PROBE_ENABLED", None)

    def tearDown(self):
        if self.saved is not None:
            os.environ["RR_OPENCODE_PROBE_ENABLED"] = self.saved

    def test_parser_exposes_the_timeout_attribute_the_command_reads(self):
        args = rr_balancer.build_parser().parse_args(
            ["opencode-probe", "--batch", "20"]
        )
        # cmd_opencode_probe reads args.opencode_timeout_ms; a bare --timeout-ms
        # would expose args.timeout_ms instead and silently skip every probe.
        self.assertEqual(args.opencode_timeout_ms, 8000)
        self.assertEqual(args.batch, 20)
        self.assertTrue(hasattr(args, "opencode_proxy"))

    def test_parser_defaults_to_enabled_with_clean_env(self):
        args = rr_balancer.build_parser().parse_args(["opencode-probe"])
        self.assertTrue(args.opencode_enabled)

    def test_env_zero_disables_by_default(self):
        os.environ["RR_OPENCODE_PROBE_ENABLED"] = "0"
        args = rr_balancer.build_parser().parse_args(["opencode-probe"])
        self.assertFalse(args.opencode_enabled)

    def test_explicit_flags_override_env_default(self):
        os.environ["RR_OPENCODE_PROBE_ENABLED"] = "0"
        args_on = rr_balancer.build_parser().parse_args(
            ["opencode-probe", "--enabled"]
        )
        self.assertTrue(args_on.opencode_enabled)
        args_off = rr_balancer.build_parser().parse_args(
            ["opencode-probe", "--no-probe"]
        )
        self.assertFalse(args_off.opencode_enabled)

    def test_command_uses_parsed_timeout_without_attribute_error(self):
        # Parse real argv, then feed the Namespace to the command with a mocked
        # probe; a dest mismatch would surface here as an AttributeError.
        args = rr_balancer.build_parser().parse_args(
            ["opencode-probe", "--batch", "20", "--timeout-ms", "3000"]
        )
        conn_path = tempfile.mktemp(suffix=".db")
        try:
            args.db = conn_path
            conn = rr_balancer.connect_db(conn_path)
            conn.execute(
                "INSERT INTO nodes (name, status, quarantined_until) "
                "VALUES ('n1','alive',0)"
            )
            conn.commit()
            conn.close()
            api = FakeAPI(["n1"], "original")
            with unittest.mock.patch.object(
                rr_balancer, "probe_opencode_via_proxy", return_value=(True, 5)
            ) as probe:
                rr_balancer.cmd_opencode_probe(args, api)
            self.assertTrue(probe.called)
            self.assertEqual(probe.call_args[0][2], 3.0)
        finally:
            if os.path.exists(conn_path):
                os.unlink(conn_path)


class OpencodeProbeCommandTest(unittest.TestCase):
    def make_db(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(path)
        return path

    def make_args(self, db, **overrides):
        defaults = dict(
            cmd="opencode-probe",
            db=db,
            group="PROXY",
            batch=20,
            opencode_url="https://opencode.ai",
            opencode_proxy=rr_balancer.DEFAULT_PROXY_URL,
            opencode_timeout_ms=8000,
            opencode_enabled=True,
        )
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_probe_persists_verdict_and_restores_selection_on_failure(self):
        db = self.make_db()
        conn = rr_balancer.connect_db(db)
        conn.execute(
            "INSERT INTO nodes (name, status, quarantined_until) VALUES ('n1','alive',0)"
        )
        conn.commit()
        conn.close()
        api = FakeAPI(["n1"], "original")
        args = self.make_args(db)
        args.opencode_enabled = True
        with unittest.mock.patch.object(
            rr_balancer, "probe_opencode_via_proxy", side_effect=OSError("boom")
        ):
            rr_balancer.cmd_opencode_probe(args, api)
        # Finally restored the original selection even though the probe raised.
        self.assertEqual(api.selected[-1], "original")
        conn = rr_balancer.connect_db(db)
        row = conn.execute(
            "SELECT opencode_ok, opencode_checked FROM nodes WHERE name='n1'"
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], 0)
        self.assertGreater(row[1], 0)

    def test_disabled_probe_is_noop(self):
        db = self.make_db()
        api = FakeAPI(["n1"], "original")
        args = self.make_args(db, opencode_enabled=False)
        rr_balancer.cmd_opencode_probe(args, api)
        self.assertEqual(api.selected, [])


if __name__ == "__main__":
    unittest.main()
