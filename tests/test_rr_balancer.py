"""Unit tests for scripts/rr_balancer.py (stdlib unittest, no network)."""

import contextlib
import io
import os
import sqlite3
import sys
import tempfile
import time
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
    """Stub ClashAPI: delays dict maps name -> delay_ms or None (dead).

    google_blocked names answer /sorry (302) on the expected=200 probe.
    """

    def __init__(self, delays, group="PROXY", google_blocked=None):
        self.delays = delays
        self.google_blocked = set(google_blocked or ())
        self.group = group
        self.selected = []
        self.members = list(delays) + ["Auto", "Load Balance", "Fallback"]
        self.connections = []
        self.closed = []
        self.close_fail = False

    def group_members(self, group):
        pool = [m for m in self.members if m not in rr_balancer.META_NAMES]
        return pool, "old-node"

    def select(self, group, name):
        self.selected.append((group, name))

    def delay(self, name, test_url, timeout_ms, expected=None):
        if expected == 200 and name in self.google_blocked:
            return None
        return self.delays.get(name)

    def get_connections(self):
        return list(self.connections)

    def close_connection(self, cid):
        if self.close_fail:
            raise RuntimeError("close failed")
        self.closed.append(cid)
        return True


def make_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    conn = rr_balancer.connect_db(path)
    return conn, path


def mark(conn, name, status, delay=None, uses=0, last_check=None, country=""):
    if last_check is None:
        last_check = int(time.time())
    conn.execute(
        "INSERT INTO nodes (name, status, delay_ms, last_check, uses, country) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (name, status, delay, last_check, uses, country),
    )
    conn.commit()


class Args:
    def __init__(self, **kw):
        self.__dict__.update(
            dict(
                db="",
                group="PROXY",
                stale_after=3600,
                batch=250,
                workers=4,
                max_fails=3,
                test_url="https://www.gstatic.com/generate_204",
                timeout_ms=3000,
                # Keep unit tests network-free; the google-gate test opts in
                # and patches the direct reachability probe.
                no_google_check=True,
                google_url=rr_balancer.DEFAULT_GOOGLE_URL,
                google_timeout_ms=8000,
                google_attempts=5,
                # Country fields default to the lock being off.
                require_country=None,
                trace_url=rr_balancer.DEFAULT_TRACE_URL,
                trace_timeout_ms=8000,
                trace_proxy=rr_balancer.DEFAULT_PROXY_URL,
            )
        )
        self.__dict__.update(kw)


class RotateTest(unittest.TestCase):
    def test_fastest_least_used_first(self):
        conn, path = make_db()
        now = int(time.time())
        mark(conn, "slow", "alive", delay=900, uses=0, last_check=now)
        mark(conn, "fast", "alive", delay=120, uses=0, last_check=now)
        mark(conn, "used", "alive", delay=50, uses=5, last_check=now)
        api = FakeAPI({"slow": 900, "fast": 120, "used": 50})
        args = Args(db=path)
        self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
        # fast wins the 0-use tie over slow despite used being quicker
        self.assertEqual(api.selected, [("PROXY", "fast")])
        uses = conn.execute("SELECT uses FROM nodes WHERE name='fast'").fetchone()[0]
        self.assertEqual(uses, 1)

    def test_rotate_skips_google_blocked(self):
        conn, path = make_db()
        now = int(time.time())
        # "blocked" is faster and unused, so only the gate can reject it.
        mark(conn, "blocked", "alive", delay=50, uses=0, last_check=now)
        mark(conn, "clean", "alive", delay=200, uses=0, last_check=now)
        api = FakeAPI({"blocked": 50, "clean": 200}, google_blocked={"blocked"})
        args = Args(db=path, no_google_check=False)

        def fake_probe(url, proxy, timeout):
            return 302 if api.selected[-1][1] in api.google_blocked else 200

        with (
            unittest.mock.patch.object(
                rr_balancer, "google_reachable_direct", return_value=True
            ),
            unittest.mock.patch.object(
                rr_balancer, "probe_status_via_proxy", side_effect=fake_probe
            ),
            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
        ):
            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
        self.assertEqual(api.selected[-1], ("PROXY", "clean"))
        row = conn.execute(
            "SELECT status, last_fail_cause, google_fails FROM nodes "
            "WHERE name='blocked'"
        ).fetchone()
        self.assertEqual(row, ("failed", "google", 1))

    def test_rotate_fails_open_when_all_blocked(self):
        conn, path = make_db()
        now = int(time.time())
        mark(conn, "a", "alive", delay=50, uses=0, last_check=now)
        api = FakeAPI({"a": 50}, google_blocked={"a"})
        args = Args(db=path, no_google_check=False, google_attempts=1)
        with (
            unittest.mock.patch.object(
                rr_balancer, "google_reachable_direct", return_value=True
            ),
            unittest.mock.patch.object(
                rr_balancer, "probe_status_via_proxy", return_value=302
            ),
            unittest.mock.patch.object(rr_balancer, "GOOGLE_SETTLE_SECONDS", 0),
        ):
            self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
        self.assertEqual(api.selected[-1], ("PROXY", "a"))

    def test_second_rotate_moves_on(self):
        conn, path = make_db()
        now = int(time.time())
        mark(conn, "a", "alive", delay=100, uses=0, last_check=now)
        mark(conn, "b", "alive", delay=200, uses=0, last_check=now)
        api = FakeAPI({"a": 100, "b": 200})
        args = Args(db=path)
        rr_balancer.cmd_rotate(args, api)
        rr_balancer.cmd_rotate(args, api)
        self.assertEqual(api.selected, [("PROXY", "a"), ("PROXY", "b")])

    def test_empty_pool_noop_never_selects(self):
        conn, path = make_db()
        mark(conn, "dead", "failed")
        api = FakeAPI({})
        args = Args(db=path)
        self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
        self.assertEqual(api.selected, [])
        reason = conn.execute(
            "SELECT reason FROM rotation_log ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        self.assertEqual(reason, "noop-empty-pool")

    def test_stale_nodes_excluded(self):
        conn, path = make_db()
        mark(conn, "stale", "alive", delay=10, uses=0, last_check=1)
        mark(conn, "fresh", "alive", delay=500, uses=0, last_check=1_700_000_000)
        api = FakeAPI({})
        args = Args(db=path, stale_after=3600)
        # now inside connect path uses real time; force via alive_pool
        pool = rr_balancer.alive_pool(conn, 1_700_000_000, 3600)
        self.assertEqual([n for n, _, _, _ in pool], ["fresh"])

    def test_meta_members_never_in_pool(self):
        api = FakeAPI({"real": 100})
        pool, _ = api.group_members("PROXY")
        self.assertEqual(pool, ["real"])


class RetestTest(unittest.TestCase):
    def test_alive_failed_and_readmit(self):
        conn, path = make_db()
        mark(conn, "good", "unknown", last_check=0)
        mark(conn, "bad", "unknown", last_check=0)
        mark(conn, "back", "failed", last_check=0)
        conn.execute("UPDATE nodes SET fails=2 WHERE name='bad'")
        conn.commit()
        api = FakeAPI({"good": 150, "bad": None, "back": 80})
        args = Args(db=path, batch=10)
        self.assertEqual(rr_balancer.cmd_retest(args, api), 0)
        st = dict(conn.execute("SELECT name, status FROM nodes").fetchall())
        self.assertEqual(st["good"], "alive")
        self.assertEqual(st["bad"], "failed")  # 3rd strike
        self.assertEqual(st["back"], "alive")  # readmitted, fails reset
        fails = conn.execute("SELECT fails FROM nodes WHERE name='back'").fetchone()[0]
        self.assertEqual(fails, 0)

    def test_oldest_first_batching(self):
        conn, path = make_db()
        mark(conn, "old", "alive", delay=9, last_check=100)
        mark(conn, "new", "alive", delay=9, last_check=1_700_000_000)
        api = FakeAPI({"old": 9, "new": 9})
        args = Args(db=path, batch=1)
        rr_balancer.cmd_retest(args, api)
        checked = conn.execute(
            "SELECT name FROM nodes WHERE last_check > 1_700_000_000"
        ).fetchall()
        self.assertEqual([r[0] for r in checked], ["old"])

    def test_all_fail_batch_keeps_nodes_alive(self):
        conn, path = make_db()
        names = ["n%d" % i for i in range(5)]
        for n in names:
            mark(conn, n, "alive", delay=100, last_check=0)
        api = FakeAPI({n: None for n in names})
        before = int(time.time())
        args = Args(db=path, batch=10)
        self.assertEqual(rr_balancer.cmd_retest(args, api), 0)
        rows = conn.execute(
            "SELECT name, status, fails, last_check FROM nodes"
        ).fetchall()
        for name, status, fails, last_check in rows:
            self.assertEqual(status, "alive", name)
            self.assertEqual(fails, 0, name)
            self.assertGreaterEqual(last_check, before, name)


class ValidateArgsTest(unittest.TestCase):
    def test_rejects_bad_retest_numbers(self):
        for kw in (
            {"cmd": "retest", "workers": 0},
            {"cmd": "retest", "batch": -1},
            {"cmd": "retest", "max_fails": 0},
            {"cmd": "retest", "timeout_ms": 499},
            {"cmd": "rotate", "stale_after": 59},
        ):
            args = Args(**kw)
            args.cmd = kw["cmd"]
            self.assertIsNotNone(rr_balancer.validate_args(args), kw)

    def test_accepts_sane_args(self):
        args = Args(cmd="retest")
        self.assertIsNone(rr_balancer.validate_args(args))
        args = Args(cmd="rotate")
        self.assertIsNone(rr_balancer.validate_args(args))

    def test_skip_marks_failed_and_advances(self):
        conn, path = make_db()
        api = FakeAPI({"n1": 2, "n2": 5})
        mark(conn, "n1", "alive", delay=2, uses=0)
        mark(conn, "n2", "alive", delay=5, uses=0)
        conn.close()
        rc = rr_balancer.cmd_skip(Args(cmd="skip", name="n1", db=path), api)
        self.assertEqual(rc, 0)
        self.assertEqual(api.selected[-1], ("PROXY", "n2"))
        conn = sqlite3.connect(path)
        st = conn.execute("SELECT status FROM nodes WHERE name='n1'").fetchone()[0]
        self.assertEqual(st, "failed")
        reason = conn.execute(
            "SELECT reason FROM rotation_log ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        self.assertEqual(reason, "manual-skip")
        conn.close()

    def test_rejects_bad_skip_numbers(self):
        args = Args(cmd="skip", name="n1", stale_after=59)
        self.assertIsNotNone(rr_balancer.validate_args(args))
        args = Args(cmd="skip", name="n1", max_fails=0)
        self.assertIsNotNone(rr_balancer.validate_args(args))

    def test_next_skips_current_selection(self):
        conn, path = make_db()
        api = FakeAPI({"cur": 50, "n2": 5})
        api.group_members = lambda group: (["cur", "n2"], "cur")
        mark(conn, "cur", "alive", delay=50, uses=3)
        mark(conn, "n2", "alive", delay=5, uses=0)
        conn.close()
        rc = rr_balancer.cmd_next(Args(cmd="next", db=path), api)
        self.assertEqual(rc, 0)
        self.assertEqual(api.selected[-1], ("PROXY", "n2"))
        conn = sqlite3.connect(path)
        st = conn.execute("SELECT status FROM nodes WHERE name='cur'").fetchone()[0]
        self.assertEqual(st, "failed")
        reason = conn.execute(
            "SELECT reason FROM rotation_log ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        self.assertEqual(reason, "manual-next")
        conn.close()

    def test_next_without_current_rotates_anyway(self):
        conn, path = make_db()
        api = FakeAPI({"n1": 2, "n2": 5})
        api.group_members = lambda group: (["n1", "n2"], None)
        mark(conn, "n1", "alive", delay=2, uses=0)
        mark(conn, "n2", "alive", delay=5, uses=0)
        conn.close()
        rc = rr_balancer.cmd_next(Args(cmd="next", db=path), api)
        self.assertEqual(rc, 0)
        self.assertEqual(api.selected[-1], ("PROXY", "n1"))


class ConnectDbTest(unittest.TestCase):
    def test_wal_and_busy_timeout(self):
        conn, path = make_db()
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode.lower(), "wal")
        timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        self.assertEqual(timeout, 10000)


class CloseStaleTest(unittest.TestCase):
    def test_closes_only_prev_chained_connections(self):
        conn, path = make_db()
        api = FakeAPI({"n1": 2, "n2": 5})
        api.connections = [
            {"id": "c1", "chains": ["old-node", "n1"]},
            {"id": "c2", "chains": ["n2"]},
        ]
        mark(conn, "n1", "alive", delay=2, uses=0)
        mark(conn, "n2", "alive", delay=5, uses=0)
        conn.close()
        rc = rr_balancer.cmd_rotate(Args(cmd="rotate", db=path), api)
        self.assertEqual(rc, 0)
        self.assertEqual(api.closed, ["c1"])

    def test_no_close_when_selection_unchanged(self):
        conn, path = make_db()
        api = FakeAPI({"old-node": 2, "n2": 5})
        api.group_members = lambda group: (["old-node", "n2"], "old-node")
        api.connections = [{"id": "c1", "chains": ["old-node"]}]
        mark(conn, "old-node", "alive", delay=2, uses=0)
        mark(conn, "n2", "alive", delay=5, uses=0)
        conn.close()
        rc = rr_balancer.cmd_rotate(Args(cmd="rotate", db=path), api)
        self.assertEqual(rc, 0)
        self.assertEqual(api.selected[-1], ("PROXY", "old-node"))
        self.assertEqual(api.closed, [])

    def test_close_failure_never_breaks_rotation(self):
        conn, path = make_db()
        api = FakeAPI({"n1": 2, "n2": 5})
        api.close_fail = True
        api.connections = [{"id": "c1", "chains": ["old-node"]}]
        mark(conn, "n1", "alive", delay=2, uses=0)
        mark(conn, "n2", "alive", delay=5, uses=0)
        conn.close()
        rc = rr_balancer.cmd_rotate(Args(cmd="rotate", db=path), api)
        self.assertEqual(rc, 0)
        self.assertEqual(api.selected[-1], ("PROXY", "n1"))
        conn = sqlite3.connect(path)
        uses = conn.execute("SELECT uses FROM nodes WHERE name='n1'").fetchone()[0]
        self.assertEqual(uses, 1)
        conn.close()


class SeedMemoryTest(unittest.TestCase):
    def test_reseed_keeps_learned_rows(self):
        conn, path = make_db()
        mark(conn, "a1", "alive", delay=10, uses=5)
        mark(conn, "u1", "unknown")
        rr_balancer.seed_names(conn, ["u1", "new1"])
        row = conn.execute(
            "SELECT status, uses, delay_ms FROM nodes WHERE name='a1'"
        ).fetchone()
        self.assertEqual(row, ("alive", 5, 10))
        self.assertIsNotNone(
            conn.execute("SELECT 1 FROM nodes WHERE name='new1'").fetchone()
        )
        conn.close()

    def test_unknown_absent_rows_pruned(self):
        conn, path = make_db()
        mark(conn, "u2", "unknown")
        mark(conn, "u1", "unknown")
        rr_balancer.seed_names(conn, ["u1"])
        self.assertIsNone(
            conn.execute("SELECT 1 FROM nodes WHERE name='u2'").fetchone()
        )
        self.assertIsNotNone(
            conn.execute("SELECT 1 FROM nodes WHERE name='u1'").fetchone()
        )
        conn.close()

    def test_alive_pool_excludes_controller_ghosts(self):
        conn, path = make_db()
        now = int(time.time())
        mark(conn, "ghost", "alive", delay=5, uses=0, last_check=now)
        mark(conn, "real", "alive", delay=50, uses=0, last_check=now)
        pool = rr_balancer.alive_pool(conn, now, 3600, allowed={"real", "other"})
        self.assertEqual([n for n, _, _, _ in pool], ["real"])
        conn.close()

    def test_retest_batch_skips_ghosts(self):
        conn, path = make_db()
        api = FakeAPI({"n1": 10})
        api.group_members = lambda group: (["n1"], "old-node")
        mark(conn, "ghost", "alive", delay=5, uses=0, last_check=100)
        mark(conn, "n1", "unknown", last_check=100)
        conn.close()
        rc = rr_balancer.cmd_retest(Args(cmd="retest", db=path, batch=10), api)
        self.assertEqual(rc, 0)
        conn = sqlite3.connect(path)
        ghost_check = conn.execute(
            "SELECT last_check FROM nodes WHERE name='ghost'"
        ).fetchone()[0]
        self.assertEqual(ghost_check, 100)
        conn.close()


class QuarantineTest(unittest.TestCase):
    def test_mark_failed_sets_24h_quarantine(self):
        conn, path = make_db()
        now = int(time.time())
        mark(conn, "n1", "alive", delay=10, uses=0, last_check=now)
        conn.close()
        conn = rr_balancer.connect_db(path)
        rr_balancer._mark_failed(conn, "n1", 3, now)
        row = conn.execute(
            "SELECT status, quarantined_until FROM nodes WHERE name='n1'"
        ).fetchone()
        self.assertEqual(row[0], "failed")
        self.assertEqual(row[1], now + 24 * 3600)
        conn.close()

    def test_pool_excludes_quarantined(self):
        conn, path = make_db()
        now = int(time.time())
        mark(conn, "q", "failed", last_check=now)
        mark(conn, "ok", "alive", delay=10, uses=0, last_check=now)
        conn.execute(
            "UPDATE nodes SET quarantined_until=? WHERE name='q'", (now + 3600,)
        )
        conn.commit()
        pool = rr_balancer.alive_pool(conn, now, 7200, allowed={"q", "ok"})
        # q is failed so pool holds only ok regardless; force alive to isolate filter
        conn.execute("UPDATE nodes SET status='alive' WHERE name='q'")
        conn.commit()
        pool = rr_balancer.alive_pool(conn, now, 7200, allowed={"q", "ok"})
        self.assertEqual([n for n, _, _, _ in pool], ["ok"])
        conn.close()

    def test_expired_quarantine_readmits(self):
        conn, path = make_db()
        now = int(time.time())
        mark(conn, "old", "alive", delay=10, uses=0, last_check=now)
        conn.execute(
            "UPDATE nodes SET quarantined_until=? WHERE name='old'", (now - 1,)
        )
        conn.commit()
        pool = rr_balancer.alive_pool(conn, now, 7200, allowed={"old"})
        self.assertEqual([n for n, _, _, _ in pool], ["old"])
        conn.close()

    def test_retest_skips_quarantined(self):
        conn, path = make_db()
        api = FakeAPI({"n1": 10})
        api.group_members = lambda group: (["n1", "q"], "old-node")
        mark(conn, "q", "failed", last_check=100)
        mark(conn, "n1", "unknown", last_check=100)
        conn.execute(
            "UPDATE nodes SET quarantined_until=? WHERE name='q'",
            (int(time.time()) + 3600,),
        )
        conn.commit()
        conn.close()
        rc = rr_balancer.cmd_retest(Args(cmd="retest", db=path, batch=10), api)
        self.assertEqual(rc, 0)
        conn = sqlite3.connect(path)
        q_check = conn.execute(
            "SELECT last_check FROM nodes WHERE name='q'"
        ).fetchone()[0]
        self.assertEqual(q_check, 100)
        conn.close()

    def test_migration_adds_column_idempotently(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(path)
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE nodes (name TEXT PRIMARY KEY, status TEXT NOT NULL "
            "DEFAULT 'unknown', delay_ms INTEGER, last_check INTEGER NOT NULL "
            "DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, "
            "uses INTEGER NOT NULL DEFAULT 0)"
        )
        conn.commit()
        conn.close()
        conn = rr_balancer.connect_db(path)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(nodes)").fetchall()]
        self.assertIn("quarantined_until", cols)
        self.assertIn("country", cols)
        self.assertIn("country_checked", cols)
        conn.close()
        conn = rr_balancer.connect_db(path)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(nodes)").fetchall()]
        self.assertIn("country", cols)
        self.assertNotIn("quota_fails", cols)
        conn.close()


class CauseCleanupTest(unittest.TestCase):
    """Only the causes this balancer acts on survive the plugin cleanup."""

    def test_fresh_schema_has_no_plugin_counters(self):
        conn, path = make_db()
        cols = [r[1] for r in conn.execute("PRAGMA table_info(nodes)").fetchall()]
        for legacy in ("quota_fails", "transport_fails", "region_fails"):
            self.assertNotIn(legacy, cols)
        self.assertIn("google_fails", cols)
        self.assertIn("country", cols)
        self.assertIn("country_checked", cols)
        conn.close()

    def test_skip_reason_google_records_cause_and_quarantines(self):
        conn, path = make_db()
        api = FakeAPI({"n1": 2, "n2": 5})
        mark(conn, "n1", "alive", delay=2, uses=0)
        mark(conn, "n2", "alive", delay=5, uses=0)
        conn.close()
        rc = rr_balancer.cmd_skip(
            Args(cmd="skip", name="n1", reason="google", db=path), api
        )
        self.assertEqual(rc, 0)
        conn = sqlite3.connect(path)
        row = conn.execute(
            "SELECT google_fails, last_fail_cause, status, quarantined_until, "
            "last_check FROM nodes WHERE name='n1'"
        ).fetchone()
        self.assertEqual(row[:3], (1, "google", "failed"))
        self.assertGreater(row[3], row[4])
        conn.close()

    def test_country_and_manual_causes_leave_google_counter_alone(self):
        conn, path = make_db()
        api = FakeAPI({"n1": 2, "n2": 5})
        mark(conn, "n1", "alive", delay=2, uses=0)
        mark(conn, "n2", "alive", delay=5, uses=0)
        conn.close()
        rr_balancer.cmd_skip(
            Args(cmd="skip", name="n1", reason="country", db=path), api
        )
        rr_balancer.cmd_skip(Args(cmd="skip", name="n2", reason="manual", db=path), api)
        conn = sqlite3.connect(path)
        rows = conn.execute(
            "SELECT name, google_fails, last_fail_cause FROM nodes ORDER BY name"
        ).fetchall()
        self.assertEqual(rows, [("n1", 0, "country"), ("n2", 0, "manual")])
        conn.close()

    def test_legacy_counters_dropped_while_rows_survive(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(path)
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE nodes (name TEXT PRIMARY KEY, status TEXT NOT NULL "
            "DEFAULT 'unknown', delay_ms INTEGER, last_check INTEGER NOT NULL "
            "DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, "
            "uses INTEGER NOT NULL DEFAULT 0, quarantined_until INTEGER NOT NULL "
            "DEFAULT 0, last_fail_cause TEXT NOT NULL DEFAULT '', "
            "quota_fails INTEGER NOT NULL DEFAULT 0, transport_fails INTEGER "
            "NOT NULL DEFAULT 0, region_fails INTEGER NOT NULL DEFAULT 0, "
            "google_fails INTEGER NOT NULL DEFAULT 0)"
        )
        conn.execute(
            "INSERT INTO nodes (name, status, uses) VALUES ('kept', 'alive', 7)"
        )
        conn.commit()
        conn.close()
        conn = rr_balancer.connect_db(path)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(nodes)").fetchall()]
        for legacy in ("quota_fails", "transport_fails", "region_fails"):
            self.assertNotIn(legacy, cols)
        row = conn.execute(
            "SELECT status, uses FROM nodes WHERE name='kept'"
        ).fetchone()
        self.assertEqual(row, ("alive", 7))
        conn.close()

    def test_order_pool_uses_then_delay_only(self):
        pool = [
            ("slow", 0, 500, "US"),
            ("fast", 0, 5, "DE"),
            ("used", 1, 1, "US"),
        ]
        self.assertEqual(
            [row[0] for row in rr_balancer.order_pool(pool)],
            ["fast", "slow", "used"],
        )

    def test_retest_success_clears_cause_but_keeps_country(self):
        conn, path = make_db()
        api = FakeAPI({"n1": 10})
        api.group_members = lambda group: (["n1"], "old-node")
        mark(conn, "n1", "unknown", last_check=100, country="US")
        conn.execute(
            "UPDATE nodes SET google_fails=2, last_fail_cause='google' WHERE name='n1'"
        )
        conn.commit()
        conn.close()
        rc = rr_balancer.cmd_retest(Args(cmd="retest", db=path, batch=10), api)
        self.assertEqual(rc, 0)
        conn = sqlite3.connect(path)
        row = conn.execute(
            "SELECT google_fails, last_fail_cause, country FROM nodes WHERE name='n1'"
        ).fetchone()
        self.assertEqual(row, (2, "", "US"))
        conn.close()


class CountryTest(unittest.TestCase):
    def test_parse_trace_country_reads_loc(self):
        body = "fl=123abc\nh=www.cloudflare.com\nip=1.2.3.4\nts=1\nloc=us\n"
        self.assertEqual(rr_balancer.parse_trace_country(body), "US")

    def test_parse_trace_country_rejects_unknown_shapes(self):
        self.assertIsNone(rr_balancer.parse_trace_country("ip=1.2.3.4\n"))
        self.assertIsNone(rr_balancer.parse_trace_country("loc=\n"))
        self.assertIsNone(rr_balancer.parse_trace_country("loc=USA\n"))
        self.assertIsNone(rr_balancer.parse_trace_country("loc=T1\n"))
        # Cloudflare reports loc=XX when it cannot place the exit (Tor, etc.).
        self.assertIsNone(rr_balancer.parse_trace_country("loc=XX\n"))
        self.assertIsNone(rr_balancer.parse_trace_country(""))

    def test_probe_country_parses_body(self):
        class _Resp:
            status = 200

            def read(self):
                return b"h=www.cloudflare.com\nloc=DE\nts=1\n"

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
            self.assertEqual(
                rr_balancer.probe_country_via_proxy(
                    rr_balancer.DEFAULT_TRACE_URL, rr_balancer.DEFAULT_PROXY_URL, 5.0
                ),
                "DE",
            )

    def test_probe_country_returns_none_on_transport_error(self):
        with unittest.mock.patch.object(
            rr_balancer.urllib.request,
            "build_opener",
            side_effect=OSError("proxy down"),
        ):
            self.assertIsNone(
                rr_balancer.probe_country_via_proxy(
                    rr_balancer.DEFAULT_TRACE_URL, rr_balancer.DEFAULT_PROXY_URL, 1.0
                )
            )

    def test_cmd_country_fills_batch_and_restores_selection(self):
        conn, path = make_db()
        now = int(time.time())
        mark(conn, "a", "alive", delay=10, uses=0, last_check=now)
        mark(conn, "b", "alive", delay=20, uses=0, last_check=now)
        api = FakeAPI({"a": 10, "b": 20})
        api.group_members = lambda group: (["a", "b"], "prev")
        with (
            unittest.mock.patch.object(
                rr_balancer, "probe_country_via_proxy", side_effect=["US", "DE"]
            ),
            unittest.mock.patch.object(rr_balancer, "TRACE_SETTLE_SECONDS", 0),
        ):
            rc = rr_balancer.cmd_country(Args(cmd="country", db=path, batch=10), api)
        self.assertEqual(rc, 0)
        conn.close()
        conn = sqlite3.connect(path)
        rows = conn.execute(
            "SELECT name, country, country_checked FROM nodes ORDER BY name"
        ).fetchall()
        self.assertEqual([(r[0], r[1]) for r in rows], [("a", "US"), ("b", "DE")])
        self.assertTrue(all(row[2] > 0 for row in rows))
        self.assertEqual(api.selected[-1], ("PROXY", "prev"))
        conn.close()

    def test_cmd_country_unknown_never_quarantines(self):
        conn, path = make_db()
        mark(conn, "a", "alive", delay=10, uses=0)
        api = FakeAPI({"a": 10})
        with (
            unittest.mock.patch.object(
                rr_balancer, "probe_country_via_proxy", return_value=None
            ),
            unittest.mock.patch.object(rr_balancer, "TRACE_SETTLE_SECONDS", 0),
        ):
            rc = rr_balancer.cmd_country(Args(cmd="country", db=path, batch=5), api)
        self.assertEqual(rc, 0)
        conn.close()
        conn = sqlite3.connect(path)
        row = conn.execute(
            "SELECT country, country_checked, status, quarantined_until, fails "
            "FROM nodes WHERE name='a'"
        ).fetchone()
        self.assertEqual(row[0], "")
        self.assertGreater(row[1], 0)
        self.assertEqual(row[2:], ("alive", 0, 0))
        conn.close()


class CountryLockTest(unittest.TestCase):
    def test_require_country_filters_to_matching_exit(self):
        conn, path = make_db()
        now = int(time.time())
        mark(conn, "us", "alive", delay=500, uses=0, last_check=now, country="US")
        mark(conn, "de", "alive", delay=10, uses=0, last_check=now, country="DE")
        api = FakeAPI({"us": 500, "de": 10})
        # Lowercase input must normalize, and the slower US exit must win.
        rc = rr_balancer.cmd_rotate(Args(db=path, require_country="us"), api)
        self.assertEqual(rc, 0)
        self.assertEqual(api.selected[-1], ("PROXY", "us"))
        conn.close()

    def test_require_country_without_match_keeps_current_selection(self):
        conn, path = make_db()
        now = int(time.time())
        mark(conn, "de", "alive", delay=10, uses=0, last_check=now, country="DE")
        mark(conn, "unmeasured", "alive", delay=5, uses=0, last_check=now)
        api = FakeAPI({"de": 10, "unmeasured": 5})
        rc = rr_balancer.cmd_rotate(Args(db=path, require_country="US"), api)
        self.assertEqual(rc, 0)
        self.assertEqual(api.selected, [])
        conn.close()

    def test_skip_with_country_reason_still_respects_lock(self):
        conn, path = make_db()
        api = FakeAPI({"n1": 2, "n2": 5})
        mark(conn, "n1", "alive", delay=2, uses=0, country="US")
        mark(conn, "n2", "alive", delay=5, uses=0, country="US")
        conn.close()
        rc = rr_balancer.cmd_skip(
            Args(
                cmd="skip", name="n1", reason="country", db=path, require_country="US"
            ),
            api,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(api.selected[-1], ("PROXY", "n2"))


class ReportTest(unittest.TestCase):
    def test_report_prints_coverage_and_country_counts(self):
        conn, path = make_db()
        mark(conn, "a", "alive", delay=10, country="US")
        mark(conn, "b", "alive", delay=20, country="US")
        mark(conn, "c", "failed", delay=30, country="DE")
        mark(conn, "d", "unknown")
        conn.execute("UPDATE nodes SET country_checked=1 WHERE name IN ('a','b','c')")
        conn.commit()
        conn.close()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = rr_balancer.cmd_report(Args(cmd="report", db=path))
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("coverage 3/4 checked", out)
        self.assertIn("US", out)
        self.assertIn("DE", out)
        self.assertIn("unknown", out)


class CountryArgsTest(unittest.TestCase):
    def test_rejects_bad_require_country(self):
        for bad in ("USA", "1A", ""):
            self.assertIsNotNone(
                rr_balancer.validate_args(Args(cmd="rotate", require_country=bad)), bad
            )

    def test_rejects_bad_country_batch_numbers(self):
        self.assertIsNotNone(rr_balancer.validate_args(Args(cmd="country", batch=0)))
        self.assertIsNotNone(
            rr_balancer.validate_args(Args(cmd="country", trace_timeout_ms=100))
        )

    def test_accepts_sane_country_args(self):
        self.assertIsNone(rr_balancer.validate_args(Args(cmd="country")))
        self.assertIsNone(
            rr_balancer.validate_args(Args(cmd="rotate", require_country="us"))
        )


if __name__ == "__main__":
    unittest.main()
