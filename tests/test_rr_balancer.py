"""Unit tests for scripts/rr_balancer.py (stdlib unittest, no network)."""

import os
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
    ),
)

import rr_balancer


class FakeAPI:
    """Stub ClashAPI: delays dict maps name -> delay_ms or None (dead)."""

    def __init__(self, delays, group="PROXY"):
        self.delays = delays
        self.group = group
        self.selected = []
        self.members = list(delays) + ["Auto", "Load Balance", "Fallback"]

    def group_members(self, group):
        pool = [m for m in self.members if m not in rr_balancer.META_NAMES]
        return pool, "old-node"

    def select(self, group, name):
        self.selected.append((group, name))

    def delay(self, name, test_url, timeout_ms):
        return self.delays.get(name)


def make_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    conn = rr_balancer.connect_db(path)
    return conn, path


def mark(conn, name, status, delay=None, uses=0, last_check=None):
    if last_check is None:
        last_check = int(time.time())
    conn.execute(
        "INSERT INTO nodes (name, status, delay_ms, last_check, uses) "
        "VALUES (?, ?, ?, ?, ?)",
        (name, status, delay, last_check, uses),
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
        api = FakeAPI({})
        args = Args(db=path)
        self.assertEqual(rr_balancer.cmd_rotate(args, api), 0)
        # fast wins the 0-use tie over slow despite used being quicker
        self.assertEqual(api.selected, [("PROXY", "fast")])
        uses = conn.execute("SELECT uses FROM nodes WHERE name='fast'").fetchone()[0]
        self.assertEqual(uses, 1)

    def test_second_rotate_moves_on(self):
        conn, path = make_db()
        now = int(time.time())
        mark(conn, "a", "alive", delay=100, uses=0, last_check=now)
        mark(conn, "b", "alive", delay=200, uses=0, last_check=now)
        api = FakeAPI({})
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
        self.assertEqual([n for n, _, _ in pool], ["fresh"])

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


if __name__ == "__main__":
    unittest.main()
