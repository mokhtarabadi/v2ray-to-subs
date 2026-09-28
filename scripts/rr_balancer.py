#!/usr/bin/env python3
"""External round-robin balancer for mihomo (Clash API + SQLite state).

Owns the PROXY group's selection from outside mihomo: tests each node
through Clash itself, keeps liveness/delay/usage in SQLite, rotates the
selected node among alive ones, and retests dead nodes until they revive.

Subcommands:
  rotate   pick next node (least-used, fastest first) and select it
  retest   check a batch of nodes (oldest-checked first) and update state

Selection policy (fastest + fresh + fair):
  - pool = status 'alive' AND checked within STALE_AFTER seconds
  - pick lowest (uses, delay_ms): equal load first, fastest wins ties
  - empty pool = logged no-op, never touches the group (no Auto fallback)
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(REPO_ROOT, "data", "balancer_state.schema.sql")
DEFAULT_DB = os.path.join(REPO_ROOT, "data", "balancer_state.db")
DEFAULT_SECRET_FILE = os.path.expanduser("~/.config/mihomo-subs/.controller_secret")

# Group members that are selectors themselves, plus mihomo builtins:
# never enter the rotation pool.
META_NAMES = {"Auto", "Load Balance", "Fallback", "DIRECT", "REJECT", "PASS"}


def utc_now_epoch() -> int:
    """Current UTC time as epoch seconds. Single clock seam for tests.

    Rotation staleness math and retest scheduling both flow through here
    so unit tests can pin time without touching module state. Callers
    must use this instead of calling time.time() directly.
    """
    return int(time.time())


class ClashAPI:
    """Thin wrapper over the mihomo external controller REST API."""

    def __init__(self, base: str, secret: str, timeout: float = 10.0) -> None:
        self.base = base.rstrip("/")
        self.secret = secret
        self.timeout = timeout

    def _request(
        self, method: str, path: str, body: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method.upper())
        req.add_header("Authorization", "Bearer " + self.secret)
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8") or "null"
                return resp.status, json.loads(raw)
        except urllib.error.HTTPError as exc:
            return exc.code, None

    def group_members(self, group: str) -> Tuple[List[str], Optional[str]]:
        """Names selectable inside a select group (meta entries excluded)."""
        status, payload = self._request("GET", "/proxies")
        if status != 200 or not isinstance(payload, dict):
            raise RuntimeError("GET /proxies failed with HTTP %s" % status)
        group_info = (payload.get("proxies") or {}).get(group)
        if not group_info:
            raise RuntimeError("group %r not found on controller" % group)
        members = [
            p.get("name", "") if isinstance(p, dict) else p
            for p in group_info.get("all") or []
        ]
        current = group_info.get("now")
        pool = [m for m in members if m and m not in META_NAMES]
        return pool, current

    def select(self, group: str, name: str) -> None:
        status, _ = self._request("PUT", "/proxies/" + group, {"name": name})
        if status != 204:
            raise RuntimeError("PUT selection %r failed with HTTP %s" % (name, status))

    def delay(self, name: str, test_url: str, timeout_ms: int) -> Optional[int]:
        qs = urllib.parse.urlencode({"timeout": timeout_ms, "url": test_url})
        path = "/proxies/%s/delay?%s" % (urllib.parse.quote(name), qs)
        try:
            status, payload = self._request("GET", path)
        except Exception:
            return None
        if status != 200 or not isinstance(payload, dict):
            return None
        delay = payload.get("delay")
        return delay if isinstance(delay, int) and delay >= 0 else None


def connect_db(db_path: str) -> sqlite3.Connection:
    """Open state DB with overlap protection for concurrent timers.

    WAL mode plus a 10s busy timeout lets the 5min rotate and 30min
    retest oneshots share the DB without `database is locked` errors.
    Pragmas are best-effort (e.g. some filesystems reject WAL).
    """
    # Fresh clones lack data/ so ensure the parent before connecting.
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)
    fresh = not os.path.exists(db_path)
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except sqlite3.OperationalError:
        pass
    if fresh:
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            conn.executescript(fh.read())
    return conn


def seed_names(conn: sqlite3.Connection, names: List[str]) -> Tuple[int, int]:
    """Insert unknown names; prune names gone from the controller."""
    cur = conn.cursor()
    cur.execute("SELECT name FROM nodes")
    known = {row[0] for row in cur.fetchall()}
    added = 0
    for name in names:
        if name not in known:
            cur.execute("INSERT INTO nodes (name) VALUES (?)", (name,))
            added += 1
    cur.execute(
        "DELETE FROM nodes WHERE name NOT IN (%s)" % ",".join("?" * len(names)),
        names,
    ) if names else None
    pruned = cur.rowcount if names else 0
    conn.commit()
    return added, pruned


def alive_pool(
    conn: sqlite3.Connection, now: int, stale_after: int
) -> List[Tuple[str, int, int]]:
    """Alive AND freshly checked nodes as (name, uses, delay_ms)."""
    cur = conn.cursor()
    cur.execute(
        "SELECT name, uses, COALESCE(delay_ms, 999999) FROM nodes "
        "WHERE status = 'alive' AND (? - last_check) <= ?",
        (now, stale_after),
    )
    return cur.fetchall()


def pick_next(pool: List[Tuple[str, int, int]]) -> Optional[str]:
    """Least-used first, fastest delay breaks ties. None when pool empty."""
    if not pool:
        return None
    return sorted(pool, key=lambda row: (row[1], row[2]))[0][0]


def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
    now = utc_now_epoch()
    conn = connect_db(args.db)
    pool_names, _ = api.group_members(args.group)
    seed_names(conn, pool_names)
    pool = alive_pool(conn, now, args.stale_after)
    name = pick_next(pool)
    if name is None:
        conn.execute(
            "INSERT INTO rotation_log (ts, node, reason) VALUES (?, '', 'noop-empty-pool')",
            (now,),
        )
        conn.commit()
        print("rotate: empty alive pool, no-op (group untouched)")
        return 0
    delay = next(d for n, u, d in pool if n == name)
    api.select(args.group, name)
    cur = conn.cursor()
    cur.execute("UPDATE nodes SET uses = uses + 1 WHERE name = ?", (name,))
    cur.execute(
        "INSERT INTO rotation_log (ts, node, delay_ms, reason) "
        "VALUES (?, ?, ?, 'rotate')",
        (now, name, None if delay >= 999999 else delay),
    )
    cur.execute(
        "INSERT OR REPLACE INTO rotation_state (id, position, updated_at) "
        "VALUES (1, COALESCE((SELECT position FROM rotation_state "
        "WHERE id = 1), 0) + 1, ?)",
        (now,),
    )
    conn.commit()
    print("rotate: selected %s (delay %sms)" % (name, delay))
    return 0


def _mark_failed(conn: sqlite3.Connection, name: str, max_fails: int, now: int) -> None:
    """Mark one node failed (retest readmits it if alive)."""
    cur = conn.cursor()
    row = cur.execute("SELECT status FROM nodes WHERE name = ?", (name,)).fetchone()
    if row is None:
        print("skip: unknown node %r, rotating anyway" % name)
    else:
        cur.execute(
            "UPDATE nodes SET status = 'failed', fails = ?, last_check = ? "
            "WHERE name = ?",
            (max_fails, now, name),
        )
        conn.commit()
        print("skip: marked %s failed (retest readmits it if alive)" % name)


def _relabel_latest(conn: sqlite3.Connection, reason: str) -> None:
    """Relabel the newest rotation row when rotate just logged 'rotate'."""
    conn.execute(
        "UPDATE rotation_log SET reason = ? "
        "WHERE id = (SELECT MAX(id) FROM rotation_log) AND reason = 'rotate'",
        (reason,),
    )
    conn.commit()


def cmd_skip(args: argparse.Namespace, api: ClashAPI) -> int:
    """Mark a flagged node failed, then rotate to the next alive node."""
    now = utc_now_epoch()
    conn = connect_db(args.db)
    pool_names, _ = api.group_members(args.group)
    seed_names(conn, pool_names)
    _mark_failed(conn, args.name, args.max_fails, now)
    conn.close()
    rc = cmd_rotate(args, api)
    if rc == 0:
        conn = connect_db(args.db)
        _relabel_latest(conn, "manual-skip")
        conn.close()
    return rc


def cmd_next(args: argparse.Namespace, api: ClashAPI) -> int:
    """Skip whatever node is currently selected, then rotate onward."""
    now = utc_now_epoch()
    conn = connect_db(args.db)
    pool_names, current = api.group_members(args.group)
    seed_names(conn, pool_names)
    if not current:
        print("next: no current selection reported, rotating anyway")
    else:
        _mark_failed(conn, current, args.max_fails, now)
    conn.close()
    rc = cmd_rotate(args, api)
    if rc == 0:
        conn = connect_db(args.db)
        _relabel_latest(conn, "manual-next")
        conn.close()
    return rc


def check_one(
    api: ClashAPI, name: str, test_url: str, timeout_ms: int
) -> Tuple[str, Optional[int]]:
    return name, api.delay(name, test_url, timeout_ms)


def cmd_retest(args: argparse.Namespace, api: ClashAPI) -> int:
    now = utc_now_epoch()
    conn = connect_db(args.db)
    pool_names, _ = api.group_members(args.group)
    added, pruned = seed_names(conn, pool_names)
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM nodes ORDER BY (status = 'alive') DESC, "
        "last_check ASC LIMIT ?",
        (args.batch,),
    )
    batch = [row[0] for row in cur.fetchall()]
    if not batch:
        print("retest: no nodes to check")
        return 0
    alive = failed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(
            pool.map(
                lambda n: check_one(api, n, args.test_url, args.timeout_ms),
                batch,
            )
        )
    # Infra guard: a full batch with zero successes means the test path
    # itself is down (test URL unreachable, controller wedged), not that
    # every node died at once. Blaming nodes here would mass-mark the
    # pool failed and wedge rotation into a permanent no-op. Bump the
    # check timestamps so the batch is not retried immediately, but
    # leave fails and status untouched.
    if len(results) >= 5 and all(delay is None for _, delay in results):
        cur.executemany(
            "UPDATE nodes SET last_check=? WHERE name=?",
            [(now, name) for name, _ in results],
        )
        conn.commit()
        print(
            "retest: all %d failed, likely infra outage, "
            "fails not incremented" % len(results)
        )
        return 0
    for name, delay in results:
        if delay is not None:
            cur.execute(
                "UPDATE nodes SET status='alive', delay_ms=?, "
                "last_check=?, fails=0 WHERE name=?",
                (delay, now, name),
            )
            alive += 1
        else:
            cur.execute(
                "UPDATE nodes SET fails=fails+1, last_check=?, "
                "status=CASE WHEN fails+1 >= ? THEN 'failed' "
                "ELSE status END WHERE name=?",
                (now, args.max_fails, name),
            )
            failed += 1
    conn.commit()
    print(
        "retest: checked %d (seed +%d prune -%d): %d alive, %d failed"
        % (len(batch), added, pruned, alive, failed)
    )
    return 0


def load_secret(secret_file: str) -> str:
    if os.path.exists(secret_file):
        with open(secret_file, encoding="utf-8") as fh:
            return fh.read().strip()
    return ""


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--controller", default="http://127.0.0.1:9090")
    ap.add_argument("--secret-file", default=DEFAULT_SECRET_FILE)
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--group", default="PROXY")
    sub = ap.add_subparsers(dest="cmd", required=True)

    rot = sub.add_parser("rotate", help="select next alive node")
    rot.add_argument("--stale-after", type=int, default=7200)

    ret = sub.add_parser("retest", help="check oldest batch of nodes")
    ret.add_argument("--batch", type=int, default=500)
    ret.add_argument("--workers", type=int, default=20)
    ret.add_argument("--max-fails", type=int, default=3)
    ret.add_argument("--test-url", default="https://www.gstatic.com/generate_204")
    ret.add_argument("--timeout-ms", type=int, default=3000)

    skp = sub.add_parser("skip", help="mark a node failed and rotate now")
    skp.add_argument("name", help="proxy name to skip (e.g. the 429-flagged node)")
    skp.add_argument("--stale-after", type=int, default=7200)
    skp.add_argument("--max-fails", type=int, default=3)

    nxt = sub.add_parser("next", help="skip the current node and rotate now")
    nxt.add_argument("--stale-after", type=int, default=7200)
    nxt.add_argument("--max-fails", type=int, default=3)
    return ap


def validate_args(args: argparse.Namespace) -> Optional[str]:
    """Reject numeric CLI values that crash or misbehave. Returns error or None."""
    if args.cmd in ("retest", "skip", "next"):
        if args.max_fails < 1:
            return "--max-fails must be >= 1"
    if args.cmd == "retest":
        if args.batch < 1:
            return "--batch must be >= 1"
        if args.workers < 1:
            return "--workers must be >= 1"
        if args.timeout_ms < 500:
            return "--timeout-ms must be >= 500"
    if args.cmd in ("rotate", "skip", "next") and args.stale_after < 60:
        return "--stale-after must be >= 60"
    return None


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    err = validate_args(args)
    if err:
        print("error: %s" % err, file=sys.stderr)
        return 2
    secret = os.environ.get("MIHOMO_CONTROLLER_SECRET") or load_secret(args.secret_file)
    if not secret:
        print("error: no controller secret (env or --secret-file)", file=sys.stderr)
        return 2
    api = ClashAPI(args.controller, secret)
    if args.cmd == "rotate":
        return cmd_rotate(args, api)
    if args.cmd == "skip":
        return cmd_skip(args, api)
    if args.cmd == "next":
        return cmd_next(args, api)
    return cmd_retest(args, api)


if __name__ == "__main__":
    sys.exit(main())
