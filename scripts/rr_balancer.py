#!/usr/bin/env python3
# Sibling Docs: scripts/README.md | Decisions: scripts/DECISIONS.md
"""External round-robin balancer for mihomo (Clash API + SQLite state).

Owns the PROXY group's selection from outside mihomo: tests each node
through Clash itself, keeps liveness/delay/usage in SQLite, rotates the
selected node among alive ones, and retests dead nodes until they revive.

Subcommands:
  rotate   pick next node (least-used, fastest first) and select it
  retest   check a batch of nodes (oldest-checked first) and update state
  country  record the observed exit country for a batch of nodes
  report   print country coverage and per-country counts
  skip     mark one node failed and rotate now
  next     mark the current node failed and rotate now

Selection policy (fastest + fresh + fair):
  - pool = status 'alive' AND checked within STALE_AFTER seconds
  - pick lowest (uses, delay_ms): equal load first, fastest wins ties
  - optional --require-country CC keeps rotation inside one observed country
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
from typing import Any, Collection, Dict, List, Optional, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(REPO_ROOT, "data", "balancer_state.schema.sql")
DEFAULT_DB = os.path.join(REPO_ROOT, "data", "balancer_state.db")
DEFAULT_SECRET_FILE = os.path.expanduser("~/.config/mihomo-subs/.controller_secret")

# Google Search is the discriminator: flagged exits answer 302 -> /sorry,
# clean exits answer 200. Lightweight Google endpoints (generate_204,
# suggest) answer identically on blocked IPs, so they cannot be used.
DEFAULT_GOOGLE_URL = "https://www.google.com/search?q=test"
DEFAULT_PROXY_URL = "http://127.0.0.1:7890"
GOOGLE_SETTLE_SECONDS = 0.3

# Cloudflare's trace endpoint reports the country Cloudflare sees for the
# connection ("loc=XX"). Read through a candidate exit it is the observed
# country of that exit, which is what a geo-locked client actually gets --
# provider remarks are unreliable (most feeds carry hash-style names).
DEFAULT_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
TRACE_SETTLE_SECONDS = 0.3

# Group members that are selectors themselves, plus mihomo builtins:
# never enter the rotation pool.
META_NAMES = {"Auto", "Load Balance", "Fallback", "DIRECT", "REJECT", "PASS"}

# Failed nodes stay out of rotation and retest for this long, so a
# rate-limited exit cannot come back minutes later.
QUARANTINE_SECONDS = 24 * 3600


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

    def delay(
        self,
        name: str,
        test_url: str,
        timeout_ms: int,
        expected: Optional[int] = None,
    ) -> Optional[int]:
        query = {"timeout": timeout_ms, "url": test_url}
        if expected is not None:
            query["expected"] = expected
        qs = urllib.parse.urlencode(query)
        path = "/proxies/%s/delay?%s" % (urllib.parse.quote(name), qs)
        try:
            status, payload = self._request("GET", path)
        except Exception:
            return None
        if status != 200 or not isinstance(payload, dict):
            return None
        delay = payload.get("delay")
        return delay if isinstance(delay, int) and delay >= 0 else None

    def get_connections(self) -> List[Dict[str, Any]]:
        """Active connections (each carries chains metadata); [] on any error."""
        try:
            status, payload = self._request("GET", "/connections")
        except Exception:
            return []
        if status != 200 or not isinstance(payload, dict):
            return []
        conns = payload.get("connections")
        return conns if isinstance(conns, list) else []

    def close_connection(self, cid: str) -> bool:
        """Close one connection by id. True on 204/200/404, False otherwise, never raises."""
        try:
            status, _ = self._request(
                "DELETE", "/connections/" + urllib.parse.quote(str(cid))
            )
        except Exception:
            return False
        return status in (200, 204, 404)


def close_stale_connections(api: Any, prev_name: str) -> Tuple[int, List[str]]:
    """Close connections chained through prev_name. Returns (closed, failed_ids).

    Never raises: per-id errors are collected into failed_ids so rotation
    bookkeeping always completes.
    """
    closed = 0
    failed: List[str] = []
    try:
        connections = api.get_connections()
    except Exception:
        return 0, []
    for conn in connections:
        chains = conn.get("chains") if isinstance(conn, dict) else None
        cid = conn.get("id") if isinstance(conn, dict) else None
        if not cid or not chains or prev_name not in chains:
            continue
        try:
            ok = api.close_connection(cid)
        except Exception:
            ok = False
        if ok:
            closed += 1
        else:
            failed.append(str(cid))
    return closed, failed


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
    else:
        # Idempotent migrations for DBs created before newer columns.
        cols = [row[1] for row in conn.execute("PRAGMA table_info(nodes)")]
        for coldef in (
            "quarantined_until INTEGER NOT NULL DEFAULT 0",
            "last_fail_cause TEXT NOT NULL DEFAULT ''",
            "google_fails INTEGER NOT NULL DEFAULT 0",
            "country TEXT NOT NULL DEFAULT ''",
            "country_checked INTEGER NOT NULL DEFAULT 0",
        ):
            col = coldef.split()[0]
            if col not in cols:
                conn.execute("ALTER TABLE nodes ADD COLUMN %s" % coldef)
        # Legacy counters that existed only for the retired rate-limit-rescue
        # plugin. DROP COLUMN needs SQLite >= 3.35; the failure is swallowed
        # so an old database always opens even where the statement is
        # unsupported (the columns are simply left dormant).
        for legacy in ("quota_fails", "transport_fails", "region_fails"):
            if legacy in cols:
                try:
                    conn.execute("ALTER TABLE nodes DROP COLUMN %s" % legacy)
                except sqlite3.OperationalError:
                    pass
        conn.commit()
    return conn


def seed_names(conn: sqlite3.Connection, names: List[str]) -> Tuple[int, int]:
    """Insert unknown names; prune only unknowns gone from the controller.

    Learned rows (alive/failed with delay, uses, fails) survive feed
    refreshes so rotation keeps working across config regenerations;
    recurring names resume with their stats intact. Unknown rows carry
    no knowledge, so dropping them is free and bounds table growth.
    """
    cur = conn.cursor()
    cur.execute("SELECT name FROM nodes")
    known = {row[0] for row in cur.fetchall()}
    added = 0
    for name in names:
        if name not in known:
            cur.execute("INSERT INTO nodes (name) VALUES (?)", (name,))
            added += 1
    pruned = 0
    if names:
        cur.execute(
            "DELETE FROM nodes WHERE status = 'unknown' AND name NOT IN (%s)"
            % ",".join("?" * len(names)),
            names,
        )
        pruned = cur.rowcount
    conn.commit()
    return added, pruned


def alive_pool(
    conn: sqlite3.Connection,
    now: int,
    stale_after: int,
    allowed: Optional[Collection[str]] = None,
) -> List[Tuple[str, int, int, str]]:
    """Alive AND freshly checked nodes as (name, uses, delay_ms, country).

    When allowed is given, only names present in the controller's current
    member list are returned, so ghosts from older feeds are never picked.
    Quarantined nodes (failed less than 24h ago) are always excluded.
    country is the last observed exit country ("" when never measured), so
    a country lock can filter the pool without another probe.
    """
    cur = conn.cursor()
    query = (
        "SELECT name, uses, COALESCE(delay_ms, 999999), "
        "COALESCE(country, '') FROM nodes "
        "WHERE status = 'alive' AND (? - last_check) <= ? "
        "AND quarantined_until <= ?"
    )
    params: List[Any] = [now, stale_after, now]
    if allowed is not None:
        allowed = list(allowed)
        if not allowed:
            return []
        query += " AND name IN (%s)" % ",".join("?" * len(allowed))
        params.extend(allowed)
    cur.execute(query, params)
    return cur.fetchall()


def order_pool(
    pool: List[Tuple[str, int, int, str]],
) -> List[Tuple[str, int, int, str]]:
    """Least-used first, then fastest delay; no per-cause weighting."""
    return sorted(pool, key=lambda row: (row[1], row[2]))


def pick_next(pool: List[Tuple[str, int, int, str]]) -> Optional[str]:
    """Least-used first, then fastest delay; no per-cause weighting."""
    if not pool:
        return None
    return order_pool(pool)[0][0]


def google_clean(
    api: ClashAPI,
    group: str,
    name: str,
    url: str,
    timeout_ms: int,
    proxy_url: str = DEFAULT_PROXY_URL,
) -> bool:
    """Select the node, then read Google Search through it without redirects.

    mihomo's /delay endpoint follows the 302 to /sorry and reports the final
    200, so it cannot see the block. This probes the live selector instead:
    a blocked exit returns 302, a clean exit returns 200.

    The node stays selected; rotation keeps it when it passes and moves on
    when it does not, so no extra switch is needed.
    """
    api.select(group, name)
    if GOOGLE_SETTLE_SECONDS:
        time.sleep(GOOGLE_SETTLE_SECONDS)
    return probe_status_via_proxy(url, proxy_url, timeout_ms / 1000.0) == 200


def probe_status_via_proxy(url: str, proxy_url: str, timeout_s: float) -> Optional[int]:
    """HTTP status for url through proxy_url, redirects NOT followed.

    Returns None on transport errors. The body is not read, so a clean
    candidate costs one request and a blocked one only its 302 headers.
    """
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
        _NoRedirect,
    )
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131"}
    )
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn 3xx into an HTTPError so the status is visible to the caller."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_trace_country(body: str) -> Optional[str]:
    """Country code from a Cloudflare cdn-cgi/trace body.

    The body is line-oriented ("loc=US"). Only a real two-letter code is
    accepted; "XX" (Cloudflare's unknown/Tor marker), a missing line, or
    anything else returns None so callers store "unknown" instead of
    inventing a country.
    """
    for line in body.splitlines():
        if line.startswith("loc="):
            code = line[4:].strip().upper()
            if code == "XX":
                return None
            if len(code) == 2 and code.isalpha():
                return code
            return None
    return None


def probe_country_via_proxy(
    trace_url: str,
    proxy_url: str = DEFAULT_PROXY_URL,
    timeout_s: float = 8.0,
) -> Optional[str]:
    """Observed exit country for trace_url read through proxy_url.

    Returns a two-letter code, or None when the trace is unreachable or
    unparseable. None is a measurement failure, never a verdict about the
    node, so callers must not quarantine on it.
    """
    req = urllib.request.Request(
        trace_url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131"}
    )
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
            _NoRedirect,
        )
        with opener.open(req, timeout=timeout_s) as resp:
            if resp.status != 200:
                return None
            body = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    return parse_trace_country(body)


def google_reachable_direct(url: str, timeout_s: float = 8.0) -> bool:
    """Guard against quarantining the whole pool during a Google outage.

    Probes the same URL from the host without a proxy. If this fails, the
    per-node Google gate is skipped for this run instead of marking every
    node blocked (infra failure, not node failure).
    """
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status == 200
    except Exception:
        return False


def cmd_rotate(args: argparse.Namespace, api: ClashAPI) -> int:
    now = utc_now_epoch()
    conn = connect_db(args.db)
    pool_names, current = api.group_members(args.group)
    seed_names(conn, pool_names)
    pool = alive_pool(conn, now, args.stale_after, allowed=set(pool_names))
    ordered = order_pool(pool)
    if not ordered:
        conn.execute(
            "INSERT INTO rotation_log (ts, node, reason) VALUES (?, '', 'noop-empty-pool')",
            (now,),
        )
        conn.commit()
        print("rotate: empty alive pool, no-op (group untouched)")
        return 0
    name = None
    delay = None
    attempts = 0
    require_country = getattr(args, "require_country", None)
    if require_country:
        require_country = require_country.strip().upper()
        locked = [row for row in ordered if (row[3] or "").upper() == require_country]
        if not locked:
            print(
                "rotate: no %s candidates in the alive pool, keeping current %s"
                % (require_country, current or "selection")
            )
            return 0
        ordered = locked
    enforce_google = not getattr(args, "no_google_check", False)
    google_url = getattr(args, "google_url", DEFAULT_GOOGLE_URL)
    google_timeout = getattr(args, "google_timeout_ms", 8000)
    google_proxy = getattr(args, "google_proxy", DEFAULT_PROXY_URL)
    max_attempts = max(1, getattr(args, "google_attempts", 5))
    if enforce_google and not google_reachable_direct(google_url):
        print("rotate: google unreachable directly, skipping google gate")
        enforce_google = False
    selected_by_probe = False
    for candidate in ordered:
        if enforce_google and attempts < max_attempts:
            attempts += 1
            if google_clean(
                api, args.group, candidate[0], google_url, google_timeout, google_proxy
            ):
                name, delay = candidate[0], candidate[2]
                selected_by_probe = True
                break
            _mark_failed(
                conn,
                candidate[0],
                getattr(args, "max_fails", 3),
                now,
                "google",
            )
            continue
        name, delay = candidate[0], candidate[2]
        break
    if name is None:
        # Every checked candidate answered 302 /sorry: fail open to the best
        # one so the client keeps working instead of going dark. When a
        # country lock is active, this stays inside the locked subset.
        name, delay = ordered[0][0], ordered[0][2]
        print("rotate: all candidates google-blocked, failing open to %s" % name)
    if not selected_by_probe:
        api.select(args.group, name)
    if current and current != name:
        try:
            closed, failed = close_stale_connections(api, current)
        except Exception as exc:
            print("close stale after switch to %s failed: %s" % (name, exc))
        else:
            print(
                "closed %d stale connections of %s after switch to %s%s"
                % (
                    closed,
                    current,
                    name,
                    (" (failed ids: %s)" % ",".join(failed)) if failed else "",
                )
            )
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


def _mark_failed(
    conn: sqlite3.Connection,
    name: str,
    max_fails: int,
    now: int,
    reason: str = "manual",
) -> None:
    """Mark one node failed and quarantine it for 24h (retest readmits after expiry).

    Causes are the ones this balancer actually acts on: google (Search
    answers /sorry), country (exit does not match the required country),
    and manual (an operator skipped it). Only google increments its
    counter; the retired quota/transport/region causes belonged to the
    rate-limit-rescue plugin and were removed with their columns.
    """
    cur = conn.cursor()
    row = cur.execute("SELECT status FROM nodes WHERE name = ?", (name,)).fetchone()
    if row is None:
        print("skip: unknown node %r, rotating anyway" % name)
    else:
        cur.execute(
            "UPDATE nodes SET status = 'failed', fails = ?, last_check = ?, "
            "quarantined_until = ?, last_fail_cause = ?, "
            "google_fails = google_fails + ? WHERE name = ?",
            (
                max_fails,
                now,
                now + QUARANTINE_SECONDS,
                reason,
                1 if reason == "google" else 0,
                name,
            ),
        )
        conn.commit()
        print("skip: marked %s failed (%s, quarantined 24h)" % (name, reason))


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
    _mark_failed(
        conn, args.name, args.max_fails, now, getattr(args, "reason", "manual")
    )
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
        _mark_failed(
            conn, current, args.max_fails, now, getattr(args, "reason", "manual")
        )
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
    if not pool_names:
        batch = []
    else:
        cur.execute(
            "SELECT name FROM nodes WHERE name IN (%s) "
            "AND quarantined_until <= ? "
            "ORDER BY (status = 'alive') DESC, last_check ASC LIMIT ?"
            % ",".join("?" * len(pool_names)),
            (*pool_names, now, args.batch),
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
                "last_check=?, fails=0, quarantined_until=0, "
                "last_fail_cause='' WHERE name=?",
                (delay, now, name),
            )
            alive += 1
        else:
            cur.execute(
                "UPDATE nodes SET fails=fails+1, last_check=?, "
                "status=CASE WHEN fails+1 >= ? THEN 'failed' "
                "ELSE status END, "
                "quarantined_until=CASE WHEN fails+1 >= ? THEN ? "
                "ELSE quarantined_until END WHERE name=?",
                (now, args.max_fails, args.max_fails, now + QUARANTINE_SECONDS, name),
            )
            failed += 1
    conn.commit()
    print(
        "retest: checked %d (seed +%d prune -%d): %d alive, %d failed"
        % (len(batch), added, pruned, alive, failed)
    )
    return 0


def cmd_country(args: argparse.Namespace, api: ClashAPI) -> int:
    """Fill the observed country for a bounded batch of nodes.

    mihomo's /delay endpoint returns only a latency, so an exit's country
    can be read only by selecting that node and requesting the trace
    through the live mixed-port. The batch is therefore bounded, oldest
    measurement first, and the previous selection is restored in a
    finally block so a sweep never leaves traffic on a probed node.
    A node whose trace cannot be read is stored as unknown with a fresh
    country_checked stamp; it is never quarantined for that reason.
    """
    now = utc_now_epoch()
    conn = connect_db(args.db)
    pool_names, prev = api.group_members(args.group)
    added, pruned = seed_names(conn, pool_names)
    cur = conn.cursor()
    batch = []
    checked = 0
    measured = 0
    try:
        if pool_names:
            cur.execute(
                "SELECT name FROM nodes WHERE name IN (%s) "
                "AND quarantined_until <= ? "
                "ORDER BY country_checked ASC, last_check ASC LIMIT ?"
                % ",".join("?" * len(pool_names)),
                (*pool_names, now, args.batch),
            )
            batch = [row[0] for row in cur.fetchall()]
        for name in batch:
            api.select(args.group, name)
            if TRACE_SETTLE_SECONDS:
                time.sleep(TRACE_SETTLE_SECONDS)
            code = probe_country_via_proxy(
                args.trace_url, args.trace_proxy, args.trace_timeout_ms / 1000.0
            )
            cur.execute(
                "UPDATE nodes SET country = ?, country_checked = ? WHERE name = ?",
                (code or "", now, name),
            )
            conn.commit()
            checked += 1
            if code:
                measured += 1
            print("country: %s -> %s" % (name, code or "unknown"))
    finally:
        if prev:
            try:
                api.select(args.group, prev)
            except Exception as exc:
                print("country: could not restore %s: %s" % (prev, exc))
    print(
        "country: checked %d (seed +%d prune -%d): %d measured, %d unknown"
        % (len(batch), added, pruned, measured, checked - measured)
    )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Print country coverage and per-country counts (no controller needed)."""
    conn = connect_db(args.db)
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
    checked = cur.execute(
        "SELECT COUNT(*) FROM nodes WHERE country_checked > 0"
    ).fetchone()[0]
    rows = cur.execute(
        "SELECT CASE WHEN country = '' THEN 'unknown' ELSE country END, "
        "COUNT(*), SUM(CASE WHEN status = 'alive' THEN 1 ELSE 0 END) "
        "FROM nodes GROUP BY 1 ORDER BY 2 DESC"
    ).fetchall()
    print("report: country coverage %d/%d checked" % (checked, total))
    for country, count, alive in rows:
        print("  %-8s %5d total %5d alive" % (country, count, alive or 0))
    return 0


def load_secret(secret_file: str) -> str:
    if os.path.exists(secret_file):
        with open(secret_file, encoding="utf-8") as fh:
            return fh.read().strip()
    return ""


def add_google_args(parser: argparse.ArgumentParser) -> None:
    """Google-clean gate flags shared by rotate/skip/next."""
    parser.add_argument(
        "--google-url",
        default=DEFAULT_GOOGLE_URL,
        help="URL that must answer 200; flagged exits answer 302 /sorry",
    )
    parser.add_argument("--google-timeout-ms", type=int, default=8000)
    parser.add_argument(
        "--google-proxy",
        default=DEFAULT_PROXY_URL,
        help="mihomo mixed-port used to read Google through the live selector",
    )
    parser.add_argument(
        "--google-attempts",
        type=int,
        default=5,
        help="max candidates to reject for /sorry before failing open",
    )
    parser.add_argument(
        "--no-google-check",
        action="store_true",
        help="disable the Google-clean gate for this run",
    )


def add_country_lock_arg(parser: argparse.ArgumentParser) -> None:
    """Country lock shared by rotate/skip/next.

    Opt-in by design: the alarm is only useful once `country` coverage is
    high, and a lock on an empty country column would freeze rotation.
    """
    parser.add_argument(
        "--require-country",
        default=None,
        metavar="CC",
        help="only rotate to exits whose observed country is CC (e.g. US); "
        "keeps the current node when no candidate matches",
    )


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--controller", default="http://127.0.0.1:9090")
    ap.add_argument("--secret-file", default=DEFAULT_SECRET_FILE)
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--group", default="PROXY")
    sub = ap.add_subparsers(dest="cmd", required=True)

    rot = sub.add_parser("rotate", help="select next alive node")
    rot.add_argument("--stale-after", type=int, default=7200)
    add_google_args(rot)
    add_country_lock_arg(rot)

    ret = sub.add_parser("retest", help="check oldest batch of nodes")
    ret.add_argument("--batch", type=int, default=500)
    ret.add_argument("--workers", type=int, default=20)
    ret.add_argument("--max-fails", type=int, default=3)
    ret.add_argument("--test-url", default="https://www.gstatic.com/generate_204")
    ret.add_argument("--timeout-ms", type=int, default=3000)

    skp = sub.add_parser("skip", help="mark a node failed and rotate now")
    skp.add_argument(
        "name", help="proxy name to skip (e.g. a rate-limited crawl target)"
    )
    skp.add_argument("--stale-after", type=int, default=7200)
    skp.add_argument("--max-fails", type=int, default=3)
    skp.add_argument(
        "--reason",
        choices=("google", "country", "manual"),
        default="manual",
        help="failure cause recorded for the node",
    )
    add_google_args(skp)
    add_country_lock_arg(skp)

    nxt = sub.add_parser("next", help="skip the current node and rotate now")
    nxt.add_argument("--stale-after", type=int, default=7200)
    nxt.add_argument("--max-fails", type=int, default=3)
    nxt.add_argument(
        "--reason",
        choices=("google", "country", "manual"),
        default="manual",
        help="failure cause recorded for the node",
    )
    add_google_args(nxt)
    add_country_lock_arg(nxt)

    cty = sub.add_parser("country", help="fill observed exit countries for a batch")
    cty.add_argument("--batch", type=int, default=20)
    cty.add_argument("--trace-url", default=DEFAULT_TRACE_URL)
    cty.add_argument("--trace-timeout-ms", type=int, default=8000)
    cty.add_argument(
        "--trace-proxy",
        default=DEFAULT_PROXY_URL,
        help="mihomo mixed-port used to read the trace through each candidate",
    )

    sub.add_parser("report", help="print country coverage and per-country counts")
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
    if args.cmd == "country":
        if args.batch < 1:
            return "--batch must be >= 1"
        if args.trace_timeout_ms < 500:
            return "--trace-timeout-ms must be >= 500"
    if args.cmd in ("rotate", "skip", "next") and args.stale_after < 60:
        return "--stale-after must be >= 60"
    if args.cmd in ("rotate", "skip", "next"):
        if args.google_timeout_ms < 500:
            return "--google-timeout-ms must be >= 500"
        if args.google_attempts < 1:
            return "--google-attempts must be >= 1"
        if args.require_country is not None:
            cc = args.require_country.strip()
            if len(cc) != 2 or not cc.isalpha():
                return "--require-country must be a two-letter country code"
    return None


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    err = validate_args(args)
    if err:
        print("error: %s" % err, file=sys.stderr)
        return 2
    if args.cmd == "report":
        return cmd_report(args)
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
    if args.cmd == "country":
        return cmd_country(args, api)
    return cmd_retest(args, api)


if __name__ == "__main__":
    sys.exit(main())
