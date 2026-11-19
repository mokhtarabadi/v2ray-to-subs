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

# YouTube backend is the app-relevant discriminator: flagged exits answer
# 403 on oEmbed metadata while youtube.com/ and music.youtube.com/ still
# answer 200, so landing pages cannot be used. Clean exits answer 200 JSON.
DEFAULT_YOUTUBE_URL = (
    "https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=aqz-KE-bpKQ"
)

# Spotify API edge block is an HTML 403 before auth evaluation; a clean
# exit reaches auth evaluation and answers 401 JSON ("no token"). So the
# probe classifies by status AND body shape, not status alone.
DEFAULT_SPOTIFY_URL = "https://api.spotify.com/v1/search?q=test&type=track"

# Gemini is the strict spare: Google's datacenter-IP detection 403s exits
# that pass Search, so a Gemini-clean exit is clean everywhere measured.
DEFAULT_GEMINI_URL = "https://gemini.google.com/"

# Throughput probe: Cloudflare serves an exact byte count, so the test is
# bounded by construction. Big enough to separate throttled exits from
# healthy ones, small enough to stay polite to free nodes.
DEFAULT_SPEED_URL = "https://speed.cloudflare.com/__down?bytes=3000000"
DEFAULT_SPEED_BYTES = 3000000

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
# rate-limited exit cannot come back minutes later. This is the *code default*;
# the effective value for a process is resolved from CLI > env > this default.
QUARANTINE_SECONDS = 24 * 3600

# Effective quarantine window for this process. ``main()`` resolves it once
# from --quarantine-seconds / RR_QUARANTINE_SECONDS; direct function callers and
# unit tests that never enter main() keep the 24h default.
_quarantine_seconds: int = QUARANTINE_SECONDS


def resolve_quarantine_seconds(cli_value: Optional[int] = None) -> int:
    """Resolve the quarantine window: CLI, then env, then the 24h default.

    Why: the operator may want a shorter window (e.g. 12h) without editing code,
    while unit tests must stay deterministic with no environment configured.

    Args:
        cli_value: value of ``--quarantine-seconds`` when supplied, else None.

    Returns:
        Positive integer number of seconds to quarantine a failed node.

    Edge cases: an empty env string counts as unset; a non-integer or
    non-positive value raises ValueError so callers fail loudly rather than
    parking nodes for a nonsensical interval.
    """
    if cli_value is not None:
        seconds = int(cli_value)
        if seconds <= 0:
            raise ValueError("quarantine seconds must be positive, got %r" % (cli_value,))
        return seconds
    env_value = os.environ.get("RR_QUARANTINE_SECONDS")
    if env_value is not None and env_value.strip() != "":
        seconds = int(env_value)
        if seconds <= 0:
            raise ValueError(
                "RR_QUARANTINE_SECONDS must be positive, got %r" % (env_value,)
            )
        return seconds
    return QUARANTINE_SECONDS


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
            "youtube_fails INTEGER NOT NULL DEFAULT 0",
            "spotify_fails INTEGER NOT NULL DEFAULT 0",
            "gemini_fails INTEGER NOT NULL DEFAULT 0",
            "country TEXT NOT NULL DEFAULT ''",
            "country_checked INTEGER NOT NULL DEFAULT 0",
            "opencode_ok INTEGER NOT NULL DEFAULT 0",
            "opencode_checked INTEGER NOT NULL DEFAULT 0",
            "opencode_delay_ms INTEGER",
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
    Quarantined nodes (still inside their configurable window) are always excluded.
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


def youtube_clean(
    api: ClashAPI,
    group: str,
    name: str,
    url: str,
    timeout_ms: int,
    proxy_url: str = DEFAULT_PROXY_URL,
) -> Optional[bool]:
    """Same select-settle shape as google_clean, tri-state YouTube verdict.

    200 is clean, 403 is flagged, anything else (transport error,
    rate-limit, removed video) is unknown and never a verdict.
    """
    api.select(group, name)
    if GOOGLE_SETTLE_SECONDS:
        time.sleep(GOOGLE_SETTLE_SECONDS)
    status = probe_status_via_proxy(url, proxy_url, timeout_ms / 1000.0)
    if status is None:
        return None
    if status == 200:
        return True
    if status == 403:
        return False
    return None


def gemini_clean(
    api: ClashAPI,
    group: str,
    name: str,
    url: str,
    timeout_ms: int,
    proxy_url: str = DEFAULT_PROXY_URL,
) -> Optional[bool]:
    """Same select-settle shape as google_clean, tri-state Gemini verdict.

    200 is clean, 403 is flagged, anything else is unknown and never
    a verdict.
    """
    api.select(group, name)
    if GOOGLE_SETTLE_SECONDS:
        time.sleep(GOOGLE_SETTLE_SECONDS)
    status = probe_status_via_proxy(url, proxy_url, timeout_ms / 1000.0)
    if status is None:
        return None
    if status == 200:
        return True
    if status == 403:
        return False
    return None


def probe_spotify_clean(url: str, proxy_url: str, timeout_s: float) -> Optional[bool]:
    """Classify a Spotify API read: True clean, False flagged, None unknown.

    The edge answers 401 JSON once the request reaches auth evaluation
    (documented no-token behavior) and 403 HTML when the exit IP is
    blocked before auth. Anything else (rate-limit, transport error) is
    unknown, and unknown is never a verdict.
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
            status, body = resp.status, resp.read(512)
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            body = exc.read(512)
        except Exception:
            body = b""
    except Exception:
        return None
    if status == 401 and b'"error"' in body:
        return True
    if status == 403:
        return False
    return None


def spotify_clean(
    api: ClashAPI,
    group: str,
    name: str,
    url: str,
    timeout_ms: int,
    proxy_url: str = DEFAULT_PROXY_URL,
) -> Optional[bool]:
    """Select, settle, then classify the Spotify API shape (None = unknown)."""
    api.select(group, name)
    if GOOGLE_SETTLE_SECONDS:
        time.sleep(GOOGLE_SETTLE_SECONDS)
    return probe_spotify_clean(url, proxy_url, timeout_ms / 1000.0)


def multi_gate_cause(
    api: ClashAPI, group: str, name: str, args: argparse.Namespace
) -> Optional[str]:
    """First-flagged cause across the probe battery, or None when clean.

    Order is Google, YouTube, Spotify, Gemini(spare): cheapest and most
    discriminating first. "unknown" means a new-probe measurement failed
    (transport or unexpected shape) and must not quarantine anyone;
    legacy Google keeps its strict None-is-flagged shape. No gate
    enabled returns None.
    """
    battery = []
    if not getattr(args, "no_google_check", False):
        battery.append(
            (
                "google",
                getattr(args, "google_url", DEFAULT_GOOGLE_URL),
                getattr(args, "google_timeout_ms", 8000),
            )
        )
    if not getattr(args, "no_youtube_check", False):
        battery.append(
            (
                "youtube",
                getattr(args, "youtube_url", DEFAULT_YOUTUBE_URL),
                getattr(args, "youtube_timeout_ms", 8000),
            )
        )
    if not getattr(args, "no_spotify_check", False):
        battery.append(
            (
                "spotify",
                getattr(args, "spotify_url", DEFAULT_SPOTIFY_URL),
                getattr(args, "spotify_timeout_ms", 8000),
            )
        )
    if not getattr(args, "no_gemini_check", False):
        battery.append(
            (
                "gemini",
                getattr(args, "gemini_url", DEFAULT_GEMINI_URL),
                getattr(args, "gemini_timeout_ms", 8000),
            )
        )
    if not battery:
        return None
    # All probes share the live mixed-port; google_proxy names that port.
    proxy_url = getattr(args, "google_proxy", DEFAULT_PROXY_URL)
    for cause, url, timeout_ms in battery:
        if cause == "spotify":
            verdict = spotify_clean(api, group, name, url, timeout_ms, proxy_url)
            if verdict is True:
                continue
            return "unknown" if verdict is None else cause
        if cause == "youtube":
            passed = youtube_clean(api, group, name, url, timeout_ms, proxy_url)
        elif cause == "gemini":
            passed = gemini_clean(api, group, name, url, timeout_ms, proxy_url)
        else:
            passed = google_clean(api, group, name, url, timeout_ms, proxy_url)
        if cause == "google":
            if not passed:
                return cause
        elif passed is None:
            return "unknown"
        elif not passed:
            return cause
    return None


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


def probe_opencode_via_proxy(
    url: str,
    proxy_url: str = DEFAULT_PROXY_URL,
    timeout_s: float = 8.0,
) -> Tuple[bool, Optional[int]]:
    """Real-HTTPS verdict for ``url`` read through the mihomo mixed-port.

    Why: mihomo's /delay only proves a TCP/TLS handshake, not that the exit can
    actually carry a request to opencode.ai (task 24 measured a node with a
    35ms delay that carried no traffic). This opens the URL through
    ``proxy_url`` with redirects disabled and classifies the response.

    Returns ``(ok, delay_ms)``. ``ok`` is True only for HTTP 200; 429 (quota or
    gate), 4xx/5xx and any transport failure are False. ``delay_ms`` is the
    round trip in integer milliseconds, or None when the request failed.

    Edge cases: non-200 is a normal failure verdict, not an exception; a
    timeout or malformed URL yields ``(False, None)``; redirects are not
    followed so a gate redirect is not mistaken for success.
    """
    started = time.monotonic()
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131"}
    )
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
            _NoRedirect,
        )
        with opener.open(req, timeout=timeout_s) as resp:
            status = resp.status
            resp.read()  # drain so the connection closes cleanly
        elapsed_ms = int(round((time.monotonic() - started) * 1000))
        return (status == 200, elapsed_ms)
    except urllib.error.HTTPError as exc:
        # A non-2xx is a real network answer but not a working exit.
        elapsed_ms = int(round((time.monotonic() - started) * 1000))
        return (False, elapsed_ms)
    except Exception:
        return (False, None)


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

    # A quota 429 means the exit itself spent its free-tier allowance, not that
    # the route is slow or dirty. Park it for the configured window so the next
    # rotation cannot pick the same spent exit, then fall through to selection.
    # With no other candidate, keep the current node: going dark is worse than
    # retrying an already-limited exit.
    reason = getattr(args, "reason", None)
    log_reason = "rotate"
    if reason == "quota" and current:
        _mark_failed(conn, current, getattr(args, "max_fails", 3), now, "quota")
        ordered = [row for row in ordered if row[0] != current]
        log_reason = "quota"
        if not ordered:
            conn.execute(
                "INSERT INTO rotation_log (ts, node, reason) VALUES (?, ?, 'quota-failopen')",
                (now, current),
            )
            conn.commit()
            print(
                "rotate: quota node %s quarantined, no other candidate, failing open"
                % current
            )
            api.select(args.group, current)
            return 0

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
    if getattr(args, "keep_if_clean", False) and current:
        alive_names = set(row[0] for row in ordered)
        if current in alive_names:
            keep_cause = multi_gate_cause(api, args.group, current, args)
            if keep_cause is None or keep_cause == "unknown":
                if keep_cause == "unknown":
                    print(
                        "rotate: current %s probe inconclusive, keeping without quarantine"
                        % current
                    )
                else:
                    print("rotate: current %s still clean, keeping" % current)
                cur = conn.cursor()
                cur.execute(
                    "UPDATE nodes SET uses = uses + 1 WHERE name = ?", (current,)
                )
                cur.execute(
                    "INSERT INTO rotation_log (ts, node, delay_ms, reason) "
                    "VALUES (?, ?, ?, 'keep-clean')",
                    (now, current, None),
                )
                cur.execute(
                    "INSERT OR REPLACE INTO rotation_state (id, position, updated_at) "
                    "VALUES (1, (SELECT COALESCE(position, 0) FROM rotation_state "
                    "WHERE id = 1) + 1, ?)",
                    (now,),
                )
                conn.commit()
                return 0
            _mark_failed(
                conn,
                current,
                getattr(args, "max_fails", 3),
                now,
                keep_cause,
            )
            ordered = [row for row in ordered if row[0] != current]
            if not ordered:
                print(
                    "rotate: current %s dirty and no other candidates, "
                    "failing open to current" % current
                )
                api.select(args.group, current)
                return 0
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
    gates_on = [
        svc
        for svc in ("google", "youtube", "spotify", "gemini")
        if not getattr(args, "no_%s_check" % svc, False)
    ]
    google_url = getattr(args, "google_url", DEFAULT_GOOGLE_URL)
    max_attempts = max(
        1,
        max(
            getattr(args, "%s_attempts" % svc, 5)
            for svc in ("google", "youtube", "spotify", "gemini")
        ),
    )
    if gates_on and not google_reachable_direct(google_url):
        print("rotate: google unreachable directly, skipping probe gates")
        gates_on = []
    selected_by_probe = False
    for candidate in ordered:
        if gates_on and attempts < max_attempts:
            attempts += 1
            cause = multi_gate_cause(api, args.group, candidate[0], args)
            if cause is None or cause == "unknown":
                if cause == "unknown":
                    print(
                        "rotate: probe inconclusive for %s, keeping without quarantine"
                        % candidate[0]
                    )
                name, delay = candidate[0], candidate[2]
                selected_by_probe = True
                break
            _mark_failed(
                conn,
                candidate[0],
                getattr(args, "max_fails", 3),
                now,
                cause,
            )
            continue
        name, delay = candidate[0], candidate[2]
        break
    if name is None:
        # Every checked candidate answered 302 /sorry: fail open to the best
        # one so the client keeps working instead of going dark. When a
        # country lock is active, this stays inside the locked subset.
        name, delay = ordered[0][0], ordered[0][2]
        print("rotate: all candidates gate-blocked, failing open to %s" % name)
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
        "VALUES (?, ?, ?, ?)",
        (now, name, None if delay >= 999999 else delay, log_reason),
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
    quarantine_seconds: Optional[int] = None,
) -> None:
    """Mark one node failed and quarantine it (retest readmits after expiry).

    The quarantine length is the process-wide effective value resolved by
    ``resolve_quarantine_seconds``; callers may override it explicitly. The
    default of ``None`` keeps direct callers and unit tests deterministic.

    Causes are the ones this balancer actually acts on: google (Search
    answers /sorry), youtube (oEmbed answers 403), spotify (API edge
    answers HTML 403), gemini (app answers 403), country (exit does not
    match the required country), quota (the free-tier allowance on this
    exit is spent), and manual (an operator skipped it).
    Each probe cause increments its own counter. Quota is stored on
    ``last_fail_cause`` only: its quarantine is enough to keep a spent exit
    out of rotation, and no per-cause counter was restored.
    Transport and region causes remain retired with their columns.
    """
    if quarantine_seconds is None:
        quarantine_seconds = _quarantine_seconds

    cur = conn.cursor()
    row = cur.execute("SELECT status FROM nodes WHERE name = ?", (name,)).fetchone()
    if row is None:
        print("skip: unknown node %r, rotating anyway" % name)
    else:
        cur.execute(
            "UPDATE nodes SET status = 'failed', fails = ?, last_check = ?, "
            "quarantined_until = ?, last_fail_cause = ?, "
            "google_fails = google_fails + ?, "
            "youtube_fails = youtube_fails + ?, "
            "spotify_fails = spotify_fails + ?, "
            "gemini_fails = gemini_fails + ? WHERE name = ?",
            (
                max_fails,
                now,
                now + quarantine_seconds,
                reason,
                1 if reason == "google" else 0,
                1 if reason == "youtube" else 0,
                1 if reason == "spotify" else 0,
                1 if reason == "gemini" else 0,
                name,
            ),
        )
        conn.commit()
        print(
            "skip: marked %s failed (%s, quarantined %sh)"
            % (name, reason, quarantine_seconds // 3600)
        )


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


def probe_throughput(
    url: str, proxy_url: str, max_bytes: int, timeout_s: float
) -> Optional[float]:
    """Download up to max_bytes through the live selector, return bytes/sec.

    One bounded read: slow or failing exits cost at most timeout_s, never
    a stall. Returns None on any transport failure. Slowness is a signal,
    never a quarantine verdict — callers must not fail nodes on it.
    """
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
        _NoRedirect,
    )
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131"}
    )
    if max_bytes < 65536:
        max_bytes = 65536
    start = time.monotonic()
    deadline = start + timeout_s
    total = 0
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            if resp.status != 200:
                return None
            while total < max_bytes:
                if time.monotonic() >= deadline:
                    break
                chunk = resp.read(min(65536, max_bytes - total))
                if not chunk:
                    break
                total += len(chunk)
    except Exception:
        return None
    elapsed = time.monotonic() - start
    if total <= 0 or elapsed <= 0:
        return None
    return total / elapsed


def cmd_fastest(args: argparse.Namespace, api: ClashAPI) -> int:
    """Pick the fastest of the top gate-clean finalists, on demand only.

    Gates the ordered pool like rotate (flagged candidates quarantine
    with cause), speed-tests the first --top clean finalists with a
    bounded download each, and selects the fastest. Slow losers are
    never quarantined. Never runs on the timer: speed costs traffic
    and time, so this stays a manual decision.
    """
    now = utc_now_epoch()
    conn = connect_db(args.db)
    pool_names, current = api.group_members(args.group)
    seed_names(conn, pool_names)
    pool = alive_pool(conn, now, args.stale_after, allowed=set(pool_names))
    ordered = order_pool(pool)
    require_country = getattr(args, "require_country", None)
    if require_country:
        require_country = require_country.strip().upper()
        locked = [row for row in ordered if (row[3] or "").upper() == require_country]
        if not locked:
            print(
                "fastest: no %s candidates in the alive pool, keeping current %s"
                % (require_country, current or "selection")
            )
            return 0
        ordered = locked
    max_attempts = max(
        1,
        max(
            getattr(args, "%s_attempts" % svc, 5)
            for svc in ("google", "youtube", "spotify", "gemini")
        ),
    )
    proxy_url = getattr(args, "google_proxy", DEFAULT_PROXY_URL)
    speed_url = getattr(args, "speed_url", DEFAULT_SPEED_URL)
    speed_bytes = max(65536, getattr(args, "speed_bytes", DEFAULT_SPEED_BYTES))
    speed_timeout = getattr(args, "speed_timeout_ms", 30000) / 1000.0
    top_n = max(1, getattr(args, "top", 3))
    attempts = 0
    finalists = []
    for candidate in ordered:
        if len(finalists) >= top_n or attempts >= max_attempts:
            break
        attempts += 1
        cause = multi_gate_cause(api, args.group, candidate[0], args)
        if cause is None or cause == "unknown":
            finalists.append(candidate[0])
        elif cause != "unknown":
            _mark_failed(conn, candidate[0], getattr(args, "max_fails", 3), now, cause)
    if not finalists:
        print("fastest: no clean finalists, keeping current selection")
        return 0
    results = []
    for name in finalists:
        api.select(args.group, name)
        if GOOGLE_SETTLE_SECONDS:
            time.sleep(GOOGLE_SETTLE_SECONDS)
        rate = probe_throughput(speed_url, proxy_url, speed_bytes, speed_timeout)
        print("fastest: %s %.0f B/s" % (name, rate if rate is not None else -1))
        results.append((name, rate if rate is not None else -1))
    results.sort(key=lambda row: row[1], reverse=True)
    winner = results[0][0]
    api.select(args.group, winner)
    if current and current != winner:
        try:
            closed, failed = close_stale_connections(api, current)
        except Exception as exc:
            print("close stale after switch to %s failed: %s" % (winner, exc))
        else:
            print(
                "closed %d stale connections of %s after switch to %s%s"
                % (
                    closed,
                    current,
                    winner,
                    (" (failed ids: %s)" % ",".join(failed)) if failed else "",
                )
            )
    cur = conn.cursor()
    cur.execute("UPDATE nodes SET uses = uses + 1 WHERE name = ?", (winner,))
    cur.execute(
        "INSERT INTO rotation_log (ts, node, delay_ms, reason) "
        "VALUES (?, ?, ?, 'fastest')",
        (now, winner, None),
    )
    cur.execute(
        "INSERT OR REPLACE INTO rotation_state (id, position, updated_at) "
        "VALUES (1, (SELECT COALESCE(position, 0) FROM rotation_state "
        "WHERE id = 1) + 1, ?)",
        (now,),
    )
    conn.commit()
    print("fastest: selected %s" % winner)
    return 0


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
                (
                    now,
                    args.max_fails,
                    args.max_fails,
                    now + _quarantine_seconds,
                    name,
                ),
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


def cmd_opencode_probe(args: argparse.Namespace, api: ClashAPI) -> int:
    """Verify through a real HTTPS request that bounded nodes reach opencode.ai.

    A low mihomo /delay is not proof a node carries traffic (task 24). This
    selects each node briefly, opens ``args.opencode_url`` through the mixed
    port, records a 200-only verdict plus delay, and restores the previous
    PROXY selection in a ``finally`` block so a sweep never strands traffic on
    a probed node. A failed probe is a measurement, never a quarantine.

    Gated by ``args.opencode_enabled`` (env RR_OPENCODE_PROBE_ENABLED); off
    means a no-op so operators can disable a noisy probe without editing units.
    """
    if not getattr(args, "opencode_enabled", True):
        print("opencode-probe: disabled (RR_OPENCODE_PROBE_ENABLED=0)")
        return 0
    now = utc_now_epoch()  # epoch seconds, consistent with other stamps
    conn = connect_db(args.db)
    pool_names, prev = api.group_members(args.group)
    added, pruned = seed_names(conn, pool_names)
    cur = conn.cursor()
    batch = []
    working = 0
    try:
        if pool_names:
            cur.execute(
                "SELECT name FROM nodes WHERE name IN (%s) "
                "AND quarantined_until <= ? "
                "ORDER BY opencode_checked ASC, last_check ASC LIMIT ?"
                % ",".join("?" * len(pool_names)),
                (*pool_names, now, args.batch),
            )
            batch = [row[0] for row in cur.fetchall()]
        for name in batch:
            api.select(args.group, name)
            if TRACE_SETTLE_SECONDS:
                time.sleep(TRACE_SETTLE_SECONDS)
            # A probe exception is a failed measurement for this node, never a
            # reason to abort the sweep or strand the selector on a probed exit.
            try:
                ok, delay_ms = probe_opencode_via_proxy(
                    args.opencode_url,
                    args.opencode_proxy,
                    args.opencode_timeout_ms / 1000.0,
                )
            except Exception as exc:
                print("opencode-probe: %s probe error: %s" % (name, exc))
                ok, delay_ms = False, None
            cur.execute(
                "UPDATE nodes SET opencode_ok = ?, opencode_checked = ?, "
                "opencode_delay_ms = ? WHERE name = ?",
                (1 if ok else 0, now, delay_ms, name),
            )
            conn.commit()
            if ok:
                working += 1
            print("opencode-probe: %s -> %s" % (name, "ok" if ok else "failed"))
    finally:
        # Always put the selector back, even on a probe exception.
        if prev:
            try:
                api.select(args.group, prev)
            except Exception as exc:
                print("opencode-probe: could not restore %s: %s" % (prev, exc))
    print(
        "opencode-probe: checked %d (seed +%d prune -%d): %d working, %d failed"
        % (len(batch), added, pruned, working, len(batch) - working)
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


def add_youtube_args(parser: argparse.ArgumentParser) -> None:
    """YouTube-backend gate flags shared by rotate/skip/next."""
    parser.add_argument(
        "--youtube-url",
        default=DEFAULT_YOUTUBE_URL,
        help="URL that must answer 200; flagged exits answer 403",
    )
    parser.add_argument("--youtube-timeout-ms", type=int, default=8000)
    parser.add_argument(
        "--youtube-attempts",
        type=int,
        default=5,
        help="max gated candidates before failing open (shared budget)",
    )
    parser.add_argument(
        "--no-youtube-check",
        action="store_true",
        help="disable the YouTube-clean gate for this run",
    )


def add_spotify_args(parser: argparse.ArgumentParser) -> None:
    """Spotify-API gate flags shared by rotate/skip/next."""
    parser.add_argument(
        "--spotify-url",
        default=DEFAULT_SPOTIFY_URL,
        help="URL that must answer 401 JSON; flagged exits answer HTML 403",
    )
    parser.add_argument("--spotify-timeout-ms", type=int, default=8000)
    parser.add_argument(
        "--spotify-attempts",
        type=int,
        default=5,
        help="max gated candidates before failing open (shared budget)",
    )
    parser.add_argument(
        "--no-spotify-check",
        action="store_true",
        help="disable the Spotify-clean gate for this run",
    )


def add_gemini_args(parser: argparse.ArgumentParser) -> None:
    """Gemini spare-gate flags shared by rotate/skip/next."""
    parser.add_argument(
        "--gemini-url",
        default=DEFAULT_GEMINI_URL,
        help="URL that must answer 200; flagged exits answer 403",
    )
    parser.add_argument("--gemini-timeout-ms", type=int, default=8000)
    parser.add_argument(
        "--gemini-attempts",
        type=int,
        default=5,
        help="max gated candidates before failing open (shared budget)",
    )
    parser.add_argument(
        "--no-gemini-check",
        action="store_true",
        help="disable the Gemini-clean gate for this run",
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
    ap.add_argument(
        "--quarantine-seconds",
        type=int,
        default=None,
        help="failed-node quarantine window in seconds (overrides RR_QUARANTINE_SECONDS; default 86400)",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    rot = sub.add_parser("rotate", help="select next alive node")
    rot.add_argument("--stale-after", type=int, default=7200)
    rot.add_argument(
        "--reason",
        choices=("google", "youtube", "spotify", "gemini", "country", "manual", "quota"),
        default="manual",
        help="failure cause; quota quarantines the current exit before rotating",
    )
    rot.add_argument(
        "--keep-if-clean",
        action="store_true",
        help="gate the current node first and keep it when clean; "
        "rotate only when it is dirty",
    )
    add_google_args(rot)
    add_youtube_args(rot)
    add_spotify_args(rot)
    add_gemini_args(rot)
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
        choices=("google", "youtube", "spotify", "gemini", "country", "manual", "quota"),
        default="manual",
        help="failure cause recorded for the node",
    )
    add_google_args(skp)
    add_youtube_args(skp)
    add_spotify_args(skp)
    add_gemini_args(skp)
    add_country_lock_arg(skp)

    nxt = sub.add_parser("next", help="skip the current node and rotate now")
    nxt.add_argument("--stale-after", type=int, default=7200)
    nxt.add_argument("--max-fails", type=int, default=3)
    nxt.add_argument(
        "--reason",
        choices=("google", "youtube", "spotify", "gemini", "country", "manual", "quota"),
        default="manual",
        help="failure cause recorded for the node",
    )
    add_google_args(nxt)
    add_youtube_args(nxt)
    add_spotify_args(nxt)
    add_gemini_args(nxt)
    add_country_lock_arg(nxt)

    fst = sub.add_parser(
        "fastest", help="pick the fastest of the top gate-clean finalists"
    )
    fst.add_argument("--stale-after", type=int, default=7200)
    fst.add_argument(
        "--top",
        type=int,
        default=3,
        help="gate-clean finalists to speed-test before picking",
    )
    fst.add_argument(
        "--speed-url",
        default=DEFAULT_SPEED_URL,
        help="exact-byte download read through each finalist",
    )
    fst.add_argument("--speed-bytes", type=int, default=DEFAULT_SPEED_BYTES)
    fst.add_argument("--speed-timeout-ms", type=int, default=30000)
    fst.add_argument("--max-fails", type=int, default=3)
    add_google_args(fst)
    add_youtube_args(fst)
    add_spotify_args(fst)
    add_gemini_args(fst)
    add_country_lock_arg(fst)

    cty = sub.add_parser("country", help="fill observed exit countries for a batch")
    cty.add_argument("--batch", type=int, default=20)
    cty.add_argument("--trace-url", default=DEFAULT_TRACE_URL)
    cty.add_argument("--trace-timeout-ms", type=int, default=8000)
    cty.add_argument(
        "--trace-proxy",
        default=DEFAULT_PROXY_URL,
        help="mihomo mixed-port used to read the trace through each candidate",
    )

    ocp = sub.add_parser(
        "opencode-probe",
        help="verify via real HTTPS that a batch of exits reaches opencode.ai",
    )
    ocp.add_argument("--batch", type=int, default=20)
    ocp.add_argument(
        "--url",
        dest="opencode_url",
        default=os.environ.get("RR_OPENCODE_URL", "https://opencode.ai"),
        help="URL opened through the proxy; override with RR_OPENCODE_URL",
    )
    # dest must match what cmd_opencode_probe reads (args.opencode_timeout_ms);
    # a bare --timeout-ms would expose args.timeout_ms and silently skip probes.
    ocp.add_argument(
        "--timeout-ms", dest="opencode_timeout_ms", type=int, default=8000
    )
    ocp.add_argument(
        "--proxy",
        dest="opencode_proxy",
        default=DEFAULT_PROXY_URL,
        help="mihomo mixed-port used to open the URL through each candidate",
    )
    ocp.add_argument(
        "--enabled",
        dest="opencode_enabled",
        default=os.environ.get("RR_OPENCODE_PROBE_ENABLED", "1") != "0",
        action="store_true",
        help="enable the probe (default on; RR_OPENCODE_PROBE_ENABLED=0 disables)",
    )
    ocp.add_argument(
        "--no-probe",
        dest="opencode_enabled",
        action="store_false",
        help="disable this probe run regardless of env",
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
    if args.cmd in ("rotate", "skip", "next", "fastest"):
        if args.google_timeout_ms < 500:
            return "--google-timeout-ms must be >= 500"
        if args.google_attempts < 1:
            return "--google-attempts must be >= 1"
        if args.youtube_timeout_ms < 500:
            return "--youtube-timeout-ms must be >= 500"
        if args.youtube_attempts < 1:
            return "--youtube-attempts must be >= 1"
        if args.spotify_timeout_ms < 500:
            return "--spotify-timeout-ms must be >= 500"
        if args.spotify_attempts < 1:
            return "--spotify-attempts must be >= 1"
        if args.gemini_timeout_ms < 500:
            return "--gemini-timeout-ms must be >= 500"
        if args.gemini_attempts < 1:
            return "--gemini-attempts must be >= 1"
        if args.require_country is not None:
            cc = args.require_country.strip()
            if len(cc) != 2 or not cc.isalpha():
                return "--require-country must be a two-letter country code"
    if args.cmd == "fastest":
        if args.top < 1:
            return "--top must be >= 1"
        if args.speed_timeout_ms < 1000:
            return "--speed-timeout-ms must be >= 1000"
    return None


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    err = validate_args(args)
    if err:
        print("error: %s" % err, file=sys.stderr)
        return 2
    global _quarantine_seconds
    try:
        _quarantine_seconds = resolve_quarantine_seconds(
            getattr(args, "quarantine_seconds", None)
        )
    except (ValueError, TypeError) as exc:
        print("error: invalid quarantine configuration: %s" % exc, file=sys.stderr)
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
    if args.cmd == "fastest":
        return cmd_fastest(args, api)
    if args.cmd == "country":
        return cmd_country(args, api)
    if args.cmd == "opencode-probe":
        return cmd_opencode_probe(args, api)
    return cmd_retest(args, api)


if __name__ == "__main__":
    sys.exit(main())
