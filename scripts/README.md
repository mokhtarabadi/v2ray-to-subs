# scripts/ — external mihomo balancer

Automation that runs beside mihomo and owns things mihomo cannot decide on
its own: which subscription node carries traffic right now, and when a node
should sit out.

## Layout

| File              | Duty                                                                 |
| ----------------- | -------------------------------------------------------------------- |
| `rr_balancer.py`  | Clash-API + SQLite balancer (`rotate`, `retest`, `country`, `report`, `skip`, `next`) |
| `maintain.sh`     | Single maintenance dispatcher run by `v2ray-to-subs.timer` every 30 minutes |

State lives in `data/balancer_state.db` (schema in
`data/balancer_state.schema.sql`, git-ignored). Run `python3 scripts/rr_balancer.py --help`
for the full CLI.

## Maintenance dispatcher

`maintain.sh` is the only scheduled entry point. Each tick it runs
`retest --batch 500`, then `country --batch 20`, then `refresh.sh` **only** if
`~/.config/mihomo-subs/config.yaml` is older than six hours. A failing job logs
a warning and the tick continues, so one bad batch never blocks the refresh.
The feed list the old refresh drop-in used is embedded in the script.

## Duties

- **Liveness + delay**: probes every pool node through mihomo's
  `/proxies/{name}/delay` endpoint and stores delay or failure.
- **Country**: `country --batch N` selects each node briefly, reads
  `https://www.cloudflare.com/cdn-cgi/trace` through the live mixed-port, and
  stores the observed two-letter code with a freshness stamp
  (`country`, `country_checked`). Unreadable traces are stored as unknown, never
  as a country and never as a failure. The previous selection is restored at the
  end of the batch.
- **Report**: `report` prints country coverage (checked/total) and per-country
  counts, so the decision to enable a country lock is data-driven.
- **Selection**: `rotate` picks the lowest `(uses, delay_ms)` row among alive,
  fresh, non-quarantined nodes and selects it in the `PROXY` group.
- **Failure causes**: `skip` / `next --reason google|youtube|spotify|gemini|country|manual`
  quarantines the node for 24 h. Each probe cause increments its own
  counter (`google_fails`, `youtube_fails`, `spotify_fails`, `gemini_fails`).
- **Multi-service clean gate**: `rotate` probes each candidate through the
  live mixed-port with redirects disabled, all-must-pass in order Google
  (`search?q=test`: 200 clean, 302 `/sorry` flagged) → YouTube backend
  (`oembed`: 200 clean, 403 flagged; landing pages are 200-weak and unused)
  → Spotify API (401 JSON clean = edge reached auth, 403 HTML flagged =
  edge IP block) → Gemini spare (200 clean, 403 flagged). The first
  flagged service quarantines with its cause and the next candidate is
  tried; an inconclusive new-probe measurement keeps the candidate
  without quarantine. Per-service `--no-*-check` flags restore fewer
  gates; the battery is skipped when Google is unreachable directly
  (infrastructure guard). One shared attempt budget (max of the four
  `--*-attempts`, default 5) bounds the run; an all-dirty pool fails
  open to the best candidate.
- **Country lock**: `--require-country CC` (on `rotate`, `skip`, `next`) keeps
  rotation inside one observed country. Candidates with no measurement never
  match, and when nothing matches the current node is kept instead of falling
  back to another country. The lock is opt-in until `report` shows coverage.
- **Retest**: rechecks the oldest batch so dead nodes rejoin on recovery.

## Invariants

1. Node names are identity hashes (`{proto}-{12hex}` from server + port), so
   learned rows survive every subscription refresh.
2. Never delete learned rows on a refresh — only never-tested rows are pruned.
3. Selection order is deterministic: `uses` → `delay_ms`, with no per-cause
   weighting.
4. Rotation always leaves the group pointing at a node. An all-blocked pool
   fails open to the best candidate, and with a country lock that failure stays
   inside the locked country.
5. An unreadable country trace is a measurement gap, never a node verdict.

## Risks

- The probe gates select a candidate in order to probe it, so a rejected
  node carries traffic for roughly `GOOGLE_SETTLE_SECONDS` per probe
  before the next candidate is tried. Bounded by the shared attempt
  budget (max of the four `--*-attempts`, default 5).
- A stricter battery can reject the whole pool where every exit is
  flagged for at least one service; fail-open then serves the least-bad
  candidate instead of going dark.
- `data/balancer_state.db` is runtime state. Losing it only loses history.
