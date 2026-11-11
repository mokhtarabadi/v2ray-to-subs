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
- **Failure causes**: `skip` / `next --reason google|country|manual`
  quarantines the node for 24 h. `google` also increments `google_fails`.
- **Google-clean gate**: `rotate` reads `https://www.google.com/search?q=test`
  through the live mixed-port with redirects disabled. A 302 to `/sorry`
  means the exit IP is anti-abuse flagged, so the candidate is quarantined
  with cause `google` and the next candidate is tried. `--no-google-check`
  restores the pre-gate behavior; the gate is skipped when Google is
  unreachable directly (infrastructure guard).
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

- The Google gate selects a candidate in order to probe it, so a rejected
  node carries traffic for roughly `GOOGLE_SETTLE_SECONDS` before the next
  candidate is tried. Bounded by `--google-attempts`.
- `data/balancer_state.db` is runtime state. Losing it only loses history.
