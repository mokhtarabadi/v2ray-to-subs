# scripts/ — external mihomo balancer

Automation that runs beside mihomo and owns things mihomo cannot decide on
its own: which subscription node carries traffic right now, and when a node
should sit out.

## Layout

| File              | Duty                                                                 |
| ----------------- | -------------------------------------------------------------------- |
| `rr_balancer.py`  | Clash-API + SQLite round-robin balancer (`rotate`, `skip`, `next`, `retest`) |

State lives in `data/balancer_state.db` (schema in
`data/balancer_state.schema.sql`, git-ignored). Run `python3 scripts/rr_balancer.py --help`
for the full CLI.

## Duties

- **Liveness + delay**: probes every pool node through mihomo's
  `/proxies/{name}/delay` endpoint and stores delay or failure.
- **Selection**: `rotate` picks the lowest `(uses, quota_fails, delay_ms)`
  row among alive, fresh, non-quarantined nodes and selects it in the
  `PROXY` group.
- **Failure causes**: `skip` / `next --reason quota|transport|region|google|manual`
  increments the per-cause counter and quarantines the node for 24 h.
- **Google-clean gate**: `rotate` reads `https://www.google.com/search?q=test`
  through the live mixed-port with redirects disabled. A 302 to `/sorry`
  means the exit IP is anti-abuse flagged, so the candidate is quarantined
  with cause `google` and the next candidate is tried. `--no-google-check`
  restores the pre-gate behavior; the gate is skipped when Google is
  unreachable directly (infrastructure guard).
- **Retest**: rechecks the oldest batch so dead nodes rejoin on recovery.

## Invariants

1. Node names are identity hashes (`{proto}-{12hex}` from server + port), so
   learned rows survive every subscription refresh.
2. Never delete learned rows on a refresh — only never-tested rows are pruned.
3. Selection order is deterministic: `uses` → `quota_fails` → `delay_ms`.
4. Rotation always leaves the group pointing at a node. An all-blocked pool
   fails open to the best candidate instead of going dark.

## Risks

- The Google gate selects a candidate in order to probe it, so a rejected
  node carries traffic for roughly `GOOGLE_SETTLE_SECONDS` before the next
  candidate is tried. Bounded by `--google-attempts`.
- `data/balancer_state.db` is runtime state. Losing it only loses history.
