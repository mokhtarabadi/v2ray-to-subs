# scripts/ — Architecture Decision Records

Chronological. Each entry: Context, Decision, Consequences, Rollback.

## 2026-11-11 — One maintenance unit, foreign-server rules, US-clean default

**Context.** The project ran three timers (refresh, retest, country) plus a
disabled rotate timer, five oneshot jobs and the proxy service, all for one
pipeline. The generated configs still carried desktop-era rules from an Iranian
client: nine `PROCESS-*` bypasses for a local xray/PattN sidecar, Iran and China
domain/IP bypasses, CN DNS resolvers (`223.5.5.5`, `doh.pub`, alidns), a
`+.ir` nameserver policy and a `geoip-code: CN` fallback filter. The host is a
foreign server with no sidecar, so those rules only stole traffic from the
proxy.

**Decision.** One timer drives one dispatcher: `v2ray-to-subs.timer` →
`v2ray-to-subs-maintain.service` → `scripts/maintain.sh`, which retests, fills a
country batch, and refreshes only when the live config is older than six hours.
The five replaced units and the refresh drop-in are deleted; the feed list that
drop-in carried now lives in the dispatcher. `mihomo-subs.service` stays a
separate unit on purpose: a maintenance run must never be able to stop the
proxy, and a proxy restart must not cancel maintenance. Rules become private/LAN
`DIRECT`, ads `REJECT`, `MATCH,PROXY`; `find-process-mode` is `off`; DNS uses
Cloudflare/Google instead of CN resolvers. The `rr` launcher defaults to
`rotate --require-country US` so a bare `rr` asks for a Google-clean US exit,
with `RR_COUNTRY` as the override and `RR_COUNTRY=` to disable it.

**Consequences.** Two project units instead of eight, and one log to read
(`journalctl --user -u v2ray-to-subs-maintain`). Traffic that used to bypass the
proxy through Iran/China rules now goes through an exit — intended, because the
host is not in either country. Ads stay blocked. A US lock with no measured US
candidate keeps the current node instead of going dark.

**Rollback.** The old unit files are in git history; re-enable the timers and
delete the dispatcher pair. Converter changes are a single-file revert; the
previous live config is in `~/.config/mihomo-subs/config.yaml.refresh-*.bak`
(only the last five are kept). `RR_COUNTRY=` removes the launcher's default
lock without touching the balancer.

## 2026-11-11 — Observed exit country, and removal of the plugin-era causes

**Context.** A country lock cannot be built from provider remarks: in the live
feed 547 of 629 remarks are hash-style names with no country, and only 14 are
labelled US. The balancer also carried `quota`, `transport`, and `region`
failure causes plus their counters, which existed to serve the retired
`opencode-rate-limit-rescue` plugin and now measure nothing that the Google
gate or a country lock acts on.

**Decision.** `country` and `country_checked` columns store the country that
Cloudflare reports for a node's connection (`cdn-cgi/trace`, `loc=XX`), read
through the live mixed-port because mihomo's `/delay` endpoint discards the
response body. `rr country --batch N` fills the columns oldest-first, restores
the previous selection in a `finally` block, and records an unreadable trace as
unknown without quarantining. `rr report` prints coverage and per-country
counts. `rotate`/`skip`/`next` accept `--require-country CC`: candidates with
no measurement never match, and when nothing matches the current node is kept
so the client never lands in the wrong country. The three plugin-era causes and
their columns are removed (guarded `DROP COLUMN`; a failure leaves them
dormant), and selection is `uses` → `delay_ms` with no per-cause weighting.

**Consequences.** A sweep briefly carries traffic through each probed node
(`TRACE_SETTLE_SECONDS` each, bounded batch), so it is a background job, not a
per-rotation cost. The country lock stays off until coverage is high; enabling
it early would freeze rotation on an empty column. Dropping the legacy counters
is destructive by design and intentional — they were never read by anything
after this change.

**Rollback.** The country columns are additive and ignored by older code;
`--require-country` is opt-in. Reverting the script restores the previous
behavior, and the additive migration re-creates the legacy columns empty if an
older build is run against an upgraded database (their values are not restorable,
which is accepted because nothing consumes them).

## 2026-11-11 — Google Search status is the anti-abuse discriminator

**Context.** Exit nodes used by crawl and media traffic get flagged by
Google; flagged IPs answer `https://www.google.com/search?q=test` with a 302
to `/sorry`, and clients see "not available in your country" on some
services. Lightweight Google endpoints (`generate_204`, suggest) answer
identically on flagged and clean IPs, so they cannot discriminate.
mihomo's own `/delay?expected=200` follows the redirect and reports the final
200, so it also cannot see the block.

**Decision.** The balancer gates rotation on a real HTTP status read of
`/search` taken through the live mixed-port (`127.0.0.1:7890`) with
redirects disabled. A 302 quarantines the candidate with cause `google`
(24 h) and increments `google_fails`; rotation then tries the next candidate
up to `--google-attempts`, and fails open to the best remaining node when
every attempt is blocked. The gate is skipped when a direct host probe of the
same URL fails, so a Google-side outage cannot quarantine the pool.
`--no-google-check` disables the gate per run.

**Consequences.** One ~94 KB request per rotation on a pass and ~0.4 KB on a
block. The `google_fails` column is additive and migrated idempotently, so old
databases self-upgrade. `retest` stays un-gated: gating it would cost a
per-node search request every interval.

**Rollback.** Pass `--no-google-check`, or revert the script; the extra
column is ignored by older code.

## 2026-11-09 — Node identity is a hash, not the provider remark

**Context.** Provider remarks reshuffle or collide between refreshes, which
wiped learned delay/failure history and made quarantine inconsistent.

**Decision.** Names are `{proto}-{12hex}` from protocol + normalized host +
port (SHA-256), sorted deterministically with a suffix on collision. The
provider remark is kept in Clash's `remark` field for humans; sing-box omits
it because the schema rejects unknown fields.

**Consequences.** History survives every feed refresh. Humans read remarks
in Clash, not in the node name.

**Rollback.** Revert naming in the converter; balancer history resets once.

## 2026-11-08 — Separate `region` failure cause

**Context.** Provider country checks (geo-blocks) are a distinct failure from
rate limits and transport faults, and treating them as generic failures
diluted the quota signal used for crawl traffic.

**Decision.** `skip` / `next` accept `--reason region`, count it in a
dedicated `region_fails` column, and quarantine like other causes.

**Consequences.** Exit selection correctly demotes geo-blocked IPs without
deleting them; the column migrated idempotently.

**Rollback.** Revert the enum and column; unknown reasons fall back to
`manual`.
