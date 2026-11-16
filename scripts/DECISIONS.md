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

## 2026-11-08 — Separate `region` failure cause (SUPERSEDED by the 2026-11-11 cause-cleanup entry above)

**Context.** Provider country checks (geo-blocks) are a distinct failure from
rate limits and transport faults, and treating them as generic failures
diluted the quota signal used for crawl traffic.

**Decision.** `skip` / `next` accept `--reason region`, count it in a
dedicated `region_fails` column, and quarantine like other causes.

**Consequences.** Exit selection correctly demotes geo-blocked IPs without
deleting them; the column migrated idempotently.

**Rollback.** Revert the enum and column; unknown reasons fall back to
`manual`.

## 2026-11-15 — Proxy-everything routing, no ads, allow-lan by default

**Context.** The generated configs still carried an ads REJECT block, a ~90-domain foreign-service pin list, a `geosite:category-ads-all` DNS policy, and `allow-lan false` defaults, while the checked-in samples were stale artifacts contradicting the generator.

**Decision.** Both generators collapse to LAN/private DIRECT plus `MATCH,PROXY` (Clash) and sniff/hijack-dns/ip_is_private plus final auto (sing-box); the ads list, its DNS policy, and the pin list are deleted. `allow-lan` defaults to true with mixed-port 7890 so scheduled refreshes serve LAN clients; TUN stays opt-in. Checked-in samples are regenerated by the converter, never hand-edited.

**Consequences.** All non-LAN traffic goes through a Google-clean US exit held by the balancer (retest 500, country 20, 6h refresh gate). LAN exposure of the mixed port is the accepted trade-off for serving LAN clients.

**Rollback.** `git checkout` the generator, regenerate, reinstall the last `.bak` live config; disable the timer pair to stop scheduled refreshes.

## 2026-11-15 — Multi-service clean gate (YouTube, Spotify, Gemini)

**Context.** Google-clean exits still failed the YouTube Music and Spotify apps: Search answers 200 while the YouTube oEmbed backend answers 403, the Spotify API edge answers HTML 403, and Gemini answers 403. Landing pages (`youtube.com/`, `music.youtube.com/`, `open.spotify.com/`) stay 200 on flagged exits, so they cannot discriminate. Live battery on a US exit confirmed the shapes (research searches timed out; experiments substituted).

**Decision.** Rotation probes all-must-pass Google → YouTube → Spotify → Gemini(spare) via `multi_gate_cause()`, reusing the redirect-disabled mixed-port pattern. First-flagged service quarantines 24h with its own cause and counter (`youtube_fails`, `spotify_fails`, `gemini_fails` via idempotent migration); inconclusive new-probe measurements never quarantine. One shared attempt budget (max of the four `--*-attempts`, default 5); per-service `--no-*-check` flags; all-dirty still fail-opens.

**Consequences.** Selection rejects exits that pass Google but fail reputation-sensitive apps; a fully-flagged pool serves the least-bad candidate instead of going dark. First live run quarantined two US nodes (`youtube`, `gemini`) and fail-opened to the best remaining.

**Rollback.** Per-service `--no-*-check` flags; `git checkout` the balancer to restore the Google-only gate.

## 2026-11-16 — Guarded auto-rotate with NL lock (`--keep-if-clean`)

**Context.** US exits kept flapping (repeated manual `rr` runs in one day) while the NL bench measured deeper and cleaner. Manual-only rotation also meant a dirty exit stayed until an operator noticed. But naive auto-rotate re-picks least-used every tick and would flap healthy exits.

**Decision.** `rotate` gains `--keep-if-clean`: the current exit is gate-tested first and kept (uses+1, `keep-clean` log) when clean or inconclusive; rotation proceeds only on a dirty verdict, with the dirty current quarantined under its cause. `maintain.sh` runs `rotate --require-country NL --keep-if-clean` every tick after the country batch. The `rr` launcher default flips US to NL (`RR_COUNTRY` still overrides, empty still disables).

**Consequences.** The pool holds the best gate-tested NL exit on its own and moves only on real dirt — no churn, no manual watching. Manual `rr` and the timer now agree on NL.

**Rollback.** Remove the rotate line from `maintain.sh`; flip the launcher default back to US; `--keep-if-clean` stays inert unless passed.

## 2026-11-16 — Hold country flipped NL to DE

**Context.** The NL exit stayed clean but the operator asked for a German hold: the DE bench is deep and the current DE exit tests clean on all four probes.

**Decision.** Default lock flipped NL to DE in `maintain.sh` and the `rr` launcher (`RR_COUNTRY` still overrides, empty still disables). Nothing else changes: same keep-if-clean guard, same battery, same fail-open.

**Consequences.** Every tick holds the best gate-tested DE exit; manual `rr` agrees.

**Rollback.** Flip both lines back to NL.

## 2026-11-16 — On-demand speed pick (`fastest`)

**Context.** Delay (HTTP 204 round-trip) says nothing about throughput: 28ms exits delivered 48–196 KB/s. Full speedtest-cli per node is over-engineering (60s+, ~100MB per candidate, abusive to free nodes, and it 502s through exits).

**Decision.** New manual-only `fastest` subcommand: gate the ordered pool (flagged quarantine with cause, same battery), speed-test the first `--top` (default 3) clean finalists with a bounded exact-byte download (default 3MB, 30s cap each), select the fastest. Slow losers are never quarantined; nobody clean loses standing. Not wired to the timer.

**Consequences.** Operator can escape a clean-but-slow exit in about a minute without disturbing the pool's learned state.

**Rollback.** Remove the subcommand; `rotate` behavior unchanged.
