# scripts/ — Architecture Decision Records

Chronological. Each entry: Context, Decision, Consequences, Rollback.

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
