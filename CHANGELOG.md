# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- External round-robin balancer (task 04): `scripts/rr_balancer.py` rotates the PROXY `select` group across alive nodes (least-used, fastest-delay tiebreak, stale excluded) with per-node delay checks and SQLite state (`data/balancer_state.schema.sql`); `tests/test_rr_balancer.py` (7 tests); `systemd/rr-rotate` (5min) and `systemd/rr-retest` (30min, 250-node batches) user timers.
- Manual `skip NAME` subcommand (task 05): marks a flagged node failed and immediately rotates to the next alive node, so a rate-limited exit can be escaped without waiting for the timer.
- Manual `next` subcommand + `~/.local/bin/rr` launcher (task 05 follow-up): bare `rr` auto-detects the currently active node via the controller, marks it failed, and rotates immediately.
- Live dedup + freshness tuning (task 08): `refresh.sh` generates with `--unique-host` (live pool ~7230 → 3771); retest batch 250→500 with alive-first ordering; stale window 1h→2h; retest coverage ~14.5h → ~3.8h.
- `--unique-host` converter flag (task 07, default off): parse-time dedup keeps only the first proxy per server host (case/whitespace normalized) and logs unique vs duplicate counts; both Clash and sing-box outputs consume the same filtered list.
- Multi-feed aggregation (task 10): converter/`manager.sh`/`refresh.sh` accept N subscription URLs, merge into one pool, dedup across the merged set with per-feed + merged counts; ss cipher alias `chacha20-poly1305` normalized to `chacha20-ietf-poly1305`.
- Balancer seed memory (task 10 follow-up): learned rows survive feed refreshes (only never-tested rows pruned); pool and retest batch exclude controller ghosts; auto-rotate timer disabled, manual `rr` owns switching.
- 24h quarantine for failed nodes (task 11): failed nodes stay out of rotation and retest for 24h, then readmit via normal retest confirmation.
- Per-cause failure tracking: `skip`/`next` accept `--reason quota|transport|manual`; rotation prefers least-used, then fewest quota fails, then fastest, so exits hitting crawl rate limits sink in priority without deletion.
- Close stale connections on proxy switch (task 09): after every successful selection change the balancer closes connections still chained to the previous node (surgical per-id close, non-fatal); shared path covers manual (`rr`/`skip`) and timer (`rotate`) modes.
- Upstream parity audit (task 12): fat-graph review of full v2rayNG/mihomo/sing-box clones confirms ss plugin-opts string shape and reality-opts coverage; no new gaps, clones removed afterwards.
- Upstream parity fixes (task 12): ss SIP003 trailing-slash parse crash fixed; v2ray-plugin `mode` defaults to websocket (required by mihomo); vless `encryption` emitted only for mihomo-accepted values.
- Upstream parity fixes (task 12): emit vless `encryption` to Clash only for values mihomo accepts (`mlkem768x25519plus…`), drop unusable values like `aes-128-gcm` that fail validation.

### Fixed
- Review hotfix: balancer clock seam, DB parent makedirs, group_members annotation, WAL sidecar ignores.
- `opencode.json` permission key corrected from `bash` to `shell` so the project config passes `scripts/validate-opencode.py` (ZAC deny set unchanged).
- Balancer hotfix (task 04, QA round): all-fail batches no longer mass-mark nodes (infra-outage guard); numeric CLI args validated with exit 2; SQLite opened in WAL mode with 10s busy timeout for concurrent timers.
- `AGENTS.md` project context hub and `docs/conventions.md` (datetime standard, SOLID guidelines, ledger standard, shell protocol).
- `AGENTS.md` first-read rule and lite-mode protocol: explicit read-`AGENTS.md`-then-`docs/conventions.md` order with absent-file notes, plus the `[LITE]` bypass procedure with mandatory escalation on hidden complexity.

## [2026-09-26]

### Fixed

- Harden proxy health checks: explicit `expected-status: 204` and `max-failed-times: 3` on Auto, Load Balance, and Fallback groups so dead nodes are filtered out of rotation (task 03).
- Force double-quoted REALITY `public-key` / `short-id` in generated Clash configs; values like `2e00` were misread as float by Go-YAML and rejected by mihomo (task 01).

### Changed

- `refresh.sh` accepts a subscription URL argument or `SUB_URL` env, falling back to the converter default (task 01).
- Load Balance group strategy switched from round-robin to consistent-hashing (task 02).

### Added

- `refresh.sh` for systemd timer: generate, validate, install, and restart mihomo-subs.
- Controller secret support for the mihomo external controller.
