# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- External round-robin balancer (task 04): `scripts/rr_balancer.py` rotates the PROXY `select` group across alive nodes (least-used, fastest-delay tiebreak, stale excluded) with per-node delay checks and SQLite state (`data/balancer_state.schema.sql`); `tests/test_rr_balancer.py` (7 tests); `systemd/rr-rotate` (5min) and `systemd/rr-retest` (30min, 250-node batches) user timers.
- Manual `skip NAME` subcommand (task 05): marks a flagged node failed and immediately rotates to the next alive node, so a rate-limited exit can be escaped without waiting for the timer.
- Manual `next` subcommand + `~/.local/bin/rr` launcher (task 05 follow-up): bare `rr` auto-detects the currently active node via the controller, marks it failed, and rotates immediately.
- `--unique-host` converter flag (task 07, default off): parse-time dedup keeps only the first proxy per server host (case/whitespace normalized) and logs unique vs duplicate counts; both Clash and sing-box outputs consume the same filtered list.

### Fixed
- Review hotfix: balancer clock seam, DB parent makedirs, group_members annotation, WAL sidecar ignores.
- Balancer hotfix (task 04, QA round): all-fail batches no longer mass-mark nodes (infra-outage guard); numeric CLI args validated with exit 2; SQLite opened in WAL mode with 10s busy timeout for concurrent timers.
- `AGENTS.md` project context hub and `docs/conventions.md` (datetime standard, SOLID guidelines, ledger standard, shell protocol).

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
