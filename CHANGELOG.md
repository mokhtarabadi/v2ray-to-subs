# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

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
