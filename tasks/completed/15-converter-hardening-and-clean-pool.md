# Task 15: Converter hardening and clean verified pool swap

**File:** `tasks/completed/15-converter-hardening-and-clean-pool.md`
**Source:** manager
**Type:** bug
**Status:** closed
**Finished:** 2026-10-31T06:55:31Z

## Goal

Harden `proxy_converter.py` so generated Clash and sing-box configs always pass `mihomo -t` and `sing-box check`, and swap the dirty 5-feed pool (4.7% alive) for a verified clean feed set (Au1rxx HTTP-over-proxy + nodesradar Google-tested).

## Manager's Notes

Manager asked to find a clean pool. Research showed patterniha (3 unique hosts) and morpheusadam (0% alive from Iran) are unusable. Au1rxx (HTTP-over-proxy verified, 522 hosts) + nodesradar (Google-tested, 331 hosts) combined yield 672 unique hosts with ~68% alive rate.

Converter bugs discovered while testing new feeds:
- Hysteria2 `fp=` emitted `fingerprint` (cert pin key) instead of `client-fingerprint` — mihomo rejects uTLS name under `fingerprint`
- REALITY public keys with stray whitespace caused "invalid REALITY public key" — sanitize + validate (base64url, 32 bytes), drop unusable nodes
- Unknown ss ciphers (garbage from mislabeled links) broke `mihomo -t` — validate against known cipher set
- v2ray-plugin `mux` emitted as string instead of bool
- sing-box: reality requires uTLS (default to chrome if none specified)
- sing-box: TUIC `token` field not supported (v5 only) — skip token-only proxies
- sing-box: `simple-obfs` → `obfs-local` (only supported name)
- sing-box: VLESS flow `xtls-rprx-vision-udp443` not supported — normalize to `xtls-rprx-vision`
- Clash: vmess cipher `null` → `auto`

## Key Finding (pre-implementation)

All generated configs must pass both `mihomo -t` and `sing-box check`. The converter must be robust against garbage in free feeds. Verified feeds (HTTP-over-proxy, Google-tested) have dramatically higher alive rates than unverified feeds.

## Local TODOs

- [x] Research and test candidate feeds (patterniha, morpheusadam, Au1rxx, nodesradar)
- [x] Fix hysteria2 fingerprint key (client-fingerprint)
- [x] Fix REALITY public key sanitization + validation
- [x] Add ss cipher validation (SS_VALID_METHODS)
- [x] Fix v2ray-plugin mux bool coercion
- [x] Fix sing-box reality uTLS requirement
- [x] Fix sing-box TUIC token skip
- [x] Fix sing-box simple-obfs → obfs-local
- [x] Fix sing-box VLESS flow udp443 normalization
- [x] Fix clash/singbox vmess cipher "null" → "auto"
- [x] Swap pool to Au1rxx + nodesradar
- [x] Reset balancer DB
- [x] Update override.conf
- [x] Verify both configs pass mihomo -t and sing-box check
- [x] Verify alive rate improved (68.4% vs 4.7%)
- [x] Run full test suite (56 tests pass)

## Acceptance Criteria

- [x] `mihomo -t` passes on generated clash config
- [x] `sing-box check` passes on generated singbox config
- [x] Pool alive rate > 50%
- [x] All existing tests pass
- [x] CHANGELOG.md updated

## Definition of Done

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `verification-before-completion` applied and evidence recorded

## Verification Evidence

- **Test command:** `mihomo -t -f clash.yaml && sing-box check -c singbox.json && pytest tests/`
- **Expected result:** Both validators pass, all tests green
- **Actual result:** mihomo -t pass (672 proxies), sing-box check pass (672 outbounds), 56/56 tests pass
- **Exit code:** 0

## Risk & Rollback

- **Risk:** New feeds may degrade over time; converter fixes are additive and safe
- **Rollback plan:** Revert override.conf to previous 5 feeds; converter fixes are backward-compatible

---

## Execution Log & Reasoning

### Changes Made

1. **proxy_converter.py** — 9 fixes:
   - Hysteria2: `fingerprint` → `client-fingerprint`
   - REALITY: sanitize pbk (strip whitespace), validate (base64url, 32 bytes), drop invalid nodes
   - ss cipher: validate against SS_VALID_METHODS, drop unknown
   - v2ray-plugin: mux coerced to bool
   - sing-box: reality requires uTLS (default chrome)
   - sing-box: TUIC token-only proxies skipped
   - sing-box: simple-obfs → obfs-local
   - sing-box: VLESS flow udp443 → xtls-rprx-vision
   - clash/singbox: vmess cipher "null" → "auto"

2. **override.conf** — swapped to Au1rxx + nodesradar

3. **Balancer DB** — reset, reseeded from new pool

4. **CHANGELOG.md** — two entries added

### Verification

- `mihomo -t`: pass (672 proxies)
- `sing-box check`: pass (672 outbounds)
- Tests: 56/56 pass
- Alive rate: 459/672 = 68.4%
- Egress: working (FRA/CDG)

### Assumptions

- A1: Au1rxx HTTP-over-proxy verification translates to high alive rate from our server — confirmed (68.4%)
- A2: Converter fixes are backward-compatible with existing feeds — confirmed (all tests pass)

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `6f1bd627c7f9fab9f0202bfe5affdefceabacbdd`
<!-- END_GIT_DIFF -->