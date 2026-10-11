# Task [12]: Cross-check parsers and configs against upstream sources

**File:** `tasks/completed/12-upstream-parity-audit.md`
**Source:** manager
**Type:** research + fix
**Status:** closed

## Goal

Study exactly which share links v2rayNG handles and how Clash (mihomo) and sing-box define per-protocol configs, then close gaps in our own converter and project graph/docs.

## Manager's Notes

Manager message (verbatim, Persian):

> سورس کد v2rayng رو بگیر،‌بعپس گرف بساز و کانفیگ هاش رو بررسی کن دقیقا هر لینکی که هندل میشه و ساخته میشه رو تا دقیق یاد بگیری
> بعدش سورس کد کلش و سینگ باکس رو بگیر با گرف کامل بفهم کانفیگش چطوری کار می‌کنه برای هرکدام در نهایت گرف پروژه خودمون رو هم بگیر و نواقص و گپ ها رو برطرف کن

English: fetch the v2rayNG source, build a grep (code search) over it and study exactly which links it handles and builds; then fetch Clash and sing-box sources and fully understand per-protocol configs; finally take our project's graph and fix deficiencies and gaps.

## Local TODOs

- [x] Map v2rayNG share-link parsing/building (schemes, params, transports)
- [x] Map mihomo per-protocol proxy fields (vmess/vless/trojan/ss/hysteria/tuic/socks)
- [x] Map sing-box per-protocol outbound schemas
- [x] Diff against `proxy_converter.py` coverage; list gaps
- [x] Fix real gaps; update project graph + docs where tied

## Acceptance Criteria

- [x] Coverage matrix (protocol × v2rayNG × mihomo × sing-box × ours) recorded
- [x] Each gap fixed or explicitly deferred with reason
- [x] Tests green, generated configs still validate

## Verification Evidence

- **Test command:** ./.venv/bin/python -m pytest tests/ -q
- **Expected result:** all pass
- **Actual result:** 38 passed, exit 0
- **Exit code:** 0

- **Test command:** generate Clash from `encryption=aes-128-gcm` vless link, then `mihomo -t -f`
- **Expected result:** config validates (unusable value dropped)
- **Actual result:** test is successful
- **Exit code:** 0

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** upstream behaviors that look like gaps but are client-specific UI concerns, not converter concerns
- **Rollback plan:** converter changes are additive behind existing behavior; full test suite gates every edit

---

## Execution Log & Reasoning

### Battery round: every scheme + param through our parser

Parsed OK: vmess-json, vless (full reality/pbk/sid/flow), trojan-grpc, ss-basic, hysteria2, hysteria1, tuic, socks5, ech-param link (no crash), xhttp, splithttp→xhttp, http/h2, kcp, quic, ss-plain.
Skipped by design: wireguard, ssr, juicity, anytls, snell, mieru (no parser; v2rayNG parses wireguard only among these).

### Fixes applied this round

1. **ss SIP003 trailing-slash crash (real bug):** `ss://b64@host:port/?plugin=...` failed with `invalid literal for int(): '8388/'` because the `?`-split left a trailing `/` on the port. Fixed with `.rstrip("/")` on hostport. Common in the wild.
2. **v2ray-plugin mode default (validation gap):** mihomo rejects `plugin-opts` without `mode` (`has unset fields: mode`). The plugin's own default is websocket, so we now fill `mode: websocket` when the link omits it. Proven by `mihomo -t` pass on the previously-failing link.
3. **vless encryption (from prior round, kept):** emit only `mlkem768x25519plus…`, drop values mihomo rejects (e.g. `aes-128-gcm` seen in the wild), per mihomo `transport/vless/encryption/factory.go` `NewClient`.

### Deferred with reason

- **wireguard/ssr/juicity/anytls/snell/mieru parsers:** new-protocol implementations (parse + clash emit + sing-box emit + tests each). v2rayNG itself skips hysteria-v1/tuic/ssr which we already cover. Recommend separate tasks if feed demand appears.
- **`ech` param:** v2rayNG reads it and mihomo has `ech-opts`, but the struct shape was not mapped and zero live feed links carry it. Defer until a real link appears.
- **sing-box `option/socks.go`:** not present at that path upstream; our minimal socks output validates, so no action.
- **tuic/hy2 perf knobs** (`reduce-rtt`, `cwnd`, `bbr-profile`, recv windows, obfs packet sizes): never present in share links; skipped.

### Upstream audit (completed)

**v2rayNG** (`2dust/v2rayNG`, `AngConfigManager` parser map + `fmt/*Fmt.kt` + `FmtBase`): parses vmess, ss, socks/socks4/socks5, trojan, vless, wireguard, hysteria2/hy2. Does NOT parse hysteria v1 (no parser mapped despite enum entry), tuic (commented out), ssr. Shared stream params read: type, headerType, host, path, seed, mtu, tti, quicSecurity, key, mode, serviceName, authority, xhttpMode/mode, xhttpExtra/extra, fm, security, insecure/allowInsecure/allow_insecure, sni, fp, alpn, ech, vcn, pcs, pbk, sid, spx, pqv, flow.
**Ours vs v2rayNG parse:** we cover everything they parse PLUS hysteria v1 and tuic. Param gaps on our side: `ech`, `vcn`, `pcs`, `pqv` (TLS-next-gen, low value), kcp/quic legacy fields (mihomo degrades these to tcp anyway). No action.

**mihomo** (`MetaCubeX/mihomo`, `adapter/outbound/*.go` option structs): all our protocols present. Actionable gap found: vless `encryption` field — parsed by us but never emitted. sing-box vless has no such field (correct to omit there).
**Fix applied:** emit `encryption` to Clash only when the value is one mihomo accepts. Proof from mihomo source (`transport/vless/encryption/factory.go` `NewClient`): only `""`/`"none"` (omitted) or `mlkem768x25519plus...` strings pass; everything else (e.g. `aes-128-gcm` seen in the wild) fails `mihomo -t` with "invaild vless encryption value". First attempt (pass-through) was proven wrong by live validation and corrected the same session.
**Other mihomo fields checked and deliberately skipped:** `packet-addr`/`xudp` (deprecated aliases of packet-encoding, already covered), `certificate`/`private-key` (mTLS client certs never ride in share links), `name-cert-verify`, shadowtls/restls/jls (obscure transports), tuic/hy2 perf knobs (`reduce-rtt`, `cwnd`, `bbr-profile`, recv windows — never present in share links), `ech-opts` (no link param feeds it today).

**sing-box** (`SagerNet/sing-box`, `testing` branch, `option/*.go`): vless has `uuid/flow/network/tls/multiplex/transport/packet_encoding` (all covered), tuic has `uuid/password/congestion_control/udp_relay_mode/udp_over_stream/zero_rtt_handshake/heartbeat` — `udp_over_stream` and `zero_rtt_handshake` have no share-link params in the wild, skipped deliberately. TUIC token + congestion/relay/heartbeat covered both sides. (Note: sing-box `option/socks.go` does not exist at that path; socks schema check deferred as low value — our socks output is minimal username/password which validates.)

### Verification

- 38 tests pass (36 existing + 2 new encryption emit/drop cases)
- Live: previously-failing `aes-128-gcm` link now generates a config that passes `mihomo -t`


### Upstream graph round (manager: build the graph with our tools)

- Admitted first: initial upstream research used curl+grep, not our graph tools. Fixed by vendoring exact sources under `.upstream/` (v2rayNG fmt parsers + manager + enums, mihomo Meta adapter/outbound for all our protocols, sing-box testing-branch option schemas) and building the project graph over it with `build_graph` (127 nodes) + `query_graph`.
- Graph-verified: mihomo `ShadowSocksOption` carries exactly name/server/port/password/cipher/udp/plugin/plugin-opts (+ exotic udp-over-tcp/fingerprint with no link params) — our ss emit covers every link-carried field. sing-box socks outbound schema confirmed via local docs (version/username/password/network).
- `.upstream/` added to `.gitignore` (third-party code incl. GPL v2rayNG sources must never be committed); graph artifacts live in gitignored `context-reports/`.


### Fat-graph round (manager: full clone, single graph, then remove clones)

- Cloned depth-1 (no history, no submodules, `.git` stripped at once): v2rayNG/master, mihomo/Meta, sing-box/testing. Built one fat graph over all three with our tools (5000 nodes, then queried it).
- Graph-verified findings: sing-box ss `plugin_opts` is a plain string (our raw-string emit is correct, no fix); mihomo `RealityOptions` needs only public-key + optional short-id (both emitted); mihomo `ShadowSocksOption` carries exactly what we emit for link-carried fields.
- No new code gaps found in this round. Clones removed afterwards (`rm -rf .upstream-full` verified absent); `.upstream/` vendor dir and graph reports remain gitignored.


## Closure

- Manager approval (exact): "Approved for closure". Battery + fat-graph rounds verified (40 tests green, live mihomo -t passes, clones removed). Staged set is task-12-only. Closing via approved path.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `9785915ae77250874e273f4647e59c7d6e0766aa`
<!-- END_GIT_DIFF -->
