# Task [07]: Unique host/IP dedup option for conversion

**File:** `tasks/completed/07-dedup-by-host.md`
**Source:** manager
**Type:** feature
**Status:** closed

## Goal

Add a CLI argument to the converter so that, when enabled, subscription parsing registers each server host/IP only once — duplicates never reach the generated service configs — and the run reports duplicate vs unique counts.

## Manager's Notes

Manager request (Persian, paraphrased): many OpenRay subscription proxies are duplicates by host/IP (credentials may differ, but host/IP is the same); since unique IP matters, dedup fires. Add a new argument to the converter: when the unique-host/unique-IP option is active, parsing must never register a duplicate host or domain (the parser knows the host/IP at parse time). Output must report how many duplicates vs how many unique came out. Our own service generation must never contain duplicates when it generates a new file. Manager order: create the task and run the autopilot stages including Brain QA and Brain reviewer.

## Local TODOs

- [x] Add unique-host CLI argument to `proxy_converter.py` (off by default)
- [x] Dedup parsed proxies by server host at parse time when enabled
- [x] Log duplicate vs unique counts on every run
- [x] Verify generated configs contain no duplicate hosts
- [x] Verify balancer rotation wraps to the start after the last alive node (folded in per manager order: usage-ordered pick re-covers from min-uses; confirm + fix here if broken)
- [x] Run bridge-QA and bridge-review

## Acceptance Criteria

- [x] New argument exists, off by default, documented in help text
- [x] With the flag on, no server host appears twice in generated outputs
- [x] Run output reports duplicate count and unique count
- [x] Default behavior (flag off) unchanged

## Verification Evidence

- **Test command:** synthetic 4-node feed through ProxyParser (shared host across vless/vless/trojan + mixed case), flag off then on
- **Expected result:** off=4 proxies (parity), on=2 unique (n1 + other) with host_dup=2
- **Actual result:** off=4, on=2 unique + 2 host duplicates skipped
- **Exit code:** 0

- **Test command:** end-to-end run() on file:// feed with unique_host=True (clash + singbox outputs)
- **Expected result:** rc=0, both outputs shrink equally, no host twice
- **Actual result:** rc=0, clash 2 proxies + sing-box 2 proxy outbounds
- **Exit code:** 0

- **Test command:** balancer suite (wrap-around regression) + py_compile + --help
- **Expected result:** 15 tests OK, compile clean, flag documented
- **Actual result:** 15 tests OK, py_compile exit 0, --unique-host in --help
- **Exit code:** 0

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [x] `CHANGELOG.md` updated via Parse-Then-Append
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** distinct nodes sharing a host (different ports/credentials) get dropped when the flag is on
- **Rollback plan:** flag defaults off; rerun without it restores full output

---

## Execution Log & Reasoning

- Autopilot locked for task 07 on manager order (Persian): task it, run autopilot incl. Brain QA + reviewer.
- Goal created (active). Memory bootstrap: no namespaces. Decision sync: personal repo dirty, push is manager-owned. Autopilot norms replayed from stored rulings (drive end-to-end, no ferrying).
- Manager follow-up (Persian, paraphrased): continue; also verify rotation wraps from the last alive node back to the first, fixing inside this same task since it is small. Added as a TODO above (balancer-side check).
- Implementation (per approved Architect plan): `ProxyParser.__init__(unique_host=False)` + `host_dup` counter; `seen_hosts` check after server/port validation, normalized strip().lower() key, first wins; `run()` plumbs `unique_host` + logs "Unique-host dedup: %d unique, %d host duplicates skipped"; `main()` adds `--unique-host` store_true. Wrap check: balancer `pick_next` re-sorts by (uses, delay) every run — no end-of-list index exists, wrap-around inherent, no fix needed (balancer suite 15 tests OK confirms).
- Verification: synthetic 4-node feed off=4 (parity) / on=2 unique + 2 dups; end-to-end file:// run rc=0, clash 2 proxies + sing-box 2 outbounds (equal shrink); py_compile OK; --help shows flag.

- Bridge-QA (brain_turn task_id 07, include_diff): VERDICT QA_PASSED. F1 default-off preserved; F2 empty servers blocked by existing guard; F3 normalization strip+lower (trailing-dot/IPv6 variants out of scope); F4 first-wins tradeoff recorded; F5 counts accurate, both generators shrink equally. Missing tests non-blocking (M1 synthetic regression test suggested, M2 variants out of spec). Routed to Code Reviewer.

- Code Review (bridge, task_id 07): APPROVED technically, status PO_REVIEW_PENDING. No blocking issues; I1 (format churn), I2 (conditional count log), I3 (no regression test) all Low, R3 no code change required before closure. Relayed to Manager; file stays in tasks/qa pending exact closure words.
- Closure approved with exact words. Metadata set to closed. Ready for atomic move and approved commit tool.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `1a236d9a4a8fd23697295f670ee45ef83a6e86ba`
<!-- END_GIT_DIFF -->
