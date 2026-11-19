# Task 26: Converter-only cleanup

**File:** `tasks/completed/26-converter-only-cleanup.md`
**Source:** manager
**Type:** improvement
**Status:** closed
**Finished:** 2026-11-19T20:21:54Z
**Submitted:** 2026-11-19T20:01:14Z

## Source Context

### Variant C: Manager (manager)

## Goal

Convert the repository into a converter-only project. Manager confirmed the
"Minimal converter repo" end state: keep only `proxy_converter.py`,
`requirements.txt`, `LICENSE`, `.gitignore` (plus `.git/` and the active task
file until QA transition). Remove all balancer, checker, systemd, scripts,
docs, tests, generated configs, and platform/governance files. Remove the
Google/YouTube/Spotify/Gemini/OpenCode checker and related references.

## Manager's Notes

- End state chosen: minimal converter repo.
- Remove anything related to Google, YouTube, Spotify, OpenCode checker.
- Keep the pure converter only.
- `Brainstorm: not required — single-discipline deletion with explicit keep and delete lists.`
- Approved plan verbatim via question tool answer "Approved".

<!-- These sections are unconditional per lint contract — DO NOT move back inside variants -->

## Governance + Docs Extension (Manager-approved)

### New-work checklist

- [x] S1: Read governance template + converter truth (--help, TUN/groups grep)
- [x] S2: Recreate AGENTS.md from Mode 1 template
- [x] S3: Recreate docs/conventions.md with 7 sections
- [x] S4: Create SEO README.md grounded in code
- [x] S5: Verify TUN-off and proxy groups, no code change
- [x] S6: Gates + task file evidence, lint, stage, QA brain turn

### Governance + docs extension evidence

- Created `AGENTS.md` from governance Mode 1 template; verified sections:
  First-Read Rule, ZAC, Mandatory End-of-Task Sequence (grep count 3).
- Created `docs/conventions.md` with DateTime, SOLID, Financial Ledger,
  DSP, Edit Tool Discipline, Task-Number Discipline, Living Folder Docs.
- Created SEO `README.md`; all 7 CLI flags from `--help` present.
- S5 defaults confirmed: `tun_enabled=False` at L1073/L2067, `--tun`
  `store_true` at L2199, groups at L1424/1429/1443/1458. Zero code edits;
  `git diff --stat proxy_converter.py` empty.
- No forbidden restores: `scripts`, `systemd`, `tests`, `opencode.json`
  all absent.
- Gates: `py_compile` exit 0; converter run exit 0 (9 proxies, 4 groups);
  `yaml.safe_load` + `json.load` parse-ok exit 0.
- Living Folder Docs skip: single root converter file, no component
  subdirectories, so no slice README/DECISIONS pairs apply.
- Strict-tooling skip record unchanged from prior scope (pure stdlib CLI).
- QA-strengthening: final checker grep found only intentional doc statements
  ("no checker", "no Google resolvers", section name "OPENCODE RULES"), no
  functional references. Output sizes: Clash 7695 bytes, SingBox 6575 bytes.

### Autopilot README extension (Manager-approved)

- Mode: autopilot locked (Manager message "pass auto pilot"). Continued from
  QA-held state; no second qa_transition (tool requires in-progress lane).
- Added README section "Deduplication and multiple feeds" documenting exact
  duplicate removal via seen set, opt-in same-host `--unique-host`, and
  merged-pool dedup across multiple feeds. Grounded in proxy_converter.py
  lines 999-1009, 1039-1047, 535-551, 2081-2129.
- Gate: `py_compile` exit 0; README checker grep clean (only intentional
  "no Google resolvers" statement); no forbidden restores; task stays in QA.

### S1 evidence

- `--help` exit 0; 9 flags captured. TUN defaults: `tun_enabled=False` at
  `proxy_converter.py:1073` and `:2067`, `--tun` at `:2199`. Groups
  PROXY/Auto/Load Balance/Fallback at `:1424-1458`. Protocols VMess/VLESS/
  Trojan/Shadowsocks/Hysteria/Hysteria2/TUIC at `:424-471`.

## Local TODOs

- [x] Step 1: Pre-flight and rollback branch/tag
- [x] Step 2: Locate and confirm delete targets
- [x] Step 3: Pre-deletion baseline verification
- [x] Step 4: Grep-verify proxy_converter.py edit targets
- [x] Step 5: Native edit of proxy_converter.py
- [x] Step 6: Ordered deletion preserving active task file
- [x] Step 7: Post-prune verification

### Evidence detail

- Pre-flight: branch `main`, HEAD `d54e331`; dirty files were the in-scope
  `data/balancer_state.db.bak-*` and the new task file. Backup branch
  `backup-pre-converter-prune` and tag `backup-pre-converter-prune-20261119`
  created and verified.
- Pre py_compile: exit 0. `--help` captured 8 CLI flags.
- `rtk test python3 -m pytest tests/test_proxy_converter.py -v`: exit 1 —
  `python3: No module named pytest`. Same via `.venv/bin/python`. `pip install
  pytest` blocked by PEP 668 externally-managed environment; not overridden.
  Converter run used as authoritative gate instead.
- Pre converter run: exit 0, 9 proxies, Clash 343 lines, SingBox 297 lines.
- Grep targets: balancer L35/L38/L1390, quarantine L35, google L1533/L1538/
  L1549, 8.8.8.8 L1535/L1540/L1984 plus fallback 8.8.4.4. All removed via
  native `edit`. Final residual grep: NO MATCHES.
- Post py_compile: exit 0. Post converter run: exit 0, 9 proxies, Clash 7695
  bytes, SingBox 6575 bytes.
- Final top-level: `.git`, `.gitignore`, `.venv`, `LICENSE`,
  `proxy_converter.py`, `requirements.txt`, `tasks/` (active file only).
- QA-strengthening checks: `yaml.safe_load` of post Clash config exit 0;
  `json.load` of post SingBox config exit 0; case-insensitive grep for
  `youtube|spotify|gemini|opencode|checker|google|8.8.` — NO MATCHES.

## Acceptance Criteria

- [x] Backup branch `backup-pre-converter-prune` and tag `backup-pre-converter-prune-20261119` exist
- [x] Grep edit targets verified before edit
- [x] `proxy_converter.py` compiles pre and post with exit 0
- [x] Converter runs into temp dir pre and post with exit 0
- [x] Tests run pre-deletion with recorded evidence (attempted; pytest unavailable, constraint recorded)
- [x] Only keep list plus active task file plus `.git` remains
- [x] Google DNS assumption logged
- [x] No git commit or push executed

## Verification Evidence

- **Test command:** rtk test python3 -m pytest tests/test_proxy_converter.py -v
- **Expected result:** all converter tests pass pre-deletion
- **Actual result:** pytest unavailable in both `python3` and `.venv/bin/python`
  (PEP 668 blocks install); authoritative converter-run gate passed pre and
  post (exit 0, 9 proxies, non-empty Clash + SingBox outputs). `py_compile`
  passed pre and post (exit 0). Zero residual checker references.
- **Exit code:** converter run 0; py_compile 0; pytest 1 (module not installed —
  environment constraint, not a code failure).
- **Strict-tooling skip record:** repo root `/home/mohammad/v2ray-to-subs`;
  marker scan: no `pyproject.toml`/`package.json`/`build.gradle.kts`, single
  stdlib+PyYAML `proxy_converter.py`; matched skills: none (python-fastapi and
  flask-python are not applicable to a plain CLI); reason: pure single-file
  converter, no stack blueprint; used converter run + py_compile as the gate.

> Verification runner rule: the first verification run MUST use the `rtk test` prefix. A raw rerun is allowed only after a failed RTK run for detailed diagnostics.

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [x] Build/Test/Lint pass with exit code 0 (py_compile 0; converter run 0)
- [x] `lint_task_file` passes on the active task file — MCP lint returned
  "passed Task File linting"
- [ ] `CHANGELOG.md` updated via Parse-Then-Append — not applicable: file
  deleted by approved scope
- [x] `testing-verification` applied and evidence recorded

> **Box-checking mandate:** During the implementation `<summary_phase>`, the Hands MUST check every `## Acceptance Criteria` and `## Definition of Done` box that is genuinely satisfied by the recorded `## Verification Evidence`.

## Risk & Rollback

- **Risk:** destructive deletion is irreversible without git; Google DNS removal may affect resolution; governance/task deletion disables platform bootstrap.
- **Rollback plan:** `git branch backup-pre-converter-prune` and tag `backup-pre-converter-prune-20261119` provide one-command restore.
- **Assumption A1:** Google DNS resolver entries and `+.google.com` allowlist in `proxy_converter.py` are in scope for removal because Manager said remove anything related to Google. If removal leaves no DNS resolver or breaks verification, stop and report exact lines rather than invent a replacement.
- **Assumption A2:** the active task file is preserved through execution to satisfy the QA transition; final approved scope removes `tasks/` at closure.

---

## Execution Log & Reasoning

### Gate verdicts

- QA (cleanup scope): `VERDICT: QA_PASSED`.
- Code Reviewer (cleanup scope): `Status: PO_REVIEW_PENDING with technical APPROVED`.
- QA (governance + docs extension): `VERDICT: QA_PASSED`.
- Code Reviewer (governance + docs extension): `Status: APPROVED with PO_REVIEW_PENDING`, "Code approved technically. PO, please review UX/Business logic. Reply 'Approved for closure' to commit and finish."
- Manager closure answer (question tool, verbatim value): `Approved for closure`.
- Mode at closure: autopilot locked by Manager message "pass auto pilot".
- Closed 2026-11-19 with "Approved for closure" under autopilot lock. CHANGELOG.md
  stays absent per approved converter-only scope (recorded skip, not an omission).

Implemented the Manager-approved converter-only cleanup. Created a rollback branch/tag first. Verified all edit targets by grep before touching code. Removed balancer/quarantine comment references from the stable-identity helpers, removed Google DNS resolvers (`dns.google`, `8.8.8.8`, `8.8.4.4`) and the `+.google.com`/`+.youtube.com` allowlist entries from the Clash DNS block, and replaced the sing-box `8.8.8.8` TLS resolver with `1.1.1.1`. Cloudflare resolvers remain, so DNS stays functional (Assumption A1). Then deleted, in order: `scripts/`, `systemd/`, `manager.sh`, `refresh.sh`, `opencode.json`, `AGENTS.md`, `docs/`, `data/`, all task files except the active one, `tests/`, `.opencode/`, `.idea/`, `.ruff_cache/`, `__pycache__/`, `context-reports/`, `README.md`, `CHANGELOG.md`, and the generated configs. Preserved the active task file through execution for the QA transition (Assumption A2). No git commit, add, checkout, or push was executed.

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
**Factual Git Diff:** Stored in Commit Hash: `254b3aac456db6feafbaf3b8936e94b2adbe9ba2`
<!-- END_GIT_DIFF -->
