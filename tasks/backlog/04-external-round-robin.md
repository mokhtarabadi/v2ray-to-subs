# Task [04]: External round-robin balancer via Clash API plus SQLite

**File:** `tasks/backlog/04-external-round-robin.md`
**Source:** manager
**Type:** feature
**Status:** open

## Goal

Build an external Python script that does true round-robin plus hash-weighted load balancing over alive proxies using the Clash API and its own SQLite state, keeping the PROXY group in select mode.

## Manager's Notes

Manager's original message (Persian, verbatim):

> ببین می‌تونی این قابلیت و توسعه بدی؟ خب؟ این‌جوری. از کلاً حالت سلکت میهومو یا همون کلش استفاده کنیم، خب؟ کاری با حالت اتوبالانس و این مواردش نداشته باشیم. بعد یک اسکریپت پایتون بنویسی با ای‌پی‌آی کلش. بعد یه دیتابیس لوکال اس‌کی‌لایت هم داشته باشی ترک کنی پروکسی‌ها رو بر اساس نیمشون، اینا یونیک‌ان. ببین الان مثلاً، ببین می‌شه، نمی‌دونم می‌شه یا نه. پروکسی‌ها رو تست کنی؟ نه، نمی‌شه. این‌جوری هی باید عوض کنی، تست کنی این خودش داستان داره. اگر یه قابلیت داشته باشی که پروکسی رو دقیقاً همون پروکسی رو از طریق خود کلش تست کنی، یعنی به کلش بگی پروکسی شماره ۵ رو تست کن، اگر کار کرد پینگش رو مثلاً خودت ذخیره کنی. بعد پروکسی‌هایی که کار نمی‌کنن رو. بعد اون‌ها رو هم بدونی یعنی خودت سیستم رو کلاً جدا از کلش باشه. بعد ای‌پی‌آی کلش به‌صورت اکسترنال بهش وصل بشه. هدف اینه: مثلاً هر، نمی‌دونم، چند ثانیه یه بار خودم، یعنی خودت به‌صورت ران‌روبین واقعاً ترافیک رو روی پروکسی‌هایی که واقعاً کار می‌کنن و پینگ دارن بالانس کنی. کاری به ای‌پی‌آی خود کلش نداشته باشی. بعد نسبت به مقداری که ازشون استفاده شده دقیقاً بار رو سعی کنی روی همه‌شون به‌صورت یکسان هندل کنی. و اگر یکی از پروکسی‌ها هم از بین رفت، تو می‌دونی دیگه، توی حالت سلکتی که انجام می‌دی، اون پروکسی دیگه اونو انتخاب نمی‌کنی. یعنی پروکسی مرد. و پروکسی‌های مرده هم هر چند وقت یک‌بار، یک‌بار دیگه هم تست بشن، اگر زنده شده باشن دوباره بهشون برگردونی به سیستم. یعنی این نواقصی که خود کلش داره بتونی با ای‌پی‌آیی که داره و یک اسکریپت پایتونی که به‌صورت اینتروالی اجرا می‌شه، هندل کنیم. یک ران‌روبین واقعی که ترو ران‌روبین به‌اضافه‌ی یک هش‌ویت لود بالانس تور می‌خوام که دقیقاً دیتات هم باید توی اس‌کی‌لایت ذخیره کنی. که بر اساس دیتای خودمون هندل کنیم، نه دیتای کلش. کلاً حالا یه چیزایی گفتم نسبت به ای‌پی‌آیی که کلش داره بهم بگو قابل پیاده‌سازی هست یا نه.

English summary: keep PROXY group in select mode, ignore mihomo auto-balance modes. Write a Python script using the Clash API plus a local SQLite database keyed by unique proxy names. Test each proxy through Clash itself (per-node delay check), store the delay for alive nodes, track dead nodes separately. The script owns the system state externally: every N seconds rotate the selected proxy round-robin among alive nodes, equalize load by tracked usage counts, skip dead nodes, and retest dead nodes on a slower loop to readmit revived ones. True round-robin plus hash-weighted balancing driven by our own data, not Clash internals. Manager asked whether this is implementable via the Clash API. Task parked on manager order: "just task it not need to handle it now".

## Local TODOs

- [ ] Confirm feasibility against Clash API surface (proxies list, per-node delay, switch now)
- [ ] Design SQLite schema (proxy name unique, delay, alive state, usage counts)
- [ ] Implement per-node test loop via Clash delay API
- [ ] Implement round-robin rotation with usage equalization
- [ ] Implement dead-node slower retest loop and readmission
- [ ] Wire interval execution (systemd timer or loop)
- [ ] Verify against live config

## Acceptance Criteria

- [ ] PROXY group stays in select mode; script owns selection
- [ ] Per-node liveness and delay stored in SQLite keyed by proxy name
- [ ] Rotation spreads traffic evenly across alive nodes by usage counts
- [ ] Dead nodes skipped and retested on slower loop, readmitted when alive

## Verification Evidence

- **Test command:** _(fill during execution)_
- **Expected result:** _(fill during execution)_
- **Actual result:** _(not yet executed — task parked)_
- **Exit code:** _(not yet executed — task parked)_

## Definition of Done

The task is NOT done unless ALL of the following are true (unconditional, applies to every source type):

- [ ] Build/Test/Lint pass with exit code 0
- [ ] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append
- [ ] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** per-node delay checks against 7000+ nodes are slow; rotation interval must account for check throughput
- **Rollback plan:** stop the script/timer; selection stays wherever it was last set, mihomo keeps working in select mode

---

## Execution Log & Reasoning

_(Parked on creation per manager order — no implementation yet.)_

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->

_(Git diff will be automatically injected here by the MCP tool. Do not edit this block manually)_

<!-- END_GIT_DIFF -->
