---
created_at: '2026-10-16T08:55:38.063937+00:00'
status: active
tags: []
updated_at: '2026-10-16T08:55:38.063955+00:00'
---

OpenCode rate-limit-rescue plugin source of truth is the private GitHub repo mokhtarabadi/opencode-rate-limit-rescue (extracted out of cognitive-lead-hq, commit a4a36f6). Global opencode.json references it as github:mokhtarabadi/opencode-rate-limit-rescue; server caches under ~/.cache/opencode/npm/git-opencode-rate-limit-rescue-*/. Change flow lives in THAT repo: edit index.js, verify with node --check index.js && node --test test.mjs, commit+push, then systemctl --user restart openchamber; if stale, delete the server cache dir and restart again, confirm the loading-plugin line in opencode.log. The old ~/.config/opencode/plugins/rate-limit-rescue path is NOT source. Rescue kinds: quota, transport, region; metrics sink ~/.local/share/opencode/ratelimit-metrics.jsonl. NEVER commit the metrics file: it contains real node names from rotation output.