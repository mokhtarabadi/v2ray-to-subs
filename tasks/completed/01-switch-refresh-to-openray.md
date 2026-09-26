# Task [01]: Switch refresh to OpenRay vless feed

**File:** `tasks/qa/01-switch-refresh-to-openray.md`
**Source:** manager
**Type:** improvement
**Status:** open

## Goal

Point the systemd refresh path at the OpenRay vless subscription without changing code defaults, and fix the REALITY short-id quoting bug the new feed exposed.

## Manager's Notes

Manager asked to set default link to https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/vless.txt, then redirected to systemd-unit approach. Manager approved the revised plan and later said "approved for closure".

## Local TODOs

- [x] Make refresh.sh accept URL arg / SUB_URL env
- [x] Add systemd override passing the OpenRay vless URL
- [x] Fix REALITY short-id YAML quoting (2e00 parsed as float)
- [x] Verify OpenRay + Patterniha feeds with mihomo -t

## Acceptance Criteria

- [x] `refresh.sh` passes a custom URL through to the converter
- [x] Systemd override pins the OpenRay vless feed
- [x] Generated OpenRay clash config passes `mihomo -t`
- [x] Default Patterniha feed still passes `mihomo -t` (regression)

## Verification Evidence

- **Test command:** ./.venv/bin/python proxy_converter.py "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/vless.txt" --only clash --clash-out /tmp/opencode/test-openray2.yaml && mihomo -t -f /tmp/opencode/test-openray2.yaml
- **Expected result:** 7330 proxies generated, mihomo test successful
- **Actual result:** 7330 proxies / 4 groups generated, configuration file test is successful
- **Exit code:** 0

- **Test command:** ./.venv/bin/python proxy_converter.py --only clash --clash-out /tmp/opencode/test-patterniha.yaml && mihomo -t -f /tmp/opencode/test-patterniha.yaml
- **Expected result:** default feed still valid
- **Actual result:** 15 proxies / 4 groups generated, configuration file test is successful
- **Exit code:** 0

- **Test command:** bash -n refresh.sh
- **Expected result:** syntax OK
- **Actual result:** syntax OK
- **Exit code:** 0

## Definition of Done

- [x] Build/Test/Lint pass with exit code 0
- [x] `lint_task_file` passes on the active task file
- [ ] `CHANGELOG.md` updated via Parse-Then-Append (no CHANGELOG.md in repo, skipped)
- [x] `verification-before-completion` applied and evidence recorded

## Risk & Rollback

- **Risk:** OpenRay feed format changes break parsing or validation
- **Rollback plan:** Remove `~/.config/systemd/user/v2ray-to-subs-refresh.service.d/override.conf`, run `systemctl --user daemon-reload`, revert the two repo files

---

## Execution Log & Reasoning

- refresh.sh: added SUB_URL from $1 or $SUB_URL env, passes it to proxy_converter.py, else converter default.
- proxy_converter.py: added _QuotedStr helper forcing double quotes on reality public-key / short-id. Root cause: PyYAML dumps 2e00 unquoted, Go-YAML reads it as float 2.0, mihomo rejects with invalid REALITY short ID. Verified 2e00 failed alone, passes quoted or omitted.
- Systemd override (outside repo, not committed): ExecStart passes the OpenRay vless URL. Refresh ran 12:12, exit 0, live config 7330 proxies, mihomo-subs.service active.
- No task-file tracking was used during the ad-hoc fix per manager's "if need and can just change systemd unit"; task file created retroactively for closure. Manager approval quote: "fine approved for closure task it and close it".

## Factual Git Diff

<!-- BEGIN_GIT_DIFF -->
```diff
diff --git a/proxy_converter.py b/proxy_converter.py
index 28b65e1..2f48768 100644
--- a/proxy_converter.py
+++ b/proxy_converter.py
@@ -157,6 +157,26 @@ UTLS_FINGERPRINTS = {
 }
 
 
+class _QuotedStr(str):
+    """A string that PyYAML always emits double-quoted.
+
+    Needed for REALITY public-key / short-id: values like "2e00" are
+    valid hex but dump unquoted by PyYAML while Go-YAML (mihomo) reads
+    them as float 2.0, failing with "invalid REALITY short ID".
+    """
+
+
+def _quoted_str_representer(dumper: yaml.Dumper, data: _QuotedStr):  # type: ignore[type-arg]
+    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style='"')
+
+
+yaml.add_representer(_QuotedStr, _quoted_str_representer)
+try:
+    yaml.SafeDumper.add_representer(_QuotedStr, _quoted_str_representer)  # type: ignore[attr-defined]
+except Exception:
+    pass
+
+
 def _unquote(value: Optional[str]) -> str:
     if not value:
         return ""
@@ -882,9 +902,9 @@ class ConfigGenerator:
         if alpn:
             block["alpn"] = alpn
         if cfg.security == "reality" and cfg.pbk:
-            reality: Dict[str, Any] = {"public-key": cfg.pbk}
+            reality: Dict[str, Any] = {"public-key": _QuotedStr(cfg.pbk)}
             if cfg.sid is not None:
-                reality["short-id"] = cfg.sid
+                reality["short-id"] = _QuotedStr(cfg.sid)
             block["reality-opts"] = reality
         return block
 
diff --git a/refresh.sh b/refresh.sh
index 83fc493..ac32654 100755
--- a/refresh.sh
+++ b/refresh.sh
@@ -16,8 +16,21 @@ trap cleanup EXIT
 # Controller secret lives in a chmod-600 file, never in git.
 export MIHOMO_CONTROLLER_SECRET="$(cat "$CONF_DIR/.controller_secret")"
 
+# Subscription source: $1 or $SUB_URL wins, else converter default.
+# Lets the systemd unit pin a custom sub without editing code.
+SUB_URL="${1:-${SUB_URL:-}}"
+if [ -n "$SUB_URL" ]; then
+  echo "[refresh] source: $SUB_URL"
+else
+  echo "[refresh] source: converter default"
+fi
+
 echo "[refresh] generating to $TMP ..."
-"$PY" "$CONVERTER" --only clash --clash-out "$TMP"
+if [ -n "$SUB_URL" ]; then
+  "$PY" "$CONVERTER" "$SUB_URL" --only clash --clash-out "$TMP"
+else
+  "$PY" "$CONVERTER" --only clash --clash-out "$TMP"
+fi
 
 echo "[refresh] validating with mihomo -t ..."
 mihomo -t -f "$TMP"
```
<!-- END_GIT_DIFF -->
