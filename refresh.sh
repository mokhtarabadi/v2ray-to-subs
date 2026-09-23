#!/usr/bin/env bash
# Regenerate mihomo-subs clash config from v2ray-to-subs, validate, install, restart.
# Called by v2ray-to-subs-refresh.service (timer). Safe to run manually too.
set -euo pipefail

REPO="$HOME/v2ray-to-subs"
PY="$REPO/.venv/bin/python"
CONVERTER="$REPO/proxy_converter.py"
CONF_DIR="$HOME/.config/mihomo-subs"
LIVE="$CONF_DIR/config.yaml"
TMP="$(mktemp /tmp/mihomo-subs-XXXXXX.yaml)"

cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

echo "[refresh] generating to $TMP ..."
"$PY" "$CONVERTER" --only clash --clash-out "$TMP"

echo "[refresh] validating with mihomo -t ..."
mihomo -t -f "$TMP"

BAK="$CONF_DIR/config.yaml.refresh-$(date +%Y%m%d-%H%M%S).bak"
cp "$LIVE" "$BAK"
echo "[refresh] backup: $BAK"

cat "$TMP" > "$LIVE"
chmod 600 "$LIVE"
echo "[refresh] installed fresh config -> $LIVE"

if systemctl --user is-active --quiet mihomo-subs.service; then
  echo "[refresh] restarting mihomo-subs.service ..."
  systemctl --user restart mihomo-subs.service
else
  echo "[refresh] starting mihomo-subs.service ..."
  systemctl --user start mihomo-subs.service
fi

# keep only last 5 backups
ls -t "$CONF_DIR"/config.yaml.refresh-*.bak 2>/dev/null | tail -n +6 | xargs -r rm -f

echo "[refresh] done. mihomo-subs: $(systemctl --user is-active mihomo-subs.service)"
