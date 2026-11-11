#!/usr/bin/env bash
# Sibling Docs: scripts/README.md | Decisions: scripts/DECISIONS.md
# Single maintenance dispatcher for this project.
#
# One timer drives one oneshot unit: retest the pool, fill observed exit
# countries, and regenerate the live config only when it is stale. This
# replaces the three separate timers (refresh, retest, country) so the
# project owns two units in total: mihomo-subs.service and this pair.
#
# The proxy service is never restarted here unless refresh.sh does it after
# installing a fresh config; a maintenance run must never leave the client
# without a proxy.
set -euo pipefail

REPO="$HOME/v2ray-to-subs"
PY="$REPO/.venv/bin/python"
BALANCER="$REPO/scripts/rr_balancer.py"
REFRESH="$REPO/refresh.sh"
LIVE="$HOME/.config/mihomo-subs/config.yaml"
REFRESH_AFTER_SEC=21600

# Feed list previously supplied by the v2ray-to-subs-refresh.service drop-in
# that this dispatcher replaces. Without these the converter falls back to its
# built-in default feed, which would silently swap the pool.
SUB_URLS=(
  "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt"
  "https://radarhub.top/v2ray.txt"
)

echo "maintain: tick start"

# A failing job must not abort the tick: retest and country both touch the
# live selector, so one bad batch should never block the refresh check.
if ! "$PY" "$BALANCER" retest --batch 500; then
  echo "maintain: retest warned (continuing)"
fi
if ! "$PY" "$BALANCER" country --batch 20; then
  echo "maintain: country warned (continuing)"
fi

NEED_REFRESH=0
if [[ ! -f "$LIVE" ]]; then
  NEED_REFRESH=1
else
  AGE=$(( $(date +%s) - $(stat -c %Y "$LIVE") ))
  if [[ "$AGE" -gt "$REFRESH_AFTER_SEC" ]]; then
    NEED_REFRESH=1
  fi
fi

if [[ "$NEED_REFRESH" -eq 1 ]]; then
  echo "maintain: refresh due, running refresh.sh"
  bash "$REFRESH" "${SUB_URLS[@]}"
else
  echo "maintain: refresh skipped (live config fresh)"
fi

echo "maintain: tick done"
