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
	"https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt"
	"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt"
	"https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/base64/all_sub.txt"
)

echo "maintain: tick start"

# A failing job must not abort the tick: retest and country both touch the
# live selector, so one bad batch should never block the refresh check.
if ! "$PY" "$BALANCER" retest --batch 1000; then
	echo "maintain: retest warned (continuing)"
fi
if ! "$PY" "$BALANCER" country --batch 40; then
	echo "maintain: country warned (continuing)"
fi

# Guarded auto-rotate: keep the best gate-tested DE exit without churn.
# --keep-if-clean only moves when the current exit is dirty; a healthy
# exit is kept untouched, so stable connections never flap.
if ! "$PY" "$BALANCER" rotate --require-country US --keep-if-clean; then
	echo "maintain: rotate warned (continuing)"
fi

NEED_REFRESH=0
if [[ ! -f "$LIVE" ]]; then
	NEED_REFRESH=1
else
	AGE=$(($(date +%s) - $(stat -c %Y "$LIVE")))
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
