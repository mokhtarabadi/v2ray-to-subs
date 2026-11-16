#!/usr/bin/env bash
# tailnet-mihomo-teardown.sh - rollback for tailnet-mihomo-setup.sh.
# Removes peer steering only. The mihomo TUN device is mihomo-owned and
# is left alone.
set -e

TUN_DEV="${TUN_DEV:-mihomo}"
TABLE="${TABLE:-100}"
MARK="${MARK:-0x55}"

nft delete table inet usproxy 2>/dev/null || true
HANDLE=$(nft --handle list chain ip nat POSTROUTING 2>/dev/null | awk -v dev="oifname \"$TUN_DEV\"" '$0 ~ dev {for(i=1;i<=NF;i++) if($i=="handle") print $(i+1)}' | head -n1)
if [ -n "$HANDLE" ]; then
	nft delete rule ip nat POSTROUTING handle "$HANDLE" 2>/dev/null || true
fi
ip rule del fwmark "$MARK" table "$TABLE" 2>/dev/null || true
ip route flush table "$TABLE" 2>/dev/null || true
echo "tailnet-mihomo teardown OK"
