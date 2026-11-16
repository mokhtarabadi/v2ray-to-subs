#!/usr/bin/env bash
# tailnet-mihomo-setup.sh - steer tailnet exit traffic into mihomo's TUN.
# Runs ONCE as root (systemd tailnet-mihomo-route.service). Idempotent.
# Only packets arriving on tailscale0 are marked; host OUTPUT, tailscaled,
# SSH and tailnet-internal traffic stay on the main table, untouched.
set -e

TUN_DEV="${TUN_DEV:-mihomo}"
TABLE="${TABLE:-100}"
MARK="${MARK:-0x55}"
PRIO="${PRIO:-5280}"

# 1. mihomo owns the TUN device (user service). Wait for it, never create it.
for _ in $(seq 1 30); do
	if ip link show dev "$TUN_DEV" >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
ip link show dev "$TUN_DEV" >/dev/null 2>&1 || {
	echo "tailnet-mihomo: device $TUN_DEV missing after 30s, aborting" >&2
	exit 1
}

# 2. Policy routing: marked packets -> TUN device (main table untouched).
ip route replace default dev "$TUN_DEV" table "$TABLE"
ip rule del fwmark "$MARK" table "$TABLE" 2>/dev/null || true
ip rule add fwmark "$MARK" table "$TABLE" priority "$PRIO"

# 3. Mark all INTERNET-bound packets from tailnet peers (TCP and UDP).
#    Tailnet-internal 100.64.0.0/10 is excluded. Low mark bits survive
#    tailscale's own remark (mark and 0xff00ffff xor 0x40000).
nft delete table inet usproxy 2>/dev/null || true
nft -f - <<NFT
table inet usproxy {
	chain prerouting {
		type filter hook prerouting priority mangle; policy accept;
		iifname "tailscale0" ip daddr != 100.64.0.0/10 meta mark set $MARK
	}
}
NFT

# 4. Skip tailscale's exit-node MASQUERADE for traffic entering the TUN
#    (mihomo terminates the connections itself; no SNAT needed).
if ! nft list chain ip nat POSTROUTING 2>/dev/null | grep -q "oifname \"$TUN_DEV\""; then
	HANDLE=$(nft --handle list chain ip nat POSTROUTING 2>/dev/null | awk '/jump ts-postrouting/{for(i=1;i<=NF;i++) if($i=="handle") print $(i+1)}' | head -n1)
	if [ -n "$HANDLE" ]; then
		nft insert rule ip nat POSTROUTING position "$HANDLE" oifname "$TUN_DEV" counter accept
	fi
fi

echo "tailnet-mihomo setup OK: fwmark $MARK for iif tailscale0 !100.64.0.0/10 -> table $TABLE via $TUN_DEV"
