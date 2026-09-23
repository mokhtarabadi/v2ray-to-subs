#!/usr/bin/env bash
# v2ray-to-subs manager - generate/validate/deploy Clash + sing-box configs
# Default source: Patterniha Free-Configs (fragment #Patterniha-F = title)
# Usage: ./manager.sh {generate|clash|singbox|tun|check|deploy|help} [url] [extra args]
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONVERTER="$DIR/proxy_converter.py"
CLASH_OUT="$DIR/clash_config.yaml"
SB_OUT="$DIR/singbox_config.json"
DEFAULT_URL="https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt#Patterniha-F"
DESKTOP_DIR="/home/mohammad/Desktop/mihomo"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*" >&2; }
info() { echo -e "${BLUE}[INFO]${NC} $*"; }

pick_python() {
  if [[ -x "$DIR/.venv/bin/python" ]]; then
    echo "$DIR/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    echo "python3"
  else
    err "no python found (tried .venv/bin/python, python3)"
    exit 1
  fi
}

find_mihomo() {
  if command -v mihomo >/dev/null 2>&1; then command -v mihomo;
  elif [[ -x "$DESKTOP_DIR/mihomo" ]]; then echo "$DESKTOP_DIR/mihomo";
  else echo ""; fi
}

find_singbox() {
  if command -v sing-box >/dev/null 2>&1; then command -v sing-box; else echo ""; fi
}

# generate [url] [--tun] [--allow-lan] [--only clash|singbox|both] [-v]
do_generate() {
  local url="$DEFAULT_URL" only="both" tun="" lan="" verbose=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tun) tun="--tun"; shift ;;
      --allow-lan) lan="--allow-lan"; shift ;;
      --only) only="$2"; shift 2 ;;
      --only=*) only="${1#--only=}"; shift ;;
      -v|--verbose) verbose="-v"; shift ;;
      -h|--help) show_help; exit 0 ;;
      -*) warn "unknown flag ignored: $1"; shift ;;
      *) url="$1"; shift ;;
    esac
  done
  case "$only" in
    clash|singbox|both) ;;
    *) err "bad --only value: $only (want clash|singbox|both)"; exit 1 ;;
  esac

  info "source: $url"
  info "outputs: $only | tun: ${tun:-off} | lan: ${lan:-off}"
  # shellcheck disable=SC2086
  "$(pick_python)" "$CONVERTER" "$url" \
    --clash-out "$CLASH_OUT" --singbox-out "$SB_OUT" \
    --only "$only" $tun $lan $verbose
  ok "generated: $CLASH_OUT + $SB_OUT (as selected)"
}

do_check() {
  local fail=0
  local mihomo singbox
  mihomo="$(find_mihomo)"; singbox="$(find_singbox)"
  if [[ -z "$mihomo" ]]; then
    warn "mihomo binary not found, skipping clash check"
  else
    info "mihomo -t $CLASH_OUT"
    if "$mihomo" -t -f "$CLASH_OUT" 2>&1 | tail -n2; then ok "clash config valid"; else err "clash check FAILED"; fail=1; fi
  fi
  if [[ -z "$singbox" ]]; then
    warn "sing-box binary not found, skipping sing-box check"
  else
    info "sing-box check $SB_OUT"
    if "$singbox" check -c "$SB_OUT"; then ok "sing-box config valid"; else err "sing-box check FAILED"; fail=1; fi
  fi
  [[ $fail -eq 0 ]] || exit 1
}

# deploy [--tun] [--allow-lan] [url] — regenerate then install to Desktop mihomo
do_deploy() {
  do_generate "$@"
  do_check
  if [[ ! -d "$DESKTOP_DIR" ]]; then
    err "desktop dir not found: $DESKTOP_DIR"
    exit 1
  fi
  local bak="$DESKTOP_DIR/config.yaml.deploy-$(date +%Y%m%d-%H%M%S).bak"
  cp "$DESKTOP_DIR/config.yaml" "$bak"
  info "backup: $bak"
  cp "$CLASH_OUT" "$DESKTOP_DIR/config.yaml"
  ok "installed $CLASH_OUT -> $DESKTOP_DIR/config.yaml"
  if [[ -x "$DESKTOP_DIR/manager.sh" ]]; then
    info "validating with Desktop manager..."
    (cd "$DESKTOP_DIR" && ./manager.sh check)
  fi
  warn "activation needs root: cd $DESKTOP_DIR && sudo ./manager.sh restart"
  warn "dashboard lands at http://127.0.0.1:9090/ui after restart (auto-downloaded)"
}

show_help() {
  cat <<EOF
v2ray-to-subs manager - $DIR
Default subscription: $DEFAULT_URL

Usage: $(basename "$0") <command> [url] [flags]

Commands:
  generate [url] [--tun] [--allow-lan] [--only clash|singbox|both] [-v]
      Regenerate configs (defaults: Patterniha URL, TUN off, loopback-only)
  clash [url] [flags]     Same as generate --only clash
  singbox [url] [flags]   Same as generate --only singbox
  tun [url]               Same as generate --tun (TUN on, loopback-only)
  check                   Validate outputs (mihomo -t + sing-box check)
  deploy [url] [flags]    generate + check + install to $DESKTOP_DIR
  help                    Show this help

Examples:
  ./manager.sh generate
  ./manager.sh generate --tun
  ./manager.sh tun "https://example.com/sub#MyProfile"
  ./manager.sh clash --only clash
  ./manager.sh check
  ./manager.sh deploy --tun

Outputs:
  Clash (mihomo): $CLASH_OUT
  sing-box:       $SB_OUT

Notes:
  - TUN needs root/CAP_NET_ADMIN: use --tun only if you run mihomo/sing-box
    with sudo or setcap; otherwise keep the loopback-only default.
  - --allow-lan binds mixed-port to all interfaces (loopback-only by default).
  - Dashboard: http://127.0.0.1:9090/ui (auto-downloaded metacubexd).
EOF
}

case "${1:-help}" in
  generate) shift; do_generate "$@" ;;
  clash) shift; do_generate --only clash "$@" ;;
  singbox) shift; do_generate --only singbox "$@" ;;
  tun) shift; do_generate --tun "$@" ;;
  check) do_check ;;
  deploy) shift; do_deploy "$@" ;;
  help|--help|-h) show_help ;;
  *) err "unknown command: $1"; show_help; exit 1 ;;
esac
