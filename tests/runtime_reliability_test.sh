#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  grep -Fq -- "$2" "$1" || fail "missing '$2' in $1"
}

assert_not_contains() {
  if grep -Fq -- "$2" "$1"; then
    fail "unexpected '$2' in $1"
  fi
}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmpdir=$(mktemp -d)
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

render_root="$tmpdir/rendered"
config="$tmpdir/config.env"
state="$tmpdir/state"
run_dir="$tmpdir/run"
fake_root="$tmpdir/fakeroot"
fakebin="$tmpdir/fakebin"
calls="$tmpdir/calls.log"
counter="$tmpdir/dig.counter"
restarted="$tmpdir/restarted"
mkdir -p "$state" "$run_dir" "$fake_root" "$fakebin"

cat >"$config" <<'EOF'
DNSCOMPLEX_NONINTERACTIVE=1
DEPLOY_MODE=routeros-policy
WAN_IFACE=eth0
ROUTEROS_LAN_IPV4=192.168.8.253
LINUX_LAN_IPV4=192.168.8.200
LAN_CLIENT_IPV4_CIDR=192.168.8.0/24
SINGBOX_SOCKS_LISTEN=192.168.8.200
SINGBOX_SOCKS_PORT=10800
AI_IPSEC_USERNAME=fixture-ai
AI_IPSEC_PASSWORD=fixture-ai-pass
CN_IPSEC_USERNAME=fixture-cn
CN_IPSEC_PASSWORD=fixture-cn-pass
AI_NFTSET_REFRESH_DOMAINS=openai.com
CN_NFTSET_REFRESH_DOMAINS=youku.com
EOF

DNSCOMPLEX_ROOT="$render_root" \
  bash "$repo_root/install.sh" --dry-run --config "$config" >/dev/null
manager="$render_root/usr/local/sbin/dnscomplex"
[[ -x "$manager" ]] || fail "manager was not rendered"

cat >"$fakebin/id" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == "-u" ]] && { printf '0\n'; exit 0; }
exit 64
EOF

cat >"$fakebin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$fakebin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"$DNS_TEST_CALLS"
if [[ "${1:-}" == "is-active" ]]; then exit 0; fi
if [[ "${1:-}" == "restart" && "${2:-}" == "smartdns" ]]; then
  : >"$DNS_TEST_RESTARTED"
fi
exit 0
EOF

cat >"$fakebin/nft" <<'EOF'
#!/usr/bin/env bash
printf 'nft %s\n' "$*" >>"$DNS_TEST_CALLS"
case "${1:-} ${2:-}" in
  "list table") exit 0 ;;
  "get element") exit 1 ;;
  "-f "*)
    sed 's/^/nft-batch /' "$2" >>"$DNS_TEST_CALLS"
    exit 0
    ;;
esac
exit 0
EOF

cat >"$fakebin/flock" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$fakebin/ip" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-} ${2:-}" == "rule show" ]]; then
  printf '100: from all fwmark 0x301 lookup 301\n'
  printf '101: from all fwmark 0x351 lookup 351\n'
fi
exit 0
EOF

cat >"$fakebin/swanctl" <<'EOF'
#!/usr/bin/env bash
printf 'swanctl %s\n' "$*" >>"$DNS_TEST_CALLS"
if [[ "${1:-}" == "--list-sas" ]]; then
  printf 'ai: #1, ESTABLISHED\n'
  printf 'cn: #2, ESTABLISHED\n'
fi
exit 0
EOF

cat >"$fakebin/timeout" <<'EOF'
#!/usr/bin/env bash
printf 'timeout %s\n' "$*" >>"$DNS_TEST_CALLS"
shift
exec "$@"
EOF

cat >"$fakebin/dig" <<'EOF'
#!/usr/bin/env bash
case "$DNS_TEST_SCENARIO" in
  healthy) printf '93.184.216.34\n' ;;
  transient)
    count=$(cat "$DNS_TEST_COUNTER" 2>/dev/null || printf 0)
    count=$((count + 1))
    printf '%s\n' "$count" >"$DNS_TEST_COUNTER"
    ((count > 3)) && printf '93.184.216.34\n'
    ;;
  deadlocked|cooldown)
    if [[ " $* " == *" @1.1.1.1 "* ||
          " $* " == *" @223.5.5.5 "* ||
          -f "$DNS_TEST_RESTARTED" ]]; then
      printf '93.184.216.34\n'
    else
      exit 9
    fi
    ;;
  external_down) exit 9 ;;
  *) exit 64 ;;
esac
EOF

chmod +x "$fakebin"/*

run_manager() {
  PATH="$fakebin:$PATH" \
  DNSCOMPLEX_CONFIG="$config" \
  DNSCOMPLEX_BASE="$state" \
  DNSCOMPLEX_RUN_DIR="$run_dir" \
  DNSCOMPLEX_FS_ROOT="$fake_root" \
  DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
  DNS_TEST_CALLS="$calls" \
  DNS_TEST_COUNTER="$counter" \
  DNS_TEST_RESTARTED="$restarted" \
  DNS_TEST_SCENARIO="${DNS_TEST_SCENARIO:-healthy}" \
  "$manager" "$@"
}

run_watchdog() {
  local scenario=$1
  : >"$calls"
  rm -f "$counter" "$restarted"
  [[ "$scenario" == "cooldown" ]] || rm -f "$run_dir/smartdns.last_restart"
  DNS_TEST_SCENARIO="$scenario" run_manager watchdog
}

run_watchdog healthy
assert_not_contains "$calls" 'restart smartdns'

run_watchdog transient
assert_not_contains "$calls" 'restart smartdns'

run_watchdog deadlocked
assert_contains "$calls" 'restart smartdns'
[[ -f "$run_dir/smartdns.last_restart" ]] || fail "watchdog did not persist cooldown state"

if run_watchdog external_down; then
  fail "watchdog must fail when listeners and positive controls are down"
fi
assert_not_contains "$calls" 'restart smartdns'

printf '%s\n' "$(date +%s)" >"$run_dir/smartdns.last_restart"
if run_watchdog cooldown; then
  fail "watchdog must report an unrecovered failure during cooldown"
fi
assert_not_contains "$calls" 'restart smartdns'

printf 'runtime reliability test: ok\n'
