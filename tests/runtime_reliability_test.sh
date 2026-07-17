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

assert_call_count() {
  local needle=$1 expected=$2 count
  count=$(grep -Fc -- "$needle" "$calls" || true)
  [[ "$count" == "$expected" ]] || fail "expected $expected '$needle' calls, got $count"
}

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
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
second_round="$tmpdir/second-round"
restarted="$tmpdir/restarted"
restart_epoch="$tmpdir/restart.epoch"
blocking="$tmpdir/blocking"
flock_dir="$tmpdir/flock"
mkdir -p "$state" "$run_dir" "$fake_root" "$fakebin" "$flock_dir"

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
if [[ "${DNS_TEST_SCENARIO:-}" == "transient" && "${1:-}" == "2" ]]; then
  : >"$DNS_TEST_SECOND_ROUND"
fi
if [[ "${1:-}" == "0.05" ||
      ( "${DNS_TEST_REAL_SLEEP:-0}" == "1" && "${1:-}" != "2" ) ]]; then
  exec /bin/sleep "$@"
fi
exit 0
EOF

cat >"$fakebin/date" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "+%s" && -n "${DNS_TEST_NOW:-}" ]]; then
  printf '%s\n' "$DNS_TEST_NOW"
  exit 0
fi
exec /bin/date "$@"
EOF

cat >"$fakebin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"$DNS_TEST_CALLS"
case "${1:-}" in
  is-active)
    [[ "${3:-}" == "${DNS_TEST_INACTIVE_UNIT:-}" ]] && exit 3
    exit 0
    ;;
  restart)
    if [[ "${2:-}" == "smartdns" ]]; then
      : >"$DNS_TEST_RESTARTED"
      /bin/date +%s >"$DNS_TEST_RESTART_EPOCH"
      [[ "${DNS_TEST_SCENARIO:-}" == "restart_failure" ]] && exit 9
    fi
    exit 0
    ;;
  start) exit 0 ;;
esac
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
printf 'flock %s\n' "$*" >>"$DNS_TEST_CALLS"
case "${DNS_TEST_FLOCK_MODE:-normal}" in
  busy) exit 1 ;;
  auto)
    mkdir "$DNS_TEST_FLOCK_DIR/held" 2>/dev/null
    ;;
esac
EOF

cat >"$fakebin/ip" <<'EOF'
#!/usr/bin/env bash
printf 'ip %s\n' "$*" >>"$DNS_TEST_CALLS"
case "${1:-} ${2:-}" in
  "rule show")
    case "${DNS_TEST_ROUTE_STATE:-complete}" in
      missing_rule|missing_all)
        printf '101: from all fwmark 0x351 lookup 351\n'
        ;;
      *)
        printf '100: from all fwmark 0x301 lookup 301\n'
        printf '101: from all fwmark 0x351 lookup 351\n'
        ;;
    esac
    ;;
  "route show")
    case "${4:-}" in
      301)
        case "${DNS_TEST_ROUTE_STATE:-complete}" in
          missing_route|missing_all) ;;
          *) printf 'default dev ipsec-ai table 301\n' ;;
        esac
        ;;
      351) printf 'default dev ipsec-cn table 351\n' ;;
    esac
    ;;
esac
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
seconds=2
while [[ $# -gt 0 ]]; do
  case "$1" in
    --signal=*|--kill-after=*) shift ;;
    *s) seconds=${1%s}; shift; break ;;
    [0-9]*) seconds=$1; shift; break ;;
    *) shift ;;
  esac
done
if [[ "${DNS_TEST_SCENARIO:-}" != "post_restart_blocking" ]]; then
  exec "$@"
fi
"$@" &
child=$!
(
  /bin/sleep "$seconds"
  kill -TERM "$child" 2>/dev/null || true
  /bin/sleep 1
  kill -KILL "$child" 2>/dev/null || true
) &
killer=$!
set +e
wait "$child"
status=$?
set -e
kill "$killer" 2>/dev/null || true
wait "$killer" 2>/dev/null || true
exit "$status"
EOF

cat >"$fakebin/dig" <<'EOF'
#!/usr/bin/env bash
is_direct=0
[[ " $* " == *" @1.1.1.1 "* || " $* " == *" @223.5.5.5 "* ]] && is_direct=1
case "$DNS_TEST_SCENARIO" in
  healthy) printf '93.184.216.34\n' ;;
  transient)
    [[ -f "$DNS_TEST_SECOND_ROUND" ]] && printf '93.184.216.34\n'
    ;;
  partial)
    if [[ "$is_direct" == "1" || " $* " != *" -p 6054 "* ]]; then
      printf '93.184.216.34\n'
    else
      exit 9
    fi
    ;;
  deadlocked|cooldown|restart_failure)
    if [[ "$is_direct" == "1" || -f "$DNS_TEST_RESTARTED" ]]; then
      printf '93.184.216.34\n'
    else
      exit 9
    fi
    ;;
  external_down) exit 9 ;;
  post_restart_blocking)
    if [[ "$is_direct" == "1" ]]; then
      printf '93.184.216.34\n'
    elif [[ -f "$DNS_TEST_RESTARTED" ]]; then
      : >"$DNS_TEST_BLOCKING"
      exec /bin/sleep 60
    else
      exit 9
    fi
    ;;
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
  DNS_TEST_SECOND_ROUND="$second_round" \
  DNS_TEST_RESTARTED="$restarted" \
  DNS_TEST_RESTART_EPOCH="$restart_epoch" \
  DNS_TEST_BLOCKING="$blocking" \
  DNS_TEST_FLOCK_DIR="$flock_dir" \
  DNS_TEST_SCENARIO="${DNS_TEST_SCENARIO:-healthy}" \
  DNS_TEST_ROUTE_STATE="${DNS_TEST_ROUTE_STATE:-complete}" \
  DNS_TEST_INACTIVE_UNIT="${DNS_TEST_INACTIVE_UNIT:-}" \
  DNS_TEST_FLOCK_MODE="${DNS_TEST_FLOCK_MODE:-normal}" \
  DNS_TEST_REAL_SLEEP="${DNS_TEST_REAL_SLEEP:-0}" \
  DNS_TEST_NOW="${DNS_TEST_NOW:-}" \
  "$manager" "$@"
}

reset_state() {
  : >"$calls"
  rm -f "$counter" "$second_round" "$restarted" "$restart_epoch" "$blocking"
  rm -rf "$flock_dir/held"
}

run_watchdog() {
  local scenario=$1
  reset_state
  case "$scenario" in
    cooldown) ;;
    *) rm -f "$run_dir/smartdns.last_restart" ;;
  esac
  DNS_TEST_SCENARIO="$scenario" run_manager watchdog
}

run_watchdog_at() {
  local now=$1 scenario=$2
  DNS_TEST_NOW="$now" run_watchdog "$scenario"
}

run_watchdog healthy
assert_not_contains "$calls" 'restart smartdns'

DNS_TEST_INACTIVE_UNIT=AdGuardHome run_watchdog healthy
assert_contains "$calls" 'systemctl restart AdGuardHome'
assert_call_count 'systemctl restart' 1
assert_not_contains "$calls" 'restart smartdns'

run_watchdog transient
assert_not_contains "$calls" 'restart smartdns'

if run_watchdog partial >"$tmpdir/partial.log" 2>&1; then
  fail "watchdog must report a persistent partial listener failure"
fi
assert_contains "$tmpdir/partial.log" 'partially unavailable'
assert_not_contains "$calls" 'restart smartdns'

run_watchdog deadlocked
assert_contains "$calls" 'restart smartdns'
[[ -f "$run_dir/smartdns.last_restart" ]] || fail "watchdog did not persist cooldown state"

if run_watchdog external_down; then
  fail "watchdog must fail when listeners and positive controls are down"
fi
assert_not_contains "$calls" 'restart smartdns'

printf '%s\n' 99401 >"$run_dir/smartdns.last_restart"
if run_watchdog_at 100000 cooldown; then
  fail "watchdog must enforce the 599-second cooldown boundary"
fi
assert_not_contains "$calls" 'restart smartdns'

printf '%s\n' 99400 >"$run_dir/smartdns.last_restart"
run_watchdog_at 100000 cooldown
assert_contains "$calls" 'restart smartdns'

for corrupt in '' nonsense 08; do
  printf '%s\n' "$corrupt" >"$run_dir/smartdns.last_restart"
  if ! run_watchdog_at 100000 cooldown >"$tmpdir/corrupt.log" 2>&1; then
    cat "$tmpdir/corrupt.log" >&2
    fail "corrupt cooldown state must permit one recovery attempt"
  fi
  assert_contains "$calls" 'restart smartdns'
  [[ "$(cat "$run_dir/smartdns.last_restart")" == "100000" ]] || fail "corrupt cooldown state was not replaced"
  [[ "$(file_mode "$run_dir/smartdns.last_restart")" == "600" ]] || fail "cooldown state is not restrictive"
done

printf '%s\n' 999999 >"$run_dir/smartdns.last_restart"
if run_watchdog_at 100000 cooldown; then
  fail "future cooldown timestamp must not report recovery"
fi
assert_not_contains "$calls" 'restart smartdns'
[[ "$(cat "$run_dir/smartdns.last_restart")" == "100000" ]] || fail "future cooldown timestamp was not clamped"

if run_watchdog_at 100000 restart_failure; then
  fail "watchdog must fail when SmartDNS restart fails"
fi
assert_contains "$calls" 'restart smartdns'
assert_not_contains "$calls" 'start --no-block dnscomplex-nftset-refresh.service'
[[ "$(cat "$run_dir/smartdns.last_restart")" == "100000" ]] || fail "failed restart did not retain cooldown timestamp"

DNS_TEST_ROUTE_STATE=complete run_watchdog healthy
assert_not_contains "$calls" 'ip rule add fwmark'

DNS_TEST_ROUTE_STATE=missing_route run_watchdog healthy
assert_contains "$calls" 'ip rule add fwmark 0x301 table 301'

DNS_TEST_ROUTE_STATE=missing_rule run_watchdog healthy
assert_contains "$calls" 'ip rule add fwmark 0x301 table 301'

legacy_root="$tmpdir/legacy-root"
mkdir -p "$legacy_root/etc/dnscomplex"
cp "$config" "$legacy_root/etc/dnscomplex/config.env"
reset_state
PATH="$fakebin:$PATH" \
DNSCOMPLEX_ROOT="$legacy_root" \
DNS_TEST_CALLS="$calls" \
DNS_TEST_COUNTER="$counter" \
DNS_TEST_SECOND_ROUND="$second_round" \
DNS_TEST_RESTARTED="$restarted" \
DNS_TEST_RESTART_EPOCH="$restart_epoch" \
DNS_TEST_BLOCKING="$blocking" \
DNS_TEST_FLOCK_DIR="$flock_dir" \
DNS_TEST_SCENARIO=healthy \
DNS_TEST_ROUTE_STATE=complete \
"$manager" watchdog
assert_not_contains "$calls" 'restart smartdns'

printf '%s\n' 'AI_EGRESS_MODE=xray' 'CN_EGRESS_MODE=xray' >>"$config"
DNS_TEST_ROUTE_STATE=missing_all run_watchdog healthy
assert_not_contains "$calls" 'ip rule add fwmark'

reset_state
rm -f "$run_dir/smartdns.last_restart"
DNS_TEST_SCENARIO=post_restart_blocking \
DNS_TEST_REAL_SLEEP=1 \
DNS_TEST_FLOCK_MODE=auto \
run_manager watchdog >"$tmpdir/blocked.log" 2>&1 &
blocked_pid=$!
for attempt in $(seq 1 100); do
  [[ -f "$blocking" ]] && break
  /bin/sleep 0.05
done
[[ -f "$blocking" ]] || fail "blocking post-restart probe did not start"
second_started=$(/bin/date +%s)
DNS_TEST_SCENARIO=healthy DNS_TEST_FLOCK_MODE=auto run_manager watchdog >"$tmpdir/busy.log" 2>&1 ||
  fail "busy watchdog invocation must coalesce"
second_elapsed=$(( $(/bin/date +%s) - second_started ))
((second_elapsed <= 3)) || fail "busy watchdog did not return promptly: ${second_elapsed}s"
assert_contains "$tmpdir/busy.log" 'coalescing invocation'
if wait "$blocked_pid"; then
  fail "watchdog must fail when listeners do not recover after restart"
fi
restart_started=$(cat "$restart_epoch")
elapsed=$(( $(/bin/date +%s) - restart_started ))
((elapsed >= 14 && elapsed <= 17)) || fail "post-restart recovery exceeded wall-clock bound: ${elapsed}s"
printf 'post_restart_elapsed_seconds=%s\n' "$elapsed"
assert_call_count 'systemctl restart smartdns' 1
assert_not_contains "$calls" 'start --no-block dnscomplex-nftset-refresh.service'
rm -rf "$flock_dir/held"

printf 'runtime reliability test: ok\n'
