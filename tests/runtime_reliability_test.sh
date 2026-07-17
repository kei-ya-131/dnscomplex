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

monotonic_millis() {
  python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)'
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
restart_monotonic="$tmpdir/restart.monotonic"
blocking="$tmpdir/blocking"
probe_pids="$tmpdir/probe-pids"
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
    if [[ "${2:-}" == "${DNS_TEST_RESTART_FAIL_UNIT:-}" ||
          ( "${2:-}" == "smartdns" && "${DNS_TEST_SCENARIO:-}" == "restart_failure" ) ]]; then
      exit 9
    fi
    if [[ "${2:-}" == "smartdns" ]]; then
      : >"$DNS_TEST_RESTARTED"
      /bin/date +%s >"$DNS_TEST_RESTART_EPOCH"
      python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)' \
        >"$DNS_TEST_RESTART_MONOTONIC"
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
#!/usr/bin/env python3
import fcntl
import os
import sys

with open(os.environ["DNS_TEST_CALLS"], "a", encoding="utf-8") as calls:
    calls.write("flock " + " ".join(sys.argv[1:]) + "\n")
fd = int(sys.argv[-1])
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit(1)
EOF

cat >"$fakebin/mktemp" <<'EOF'
#!/usr/bin/env bash
if [[ "${DNS_TEST_MKTEMP_FAIL:-}" == "probe" && " $* " == *".smartdns-probe."* ]]; then
  exit 9
fi
exec /usr/bin/mktemp "$@"
EOF

cat >"$fakebin/mv" <<'EOF'
#!/usr/bin/env bash
if [[ "${DNS_TEST_STATE_WRITE_FAIL:-0}" == "1" &&
      "${*: -1}" == */smartdns.last_restart ]]; then
  exit 9
fi
exec /bin/mv "$@"
EOF

cat >"$fakebin/ip" <<'EOF'
#!/usr/bin/env bash
printf 'ip %s\n' "$*" >>"$DNS_TEST_CALLS"
case "${DNS_TEST_ROUTE_APPLY_FAIL:-0}" in
  1|all)
    if [[ "${1:-} ${2:-}" == "rule add" || "${1:-} ${2:-}" == "route replace" ]]; then
      exit 9
    fi
    ;;
  rule)
    [[ "${1:-} ${2:-}" == "rule add" ]] && exit 9
    ;;
  route)
    [[ "${1:-} ${2:-}" == "route replace" ]] && exit 9
    ;;
esac
case "${1:-} ${2:-}" in
  "rule show")
    [[ "${DNS_TEST_ROUTE_STATE:-complete}" == "inspect_fail" ]] && exit 9
    case "${DNS_TEST_ROUTE_STATE:-complete}" in
      missing_rule|missing_all)
        printf '101: from all fwmark 0x351 lookup 351\n'
        ;;
      missing_cn)
        printf '100: from all fwmark 0x301 lookup 301\n'
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
      351)
        [[ "${DNS_TEST_ROUTE_STATE:-complete}" == "missing_cn" ]] ||
          printf 'default dev ipsec-cn table 351\n'
        ;;
    esac
    ;;
esac
exit 0
EOF

cat >"$fakebin/swanctl" <<'EOF'
#!/usr/bin/env bash
printf 'swanctl %s\n' "$*" >>"$DNS_TEST_CALLS"
if [[ "${1:-}" == "--list-sas" ]]; then
  if [[ "${DNS_TEST_IPSEC_FAIL_CHILD:-}" != "ai" ]]; then
    printf 'ai: #1, ESTABLISHED\n'
    [[ -z "${DNS_TEST_AI_VIP:-}" ]] ||
      printf '  local 192.0.2.1[4500] [%s]\n' "$DNS_TEST_AI_VIP"
  fi
  if [[ "${DNS_TEST_IPSEC_FAIL_CHILD:-}" != "cn" ]]; then
    printf 'cn: #2, ESTABLISHED\n'
    [[ -z "${DNS_TEST_CN_VIP:-}" ]] ||
      printf '  local 192.0.2.2[4500] [%s]\n' "$DNS_TEST_CN_VIP"
  fi
fi
if [[ "${1:-}" == "--initiate" && "${3:-}" == "${DNS_TEST_IPSEC_FAIL_CHILD:-}" ]]; then
  exit 9
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
printf '%s\n' "$child" >>"$DNS_TEST_PROBE_PIDS"
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
printf 'dig %s\n' "$*" >>"$DNS_TEST_CALLS"
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
  DNS_TEST_RESTART_MONOTONIC="$restart_monotonic" \
  DNS_TEST_BLOCKING="$blocking" \
  DNS_TEST_PROBE_PIDS="$probe_pids" \
  DNS_TEST_SCENARIO="${DNS_TEST_SCENARIO:-healthy}" \
  DNS_TEST_ROUTE_STATE="${DNS_TEST_ROUTE_STATE:-complete}" \
  DNS_TEST_ROUTE_APPLY_FAIL="${DNS_TEST_ROUTE_APPLY_FAIL:-0}" \
  DNS_TEST_IPSEC_FAIL_CHILD="${DNS_TEST_IPSEC_FAIL_CHILD:-}" \
  DNS_TEST_AI_VIP="${DNS_TEST_AI_VIP:-}" \
  DNS_TEST_CN_VIP="${DNS_TEST_CN_VIP:-}" \
  DNS_TEST_INACTIVE_UNIT="${DNS_TEST_INACTIVE_UNIT:-}" \
  DNS_TEST_RESTART_FAIL_UNIT="${DNS_TEST_RESTART_FAIL_UNIT:-}" \
  DNS_TEST_MKTEMP_FAIL="${DNS_TEST_MKTEMP_FAIL:-}" \
  DNS_TEST_STATE_WRITE_FAIL="${DNS_TEST_STATE_WRITE_FAIL:-0}" \
  DNS_TEST_REAL_SLEEP="${DNS_TEST_REAL_SLEEP:-0}" \
  DNS_TEST_NOW="${DNS_TEST_NOW:-}" \
  DNSCOMPLEX_CONFIG="${DNS_TEST_CONFIG:-$config}" \
  "$manager" "$@"
}

reset_state() {
  : >"$calls"
  rm -f "$counter" "$second_round" "$restarted" "$restart_epoch" \
    "$restart_monotonic" "$blocking" "$probe_pids"
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

for failed_unit in nftables smartdns AdGuardHome sing-box xray-dnscomplex; do
  if DNS_TEST_INACTIVE_UNIT="$failed_unit" \
     DNS_TEST_RESTART_FAIL_UNIT="$failed_unit" \
     run_watchdog healthy >"$tmpdir/core-restart-${failed_unit}.log" 2>&1; then
    fail "$failed_unit restart failure was reported as healthy"
  fi
  assert_contains "$calls" "systemctl restart $failed_unit"
  assert_not_contains "$calls" 'dig '
  run_watchdog healthy >"$tmpdir/core-release-${failed_unit}.log" 2>&1
  assert_not_contains "$tmpdir/core-release-${failed_unit}.log" 'coalescing invocation'
  assert_contains "$calls" 'dig '
  assert_not_contains "$tmpdir/core-restart-${failed_unit}.log" 'coalescing invocation'
done

run_watchdog transient
assert_not_contains "$calls" 'restart smartdns'

if run_watchdog partial >"$tmpdir/partial.log" 2>&1; then
  fail "watchdog must report a persistent partial listener failure"
fi
assert_contains "$tmpdir/partial.log" 'partially unavailable'
assert_not_contains "$calls" 'restart smartdns'

if DNS_TEST_MKTEMP_FAIL=probe \
   run_watchdog deadlocked >"$tmpdir/probe-temp-failure.log" 2>&1; then
  fail "probe temp allocation failure was reported as healthy"
fi
assert_not_contains "$calls" 'restart smartdns'
assert_not_contains "$tmpdir/probe-temp-failure.log" '/default'
assert_not_contains "$tmpdir/probe-temp-failure.log" '/ai'
assert_not_contains "$tmpdir/probe-temp-failure.log" '/cn'

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

for corrupt in '' nonsense 08 12345678901; do
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

rm -f "$run_dir/smartdns.last_restart"
if DNS_TEST_STATE_WRITE_FAIL=1 run_watchdog_at 100000 cooldown; then
  fail "timestamp replacement failure was reported as healthy"
fi
assert_not_contains "$calls" 'restart smartdns'
if compgen -G "$run_dir/.smartdns.last_restart.*" >/dev/null; then
  fail "timestamp replacement failure left a temporary file"
fi

DNS_TEST_ROUTE_STATE=complete run_watchdog healthy
assert_not_contains "$calls" 'ip rule add fwmark'

if DNS_TEST_ROUTE_STATE=inspect_fail \
   run_watchdog healthy >"$tmpdir/route-inspection-failure.log" 2>&1; then
  fail "failed policy-route inspection was reported as healthy"
fi
assert_not_contains "$calls" 'ip rule add fwmark'
assert_not_contains "$calls" 'dig '

DNS_TEST_ROUTE_STATE=missing_route run_watchdog healthy
assert_contains "$calls" 'ip route replace default dev ipsec-ai table 301'
assert_not_contains "$calls" 'ip rule add fwmark 0x301 table 301'
assert_not_contains "$calls" 'ip route replace default dev ipsec-cn table 351'

DNS_TEST_ROUTE_STATE=missing_rule run_watchdog healthy
assert_contains "$calls" 'ip rule add fwmark 0x301 table 301'
assert_not_contains "$calls" 'ip route replace default dev ipsec-cn table 351'

DNS_TEST_ROUTE_STATE=missing_cn run_watchdog healthy
assert_contains "$calls" 'ip rule add fwmark 0x351 table 351'
assert_contains "$calls" 'ip route replace default dev ipsec-cn table 351'
assert_not_contains "$calls" 'ip route replace default dev ipsec-ai table 301'

if DNS_TEST_ROUTE_STATE=missing_rule DNS_TEST_ROUTE_APPLY_FAIL=rule \
   run_watchdog healthy >"$tmpdir/rule-repair-failure.log" 2>&1; then
  fail "failed policy-rule reconciliation was reported as healthy"
fi
assert_contains "$calls" 'ip rule add fwmark 0x301 table 301'
assert_not_contains "$calls" 'dig '

if DNS_TEST_ROUTE_STATE=missing_route DNS_TEST_ROUTE_APPLY_FAIL=route \
   run_watchdog healthy >"$tmpdir/route-repair-failure.log" 2>&1; then
  fail "failed policy-route reconciliation was reported as healthy"
fi
assert_contains "$calls" 'ip route replace default dev ipsec-ai table 301'
assert_not_contains "$calls" 'dig '

if DNS_TEST_IPSEC_FAIL_CHILD=ai \
   run_watchdog healthy >"$tmpdir/ipsec-repair-failure.log" 2>&1; then
  fail "failed IPsec child repair was reported as healthy"
fi
assert_contains "$calls" 'swanctl --initiate --child ai'
assert_not_contains "$calls" 'dig '

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
DNS_TEST_RESTART_MONOTONIC="$restart_monotonic" \
DNS_TEST_BLOCKING="$blocking" \
DNS_TEST_PROBE_PIDS="$probe_pids" \
DNS_TEST_SCENARIO=healthy \
DNS_TEST_ROUTE_STATE=complete \
"$manager" watchdog
assert_not_contains "$calls" 'restart smartdns'

ai_xray_config="$tmpdir/ai-xray.env"
cp "$config" "$ai_xray_config"
printf '%s\n' 'AI_EGRESS_MODE=xray' >>"$ai_xray_config"
DNS_TEST_CONFIG="$ai_xray_config" DNS_TEST_ROUTE_STATE=missing_all run_watchdog healthy
assert_not_contains "$calls" 'ip rule add fwmark'
DNS_TEST_CONFIG="$ai_xray_config" DNS_TEST_ROUTE_STATE=missing_cn \
  DNS_TEST_AI_VIP=10.64.0.1 run_watchdog healthy
assert_contains "$calls" 'ip rule add fwmark 0x351 table 351'
assert_contains "$calls" 'ip route replace default dev ipsec-cn table 351'
assert_not_contains "$calls" 'ip rule add fwmark 0x301 table 301'
assert_not_contains "$calls" 'ip route replace default dev ipsec-ai table 301'
assert_not_contains "$calls" 'dnscomplex-ai-snat'

cn_xray_config="$tmpdir/cn-xray.env"
cp "$config" "$cn_xray_config"
printf '%s\n' 'CN_EGRESS_MODE=xray' >>"$cn_xray_config"
DNS_TEST_CONFIG="$cn_xray_config" DNS_TEST_ROUTE_STATE=missing_cn run_watchdog healthy
assert_not_contains "$calls" 'ip rule add fwmark'
DNS_TEST_CONFIG="$cn_xray_config" DNS_TEST_ROUTE_STATE=missing_all \
  DNS_TEST_CN_VIP=10.64.0.2 run_watchdog healthy
assert_contains "$calls" 'ip rule add fwmark 0x301 table 301'
assert_contains "$calls" 'ip route replace default dev ipsec-ai table 301'
assert_not_contains "$calls" 'ip rule add fwmark 0x351 table 351'
assert_not_contains "$calls" 'ip route replace default dev ipsec-cn table 351'
assert_not_contains "$calls" 'dnscomplex-cn-snat'

reset_state
rm -f "$run_dir/smartdns.last_restart"
DNS_TEST_SCENARIO=post_restart_blocking \
DNS_TEST_REAL_SLEEP=1 \
run_manager watchdog >"$tmpdir/blocked.log" 2>&1 &
blocked_pid=$!
for _ in $(seq 1 100); do
  [[ -f "$blocking" ]] && break
  /bin/sleep 0.05
done
[[ -f "$blocking" ]] || fail "blocking post-restart probe did not start"
second_started=$(monotonic_millis)
DNS_TEST_SCENARIO=healthy run_manager watchdog >"$tmpdir/busy.log" 2>&1 ||
  fail "busy watchdog invocation must coalesce"
second_elapsed=$(( $(monotonic_millis) - second_started ))
((second_elapsed <= 1000)) || fail "busy watchdog did not return promptly: ${second_elapsed}ms"
assert_contains "$tmpdir/busy.log" 'coalescing invocation'
if wait "$blocked_pid"; then
  fail "watchdog must fail when listeners do not recover after restart"
fi
restart_started=$(cat "$restart_monotonic")
elapsed=$(( $(monotonic_millis) - restart_started ))
((elapsed <= 15000)) || fail "post-restart recovery exceeded wall-clock bound: ${elapsed}ms"
printf 'post_restart_elapsed_milliseconds=%s\n' "$elapsed"
assert_call_count 'systemctl restart smartdns' 1
assert_not_contains "$calls" 'start --no-block dnscomplex-nftset-refresh.service'
if [[ -r "$probe_pids" ]]; then
  while IFS= read -r child_pid; do
    if kill -0 "$child_pid" 2>/dev/null; then
      kill "$child_pid" 2>/dev/null || true
      fail "probe child $child_pid survived watchdog return"
    fi
  done <"$probe_pids"
fi
if compgen -G "$run_dir/.smartdns-probe.*" >/dev/null; then
  fail "probe temporary directory survived watchdog return"
fi
run_watchdog healthy >"$tmpdir/final-lock-release.log" 2>&1
assert_not_contains "$tmpdir/final-lock-release.log" 'coalescing invocation'
assert_contains "$calls" 'dig '

printf 'runtime reliability test: ok\n'
