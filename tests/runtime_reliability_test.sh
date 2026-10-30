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
  count=$(grep -F -- "$needle" "$calls" | grep -vc '^timeout ' || true)
  [[ "$count" == "$expected" ]] || fail "expected $expected '$needle' calls, got $count"
}

assert_call_before() {
  local first=$1 second=$2 first_line second_line
  first_line=$(grep -nF -- "$first" "$calls" | head -n1)
  second_line=$(grep -nF -- "$second" "$calls" | head -n1)
  [[ -n "$first_line" ]] || fail "missing '$first' in $calls"
  [[ -n "$second_line" ]] || fail "missing '$second' in $calls"
  first_line=${first_line%%:*}
  second_line=${second_line%%:*}
  ((first_line < second_line)) ||
    fail "expected '$first' before '$second'"
}

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

assert_health_check() {
  local file=$1 name=$2 expected_status=$3
  python3 - "$file" "$name" "$expected_status" <<'PY'
import json
import sys

path, name, expected = sys.argv[1:4]
with open(path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)
checks = {item["name"]: item for item in payload["checks"]}
actual = checks.get(name, {}).get("status")
if actual != expected:
    raise SystemExit(f"{name} status={actual!r}, expected={expected!r}")
PY
}

assert_health_detail_contains() {
  local file=$1 name=$2 needle=$3
  python3 - "$file" "$name" "$needle" <<'PY'
import json
import sys

path, name, needle = sys.argv[1:4]
with open(path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)
checks = {item["name"]: item for item in payload["checks"]}
detail = checks.get(name, {}).get("detail", "")
if needle not in detail:
    raise SystemExit(f"{name} detail={detail!r}, expected substring={needle!r}")
PY
}

monotonic_millis() {
  python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)'
}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmpdir=$(mktemp -d)
writer_pid=""
maintenance_pid=""
timer_holder_pid=""
timer_wait_pid=""
cleanup() {
  if [[ -n "$writer_pid" ]]; then
    kill "$writer_pid" 2>/dev/null || true
    wait "$writer_pid" 2>/dev/null || true
  fi
  if [[ -n "$maintenance_pid" ]]; then
    kill "$maintenance_pid" 2>/dev/null || true
    wait "$maintenance_pid" 2>/dev/null || true
  fi
  if [[ -n "$timer_wait_pid" ]]; then
    kill "$timer_wait_pid" 2>/dev/null || true
    wait "$timer_wait_pid" 2>/dev/null || true
  fi
  if [[ -n "$timer_holder_pid" ]]; then
    kill "$timer_holder_pid" 2>/dev/null || true
    wait "$timer_holder_pid" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT

render_root="$tmpdir/rendered"
config="$tmpdir/config.env"
state="$tmpdir/state"
run_dir="$tmpdir/run"
fake_root="$tmpdir/fakeroot"
fakebin="$tmpdir/fakebin"
fakepy="$tmpdir/fakepy"
calls="$tmpdir/calls.log"
counter="$tmpdir/dig.counter"
second_round="$tmpdir/second-round"
restarted="$tmpdir/restarted"
restart_epoch="$tmpdir/restart.epoch"
restart_monotonic="$tmpdir/restart.monotonic"
restart_fail_once_state="$tmpdir/restart-fail-once"
blocking="$tmpdir/blocking"
probe_pids="$tmpdir/probe-pids"
nft_race="$tmpdir/nft-race"
tar_blocking="$tmpdir/tar-blocking"
socket_calls="$tmpdir/socket-calls"
ipsec_started="$tmpdir/ipsec-started"
systemctl_state="$tmpdir/systemctl-state"
systemctl_fail_state="$tmpdir/systemctl-fail-state"
restore_move_counter="$tmpdir/restore-move-counter"
ipsec_ai_snat_vip="$tmpdir/ipsec-ai-snat-vip"
ipsec_cn_snat_vip="$tmpdir/ipsec-cn-snat-vip"
ipsec_ai_snat_set="$tmpdir/ipsec-ai-snat-set"
ipsec_cn_snat_set="$tmpdir/ipsec-cn-snat-set"
gate_closed_ai="$tmpdir/gate-closed-ai"
gate_closed_cn="$tmpdir/gate-closed-cn"
ipsec_singbox_config="$fake_root/etc/sing-box/config.json"
lan_alias_state="$fake_root/var/lib/dnscomplex/lan-alias.json"
mkdir -p "$state" "$run_dir" "$fake_root" "$fakebin" "$fakepy"
mkdir -p "$fake_root/usr/local/libexec"
mkdir -p "$fake_root/usr/local/lib/dnscomplex"
cat >"$fake_root/usr/local/lib/dnscomplex/profile-dataplane-probe.py" <<'EOF'
#!/usr/bin/env bash
profile=""
all_args=$*
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) profile=$2; shift 2 ;;
    *) shift ;;
  esac
done
upper=$(printf '%s' "$profile" | tr '[:lower:]' '[:upper:]')
status_var="DNS_TEST_PROFILE_PROBE_${upper}_STATUS"
status=${!status_var:-pass}
gate_var="DNS_TEST_GATE_CLOSED_${upper}"
gate_was_closed=0
[[ ! -f "${!gate_var}" ]] || gate_was_closed=1
printf 'profile-dataplane-probe profile=%s status=%s gate-closed=%s args=%s\n' \
  "$profile" "$status" "$gate_was_closed" "$all_args" >>"$DNS_TEST_CALLS"
printf '{"status":"%s","profile":"%s","phase":"dns","reason":"test"}\n' \
  "$status" "$profile"
[[ "$status" == pass ]]
EOF
chmod 0755 "$fake_root/usr/local/lib/dnscomplex/profile-dataplane-probe.py"
cat >"$fake_root/usr/local/libexec/dnscomplex-lan-alias" <<'EOF'
#!/usr/bin/env python3
import json
import os
import stat
import sys

if sys.argv[1] == "state-owned":
    state_path = sys.argv[sys.argv.index("--state") + 1]
    if not os.path.lexists(state_path):
        raise SystemExit(1)
    if os.path.islink(state_path) or not os.path.isfile(state_path):
        raise SystemExit(2)
    if stat.S_IMODE(os.stat(state_path).st_mode) != 0o600:
        raise SystemExit(2)
    try:
        state = json.loads(open(state_path, encoding="utf-8").read())
    except Exception:
        raise SystemExit(2)
    expected = {
        "schema": 1,
        "status": "owned",
        "address": "198.18.255.254",
        "interface": "lo",
        "label": "lo:dc-alias",
        "outbound_tag": "lan-legacy-alias",
        "pool": "198.18.255.0/24",
    }
    raise SystemExit(0 if all(state.get(key) == value for key, value in expected.items()) else 2)
if sys.argv[1] not in {"close", "reconcile", "verify-owner"}:
    raise SystemExit(64)
with open(os.environ["DNS_TEST_CALLS"], "a", encoding="utf-8") as fh:
    fh.write("lan-alias " + " ".join(sys.argv[1:]) +
             " watchdog-deadline=" + os.environ.get("DNSCOMPLEX_WATCHDOG_DEADLINE_MS", "") + "\n")
EOF
chmod 0755 "$fake_root/usr/local/libexec/dnscomplex-lan-alias"
write_owned_alias_state() {
  mkdir -p "$(dirname "$lan_alias_state")"
  cat >"$lan_alias_state" <<'JSON'
{"schema":1,"status":"owned","address":"198.18.255.254","interface":"lo","label":"lo:dc-alias","outbound_tag":"lan-legacy-alias","pool":"198.18.255.0/24"}
JSON
  chmod 0600 "$lan_alias_state"
}
mkdir -p \
  "$fake_root/proc/sys/net/ipv4/conf/all" \
  "$fake_root/proc/sys/net/ipv4/conf/default" \
  "$fake_root/proc/sys/net/ipv4/conf/eth0"
printf '0\n' >"$fake_root/proc/sys/net/ipv4/conf/all/send_redirects"
printf '0\n' >"$fake_root/proc/sys/net/ipv4/conf/default/send_redirects"
printf '0\n' >"$fake_root/proc/sys/net/ipv4/conf/eth0/send_redirects"

cat >"$config" <<'EOF'
DNSCOMPLEX_NONINTERACTIVE=1
DEPLOY_MODE=routeros-policy
WAN_IFACE=eth0
ROUTEROS_LAN_IPV4=192.168.50.253
LINUX_LAN_IPV4=192.168.50.200
LAN_CLIENT_IPV4_CIDR=192.168.50.0/24
SINGBOX_SOCKS_LISTEN=192.168.50.200
SINGBOX_SOCKS_PORT=10800
AI_IPSEC_USERNAME=fixture-ai
AI_IPSEC_PASSWORD=fixture-ai-pass
AI_IPSEC_SERVER=fixture-ai.example
CN_IPSEC_USERNAME=fixture-cn
CN_IPSEC_PASSWORD=fixture-cn-pass
CN_IPSEC_SERVER=fixture-cn.example
IPSEC_REMOTE_ID=fixture.example
AI_NFTSET_REFRESH_DOMAINS=openai.com
CN_NFTSET_REFRESH_DOMAINS=youku.com
EOF

DNSCOMPLEX_ROOT="$render_root" \
  bash "$repo_root/install.sh" --dry-run --config "$config" >/dev/null
manager="$render_root/usr/local/sbin/dnscomplex"
[[ -x "$manager" ]] || fail "manager was not rendered"
mkdir -p "$fake_root/usr/local/lib/dnscomplex-config"
cp "$render_root/usr/local/lib/dnscomplex-config/candidate.py" \
  "$fake_root/usr/local/lib/dnscomplex-config/candidate.py"

# The real embedded alias helper must stop within the watchdog deadline. A
# deliberately slow address query expires the shared budget after it has
# closed both readiness gates; cleanup gets one bounded close/readback window
# and must never launch sing-box without budget.
alias_deadline_helper="${DNS_TEST_ALIAS_DEADLINE_HELPER:-$render_root/usr/local/libexec/dnscomplex-lan-alias}"
[[ -f "$alias_deadline_helper" ]] || fail "LAN alias helper was not rendered"
alias_deadline_root="$tmpdir/alias-deadline"
mkdir -p "$alias_deadline_root/bin" "$alias_deadline_root/state"
alias_deadline_calls="$alias_deadline_root/calls"
cat >"$alias_deadline_root/bin/nft" <<'EOF'
#!/usr/bin/env bash
printf 'nft %s\n' "$*" >>"$DNS_TEST_ALIAS_DEADLINE_CALLS"
if [[ "${1:-} ${2:-}" == "-j list" ]]; then
  set_name=${6:-}
  elem='[{"prefix":{"addr":"0.0.0.0","len":0}}]'
  [[ ! -f "$DNS_TEST_ALIAS_DEADLINE_CALLS.$set_name.closed" ]] || elem='[]'
  printf '{"nftables":[{"set":{"family":"inet","table":"dnscomplex","name":"%s","type":"ipv4_addr","elem":%s}}]}\n' "$set_name" "$elem"
  exit 0
fi
if [[ "${1:-} ${2:-}" == "-c -f" ]]; then cat >/dev/null; exit 0; fi
if [[ "${1:-} ${2:-}" == "-f -" ]]; then
  batch=$(cat)
  printf '%s\n' "$batch" >>"$DNS_TEST_ALIAS_DEADLINE_CALLS"
  for set_name in lan_alias_ready4 lan_alias_config_ready4; do
    if grep -Fq "flush set inet dnscomplex $set_name" <<<"$batch"; then
      : >"$DNS_TEST_ALIAS_DEADLINE_CALLS.$set_name.closed"
    fi
    if grep -Fq "add element inet dnscomplex $set_name { 0.0.0.0/0 }" <<<"$batch"; then
      rm -f "$DNS_TEST_ALIAS_DEADLINE_CALLS.$set_name.closed"
    fi
  done
  exit 0
fi
exit 64
EOF
cat >"$alias_deadline_root/bin/ip" <<'EOF'
#!/usr/bin/env bash
printf 'ip %s\n' "$*" >>"$DNS_TEST_ALIAS_DEADLINE_CALLS"
if [[ "$*" == "-j address show" && "${DNS_TEST_ALIAS_SLOW_IP:-0}" == "1" ]]; then
  exec /bin/sleep 3
fi
case "$*" in
  "-j address show"|"-j route show table all") printf '[]\n' ;;
esac
exit 0
EOF
cat >"$alias_deadline_root/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"$DNS_TEST_ALIAS_DEADLINE_CALLS"
[[ " $* " != *" restart sing-box "* ]]
EOF
cat >"$alias_deadline_root/bin/sing-box" <<'EOF'
#!/usr/bin/env bash
printf 'sing-box %s\n' "$*" >>"$DNS_TEST_ALIAS_DEADLINE_CALLS"
exit 0
EOF
chmod 0755 "$alias_deadline_root/bin/"*
printf '{}\n' >"$alias_deadline_root/config.json"
if ! DNS_TEST_ALIAS_SLOW_IP=1 DNS_TEST_ALIAS_DEADLINE_CALLS="$alias_deadline_calls" \
   PATH="$alias_deadline_root/bin:$PATH" python3 - "$alias_deadline_helper" \
     "$alias_deadline_root/config.json" "$alias_deadline_root/state/alias.json" \
     "$alias_deadline_root/timeout-marker" \
     >"$alias_deadline_root/stdout" 2>"$alias_deadline_root/stderr" <<'PY'
import subprocess
import sys
import time
import os
from pathlib import Path

helper, config, state, timeout_marker = sys.argv[1:]
deadline_ms = time.monotonic_ns() // 1_000_000 + 1200
env = os.environ.copy()
env["DNSCOMPLEX_WATCHDOG_DEADLINE_MS"] = str(deadline_ms)
started = time.monotonic()
try:
    result = subprocess.run([
        sys.executable, helper, "reconcile", "--config", config, "--state", state,
        "--ai-mode", "xray", "--cn-mode", "xray",
    ], check=False, capture_output=True, text=True, timeout=3.5, env=env)
except subprocess.TimeoutExpired:
    Path(timeout_marker).write_text("outer timeout\n", encoding="utf-8")
    result = None
if result is not None:
    if result.returncode == 0:
        Path(timeout_marker).write_text("unexpected success\n", encoding="utf-8")
    elif time.monotonic() - started >= 2.8:
        Path(timeout_marker).write_text("deadline ignored\n", encoding="utf-8")
PY
then
  fail "slow LAN alias helper did not fail closed within its shared deadline"
fi
if [[ ! -f "$alias_deadline_calls" ]]; then
  cat "$alias_deadline_root/stderr" >&2
  fail "slow LAN alias helper did not reach the nft gate close"
fi
assert_contains "$alias_deadline_calls" 'flush set inet dnscomplex lan_alias_ready4'
assert_contains "$alias_deadline_calls" 'list set inet dnscomplex lan_alias_ready4'
assert_contains "$alias_deadline_calls" 'ip -j address show'
[[ -f "$alias_deadline_calls.lan_alias_ready4.closed" ]] ||
  fail "deadline failure left the raw alias gate open"
[[ -f "$alias_deadline_calls.lan_alias_config_ready4.closed" ]] ||
  fail "deadline failure with invalid config proof left config readiness open"
assert_not_contains "$alias_deadline_calls" 'systemctl restart sing-box'
assert_not_contains "$alias_deadline_calls" 'sing-box check'
[[ ! -e "$alias_deadline_root/timeout-marker" ]] ||
  fail "slow LAN alias helper ignored the shared watchdog deadline"
alias_clear_count=$(grep -Fc 'flush set inet dnscomplex lan_alias_ready4' "$alias_deadline_calls" || true)
((alias_clear_count >= 2)) || fail "deadline failure did not get bounded raw-gate cleanup"
alias_helper="$fake_root/usr/local/libexec/dnscomplex-lan-alias"
mv "$alias_helper" "${alias_helper}.saved"
if ! PATH="$fakebin:$PATH" DNSCOMPLEX_CONFIG="$config" \
     DNSCOMPLEX_FS_ROOT="$fake_root" \
     bash -c 'source "$1"; load_config; lan_alias_close_cmd' _ "$manager"; then
  fail "legacy runtime without alias ownership state must skip absent helper safely"
fi
mv "${alias_helper}.saved" "$alias_helper"
mkdir -p "$(dirname "$ipsec_singbox_config")"
cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"

cat >"$fakepy/socket.py" <<'PY'
import os

AF_INET = 2
AF_INET6 = 10
SOCK_STREAM = 1


def _record(kind, family, address):
    path = os.environ.get("DNS_TEST_SOCKET_CALLS", "")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{kind} family={family} address={address!r}\n")


class _Connection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def close(self):
        return None


def create_connection(address, timeout=None):
    _record("create_connection", 0, address)
    if os.environ.get("DNS_TEST_SOCKS_CONNECTIVITY", "1") != "1":
        raise OSError("simulated SOCKS listener failure")
    return _Connection()


class socket:
    def __init__(self, family, sock_type):
        self.family = family
        self.sock_type = sock_type
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        _record("connect", self.family, address)
        key = "DNS_TEST_IPV6_CONNECTIVITY" if self.family == AF_INET6 else "DNS_TEST_IPV4_CONNECTIVITY"
        if os.environ.get(key, "1") != "1":
            raise OSError(f"simulated connectivity failure for family {self.family}")

    def close(self):
        return None
PY

for reserved_ip in \
  0.1.2.3 10.0.0.1 100.64.0.1 100.127.255.254 127.0.0.1 \
  169.254.1.1 172.16.0.1 172.31.255.254 192.0.0.1 192.0.2.1 \
  192.88.99.1 192.168.1.1 198.18.0.1 198.19.255.254 \
  198.51.100.1 203.0.113.1 224.0.0.1 240.0.0.1 255.255.255.255; do
  if bash -c 'source "$1"; public_ipv4 "$2"' _ "$manager" "$reserved_ip"; then
    fail "reserved IPv4 was accepted for nftset refresh: $reserved_ip"
  fi
done
for public_ip in \
  1.1.1.1 100.63.255.254 100.128.0.1 172.15.255.254 \
  172.32.0.1 198.17.255.254 198.20.0.1 203.0.114.1 223.255.255.254; do
  if ! bash -c 'source "$1"; public_ipv4 "$2"' _ "$manager" "$public_ip"; then
    fail "public IPv4 was rejected for nftset refresh: $public_ip"
  fi
done

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

cat >"$fakebin/sync" <<'EOF'
#!/usr/bin/env bash
printf 'sync %s\n' "$*" >>"$DNS_TEST_CALLS"
exit 0
EOF

cat >"$fakebin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"$DNS_TEST_CALLS"
unit=${!#:-}
set_unit_active() {
  local target=$1 tmp
  [[ -f "$DNS_TEST_SYSTEMCTL_STATE" ]] || return 0
  tmp="${DNS_TEST_SYSTEMCTL_STATE}.tmp"
  grep -Fxv -- "$target" "$DNS_TEST_SYSTEMCTL_STATE" >"$tmp" || true
  /bin/mv -f "$tmp" "$DNS_TEST_SYSTEMCTL_STATE"
}
case "${1:-}" in
  daemon-reload)
    if [[ "${DNS_TEST_SYSTEMCTL_FAIL_ONCE:-}" == "daemon-reload" &&
          ! -e "$DNS_TEST_SYSTEMCTL_FAIL_STATE" ]]; then
      : >"$DNS_TEST_SYSTEMCTL_FAIL_STATE"
      exit 9
    fi
    exit 0
    ;;
  show)
    printf 'loaded\n'
    exit 0
    ;;
  is-enabled)
    if [[ "$unit" == "${DNS_TEST_DISABLED_UNIT:-}" ]]; then
      [[ " $* " == *" --quiet "* ]] || printf 'disabled\n'
      exit 1
    fi
    [[ " $* " == *" --quiet "* ]] || printf 'enabled\n'
    exit 0
    ;;
  is-active)
    if [[ "$unit" == "${DNS_TEST_INACTIVE_UNIT:-}" ]] ||
       grep -Fxq -- "$unit" "$DNS_TEST_SYSTEMCTL_STATE" 2>/dev/null; then
      [[ " $* " == *" --quiet "* ]] || printf 'inactive\n'
      exit 3
    fi
    if [[ "$unit" == "${DNS_TEST_ACTIVATING_UNIT:-}" ]]; then
      [[ " $* " == *" --quiet "* ]] || printf 'activating\n'
      exit 3
    fi
    [[ " $* " == *" --quiet "* ]] || printf 'active\n'
    exit 0
    ;;
  restart)
    if [[ "${2:-}" == "${DNS_TEST_RESTART_FAIL_ONCE_UNIT:-}" &&
          ! -e "$DNS_TEST_RESTART_FAIL_ONCE_STATE" ]]; then
      : >"$DNS_TEST_RESTART_FAIL_ONCE_STATE"
      exit 9
    fi
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
    set_unit_active "${2:-}"
    exit 0
    ;;
  start)
    set_unit_active "$unit"
    exit 0
    ;;
  stop)
    if [[ "$unit" == "${DNS_TEST_STOP_FAIL_UNIT:-}" ]]; then
      exit 9
    fi
    case "$unit" in
      smartdns.service|AdGuardHome.service|sing-box.service|dnscomplex-web.service)
        if ! grep -Fxq -- "dnscomplex-network-ready.service" \
             "$DNS_TEST_SYSTEMCTL_STATE" 2>/dev/null; then
          # Simulate Upholds= immediately pulling the service back up.
          exit 0
        fi
        ;;
    esac
    grep -Fxq -- "$unit" "$DNS_TEST_SYSTEMCTL_STATE" 2>/dev/null ||
      printf '%s\n' "$unit" >>"$DNS_TEST_SYSTEMCTL_STATE"
    exit 0
    ;;
esac
exit 0
EOF

cat >"$fakebin/nft" <<'EOF'
#!/usr/bin/env bash
printf 'nft %s\n' "$*" >>"$DNS_TEST_CALLS"
ai_snat_state=${DNS_TEST_IPSEC_AI_SNAT_VIP:-${DNS_TEST_CALLS}.ipsec-ai-snat}
cn_snat_state=${DNS_TEST_IPSEC_CN_SNAT_VIP:-${DNS_TEST_CALLS}.ipsec-cn-snat}
ai_alias_snat_state=${DNS_TEST_CALLS}.ipsec-ai-alias-snat
cn_alias_snat_state=${DNS_TEST_CALLS}.ipsec-cn-alias-snat
ai_alias_extra_cleared=${DNS_TEST_CALLS}.ai-alias-extra-cleared
ai_set_state=${DNS_TEST_IPSEC_AI_SNAT_SET:-${DNS_TEST_CALLS}.ipsec-ai-snat-set}
cn_set_state=${DNS_TEST_IPSEC_CN_SNAT_SET:-${DNS_TEST_CALLS}.ipsec-cn-snat-set}
closed_ai=${DNS_TEST_GATE_CLOSED_AI:-${DNS_TEST_CALLS}.gate-closed-ai}
closed_cn=${DNS_TEST_GATE_CLOSED_CN:-${DNS_TEST_CALLS}.gate-closed-cn}
ai_probe_vip_state=${DNS_TEST_CALLS}.probe-ai-vip
cn_probe_vip_state=${DNS_TEST_CALLS}.probe-cn-vip
ai_extra_cleared=${DNS_TEST_CALLS}.ai-extra-cleared
if [[ "${DNS_TEST_NFT_ADD_FAIL:-0}" == "1" &&
      "${1:-} ${2:-}" == "add rule" ]]; then
  exit 9
fi
if [[ "${1:-}" == "-a" && "${2:-}" == "list" &&
      "${3:-}" == "chain" ]]; then
  shift
fi
case "${1:-} ${2:-}" in
  "-j list")
    if [[ "${3:-} ${4:-} ${5:-}" == "table inet dnscomplex" ]]; then
      entries=""
      for profile in ai cn; do
        case "$profile" in ai) closed=$closed_ai ;; cn) closed=$closed_cn ;; esac
        for family in 4 6; do
          name="${profile}_ready${family}"
          # Match the list-set model: a fixture with no pre-existing/open
          # readiness sets must not invent open gates in list-table readback.
          if [[ -f "$closed" || ( "${DNS_TEST_NFT_EXISTING:-0}" != 1 &&
                                  "${DNS_TEST_HEALTH_GATE_OPEN:-0}" != 1 &&
                                  ! -f "${DNS_TEST_CALLS}.gate-open-$profile" ) ]]; then
            elem='[]'
          elif [[ "$family" == 4 ]]; then
            elem='[{"prefix":{"addr":"0.0.0.0","len":0}}]'
          else
            elem='[{"prefix":{"addr":"::","len":0}}]'
          fi
          [[ -z "$entries" ]] || entries+=,
          entries+="{\"set\":{\"family\":\"inet\",\"table\":\"dnscomplex\",\"name\":\"$name\",\"elem\":$elem}}"
        done
      done
      printf '{"nftables":[%s]}\n' "$entries"
      exit 0
    fi
    [[ "${3:-}" == "set" && "${4:-}" == "inet" && "${5:-}" == "dnscomplex" ]] || exit 2
    case "${6:-}" in
      ai_probe_vip4)
        gate_type=ipv4_addr; gate_addr=0.0.0.0; gate_elem='[]'
        if [[ -f "$ai_probe_vip_state" ]]; then
          [[ ! -s "$ai_probe_vip_state" ]] || gate_elem="[\"$(cat "$ai_probe_vip_state")\"]"
        elif [[ "${DNS_TEST_ROUTE_STATE:-complete}" == complete && -n "${DNS_TEST_AI_VIP:-}" ]]; then
          gate_elem="[\"${DNS_TEST_AI_VIP}\"]"
        fi
        printf '{"nftables":[{"set":{"family":"inet","table":"dnscomplex","name":"%s","type":"%s","elem":%s}}]}\n' "$6" "$gate_type" "$gate_elem"
        exit 0
        ;;
      cn_probe_vip4)
        gate_type=ipv4_addr; gate_addr=0.0.0.0; gate_elem='[]'
        if [[ -f "$cn_probe_vip_state" ]]; then
          [[ ! -s "$cn_probe_vip_state" ]] || gate_elem="[\"$(cat "$cn_probe_vip_state")\"]"
        elif [[ "${DNS_TEST_ROUTE_STATE:-complete}" == complete && -n "${DNS_TEST_CN_VIP:-}" ]]; then
          gate_elem="[\"${DNS_TEST_CN_VIP}\"]"
        fi
        printf '{"nftables":[{"set":{"family":"inet","table":"dnscomplex","name":"%s","type":"%s","elem":%s}}]}\n' "$6" "$gate_type" "$gate_elem"
        exit 0
        ;;
    esac
    if [[ "${6:-}" == ai_ready4 || "${6:-}" == cn_ready4 ]]; then
      gate_profile=${6%%_*}
      [[ "${DNS_TEST_NFT_EXISTING:-0}" == "1" || "${DNS_TEST_HEALTH_GATE_OPEN:-0}" == "1" ||
         -f "${DNS_TEST_CALLS}.gate-open-$gate_profile" ]] || exit 1
    else
      [[ "${DNS_TEST_NFT_EXISTING:-0}" == "1" ]] || exit 1
    fi
    case "${6:-}" in
      ai_ready4)
        gate_type=ipv4_addr; gate_addr=0.0.0.0; gate_elem=""
        [[ ! -f "$closed_ai" ]] || gate_elem='[]'
        ;;
      cn_ready4)
        gate_type=ipv4_addr; gate_addr=0.0.0.0; gate_elem=""
        [[ ! -f "$closed_cn" ]] || gate_elem='[]'
        ;;
      ai_ready6|cn_ready6) gate_type=ipv6_addr; gate_addr=:: ;;
      *) exit 2 ;;
    esac
    gate_elem=${gate_elem:-"[{\"prefix\":{\"addr\":\"$gate_addr\",\"len\":0}}]"}
    printf '{"nftables":[{"set":{"family":"inet","table":"dnscomplex","name":"%s","type":"%s","elem":%s}}]}\n' "$6" "$gate_type" "$gate_elem"
    exit 0
    ;;
  "list table") exit 0 ;;
  "list chain")
    cat <<'NFT'
table inet dnscomplex {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "eth0" ip saddr 192.168.50.0/24 ip daddr != { 0.0.0.0/8 } counter snat ip to 192.168.50.200 comment "dnscomplex-routeros-default-snat"
  }
}
NFT
    if [[ -s "$ai_snat_state" ]]; then
      ai_set=$(cat "$ai_set_state" 2>/dev/null || printf ai4)
      ai_extra=""
      if [[ -n "${DNS_TEST_AI_SNAT_EXTRA:-}" && ! -f "$ai_extra_cleared" ]]; then
        ai_extra="${DNS_TEST_AI_SNAT_EXTRA} "
      fi
      printf '    oifname "ipsec-ai" ip daddr @%s %ssnat ip to %s comment "dnscomplex-ai-snat" # handle 51\n' \
        "$ai_set" "$ai_extra" "$(cat "$ai_snat_state")"
    fi
    if [[ -s "$cn_snat_state" ]]; then
      cn_set=$(cat "$cn_set_state" 2>/dev/null || printf cn4)
      printf '    oifname "ipsec-cn" ip daddr @%s snat ip to %s comment "dnscomplex-cn-snat" # handle 52\n' \
        "$cn_set" "$(cat "$cn_snat_state")"
    fi
    if [[ -s "$ai_alias_snat_state" ]]; then
      printf '    oifname "ipsec-ai" ip saddr @lan_alias_source4 snat ip to %s comment "dnscomplex-lan-alias-snat-ai" # handle 53\n' \
        "$(cat "$ai_alias_snat_state")"
    fi
    if [[ -n "${DNS_TEST_AI_ALIAS_SNAT_EXTRA:-}" && ! -f "$ai_alias_extra_cleared" ]]; then
      printf '    oifname "ipsec-ai" ip saddr @lan_alias_source4 snat ip to %s comment "dnscomplex-lan-alias-snat-ai" # handle 55\n' \
        "$DNS_TEST_AI_ALIAS_SNAT_EXTRA"
    fi
    if [[ -s "$cn_alias_snat_state" ]]; then
      printf '    oifname "ipsec-cn" ip saddr @lan_alias_source4 snat ip to %s comment "dnscomplex-lan-alias-snat-cn" # handle 54\n' \
        "$(cat "$cn_alias_snat_state")"
    fi
    exit 0
    ;;
  "delete rule")
    case "${7:-}" in
      51)
        : >"$ai_snat_state"
        : >"$ai_set_state"
        [[ -z "${DNS_TEST_AI_SNAT_EXTRA:-}" ]] || : >"$ai_extra_cleared"
        ;;
      52) : >"$cn_snat_state"; : >"$cn_set_state" ;;
      53) : >"$ai_alias_snat_state" ;;
      54) : >"$cn_alias_snat_state" ;;
      55) : >"$ai_alias_extra_cleared" ;;
    esac
    exit 0
    ;;
  "add rule")
    snat_vip=""
    snat_set=""
    previous=""
    for token in "$@"; do
      if [[ "$previous" == "to" ]]; then snat_vip=$token; fi
      if [[ "$previous" == "daddr" ]]; then snat_set=${token#@}; fi
      previous=$token
    done
    if [[ " $* " == *' comment dnscomplex-lan-alias-snat-ai '* ]]; then
      printf '%s\n' "$snat_vip" >"$ai_alias_snat_state"
    elif [[ " $* " == *' comment dnscomplex-lan-alias-snat-cn '* ]]; then
      printf '%s\n' "$snat_vip" >"$cn_alias_snat_state"
    elif [[ " $* " == *' comment dnscomplex-ai-snat '* ]]; then
      printf '%s\n' "$snat_vip" >"$ai_snat_state"
      printf '%s\n' "$snat_set" >"$ai_set_state"
    elif [[ " $* " == *' comment dnscomplex-cn-snat '* ]]; then
      printf '%s\n' "$snat_vip" >"$cn_snat_state"
      printf '%s\n' "$snat_set" >"$cn_set_state"
    fi
    exit 0
    ;;
  "get element")
    [[ "${DNS_TEST_NFT_EXISTING:-0}" == "1" ]] && exit 0
    if [[ -f "$DNS_TEST_NFT_RACE_STATE" ]]; then
      case "${DNS_TEST_NFT_RACE_PROFILE:-}" in
        ai) [[ "${5:-}" == "ai4" ]] && exit 0 ;;
        cn) [[ "${5:-}" == "cn4" ]] && exit 0 ;;
      esac
    fi
    exit 1
    ;;
  "-f "*)
    batch_source="$2"
    if [[ "$batch_source" == "-" ]]; then
      batch_source="${DNS_TEST_CALLS}.nft-stdin"
      cat >"$batch_source"
    fi
    sed 's/^/nft-batch /' "$batch_source" >>"$DNS_TEST_CALLS"
    if [[ "${DNS_TEST_NFT_CLEAR_FAIL_PROFILE:-}" == "ai" ]] &&
       grep -Fq 'flush set inet dnscomplex ai_ready4' "$batch_source"; then
      exit 9
    fi
    if [[ "${DNS_TEST_NFT_CLEAR_FAIL_PROFILE:-}" == "cn" ]] &&
       grep -Fq 'flush set inet dnscomplex cn_ready4' "$batch_source"; then
      exit 9
    fi
    for profile in ai cn; do
      case "$profile" in
        ai) probe_set_state=$ai_probe_vip_state ;;
        cn) probe_set_state=$cn_probe_vip_state ;;
      esac
      if grep -Fq "flush set inet dnscomplex ${profile}_probe_vip4" "$batch_source"; then
        : >"$probe_set_state"
      fi
      probe_addr=$(sed -n "s/.*add element inet dnscomplex ${profile}_probe_vip4 { \([^}]*\) }.*/\1/p" "$batch_source" | head -n1)
      [[ -z "$probe_addr" ]] || printf '%s\n' "$probe_addr" >"$probe_set_state"
      gate_set="${profile}_ready4"
      if grep -Fq "flush set inet dnscomplex $gate_set" "$batch_source"; then
        if [[ "$profile" == ai ]]; then : >"$closed_ai"; else : >"$closed_cn"; fi
        rm -f "${DNS_TEST_CALLS}.gate-open-$profile"
      fi
      if grep -Fq "add element inet dnscomplex $gate_set" "$batch_source"; then
        if [[ "$profile" == ai ]]; then rm -f "$closed_ai"; else rm -f "$closed_cn"; fi
        : >"${DNS_TEST_CALLS}.gate-open-$profile"
      fi
    done
    if [[ "${DNS_TEST_NFT_RACE_PROFILE:-}" == "ai" ]] &&
       grep -Fq ' dnscomplex ai4 ' "$batch_source"; then
      : >"$DNS_TEST_NFT_RACE_STATE"
      exit 9
    fi
    if [[ "${DNS_TEST_NFT_RACE_PROFILE:-}" == "cn" ]] &&
       grep -Fq ' dnscomplex cn4 ' "$batch_source"; then
      : >"$DNS_TEST_NFT_RACE_STATE"
      exit 9
    fi
    if [[ "${DNS_TEST_NFT_BATCH_FAIL_PROFILE:-}" == "ai" ]] &&
       grep -Fq ' dnscomplex ai4 ' "$batch_source"; then
      exit 9
    fi
    if [[ "${DNS_TEST_NFT_BATCH_FAIL_PROFILE:-}" == "cn" ]] &&
       grep -Fq ' dnscomplex cn4 ' "$batch_source"; then
      exit 9
    fi
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
import time

with open(os.environ["DNS_TEST_CALLS"], "a", encoding="utf-8") as calls:
    calls.write("flock " + " ".join(sys.argv[1:]) + "\n")
fd = int(sys.argv[-1])
args = sys.argv[1:-1]
if "-u" in args:
    fcntl.flock(fd, fcntl.LOCK_UN)
    raise SystemExit(0)
wait_seconds = None
if "-w" in args:
    index = args.index("-w")
    wait_seconds = float(args[index + 1])
deadline = None if wait_seconds is None else time.monotonic() + wait_seconds
while True:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raise SystemExit(0)
    except BlockingIOError:
        if deadline is None or time.monotonic() >= deadline:
            raise SystemExit(1)
        time.sleep(0.01)
EOF

cat >"$fakebin/mktemp" <<'EOF'
#!/usr/bin/env bash
if [[ "${DNS_TEST_MKTEMP_FAIL:-}" == "probe" && " $* " == *".smartdns-probe."* ]]; then
  exit 9
fi
if [[ "${DNS_TEST_MKTEMP_FAIL:-}" == "nftset-ai" && " $* " == *".nftset-ai."* ]]; then
  exit 9
fi
if [[ "${DNS_TEST_MKTEMP_FAIL:-}" == "nftset-cn" && " $* " == *".nftset-cn."* ]]; then
  exit 9
fi
exec /usr/bin/mktemp "$@"
EOF

cat >"$fakebin/cp" <<'EOF'
#!/usr/bin/env bash
printf 'cp %s\n' "$*" >>"$DNS_TEST_CALLS"
destination=${*: -1}
if [[ "${DNS_TEST_RESTORE_STAGE_FAIL:-0}" == "1" &&
      "$destination" == */.dnscomplex-restore.*/candidate ]]; then
  exit 9
fi
exec /bin/cp "$@"
EOF

cat >"$fakebin/sing-box" <<'EOF'
#!/usr/bin/env bash
printf 'sing-box %s\n' "$*" >>"$DNS_TEST_CALLS"
if [[ "${1:-}" == "check" && "${DNS_TEST_SINGBOX_CHECK_FAIL:-0}" == "1" ]]; then
  exit 9
fi
exit 0
EOF

cat >"$fakebin/install" <<'EOF'
#!/usr/bin/env bash
printf 'install %s\n' "$*" >>"$DNS_TEST_CALLS"
if [[ "${DNS_TEST_INSTALL_FAIL:-0}" == "1" ]]; then exit 9; fi
exec /usr/bin/install "$@"
EOF

cat >"$fakebin/mv" <<'EOF'
#!/usr/bin/env bash
printf 'mv %s\n' "$*" >>"$DNS_TEST_CALLS"
if [[ "${DNS_TEST_STATE_WRITE_FAIL:-0}" == "1" &&
      "${*: -1}" == */smartdns.last_restart ]]; then
  exit 9
fi
if [[ " $* " == *".dnscomplex-restore."* &&
      "${DNS_TEST_RESTORE_FAIL_MOVE:-0}" =~ ^[1-9][0-9]*$ ]]; then
  count=0
  [[ ! -f "$DNS_TEST_RESTORE_MOVE_COUNTER" ]] ||
    count=$(cat "$DNS_TEST_RESTORE_MOVE_COUNTER")
  count=$((count + 1))
  printf '%s\n' "$count" >"$DNS_TEST_RESTORE_MOVE_COUNTER"
  if [[ "$count" == "$DNS_TEST_RESTORE_FAIL_MOVE" ]]; then
    exit 9
  fi
fi
exec /bin/mv "$@"
EOF

cat >"$fakebin/smartdns" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-v" ]]; then
  printf '%s\n' "${DNS_TEST_SMARTDNS_VERSION:-smartdns 1.2026.06.28-1614 (Release48.2)}"
  exit 0
fi
exit 64
EOF

cat >"$fakebin/ip" <<'EOF'
#!/usr/bin/env bash
printf 'ip %s\n' "$*" >>"$DNS_TEST_CALLS"
underlay_iface=${DNS_TEST_UNDERLAY_IFACE:-eth0}
underlay_ipv4=${DNS_TEST_UNDERLAY_IPV4:-192.168.50.200}
underlay_gateway=${DNS_TEST_UNDERLAY_GATEWAY:-192.168.50.253}
if [[ "$*" == "-4 -o addr show dev $underlay_iface scope global" ]]; then
  case "${DNS_TEST_WAN_ADDRESS:-expected}" in
    expected)
      printf '2: %s    inet %s/24 brd 192.168.50.255 scope global %s\n' \
        "$underlay_iface" "$underlay_ipv4" "$underlay_iface"
      ;;
    wrong)
      printf '2: eth0    inet 192.168.50.201/24 brd 192.168.50.255 scope global eth0\n'
      ;;
    missing) ;;
  esac
  exit 0
fi
if [[ "$*" == "-4 route show default" ||
      "$*" == "-4 route show default dev $underlay_iface" ]]; then
  if [[ "${DNS_TEST_WAN_ROUTE:-expected}" != "missing" ]]; then
    if [[ "${DNS_TEST_WAN_ROUTE:-expected}" == "filtered_dev_elided" &&
          "$*" == *" dev $underlay_iface" ]]; then
      printf 'default via %s proto dhcp src %s\n' \
        "$underlay_gateway" "$underlay_ipv4"
      exit 0
    fi
    printf 'default via %s dev %s proto dhcp src %s\n' \
      "$underlay_gateway" "$underlay_iface" "$underlay_ipv4"
  fi
  exit 0
fi
if [[ "$*" == "link show ipsec-ai" ||
      "$*" == "link show dev ipsec-ai" ||
      "$*" == "-o link show dev ipsec-ai" ]]; then
  case "${DNS_TEST_AI_INTERFACE_STATE:-up}" in
    missing) exit 1 ;;
    hang)
      /bin/sleep 10
      exit 9
      ;;
    down)
      printf '5: ipsec-ai@%s: <NOARP> mtu 1400 state DOWN mode DEFAULT\n' "$underlay_iface"
      ;;
    *)
      printf '5: ipsec-ai@%s: <NOARP,UP,LOWER_UP> mtu 1400 state UNKNOWN mode DEFAULT\n' "$underlay_iface"
      ;;
  esac
  exit 0
fi
if [[ "$*" == "link show ipsec-cn" ||
      "$*" == "link show dev ipsec-cn" ||
      "$*" == "-o link show dev ipsec-cn" ]]; then
  case "${DNS_TEST_CN_INTERFACE_STATE:-up}" in
    missing) exit 1 ;;
    down)
      printf '6: ipsec-cn@%s: <NOARP> mtu 1400 state DOWN mode DEFAULT\n' "$underlay_iface"
      ;;
    *)
      printf '6: ipsec-cn@%s: <NOARP,UP,LOWER_UP> mtu 1400 state UNKNOWN mode DEFAULT\n' "$underlay_iface"
      ;;
  esac
  exit 0
fi
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
    ai_rule_token=0x301
    cn_rule_token=0x351
    case "${DNS_TEST_AI_RULE_MASK_STATE:-none}" in
      full) ai_rule_token=0x301/0xffffffff ;;
      zero) ai_rule_token=0x301/0x0 ;;
    esac
    case "${DNS_TEST_CN_RULE_MASK_STATE:-none}" in
      full) cn_rule_token=0x351/0xffffffff ;;
      zero) cn_rule_token=0x351/0x0 ;;
    esac
    ai_rule_from="from all"
    ai_rule_suffix=""
    case "${DNS_TEST_AI_RULE_SHAPE_STATE:-simple}" in
      restricted) ai_rule_from="from 10.0.0.0/8" ;;
      suppressed) ai_rule_suffix=" suppress_prefixlength 0" ;;
    esac
    case "${DNS_TEST_ROUTE_STATE:-complete}" in
      missing_rule|missing_all)
        printf '10351: from all fwmark %s lookup 351\n' "$cn_rule_token"
        ;;
      missing_cn)
        [[ -n "$(grep -F 'ip rule del priority 10301' "$DNS_TEST_CALLS" || true)" ]] ||
          printf '10301: %s fwmark %s lookup 301%s\n' \
            "$ai_rule_from" "$ai_rule_token" "$ai_rule_suffix"
        ;;
      *)
        [[ -n "$(grep -F 'ip rule del priority 10301' "$DNS_TEST_CALLS" || true)" ]] ||
          printf '10301: %s fwmark %s lookup 301%s\n' \
            "$ai_rule_from" "$ai_rule_token" "$ai_rule_suffix"
        [[ -n "$(grep -F 'ip rule del priority 10351' "$DNS_TEST_CALLS" || true)" ]] ||
          printf '10351: from all fwmark %s lookup 351\n' "$cn_rule_token"
        ;;
    esac
    case "${DNS_TEST_AI_RULE_CONFLICT:-none}" in
      zero-mask)
        printf '100: from all fwmark 0x301/0x0 lookup 301\n'
        ;;
      negated-other)
        printf '100: not from all fwmark 0x999 lookup 301\n'
        ;;
      negated-target)
        printf '100: not from all fwmark 0x301/0xffffffaf lookup 301\n'
        ;;
      negated-restricted)
        printf '100: not from 10.0.0.0/8 fwmark 0x301/0xffffffaf lookup 301\n'
        ;;
    esac
    if [[ "${DNS_TEST_CN_RULE_CONFLICT:-none}" == "zero-mask" ]]; then
      printf '101: from all fwmark 0x351/0x0 lookup 351\n'
    fi
    if ! grep -Fq 'ip rule del priority 10301' "$DNS_TEST_CALLS"; then
      case "${DNS_TEST_AI_RULE_SAME_PRIORITY_CONFLICT:-none}" in
        stale)
          printf '10301: from all fwmark 0x301/0x0 lookup 999\n'
          ;;
        duplicate)
          printf '10301: from all fwmark 0x301 lookup 301\n'
          ;;
      esac
    fi
    if grep -Fq 'ip rule add fwmark 0x301 table 301' "$DNS_TEST_CALLS"; then
      printf '10301: from all fwmark 0x301 lookup 301\n'
    fi
    if grep -Fq 'ip rule add fwmark 0x351 table 351' "$DNS_TEST_CALLS"; then
      printf '10351: from all fwmark 0x351 lookup 351\n'
    fi
    if [[ "${DNS_TEST_ROUTE_STATE:-complete}" != missing_all ]] &&
       ! grep -Fq 'ip rule add fwmark 0x3A1 table 301' "$DNS_TEST_CALLS" &&
       ! grep -Fq 'ip rule del fwmark 0x3A1 table 301 priority 10201' "$DNS_TEST_CALLS"; then
      printf '10201: from all fwmark 0x3a1 lookup 301\n'
    fi
    if [[ "${DNS_TEST_ROUTE_STATE:-complete}" != missing_all ]] &&
       ! grep -Fq 'ip rule add fwmark 0x3F1 table 351' "$DNS_TEST_CALLS" &&
       ! grep -Fq 'ip rule del fwmark 0x3F1 table 351 priority 10251' "$DNS_TEST_CALLS"; then
      printf '10251: from all fwmark 0x3f1 lookup 351\n'
    fi
    if grep -Fq 'ip rule add fwmark 0x3A1 table 301' "$DNS_TEST_CALLS" &&
       ! grep -Fq 'ip rule del fwmark 0x3A1 table 301 priority 10201' "$DNS_TEST_CALLS"; then
      printf '10201: from all fwmark 0x3a1 lookup 301\n'
    fi
    if grep -Fq 'ip rule add fwmark 0x3F1 table 351' "$DNS_TEST_CALLS" &&
       ! grep -Fq 'ip rule del fwmark 0x3F1 table 351 priority 10251' "$DNS_TEST_CALLS"; then
      printf '10251: from all fwmark 0x3f1 lookup 351\n'
    fi
    if [[ "${DNS_TEST_PROBE_RULE_CONFLICT:-}" == ai ]]; then
      printf '10201: from all fwmark 0x3a1/0x0 lookup 999\n'
    elif [[ "${DNS_TEST_PROBE_RULE_CONFLICT:-}" == cn ]]; then
      printf '10251: from all fwmark 0x3f1/0x0 lookup 999\n'
    fi
    ;;
  "route show")
    case "${4:-}" in
      301)
        if [[ "${DNS_TEST_ROUTE_APPLY_STICKY_PROFILE:-}" != "ai" ]] &&
           grep -Fq 'ip route replace default dev ipsec-ai src ' "$DNS_TEST_CALLS"; then
          printf 'default dev ipsec-ai table 301 src %s\n' "${DNS_TEST_AI_VIP:-}"
          exit 0
        fi
        case "${DNS_TEST_ROUTE_STATE:-complete}" in
          missing_route|missing_all) ;;
          *)
            printf 'default dev ipsec-ai table 301'
            case "${DNS_TEST_AI_ROUTE_SOURCE_STATE:-match}" in
              missing) ;;
              wrong) printf ' src 10.127.255.1' ;;
              *)
                [[ -z "${DNS_TEST_AI_VIP:-}" ]] ||
                  printf ' src %s' "$DNS_TEST_AI_VIP"
                ;;
            esac
            printf '\n'
            ;;
        esac
        ;;
      351)
        if [[ "${DNS_TEST_ROUTE_APPLY_STICKY_PROFILE:-}" != "cn" ]] &&
           grep -Fq 'ip route replace default dev ipsec-cn src ' "$DNS_TEST_CALLS"; then
          printf 'default dev ipsec-cn table 351 src %s\n' "${DNS_TEST_CN_VIP:-}"
          exit 0
        fi
        if [[ "${DNS_TEST_ROUTE_STATE:-complete}" != "missing_cn" ]]; then
          printf 'default dev ipsec-cn table 351'
          case "${DNS_TEST_CN_ROUTE_SOURCE_STATE:-match}" in
            missing) ;;
            wrong) printf ' src 10.127.255.2' ;;
            *)
              [[ -z "${DNS_TEST_CN_VIP:-}" ]] ||
                printf ' src %s' "$DNS_TEST_CN_VIP"
              ;;
          esac
          printf '\n'
        fi
        ;;
    esac
    ;;
esac
exit 0
EOF

cat >"$fakebin/swanctl" <<'EOF'
#!/usr/bin/env bash
printf 'swanctl %s\n' "$*" >>"$DNS_TEST_CALLS"
if [[ "${DNS_TEST_SWAN_SUCCESS_NOISE:-0}" == "1" &&
      ( "${1:-}" == "--load-all" || "${1:-}" == "--initiate" ) ]]; then
  printf 'simulated optional plugin warning\n' >&2
fi
if [[ "${1:-}" == "--stats" && "${DNS_TEST_VICI_AVAILABLE:-1}" != "1" ]]; then
  exit 9
fi
if [[ "${1:-}" == "--load-all" && "${DNS_TEST_SWAN_LOAD_FAIL:-0}" == "1" ]]; then
  exit 9
fi
if [[ "${1:-}" == "--list-conns" ]]; then
  if [[ "${DNS_TEST_CONNECTIONS_MISSING:-0}" != "1" ]]; then
    printf 'ai: IKEv2\n'
    printf 'cn: IKEv2\n'
  fi
  exit 0
fi
ipsec_child_up() {
  local child=$1
  if [[ "${DNS_TEST_IPSEC_START_EMPTY:-0}" == "1" ]]; then
    grep -Fxq "$child" "$DNS_TEST_IPSEC_STARTED" 2>/dev/null
  else
    [[ "${DNS_TEST_IPSEC_FAIL_CHILD:-}" != "$child" ]]
  fi
}
emit_ipsec_sa() {
  local child=$1 id=$2 vip=$3 state child_id
  child_id=$id
  if [[ "$child" == ai && -n "${DNS_TEST_AI_CHILD_ID:-}" ]]; then
    child_id=$DNS_TEST_AI_CHILD_ID
  elif [[ "$child" == cn && -n "${DNS_TEST_CN_CHILD_ID:-}" ]]; then
    child_id=$DNS_TEST_CN_CHILD_ID
  fi
  if [[ "$child" == "ai" ]]; then
    state=${DNS_TEST_AI_SA_STATE:-healthy}
  else
    state=${DNS_TEST_CN_SA_STATE:-healthy}
  fi
  [[ "$state" != "missing" ]] || return 0
  if [[ "$state" == "connecting" ]]; then
    printf '%s: #%s, CONNECTING, IKEv2\n' "$child" "$id"
    return 0
  fi
  if [[ "$state" == "split-components" ]]; then
    printf '%s: #10, ESTABLISHED, IKEv2\n' "$child"
    printf '  local 192.0.2.%s[4500] [%s]\n' "$id" "$vip"
    printf '%s: #11, ESTABLISHED, IKEv2\n' "$child"
    printf '  %s: #11, reqid 11, INSTALLED, TUNNEL, ESP\n' "$child"
    return 0
  fi
  if [[ "$state" == "multi-healthy" ]]; then
    printf '%s: #10, ESTABLISHED, IKEv2\n' "$child"
    printf '  %s: #10, reqid 10, INSTALLED, TUNNEL, ESP\n' "$child"
  fi
  printf '%s: #%s, ESTABLISHED, IKEv2\n' "$child" "$id"
  if [[ "$state" != "no-vip" && -n "$vip" ]]; then
    printf '  local 192.0.2.%s[4500] [%s]\n' "$id" "$vip"
  fi
  case "$state" in
    no-child) ;;
    child-not-installed)
      printf '  %s: #%s, reqid %s, ROUTED, TUNNEL, ESP\n' "$child" "$child_id" "$child_id"
      ;;
    *)
      printf '  %s: #%s, reqid %s, INSTALLED, TUNNEL, ESP\n' "$child" "$child_id" "$child_id"
      ;;
  esac
}
if [[ "${1:-}" == "--list-sas" ]]; then
  if ipsec_child_up ai; then
    emit_ipsec_sa ai 1 "${DNS_TEST_AI_VIP:-}"
  fi
  if ipsec_child_up cn; then
    emit_ipsec_sa cn 2 "${DNS_TEST_CN_VIP:-}"
  fi
  [[ "${DNS_TEST_SWAN_LIST_FAIL:-0}" != "1" ]] || exit 9
fi
if [[ "${1:-}" == "--initiate" && "${3:-}" == "${DNS_TEST_IPSEC_FAIL_CHILD:-}" ]]; then
  exit 9
fi
if [[ "${1:-}" == "--initiate" && "${DNS_TEST_IPSEC_START_EMPTY:-0}" == "1" ]]; then
  printf '%s\n' "${3:-}" >>"$DNS_TEST_IPSEC_STARTED"
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
if [[ "${DNS_TEST_SCENARIO:-}" != "post_restart_blocking" ||
      "${1:-}" != "dig" ]]; then
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

cat >"$fakebin/tar" <<'EOF'
#!/usr/bin/env bash
if [[ "${DNS_TEST_TAR_FAIL:-0}" == "1" && "${1:-}" == "-czf" ]]; then
  printf 'partial archive\n' >"$2"
  exit 9
fi
if [[ "${DNS_TEST_TAR_DELAY:-0}" == "1" && "${1:-}" == "-czf" ]]; then
  : >"$DNS_TEST_TAR_BLOCKING"
  /bin/sleep 2
fi
exec /usr/bin/tar "$@"
EOF

cat >"$fakebin/dnscomplex-fix-stub" <<'EOF'
#!/usr/bin/env bash
printf 'fix-stub %s\n' "$*" >>"$DNS_TEST_CALLS"
[[ "${1:-}" == "fix" ]] || exit 64
[[ "${DNSCOMPLEX_MAINTENANCE_LOCK_HELD:-0}" == "1" ]] || exit 65
( : >&8 ) 2>/dev/null || exit 66
[[ "${DNS_TEST_FIX_FAIL:-0}" != "1" ]]
EOF

cat >"$fakebin/dnscomplex-fix-mutating-stub" <<'EOF'
#!/usr/bin/env bash
printf 'fix-mutating-stub %s\n' "$*" >>"$DNS_TEST_CALLS"
[[ "${1:-}" == "fix" ]] || exit 64
printf '%s\n' apply-config-mutated >"$DNS_TEST_APPLY_RUNTIME"
exit 9
EOF

cat >"$fakebin/dig" <<'EOF'
#!/usr/bin/env bash
printf 'dig %s\n' "$*" >>"$DNS_TEST_CALLS"
if [[ " $* " == *" gateway.icloud.com "* &&
      "${DNS_TEST_ICLOUD_GATEWAY_DNS:-1}" != "1" ]]; then
  exit 0
fi
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
  nft_success) printf '93.184.216.34\n' ;;
  nft_ai_down)
    if [[ " $* " == *" -p 6054 "* ]]; then
      exit 9
    fi
    printf '93.184.216.34\n'
    ;;
  nft_private) printf '100.64.0.1\n' ;;
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
  DNS_TEST_IPSEC_AI_SNAT_VIP="$ipsec_ai_snat_vip" \
  DNS_TEST_IPSEC_CN_SNAT_VIP="$ipsec_cn_snat_vip" \
  DNS_TEST_IPSEC_AI_SNAT_SET="$ipsec_ai_snat_set" \
  DNS_TEST_IPSEC_CN_SNAT_SET="$ipsec_cn_snat_set" \
  DNS_TEST_GATE_CLOSED_AI="$gate_closed_ai" \
  DNS_TEST_GATE_CLOSED_CN="$gate_closed_cn" \
  DNS_TEST_SINGBOX_CONFIG="$ipsec_singbox_config" \
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
  DNS_TEST_ROUTE_APPLY_STICKY_PROFILE="${DNS_TEST_ROUTE_APPLY_STICKY_PROFILE:-}" \
  DNS_TEST_AI_RULE_MASK_STATE="${DNS_TEST_AI_RULE_MASK_STATE:-none}" \
  DNS_TEST_CN_RULE_MASK_STATE="${DNS_TEST_CN_RULE_MASK_STATE:-none}" \
  DNS_TEST_AI_RULE_SHAPE_STATE="${DNS_TEST_AI_RULE_SHAPE_STATE:-simple}" \
  DNS_TEST_AI_RULE_CONFLICT="${DNS_TEST_AI_RULE_CONFLICT:-none}" \
  DNS_TEST_CN_RULE_CONFLICT="${DNS_TEST_CN_RULE_CONFLICT:-none}" \
  DNS_TEST_AI_RULE_SAME_PRIORITY_CONFLICT="${DNS_TEST_AI_RULE_SAME_PRIORITY_CONFLICT:-none}" \
  DNS_TEST_IPSEC_FAIL_CHILD="${DNS_TEST_IPSEC_FAIL_CHILD:-}" \
  DNS_TEST_IPSEC_START_EMPTY="${DNS_TEST_IPSEC_START_EMPTY:-0}" \
  DNS_TEST_IPSEC_STARTED="$ipsec_started" \
  DNS_TEST_WAN_ADDRESS="${DNS_TEST_WAN_ADDRESS:-expected}" \
  DNS_TEST_WAN_ROUTE="${DNS_TEST_WAN_ROUTE:-expected}" \
  DNS_TEST_UNDERLAY_IFACE="${DNS_TEST_UNDERLAY_IFACE:-eth0}" \
  DNS_TEST_UNDERLAY_IPV4="${DNS_TEST_UNDERLAY_IPV4:-192.168.50.200}" \
  DNS_TEST_UNDERLAY_GATEWAY="${DNS_TEST_UNDERLAY_GATEWAY:-192.168.50.253}" \
  DNS_TEST_VICI_AVAILABLE="${DNS_TEST_VICI_AVAILABLE:-1}" \
  DNS_TEST_SWAN_LOAD_FAIL="${DNS_TEST_SWAN_LOAD_FAIL:-0}" \
  DNS_TEST_SWAN_SUCCESS_NOISE="${DNS_TEST_SWAN_SUCCESS_NOISE:-0}" \
  DNS_TEST_SWAN_LIST_FAIL="${DNS_TEST_SWAN_LIST_FAIL:-0}" \
  DNS_TEST_CONNECTIONS_MISSING="${DNS_TEST_CONNECTIONS_MISSING:-0}" \
  DNS_TEST_AI_SA_STATE="${DNS_TEST_AI_SA_STATE:-healthy}" \
  DNS_TEST_CN_SA_STATE="${DNS_TEST_CN_SA_STATE:-healthy}" \
  DNS_TEST_AI_VIP="${DNS_TEST_AI_VIP:-}" \
  DNS_TEST_CN_VIP="${DNS_TEST_CN_VIP:-}" \
  DNS_TEST_AI_CHILD_ID="${DNS_TEST_AI_CHILD_ID:-}" \
  DNS_TEST_CN_CHILD_ID="${DNS_TEST_CN_CHILD_ID:-}" \
  DNS_TEST_AI_INTERFACE_STATE="${DNS_TEST_AI_INTERFACE_STATE:-up}" \
  DNS_TEST_CN_INTERFACE_STATE="${DNS_TEST_CN_INTERFACE_STATE:-up}" \
  DNS_TEST_AI_ROUTE_SOURCE_STATE="${DNS_TEST_AI_ROUTE_SOURCE_STATE:-match}" \
  DNS_TEST_CN_ROUTE_SOURCE_STATE="${DNS_TEST_CN_ROUTE_SOURCE_STATE:-match}" \
  DNS_TEST_PROFILE_PROBE_AI_STATUS="${DNS_TEST_PROFILE_PROBE_AI_STATUS:-pass}" \
  DNS_TEST_PROFILE_PROBE_CN_STATUS="${DNS_TEST_PROFILE_PROBE_CN_STATUS:-pass}" \
  DNS_TEST_GATE_CLOSED_AI="$gate_closed_ai" \
  DNS_TEST_GATE_CLOSED_CN="$gate_closed_cn" \
  DNS_TEST_INACTIVE_UNIT="${DNS_TEST_INACTIVE_UNIT:-}" \
  DNS_TEST_ACTIVATING_UNIT="${DNS_TEST_ACTIVATING_UNIT:-}" \
  DNS_TEST_DISABLED_UNIT="${DNS_TEST_DISABLED_UNIT:-}" \
  DNS_TEST_RESTART_FAIL_UNIT="${DNS_TEST_RESTART_FAIL_UNIT:-}" \
  DNS_TEST_RESTART_FAIL_ONCE_UNIT="${DNS_TEST_RESTART_FAIL_ONCE_UNIT:-}" \
  DNS_TEST_RESTART_FAIL_ONCE_STATE="$restart_fail_once_state" \
  DNS_TEST_STOP_FAIL_UNIT="${DNS_TEST_STOP_FAIL_UNIT:-}" \
  DNS_TEST_SYSTEMCTL_STATE="$systemctl_state" \
  DNS_TEST_SYSTEMCTL_FAIL_ONCE="${DNS_TEST_SYSTEMCTL_FAIL_ONCE:-}" \
  DNS_TEST_SYSTEMCTL_FAIL_STATE="$systemctl_fail_state" \
  DNS_TEST_MKTEMP_FAIL="${DNS_TEST_MKTEMP_FAIL:-}" \
  DNS_TEST_RESTORE_STAGE_FAIL="${DNS_TEST_RESTORE_STAGE_FAIL:-0}" \
  DNS_TEST_RESTORE_FAIL_MOVE="${DNS_TEST_RESTORE_FAIL_MOVE:-0}" \
  DNS_TEST_RESTORE_MOVE_COUNTER="$restore_move_counter" \
  DNS_TEST_STATE_WRITE_FAIL="${DNS_TEST_STATE_WRITE_FAIL:-0}" \
  DNS_TEST_NFT_EXISTING="${DNS_TEST_NFT_EXISTING:-0}" \
  DNS_TEST_NFT_ADD_FAIL="${DNS_TEST_NFT_ADD_FAIL:-0}" \
  DNS_TEST_NFT_CLEAR_FAIL_PROFILE="${DNS_TEST_NFT_CLEAR_FAIL_PROFILE:-}" \
  DNS_TEST_NFT_BATCH_FAIL_PROFILE="${DNS_TEST_NFT_BATCH_FAIL_PROFILE:-}" \
  DNS_TEST_NFT_RACE_PROFILE="${DNS_TEST_NFT_RACE_PROFILE:-}" \
  DNS_TEST_NFT_RACE_STATE="$nft_race" \
  DNS_TEST_TAR_DELAY="${DNS_TEST_TAR_DELAY:-0}" \
  DNS_TEST_TAR_FAIL="${DNS_TEST_TAR_FAIL:-0}" \
  DNS_TEST_TAR_BLOCKING="$tar_blocking" \
  DNS_TEST_SOCKET_CALLS="$socket_calls" \
  DNS_TEST_SOCKS_CONNECTIVITY="${DNS_TEST_SOCKS_CONNECTIVITY:-1}" \
  DNS_TEST_IPV4_CONNECTIVITY="${DNS_TEST_IPV4_CONNECTIVITY:-1}" \
  DNS_TEST_IPV6_CONNECTIVITY="${DNS_TEST_IPV6_CONNECTIVITY:-1}" \
  DNS_TEST_ICLOUD_GATEWAY_DNS="${DNS_TEST_ICLOUD_GATEWAY_DNS:-1}" \
  PYTHONPATH="${DNS_TEST_PYTHONPATH:-}" \
  DNS_TEST_REAL_SLEEP="${DNS_TEST_REAL_SLEEP:-0}" \
  DNS_TEST_NOW="${DNS_TEST_NOW:-}" \
  DNSCOMPLEX_FORCE_SERVICE_STATE="${DNSCOMPLEX_FORCE_SERVICE_STATE:-1}" \
  DNSCOMPLEX_CONFIG="${DNS_TEST_CONFIG:-$config}" \
    "$manager" "$@"
}

run_route_repair() {
  PATH="$fakebin:$PATH" \
  DNSCOMPLEX_CONFIG="${DNS_TEST_CONFIG:-$config}" \
  DNSCOMPLEX_BASE="$state" \
  DNSCOMPLEX_RUN_DIR="$run_dir" \
  DNSCOMPLEX_FS_ROOT="$fake_root" \
  DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
  DNS_TEST_CALLS="$calls" \
  DNS_TEST_PROFILE_PROBE_AI_STATUS="${DNS_TEST_PROFILE_PROBE_AI_STATUS:-pass}" \
  DNS_TEST_PROFILE_PROBE_CN_STATUS="${DNS_TEST_PROFILE_PROBE_CN_STATUS:-pass}" \
  DNS_TEST_PROBE_RULE_CONFLICT="${DNS_TEST_PROBE_RULE_CONFLICT:-}" \
  DNS_TEST_IPSEC_AI_SNAT_VIP="$ipsec_ai_snat_vip" \
  DNS_TEST_IPSEC_CN_SNAT_VIP="$ipsec_cn_snat_vip" \
  DNS_TEST_IPSEC_AI_SNAT_SET="$ipsec_ai_snat_set" \
  DNS_TEST_IPSEC_CN_SNAT_SET="$ipsec_cn_snat_set" \
  DNS_TEST_GATE_CLOSED_AI="$gate_closed_ai" \
  DNS_TEST_GATE_CLOSED_CN="$gate_closed_cn" \
  DNS_TEST_SINGBOX_CONFIG="$ipsec_singbox_config" \
  bash -c 'source "$1"; load_config; repair_policy_routes_if_needed' _ "$manager"
}

run_manager_with_fix_stub() {
  PATH="$fakebin:$PATH" \
  DNSCOMPLEX_CONFIG="$config" \
  DNSCOMPLEX_BASE="$state" \
  DNSCOMPLEX_RUN_DIR="$run_dir" \
  DNSCOMPLEX_FS_ROOT="$fake_root" \
  DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
  DNS_TEST_CALLS="$calls" \
  DNS_TEST_FIX_FAIL="${DNS_TEST_FIX_FAIL:-0}" \
  bash -c '
    source "$1"
    shift
    main "$@"
  ' "$fakebin/dnscomplex-fix-stub" "$manager" "$@"
}

run_health() {
  DNS_TEST_HEALTH_GATE_OPEN="${DNS_TEST_HEALTH_GATE_OPEN:-1}" \
  DNS_TEST_PYTHONPATH="$fakepy" \
  DNS_TEST_AI_VIP="${DNS_TEST_AI_VIP:-10.64.0.1}" \
  DNS_TEST_CN_VIP="${DNS_TEST_CN_VIP:-10.64.0.2}" \
  DNS_TEST_IPV4_CONNECTIVITY="${DNS_TEST_IPV4_CONNECTIVITY:-1}" \
  DNS_TEST_IPV6_CONNECTIVITY="${DNS_TEST_IPV6_CONNECTIVITY:-1}" \
    run_manager health --json
}

reset_state() {
  : >"$calls"
  rm -f "$counter" "$second_round" "$restarted" "$restart_epoch" \
    "$restart_monotonic" "$blocking" "$probe_pids" "$nft_race" \
    "$tar_blocking" "$socket_calls" "$ipsec_started" "$systemctl_state" \
    "$systemctl_fail_state" "$restore_move_counter" "$restart_fail_once_state" \
    "$run_dir/ipsec-ai.retry" "$run_dir/ipsec-cn.retry"
  rm -f "$run_dir/profile-dataplane-ai.success" \
    "$run_dir/profile-dataplane-cn.success"
  rm -f "$gate_closed_ai" "$gate_closed_cn" "${calls}.probe-ai-vip" "${calls}.probe-cn-vip"
  rm -f "${calls}.gate-open-ai" "${calls}.gate-open-cn"
  rm -f "${calls}.ipsec-ai-alias-snat" "${calls}.ipsec-cn-alias-snat"
  rm -f "${calls}.ai-extra-cleared" "${calls}.ai-alias-extra-cleared"
  rm -f "$lan_alias_state"
}

run_watchdog() {
  local scenario=$1
  reset_state
  if [[ "${DNS_TEST_SEED_STALE_PROOF:-0}" == "1" ]]; then
    printf '10.64.0.1 %064d 2\n' 0 >"$run_dir/profile-dataplane-ai.success"
    printf '10.64.0.2 %064d 2\n' 0 >"$run_dir/profile-dataplane-cn.success"
    chmod 0600 "$run_dir/profile-dataplane-ai.success" "$run_dir/profile-dataplane-cn.success"
  fi
  case "$scenario" in
    cooldown) ;;
    *) rm -f "$run_dir/smartdns.last_restart" ;;
  esac
  DNS_TEST_SCENARIO="$scenario" \
  DNS_TEST_AI_VIP="${DNS_TEST_AI_VIP:-10.64.0.1}" \
  DNS_TEST_CN_VIP="${DNS_TEST_CN_VIP:-10.64.0.2}" \
    run_manager watchdog
}

run_watchdog_at() {
  local now=$1 scenario=$2
  DNS_TEST_NOW="$now" run_watchdog "$scenario"
}

smartdns_tag=$(PATH="$fakebin:$PATH" \
  DNS_TEST_SMARTDNS_VERSION='smartdns 1.2026.06.28-1614 (Release48.2)' \
  bash -c 'source "$1"; component_current_tag smartdns' _ "$manager")
[[ "$smartdns_tag" == "Release48.2" ]] ||
  fail "SmartDNS dotted release tag was truncated to $smartdns_tag"

run_watchdog healthy
assert_not_contains "$calls" 'restart smartdns'
deadline_call=$(grep -E '^lan-alias reconcile ' "$calls" | head -n1)
[[ "$deadline_call" =~ watchdog-deadline=[1-9][0-9]+$ ]] ||
  fail "watchdog did not pass its shared monotonic deadline to the LAN alias helper"

DNS_TEST_INACTIVE_UNIT=AdGuardHome run_watchdog healthy
assert_contains "$calls" 'systemctl restart AdGuardHome'
assert_call_count 'systemctl restart' 1
assert_not_contains "$calls" 'restart smartdns'

if DNS_TEST_ACTIVATING_UNIT=nftables DNS_TEST_SEED_STALE_PROOF=1 \
   run_watchdog healthy >"$tmpdir/watchdog-unit-state-unknown.log" 2>&1; then
  fail "watchdog treated an indeterminate systemd state as proven inactive"
fi
assert_not_contains "$calls" 'systemctl restart nftables'
assert_contains "$tmpdir/watchdog-unit-state-unknown.log" 'activity state is unknown'
assert_contains "$calls" 'nft-batch flush set inet dnscomplex ai_ready4'
assert_contains "$calls" 'nft-batch flush set inet dnscomplex cn_ready4'
failclosed_nft_batches=$(grep -F 'nft -f -' "$calls" | grep -vc '^timeout ' || true)
[[ "$failclosed_nft_batches" == 1 ]] ||
  fail "watchdog fail-closed used $failclosed_nft_batches nft batches instead of one"
assert_contains "$calls" 'nft -j list table inet dnscomplex'
if ! grep -Fq 'jq -e' "$calls"; then
  cat "$calls" >&2
  fail "watchdog fail-closed did not invoke bounded JSON verification"
fi
[[ ! -e "$run_dir/profile-dataplane-ai.success" &&
   ! -e "$run_dir/profile-dataplane-cn.success" ]] ||
  fail "watchdog fail-closed retained old dataplane success evidence"

if DNS_TEST_ROUTE_STATE=inspect_fail DNS_TEST_SEED_STALE_PROOF=1 \
   run_watchdog healthy >"$tmpdir/watchdog-ip-rule-inspect-failed.log" 2>&1; then
  fail "watchdog reported healthy after ip rule state could not be inspected"
fi
assert_contains "$tmpdir/watchdog-ip-rule-inspect-failed.log" 'policy routes could not be inspected'
assert_contains "$calls" 'nft-batch flush set inet dnscomplex ai_ready4'
assert_contains "$calls" 'nft-batch flush set inet dnscomplex cn_ready4'
[[ ! -e "$run_dir/profile-dataplane-ai.success" &&
   ! -e "$run_dir/profile-dataplane-cn.success" ]] ||
  fail "watchdog route-inspection failure retained old dataplane success evidence"

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
assert_contains "$calls" \
  'ip route replace default dev ipsec-ai src 10.64.0.1 table 301'
assert_not_contains "$calls" 'ip rule add fwmark 0x301 table 301'
assert_not_contains "$calls" 'ip route replace default dev ipsec-cn'

DNS_TEST_ROUTE_STATE=missing_rule run_watchdog healthy
assert_contains "$calls" 'ip rule add fwmark 0x301 table 301'
assert_not_contains "$calls" 'ip route replace default dev ipsec-cn'

DNS_TEST_ROUTE_STATE=missing_cn run_watchdog healthy
assert_contains "$calls" 'ip rule add fwmark 0x351 table 351'
assert_contains "$calls" \
  'ip route replace default dev ipsec-cn src 10.64.0.2 table 351'
assert_not_contains "$calls" 'ip route replace default dev ipsec-ai'

DNS_TEST_AI_ROUTE_SOURCE_STATE=wrong run_watchdog healthy
assert_contains "$calls" \
  'ip route replace default dev ipsec-ai src 10.64.0.1 table 301'
assert_not_contains "$calls" 'ip route replace default dev ipsec-cn'

mkdir -p "$(dirname "$ipsec_singbox_config")"
cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"
if DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.3 \
   DNS_TEST_CN_VIP=10.64.0.2 run_watchdog healthy \
     >"$tmpdir/ipsec-vip-rotation.log" 2>&1; then
  [[ "$(jq -r '.outbounds[] | select(.tag=="ai-ipsec") | .inet4_bind_address' "$ipsec_singbox_config")" == "10.64.0.3" ]] ||
    fail "open AI egress gate did not reconcile sing-box bind address after VIP rotation"
  [[ "$(cat "$ipsec_ai_snat_vip")" == "10.64.0.3" ]] ||
    fail "open AI egress gate did not reconcile the owned SNAT rule after VIP rotation"
  [[ "$(jq -r '.outbounds[] | select(.tag=="cn-ipsec") | .inet4_bind_address' "$ipsec_singbox_config")" == "10.64.0.2" ]] ||
    fail "AI VIP reconciliation changed the CN sing-box bind address"
  [[ "$(cat "$ipsec_cn_snat_vip")" == "10.64.0.2" ]] ||
    fail "AI VIP reconciliation changed the CN SNAT rule"
  assert_call_count 'systemctl restart sing-box' 1
  DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.3 \
    DNS_TEST_CN_VIP=10.64.0.2 run_manager watchdog
  assert_call_count 'systemctl restart sing-box' 1
  assert_not_contains "$calls" 'ip route replace default dev ipsec-ai src 10.64.0.3 table 301'
  assert_call_before 'nft-batch flush set inet dnscomplex ai_ready4' \
    'nft add rule inet dnscomplex postrouting oifname ipsec-ai'
  assert_call_before 'nft add rule inet dnscomplex postrouting oifname ipsec-ai' \
    'install -m 0644'
  assert_call_before 'sing-box check -c' 'systemctl restart sing-box'
  assert_call_before 'systemctl restart sing-box' \
    'nft-batch add element inet dnscomplex ai_ready4'
  restart_line=$(grep -nF 'systemctl restart sing-box' "$calls" | tail -n1 | cut -d: -f1)
  gate_open_line=$(grep -nF 'nft-batch add element inet dnscomplex ai_ready4' "$calls" | tail -n1 | cut -d: -f1)
  if ! awk -v restart="$restart_line" -v gate="$gate_open_line" \
      'NR > restart && NR < gate && index($0, "swanctl --list-sas") { found=1 } END { exit(found ? 0 : 1) }' \
      "$calls"; then
    fail "AI gate reopened before a fresh IPsec SA/VIP recheck"
  fi
else
  cat "$tmpdir/ipsec-vip-rotation.log" >&2
  fail "watchdog rejected an otherwise healthy rotated IPsec VIP"
fi

reset_state
cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"
if DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_INTERFACE_STATE=down \
   DNS_TEST_NFT_CLEAR_FAIL_PROFILE=ai run_watchdog healthy \
     >"$tmpdir/ipsec-not-ready-gate-clear-failure.log" 2>&1; then
  fail "SA-not-ready profile reported healthy after its egress gate failed to close"
fi
assert_contains "$calls" 'nft-batch flush set inet dnscomplex ai_ready4'
assert_not_contains "$calls" 'systemctl restart sing-box'

reset_state
cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"
if DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.3 \
   DNS_TEST_CN_VIP=10.64.0.4 run_watchdog healthy \
     >"$tmpdir/ipsec-dual-vip-rotation.log" 2>&1; then
  DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.3 \
    DNS_TEST_CN_VIP=10.64.0.4 run_manager watchdog
  assert_call_before 'nft-batch flush set inet dnscomplex ai_ready4' \
    'sing-box check -c'
  assert_call_before 'nft-batch flush set inet dnscomplex cn_ready4' \
    'sing-box check -c'
  assert_call_before 'systemctl restart sing-box' \
    'nft-batch add element inet dnscomplex ai_ready4'
  assert_call_before 'systemctl restart sing-box' \
    'nft-batch add element inet dnscomplex cn_ready4'
else
  cat "$tmpdir/ipsec-dual-vip-rotation.log" >&2
  fail "watchdog rejected otherwise healthy simultaneous IPsec VIP rotations"
fi

cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"

reset_state
DNS_TEST_NFT_EXISTING=1 DNS_TEST_SCENARIO=healthy \
  DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 run_manager watchdog
assert_call_count 'systemctl restart sing-box' 0
assert_not_contains "$calls" 'nft delete rule inet dnscomplex postrouting'
assert_not_contains "$calls" 'nft add rule inet dnscomplex postrouting oifname ipsec-ai'
[[ "$(wc -l <"$ipsec_ai_snat_vip" | tr -d ' ')" == "1" ]] ||
  fail "stable AI VIP did not retain exactly one owned SNAT rule"

reset_state
cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
printf 'ai4\n' >"$ipsec_ai_snat_set"
printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"
printf 'cn4\n' >"$ipsec_cn_snat_set"
printf '10.64.0.1\n' >"${calls}.ipsec-ai-alias-snat"
write_owned_alias_state
DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.1 \
  DNS_TEST_CN_VIP=10.64.0.2 DNS_TEST_SCENARIO=healthy run_manager watchdog
assert_call_count 'systemctl restart sing-box' 0
assert_not_contains "$calls" 'nft delete rule inet dnscomplex postrouting'
assert_not_contains "$calls" 'nft add rule inet dnscomplex postrouting oifname ipsec-ai ip saddr @lan_alias_source4'

for alias_drift in missing stale duplicate; do
  reset_state
  cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
  printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
  printf 'ai4\n' >"$ipsec_ai_snat_set"
  printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"
  printf 'cn4\n' >"$ipsec_cn_snat_set"
  write_owned_alias_state
  if [[ "$alias_drift" == stale ]]; then
    printf '10.64.0.10\n' >"${calls}.ipsec-ai-alias-snat"
  elif [[ "$alias_drift" == duplicate ]]; then
    printf '10.64.0.1\n' >"${calls}.ipsec-ai-alias-snat"
    export DNS_TEST_AI_ALIAS_SNAT_EXTRA=10.64.0.1
  else
    unset DNS_TEST_AI_ALIAS_SNAT_EXTRA
  fi
  if DNS_TEST_NFT_EXISTING=1 DNS_TEST_SCENARIO=healthy \
     DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 run_manager watchdog \
       >"$tmpdir/alias-snat-${alias_drift}.log" 2>&1; then
    DNS_TEST_NFT_EXISTING=1 DNS_TEST_SCENARIO=healthy \
      DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 run_manager watchdog
    [[ "$(cat "${calls}.ipsec-ai-alias-snat")" == "10.64.0.1" ]] ||
      fail "$alias_drift alias SNAT was not repaired to the current AI VIP"
    assert_call_count 'nft add rule inet dnscomplex postrouting oifname ipsec-ai ip saddr @lan_alias_source4' 1
    assert_call_before 'nft-batch flush set inet dnscomplex ai_ready4' \
      'nft add rule inet dnscomplex postrouting oifname ipsec-ai ip saddr @lan_alias_source4'
    assert_call_before 'swanctl --list-sas' \
      'nft-batch add element inet dnscomplex ai_ready4'
    assert_call_count 'systemctl restart sing-box' 0
  else
    cat "$tmpdir/alias-snat-${alias_drift}.log" >&2
    fail "watchdog rejected repair of $alias_drift alias-only SNAT drift"
  fi
  unset DNS_TEST_AI_ALIAS_SNAT_EXTRA
done

for invalid_alias_state in partial corrupt mode fields symlink; do
  reset_state
  cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
  printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
  printf 'ai4\n' >"$ipsec_ai_snat_set"
  printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"
  printf 'cn4\n' >"$ipsec_cn_snat_set"
  write_owned_alias_state
  case "$invalid_alias_state" in
    partial) printf '{"schema":1}\n' >"$lan_alias_state" ;;
    corrupt) printf '{broken json\n' >"$lan_alias_state" ;;
    mode) chmod 0644 "$lan_alias_state" ;;
    fields)
      jq '.outbound_tag="foreign-outbound"' "$lan_alias_state" >"$lan_alias_state.tmp"
      mv "$lan_alias_state.tmp" "$lan_alias_state"
      chmod 0600 "$lan_alias_state"
      ;;
    symlink)
      mv "$lan_alias_state" "$lan_alias_state.target"
      ln -s "$lan_alias_state.target" "$lan_alias_state"
      ;;
  esac
  if DNS_TEST_NFT_EXISTING=1 DNS_TEST_SCENARIO=healthy \
     DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 \
     run_manager watchdog >"$tmpdir/alias-state-${invalid_alias_state}.log" 2>&1; then
    cat "$tmpdir/alias-state-${invalid_alias_state}.log" >&2
    fail "$invalid_alias_state LAN alias ownership state was treated as healthy"
  fi
  [[ -f "$gate_closed_ai" && -f "$gate_closed_cn" ]] ||
    fail "$invalid_alias_state alias state did not close all selected IPsec gates"
  assert_not_contains "$calls" 'nft delete rule inet dnscomplex postrouting handle 53'
  assert_not_contains "$calls" 'nft delete rule inet dnscomplex postrouting handle 54'
  assert_not_contains "$calls" 'nft add rule inet dnscomplex postrouting oifname ipsec-ai ip saddr @lan_alias_source4'
  assert_not_contains "$calls" 'nft add rule inet dnscomplex postrouting oifname ipsec-cn ip saddr @lan_alias_source4'
  rm -f "$lan_alias_state.target"
done

reset_state
cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
printf '10.64.0.10\n' >"$ipsec_ai_snat_vip"
printf 'ai40\n' >"$ipsec_ai_snat_set"
printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"
printf 'cn4\n' >"$ipsec_cn_snat_set"
DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.1 \
  DNS_TEST_CN_VIP=10.64.0.2 run_watchdog healthy
[[ "$(cat "$ipsec_ai_snat_vip")" == "10.64.0.1" &&
   "$(cat "$ipsec_ai_snat_set")" == "ai4" ]] ||
  fail "SNAT drift matching confused AI VIP .10 or nftset ai40 with .1/ai4"

reset_state
cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
printf 'ai4\n' >"$ipsec_ai_snat_set"
printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"
printf 'cn4\n' >"$ipsec_cn_snat_set"
write_owned_alias_state
DNS_TEST_AI_SNAT_EXTRA='tcp dport 443' DNS_TEST_NFT_EXISTING=1 \
  DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 \
  DNS_TEST_SCENARIO=healthy run_manager watchdog
assert_call_count 'nft delete rule inet dnscomplex postrouting handle 51' 1
assert_call_count 'nft add rule inet dnscomplex postrouting oifname ipsec-ai ip daddr @ai4' 1
assert_call_count 'nft add rule inet dnscomplex postrouting oifname ipsec-ai ip saddr @lan_alias_source4' 1
[[ ! -s "${calls}.ai-extra-cleared" ]] ||
  fail "test fake retained an extra AI SNAT packet filter after replacement"

reset_state
cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
printf 'ai4\n' >"$ipsec_ai_snat_set"
printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"
printf 'cn4\n' >"$ipsec_cn_snat_set"
DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_SA_STATE=no-vip \
  DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 \
  run_watchdog healthy
[[ ! -s "$ipsec_ai_snat_vip" ]] ||
  fail "missing AI VIP left the old owned SNAT rule installed"
[[ -f "$gate_closed_ai" ]] ||
  fail "missing AI VIP left the AI egress gate open"
[[ "$(cat "$ipsec_cn_snat_vip")" == "10.64.0.2" ]] ||
  fail "missing AI VIP reconciliation changed CN SNAT"

for failure in check install restart; do
  reset_state
  cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
  printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
  printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"
  if [[ "$failure" == check ]]; then
    DNS_TEST_SINGBOX_CHECK_FAIL=1 DNS_TEST_NFT_EXISTING=1 \
      DNS_TEST_AI_VIP=10.64.0.3 DNS_TEST_CN_VIP=10.64.0.2 \
      run_watchdog healthy >"$tmpdir/ipsec-vip-check-failure.log" 2>&1 &&
      fail "VIP reconciliation reported success after sing-box check failure"
  elif [[ "$failure" == install ]]; then
    DNS_TEST_INSTALL_FAIL=1 DNS_TEST_NFT_EXISTING=1 \
      DNS_TEST_AI_VIP=10.64.0.3 DNS_TEST_CN_VIP=10.64.0.2 \
      run_watchdog healthy >"$tmpdir/ipsec-vip-install-failure.log" 2>&1 &&
      fail "VIP reconciliation reported success after config install failure"
  else
    DNS_TEST_RESTART_FAIL_UNIT=sing-box DNS_TEST_NFT_EXISTING=1 \
      DNS_TEST_AI_VIP=10.64.0.3 DNS_TEST_CN_VIP=10.64.0.2 \
      run_watchdog healthy >"$tmpdir/ipsec-vip-restart-failure.log" 2>&1 &&
      fail "VIP reconciliation reported success after sing-box restart failure"
  fi
  [[ "$(jq -r '.outbounds[] | select(.tag=="ai-ipsec") | .inet4_bind_address' "$ipsec_singbox_config")" == "10.64.0.1" ]] ||
    fail "$failure failure did not preserve the previous sing-box config"
  [[ -f "$gate_closed_ai" ]] ||
    fail "$failure failure reopened the AI gate before reconciliation completed"
  assert_not_contains "$calls" 'nft-batch add element inet dnscomplex ai_ready4'
done

reset_state
cat >"$ipsec_singbox_config" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"

if DNS_TEST_AI_ROUTE_SOURCE_STATE=wrong \
   DNS_TEST_ROUTE_APPLY_STICKY_PROFILE=ai \
   run_watchdog healthy >"$tmpdir/route-repair-not-applied.log" 2>&1; then
  fail "watchdog accepted a route repair that did not change runtime state"
fi
assert_contains "$calls" \
  'ip route replace default dev ipsec-ai src 10.64.0.1 table 301'
assert_not_contains "$calls" 'dig '

DNS_TEST_AI_RULE_MASK_STATE=full run_watchdog healthy
assert_not_contains "$calls" 'ip rule add fwmark 0x301 table 301'

DNS_TEST_AI_RULE_MASK_STATE=zero run_watchdog healthy
assert_contains "$calls" 'ip rule del priority 10301'
assert_contains "$calls" 'ip rule add fwmark 0x301 table 301'

if DNS_TEST_AI_RULE_CONFLICT=zero-mask \
   run_watchdog healthy >"$tmpdir/rule-higher-conflict.log" 2>&1; then
  fail "watchdog accepted a higher-priority fwmark rule with a zero mask"
fi
assert_not_contains "$calls" 'dig '

if DNS_TEST_AI_RULE_CONFLICT=negated-other \
   run_watchdog healthy >"$tmpdir/rule-negated-conflict.log" 2>&1; then
  fail "watchdog accepted a higher-priority negated rule that matches AI"
fi
assert_not_contains "$calls" 'dig '

if DNS_TEST_AI_RULE_CONFLICT=negated-target \
   run_watchdog healthy >"$tmpdir/probe-rule-negated-target.log" 2>&1; then
  fail "watchdog accepted a foreign negated rule that captures the reserved AI probe mark"
fi
assert_contains "$tmpdir/probe-rule-negated-target.log" \
  'ai dataplane probe fwmark rule conflicts'
assert_not_contains "$calls" 'profile-dataplane-probe profile=ai status='
assert_not_contains "$calls" 'ip rule add fwmark 0x301 table 301'

if DNS_TEST_AI_RULE_CONFLICT=negated-restricted \
   run_watchdog healthy >"$tmpdir/rule-negated-restricted.log" 2>&1; then
  fail "watchdog accepted a negated rule with a restrictive source selector"
fi
assert_not_contains "$calls" 'dig '

for shape_state in restricted suppressed; do
  DNS_TEST_AI_RULE_SHAPE_STATE="$shape_state" run_watchdog healthy
  assert_contains "$calls" 'ip rule del priority 10301'
  assert_contains "$calls" 'ip rule add fwmark 0x301 table 301'
done

for same_priority_conflict in stale duplicate; do
  DNS_TEST_AI_RULE_SAME_PRIORITY_CONFLICT="$same_priority_conflict" \
    run_watchdog healthy
  assert_contains "$calls" 'ip rule del priority 10301'
  assert_contains "$calls" 'ip rule add fwmark 0x301 table 301'
done

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
assert_contains "$calls" \
  'ip route replace default dev ipsec-ai src 10.64.0.1 table 301'
assert_not_contains "$calls" 'dig '

DNS_TEST_AI_SA_STATE=no-child \
  run_watchdog healthy >"$tmpdir/ipsec-child-missing.log" 2>&1
assert_contains "$calls" 'swanctl --initiate --child ai'
assert_contains "$calls" 'dig '

DNS_TEST_AI_SA_STATE=no-vip \
  run_watchdog healthy >"$tmpdir/ipsec-vip-missing.log" 2>&1
assert_contains "$calls" 'swanctl --initiate --child ai'
assert_contains "$calls" 'dig '

DNS_TEST_IPSEC_FAIL_CHILD=ai DNS_TEST_NOW=1000 \
  run_watchdog healthy >"$tmpdir/ipsec-repair-failure.log" 2>&1
assert_contains "$calls" 'swanctl --initiate --child ai'
assert_not_contains "$calls" 'swanctl --load-all --noprompt'
assert_contains "$calls" 'dig '
[[ "$(cat "$run_dir/ipsec-ai.retry")" == "1 1060" ]] ||
  fail "AI IPsec retry state did not record the first 60-second delay"
DNS_TEST_IPSEC_FAIL_CHILD=ai DNS_TEST_NOW=1030 \
  run_manager watchdog >"$tmpdir/ipsec-repair-backoff.log" 2>&1
[[ "$(cat "$run_dir/ipsec-ai.retry")" == "1 1060" ]] ||
  fail "AI IPsec retried inside backoff: $(cat "$run_dir/ipsec-ai.retry" 2>/dev/null || printf missing)"
assert_call_count 'swanctl --initiate --child ai' 1
DNS_TEST_IPSEC_FAIL_CHILD=ai DNS_TEST_NOW=1060 \
  run_manager watchdog >>"$tmpdir/ipsec-repair-backoff.log" 2>&1
assert_call_count 'swanctl --initiate --child ai' 2

reset_state
DNS_TEST_CONNECTIONS_MISSING=1 DNS_TEST_IPSEC_FAIL_CHILD=ai \
  DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 DNS_TEST_NOW=2000 \
  run_manager watchdog >"$tmpdir/ipsec-config-reload.log" 2>&1
assert_call_count \
  'swanctl --load-all --noprompt' 1
assert_contains "$calls" 'swanctl --initiate --child ai'

DNS_TEST_CONNECTIONS_MISSING=0 DNS_TEST_IPSEC_FAIL_CHILD='' \
  DNS_TEST_IPSEC_START_EMPTY=0 DNS_TEST_AI_SA_STATE=healthy \
  DNS_TEST_CN_SA_STATE=healthy DNS_TEST_AI_VIP=10.64.0.1 \
  DNS_TEST_CN_VIP=10.64.0.2 DNS_TEST_NOW=2060 \
  run_manager watchdog >/dev/null
[[ ! -e "$run_dir/ipsec-ai.retry" ]] ||
  fail "successful AI IPsec recovery did not clear retry state"

reset_state
PATH="$fakebin:$PATH" \
DNSCOMPLEX_CONFIG="$config" \
DNSCOMPLEX_BASE="$state" \
DNSCOMPLEX_RUN_DIR="$run_dir" \
DNS_TEST_CALLS="$calls" \
bash -c '
  source "$1"
  load_config
  need_root() { :; }
  cn_override_current_ip() { printf "%s\n" 47.246.99.254; }
  cn_override_candidate_ips() { printf "%s\n" 47.246.99.254; }
  probe_cn_override_ip() { return 1; }
  write_config_cmd() { printf "unexpected config write\n" >>"$DNS_TEST_CALLS"; return 99; }
  rewrite_smartdns_static_overrides() { printf "unexpected SmartDNS rewrite\n" >>"$DNS_TEST_CALLS"; return 99; }
  refresh_cn_overrides_cmd youku.com
' _ "$manager" >"$tmpdir/cn-override-preserved.log" 2>&1 ||
  fail "an unreachable CN candidate with a preserved override was reported as a service failure"
assert_not_contains "$calls" 'unexpected config write'
assert_not_contains "$calls" 'unexpected SmartDNS rewrite'
assert_not_contains "$calls" 'systemctl restart smartdns'

reset_state
DNS_TEST_IPSEC_START_EMPTY=1 DNS_TEST_ROUTE_STATE=missing_all \
  DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 \
  run_manager watchdog
assert_call_count \
  'swanctl --load-all --noprompt' 0
assert_contains "$calls" 'swanctl --initiate --child ai'
assert_contains "$calls" 'swanctl --initiate --child cn'
assert_contains "$calls" 'ip route replace default dev ipsec-ai src 10.64.0.1 table 301'
assert_contains "$calls" 'ip route replace default dev ipsec-cn src 10.64.0.2 table 351'
assert_not_contains "$calls" 'nft-batch add element inet dnscomplex ai_ready4'
assert_not_contains "$calls" 'nft-batch add element inet dnscomplex cn_ready4'
DNS_TEST_IPSEC_START_EMPTY=1 DNS_TEST_ROUTE_STATE=missing_all \
  DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 \
  run_manager watchdog
assert_contains "$calls" 'nft-batch add element inet dnscomplex ai_ready4'
assert_contains "$calls" 'nft-batch add element inet dnscomplex cn_ready4'
assert_call_before 'swanctl --initiate --child ai' \
  'ip route replace default dev ipsec-ai src 10.64.0.1 table 301'

reset_state
: >"$ipsec_ai_snat_vip"
: >"$ipsec_cn_snat_vip"
if DNS_TEST_NFT_ADD_FAIL=1 DNS_TEST_AI_VIP=10.64.0.1 \
   DNS_TEST_CN_VIP=10.64.0.2 \
   run_manager routes up >"$tmpdir/routes-nat-failure.log" 2>&1; then
  fail "policy routes reported success after dynamic SNAT failure"
fi
assert_contains "$calls" 'nft add rule inet dnscomplex postrouting'
assert_not_contains "$calls" 'nft-batch add element inet dnscomplex ai_ready4'
assert_not_contains "$calls" 'nft-batch add element inet dnscomplex cn_ready4'
printf '10.64.0.1\n' >"$ipsec_ai_snat_vip"
printf '10.64.0.2\n' >"$ipsec_cn_snat_vip"

reset_state
PATH="$fakebin:$PATH" \
DNSCOMPLEX_CONFIG="$config" \
DNSCOMPLEX_BASE="$state" \
DNSCOMPLEX_RUN_DIR="$run_dir" \
DNSCOMPLEX_FS_ROOT="$fake_root" \
DNS_TEST_CALLS="$calls" \
DNS_TEST_SYSTEMCTL_STATE="$systemctl_state" \
DNS_TEST_SYSTEMCTL_FAIL_STATE="$systemctl_fail_state" \
bash -c '
  source "$1"
  load_config
  AI_EGRESS_MODE=xray
  CN_EGRESS_MODE=ipsec
  egress_ready_cmd xray
' _ "$manager"
assert_contains "$calls" 'nft-batch add element inet dnscomplex ai_ready4'
assert_not_contains "$calls" 'nft-batch add element inet dnscomplex cn_ready4'

reset_state
run_manager egress-ready xray
assert_not_contains "$calls" 'nft-batch flush set inet dnscomplex ai_ready4'
assert_not_contains "$calls" 'nft-batch flush set inet dnscomplex cn_ready4'

reset_state
DNS_TEST_IPSEC_START_EMPTY=1 \
  DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 \
  DNS_TEST_SWAN_SUCCESS_NOISE=1 \
  run_manager ipsec-ready >"$tmpdir/ipsec-ready-success.log" 2>&1
assert_contains "$calls" 'ip -4 -o addr show dev eth0 scope global'
assert_contains "$calls" 'swanctl --stats'
assert_contains "$calls" 'swanctl --load-all --noprompt'
assert_contains "$calls" 'swanctl --initiate --child ai'
assert_contains "$calls" 'swanctl --initiate --child cn'
assert_call_before 'ip -4 -o addr show dev eth0 scope global' 'swanctl --load-all --noprompt'
assert_call_before 'swanctl --load-all --noprompt' 'swanctl --initiate --child ai'
assert_not_contains "$tmpdir/ipsec-ready-success.log" 'simulated optional plugin warning'

reset_state
if ! DNS_TEST_WAN_ROUTE=filtered_dev_elided DNS_TEST_IPSEC_START_EMPTY=1 \
     DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 \
     DNSCOMPLEX_IPSEC_BOOT_TIMEOUT=5 \
     run_manager ipsec-ready >"$tmpdir/ipsec-filtered-route.log" 2>&1; then
  fail "IPsec readiness rejected a valid default route after iproute2 elided its device"
fi
grep -Fxq 'ip -4 route show default' "$calls" ||
  fail "IPsec readiness did not inspect complete default routes"

reset_state
if DNS_TEST_WAN_ADDRESS=wrong DNS_TEST_REAL_SLEEP=1 \
   DNSCOMPLEX_IPSEC_BOOT_TIMEOUT=1 \
   run_manager ipsec-ready >"$tmpdir/ipsec-underlay-timeout.log" 2>&1; then
  fail "IPsec readiness accepted the wrong DHCP address"
fi
assert_contains "$calls" 'ip -4 -o addr show dev eth0 scope global'
assert_not_contains "$calls" 'swanctl --load-all --noprompt'

reset_state
if DNS_TEST_WAN_ROUTE=missing DNS_TEST_REAL_SLEEP=1 \
   DNSCOMPLEX_IPSEC_BOOT_TIMEOUT=1 \
   run_manager ipsec-ready >"$tmpdir/ipsec-route-timeout.log" 2>&1; then
  fail "IPsec readiness accepted a missing RouterOS default route"
fi
grep -Fxq 'ip -4 route show default' "$calls" ||
  fail "IPsec readiness did not inspect complete default routes"
assert_not_contains "$calls" 'swanctl --load-all --noprompt'

reset_state
if DNS_TEST_VICI_AVAILABLE=0 DNS_TEST_REAL_SLEEP=1 \
   DNSCOMPLEX_IPSEC_BOOT_TIMEOUT=2 \
   run_manager ipsec-ready >"$tmpdir/ipsec-vici-timeout.log" 2>&1; then
  fail "IPsec readiness accepted an unavailable VICI daemon"
fi
assert_contains "$calls" 'swanctl --stats'
assert_not_contains "$calls" 'swanctl --load-all --noprompt'

ai_xray_boot_config="$tmpdir/ai-xray-boot.env"
cp "$config" "$ai_xray_boot_config"
printf '%s\n' 'AI_EGRESS_MODE=xray' >>"$ai_xray_boot_config"
reset_state
DNS_TEST_CONFIG="$ai_xray_boot_config" DNS_TEST_IPSEC_START_EMPTY=1 \
  DNS_TEST_CN_VIP=10.64.0.2 \
  run_manager ipsec-ready
assert_not_contains "$calls" 'swanctl --initiate --child ai'
assert_contains "$calls" 'swanctl --initiate --child cn'

both_xray_boot_config="$tmpdir/both-xray-boot.env"
cp "$ai_xray_boot_config" "$both_xray_boot_config"
printf '%s\n' 'CN_EGRESS_MODE=xray' >>"$both_xray_boot_config"
reset_state
DNS_TEST_CONFIG="$both_xray_boot_config" run_manager ipsec-ready
assert_not_contains "$calls" 'ip -4 -o addr show dev eth0 scope global'
assert_not_contains "$calls" 'swanctl --load-all --noprompt'
assert_not_contains "$calls" 'swanctl --initiate --child'

reset_state
DNS_TEST_CONFIG="$both_xray_boot_config" \
  DNS_TEST_WAN_ROUTE=filtered_dev_elided \
  run_manager network-ready
assert_contains "$calls" 'ip -4 -o addr show dev eth0 scope global'
grep -Fxq 'ip -4 route show default' "$calls" ||
  fail "network readiness did not inspect complete default routes"
assert_not_contains "$calls" 'swanctl'

reset_state
if DNS_TEST_CONFIG="$both_xray_boot_config" DNS_TEST_WAN_ROUTE=missing \
   DNS_TEST_REAL_SLEEP=1 DNSCOMPLEX_IPSEC_BOOT_TIMEOUT=1 \
   run_manager network-ready >"$tmpdir/network-ready-timeout.log" 2>&1; then
  fail "network readiness accepted a missing RouterOS default route"
fi
assert_not_contains "$calls" 'swanctl'

vlan_boot_config="$tmpdir/vlan-boot.env"
cat >"$vlan_boot_config" <<'EOF'
DEPLOY_MODE=vlan-gateway
WAN_IFACE=eth0
TRANSIT_VLAN_ID=10
LINUX_TRANSIT_IPV4=10.255.10.2
ROUTEROS_TRANSIT_IPV4=10.255.10.1
AI_EGRESS_MODE=ipsec
CN_EGRESS_MODE=xray
EOF
reset_state
DNS_TEST_CONFIG="$vlan_boot_config" DNS_TEST_IPSEC_START_EMPTY=1 \
  DNS_TEST_UNDERLAY_IFACE=eth0.10 DNS_TEST_UNDERLAY_IPV4=10.255.10.2 \
  DNS_TEST_UNDERLAY_GATEWAY=10.255.10.1 DNS_TEST_AI_VIP=10.64.0.1 \
  run_manager ipsec-ready
assert_contains "$calls" 'ip -4 -o addr show dev eth0.10 scope global'
grep -Fxq 'ip -4 route show default' "$calls" ||
  fail "VLAN IPsec readiness did not inspect complete default routes"
assert_contains "$calls" 'swanctl --initiate --child ai'
assert_not_contains "$calls" 'swanctl --initiate --child cn'

legacy_root="$tmpdir/legacy-root"
mkdir -p "$legacy_root/etc/dnscomplex" "$legacy_root/etc/sing-box"
cp "$config" "$legacy_root/etc/dnscomplex/config.env"
mkdir -p "$legacy_root/usr/local/lib/dnscomplex"
cp "$fake_root/usr/local/lib/dnscomplex/profile-dataplane-probe.py" \
  "$legacy_root/usr/local/lib/dnscomplex/profile-dataplane-probe.py"
chmod 0755 "$legacy_root/usr/local/lib/dnscomplex/profile-dataplane-probe.py"
cat >"$legacy_root/etc/sing-box/config.json" <<'JSON'
{"outbounds":[{"tag":"ai-ipsec","inet4_bind_address":"10.64.0.1"},{"tag":"cn-ipsec","inet4_bind_address":"10.64.0.2"}]}
JSON
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
DNS_TEST_AI_VIP=10.64.0.1 \
DNS_TEST_CN_VIP=10.64.0.2 \
"$manager" watchdog
assert_not_contains "$calls" 'restart smartdns'

ai_xray_config="$tmpdir/ai-xray.env"
cp "$config" "$ai_xray_config"
printf '%s\n' 'AI_EGRESS_MODE=xray' >>"$ai_xray_config"
DNS_TEST_CONFIG="$ai_xray_config" DNS_TEST_ROUTE_STATE=missing_all run_watchdog healthy
assert_contains "$calls" 'ip rule add fwmark 0x3F1 table 351 priority 10251'
assert_contains "$calls" \
  'ip route replace default dev ipsec-cn src 10.64.0.2 table 351'
assert_not_contains "$calls" 'ip rule add fwmark 0x3A1 table 301'
assert_not_contains "$calls" 'ip route replace default dev ipsec-ai'
DNS_TEST_CONFIG="$ai_xray_config" DNS_TEST_ROUTE_STATE=missing_cn \
  DNS_TEST_AI_VIP=10.64.0.1 run_watchdog healthy
assert_contains "$calls" 'ip rule add fwmark 0x351 table 351'
assert_contains "$calls" \
  'ip route replace default dev ipsec-cn src 10.64.0.2 table 351'
assert_not_contains "$calls" 'ip rule add fwmark 0x301 table 301'
assert_not_contains "$calls" 'ip route replace default dev ipsec-ai'
assert_not_contains "$calls" 'dnscomplex-ai-snat'

cn_xray_config="$tmpdir/cn-xray.env"
cp "$config" "$cn_xray_config"
printf '%s\n' 'CN_EGRESS_MODE=xray' >>"$cn_xray_config"
DNS_TEST_CONFIG="$cn_xray_config" DNS_TEST_ROUTE_STATE=missing_cn run_watchdog healthy
assert_not_contains "$calls" 'ip rule add fwmark'
DNS_TEST_CONFIG="$cn_xray_config" DNS_TEST_ROUTE_STATE=missing_all \
  DNS_TEST_CN_VIP=10.64.0.2 run_watchdog healthy
assert_contains "$calls" 'ip rule add fwmark 0x301 table 301'
assert_contains "$calls" \
  'ip route replace default dev ipsec-ai src 10.64.0.1 table 301'
assert_not_contains "$calls" 'ip rule add fwmark 0x351 table 351'
assert_not_contains "$calls" 'ip route replace default dev ipsec-cn'
assert_not_contains "$calls" 'dnscomplex-cn-snat'

printf 'ai-last-known-good\n' >"$state/nftset-ai.last_refresh"
printf 'cn-last-known-good\n' >"$state/nftset-cn.last_refresh"
reset_state
if DNS_TEST_SCENARIO=external_down run_manager refresh-nftsets \
   >"$tmpdir/nftset-zero-answer.log" 2>&1; then
  fail "zero-answer nftset refresh was reported as healthy"
fi
[[ "$(cat "$state/nftset-ai.last_refresh")" == "ai-last-known-good" ]] ||
  fail "zero-answer AI refresh changed freshness timestamp"
[[ "$(cat "$state/nftset-cn.last_refresh")" == "cn-last-known-good" ]] ||
  fail "zero-answer CN refresh changed freshness timestamp"
assert_not_contains "$calls" 'nft flush set'

rm -f "$state/nftset-ai.last_refresh" "$state/nftset-cn.last_refresh"
reset_state
DNS_TEST_SCENARIO=nft_success run_manager refresh-nftsets
assert_contains "$calls" 'nft-batch add element inet dnscomplex ai4'
assert_contains "$calls" 'nft-batch add element inet dnscomplex cn4'
[[ "$(cat "$state/nftset-ai.last_refresh")" =~ ^[0-9]+$ ]] ||
  fail "successful AI refresh did not update freshness"
[[ "$(cat "$state/nftset-cn.last_refresh")" =~ ^[0-9]+$ ]] ||
  fail "successful CN refresh did not update freshness"
assert_not_contains "$calls" 'nft flush set'

printf 'ai-before-partial\n' >"$state/nftset-ai.last_refresh"
printf 'cn-before-partial\n' >"$state/nftset-cn.last_refresh"
reset_state
if DNS_TEST_SCENARIO=nft_ai_down run_manager refresh-nftsets \
   >"$tmpdir/nftset-ai-down.log" 2>&1; then
  fail "one-profile nftset failure was reported as healthy"
fi
[[ "$(cat "$state/nftset-ai.last_refresh")" == "ai-before-partial" ]] ||
  fail "failed AI profile changed freshness timestamp"
[[ "$(cat "$state/nftset-cn.last_refresh")" =~ ^[0-9]+$ ]] ||
  fail "healthy CN profile was not refreshed independently"
assert_not_contains "$calls" 'nft-batch add element inet dnscomplex ai4'
assert_contains "$calls" 'nft-batch add element inet dnscomplex cn4'

printf 'ai-before-private\n' >"$state/nftset-ai.last_refresh"
printf 'cn-before-private\n' >"$state/nftset-cn.last_refresh"
reset_state
if DNS_TEST_SCENARIO=nft_private run_manager refresh-nftsets \
   >"$tmpdir/nftset-private.log" 2>&1; then
  fail "reserved-address nftset refresh was reported as healthy"
fi
[[ "$(cat "$state/nftset-ai.last_refresh")" == "ai-before-private" ]] ||
  fail "reserved AI answer changed freshness timestamp"
[[ "$(cat "$state/nftset-cn.last_refresh")" == "cn-before-private" ]] ||
  fail "reserved CN answer changed freshness timestamp"
assert_not_contains "$calls" 'nft-batch add element'

printf 'ai-before-batch-failure\n' >"$state/nftset-ai.last_refresh"
printf 'cn-before-batch-failure\n' >"$state/nftset-cn.last_refresh"
reset_state
if DNS_TEST_SCENARIO=nft_success DNS_TEST_NFT_BATCH_FAIL_PROFILE=ai \
   run_manager refresh-nftsets >"$tmpdir/nftset-batch-failure.log" 2>&1; then
  fail "failed AI nft transaction was reported as healthy"
fi
[[ "$(cat "$state/nftset-ai.last_refresh")" == "ai-before-batch-failure" ]] ||
  fail "failed AI nft transaction changed freshness timestamp"
[[ "$(cat "$state/nftset-cn.last_refresh")" =~ ^[0-9]+$ ]] ||
  fail "AI transaction failure prevented independent CN refresh"

rm -f "$state/nftset-ai.last_refresh" "$state/nftset-cn.last_refresh"
reset_state
DNS_TEST_SCENARIO=nft_success DNS_TEST_NFT_EXISTING=1 \
  run_manager refresh-nftsets
assert_not_contains "$calls" 'nft-batch add element'
[[ "$(cat "$state/nftset-ai.last_refresh")" =~ ^[0-9]+$ ]] ||
  fail "existing AI candidates did not update freshness"
[[ "$(cat "$state/nftset-cn.last_refresh")" =~ ^[0-9]+$ ]] ||
  fail "existing CN candidates did not update freshness"

rm -f "$state/nftset-ai.last_refresh" "$state/nftset-cn.last_refresh"
reset_state
DNS_TEST_SCENARIO=nft_success DNS_TEST_NFT_RACE_PROFILE=ai \
  run_manager refresh-nftsets
[[ -f "$nft_race" ]] || fail "AI nft race scenario did not execute"
[[ "$(cat "$state/nftset-ai.last_refresh")" =~ ^[0-9]+$ ]] ||
  fail "concurrent AI insertion was not accepted"
[[ "$(cat "$state/nftset-cn.last_refresh")" =~ ^[0-9]+$ ]] ||
  fail "AI insertion race prevented CN refresh"

printf 'ai-before-temp-failure\n' >"$state/nftset-ai.last_refresh"
rm -f "$state/nftset-cn.last_refresh"
reset_state
if DNS_TEST_SCENARIO=nft_success DNS_TEST_MKTEMP_FAIL=nftset-ai \
   run_manager refresh-nftsets >"$tmpdir/nftset-temp-failure.log" 2>&1; then
  fail "nftset temporary-file failure was reported as healthy"
fi
[[ "$(cat "$state/nftset-ai.last_refresh")" == "ai-before-temp-failure" ]] ||
  fail "AI temporary-file failure changed freshness timestamp"
[[ "$(cat "$state/nftset-cn.last_refresh")" =~ ^[0-9]+$ ]] ||
  fail "AI temporary-file failure prevented independent CN refresh"
if compgen -G "$run_dir/.nftset-*" >/dev/null; then
  fail "nftset refresh left a temporary file"
fi

for rel in \
  etc/dnscomplex \
  etc/sing-box \
  etc/smartdns \
  etc/AdGuardHome \
  etc/swanctl \
  etc/strongswan.d/charon \
  etc/nftables.d \
  etc/systemd/system \
  usr/local/sbin \
  usr/local/libexec \
  usr/local/lib/dnscomplex-redact \
  usr/local/lib/dnscomplex-web \
  var/lib/dnscomplex; do
  mkdir -p "$fake_root/$rel"
done
cp "$render_root/usr/local/libexec/dnscomplex-restore-recover" \
  "$fake_root/usr/local/libexec/dnscomplex-restore-recover"
cp "$render_root/usr/local/lib/dnscomplex-redact/redact.py" \
  "$fake_root/usr/local/lib/dnscomplex-redact/redact.py"
printf 'fixture\n' >"$fake_root/etc/dnscomplex/config.env"
printf 'fixture\n' >"$fake_root/etc/nftables.d/dnscomplex.nft"
printf 'dhcp-plugin-before\n' >"$fake_root/etc/strongswan.d/charon/dhcp.conf"
printf 'web-unit-before\n' >"$fake_root/etc/systemd/system/dnscomplex-web.service"
printf 'manager-before\n' >"$fake_root/usr/local/sbin/dnscomplex"
printf 'web-before\n' >"$fake_root/usr/local/lib/dnscomplex-web/app.py"

live_db="$fake_root/var/lib/dnscomplex/metrics.sqlite3"
python3 - "$live_db" <<'PY'
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
db.execute("PRAGMA journal_mode=WAL")
db.execute("CREATE TABLE samples(ts INTEGER NOT NULL, value REAL NOT NULL)")
db.execute("INSERT INTO samples VALUES (1, 1.0)")
db.commit()
db.close()
PY

python3 - "$live_db" <<'PY' &
import sqlite3
import sys
import time

db = sqlite3.connect(sys.argv[1])
for value in range(2, 1000):
    db.execute("INSERT INTO samples VALUES (?, ?)", (value, float(value)))
    db.commit()
    time.sleep(0.002)
db.close()
PY
writer_pid=$!

archive="$tmpdir/live-backup.tar.gz"
extract="$tmpdir/extracted"
mkdir -p "$extract"
DNS_TEST_INACTIVE_UNIT=systemd-resolved.service \
DNS_TEST_DISABLED_UNIT=systemd-resolved.service \
run_manager backup "$archive"
kill "$writer_pid" 2>/dev/null || true
wait "$writer_pid" 2>/dev/null || true
writer_pid=""

tar -tzf "$archive" | grep -Fxq './var/lib/dnscomplex/metrics.sqlite3' ||
  fail "backup archive is missing the SQLite snapshot"
tar -tzf "$archive" | grep -Fxq './.dnscomplex-backup/format' ||
  fail "backup archive is missing its format marker"
tar -tzf "$archive" | grep -Fxq './.dnscomplex-backup/manifest.tsv' ||
  fail "backup archive is missing its managed-path manifest"
tar -tzf "$archive" | grep -Fxq './.dnscomplex-backup/service-state.tsv' ||
  fail "backup archive is missing its service-state snapshot"
tar -tzf "$archive" | grep -Fxq './etc/strongswan.d/charon/dhcp.conf' ||
  fail "backup archive is missing a managed strongSwan plugin configuration"
tar -tzf "$archive" | grep -Fxq './etc/systemd/system/dnscomplex-web.service' ||
  fail "backup archive is missing a managed systemd unit"
tar -tzf "$archive" | grep -Fxq './usr/local/sbin/dnscomplex' ||
  fail "backup archive is missing the management executable"
tar -tzf "$archive" | grep -Fxq './usr/local/lib/dnscomplex-redact/redact.py' ||
  fail "backup archive is missing the structural redactor"
if tar -tzf "$archive" | grep -Fxq './'; then
  fail "backup archive contains the filesystem root entry"
fi
if tar -tzf "$archive" | grep -Eq 'metrics[.]sqlite3-(wal|shm|journal)$'; then
  fail "backup contains transient SQLite sidecar files"
fi
tar -xzf "$archive" -C "$extract"
python3 - "$extract/var/lib/dnscomplex/metrics.sqlite3" <<'PY'
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
assert db.execute("SELECT COUNT(*) FROM samples").fetchone()[0] > 0
db.close()
PY
[[ "$(file_mode "$archive")" == "600" ]] ||
  fail "backup archive mode is not 0600"

grep -Fxq $'present\tetc/strongswan.d/charon/dhcp.conf' \
  "$extract/.dnscomplex-backup/manifest.tsv" ||
  fail "backup manifest did not record a present managed path"
grep -Fxq $'absent\tetc/systemd/network/10-dnscomplex-vlans.netdev' \
  "$extract/.dnscomplex-backup/manifest.tsv" ||
  fail "backup manifest did not record an absent managed path"
grep -Fq $'smartdns.service\tenabled\tactive' \
  "$extract/.dnscomplex-backup/service-state.tsv" ||
  fail "backup did not capture an enabled active service"
grep -Fq $'systemd-resolved.service\tdisabled\tinactive' \
  "$extract/.dnscomplex-backup/service-state.tsv" ||
  fail "backup did not capture a disabled inactive service"

prepare_changed_restore_state() {
  printf 'dhcp-plugin-after\n' >"$fake_root/etc/strongswan.d/charon/dhcp.conf"
  mkdir -p "$fake_root/etc/systemd/network"
  printf 'stale-network-file\n' \
    >"$fake_root/etc/systemd/network/10-dnscomplex-vlans.netdev"
  printf 'must-survive\n' >"$fake_root/etc/unrelated.conf"
}

assert_changed_restore_state_preserved() {
  local leftover
  [[ "$(cat "$fake_root/etc/strongswan.d/charon/dhcp.conf")" == "dhcp-plugin-after" ]] ||
    fail "failed restore did not preserve the current managed file"
  [[ "$(cat "$fake_root/etc/systemd/network/10-dnscomplex-vlans.netdev")" == "stale-network-file" ]] ||
    fail "failed restore did not preserve a current managed path absent from the archive"
  [[ "$(cat "$fake_root/etc/unrelated.conf")" == "must-survive" ]] ||
    fail "failed restore changed an unrelated file"
  leftover=$(find "$fake_root" -name '.dnscomplex-restore.*' -print)
  if [[ -n "$leftover" ]]; then
    [[ ! -f "$tmpdir/restore-stage-failure.log" ]] ||
      sed 's/^/restore-log: /' "$tmpdir/restore-stage-failure.log" >&2
    fail "failed restore left a sibling staging directory: $leftover"
  fi
  if find "$fake_root/var/lib/dnscomplex-restore" -name 'transaction.*' -print -quit 2>/dev/null |
     grep -q .; then
    fail "failed restore left a completed recovery transaction"
  fi
}

prepare_changed_restore_state
reset_state
chmod 0644 "$fake_root/usr/local/libexec/dnscomplex-restore-recover"
if run_manager restore "$archive" \
   >"$tmpdir/restore-helper-missing.log" 2>&1; then
  fail "restore started without an executable recovery helper"
fi
assert_changed_restore_state_preserved
assert_not_contains "$calls" 'systemctl stop '
chmod 0755 "$fake_root/usr/local/libexec/dnscomplex-restore-recover"

prepare_changed_restore_state
reset_state
if DNS_TEST_ACTIVATING_UNIT=dnscomplex-network-ready.service \
   DNS_TEST_RESTORE_STAGE_FAIL=1 run_manager restore "$archive" \
   >"$tmpdir/restore-stage-failure.log" 2>&1; then
  fail "restore accepted a candidate staging failure"
fi
assert_changed_restore_state_preserved
assert_contains "$calls" 'systemctl stop dnscomplex-network-ready.service'
assert_contains "$calls" 'systemctl daemon-reload'
assert_call_before 'systemctl stop dnscomplex-network-ready.service' \
  'cp -a -- '

prepare_changed_restore_state
reset_state
if DNS_TEST_RESTORE_FAIL_MOVE=2 run_manager restore "$archive" \
   >"$tmpdir/restore-move-failure.log" 2>&1; then
  fail "restore accepted an injected rename failure"
fi
assert_changed_restore_state_preserved
assert_contains "$calls" 'systemctl stop smartdns.service'
assert_call_before 'systemctl stop smartdns.service' 'mv -- '
assert_call_before 'systemctl stop dnscomplex-network-ready.service' \
  'cp -a -- '

prepare_changed_restore_state
reset_state
if DNS_TEST_SYSTEMCTL_FAIL_ONCE=daemon-reload run_manager restore "$archive" \
   >"$tmpdir/restore-service-failure.log" 2>&1; then
  fail "restore accepted a service-state application failure"
fi
assert_changed_restore_state_preserved
assert_call_count 'systemctl daemon-reload' 2

prepare_changed_restore_state
reset_state
if DNS_TEST_RESTART_FAIL_ONCE_UNIT=smartdns.service run_manager restore "$archive" \
   >"$tmpdir/restore-partial-service-failure.log" 2>&1; then
  fail "restore accepted a partial service-state application failure"
fi
assert_changed_restore_state_preserved
assert_call_count 'systemctl stop dnscomplex-network-ready.service' 2

printf 'dhcp-plugin-after\n' >"$fake_root/etc/strongswan.d/charon/dhcp.conf"
mkdir -p "$fake_root/etc/systemd/network"
printf 'stale-network-file\n' \
  >"$fake_root/etc/systemd/network/10-dnscomplex-vlans.netdev"
printf 'must-survive\n' >"$fake_root/etc/unrelated.conf"
reset_state
DNS_TEST_INACTIVE_UNIT=systemd-resolved.service \
DNS_TEST_DISABLED_UNIT=systemd-resolved.service \
run_manager restore "$archive"
[[ "$(cat "$fake_root/etc/strongswan.d/charon/dhcp.conf")" == "dhcp-plugin-before" ]] ||
  fail "restore did not replace a changed managed file"
[[ ! -e "$fake_root/etc/systemd/network/10-dnscomplex-vlans.netdev" ]] ||
  fail "restore did not remove a managed file that was absent at backup time"
[[ "$(cat "$fake_root/etc/unrelated.conf")" == "must-survive" ]] ||
  fail "restore changed an unrelated file"
assert_contains "$calls" 'systemctl daemon-reload'
assert_contains "$calls" 'systemctl enable smartdns.service'
assert_contains "$calls" 'systemctl restart smartdns.service'
assert_call_before 'systemctl restart dnscomplex-network-ready.service' \
  'systemctl restart dnscomplex-routing.service'
assert_call_before 'systemctl restart dnscomplex-routing.service' \
  'systemctl restart smartdns.service'
assert_contains "$calls" 'systemctl disable systemd-resolved.service'
assert_contains "$calls" 'systemctl stop systemd-resolved.service'
assert_not_contains "$calls" 'dnscomplex-restore-recovery.service'
leftover=$(find "$fake_root" -name '.dnscomplex-restore.*' -print)
if [[ -n "$leftover" ]]; then
  fail "successful restore left a sibling staging directory: $leftover"
fi
if find "$fake_root/var/lib/dnscomplex-restore" -name 'transaction.*' -print -quit 2>/dev/null |
   grep -q .; then
  fail "successful restore left a recovery transaction"
fi

compat_stage="$tmpdir/format2-compat-stage"
compat_archive="$tmpdir/format2-without-redactor.tar.gz"
cp -a "$extract" "$compat_stage"
rm -rf "$compat_stage/usr/local/lib/dnscomplex-redact"
grep -Fv $'\tusr/local/lib/dnscomplex-redact' \
  "$compat_stage/.dnscomplex-backup/manifest.tsv" \
  >"$compat_stage/.dnscomplex-backup/manifest.tsv.new"
mv "$compat_stage/.dnscomplex-backup/manifest.tsv.new" \
  "$compat_stage/.dnscomplex-backup/manifest.tsv"
/usr/bin/tar -czf "$compat_archive" -C "$compat_stage" \
  ./.dnscomplex-backup ./etc ./usr ./var
printf 'current-redactor\n' \
  >"$fake_root/usr/local/lib/dnscomplex-redact/redact.py"
reset_state
DNS_TEST_INACTIVE_UNIT=systemd-resolved.service \
DNS_TEST_DISABLED_UNIT=systemd-resolved.service \
run_manager restore "$compat_archive"
[[ "$(cat "$fake_root/usr/local/lib/dnscomplex-redact/redact.py")" == "current-redactor" ]] ||
  fail "format-2 compatibility restore replaced an optional path omitted by the archive"

recovery_helper="$render_root/usr/local/libexec/dnscomplex-restore-recover"
crash_dst="$fake_root/etc/dnscomplex/crash.conf"
crash_slot="$fake_root/etc/dnscomplex/.dnscomplex-restore.crash.conf.CRASH1"
crash_tx="$fake_root/var/lib/dnscomplex-restore/transaction.crash"
mkdir -p "$crash_slot" "$crash_tx"
printf 'before-crash\n' >"$crash_slot/before"
printf 'after-crash\n' >"$crash_dst"
printf 'present\t%s\t%s\t1' "$crash_dst" "$crash_slot" \
  >"$crash_tx/entries.tsv"
: >"$crash_tx/pre-service-state.tsv"
: >"$crash_tx/services-quiescing"
reset_state
PATH="$fakebin:$PATH" \
DNS_TEST_CALLS="$calls" \
DNS_TEST_RESTORE_MOVE_COUNTER="$restore_move_counter" \
DNSCOMPLEX_FS_ROOT="$fake_root" \
DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
DNSCOMPLEX_OPERATION_HELPER="$fake_root/usr/local/libexec/dnscomplex-operation" \
DNSCOMPLEX_RESTORE_STATE_DIR="$fake_root/var/lib/dnscomplex-restore" \
  "$recovery_helper" --files
assert_not_contains "$calls" 'systemctl '
[[ "$(cat "$crash_dst")" == "before-crash" ]] ||
  fail "boot recovery did not restore the pre-transaction file"
[[ -f "$crash_tx/files-recovered" && ! -e "$crash_slot" ]] ||
  fail "early boot recovery did not retain the deferred service journal"
PATH="$fakebin:$PATH" \
DNS_TEST_CALLS="$calls" \
DNS_TEST_SYSTEMCTL_STATE="$systemctl_state" \
DNS_TEST_SYSTEMCTL_FAIL_STATE="$systemctl_fail_state" \
DNS_TEST_RESTORE_MOVE_COUNTER="$restore_move_counter" \
DNSCOMPLEX_FS_ROOT="$fake_root" \
DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
DNSCOMPLEX_OPERATION_HELPER="$fake_root/usr/local/libexec/dnscomplex-operation" \
DNSCOMPLEX_RESTORE_STATE_DIR="$fake_root/var/lib/dnscomplex-restore" \
  "$recovery_helper" --services
[[ ! -e "$crash_tx" ]] ||
  fail "late boot recovery did not clean the completed transaction"

partial_cleanup="$fake_root/var/lib/dnscomplex-restore/cleanup.transaction.partial"
mkdir -p "$partial_cleanup"
printf 'partial-cleanup\n' >"$partial_cleanup/leftover"
PATH="$fakebin:$PATH" \
DNS_TEST_CALLS="$calls" \
DNS_TEST_RESTORE_MOVE_COUNTER="$restore_move_counter" \
DNSCOMPLEX_FS_ROOT="$fake_root" \
DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
DNSCOMPLEX_OPERATION_HELPER="$fake_root/usr/local/libexec/dnscomplex-operation" \
DNSCOMPLEX_RESTORE_STATE_DIR="$fake_root/var/lib/dnscomplex-restore" \
  "$recovery_helper" --files
[[ ! -e "$partial_cleanup" ]] ||
  fail "recovery did not remove an interrupted cleanup directory"

committed_victim="$tmpdir/committed-journal-victim"
committed_tx="$fake_root/var/lib/dnscomplex-restore/transaction.bad-committed"
mkdir -p "$committed_victim" "$committed_tx"
printf 'keep\n' >"$committed_victim/value"
printf 'present\t%s\t%s\t0\n' \
  "$fake_root/etc/dnscomplex/config.env" "$committed_victim" \
  >"$committed_tx/entries.tsv"
: >"$committed_tx/committed"
if PATH="$fakebin:$PATH" \
   DNS_TEST_CALLS="$calls" \
   DNS_TEST_RESTORE_MOVE_COUNTER="$restore_move_counter" \
   DNSCOMPLEX_FS_ROOT="$fake_root" \
DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
DNSCOMPLEX_OPERATION_HELPER="$fake_root/usr/local/libexec/dnscomplex-operation" \
DNSCOMPLEX_RESTORE_STATE_DIR="$fake_root/var/lib/dnscomplex-restore" \
     "$recovery_helper" --transaction "$committed_tx" \
     >"$tmpdir/bad-committed-recovery.log" 2>&1; then
  fail "recovery accepted an unsafe committed journal"
fi
[[ "$(cat "$committed_victim/value")" == "keep" ]] ||
  fail "recovery removed a path from an unsafe committed journal"
rm -rf "$committed_tx" "$committed_victim"

unsafe_service_tx="$fake_root/var/lib/dnscomplex-restore/transaction.unsafe-service"
mkdir -p "$unsafe_service_tx"
: >"$unsafe_service_tx/entries.tsv"
: >"$unsafe_service_tx/services-quiescing"
printf 'unmanaged-dangerous.service\tenabled\tactive\n' \
  >"$unsafe_service_tx/pre-service-state.tsv"
reset_state
if PATH="$fakebin:$PATH" \
   DNS_TEST_CALLS="$calls" \
   DNS_TEST_SYSTEMCTL_STATE="$systemctl_state" \
   DNS_TEST_SYSTEMCTL_FAIL_STATE="$systemctl_fail_state" \
   DNS_TEST_RESTORE_MOVE_COUNTER="$restore_move_counter" \
   DNSCOMPLEX_FS_ROOT="$fake_root" \
DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
DNSCOMPLEX_OPERATION_HELPER="$fake_root/usr/local/libexec/dnscomplex-operation" \
DNSCOMPLEX_RESTORE_STATE_DIR="$fake_root/var/lib/dnscomplex-restore" \
     "$recovery_helper" --transaction "$unsafe_service_tx" \
     >"$tmpdir/unsafe-service-recovery.log" 2>&1; then
  fail "recovery accepted an unmanaged service-state unit"
fi
assert_not_contains "$calls" 'unmanaged-dangerous.service'
rm -rf "$unsafe_service_tx"

invalid_state_dir="$tmpdir/restore-state-is-file"
printf 'not-a-directory\n' >"$invalid_state_dir"
if PATH="$fakebin:$PATH" \
   DNS_TEST_CALLS="$calls" \
   DNS_TEST_RESTORE_MOVE_COUNTER="$restore_move_counter" \
   DNSCOMPLEX_FS_ROOT="$fake_root" \
DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
DNSCOMPLEX_OPERATION_HELPER="$fake_root/usr/local/libexec/dnscomplex-operation" \
DNSCOMPLEX_RESTORE_STATE_DIR="$invalid_state_dir" \
     "$recovery_helper" >"$tmpdir/invalid-recovery-state-dir.log" 2>&1; then
  fail "recovery accepted a regular file as its state directory"
fi

invalid_state_stage="$tmpdir/invalid-service-state-stage"
invalid_state_archive="$tmpdir/invalid-service-state.tar.gz"
cp -a "$extract" "$invalid_state_stage"
{
  printf 'smartdns.service\tenabled\tactive\n'
  printf 'unmanaged-dangerous.service\tdisabled\tinactive\n'
} >"$invalid_state_stage/.dnscomplex-backup/service-state.tsv"
/usr/bin/tar -czf "$invalid_state_archive" -C "$invalid_state_stage" \
  ./.dnscomplex-backup \
  ./etc \
  ./usr \
  ./var
printf 'must-not-change\n' >"$fake_root/etc/strongswan.d/charon/dhcp.conf"
reset_state
if run_manager restore "$invalid_state_archive" \
   >"$tmpdir/invalid-service-state.log" 2>&1; then
  fail "restore accepted an unmanaged service-state entry"
fi
[[ "$(cat "$fake_root/etc/strongswan.d/charon/dhcp.conf")" == "must-not-change" ]] ||
  fail "restore changed managed files before validating all service-state metadata"
assert_not_contains "$calls" 'systemctl daemon-reload'

restore_root="$tmpdir/restore-root-mode"
mkdir -p "$restore_root"
chmod 0711 "$restore_root"
tar -xzf "$archive" -C "$restore_root"
[[ "$(file_mode "$restore_root")" == "711" ]] ||
  fail "backup extraction changed the restore root mode"

legacy_stage="$tmpdir/legacy-backup-stage"
legacy_archive="$tmpdir/legacy-backup.tar.gz"
legacy_restore_root="$tmpdir/legacy-restore-root"
mkdir -p \
  "$legacy_stage/etc/dnscomplex" \
  "$legacy_restore_root/etc/smartdns" \
  "$legacy_restore_root/usr/local/libexec"
printf 'legacy-fixture\n' >"$legacy_stage/etc/dnscomplex/config.env"
printf 'preserve-current\n' >"$legacy_restore_root/etc/smartdns/current.conf"
cp "$render_root/usr/local/libexec/dnscomplex-restore-recover" \
  "$legacy_restore_root/usr/local/libexec/dnscomplex-restore-recover"
chmod 0700 "$legacy_stage"
chmod 0711 "$legacy_restore_root"
/usr/bin/tar -czf "$legacy_archive" -C "$legacy_stage" .
if PATH="$fakebin:$PATH" \
   DNSCOMPLEX_CONFIG="$config" \
   DNSCOMPLEX_BASE="$state" \
   DNSCOMPLEX_RUN_DIR="$run_dir" \
   DNSCOMPLEX_FS_ROOT="$legacy_restore_root" \
   DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/legacy-restore-failure.lock" \
   DNS_TEST_CALLS="$calls" \
   DNS_TEST_SYSTEMCTL_STATE="$systemctl_state" \
   DNS_TEST_SYSTEMCTL_FAIL_STATE="$systemctl_fail_state" \
   DNS_TEST_RESTART_FAIL_ONCE_STATE="$restart_fail_once_state" \
   DNS_TEST_RESTORE_MOVE_COUNTER="$restore_move_counter" \
   DNS_TEST_LEGACY_PRESERVED="$legacy_restore_root/etc/smartdns/current.conf" \
   bash -c '
     source "$1"
     load_config
     legacy_reconcile_cmd() {
       printf "reconcile-mutated\n" >"$DNS_TEST_LEGACY_PRESERVED"
       return 9
     }
     restore_cmd "$2"
   ' _ "$manager" "$legacy_archive" \
     >"$tmpdir/legacy-reconcile-failure.log" 2>&1; then
  fail "legacy migration accepted a reconciliation failure"
fi
if [[ -e "$legacy_restore_root/etc/dnscomplex/config.env" ]]; then
  sed 's/^/legacy-restore-log: /' \
    "$tmpdir/legacy-reconcile-failure.log" >&2
  fail "failed legacy reconciliation retained restored config"
fi
[[ "$(cat "$legacy_restore_root/etc/smartdns/current.conf")" == "preserve-current" ]] ||
  fail "failed legacy reconciliation did not roll back a preserved path"

PATH="$fakebin:$PATH" \
DNSCOMPLEX_CONFIG="$config" \
DNSCOMPLEX_BASE="$state" \
DNSCOMPLEX_RUN_DIR="$run_dir" \
DNSCOMPLEX_FS_ROOT="$legacy_restore_root" \
DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/legacy-restore.lock" \
DNS_TEST_CALLS="$calls" \
DNS_TEST_SYSTEMCTL_STATE="$systemctl_state" \
DNS_TEST_SYSTEMCTL_FAIL_STATE="$systemctl_fail_state" \
DNS_TEST_RESTART_FAIL_ONCE_STATE="$restart_fail_once_state" \
DNS_TEST_RESTORE_MOVE_COUNTER="$restore_move_counter" \
DNS_TEST_LEGACY_RECONCILED="$tmpdir/legacy-reconciled" \
bash -c '
  source "$1"
  load_config
  legacy_reconcile_cmd() { : >"$DNS_TEST_LEGACY_RECONCILED"; }
  restore_cmd "$2"
' _ "$manager" "$legacy_archive"
[[ "$(file_mode "$legacy_restore_root")" == "711" ]] ||
  fail "legacy migration restore changed the filesystem root mode"
[[ "$(cat "$legacy_restore_root/etc/dnscomplex/config.env")" == "legacy-fixture" ]] ||
  fail "legacy migration restore did not apply archived state"
[[ "$(cat "$legacy_restore_root/etc/smartdns/current.conf")" == "preserve-current" ]] ||
  fail "legacy migration restore did not preserve unspecified managed state"
[[ -f "$tmpdir/legacy-reconciled" ]] ||
  fail "legacy migration restore did not reconcile derived runtime state"

malicious_archive="$tmpdir/malicious-backup.tar.gz"
python3 - "$malicious_archive" <<'PY'
import io
import tarfile
import sys

with tarfile.open(sys.argv[1], "w:gz") as archive:
    payload = b"escaped\n"
    member = tarfile.TarInfo("../escaped-by-backup")
    member.size = len(payload)
    archive.addfile(member, io.BytesIO(payload))
PY
rm -f "$tmpdir/escaped-by-backup"
if run_manager restore "$malicious_archive" \
   >"$tmpdir/malicious-restore.log" 2>&1; then
  fail "restore accepted an archive with path traversal"
fi
[[ ! -e "$tmpdir/escaped-by-backup" ]] ||
  fail "restore wrote outside the target root"

first_archive="$tmpdir/first-locked-backup.tar.gz"
second_archive="$tmpdir/second-locked-backup.tar.gz"
rm -f "$tar_blocking"
DNS_TEST_TAR_DELAY=1 run_manager backup "$first_archive" \
  >"$tmpdir/first-locked-backup.log" 2>&1 &
maintenance_pid=$!
for _ in $(seq 1 100); do
  [[ -f "$tar_blocking" ]] && break
  /bin/sleep 0.05
done
[[ -f "$tar_blocking" ]] || fail "delayed backup did not reach tar stage"
if ! run_manager watchdog >"$tmpdir/watchdog-during-maintenance.log" 2>&1; then
  fail "watchdog must skip cleanly while maintenance is in progress"
fi
assert_contains "$tmpdir/watchdog-during-maintenance.log" \
  'another dnscomplex maintenance operation is already running; skipping watchdog'
assert_not_contains "$tmpdir/watchdog-during-maintenance.log" 'dig '
lock_started=$(monotonic_millis)
if run_manager backup "$second_archive" >"$tmpdir/second-locked-backup.log" 2>&1; then
  fail "overlapping backup bypassed the maintenance lock"
fi
lock_elapsed=$(( $(monotonic_millis) - lock_started ))
((lock_elapsed <= 1000)) ||
  fail "overlapping backup did not fail promptly: ${lock_elapsed}ms"
assert_contains "$tmpdir/second-locked-backup.log" \
  'another dnscomplex maintenance operation is already running'
cp "$config" "$tmpdir/config-before-locked-mutator.env"
lock_started=$(monotonic_millis)
if run_manager set-web-password locked-mutator-password \
   >"$tmpdir/locked-mutator.log" 2>&1; then
  fail "persistent config mutation bypassed the backup maintenance lock"
fi
lock_elapsed=$(( $(monotonic_millis) - lock_started ))
((lock_elapsed <= 1000)) ||
  fail "locked config mutation did not fail promptly: ${lock_elapsed}ms"
cmp -s "$config" "$tmpdir/config-before-locked-mutator.env" ||
  fail "blocked config mutation changed config.env"
assert_contains "$tmpdir/locked-mutator.log" \
  'another dnscomplex maintenance operation is already running'
wait "$maintenance_pid"
maintenance_pid=""
[[ -f "$first_archive" ]] || fail "locked backup did not complete"
rm -f "$tar_blocking"
run_manager backup "$second_archive" >"$tmpdir/backup-lock-release.log" 2>&1
[[ -f "$second_archive" ]] || fail "maintenance lock was not released after backup"

timer_wait_lock="$tmpdir/timer-wait.lock"
timer_wait_done="$tmpdir/timer-wait.done"
metrics_no_wait_done="$tmpdir/metrics-no-wait.done"
timer_holder_ready="$tmpdir/timer-wait.ready"
python3 - "$timer_wait_lock" "$timer_holder_ready" <<'PY' &
import fcntl
import sys
import time

lock_path, ready_path = sys.argv[1:3]
with open(lock_path, "w", encoding="utf-8") as fh:
    fcntl.flock(fh, fcntl.LOCK_EX)
    open(ready_path, "w", encoding="utf-8").close()
    time.sleep(0.5)
PY
timer_holder_pid=$!
for _ in $(seq 1 100); do
  [[ -e "$timer_holder_ready" ]] && break
  /bin/sleep 0.01
done
[[ -e "$timer_holder_ready" ]] || fail "timer lock holder did not start"
(
  PATH="$fakebin:$PATH" \
  DNS_TEST_CALLS="$calls" \
  DNSCOMPLEX_CONFIG="$config" \
  DNSCOMPLEX_BASE="$state" \
  DNSCOMPLEX_RUN_DIR="$run_dir" \
  DNSCOMPLEX_FS_ROOT="$fake_root" \
  DNSCOMPLEX_TIMER_MODE=1 \
  DNSCOMPLEX_MAINTENANCE_LOCK="$timer_wait_lock" \
    bash -c '
      source "$1"
      refresh_nftsets_cmd() { :; }
      main refresh-nftsets
    ' _ "$manager"
  : >"$timer_wait_done"
) &
timer_wait_pid=$!
PATH="$fakebin:$PATH" \
DNS_TEST_CALLS="$calls" \
DNSCOMPLEX_CONFIG="$config" \
DNSCOMPLEX_BASE="$state" \
DNSCOMPLEX_RUN_DIR="$run_dir" \
DNSCOMPLEX_FS_ROOT="$fake_root" \
DNSCOMPLEX_TIMER_MODE=1 \
DNSCOMPLEX_MAINTENANCE_LOCK="$timer_wait_lock" \
  bash -c '
    source "$1"
    metrics_sample_cmd() { :; }
    main metrics-sample
  ' _ "$manager"
: >"$metrics_no_wait_done"
/bin/sleep 0.1
[[ ! -e "$timer_wait_done" ]] || fail "timer service bypassed the maintenance lock"
[[ -e "$metrics_no_wait_done" ]] || fail "metrics sampling waited on the global maintenance lock"
wait "$timer_holder_pid"
timer_holder_pid=""
wait "$timer_wait_pid"
timer_wait_pid=""
[[ -e "$timer_wait_done" ]] || fail "timer service did not complete after the maintenance lock was released"

cp "$config" "$tmpdir/config-before-json-apply.env"
config_json="$tmpdir/config-update.json"
printf '%s\n' \
  '{"DNSCOMPLEX_WEB_PASSWORD":"transaction-password","DNSCOMPLEX_UPDATE_TIME":"03:15"}' \
  >"$config_json"
reset_state
run_manager_with_fix_stub apply-config-json "$config_json"
assert_contains "$config" "DNSCOMPLEX_WEB_PASSWORD='transaction-password'"
assert_contains "$config" "DNSCOMPLEX_UPDATE_TIME='03:15'"
assert_contains "$config" "AI_IPSEC_USERNAME='fixture-ai'"
assert_contains "$calls" 'fix-stub fix'

printf '%s\n' '{"DNSCOMPLEX_WEB_PASSWORD":"********"}' >"$config_json"
run_manager_with_fix_stub apply-config-json "$config_json"
assert_contains "$config" "DNSCOMPLEX_WEB_PASSWORD='transaction-password'"

cp "$config" "$tmpdir/config-before-failed-json-apply.env"
printf '%s\n' '{"DNSCOMPLEX_UPDATE_TIME":"02:45"}' >"$config_json"
if DNS_TEST_FIX_FAIL=1 run_manager_with_fix_stub apply-config-json "$config_json" \
   >"$tmpdir/failed-json-apply.log" 2>&1; then
  fail "failed config repair was reported as a successful config transaction"
fi
cmp -s "$config" "$tmpdir/config-before-failed-json-apply.env" ||
  fail "failed config transaction did not restore the previous config"
cp "$tmpdir/config-before-json-apply.env" "$config"

transaction_root="$tmpdir/egress-transaction-root"
transaction_config="$transaction_root/etc/dnscomplex/config.env"
transaction_base="$transaction_root/var/lib/dnscomplex"
transaction_run="$transaction_root/run/dnscomplex"
transaction_lock="$tmpdir/egress-transaction.lock"
egress_failure_called="$tmpdir/egress-failure-called"
mkdir -p "$transaction_root/etc/dnscomplex" "$transaction_root/etc/sing-box" \
  "$transaction_base" "$transaction_run" "$transaction_root/usr/local/libexec"
mkdir -p "$transaction_root/usr/local/lib/dnscomplex-config"
cp "$render_root/usr/local/lib/dnscomplex-config/candidate.py" \
  "$transaction_root/usr/local/lib/dnscomplex-config/candidate.py"
cp "$config" "$transaction_config"
cp "$render_root/usr/local/libexec/dnscomplex-restore-recover" \
  "$transaction_root/usr/local/libexec/dnscomplex-restore-recover"
cat >"$transaction_root/usr/local/libexec/dnscomplex-lan-alias" <<'EOF'
#!/usr/bin/env python3
import os
import sys

if sys.argv[1] != "close":
    raise SystemExit(64)
with open(os.environ["DNS_TEST_CALLS"], "a", encoding="utf-8") as fh:
    fh.write("lan-alias " + " ".join(sys.argv[1:]) + "\n")
EOF
chmod 0755 "$transaction_root/usr/local/libexec/dnscomplex-lan-alias"
printf '%s\n' 'egress-before' >"$transaction_root/etc/sing-box/config.json"
cp "$transaction_config" "$tmpdir/egress-config-before.env"
: >"$systemctl_state"
printf '%s\n' dnscomplex-network-ready.service >"$systemctl_state"
if PATH="$fakebin:$PATH" \
   DNSCOMPLEX_CONFIG="$transaction_config" \
   DNSCOMPLEX_BASE="$transaction_base" \
   DNSCOMPLEX_RUN_DIR="$transaction_run" \
   DNSCOMPLEX_FS_ROOT="$transaction_root" \
   DNSCOMPLEX_MAINTENANCE_LOCK="$transaction_lock" \
   DNSCOMPLEX_FORCE_SERVICE_STATE=1 \
   DNS_TEST_CALLS="$calls" \
   DNS_TEST_SYSTEMCTL_STATE="$systemctl_state" \
   DNS_TEST_SYSTEMCTL_FAIL_STATE="$systemctl_fail_state" \
   DNS_TEST_RESTART_FAIL_ONCE_STATE="$restart_fail_once_state" \
   DNS_TEST_EGRESS_FAILURE_CALLED="$egress_failure_called" \
   bash -c '
     source "$1"
     load_config
     apply_egress_stack_cmd() {
       : >"$DNS_TEST_EGRESS_FAILURE_CALLED"
       printf "%s\\n" egress-mutated >"$(fs_path /etc/sing-box/config.json)"
       return 9
     }
     set_egress_cmd ai ipsec
   ' _ "$manager" >"$tmpdir/failed-egress-transaction.log" 2>&1; then
  fail "failed egress apply was reported as successful"
fi
if [[ ! -f "$egress_failure_called" ]]; then
  sed 's/^/egress-transaction-log: /' "$tmpdir/failed-egress-transaction.log" >&2
  fail "egress failure injection was not reached"
fi
cmp -s "$transaction_config" "$tmpdir/egress-config-before.env" ||
  fail "failed egress transaction did not restore config.env"
[[ "$(cat "$transaction_root/etc/sing-box/config.json")" == 'egress-before' ]] ||
  fail "failed egress transaction did not restore generated runtime"

apply_candidate="$tmpdir/apply-config-candidate.env"
cp "$transaction_config" "$apply_candidate"
python3 - "$apply_candidate" <<'PY'
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    lines = fh.readlines()
with open(path, "w", encoding="utf-8") as fh:
    for line in lines:
        if line.startswith("DNSCOMPLEX_UPDATE_TIME="):
            fh.write("DNSCOMPLEX_UPDATE_TIME='02:45'\n")
        else:
            fh.write(line)
PY
cp "$transaction_config" "$tmpdir/apply-config-before.env"
printf '%s\n' 'apply-config-before' >"$transaction_root/etc/sing-box/config.json"
if PATH="$fakebin:$PATH" \
   DNSCOMPLEX_CONFIG="$transaction_config" \
   DNSCOMPLEX_BASE="$transaction_base" \
   DNSCOMPLEX_RUN_DIR="$transaction_run" \
   DNSCOMPLEX_FS_ROOT="$transaction_root" \
   DNSCOMPLEX_MAINTENANCE_LOCK="$transaction_lock" \
   DNSCOMPLEX_FORCE_SERVICE_STATE=1 \
   DNS_TEST_CALLS="$calls" \
   DNS_TEST_SYSTEMCTL_STATE="$systemctl_state" \
   DNS_TEST_SYSTEMCTL_FAIL_STATE="$systemctl_fail_state" \
   DNS_TEST_RESTART_FAIL_ONCE_STATE="$restart_fail_once_state" \
   DNS_TEST_APPLY_RUNTIME="$transaction_root/etc/sing-box/config.json" \
   bash -c '
     source "$1"
     load_config
     main apply-config "$2"
   ' "$fakebin/dnscomplex-fix-mutating-stub" "$manager" "$apply_candidate" \
   >"$tmpdir/failed-apply-config-transaction.log" 2>&1; then
  fail "failed apply-config transaction was reported as successful"
fi
cmp -s "$transaction_config" "$tmpdir/apply-config-before.env" ||
  fail "failed apply-config transaction did not restore config.env"
[[ "$(cat "$transaction_root/etc/sing-box/config.json")" == 'apply-config-before' ]] ||
  fail "failed apply-config transaction did not restore generated runtime"
if find "$transaction_root/var/lib/dnscomplex-restore" \
   -maxdepth 1 -name 'transaction.*' -print -quit 2>/dev/null | grep -q .; then
  fail "failed apply-config transaction left a recovery journal"
fi

nested_archive="$tmpdir/nested-lock-backup.tar.gz"
PATH="$fakebin:$PATH" \
DNSCOMPLEX_CONFIG="$config" \
DNSCOMPLEX_BASE="$state" \
DNSCOMPLEX_RUN_DIR="$run_dir" \
DNSCOMPLEX_FS_ROOT="$fake_root" \
DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
DNS_TEST_CALLS="$calls" \
DNS_TEST_TAR_DELAY=0 \
DNS_TEST_TAR_FAIL=0 \
DNS_TEST_TAR_BLOCKING="$tar_blocking" \
bash -c '
  source "$1"
  load_config
  acquire_maintenance_lock
  backup_cmd "$2"
' _ "$manager" "$nested_archive"
[[ -f "$nested_archive" ]] || fail "nested backup did not reuse maintenance lock"

if PATH="$fakebin:$PATH" \
   DNSCOMPLEX_CONFIG="$config" \
   DNSCOMPLEX_FS_ROOT="$fake_root" \
   DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
   DNS_TEST_CALLS="$calls" \
   bash -c '
     source "$1"
     load_config
     DNSCOMPLEX_MAINTENANCE_LOCK_HELD=1
     acquire_maintenance_lock
   ' _ "$manager" >"$tmpdir/forged-maintenance-lock.log" 2>&1; then
  fail "forged maintenance-lock state bypassed descriptor validation"
fi
assert_contains "$tmpdir/forged-maintenance-lock.log" \
  'maintenance lock state is set without an inherited lock descriptor'

failed_archive="$tmpdir/preserved-on-failure.tar.gz"
printf 'known-good-archive\n' >"$failed_archive"
if DNS_TEST_TAR_FAIL=1 run_manager backup "$failed_archive" \
   >"$tmpdir/failed-archive.log" 2>&1; then
  fail "failed tar operation was reported as a successful backup"
fi
[[ "$(cat "$failed_archive")" == "known-good-archive" ]] ||
  fail "failed backup replaced the existing archive"
if compgen -G "$tmpdir/.preserved-on-failure.tar.gz.*" >/dev/null; then
  fail "failed backup left a temporary archive"
fi

reset_state
run_health >"$tmpdir/health-connectivity-ok.json"
assert_health_check "$tmpdir/health-connectivity-ok.json" ai-ipsec-selected-egress ok
assert_health_check "$tmpdir/health-connectivity-ok.json" cn-ipsec-selected-egress ok
assert_health_detail_contains "$tmpdir/health-connectivity-ok.json" \
  ai-ipsec-selected-egress 'child_installed=True'
assert_health_detail_contains "$tmpdir/health-connectivity-ok.json" \
  ai-ipsec-selected-egress 'route_source_matches=True'
assert_health_check "$tmpdir/health-connectivity-ok.json" \
  ai-ipsec-dataplane-probe warn
assert_health_detail_contains "$tmpdir/health-connectivity-ok.json" \
  ai-ipsec-dataplane-probe 'proof=missing'
assert_health_check "$tmpdir/health-connectivity-ok.json" default-ipv4-connectivity ok
assert_health_check "$tmpdir/health-connectivity-ok.json" default-ipv6-connectivity ok
assert_health_check "$tmpdir/health-connectivity-ok.json" icloud-gateway-dns ok
ai_health_identity=$(printf '%s\n' '10.64.0.1' 'ai: #1, ESTABLISHED, IKEv2' 'ai: #1, 1, INSTALLED, TUNNEL, ESP' | sha256sum | awk '{print $1}')
cn_health_identity=$(printf '%s\n' '10.64.0.2' 'cn: #2, ESTABLISHED, IKEv2' 'cn: #2, 2, INSTALLED, TUNNEL, ESP' | sha256sum | awk '{print $1}')
printf '10.64.0.1 %s 2\n' "$ai_health_identity" >"$run_dir/profile-dataplane-ai.success"
printf '10.64.0.2 %s 2\n' "$cn_health_identity" >"$run_dir/profile-dataplane-cn.success"
chmod 0600 "$run_dir/profile-dataplane-ai.success" "$run_dir/profile-dataplane-cn.success"
: >"$gate_closed_ai"
: >"$gate_closed_cn"
if DNS_TEST_NFT_EXISTING=1 run_health >"$tmpdir/health-dataplane-gates-closed.json"; then
  fail "health accepted cached dataplane proof while both profile gates were closed"
fi
python3 - "$tmpdir/health-dataplane-gates-closed.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as fh:
    assert json.load(fh)["status"] == "unhealthy"
PY
assert_health_check "$tmpdir/health-dataplane-gates-closed.json" \
  ai-ipsec-dataplane-probe fail
assert_health_check "$tmpdir/health-dataplane-gates-closed.json" \
  cn-ipsec-dataplane-probe fail
rm -f "$gate_closed_ai" "$gate_closed_cn"
DNS_TEST_NFT_EXISTING=1 run_health >"$tmpdir/health-dataplane-open.json"
assert_health_check "$tmpdir/health-dataplane-open.json" ai-ipsec-dataplane-probe ok
assert_health_detail_contains "$tmpdir/health-dataplane-open.json" \
  ai-ipsec-dataplane-probe 'proof=cached'
touch -t 200001010000 "$run_dir/profile-dataplane-ai.success"
DNS_TEST_NFT_EXISTING=1 run_health >"$tmpdir/health-dataplane-stale.json"
python3 - "$tmpdir/health-dataplane-stale.json" <<'PYJSON'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as fh:
    assert json.load(fh)["status"] == "degraded"
PYJSON
assert_health_check "$tmpdir/health-dataplane-stale.json" ai-ipsec-dataplane-probe warn
assert_health_detail_contains "$tmpdir/health-dataplane-stale.json" \
  ai-ipsec-dataplane-probe 'proof=stale'
assert_contains "$socket_calls" 'connect family=2'
assert_contains "$socket_calls" 'connect family=10'
assert_not_contains "$socket_calls" '1.1.1.1'

if DNS_TEST_ICLOUD_GATEWAY_DNS=0 run_health >"$tmpdir/health-icloud-gateway-failed.json"; then
  fail "health accepted an unresolvable iCloud gateway"
fi
assert_health_check "$tmpdir/health-icloud-gateway-failed.json" icloud-gateway-dns fail

for state_and_component in \
  'connecting:ike_established=False' \
  'no-child:child_installed=False' \
  'child-not-installed:child_installed=False' \
  'no-vip:vip_valid=False' \
  'split-components:vip=none'; do
  state=${state_and_component%%:*}
  component=${state_and_component#*:}
  reset_state
  if DNS_TEST_AI_SA_STATE="$state" \
     run_health >"$tmpdir/health-ipsec-${state}.json"; then
    fail "health accepted AI IPsec state $state"
  fi
  assert_health_check "$tmpdir/health-ipsec-${state}.json" \
    ai-ipsec-selected-egress fail
  assert_health_detail_contains "$tmpdir/health-ipsec-${state}.json" \
    ai-ipsec-selected-egress "$component"
done

reset_state
DNS_TEST_AI_SA_STATE=multi-healthy \
run_health >"$tmpdir/health-ipsec-multi-healthy.json"
assert_health_check "$tmpdir/health-ipsec-multi-healthy.json" \
  ai-ipsec-selected-egress ok

reset_state
if DNS_TEST_AI_INTERFACE_STATE=down \
   run_health >"$tmpdir/health-ipsec-interface-down.json"; then
  fail "health accepted a down AI xfrm interface"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-interface-down.json" \
  ai-ipsec-selected-egress 'interface_up=False'

reset_state
if DNS_TEST_AI_INTERFACE_STATE=missing \
   run_health >"$tmpdir/health-ipsec-interface-missing.json"; then
  fail "health accepted a missing AI xfrm interface"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-interface-missing.json" \
  ai-ipsec-selected-egress 'interface_up=False'

reset_state
if DNS_TEST_AI_INTERFACE_STATE=hang \
   run_health >"$tmpdir/health-ipsec-interface-timeout.json"; then
  fail "health accepted a timed-out AI xfrm interface inspection"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-interface-timeout.json" \
  ai-ipsec-selected-egress 'interface_up=False'

reset_state
if DNS_TEST_AI_VIP=999.64.0.1 \
   run_health >"$tmpdir/health-ipsec-vip-invalid.json"; then
  fail "health accepted an invalid AI virtual IPv4"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-vip-invalid.json" \
  ai-ipsec-selected-egress 'vip_valid=False'

reset_state
if DNS_TEST_ROUTE_STATE=missing_rule \
   run_health >"$tmpdir/health-ipsec-rule-missing.json"; then
  fail "health accepted a missing AI fwmark policy rule"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-rule-missing.json" \
  ai-ipsec-selected-egress 'policy_rule=False'

reset_state
if DNS_TEST_AI_RULE_MASK_STATE=zero \
   run_health >"$tmpdir/health-ipsec-rule-zero-mask.json"; then
  fail "health accepted an AI fwmark rule with a zero mask"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-rule-zero-mask.json" \
  ai-ipsec-selected-egress 'policy_rule=False'

reset_state
if DNS_TEST_AI_RULE_CONFLICT=zero-mask \
   run_health >"$tmpdir/health-ipsec-rule-higher-conflict.json"; then
  fail "health accepted a higher-priority fwmark rule with a zero mask"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-rule-higher-conflict.json" \
  ai-ipsec-selected-egress 'policy_rule=False'

reset_state
if DNS_TEST_AI_RULE_CONFLICT=negated-other \
   run_health >"$tmpdir/health-ipsec-rule-negated-conflict.json"; then
  fail "health accepted a higher-priority negated rule that matches AI"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-rule-negated-conflict.json" \
  ai-ipsec-selected-egress 'policy_rule=False'

reset_state
DNS_TEST_AI_RULE_CONFLICT=negated-target \
run_health >"$tmpdir/health-ipsec-rule-negated-nonmatch.json"
assert_health_check "$tmpdir/health-ipsec-rule-negated-nonmatch.json" \
  ai-ipsec-selected-egress ok

reset_state
if DNS_TEST_AI_RULE_CONFLICT=negated-restricted \
   run_health >"$tmpdir/health-ipsec-rule-negated-restricted.json"; then
  fail "health accepted a negated rule with a restrictive source selector"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-rule-negated-restricted.json" \
  ai-ipsec-selected-egress 'policy_rule=False'

for shape_state in restricted suppressed; do
  reset_state
  if DNS_TEST_AI_RULE_SHAPE_STATE="$shape_state" \
     run_health >"$tmpdir/health-ipsec-rule-shape-${shape_state}.json"; then
    fail "health accepted an AI policy rule with $shape_state semantics"
  fi
  assert_health_detail_contains \
    "$tmpdir/health-ipsec-rule-shape-${shape_state}.json" \
    ai-ipsec-selected-egress 'policy_rule=False'
done

for same_priority_conflict in stale duplicate; do
  reset_state
  if DNS_TEST_AI_RULE_SAME_PRIORITY_CONFLICT="$same_priority_conflict" \
     run_health >"$tmpdir/health-ipsec-rule-same-${same_priority_conflict}.json"; then
    fail "health accepted AI rules with a same-priority $same_priority_conflict"
  fi
  assert_health_detail_contains \
    "$tmpdir/health-ipsec-rule-same-${same_priority_conflict}.json" \
    ai-ipsec-selected-egress 'policy_rule=False'
done

reset_state
DNS_TEST_AI_RULE_MASK_STATE=full \
run_health >"$tmpdir/health-ipsec-rule-full-mask.json"
assert_health_check "$tmpdir/health-ipsec-rule-full-mask.json" \
  ai-ipsec-selected-egress ok

reset_state
if DNS_TEST_ROUTE_STATE=missing_route \
   run_health >"$tmpdir/health-ipsec-route-missing.json"; then
  fail "health accepted a missing AI policy route"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-route-missing.json" \
  ai-ipsec-selected-egress 'route_source_matches=False'

reset_state
if DNS_TEST_AI_ROUTE_SOURCE_STATE=wrong \
   run_health >"$tmpdir/health-ipsec-route-source-wrong.json"; then
  fail "health accepted an AI policy route with the wrong source address"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-route-source-wrong.json" \
  ai-ipsec-selected-egress 'route_source_matches=False'

reset_state
if DNS_TEST_AI_ROUTE_SOURCE_STATE=missing \
   run_health >"$tmpdir/health-ipsec-route-source-missing.json"; then
  fail "health accepted an AI policy route without a source address"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-route-source-missing.json" \
  ai-ipsec-selected-egress 'route_source_matches=False'

reset_state
if DNS_TEST_SWAN_LIST_FAIL=1 \
   run_health >"$tmpdir/health-ipsec-swanctl-failed.json"; then
  fail "health accepted a failed swanctl query with partial stdout"
fi
assert_health_detail_contains "$tmpdir/health-ipsec-swanctl-failed.json" \
  ai-ipsec-selected-egress 'ike_established=False'

reset_state
DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 \
  run_manager test-ipsec
reset_state
if DNS_TEST_AI_SA_STATE=no-child \
   DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 \
   run_manager test-ipsec >"$tmpdir/test-ipsec-no-child.log" 2>&1; then
  fail "test-ipsec accepted an established IKE_SA without an installed CHILD_SA"
fi

reset_state
if DNS_TEST_SWAN_LIST_FAIL=1 \
   DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 \
   run_manager test-ipsec >"$tmpdir/test-ipsec-swanctl-failed.log" 2>&1; then
  fail "test-ipsec accepted a failed swanctl query with partial stdout"
fi

reset_state
if DNS_TEST_SWAN_LIST_FAIL=1 DNS_TEST_NFT_EXISTING=1 \
   DNS_TEST_NFT_CLEAR_FAIL_PROFILE=ai run_route_repair \
     >"$tmpdir/route-swanctl-failed.log" 2>&1; then
  fail "route reconciliation accepted a failed SA query"
fi
assert_contains "$calls" 'nft-batch flush set inet dnscomplex ai_ready4'
assert_contains "$calls" 'nft-batch flush set inet dnscomplex cn_ready4'
[[ -f "$gate_closed_cn" ]] ||
  fail "route reconciliation did not close CN after AI gate clear failed"
[[ ! -f "$gate_closed_ai" ]] ||
  fail "failed AI gate clear was incorrectly recorded as successful"

reset_state
if DNS_TEST_SWAN_LIST_FAIL=1 DNS_TEST_NFT_EXISTING=1 \
   DNS_TEST_NFT_CLEAR_FAIL_PROFILE=ai run_watchdog healthy \
     >"$tmpdir/watchdog-swanctl-failed.log" 2>&1; then
  fail "watchdog reported healthy after SA inspection failed"
fi
assert_contains "$calls" 'nft-batch flush set inet dnscomplex ai_ready4'
assert_contains "$calls" 'nft-batch flush set inet dnscomplex cn_ready4'
[[ -f "$gate_closed_cn" ]] ||
  fail "child repair did not close CN after AI gate clear failed"
assert_contains "$tmpdir/watchdog-swanctl-failed.log" \
  'ai egress gate could not be closed'
assert_not_contains "$calls" 'swanctl --load-all --noprompt'
assert_not_contains "$calls" 'swanctl --initiate --child'

for failed_profile in ai cn; do
  reset_state
  if [[ "$failed_profile" == ai ]]; then
    if DNS_TEST_AI_SA_STATE=no-child DNS_TEST_NFT_EXISTING=1 \
       DNS_TEST_NFT_CLEAR_FAIL_PROFILE=ai run_watchdog healthy \
         >"$tmpdir/watchdog-ai-gate-clear-failure.log" 2>&1; then
      fail "watchdog reported healthy after AI gate clear failed"
    fi
  else
    if DNS_TEST_CN_SA_STATE=no-child DNS_TEST_NFT_EXISTING=1 \
       DNS_TEST_NFT_CLEAR_FAIL_PROFILE=cn run_watchdog healthy \
         >"$tmpdir/watchdog-cn-gate-clear-failure.log" 2>&1; then
      fail "watchdog reported healthy after CN gate clear failed"
    fi
  fi
  assert_not_contains "$calls" 'swanctl --load-all --noprompt'
  assert_not_contains "$calls" "swanctl --initiate --child $failed_profile"
done

reset_state
DNS_TEST_CONFIG="$both_xray_boot_config" DNS_TEST_SWAN_LIST_FAIL=1 \
  DNS_TEST_NFT_EXISTING=1 run_watchdog healthy
assert_not_contains "$calls" 'swanctl --list-sas'

metrics_exporter="$render_root/usr/local/lib/dnscomplex-metrics/exporter.py"
metrics_health_stub="$tmpdir/metrics-health-stub"
cat >"$metrics_health_stub" <<'EOF'
#!/usr/bin/env bash
status=ok
[[ "${DNS_TEST_AI_SA_STATE:-healthy}" == "healthy" ]] || status=fail
printf '{"status":"%s","checks":[{"name":"ai-ipsec-selected-egress","status":"%s"}]}\n' \
  "$([[ "$status" == "ok" ]] && printf healthy || printf unhealthy)" \
  "$status"
[[ "$status" == "ok" ]]
EOF
chmod +x "$metrics_health_stub"
reset_state
if ! PATH="$fakebin:$PATH" \
   DNSCOMPLEX_MANAGER="$metrics_health_stub" \
   DNS_TEST_CALLS="$calls" \
   DNS_TEST_AI_SA_STATE=no-child \
   python3 - "$metrics_exporter" <<'PY'
import runpy
import sys

module = runpy.run_path(sys.argv[1], run_name="dnscomplex_metrics_test")
assert module["ipsec_up"]("ai") == 0
PY
then
  fail "metrics marked AI IPsec up without an installed CHILD_SA"
fi

reset_state
if DNS_TEST_IPV4_CONNECTIVITY=0 \
   run_health >"$tmpdir/health-ipv4-failed.json"; then
  fail "failed default IPv4 connectivity was not unhealthy"
fi
assert_health_check "$tmpdir/health-ipv4-failed.json" default-ipv4-connectivity fail
python3 - "$tmpdir/health-ipv4-failed.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    assert json.load(fh)["status"] == "unhealthy"
PY

reset_state
DNS_TEST_IPV6_CONNECTIVITY=0 \
run_health >"$tmpdir/health-ipv6-failed.json"
assert_health_check "$tmpdir/health-ipv6-failed.json" default-ipv4-connectivity ok
assert_health_check "$tmpdir/health-ipv6-failed.json" default-ipv6-connectivity warn

ipv6_off_config="$tmpdir/ipv6-off.env"
cp "$config" "$ipv6_off_config"
printf '%s\n' 'DEFAULT_IPV6_MODE=off' >>"$ipv6_off_config"
reset_state
DNS_TEST_CONFIG="$ipv6_off_config" \
DNS_TEST_IPV6_CONNECTIVITY=0 \
run_health >"$tmpdir/health-ipv6-off.json"
assert_health_check "$tmpdir/health-ipv6-off.json" default-ipv6-connectivity ok
assert_not_contains "$socket_calls" 'connect family=10'

reset_state
rm -f "$run_dir/smartdns.last_restart"
DNS_TEST_SCENARIO=post_restart_blocking \
DNS_TEST_REAL_SLEEP=1 \
DNS_TEST_AI_VIP=10.64.0.1 \
DNS_TEST_CN_VIP=10.64.0.2 \
  run_manager watchdog >"$tmpdir/blocked.log" 2>&1 &
blocked_pid=$!
marker_wait_started=$(monotonic_millis)
for _ in $(seq 1 400); do
  [[ -f "$blocking" ]] && break
  if ! kill -0 "$blocked_pid" 2>/dev/null; then
    wait "$blocked_pid" 2>/dev/null || true
    cat "$tmpdir/blocked.log" >&2
    fail "watchdog exited before the post-restart blocking probe started"
  fi
  /bin/sleep 0.05
done
marker_wait_elapsed=$(( $(monotonic_millis) - marker_wait_started ))
printf 'post_restart_marker_wait_milliseconds=%s\n' "$marker_wait_elapsed"
if [[ ! -f "$blocking" ]]; then
  cat "$tmpdir/blocked.log" >&2
  kill "$blocked_pid" 2>/dev/null || true
  wait "$blocked_pid" 2>/dev/null || true
  fail "blocking post-restart probe did not start"
fi
second_started=$(monotonic_millis)
DNS_TEST_SCENARIO=healthy \
DNS_TEST_AI_VIP=10.64.0.1 \
DNS_TEST_CN_VIP=10.64.0.2 \
run_manager watchdog >"$tmpdir/busy.log" 2>&1 ||
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

update_calls="$tmpdir/update.calls"
update_restored_bins="$tmpdir/update.restored-bins"
update_restored_config="$tmpdir/update.restored-config"
update_self="$tmpdir/update-self"
cat >"$update_self" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'self %s\n' "$*" >>"$DNS_TEST_UPDATE_CALLS"
case "${1:-}" in
  validate-config)
    [[ "${DNS_TEST_UPDATE_FAIL_STAGE:-}" != "validate-config" ]]
    ;;
  ipsec-ready)
    [[ "${DNS_TEST_UPDATE_FAIL_STAGE:-}" != "ipsec-ready" ]]
    ;;
  routes)
    [[ "${2:-}" == "up" ]]
    [[ "${DNS_TEST_UPDATE_FAIL_STAGE:-}" != "routes" ]]
    ;;
  test)
    [[ "${DNS_TEST_UPDATE_FAIL_STAGE:-}" != "test" ]]
    ;;
  *)
    exit 64
    ;;
esac
EOF
chmod +x "$update_self"

run_update_impl() {
  local scenario=$1
  : >"$update_calls"
  rm -f "$update_restored_bins" "$update_restored_config"
  set +e
  DNSCOMPLEX_CONFIG="$config" \
  DNSCOMPLEX_BASE="$state" \
  DNSCOMPLEX_RUN_DIR="$run_dir" \
  DNSCOMPLEX_FS_ROOT="$fake_root" \
  DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/maintenance.lock" \
  DNS_TEST_UPDATE_CALLS="$update_calls" \
  DNS_TEST_UPDATE_FAIL_STAGE="$scenario" \
  DNS_TEST_UPDATE_RESTORED_BINS="$update_restored_bins" \
  DNS_TEST_UPDATE_RESTORED_CONFIG="$update_restored_config" \
  MANAGER="$manager" \
  bash -c '
    set -euo pipefail
    source "$MANAGER"
    load_config
    need_root() { :; }
    backup_cmd() {
      printf "backup %s\n" "$*" >>"$DNS_TEST_UPDATE_CALLS"
      [[ "$DNS_TEST_UPDATE_FAIL_STAGE" != "backup" ]]
    }
    backup_release_binaries() {
      printf "backup-binaries %s\n" "$*" >>"$DNS_TEST_UPDATE_CALLS"
    }
    restore_release_binaries() {
      printf "restore-binaries %s\n" "$*" >>"$DNS_TEST_UPDATE_CALLS"
      : >"$DNS_TEST_UPDATE_RESTORED_BINS"
    }
    restore_cmd() {
      printf "restore-config %s\n" "$*" >>"$DNS_TEST_UPDATE_CALLS"
      : >"$DNS_TEST_UPDATE_RESTORED_CONFIG"
    }
    write_config_cmd() {
      printf "write-config\n" >>"$DNS_TEST_UPDATE_CALLS"
      [[ "$DNS_TEST_UPDATE_FAIL_STAGE" != "write-config" ]]
    }
    apt-get() {
      printf "apt-get %s\n" "$*" >>"$DNS_TEST_UPDATE_CALLS"
    }
    update_release_if_needed() {
      printf "release %s\n" "$1" >>"$DNS_TEST_UPDATE_CALLS"
      [[ "$DNS_TEST_UPDATE_FAIL_STAGE" != "release" ]] || return 9
      UPDATED_SERVICES+=(sing-box)
    }
    sing-box() {
      printf "sing-box %s\n" "$*" >>"$DNS_TEST_UPDATE_CALLS"
      [[ "$DNS_TEST_UPDATE_FAIL_STAGE" != "config-check" ]]
    }
    xray() {
      printf "xray %s\n" "$*" >>"$DNS_TEST_UPDATE_CALLS"
    }
    nft() {
      printf "nft %s\n" "$*" >>"$DNS_TEST_UPDATE_CALLS"
    }
    systemctl() {
      printf "systemctl %s\n" "$*" >>"$DNS_TEST_UPDATE_CALLS"
      [[ "$DNS_TEST_UPDATE_FAIL_STAGE" != "restart" || "${1:-}" != "restart" ]]
    }
    set +e
    (
      set -e
      update_software_impl
    )
    rc=$?
    set -e
    exit "$rc"
  ' "$update_self"
  local rc=$?
  set -e
  return "$rc"
}

for update_failure in \
  write-config \
  release \
  validate-config \
  config-check \
  restart \
  ipsec-ready \
  routes \
  test; do
  if run_update_impl "$update_failure"; then
    fail "update failure stage unexpectedly succeeded: $update_failure"
  fi
  [[ -f "$update_restored_bins" ]] ||
    fail "release binaries were not restored after $update_failure"
  [[ -f "$update_restored_config" ]] ||
    fail "configuration was not restored after $update_failure"
done

run_update_impl healthy
[[ ! -e "$update_restored_bins" && ! -e "$update_restored_config" ]] ||
  fail "successful update unexpectedly ran rollback"
assert_not_contains "$update_calls" 'apt-get '

update_approval_marker="$tmpdir/update-approval-ran"
if DNS_TEST_UPDATE_APPROVAL_MARKER="$update_approval_marker" \
   DNSCOMPLEX_CONFIG="$config" \
   MANAGER="$manager" \
   bash -c '
     set -euo pipefail
     source "$MANAGER"
     load_config
     need_root() { :; }
     acquire_maintenance_lock() { :; }
     update_software_impl() { : >"$DNS_TEST_UPDATE_APPROVAL_MARKER"; }
     update_software_cmd
   ' >"$tmpdir/update-approval.log" 2>&1; then
  fail "component update accepted missing unverified-asset acknowledgement"
fi
[[ ! -e "$update_approval_marker" ]] ||
  fail "component update mutated state before explicit acknowledgement"

system_update_calls="$tmpdir/system-update.calls"
run_system_update_impl() {
  : >"$system_update_calls"
  DNS_TEST_SYSTEM_UPDATE_FAIL="${1:-none}" \
  DNS_TEST_SYSTEM_UPDATE_CALLS="$system_update_calls" \
  DNSCOMPLEX_CONFIG="$config" \
  MANAGER="$manager" \
  bash -c '
    set -euo pipefail
    source "$MANAGER"
    load_config
    need_root() { :; }
    apt-get() {
      printf "apt-get %s\n" "$*" >>"$DNS_TEST_SYSTEM_UPDATE_CALLS"
      if [[ "$DNS_TEST_SYSTEM_UPDATE_FAIL" == "upgrade" && "$*" == *"upgrade"* ]]; then
        return 9
      fi
    }
    test_cmd() {
      printf "test\n" >>"$DNS_TEST_SYSTEM_UPDATE_CALLS"
    }
    write_config_cmd() {
      printf "forbidden-write-config\n" >>"$DNS_TEST_SYSTEM_UPDATE_CALLS"
    }
    update_release_if_needed() {
      printf "forbidden-release-update\n" >>"$DNS_TEST_SYSTEM_UPDATE_CALLS"
    }
    rollback_component_update() {
      printf "forbidden-rollback\n" >>"$DNS_TEST_SYSTEM_UPDATE_CALLS"
    }
    system_update_impl
  '
}

run_system_update_impl healthy
assert_contains "$system_update_calls" 'apt-get update'
assert_contains "$system_update_calls" 'upgrade'
assert_contains "$system_update_calls" '--with-new-pkgs'
assert_contains "$system_update_calls" 'test'
assert_not_contains "$system_update_calls" 'forbidden-'

if run_system_update_impl upgrade >"$tmpdir/system-update-failure.log" 2>&1; then
  fail "partial Debian package update failure was reported as success"
fi
assert_not_contains "$system_update_calls" 'forbidden-rollback'

# A route-ready IPsec profile needs two successful dataplane observations
# before an empty readiness set can be opened. The explicit TLS probe itself
# must work while the ordinary profile gates are closed.
reset_state
: >"$gate_closed_ai"
: >"$gate_closed_cn"
if ! DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.1 \
     DNS_TEST_CN_VIP=10.64.0.2 run_route_repair; then
  fail "first closed-gate dataplane observation should be accepted as warm-up"
fi
assert_contains "$calls" 'profile-dataplane-probe profile=ai status=pass gate-closed=1'
assert_contains "$calls" 'profile-dataplane-probe profile=cn status=pass gate-closed=1'
[[ -f "$gate_closed_ai" && -f "$gate_closed_cn" ]] ||
  fail "one successful dataplane probe opened a profile gate before the second proof"
[[ "$(awk '{print $1, $3}' "$run_dir/profile-dataplane-ai.success")" == '10.64.0.1 1' ]] ||
  fail "AI dataplane success evidence did not record current VIP and first pass"
[[ "$(awk '{print $1, $3}' "$run_dir/profile-dataplane-cn.success")" == '10.64.0.2 1' ]] ||
  fail "CN dataplane success evidence did not record current VIP and first pass"

if ! DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.1 \
     DNS_TEST_CN_VIP=10.64.0.2 run_route_repair; then
  fail "second closed-gate dataplane observation should open healthy profiles"
fi
[[ ! -f "$gate_closed_ai" && ! -f "$gate_closed_cn" ]] ||
  fail "two consecutive dataplane successes did not open selected profile gates"
assert_contains "$calls" 'profile-dataplane-probe profile=ai status=pass gate-closed=1'
assert_contains "$calls" 'profile-dataplane-probe profile=cn status=pass gate-closed=1'

# The health proof only needs two passes; the persistent count must saturate
# rather than eventually becoming invalid after many watchdog observations.
identity_ai=$(awk '{print $2}' "$run_dir/profile-dataplane-ai.success")
printf '10.64.0.1 %s 999\n' "$identity_ai" >"$run_dir/profile-dataplane-ai.success"
DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.1 \
  DNS_TEST_CN_VIP=10.64.0.2 run_route_repair ||
  fail "AI dataplane probe failed with a high prior success count"
DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.1 \
  DNS_TEST_CN_VIP=10.64.0.2 run_route_repair ||
  fail "AI dataplane probe failed after its success count saturated"
[[ ! -f "$gate_closed_ai" ]] ||
  fail "high dataplane success count closed the healthy AI gate"
[[ "$(awk '{print $3}' "$run_dir/profile-dataplane-ai.success")" == 2 ]] ||
  fail "dataplane success count did not saturate at two"

# A same-VIP CHILD_SA rekey with a passing probe updates the fingerprint but
# must not close an already-open profile gate during make-before-break.
old_ai_identity=$(awk '{print $2}' "$run_dir/profile-dataplane-ai.success")
if ! DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.1 \
     DNS_TEST_CN_VIP=10.64.0.2 DNS_TEST_AI_CHILD_ID=11 run_route_repair; then
  fail "same-VIP CHILD_SA rekey with a passing dataplane probe failed"
fi
[[ ! -f "$gate_closed_ai" ]] ||
  fail "same-VIP CHILD_SA rekey closed an already-healthy AI gate"
new_ai_identity=$(awk '{print $2}' "$run_dir/profile-dataplane-ai.success")
[[ "$new_ai_identity" != "$old_ai_identity" ]] ||
  fail "dataplane evidence did not track a same-IKE CHILD_SA identity change"
[[ "$(awk '{print $3}' "$run_dir/profile-dataplane-ai.success")" == 1 ]] ||
  fail "same-VIP rekey did not start fresh probe evidence for the new CHILD_SA"

# A failed probe immediately clears only its own gate; the healthy peer gets
# its independent evidence and the watchdog never substitutes another route.
reset_state
: >"$gate_closed_ai"
: >"$gate_closed_cn"
if DNS_TEST_NFT_EXISTING=1 DNS_TEST_AI_VIP=10.64.0.1 \
   DNS_TEST_CN_VIP=10.64.0.2 DNS_TEST_PROFILE_PROBE_AI_STATUS=fail \
   run_route_repair >"$tmpdir/profile-probe-failure.log" 2>&1; then
  fail "failed AI dataplane probe was reported as route healthy"
fi
[[ -f "$gate_closed_ai" ]] || fail "failed AI dataplane probe opened the AI gate"
[[ "$(awk '{print $1, $3}' "$run_dir/profile-dataplane-cn.success")" == '10.64.0.2 1' ]] ||
  fail "AI probe failure prevented independent CN dataplane verification"
[[ ! -e "$run_dir/profile-dataplane-ai.success" ]] ||
  fail "failed AI dataplane probe retained success evidence"
assert_not_contains "$calls" '/default'
assert_not_contains "$calls" 'profile-dataplane-probe profile=ai status=pass'

# Xray-selected profiles do not run an IPsec probe and keep their normal
# service-based gate behavior.
reset_state
DNS_TEST_CONFIG="$both_xray_boot_config" DNS_TEST_NFT_EXISTING=1 \
  run_route_repair
assert_not_contains "$calls" 'profile-dataplane-probe'

printf 'runtime reliability test: ok\n'
