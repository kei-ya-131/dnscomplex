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
cleanup() {
  if [[ -n "$writer_pid" ]]; then
    kill "$writer_pid" 2>/dev/null || true
    wait "$writer_pid" 2>/dev/null || true
  fi
  if [[ -n "$maintenance_pid" ]]; then
    kill "$maintenance_pid" 2>/dev/null || true
    wait "$maintenance_pid" 2>/dev/null || true
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
blocking="$tmpdir/blocking"
probe_pids="$tmpdir/probe-pids"
nft_race="$tmpdir/nft-race"
tar_blocking="$tmpdir/tar-blocking"
socket_calls="$tmpdir/socket-calls"
ipsec_started="$tmpdir/ipsec-started"
mkdir -p "$state" "$run_dir" "$fake_root" "$fakebin" "$fakepy"

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

cat >"$fakebin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"$DNS_TEST_CALLS"
unit=${!#:-}
case "${1:-}" in
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
    if [[ "$unit" == "${DNS_TEST_INACTIVE_UNIT:-}" ]]; then
      [[ " $* " == *" --quiet "* ]] || printf 'inactive\n'
      exit 3
    fi
    [[ " $* " == *" --quiet "* ]] || printf 'active\n'
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
if [[ "${DNS_TEST_NFT_ADD_FAIL:-0}" == "1" &&
      "${1:-} ${2:-}" == "add rule" ]]; then
  exit 9
fi
case "${1:-} ${2:-}" in
  "list table") exit 0 ;;
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
    sed 's/^/nft-batch /' "$2" >>"$DNS_TEST_CALLS"
    if [[ "${DNS_TEST_NFT_RACE_PROFILE:-}" == "ai" ]] &&
       grep -Fq ' dnscomplex ai4 ' "$2"; then
      : >"$DNS_TEST_NFT_RACE_STATE"
      exit 9
    fi
    if [[ "${DNS_TEST_NFT_RACE_PROFILE:-}" == "cn" ]] &&
       grep -Fq ' dnscomplex cn4 ' "$2"; then
      : >"$DNS_TEST_NFT_RACE_STATE"
      exit 9
    fi
    if [[ "${DNS_TEST_NFT_BATCH_FAIL_PROFILE:-}" == "ai" ]] &&
       grep -Fq ' dnscomplex ai4 ' "$2"; then
      exit 9
    fi
    if [[ "${DNS_TEST_NFT_BATCH_FAIL_PROFILE:-}" == "cn" ]] &&
       grep -Fq ' dnscomplex cn4 ' "$2"; then
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
if [[ "${DNS_TEST_MKTEMP_FAIL:-}" == "nftset-ai" && " $* " == *".nftset-ai."* ]]; then
  exit 9
fi
if [[ "${DNS_TEST_MKTEMP_FAIL:-}" == "nftset-cn" && " $* " == *".nftset-cn."* ]]; then
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
underlay_ipv4=${DNS_TEST_UNDERLAY_IPV4:-192.168.8.200}
underlay_gateway=${DNS_TEST_UNDERLAY_GATEWAY:-192.168.8.253}
if [[ "$*" == "-4 -o addr show dev $underlay_iface scope global" ]]; then
  case "${DNS_TEST_WAN_ADDRESS:-expected}" in
    expected)
      printf '2: %s    inet %s/24 brd 192.168.8.255 scope global %s\n' \
        "$underlay_iface" "$underlay_ipv4" "$underlay_iface"
      ;;
    wrong)
      printf '2: eth0    inet 192.168.8.201/24 brd 192.168.8.255 scope global eth0\n'
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
    case "${DNS_TEST_ROUTE_STATE:-complete}" in
      missing_rule|missing_all)
        printf '101: from all fwmark %s lookup 351\n' "$cn_rule_token"
        ;;
      missing_cn)
        printf '100: from all fwmark %s lookup 301\n' "$ai_rule_token"
        ;;
      *)
        printf '100: from all fwmark %s lookup 301\n' "$ai_rule_token"
        printf '101: from all fwmark %s lookup 351\n' "$cn_rule_token"
        ;;
    esac
    if grep -Fq 'ip rule add fwmark 0x301 table 301' "$DNS_TEST_CALLS"; then
      printf '10301: from all fwmark 0x301 lookup 301\n'
    fi
    if grep -Fq 'ip rule add fwmark 0x351 table 351' "$DNS_TEST_CALLS"; then
      printf '10351: from all fwmark 0x351 lookup 351\n'
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
ipsec_child_up() {
  local child=$1
  if [[ "${DNS_TEST_IPSEC_START_EMPTY:-0}" == "1" ]]; then
    grep -Fxq "$child" "$DNS_TEST_IPSEC_STARTED" 2>/dev/null
  else
    [[ "${DNS_TEST_IPSEC_FAIL_CHILD:-}" != "$child" ]]
  fi
}
emit_ipsec_sa() {
  local child=$1 id=$2 vip=$3 state
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
      printf '  %s: #%s, reqid %s, ROUTED, TUNNEL, ESP\n' "$child" "$id" "$id"
      ;;
    *)
      printf '  %s: #%s, reqid %s, INSTALLED, TUNNEL, ESP\n' "$child" "$id" "$id"
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
  DNS_TEST_IPSEC_FAIL_CHILD="${DNS_TEST_IPSEC_FAIL_CHILD:-}" \
  DNS_TEST_IPSEC_START_EMPTY="${DNS_TEST_IPSEC_START_EMPTY:-0}" \
  DNS_TEST_IPSEC_STARTED="$ipsec_started" \
  DNS_TEST_WAN_ADDRESS="${DNS_TEST_WAN_ADDRESS:-expected}" \
  DNS_TEST_WAN_ROUTE="${DNS_TEST_WAN_ROUTE:-expected}" \
  DNS_TEST_UNDERLAY_IFACE="${DNS_TEST_UNDERLAY_IFACE:-eth0}" \
  DNS_TEST_UNDERLAY_IPV4="${DNS_TEST_UNDERLAY_IPV4:-192.168.8.200}" \
  DNS_TEST_UNDERLAY_GATEWAY="${DNS_TEST_UNDERLAY_GATEWAY:-192.168.8.253}" \
  DNS_TEST_VICI_AVAILABLE="${DNS_TEST_VICI_AVAILABLE:-1}" \
  DNS_TEST_SWAN_LOAD_FAIL="${DNS_TEST_SWAN_LOAD_FAIL:-0}" \
  DNS_TEST_SWAN_SUCCESS_NOISE="${DNS_TEST_SWAN_SUCCESS_NOISE:-0}" \
  DNS_TEST_SWAN_LIST_FAIL="${DNS_TEST_SWAN_LIST_FAIL:-0}" \
  DNS_TEST_AI_SA_STATE="${DNS_TEST_AI_SA_STATE:-healthy}" \
  DNS_TEST_CN_SA_STATE="${DNS_TEST_CN_SA_STATE:-healthy}" \
  DNS_TEST_AI_VIP="${DNS_TEST_AI_VIP:-}" \
  DNS_TEST_CN_VIP="${DNS_TEST_CN_VIP:-}" \
  DNS_TEST_AI_INTERFACE_STATE="${DNS_TEST_AI_INTERFACE_STATE:-up}" \
  DNS_TEST_CN_INTERFACE_STATE="${DNS_TEST_CN_INTERFACE_STATE:-up}" \
  DNS_TEST_AI_ROUTE_SOURCE_STATE="${DNS_TEST_AI_ROUTE_SOURCE_STATE:-match}" \
  DNS_TEST_CN_ROUTE_SOURCE_STATE="${DNS_TEST_CN_ROUTE_SOURCE_STATE:-match}" \
  DNS_TEST_INACTIVE_UNIT="${DNS_TEST_INACTIVE_UNIT:-}" \
  DNS_TEST_DISABLED_UNIT="${DNS_TEST_DISABLED_UNIT:-}" \
  DNS_TEST_RESTART_FAIL_UNIT="${DNS_TEST_RESTART_FAIL_UNIT:-}" \
  DNS_TEST_MKTEMP_FAIL="${DNS_TEST_MKTEMP_FAIL:-}" \
  DNS_TEST_STATE_WRITE_FAIL="${DNS_TEST_STATE_WRITE_FAIL:-0}" \
  DNS_TEST_NFT_EXISTING="${DNS_TEST_NFT_EXISTING:-0}" \
  DNS_TEST_NFT_ADD_FAIL="${DNS_TEST_NFT_ADD_FAIL:-0}" \
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
  PYTHONPATH="${DNS_TEST_PYTHONPATH:-}" \
  DNS_TEST_REAL_SLEEP="${DNS_TEST_REAL_SLEEP:-0}" \
  DNS_TEST_NOW="${DNS_TEST_NOW:-}" \
  DNSCOMPLEX_FORCE_SERVICE_STATE="${DNSCOMPLEX_FORCE_SERVICE_STATE:-1}" \
  DNSCOMPLEX_CONFIG="${DNS_TEST_CONFIG:-$config}" \
    "$manager" "$@"
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
    "$tar_blocking" "$socket_calls" "$ipsec_started"
}

run_watchdog() {
  local scenario=$1
  reset_state
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
assert_contains "$calls" 'ip rule add fwmark 0x301 table 301'

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

if DNS_TEST_AI_SA_STATE=no-child \
   run_watchdog healthy >"$tmpdir/ipsec-child-missing.log" 2>&1; then
  fail "watchdog accepted an IKE_SA without an installed AI CHILD_SA"
fi
assert_contains "$calls" 'swanctl --initiate --child ai'
assert_not_contains "$calls" 'dig '

if DNS_TEST_AI_SA_STATE=no-vip \
   run_watchdog healthy >"$tmpdir/ipsec-vip-missing.log" 2>&1; then
  fail "watchdog accepted an installed AI CHILD_SA without a virtual IPv4"
fi
assert_contains "$calls" 'swanctl --initiate --child ai'
assert_not_contains "$calls" 'dig '

if DNS_TEST_IPSEC_FAIL_CHILD=ai \
   run_watchdog healthy >"$tmpdir/ipsec-repair-failure.log" 2>&1; then
  fail "failed IPsec child repair was reported as healthy"
fi
assert_contains "$calls" 'swanctl --initiate --child ai'
assert_contains "$calls" 'swanctl --load-all --noprompt'
assert_call_before 'swanctl --load-all --noprompt' 'swanctl --initiate --child ai'
assert_not_contains "$calls" 'dig '

reset_state
DNS_TEST_IPSEC_START_EMPTY=1 DNS_TEST_ROUTE_STATE=missing_all \
  DNS_TEST_AI_VIP=10.64.0.1 DNS_TEST_CN_VIP=10.64.0.2 \
  run_manager watchdog
assert_call_count 'timeout 10 swanctl --load-all --noprompt' 1
assert_contains "$calls" 'swanctl --initiate --child ai'
assert_contains "$calls" 'swanctl --initiate --child cn'
assert_contains "$calls" 'ip route replace default dev ipsec-ai src 10.64.0.1 table 301'
assert_contains "$calls" 'ip route replace default dev ipsec-cn src 10.64.0.2 table 351'
assert_call_before 'swanctl --initiate --child ai' \
  'ip route replace default dev ipsec-ai src 10.64.0.1 table 301'

reset_state
if DNS_TEST_NFT_ADD_FAIL=1 DNS_TEST_AI_VIP=10.64.0.1 \
   DNS_TEST_CN_VIP=10.64.0.2 \
   run_manager routes up >"$tmpdir/routes-nat-failure.log" 2>&1; then
  fail "policy routes reported success after dynamic SNAT failure"
fi
assert_contains "$calls" 'nft add rule inet dnscomplex postrouting'

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
   DNSCOMPLEX_IPSEC_BOOT_TIMEOUT=1 \
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
DNS_TEST_AI_VIP=10.64.0.1 \
DNS_TEST_CN_VIP=10.64.0.2 \
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
  usr/local/lib/dnscomplex-web \
  var/lib/dnscomplex; do
  mkdir -p "$fake_root/$rel"
done
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
assert_contains "$calls" 'systemctl disable systemd-resolved.service'
assert_contains "$calls" 'systemctl stop systemd-resolved.service'

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
mkdir -p "$legacy_stage/etc/dnscomplex" "$legacy_restore_root"
printf 'legacy-fixture\n' >"$legacy_stage/etc/dnscomplex/config.env"
chmod 0700 "$legacy_stage"
chmod 0711 "$legacy_restore_root"
/usr/bin/tar -czf "$legacy_archive" -C "$legacy_stage" .
if /usr/bin/tar --help 2>&1 | grep -Fq -- '--no-overwrite-dir'; then
  PATH="$fakebin:$PATH" \
  DNSCOMPLEX_CONFIG="$config" \
  DNSCOMPLEX_BASE="$state" \
  DNSCOMPLEX_RUN_DIR="$run_dir" \
  DNSCOMPLEX_FS_ROOT="$legacy_restore_root" \
  DNSCOMPLEX_MAINTENANCE_LOCK="$tmpdir/legacy-restore.lock" \
  DNS_TEST_CALLS="$calls" \
  bash -c '
    source "$1"
    load_config
    fix_cmd() { :; }
    restore_cmd "$2"
  ' _ "$manager" "$legacy_archive"
  [[ "$(file_mode "$legacy_restore_root")" == "711" ]] ||
    fail "legacy backup restore changed the filesystem root mode"
  [[ "$(cat "$legacy_restore_root/etc/dnscomplex/config.env")" == "legacy-fixture" ]] ||
    fail "legacy backup restore did not extract the archived state"
fi

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
assert_health_check "$tmpdir/health-connectivity-ok.json" default-ipv4-connectivity ok
assert_health_check "$tmpdir/health-connectivity-ok.json" default-ipv6-connectivity ok
assert_contains "$socket_calls" 'connect family=2'
assert_contains "$socket_calls" 'connect family=10'
assert_not_contains "$socket_calls" '1.1.1.1'

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
for _ in $(seq 1 100); do
  [[ -f "$blocking" ]] && break
  /bin/sleep 0.05
done
if [[ ! -f "$blocking" ]]; then
  cat "$tmpdir/blocked.log" >&2
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
      if [[ "$DNS_TEST_UPDATE_FAIL_STAGE" == "apt-update" && "${1:-}" == "update" ]]; then
        return 9
      fi
      if [[ "$DNS_TEST_UPDATE_FAIL_STAGE" == "apt-upgrade" && "$*" == *"upgrade"* ]]; then
        return 9
      fi
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

for apt_failure in apt-update apt-upgrade; do
  if run_update_impl "$apt_failure"; then
    fail "APT failure stage unexpectedly succeeded: $apt_failure"
  fi
  [[ ! -e "$update_restored_bins" && ! -e "$update_restored_config" ]] ||
    fail "APT-only failure incorrectly claimed component rollback: $apt_failure"
  assert_not_contains "$update_calls" 'write-config'
done

run_update_impl healthy
[[ ! -e "$update_restored_bins" && ! -e "$update_restored_config" ]] ||
  fail "successful update unexpectedly ran rollback"

printf 'runtime reliability test: ok\n'
