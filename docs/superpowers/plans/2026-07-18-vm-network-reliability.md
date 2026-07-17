# VM Network Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair the live SmartDNS outage on `192.168.8.200`, add bounded self-healing and failure-safe state handling, and reproduce every persistent repair in `install.sh`.

**Architecture:** Keep the existing AdGuard Home -> sing-box -> SmartDNS and domain-based default/AI/CN routing pipeline. Avoid the reported SmartDNS HTTP/2 path, detect live-but-unresponsive listeners with independent positive controls, preserve nftsets on DNS failure, snapshot SQLite consistently, and make the existing systemd/DHCP integration deterministic.

**Tech Stack:** Bash, systemd, SmartDNS, sing-box, AdGuard Home, nftables, Python 3 `sqlite3`, dhcpcd, strongSwan, Xray.

## Global Constraints

- Routing remains domain based; do not force all WeChat, mini-program, UnionPay, or Chinese traffic into one route.
- Keep `default`, `AI`, and `CN` classifications and current IPsec egress modes unchanged.
- Keep the external SOCKS listener exactly `192.168.8.200:10800`; never replace it with `0.0.0.0:1080`.
- Keep WeChat domains classified as `default` unless an existing explicit domain rule says otherwise.
- Never write a static address for `macbookair.local`.
- Keep RouterOS at `192.168.8.253`, the VM at `192.168.8.200`, and IPv6 enabled.
- Preserve all pre-existing uncommitted edits in `install.sh` and `tests/install_contract_test.sh`.
- Never print or commit credentials, web passwords, Xray URIs, or unredacted configuration.

---

## File Map

- Modify: `install.sh`
  - Render SmartDNS HTTP/1.1 mitigation and service drop-in.
  - Render corrected timers and dhcpcd resolver ownership.
  - Add the watchdog, failure-safe nftset refresh, real connectivity probes,
    and consistent backup implementation to the embedded management script.
- Modify: `tests/install_contract_test.sh`
  - Lock rendered configuration, timer, policy, and invariant contracts.
- Create: `tests/runtime_reliability_test.sh`
  - Execute the rendered management script against fake `dig`, `nft`, and
    `systemctl` commands to test failure behaviour without root access.
- Existing: `docs/superpowers/specs/2026-07-17-vm-network-reliability-design.md`
  - Source of truth for acceptance criteria; no implementation edits needed.

### Task 0: Preserve the Approved Dirty-Tree Baseline

**Files:**
- Existing modified file: `install.sh`
- Existing modified file: `tests/install_contract_test.sh`

**Interfaces:**
- Consumes: the approved domain-routing, Xray, `.local`, QUIC, health, and UI
  work already present in the working tree.
- Produces: a verified baseline commit so later task commits contain only their
  own reliability changes.

- [ ] **Step 1: Save an external safety copy of the current patch**

```bash
git diff --binary -- install.sh tests/install_contract_test.sh \
  > /tmp/dnscomplex-approved-baseline-20260718.patch
test -s /tmp/dnscomplex-approved-baseline-20260718.patch
```

Expected: the patch file exists and is non-empty.

- [ ] **Step 2: Verify the current baseline before committing it**

```bash
bash -n install.sh
bash tests/install_contract_test.sh
git diff --check -- install.sh tests/install_contract_test.sh
```

Expected: syntax check exits zero, the contract test reports
`install contract test: ok`, and `git diff --check` is silent.

- [ ] **Step 3: Check that the baseline does not contain deployed secrets**

```bash
{ git diff -- install.sh tests/install_contract_test.sh |
    rg -n 'AI_IPSEC_PASSWORD|CN_IPSEC_PASSWORD|DNSCOMPLEX_WEB_PASSWORD|vmess://|vless://|trojan://|ss://' ||
    true; } > /tmp/dnscomplex-baseline-sensitive-lines.txt
sed -n '1,200p' /tmp/dnscomplex-baseline-sensitive-lines.txt
```

Expected: only variable names, redaction code, and fixture values appear.
There must be no deployed credential, web password, or Xray URI.

- [ ] **Step 4: Commit only the two approved baseline files**

```bash
git add install.sh tests/install_contract_test.sh
git diff --cached --check
git commit -m "fix: preserve current split-routing improvements"
```

Expected: the specification and plan remain separate documentation changes;
the baseline commit contains only `install.sh` and
`tests/install_contract_test.sh`.

### Task 1: Render Stable SmartDNS, DHCP, and Timer Configuration

**Files:**
- Modify: `tests/install_contract_test.sh`
- Modify: `install.sh`

**Interfaces:**
- Consumes: existing `smartdns_upstream_line`, `render_ipsec_services`,
  `render_all`, and `enable_services`.
- Produces: `configure_dhcpcd_resolver_ownership`,
  `/etc/systemd/system/smartdns.service.d/dnscomplex.conf`, and corrected
  timer unit files.

- [ ] **Step 1: Add failing render-contract assertions**

Add these assertions after the existing SmartDNS and systemd assertions:

```bash
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" \
  'server-https https://cloudflare-dns.com/dns-query -group default -alpn http/1.1'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" \
  'server-https https://dns.alidns.com/dns-query -group cn -alpn http/1.1'
assert_file "$tmpdir/root/etc/systemd/system/smartdns.service.d/dnscomplex.conf"
assert_contains "$tmpdir/root/etc/systemd/system/smartdns.service.d/dnscomplex.conf" 'Restart=always'
assert_contains "$tmpdir/root/etc/systemd/system/smartdns.service.d/dnscomplex.conf" 'RestartSec=2s'
assert_contains "$tmpdir/root/etc/systemd/system/smartdns.service.d/dnscomplex.conf" 'TimeoutStopSec=5s'
assert_contains "$tmpdir/root/etc/dhcpcd.conf" 'nohook resolv.conf'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.timer" \
  'OnCalendar=*-*-* 00/6:00:00'
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.timer" \
  'OnUnitActiveSec=6h'
assert_contains "$repo_root/install.sh" 'dhcpcd --rebind "$WAN_IFACE"'
assert_contains "$repo_root/install.sh" 'systemctl restart dnscomplex-health.timer'
```

- [ ] **Step 2: Run the contract test and confirm RED**

Run:

```bash
bash tests/install_contract_test.sh
```

Expected: failure naming the missing HTTP/1.1 SmartDNS line or service drop-in.

- [ ] **Step 3: Implement the render changes**

Change the HTTPS branch of `smartdns_upstream_line` to:

```bash
https://*|http://*)
  printf 'server-https %s -group %s -alpn http/1.1\n' "$upstream" "$group"
  ;;
```

Add an idempotent dhcpcd renderer:

```bash
configure_dhcpcd_resolver_ownership() {
  [[ "$DEPLOY_MODE" == "routeros-policy" ]] || return 0
  local target
  target=$(target_path /etc/dhcpcd.conf)
  mkdir -p "$(dirname "$target")"
  touch "$target"
  if ! grep -Eq '^[[:space:]]*nohook[[:space:]]+([^#]*,[[:space:]]*)?resolv[.]conf([[:space:]],|[[:space:]]*$)' "$target"; then
    {
      printf '\n# dnscomplex owns /etc/resolv.conf in routeros-policy mode.\n'
      printf 'nohook resolv.conf\n'
    } >>"$target"
  fi
}
```

Call it from `render_all` before service files are rendered. Render the
SmartDNS drop-in from `render_ipsec_services`:

```ini
[Unit]
StartLimitIntervalSec=60s
StartLimitBurst=5

[Service]
Restart=always
RestartSec=2s
TimeoutStopSec=5s
```

Replace the CN override timer schedule with:

```ini
[Timer]
OnCalendar=*-*-* 00/6:00:00
RandomizedDelaySec=10m
Persistent=true
Unit=dnscomplex-cn-overrides.service
```

After `systemctl enable --now` in `enable_services`, explicitly restart the
rendered timers:

```bash
systemctl restart \
  dnscomplex-health.timer \
  dnscomplex-update.timer \
  dnscomplex-cn-overrides.timer \
  dnscomplex-nftset-refresh.timer \
  dnscomplex-metrics-sample.timer
if [[ "$DEPLOY_MODE" == "routeros-policy" ]] && command -v dhcpcd >/dev/null 2>&1; then
  dhcpcd --rebind "$WAN_IFACE" || warn "dhcpcd could not reload nohook resolv.conf"
fi
```

- [ ] **Step 4: Run the contract test and confirm GREEN**

Run:

```bash
bash tests/install_contract_test.sh
```

Expected: `install contract test: ok`.

- [ ] **Step 5: Commit the configuration rendering task**

```bash
git add install.sh tests/install_contract_test.sh
git commit -m "fix: harden DNS service and timer rendering"
```

### Task 2: Add a Symptom-Based SmartDNS Watchdog

**Files:**
- Create: `tests/runtime_reliability_test.sh`
- Modify: `tests/install_contract_test.sh`
- Modify: `install.sh`

**Interfaces:**
- Consumes: rendered `/usr/local/sbin/dnscomplex`, SmartDNS ports from
  `config.env`, and `dnscomplex-health.timer`.
- Produces: `smartdns_listener_round`, `direct_dns_available`,
  `wait_smartdns_listeners`, and `watchdog_cmd`.

- [ ] **Step 1: Add the watchdog behaviour test**

The test renders the manager into a temporary root, supplies fake commands in
`PATH`, and runs these scenarios:

```bash
#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_contains() { grep -Fq -- "$2" "$1" || fail "missing '$2' in $1"; }
assert_not_contains() {
  if grep -Fq -- "$2" "$1"; then fail "unexpected '$2' in $1"; fi
}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmpdir=$(mktemp -d)
writer_pid=""
cleanup() {
  [[ -z "$writer_pid" ]] || kill "$writer_pid" 2>/dev/null || true
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
exec /usr/bin/id "$@"
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
```

Create the fake `dig` command with the scenario switch below, then make every
fake executable and define the execution helpers:

```bash
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
```

`run_manager` inherits `DNS_TEST_SCENARIO` from each scenario invocation. The
fake `dig` executable is:

```bash
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
  nft_success) printf '93.184.216.34\n' ;;
  external_down) exit 9 ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$fakebin/dig"
```

Run these assertions:

```bash
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
```

Append this to the contract test so the new test cannot be skipped:

```bash
bash "$repo_root/tests/runtime_reliability_test.sh"
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-health.service" \
  'ExecStart=/usr/local/sbin/dnscomplex watchdog'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'SmartDNS listeners and direct DNS positive controls are unavailable'
watchdog_body=$(awk '
  /^watchdog_cmd\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$watchdog_body" in
  *'swanctl --load-all'*|*migrate_config_cmd*|*apply_runtime_network_settings*)
    fail "watchdog contains unconditional heavy repair work"
    ;;
esac
```

- [ ] **Step 2: Run the new test and confirm RED**

Run:

```bash
bash tests/runtime_reliability_test.sh
```

Expected: failure because `watchdog` is an unknown command.

- [ ] **Step 3: Make manager paths testable**

At the top of the embedded manager, replace fixed state paths with:

```bash
CONFIG=${DNSCOMPLEX_CONFIG:-/etc/dnscomplex/config.env}
BASE=${DNSCOMPLEX_BASE:-/var/lib/dnscomplex}
RUN_DIR=${DNSCOMPLEX_RUN_DIR:-/run/dnscomplex}
FS_ROOT=${DNSCOMPLEX_FS_ROOT:-}
MAINTENANCE_LOCK=${DNSCOMPLEX_MAINTENANCE_LOCK:-/run/lock/dnscomplex-maintenance.lock}
GEO_DIR=$BASE/geosite
DLC_DIR=$GEO_DIR/domain-list-community
```

- [ ] **Step 4: Implement the watchdog**

Add these bounded probes:

```bash
smartdns_probe() {
  local domain=$1 port=$2
  dig +time=2 +tries=1 +short A "$domain" @127.0.0.1 -p "$port" 2>/dev/null |
    grep -Eq '^[0-9]+([.][0-9]+){3}$'
}

smartdns_listener_round() {
  local failed=0
  smartdns_probe example.com "$SMARTDNS_DEFAULT_PORT" || failed=1
  smartdns_probe openai.com "$SMARTDNS_AI_PORT" || failed=1
  smartdns_probe youku.com "$SMARTDNS_CN_PORT" || failed=1
  return "$failed"
}

direct_dns_available() {
  local server
  for server in 1.1.1.1 223.5.5.5; do
    if dig +time=2 +tries=1 +short A example.com "@$server" 2>/dev/null |
      grep -Eq '^[0-9]+([.][0-9]+){3}$'; then
      return 0
    fi
  done
  return 1
}

wait_smartdns_listeners() {
  local attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    smartdns_listener_round && return 0
    sleep 1
  done
  return 1
}

repair_policy_routes_if_needed() {
  command -v ip >/dev/null 2>&1 || return 0
  local rules
  rules=$(ip rule show 2>/dev/null || true)
  if ! grep -Eq "fwmark ${AI_MARK}.*lookup ${AI_TABLE}" <<<"$rules" ||
     ! grep -Eq "fwmark ${CN_MARK}.*lookup ${CN_TABLE}" <<<"$rules"; then
    "$0" routes up || warn "policy routes are missing and could not be repaired"
  fi
}

repair_ipsec_children_if_needed() {
  command -v swanctl >/dev/null 2>&1 || return 0
  local child mode
  for child in ai cn; do
    case "$child" in
      ai) mode=${AI_EGRESS_MODE:-ipsec} ;;
      cn) mode=${CN_EGRESS_MODE:-ipsec} ;;
    esac
    [[ "$mode" == "ipsec" ]] || continue
    if ! timeout 5 swanctl --list-sas 2>/dev/null |
      grep -Eq "^${child}: #[0-9]+, ESTABLISHED"; then
      timeout 15 swanctl --initiate --child "$child" >/dev/null 2>&1 ||
        warn "$child IPsec child is not established"
    fi
  done
}
```

Implement `watchdog_cmd` with these exact decisions:

```bash
watchdog_cmd() {
  need_root
  local unit now last=0
  mkdir -p "$RUN_DIR"

  for unit in nftables smartdns AdGuardHome sing-box; do
    systemctl is-active --quiet "$unit" || systemctl restart "$unit"
  done
  if [[ "${XRAY_ENABLED:-1}" == "1" ]]; then
    systemctl is-active --quiet xray-dnscomplex || systemctl restart xray-dnscomplex
  fi
  repair_policy_routes_if_needed
  repair_ipsec_children_if_needed

  if smartdns_listener_round; then
    return 0
  fi
  sleep 2
  if smartdns_listener_round; then
    return 0
  fi
  if ! direct_dns_available; then
    warn "SmartDNS listeners and direct DNS positive controls are unavailable; external outage suspected"
    return 1
  fi

  now=$(date +%s)
  [[ -r "$RUN_DIR/smartdns.last_restart" ]] && read -r last <"$RUN_DIR/smartdns.last_restart"
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  if ((now - last < 600)); then
    warn "SmartDNS remains unresponsive inside the 600-second restart cooldown"
    return 1
  fi

  printf '%s\n' "$now" >"$RUN_DIR/smartdns.last_restart"
  systemctl restart smartdns
  wait_smartdns_listeners || {
    warn "SmartDNS restart did not restore all listeners"
    return 1
  }
  systemctl start --no-block dnscomplex-nftset-refresh.service || true
}
```

Add `watchdog` to usage and main dispatch. Change the health service to execute
`dnscomplex watchdog`. Keep `health --json` read-only; plain `health` delegates
to `watchdog_cmd` for compatibility. Remove unconditional config migration,
sysctl rewrites, `systemctl enable`, `swanctl --load-all`, and route rewrites
from the timer path.

- [ ] **Step 5: Run watchdog tests and confirm GREEN**

Run:

```bash
bash tests/runtime_reliability_test.sh
bash tests/install_contract_test.sh
```

Expected: both tests report `ok`.

- [ ] **Step 6: Commit the watchdog task**

```bash
git add install.sh tests/install_contract_test.sh tests/runtime_reliability_test.sh
git commit -m "fix: recover live-but-stalled SmartDNS"
```

### Task 3: Preserve nftsets When DNS Fails

**Files:**
- Modify: `tests/runtime_reliability_test.sh`
- Modify: `tests/install_contract_test.sh`
- Modify: `install.sh`

**Interfaces:**
- Consumes: `nftset_refresh_domain_stream`, `public_ipv4`, `$BASE`, and
  `DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT`.
- Produces: failure-safe `refresh_nftset_group` and `refresh_nftsets_cmd`.

- [ ] **Step 1: Replace the destructive contract**

Remove the existing assertion that `refresh-nftsets` must flush before
repopulation. Add:

```bash
refresh_nftsets_body=$(awk '
  /^refresh_nftsets_cmd\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$refresh_nftsets_body" in
  *flush_policy_nftsets_cmd*) fail "refresh-nftsets must not flush last-known-good policy sets" ;;
esac
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'zero usable answers; keeping last-known-good'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  '"$BASE/nftset-${profile}.last_refresh"'
```

Extend the runtime test:

```bash
before_ai=unchanged
printf '%s\n' "$before_ai" >"$state/nftset-ai.last_refresh"
DNS_TEST_SCENARIO=external_down run_manager refresh-nftsets && \
  fail "zero-answer refresh must fail"
[[ "$(cat "$state/nftset-ai.last_refresh")" == "$before_ai" ]] || \
  fail "zero-answer refresh changed freshness timestamp"
assert_not_contains "$calls" 'flush set'

DNS_TEST_SCENARIO=nft_success run_manager refresh-nftsets
assert_contains "$calls" 'add element inet dnscomplex ai4'
assert_contains "$calls" 'add element inet dnscomplex cn4'
[[ "$(cat "$state/nftset-ai.last_refresh")" =~ ^[0-9]+$ ]] || \
  fail "successful AI refresh did not update freshness"
```

- [ ] **Step 2: Run the runtime test and confirm RED**

Run:

```bash
bash tests/runtime_reliability_test.sh
```

Expected: zero-answer scenario changes timestamps or logs a set flush.

- [ ] **Step 3: Implement candidate-first refresh**

Rewrite `refresh_nftset_group` to:

```bash
refresh_nftset_group() {
  local profile=$1 port=$2 set_name=$3
  local domain output ip domains=0 answered=0 failed=0 added=0
  local candidates batch
  candidates=$(mktemp)
  batch=$(mktemp)

  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    domains=$((domains + 1))
    output=$(dig +time=2 +tries=1 +short "@127.0.0.1" -p "$port" A "$domain" 2>/dev/null |
      grep -E '^[0-9]+([.][0-9]+){3}$' || true)
    if [[ -z "$output" ]]; then
      failed=$((failed + 1))
      continue
    fi
    answered=$((answered + 1))
    while IFS= read -r ip; do
      public_ipv4 "$ip" && printf '%s\n' "$ip" >>"$candidates"
    done <<<"$output"
  done < <(nftset_refresh_domain_stream "$profile")

  sort -u -o "$candidates" "$candidates"
  if [[ "$answered" == "0" || ! -s "$candidates" ]]; then
    rm -f "$candidates" "$batch"
    warn "$profile nftset refresh had zero usable answers; keeping last-known-good elements"
    return 1
  fi

  while IFS= read -r ip; do
    if ! nft get element inet dnscomplex "$set_name" "{ $ip }" >/dev/null 2>&1; then
      printf 'add element inet dnscomplex %s { %s timeout %s }\n' \
        "$set_name" "$ip" "$DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT" >>"$batch"
      added=$((added + 1))
    fi
  done <"$candidates"

  if [[ -s "$batch" ]] && ! nft -f "$batch"; then
    while IFS= read -r ip; do
      nft get element inet dnscomplex "$set_name" "{ $ip }" >/dev/null 2>&1 || {
        rm -f "$candidates" "$batch"
        warn "$profile nftset transaction failed; keeping existing elements"
        return 1
      }
    done <"$candidates"
  fi

  mkdir -p "$BASE"
  date +%s >"$BASE/nftset-${profile}.last_refresh"
  log "refreshed $profile nftset: domains=$domains answered=$answered new_ips=$added no_answer=$failed"
  rm -f "$candidates" "$batch"
}
```

Remove `flush_policy_nftsets_cmd` from `refresh_nftsets_cmd`, run AI and CN
independently, and return non-zero if either profile fails:

```bash
local failed=0
refresh_nftset_group ai "$SMARTDNS_AI_PORT" ai4 || failed=1
refresh_nftset_group cn "$SMARTDNS_CN_PORT" cn4 || failed=1
return "$failed"
```

- [ ] **Step 4: Run nftset and contract tests and confirm GREEN**

Run:

```bash
bash tests/runtime_reliability_test.sh
bash tests/install_contract_test.sh
```

Expected: both tests report `ok`; no rendered refresh command calls
`flush_policy_nftsets_cmd`.

- [ ] **Step 5: Commit the nftset task**

```bash
git add install.sh tests/install_contract_test.sh tests/runtime_reliability_test.sh
git commit -m "fix: retain routing sets during DNS outages"
```

### Task 4: Make Backups Consistent During Metrics Writes

**Files:**
- Modify: `tests/runtime_reliability_test.sh`
- Modify: `tests/install_contract_test.sh`
- Modify: `install.sh`

**Interfaces:**
- Consumes: `FS_ROOT`, Python 3 `sqlite3`, `tar`, and `flock`.
- Produces: `acquire_maintenance_lock`, `fs_path`, `snapshot_copy`,
  `sqlite_backup`, and locked backup/update commands.

- [ ] **Step 1: Add a live-SQLite backup test**

Create a fake root containing the managed config directories and a SQLite
database. Start a background Python writer, invoke backup, stop the writer,
then verify:

```bash
for rel in \
  etc/dnscomplex \
  etc/sing-box \
  etc/smartdns \
  etc/AdGuardHome \
  etc/swanctl \
  etc/nftables.d \
  var/lib/dnscomplex; do
  mkdir -p "$fake_root/$rel"
done
printf 'fixture\n' >"$fake_root/etc/dnscomplex/config.env"
printf 'fixture\n' >"$fake_root/etc/nftables.d/dnscomplex.nft"

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
run_manager backup "$archive"
kill "$writer_pid" 2>/dev/null || true
wait "$writer_pid" 2>/dev/null || true
writer_pid=""

tar -tzf "$archive" | grep -Fxq './var/lib/dnscomplex/metrics.sqlite3'
if tar -tzf "$archive" | grep -Eq 'metrics[.]sqlite3-(wal|shm)$'; then
  fail "backup contains transient SQLite sidecar files"
fi
tar -xzf "$archive" -C "$extract"
python3 - "$extract/var/lib/dnscomplex/metrics.sqlite3" <<'PY'
import sqlite3
import sys
db = sqlite3.connect(sys.argv[1])
assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
assert db.execute("SELECT COUNT(*) FROM samples").fetchone()[0] > 0
PY
```

Also assert the archive does not contain
`metrics.sqlite3-wal` or `metrics.sqlite3-shm`.

- [ ] **Step 2: Run the backup test and confirm RED**

Run:

```bash
bash tests/runtime_reliability_test.sh
```

Expected: the current backup reads real `/etc` paths or fails while the
database changes.

- [ ] **Step 3: Implement immutable staging and SQLite backup**

Add:

```bash
acquire_maintenance_lock() {
  [[ "${DNSCOMPLEX_MAINTENANCE_LOCK_HELD:-0}" == "1" ]] && return 0
  mkdir -p "$(dirname "$MAINTENANCE_LOCK")"
  exec 9>"$MAINTENANCE_LOCK"
  flock -n 9 ||
    die "another dnscomplex backup or update is already running"
  DNSCOMPLEX_MAINTENANCE_LOCK_HELD=1
}

fs_path() {
  printf '%s%s\n' "$FS_ROOT" "$1"
}

snapshot_copy() {
  local stage=$1 rel=$2 src dst
  src=$(fs_path "/$rel")
  dst="$stage/$rel"
  [[ -e "$src" ]] || return 0
  mkdir -p "$(dirname "$dst")"
  cp -a "$src" "$dst"
}

sqlite_backup() {
  local source=$1 destination=$2
  python3 - "$source" "$destination" <<'PY'
import os
import sqlite3
import sys
source, destination = sys.argv[1:3]
os.makedirs(os.path.dirname(destination), exist_ok=True)
src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
dst = sqlite3.connect(destination)
with dst:
    src.backup(dst)
if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
    raise SystemExit("SQLite backup integrity check failed")
dst.close()
src.close()
PY
}
```

Use this backup implementation:

```bash
backup_cmd() {
  need_root
  local output=${1:-"/var/backups/dnscomplex-$(date +%Y%m%d-%H%M%S).tar.gz"}
  acquire_maintenance_lock
  mkdir -p "$(dirname "$output")"

  (
    set -e
    local stage verify rel live_db archived_db
    stage=$(mktemp -d)
    verify=$(mktemp -d)
    trap 'rm -rf "$stage" "$verify"' EXIT

    for rel in \
      etc/dnscomplex \
      etc/sing-box \
      etc/smartdns \
      etc/AdGuardHome \
      etc/swanctl \
      etc/nftables.d/dnscomplex.nft \
      var/lib/dnscomplex; do
      snapshot_copy "$stage" "$rel"
    done

    rm -f \
      "$stage/var/lib/dnscomplex/metrics.sqlite3-wal" \
      "$stage/var/lib/dnscomplex/metrics.sqlite3-shm"
    live_db=$(fs_path /var/lib/dnscomplex/metrics.sqlite3)
    archived_db="$stage/var/lib/dnscomplex/metrics.sqlite3"
    if [[ -f "$live_db" ]]; then
      rm -f "$archived_db"
      sqlite_backup "$live_db" "$archived_db"
    fi

    tar -czf "$output" -C "$stage" .
    tar -tzf "$output" >/dev/null
    if [[ -f "$archived_db" ]]; then
      tar -xzf "$output" -C "$verify" ./var/lib/dnscomplex/metrics.sqlite3
      python3 - "$verify/var/lib/dnscomplex/metrics.sqlite3" <<'PY'
import sqlite3
import sys
db = sqlite3.connect(sys.argv[1])
result = db.execute("PRAGMA integrity_check").fetchone()[0]
db.close()
if result != "ok":
    raise SystemExit("archived SQLite integrity check failed")
PY
    fi
  )
  log "backup written: $output"
}
```

Call `acquire_maintenance_lock` at the start of `update_software_cmd`. Its
nested `backup_cmd` sees `DNSCOMPLEX_MAINTENANCE_LOCK_HELD=1` and reuses the
same process-level lock instead of locking again.

Add contract assertions for `src.backup(dst)`,
`/run/lock/dnscomplex-maintenance.lock`, `acquire_maintenance_lock`, and
`PRAGMA integrity_check`.

- [ ] **Step 4: Run the backup and complete contract tests**

Run:

```bash
bash tests/runtime_reliability_test.sh
bash tests/install_contract_test.sh
```

Expected: both report `ok`, including the live-writer backup test.

- [ ] **Step 5: Commit the backup task**

```bash
git add install.sh tests/install_contract_test.sh tests/runtime_reliability_test.sh
git commit -m "fix: snapshot live state before backup"
```

### Task 5: Test Real Connectivity and Lock All Invariants

**Files:**
- Modify: `tests/install_contract_test.sh`
- Modify: `install.sh`

**Interfaces:**
- Consumes: embedded Python `health_checks_json`.
- Produces: `tcp_connectivity` checks for IPv4 and IPv6.

- [ ] **Step 1: Add failing health and invariant assertions**

Add assertions for:

```bash
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'socket.AF_INET'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'socket.AF_INET6'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'default-ipv4-connectivity'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'default-ipv6-connectivity'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'IPv6 route lookup ok'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'SmartDNS listeners and direct DNS positive controls are unavailable'
```

Retain and re-run every existing assertion for SOCKS, AI/CN egress,
`LOCAL_DOMAIN_IPV6_POLICY`, RouterOS, and domain lists.

- [ ] **Step 2: Run the contract test and confirm RED**

Run:

```bash
bash tests/install_contract_test.sh
```

Expected: missing `default-ipv4-connectivity`.

- [ ] **Step 3: Replace the IPv6 route-only health check**

In the embedded health Python add `import socket`, then add:

```python
def tcp_connectivity(host, family, timeout=3.0):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        address = (host, 443, 0, 0) if family == socket.AF_INET6 else (host, 443)
        sock.connect(address)
        return True
    except OSError:
        return False
    finally:
        sock.close()
```

Add an IPv4 check against `1.1.1.1:443`. For IPv6 `off`, report informational
success; otherwise try both `2606:4700:4700::1111` and
`2001:4860:4860::8888`, succeeding if either connects.

- [ ] **Step 4: Run all local verification**

Run:

```bash
bash -n install.sh
bash -n tests/install_contract_test.sh
bash -n tests/runtime_reliability_test.sh
bash tests/runtime_reliability_test.sh
bash tests/install_contract_test.sh
git diff --check
```

Expected: every command exits zero; both test scripts report `ok`.

- [ ] **Step 5: Review the complete diff against the specification**

Run:

```bash
git diff -- install.sh tests/install_contract_test.sh tests/runtime_reliability_test.sh
rg -n '0[.]0[.]0[.]0:1080|macbookair[.]local|flush_policy_nftsets_cmd' \
  install.sh tests
```

Expected:

- no new forced `0.0.0.0:1080` deployment value;
- no static `macbookair.local` entry;
- no call to `flush_policy_nftsets_cmd` inside `refresh_nftsets_cmd`;
- existing default/AI/CN domain rendering remains present.

- [ ] **Step 6: Commit the completed local implementation**

```bash
git add install.sh tests/install_contract_test.sh tests/runtime_reliability_test.sh
git commit -m "fix: complete VM network reliability safeguards"
```

### Task 6: Capture and Repair the Remote VM

**Files:**
- Deploy: local `install.sh` to remote `/root/install.sh`
- Read/modify remotely: managed files generated by `install.sh`

**Interfaces:**
- Consumes: current `/etc/dnscomplex/config.env` without printing it.
- Produces: repaired services and a pre-change archive under `/var/backups`.

- [ ] **Step 1: Capture a redacted pre-change evidence bundle**

Run read-only commands and save output locally under `/tmp`:

```bash
ssh root@192.168.8.200 \
  'date -Is; uptime; free -h; df -h /; systemctl --failed --no-pager' \
  > /tmp/dnscomplex-pre-system.txt
ssh root@192.168.8.200 \
  'ss -lunp; ip -s link show ens18; ip route; ip -6 route' \
  > /tmp/dnscomplex-pre-network.txt
ssh root@192.168.8.200 'dnscomplex health --json' \
  > /tmp/dnscomplex-pre-health.json || true
ssh root@192.168.8.200 \
  'systemctl list-timers "dnscomplex-*" --all --no-pager' \
  > /tmp/dnscomplex-pre-timers.txt
ssh root@192.168.8.200 'sha256sum /root/install.sh' \
  > /tmp/dnscomplex-pre-installer-sha256.txt
```

Expected precondition: SmartDNS queues or listener probes still demonstrate
the outage, unless the process recovered independently.

- [ ] **Step 2: Create an out-of-band backup before replacing the manager**

Temporarily stop writers, archive state, and immediately restart them:

```bash
ssh root@192.168.8.200 \
  'systemctl stop dnscomplex-update.timer dnscomplex-cn-overrides.timer dnscomplex-nftset-refresh.timer dnscomplex-metrics-sample.timer dnscomplex-metrics-sample.service dnscomplex-metrics.service'
ssh root@192.168.8.200 \
  'tar -czf /var/backups/dnscomplex-pre-reliability-20260718.tar.gz /etc/dnscomplex /etc/sing-box /etc/smartdns /etc/AdGuardHome /etc/swanctl /etc/nftables.d/dnscomplex.nft /var/lib/dnscomplex /root/install.sh'
ssh root@192.168.8.200 \
  'systemctl start dnscomplex-metrics.service dnscomplex-metrics-sample.timer dnscomplex-nftset-refresh.timer dnscomplex-cn-overrides.timer dnscomplex-update.timer'
ssh root@192.168.8.200 \
  'tar -tzf /var/backups/dnscomplex-pre-reliability-20260718.tar.gz >/dev/null'
```

Expected: archive validation exits zero.

- [ ] **Step 3: Record invariant values without exposing secrets**

Use a remote shell that prints only the approved non-secret keys:

```bash
ssh root@192.168.8.200 'bash -s' <<'REMOTE'
set -euo pipefail
. /etc/dnscomplex/config.env
for key in \
  DEPLOY_MODE \
  ROUTEROS_LAN_IPV4 \
  LINUX_LAN_IPV4 \
  SINGBOX_SOCKS_LISTEN \
  SINGBOX_SOCKS_PORT \
  AI_EGRESS_MODE \
  CN_EGRESS_MODE \
  AI_QUIC_POLICY \
  CN_QUIC_POLICY \
  LOCAL_DOMAIN_IPV6_POLICY \
  DEFAULT_IPV6_MODE; do
  printf '%s=%s\n' "$key" "${!key}"
done
REMOTE
```

Expected: `routeros-policy`, `192.168.8.253`, `192.168.8.200`,
`192.168.8.200`, `10800`, current AI/CN modes, `reject`, `reject`,
`ipv4_only`, and `auto`.

- [ ] **Step 4: Deploy the tested installer**

Run:

```bash
scp install.sh root@192.168.8.200:/root/install.sh.new
ssh root@192.168.8.200 \
  'install -m 0755 /root/install.sh.new /root/install.sh && /root/install.sh --config /etc/dnscomplex/config.env --yes'
```

Expected: installer completes and service validation produces no syntax or
configuration error.

- [ ] **Step 5: Clear the active deadlock and warm policy state**

Run:

```bash
ssh root@192.168.8.200 \
  'systemctl restart smartdns && dnscomplex refresh-nftsets && dnscomplex test-dns'
```

Expected: all three SmartDNS profiles and port 53 answer.

### Task 7: Prove Recovery, Routing, and Data Safety Remotely

**Files:**
- Verify only; no new source files.

**Interfaces:**
- Consumes: deployed watchdog, nftset refresh, backup, and existing soak runner.
- Produces: fresh evidence for every remote acceptance criterion.

- [ ] **Step 1: Verify DNS latency and listener queues**

Run repeated queries through ports `6053`, `6054`, `6055`, `1053`, and `53`,
then inspect `ss -lunp`.

```bash
ssh root@192.168.8.200 'bash -s' <<'REMOTE'
set -euo pipefail
for iteration in 1 2 3 4 5; do
  dig +time=2 +tries=1 +short A example.com @127.0.0.1 -p 6053 | grep -Eq '^[0-9]+([.][0-9]+){3}$'
  dig +time=2 +tries=1 +short A openai.com @127.0.0.1 -p 6054 | grep -Eq '^[0-9]+([.][0-9]+){3}$'
  dig +time=2 +tries=1 +short A youku.com @127.0.0.1 -p 6055 | grep -Eq '^[0-9]+([.][0-9]+){3}$'
  dig +time=2 +tries=1 +short A example.com @127.0.0.1 -p 1053 | grep -Eq '^[0-9]+([.][0-9]+){3}$'
  dig +time=2 +tries=1 +short A example.com @127.0.0.1 -p 53 | grep -Eq '^[0-9]+([.][0-9]+){3}$'
done
ss -lunp | grep -E ':(53|1053|6053|6054|6055)[[:space:]]'
REMOTE
```

Expected:

- every query succeeds;
- normal cached queries complete well below 500 ms;
- SmartDNS receive queues remain near zero.

- [ ] **Step 2: Verify classification and unchanged policy**

Run:

```bash
ssh root@192.168.8.200 'dnscomplex trace-domain openai.com'
ssh root@192.168.8.200 'dnscomplex trace-domain youku.com'
ssh root@192.168.8.200 'dnscomplex trace-domain servicewechat.com'
ssh root@192.168.8.200 'dnscomplex trace-domain weixin.qq.com'
ssh root@192.168.8.200 'swanctl --list-sas; ip rule; ip route show table 301; ip route show table 351'
```

Expected: OpenAI is AI, Youku is CN, WeChat examples remain default, both
selected IPsec SAs are established, and policy tables remain present.

- [ ] **Step 3: Verify SOCKS from the Xray server**

Run:

```bash
ssh root@192.168.8.180 \
  'curl --socks5-hostname 192.168.8.200:10800 --connect-timeout 8 -fsS -o /dev/null https://www.example.com/'
```

Expected: exit zero. Confirm the VM still listens on
`192.168.8.200:10800`.

- [ ] **Step 4: Fault-inject nftset refresh**

Record nftset counts and freshness timestamps. Stop the health timer, send
`SIGSTOP` to SmartDNS, run `dnscomplex refresh-nftsets`, and expect failure.
Then compare counts/timestamps, restart SmartDNS, and re-enable the timer.

```bash
ssh root@192.168.8.200 'bash -s' <<'REMOTE'
set -euo pipefail
set_count() {
  nft list set inet dnscomplex "$1" |
    grep -Eo '([0-9]{1,3}[.]){3}[0-9]{1,3}' |
    wc -l
}
systemctl stop dnscomplex-health.timer
pid=$(cat /run/smartdns.pid)
cleanup() {
  kill -CONT "$pid" 2>/dev/null || true
  systemctl restart smartdns
  systemctl start dnscomplex-health.timer
}
trap cleanup EXIT

ai_before=$(set_count ai4)
cn_before=$(set_count cn4)
ai_stamp_before=$(cat /var/lib/dnscomplex/nftset-ai.last_refresh)
cn_stamp_before=$(cat /var/lib/dnscomplex/nftset-cn.last_refresh)
kill -STOP "$pid"
set +e
dnscomplex refresh-nftsets
rc=$?
set -e
[[ "$rc" != "0" ]]
[[ "$(set_count ai4)" == "$ai_before" ]]
[[ "$(set_count cn4)" == "$cn_before" ]]
[[ "$(cat /var/lib/dnscomplex/nftset-ai.last_refresh)" == "$ai_stamp_before" ]]
[[ "$(cat /var/lib/dnscomplex/nftset-cn.last_refresh)" == "$cn_stamp_before" ]]
REMOTE
```

Expected:

- refresh exits non-zero;
- prior set entries remain;
- freshness timestamps remain unchanged;
- DNS recovers after SmartDNS restart.

- [ ] **Step 5: Fault-inject a live-but-unresponsive resolver**

Stop the health timer, record the SmartDNS PID, send `SIGSTOP`, run
`dnscomplex watchdog`, record the new PID, and restart the timer.

```bash
ssh root@192.168.8.200 'bash -s' <<'REMOTE'
set -euo pipefail
systemctl stop dnscomplex-health.timer
cleanup() {
  systemctl restart smartdns 2>/dev/null || true
  systemctl start dnscomplex-health.timer
}
trap cleanup EXIT
rm -f /run/dnscomplex/smartdns.last_restart
old_pid=$(cat /run/smartdns.pid)
kill -STOP "$old_pid"
started=$(date +%s)
dnscomplex watchdog
elapsed=$(($(date +%s) - started))
new_pid=$(cat /run/smartdns.pid)
[[ "$new_pid" != "$old_pid" ]]
((elapsed <= 45))
dig +time=2 +tries=1 +short A example.com @127.0.0.1 -p 6053 |
  grep -Eq '^[0-9]+([.][0-9]+){3}$'
REMOTE
```

Expected:

- watchdog detects two complete listener failures;
- direct positive control succeeds;
- systemd replaces SmartDNS within the bounded interval;
- the PID changes;
- all listeners answer after recovery;
- nftset refresh is started after recovery.

- [ ] **Step 6: Verify backup while metrics remain active**

Run:

```bash
ssh root@192.168.8.200 \
  'dnscomplex backup /var/backups/dnscomplex-post-reliability.tar.gz'
ssh root@192.168.8.200 \
  'tar -tzf /var/backups/dnscomplex-post-reliability.tar.gz >/dev/null'
ssh root@192.168.8.200 \
  'systemctl reset-failed dnscomplex-update.service dnscomplex-update.timer'
```

Extract the archived metrics database into a temporary directory and run
`PRAGMA integrity_check`.

```bash
ssh root@192.168.8.200 'bash -s' <<'REMOTE'
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar -xzf /var/backups/dnscomplex-post-reliability.tar.gz \
  -C "$tmp" ./var/lib/dnscomplex/metrics.sqlite3
python3 - "$tmp/var/lib/dnscomplex/metrics.sqlite3" <<'PY'
import sqlite3
import sys
db = sqlite3.connect(sys.argv[1])
assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
db.close()
PY
if tar -tzf /var/backups/dnscomplex-post-reliability.tar.gz |
  grep -Eq 'metrics[.]sqlite3-(wal|shm)$'; then
  exit 1
fi
REMOTE
```

Expected: archive and SQLite checks both return success; no `-wal` or `-shm`
file is archived.

- [ ] **Step 7: Run a sustained soak**

Run:

```bash
ssh root@192.168.8.200 \
  'dnscomplex soak --duration 10m --clients 200 --dns-qps 25 --profiles ai,cn,default --idle-resume --output-json /var/log/dnscomplex/reliability-soak.json'
```

Expected: success ratio meets the runner threshold, p95 latency remains under
its configured limit, profile failures are zero, and SmartDNS queues do not
grow after the run.

- [ ] **Step 8: Verify timers, DHCP noise, and failed units**

Observe journals for at least two health intervals:

```bash
ssh root@192.168.8.200 'systemctl list-timers "dnscomplex-*" --all --no-pager'
ssh root@192.168.8.200 \
  'if journalctl --since "3 minutes ago" --no-pager | grep -E "resolve1|Failed to set DNS configuration"; then exit 1; fi'
ssh root@192.168.8.200 'systemctl --failed --no-pager'
```

Expected:

- health and CN override timers have future triggers;
- no repeated systemd-resolved D-Bus noise appears;
- no dnscomplex-related unit remains failed.

### Task 8: Final Synchronisation and Verification

**Files:**
- Verify: `install.sh`
- Verify: remote `/root/install.sh`

**Interfaces:**
- Consumes: all local and remote acceptance evidence.
- Produces: final matching installer hashes and repair report.

- [ ] **Step 1: Re-run all local tests fresh**

Run:

```bash
bash -n install.sh
bash tests/runtime_reliability_test.sh
bash tests/install_contract_test.sh
git diff --check
```

Expected: every command exits zero.

- [ ] **Step 2: Re-run remote health fresh**

Run:

```bash
ssh root@192.168.8.200 'dnscomplex health --json'
ssh root@192.168.8.200 'dnscomplex doctor'
ssh root@192.168.8.200 'dnscomplex test'
```

Expected: health is not `unhealthy`, doctor reports no unresolved fault, and
the complete runtime test exits zero.

- [ ] **Step 3: Compare installer hashes**

Run:

```bash
shasum -a 256 install.sh
ssh root@192.168.8.200 'sha256sum /root/install.sh'
```

Expected: both SHA-256 values are identical.

- [ ] **Step 4: Review the requirements checklist**

Check every acceptance criterion in
`docs/superpowers/specs/2026-07-17-vm-network-reliability-design.md` against
fresh command evidence. Document any external dependency failure instead of
claiming it passed.

- [ ] **Step 5: Commit any final test-only correction**

Only if Task 7 or Task 8 required a source correction:

```bash
git add install.sh tests/install_contract_test.sh tests/runtime_reliability_test.sh
git commit -m "test: close VM reliability verification gaps"
```
