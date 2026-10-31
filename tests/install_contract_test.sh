#!/usr/bin/env bash
# shellcheck disable=SC2016 # Assertions intentionally match literal shell source.
set -euo pipefail

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

assert_symlink_target() {
  local path=$1
  local expected=$2
  [[ -L "$path" ]] || fail "missing symlink: $path"
  [[ "$(readlink "$path")" == "$expected" ]] || fail "unexpected symlink target for $path: $(readlink "$path")"
}

assert_contains() {
  local file=$1
  local needle=$2
  grep -Fq -- "$needle" "$file" || fail "missing '$needle' in $file"
}

assert_not_contains() {
  local file=$1
  local needle=$2
  if grep -Fq -- "$needle" "$file"; then
    fail "unexpected '$needle' in $file"
  fi
}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

assert_file "$repo_root/install.sh"
bash -n "$repo_root/install.sh"

bash "$repo_root/install.sh" --help >/dev/null

cat >"$tmpdir/config.env" <<'EOF'
DNSCOMPLEX_NONINTERACTIVE=1
WAN_IFACE=eth0
TRANSIT_VLAN_ID=10
LAN_VLAN_ID=20
ROUTEROS_TRANSIT_IPV4=10.255.10.1
LINUX_TRANSIT_IPV4=10.255.10.2
TRANSIT_IPV4_CIDR=10.255.10.2/30
ROUTEROS_TRANSIT_IPV6=fd00:10::1
LINUX_TRANSIT_IPV6=fd00:10::2
TRANSIT_IPV6_CIDR=fd00:10::2/64
LAN_IPV4_CIDR=192.168.88.1/24
LAN_DHCP_START=192.168.88.100
LAN_DHCP_END=192.168.88.250
LAN_IPV6_PREFIX=fd00:88::/64
SINGBOX_SOCKS_LISTEN=192.168.88.1
SINGBOX_SOCKS_PORT=2080
AI_IPSEC_USERNAME=ai-user
AI_IPSEC_PASSWORD=ai-pass
CN_IPSEC_USERNAME=cn-user
CN_IPSEC_PASSWORD=cn-pass
EOF

DNSCOMPLEX_ROOT="$tmpdir/root" bash "$repo_root/install.sh" --dry-run --config "$tmpdir/config.env"

# A dry-run upgrade must replace stale helpers/units with the same emitted bytes
# and modes as a new install. Never invoke those intentionally stale fixtures.
python3 - "$repo_root/install.sh" "$tmpdir/root" "$tmpdir/artifact-baseline" <<'PY_ARTIFACTS'
from pathlib import Path
import shutil, sys
source=Path(sys.argv[1]).read_text(); root=Path(sys.argv[2]); saved=Path(sys.argv[3])
artifacts={
 'usr/local/sbin/dnscomplex': 'MANAGER',
 'usr/local/lib/dnscomplex-web/app.py': 'PY',
 'usr/local/lib/dnscomplex-soak/runner.py': 'PY',
 'usr/local/lib/dnscomplex-config/candidate.py': 'CONFIG_PARSER',
 'usr/local/lib/dnscomplex-config/adguard-auth.py': 'ADGUARD_AUTH',
 'usr/local/libexec/dnscomplex-operation': 'OPERATION_HELPER',
 'usr/local/libexec/dnscomplex-restore-recover': 'RECOVERY',
}
units=['dnscomplex-operation@.service','dnscomplex-operation-recovery@.service',
 'dnscomplex-operation-guard@.service','dnscomplex-operation-guard@.timer',
 'dnscomplex-restore-recovery.service','dnscomplex-restore-services.service']
artifacts.update({'etc/systemd/system/'+unit:'EOF' for unit in units})
manager=(root/'usr/local/sbin/dnscomplex').read_text()
backup_paths=manager.split("managed_backup_paths() {\n  cat <<'EOF'\n",1)[1].split('\nEOF',1)[0].splitlines()
for rel,marker in artifacts.items():
    path=root/rel
    writer='write_file_atomic' if marker=='MANAGER' else 'write_file'
    emitted=source.split(writer+' /'+rel+" <<'"+marker+"'\n",1)[1].split('\n'+marker+'\n',1)[0]+'\n'
    assert path.read_text()==emitted, rel+' differs from installer embedded source'
    expected_mode=0o755 if rel.startswith('usr/') else 0o644
    assert path.stat().st_mode & 0o777 == expected_mode, rel+' mode'
    if rel.startswith('usr/local/') or 'operation' in rel:
        assert any(rel==entry or rel.startswith(entry+'/') for entry in backup_paths), rel+' missing backup coverage'
    target=saved/rel; target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(path,target)
    path.write_text('stale upgrade fixture\n')
    if rel.startswith('usr/'): path.chmod(0o600)
PY_ARTIFACTS
DNSCOMPLEX_ROOT="$tmpdir/root" bash "$repo_root/install.sh" --dry-run --config "$tmpdir/config.env"
python3 - "$tmpdir/root" "$tmpdir/artifact-baseline" <<'PY_UPGRADE'
from pathlib import Path
import sys
root,saved=map(Path,sys.argv[1:])
for before in saved.rglob('*'):
    if before.is_file():
        after=root/before.relative_to(saved)
        assert before.read_bytes()==after.read_bytes(), str(after)+' upgrade bytes'
        assert before.stat().st_mode & 0o777 == after.stat().st_mode & 0o777, str(after)+' upgrade mode'
print('new install / stale upgrade: manager, web, soak, parser, operation, recovery and units match embedded source')
PY_UPGRADE
python3 "$repo_root/tests/web_diagnostic_semantics_test.py"

cat "$tmpdir/config.env" >"$tmpdir/old-ai-samples.env"
cat >>"$tmpdir/old-ai-samples.env" <<'EOF'
AI_SAMPLE_DOMAINS='openai.com anthropic.com claude.ai meta.com facebook.com instagram.com whatsapp.com threads.net'
EOF
DNSCOMPLEX_ROOT="$tmpdir/root-old-ai-samples" bash "$repo_root/install.sh" --dry-run --config "$tmpdir/old-ai-samples.env"

assert_file "$tmpdir/root/etc/sing-box/config.json"
assert_file "$tmpdir/root/etc/smartdns/smartdns.conf"
assert_file "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml"
assert_file "$tmpdir/root/etc/swanctl/swanctl.conf"
assert_file "$tmpdir/root/etc/strongswan.d/swanctl.conf"
assert_file "$tmpdir/root/etc/strongswan.d/charon/resolve.conf"
assert_file "$tmpdir/root/etc/strongswan.d/charon/agent.conf"
assert_file "$tmpdir/root/etc/strongswan.d/charon/tpm.conf"
assert_file "$tmpdir/root/etc/strongswan.d/charon/dhcp.conf"
assert_file "$tmpdir/root/etc/modules-load.d/dnscomplex.conf"
assert_file "$tmpdir/root/etc/nftables.d/dnscomplex.nft"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.timer"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-nftset-refresh.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-nftset-refresh.timer"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-network-ready.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-ipsec-ready.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-web.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-metrics.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-metrics-sample.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-metrics-sample.timer"
assert_file "$tmpdir/root/etc/systemd/system/xray-dnscomplex.service"
assert_file "$tmpdir/root/etc/systemd/system/smartdns.service.d/dnscomplex.conf"
assert_file "$tmpdir/root/etc/systemd/system/sing-box.service.d/dnscomplex.conf"
assert_file "$tmpdir/root/etc/systemd/journald.conf.d/dnscomplex.conf"
assert_symlink_target "$tmpdir/root/etc/systemd/system-generators/systemd-ssh-generator" /dev/null
assert_file "$tmpdir/root/usr/local/sbin/dnscomplex"
assert_file "$tmpdir/root/usr/local/libexec/dnscomplex-lan-alias"
assert_contains "$repo_root/install.sh" 'curl_bounded()'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'curl_bounded()'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'inspect local UDP 500/4500 underlay/firewall before updating IPsec credentials'
assert_not_contains "$repo_root/install.sh" 'curl -fsSL'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'curl -fsSL'
assert_file "$tmpdir/root/usr/local/lib/dnscomplex-xray/render.py"
assert_file "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py"
assert_file "$tmpdir/root/usr/local/lib/dnscomplex-config/candidate.py"
[[ -x "$tmpdir/root/usr/local/lib/dnscomplex-config/candidate.py" ]] || fail "candidate parser is not executable"
parser_mode=$(stat -c '%a' "$tmpdir/root/usr/local/lib/dnscomplex-config/candidate.py" 2>/dev/null || stat -f '%Lp' "$tmpdir/root/usr/local/lib/dnscomplex-config/candidate.py")
[[ "$parser_mode" == "755" ]] || fail "candidate parser mode is not 0755"
DNSCOMPLEX_FS_ROOT="$tmpdir/root" bash "$tmpdir/root/usr/local/sbin/dnscomplex" validate-config "$tmpdir/root/etc/dnscomplex/config.env"
python3 "$repo_root/tests/config_candidate_safety_test.py"
python3 "$repo_root/tests/adguard_auth_safety_test.py"
python3 "$repo_root/tests/secret_file_creation_test.py"
python3 "$repo_root/tests/metrics_resource_boundary_test.py"
assert_file "$tmpdir/root/usr/local/lib/dnscomplex-metrics/exporter.py"
assert_file "$tmpdir/root/usr/local/lib/dnscomplex-soak/runner.py"
assert_file "$tmpdir/root/etc/prometheus/dnscomplex.rules.yml"
assert_file "$tmpdir/root/usr/local/etc/xray/config.json"
assert_file "$tmpdir/root/var/lib/dnscomplex/routeros.rsc"
assert_file "$tmpdir/root/var/lib/dnscomplex/geosite/ai.sources"
assert_file "$tmpdir/root/var/lib/dnscomplex/geosite/ai-support.sources"
assert_file "$tmpdir/root/var/lib/dnscomplex/geosite/cn-video.sources"

cat >"$tmpdir/adguard-current.yaml" <<'EOF'
http:
  pprof:
    port: 6060
    enabled: false
  address: 0.0.0.0:3000
  session_ttl: 30d
bind_host: 0.0.0.0
bind_port: 3000
dns:
  bind_hosts:
    - 0.0.0.0
    - '::'
  port: 53
EOF
bash -c 'source "$1"; normalize_adguard_http_config "$2" "$3"' \
  _ "$tmpdir/root/usr/local/sbin/dnscomplex" \
  "$tmpdir/adguard-current.yaml" "$tmpdir/adguard-current.normalized.yaml"
assert_contains "$tmpdir/adguard-current.normalized.yaml" '  address: 127.0.0.1:3000'
assert_not_contains "$tmpdir/adguard-current.normalized.yaml" '  address: 0.0.0.0:3000'
assert_not_contains "$tmpdir/adguard-current.normalized.yaml" 'bind_host:'
assert_contains "$tmpdir/adguard-current.normalized.yaml" '    - 0.0.0.0'

cat >"$tmpdir/adguard-legacy.yaml" <<'EOF'
bind_host: 0.0.0.0
bind_port: 3000
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
EOF
bash -c 'source "$1"; normalize_adguard_http_config "$2" "$3"' \
  _ "$tmpdir/root/usr/local/sbin/dnscomplex" \
  "$tmpdir/adguard-legacy.yaml" "$tmpdir/adguard-legacy.normalized.yaml"
assert_contains "$tmpdir/adguard-legacy.normalized.yaml" 'http:'
assert_contains "$tmpdir/adguard-legacy.normalized.yaml" '  address: 127.0.0.1:3000'
assert_not_contains "$tmpdir/adguard-legacy.normalized.yaml" 'bind_host:'
assert_contains "$tmpdir/adguard-legacy.normalized.yaml" '    - 0.0.0.0'

assert_contains "$tmpdir/root/etc/sing-box/config.json" '"type": "tun"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"level": "warn"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"auto_route": true'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"auto_redirect": true'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"auto_redirect_input_mark": 8227'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"auto_redirect_output_mark": 8228'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"strict_route": true'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"type": "socks"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"listen": "192.168.88.1"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"listen_port": 2080'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"type": "mixed"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"tag": "mixed-in"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"listen_port": 1081'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"tag": "dns-in-udp"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"listen_port": 1053'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"tag": "smartdns-default"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"tag": "smartdns-ai"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"tag": "smartdns-cn"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"query_type": ['
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"HTTPS"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"SVCB"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"mask.icloud.com"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"mask-h2.icloud.com"'
assert_not_contains "$tmpdir/root/etc/sing-box/config.json" '"gateway.icloud.com"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'icloud-gateway-dns'
assert_contains "$tmpdir/root/etc/sing-box/config.json" 'geosite-ai-openai.srs'
assert_contains "$tmpdir/root/etc/sing-box/config.json" 'geosite-ai-anthropic.srs'
assert_not_contains "$tmpdir/root/etc/sing-box/config.json" 'geosite-ai-meta.srs'
assert_contains "$tmpdir/root/etc/sing-box/config.json" 'geosite-ai-support.srs'
assert_contains "$tmpdir/root/etc/sing-box/config.json" 'geosite-cn-video.srs'
assert_not_contains "$tmpdir/root/etc/sing-box/config.json" '"strategy": "ipv6_only"'
assert_not_contains "$tmpdir/root/etc/sing-box/config.json" '"geosite":'
assert_not_contains "$tmpdir/root/etc/sing-box/config.json" '"address_resolver":'
assert_not_contains "$tmpdir/root/etc/sing-box/config.json" '"domain_strategy":'
assert_not_contains "$tmpdir/root/etc/sing-box/config.json" '"type": "block"'
assert_not_contains "$tmpdir/root/etc/sing-box/config.json" '"sniff": true'
assert_not_contains "$tmpdir/root/etc/sing-box/config.json" '"detour": "default"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"type": "udp"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"server": "127.0.0.1"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"action": "sniff"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"domain_resolver":'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"default_domain_resolver":'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"strategy": "prefer_ipv6"'
jq -e 'all(.dns.rules[]; has("strategy") | not)' \
  "$tmpdir/root/etc/sing-box/config.json" >/dev/null ||
  fail "sing-box DNS rules still use the legacy rule-level strategy field"
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"bind_interface": "ipsec-ai"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"bind_interface": "ipsec-cn"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"tag": "ai-xray"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"tag": "cn-xray"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"server_port": 16054'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"server_port": 16055'
jq -e 'all(.outbounds[]; has("routing_mark") | not)' \
  "$tmpdir/root/etc/sing-box/config.json" >/dev/null || fail "default outbound lacks classified mark"

assert_contains "$tmpdir/root/usr/local/etc/xray/config.json" '"tag": "xray-ai-in"'
assert_contains "$tmpdir/root/usr/local/etc/xray/config.json" '"tag": "xray-cn-in"'
assert_contains "$tmpdir/root/usr/local/etc/xray/config.json" '"port": 16054'
assert_contains "$tmpdir/root/usr/local/etc/xray/config.json" '"port": 16055'
assert_contains "$tmpdir/root/usr/local/etc/xray/config.json" '"outboundTag": "xray-ai-out"'
assert_contains "$tmpdir/root/usr/local/etc/xray/config.json" '"outboundTag": "xray-cn-out"'
assert_contains "$tmpdir/root/usr/local/etc/xray/config.json" '"protocol": "freedom"'

assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'server-name default'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'bind 127.0.0.1:6053 -group default'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'bind 127.0.0.1:6054 -group ai'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'bind 127.0.0.1:6055 -group cn'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'bind 127.0.0.1:6054 -group ai -force-aaaa-soa -nftset #4:inet#dnscomplex#ai4,#6:-'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'bind 127.0.0.1:6055 -group cn -force-aaaa-soa -nftset #4:inet#dnscomplex#cn4,#6:-'
assert_not_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'force-qtype-SOA 65'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'cache-size 65536'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'cache-persist yes'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'cache-file /var/lib/smartdns/dnscomplex.cache'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'cache-checkpoint-time 86400'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'serve-expired-ttl 259200'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'serve-expired-reply-ttl 3'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'serve-expired-prefetch-time 21600'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'mdns-lookup yes'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'hosts-file /etc/dnscomplex/local-hosts'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'address /local/#6'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'address /-.youku.com/47.246.99.254'
assert_not_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'address /youku.com/47.246.99.254'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" \
  'server-https https://cloudflare-dns.com/dns-query -alpn http/1.1'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" \
  'server-https https://dns.alidns.com/dns-query -group cn -alpn http/1.1'
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_OVERRIDE_PROBE_DOMAINS='youku.com=youku.com,www.youku.com'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_OVERRIDE_PROBE_RESOLVERS='223.5.5.5 119.29.29.29 1.1.1.1 8.8.8.8'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DEFAULT_DNS_STRATEGY='prefer_ipv6'"
assert_not_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'domain-set'
assert_not_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'nameserver /domain-set'
assert_not_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'nftset /domain-set'

assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" "    - '127.0.0.1:1053'"
assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" 'http:'
assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '  address: 127.0.0.1:3000'
assert_not_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" 'bind_host:'
assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '  cache_enabled: false'
assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '  cache_size: 0'
assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '  cache_optimistic: false'
assert_not_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '  cache_size: 67108864'
assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" "  - '@@||claude.ai^'"
assert_not_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" "  - '@@||api.statsig.com^'"
assert_not_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" "  - '@@||api.revenuecat.com^'"
assert_not_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '[/openai.com/]127.0.0.1:6054'
assert_not_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '[/bilibili.com/]127.0.0.1:6055'

assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'vpn-ai.example.net'
assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'vpn-cn.example.net'
assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'eap-mschapv2'
assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'dpd_delay'
assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'local_addrs ='
assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'id = vpn.example.net'
assert_contains "$tmpdir/root/etc/strongswan.d/charon/resolve.conf" 'load = no'
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "IPSEC_REMOTE_ID='vpn.example.net'"
assert_file "$tmpdir/root/etc/swanctl/x509ca/README.dnscomplex"

assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'type nat hook prerouting priority dstnat'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'tcp option maxseg size set 1200'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'udp dport { 784, 853, 8853 } drop'
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_QUIC_POLICY='allow'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_QUIC_POLICY='reject'"
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-ai-quic-reject'
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-ai-quic-reject-restore'
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-ai-quic-reject-output'
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-ai-classified-quic-reject'
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-lan-alias-quic-reject-ai'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'udp dport 443 counter reject with icmp type port-unreachable comment "dnscomplex-cn-quic-reject"'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'udp dport 443 counter reject with icmp type port-unreachable comment "dnscomplex-cn-quic-reject-output"'

# An older config without either policy inherits the current per-profile defaults
# at runtime, not the values from the current installer template.
sed '/^AI_QUIC_POLICY=/d; /^CN_QUIC_POLICY=/d' \
  "$tmpdir/root/etc/dnscomplex/config.env" >"$tmpdir/missing-quic-policy.env"
runtime_quic_rules=$(DNSCOMPLEX_CONFIG="$tmpdir/missing-quic-policy.env" \
  DNSCOMPLEX_ROOT="$tmpdir/root" bash -c '
    source "$1"
    load_config
    printf "policies=%s/%s\n" "$AI_QUIC_POLICY" "$CN_QUIC_POLICY"
    runtime_nft_prerouting_rules eth0.20 ai ai4 "$AI_MARK" xray "$AI_QUIC_POLICY"
    runtime_nft_restore_rules eth0.20 ai ai4 "$AI_MARK" xray "$AI_QUIC_POLICY"
    runtime_nft_lan_alias_output_rules
    runtime_nft_output_rules ai ai4 "$AI_MARK" xray "$AI_QUIC_POLICY"
    runtime_nft_output_rules cn cn4 "$CN_MARK" xray "$CN_QUIC_POLICY"
  ' _ "$tmpdir/root/usr/local/sbin/dnscomplex")
[[ "$runtime_quic_rules" == *'policies=allow/reject'* ]] ||
  fail "missing runtime QUIC policies did not resolve to AI allow and CN reject"
for ai_reject in dnscomplex-ai-quic-reject dnscomplex-lan-alias-quic-reject-ai; do
  [[ "$runtime_quic_rules" != *"$ai_reject"* ]] ||
    fail "missing AI_QUIC_POLICY unexpectedly generated $ai_reject"
done
assert_contains <(printf '%s\n' "$runtime_quic_rules") 'dnscomplex-cn-quic-reject'
assert_contains <(printf '%s\n' "$runtime_quic_rules") 'dnscomplex-lan-alias-quic-reject-cn'

# Explicit reject remains available and emits the complete Xray QUIC rejection path.
cp "$tmpdir/config.env" "$tmpdir/explicit-ai-quic-reject.env"
cat >>"$tmpdir/explicit-ai-quic-reject.env" <<'EOF'
AI_EGRESS_MODE='xray'
CN_EGRESS_MODE='xray'
AI_QUIC_POLICY='reject'
CN_QUIC_POLICY='reject'
EOF
DNSCOMPLEX_ROOT="$tmpdir/root-explicit-ai-quic-reject" \
  bash "$repo_root/install.sh" --dry-run --config "$tmpdir/explicit-ai-quic-reject.env"
assert_contains "$tmpdir/root-explicit-ai-quic-reject/etc/dnscomplex/config.env" \
  "AI_QUIC_POLICY='reject'"
assert_contains "$tmpdir/root-explicit-ai-quic-reject/etc/nftables.d/dnscomplex.nft" \
  'dnscomplex-ai-quic-reject'
assert_contains "$tmpdir/root-explicit-ai-quic-reject/etc/nftables.d/dnscomplex.nft" \
  'dnscomplex-ai-quic-reject-restore'
assert_contains "$tmpdir/root-explicit-ai-quic-reject/etc/nftables.d/dnscomplex.nft" \
  'dnscomplex-lan-alias-quic-reject-ai'
assert_contains "$tmpdir/root-explicit-ai-quic-reject/etc/nftables.d/dnscomplex.nft" \
  'dnscomplex-ai-quic-reject-output'
assert_contains "$tmpdir/root-explicit-ai-quic-reject/etc/sing-box/config.json" \
  '"network":"udp","port":443,"action":"reject"'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'ct mark set 0x2024 meta mark set 0x301 counter comment "dnscomplex-ai-preroute"'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'ct mark set 0x2024 meta mark set 0x351 counter comment "dnscomplex-cn-preroute"'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'chain prerouting_policy_restore'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'type filter hook prerouting priority filter'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'meta mark set 0x301 counter comment "dnscomplex-ai-policy-restore"'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'meta mark set 0x351 counter comment "dnscomplex-cn-policy-restore"'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'ip daddr @ai4 meta l4proto { icmp, tcp, udp } meta mark set 0x301'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'ip daddr @cn4 meta l4proto { icmp, tcp, udp } meta mark set 0x351'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-ai-xray-icmp-drop'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-cn-xray-icmp-drop'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'chain postrouting'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'set lan_alias_ready4'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-lan-alias-not-ready'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-lan-alias-fresh-flow'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'set lan_alias_config_ready4'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'ip daddr @lan_alias_config_ready4 meta l4proto { tcp, udp } ct mark != 0x2024 return'
assert_file "$tmpdir/root/usr/local/lib/dnscomplex/profile-dataplane-probe.py"
cmp -s "$repo_root/tools/profile_dataplane_probe.py" \
  "$tmpdir/root/usr/local/lib/dnscomplex/profile-dataplane-probe.py" ||
  fail "installed IPsec dataplane probe differs from its reviewed source asset"
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'set ai_probe_vip4'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'set cn_probe_vip4'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" \
  'ip saddr @ai_probe_vip4 oifname "ipsec-ai" ip daddr 104.16.248.249 tcp dport 443 meta mark 0x3a1 counter meta mark set 0x301 accept comment "dnscomplex-ai-dataplane-probe"'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" \
  'ip saddr @cn_probe_vip4 oifname "ipsec-cn" ip daddr 223.6.6.6 tcp dport 443 meta mark 0x3f1 counter meta mark set 0x351 accept comment "dnscomplex-cn-dataplane-probe"'
python3 - "$tmpdir/root/etc/nftables.d/dnscomplex.nft" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
output = text.split("  chain output {", 1)[1]
for profile, mark in (("ai", "0x3a1"), ("cn", "0x3f1")):
    probe_tag = f'comment "dnscomplex-{profile}-dataplane-probe"'
    classifier_tag = f'comment "dnscomplex-{profile}-classified-output"'
    probe = output.index(probe_tag)
    classifier = output.index(classifier_tag)
    assert probe < classifier, f"{profile} dataplane probe exception must precede classifiers"
    probe_rule = next(line for line in output.splitlines() if probe_tag in line)
    assert f'meta mark {mark} ' in probe_rule
assert output.index('comment "dnscomplex-lan-alias-not-ready"') < output.index('ip daddr { 0.0.0.0/8, 10.0.0.0/8')
assert output.index('comment "dnscomplex-lan-alias-default-output"') < output.index('udp dport { 500, 4500 } accept comment "dnscomplex-ipsec-underlay"')
assert output.index('comment "dnscomplex-lan-alias-default-output"') < output.index('ip daddr { 0.0.0.0/8, 10.0.0.0/8')
PY
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-lan-alias-snat-default'
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'elements = { 198.18.255.254 }'
assert_contains "$tmpdir/root/usr/local/libexec/dnscomplex-lan-alias" 'dnscomplex-lan-alias-owned-source-guard'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'lan_alias_reconcile_cmd || return 1'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'lan_alias_close_cmd'
python3 - "$tmpdir/root/etc/nftables.d/dnscomplex.nft" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
base = text.index("ip saddr @lan_alias_source4 meta mark set 0x2024")
ai = text.index("dnscomplex-lan-alias-classified-ai")
cn = text.index("dnscomplex-lan-alias-classified-cn")
accept = text.index("dnscomplex-lan-alias-default-output")
assert base < ai < cn < accept, "LAN alias must establish default mark then preserve AI→CN last-match order"
assert "ip saddr @lan_alias_source4 counter accept comment \"dnscomplex-lan-alias-default-output\"" in text
PY
cp "$tmpdir/config.env" "$tmpdir/xray-alias.env"
cat >>"$tmpdir/xray-alias.env" <<'EOF'
AI_EGRESS_MODE=xray
CN_EGRESS_MODE=xray
AI_QUIC_POLICY=reject
AI_XRAY_URI=vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls#ai
CN_XRAY_URI=vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls#cn
EOF
DNSCOMPLEX_ROOT="$tmpdir/root-xray-alias" bash "$repo_root/install.sh" --dry-run --config "$tmpdir/xray-alias.env"
xray_alias_rules="$tmpdir/root-xray-alias/etc/nftables.d/dnscomplex.nft"
assert_contains "$xray_alias_rules" 'dnscomplex-lan-alias-quic-reject-ai'
assert_contains "$xray_alias_rules" 'dnscomplex-lan-alias-quic-reject-cn'
assert_not_contains "$xray_alias_rules" 'dnscomplex-lan-alias-classified-'
python3 - "$xray_alias_rules" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
output = text.split("  chain output {", 1)[1]
ready = output.index('ip saddr != 198.18.255.254 meta mark 0x301 ip daddr @ai_ready4')
alias = output.index('comment "dnscomplex-lan-alias-not-ready"')
private = output.index('ip daddr { 0.0.0.0/8, 10.0.0.0/8')
underlay = output.index('udp dport { 500, 4500 } accept comment "dnscomplex-ipsec-underlay"')
assert ready < alias < private < underlay
PY

# Re-render and restore must retain the exact helper that owns persisted alias state.
assert_contains "$repo_root/install.sh" 'usr/local/libexec/dnscomplex-lan-alias'
python3 - "$repo_root/install.sh" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
main = source[source.index("main() {"):source.rindex("main \"$@\"")]
assert "close_existing_lan_alias_before_render" in main, \
    "installer must close and verify live alias readiness before rendering replacement config"
assert main.index("close_existing_lan_alias_before_render") < main.index("render_all"), \
    "installer must close and verify live alias readiness before rendering replacement config"
backup = source[source.index("managed_backup_paths() {"):source.index("optional_backup_paths() {")]
legacy = source[source.index("legacy_backup_paths() {"):source.index("managed_service_units() {")]
assert "usr/local/libexec/dnscomplex-lan-alias" in backup and \
       "usr/local/libexec/dnscomplex-lan-alias" in legacy, \
    "managed/legacy backups must retain the helper paired with alias state"
guard = source[source.index("def _ensure_owned_source_guard"):source.index("def _nft_rule_tokens")]
assert '"dnscomplex-lan-alias-not-ready"' in guard, \
    "runtime source quarantine must be inserted before set-based alias classification"
assert '"dnscomplex-domain-default-output"' not in guard, \
    "generic output accept is too late to anchor the persistent alias quarantine"
PY
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-routeros-default-snat'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'size 262144'
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'flags interval,timeout'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'flags timeout'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" \
  'udp dport { 500, 4500 } accept comment "dnscomplex-ipsec-underlay"'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'set ai_ready4'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'set cn_ready4'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" \
  'ip daddr @ai4 ip daddr != @ai_ready4 counter drop'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" \
  'ip daddr @cn4 ip daddr != @cn_ready4 counter drop'
assert_contains "$tmpdir/root/etc/systemd/system/xray-dnscomplex.service" \
  'ExecStartPost=/usr/local/sbin/dnscomplex egress-ready xray'
assert_contains "$tmpdir/root/etc/systemd/system/xray-dnscomplex.service" \
  'ExecStopPost=/usr/local/sbin/dnscomplex egress-ready clear-xray'
assert_contains "$tmpdir/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv4.ip_forward = 1'
assert_contains "$tmpdir/root/etc/sysctl.d/90-dnscomplex.conf" 'net.netfilter.nf_conntrack_max = 1048576'
assert_contains "$tmpdir/root/etc/sysctl.d/90-dnscomplex.conf" 'net.netfilter.nf_conntrack_tcp_timeout_established = 86400'
assert_contains "$tmpdir/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv4.tcp_max_syn_backlog = 65535'
assert_contains "$tmpdir/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv4.ip_local_port_range = 1024 65535'
assert_contains "$tmpdir/root/etc/modules-load.d/dnscomplex.conf" 'nf_conntrack'
assert_contains "$repo_root/install.sh" 'apply_runtime_network_settings'
assert_contains "$repo_root/install.sh" 'resolve_default_ipv6_mode'
assert_contains "$repo_root/install.sh" 'DEFAULT_IPV6_MODE'
assert_contains "$repo_root/install.sh" 'sysctl -w net.ipv4.ip_forward=1'
assert_contains "$repo_root/install.sh" 'modprobe nf_conntrack'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'modprobe nf_conntrack'

for cmd in status test health fix doctor update-geosite add-domain remove-domain set-socks set-ipsec set-update-time refresh-nftsets refresh-cn-overrides trace-domain test-dns test-ipsec mss-calibrate routeros-print update-software system-update backup restore metrics-sample soak wizard validate-config render-config support-bundle; do
  assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" "$cmd"
done
for cmd in apply-egress-json set-egress set-xray-uri set-xray-json test-xray xray-status egress-ready render-xray; do
  assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" "$cmd"
done
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'set Xray URI/JSON before switching AI to xray'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'set Xray URI/JSON before switching CN to xray'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'AI/CN egress are not using IPsec; skipping IPsec test'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'AI_EGRESS_MODE:-ipsec'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'CN_EGRESS_MODE:-ipsec'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'AI_QUIC_POLICY:=allow'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'CN_QUIC_POLICY:=reject'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'LOCAL_DOMAIN_IPV6_POLICY:=ipv4_only'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'xray run -test -format=json'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'write_nftables_runtime_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'nft -c -f /etc/nftables.conf'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'flush_quic_conntrack_cmd'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'conntrack -D -p udp --dport 443'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'systemctl restart xray-dnscomplex sing-box'

# Execute the generated manager's actual egress-stack function with command
# shims. QUIC policy combinations must not retire unrelated conntrack flows.
egress_function="$tmpdir/apply-egress-function.sh"
awk '
  /^apply_egress_stack_cmd\(\) \{/ { copying=1 }
  copying { print }
  copying && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex" >"$egress_function"
assert_contains "$egress_function" 'apply_egress_stack_cmd() {'
egress_harness="$tmpdir/apply-egress-harness.sh"
cat >"$egress_harness" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
record() { printf '%s\n' "$*" >>"$EGRESS_CALL_LOG"; }
need_root() { record need_root; }
render_xray_config_cmd() { record render_xray_config_cmd; }
write_singbox_egress_cmd() { record write_singbox_egress_cmd; }
write_nftables_runtime_cmd() { record write_nftables_runtime_cmd; }
systemctl() { record "systemctl $*"; }
conntrack() { record "conntrack $*"; }
EOF
cat "$egress_function" >>"$egress_harness"
cat >>"$egress_harness" <<'EOF'
case "${1:-}" in
  run) apply_egress_stack_cmd ;;
  ipsec-ready) record 'manager ipsec-ready' ;;
  routes) record "manager routes ${2:-}" ;;
  *) exit 64 ;;
esac
EOF
chmod 0700 "$egress_harness"
for policy_pair in allow:reject reject:allow reject:reject allow:allow; do
  ai_policy=${policy_pair%%:*}
  cn_policy=${policy_pair#*:}
  call_log="$tmpdir/egress-${ai_policy}-${cn_policy}.log"
  : >"$call_log"
  AI_QUIC_POLICY="$ai_policy" CN_QUIC_POLICY="$cn_policy" \
    EGRESS_CALL_LOG="$call_log" bash "$egress_harness" run
  assert_not_contains "$call_log" 'conntrack'
  awk '
    NR==1 && $0!="need_root" { exit 1 }
    NR==2 && $0!="render_xray_config_cmd" { exit 1 }
    NR==3 && $0!="write_singbox_egress_cmd" { exit 1 }
    NR==4 && $0!="write_nftables_runtime_cmd" { exit 1 }
    NR==5 && $0!="systemctl daemon-reload" { exit 1 }
    NR==6 && $0!="systemctl enable --now xray-dnscomplex" { exit 1 }
    NR==7 && $0!="systemctl restart xray-dnscomplex sing-box" { exit 1 }
    NR==8 && $0!="manager ipsec-ready" { exit 1 }
    NR==9 && $0!="manager routes up" { exit 1 }
    END { if (NR!=9) exit 1 }
  ' "$call_log" || fail "egress apply order changed for AI/CN QUIC policies $policy_pair"
done
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'state_transaction_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'fix --strict'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'egress_ready_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'migrate_config_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'config_missing_keys'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'doctor_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'health_json_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'health_checks_json'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" '"checks"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" '"failure_reasons"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" '"recommended_actions"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'test_socks_listener'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'singbox-socks-listener'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'smartdns-ai-listener'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'nftset-ai-freshness'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'default-ipv6-connectivity'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'ipsec_sa_state_from_sas'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'child_installed='
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'route_source_matches='
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" ', INSTALLED'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'mask_value == 0xffffffff'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'actual_mask == 0xFFFFFFFF'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'IPSEC_RULE_HIGHER_CONFLICT'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'IPSEC_RULE_EXACT_COUNT'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'IPSEC_RULE_SAME_PRIORITY_STALE'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'ip rule del priority "$priority"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'priority = "10301"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'priority = "10351"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'ipsec_profile_sa_ready "$profile" "$sas"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'record_ipsec_retry_failure "$child"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'StrongSwan SA state could not be queried'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'ok = (profile + ":") in sas'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'metrics_sample_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'soak_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" '--output-json'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" '/usr/local/lib/dnscomplex-soak/runner.py'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'soak_trace_expect chatgpt.com AI'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'soak_trace_expect youku.com CN'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'soak_trace_expect facebook.com default'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'idle-resume nftset recovery'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'local-hosts idle-resume'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-soak/runner.py" '"success_ratio"'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-soak/runner.py" '"latency_p95_ms"'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-soak/runner.py" '"profile_failures"'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-soak/runner.py" 'synthetic DNS/profile load test'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'wizard_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'validate_config_file_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'render_config_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'support_bundle_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'redact_stream'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'DNSCOMPLEX_UPDATE_CHANNEL'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'DNSCOMPLEX_PINNED_VERSION'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'GITHUB_RELEASE_POLICY'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'update_software_stage'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" '--channel stable|beta|pinned'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" '--version VERSION'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" '--include-logs minimal|standard|full'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'adguard_cache_diagnostics'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'trace_domain_cmd'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'source="nftset:${hit,,}4"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'status_cmd "$@" ;;'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'status [--verbose]'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'set_socks_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'set_ipsec_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'set_web_password_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'set_update_time_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'refresh_cn_overrides_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'refresh_nftsets_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'mss_recommended_value'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'applied IPSEC_TCP_MSS'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'expected exactly one owned runtime MSS rule with handle'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'runtime MSS readback did not match candidate handle/value'
mss_apply_body=$(awk '
  /^mss_apply_candidate_cmd\(\) \(/ { inside=1 }
  inside { print }
  inside && /^\)$/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$mss_apply_body" in
  *'nft -c -f "$stage/delta.nft" || return $?'*'atomic_publish_file_cmd "$candidate" "$target" 0644 || return $?'*'write_config_cmd || return $?'*'nft -f "$stage/delta.nft" || return $?'*'MSS_READBACK'*) ;;
  *) fail "MSS must precheck its targeted handle delta before publication and verify runtime readback" ;;
esac
case "$mss_apply_body" in
  *'systemctl restart nftables'*|*'refresh_nftsets_cmd'*)
    fail "MSS calibration must preserve unrelated classification/readiness sets" ;;
esac
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'set-local-host'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'test-local-name'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'remove_macbook_air_local_override'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'MacBookAir .local addresses should follow mDNS or RouterOS DHCP/DNS'

manager_root="$tmpdir/manager-behavior"
manager="$tmpdir/root/usr/local/sbin/dnscomplex"
mkdir -p "$manager_root/etc/dnscomplex"
: >"$manager_root/etc/dnscomplex/config.env"

# This small fixture exercises validation/publication, with the same isolated
# transaction seam as focused mutation tests. Real journals/recovery are covered
# by state/lifecycle tests and runtime_reliability_test.sh below.
run_rendered_manager() {
  DNSCOMPLEX_ROOT="$manager_root" MANAGER="$manager" \
  LOCAL_TEST_CALLS="$tmpdir/local-host-calls" bash -c '
    source "$MANAGER"
    need_root() { :; }
    acquire_maintenance_lock() { :; }
    state_transaction_cmd() {
      local callback=$2 before rc=0
      shift 2
      before=$(mktemp) || return $?
      cp "$LOCAL_HOSTS" "$before" || return $?
      "$callback" "$@" || rc=$?
      if ((rc != 0)); then cp "$before" "$LOCAL_HOSTS" || return $?; fi
      rm -f "$before"
      return "$rc"
    }
    restart_dns_stack() {
      printf "restart\n" >>"$LOCAL_TEST_CALLS"
      [[ "${LOCAL_TEST_FAIL:-}" != restart ]]
    }
    dig() {
      printf "probe\n" >>"$LOCAL_TEST_CALLS"
      awk "{print \$1}" "$LOCAL_HOSTS"
    }
    if [[ "${LOCAL_TEST_FAIL:-}" == publish ]]; then
      atomic_publish_file_cmd() { return 41; }
    fi
    main "$@"
  ' _ "$@"
}

assert_local_host_rejected() {
  local label=$1 host=$2 ip=$3 before after
  printf '192.0.2.10 existing.local\n' >"$manager_root/etc/dnscomplex/local-hosts"
  before=$(mktemp)
  cp "$manager_root/etc/dnscomplex/local-hosts" "$before"
  if run_rendered_manager set-local-host "$host" "$ip" >"$tmpdir/${label}.log" 2>&1; then
    rm -f "$before"
    fail "$label: invalid local host was accepted"
  fi
  after=$(cat "$manager_root/etc/dnscomplex/local-hosts")
  cmp -s "$before" "$manager_root/etc/dnscomplex/local-hosts" || {
    rm -f "$before"
    fail "$label: local-hosts changed after rejected input"
  }
  rm -f "$before"
  [[ "$after" == "192.0.2.10 existing.local" ]] || fail "$label: unexpected local-hosts contents"
}

printf '192.0.2.20 printer.local\n' >"$manager_root/etc/dnscomplex/local-hosts"
run_rendered_manager set-local-host printer.local 192.0.2.21 >"$tmpdir/local-host-success.log" 2>&1 || {
  cat "$tmpdir/local-host-success.log" >&2
  fail "valid local host publication failed"
}
assert_contains "$manager_root/etc/dnscomplex/local-hosts" '192.0.2.21 printer.local'
for local_failure in publish restart; do
  printf '192.0.2.20 printer.local\n' >"$manager_root/etc/dnscomplex/local-hosts"
  : >"$tmpdir/local-host-calls"
  if LOCAL_TEST_FAIL="$local_failure" run_rendered_manager set-local-host printer.local 192.0.2.21 >"$tmpdir/local-host-$local_failure.log" 2>&1; then
    fail "local host $local_failure failure was reported as success"
  fi
  assert_contains "$manager_root/etc/dnscomplex/local-hosts" '192.0.2.20 printer.local'
  assert_not_contains "$manager_root/etc/dnscomplex/local-hosts" '192.0.2.21 printer.local'
  assert_not_contains "$tmpdir/local-host-calls" 'probe'
  if [[ "$local_failure" == publish ]]; then
    assert_not_contains "$tmpdir/local-host-calls" 'restart'
  else
    assert_contains "$tmpdir/local-host-calls" 'restart'
  fi
done
assert_local_host_rejected 'reject-macbookair' 'macbookair.local' '192.0.2.30'
assert_local_host_rejected 'reject-macbook-air' 'macbook-air.local' '192.0.2.31'
assert_local_host_rejected 'reject-host-injection' $'safe.local\nmacbookair.local' '192.0.2.32'
assert_local_host_rejected 'reject-out-of-range-ipv4' 'router.local' '256.1.1.1'

cat >"$manager_root/etc/dnscomplex/config.env" <<'EOF'
DEPLOY_MODE=routeros-policy
LINUX_LAN_IPV4=192.168.50.200
SINGBOX_SOCKS_LISTEN=192.168.50.200
SINGBOX_SOCKS_PORT=10800
EOF
cp "$manager_root/etc/dnscomplex/config.env" "$tmpdir/socks-before.env"
set_socks_reject_log="$tmpdir/set-socks-policy-reject.log"
if run_rendered_manager set-socks 0.0.0.0 1080 >"$set_socks_reject_log" 2>&1; then
  fail "routeros-policy set-socks accepted a non-VM listen address"
fi
assert_contains "$set_socks_reject_log" 'routeros-policy SOCKS requires LINUX_LAN_IPV4 and port 10800'
set_socks_port_reject_log="$tmpdir/set-socks-policy-port-reject.log"
if run_rendered_manager set-socks 192.168.50.200 1080 >"$set_socks_port_reject_log" 2>&1; then
  fail "routeros-policy set-socks accepted a port other than 10800"
fi
assert_contains "$set_socks_port_reject_log" 'routeros-policy SOCKS requires LINUX_LAN_IPV4 and port 10800'
cmp -s "$tmpdir/socks-before.env" "$manager_root/etc/dnscomplex/config.env" || fail "rejected SOCKS requests changed config"
[[ ! -e "$manager_root/etc/sing-box/config.json" ]] || fail "rejected SOCKS requests published an inbound candidate"

wizard_output=$(run_rendered_manager wizard)
for wizard_value in \
  'ROUTEROS_LAN_IPV4=192.168.50.253' \
  'LINUX_LAN_IPV4=192.168.50.200' \
  'LAN_CLIENT_IPV4_CIDR=192.168.50.0/24' \
  'SINGBOX_SOCKS_LISTEN=192.168.50.200' \
  'SINGBOX_SOCKS_PORT=10800' \
  'DNSCOMPLEX_WEB_LISTEN=192.168.50.200' \
  'LAN_IPV6_PREFIX=fd00:88::/64' \
  'DEFAULT_IPV6_MODE=auto'; do
  grep -Fqx "$wizard_value" <<<"$wizard_output" || fail "wizard output missing $wizard_value"
done
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'DEBIAN_FRONTEND=noninteractive dpkg --force-confdef --force-confold -i'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'Dpkg::Options::=--force-confold'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'public_ipv4'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'remove_list_item'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'add_list_item'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'AI_GEOSITE_SOURCES=$sources; AI_SUPPORT_DOMAINS=$support'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'CN_VIDEO_SOURCES=$sources'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'if [[ "$profile" == ai ]]; then port=$SMARTDNS_AI_PORT; set_name=ai4;'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'else port=$SMARTDNS_CN_PORT; set_name=cn4; fi'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'nft add element inet dnscomplex cn4'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  "printf 'add element inet dnscomplex %s { %s timeout %s }"
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'nft list table inet dnscomplex >/dev/null 2>&1 || die "nftables dnscomplex table is missing"'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'nft list table inet dnscomplex >/dev/null 2>&1 || systemctl restart nftables || true'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'if refresh_nftset_group "$profile" "$port" "$set_name"; then'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'kept_previous'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'state_transaction_cmd "domain batch $profile" apply_domain_rules_candidate_cmd'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.service" 'ExecStart=/usr/local/sbin/dnscomplex refresh-cn-overrides'
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.service" 'Restart='
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.service" 'StartLimit'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.service" \
  'Environment=DNSCOMPLEX_TIMER_MODE=1'
assert_contains "$tmpdir/root/etc/systemd/system/smartdns.service.d/dnscomplex.conf" 'Restart=always'
assert_contains "$tmpdir/root/etc/systemd/system/smartdns.service.d/dnscomplex.conf" 'RestartSec=2s'
assert_contains "$tmpdir/root/etc/systemd/system/smartdns.service.d/dnscomplex.conf" 'TimeoutStopSec=5s'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.timer" 'OnCalendar=*-*-* 00/6:00:00'
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.timer" 'OnUnitActiveSec=6h'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-nftset-refresh.service" 'ExecStart=/usr/local/sbin/dnscomplex refresh-nftsets'
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-nftset-refresh.service" 'Restart='
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-nftset-refresh.service" 'StartLimit'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-nftset-refresh.service" \
  'Environment=DNSCOMPLEX_TIMER_MODE=1'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-nftset-refresh.timer" 'OnUnitActiveSec=5m'
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-update.service" 'Restart='
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-update.service" 'StartLimit'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-update.service" \
  'Environment=DNSCOMPLEX_TIMER_MODE=1'
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-metrics-sample.service" 'Restart='
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-metrics-sample.service" 'StartLimit'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-metrics-sample.service" \
  'Environment=DNSCOMPLEX_TIMER_MODE=1'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-network-ready.service" \
  'ExecStart=/usr/local/sbin/dnscomplex network-ready'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-network-ready.service" \
  'Environment=DNSCOMPLEX_SERVICE_MODE=1'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-network-ready.service" \
  'Before=dnscomplex-ipsec-ready.service dnscomplex-web.service sing-box.service AdGuardHome.service'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-network-ready.service" \
  'Upholds=dnscomplex-ipsec-ready.service sing-box.service AdGuardHome.service dnscomplex-web.service'
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-network-ready.service" \
  'OnSuccess='
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-network-ready.service" \
  'Restart=on-failure'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-ipsec-ready.service" \
  'After=dnscomplex-network-ready.service dnscomplex-ipsec-ifaces.service strongswan-starter.service strongswan-swanctl.service strongswan.service ipsec.service'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-ipsec-ready.service" \
  'Requires=dnscomplex-network-ready.service dnscomplex-ipsec-ifaces.service'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-ipsec-ready.service" \
  'Before=dnscomplex-routing.service'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-ipsec-ready.service" \
  'ExecStart=/usr/local/sbin/dnscomplex ipsec-ready'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-ipsec-ready.service" \
  'Environment=DNSCOMPLEX_SERVICE_MODE=1'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-ipsec-ready.service" \
  'TimeoutStartSec=120s'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-ipsec-ready.service" \
  'OnSuccess=dnscomplex-routing.service'
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-ipsec-ready.service" \
  'Restart='
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-ipsec-ready.service" \
  'StartLimit'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-health.service" \
  'TimeoutStartSec=45s'
assert_contains "$tmpdir/root/etc/systemd/journald.conf.d/dnscomplex.conf" \
  'SystemMaxUse=1536M'
assert_contains "$tmpdir/root/etc/systemd/journald.conf.d/dnscomplex.conf" \
  'SystemKeepFree=1G'
assert_contains "$tmpdir/root/etc/systemd/journald.conf.d/dnscomplex.conf" \
  'RuntimeMaxUse=64M'
assert_contains "$tmpdir/root/etc/systemd/journald.conf.d/dnscomplex.conf" \
  'MaxRetentionSec=30day'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-routing.service" \
  'Requires=dnscomplex-ipsec-ready.service'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-routing.service" \
  'After=network-online.target nftables.service dnscomplex-ipsec-ifaces.service dnscomplex-ipsec-ready.service'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-routing.service" \
  'PartOf=nftables.service'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-routing.service" \
  'Environment=DNSCOMPLEX_SERVICE_MODE=1'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-ipsec-ifaces.service" \
  'Environment=DNSCOMPLEX_SERVICE_MODE=1'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-web.service" \
  'Requires=dnscomplex-network-ready.service'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-web.service" \
  'After=dnscomplex-network-ready.service'
assert_contains "$tmpdir/root/etc/systemd/system/sing-box.service.d/dnscomplex.conf" \
  'Requires=dnscomplex-network-ready.service'
assert_contains "$tmpdir/root/etc/systemd/system/sing-box.service.d/dnscomplex.conf" \
  'After=dnscomplex-network-ready.service'
assert_contains "$tmpdir/root/etc/systemd/system/sing-box.service.d/dnscomplex.conf" \
  'BindReadOnlyPaths=/usr/bin/true:/usr/bin/resolvectl'
assert_contains "$tmpdir/root/etc/systemd/system/AdGuardHome.service" \
  'Requires=dnscomplex-network-ready.service'
assert_contains "$tmpdir/root/etc/systemd/system/AdGuardHome.service" \
  '--web-addr 127.0.0.1:3000'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  '  address: 127.0.0.1:3000'
assert_contains "$repo_root/install.sh" 'dnscomplex-cn-overrides.timer'
assert_contains "$repo_root/install.sh" 'dnscomplex-nftset-refresh.timer'
assert_contains "$repo_root/install.sh" 'dnscomplex-ipsec-ready'
enable_services_body=$(awk '
  /^enable_services\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$repo_root/install.sh")
ipsec_enable_line=$(grep -nF 'for ipsec_unit in' <<<"$enable_services_body")
ipsec_restart_line=$(grep -nF 'systemctl restart "$ipsec_unit"' <<<"$enable_services_body")
ready_enable_line=$(grep -nF 'systemctl enable dnscomplex-ipsec-ready dnscomplex-routing' <<<"$enable_services_body")
network_enable_line=$(grep -nF 'systemctl enable --now dnscomplex-network-ready' <<<"$enable_services_body")
[[ -n "$network_enable_line" && -n "$ipsec_enable_line" && -n "$ipsec_restart_line" && -n "$ready_enable_line" ]] ||
  fail "service enable order markers are missing"
ipsec_enable_line=${ipsec_enable_line%%:*}
ipsec_restart_line=${ipsec_restart_line%%:*}
ready_enable_line=${ready_enable_line%%:*}
network_enable_line=${network_enable_line%%:*}
((network_enable_line < ipsec_enable_line)) ||
  fail "network readiness must start before IPsec services"
((ipsec_enable_line < ipsec_restart_line && ipsec_restart_line < ready_enable_line)) ||
  fail "selected strongSwan unit must restart before IPsec readiness"
assert_not_contains "$repo_root/install.sh" 'dhcpcd --rebind "$WAN_IFACE"'
assert_contains "$repo_root/install.sh" 'systemctl restart dnscomplex-health.timer'
assert_contains "$repo_root/install.sh" 'validate_rendered_install'
assert_contains "$repo_root/install.sh" 'timeout 2 unshare --net -- smartdns -f'
assert_contains "$repo_root/install.sh" '/opt/AdGuardHome/AdGuardHome --check-config'
assert_contains "$repo_root/install.sh" 'systemd-analyze verify'
assert_contains "$repo_root/install.sh" 'python3 -m py_compile'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'apply_runtime_network_settings'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'resolve_default_ipv6_mode'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'ipv6_tcp_available'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'unit_exists'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'print_unit_state'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'ipsec_vip'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'wait_for_ipsec_underlay'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'swanctl --load-all --noprompt'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'ipsec-ready) ipsec_ready_cmd "$@" ;;'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'sync_ipsec_nat'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'sync_singbox_ipsec_bind_addresses'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'inet4_bind_address'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'merge_adguard_user_rules'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'sync_geosite_sources_from_config'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'wait_dns_ready'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'restart_dns_stack'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'fix_smartdns_wrapper'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'ensure_smartdns_enabled'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'ln -sfn /usr/local/lib/smartdns/run-smartdns /usr/sbin/smartdns'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'systemctl enable smartdns'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'render_adguard_runtime'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'write_adguard_upstream_rules'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'domain_regex'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'write_env_var DEFAULT_DNS_STRATEGY "$DEFAULT_DNS_STRATEGY"'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'write_env_var DEFAULT_IPV6_MODE "$DEFAULT_IPV6_MODE"'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'write_env_var AI_QUIC_POLICY "$AI_QUIC_POLICY"'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'write_env_var CN_QUIC_POLICY "$CN_QUIC_POLICY"'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'write_env_var LOCAL_DOMAIN_IPV6_POLICY "$LOCAL_DOMAIN_IPV6_POLICY"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'systemctl show --property=TimersCalendar --value dnscomplex-update.timer | grep -Fq -- "$DNSCOMPLEX_UPDATE_TIME:00" || return 1'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" '/var/log/dnscomplex/update-'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'github_latest_release_tag'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'update_release_if_needed'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'already latest; skip'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'systemctl restart sing-box smartdns AdGuardHome nftables'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-update.service" \
  'ExecStart=/usr/local/sbin/dnscomplex update-geosite'
assert_not_contains "$tmpdir/root/etc/systemd/system/dnscomplex-update.service" \
  'update-software'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  '--allow-unverified-release-assets'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  '--acknowledge-no-os-rollback'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" "grep -Eo '([0-9]{1,3}\\.){3}[0-9]{1,3}' || true"
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'local_addrs = $local_ip'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'id = $IPSEC_REMOTE_ID'
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "SINGBOX_SOCKS_LISTEN='192.168.88.1'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "SINGBOX_SOCKS_PORT='2080'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "SINGBOX_HTTP_LISTEN='0.0.0.0'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "SINGBOX_HTTP_PORT='1081'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "APPLE_PRIVATE_RELAY_BLOCK='1'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DNSCOMPLEX_WEB_LISTEN='192.168.88.1'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DNSCOMPLEX_WEB_PORT='8088'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DNSCOMPLEX_UPDATE_TIME='04:20'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DNSCOMPLEX_UPDATE_LAST_LOG='/var/log/dnscomplex/update-latest.log'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DNSCOMPLEX_UPDATE_CHANNEL='stable'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DNSCOMPLEX_PINNED_VERSION=''"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "GITHUB_RELEASE_POLICY='latest'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DNSCOMPLEX_NFTSET_REFRESH_INTERVAL='5m'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT='2h'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "IPSEC_TCP_MSS='1200'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "ADGUARD_DNS_CACHE_MODE='off'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "HA_MODE='single'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "HA_HEALTH_URL='/healthz'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "HA_FAILOVER_POLICY='primary-secondary-routeros'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DNSCOMPLEX_METRICS_LISTEN='0.0.0.0'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DNSCOMPLEX_METRICS_PORT='9108'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "PROMETHEUS_MODE='exporter-only'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "XRAY_ENABLED='1'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_EGRESS_MODE='ipsec'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_EGRESS_MODE='ipsec'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_QUIC_POLICY='allow'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_QUIC_POLICY='reject'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "LOCAL_DOMAIN_IPV6_POLICY='ipv4_only'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "XRAY_LISTEN_HOST='127.0.0.1'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "XRAY_AI_SOCKS_PORT='16054'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "XRAY_CN_SOCKS_PORT='16055'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_XRAY_URI=''"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_XRAY_URI=''"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_XRAY_OUTBOUND_JSON=''"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_XRAY_OUTBOUND_JSON=''"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_NFTSET_REFRESH_DOMAINS='chatgpt.com ios.chat.openai.com openai.com api.openai.com oaistatic.com oaiusercontent.com files.oaiusercontent.com cdn.oaistatic.com persistent.oaistatic.com cdn.openai.com anthropic.com claude.ai claude.com meta.ai'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_NFTSET_REFRESH_DOMAINS='bilibili.com iqiyi.com youku.com douyin.com kuaishou.com acfun.cn mgtv.com v.qq.com tv.cctv.com'"
assert_not_contains "$tmpdir/root/etc/dnscomplex/config.env" " v.qq.com qq.com "
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_SUPPORT_DOMAINS='meta.ai'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_SAMPLE_DOMAINS='openai.com anthropic.com claude.ai meta.ai'"
assert_contains "$tmpdir/root/etc/dnscomplex/ai.seed-domains" 'meta.ai'
assert_contains "$tmpdir/root/etc/dnscomplex/ai.domains" 'meta.ai'
assert_contains "$tmpdir/root/etc/dnscomplex/ai.domains" 'chatgpt.com'
assert_not_contains "$tmpdir/root/etc/dnscomplex/ai.seed-domains" 'facebook.com'
assert_not_contains "$tmpdir/root/etc/dnscomplex/ai.seed-domains" 'instagram.com'
assert_not_contains "$tmpdir/root/etc/dnscomplex/ai.domains" 'facebook.com'
assert_not_contains "$tmpdir/root/etc/dnscomplex/ai.domains" 'instagram.com'
assert_contains "$tmpdir/root-old-ai-samples/etc/dnscomplex/config.env" "AI_SAMPLE_DOMAINS='openai.com anthropic.com claude.ai meta.ai'"
assert_not_contains "$tmpdir/root-old-ai-samples/etc/dnscomplex/config.env" 'facebook.com'
assert_not_contains "$tmpdir/root-old-ai-samples/etc/dnscomplex/ai.seed-domains" 'facebook.com'
assert_not_contains "$tmpdir/root-old-ai-samples/etc/dnscomplex/ai.domains" 'instagram.com'
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "SING_GEOSITE_RULESET_BASE_URL='https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set'"
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'SagerNet/sing-box'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'AdguardTeam/AdGuardHome'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'pymumu/smartdns'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'XTLS/Xray-core'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'github_latest_asset_url'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'migrate_ai_meta_sample_domains'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'sync_domain_seed_files_from_config'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'flush_policy_nftsets_cmd'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'nft flush set inet dnscomplex ai4'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'nft flush set inet dnscomplex cn4'
refresh_nftsets_body=$(awk '
  /^refresh_nftsets_cmd\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$refresh_nftsets_body" in
  *flush_policy_nftsets_cmd*) fail "refresh-nftsets must keep last-known-good policy sets" ;;
  *'nft delete element inet dnscomplex "$set_name"'*) fail "refresh-nftsets must not delete policy set elements" ;;
esac
update_geosite_body=$(awk '
  /^update_geosite_cmd\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$update_geosite_body" in
  *flush_policy_nftsets_cmd*) fail "update-geosite must keep last-known-good policy sets" ;;
esac
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'zero usable answers; keeping last-known-good'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  '"$BASE/nftset-${profile}.last_refresh"'

assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/ai.sources" 'openai'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/ai.sources" 'anthropic'
assert_not_contains "$tmpdir/root/var/lib/dnscomplex/geosite/ai.sources" 'meta'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/ai-support.sources" 'meta.ai'
assert_not_contains "$tmpdir/root/var/lib/dnscomplex/geosite/ai-support.sources" 'api.revenuecat.com'
assert_not_contains "$tmpdir/root/var/lib/dnscomplex/geosite/ai-support.sources" 'api.statsig.com'
assert_not_contains "$tmpdir/root/var/lib/dnscomplex/geosite/ai-support.sources" 'events.statsigapi.net'
assert_not_contains "$tmpdir/root/var/lib/dnscomplex/geosite/ai-support.sources" 'featuregates.org'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/cn-video.sources" 'bilibili'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/cn-video.sources" 'iqiyi'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/cn-video.sources" 'youku'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/cn-video.sources" 'douyin'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/cn-video.sources" 'kuaishou'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/cn-video.sources" 'acfun'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/cn-video.sources" 'v.qq.com'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/cn-video.sources" 'cibntv.net'

assert_contains "$tmpdir/root/var/lib/dnscomplex/routeros.rsc" '/interface/vlan/add'
assert_contains "$tmpdir/root/var/lib/dnscomplex/routeros.rsc" '/ipv6/route/add'
assert_contains "$tmpdir/root/var/lib/dnscomplex/routeros.rsc" '192.168.88.0/24'
assert_contains "$tmpdir/root/var/lib/dnscomplex/routeros.rsc" 'fd00:88::/64'

assert_contains "$repo_root/install.sh" 'https://api.github.com/repos/'
assert_contains "$repo_root/install.sh" '/releases/latest'
assert_contains "$repo_root/install.sh" 'SagerNet/sing-box'
assert_contains "$repo_root/install.sh" 'AdguardTeam/AdGuardHome'
assert_contains "$repo_root/install.sh" 'pymumu/smartdns'
assert_contains "$repo_root/install.sh" 'XTLS/Xray-core'
assert_contains "$repo_root/install.sh" 'ln -sfn /usr/local/lib/smartdns/run-smartdns /usr/sbin/smartdns'
assert_contains "$repo_root/install.sh" 'systemctl enable smartdns'
assert_contains "$repo_root/install.sh" 'systemctl enable --now smartdns AdGuardHome sing-box xray-dnscomplex'
assert_contains "$repo_root/install.sh" 'systemctl enable --now dnscomplex-web'
assert_contains "$repo_root/install.sh" 'systemctl enable --now dnscomplex-metrics'
assert_contains "$repo_root/install.sh" 'dnscomplex-metrics-sample.timer'
assert_contains "$repo_root/install.sh" 'write_file_atomic()'
assert_contains "$repo_root/install.sh" \
  "write_file_atomic /usr/local/sbin/dnscomplex <<'MANAGER'"
assert_not_contains "$repo_root/install.sh" \
  "write_file /usr/local/sbin/dnscomplex <<'MANAGER'"
assert_contains "$repo_root/install.sh" 'Dpkg::Options::=--force-confold'
assert_contains "$repo_root/install.sh" 'upgrade -y --with-new-pkgs'
assert_contains "$repo_root/install.sh" 'update_release_if_needed'
assert_contains "$repo_root/install.sh" 'conntrack'
assert_contains "$repo_root/install.sh" 'libstrongswan-extra-plugins'
assert_contains "$tmpdir/root/etc/strongswan.d/charon/agent.conf" 'load = no'
assert_contains "$tmpdir/root/etc/strongswan.d/charon/tpm.conf" 'load = no'
assert_contains "$tmpdir/root/etc/strongswan.d/charon/dhcp.conf" 'load = no'
assert_contains "$tmpdir/root/etc/strongswan.d/swanctl.conf" \
  'load = test-vectors aesni aes rc2 sha2 sha1 md5 mgf1 rdrand random x509 pubkey pkcs1 pkcs7 pkcs12 dnskey sshkey pem openssl gcrypt pkcs8 af-alg gmp curve25519 hmac kdf drbg'
assert_not_contains "$tmpdir/root/etc/strongswan.d/swanctl.conf" 'agent'
assert_contains "$repo_root/install.sh" 'dnscomplex update-geosite'
assert_contains "$repo_root/install.sh" 'dnscomplex watchdog'
assert_contains "$repo_root/install.sh" 'dnscomplex test'
assert_contains "$repo_root/install.sh" 'doctor_cmd'
assert_contains "$repo_root/install.sh" 'DNSCOMPLEX_UPDATE_LAST_LOG'
assert_contains "$repo_root/install.sh" 'prefetch-domain yes'
assert_contains "$repo_root/install.sh" 'cache_enabled: false'
assert_contains "$repo_root/install.sh" 'dnscomplex_conntrack_usage_ratio'
assert_contains "$repo_root/install.sh" 'dnscomplex_dns_latency_ms'

enable_services_body=$(awk '
  /^enable_services\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$repo_root/install.sh")
case "$enable_services_body" in
  *'systemctl restart nftables || true'*)
    fail "installer must not ignore nftables restart failure"
    ;;
esac
case "$enable_services_body" in
  *'systemctl restart dnscomplex-ipsec-ready || warn'*'systemctl restart dnscomplex-routing || warn'*) ;;
  *) fail "installer must tolerate an unavailable external IPsec peer after local preflight succeeds" ;;
esac
case "$enable_services_body" in
  *'systemctl reset-failed'*'dnscomplex-cn-overrides'*'dnscomplex-nftset-refresh'*'dnscomplex-metrics-sample'*) ;;
  *) fail "installer must clear stale failures from repaired timer-triggered services" ;;
esac

installer_main_body=$(awk '
  /^main\(\) \{/ {
    inside=1
    body=$0 ORS
    next
  }
  inside {
    body=body $0 ORS
    if (/^}/) {
      inside=0
      last=body
    }
  }
  END { printf "%s", last }
' "$repo_root/install.sh")
case "$installer_main_body" in
  *acquire_installer_maintenance_lock*install_packages*render_all*validate_rendered_install*release_installer_maintenance_lock*enable_services*'DNSCOMPLEX_TIMER_MODE=1 dnscomplex update-geosite'*'dnscomplex watchdog'*'DNSCOMPLEX_TIMER_MODE=1 dnscomplex refresh-nftsets'*'dnscomplex test || warn'*) ;;
  *) fail "installer must lock, preflight before service changes, and run final validation automatically" ;;
esac
assert_not_contains "$repo_root/install.sh" 'apt-get install -y smartdns'
assert_not_contains "$repo_root/install.sh" 'https://sing-box.app/deb-install.sh'
assert_not_contains "$repo_root/install.sh" 'AdGuardHome/master/scripts/install.sh'
assert_not_contains "$repo_root/install.sh" 'systemd-resolved cron dnsutils'

assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'ThreadingHTTPServer'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'CONFIG_KEYS'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" \
  '[DNSCOMPLEX, "apply-config-json", path]'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" \
  '[DNSCOMPLEX, "apply-config", path]'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" \
  '[sys.executable, "/usr/local/lib/dnscomplex-metrics/exporter.py", "--current"]'
assert_not_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" \
  'os.replace(tmp, CONFIG)'
assert_not_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" \
  'CONFIG + ".wizardbak"'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'AI_EGRESS_MODE'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'AI_QUIC_POLICY'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'LOCAL_DOMAIN_IPV6_POLICY'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'AI_XRAY_URI'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'set-egress'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'return operation_submit("egress-apply", payload)'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'egress-apply) apply_egress_json_cmd "$operation/payload.json" ;;'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'test-xray'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '"-format=json"'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/egress/test'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/egress/apply'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/rules/domain'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/rules/geosite'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/rules/rebuild'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/trace-domain'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'domains_model'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'renderDomainSections'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'splitOutput'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'runWithOutput'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '處理中'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '操作結果'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '內建來源'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '自訂項目'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '建議下一步'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '常用設定只放日常會改的項目'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '精靈會先驗證，不會直接覆蓋 production'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" \
  '每日排程只更新域名／geosite／SRS 規則資料'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'white-space:pre-wrap'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'overflow-wrap:anywhere'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'AI_NFTSET_REFRESH_DOMAINS'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'smartdns_diagnostics'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'ipv6_diagnostics'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'DEFAULT_DNS_STRATEGY'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'DNSCOMPLEX_UPDATE_CHANNEL'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'DNSCOMPLEX_PINNED_VERSION'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'GITHUB_RELEASE_POLICY'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'refresh-nftsets'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'refresh-cn-overrides'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'test-dns'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'test-ipsec'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/connections'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'active_connections'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'dns_answer_ips'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'set-update-time'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'set-web-password'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '管理界面帳號密碼'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'MSS 狀態'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '校準並套用 MSS'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '本機 .local 名稱'
assert_not_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '可把 Mac 的 LAN IP 綁定到 .local 名稱'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'renderConfigGroups'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'config-groups'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'data-config-key'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'config-input-grid'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" "querySelectorAll('[data-config-key]')"
assert_not_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'id="configForm"'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '"AI_SAMPLE_DOMAINS"'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '"CN_SAMPLE_DOMAINS"'
assert_not_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" \
  '<button onclick="runAction('\''update-software'\'')"'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'last_update_log'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'domain_source'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'profile_source'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'trace-domain'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'doctor'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/metrics/current'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/metrics/history'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/ui/summary'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'ui_summary'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '我想做'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '需要處理'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '日常'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '設定'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '進階'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '上網測試'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'DNS 去廣告'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '服務狀態'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '營運健康中心'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/ops/health'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/ops/soak/status'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/ops/soak/run'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'summaryCards'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'taskGrid'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'profileCards'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/wizard/schema'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/wizard/validate'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/wizard/apply'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/update/status'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/update/run'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/support-bundle'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'redact_text'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'supportBundle'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'dnscomplex_session'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'Set-Cookie'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'cookie_ok'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'send_login_page'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'handle_login'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'if self.path == "/login"'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'method="post" action="/login"'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'dnscomplex 登入'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'self.send_header("Location", "/")'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'send_auth_challenge'
python3 - "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" "$tmpdir" <<'PY'
import importlib.util
import email.message
import pathlib
import io
import types
import urllib.parse
import sys

app_path = pathlib.Path(sys.argv[1])
tmpdir = pathlib.Path(sys.argv[2])
config = tmpdir / "web-login.env"
config.write_text("DNSCOMPLEX_WEB_PASSWORD=test-secret\n", encoding="utf-8")
spec = importlib.util.spec_from_file_location("dnscomplex_web_contract", app_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.CONFIG = str(config)
payload = urllib.parse.urlencode({"username": "admin", "password": "wrong"}).encode()
handler = object.__new__(module.Handler)
handler.headers = email.message.Message()
handler.headers["Content-Length"] = str(len(payload))
handler.headers["Content-Type"] = "application/x-www-form-urlencoded"
class Input(io.BytesIO):
    def finish_input(self): self.finished = True  # Real deadline covered by HTTP socket tests.
handler.rfile = Input(payload)
handler.wfile = io.BytesIO()
handler.responses = []
handler.response_headers = []
handler.send_response = types.MethodType(lambda self, code: self.responses.append(code), handler)
handler.send_header = types.MethodType(lambda self, key, value: self.response_headers.append((key, value)), handler)
handler.end_headers = types.MethodType(lambda self: None, handler)
handler.handle_login()
assert handler.rfile.finished, "login must finish its bounded body read"
body = handler.wfile.getvalue().decode("utf-8")
if handler.responses != [401] or "登入資料不正確" not in body:
    raise SystemExit(f"invalid login returned {handler.responses}: {body[:120]!r}")
PY
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'journalctl --disk-usage'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'dnscomplex-ipsec-ready'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'dnscomplex-routing'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'strongswan'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'ip xfrm state'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  '--lines=20000'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'drawChart'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '<canvas'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-metrics/exporter.py" 'dnscomplex_health_status'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-metrics/exporter.py" 'dnscomplex_dns_latency_p95_ms'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-metrics/exporter.py" 'dnscomplex_dns_success_ratio'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-metrics/exporter.py" 'dnscomplex_nftset_age_seconds'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-metrics/exporter.py" 'dnscomplex_profile_connections'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-metrics/exporter.py" 'dnscomplex_ipv6_connection_ratio'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-metrics/exporter.py" 'schema_version'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-metrics/exporter.py" \
  'DNSCOMPLEX_MANAGER'
assert_not_contains "$tmpdir/root/usr/local/lib/dnscomplex-metrics/exporter.py" \
  'child + ":" in run(["swanctl", "--list-sas"], 5).stdout'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-web.service" 'ExecStart=/usr/bin/python3 /usr/local/lib/dnscomplex-web/app.py'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-metrics.service" 'ExecStart=/usr/bin/python3 /usr/local/lib/dnscomplex-metrics/exporter.py'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-metrics-sample.service" 'ExecStart=/usr/local/sbin/dnscomplex metrics-sample'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-metrics-sample.timer" 'OnUnitInactiveSec=15s'
assert_contains "$tmpdir/root/etc/systemd/system/xray-dnscomplex.service" 'ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json'
assert_contains "$tmpdir/root/etc/prometheus/dnscomplex.rules.yml" 'DnscomplexConntrackHigh'
assert_contains "$tmpdir/root/etc/prometheus/dnscomplex.rules.yml" 'DnscomplexAdGuardCacheEnabled'
assert_contains "$tmpdir/root/etc/prometheus/dnscomplex.rules.yml" 'DnscomplexHealthUnhealthy'
assert_contains "$tmpdir/root/etc/prometheus/dnscomplex.rules.yml" 'DnscomplexDnsSuccessLow'
assert_contains "$tmpdir/root/etc/prometheus/dnscomplex.rules.yml" 'DnscomplexNftsetStale'
assert_contains "$tmpdir/root/etc/prometheus/dnscomplex.rules.yml" 'DnscomplexDefaultIpv6Broken'

secret_probe="$tmpdir/secret-probe.txt"
cat >"$secret_probe" <<'EOF'
AI_IPSEC_PASSWORD='alpha beta gamma'
AI_IPSEC_USERNAME=secret-user
CN_IPSEC_PASSWORD='quote'\''inside value'
AI_XRAY_OUTBOUND_JSON='{"password":"json secret with spaces","token":"nested token value","server":"203.0.113.8"}'
CN_XRAY_OUTBOUND_JSON='{
  "password": "multiline json secret"
}'
AI_XRAY_URI=vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls#ai
GITHUB_TOKEN=redaction-probe-token-value
{"password":"standalone json secret","token":"standalone token value"}
password: colon secret with spaces
Authorization: Bearer bearer-secret-value
LAN=192.168.88.1 203.0.113.8 fd00:88::1 hostname router.local
EOF
assert_file "$tmpdir/root/usr/local/lib/dnscomplex-redact/redact.py"
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  '/usr/local/lib/dnscomplex-redact/redact.py'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" \
  '/usr/local/lib/dnscomplex-redact/redact.py'
redacted_probe=$(DNSCOMPLEX_FS_ROOT="$tmpdir/root" bash -c '
  source "$1"
  redact_stream <"$2"
' _ "$tmpdir/root/usr/local/sbin/dnscomplex" "$secret_probe")
case "$redacted_probe" in
  *"alpha beta gamma"*|*secret-user*|*"quote'inside value"*|\
  *"json secret with spaces"*|*"nested token value"*|\
  *"multiline json secret"*|*"standalone json secret"*|\
  *"standalone token value"*|*"colon secret with spaces"*|\
  *bearer-secret-value*|*123e4567-e89b-12d3-a456-426614174000*|\
  *redaction-probe-token-value*|*192.168.88.1*|*203.0.113.8*|\
  *fd00:88::1*|*router.local*)
    fail "support redaction leaked sensitive probe: $redacted_probe"
    ;;
esac
printf '%s\n' "$redacted_probe" | grep -Fq '[REDACTED' || fail "support redaction did not mark redacted values"
redacted_probe_twice=$(printf '%s' "$redacted_probe" | \
  DNSCOMPLEX_FS_ROOT="$tmpdir/root" bash -c '
  source "$1"
  redact_stream
' _ "$tmpdir/root/usr/local/sbin/dnscomplex")
[[ "$redacted_probe_twice" == "$redacted_probe" ]] ||
  fail "support redaction is not idempotent"
literal_secret_config="$tmpdir/redactor-literal-config.env"
cat >"$literal_secret_config" <<'EOF'
AI_IPSEC_PASSWORD='decoded secret with spaces'
CN_IPSEC_PASSWORD='quote'\''inside value'
EOF
literal_redacted=$(printf '%s\n' \
  "upstream echoed decoded secret with spaces" \
  "peer rejected quote'inside value" |
  python3 "$tmpdir/root/usr/local/lib/dnscomplex-redact/redact.py" \
    --config "$literal_secret_config")
case "$literal_redacted" in
  *"decoded secret with spaces"*|*"quote'inside value"*)
    fail "redactor leaked a decoded config secret in another log format"
    ;;
esac

policy_tmp=$(mktemp -d)
cat >"$policy_tmp/config.env" <<'EOF'
DNSCOMPLEX_NONINTERACTIVE=1
DEPLOY_MODE=routeros-policy
WAN_IFACE=ens18
ROUTEROS_LAN_IPV4=192.168.50.253
LINUX_LAN_IPV4=192.168.50.200
LAN_CLIENT_IPV4_CIDR=192.168.50.0/24
SINGBOX_SOCKS_LISTEN=192.168.50.200
SINGBOX_SOCKS_PORT=10800
AI_IPSEC_USERNAME=ai-user
AI_IPSEC_PASSWORD=ai-pass
CN_IPSEC_USERNAME=cn-user
CN_IPSEC_PASSWORD=cn-pass
HA_MODE=primary
HA_PRIMARY_IP=192.168.50.200
HA_SECONDARY_IP=192.168.50.201
EOF
mkdir -p "$policy_tmp/root/etc"
cat >"$policy_tmp/root/etc/nsswitch.conf" <<'EOF'
passwd: files systemd
group: files systemd
hosts: files myhostname resolve [!UNAVAIL=return] # resolver chain
networks: files
EOF
DNSCOMPLEX_ROOT="$policy_tmp/root" bash "$repo_root/install.sh" --dry-run --config "$policy_tmp/config.env"
assert_file "$policy_tmp/root/etc/sing-box/config.json"
assert_file "$policy_tmp/root/etc/nftables.d/dnscomplex.nft"
assert_file "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc"
assert_contains "$policy_tmp/root/etc/dnscomplex/config.env" "DEPLOY_MODE='routeros-policy'"
assert_contains "$policy_tmp/root/etc/dhcpcd.conf" 'nohook resolv.conf'
assert_contains "$policy_tmp/root/etc/nsswitch.conf" 'hosts: files myhostname dns # resolver chain'
assert_not_contains "$policy_tmp/root/etc/nsswitch.conf" ' resolve '
assert_contains "$policy_tmp/root/etc/sing-box/config.json" '"include_interface": ['
assert_contains "$policy_tmp/root/etc/sing-box/config.json" '"ens18"'
assert_contains "$policy_tmp/root/etc/sing-box/config.json" '"listen": "192.168.50.200"'
assert_contains "$policy_tmp/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv6.conf.ens18.accept_ra = 2'
assert_contains "$policy_tmp/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv6.conf.ens18.autoconf = 1'
assert_contains "$policy_tmp/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv6.conf.ens18.addr_gen_mode = 0'
assert_contains "$policy_tmp/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv4.conf.ens18.rp_filter = 0'
assert_contains "$policy_tmp/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv4.conf.all.send_redirects = 0'
assert_contains "$policy_tmp/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv4.conf.default.send_redirects = 0'
assert_contains "$policy_tmp/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv4.conf.ens18.send_redirects = 0'
assert_contains "$policy_tmp/root/etc/nftables.d/dnscomplex.nft" 'iifname "ens18" udp dport 53 redirect to :53'
assert_contains "$policy_tmp/root/etc/nftables.d/dnscomplex.nft" \
  'oifname "ens18" ip saddr 192.168.50.0/24 ip daddr != { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } counter snat ip to 192.168.50.200 comment "dnscomplex-routeros-default-snat"'
assert_contains "$policy_tmp/root/usr/local/sbin/dnscomplex" 'dnscomplex-routeros-default-snat'
assert_contains "$policy_tmp/root/usr/local/sbin/dnscomplex" 'routeros-default-snat'
assert_contains "$policy_tmp/root/usr/local/sbin/dnscomplex" 'routeros-send-redirects'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" '192.168.50.200'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'action=mark-routing'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'dst-port=53'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'src-address-list=dnscomplex-clients'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'tool/netwatch/add'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'dnscomplex-primary-health'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'dnscomplex-secondary-health'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'type=http-get'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'url="http://192.168.50.200:9108/healthz"'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'url="http://192.168.50.201:9108/healthz"'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'dnscomplex-policy-to-vm-primary'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'dnscomplex-policy-to-vm-secondary'
assert_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'dnscomplex-fail-open'
assert_not_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" '/ip/dhcp-server/network/set'
assert_not_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'src-address=192.168.50.0/24'
assert_not_contains "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc" '/interface/vlan/add'
assert_contains "$repo_root/install.sh" 'disable_conflicting_lan_services'
assert_contains "$repo_root/install.sh" 'disable_systemd_ssh_generator'
assert_contains "$repo_root/install.sh" 'systemctl stop sshd-unix-local.socket sshd-vsock.socket sshd-unix-export.socket'
assert_contains "$repo_root/install.sh" 'systemctl reset-failed dnsmasq radvd systemd-resolved'
# shellcheck disable=SC2016
assert_contains "$repo_root/install.sh" 'if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then'
[[ ! -f "$policy_tmp/root/etc/systemd/network/10-dnscomplex-vlans.netdev" ]] || fail "routeros-policy must not render VLAN netdev"
[[ ! -f "$policy_tmp/root/etc/dnsmasq.d/dnscomplex.conf" ]] || fail "routeros-policy must not enable Linux DHCP"
DNSCOMPLEX_ROOT="$policy_tmp/root" bash "$repo_root/install.sh" --dry-run --config "$policy_tmp/config.env"
[[ "$(grep -Ec '^[[:space:]]*nohook[[:space:]]+resolv[.]conf[[:space:]]*$' "$policy_tmp/root/etc/dhcpcd.conf")" == "1" ]] || fail "routeros-policy dhcpcd nohook must be idempotent"

policy_defaults_tmp=$(mktemp -d)
cat >"$policy_defaults_tmp/config.env" <<'EOF'
DNSCOMPLEX_NONINTERACTIVE=1
DEPLOY_MODE=routeros-policy
WAN_IFACE=ens18
ROUTEROS_LAN_IPV4=192.168.50.253
LINUX_LAN_IPV4=192.168.50.200
LAN_CLIENT_IPV4_CIDR=192.168.50.0/24
AI_IPSEC_USERNAME=ai-user
AI_IPSEC_PASSWORD=ai-pass
CN_IPSEC_USERNAME=cn-user
CN_IPSEC_PASSWORD=cn-pass
EOF
DNSCOMPLEX_ROOT="$policy_defaults_tmp/root" bash "$repo_root/install.sh" --dry-run --config "$policy_defaults_tmp/config.env"
assert_contains "$policy_defaults_tmp/root/etc/dnscomplex/config.env" "SINGBOX_SOCKS_LISTEN='192.168.50.200'"
assert_contains "$policy_defaults_tmp/root/etc/dnscomplex/config.env" "SINGBOX_SOCKS_PORT='10800'"
assert_contains "$policy_defaults_tmp/root/etc/sing-box/config.json" '"listen": "192.168.50.200"'
assert_contains "$policy_defaults_tmp/root/etc/sing-box/config.json" '"listen_port": 10800'

cp "$policy_defaults_tmp/config.env" "$policy_defaults_tmp/wrong-port.env"
cat >>"$policy_defaults_tmp/wrong-port.env" <<'EOF'
SINGBOX_SOCKS_LISTEN=192.168.50.200
SINGBOX_SOCKS_PORT=1080
EOF
if DNSCOMPLEX_ROOT="$policy_defaults_tmp/wrong-port-root" \
  bash "$repo_root/install.sh" --dry-run --config "$policy_defaults_tmp/wrong-port.env" >/dev/null 2>&1; then
  fail "routeros-policy installer accepted a SOCKS port other than 10800"
fi

cat >>"$policy_defaults_tmp/config.env" <<'EOF'
SINGBOX_SOCKS_LISTEN=0.0.0.0
SINGBOX_SOCKS_PORT=1080
EOF
if DNSCOMPLEX_ROOT="$policy_defaults_tmp/invalid-root" \
  bash "$repo_root/install.sh" --dry-run --config "$policy_defaults_tmp/config.env" >/dev/null 2>&1; then
  fail "routeros-policy installer accepted a non-VM SOCKS listen address"
fi
rm -rf "$policy_defaults_tmp"
rm -rf "$policy_tmp"

single_policy_tmp=$(mktemp -d)
cat >"$single_policy_tmp/config.env" <<'EOF'
DNSCOMPLEX_NONINTERACTIVE=1
DEPLOY_MODE=routeros-policy
WAN_IFACE=ens18
ROUTEROS_LAN_IPV4=192.168.50.253
LINUX_LAN_IPV4=192.168.50.200
LAN_CLIENT_IPV4_CIDR=192.168.50.0/24
SINGBOX_SOCKS_LISTEN=192.168.50.200
SINGBOX_SOCKS_PORT=10800
AI_IPSEC_USERNAME=ai-user
AI_IPSEC_PASSWORD=ai-pass
CN_IPSEC_USERNAME=cn-user
CN_IPSEC_PASSWORD=cn-pass
EOF
DNSCOMPLEX_ROOT="$single_policy_tmp/root" bash "$repo_root/install.sh" --dry-run --config "$single_policy_tmp/config.env"
assert_contains "$single_policy_tmp/root/var/lib/dnscomplex/routeros.rsc" 'dnscomplex-primary-health dnscomplex-fail-open'
assert_contains "$single_policy_tmp/root/var/lib/dnscomplex/routeros.rsc" '/ip/firewall/mangle/disable [find where comment=dnscomplex-policy-to-vm]'
assert_contains "$single_policy_tmp/root/var/lib/dnscomplex/routeros.rsc" '/ip/firewall/nat/disable [find where comment~\"dnscomplex-force-dns\"]'
rm -rf "$single_policy_tmp"

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
fix_body=$(awk '
  /^fix_cmd\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$fix_body" in
  *'swanctl --initiate --child ai'*|*'swanctl --initiate --child cn'*)
    fail "fix command initiates unselected IPsec profiles"
    ;;
esac
# shellcheck disable=SC2016
grep -Fq 'state_transaction_cmd "repair" state_transaction_manager_cmd fix_cmd --strict' <<<"$fix_body" ||
  fail "fix command does not use a transactional strict repair boundary"
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'flock -n 9'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'future SmartDNS restart timestamp clamped to the current time'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'write_smartdns_restart_epoch'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'mktemp "$RUN_DIR/.smartdns.last_restart.XXXXXX"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'chmod 0600 "$temp"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'mv -f "$temp" "$RUN_DIR/smartdns.last_restart"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'monotonic_millis) + 14500'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'restart_watchdog_unit_if_inactive "$unit" || return 1'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'could not allocate SmartDNS probe state'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'trap cleanup_restart_epoch_temp EXIT HUP INT TERM'
assert_contains "$repo_root/install.sh" 'cron dnsutils python3 python3-bcrypt python3-yaml coreutils util-linux'
health_body=$(awk '
  /^health_cmd\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$health_body" in
  *watchdog_cmd*) ;;
  *) fail "plain health does not delegate to watchdog" ;;
esac
case "$health_body" in
  *migrate_config_cmd*|*apply_runtime_network_settings*|*swanctl*|*routes*)
    fail "plain health retains timer repair work"
    ;;
esac
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'CONFIG=${DNSCOMPLEX_CONFIG:-${FS_ROOT%/}/etc/dnscomplex/config.env}'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'BASE=${DNSCOMPLEX_BASE:-${FS_ROOT}/var/lib/dnscomplex}'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'RUN_DIR=${DNSCOMPLEX_RUN_DIR:-${FS_ROOT}/run/dnscomplex}'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'FS_ROOT=${DNSCOMPLEX_FS_ROOT:-$DNSCOMPLEX_ROOT}'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'MAINTENANCE_LOCK=${DNSCOMPLEX_MAINTENANCE_LOCK:-${FS_ROOT}/run/lock/dnscomplex-maintenance.lock}'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'socket.AF_INET'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'socket.AF_INET6'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'default-ipv4-connectivity'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'default-ipv6-connectivity'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'IPv6 route lookup ok'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'tcp_connectivity("1.1.1.1"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'SmartDNS listeners and direct DNS positive controls are unavailable'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'acquire_maintenance_lock'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'acquire_maintenance_lock --skip-busy'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'acquire_maintenance_lock --wait'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'internal_service_command'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'timer_service_command'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'tmp=$(mktemp "$(dirname "$CONFIG")/.config.env.XXXXXX")'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'mv -f "$tmp" "$CONFIG"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'snapshot_copy'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'sqlite_backup'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'src.backup(dst)'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'PRAGMA integrity_check'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'metrics.sqlite3-wal'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'metrics.sqlite3-shm'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'metrics.sqlite3-journal'
assert_file "$tmpdir/root/usr/local/libexec/dnscomplex-restore-recover"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-restore-recovery.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-restore-services.service"
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-restore-recovery.service" \
  'Before=sysinit.target network-pre.target dnscomplex-network-ready.service'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-restore-recovery.service" \
  'RequiredBy=sysinit.target'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-restore-recovery.service" \
  'ExecStart=/usr/local/libexec/dnscomplex-restore-recover --files'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-restore-services.service" \
  'After=basic.target dnscomplex-restore-recovery.service'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-restore-services.service" \
  'Before=multi-user.target'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-restore-services.service" \
  'ExecStart=/usr/local/libexec/dnscomplex-restore-recover --services'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-restore-services.service" \
  'RequiredBy=multi-user.target'
assert_contains "$tmpdir/root/usr/local/libexec/dnscomplex-restore-recover" \
  'service_unit_allowed'
assert_contains "$tmpdir/root/usr/local/libexec/dnscomplex-restore-recover" \
  'durable_sync_path'
assert_contains "$tmpdir/root/usr/local/libexec/dnscomplex-restore-recover" \
  'read -r entry || [[ -n "$entry" ]]'
assert_contains "$tmpdir/root/usr/local/libexec/dnscomplex-restore-recover" \
  'mv -- "$transaction" "$finalized"'
assert_contains "$tmpdir/root/usr/local/libexec/dnscomplex-restore-recover" \
  'restore_service_units_in_order'
backup_body=$(awk '
  /^backup_cmd\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$backup_body" in
  *acquire_maintenance_lock*sqlite_backup*'tar -czf'*) ;;
  *) fail "backup must lock, snapshot SQLite, then create the archive" ;;
esac
update_software_body=$(awk '
  /^update_software_cmd\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$update_software_body" in
  *acquire_maintenance_lock*update_software_impl*) ;;
  *) fail "software update must acquire maintenance lock before entering the transaction" ;;
esac
case "$update_software_body" in
  *write_config_cmd*) fail "software update command mutated config before the transaction backup" ;;
esac
update_software_impl_body=$(awk '
  /^update_software_impl\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$update_software_impl_body" in
  *backup_cmd*backup_release_binaries*write_config_cmd*update_release_if_needed*) ;;
  *) fail "component update must back up before release and config mutations" ;;
esac
case "$update_software_impl_body" in
  *apt-get*) fail "component update must not mutate Debian package state" ;;
esac
case "$update_software_impl_body" in
  *'systemctl restart "${UPDATED_SERVICES[@]}"'*'"$0" ipsec-ready'*'"$0" routes up'*\
'post-update health validation'*'"$0" test'*) ;;
  *) fail "software update must restore selected egress before post-update validation" ;;
esac
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'rollback_component_update "$before"'
system_update_impl_body=$(awk '
  /^system_update_impl\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$system_update_impl_body" in
  *'apt-get update'*'upgrade -y --with-new-pkgs'*test_cmd*) ;;
  *) fail "system update must keep Debian package mutation in its own explicit flow" ;;
esac
case "$system_update_impl_body" in
  *write_config_cmd*|*update_release_if_needed*|*rollback_component_update*)
    fail "system update must not mix config/release mutation or application rollback"
    ;;
esac
for mutator in \
  watchdog network-ready ipsec-ready ipsec-ifaces routes fix update-geosite apply-domain-rules-json add-domain remove-domain set-socks set-ipsec \
  set-web-password set-local-host set-egress apply-egress-json set-xray-uri set-xray-json \
  render-xray set-update-time refresh-nftsets \
  refresh-cn-overrides mss-calibrate update-software system-update \
  apply-config apply-config-json backup restore; do
  bash -c 'source "$1"; persistent_mutator_command "$2"' \
    _ "$tmpdir/root/usr/local/sbin/dnscomplex" "$mutator" ||
    fail "persistent command is not covered by the maintenance lock: $mutator"
done
if bash -c 'source "$1"; persistent_mutator_command metrics-sample' \
   _ "$tmpdir/root/usr/local/sbin/dnscomplex"; then
  fail "metrics sampling must not take the global maintenance lock"
fi
if DNSCOMPLEX_TIMER_MODE=1 bash -c 'source "$1"; timer_service_command metrics-sample' \
   _ "$tmpdir/root/usr/local/sbin/dnscomplex"; then
  fail "timer-mode metrics sampling must not take the global maintenance lock"
fi
if bash -c 'source "$1"; persistent_mutator_command health --json' \
   _ "$tmpdir/root/usr/local/sbin/dnscomplex"; then
  fail "health --json must remain read-only and not acquire the maintenance lock"
fi
for read_only in status doctor trace-domain render-config support-bundle test test-ipsec test-xray; do
  if bash -c 'source "$1"; persistent_mutator_command "$2"' \
     _ "$tmpdir/root/usr/local/sbin/dnscomplex" "$read_only"; then
    fail "read-only command unnecessarily takes the maintenance lock: $read_only"
  fi
done
manager_main_body=$(awk '
  /^main\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$manager_main_body" in
  *internal_service_command*timer_service_command*'acquire_maintenance_lock --wait'*persistent_mutator_command*acquire_maintenance_lock*load_config*'case "$cmd" in'*) ;;
  *) fail "manager must lock persistent commands before loading shared config" ;;
esac
restore_body=$(awk '
  /^restore_cmd\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$restore_body" in
  *acquire_maintenance_lock*) ;;
  *) fail "restore must share the maintenance lock" ;;
esac
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'validate_backup_archive "$archive_copy"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'tar -xzf "$archive_copy" -C "$stage"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'restore_v2_backup "$stage"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'validate_backup_manifest "$stage"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'restore_service_state "$stage/.dnscomplex-backup/service-state.tsv"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'snapshot_service_state "$transaction/pre-service-state.tsv"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'restore_quiesce_units'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'verify_restore_recovery_helper'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'convert_legacy_backup_stage'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'legacy_reconcile_cmd'
legacy_reconcile_body=$(awk '
  /^legacy_reconcile_cmd\(\) \{/ { inside=1 }
  inside { print }
  inside && /^}/ { exit }
' "$tmpdir/root/usr/local/sbin/dnscomplex")
case "$legacy_reconcile_body" in
  *'|| true'*) fail "legacy reconciliation retains best-effort failures" ;;
esac
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'services-quiescing'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'optional_backup_paths'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'dnscomplex-restore-recovery.service'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  '.dnscomplex-restore.'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  'dnscomplex-restore-recover'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" \
  '"$transaction/committed"'

printf 'install contract test: ok\n'
