#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
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

assert_file "$tmpdir/root/etc/sing-box/config.json"
assert_file "$tmpdir/root/etc/smartdns/smartdns.conf"
assert_file "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml"
assert_file "$tmpdir/root/etc/swanctl/swanctl.conf"
assert_file "$tmpdir/root/etc/nftables.d/dnscomplex.nft"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.timer"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-nftset-refresh.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-nftset-refresh.timer"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-web.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-metrics.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-metrics-sample.service"
assert_file "$tmpdir/root/etc/systemd/system/dnscomplex-metrics-sample.timer"
assert_file "$tmpdir/root/etc/systemd/system/xray-dnscomplex.service"
assert_file "$tmpdir/root/usr/local/sbin/dnscomplex"
assert_file "$tmpdir/root/usr/local/lib/dnscomplex-xray/render.py"
assert_file "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py"
assert_file "$tmpdir/root/usr/local/lib/dnscomplex-metrics/exporter.py"
assert_file "$tmpdir/root/etc/prometheus/dnscomplex.rules.yml"
assert_file "$tmpdir/root/usr/local/etc/xray/config.json"
assert_file "$tmpdir/root/var/lib/dnscomplex/routeros.rsc"
assert_file "$tmpdir/root/var/lib/dnscomplex/geosite/ai.sources"
assert_file "$tmpdir/root/var/lib/dnscomplex/geosite/ai-support.sources"
assert_file "$tmpdir/root/var/lib/dnscomplex/geosite/cn-video.sources"

assert_contains "$tmpdir/root/etc/sing-box/config.json" '"type": "tun"'
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
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"gateway.icloud.com"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" 'geosite-ai-openai.srs'
assert_contains "$tmpdir/root/etc/sing-box/config.json" 'geosite-ai-anthropic.srs'
assert_contains "$tmpdir/root/etc/sing-box/config.json" 'geosite-ai-meta.srs'
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
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"bind_interface": "ipsec-ai"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"bind_interface": "ipsec-cn"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"tag": "ai-xray"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"tag": "cn-xray"'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"server_port": 16054'
assert_contains "$tmpdir/root/etc/sing-box/config.json" '"server_port": 16055'
assert_not_contains "$tmpdir/root/etc/sing-box/config.json" '"routing_mark":'

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
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'force-qtype-SOA 65'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'cache-size 65536'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'cache-persist yes'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'cache-file /var/lib/smartdns/dnscomplex.cache'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'cache-checkpoint-time 86400'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'serve-expired-ttl 259200'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'serve-expired-reply-ttl 3'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'serve-expired-prefetch-time 21600'
assert_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'address /-.youku.com/47.246.99.254'
assert_not_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'address /youku.com/47.246.99.254'
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_OVERRIDE_PROBE_DOMAINS='youku.com=youku.com,www.youku.com'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_OVERRIDE_PROBE_RESOLVERS='223.5.5.5 119.29.29.29 1.1.1.1 8.8.8.8'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "DEFAULT_DNS_STRATEGY='prefer_ipv6'"
assert_not_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'domain-set'
assert_not_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'nameserver /domain-set'
assert_not_contains "$tmpdir/root/etc/smartdns/smartdns.conf" 'nftset /domain-set'

assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" "    - '127.0.0.1:1053'"
assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '  cache_enabled: false'
assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '  cache_size: 0'
assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '  cache_optimistic: false'
assert_not_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '  cache_size: 67108864'
assert_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" "  - '@@||claude.ai^'"
assert_not_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" "  - '@@||api.statsig.com^'"
assert_not_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" "  - '@@||api.revenuecat.com^'"
assert_not_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '[/openai.com/]127.0.0.1:6054'
assert_not_contains "$tmpdir/root/etc/AdGuardHome/AdGuardHome.yaml" '[/bilibili.com/]127.0.0.1:6055'

assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'sx301001-ikev.ptoserver.com'
assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'sx351401-ikev.ptoserver.com'
assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'eap-mschapv2'
assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'dpd_delay'
assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'local_addrs ='
assert_contains "$tmpdir/root/etc/swanctl/swanctl.conf" 'id = pointtoserver.com'
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "IPSEC_REMOTE_ID='pointtoserver.com'"
assert_file "$tmpdir/root/etc/swanctl/x509ca/README.dnscomplex"

assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'type nat hook prerouting priority dstnat'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'tcp option maxseg size set 1200'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept'
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'udp dport { 784, 853, 8853 } drop'
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-ai-block-quic'
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-cn-block-quic'
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-ai-output-block-quic'
assert_not_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'dnscomplex-cn-output-block-quic'
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
assert_contains "$tmpdir/root/etc/nftables.d/dnscomplex.nft" 'size 262144'
assert_contains "$tmpdir/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv4.ip_forward = 1'
assert_contains "$tmpdir/root/etc/sysctl.d/90-dnscomplex.conf" 'net.netfilter.nf_conntrack_max = 1048576'
assert_contains "$tmpdir/root/etc/sysctl.d/90-dnscomplex.conf" 'net.netfilter.nf_conntrack_tcp_timeout_established = 86400'
assert_contains "$tmpdir/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv4.tcp_max_syn_backlog = 65535'
assert_contains "$tmpdir/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv4.ip_local_port_range = 1024 65535'
assert_contains "$repo_root/install.sh" 'apply_runtime_network_settings'
assert_contains "$repo_root/install.sh" 'resolve_default_ipv6_mode'
assert_contains "$repo_root/install.sh" 'DEFAULT_IPV6_MODE'
assert_contains "$repo_root/install.sh" 'sysctl -w net.ipv4.ip_forward=1'

for cmd in status test health fix doctor update-geosite add-domain remove-domain set-socks set-ipsec set-update-time refresh-nftsets refresh-cn-overrides trace-domain test-dns test-ipsec mss-calibrate routeros-print update-software backup restore metrics-sample soak wizard validate-config render-config support-bundle; do
  assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" "$cmd"
done
for cmd in set-egress set-xray-uri set-xray-json test-xray xray-status render-xray; do
  assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" "$cmd"
done
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'set Xray URI/JSON before switching AI to xray'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'set Xray URI/JSON before switching CN to xray'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'AI/CN egress are not using IPsec; skipping IPsec test'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'AI_EGRESS_MODE:-ipsec'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'CN_EGRESS_MODE:-ipsec'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'xray run -test -format=json'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'migrate_config_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'config_missing_keys'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'doctor_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'health_json_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'metrics_sample_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'soak_cmd'
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
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'set_update_time_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'refresh_cn_overrides_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'refresh_nftsets_cmd'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'public_ipv4'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'refresh_nftset_group ai "$SMARTDNS_AI_PORT" ai4'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'refresh_nftset_group cn "$SMARTDNS_CN_PORT" cn4'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'nft add element inet dnscomplex cn4'
# shellcheck disable=SC2016
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'nft add element inet dnscomplex "$set_name"'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'nft list table inet dnscomplex >/dev/null 2>&1 || systemctl restart nftables || true'
assert_contains "$repo_root/install.sh" 'systemctl restart nftables || true'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.service" 'ExecStart=/usr/local/sbin/dnscomplex refresh-cn-overrides'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-cn-overrides.timer" 'OnUnitActiveSec=6h'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-nftset-refresh.service" 'ExecStart=/usr/local/sbin/dnscomplex refresh-nftsets'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-nftset-refresh.timer" 'OnUnitActiveSec=5m'
assert_contains "$repo_root/install.sh" 'dnscomplex-cn-overrides.timer'
assert_contains "$repo_root/install.sh" 'dnscomplex-nftset-refresh.timer'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'apply_runtime_network_settings'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'resolve_default_ipv6_mode'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'ipv6_tcp_available'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'unit_exists'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'print_unit_state'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'ipsec_vip'
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
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'systemctl reset-failed dnscomplex-update.service'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" '/var/log/dnscomplex/update-'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'github_latest_release_tag'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'update_release_if_needed'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'already latest; skip'
assert_not_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'systemctl restart sing-box smartdns AdGuardHome nftables'
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
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "XRAY_LISTEN_HOST='127.0.0.1'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "XRAY_AI_SOCKS_PORT='16054'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "XRAY_CN_SOCKS_PORT='16055'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_XRAY_URI=''"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_XRAY_URI=''"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_XRAY_OUTBOUND_JSON=''"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_XRAY_OUTBOUND_JSON=''"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_NFTSET_REFRESH_DOMAINS='chatgpt.com ios.chat.openai.com openai.com api.openai.com oaistatic.com oaiusercontent.com files.oaiusercontent.com cdn.oaistatic.com persistent.oaistatic.com cdn.openai.com anthropic.com claude.ai claude.com meta.ai'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "CN_NFTSET_REFRESH_DOMAINS='bilibili.com iqiyi.com youku.com douyin.com kuaishou.com acfun.cn mgtv.com v.qq.com qq.com tv.cctv.com'"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "AI_SUPPORT_DOMAINS=''"
assert_contains "$tmpdir/root/etc/dnscomplex/config.env" "SING_GEOSITE_RULESET_BASE_URL='https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set'"
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'SagerNet/sing-box'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'AdguardTeam/AdGuardHome'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'pymumu/smartdns'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'XTLS/Xray-core'
assert_contains "$tmpdir/root/usr/local/sbin/dnscomplex" 'github_latest_asset_url'

assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/ai.sources" 'openai'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/ai.sources" 'anthropic'
assert_contains "$tmpdir/root/var/lib/dnscomplex/geosite/ai.sources" 'meta'
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
assert_contains "$repo_root/install.sh" 'apt-get upgrade -y'
assert_contains "$repo_root/install.sh" 'update_release_if_needed'
assert_contains "$repo_root/install.sh" 'conntrack'
assert_contains "$repo_root/install.sh" 'dnscomplex update-geosite'
assert_contains "$repo_root/install.sh" 'dnscomplex routes up || true'
assert_contains "$repo_root/install.sh" 'doctor_cmd'
assert_contains "$repo_root/install.sh" 'DNSCOMPLEX_UPDATE_LAST_LOG'
assert_contains "$repo_root/install.sh" 'prefetch-domain yes'
assert_contains "$repo_root/install.sh" 'cache_enabled: false'
assert_contains "$repo_root/install.sh" 'dnscomplex_conntrack_usage_ratio'
assert_contains "$repo_root/install.sh" 'dnscomplex_dns_latency_ms'
assert_not_contains "$repo_root/install.sh" 'apt-get install -y smartdns'
assert_not_contains "$repo_root/install.sh" 'https://sing-box.app/deb-install.sh'
assert_not_contains "$repo_root/install.sh" 'AdGuardHome/master/scripts/install.sh'
assert_not_contains "$repo_root/install.sh" 'systemd-resolved cron dnsutils'

assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'ThreadingHTTPServer'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'CONFIG_KEYS'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'AI_EGRESS_MODE'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'AI_XRAY_URI'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'set-egress'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'set-xray-uri'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'test-xray'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '"-format=json"'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/egress/test'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/egress/apply'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/rules/domain'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/rules/geosite'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/rules/rebuild'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '/api/trace-domain'
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
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'update-software'
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
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" 'drawChart'
assert_contains "$tmpdir/root/usr/local/lib/dnscomplex-web/app.py" '<canvas'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-web.service" 'ExecStart=/usr/bin/python3 /usr/local/lib/dnscomplex-web/app.py'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-metrics.service" 'ExecStart=/usr/bin/python3 /usr/local/lib/dnscomplex-metrics/exporter.py'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-metrics-sample.service" 'ExecStart=/usr/local/sbin/dnscomplex metrics-sample'
assert_contains "$tmpdir/root/etc/systemd/system/dnscomplex-metrics-sample.timer" 'OnUnitActiveSec=60s'
assert_contains "$tmpdir/root/etc/systemd/system/xray-dnscomplex.service" 'ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json'
assert_contains "$tmpdir/root/etc/prometheus/dnscomplex.rules.yml" 'DnscomplexConntrackHigh'
assert_contains "$tmpdir/root/etc/prometheus/dnscomplex.rules.yml" 'DnscomplexAdGuardCacheEnabled'

secret_probe="$tmpdir/secret-probe.txt"
cat >"$secret_probe" <<'EOF'
AI_IPSEC_PASSWORD=super-secret-pass
AI_IPSEC_USERNAME=secret-user
CN_IPSEC_PASSWORD=cn-super-secret
AI_XRAY_OUTBOUND_JSON={"password":"json-secret","server":"203.0.113.8"}
AI_XRAY_URI=vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls#ai
GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef123456
LAN=192.168.88.1 203.0.113.8 fd00:88::1 hostname router.local
EOF
redacted_probe=$(bash -c '
  source "$1"
  redact_stream <"$2"
' _ "$tmpdir/root/usr/local/sbin/dnscomplex" "$secret_probe")
case "$redacted_probe" in
  *super-secret-pass*|*secret-user*|*cn-super-secret*|*json-secret*|*123e4567-e89b-12d3-a456-426614174000*|*ghp_1234567890abcdef1234567890abcdef123456*|*192.168.88.1*|*203.0.113.8*|*fd00:88::1*|*router.local*)
    fail "support redaction leaked sensitive probe: $redacted_probe"
    ;;
esac
printf '%s\n' "$redacted_probe" | grep -Fq '[REDACTED' || fail "support redaction did not mark redacted values"

policy_tmp=$(mktemp -d)
cat >"$policy_tmp/config.env" <<'EOF'
DNSCOMPLEX_NONINTERACTIVE=1
DEPLOY_MODE=routeros-policy
WAN_IFACE=ens18
ROUTEROS_LAN_IPV4=192.168.50.253
LINUX_LAN_IPV4=192.168.50.200
LAN_CLIENT_IPV4_CIDR=192.168.50.0/24
SINGBOX_SOCKS_LISTEN=192.168.50.200
SINGBOX_SOCKS_PORT=1080
AI_IPSEC_USERNAME=ai-user
AI_IPSEC_PASSWORD=ai-pass
CN_IPSEC_USERNAME=cn-user
CN_IPSEC_PASSWORD=cn-pass
HA_MODE=primary
HA_PRIMARY_IP=192.168.50.200
HA_SECONDARY_IP=192.168.50.201
EOF
DNSCOMPLEX_ROOT="$policy_tmp/root" bash "$repo_root/install.sh" --dry-run --config "$policy_tmp/config.env"
assert_file "$policy_tmp/root/etc/sing-box/config.json"
assert_file "$policy_tmp/root/etc/nftables.d/dnscomplex.nft"
assert_file "$policy_tmp/root/var/lib/dnscomplex/routeros.rsc"
assert_contains "$policy_tmp/root/etc/dnscomplex/config.env" "DEPLOY_MODE='routeros-policy'"
assert_contains "$policy_tmp/root/etc/sing-box/config.json" '"include_interface": ['
assert_contains "$policy_tmp/root/etc/sing-box/config.json" '"ens18"'
assert_contains "$policy_tmp/root/etc/sing-box/config.json" '"listen": "192.168.50.200"'
assert_contains "$policy_tmp/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv6.conf.ens18.accept_ra = 2'
assert_contains "$policy_tmp/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv6.conf.ens18.autoconf = 1'
assert_contains "$policy_tmp/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv6.conf.ens18.addr_gen_mode = 0'
assert_contains "$policy_tmp/root/etc/sysctl.d/90-dnscomplex.conf" 'net.ipv4.conf.ens18.rp_filter = 0'
assert_contains "$policy_tmp/root/etc/nftables.d/dnscomplex.nft" 'iifname "ens18" udp dport 53 redirect to :53'
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
assert_contains "$repo_root/install.sh" 'systemctl reset-failed dnsmasq radvd systemd-resolved'
# shellcheck disable=SC2016
assert_contains "$repo_root/install.sh" 'if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then'
[[ ! -f "$policy_tmp/root/etc/systemd/network/10-dnscomplex-vlans.netdev" ]] || fail "routeros-policy must not render VLAN netdev"
[[ ! -f "$policy_tmp/root/etc/dnsmasq.d/dnscomplex.conf" ]] || fail "routeros-policy must not enable Linux DHCP"
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
SINGBOX_SOCKS_PORT=1080
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

printf 'install contract ok\n'
