#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

DNSCOMPLEX_VERSION="0.1.0"
DNSCOMPLEX_ROOT="${DNSCOMPLEX_ROOT:-}"
CONFIG_PATH=""
DRY_RUN=0
ASSUME_YES=0

AI_IPSEC_SERVER_DEFAULT="sx301001-ikev.ptoserver.com"
CN_IPSEC_SERVER_DEFAULT="sx351401-ikev.ptoserver.com"
SMARTDNS_DEFAULT_PORT=6053
SMARTDNS_AI_PORT=6054
SMARTDNS_CN_PORT=6055
SINGBOX_DNS_LISTEN="127.0.0.1"
SINGBOX_DNS_PORT=1053
SINGBOX_SOCKS_LISTEN="0.0.0.0"
SINGBOX_SOCKS_PORT=1080
SINGBOX_HTTP_LISTEN="0.0.0.0"
SINGBOX_HTTP_PORT=1081
XRAY_ENABLED=1
XRAY_LISTEN_HOST="127.0.0.1"
XRAY_AI_SOCKS_PORT=16054
XRAY_CN_SOCKS_PORT=16055
AI_EGRESS_MODE="ipsec"
CN_EGRESS_MODE="ipsec"
AI_XRAY_URI=""
CN_XRAY_URI=""
AI_XRAY_OUTBOUND_JSON=""
CN_XRAY_OUTBOUND_JSON=""
APPLE_PRIVATE_RELAY_BLOCK=1
DNSCOMPLEX_WEB_PORT=8088
DNSCOMPLEX_UPDATE_TIME="04:20"
DNSCOMPLEX_UPDATE_CHANNEL="stable"
DNSCOMPLEX_PINNED_VERSION=""
GITHUB_RELEASE_POLICY="latest"
DNSCOMPLEX_NFTSET_REFRESH_INTERVAL="5m"
DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT="2h"
IPSEC_TCP_MSS=1200
AI_MARK="0x301"
CN_MARK="0x351"
AI_MARK_DEC="769"
CN_MARK_DEC="849"
SINGBOX_AUTO_REDIRECT_INPUT_MARK="0x2023"
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK="0x2024"
SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC="8227"
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC="8228"
AI_TABLE="301"
CN_TABLE="351"
AI_XFRM_ID="301"
CN_XFRM_ID="351"
DEPLOY_MODE="vlan-gateway"

AI_GEOSITE_SOURCES_DEFAULT="openai anthropic"
AI_SUPPORT_DOMAINS_DEFAULT="meta.ai"
AI_NFTSET_REFRESH_DOMAINS_DEFAULT="chatgpt.com ios.chat.openai.com openai.com api.openai.com oaistatic.com oaiusercontent.com files.oaiusercontent.com cdn.oaistatic.com persistent.oaistatic.com cdn.openai.com anthropic.com claude.ai claude.com meta.ai"
SING_GEOSITE_RULESET_BASE_URL_DEFAULT="https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set"
CN_VIDEO_SOURCES_DEFAULT="acfun bilibili douyin douyu gitv hunantv huya iqiyi kuaishou le pptv youku wasu v.qq.com video.qq.com tencentvideo.com cibntv.net"
AI_SAMPLE_DOMAINS_DEFAULT="openai.com anthropic.com claude.ai meta.ai"
CN_SAMPLE_DOMAINS_DEFAULT="bilibili.com iqiyi.com youku.com douyin.com kuaishou.com acfun.cn mgtv.com v.qq.com qq.com tv.cctv.com"
CN_NFTSET_REFRESH_DOMAINS_DEFAULT="$CN_SAMPLE_DOMAINS_DEFAULT"
CN_STATIC_A_OVERRIDES_DEFAULT="youku.com=47.246.99.254"
CN_OVERRIDE_PROBE_DOMAINS_DEFAULT="youku.com=youku.com,www.youku.com"
CN_OVERRIDE_PROBE_RESOLVERS_DEFAULT="223.5.5.5 119.29.29.29 1.1.1.1 8.8.8.8"

usage() {
  cat <<'EOF'
dnscomplex Debian 13 one-arm split gateway installer

Usage:
  ./install.sh [--config FILE] [--dry-run] [--yes]
  ./install.sh --help

Options:
  --config FILE  Load shell-style environment variables from FILE.
  --dry-run      Render all managed files under DNSCOMPLEX_ROOT and skip system changes.
  --yes          Accept prompts where defaults are available.
  --help         Show this help.

Required non-interactive variables:
  DEPLOY_MODE=vlan-gateway:
    WAN_IFACE TRANSIT_VLAN_ID LAN_VLAN_ID
    ROUTEROS_TRANSIT_IPV4 LINUX_TRANSIT_IPV4 TRANSIT_IPV4_CIDR
    ROUTEROS_TRANSIT_IPV6 LINUX_TRANSIT_IPV6 TRANSIT_IPV6_CIDR
    LAN_IPV4_CIDR LAN_DHCP_START LAN_DHCP_END LAN_IPV6_PREFIX
  DEPLOY_MODE=routeros-policy:
    WAN_IFACE ROUTEROS_LAN_IPV4 LINUX_LAN_IPV4 LAN_CLIENT_IPV4_CIDR
  AI_IPSEC_USERNAME AI_IPSEC_PASSWORD CN_IPSEC_USERNAME CN_IPSEC_PASSWORD

Optional variables:
  DEPLOY_MODE AI_IPSEC_SERVER CN_IPSEC_SERVER
  SINGBOX_SOCKS_LISTEN SINGBOX_SOCKS_PORT
  SINGBOX_HTTP_LISTEN SINGBOX_HTTP_PORT APPLE_PRIVATE_RELAY_BLOCK
  XRAY_ENABLED AI_EGRESS_MODE CN_EGRESS_MODE AI_XRAY_URI CN_XRAY_URI
  AI_XRAY_OUTBOUND_JSON CN_XRAY_OUTBOUND_JSON XRAY_LISTEN_HOST XRAY_AI_SOCKS_PORT XRAY_CN_SOCKS_PORT
  SINGBOX_DNS_LISTEN SINGBOX_DNS_PORT
  DNSCOMPLEX_WEB_LISTEN DNSCOMPLEX_WEB_PORT DNSCOMPLEX_WEB_PASSWORD DNSCOMPLEX_UPDATE_TIME
  DNSCOMPLEX_NFTSET_REFRESH_INTERVAL DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT IPSEC_TCP_MSS
  DEFAULT_DNS_UPSTREAMS DEFAULT_DNS_STRATEGY AI_DNS_UPSTREAMS CN_DNS_UPSTREAMS
  DEFAULT_IPV6_MODE=auto|on|off
  AI_GEOSITE_SOURCES AI_SUPPORT_DOMAINS SING_GEOSITE_RULESET_BASE_URL
  AI_NFTSET_REFRESH_DOMAINS CN_NFTSET_REFRESH_DOMAINS
  CN_VIDEO_SOURCES AI_SAMPLE_DOMAINS CN_SAMPLE_DOMAINS
  CN_STATIC_A_OVERRIDES CN_OVERRIDE_PROBE_DOMAINS CN_OVERRIDE_PROBE_RESOLVERS
EOF
}

log() {
  printf '[dnscomplex] %s\n' "$*"
}

warn() {
  printf '[dnscomplex] WARN: %s\n' "$*" >&2
}

die() {
  printf '[dnscomplex] ERROR: %s\n' "$*" >&2
  exit 1
}

parse_args() {
  while (($#)); do
    case "$1" in
      --config)
        shift
        [[ $# -gt 0 ]] || die "--config requires a file"
        CONFIG_PATH=$1
        ;;
      --dry-run)
        DRY_RUN=1
        ;;
      --yes|-y)
        ASSUME_YES=1
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
    shift
  done
}

load_config() {
  if [[ -n "$CONFIG_PATH" ]]; then
    [[ -f "$CONFIG_PATH" ]] || die "config file not found: $CONFIG_PATH"
    set -a
    # shellcheck disable=SC1090
    . "$CONFIG_PATH"
    set +a
  fi

  : "${AI_IPSEC_SERVER:=$AI_IPSEC_SERVER_DEFAULT}"
  : "${CN_IPSEC_SERVER:=$CN_IPSEC_SERVER_DEFAULT}"
  : "${IPSEC_REMOTE_ID:=pointtoserver.com}"
  : "${DEFAULT_DNS_UPSTREAMS:=https://cloudflare-dns.com/dns-query tls://1.1.1.1 https://dns.google/dns-query tls://dns.google}"
  : "${DEFAULT_DNS_STRATEGY:=prefer_ipv6}"
  : "${DEFAULT_IPV6_MODE:=auto}"
  : "${AI_DNS_UPSTREAMS:=https://cloudflare-dns.com/dns-query tls://1.1.1.1 https://dns.google/dns-query tls://dns.google}"
  : "${CN_DNS_UPSTREAMS:=https://dns.alidns.com/dns-query tls://dns.alidns.com https://doh.pub/dns-query tls://dot.pub}"
  : "${SMARTDNS_DEFAULT_PORT:=6053}"
  : "${SMARTDNS_AI_PORT:=6054}"
  : "${SMARTDNS_CN_PORT:=6055}"
  : "${SMARTDNS_DEFAULT_PORT:=6053}"
  : "${SMARTDNS_AI_PORT:=6054}"
  : "${SMARTDNS_CN_PORT:=6055}"
  : "${AI_GEOSITE_SOURCES:=$AI_GEOSITE_SOURCES_DEFAULT}"
  : "${AI_SUPPORT_DOMAINS:=$AI_SUPPORT_DOMAINS_DEFAULT}"
  : "${AI_NFTSET_REFRESH_DOMAINS:=$AI_NFTSET_REFRESH_DOMAINS_DEFAULT}"
  : "${SING_GEOSITE_RULESET_BASE_URL:=$SING_GEOSITE_RULESET_BASE_URL_DEFAULT}"
  : "${CN_VIDEO_SOURCES:=$CN_VIDEO_SOURCES_DEFAULT}"
  : "${AI_SAMPLE_DOMAINS:=$AI_SAMPLE_DOMAINS_DEFAULT}"
  : "${CN_SAMPLE_DOMAINS:=$CN_SAMPLE_DOMAINS_DEFAULT}"
  : "${CN_NFTSET_REFRESH_DOMAINS:=$CN_NFTSET_REFRESH_DOMAINS_DEFAULT}"
  : "${CN_STATIC_A_OVERRIDES:=$CN_STATIC_A_OVERRIDES_DEFAULT}"
  : "${CN_OVERRIDE_PROBE_DOMAINS:=$CN_OVERRIDE_PROBE_DOMAINS_DEFAULT}"
  : "${CN_OVERRIDE_PROBE_RESOLVERS:=$CN_OVERRIDE_PROBE_RESOLVERS_DEFAULT}"
  migrate_ai_meta_sample_domains
  : "${DEPLOY_MODE:=vlan-gateway}"
  : "${LAN_IPV6_GATEWAY:=$(ipv6_gateway_from_prefix "${LAN_IPV6_PREFIX:-fd00:88::/64}")}"
  : "${SINGBOX_SOCKS_LISTEN:=0.0.0.0}"
  : "${SINGBOX_SOCKS_PORT:=1080}"
  : "${SINGBOX_HTTP_LISTEN:=0.0.0.0}"
  : "${SINGBOX_HTTP_PORT:=1081}"
  : "${XRAY_ENABLED:=1}"
  : "${XRAY_LISTEN_HOST:=127.0.0.1}"
  : "${XRAY_AI_SOCKS_PORT:=16054}"
  : "${XRAY_CN_SOCKS_PORT:=16055}"
  : "${AI_EGRESS_MODE:=ipsec}"
  : "${CN_EGRESS_MODE:=ipsec}"
  : "${AI_XRAY_URI:=}"
  : "${CN_XRAY_URI:=}"
  : "${AI_XRAY_OUTBOUND_JSON:=}"
  : "${CN_XRAY_OUTBOUND_JSON:=}"
  : "${APPLE_PRIVATE_RELAY_BLOCK:=1}"
  : "${SINGBOX_DNS_LISTEN:=127.0.0.1}"
  : "${SINGBOX_DNS_PORT:=1053}"
  : "${DNSCOMPLEX_WEB_LISTEN:=$(default_web_listen)}"
  : "${DNSCOMPLEX_WEB_PORT:=8088}"
  : "${DNSCOMPLEX_WEB_PASSWORD:=$(generate_web_password)}"
  : "${DNSCOMPLEX_METRICS_LISTEN:=0.0.0.0}"
  : "${DNSCOMPLEX_METRICS_PORT:=9108}"
  : "${DNSCOMPLEX_UPDATE_TIME:=04:20}"
  : "${DNSCOMPLEX_UPDATE_LAST_LOG:=/var/log/dnscomplex/update-latest.log}"
  : "${DNSCOMPLEX_UPDATE_CHANNEL:=stable}"
  : "${DNSCOMPLEX_PINNED_VERSION:=}"
  : "${GITHUB_RELEASE_POLICY:=latest}"
  : "${DNSCOMPLEX_NFTSET_REFRESH_INTERVAL:=5m}"
  : "${DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT:=2h}"
  : "${ADGUARD_DNS_CACHE_MODE:=off}"
  : "${HA_MODE:=single}"
  : "${HA_PRIMARY_IP:=${LINUX_LAN_IPV4:-}}"
  : "${HA_SECONDARY_IP:=}"
  : "${HA_HEALTH_URL:=/healthz}"
  : "${HA_FAILOVER_POLICY:=primary-secondary-routeros}"
  : "${PROMETHEUS_MODE:=exporter-only}"
  : "${IPSEC_TCP_MSS:=1200}"
  : "${DNSCOMPLEX_NONINTERACTIVE:=0}"

  case "$DEFAULT_DNS_STRATEGY" in
    prefer_ipv4|prefer_ipv6)
      ;;
    *)
      die "DEFAULT_DNS_STRATEGY must be prefer_ipv4 or prefer_ipv6"
      ;;
  esac
}

prompt_var() {
  local name=$1
  local prompt=$2
  local default=${3:-}
  local current=${!name:-}

  [[ -n "$current" ]] && return 0
  if [[ "$DNSCOMPLEX_NONINTERACTIVE" == "1" || "$ASSUME_YES" == "1" ]]; then
    [[ -n "$default" ]] || return 0
    printf -v "$name" '%s' "$default"
    export "${name?}"
    return 0
  fi

  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " current
    current=${current:-$default}
  else
    read -r -p "$prompt: " current
  fi
  printf -v "$name" '%s' "$current"
  export "${name?}"
}

collect_interactive_config() {
  prompt_var DEPLOY_MODE "Deployment mode (vlan-gateway/routeros-policy)" "vlan-gateway"
  prompt_var WAN_IFACE "Linux network interface"
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    prompt_var ROUTEROS_LAN_IPV4 "RouterOS LAN IPv4" "192.168.50.253"
    prompt_var LINUX_LAN_IPV4 "Linux VM static DHCP IPv4" "192.168.50.200"
    prompt_var LAN_CLIENT_IPV4_CIDR "LAN client IPv4 CIDR" "192.168.50.0/24"
  else
    prompt_var TRANSIT_VLAN_ID "RouterOS transit VLAN ID" "10"
    prompt_var LAN_VLAN_ID "LAN VLAN ID" "20"
    prompt_var ROUTEROS_TRANSIT_IPV4 "RouterOS transit IPv4"
    prompt_var LINUX_TRANSIT_IPV4 "Linux transit IPv4"
    prompt_var TRANSIT_IPV4_CIDR "Linux transit IPv4 CIDR"
    prompt_var ROUTEROS_TRANSIT_IPV6 "RouterOS transit IPv6"
    prompt_var LINUX_TRANSIT_IPV6 "Linux transit IPv6"
    prompt_var TRANSIT_IPV6_CIDR "Linux transit IPv6 CIDR"
    prompt_var LAN_IPV4_CIDR "LAN gateway IPv4 CIDR"
    prompt_var LAN_DHCP_START "LAN DHCP start IPv4"
    prompt_var LAN_DHCP_END "LAN DHCP end IPv4"
    prompt_var LAN_IPV6_PREFIX "LAN IPv6 prefix"
  fi
  prompt_var SINGBOX_SOCKS_LISTEN "SOCKS listen address" "0.0.0.0"
  prompt_var SINGBOX_SOCKS_PORT "SOCKS listen port" "1080"
  prompt_var DNSCOMPLEX_WEB_LISTEN "Management web listen address" "$(default_web_listen)"
  prompt_var DNSCOMPLEX_WEB_PORT "Management web listen port" "8088"
  prompt_var DNSCOMPLEX_WEB_PASSWORD "Management web password" "$DNSCOMPLEX_WEB_PASSWORD"
  prompt_var DNSCOMPLEX_UPDATE_TIME "Daily auto-update time (HH:MM)" "04:20"
  prompt_var AI_IPSEC_SERVER "AI IPsec server" "$AI_IPSEC_SERVER_DEFAULT"
  prompt_var CN_IPSEC_SERVER "CN IPsec server" "$CN_IPSEC_SERVER_DEFAULT"
  prompt_var AI_IPSEC_USERNAME "AI IPsec username"
  prompt_var AI_IPSEC_PASSWORD "AI IPsec password"
  prompt_var CN_IPSEC_USERNAME "CN IPsec username"
  prompt_var CN_IPSEC_PASSWORD "CN IPsec password"
}

require_var() {
  local name=$1
  [[ -n "${!name:-}" ]] || die "missing required variable: $name"
}

validate_config() {
  local required=(WAN_IFACE AI_IPSEC_SERVER CN_IPSEC_SERVER AI_IPSEC_USERNAME AI_IPSEC_PASSWORD CN_IPSEC_USERNAME CN_IPSEC_PASSWORD)
  case "$DEPLOY_MODE" in
    vlan-gateway)
      required+=(
        TRANSIT_VLAN_ID LAN_VLAN_ID
        ROUTEROS_TRANSIT_IPV4 LINUX_TRANSIT_IPV4 TRANSIT_IPV4_CIDR
        ROUTEROS_TRANSIT_IPV6 LINUX_TRANSIT_IPV6 TRANSIT_IPV6_CIDR
        LAN_IPV4_CIDR LAN_DHCP_START LAN_DHCP_END LAN_IPV6_PREFIX
      )
      ;;
    routeros-policy)
      required+=(ROUTEROS_LAN_IPV4 LINUX_LAN_IPV4 LAN_CLIENT_IPV4_CIDR)
      ;;
    *)
      die "DEPLOY_MODE must be vlan-gateway or routeros-policy"
      ;;
  esac
  local name
  for name in "${required[@]}"; do
    require_var "$name"
  done
  [[ "$SINGBOX_SOCKS_PORT" =~ ^[0-9]+$ ]] || die "SINGBOX_SOCKS_PORT must be numeric"
  [[ "$XRAY_AI_SOCKS_PORT" =~ ^[0-9]+$ ]] || die "XRAY_AI_SOCKS_PORT must be numeric"
  [[ "$XRAY_CN_SOCKS_PORT" =~ ^[0-9]+$ ]] || die "XRAY_CN_SOCKS_PORT must be numeric"
  [[ "$DNSCOMPLEX_WEB_PORT" =~ ^[0-9]+$ ]] || die "DNSCOMPLEX_WEB_PORT must be numeric"
  [[ "$DNSCOMPLEX_METRICS_PORT" =~ ^[0-9]+$ ]] || die "DNSCOMPLEX_METRICS_PORT must be numeric"
  [[ "$IPSEC_TCP_MSS" =~ ^[0-9]+$ ]] || die "IPSEC_TCP_MSS must be numeric"
  ((DNSCOMPLEX_WEB_PORT >= 1 && DNSCOMPLEX_WEB_PORT <= 65535)) || die "DNSCOMPLEX_WEB_PORT must be 1-65535"
  ((XRAY_AI_SOCKS_PORT >= 1 && XRAY_AI_SOCKS_PORT <= 65535)) || die "XRAY_AI_SOCKS_PORT must be 1-65535"
  ((XRAY_CN_SOCKS_PORT >= 1 && XRAY_CN_SOCKS_PORT <= 65535)) || die "XRAY_CN_SOCKS_PORT must be 1-65535"
  ((DNSCOMPLEX_METRICS_PORT >= 1 && DNSCOMPLEX_METRICS_PORT <= 65535)) || die "DNSCOMPLEX_METRICS_PORT must be 1-65535"
  ((IPSEC_TCP_MSS >= 536 && IPSEC_TCP_MSS <= 1460)) || die "IPSEC_TCP_MSS must be 536-1460"
  [[ "$DNSCOMPLEX_UPDATE_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "DNSCOMPLEX_UPDATE_TIME must be HH:MM"
  case "$DNSCOMPLEX_UPDATE_CHANNEL" in stable|beta|pinned) ;; *) die "DNSCOMPLEX_UPDATE_CHANNEL must be stable, beta, or pinned" ;; esac
  case "$GITHUB_RELEASE_POLICY" in latest|pinned) ;; *) die "GITHUB_RELEASE_POLICY must be latest or pinned" ;; esac
  if [[ "$DNSCOMPLEX_UPDATE_CHANNEL" == "pinned" || "$GITHUB_RELEASE_POLICY" == "pinned" ]]; then
    [[ -n "$DNSCOMPLEX_PINNED_VERSION" ]] || die "DNSCOMPLEX_PINNED_VERSION is required when update channel or GitHub policy is pinned"
  fi
  case "$ADGUARD_DNS_CACHE_MODE" in off|small|large) ;; *) die "ADGUARD_DNS_CACHE_MODE must be off, small, or large" ;; esac
  case "$HA_MODE" in single|primary|secondary) ;; *) die "HA_MODE must be single, primary, or secondary" ;; esac
  case "$PROMETHEUS_MODE" in exporter-only|local) ;; *) die "PROMETHEUS_MODE must be exporter-only or local" ;; esac
  case "$AI_EGRESS_MODE" in ipsec|xray) ;; *) die "AI_EGRESS_MODE must be ipsec or xray" ;; esac
  case "$CN_EGRESS_MODE" in ipsec|xray) ;; *) die "CN_EGRESS_MODE must be ipsec or xray" ;; esac
  case "$XRAY_ENABLED" in 0|1) ;; *) die "XRAY_ENABLED must be 0 or 1" ;; esac
}

require_debian13() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  [[ -r /etc/os-release ]] || die "/etc/os-release not found"
  # shellcheck source=/dev/null
  . /etc/os-release
  [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "13" ]] || die "this installer supports Debian 13 only; detected ${PRETTY_NAME:-unknown}"
}

require_root() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  [[ "$(id -u)" == "0" ]] || die "run as root"
}

target_path() {
  local path=$1
  [[ "$path" == /* ]] || die "target path must be absolute: $path"
  printf '%s%s' "$DNSCOMPLEX_ROOT" "$path"
}

write_file() {
  local path=$1
  local target
  target=$(target_path "$path")
  mkdir -p "$(dirname "$target")"
  cat >"$target"
}

append_file() {
  local path=$1
  local target
  target=$(target_path "$path")
  mkdir -p "$(dirname "$target")"
  cat >>"$target"
}

chmod_target() {
  local mode=$1
  local path=$2
  chmod "$mode" "$(target_path "$path")"
}

run_cmd() {
  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run: $*"
    return 0
  fi
  "$@"
}

cidr_addr() {
  printf '%s\n' "${1%%/*}"
}

default_web_listen() {
  if [[ "${DEPLOY_MODE:-}" == "routeros-policy" && -n "${LINUX_LAN_IPV4:-}" ]]; then
    printf '%s\n' "$LINUX_LAN_IPV4"
  elif [[ -n "${LAN_IPV4_CIDR:-}" ]]; then
    cidr_addr "$LAN_IPV4_CIDR"
  elif [[ -n "${LINUX_LAN_IPV4:-}" ]]; then
    printf '%s\n' "$LINUX_LAN_IPV4"
  else
    printf '127.0.0.1\n'
  fi
}

generate_web_password() {
  local generated
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    generated=$(tr -d '-' </proc/sys/kernel/random/uuid | cut -c1-20)
  else
    generated="dnscomplex-$(date +%s)"
  fi
  printf '%s\n' "$generated"
}

cidr_prefix() {
  printf '%s\n' "${1##*/}"
}

ipv6_gateway_from_prefix() {
  local prefix_addr=${1%%/*}
  case "$prefix_addr" in
    *::) printf '%s1\n' "$prefix_addr" ;;
    *:) printf '%s1\n' "$prefix_addr" ;;
    *) printf '%s\n' "$prefix_addr" ;;
  esac
}

ipv4_to_int() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  printf '%u\n' "$(((a << 24) + (b << 16) + (c << 8) + d))"
}

int_to_ipv4() {
  local n=$1
  printf '%u.%u.%u.%u\n' "$(((n >> 24) & 255))" "$(((n >> 16) & 255))" "$(((n >> 8) & 255))" "$((n & 255))"
}

ipv4_network() {
  local cidr=$1
  local ip prefix ip_int mask network
  ip=$(cidr_addr "$cidr")
  prefix=$(cidr_prefix "$cidr")
  ip_int=$(ipv4_to_int "$ip")
  if [[ "$prefix" == "0" ]]; then
    mask=0
  else
    mask=$(((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF))
  fi
  network=$((ip_int & mask))
  printf '%s/%s\n' "$(int_to_ipv4 "$network")" "$prefix"
}

linux_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    armv7l) printf 'armv7\n' ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

xray_asset_pattern() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'Xray-linux-64\\.zip$\n' ;;
    aarch64|arm64) printf 'Xray-linux-arm64-v8a\\.zip$\n' ;;
    armv7l) printf 'Xray-linux-arm32-v7a\\.zip$\n' ;;
    *) die "unsupported Xray architecture: $(uname -m)" ;;
  esac
}

github_latest_asset_url() {
  local repo=$1
  local pattern=$2
  local asset
  asset=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" |
    jq -r --arg pattern "$pattern" '.assets[].browser_download_url | select(test($pattern))' |
    head -n1)
  [[ -n "$asset" ]] || die "could not locate latest GitHub release asset for $repo matching $pattern"
  printf '%s\n' "$asset"
}

smartdns_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'x86_64\n' ;;
    aarch64|arm64) printf 'aarch64\n' ;;
    *) die "unsupported SmartDNS architecture: $(uname -m)" ;;
  esac
}

list_lines() {
  local item
  for item in "$@"; do
    printf '%s\n' "$item"
  done
}

split_words() {
  local text=$1
  local old_ifs=$IFS
  local item
  IFS=' '
  for item in $text; do
    [[ -n "$item" ]] && printf '%s\n' "$item"
  done
  IFS=$old_ifs
}

migrate_ai_meta_sample_domains() {
  local item changed=0 has_meta_ai=0
  local -a kept=()
  while IFS= read -r item; do
    [[ -n "$item" ]] || continue
    case "$item" in
      facebook.com|instagram.com|meta.com|threads.net|whatsapp.com)
        changed=1
        continue
        ;;
      meta.ai)
        has_meta_ai=1
        ;;
    esac
    kept+=("$item")
  done < <(split_words "${AI_SAMPLE_DOMAINS:-}")
  if [[ "$has_meta_ai" == "0" ]]; then
    kept+=("meta.ai")
    changed=1
  fi
  if [[ "$changed" == "1" ]]; then
    AI_SAMPLE_DOMAINS=$(printf '%s\n' "${kept[@]}" | awk '!seen[$0]++' | xargs)
  fi
}

smartdns_upstream_line() {
  local upstream=$1
  local group=$2
  case "$upstream" in
    h3://*)
      printf 'server-h3 %s -group %s\n' "$upstream" "$group"
      ;;
    https://*|http://*)
      printf 'server-https %s -group %s\n' "$upstream" "$group"
      ;;
    tls://*)
      printf 'server-tls %s -group %s\n' "$upstream" "$group"
      ;;
    quic://*|doq://*)
      printf 'server-quic %s -group %s\n' "$upstream" "$group"
      ;;
    tcp://*)
      printf 'server-tcp %s -group %s\n' "${upstream#tcp://}" "$group"
      ;;
    *)
      printf 'server %s -group %s\n' "$upstream" "$group"
      ;;
  esac
}

smartdns_static_address_line() {
  local override=$1
  local domain=${override%%=*}
  local address=${override#*=}
  [[ -n "$domain" && -n "$address" && "$domain" != "$address" ]] || return 0
  printf 'address /-.%s/%s\n' "$domain" "$address"
}

save_runtime_config() {
  write_file /etc/dnscomplex/config.env <<EOF
DNSCOMPLEX_VERSION='$DNSCOMPLEX_VERSION'
DEPLOY_MODE='$DEPLOY_MODE'
WAN_IFACE='$WAN_IFACE'
TRANSIT_VLAN_ID='${TRANSIT_VLAN_ID:-}'
LAN_VLAN_ID='${LAN_VLAN_ID:-}'
ROUTEROS_TRANSIT_IPV4='${ROUTEROS_TRANSIT_IPV4:-}'
LINUX_TRANSIT_IPV4='${LINUX_TRANSIT_IPV4:-}'
TRANSIT_IPV4_CIDR='${TRANSIT_IPV4_CIDR:-}'
ROUTEROS_TRANSIT_IPV6='${ROUTEROS_TRANSIT_IPV6:-}'
LINUX_TRANSIT_IPV6='${LINUX_TRANSIT_IPV6:-}'
TRANSIT_IPV6_CIDR='${TRANSIT_IPV6_CIDR:-}'
ROUTEROS_LAN_IPV4='${ROUTEROS_LAN_IPV4:-}'
LINUX_LAN_IPV4='${LINUX_LAN_IPV4:-}'
LAN_CLIENT_IPV4_CIDR='${LAN_CLIENT_IPV4_CIDR:-}'
LAN_IPV4_CIDR='${LAN_IPV4_CIDR:-}'
LAN_DHCP_START='${LAN_DHCP_START:-}'
LAN_DHCP_END='${LAN_DHCP_END:-}'
LAN_IPV6_PREFIX='${LAN_IPV6_PREFIX:-}'
LAN_IPV6_GATEWAY='${LAN_IPV6_GATEWAY:-}'
AI_IPSEC_SERVER='$AI_IPSEC_SERVER'
CN_IPSEC_SERVER='$CN_IPSEC_SERVER'
IPSEC_REMOTE_ID='$IPSEC_REMOTE_ID'
AI_IPSEC_USERNAME='$AI_IPSEC_USERNAME'
AI_IPSEC_PASSWORD='$AI_IPSEC_PASSWORD'
CN_IPSEC_USERNAME='$CN_IPSEC_USERNAME'
CN_IPSEC_PASSWORD='$CN_IPSEC_PASSWORD'
DEFAULT_DNS_UPSTREAMS='$DEFAULT_DNS_UPSTREAMS'
DEFAULT_DNS_STRATEGY='$DEFAULT_DNS_STRATEGY'
DEFAULT_IPV6_MODE='$DEFAULT_IPV6_MODE'
AI_DNS_UPSTREAMS='$AI_DNS_UPSTREAMS'
CN_DNS_UPSTREAMS='$CN_DNS_UPSTREAMS'
AI_GEOSITE_SOURCES='$AI_GEOSITE_SOURCES'
AI_SUPPORT_DOMAINS='$AI_SUPPORT_DOMAINS'
AI_NFTSET_REFRESH_DOMAINS='$AI_NFTSET_REFRESH_DOMAINS'
SING_GEOSITE_RULESET_BASE_URL='$SING_GEOSITE_RULESET_BASE_URL'
CN_VIDEO_SOURCES='$CN_VIDEO_SOURCES'
AI_SAMPLE_DOMAINS='$AI_SAMPLE_DOMAINS'
CN_SAMPLE_DOMAINS='$CN_SAMPLE_DOMAINS'
CN_NFTSET_REFRESH_DOMAINS='$CN_NFTSET_REFRESH_DOMAINS'
CN_STATIC_A_OVERRIDES='$CN_STATIC_A_OVERRIDES'
CN_OVERRIDE_PROBE_DOMAINS='$CN_OVERRIDE_PROBE_DOMAINS'
CN_OVERRIDE_PROBE_RESOLVERS='$CN_OVERRIDE_PROBE_RESOLVERS'
SMARTDNS_DEFAULT_PORT='$SMARTDNS_DEFAULT_PORT'
SMARTDNS_AI_PORT='$SMARTDNS_AI_PORT'
SMARTDNS_CN_PORT='$SMARTDNS_CN_PORT'
SINGBOX_DNS_PORT='$SINGBOX_DNS_PORT'
SINGBOX_DNS_LISTEN='$SINGBOX_DNS_LISTEN'
SINGBOX_SOCKS_PORT='$SINGBOX_SOCKS_PORT'
SINGBOX_SOCKS_LISTEN='$SINGBOX_SOCKS_LISTEN'
SINGBOX_HTTP_PORT='$SINGBOX_HTTP_PORT'
SINGBOX_HTTP_LISTEN='$SINGBOX_HTTP_LISTEN'
XRAY_ENABLED='$XRAY_ENABLED'
XRAY_LISTEN_HOST='$XRAY_LISTEN_HOST'
XRAY_AI_SOCKS_PORT='$XRAY_AI_SOCKS_PORT'
XRAY_CN_SOCKS_PORT='$XRAY_CN_SOCKS_PORT'
AI_EGRESS_MODE='$AI_EGRESS_MODE'
CN_EGRESS_MODE='$CN_EGRESS_MODE'
AI_XRAY_URI='$AI_XRAY_URI'
CN_XRAY_URI='$CN_XRAY_URI'
AI_XRAY_OUTBOUND_JSON='$AI_XRAY_OUTBOUND_JSON'
CN_XRAY_OUTBOUND_JSON='$CN_XRAY_OUTBOUND_JSON'
APPLE_PRIVATE_RELAY_BLOCK='$APPLE_PRIVATE_RELAY_BLOCK'
DNSCOMPLEX_WEB_LISTEN='$DNSCOMPLEX_WEB_LISTEN'
DNSCOMPLEX_WEB_PORT='$DNSCOMPLEX_WEB_PORT'
DNSCOMPLEX_WEB_PASSWORD='$DNSCOMPLEX_WEB_PASSWORD'
DNSCOMPLEX_METRICS_LISTEN='$DNSCOMPLEX_METRICS_LISTEN'
DNSCOMPLEX_METRICS_PORT='$DNSCOMPLEX_METRICS_PORT'
DNSCOMPLEX_UPDATE_TIME='$DNSCOMPLEX_UPDATE_TIME'
DNSCOMPLEX_UPDATE_LAST_LOG='$DNSCOMPLEX_UPDATE_LAST_LOG'
DNSCOMPLEX_UPDATE_CHANNEL='$DNSCOMPLEX_UPDATE_CHANNEL'
DNSCOMPLEX_PINNED_VERSION='$DNSCOMPLEX_PINNED_VERSION'
GITHUB_RELEASE_POLICY='$GITHUB_RELEASE_POLICY'
DNSCOMPLEX_NFTSET_REFRESH_INTERVAL='$DNSCOMPLEX_NFTSET_REFRESH_INTERVAL'
DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT='$DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT'
ADGUARD_DNS_CACHE_MODE='$ADGUARD_DNS_CACHE_MODE'
HA_MODE='$HA_MODE'
HA_PRIMARY_IP='$HA_PRIMARY_IP'
HA_SECONDARY_IP='$HA_SECONDARY_IP'
HA_HEALTH_URL='$HA_HEALTH_URL'
HA_FAILOVER_POLICY='$HA_FAILOVER_POLICY'
PROMETHEUS_MODE='$PROMETHEUS_MODE'
IPSEC_TCP_MSS='$IPSEC_TCP_MSS'
AI_MARK='$AI_MARK'
CN_MARK='$CN_MARK'
AI_MARK_DEC='$AI_MARK_DEC'
CN_MARK_DEC='$CN_MARK_DEC'
SINGBOX_AUTO_REDIRECT_INPUT_MARK='$SINGBOX_AUTO_REDIRECT_INPUT_MARK'
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK='$SINGBOX_AUTO_REDIRECT_OUTPUT_MARK'
SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC='$SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC'
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC='$SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC'
AI_TABLE='$AI_TABLE'
CN_TABLE='$CN_TABLE'
AI_XFRM_ID='$AI_XFRM_ID'
CN_XFRM_ID='$CN_XFRM_ID'
EOF
  chmod_target 0600 /etc/dnscomplex/config.env
}

install_packages() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    install -y \
    ca-certificates curl jq tar unzip iproute2 nftables conntrack dnsmasq radvd \
    strongswan-swanctl strongswan-charon libcharon-extra-plugins \
    cron dnsutils python3
  if [[ "$PROMETHEUS_MODE" == "local" ]]; then
    apt-get \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      install -y prometheus alertmanager
  fi
  mkdir -p /var/lib/smartdns
  disable_conflicting_lan_services
  install_smartdns_release
  install_singbox_release
  install_adguardhome_release
  install_xray_release
}

disable_conflicting_lan_services() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    systemctl disable --now dnsmasq radvd systemd-resolved 2>/dev/null || true
    systemctl reset-failed dnsmasq radvd systemd-resolved 2>/dev/null || true
    if [[ -L /etc/resolv.conf ]] && readlink /etc/resolv.conf | grep -q 'systemd/resolve'; then
      rm -f /etc/resolv.conf
      printf 'nameserver %s\n' "${ROUTEROS_LAN_IPV4:-1.1.1.1}" >/etc/resolv.conf
    fi
  fi
}

install_smartdns_release() {
  local arch asset tmp
  arch=$(smartdns_arch)
  tmp=$(mktemp -d)
  asset=$(github_latest_asset_url "pymumu/smartdns" "${arch}-debian-all\\.deb$")
  curl -fsSL -o "$tmp/smartdns.deb" "$asset"
  DEBIAN_FRONTEND=noninteractive dpkg --force-confdef --force-confold -i "$tmp/smartdns.deb" || \
    DEBIAN_FRONTEND=noninteractive apt-get \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      -f install -y
  fix_smartdns_wrapper
  ensure_smartdns_enabled
  command -v smartdns >/dev/null || die "SmartDNS install did not provide smartdns binary"
  rm -rf "$tmp"
}

fix_smartdns_wrapper() {
  [[ -x /usr/local/lib/smartdns/run-smartdns ]] || die "SmartDNS wrapper missing: /usr/local/lib/smartdns/run-smartdns"
  ln -sfn /usr/local/lib/smartdns/run-smartdns /usr/sbin/smartdns
}

ensure_smartdns_enabled() {
  systemctl enable smartdns >/dev/null 2>&1 || true
}

install_singbox_release() {
  local arch asset tmp
  arch=$(linux_arch)
  tmp=$(mktemp -d)
  asset=$(github_latest_asset_url "SagerNet/sing-box" "sing-box_.*_linux_${arch}\\.deb$")
  curl -fsSL -o "$tmp/sing-box.deb" "$asset"
  DEBIAN_FRONTEND=noninteractive dpkg --force-confdef --force-confold -i "$tmp/sing-box.deb" || \
    DEBIAN_FRONTEND=noninteractive apt-get \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      -f install -y
  command -v sing-box >/dev/null || die "sing-box install did not provide sing-box binary"
  rm -rf "$tmp"
}

install_adguardhome_release() {
  local arch asset tmp
  arch=$(linux_arch)
  tmp=$(mktemp -d)
  asset=$(github_latest_asset_url "AdguardTeam/AdGuardHome" "AdGuardHome_linux_${arch}\\.tar\\.gz$")
  curl -fsSL -o "$tmp/AdGuardHome.tar.gz" "$asset"
  tar -xzf "$tmp/AdGuardHome.tar.gz" -C "$tmp"
  systemctl stop AdGuardHome 2>/dev/null || true
  install -d -m 0755 /opt/AdGuardHome
  install -m 0755 "$tmp/AdGuardHome/AdGuardHome" /opt/AdGuardHome/AdGuardHome
  /opt/AdGuardHome/AdGuardHome --version >/dev/null || die "AdGuard Home install did not provide a working executable"
  rm -rf "$tmp"
}

install_xray_release() {
  local asset tmp pattern
  tmp=$(mktemp -d)
  pattern=$(xray_asset_pattern)
  asset=$(github_latest_asset_url "XTLS/Xray-core" "$pattern")
  curl -fsSL -o "$tmp/xray.zip" "$asset"
  unzip -q "$tmp/xray.zip" -d "$tmp/xray"
  install -m 0755 "$tmp/xray/xray" /usr/local/bin/xray
  install -d -m 0755 /usr/local/share/xray
  [[ -f "$tmp/xray/geoip.dat" ]] && install -m 0644 "$tmp/xray/geoip.dat" /usr/local/share/xray/geoip.dat
  [[ -f "$tmp/xray/geosite.dat" ]] && install -m 0644 "$tmp/xray/geosite.dat" /usr/local/share/xray/geosite.dat
  command -v xray >/dev/null || die "Xray install did not provide xray binary"
  rm -rf "$tmp"
}

render_xray_support() {
  write_file /usr/local/lib/dnscomplex-xray/render.py <<'PY'
#!/usr/bin/env python3
import argparse
import base64
import json
import os
import shlex
import sys
import urllib.parse


def parse_env(path):
    data = {}
    if not os.path.exists(path):
        return data
    with open(path, "r", encoding="utf-8") as fh:
        pending_key = None
        pending_value = []
        for raw in fh:
            line = raw.rstrip("\n")
            if pending_key:
                pending_value.append(line)
                if line.endswith("'") and not line.endswith("\\'"):
                    data[pending_key] = "\n".join(pending_value)[:-1]
                    pending_key = None
                    pending_value = []
                continue
            if not line or line.lstrip().startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if value.startswith("'") and not value.endswith("'"):
                pending_key = key
                pending_value = [value[1:]]
                continue
            try:
                parts = shlex.split(value, posix=True)
                data[key] = parts[0] if parts else ""
            except ValueError:
                data[key] = value.strip("'\"")
    return data


def b64decode_text(value):
    value = value.strip()
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode()).decode("utf-8")


def first(qs, key, default=""):
    values = qs.get(key, [])
    return values[0] if values else default


def stream_settings(qs, host):
    network = first(qs, "type", first(qs, "net", "tcp")) or "tcp"
    security = first(qs, "security", first(qs, "tls", ""))
    sni = first(qs, "sni", first(qs, "peer", host))
    settings = {"network": network}
    if security and security not in {"none", "false"}:
        settings["security"] = security
        tls_key = "realitySettings" if security == "reality" else "tlsSettings"
        tls_settings = {}
        if sni:
            tls_settings["serverName"] = sni
        fp = first(qs, "fp", first(qs, "fingerprint", ""))
        if fp:
            tls_settings["fingerprint"] = fp
        alpn = first(qs, "alpn", "")
        if alpn:
            tls_settings["alpn"] = [item for item in alpn.split(",") if item]
        pbk = first(qs, "pbk", first(qs, "publicKey", ""))
        if pbk:
            tls_settings["publicKey"] = pbk
        sid = first(qs, "sid", first(qs, "shortId", ""))
        if sid:
            tls_settings["shortId"] = sid
        spider = first(qs, "spx", first(qs, "spiderX", ""))
        if spider:
            tls_settings["spiderX"] = spider
        settings[tls_key] = tls_settings
    if network == "ws":
        ws = {"path": first(qs, "path", "/")}
        ws_host = first(qs, "host", "")
        if ws_host:
            ws["headers"] = {"Host": ws_host}
        settings["wsSettings"] = ws
    elif network == "grpc":
        service = first(qs, "serviceName", first(qs, "service", ""))
        if service:
            settings["grpcSettings"] = {"serviceName": service}
    elif network == "xhttp":
        path = first(qs, "path", "")
        xhttp = {}
        if path:
            xhttp["path"] = path
        host_header = first(qs, "host", "")
        if host_header:
            xhttp["host"] = host_header
        if xhttp:
            settings["xhttpSettings"] = xhttp
    return settings


def parse_vless(uri, tag):
    parsed = urllib.parse.urlparse(uri)
    qs = urllib.parse.parse_qs(parsed.query)
    if not parsed.username or not parsed.hostname or not parsed.port:
        raise ValueError("vless URI must include uuid@host:port")
    user = {"id": urllib.parse.unquote(parsed.username), "encryption": first(qs, "encryption", "none")}
    flow = first(qs, "flow", "")
    if flow:
        user["flow"] = flow
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {"vnext": [{"address": parsed.hostname, "port": parsed.port, "users": [user]}]},
        "streamSettings": stream_settings(qs, parsed.hostname),
    }


def parse_trojan(uri, tag):
    parsed = urllib.parse.urlparse(uri)
    qs = urllib.parse.parse_qs(parsed.query)
    if not parsed.username or not parsed.hostname or not parsed.port:
        raise ValueError("trojan URI must include password@host:port")
    return {
        "tag": tag,
        "protocol": "trojan",
        "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port, "password": urllib.parse.unquote(parsed.username)}]},
        "streamSettings": stream_settings(qs, parsed.hostname),
    }


def parse_vmess(uri, tag):
    raw = uri[len("vmess://"):]
    payload = json.loads(b64decode_text(raw))
    host = payload.get("add") or payload.get("address")
    port = int(payload.get("port") or 443)
    user_id = payload.get("id")
    if not host or not user_id:
        raise ValueError("vmess URI must include add/id")
    qs = {
        "type": [payload.get("net", "tcp")],
        "security": [payload.get("tls", "")],
        "sni": [payload.get("sni") or payload.get("host") or host],
        "path": [payload.get("path", "")],
        "host": [payload.get("host", "")],
    }
    user = {"id": user_id, "alterId": int(payload.get("aid") or 0), "security": payload.get("scy") or "auto"}
    return {
        "tag": tag,
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": stream_settings(qs, host),
    }


def parse_ss(uri, tag):
    raw = uri[len("ss://"):]
    if "@" not in raw:
        decoded = b64decode_text(raw.split("#", 1)[0])
        raw = decoded
    parsed = urllib.parse.urlparse("ss://" + raw)
    if not parsed.hostname or not parsed.port:
        raise ValueError("ss URI must include method:password@host:port")
    userinfo = urllib.parse.unquote(parsed.netloc.rsplit("@", 1)[0])
    if ":" not in userinfo:
        userinfo = b64decode_text(userinfo)
    method, password = userinfo.split(":", 1)
    return {
        "tag": tag,
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port, "method": method, "password": password}]},
    }


def parse_uri(uri, tag):
    if uri.startswith("vless://"):
        return parse_vless(uri, tag)
    if uri.startswith("vmess://"):
        return parse_vmess(uri, tag)
    if uri.startswith("trojan://"):
        return parse_trojan(uri, tag)
    if uri.startswith("ss://"):
        return parse_ss(uri, tag)
    raise ValueError("supported URI schemes: vless, vmess, trojan, ss")


def outbound_for(cfg, profile):
    upper = profile.upper()
    tag = f"xray-{profile}-out"
    raw_json = cfg.get(f"{upper}_XRAY_OUTBOUND_JSON", "").strip()
    uri = cfg.get(f"{upper}_XRAY_URI", "").strip()
    if raw_json:
        outbound = json.loads(raw_json)
        if not isinstance(outbound, dict):
            raise ValueError(f"{upper}_XRAY_OUTBOUND_JSON must be a JSON object")
        outbound["tag"] = tag
        return outbound
    if uri:
        return parse_uri(uri, tag)
    return {"tag": tag, "protocol": "freedom", "settings": {}}


def render(cfg):
    listen = cfg.get("XRAY_LISTEN_HOST", "127.0.0.1")
    ai_port = int(cfg.get("XRAY_AI_SOCKS_PORT", "16054"))
    cn_port = int(cfg.get("XRAY_CN_SOCKS_PORT", "16055"))
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "xray-ai-in",
                "listen": listen,
                "port": ai_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            },
            {
                "tag": "xray-cn-in",
                "listen": listen,
                "port": cn_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            },
        ],
        "outbounds": [outbound_for(cfg, "ai"), outbound_for(cfg, "cn")],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["xray-ai-in"], "outboundTag": "xray-ai-out"},
                {"type": "field", "inboundTag": ["xray-cn-in"], "outboundTag": "xray-cn-out"},
            ],
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/dnscomplex/config.env")
    parser.add_argument("--output", default="-")
    parser.add_argument("--profile", choices=["ai", "cn"])
    parser.add_argument("--uri")
    parser.add_argument("--json")
    args = parser.parse_args()
    cfg = parse_env(args.config)
    if args.profile and args.uri is not None:
        cfg[f"{args.profile.upper()}_XRAY_URI"] = args.uri
        cfg[f"{args.profile.upper()}_XRAY_OUTBOUND_JSON"] = ""
    if args.profile and args.json is not None:
        cfg[f"{args.profile.upper()}_XRAY_OUTBOUND_JSON"] = args.json
        cfg[f"{args.profile.upper()}_XRAY_URI"] = ""
    data = render(cfg)
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        tmp = args.output + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, args.output)


if __name__ == "__main__":
    main()
PY
  chmod_target 0755 /usr/local/lib/dnscomplex-xray/render.py
  python3 "$(target_path /usr/local/lib/dnscomplex-xray/render.py)" \
    --config "$(target_path /etc/dnscomplex/config.env)" \
    --output "$(target_path /usr/local/etc/xray/config.json)"
  chmod_target 0600 /usr/local/etc/xray/config.json

  write_file /etc/systemd/system/xray-dnscomplex.service <<'EOF'
[Unit]
Description=dnscomplex Xray sidecar
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

render_network() {
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    write_file /etc/sysctl.d/90-dnscomplex.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.default.accept_ra = 2
net.ipv6.conf.default.autoconf = 1
net.ipv6.conf.$WAN_IFACE.accept_ra = 2
net.ipv6.conf.$WAN_IFACE.autoconf = 1
net.ipv6.conf.$WAN_IFACE.addr_gen_mode = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.$WAN_IFACE.rp_filter = 0
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180
net.ipv4.ip_local_port_range = 1024 65535
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 250000
EOF
    write_file /etc/dnscomplex/network-mode.txt <<EOF
routeros-policy mode keeps $WAN_IFACE under the existing RouterOS DHCP/static lease.
Do not enable Linux DHCP/RA in this mode.
EOF
    return 0
  fi

  local lan_if="${WAN_IFACE}.${LAN_VLAN_ID}"
  local transit_if="${WAN_IFACE}.${TRANSIT_VLAN_ID}"
  local lan_ipv4_addr
  local lan_ipv6_prefix_len
  lan_ipv4_addr=$(cidr_addr "$LAN_IPV4_CIDR")
  lan_ipv6_prefix_len=$(cidr_prefix "$LAN_IPV6_PREFIX")

  write_file /etc/systemd/network/10-dnscomplex-vlans.netdev <<EOF
[NetDev]
Name=$transit_if
Kind=vlan

[VLAN]
Id=$TRANSIT_VLAN_ID

[NetDev]
Name=$lan_if
Kind=vlan

[VLAN]
Id=$LAN_VLAN_ID
EOF

  write_file /etc/systemd/network/10-dnscomplex-trunk.network <<EOF
[Match]
Name=$WAN_IFACE

[Network]
VLAN=$transit_if
VLAN=$lan_if
EOF

  write_file /etc/systemd/network/20-dnscomplex-transit.network <<EOF
[Match]
Name=$transit_if

[Network]
Address=$TRANSIT_IPV4_CIDR
Address=$TRANSIT_IPV6_CIDR
Gateway=$ROUTEROS_TRANSIT_IPV4
Gateway=$ROUTEROS_TRANSIT_IPV6
IPv6AcceptRA=no
IPForward=yes
EOF

  write_file /etc/systemd/network/30-dnscomplex-lan.network <<EOF
[Match]
Name=$lan_if

[Network]
Address=$LAN_IPV4_CIDR
Address=$LAN_IPV6_GATEWAY/$lan_ipv6_prefix_len
IPForward=yes
IPv6SendRA=yes
DHCPServer=no

[IPv6SendRA]
Managed=false
OtherInformation=true
RouterLifetimeSec=1800

[IPv6Prefix]
Prefix=$LAN_IPV6_PREFIX
EOF

  write_file /etc/sysctl.d/90-dnscomplex.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180
net.ipv4.ip_local_port_range = 1024 65535
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 250000
EOF

  write_file /etc/dnsmasq.d/dnscomplex.conf <<EOF
interface=$lan_if
bind-interfaces
dhcp-authoritative
dhcp-range=$LAN_DHCP_START,$LAN_DHCP_END,12h
dhcp-option=option:router,$lan_ipv4_addr
dhcp-option=option:dns-server,$lan_ipv4_addr
dhcp-option=option:domain-search,lan
dhcp-option=option6:dns-server,[$LAN_IPV6_GATEWAY]
enable-ra
dhcp-range=::100,::ffff,constructor:$lan_if,ra-stateless,ra-names,12h
EOF

  write_file /etc/radvd.conf <<EOF
interface $lan_if
{
  AdvSendAdvert on;
  MaxRtrAdvInterval 60;
  AdvOtherConfigFlag on;
  prefix $LAN_IPV6_PREFIX
  {
    AdvOnLink on;
    AdvAutonomous on;
  };
  RDNSS $LAN_IPV6_GATEWAY {};
};
EOF
}

apply_runtime_network_settings() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
  sysctl -w net.ipv6.conf.default.forwarding=1 >/dev/null
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
  sysctl -w net.netfilter.nf_conntrack_max=1048576 >/dev/null || true
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=86400 >/dev/null || true
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close_wait=60 >/dev/null || true
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_fin_wait=30 >/dev/null || true
  sysctl -w net.netfilter.nf_conntrack_udp_timeout=60 >/dev/null || true
  sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=180 >/dev/null || true
  sysctl -w "net.ipv4.ip_local_port_range=1024 65535" >/dev/null || true
  sysctl -w net.core.somaxconn=65535 >/dev/null || true
  sysctl -w net.ipv4.tcp_max_syn_backlog=65535 >/dev/null || true
  sysctl -w net.core.netdev_max_backlog=250000 >/dev/null || true
  if [[ -n "${WAN_IFACE:-}" && -d "/proc/sys/net/ipv4/conf/$WAN_IFACE" ]]; then
    sysctl -w "net.ipv4.conf.$WAN_IFACE.rp_filter=0" >/dev/null
  fi
  if [[ "$DEPLOY_MODE" == "routeros-policy" && -n "${WAN_IFACE:-}" && -d "/proc/sys/net/ipv6/conf/$WAN_IFACE" ]]; then
    sysctl -w net.ipv6.conf.default.accept_ra=2 >/dev/null || true
    sysctl -w net.ipv6.conf.default.autoconf=1 >/dev/null || true
    sysctl -w "net.ipv6.conf.$WAN_IFACE.accept_ra=2" >/dev/null || true
    sysctl -w "net.ipv6.conf.$WAN_IFACE.autoconf=1" >/dev/null || true
    sysctl -w "net.ipv6.conf.$WAN_IFACE.addr_gen_mode=0" >/dev/null || true
  fi
}

ipv6_tcp_available() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  local host
  for host in 2606:4700:10::6814:179a 2001:4860:4860::8888 2404:6800:4005:81a::200e; do
    timeout 4 bash -c "</dev/tcp/$host/443" >/dev/null 2>&1 && return 0
  done
  return 1
}

resolve_default_ipv6_mode() {
  case "$DEFAULT_IPV6_MODE" in
    on)
      DEFAULT_IPV6_ACTIVE=1
      ;;
    off)
      DEFAULT_IPV6_ACTIVE=0
      ;;
    auto)
      if [[ "$DRY_RUN" == "1" ]]; then
        DEFAULT_IPV6_ACTIVE=1
      elif ipv6_tcp_available; then
        DEFAULT_IPV6_ACTIVE=1
      else
        DEFAULT_IPV6_ACTIVE=0
        warn "default IPv6 TCP is not reachable; default DNS will suppress AAAA until DEFAULT_IPV6_MODE=on or IPv6 routing is fixed"
      fi
      ;;
    *)
      die "DEFAULT_IPV6_MODE must be auto, on, or off"
      ;;
  esac
  export DEFAULT_IPV6_ACTIVE
}

render_geosite_seeds() {
  local item
  write_file /var/lib/dnscomplex/geosite/ai.sources <<EOF
$(split_words "$AI_GEOSITE_SOURCES")
EOF
  write_file /var/lib/dnscomplex/geosite/ai-support.sources <<EOF
$(split_words "$AI_SUPPORT_DOMAINS")
EOF
  write_file /var/lib/dnscomplex/geosite/cn-video.sources <<EOF
$(split_words "$CN_VIDEO_SOURCES")
EOF
  write_file /var/lib/dnscomplex/geosite/ai.custom <<'EOF'
# One geosite source name or raw domain per line.
EOF
  write_file /var/lib/dnscomplex/geosite/cn-video.custom <<'EOF'
# One geosite source name or raw domain per line.
EOF
  write_file /etc/dnscomplex/ai.seed-domains <<EOF
$(split_words "$AI_SAMPLE_DOMAINS")
EOF
  write_file /etc/dnscomplex/cn-video.seed-domains <<EOF
$(split_words "$CN_SAMPLE_DOMAINS")
EOF
  write_file /etc/dnscomplex/ai.domains <<EOF
$(split_words "$AI_SAMPLE_DOMAINS")
$(split_words "$AI_SUPPORT_DOMAINS")
$(split_words "$AI_NFTSET_REFRESH_DOMAINS")
EOF
  write_file /etc/dnscomplex/cn-video.domains <<EOF
$(split_words "$CN_SAMPLE_DOMAINS")
EOF
}

render_smartdns() {
  local upstream
  local default_bind="bind 127.0.0.1:$SMARTDNS_DEFAULT_PORT -group default"
  if [[ "${DEFAULT_IPV6_ACTIVE:-1}" == "0" ]]; then
    default_bind+=" -force-aaaa-soa"
  fi
  {
    cat <<EOF
server-name default
$default_bind
bind 127.0.0.1:$SMARTDNS_AI_PORT -group ai -force-aaaa-soa -nftset #4:inet#dnscomplex#ai4,#6:-
bind 127.0.0.1:$SMARTDNS_CN_PORT -group cn -force-aaaa-soa -nftset #4:inet#dnscomplex#cn4,#6:-
cache-size 65536
cache-persist yes
cache-file /var/lib/smartdns/dnscomplex.cache
cache-checkpoint-time 86400
prefetch-domain yes
serve-expired yes
serve-expired-ttl 259200
serve-expired-reply-ttl 3
serve-expired-prefetch-time 21600
mdns-lookup yes
hosts-file /etc/dnscomplex/local-hosts
dualstack-ip-selection yes
nftset-timeout yes
force-qtype-SOA 65
EOF
    while IFS= read -r upstream; do
      smartdns_static_address_line "$upstream"
    done < <(split_words "$CN_STATIC_A_OVERRIDES")
    while IFS= read -r upstream; do
      smartdns_upstream_line "$upstream" default
    done < <(split_words "$DEFAULT_DNS_UPSTREAMS")
    while IFS= read -r upstream; do
      smartdns_upstream_line "$upstream" ai
    done < <(split_words "$AI_DNS_UPSTREAMS")
    while IFS= read -r upstream; do
      smartdns_upstream_line "$upstream" cn
    done < <(split_words "$CN_DNS_UPSTREAMS")
  } | write_file /etc/smartdns/smartdns.conf
}

render_local_hosts() {
  local target
  target=$(target_path /etc/dnscomplex/local-hosts)
  if [[ ! -e "$target" ]]; then
    write_file /etc/dnscomplex/local-hosts <<'EOF'
# Optional local DNS overrides for .local/Codex callbacks.
# Example:
# 192.0.2.10 example-host.local
EOF
  fi
}

write_adguard_allow_rules() {
  local domain
  {
    split_words "${AI_SAMPLE_DOMAINS:-}"
    split_words "${AI_SUPPORT_DOMAINS:-}"
  } | while IFS= read -r domain; do
    [[ -n "$domain" && "$domain" != \#* ]] || continue
    [[ "$domain" == *.* ]] || continue
    printf "  - '@@||%s^'\n" "$domain"
  done | sort -u
}

adguard_cache_yaml() {
  case "$ADGUARD_DNS_CACHE_MODE" in
    off)
      cat <<'EOF'
  cache_enabled: false
  cache_size: 0
  cache_optimistic: false
  cache_ttl_min: 0
  cache_ttl_max: 0
EOF
      ;;
    small)
      cat <<'EOF'
  cache_enabled: true
  cache_size: 4194304
  cache_optimistic: false
  cache_ttl_min: 0
  cache_ttl_max: 0
EOF
      ;;
    large)
      cat <<'EOF'
  cache_enabled: true
  cache_size: 67108864
  cache_optimistic: false
  cache_ttl_min: 0
  cache_ttl_max: 0
EOF
      ;;
  esac
}

render_adguard() {
  local allow_rules
  allow_rules=$(mktemp)
  write_adguard_allow_rules >"$allow_rules"
  {
    cat <<EOF
bind_host: 0.0.0.0
bind_port: 3000
users: []
auth_attempts: 5
block_auth_min: 15
http_proxy: ""
language: en
theme: auto
dns:
  bind_hosts:
    - 0.0.0.0
    - "::"
  port: 53
  anonymize_client_ip: false
  ratelimit: 0
  protection_enabled: true
  filtering_enabled: true
  parental_enabled: false
  safe_search:
    enabled: false
  upstream_dns:
    - '$SINGBOX_DNS_LISTEN:$SINGBOX_DNS_PORT'
EOF
    cat <<'EOF'
  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
  fallback_dns: []
  blocking_mode: default
  blocked_response_ttl: 10
EOF
    adguard_cache_yaml
    cat <<'EOF'
  bogus_nxdomain: []
  aaaa_disabled: false
  enable_dnssec: true
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
whitelist_filters: []
user_rules:
EOF
    cat "$allow_rules"
    cat <<'EOF'
dhcp:
  enabled: false
clients:
  runtime_sources:
    whois: true
    arp: true
    rdns: true
    dhcp: false
log:
  enabled: true
  file: ""
  max_backups: 0
  max_size: 100
  max_age: 3
  compress: false
schema_version: 29
EOF
  } | write_file /etc/AdGuardHome/AdGuardHome.yaml
  rm -f "$allow_rules"
}

render_adguard_service() {
  write_file /etc/systemd/system/AdGuardHome.service <<'EOF'
[Unit]
Description=AdGuard Home DNS filtering server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=false
ExecStart=/opt/AdGuardHome/AdGuardHome -c /etc/AdGuardHome/AdGuardHome.yaml -w /opt/AdGuardHome
Restart=on-failure
RestartSec=5s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

render_swanctl() {
  local local_ip="${LINUX_TRANSIT_IPV4:-}"
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    local_ip="$LINUX_LAN_IPV4"
  fi
  write_file /etc/swanctl/swanctl.conf <<EOF
connections {
  ai {
    version = 2
    local_addrs = $local_ip
    remote_addrs = $AI_IPSEC_SERVER
    vips = 0.0.0.0
    proposals = aes256-sha256-modp2048,aes128-sha256-modp2048
    dpd_delay = 20s
    dpd_timeout = 90s
    rekey_time = 0s
    local {
      auth = eap-mschapv2
      eap_id = $AI_IPSEC_USERNAME
    }
    remote {
      auth = pubkey
      id = $IPSEC_REMOTE_ID
    }
    children {
      ai {
        local_ts = 0.0.0.0/0
        remote_ts = 0.0.0.0/0
        if_id_in = $AI_XFRM_ID
        if_id_out = $AI_XFRM_ID
        esp_proposals = aes256-sha256,aes128-sha256
        dpd_action = restart
        start_action = start
        close_action = restart
      }
    }
  }
  cn {
    version = 2
    local_addrs = $local_ip
    remote_addrs = $CN_IPSEC_SERVER
    vips = 0.0.0.0
    proposals = aes256-sha256-modp2048,aes128-sha256-modp2048
    dpd_delay = 20s
    dpd_timeout = 90s
    rekey_time = 0s
    local {
      auth = eap-mschapv2
      eap_id = $CN_IPSEC_USERNAME
    }
    remote {
      auth = pubkey
      id = $IPSEC_REMOTE_ID
    }
    children {
      cn {
        local_ts = 0.0.0.0/0
        remote_ts = 0.0.0.0/0
        if_id_in = $CN_XFRM_ID
        if_id_out = $CN_XFRM_ID
        esp_proposals = aes256-sha256,aes128-sha256
        dpd_action = restart
        start_action = start
        close_action = restart
      }
    }
  }
}

secrets {
  eap-ai {
    id = $AI_IPSEC_USERNAME
    secret = "$AI_IPSEC_PASSWORD"
  }
  eap-cn {
    id = $CN_IPSEC_USERNAME
    secret = "$CN_IPSEC_PASSWORD"
  }
}
EOF
  chmod_target 0600 /etc/swanctl/swanctl.conf
}

render_strongswan_resolve_plugin() {
  write_file /etc/strongswan.d/charon/resolve.conf <<'EOF'
resolve {
    # dnscomplex keeps DNS policy in AdGuard Home, sing-box, and SmartDNS.
    # Disable strongSwan's resolve plugin so peer-pushed DNS servers do not
    # touch system DNS or generate resolvconf/systemd-resolved errors.
    load = no
}
EOF
}

render_ipsec_ca_store() {
  local target_dir ca copied=0
  target_dir=$(target_path /etc/swanctl/x509ca)
  mkdir -p "$target_dir"
  if [[ "$DRY_RUN" == "1" ]]; then
    write_file /etc/swanctl/x509ca/README.dnscomplex <<'EOF'
dnscomplex copies the Debian system CA store here during real installation so swanctl can validate public IPsec server certificates.
EOF
    return 0
  fi
  for ca in /etc/ssl/certs/*.pem; do
    [[ -f "$ca" ]] || continue
    install -m 0644 "$ca" "$target_dir/$(basename "$ca")"
    copied=$((copied + 1))
  done
  [[ "$copied" -gt 0 ]] || warn "no system CA certificates copied into /etc/swanctl/x509ca"
}

singbox_private_relay_dns_rule() {
  [[ "${APPLE_PRIVATE_RELAY_BLOCK:-1}" == "1" ]] || return 0
  cat <<'EOF'
      {
        "domain": [
          "mask.icloud.com",
          "mask-h2.icloud.com",
          "mask-api.icloud.com",
          "mask-t.apple-dns.net",
          "mask.apple-dns.net",
          "gateway.icloud.com"
        ],
        "action": "reject"
      },
EOF
}

rule_set_safe_name() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9_-' '-'
}

render_singbox_rule_set_entries() {
  local first=1 source safe
  emit_comma() {
    if [[ "$first" == "1" ]]; then
      first=0
    else
      printf ',\n'
    fi
  }

  while IFS= read -r source; do
    [[ -n "$source" ]] || continue
    safe=$(rule_set_safe_name "$source")
    emit_comma
    cat <<EOF
      {
        "type": "local",
        "tag": "geosite-ai-$safe",
        "format": "binary",
        "path": "/var/lib/dnscomplex/geosite/geosite-ai-$safe.srs"
      }
EOF
  done < <(split_words "$AI_GEOSITE_SOURCES")

  emit_comma
  cat <<'EOF'
      {
        "type": "local",
        "tag": "geosite-ai-support",
        "format": "binary",
        "path": "/var/lib/dnscomplex/geosite/geosite-ai-support.srs"
      }
EOF
  emit_comma
  cat <<'EOF'
      {
        "type": "local",
        "tag": "geosite-cn-video",
        "format": "binary",
        "path": "/var/lib/dnscomplex/geosite/geosite-cn-video.srs"
      }
EOF
}

render_singbox_ai_route_rules() {
  local source safe outbound
  outbound=$(profile_outbound_tag ai)
  while IFS= read -r source; do
    [[ -n "$source" ]] || continue
    safe=$(rule_set_safe_name "$source")
    cat <<EOF
      {
        "rule_set": "geosite-ai-$safe",
        "action": "route",
        "outbound": "$outbound"
      },
EOF
  done < <(split_words "$AI_GEOSITE_SOURCES")
  cat <<EOF
      {
        "rule_set": "geosite-ai-support",
        "action": "route",
        "outbound": "$outbound"
      },
EOF
}

render_singbox_ai_dns_rules() {
  local source safe
  while IFS= read -r source; do
    [[ -n "$source" ]] || continue
    safe=$(rule_set_safe_name "$source")
    cat <<EOF
      {
        "rule_set": "geosite-ai-$safe",
        "query_type": [
          "HTTPS",
          "SVCB"
        ],
        "action": "reject"
      },
EOF
  done < <(split_words "$AI_GEOSITE_SOURCES")
  cat <<'EOF'
      {
        "rule_set": "geosite-ai-support",
        "query_type": [
          "HTTPS",
          "SVCB"
        ],
        "action": "reject"
      },
EOF

  while IFS= read -r source; do
    [[ -n "$source" ]] || continue
    safe=$(rule_set_safe_name "$source")
    cat <<EOF
      {
        "rule_set": "geosite-ai-$safe",
        "action": "route",
        "server": "smartdns-ai",
        "strategy": "ipv4_only"
      },
EOF
  done < <(split_words "$AI_GEOSITE_SOURCES")
  cat <<'EOF'
      {
        "rule_set": "geosite-ai-support",
        "action": "route",
        "server": "smartdns-ai",
        "strategy": "ipv4_only"
      },
EOF
}

profile_outbound_tag() {
  case "$1" in
    ai)
      [[ "${AI_EGRESS_MODE:-ipsec}" == "xray" ]] && printf 'ai-xray\n' || printf 'ai-ipsec\n'
      ;;
    cn)
      [[ "${CN_EGRESS_MODE:-ipsec}" == "xray" ]] && printf 'cn-xray\n' || printf 'cn-ipsec\n'
      ;;
    *)
      die "profile must be ai or cn"
      ;;
  esac
}

render_singbox() {
  local lan_if="${WAN_IFACE}.${LAN_VLAN_ID:-}"
  local exclude4="${LAN_IPV4_CIDR:-}"
  local exclude_transit4="${TRANSIT_IPV4_CIDR:-}"
  local exclude6="${LAN_IPV6_PREFIX:-}"
  local exclude_transit6="${TRANSIT_IPV6_CIDR:-}"
  local cn_outbound
  cn_outbound=$(profile_outbound_tag cn)
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    lan_if="$WAN_IFACE"
    exclude4="$LAN_CLIENT_IPV4_CIDR"
    exclude_transit4="${LINUX_LAN_IPV4}/32"
    exclude6="fe80::/10"
    exclude_transit6="::1/128"
  fi
  write_file /etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "dnscomplex0",
      "address": [
        "172.31.255.1/30",
        "fd00:dc::1/126"
      ],
      "mtu": 1500,
      "auto_route": true,
      "auto_redirect": true,
      "auto_redirect_input_mark": $SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC,
      "auto_redirect_output_mark": $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC,
      "strict_route": true,
      "stack": "system",
      "include_interface": [
        "$lan_if"
      ],
      "route_exclude_address": [
        "$exclude4",
        "$exclude_transit4",
        "$exclude6",
        "$exclude_transit6"
      ]
    },
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "$SINGBOX_SOCKS_LISTEN",
      "listen_port": $SINGBOX_SOCKS_PORT
    },
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "$SINGBOX_HTTP_LISTEN",
      "listen_port": $SINGBOX_HTTP_PORT
    },
    {
      "type": "direct",
      "tag": "dns-in-udp",
      "listen": "$SINGBOX_DNS_LISTEN",
      "listen_port": $SINGBOX_DNS_PORT,
      "network": "udp",
      "override_address": "8.8.8.8",
      "override_port": 53
    },
    {
      "type": "direct",
      "tag": "dns-in-tcp",
      "listen": "$SINGBOX_DNS_LISTEN",
      "listen_port": $SINGBOX_DNS_PORT,
      "network": "tcp",
      "override_address": "8.8.8.8",
      "override_port": 53
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "default"
    },
    {
      "type": "direct",
      "tag": "ai-ipsec",
      "bind_interface": "ipsec-ai",
      "domain_resolver": {
        "server": "smartdns-ai",
        "strategy": "ipv4_only"
      }
    },
    {
      "type": "direct",
      "tag": "cn-ipsec",
      "bind_interface": "ipsec-cn",
      "domain_resolver": {
        "server": "smartdns-cn",
        "strategy": "ipv4_only"
      }
    },
    {
      "type": "socks",
      "tag": "ai-xray",
      "server": "$XRAY_LISTEN_HOST",
      "server_port": $XRAY_AI_SOCKS_PORT,
      "version": "5"
    },
    {
      "type": "socks",
      "tag": "cn-xray",
      "server": "$XRAY_LISTEN_HOST",
      "server_port": $XRAY_CN_SOCKS_PORT,
      "version": "5"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": {
      "server": "smartdns-default",
      "strategy": "$DEFAULT_DNS_STRATEGY"
    },
    "rule_set": [
$(render_singbox_rule_set_entries)
    ],
    "rules": [
      {
        "action": "sniff",
        "timeout": "1s"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
$(render_singbox_ai_route_rules)
      {
        "rule_set": "geosite-cn-video",
        "action": "route",
        "outbound": "$cn_outbound"
      },
      {
        "ip_is_private": true,
        "action": "route",
        "outbound": "default"
      }
    ],
    "final": "default"
  },
  "dns": {
    "servers": [
      {
        "type": "udp",
        "tag": "smartdns-default",
        "server": "127.0.0.1",
        "server_port": $SMARTDNS_DEFAULT_PORT
      },
      {
        "type": "udp",
        "tag": "smartdns-ai",
        "server": "127.0.0.1",
        "server_port": $SMARTDNS_AI_PORT
      },
      {
        "type": "udp",
        "tag": "smartdns-cn",
        "server": "127.0.0.1",
        "server_port": $SMARTDNS_CN_PORT
      }
    ],
    "rules": [
$(singbox_private_relay_dns_rule)
$(render_singbox_ai_dns_rules)
      {
        "rule_set": "geosite-cn-video",
        "query_type": [
          "HTTPS",
          "SVCB"
        ],
        "action": "reject"
      },
      {
        "rule_set": "geosite-cn-video",
        "action": "route",
        "server": "smartdns-cn",
        "strategy": "ipv4_only"
      }
    ],
    "final": "smartdns-default",
    "strategy": "$DEFAULT_DNS_STRATEGY"
  }
}
EOF
}

render_nft_profile_prerouting_rules() {
  local lan_if=$1 profile=$2 set_name=$3 mark=$4 mode=$5
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
    iifname "$lan_if" ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop"
EOF
  else
    cat <<EOF
    iifname "$lan_if" ip daddr 255.255.255.255 meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop"
    iifname "$lan_if" ip daddr @$set_name meta l4proto { icmp, tcp, udp } ct mark set $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK meta mark set $mark counter comment "dnscomplex-${profile}-preroute"
EOF
  fi
}

render_nft_profile_restore_rules() {
  local lan_if=$1 profile=$2 set_name=$3 mark=$4 mode=$5
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
    iifname "$lan_if" ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop-restore"
EOF
  else
    cat <<EOF
    iifname "$lan_if" ip daddr @$set_name meta l4proto { icmp, tcp, udp } meta mark set $mark counter comment "dnscomplex-${profile}-policy-restore"
EOF
  fi
}

render_nft_profile_output_rules() {
  local profile=$1 set_name=$2 mark=$3 mode=$4
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
    ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop-output"
EOF
  else
    cat <<EOF
    ip daddr @$set_name meta l4proto { icmp, tcp, udp } meta mark set $mark
EOF
  fi
}

render_nftables() {
  local lan_if="${WAN_IFACE}.${LAN_VLAN_ID:-}"
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    lan_if="$WAN_IFACE"
  fi
  write_file /etc/nftables.d/dnscomplex.nft <<EOF
table inet dnscomplex {
  set ai4 {
    type ipv4_addr
    flags interval,timeout
    size 262144
  }

  set cn4 {
    type ipv4_addr
    flags interval,timeout
    size 262144
  }

  set known_doh4 {
    type ipv4_addr
    flags interval
    elements = { 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112, 223.5.5.5, 223.6.6.6, 119.29.29.29 }
  }

  chain dns_redirect {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "$lan_if" udp dport 53 redirect to :53
    iifname "$lan_if" tcp dport 53 redirect to :53
  }

  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname "$lan_if" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept
    iifname "$lan_if" udp dport { 784, 853, 8853 } drop
    iifname "$lan_if" tcp dport 853 drop
    iifname "$lan_if" ip daddr @known_doh4 tcp dport 443 drop
$(render_nft_profile_prerouting_rules "$lan_if" ai ai4 "$AI_MARK" "$AI_EGRESS_MODE")
$(render_nft_profile_prerouting_rules "$lan_if" cn cn4 "$CN_MARK" "$CN_EGRESS_MODE")
  }

  chain prerouting_policy_restore {
    type filter hook prerouting priority filter; policy accept;
    iifname "$lan_if" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept
$(render_nft_profile_restore_rules "$lan_if" ai ai4 "$AI_MARK" "$AI_EGRESS_MODE")
$(render_nft_profile_restore_rules "$lan_if" cn cn4 "$CN_MARK" "$CN_EGRESS_MODE")
  }

  chain forward {
    type filter hook forward priority filter; policy accept;
    tcp flags syn tcp option maxseg size set $IPSEC_TCP_MSS
  }

  chain output {
    type route hook output priority mangle; policy accept;
    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept
$(render_nft_profile_output_rules ai ai4 "$AI_MARK" "$AI_EGRESS_MODE")
$(render_nft_profile_output_rules cn cn4 "$CN_MARK" "$CN_EGRESS_MODE")
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
  }
}
EOF

  write_file /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.nft"
EOF
}

render_ipsec_services() {
  write_file /etc/systemd/system/dnscomplex-ipsec-ifaces.service <<EOF
[Unit]
Description=dnscomplex route-based IPsec XFRM interfaces
Before=strongswan.service strongswan-swanctl.service
After=systemd-networkd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/dnscomplex ipsec-ifaces up
ExecStop=/usr/local/sbin/dnscomplex ipsec-ifaces down

[Install]
WantedBy=multi-user.target
EOF

  write_file /etc/systemd/system/dnscomplex-routing.service <<EOF
[Unit]
Description=dnscomplex policy routing
After=network-online.target dnscomplex-ipsec-ifaces.service
Wants=network-online.target dnscomplex-ipsec-ifaces.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/dnscomplex routes up
ExecStop=/usr/local/sbin/dnscomplex routes down

[Install]
WantedBy=multi-user.target
EOF

  write_file /etc/systemd/system/dnscomplex-health.service <<'EOF'
[Unit]
Description=dnscomplex health check and self-heal

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dnscomplex health
EOF

  write_file /etc/systemd/system/dnscomplex-health.timer <<'EOF'
[Unit]
Description=Run dnscomplex health check every minute

[Timer]
OnBootSec=90s
OnUnitActiveSec=60s
AccuracySec=15s
Unit=dnscomplex-health.service

[Install]
WantedBy=timers.target
EOF

  write_file /etc/systemd/system/dnscomplex-update.service <<'EOF'
[Unit]
Description=dnscomplex conservative software and geosite update

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dnscomplex update-software
ExecStart=/usr/local/sbin/dnscomplex update-geosite
EOF

  write_file /etc/systemd/system/dnscomplex-update.timer <<EOF
[Unit]
Description=Run dnscomplex conservative updates daily

[Timer]
OnCalendar=*-*-* $DNSCOMPLEX_UPDATE_TIME:00
RandomizedDelaySec=30m
Persistent=true
Unit=dnscomplex-update.service

[Install]
WantedBy=timers.target
EOF

  write_file /etc/systemd/system/dnscomplex-cn-overrides.service <<'EOF'
[Unit]
Description=Refresh dnscomplex CN static A overrides by reachability probe
After=network-online.target strongswan-starter.service smartdns.service nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dnscomplex refresh-cn-overrides
EOF

  write_file /etc/systemd/system/dnscomplex-cn-overrides.timer <<'EOF'
[Unit]
Description=Run dnscomplex CN override refresh periodically

[Timer]
OnBootSec=5m
OnUnitActiveSec=6h
RandomizedDelaySec=10m
Persistent=true
Unit=dnscomplex-cn-overrides.service

[Install]
WantedBy=timers.target
EOF

  write_file /etc/systemd/system/dnscomplex-nftset-refresh.service <<'EOF'
[Unit]
Description=Refresh dnscomplex AI/CN nftset IP cache
After=network-online.target smartdns.service nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dnscomplex refresh-nftsets
EOF

  write_file /etc/systemd/system/dnscomplex-nftset-refresh.timer <<EOF
[Unit]
Description=Keep dnscomplex AI/CN nftsets warm

[Timer]
OnBootSec=2m
OnUnitActiveSec=$DNSCOMPLEX_NFTSET_REFRESH_INTERVAL
AccuracySec=30s
Persistent=true
Unit=dnscomplex-nftset-refresh.service

[Install]
WantedBy=timers.target
EOF
}

render_routeros() {
  local lan_network
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    local primary_ip secondary_ip health_url primary_url secondary_url
    primary_ip=${HA_PRIMARY_IP:-$LINUX_LAN_IPV4}
    secondary_ip=${HA_SECONDARY_IP:-}
    health_url=${HA_HEALTH_URL:-/healthz}
    primary_url="http://${primary_ip}:${DNSCOMPLEX_METRICS_PORT}${health_url}"
    secondary_url="http://${secondary_ip}:${DNSCOMPLEX_METRICS_PORT}${health_url}"
    write_file /var/lib/dnscomplex/routeros.rsc <<EOF
# RouterOS 7 template for DEPLOY_MODE=routeros-policy.
# The Linux VM keeps its RouterOS DHCP static lease: $LINUX_LAN_IPV4.
# HA mode: $HA_MODE. Primary: $primary_ip. Secondary: ${secondary_ip:-none}.
# Replace <LAN_BRIDGE_OR_INTERFACE> with your LAN bridge/interface name.
# Fail-open design: RouterOS remains the default gateway. Only clients added to
# the dnscomplex-clients address-list are policy-routed to dnscomplex. If all
# dnscomplex VMs are down, Netwatch disables the policy and DNS redirect rules
# so clients fall back to normal RouterOS internet access.

/routing/table/add name=dnscomplex fib disabled=no
/ip/route/add dst-address=0.0.0.0/0 gateway=$primary_ip routing-table=dnscomplex distance=1 check-gateway=ping comment=dnscomplex-policy-to-vm-primary
EOF
    if [[ -n "$secondary_ip" ]]; then
      cat <<EOF | append_file /var/lib/dnscomplex/routeros.rsc
/ip/route/add dst-address=0.0.0.0/0 gateway=$secondary_ip routing-table=dnscomplex distance=2 check-gateway=ping comment=dnscomplex-policy-to-vm-secondary
EOF
    else
      cat <<'EOF' | append_file /var/lib/dnscomplex/routeros.rsc
# Optional secondary VM:
# /ip/route/add dst-address=0.0.0.0/0 gateway=<SECONDARY_VM_IP> routing-table=dnscomplex distance=2 check-gateway=ping comment=dnscomplex-policy-to-vm-secondary
EOF
    fi
    cat <<EOF | append_file /var/lib/dnscomplex/routeros.rsc

# Add test clients manually, for example:
# /ip/firewall/address-list/add list=dnscomplex-clients address=192.168.50.123 comment=dnscomplex-test-phone
/ip/firewall/address-list/add list=dnscomplex-vm address=$primary_ip comment=dnscomplex-vm-primary
EOF
    if [[ -n "$secondary_ip" ]]; then
      cat <<EOF | append_file /var/lib/dnscomplex/routeros.rsc
/ip/firewall/address-list/add list=dnscomplex-vm address=$secondary_ip comment=dnscomplex-vm-secondary
EOF
    fi
    cat <<EOF | append_file /var/lib/dnscomplex/routeros.rsc
/ip/firewall/mangle/add chain=prerouting in-interface=<LAN_BRIDGE_OR_INTERFACE> src-address-list=dnscomplex-clients dst-address-list=!dnscomplex-vm action=mark-routing new-routing-mark=dnscomplex passthrough=no comment=dnscomplex-policy-to-vm

# Optional DNS enforcement for the same test clients only. Do not change the
# whole DHCP network DNS if you want RouterOS to keep working when the VM is down.
/ip/firewall/nat/add chain=dstnat in-interface=<LAN_BRIDGE_OR_INTERFACE> protocol=udp dst-port=53 src-address-list=dnscomplex-clients action=dst-nat to-addresses=$primary_ip to-ports=53 comment=dnscomplex-force-dns-udp
/ip/firewall/nat/add chain=dstnat in-interface=<LAN_BRIDGE_OR_INTERFACE> protocol=tcp dst-port=53 src-address-list=dnscomplex-clients action=dst-nat to-addresses=$primary_ip to-ports=53 comment=dnscomplex-force-dns-tcp

# RouterOS 7.4+ health checks use HTTP GET against dnscomplex exporter /healthz.
# Compatible simple ping probes are included disabled; enable them only if your
# RouterOS build does not support type=http-get.
EOF
    if [[ -n "$secondary_ip" ]]; then
      cat <<EOF | append_file /var/lib/dnscomplex/routeros.rsc
/tool/netwatch/add host=$primary_ip interval=10s timeout=2s type=http-get url="$primary_url" comment=dnscomplex-primary-health \\
  down-script="/ip/route/disable [find where comment=dnscomplex-policy-to-vm-primary]; /ip/firewall/nat/set [find where comment~\\"dnscomplex-force-dns\\"] to-addresses=${secondary_ip:-$primary_ip}; :log warning \\"dnscomplex primary down\\"" \\
  up-script="/ip/route/enable [find where comment=dnscomplex-policy-to-vm-primary]; /ip/firewall/nat/set [find where comment~\\"dnscomplex-force-dns\\"] to-addresses=$primary_ip; /ip/firewall/mangle/enable [find where comment=dnscomplex-policy-to-vm]; /ip/firewall/nat/enable [find where comment~\\"dnscomplex-force-dns\\"]; :log info \\"dnscomplex primary up\\""
/tool/netwatch/add host=$primary_ip interval=10s timeout=2s type=simple disabled=yes comment=dnscomplex-primary-health-simple
EOF
    else
      cat <<EOF | append_file /var/lib/dnscomplex/routeros.rsc
/tool/netwatch/add host=$primary_ip interval=10s timeout=2s type=http-get url="$primary_url" comment=dnscomplex-primary-health \\
  down-script="/ip/route/disable [find where comment=dnscomplex-policy-to-vm-primary]; /ip/firewall/mangle/disable [find where comment=dnscomplex-policy-to-vm]; /ip/firewall/nat/disable [find where comment~\\"dnscomplex-force-dns\\"]; :log warning \\"dnscomplex-primary-health dnscomplex-fail-open\\"" \\
  up-script="/ip/route/enable [find where comment=dnscomplex-policy-to-vm-primary]; /ip/firewall/mangle/enable [find where comment=dnscomplex-policy-to-vm]; /ip/firewall/nat/enable [find where comment~\\"dnscomplex-force-dns\\"]; :log info \\"dnscomplex primary up\\""
/tool/netwatch/add host=$primary_ip interval=10s timeout=2s type=simple disabled=yes comment=dnscomplex-primary-health-simple
EOF
    fi
    if [[ -n "$secondary_ip" ]]; then
      cat <<EOF | append_file /var/lib/dnscomplex/routeros.rsc
/tool/netwatch/add host=$secondary_ip interval=10s timeout=2s type=http-get url="$secondary_url" comment=dnscomplex-secondary-health \\
  down-script="/ip/route/disable [find where comment=dnscomplex-policy-to-vm-secondary]; /ip/firewall/mangle/disable [find where comment=dnscomplex-policy-to-vm]; /ip/firewall/nat/disable [find where comment~\\"dnscomplex-force-dns\\"]; :log warning \\"dnscomplex-secondary-health dnscomplex-fail-open\\"" \\
  up-script="/ip/route/enable [find where comment=dnscomplex-policy-to-vm-secondary]; /ip/firewall/mangle/enable [find where comment=dnscomplex-policy-to-vm]; /ip/firewall/nat/enable [find where comment~\\"dnscomplex-force-dns\\"]; :log info \\"dnscomplex secondary up\\""
/tool/netwatch/add host=$secondary_ip interval=10s timeout=2s type=simple disabled=yes comment=dnscomplex-secondary-health-simple
EOF
    else
      cat <<'EOF' | append_file /var/lib/dnscomplex/routeros.rsc
# dnscomplex-fail-open: without a secondary VM, primary down disables policy
# and DNS redirect so clients use RouterOS directly.
EOF
    fi
    cat <<'EOF' | append_file /var/lib/dnscomplex/routeros.rsc

# IPv6 note: keep exactly one RA/default-router source on the LAN. A stale VM
# advertising RA can steal IPv6 default routes even when RouterOS IPv6 is correct.
EOF
    return 0
  fi

  local transit_if="dnscomplex-transit-v${TRANSIT_VLAN_ID}"
  local lan_vlan="dnscomplex-lan-v${LAN_VLAN_ID}"
  lan_network=$(ipv4_network "$LAN_IPV4_CIDR")

  write_file /var/lib/dnscomplex/routeros.rsc <<EOF
# Review before applying on RouterOS 7.
# Replace interface=<TRUNK_PORT> with the physical port connected to $WAN_IFACE.
/interface/vlan/add name=$transit_if vlan-id=$TRANSIT_VLAN_ID interface=<TRUNK_PORT>
/interface/vlan/add name=$lan_vlan vlan-id=$LAN_VLAN_ID interface=<TRUNK_PORT>
/ip/address/add address=$ROUTEROS_TRANSIT_IPV4/30 interface=$transit_if comment=dnscomplex-transit
/ipv6/address/add address=$ROUTEROS_TRANSIT_IPV6/64 interface=$transit_if advertise=no comment=dnscomplex-transit
/ip/route/add dst-address=$lan_network gateway=$LINUX_TRANSIT_IPV4 comment=dnscomplex-lan-v4
/ipv6/route/add dst-address=$LAN_IPV6_PREFIX gateway=$LINUX_TRANSIT_IPV6 comment=dnscomplex-lan-v6
/ip/firewall/filter/add chain=forward src-address=$lan_network action=accept comment=dnscomplex-lan-forward
/ipv6/firewall/filter/add chain=forward src-address=$LAN_IPV6_PREFIX action=accept comment=dnscomplex-lan-forward
# Keep RouterOS WAN NAT/firewall policy authoritative for default IPv4/IPv6 connectivity.
# If you keep RouterOS DHCP/RA elsewhere, make sure clients use $LAN_IPV4_CIDR and DNS gateway $(cidr_addr "$LAN_IPV4_CIDR").
EOF
}

render_management_script() {
  write_file /usr/local/sbin/dnscomplex <<'MANAGER'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

CONFIG=/etc/dnscomplex/config.env
BASE=/var/lib/dnscomplex
GEO_DIR=$BASE/geosite
DLC_DIR=$GEO_DIR/domain-list-community

die() {
  printf '[dnscomplex] ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[dnscomplex] %s\n' "$*"
}

warn() {
  printf '[dnscomplex] WARN: %s\n' "$*" >&2
}

load_config() {
  [[ -r "$CONFIG" ]] || die "missing $CONFIG"
  # shellcheck source=/dev/null
  . "$CONFIG"
  : "${DEPLOY_MODE:=vlan-gateway}"
  : "${DEFAULT_DNS_UPSTREAMS:=https://cloudflare-dns.com/dns-query tls://1.1.1.1 https://dns.google/dns-query tls://dns.google}"
  : "${DEFAULT_DNS_STRATEGY:=prefer_ipv6}"
  : "${DEFAULT_IPV6_MODE:=auto}"
  : "${AI_DNS_UPSTREAMS:=https://cloudflare-dns.com/dns-query tls://1.1.1.1 https://dns.google/dns-query tls://dns.google}"
  : "${CN_DNS_UPSTREAMS:=https://dns.alidns.com/dns-query tls://dns.alidns.com https://doh.pub/dns-query tls://dot.pub}"
  : "${SINGBOX_SOCKS_LISTEN:=0.0.0.0}"
  : "${SINGBOX_SOCKS_PORT:=1080}"
  : "${SINGBOX_DNS_LISTEN:=127.0.0.1}"
  : "${SINGBOX_DNS_PORT:=1053}"
  : "${SINGBOX_HTTP_LISTEN:=0.0.0.0}"
  : "${SINGBOX_HTTP_PORT:=1081}"
  : "${XRAY_ENABLED:=1}"
  : "${XRAY_LISTEN_HOST:=127.0.0.1}"
  : "${XRAY_AI_SOCKS_PORT:=16054}"
  : "${XRAY_CN_SOCKS_PORT:=16055}"
  : "${AI_EGRESS_MODE:=ipsec}"
  : "${CN_EGRESS_MODE:=ipsec}"
  : "${AI_XRAY_URI:=}"
  : "${CN_XRAY_URI:=}"
  : "${AI_XRAY_OUTBOUND_JSON:=}"
  : "${CN_XRAY_OUTBOUND_JSON:=}"
  : "${DNSCOMPLEX_WEB_LISTEN:=127.0.0.1}"
  : "${DNSCOMPLEX_WEB_PORT:=8088}"
  : "${DNSCOMPLEX_WEB_PASSWORD:=dnscomplex}"
  : "${DNSCOMPLEX_METRICS_LISTEN:=0.0.0.0}"
  : "${DNSCOMPLEX_METRICS_PORT:=9108}"
  : "${DNSCOMPLEX_UPDATE_TIME:=04:20}"
  : "${DNSCOMPLEX_UPDATE_LAST_LOG:=/var/log/dnscomplex/update-latest.log}"
  : "${DNSCOMPLEX_UPDATE_CHANNEL:=stable}"
  : "${DNSCOMPLEX_PINNED_VERSION:=}"
  : "${GITHUB_RELEASE_POLICY:=latest}"
  : "${DNSCOMPLEX_NFTSET_REFRESH_INTERVAL:=5m}"
  : "${DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT:=2h}"
  : "${ADGUARD_DNS_CACHE_MODE:=off}"
  : "${HA_MODE:=single}"
  : "${HA_PRIMARY_IP:=${LINUX_LAN_IPV4:-}}"
  : "${HA_SECONDARY_IP:=}"
  : "${HA_HEALTH_URL:=/healthz}"
  : "${HA_FAILOVER_POLICY:=primary-secondary-routeros}"
  : "${PROMETHEUS_MODE:=exporter-only}"
  : "${IPSEC_TCP_MSS:=1200}"
  : "${APPLE_PRIVATE_RELAY_BLOCK:=1}"
  : "${AI_GEOSITE_SOURCES:=openai anthropic}"
  : "${AI_SUPPORT_DOMAINS:=meta.ai}"
  : "${AI_NFTSET_REFRESH_DOMAINS:=chatgpt.com ios.chat.openai.com openai.com api.openai.com oaistatic.com oaiusercontent.com files.oaiusercontent.com cdn.oaistatic.com persistent.oaistatic.com cdn.openai.com anthropic.com claude.ai claude.com meta.ai}"
  : "${SING_GEOSITE_RULESET_BASE_URL:=https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set}"
  : "${CN_VIDEO_SOURCES:=acfun bilibili douyin douyu gitv hunantv huya iqiyi kuaishou le pptv youku wasu v.qq.com video.qq.com tencentvideo.com cibntv.net}"
  : "${AI_SAMPLE_DOMAINS:=openai.com anthropic.com claude.ai meta.ai}"
  : "${CN_SAMPLE_DOMAINS:=bilibili.com iqiyi.com youku.com douyin.com kuaishou.com acfun.cn mgtv.com v.qq.com qq.com tv.cctv.com}"
  : "${CN_NFTSET_REFRESH_DOMAINS:=$CN_SAMPLE_DOMAINS}"
  : "${CN_STATIC_A_OVERRIDES:=}"
  : "${CN_OVERRIDE_PROBE_DOMAINS:=youku.com=youku.com,www.youku.com}"
  : "${CN_OVERRIDE_PROBE_RESOLVERS:=223.5.5.5 119.29.29.29 1.1.1.1 8.8.8.8}"
  : "${CN_OVERRIDE_PROBE_TIMEOUT:=8}"
  migrate_ai_meta_sample_domains
  : "${AI_MARK:=0x301}"
  : "${CN_MARK:=0x351}"
  : "${AI_MARK_DEC:=769}"
  : "${CN_MARK_DEC:=849}"
  : "${SINGBOX_AUTO_REDIRECT_INPUT_MARK:=0x2023}"
  : "${SINGBOX_AUTO_REDIRECT_OUTPUT_MARK:=0x2024}"
  : "${SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC:=8227}"
  : "${SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC:=8228}"
  : "${AI_TABLE:=301}"
  : "${CN_TABLE:=351}"
  : "${AI_XFRM_ID:=301}"
  : "${CN_XFRM_ID:=351}"
}

config_schema_keys() {
  cat <<'EOF'
DNSCOMPLEX_VERSION
DEPLOY_MODE
WAN_IFACE
TRANSIT_VLAN_ID
LAN_VLAN_ID
ROUTEROS_TRANSIT_IPV4
LINUX_TRANSIT_IPV4
TRANSIT_IPV4_CIDR
ROUTEROS_TRANSIT_IPV6
LINUX_TRANSIT_IPV6
TRANSIT_IPV6_CIDR
ROUTEROS_LAN_IPV4
LINUX_LAN_IPV4
LAN_CLIENT_IPV4_CIDR
LAN_IPV4_CIDR
LAN_DHCP_START
LAN_DHCP_END
LAN_IPV6_PREFIX
LAN_IPV6_GATEWAY
AI_IPSEC_SERVER
CN_IPSEC_SERVER
IPSEC_REMOTE_ID
AI_IPSEC_USERNAME
AI_IPSEC_PASSWORD
CN_IPSEC_USERNAME
CN_IPSEC_PASSWORD
DEFAULT_DNS_UPSTREAMS
DEFAULT_DNS_STRATEGY
DEFAULT_IPV6_MODE
AI_DNS_UPSTREAMS
CN_DNS_UPSTREAMS
AI_GEOSITE_SOURCES
AI_SUPPORT_DOMAINS
AI_NFTSET_REFRESH_DOMAINS
SING_GEOSITE_RULESET_BASE_URL
CN_VIDEO_SOURCES
AI_SAMPLE_DOMAINS
CN_SAMPLE_DOMAINS
CN_NFTSET_REFRESH_DOMAINS
CN_STATIC_A_OVERRIDES
CN_OVERRIDE_PROBE_DOMAINS
CN_OVERRIDE_PROBE_RESOLVERS
SMARTDNS_DEFAULT_PORT
SMARTDNS_AI_PORT
SMARTDNS_CN_PORT
SINGBOX_DNS_LISTEN
SINGBOX_DNS_PORT
SINGBOX_SOCKS_LISTEN
SINGBOX_SOCKS_PORT
SINGBOX_HTTP_LISTEN
SINGBOX_HTTP_PORT
XRAY_ENABLED
XRAY_LISTEN_HOST
XRAY_AI_SOCKS_PORT
XRAY_CN_SOCKS_PORT
AI_EGRESS_MODE
CN_EGRESS_MODE
AI_XRAY_URI
CN_XRAY_URI
AI_XRAY_OUTBOUND_JSON
CN_XRAY_OUTBOUND_JSON
DNSCOMPLEX_WEB_LISTEN
DNSCOMPLEX_WEB_PORT
DNSCOMPLEX_WEB_PASSWORD
DNSCOMPLEX_METRICS_LISTEN
DNSCOMPLEX_METRICS_PORT
DNSCOMPLEX_UPDATE_TIME
DNSCOMPLEX_UPDATE_LAST_LOG
DNSCOMPLEX_UPDATE_CHANNEL
DNSCOMPLEX_PINNED_VERSION
GITHUB_RELEASE_POLICY
DNSCOMPLEX_NFTSET_REFRESH_INTERVAL
DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT
ADGUARD_DNS_CACHE_MODE
HA_MODE
HA_PRIMARY_IP
HA_SECONDARY_IP
HA_HEALTH_URL
HA_FAILOVER_POLICY
PROMETHEUS_MODE
IPSEC_TCP_MSS
APPLE_PRIVATE_RELAY_BLOCK
AI_MARK
CN_MARK
AI_MARK_DEC
CN_MARK_DEC
SINGBOX_AUTO_REDIRECT_INPUT_MARK
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK
SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC
AI_TABLE
CN_TABLE
AI_XFRM_ID
CN_XFRM_ID
EOF
}

config_missing_keys() {
  local key missing=0
  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    if ! grep -Eq "^${key}=" "$CONFIG" 2>/dev/null; then
      printf '%s\n' "$key"
      missing=1
    fi
  done < <(config_schema_keys)
  return "$missing"
}

migrate_config_cmd() {
  need_root
  local missing
  missing=$(config_missing_keys || true)
  if [[ -n "$missing" ]]; then
    log "migrating config; adding missing keys: $(tr '\n' ' ' <<<"$missing" | sed 's/[[:space:]]*$//')"
    write_config_cmd
  fi
}

split_words() {
  tr ' ,;' '\n\n\n' <<<"${1:-}" | sed '/^$/d'
}

migrate_ai_meta_sample_domains() {
  local item changed=0 has_meta_ai=0
  local -a kept=()
  while IFS= read -r item; do
    [[ -n "$item" ]] || continue
    case "$item" in
      facebook.com|instagram.com|meta.com|threads.net|whatsapp.com)
        changed=1
        continue
        ;;
      meta.ai)
        has_meta_ai=1
        ;;
    esac
    kept+=("$item")
  done < <(split_words "${AI_SAMPLE_DOMAINS:-}")
  if [[ "$has_meta_ai" == "0" ]]; then
    kept+=("meta.ai")
    changed=1
  fi
  if [[ "$changed" == "1" ]]; then
    AI_SAMPLE_DOMAINS=$(printf '%s\n' "${kept[@]}" | awk '!seen[$0]++' | xargs)
  fi
}

rule_set_safe_name() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9_-' '-'
}

need_root() {
  [[ "$(id -u)" == "0" ]] || die "run as root"
}

write_adguard_upstream_rules() {
  printf "    - '%s:%s'\n" "$SINGBOX_DNS_LISTEN" "$SINGBOX_DNS_PORT"
}

write_adguard_allow_rules() {
  local domain
  {
    split_words "${AI_SAMPLE_DOMAINS:-}"
    split_words "${AI_SUPPORT_DOMAINS:-}"
  } | while IFS= read -r domain; do
    [[ -n "$domain" && "$domain" != \#* ]] || continue
    [[ "$domain" == *.* ]] || continue
    printf "  - '@@||%s^'\n" "$domain"
  done | sort -u
}

merge_adguard_user_rules() {
  local input=$1
  local output=$2
  local allow_rules=$3
  awk -v allow_rules="$allow_rules" '
    BEGIN {
      while ((getline line < allow_rules) > 0) {
        allow[++allow_count] = line
        allow_map[line] = 1
      }
      close(allow_rules)
    }
    function print_allow_rules() {
      for (i = 1; i <= allow_count; i++) {
        print allow[i]
      }
    }
    function is_legacy_support_allow(line) {
      return line ~ /^  - '\''@@\|\|(api\.revenuecat\.com|api\.statsig\.com|events\.statsigapi\.net|featuregates\.org|o33249\.ingest\.sentry\.io|o33249\.ingest\.us\.sentry\.io)\^'\''$/
    }
    /^user_rules:[[:space:]]*\[\][[:space:]]*$/ {
      print "user_rules:"
      print_allow_rules()
      inserted = 1
      in_user_rules = 1
      next
    }
    /^user_rules:[[:space:]]*$/ {
      print
      print_allow_rules()
      inserted = 1
      in_user_rules = 1
      next
    }
    in_user_rules && /^[^[:space:]][^:]*:/ {
      in_user_rules = 0
    }
    in_user_rules && ($0 in allow_map) {
      next
    }
    in_user_rules && is_legacy_support_allow($0) && !($0 in allow_map) {
      next
    }
    { print }
    END {
      if (!inserted) {
        print "user_rules:"
        print_allow_rules()
      }
    }
  ' "$input" >"$output"
}

adguard_cache_yaml() {
  case "$ADGUARD_DNS_CACHE_MODE" in
    off)
      cat <<'EOF'
  cache_enabled: false
  cache_size: 0
  cache_optimistic: false
  cache_ttl_min: 0
  cache_ttl_max: 0
EOF
      ;;
    small)
      cat <<'EOF'
  cache_enabled: true
  cache_size: 4194304
  cache_optimistic: false
  cache_ttl_min: 0
  cache_ttl_max: 0
EOF
      ;;
    large)
      cat <<'EOF'
  cache_enabled: true
  cache_size: 67108864
  cache_optimistic: false
  cache_ttl_min: 0
  cache_ttl_max: 0
EOF
      ;;
    *)
      warn "unknown ADGUARD_DNS_CACHE_MODE=$ADGUARD_DNS_CACHE_MODE; using off"
      ADGUARD_DNS_CACHE_MODE=off
      adguard_cache_yaml
      ;;
  esac
}

normalize_adguard_cache_config() {
  local input=$1
  local output=$2
  local cache_block
  cache_block=$(mktemp)
  adguard_cache_yaml >"$cache_block"
  awk -v cache="$cache_block" '
    BEGIN {
      while ((getline line < cache) > 0) {
        block = block line ORS
      }
      close(cache)
    }
    /^  cache_/ { next }
    /^  (bogus_nxdomain|blocked_response_ttl):/ && !inserted {
      printf "%s", block
      inserted = 1
    }
    /^  blocked_response_ttl:/ {
      print
      next
    }
    { print }
    END {
      if (!inserted) {
        printf "%s", block
      }
    }
  ' "$input" >"$output"
  rm -f "$cache_block"
}

render_adguard_runtime() {
  local tmp rules allow_rules merged
  tmp=$(mktemp)
  rules=$(mktemp)
  allow_rules=$(mktemp)
  merged=$(mktemp)
  write_adguard_upstream_rules >"$rules"
  write_adguard_allow_rules >"$allow_rules"

  if [[ -s /etc/AdGuardHome/AdGuardHome.yaml ]] && grep -q '^  upstream_dns:' /etc/AdGuardHome/AdGuardHome.yaml; then
    awk -v rules="$rules" '
      BEGIN {
        while ((getline line < rules) > 0) {
          block = block line ORS
        }
        close(rules)
      }
      /^  upstream_dns:/ {
        print
        printf "%s", block
        skip = 1
        next
      }
      skip && /^  bootstrap_dns:/ {
        skip = 0
        print
        next
      }
      !skip { print }
    ' /etc/AdGuardHome/AdGuardHome.yaml >"$tmp"
  else
    {
      cat <<EOF
bind_host: 0.0.0.0
bind_port: 3000
users: []
auth_attempts: 5
block_auth_min: 15
http_proxy: ""
language: en
theme: auto
dns:
  bind_hosts:
    - 0.0.0.0
    - "::"
  port: 53
  anonymize_client_ip: false
  ratelimit: 0
  protection_enabled: true
  filtering_enabled: true
  parental_enabled: false
  safe_search:
    enabled: false
  upstream_dns:
EOF
      cat "$rules"
      cat <<'EOF'
  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
  fallback_dns: []
  blocking_mode: default
  blocked_response_ttl: 10
EOF
      adguard_cache_yaml
      cat <<'EOF'
  bogus_nxdomain: []
  aaaa_disabled: false
  enable_dnssec: true
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
whitelist_filters: []
user_rules:
EOF
      cat "$allow_rules"
      cat <<'EOF'
dhcp:
  enabled: false
clients:
  runtime_sources:
    whois: true
    arp: true
    rdns: true
    dhcp: false
log:
  enabled: true
  file: ""
  max_backups: 0
  max_size: 100
  max_age: 3
  compress: false
schema_version: 29
EOF
    } >"$tmp"
  fi

  normalize_adguard_cache_config "$tmp" "$tmp.cache"
  mv "$tmp.cache" "$tmp"
  merge_adguard_user_rules "$tmp" "$merged" "$allow_rules"
  install -m 0644 "$merged" /etc/AdGuardHome/AdGuardHome.yaml
  rm -f "$tmp" "$rules" "$allow_rules" "$merged"
}

apply_runtime_network_settings() {
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
  sysctl -w net.ipv6.conf.default.forwarding=1 >/dev/null
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
  sysctl -w net.netfilter.nf_conntrack_max=1048576 >/dev/null || true
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=86400 >/dev/null || true
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close_wait=60 >/dev/null || true
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_fin_wait=30 >/dev/null || true
  sysctl -w net.netfilter.nf_conntrack_udp_timeout=60 >/dev/null || true
  sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=180 >/dev/null || true
  sysctl -w "net.ipv4.ip_local_port_range=1024 65535" >/dev/null || true
  sysctl -w net.core.somaxconn=65535 >/dev/null || true
  sysctl -w net.ipv4.tcp_max_syn_backlog=65535 >/dev/null || true
  sysctl -w net.core.netdev_max_backlog=250000 >/dev/null || true
  if [[ -n "${WAN_IFACE:-}" && -d "/proc/sys/net/ipv4/conf/$WAN_IFACE" ]]; then
    sysctl -w "net.ipv4.conf.$WAN_IFACE.rp_filter=0" >/dev/null
  fi
  if [[ "$DEPLOY_MODE" == "routeros-policy" && -n "${WAN_IFACE:-}" && -d "/proc/sys/net/ipv6/conf/$WAN_IFACE" ]]; then
    sysctl -w net.ipv6.conf.default.accept_ra=2 >/dev/null || true
    sysctl -w net.ipv6.conf.default.autoconf=1 >/dev/null || true
    sysctl -w "net.ipv6.conf.$WAN_IFACE.accept_ra=2" >/dev/null || true
    sysctl -w "net.ipv6.conf.$WAN_IFACE.autoconf=1" >/dev/null || true
    sysctl -w "net.ipv6.conf.$WAN_IFACE.addr_gen_mode=0" >/dev/null || true
  fi
}

ipv6_tcp_available() {
  local host
  for host in 2606:4700:10::6814:179a 2001:4860:4860::8888 2404:6800:4005:81a::200e; do
    timeout 4 bash -c "</dev/tcp/$host/443" >/dev/null 2>&1 && return 0
  done
  return 1
}

resolve_default_ipv6_mode() {
  case "$DEFAULT_IPV6_MODE" in
    on)
      DEFAULT_IPV6_ACTIVE=1
      ;;
    off)
      DEFAULT_IPV6_ACTIVE=0
      ;;
    auto)
      if ipv6_tcp_available; then
        DEFAULT_IPV6_ACTIVE=1
      else
        DEFAULT_IPV6_ACTIVE=0
        warn "default IPv6 TCP is not reachable; default DNS should suppress AAAA until DEFAULT_IPV6_MODE=on or IPv6 routing is fixed"
      fi
      ;;
    *)
      die "DEFAULT_IPV6_MODE must be auto, on, or off"
      ;;
  esac
  export DEFAULT_IPV6_ACTIVE
}

linux_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    armv7l) printf 'armv7\n' ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

smartdns_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'x86_64\n' ;;
    aarch64|arm64) printf 'aarch64\n' ;;
    *) die "unsupported SmartDNS architecture: $(uname -m)" ;;
  esac
}

xray_asset_pattern() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'Xray-linux-64\\.zip$\n' ;;
    aarch64|arm64) printf 'Xray-linux-arm64-v8a\\.zip$\n' ;;
    armv7l) printf 'Xray-linux-arm32-v7a\\.zip$\n' ;;
    *) die "unsupported Xray architecture: $(uname -m)" ;;
  esac
}

github_release_api_url() {
  local repo=$1
  local channel=${DNSCOMPLEX_UPDATE_CHANNEL:-stable}
  local version=${DNSCOMPLEX_PINNED_VERSION:-}
  if [[ "${GITHUB_RELEASE_POLICY:-latest}" == "pinned" || "$channel" == "pinned" ]]; then
    [[ -n "$version" ]] || die "DNSCOMPLEX_PINNED_VERSION is required for pinned GitHub releases"
    printf 'https://api.github.com/repos/%s/releases/tags/%s\n' "$repo" "$version"
    return 0
  fi
  case "$channel" in
    stable)
      printf 'https://api.github.com/repos/%s/releases/latest\n' "$repo"
      ;;
    beta)
      printf 'https://api.github.com/repos/%s/releases\n' "$repo"
      ;;
    *)
      die "unsupported DNSCOMPLEX_UPDATE_CHANNEL=$channel"
      ;;
  esac
}

github_release_json() {
  local repo=$1
  local url
  url=$(github_release_api_url "$repo")
  if [[ "${DNSCOMPLEX_UPDATE_CHANNEL:-stable}" == "beta" && "${GITHUB_RELEASE_POLICY:-latest}" != "pinned" ]]; then
    curl -fsSL "$url" | jq 'map(select(.draft == false)) | .[0]'
  else
    curl -fsSL "$url"
  fi
}

github_latest_asset_url() {
  local repo=$1
  local pattern=$2
  local asset
  asset=$(github_release_json "$repo" |
    jq -r --arg pattern "$pattern" '.assets[].browser_download_url | select(test($pattern))' |
    head -n1)
  [[ -n "$asset" ]] || die "could not locate GitHub release asset for $repo matching $pattern"
  printf '%s\n' "$asset"
}

github_latest_release_tag() {
  local repo=$1
  github_release_json "$repo" | jq -r '.tag_name'
}

component_current_tag() {
  local component=$1
  case "$component" in
    sing-box)
      sing-box version 2>/dev/null | awk '/^sing-box version / {print "v" $3; exit}'
      ;;
    smartdns)
      smartdns -v 2>&1 | grep -Eo 'Release[0-9]+' | head -n1
      ;;
    AdGuardHome)
      /opt/AdGuardHome/AdGuardHome --version 2>/dev/null | grep -Eo 'v[0-9]+(\.[0-9]+)+' | head -n1
      ;;
    xray)
      xray version 2>/dev/null | awk '/^Xray / {print "v" $2; exit}'
      ;;
    *)
      return 1
      ;;
  esac
}

update_release_if_needed() {
  local component=$1
  local repo=$2
  local service=$3
  local installer=$4
  local latest current
  latest=$(github_latest_release_tag "$repo")
  [[ -n "$latest" && "$latest" != "null" ]] || die "could not read latest release tag for $repo"
  current=$(component_current_tag "$component" || true)
  if [[ -n "$current" && "$current" == "$latest" ]]; then
    log "$component $current already latest; skip"
    return 0
  fi
  log "stage: GitHub release update $component (${current:-unknown} -> $latest)"
  "$installer"
  UPDATED_SERVICES+=("$service")
}

write_env_var() {
  local name=$1
  local value=$2
  printf "%s='" "$name"
  printf "%s" "$value" | sed "s/'/'\\\\''/g"
  printf "'\n"
}

write_config_cmd() {
  need_root
  local tmp
  tmp=$(mktemp)
	  {
	    write_env_var DNSCOMPLEX_VERSION "${DNSCOMPLEX_VERSION:-0.1.0}"
    write_env_var DEPLOY_MODE "${DEPLOY_MODE:-vlan-gateway}"
	    write_env_var WAN_IFACE "$WAN_IFACE"
    write_env_var TRANSIT_VLAN_ID "${TRANSIT_VLAN_ID:-}"
    write_env_var LAN_VLAN_ID "${LAN_VLAN_ID:-}"
    write_env_var ROUTEROS_TRANSIT_IPV4 "${ROUTEROS_TRANSIT_IPV4:-}"
    write_env_var LINUX_TRANSIT_IPV4 "${LINUX_TRANSIT_IPV4:-}"
    write_env_var TRANSIT_IPV4_CIDR "${TRANSIT_IPV4_CIDR:-}"
    write_env_var ROUTEROS_TRANSIT_IPV6 "${ROUTEROS_TRANSIT_IPV6:-}"
    write_env_var LINUX_TRANSIT_IPV6 "${LINUX_TRANSIT_IPV6:-}"
    write_env_var TRANSIT_IPV6_CIDR "${TRANSIT_IPV6_CIDR:-}"
    write_env_var ROUTEROS_LAN_IPV4 "${ROUTEROS_LAN_IPV4:-}"
    write_env_var LINUX_LAN_IPV4 "${LINUX_LAN_IPV4:-}"
    write_env_var LAN_CLIENT_IPV4_CIDR "${LAN_CLIENT_IPV4_CIDR:-}"
    write_env_var LAN_IPV4_CIDR "${LAN_IPV4_CIDR:-}"
    write_env_var LAN_DHCP_START "${LAN_DHCP_START:-}"
    write_env_var LAN_DHCP_END "${LAN_DHCP_END:-}"
    write_env_var LAN_IPV6_PREFIX "${LAN_IPV6_PREFIX:-}"
    write_env_var LAN_IPV6_GATEWAY "${LAN_IPV6_GATEWAY:-}"
    write_env_var AI_IPSEC_SERVER "$AI_IPSEC_SERVER"
    write_env_var CN_IPSEC_SERVER "$CN_IPSEC_SERVER"
    write_env_var IPSEC_REMOTE_ID "$IPSEC_REMOTE_ID"
    write_env_var AI_IPSEC_USERNAME "$AI_IPSEC_USERNAME"
    write_env_var AI_IPSEC_PASSWORD "$AI_IPSEC_PASSWORD"
    write_env_var CN_IPSEC_USERNAME "$CN_IPSEC_USERNAME"
	    write_env_var CN_IPSEC_PASSWORD "$CN_IPSEC_PASSWORD"
	    write_env_var DEFAULT_DNS_UPSTREAMS "$DEFAULT_DNS_UPSTREAMS"
	    write_env_var DEFAULT_DNS_STRATEGY "$DEFAULT_DNS_STRATEGY"
	    write_env_var DEFAULT_IPV6_MODE "$DEFAULT_IPV6_MODE"
    write_env_var AI_DNS_UPSTREAMS "$AI_DNS_UPSTREAMS"
    write_env_var CN_DNS_UPSTREAMS "$CN_DNS_UPSTREAMS"
    write_env_var AI_GEOSITE_SOURCES "$AI_GEOSITE_SOURCES"
    write_env_var AI_SUPPORT_DOMAINS "$AI_SUPPORT_DOMAINS"
    write_env_var AI_NFTSET_REFRESH_DOMAINS "$AI_NFTSET_REFRESH_DOMAINS"
    write_env_var SING_GEOSITE_RULESET_BASE_URL "$SING_GEOSITE_RULESET_BASE_URL"
    write_env_var CN_VIDEO_SOURCES "$CN_VIDEO_SOURCES"
    write_env_var AI_SAMPLE_DOMAINS "$AI_SAMPLE_DOMAINS"
    write_env_var CN_SAMPLE_DOMAINS "$CN_SAMPLE_DOMAINS"
    write_env_var CN_NFTSET_REFRESH_DOMAINS "$CN_NFTSET_REFRESH_DOMAINS"
    write_env_var CN_STATIC_A_OVERRIDES "$CN_STATIC_A_OVERRIDES"
    write_env_var CN_OVERRIDE_PROBE_DOMAINS "$CN_OVERRIDE_PROBE_DOMAINS"
    write_env_var CN_OVERRIDE_PROBE_RESOLVERS "$CN_OVERRIDE_PROBE_RESOLVERS"
    write_env_var SMARTDNS_DEFAULT_PORT "$SMARTDNS_DEFAULT_PORT"
    write_env_var SMARTDNS_AI_PORT "$SMARTDNS_AI_PORT"
    write_env_var SMARTDNS_CN_PORT "$SMARTDNS_CN_PORT"
    write_env_var SINGBOX_DNS_LISTEN "$SINGBOX_DNS_LISTEN"
    write_env_var SINGBOX_DNS_PORT "$SINGBOX_DNS_PORT"
    write_env_var SINGBOX_SOCKS_LISTEN "$SINGBOX_SOCKS_LISTEN"
    write_env_var SINGBOX_SOCKS_PORT "$SINGBOX_SOCKS_PORT"
    write_env_var SINGBOX_HTTP_LISTEN "$SINGBOX_HTTP_LISTEN"
    write_env_var SINGBOX_HTTP_PORT "$SINGBOX_HTTP_PORT"
    write_env_var XRAY_ENABLED "$XRAY_ENABLED"
    write_env_var XRAY_LISTEN_HOST "$XRAY_LISTEN_HOST"
    write_env_var XRAY_AI_SOCKS_PORT "$XRAY_AI_SOCKS_PORT"
    write_env_var XRAY_CN_SOCKS_PORT "$XRAY_CN_SOCKS_PORT"
    write_env_var AI_EGRESS_MODE "$AI_EGRESS_MODE"
    write_env_var CN_EGRESS_MODE "$CN_EGRESS_MODE"
    write_env_var AI_XRAY_URI "$AI_XRAY_URI"
    write_env_var CN_XRAY_URI "$CN_XRAY_URI"
    write_env_var AI_XRAY_OUTBOUND_JSON "$AI_XRAY_OUTBOUND_JSON"
    write_env_var CN_XRAY_OUTBOUND_JSON "$CN_XRAY_OUTBOUND_JSON"
    write_env_var DNSCOMPLEX_WEB_LISTEN "$DNSCOMPLEX_WEB_LISTEN"
    write_env_var DNSCOMPLEX_WEB_PORT "$DNSCOMPLEX_WEB_PORT"
	    write_env_var DNSCOMPLEX_WEB_PASSWORD "$DNSCOMPLEX_WEB_PASSWORD"
	    write_env_var DNSCOMPLEX_METRICS_LISTEN "$DNSCOMPLEX_METRICS_LISTEN"
	    write_env_var DNSCOMPLEX_METRICS_PORT "$DNSCOMPLEX_METRICS_PORT"
	    write_env_var DNSCOMPLEX_UPDATE_TIME "$DNSCOMPLEX_UPDATE_TIME"
	    write_env_var DNSCOMPLEX_UPDATE_LAST_LOG "$DNSCOMPLEX_UPDATE_LAST_LOG"
	    write_env_var DNSCOMPLEX_UPDATE_CHANNEL "$DNSCOMPLEX_UPDATE_CHANNEL"
	    write_env_var DNSCOMPLEX_PINNED_VERSION "$DNSCOMPLEX_PINNED_VERSION"
	    write_env_var GITHUB_RELEASE_POLICY "$GITHUB_RELEASE_POLICY"
	    write_env_var DNSCOMPLEX_NFTSET_REFRESH_INTERVAL "$DNSCOMPLEX_NFTSET_REFRESH_INTERVAL"
    write_env_var DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT "$DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT"
    write_env_var ADGUARD_DNS_CACHE_MODE "$ADGUARD_DNS_CACHE_MODE"
    write_env_var HA_MODE "$HA_MODE"
    write_env_var HA_PRIMARY_IP "$HA_PRIMARY_IP"
    write_env_var HA_SECONDARY_IP "$HA_SECONDARY_IP"
    write_env_var HA_HEALTH_URL "$HA_HEALTH_URL"
    write_env_var HA_FAILOVER_POLICY "$HA_FAILOVER_POLICY"
    write_env_var PROMETHEUS_MODE "$PROMETHEUS_MODE"
    write_env_var IPSEC_TCP_MSS "$IPSEC_TCP_MSS"
    write_env_var APPLE_PRIVATE_RELAY_BLOCK "$APPLE_PRIVATE_RELAY_BLOCK"
    write_env_var AI_MARK "$AI_MARK"
    write_env_var CN_MARK "$CN_MARK"
	    write_env_var AI_MARK_DEC "$AI_MARK_DEC"
	    write_env_var CN_MARK_DEC "$CN_MARK_DEC"
	    write_env_var SINGBOX_AUTO_REDIRECT_INPUT_MARK "$SINGBOX_AUTO_REDIRECT_INPUT_MARK"
	    write_env_var SINGBOX_AUTO_REDIRECT_OUTPUT_MARK "$SINGBOX_AUTO_REDIRECT_OUTPUT_MARK"
	    write_env_var SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC "$SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC"
	    write_env_var SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC "$SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC"
	    write_env_var AI_TABLE "$AI_TABLE"
    write_env_var CN_TABLE "$CN_TABLE"
    write_env_var AI_XFRM_ID "$AI_XFRM_ID"
    write_env_var CN_XFRM_ID "$CN_XFRM_ID"
  } >"$tmp"
  install -m 0600 "$tmp" "$CONFIG"
  rm -f "$tmp"
}

usage() {
  cat <<'EOF'
Usage: dnscomplex <command> [args]

Commands:
  status [--verbose]
  test
  health [--json]
  fix
  doctor
  update-geosite
  add-domain ai|cn DOMAIN_OR_GEOSITE
  remove-domain ai|cn DOMAIN_OR_GEOSITE
  set-socks LISTEN PORT
  set-ipsec ai|cn USER PASSWORD
  set-web-password PASSWORD
  set-local-host HOST.local IPv4
  test-local-name HOST.local
  set-egress ai|cn ipsec|xray
  set-xray-uri ai|cn URI
  set-xray-json ai|cn JSON_FILE
  test-xray [ai|cn]
  xray-status
  render-xray
  set-update-time HH:MM
  refresh-nftsets
  refresh-cn-overrides [DOMAIN ...]
  trace-domain DOMAIN
  test-dns
  test-ipsec
  mss-calibrate
  routeros-print
  update-software [--channel stable|beta|pinned] [--version VERSION]
  metrics-sample
  soak [--duration 30m] [--clients 1000] [--dns-qps 50] [--profiles ai,cn,default] [--idle-resume]
  wizard
  validate-config [--json] ENV_FILE
  render-config [--redacted]
  support-bundle [--output PATH] [--include-logs minimal|standard|full]
  backup [OUTPUT_TAR_GZ]
  restore INPUT_TAR_GZ
  ipsec-ifaces up|down
  routes up|down
EOF
}

unit_exists() {
  local state
  state=$(systemctl show -p LoadState --value "$1" 2>/dev/null || true)
  [[ -n "$state" && "$state" != "not-found" ]]
}

print_unit_state() {
  local unit=$1
  local active enabled
  unit_exists "$unit" || return 0
  active=$(systemctl is-active "$unit" 2>/dev/null || true)
  enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
  printf '%-32s active=%-10s enabled=%s\n' "$unit" "$active" "$enabled"
}

status_cmd() {
  local unit verbose=0 missing
  if [[ "${1:-}" == "--verbose" || "${1:-}" == "verbose" ]]; then
    verbose=1
  fi
  printf 'deploy_mode=%s default_ipv6_mode=%s default_dns_strategy=%s adguard_cache=%s ha_mode=%s primary=%s secondary=%s ai_egress=%s cn_egress=%s update_channel=%s pinned_version=%s github_policy=%s\n' \
    "$DEPLOY_MODE" "$DEFAULT_IPV6_MODE" "$DEFAULT_DNS_STRATEGY" "$ADGUARD_DNS_CACHE_MODE" "$HA_MODE" "${HA_PRIMARY_IP:-}" "${HA_SECONDARY_IP:-}" "$AI_EGRESS_MODE" "$CN_EGRESS_MODE" "$DNSCOMPLEX_UPDATE_CHANNEL" "${DNSCOMPLEX_PINNED_VERSION:-}" "$GITHUB_RELEASE_POLICY"
  missing=$(config_missing_keys || true)
  if [[ -n "$missing" ]]; then
    printf 'config_missing_keys=%s\n' "$(tr '\n' ',' <<<"$missing" | sed 's/,$//')"
  fi
  printf 'update_last_log=%s\n' "$DNSCOMPLEX_UPDATE_LAST_LOG"
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    printf 'routeros_policy_ipv6_note=%s\n' 'VM does not advertise RA in routeros-policy mode; IPv6 clients follow RouterOS RA unless RouterOS routes or policy-routes them through this VM.'
  fi
  for unit in \
    sing-box.service \
    smartdns.service \
    AdGuardHome.service \
    strongswan-starter.service \
    strongswan-swanctl.service \
    strongswan.service \
    ipsec.service \
    nftables.service \
    xray-dnscomplex.service \
    dnscomplex-web.service \
    dnscomplex-metrics.service \
    dnscomplex-health.timer \
    dnscomplex-update.timer \
    dnscomplex-cn-overrides.timer \
    dnscomplex-nftset-refresh.timer \
    dnscomplex-metrics-sample.timer; do
    print_unit_state "$unit"
  done
  if [[ "$DEPLOY_MODE" != "routeros-policy" ]]; then
    print_unit_state dnsmasq.service
    print_unit_state radvd.service
  fi
  printf '\n[ipsec]\n'
  swanctl --list-sas 2>/dev/null || true
  printf '\n[ip rules]\n'
  ip rule show | grep -E "fwmark (${AI_MARK}|${CN_MARK})" || true
  if [[ "$verbose" == "1" ]]; then
    printf '\n[nft dnscomplex]\n'
    nft list table inet dnscomplex || true
  else
    printf '\n[nft]\n'
    nft list table inet dnscomplex >/dev/null 2>&1 && printf 'dnscomplex table=present\n' || printf 'dnscomplex table=missing\n'
    for set_name in ai4 cn4; do
      local count
      count=$(nft list set inet dnscomplex "$set_name" 2>/dev/null | { grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' || true; } | wc -l | tr -d ' ')
      printf '%s_count=%s\n' "$set_name" "${count:-0}"
    done
  fi
  if [[ -r /proc/sys/net/netfilter/nf_conntrack_count && -r /proc/sys/net/netfilter/nf_conntrack_max ]]; then
    local ct_count ct_max
    ct_count=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
    ct_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
    printf 'conntrack=%s/%s\n' "$ct_count" "$ct_max"
  fi
}

restart_ipsec_service() {
  local unit
  for unit in strongswan-swanctl strongswan-starter strongswan ipsec; do
    if systemctl list-unit-files "${unit}.service" >/dev/null 2>&1; then
      systemctl restart "$unit"
      return 0
    fi
  done
  return 1
}

wait_dns_ready() {
  command -v dig >/dev/null 2>&1 || return 0
  local attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if dig +time=1 +tries=1 +short A example.com @127.0.0.1 -p 53 2>/dev/null | grep -Eq '^[0-9]+\.'; then
      return 0
    fi
    sleep 1
  done
  return 1
}

restart_dns_stack() {
  fix_smartdns_wrapper
  ensure_smartdns_enabled
  systemctl restart smartdns sing-box AdGuardHome
  wait_dns_ready || warn "DNS stack restarted but did not answer readiness probe within 10 seconds"
}

download_geosite_source() {
  mkdir -p "$GEO_DIR"
  local tmp
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/dlc.zip" https://github.com/v2fly/domain-list-community/archive/refs/heads/master.zip
  unzip -q "$tmp/dlc.zip" -d "$tmp"
  rm -rf "$DLC_DIR"
  mv "$tmp"/domain-list-community-master "$DLC_DIR"
  rm -rf "$tmp"
}

download_sing_geosite_ai_rule_sets() {
  mkdir -p "$GEO_DIR"
  local source safe url target tmp
  while IFS= read -r source; do
    source=$(printf '%s\n' "$source" | trim_line)
    [[ -n "$source" ]] || continue
    safe=$(rule_set_safe_name "$source")
    url="${SING_GEOSITE_RULESET_BASE_URL%/}/geosite-${source}.srs"
    target="$GEO_DIR/geosite-ai-$safe.srs"
    tmp=$(mktemp)
    if ! curl -fsSL -o "$tmp" "$url"; then
      rm -f "$tmp"
      die "failed to download sing-geosite rule-set: $url"
    fi
    install -m 0644 "$tmp" "$target"
    rm -f "$tmp"
  done < <(split_words "$AI_GEOSITE_SOURCES")
}

trim_line() {
  sed -e 's/[[:space:]]*#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

resolve_one_source() {
  local source=$1
  local out_suffix=$2
  local out_exact=$3
  local out_keyword=$4
  local out_regex=$5
  local data_file="$DLC_DIR/data/$source"
  local line token include

  if [[ ! -f "$data_file" ]]; then
    if [[ "$source" == *.* ]]; then
      printf '%s\n' "$source" >>"$out_suffix"
      return 0
    fi
    log "warning: geosite source not found: $source"
    return 0
  fi

  while IFS= read -r line || [[ -n "$line" ]]; do
    token=$(printf '%s\n' "$line" | trim_line)
    [[ -z "$token" ]] && continue
    token=${token%% *}
    case "$token" in
      include:*)
        include=${token#include:}
        include=${include%%@*}
        resolve_one_source "$include" "$out_suffix" "$out_exact" "$out_keyword" "$out_regex"
        ;;
      full:*)
        printf '%s\n' "${token#full:}" >>"$out_exact"
        ;;
      domain:*)
        printf '%s\n' "${token#domain:}" >>"$out_suffix"
        ;;
      keyword:*)
        printf '%s\n' "${token#keyword:}" >>"$out_keyword"
        ;;
      regexp:*)
        printf '%s\n' "${token#regexp:}" >>"$out_regex"
        ;;
      @*)
        :
        ;;
      *)
        printf '%s\n' "$token" >>"$out_suffix"
        ;;
    esac
  done <"$data_file"
}

unique_file() {
  local file=$1
  sort -u "$file" -o "$file"
}

json_array_from_file() {
  local file=$1
  if [[ -s "$file" ]]; then
    jq -R -s 'split("\n") | map(select(length > 0))' "$file"
  else
    printf '[]\n'
  fi
}

compile_profile() {
  local profile=$1
  local source_file=$2
  local custom_file=$3
  local suffix="$GEO_DIR/$profile.suffix"
  local exact="$GEO_DIR/$profile.exact"
  local keyword="$GEO_DIR/$profile.keyword"
  local regex="$GEO_DIR/$profile.regex"
  local domains="$GEO_DIR/$profile.domains"
  local json="$GEO_DIR/$profile.json"
  local source

  : >"$suffix"
  : >"$exact"
  : >"$keyword"
  : >"$regex"

  while IFS= read -r source || [[ -n "$source" ]]; do
    source=$(printf '%s\n' "$source" | trim_line)
    [[ -z "$source" ]] && continue
    resolve_one_source "$source" "$suffix" "$exact" "$keyword" "$regex"
  done <"$source_file"

  if [[ -f "$custom_file" ]]; then
    while IFS= read -r source || [[ -n "$source" ]]; do
      source=$(printf '%s\n' "$source" | trim_line)
      [[ -z "$source" ]] && continue
      resolve_one_source "$source" "$suffix" "$exact" "$keyword" "$regex"
    done <"$custom_file"
  fi

  unique_file "$suffix"
  unique_file "$exact"
  unique_file "$keyword"
  unique_file "$regex"
  cat "$suffix" "$exact" | sort -u >"$domains"

  jq -n \
    --argjson suffix "$(json_array_from_file "$suffix")" \
    --argjson exact "$(json_array_from_file "$exact")" \
    --argjson keyword "$(json_array_from_file "$keyword")" \
    --argjson regex "$(json_array_from_file "$regex")" \
    '{version: 2, rules: [{domain_suffix: $suffix, domain: $exact, domain_keyword: $keyword, domain_regex: $regex}]}' >"$json"

  sing-box rule-set compile --output "$GEO_DIR/geosite-$profile.srs" "$json"
}

install_domain_files() {
  {
    [[ -f /etc/dnscomplex/ai.seed-domains ]] && cat /etc/dnscomplex/ai.seed-domains
    [[ -f "$GEO_DIR/ai-support.domains" ]] && cat "$GEO_DIR/ai-support.domains"
    split_words "${AI_NFTSET_REFRESH_DOMAINS:-}"
  } | sort -u >/etc/dnscomplex/ai.domains
  install -m 0644 "$GEO_DIR/cn-video.domains" /etc/dnscomplex/cn-video.domains
}

sync_geosite_sources_from_config() {
  mkdir -p "$GEO_DIR"
  split_words "${AI_GEOSITE_SOURCES:-}" >"$GEO_DIR/ai.sources"
  split_words "${AI_SUPPORT_DOMAINS:-}" >"$GEO_DIR/ai-support.sources"
  split_words "${CN_VIDEO_SOURCES:-}" >"$GEO_DIR/cn-video.sources"
}

sync_domain_seed_files_from_config() {
  split_words "${AI_SAMPLE_DOMAINS:-}" >/etc/dnscomplex/ai.seed-domains
  split_words "${CN_SAMPLE_DOMAINS:-}" >/etc/dnscomplex/cn-video.seed-domains
}

flush_policy_nftsets_cmd() {
  nft flush set inet dnscomplex ai4 >/dev/null 2>&1 || true
  nft flush set inet dnscomplex cn4 >/dev/null 2>&1 || true
}

update_geosite_cmd() {
  need_root
  mkdir -p "$GEO_DIR"
  sync_geosite_sources_from_config
  sync_domain_seed_files_from_config
  write_config_cmd
  download_sing_geosite_ai_rule_sets
  download_geosite_source
  compile_profile ai-support "$GEO_DIR/ai-support.sources" "$GEO_DIR/ai.custom"
  compile_profile cn-video "$GEO_DIR/cn-video.sources" "$GEO_DIR/cn-video.custom"
  install_domain_files
  render_adguard_runtime
  sing-box check -c /etc/sing-box/config.json
  restart_dns_stack
  flush_policy_nftsets_cmd
  refresh_nftsets_cmd || warn "nftset refresh failed after geosite update"
}

profile_file() {
  case "$1" in
    ai) printf '%s\n' "$GEO_DIR/ai.custom" ;;
    cn) printf '%s\n' "$GEO_DIR/cn-video.custom" ;;
    *) die "profile must be ai or cn" ;;
  esac
}

add_list_item() {
  local list=$1
  local item=$2
  {
    split_words "$list"
    printf '%s\n' "$item"
  } | awk 'NF && !seen[$0]++'
}

remove_list_item() {
  local list=$1
  local item=$2
  split_words "$list" | awk -v item="$item" 'NF && $0 != item && !seen[$0]++'
}

add_domain_cmd() {
  need_root
  [[ $# -eq 2 ]] || die "usage: dnscomplex add-domain ai|cn DOMAIN_OR_GEOSITE"
  local profile=$1
  local value=$2
  local file
  file=$(profile_file "$profile")
  mkdir -p "$(dirname "$file")"
  if [[ "$value" != *.* ]]; then
    case "$profile" in
      ai)
        AI_GEOSITE_SOURCES=$(add_list_item "$AI_GEOSITE_SOURCES" "$value" | xargs)
        write_config_cmd
        ;;
      cn)
        CN_VIDEO_SOURCES=$(add_list_item "$CN_VIDEO_SOURCES" "$value" | xargs)
        write_config_cmd
        ;;
    esac
  else
    grep -Fxq "$value" "$file" 2>/dev/null || printf '%s\n' "$value" >>"$file"
  fi
  update_geosite_cmd
}

remove_domain_cmd() {
  need_root
  [[ $# -eq 2 ]] || die "usage: dnscomplex remove-domain ai|cn DOMAIN_OR_GEOSITE"
  local profile=$1
  local value=$2
  local file tmp changed=0
  file=$(profile_file "$profile")
  tmp=$(mktemp)
  grep -Fxv "$value" "$file" >"$tmp" || true
  install -m 0644 "$tmp" "$file"
  rm -f "$tmp"
  case "$profile" in
    ai)
      if split_words "$AI_GEOSITE_SOURCES" | grep -Fxq "$value"; then
        AI_GEOSITE_SOURCES=$(remove_list_item "$AI_GEOSITE_SOURCES" "$value" | xargs)
        changed=1
      fi
      if split_words "$AI_SUPPORT_DOMAINS" | grep -Fxq "$value"; then
        AI_SUPPORT_DOMAINS=$(remove_list_item "$AI_SUPPORT_DOMAINS" "$value" | xargs)
        changed=1
      fi
      ;;
    cn)
      if split_words "$CN_VIDEO_SOURCES" | grep -Fxq "$value"; then
        CN_VIDEO_SOURCES=$(remove_list_item "$CN_VIDEO_SOURCES" "$value" | xargs)
        changed=1
      fi
      ;;
  esac
  ((changed == 0)) || write_config_cmd
  update_geosite_cmd
}

smartdns_static_address_line() {
  local override=$1
  local domain=${override%%=*}
  local address=${override#*=}
  [[ -n "$domain" && -n "$address" && "$domain" != "$address" ]] || return 0
  printf 'address /-.%s/%s\n' "$domain" "$address"
}

cn_override_current_ip() {
  local domain=$1
  local override
  while IFS= read -r override; do
    [[ "${override%%=*}" == "$domain" ]] || continue
    printf '%s\n' "${override#*=}"
    return 0
  done < <(tr ' ' '\n' <<<"$CN_STATIC_A_OVERRIDES")
}

cn_override_sources() {
  local domain=$1
  local override sources source
  while IFS= read -r override; do
    [[ "${override%%=*}" == "$domain" ]] || continue
    sources=${override#*=}
    tr ',' '\n' <<<"$sources"
    return 0
  done < <(tr ' ' '\n' <<<"$CN_OVERRIDE_PROBE_DOMAINS")
  printf '%s\n' "$domain"
  source=${domain#www.}
  [[ "$source" != "$domain" ]] || printf 'www.%s\n' "$domain"
}

cn_override_candidate_ips() {
  local domain=$1
  local resolver source current
  current=$(cn_override_current_ip "$domain" || true)
  [[ -n "$current" ]] && printf '%s\n' "$current"
  while IFS= read -r source; do
    [[ -n "$source" ]] || continue
    while IFS= read -r resolver; do
      [[ -n "$resolver" ]] || continue
      dig +time=2 +tries=1 "@$resolver" A "$source" +short 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' || true
    done < <(tr ' ' '\n' <<<"$CN_OVERRIDE_PROBE_RESOLVERS")
  done < <(cn_override_sources "$domain")
}

probe_cn_override_ip() {
  local domain=$1
  local ip=$2
  nft add element inet dnscomplex cn4 "{ $ip timeout 5m }" >/dev/null 2>&1 || true
  "$0" routes up >/dev/null 2>&1 || true
  timeout "$CN_OVERRIDE_PROBE_TIMEOUT" \
    curl -4 -k -fsS -o /dev/null --connect-timeout 4 \
    --interface ipsec-cn \
    --resolve "$domain:443:$ip" \
    "https://$domain/" >/dev/null 2>&1
}

rewrite_smartdns_static_overrides() {
  local tmp filtered override domain line
  tmp=$(mktemp)
  filtered=$(mktemp)
  cp /etc/smartdns/smartdns.conf "$tmp"
  while IFS= read -r override; do
    [[ -n "$override" ]] || continue
    domain=${override%%=*}
    : >"$filtered"
    while IFS= read -r line || [[ -n "$line" ]]; do
      case "$line" in
        "address /$domain/"*|"address /-.$domain/"*) continue ;;
      esac
      printf '%s\n' "$line" >>"$filtered"
    done <"$tmp"
    mv "$filtered" "$tmp"
    filtered=$(mktemp)
  done < <(tr ' ' '\n' <<<"$CN_STATIC_A_OVERRIDES")
  while IFS= read -r override; do
    smartdns_static_address_line "$override"
  done < <(tr ' ' '\n' <<<"$CN_STATIC_A_OVERRIDES") >>"$tmp"
  install -m 0644 "$tmp" /etc/smartdns/smartdns.conf
  rm -f "$tmp" "$filtered"
}

valid_refresh_timeout() {
  [[ "$DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT" =~ ^[0-9]+(ms|s|m|h|d)?$ ]]
}

public_ipv4() {
  local ip=$1 a b c d
  IFS=. read -r a b c d <<<"$ip"
  [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] || return 1
  ((a >= 1 && a <= 223 && b >= 0 && b <= 255 && c >= 0 && c <= 255 && d >= 0 && d <= 255)) || return 1
  ((a == 10 || a == 127)) && return 1
  ((a == 169 && b == 254)) && return 1
  ((a == 172 && b >= 16 && b <= 31)) && return 1
  ((a == 192 && b == 168)) && return 1
  return 0
}

nftset_refresh_domain_stream() {
  local profile=$1
  local files=()
  case "$profile" in
    ai)
      files=(
        "$GEO_DIR/ai.exact"
        "$GEO_DIR/ai-support.exact"
        /etc/dnscomplex/ai.domains
        "$GEO_DIR/ai.custom"
        "$GEO_DIR/ai-support.custom"
      )
      ;;
    cn)
      files=(
        "$GEO_DIR/cn-video.exact"
        "$GEO_DIR/cn-video.custom"
      )
      ;;
    *) die "profile must be ai or cn" ;;
  esac

  {
    case "$profile" in
      ai) split_words "${AI_NFTSET_REFRESH_DOMAINS:-}" ;;
      cn) split_words "${CN_NFTSET_REFRESH_DOMAINS:-}" ;;
    esac
    awk '
      {
        sub(/[[:space:]]*#.*/, "", $0)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
      }
      $0 ~ /^[A-Za-z0-9_.-]+$/ && $0 ~ /\./ { print tolower($0) }
    ' "${files[@]}" 2>/dev/null
  } | awk '
    {
      sub(/[[:space:]]*#.*/, "", $0)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
    }
    $0 ~ /^[A-Za-z0-9_.-]+$/ && $0 ~ /\./ { print tolower($0) }
  ' | sort -u
}

refresh_nftset_group() {
  local profile=$1
  local port=$2
  local set_name=$3
  local domain output ip domains=0 added=0 failed=0

  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    domains=$((domains + 1))
    output=$(dig +time=2 +tries=1 +short "@127.0.0.1" -p "$port" A "$domain" 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' || true)
    if [[ -z "$output" ]]; then
      failed=$((failed + 1))
      continue
    fi
    while IFS= read -r ip; do
      [[ -n "$ip" ]] || continue
      public_ipv4 "$ip" || continue
      nft delete element inet dnscomplex "$set_name" "{ $ip }" >/dev/null 2>&1 || true
      if nft add element inet dnscomplex "$set_name" "{ $ip timeout $DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT }" >/dev/null 2>&1; then
        added=$((added + 1))
      fi
    done <<<"$output"
  done < <(nftset_refresh_domain_stream "$profile")

  log "refreshed $profile nftset: domains=$domains ips_added_or_renewed=$added no_answer=$failed"
}

refresh_nftsets_cmd() {
  need_root
  command -v dig >/dev/null 2>&1 || die "install dnsutils for dig"
  command -v nft >/dev/null 2>&1 || die "install nftables"
  valid_refresh_timeout || die "DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT must look like 30m, 2h, or 3600s"
  nft list table inet dnscomplex >/dev/null 2>&1 || systemctl restart nftables || true
  nft list table inet dnscomplex >/dev/null 2>&1 || die "nftables dnscomplex table is missing"
  refresh_nftset_group ai "$SMARTDNS_AI_PORT" ai4
  refresh_nftset_group cn "$SMARTDNS_CN_PORT" cn4
}

replace_cn_static_override() {
  local domain=$1
  local ip=$2
  local override next=()
  while IFS= read -r override; do
    [[ -n "$override" ]] || continue
    [[ "${override%%=*}" == "$domain" ]] && continue
    next+=("$override")
  done < <(tr ' ' '\n' <<<"$CN_STATIC_A_OVERRIDES")
  next+=("$domain=$ip")
  CN_STATIC_A_OVERRIDES=""
  for override in "${next[@]}"; do
    if [[ -z "$CN_STATIC_A_OVERRIDES" ]]; then
      CN_STATIC_A_OVERRIDES=$override
    else
      CN_STATIC_A_OVERRIDES+=" $override"
    fi
  done
}

refresh_cn_overrides_cmd() {
  need_root
  command -v dig >/dev/null 2>&1 || die "install dnsutils for dig"
  command -v curl >/dev/null 2>&1 || die "install curl"
  ip link show ipsec-cn >/dev/null || die "ipsec-cn interface is missing"

  local domains=("$@")
  local override domain ip selected failed=0
  if [[ ${#domains[@]} -eq 0 ]]; then
    while IFS= read -r override; do
      [[ -n "$override" ]] || continue
      domains+=("${override%%=*}")
    done < <(tr ' ' '\n' <<<"$CN_STATIC_A_OVERRIDES")
    while IFS= read -r override; do
      [[ -n "$override" ]] || continue
      domain=${override%%=*}
      printf '%s\n' "${domains[@]}" | grep -Fxq "$domain" || domains+=("$domain")
    done < <(tr ' ' '\n' <<<"$CN_OVERRIDE_PROBE_DOMAINS")
  fi

  [[ ${#domains[@]} -gt 0 ]] || die "no CN override domains configured"

  for domain in "${domains[@]}"; do
    selected=""
    while IFS= read -r ip; do
      [[ -n "$ip" ]] || continue
      if probe_cn_override_ip "$domain" "$ip"; then
        selected=$ip
        break
      fi
    done < <(cn_override_candidate_ips "$domain" | awk '!seen[$0]++')

    if [[ -n "$selected" ]]; then
      replace_cn_static_override "$domain" "$selected"
      log "CN override selected: $domain=$selected"
    else
      warn "no reachable CN override candidate found for $domain; existing value kept"
      failed=1
    fi
  done

  write_config_cmd
  rewrite_smartdns_static_overrides
  systemctl restart smartdns
  [[ "$failed" == "0" ]] || die "one or more CN override probes failed"
}

test_dns_cmd() {
  local failed=0
  resolve_default_ipv6_mode
  command -v dig >/dev/null 2>&1 || die "install dnsutils for dig"

  dns_wait_match() {
    local type=$1
    local domain=$2
    local pattern=$3
    local attempt output
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
      output=$(dig +time=2 +tries=1 +short "$type" "$domain" @127.0.0.1 -p 53 2>/dev/null || true)
      if grep -Eq "$pattern" <<<"$output"; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  dns_query() {
    dig +time=2 +tries=1 +short "$1" "$2" @127.0.0.1 -p 53 2>/dev/null || true
  }

  dns_wait_match A openai.com '^[0-9]+\.' || failed=1
  if dns_query AAAA openai.com | grep -q ':'; then
    log "warning: AI AAAA response observed; check AdGuard/SmartDNS routing"
    failed=1
  fi
  dns_wait_match A bilibili.com '^[0-9]+\.' || failed=1
  dns_wait_match A example.com '^[0-9]+\.' || failed=1
  if [[ "$DEFAULT_IPV6_ACTIVE" == "1" ]]; then
    dns_wait_match AAAA example.com ':' || failed=1
  elif dns_query AAAA example.com | grep -q ':'; then
    log "warning: default AAAA response observed while DEFAULT_IPV6_MODE resolved inactive"
    failed=1
  fi
  log "Residual risk: generic DoH over TCP/443 cannot be detected with 100% confidence; known providers are blocked by nftables only."
  [[ "$failed" == "0" ]] || die "DNS test failed"
}

test_ipsec_cmd() {
  local sas required=0 failed=0
  sas=$(swanctl --list-sas 2>/dev/null || true)
  if [[ "${AI_EGRESS_MODE:-ipsec}" == "ipsec" ]]; then
    required=1
    grep -Eq '^ai:' <<<"$sas" || { warn "AI IPsec SA not found"; failed=1; }
    ip link show ipsec-ai >/dev/null || { warn "ipsec-ai interface not found"; failed=1; }
  fi
  if [[ "${CN_EGRESS_MODE:-ipsec}" == "ipsec" ]]; then
    required=1
    grep -Eq '^cn:' <<<"$sas" || { warn "CN IPsec SA not found"; failed=1; }
    ip link show ipsec-cn >/dev/null || { warn "ipsec-cn interface not found"; failed=1; }
  fi
  if [[ "$required" == "0" ]]; then
    log "AI/CN egress are not using IPsec; skipping IPsec test"
    return 0
  fi
  [[ "$failed" == "0" ]]
}

mss_calibrate_cmd() {
  need_root
  local mtu_ai mtu_cn mss_ai mss_cn recommended
  mtu_ai=$(ip link show ipsec-ai 2>/dev/null | awk '/mtu/ {for (i=1;i<=NF;i++) if ($i=="mtu") print $(i+1)}' | head -n1)
  mtu_cn=$(ip link show ipsec-cn 2>/dev/null | awk '/mtu/ {for (i=1;i<=NF;i++) if ($i=="mtu") print $(i+1)}' | head -n1)
  mtu_ai=${mtu_ai:-1400}
  mtu_cn=${mtu_cn:-1400}
  mss_ai=$((mtu_ai - 60))
  mss_cn=$((mtu_cn - 60))
  log "AI MSS candidate: $mss_ai"
  log "CN MSS candidate: $mss_cn"
  recommended=$(mss_recommended_value "$mss_ai" "$mss_cn")
  IPSEC_TCP_MSS=$recommended
  write_config_cmd
  if [[ -f /etc/nftables.d/dnscomplex.nft ]]; then
    sed -i -E "s/(tcp flags syn tcp option maxseg size set )[0-9]+/\\1$IPSEC_TCP_MSS/" /etc/nftables.d/dnscomplex.nft
  fi
  systemctl restart nftables
  refresh_nftsets_cmd || warn "nftset refresh failed after MSS calibration"
  log "applied IPSEC_TCP_MSS=$IPSEC_TCP_MSS"
}

mss_recommended_value() {
  local ai=$1 cn=$2 value
  value=$ai
  ((cn < value)) && value=$cn
  ((value > 1360)) && value=1360
  ((value < 536)) && value=536
  printf '%s\n' "$value"
}

ipsec_ifaces_cmd() {
  need_root
  local action=${1:-}
  local underlay="${WAN_IFACE}.${TRANSIT_VLAN_ID:-}"
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    underlay="$WAN_IFACE"
  fi
  case "$action" in
    up)
      ip link show ipsec-ai >/dev/null 2>&1 || ip link add ipsec-ai type xfrm dev "$underlay" if_id "$AI_XFRM_ID"
      ip link show ipsec-cn >/dev/null 2>&1 || ip link add ipsec-cn type xfrm dev "$underlay" if_id "$CN_XFRM_ID"
      ip link set ipsec-ai mtu 1400 up
      ip link set ipsec-cn mtu 1400 up
      ;;
    down)
      ip link del ipsec-ai 2>/dev/null || true
      ip link del ipsec-cn 2>/dev/null || true
      ;;
    *)
      die "usage: dnscomplex ipsec-ifaces up|down"
      ;;
  esac
}

ipsec_vip() {
  local child=$1
  swanctl --list-sas 2>/dev/null | awk -v child="$child" '
    $1 == child ":" {
      in_child = 1
      next
    }
    /^[[:alnum:]_-]+:/ {
      in_child = 0
    }
    in_child && $0 ~ /local .*\[[0-9.]+\]/ {
      line = $0
      sub(/^.*\[/, "", line)
      sub(/\].*$/, "", line)
      print line
      exit
    }
  '
}

delete_nft_rules_by_comment() {
  local chain=$1
  local comment=$2
  local handle
  while read -r handle; do
    [[ -n "$handle" ]] || continue
    nft delete rule inet dnscomplex "$chain" handle "$handle" 2>/dev/null || true
  done < <(nft -a list chain inet dnscomplex "$chain" 2>/dev/null | awk -v comment="\"$comment\"" '$0 ~ comment {print $NF}')
}

sync_ipsec_nat() {
  nft list chain inet dnscomplex postrouting >/dev/null 2>&1 || \
    nft add chain inet dnscomplex postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'

  delete_nft_rules_by_comment postrouting dnscomplex-ai-snat
  delete_nft_rules_by_comment postrouting dnscomplex-cn-snat

  local ai_vip cn_vip
  ai_vip=$(ipsec_vip ai || true)
  cn_vip=$(ipsec_vip cn || true)

  if [[ -n "$ai_vip" ]]; then
    nft add rule inet dnscomplex postrouting oifname "ipsec-ai" ip daddr @ai4 snat ip to "$ai_vip" comment "dnscomplex-ai-snat"
  else
    warn "AI IPsec virtual IPv4 is not available yet; SNAT rule not installed"
  fi

  if [[ -n "$cn_vip" ]]; then
    nft add rule inet dnscomplex postrouting oifname "ipsec-cn" ip daddr @cn4 snat ip to "$cn_vip" comment "dnscomplex-cn-snat"
  else
    warn "CN IPsec virtual IPv4 is not available yet; SNAT rule not installed"
  fi
}

sync_singbox_ipsec_bind_addresses() {
  command -v jq >/dev/null 2>&1 || return 0
  [[ -f /etc/sing-box/config.json ]] || return 0

  local ai_vip cn_vip current_ai current_cn tmp needs_update=0
  ai_vip=$(ipsec_vip ai || true)
  cn_vip=$(ipsec_vip cn || true)
  [[ -n "$ai_vip" || -n "$cn_vip" ]] || return 0

  current_ai=$(jq -r '.outbounds[] | select(.tag=="ai-ipsec") | .inet4_bind_address // ""' /etc/sing-box/config.json)
  current_cn=$(jq -r '.outbounds[] | select(.tag=="cn-ipsec") | .inet4_bind_address // ""' /etc/sing-box/config.json)
  [[ -n "$ai_vip" && "$current_ai" != "$ai_vip" ]] && needs_update=1
  [[ -n "$cn_vip" && "$current_cn" != "$cn_vip" ]] && needs_update=1
  [[ "$needs_update" == "1" ]] || return 0

  tmp=$(mktemp)
  jq --arg ai "$ai_vip" --arg cn "$cn_vip" '
    if $ai != "" then
      (.outbounds[] | select(.tag=="ai-ipsec") | .inet4_bind_address) = $ai
    else
      .
    end |
    if $cn != "" then
      (.outbounds[] | select(.tag=="cn-ipsec") | .inet4_bind_address) = $cn
    else
      .
    end
  ' /etc/sing-box/config.json >"$tmp"
  install -m 0644 "$tmp" /etc/sing-box/config.json
  rm -f "$tmp"
  sing-box check -c /etc/sing-box/config.json
  systemctl restart sing-box || true
}

routes_cmd() {
  need_root
  local action=${1:-}
  local ai_vip cn_vip
  case "$action" in
    up)
      ip rule add fwmark "$AI_MARK" table "$AI_TABLE" priority 10301 2>/dev/null || true
      ip rule add fwmark "$CN_MARK" table "$CN_TABLE" priority 10351 2>/dev/null || true
      ai_vip=$(ipsec_vip ai || true)
      cn_vip=$(ipsec_vip cn || true)
      if [[ -n "$ai_vip" ]]; then
        ip route replace default dev ipsec-ai src "$ai_vip" table "$AI_TABLE"
      else
        ip route replace default dev ipsec-ai table "$AI_TABLE"
      fi
      if [[ -n "$cn_vip" ]]; then
        ip route replace default dev ipsec-cn src "$cn_vip" table "$CN_TABLE"
      else
        ip route replace default dev ipsec-cn table "$CN_TABLE"
      fi
      sync_ipsec_nat || true
      sync_singbox_ipsec_bind_addresses || true
      ;;
    down)
      ip rule del fwmark "$AI_MARK" table "$AI_TABLE" priority 10301 2>/dev/null || true
      ip rule del fwmark "$CN_MARK" table "$CN_TABLE" priority 10351 2>/dev/null || true
      ip route flush table "$AI_TABLE" 2>/dev/null || true
      ip route flush table "$CN_TABLE" 2>/dev/null || true
      delete_nft_rules_by_comment postrouting dnscomplex-ai-snat
      delete_nft_rules_by_comment postrouting dnscomplex-cn-snat
      ;;
    *)
      die "usage: dnscomplex routes up|down"
      ;;
  esac
}

fix_cmd() {
  need_root
  migrate_config_cmd
  apply_runtime_network_settings
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    systemctl restart nftables || true
    systemctl disable --now dnsmasq radvd systemd-resolved 2>/dev/null || true
    systemctl reset-failed dnsmasq radvd systemd-resolved 2>/dev/null || true
  else
    systemctl restart systemd-networkd dnsmasq radvd nftables || true
  fi
  restart_ipsec_service || true
  systemctl restart dnscomplex-ipsec-ifaces dnscomplex-routing || true
  systemctl enable --now dnscomplex-metrics dnscomplex-metrics-sample.timer 2>/dev/null || true
  systemctl enable --now xray-dnscomplex 2>/dev/null || true
  systemctl restart dnscomplex-metrics || true
  apply_egress_stack_cmd || true
  write_update_timer_cmd || true
  systemctl reset-failed dnscomplex-update.service dnscomplex-update.timer 2>/dev/null || true
  swanctl --load-all >/tmp/dnscomplex-swanctl-load.log 2>&1 || cat /tmp/dnscomplex-swanctl-load.log >&2
  swanctl --initiate --child ai || true
  swanctl --initiate --child cn || true
  "$0" routes up || true
  render_adguard_runtime || true
  restart_dns_stack || true
  "$0" refresh-nftsets || true
}

doctor_cmd() {
  local failed=0 missing failed_units
  missing=$(config_missing_keys || true)
  if [[ -n "$missing" ]]; then
    failed=1
    printf '[config] missing keys:\n%s\n' "$missing"
  else
    printf '[config] ok\n'
  fi

  failed_units=$(systemctl --failed --plain --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^(dnscomplex|sing-box|smartdns|AdGuardHome|strongswan|nftables|xray)' || true)
  if [[ -n "$failed_units" ]]; then
    failed=1
    printf '[systemd] failed units:\n%s\n' "$failed_units"
  else
    printf '[systemd] no failed dnscomplex-related units\n'
  fi

  printf '[update] last_log=%s\n' "$DNSCOMPLEX_UPDATE_LAST_LOG"
  if [[ -r "$DNSCOMPLEX_UPDATE_LAST_LOG" ]]; then
    tail -n 40 "$DNSCOMPLEX_UPDATE_LAST_LOG"
  else
    printf '[update] no update log found yet\n'
  fi

  if adguard_cache_diagnostics; then
    printf '[cache] AdGuard cache policy ok; SmartDNS remains the DNS cache authority\n'
  else
    failed=1
    printf '[cache] double DNS cache risk: AdGuard cache is enabled while SmartDNS cache is active\n'
  fi

  if [[ -r /proc/sys/net/netfilter/nf_conntrack_count && -r /proc/sys/net/netfilter/nf_conntrack_max ]]; then
    local ct_count ct_max ct_pct
    ct_count=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
    ct_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
    ct_pct=$(conntrack_usage_percent)
    printf '[conntrack] count=%s max=%s usage=%s%%\n' "$ct_count" "$ct_max" "$ct_pct"
  fi

  command -v dig >/dev/null 2>&1 && dig +time=2 +tries=1 +short A example.com @127.0.0.1 -p 53 >/dev/null || {
    failed=1
    printf '[dns] local DNS check failed\n'
  }
  sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1 || {
    failed=1
    printf '[sing-box] config check failed\n'
  }
  xray run -test -format=json -config /usr/local/etc/xray/config.json >/dev/null 2>&1 || {
    failed=1
    printf '[xray] config check failed\n'
  }
  nft -c -f /etc/nftables.conf >/dev/null 2>&1 || {
    failed=1
    printf '[nft] config check failed\n'
  }
  printf '[quic] UDP/443 is allowed by default unless profile nftset rules mark AI/CN traffic; DoT/DoQ ports are blocked in nftables.\n'
  return "$failed"
}

trace_domain_cmd() {
  [[ $# -eq 1 ]] || die "usage: dnscomplex trace-domain DOMAIN"
  local domain=$1 profile=default source=default ips_v4 ips_v6 ip hit outbound=default
  if grep -Rhs -F "$domain" "$GEO_DIR"/ai.sources "$GEO_DIR"/ai.custom "$GEO_DIR"/ai-support.sources /etc/dnscomplex/ai.domains 2>/dev/null | grep -Fxq "$domain"; then
    profile=AI
    source=ai-domain-list
  elif grep -Rhs -F "$domain" "$GEO_DIR"/cn-video.sources "$GEO_DIR"/cn-video.custom /etc/dnscomplex/cn-video.domains 2>/dev/null | grep -Fxq "$domain"; then
    profile=CN
    source=cn-domain-list
  fi
  command -v dig >/dev/null 2>&1 || die "install dnsutils for dig"
  ips_v4=$(dig +time=3 +tries=1 +short A "$domain" @127.0.0.1 -p 53 2>/dev/null | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || true)
  ips_v6=$(dig +time=3 +tries=1 +short AAAA "$domain" @127.0.0.1 -p 53 2>/dev/null | grep ':' || true)
  printf 'domain=%s\n' "$domain"
  printf 'A=%s\n' "${ips_v4:-none}"
  printf 'AAAA=%s\n' "${ips_v6:-none}"
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    hit=default
    nft get element inet dnscomplex ai4 "{ $ip }" >/dev/null 2>&1 && hit=AI
    nft get element inet dnscomplex cn4 "{ $ip }" >/dev/null 2>&1 && hit=CN
    if [[ "$hit" == "AI" || "$hit" == "CN" ]]; then
      profile=$hit
      source="nftset:${hit,,}4"
    fi
    printf 'nftset[%s]=%s\n' "$ip" "$hit"
  done <<<"$ips_v4"
  printf 'profile=%s\nprofile_source=%s\n' "$profile" "$source"
  case "$profile" in
    AI) outbound=$(profile_outbound_tag ai) ;;
    CN) outbound=$(profile_outbound_tag cn) ;;
    *) outbound=default ;;
  esac
  printf 'expected_outbound=%s\n' "$outbound"
  if [[ "$profile" =~ ^(AI|CN)$ && -n "$ips_v6" ]]; then
    printf 'warning=%s\n' "$profile domain returned AAAA; AI/CN should remain IPv4-only"
    return 1
  fi
}

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))' 2>/dev/null || printf '"%s"' "$(sed 's/\\/\\\\/g; s/"/\\"/g')"
}

service_ok() {
  systemctl is-active --quiet "$1" 2>/dev/null
}

conntrack_usage_percent() {
  local count max
  count=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || printf '0')
  max=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || printf '1')
  awk -v c="$count" -v m="$max" 'BEGIN { if (m <= 0) m = 1; printf "%.2f", (c / m) * 100 }'
}

dns_latency_ms() {
  local domain=${1:-example.com}
  command -v dig >/dev/null 2>&1 || { printf '0\n'; return 1; }
  dig +time=2 +tries=1 +stats +short A "$domain" @127.0.0.1 -p 53 2>/dev/null |
    awk '/Query time:/ {print $4; found=1} END {if (!found) print 0}'
}

adguard_cache_diagnostics() {
  local file=/etc/AdGuardHome/AdGuardHome.yaml enabled size
  enabled=$(awk -F: '/^  cache_enabled:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$file" 2>/dev/null || true)
  size=$(awk -F: '/^  cache_size:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$file" 2>/dev/null || true)
  enabled=${enabled:-unknown}
  size=${size:-unknown}
  printf 'adguard_cache_enabled=%s adguard_cache_size=%s expected_mode=%s\n' "$enabled" "$size" "$ADGUARD_DNS_CACHE_MODE"
  if [[ "$ADGUARD_DNS_CACHE_MODE" == "off" && ( "$enabled" == "true" || "$size" != "0" ) ]]; then
    return 1
  fi
  return 0
}

health_json_cmd() {
  local failed=0 dns_ms ct_pct service services_json cache_ok ipsec_ok
  services_json=""
  for service in sing-box.service smartdns.service AdGuardHome.service nftables.service xray-dnscomplex.service; do
    if service_ok "$service"; then
      services_json+="{\"name\":\"$service\",\"ok\":true},"
    else
      failed=1
      services_json+="{\"name\":\"$service\",\"ok\":false},"
    fi
  done
  services_json="[${services_json%,}]"
  dns_ms=$(dns_latency_ms example.com || true)
  ct_pct=$(conntrack_usage_percent)
  cache_ok=true
  adguard_cache_diagnostics >/dev/null || { cache_ok=false; failed=1; }
  ipsec_ok=true
  local sas
  sas=$(swanctl --list-sas 2>/dev/null || true)
  if [[ "${AI_EGRESS_MODE:-ipsec}" == "ipsec" ]] && ! grep -Eq '^ai:' <<<"$sas"; then
    ipsec_ok=false
    failed=1
  fi
  if [[ "${CN_EGRESS_MODE:-ipsec}" == "ipsec" ]] && ! grep -Eq '^cn:' <<<"$sas"; then
    ipsec_ok=false
    failed=1
  fi
  awk -v health="$([[ "$failed" == "0" ]] && printf healthy || printf degraded)" \
    -v services="$services_json" \
    -v dns_ms="${dns_ms:-0}" \
    -v ct_pct="${ct_pct:-0}" \
    -v cache_ok="$cache_ok" \
    -v ipsec_ok="$ipsec_ok" \
    -v ha_mode="$HA_MODE" \
    -v primary="${HA_PRIMARY_IP:-}" \
    -v secondary="${HA_SECONDARY_IP:-}" \
    'BEGIN {
      printf "{"
      printf "\"status\":\"%s\",", health
      printf "\"services\":%s,", services
      printf "\"dns_latency_ms\":%s,", dns_ms + 0
      printf "\"conntrack_usage_percent\":%s,", ct_pct + 0
      printf "\"adguard_cache_ok\":%s,", cache_ok
      printf "\"ipsec_ok\":%s,", ipsec_ok
      printf "\"ha_mode\":\"%s\",\"ha_primary_ip\":\"%s\",\"ha_secondary_ip\":\"%s\"", ha_mode, primary, secondary
      printf "}\n"
    }'
  [[ "$failed" == "0" ]]
}

health_cmd() {
  if [[ "${1:-}" == "--json" ]]; then
    health_json_cmd
    return $?
  fi
  need_root
  migrate_config_cmd || true
  apply_runtime_network_settings
  nft list table inet dnscomplex >/dev/null 2>&1 || systemctl restart nftables || true
  fix_smartdns_wrapper || true
  ensure_smartdns_enabled || true
  systemctl is-active --quiet smartdns || systemctl restart smartdns || true
  systemctl is-active --quiet AdGuardHome || systemctl restart AdGuardHome || true
  systemctl is-active --quiet sing-box || systemctl restart sing-box || true
  systemctl is-active --quiet xray-dnscomplex || systemctl restart xray-dnscomplex || true
  if [[ "${AI_EGRESS_MODE:-ipsec}" == "ipsec" || "${CN_EGRESS_MODE:-ipsec}" == "ipsec" ]]; then
    systemctl is-active --quiet strongswan-starter || systemctl is-active --quiet strongswan-swanctl || restart_ipsec_service || true
  fi
  "$0" ipsec-ifaces up || true
  "$0" routes up || true
  timeout 8 swanctl --load-all --noprompt >/dev/null 2>&1 || true
  local child
  for child in ai cn; do
    if [[ "$child" == "ai" && "${AI_EGRESS_MODE:-ipsec}" != "ipsec" ]]; then
      continue
    fi
    if [[ "$child" == "cn" && "${CN_EGRESS_MODE:-ipsec}" != "ipsec" ]]; then
      continue
    fi
    if ! timeout 5 swanctl --list-sas 2>/dev/null | grep -Eq "^${child}: #[0-9]+, ESTABLISHED"; then
      timeout 15 swanctl --initiate --child "$child" >/dev/null 2>&1 || true
    fi
  done
  "$0" routes up || true
}

write_update_timer_cmd() {
  need_root
  [[ "$DNSCOMPLEX_UPDATE_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "DNSCOMPLEX_UPDATE_TIME must be HH:MM"
  cat >/etc/systemd/system/dnscomplex-update.timer <<EOF
[Unit]
Description=Run dnscomplex conservative updates daily

[Timer]
OnCalendar=*-*-* $DNSCOMPLEX_UPDATE_TIME:00
RandomizedDelaySec=30m
Persistent=true
Unit=dnscomplex-update.service

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now dnscomplex-update.timer
  systemctl restart dnscomplex-update.timer
}

set_update_time_cmd() {
  need_root
  [[ $# -eq 1 ]] || die "usage: dnscomplex set-update-time HH:MM"
  DNSCOMPLEX_UPDATE_TIME=$1
  [[ "$DNSCOMPLEX_UPDATE_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "update time must be HH:MM"
  write_config_cmd
  write_update_timer_cmd
}

set_web_password_cmd() {
  need_root
  [[ $# -eq 1 ]] || die "usage: dnscomplex set-web-password PASSWORD"
  local pass=$1
  if [[ "$pass" == "-" ]]; then
    read -r -s -p "Web password: " pass
    printf '\n'
  fi
  [[ ${#pass} -ge 8 ]] || die "web password must be at least 8 characters"
  DNSCOMPLEX_WEB_PASSWORD=$pass
  write_config_cmd
  log "web password updated; log in again with username admin"
}

set_local_host_cmd() {
  need_root
  [[ $# -eq 2 ]] || die "usage: dnscomplex set-local-host HOST.local IPv4"
  local host=$1 ip=$2 tmp
  [[ "$host" == *.local ]] || die "host must end with .local"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "IPv4 address required"
  mkdir -p /etc/dnscomplex
  touch /etc/dnscomplex/local-hosts
  tmp=$(mktemp)
  awk -v host="$host" 'tolower($2) != tolower(host)' /etc/dnscomplex/local-hosts >"$tmp" || true
  printf '%s %s\n' "$ip" "$host" >>"$tmp"
  install -m 0644 "$tmp" /etc/dnscomplex/local-hosts
  rm -f "$tmp"
  restart_dns_stack || true
  log "local host override applied: $host -> $ip"
}

test_local_name_cmd() {
  [[ $# -eq 1 ]] || die "usage: dnscomplex test-local-name HOST.local"
  local host=$1
  dig +time=2 +tries=1 "$host" @127.0.0.1 -p 53 A +noall +answer +authority || true
}

set_socks_cmd() {
  need_root
  [[ $# -eq 2 ]] || die "usage: dnscomplex set-socks LISTEN PORT"
  local listen=$1
  local port=$2
  [[ "$port" =~ ^[0-9]+$ ]] || die "SOCKS port must be numeric"
  ((port >= 1 && port <= 65535)) || die "SOCKS port must be 1-65535"

  local tmp
  tmp=$(mktemp)
  jq --arg listen "$listen" --argjson port "$port" '
    (.inbounds[] | select(.tag == "socks-in").listen) = $listen |
    (.inbounds[] | select(.tag == "socks-in").listen_port) = $port
  ' /etc/sing-box/config.json >"$tmp"
  jq -e --arg listen "$listen" --argjson port "$port" '
    any(.inbounds[]?; .tag == "socks-in" and .listen == $listen and .listen_port == $port)
  ' "$tmp" >/dev/null || {
    rm -f "$tmp"
    die "socks-in inbound not found in /etc/sing-box/config.json"
  }
  sing-box check -c "$tmp"
  install -m 0644 "$tmp" /etc/sing-box/config.json
  rm -f "$tmp"

  SINGBOX_SOCKS_LISTEN=$listen
  SINGBOX_SOCKS_PORT=$port
  write_config_cmd
  systemctl restart sing-box
}

profile_outbound_tag() {
  case "$1" in
    ai) [[ "${AI_EGRESS_MODE:-ipsec}" == "xray" ]] && printf 'ai-xray\n' || printf 'ai-ipsec\n' ;;
    cn) [[ "${CN_EGRESS_MODE:-ipsec}" == "xray" ]] && printf 'cn-xray\n' || printf 'cn-ipsec\n' ;;
    *) die "profile must be ai or cn" ;;
  esac
}

xray_test_config_file() {
  local file=$1
  if command -v xray >/dev/null 2>&1; then
    xray run -test -format=json -config "$file"
  else
    python3 -m json.tool "$file" >/dev/null
    warn "xray binary is not installed; only JSON syntax was validated"
  fi
}

render_xray_config_cmd() {
  need_root
  [[ -x /usr/local/lib/dnscomplex-xray/render.py ]] || die "Xray renderer is missing"
  local tmp
  tmp=$(mktemp)
  /usr/local/lib/dnscomplex-xray/render.py --config "$CONFIG" --output "$tmp"
  xray_test_config_file "$tmp"
  install -m 0600 "$tmp" /usr/local/etc/xray/config.json
  rm -f "$tmp"
}

write_singbox_egress_cmd() {
  need_root
  command -v jq >/dev/null 2>&1 || die "jq is required"
  [[ -f /etc/sing-box/config.json ]] || die "/etc/sing-box/config.json is missing"
  local ai_out cn_out tmp
  ai_out=$(profile_outbound_tag ai)
  cn_out=$(profile_outbound_tag cn)
  tmp=$(mktemp)
  jq --arg ai "$ai_out" --arg cn "$cn_out" '
    (.route.rules[]? | select(.action == "route" and (.rule_set? | type == "string") and ((.rule_set | startswith("geosite-ai-")) or .rule_set == "geosite-ai-support")).outbound) = $ai |
    (.route.rules[]? | select(.action == "route" and .rule_set? == "geosite-cn-video").outbound) = $cn
  ' /etc/sing-box/config.json >"$tmp"
  sing-box check -c "$tmp"
  install -m 0644 "$tmp" /etc/sing-box/config.json
  rm -f "$tmp"
}

runtime_nft_prerouting_rules() {
  local lan_if=$1 profile=$2 set_name=$3 mark=$4 mode=$5
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
    iifname "$lan_if" ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop"
EOF
  else
    cat <<EOF
    iifname "$lan_if" ip daddr 255.255.255.255 meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop"
    iifname "$lan_if" ip daddr @$set_name meta l4proto { icmp, tcp, udp } ct mark set $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK meta mark set $mark counter comment "dnscomplex-${profile}-preroute"
EOF
  fi
}

runtime_nft_restore_rules() {
  local lan_if=$1 profile=$2 set_name=$3 mark=$4 mode=$5
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
    iifname "$lan_if" ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop-restore"
EOF
  else
    cat <<EOF
    iifname "$lan_if" ip daddr @$set_name meta l4proto { icmp, tcp, udp } meta mark set $mark counter comment "dnscomplex-${profile}-policy-restore"
EOF
  fi
}

runtime_nft_output_rules() {
  local profile=$1 set_name=$2 mark=$3 mode=$4
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
    ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop-output"
EOF
  else
    cat <<EOF
    ip daddr @$set_name meta l4proto { icmp, tcp, udp } meta mark set $mark
EOF
  fi
}

write_nftables_runtime_cmd() {
  need_root
  local lan_if="${WAN_IFACE}.${LAN_VLAN_ID:-}"
  [[ "$DEPLOY_MODE" == "routeros-policy" ]] && lan_if="$WAN_IFACE"
  mkdir -p /etc/nftables.d
  cat >/etc/nftables.d/dnscomplex.nft <<EOF
table inet dnscomplex {
  set ai4 {
    type ipv4_addr
    flags interval,timeout
    size 262144
  }

  set cn4 {
    type ipv4_addr
    flags interval,timeout
    size 262144
  }

  set known_doh4 {
    type ipv4_addr
    flags interval
    elements = { 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112, 223.5.5.5, 223.6.6.6, 119.29.29.29 }
  }

  chain dns_redirect {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "$lan_if" udp dport 53 redirect to :53
    iifname "$lan_if" tcp dport 53 redirect to :53
  }

  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname "$lan_if" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept
    iifname "$lan_if" udp dport { 784, 853, 8853 } drop
    iifname "$lan_if" tcp dport 853 drop
    iifname "$lan_if" ip daddr @known_doh4 tcp dport 443 drop
$(runtime_nft_prerouting_rules "$lan_if" ai ai4 "$AI_MARK" "$AI_EGRESS_MODE")
$(runtime_nft_prerouting_rules "$lan_if" cn cn4 "$CN_MARK" "$CN_EGRESS_MODE")
  }

  chain prerouting_policy_restore {
    type filter hook prerouting priority filter; policy accept;
    iifname "$lan_if" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept
$(runtime_nft_restore_rules "$lan_if" ai ai4 "$AI_MARK" "$AI_EGRESS_MODE")
$(runtime_nft_restore_rules "$lan_if" cn cn4 "$CN_MARK" "$CN_EGRESS_MODE")
  }

  chain forward {
    type filter hook forward priority filter; policy accept;
    tcp flags syn tcp option maxseg size set $IPSEC_TCP_MSS
  }

  chain output {
    type route hook output priority mangle; policy accept;
    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept
$(runtime_nft_output_rules ai ai4 "$AI_MARK" "$AI_EGRESS_MODE")
$(runtime_nft_output_rules cn cn4 "$CN_MARK" "$CN_EGRESS_MODE")
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
  }
}
EOF
  cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.nft"
EOF
  nft -c -f /etc/nftables.conf
  systemctl restart nftables || true
}

apply_egress_stack_cmd() {
  need_root
  render_xray_config_cmd
  write_singbox_egress_cmd
  write_nftables_runtime_cmd
  systemctl daemon-reload
  systemctl enable --now xray-dnscomplex 2>/dev/null || true
  systemctl restart xray-dnscomplex sing-box || true
  "$0" routes up || true
}

set_egress_cmd() {
  need_root
  [[ $# -eq 2 ]] || die "usage: dnscomplex set-egress ai|cn ipsec|xray"
  local profile=$1 mode=$2
  [[ "$mode" == "ipsec" || "$mode" == "xray" ]] || die "mode must be ipsec or xray"
  if [[ "$mode" == "xray" ]]; then
    case "$profile" in
      ai) [[ -n "${AI_XRAY_URI:-}" || -n "${AI_XRAY_OUTBOUND_JSON:-}" ]] || die "set Xray URI/JSON before switching AI to xray" ;;
      cn) [[ -n "${CN_XRAY_URI:-}" || -n "${CN_XRAY_OUTBOUND_JSON:-}" ]] || die "set Xray URI/JSON before switching CN to xray" ;;
      *) ;;
    esac
  fi
  case "$profile" in
    ai) AI_EGRESS_MODE=$mode ;;
    cn) CN_EGRESS_MODE=$mode ;;
    *) die "profile must be ai or cn" ;;
  esac
  write_config_cmd
  apply_egress_stack_cmd
}

set_xray_uri_cmd() {
  need_root
  [[ $# -eq 2 ]] || die "usage: dnscomplex set-xray-uri ai|cn URI"
  local profile=$1 uri=$2 tmp
  [[ "$profile" == "ai" || "$profile" == "cn" ]] || die "profile must be ai or cn"
  tmp=$(mktemp)
  /usr/local/lib/dnscomplex-xray/render.py --config "$CONFIG" --profile "$profile" --uri "$uri" --output "$tmp"
  xray_test_config_file "$tmp"
  rm -f "$tmp"
  case "$profile" in
    ai) AI_XRAY_URI=$uri; AI_XRAY_OUTBOUND_JSON="" ;;
    cn) CN_XRAY_URI=$uri; CN_XRAY_OUTBOUND_JSON="" ;;
  esac
  write_config_cmd
  apply_egress_stack_cmd
}

set_xray_json_cmd() {
  need_root
  [[ $# -eq 2 ]] || die "usage: dnscomplex set-xray-json ai|cn JSON_FILE"
  local profile=$1 file=$2 json tmp
  [[ "$profile" == "ai" || "$profile" == "cn" ]] || die "profile must be ai or cn"
  [[ -r "$file" ]] || die "JSON file not readable: $file"
  json=$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), separators=(",", ":")))' "$file")
  tmp=$(mktemp)
  /usr/local/lib/dnscomplex-xray/render.py --config "$CONFIG" --profile "$profile" --json "$json" --output "$tmp"
  xray_test_config_file "$tmp"
  rm -f "$tmp"
  case "$profile" in
    ai) AI_XRAY_OUTBOUND_JSON=$json; AI_XRAY_URI="" ;;
    cn) CN_XRAY_OUTBOUND_JSON=$json; CN_XRAY_URI="" ;;
  esac
  write_config_cmd
  apply_egress_stack_cmd
}

test_xray_cmd() {
  local profile=${1:-}
  case "$profile" in
    ""|ai|cn) ;;
    *) die "usage: dnscomplex test-xray [ai|cn]" ;;
  esac
  render_xray_config_cmd
  systemctl is-active --quiet xray-dnscomplex 2>/dev/null || warn "xray-dnscomplex.service is not active"
  if [[ -n "$profile" ]]; then
    local port
    [[ "$profile" == "ai" ]] && port=$XRAY_AI_SOCKS_PORT || port=$XRAY_CN_SOCKS_PORT
    if command -v curl >/dev/null 2>&1; then
      curl --socks5-hostname "$XRAY_LISTEN_HOST:$port" -4 -fsS --connect-timeout 6 -o /dev/null https://www.cloudflare.com/cdn-cgi/trace || \
        warn "Xray $profile local SOCKS connectivity probe failed"
    fi
  fi
}

xray_status_cmd() {
  printf 'xray_enabled=%s ai_egress=%s cn_egress=%s listen=%s ai_port=%s cn_port=%s\n' \
    "$XRAY_ENABLED" "$AI_EGRESS_MODE" "$CN_EGRESS_MODE" "$XRAY_LISTEN_HOST" "$XRAY_AI_SOCKS_PORT" "$XRAY_CN_SOCKS_PORT"
  print_unit_state xray-dnscomplex.service
  if command -v xray >/dev/null 2>&1; then
    xray version | head -n1
  fi
}

write_swanctl_cmd() {
  need_root
  local tmp local_ip="${LINUX_TRANSIT_IPV4:-}"
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    local_ip="$LINUX_LAN_IPV4"
  fi
  tmp=$(mktemp)
  cat >"$tmp" <<EOF
connections {
  ai {
    version = 2
    local_addrs = $local_ip
    remote_addrs = $AI_IPSEC_SERVER
    vips = 0.0.0.0
    proposals = aes256-sha256-modp2048,aes128-sha256-modp2048
    dpd_delay = 20s
    dpd_timeout = 90s
    rekey_time = 0s
    local {
      auth = eap-mschapv2
      eap_id = $AI_IPSEC_USERNAME
    }
    remote {
      auth = pubkey
      id = $IPSEC_REMOTE_ID
    }
    children {
      ai {
        local_ts = 0.0.0.0/0
        remote_ts = 0.0.0.0/0
        if_id_in = $AI_XFRM_ID
        if_id_out = $AI_XFRM_ID
        esp_proposals = aes256-sha256,aes128-sha256
        dpd_action = restart
        start_action = start
        close_action = restart
      }
    }
  }
  cn {
    version = 2
    local_addrs = $local_ip
    remote_addrs = $CN_IPSEC_SERVER
    vips = 0.0.0.0
    proposals = aes256-sha256-modp2048,aes128-sha256-modp2048
    dpd_delay = 20s
    dpd_timeout = 90s
    rekey_time = 0s
    local {
      auth = eap-mschapv2
      eap_id = $CN_IPSEC_USERNAME
    }
    remote {
      auth = pubkey
      id = $IPSEC_REMOTE_ID
    }
    children {
      cn {
        local_ts = 0.0.0.0/0
        remote_ts = 0.0.0.0/0
        if_id_in = $CN_XFRM_ID
        if_id_out = $CN_XFRM_ID
        esp_proposals = aes256-sha256,aes128-sha256
        dpd_action = restart
        start_action = start
        close_action = restart
      }
    }
  }
}

secrets {
  eap-ai {
    id = $AI_IPSEC_USERNAME
    secret = "$AI_IPSEC_PASSWORD"
  }
  eap-cn {
    id = $CN_IPSEC_USERNAME
    secret = "$CN_IPSEC_PASSWORD"
  }
}
EOF
  install -m 0600 "$tmp" /etc/swanctl/swanctl.conf
  rm -f "$tmp"
}

set_ipsec_cmd() {
  need_root
  [[ $# -eq 3 ]] || die "usage: dnscomplex set-ipsec ai|cn USER PASSWORD"
  local profile=$1
  local user=$2
  local pass=$3
  if [[ "$pass" == "-" ]]; then
    read -r -s -p "IPsec password: " pass
    printf '\n'
  fi
  [[ -n "$user" ]] || die "IPsec username cannot be empty"
  [[ -n "$pass" ]] || die "IPsec password cannot be empty"

  case "$profile" in
    ai)
      AI_IPSEC_USERNAME=$user
      AI_IPSEC_PASSWORD=$pass
      ;;
    cn)
      CN_IPSEC_USERNAME=$user
      CN_IPSEC_PASSWORD=$pass
      ;;
    *)
      die "profile must be ai or cn"
      ;;
  esac

  write_swanctl_cmd
  write_config_cmd
  swanctl --load-all --noprompt || restart_ipsec_service || true
  swanctl --initiate --child "$profile" || true
  "$0" routes up || true
}

json_escape() {
  jq -Rs . <<<"${1:-}" | sed 's/^"//; s/"$//'
}

validate_loaded_config() {
  local errors=0 ports port_seen="" port name cidr
  case "${DEPLOY_MODE:-}" in vlan-gateway|routeros-policy) ;; *) printf 'error: DEPLOY_MODE must be vlan-gateway or routeros-policy\n'; errors=$((errors + 1)) ;; esac
  case "${DEFAULT_DNS_STRATEGY:-prefer_ipv6}" in prefer_ipv4|prefer_ipv6) ;; *) printf 'error: DEFAULT_DNS_STRATEGY must be prefer_ipv4 or prefer_ipv6\n'; errors=$((errors + 1)) ;; esac
  case "${DEFAULT_IPV6_MODE:-auto}" in auto|on|off) ;; *) printf 'error: DEFAULT_IPV6_MODE must be auto, on, or off\n'; errors=$((errors + 1)) ;; esac
  case "${ADGUARD_DNS_CACHE_MODE:-off}" in off|small|large) ;; *) printf 'error: ADGUARD_DNS_CACHE_MODE must be off, small, or large\n'; errors=$((errors + 1)) ;; esac
  case "${DNSCOMPLEX_UPDATE_CHANNEL:-stable}" in stable|beta|pinned) ;; *) printf 'error: DNSCOMPLEX_UPDATE_CHANNEL must be stable, beta, or pinned\n'; errors=$((errors + 1)) ;; esac
  case "${GITHUB_RELEASE_POLICY:-latest}" in latest|pinned) ;; *) printf 'error: GITHUB_RELEASE_POLICY must be latest or pinned\n'; errors=$((errors + 1)) ;; esac
  if [[ "${DNSCOMPLEX_UPDATE_CHANNEL:-stable}" == "pinned" || "${GITHUB_RELEASE_POLICY:-latest}" == "pinned" ]]; then
    [[ -n "${DNSCOMPLEX_PINNED_VERSION:-}" ]] || { printf 'error: DNSCOMPLEX_PINNED_VERSION is required for pinned update policy\n'; errors=$((errors + 1)); }
  fi
  for name in SINGBOX_SOCKS_PORT SINGBOX_HTTP_PORT SINGBOX_DNS_PORT SMARTDNS_DEFAULT_PORT SMARTDNS_AI_PORT SMARTDNS_CN_PORT DNSCOMPLEX_WEB_PORT DNSCOMPLEX_METRICS_PORT XRAY_AI_SOCKS_PORT XRAY_CN_SOCKS_PORT; do
    port=${!name:-}
    [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] || { printf 'error: %s must be port 1-65535\n' "$name"; errors=$((errors + 1)); continue; }
    if grep -Eq "(^| )${port}( |$)" <<<"$port_seen"; then
      printf 'error: duplicate listen port %s around %s\n' "$port" "$name"
      errors=$((errors + 1))
    fi
    port_seen="$port_seen $port"
  done
  case "${AI_EGRESS_MODE:-ipsec}" in ipsec|xray) ;; *) printf 'error: AI_EGRESS_MODE must be ipsec or xray\n'; errors=$((errors + 1)) ;; esac
  case "${CN_EGRESS_MODE:-ipsec}" in ipsec|xray) ;; *) printf 'error: CN_EGRESS_MODE must be ipsec or xray\n'; errors=$((errors + 1)) ;; esac
  if [[ "${AI_EGRESS_MODE:-ipsec}" == "xray" ]]; then
    [[ -n "${AI_XRAY_URI:-}" || -n "${AI_XRAY_OUTBOUND_JSON:-}" ]] || { printf 'error: AI xray mode requires AI_XRAY_URI or AI_XRAY_OUTBOUND_JSON\n'; errors=$((errors + 1)); }
  fi
  if [[ "${CN_EGRESS_MODE:-ipsec}" == "xray" ]]; then
    [[ -n "${CN_XRAY_URI:-}" || -n "${CN_XRAY_OUTBOUND_JSON:-}" ]] || { printf 'error: CN xray mode requires CN_XRAY_URI or CN_XRAY_OUTBOUND_JSON\n'; errors=$((errors + 1)); }
  fi
  for cidr in "${LAN_IPV4_CIDR:-}" "${TRANSIT_IPV4_CIDR:-}" "${LAN_CLIENT_IPV4_CIDR:-}"; do
    [[ -z "$cidr" ]] && continue
    python3 - "$cidr" <<'PY' >/dev/null 2>&1 || { printf 'error: invalid IPv4 CIDR %s\n' "$cidr"; errors=$((errors + 1)); }
import ipaddress, sys
ipaddress.ip_interface(sys.argv[1])
PY
  done
  for cidr in "${LAN_IPV6_PREFIX:-}" "${TRANSIT_IPV6_CIDR:-}"; do
    [[ -z "$cidr" ]] && continue
    python3 - "$cidr" <<'PY' >/dev/null 2>&1 || { printf 'error: invalid IPv6 CIDR/prefix %s\n' "$cidr"; errors=$((errors + 1)); }
import ipaddress, sys
ipaddress.ip_network(sys.argv[1], strict=False)
PY
  done
  if [[ "${SMARTDNS_AI_PORT:-6054}" == "${SMARTDNS_CN_PORT:-6055}" ]]; then
    printf 'error: AI/CN SmartDNS ports must be different to preserve A-only nftset policy\n'
    errors=$((errors + 1))
  fi
  return "$errors"
}

validate_config_file_cmd() {
  local json=0 file output rc
  if [[ "${1:-}" == "--json" ]]; then
    json=1
    shift
  fi
  [[ $# -eq 1 ]] || die "usage: dnscomplex validate-config [--json] ENV_FILE"
  file=$1
  [[ -r "$file" ]] || die "config file not readable: $file"
  output=$(
    set +e
    # shellcheck source=/dev/null
    CONFIG="$file"
    load_config >/dev/null 2>&1
    validate_loaded_config
    printf '__RC__=%s\n' "$?"
  )
  rc=$(awk -F= '/^__RC__/ {print $2}' <<<"$output")
  output=$(sed '/^__RC__=/d' <<<"$output")
  rc=${rc:-1}
  if [[ "$json" == "1" ]]; then
    jq -n --argjson ok "$([[ "$rc" == "0" ]] && printf true || printf false)" --arg output "$output" '{ok:$ok, output:$output}'
  else
    if [[ "$rc" == "0" ]]; then
      printf 'config valid: %s\n' "$file"
    else
      printf '%s\n' "$output"
    fi
  fi
  return "$rc"
}

redact_stream() {
  python3 -c '
import re
import sys

text = sys.stdin.read()
patterns = [
    (r"(AI_IPSEC_USERNAME|CN_IPSEC_USERNAME|AI_IPSEC_PASSWORD|CN_IPSEC_PASSWORD|DNSCOMPLEX_WEB_PASSWORD|AI_XRAY_URI|CN_XRAY_URI|AI_XRAY_OUTBOUND_JSON|CN_XRAY_OUTBOUND_JSON|GITHUB_TOKEN|GH_TOKEN|TOKEN|USERNAME|PASSWORD|SECRET|PSK|COOKIE|SESSION)=([^\s]+)", r"\1=[REDACTED_SECRET]"),
    (r"(vless|vmess|trojan|ss)://[^\s]+", r"\1://[REDACTED_XRAY_URI]"),
    (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "[REDACTED_UUID]"),
    (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "[REDACTED_IPV4]"),
    (r"\bfd[0-9a-fA-F:]*:[0-9a-fA-F:]*\b", "[REDACTED_IPV6]"),
    (r"\b[\w.-]+\.local\b", "[REDACTED_HOSTNAME]"),
]
for pattern, repl in patterns:
    text = re.sub(pattern, repl, text)
sys.stdout.write(text)
'
}

render_config_cmd() {
  local redacted=0
  if [[ "${1:-}" == "--redacted" ]]; then
    redacted=1
    shift
  fi
  [[ $# -eq 0 ]] || die "usage: dnscomplex render-config [--redacted]"
  if [[ "$redacted" == "1" ]]; then
    cat "$CONFIG" | redact_stream
  else
    cat "$CONFIG"
  fi
}

wizard_cmd() {
  cat <<'EOF'
# dnscomplex wizard template
# Save this as config.env, fill the blanks, then run:
#   dnscomplex validate-config config.env
#   sudo bash install.sh --config config.env --yes
DNSCOMPLEX_NONINTERACTIVE=1
DEPLOY_MODE=routeros-policy
WAN_IFACE=eth0
ROUTEROS_LAN_IPV4=192.0.2.1
LINUX_LAN_IPV4=192.0.2.2
LAN_CLIENT_IPV4_CIDR=192.0.2.0/24
SINGBOX_SOCKS_LISTEN=192.0.2.2
SINGBOX_SOCKS_PORT=1080
DNSCOMPLEX_WEB_LISTEN=192.0.2.2
DNSCOMPLEX_WEB_PORT=8088
DNSCOMPLEX_UPDATE_CHANNEL=stable
GITHUB_RELEASE_POLICY=latest
AI_EGRESS_MODE=ipsec
CN_EGRESS_MODE=ipsec
AI_IPSEC_USERNAME=
AI_IPSEC_PASSWORD=
CN_IPSEC_USERNAME=
CN_IPSEC_PASSWORD=
EOF
}

support_bundle_cmd() {
  need_root
  local output="" include_logs=standard tmp
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output) output=${2:-}; shift 2 ;;
      --include-logs) include_logs=${2:-}; shift 2 ;;
      *) die "usage: dnscomplex support-bundle [--output PATH] [--include-logs minimal|standard|full]" ;;
    esac
  done
  case "$include_logs" in minimal|standard|full) ;; *) die "--include-logs must be minimal, standard, or full" ;; esac
  output=${output:-"/var/log/dnscomplex/support-bundle-$(date +%Y%m%d-%H%M%S).tar.gz"}
  tmp=$(mktemp -d)
  mkdir -p "$tmp/raw" "$tmp/redacted"
  {
    printf 'dnscomplex_version=%s\n' "${DNSCOMPLEX_VERSION:-unknown}"
    printf 'created_at=%s\n' "$(date -Is)"
    printf 'include_logs=%s\n' "$include_logs"
  } >"$tmp/raw/summary.txt"
  "$0" status --verbose >"$tmp/raw/status.txt" 2>&1 || true
  "$0" doctor >"$tmp/raw/doctor.txt" 2>&1 || true
  "$0" health --json >"$tmp/raw/health.json" 2>&1 || true
  for domain in openai.com claude.ai youku.com youtube.com example.com; do
    "$0" trace-domain "$domain" >"$tmp/raw/trace-$domain.txt" 2>&1 || true
  done
  systemctl --no-pager --plain status sing-box smartdns AdGuardHome xray-dnscomplex dnscomplex-web dnscomplex-metrics >"$tmp/raw/systemctl-status.txt" 2>&1 || true
  systemctl list-timers 'dnscomplex-*.timer' --no-pager >"$tmp/raw/timers.txt" 2>&1 || true
  nft list table inet dnscomplex >"$tmp/raw/nft-dnscomplex.txt" 2>&1 || true
  conntrack -S >"$tmp/raw/conntrack-stats.txt" 2>&1 || true
  "$0" metrics-sample >"$tmp/raw/metrics-sample.json" 2>&1 || true
  [[ -r "$BASE/routeros.rsc" ]] && cp "$BASE/routeros.rsc" "$tmp/raw/routeros.rsc"
  render_config_cmd --redacted >"$tmp/raw/config.env.redacted" 2>&1 || true
  if [[ "$include_logs" != "minimal" ]]; then
    journalctl -u dnscomplex-web -u dnscomplex-metrics -u sing-box -u smartdns -u AdGuardHome --since "24 hours ago" --no-pager >"$tmp/raw/journal.txt" 2>&1 || true
    [[ -r "${DNSCOMPLEX_UPDATE_LAST_LOG:-}" ]] && cp "$DNSCOMPLEX_UPDATE_LAST_LOG" "$tmp/raw/update-latest.log"
  fi
  if [[ "$include_logs" == "full" ]]; then
    ls -la /var/log/dnscomplex >"$tmp/raw/dnscomplex-log-list.txt" 2>&1 || true
  fi
  while IFS= read -r -d '' file; do
    rel=${file#"$tmp/raw/"}
    mkdir -p "$tmp/redacted/$(dirname "$rel")"
    redact_stream <"$file" >"$tmp/redacted/$rel"
  done < <(find "$tmp/raw" -type f -print0)
  mkdir -p "$(dirname "$output")"
  tar -czf "$output" -C "$tmp/redacted" .
  rm -rf "$tmp"
  log "support bundle written: $output"
}

install_smartdns_release() {
  local arch asset tmp
  arch=$(smartdns_arch)
  tmp=$(mktemp -d)
  asset=$(github_latest_asset_url "pymumu/smartdns" "${arch}-debian-all\\.deb$")
  curl -fsSL -o "$tmp/smartdns.deb" "$asset"
  DEBIAN_FRONTEND=noninteractive dpkg --force-confdef --force-confold -i "$tmp/smartdns.deb" || \
    DEBIAN_FRONTEND=noninteractive apt-get \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      -f install -y
  fix_smartdns_wrapper
  ensure_smartdns_enabled
  command -v smartdns >/dev/null || die "SmartDNS install did not provide smartdns binary"
  rm -rf "$tmp"
}

fix_smartdns_wrapper() {
  [[ -x /usr/local/lib/smartdns/run-smartdns ]] || die "SmartDNS wrapper missing: /usr/local/lib/smartdns/run-smartdns"
  ln -sfn /usr/local/lib/smartdns/run-smartdns /usr/sbin/smartdns
}

ensure_smartdns_enabled() {
  systemctl enable smartdns >/dev/null 2>&1 || true
}

install_singbox_release() {
  local arch asset tmp
  arch=$(linux_arch)
  tmp=$(mktemp -d)
  asset=$(github_latest_asset_url "SagerNet/sing-box" "sing-box_.*_linux_${arch}\\.deb$")
  curl -fsSL -o "$tmp/sing-box.deb" "$asset"
  DEBIAN_FRONTEND=noninteractive dpkg --force-confdef --force-confold -i "$tmp/sing-box.deb" || \
    DEBIAN_FRONTEND=noninteractive apt-get \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      -f install -y
  command -v sing-box >/dev/null || die "sing-box install did not provide sing-box binary"
  rm -rf "$tmp"
}

install_adguardhome_release() {
  local arch asset tmp
  arch=$(linux_arch)
  tmp=$(mktemp -d)
  asset=$(github_latest_asset_url "AdguardTeam/AdGuardHome" "AdGuardHome_linux_${arch}\\.tar\\.gz$")
  curl -fsSL -o "$tmp/AdGuardHome.tar.gz" "$asset"
  tar -xzf "$tmp/AdGuardHome.tar.gz" -C "$tmp"
  systemctl stop AdGuardHome 2>/dev/null || true
  install -d -m 0755 /opt/AdGuardHome
  install -m 0755 "$tmp/AdGuardHome/AdGuardHome" /opt/AdGuardHome/AdGuardHome
  /opt/AdGuardHome/AdGuardHome --version >/dev/null || die "AdGuard Home install did not provide a working executable"
  rm -rf "$tmp"
}

install_xray_release() {
  local asset tmp pattern
  tmp=$(mktemp -d)
  pattern=$(xray_asset_pattern)
  asset=$(github_latest_asset_url "XTLS/Xray-core" "$pattern")
  curl -fsSL -o "$tmp/xray.zip" "$asset"
  unzip -q "$tmp/xray.zip" -d "$tmp/xray"
  install -m 0755 "$tmp/xray/xray" /usr/local/bin/xray
  install -d -m 0755 /usr/local/share/xray
  [[ -f "$tmp/xray/geoip.dat" ]] && install -m 0644 "$tmp/xray/geoip.dat" /usr/local/share/xray/geoip.dat
  [[ -f "$tmp/xray/geosite.dat" ]] && install -m 0644 "$tmp/xray/geosite.dat" /usr/local/share/xray/geosite.dat
  command -v xray >/dev/null || die "Xray install did not provide xray binary"
  rm -rf "$tmp"
}

backup_release_binaries() {
  local dir=$1
  mkdir -p "$dir"
  for bin in sing-box smartdns xray; do
    if command -v "$bin" >/dev/null 2>&1; then
      cp -a "$(command -v "$bin")" "$dir/$bin"
    fi
  done
  if [[ -x /opt/AdGuardHome/AdGuardHome ]]; then
    cp -a /opt/AdGuardHome/AdGuardHome "$dir/AdGuardHome"
  fi
}

restore_release_binaries() {
  local dir=$1
  [[ -d "$dir" ]] || return 0
  [[ -f "$dir/sing-box" && -n "$(command -v sing-box 2>/dev/null || true)" ]] && install -m 0755 "$dir/sing-box" "$(command -v sing-box)"
  [[ -f "$dir/smartdns" && -n "$(command -v smartdns 2>/dev/null || true)" ]] && install -m 0755 "$dir/smartdns" "$(command -v smartdns)"
  [[ -f "$dir/xray" && -n "$(command -v xray 2>/dev/null || true)" ]] && install -m 0755 "$dir/xray" "$(command -v xray)"
  [[ -f "$dir/AdGuardHome" ]] && install -m 0755 "$dir/AdGuardHome" /opt/AdGuardHome/AdGuardHome
}

update_software_impl() {
  need_root
  local before
  UPDATED_SERVICES=()
  before=$(mktemp -d)
  update_software_stage "backup current config and release binaries"
  backup_cmd "$before/dnscomplex-pre-update.tar.gz"
  backup_release_binaries "$before/bin"
  export DEBIAN_FRONTEND=noninteractive
  update_software_stage "Debian apt update"
  apt-get update
  update_software_stage "Debian apt upgrade"
  apt-get \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    upgrade -y
  update_software_stage "GitHub release metadata and asset verification channel=${DNSCOMPLEX_UPDATE_CHANNEL:-stable} policy=${GITHUB_RELEASE_POLICY:-latest} pinned=${DNSCOMPLEX_PINNED_VERSION:-}"
  update_release_if_needed sing-box SagerNet/sing-box sing-box install_singbox_release
  update_release_if_needed smartdns pymumu/smartdns smartdns install_smartdns_release
  update_release_if_needed AdGuardHome AdguardTeam/AdGuardHome AdGuardHome install_adguardhome_release
  update_release_if_needed xray XTLS/Xray-core xray-dnscomplex install_xray_release
  update_software_stage "dnscomplex installer/schema validation"
  "$0" validate-config "$CONFIG"
  update_software_stage "config validation"
  if sing-box check -c /etc/sing-box/config.json && xray run -test -format=json -config /usr/local/etc/xray/config.json && nft -c -f /etc/nftables.conf; then
    if ((${#UPDATED_SERVICES[@]} > 0)); then
      update_software_stage "restart changed services: ${UPDATED_SERVICES[*]}"
      systemctl restart "${UPDATED_SERVICES[@]}"
    else
      update_software_stage "no GitHub component changed; no service restart needed"
    fi
    update_software_stage "post-update health validation"
    if "$0" test; then
      :
    else
      log "health validation failed after update; restoring backup"
      restore_release_binaries "$before/bin"
      restore_cmd "$before/dnscomplex-pre-update.tar.gz"
      rm -rf "$before"
      die "software update rolled back"
    fi
  else
    log "validation failed after update; restoring config backup"
    restore_release_binaries "$before/bin"
    restore_cmd "$before/dnscomplex-pre-update.tar.gz"
    rm -rf "$before"
    die "software update rolled back"
  fi
  rm -rf "$before"
}

update_software_cmd() {
  need_root
  local requested_channel="" requested_version=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --channel)
        requested_channel=${2:-}
        shift 2
        ;;
      --version)
        requested_version=${2:-}
        shift 2
        ;;
      *)
        die "usage: dnscomplex update-software [--channel stable|beta|pinned] [--version VERSION]"
        ;;
    esac
  done
  if [[ -n "$requested_channel" ]]; then
    case "$requested_channel" in stable|beta|pinned) ;; *) die "--channel must be stable, beta, or pinned" ;; esac
    DNSCOMPLEX_UPDATE_CHANNEL=$requested_channel
    [[ "$requested_channel" == "pinned" ]] && GITHUB_RELEASE_POLICY=pinned || GITHUB_RELEASE_POLICY=latest
  fi
  if [[ -n "$requested_version" ]]; then
    DNSCOMPLEX_PINNED_VERSION=$requested_version
    DNSCOMPLEX_UPDATE_CHANNEL=pinned
    GITHUB_RELEASE_POLICY=pinned
  fi
  if [[ "$DNSCOMPLEX_UPDATE_CHANNEL" == "pinned" || "$GITHUB_RELEASE_POLICY" == "pinned" ]]; then
    [[ -n "$DNSCOMPLEX_PINNED_VERSION" ]] || die "--version VERSION is required for pinned updates"
  fi
  write_config_cmd
  mkdir -p /var/log/dnscomplex
  local stamp_log log_file rc
  stamp_log="/var/log/dnscomplex/update-$(date +%Y%m%d-%H%M%S).log"
  log_file="${DNSCOMPLEX_UPDATE_LAST_LOG:-/var/log/dnscomplex/update-latest.log}"
  mkdir -p "$(dirname "$log_file")"
  set +e
  {
    set -e
    log "update log: $stamp_log"
    update_software_impl
    log "software update completed"
  } 2>&1 | tee "$stamp_log" "$log_file"
  rc=${PIPESTATUS[0]}
  set -e
  if [[ "$rc" != "0" ]]; then
    log "software update failed; see $stamp_log"
    return "$rc"
  fi
}

update_software_stage() {
  log "stage: $*"
}

routeros_print_cmd() {
  cat "$BASE/routeros.rsc"
}

metrics_sample_cmd() {
  if [[ -x /usr/local/lib/dnscomplex-metrics/exporter.py ]]; then
    /usr/local/lib/dnscomplex-metrics/exporter.py --sample
  else
    die "metrics exporter is not installed"
  fi
}

soak_trace_expect() {
  local domain=$1
  local expected=$2
  local output profile
  output=$("$0" trace-domain "$domain" 2>&1) || {
    printf 'trace failed domain=%s expected=%s\n%s\n' "$domain" "$expected" "$output"
    return 1
  }
  profile=$(awk -F= '$1 == "profile" {print $2; exit}' <<<"$output")
  if [[ "$profile" != "$expected" ]]; then
    printf 'trace mismatch domain=%s expected=%s actual=%s\n%s\n' "$domain" "$expected" "${profile:-missing}" "$output"
    return 1
  fi
  printf 'trace ok domain=%s profile=%s\n' "$domain" "$profile"
}

soak_local_hosts_check() {
  local host failures=0
  [[ -f /etc/dnscomplex/local-hosts ]] || return 0
  while IFS= read -r host; do
    [[ -n "$host" ]] || continue
    if ! dig +time=2 +tries=1 +short A "$host" @127.0.0.1 -p 53 | grep -Eq '^[0-9]+(\.[0-9]+){3}$'; then
      printf 'local-hosts idle-resume failed host=%s\n' "$host"
      failures=$((failures + 1))
    fi
  done < <(awk '$1 ~ /^[0-9]+(\.[0-9]+){3}$/ && $2 ~ /\./ {print $2}' /etc/dnscomplex/local-hosts)
  [[ "$failures" == "0" ]]
}

soak_idle_resume_check() {
  printf 'idle-resume nftset recovery start\n'
  flush_policy_nftsets_cmd
  refresh_nftsets_cmd
  soak_trace_expect chatgpt.com AI
  soak_trace_expect claude.ai AI
  soak_trace_expect meta.ai AI
  soak_trace_expect youku.com CN
  soak_trace_expect facebook.com default
  soak_trace_expect instagram.com default
  soak_trace_expect youtube.com default
  soak_local_hosts_check
  printf 'idle-resume nftset recovery done\n'
}

duration_to_seconds() {
  local value=$1 number unit
  if [[ "$value" =~ ^([0-9]+)([smhd]?)$ ]]; then
    number=${BASH_REMATCH[1]}
    unit=${BASH_REMATCH[2]:-s}
    case "$unit" in
      s) printf '%s\n' "$number" ;;
      m) printf '%s\n' "$((number * 60))" ;;
      h) printf '%s\n' "$((number * 3600))" ;;
      d) printf '%s\n' "$((number * 86400))" ;;
    esac
  else
    die "invalid duration: $value"
  fi
}

soak_cmd() {
  local duration=30m clients=1000 dns_qps=50 profiles=ai,cn,default idle_resume=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --duration) duration=$2; shift 2 ;;
      --clients) clients=$2; shift 2 ;;
      --dns-qps) dns_qps=$2; shift 2 ;;
      --profiles) profiles=$2; shift 2 ;;
      --idle-resume) idle_resume=1; shift ;;
      *) die "unknown soak option: $1" ;;
    esac
  done
  [[ "$clients" =~ ^[0-9]+$ ]] || die "--clients must be numeric"
  [[ "$dns_qps" =~ ^[0-9]+$ ]] || die "--dns-qps must be numeric"
  local seconds deadline log_file summary_file iter=0 failures=0 domains=(example.com openai.com claude.ai bilibili.com youku.com youtube.com)
  seconds=$(duration_to_seconds "$duration")
  mkdir -p /var/log/dnscomplex
  log_file="/var/log/dnscomplex/soak-$(date +%Y%m%d-%H%M%S).log"
  summary_file="${log_file%.log}.json"
  deadline=$((SECONDS + seconds))
  {
    printf 'start=%s duration=%s clients=%s dns_qps=%s profiles=%s idle_resume=%s\n' "$(date -Is)" "$duration" "$clients" "$dns_qps" "$profiles" "$idle_resume"
    if [[ "$idle_resume" == "1" ]]; then
      if ! soak_idle_resume_check; then
        failures=$((failures + 1))
      fi
    fi
    while ((SECONDS < deadline)); do
      iter=$((iter + 1))
      if ! "$0" health --json; then
        failures=$((failures + 1))
      fi
      for domain in "${domains[@]}"; do
        dig +time=2 +tries=1 +short A "$domain" @127.0.0.1 -p 53 >/dev/null 2>&1 || failures=$((failures + 1))
      done
      metrics_sample_cmd >/dev/null 2>&1 || true
      sleep 10
    done
    printf 'end=%s iterations=%s failures=%s\n' "$(date -Is)" "$iter" "$failures"
  } > >(tee "$log_file")
  printf '{"duration":"%s","clients":%s,"dns_qps":%s,"profiles":"%s","idle_resume":%s,"iterations":%s,"failures":%s,"log":"%s"}\n' \
    "$duration" "$clients" "$dns_qps" "$profiles" "$idle_resume" "$iter" "$failures" "$log_file" >"$summary_file"
  log "soak summary: $summary_file"
  [[ "$failures" == "0" ]]
}

backup_cmd() {
  need_root
  local output=${1:-"/var/backups/dnscomplex-$(date +%Y%m%d-%H%M%S).tar.gz"}
  mkdir -p "$(dirname "$output")"
  tar -czf "$output" \
    /etc/dnscomplex \
    /etc/sing-box \
    /etc/smartdns \
    /etc/AdGuardHome \
    /etc/swanctl \
    /etc/nftables.d/dnscomplex.nft \
    /var/lib/dnscomplex
  log "backup written: $output"
}

restore_cmd() {
  need_root
  [[ $# -eq 1 ]] || die "usage: dnscomplex restore INPUT_TAR_GZ"
  tar -xzf "$1" -C /
  fix_cmd
}

test_cmd() {
  local swan_log
  swan_log=$(mktemp)
  test_dns_cmd
  test_ipsec_cmd
  sing-box check -c /etc/sing-box/config.json
  xray run -test -format=json -config /usr/local/etc/xray/config.json
  nft -c -f /etc/nftables.conf
  if ! swanctl --load-all --noprompt >"$swan_log" 2>&1; then
    cat "$swan_log" >&2
    rm -f "$swan_log"
    die "swanctl configuration load failed"
  fi
  rm -f "$swan_log"
  log "dnscomplex tests completed"
}

main() {
  load_config
  local cmd=${1:-help}
  shift || true
  case "$cmd" in
    status) status_cmd "$@" ;;
    test) test_cmd "$@" ;;
    health) health_cmd "$@" ;;
    fix) fix_cmd "$@" ;;
    doctor) doctor_cmd "$@" ;;
    update-geosite) update_geosite_cmd "$@" ;;
    add-domain) add_domain_cmd "$@" ;;
    remove-domain) remove_domain_cmd "$@" ;;
    set-socks) set_socks_cmd "$@" ;;
    set-ipsec) set_ipsec_cmd "$@" ;;
    set-web-password) set_web_password_cmd "$@" ;;
    set-local-host) set_local_host_cmd "$@" ;;
    test-local-name) test_local_name_cmd "$@" ;;
    set-egress) set_egress_cmd "$@" ;;
    set-xray-uri) set_xray_uri_cmd "$@" ;;
    set-xray-json) set_xray_json_cmd "$@" ;;
    test-xray) test_xray_cmd "$@" ;;
    xray-status) xray_status_cmd "$@" ;;
    render-xray) render_xray_config_cmd "$@" ;;
    set-update-time) set_update_time_cmd "$@" ;;
    refresh-nftsets) refresh_nftsets_cmd "$@" ;;
    refresh-cn-overrides) refresh_cn_overrides_cmd "$@" ;;
    trace-domain) trace_domain_cmd "$@" ;;
    test-dns) test_dns_cmd "$@" ;;
    test-ipsec) test_ipsec_cmd "$@" ;;
    mss-calibrate) mss_calibrate_cmd "$@" ;;
    routeros-print) routeros_print_cmd "$@" ;;
    update-software) update_software_cmd "$@" ;;
    metrics-sample) metrics_sample_cmd "$@" ;;
    soak) soak_cmd "$@" ;;
    wizard) wizard_cmd "$@" ;;
    validate-config) validate_config_file_cmd "$@" ;;
    render-config) render_config_cmd "$@" ;;
    support-bundle) support_bundle_cmd "$@" ;;
    backup) backup_cmd "$@" ;;
    restore) restore_cmd "$@" ;;
    ipsec-ifaces) ipsec_ifaces_cmd "$@" ;;
    routes) routes_cmd "$@" ;;
    help|--help|-h) usage ;;
    *) usage; die "unknown command: $cmd" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
MANAGER
  chmod_target 0755 /usr/local/sbin/dnscomplex
}

render_metrics_exporter() {
  write_file /usr/local/lib/dnscomplex-metrics/exporter.py <<'PY'
#!/usr/bin/env python3
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG = "/etc/dnscomplex/config.env"
DB = "/var/lib/dnscomplex/metrics.sqlite3"
DNSCOMPLEX = "/usr/local/sbin/dnscomplex"

SERVICES = ["sing-box.service", "smartdns.service", "AdGuardHome.service", "nftables.service", "dnscomplex-web.service"]

def parse_config():
    data = {}
    if not os.path.exists(CONFIG):
        return data
    with open(CONFIG, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key] = value.strip().strip("'\"")
    return data

def run(args, timeout=5):
    try:
        return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        return subprocess.CompletedProcess(args, 1, "")

def service_up(name):
    return 1 if run(["systemctl", "is-active", "--quiet", name], 3).returncode == 0 else 0

def read_int(path, default=0):
    try:
        return int(open(path, "r", encoding="utf-8").read().strip())
    except Exception:
        return default

def dns_latency(domain):
    proc = run(["dig", "+time=2", "+tries=1", "+stats", "A", domain, "@127.0.0.1", "-p", "53"], 5)
    for line in proc.stdout.splitlines():
        if "Query time:" in line:
            try:
                return float(line.split()[3])
            except Exception:
                return 0.0
    return 0.0

def nft_count(set_name):
    proc = run(["nft", "list", "set", "inet", "dnscomplex", set_name], 5)
    return len(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", proc.stdout)))

def ipsec_up(child):
    return 1 if child + ":" in run(["swanctl", "--list-sas"], 5).stdout else 0

def adguard_cache_enabled():
    path = "/etc/AdGuardHome/AdGuardHome.yaml"
    enabled = 0
    size = 0
    try:
        for line in open(path, "r", encoding="utf-8", errors="replace"):
            if line.startswith("  cache_enabled:"):
                enabled = 1 if line.split(":", 1)[1].strip().lower() == "true" else 0
            if line.startswith("  cache_size:"):
                size = int(line.split(":", 1)[1].strip())
    except Exception:
        return 0
    return 1 if enabled or size > 0 else 0

def collect():
    cfg = parse_config()
    count = read_int("/proc/sys/net/netfilter/nf_conntrack_count")
    max_count = max(read_int("/proc/sys/net/netfilter/nf_conntrack_max", 1), 1)
    data = {
        "ts": int(time.time()),
        "conntrack_count": count,
        "conntrack_max": max_count,
        "conntrack_usage_ratio": count / max_count,
        "dns_latency_ms": dns_latency("example.com"),
        "ai_nftset_count": nft_count("ai4"),
        "cn_nftset_count": nft_count("cn4"),
        "ipsec_ai_up": ipsec_up("ai"),
        "ipsec_cn_up": ipsec_up("cn"),
        "adguard_cache_enabled": adguard_cache_enabled(),
        "ha_mode": cfg.get("HA_MODE", "single"),
    }
    for service in SERVICES:
        data["service_" + service.replace(".", "_").replace("-", "_")] = service_up(service)
    return data

def ensure_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    with sqlite3.connect(DB) as con:
        con.execute(
            "create table if not exists samples (ts integer primary key, conntrack_usage_ratio real, dns_latency_ms real, ai_nftset_count integer, cn_nftset_count integer, ipsec_ai_up integer, ipsec_cn_up integer, adguard_cache_enabled integer)"
        )

def sample():
    ensure_db()
    data = collect()
    with sqlite3.connect(DB) as con:
        con.execute(
            "insert or replace into samples values (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                data["ts"],
                data["conntrack_usage_ratio"],
                data["dns_latency_ms"],
                data["ai_nftset_count"],
                data["cn_nftset_count"],
                data["ipsec_ai_up"],
                data["ipsec_cn_up"],
                data["adguard_cache_enabled"],
            ),
        )
        con.execute("delete from samples where ts < ?", (data["ts"] - 7 * 86400,))
    return data

def prometheus_text():
    data = collect()
    lines = [
        "# HELP dnscomplex_conntrack_usage_ratio Conntrack usage ratio.",
        "# TYPE dnscomplex_conntrack_usage_ratio gauge",
        f"dnscomplex_conntrack_usage_ratio {data['conntrack_usage_ratio']}",
        "# HELP dnscomplex_dns_latency_ms Local DNS latency in milliseconds.",
        "# TYPE dnscomplex_dns_latency_ms gauge",
        f"dnscomplex_dns_latency_ms {data['dns_latency_ms']}",
        f"dnscomplex_nftset_entries{{profile=\"ai\"}} {data['ai_nftset_count']}",
        f"dnscomplex_nftset_entries{{profile=\"cn\"}} {data['cn_nftset_count']}",
        f"dnscomplex_ipsec_up{{profile=\"ai\"}} {data['ipsec_ai_up']}",
        f"dnscomplex_ipsec_up{{profile=\"cn\"}} {data['ipsec_cn_up']}",
        f"dnscomplex_adguard_cache_enabled {data['adguard_cache_enabled']}",
    ]
    for service in SERVICES:
        key = "service_" + service.replace(".", "_").replace("-", "_")
        lines.append(f"dnscomplex_service_up{{service=\"{service}\"}} {data[key]}")
    return "\n".join(lines) + "\n"

def health_ok():
    proc = run([DNSCOMPLEX, "health", "--json"], 12)
    return proc.returncode == 0, proc.stdout or "{}"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send(self, code, body, content_type):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/metrics":
            self.send(200, prometheus_text(), "text/plain; version=0.0.4; charset=utf-8")
            return
        if self.path == "/healthz":
            ok, body = health_ok()
            self.send(200 if ok else 503, body, "application/json; charset=utf-8")
            return
        if self.path == "/current":
            self.send(200, json.dumps(collect()), "application/json; charset=utf-8")
            return
        self.send(404, "not found\n", "text/plain; charset=utf-8")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--sample":
        print(json.dumps(sample(), ensure_ascii=False))
        return
    cfg = parse_config()
    listen = cfg.get("DNSCOMPLEX_METRICS_LISTEN", "0.0.0.0")
    port = int(cfg.get("DNSCOMPLEX_METRICS_PORT", "9108"))
    ThreadingHTTPServer((listen, port), Handler).serve_forever()

if __name__ == "__main__":
    main()
PY
  chmod_target 0755 /usr/local/lib/dnscomplex-metrics/exporter.py

  write_file /etc/systemd/system/dnscomplex-metrics.service <<'EOF'
[Unit]
Description=dnscomplex Prometheus metrics and RouterOS health endpoint
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/lib/dnscomplex-metrics/exporter.py
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  write_file /etc/systemd/system/dnscomplex-metrics-sample.service <<'EOF'
[Unit]
Description=Record dnscomplex metrics sample
After=network-online.target dnscomplex-metrics.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dnscomplex metrics-sample
EOF

  write_file /etc/systemd/system/dnscomplex-metrics-sample.timer <<'EOF'
[Unit]
Description=Sample dnscomplex metrics for management trends

[Timer]
OnBootSec=60s
OnUnitActiveSec=60s
AccuracySec=10s
Persistent=true
Unit=dnscomplex-metrics-sample.service

[Install]
WantedBy=timers.target
EOF

  write_file /etc/prometheus/dnscomplex.rules.yml <<'EOF'
groups:
  - name: dnscomplex
    rules:
      - alert: DnscomplexConntrackHigh
        expr: dnscomplex_conntrack_usage_ratio > 0.70
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: dnscomplex conntrack usage is high
      - alert: DnscomplexConntrackCritical
        expr: dnscomplex_conntrack_usage_ratio > 0.85
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: dnscomplex conntrack usage is critical
      - alert: DnscomplexDnsLatencyHigh
        expr: dnscomplex_dns_latency_ms > 500
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: dnscomplex DNS latency is high
      - alert: DnscomplexIpsecDown
        expr: dnscomplex_ipsec_up == 0
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: dnscomplex IPsec tunnel is down
      - alert: DnscomplexAdGuardCacheEnabled
        expr: dnscomplex_adguard_cache_enabled > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: AdGuard DNS cache is enabled; SmartDNS should be the cache authority
EOF
}

render_web_interface() {
  write_file /usr/local/lib/dnscomplex-web/app.py <<'PY'
#!/usr/bin/env python3
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG = "/etc/dnscomplex/config.env"
DNSCOMPLEX = "/usr/local/sbin/dnscomplex"

SERVICES = [
    "sing-box.service",
    "smartdns.service",
    "AdGuardHome.service",
    "strongswan-starter.service",
    "nftables.service",
    "xray-dnscomplex.service",
    "dnscomplex-health.timer",
    "dnscomplex-update.timer",
    "dnscomplex-cn-overrides.timer",
    "dnscomplex-nftset-refresh.timer",
    "dnscomplex-metrics.service",
    "dnscomplex-metrics-sample.timer",
    "dnscomplex-web.service",
]

CONFIG_KEYS = [
    "AI_IPSEC_SERVER",
    "CN_IPSEC_SERVER",
    "IPSEC_REMOTE_ID",
    "DEFAULT_DNS_UPSTREAMS",
    "DEFAULT_DNS_STRATEGY",
    "AI_DNS_UPSTREAMS",
    "CN_DNS_UPSTREAMS",
    "AI_GEOSITE_SOURCES",
    "AI_SUPPORT_DOMAINS",
    "AI_NFTSET_REFRESH_DOMAINS",
    "CN_VIDEO_SOURCES",
    "AI_SAMPLE_DOMAINS",
    "CN_SAMPLE_DOMAINS",
    "CN_NFTSET_REFRESH_DOMAINS",
    "CN_STATIC_A_OVERRIDES",
    "CN_OVERRIDE_PROBE_DOMAINS",
    "CN_OVERRIDE_PROBE_RESOLVERS",
    "SINGBOX_SOCKS_LISTEN",
    "SINGBOX_SOCKS_PORT",
    "SINGBOX_HTTP_LISTEN",
    "SINGBOX_HTTP_PORT",
    "XRAY_ENABLED",
    "XRAY_LISTEN_HOST",
    "XRAY_AI_SOCKS_PORT",
    "XRAY_CN_SOCKS_PORT",
    "AI_EGRESS_MODE",
    "CN_EGRESS_MODE",
    "AI_XRAY_URI",
    "CN_XRAY_URI",
    "AI_XRAY_OUTBOUND_JSON",
    "CN_XRAY_OUTBOUND_JSON",
    "DNSCOMPLEX_WEB_LISTEN",
    "DNSCOMPLEX_WEB_PORT",
    "DNSCOMPLEX_METRICS_LISTEN",
    "DNSCOMPLEX_METRICS_PORT",
    "DNSCOMPLEX_UPDATE_TIME",
    "DNSCOMPLEX_UPDATE_LAST_LOG",
    "DNSCOMPLEX_UPDATE_CHANNEL",
    "DNSCOMPLEX_PINNED_VERSION",
    "GITHUB_RELEASE_POLICY",
    "DNSCOMPLEX_NFTSET_REFRESH_INTERVAL",
    "DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT",
    "ADGUARD_DNS_CACHE_MODE",
    "HA_MODE",
    "HA_PRIMARY_IP",
    "HA_SECONDARY_IP",
    "HA_HEALTH_URL",
    "HA_FAILOVER_POLICY",
    "PROMETHEUS_MODE",
    "IPSEC_TCP_MSS",
    "APPLE_PRIVATE_RELAY_BLOCK",
]

SECRET_KEYS = {"AI_XRAY_URI", "CN_XRAY_URI", "AI_XRAY_OUTBOUND_JSON", "CN_XRAY_OUTBOUND_JSON"}
MASKED_SECRET = "********"

HTML = r"""<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>dnscomplex</title>
  <style>
    :root { color-scheme: light; --bg:#f6f7f9; --panel:#fff; --text:#17202a; --muted:#687385; --line:#d7dde6; --ok:#137a3a; --bad:#b42318; --warn:#9a6700; --accent:#0b5cad; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--text); }
    header { display:flex; align-items:flex-start; justify-content:space-between; gap:18px; padding:12px 20px; background:#ffffff; border-bottom:1px solid var(--line); position:sticky; top:0; z-index:2; }
    h1 { font-size:18px; margin:0; font-weight:700; }
    main { max-width:1380px; margin:0 auto; padding:18px; display:grid; gap:16px; }
    nav { display:flex; flex-wrap:wrap; gap:12px; justify-content:flex-end; }
    .nav-group { display:flex; align-items:center; gap:6px; border-left:1px solid var(--line); padding-left:12px; }
    .nav-group:first-child { border-left:0; padding-left:0; }
    .nav-label { color:var(--muted); font-size:12px; font-weight:700; }
    button, input, textarea, select { font:inherit; }
    button { border:1px solid var(--line); background:#fff; color:var(--text); border-radius:6px; padding:8px 11px; cursor:pointer; }
    button.primary { background:var(--accent); color:white; border-color:var(--accent); }
    button.danger { color:var(--bad); }
    section { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; }
    h2 { font-size:15px; margin:0 0 12px; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(270px, 1fr)); gap:12px; }
    .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .field { display:grid; gap:5px; margin-bottom:10px; }
    label { color:var(--muted); font-size:12px; }
    input, textarea, select { width:100%; border:1px solid var(--line); border-radius:6px; background:#fff; color:var(--text); padding:8px; }
    textarea { min-height:74px; resize:vertical; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .config-input-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); gap:12px 16px; margin-top:12px; }
    .config-input-grid .field { margin-bottom:0; }
    .config-input-grid label { overflow-wrap:anywhere; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { text-align:left; padding:8px; border-bottom:1px solid var(--line); vertical-align:top; }
    th { color:var(--muted); font-weight:600; }
    .status { display:inline-flex; align-items:center; gap:6px; }
    .dot { width:9px; height:9px; border-radius:50%; background:var(--muted); display:inline-block; }
    .active .dot { background:var(--ok); }
    .failed .dot, .inactive .dot { background:var(--bad); }
    .muted { color:var(--muted); }
    pre { margin:0; background:#0f1720; color:#dbe7ff; border-radius:8px; padding:12px; overflow:auto; max-height:420px; max-width:100%; font-size:12px; white-space:pre-wrap; overflow-wrap:anywhere; word-break:break-word; }
    .tabs { display:flex; gap:8px; flex-wrap:wrap; }
    .tabs button[aria-selected="true"] { background:#e9f2ff; border-color:#b7d4fa; color:#073b75; }
    .view { display:none; }
    .view.active { display:grid; gap:16px; }
    .summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; }
    .summary-card, .task-card, .profile-card { border:1px solid var(--line); border-radius:8px; background:#fff; padding:14px; }
    .summary-card strong { display:block; font-size:22px; margin-top:4px; }
    .summary-card small, .profile-card small { color:var(--muted); }
    .summary-card.ok { border-color:#b7e0c4; background:#f4fbf6; }
    .summary-card.warn { border-color:#f2d18b; background:#fff9e8; }
    .summary-card.bad { border-color:#efb4ad; background:#fff4f3; }
    .task-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; }
    .task-card { text-align:left; min-height:92px; }
    .task-card b { display:block; margin-bottom:5px; }
    .task-card span { color:var(--muted); font-size:13px; }
    .profile-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; }
    .profile-card h3 { margin:0 0 8px; font-size:16px; }
    .badge { display:inline-flex; align-items:center; border-radius:999px; padding:3px 8px; font-size:12px; border:1px solid var(--line); background:#f8fafc; }
    .badge.ok { color:var(--ok); border-color:#b7e0c4; background:#f4fbf6; }
    .badge.warn { color:var(--warn); border-color:#f2d18b; background:#fff9e8; }
    .badge.bad { color:var(--bad); border-color:#efb4ad; background:#fff4f3; }
    .warning-list { display:grid; gap:8px; }
    .warning-item { border-left:4px solid var(--warn); background:#fff9e8; padding:10px 12px; border-radius:6px; }
    .empty-state { color:var(--muted); border:1px dashed var(--line); border-radius:8px; padding:14px; }
    .section-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:12px; }
    .help-card { background:#f8fafc; border:1px solid var(--line); border-radius:8px; padding:12px; color:#334155; }
    .help-card h3 { margin:0 0 6px; font-size:14px; }
    .help-card p { margin:0; color:var(--muted); font-size:13px; line-height:1.45; }
    .mini-list { margin:8px 0 0; padding-left:18px; color:var(--muted); font-size:13px; line-height:1.55; }
    .domain-sections { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; }
    .domain-box { border:1px solid var(--line); border-radius:8px; padding:12px; background:#fff; }
    .domain-box h3 { margin:0 0 8px; font-size:14px; }
    .pill-list { display:flex; gap:6px; flex-wrap:wrap; }
    .pill { border:1px solid var(--line); border-radius:999px; padding:3px 8px; background:#f8fafc; font-size:12px; }
    .form-hint { color:var(--muted); font-size:12px; line-height:1.45; }
    .output-note { margin-top:10px; color:var(--muted); font-size:12px; }
    .config-advanced summary { cursor:pointer; color:var(--accent); font-weight:700; margin-bottom:10px; }
    @media (max-width: 760px) {
      header { position:static; display:grid; }
      nav { justify-content:flex-start; }
      .nav-group { width:100%; border-left:0; padding-left:0; flex-wrap:wrap; }
      button { min-height:38px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>dnscomplex</h1>
    <nav class="tabs">
      <div class="nav-group"><span class="nav-label">日常</span><button data-tab="overview" aria-selected="true">總覽</button><button data-tab="daily-test">上網測試</button><button data-tab="connections">活躍連線</button><button data-tab="traffic">流量趨勢</button></div>
      <div class="nav-group"><span class="nav-label">設定</span><button data-tab="dns">DNS 去廣告</button><button data-tab="split">AI/CN 分流</button><button data-tab="config">常用設定</button><button data-tab="wizard">精靈</button></div>
      <div class="nav-group"><span class="nav-label">進階</span><button data-tab="services">服務狀態</button><button data-tab="update">更新</button><button data-tab="diagnostics">診斷</button><button data-tab="maintenance">進階維護</button></div>
    </nav>
  </header>
  <main>
    <div id="overview" class="view active">
      <section>
        <div class="section-head"><h2>而家是否正常</h2><button onclick="refreshAll()">刷新</button></div>
        <div id="summaryCards" class="summary-grid"></div>
      </section>
      <section>
        <div class="section-head"><h2>需要處理</h2><button onclick="runAction('doctor')">執行 Doctor</button></div>
        <div id="warningList" class="warning-list"></div>
      </section>
      <section>
        <h2>我想做...</h2>
        <div id="taskGrid" class="task-grid">
          <button class="task-card" onclick="openTab('daily-test')"><b>測試手機上網</b><span>檢查 DNS、AI/CN、IPv6 同常見網站。</span></button>
          <button class="task-card" onclick="openTab('split')"><b>設定 AI / CN 出口</b><span>切換 IPsec 或 Xray，測試後先套用。</span></button>
          <button class="task-card" onclick="openTab('split')"><b>新增要分流的網站</b><span>加入 AI/CN domain 或 geosite/SRS。</span></button>
          <button class="task-card" onclick="openTab('config')"><b>修改 SOCKS / IPsec</b><span>管理接入地址、端口及帳密。</span></button>
          <button class="task-card" onclick="openTab('update')"><b>檢查更新</b><span>查看 stable/beta/pinned channel 和更新紀錄。</span></button>
          <button class="task-card" onclick="openTab('diagnostics')"><b>生成診斷包</b><span>一鍵產生已消㾗 support bundle。</span></button>
        </div>
      </section>
      <section>
        <h2>分流摘要</h2>
        <div id="profileCards" class="profile-grid"></div>
      </section>
    </div>
    <div id="daily-test" class="view">
      <section>
        <div class="section-head"><h2>上網測試</h2><button onclick="runAction('test')">完整測試</button></div>
        <div class="task-grid">
          <button class="task-card" onclick="runAction('test-dns')"><b>測試 DNS</b><span>確認 AdGuard + SmartDNS 回應正常。</span></button>
          <button class="task-card" onclick="runAction('test-ipsec')"><b>測試 AI/CN IPsec</b><span>確認分流隧道連線狀態。</span></button>
          <button class="task-card" onclick="runAction('refresh-nftsets')"><b>刷新分流 IP</b><span>修正手機閒置後 nftset 過期問題。</span></button>
          <button class="task-card" onclick="traceDomainValue('chatgpt.com')"><b>Trace ChatGPT</b><span>檢查 AI 分流路徑。</span></button>
          <button class="task-card" onclick="traceDomainValue('youku.com')"><b>Trace Youku</b><span>檢查 CN 分流路徑。</span></button>
          <button class="task-card" onclick="traceDomainValue('youtube.com')"><b>Trace YouTube</b><span>檢查 default / IPv6 路徑。</span></button>
        </div>
        <div class="row" style="margin-top:12px">
          <input id="quickTraceDomain" placeholder="輸入 domain，例如 claude.ai">
          <button onclick="traceDomainValue(quickTraceDomain.value)">Trace domain</button>
        </div>
      </section>
      <section><h2>測試輸出</h2><pre id="dailyOutput"></pre></section>
    </div>
    <div id="traffic" class="view">
      <section>
        <div class="row" style="justify-content:space-between"><h2>趨勢</h2><button onclick="loadMetrics()">刷新</button></div>
        <div class="grid">
          <canvas id="conntrackChart" height="160"></canvas>
          <canvas id="latencyChart" height="160"></canvas>
          <canvas id="profileChart" height="160"></canvas>
          <canvas id="ipsecChart" height="160"></canvas>
        </div>
      </section>
      <section><div class="row" style="justify-content:space-between"><h2>流量與 nft counters</h2><button onclick="loadTraffic()">刷新</button></div><pre id="trafficText"></pre></section>
    </div>
    <div id="connections" class="view">
      <section>
        <div class="row" style="justify-content:space-between"><h2>活躍連線</h2><button onclick="loadConnections()">刷新</button></div>
        <div id="connectionsTable"></div>
        <p class="muted">Domain 由 AdGuard DNS 查詢紀錄對應目的 IP；直接連 IP、外部 DoH、或不經 200VM 的流量會標示為 unknown/bypass。</p>
      </section>
    </div>
    <div id="dns" class="view">
      <section>
        <div class="section-head"><h2>DNS 去廣告</h2><button onclick="runAction('test-dns')">測試 DNS</button></div>
        <div id="dnsSummary" class="summary-grid"></div>
      </section>
      <section>
        <h2>常用操作</h2>
        <div class="task-grid">
          <button class="task-card" onclick="runAction('refresh-nftsets')"><b>刷新 AI/CN IP 快取</b><span>讓 SmartDNS 重新寫入 nftset。</span></button>
          <button class="task-card" onclick="runAction('refresh-cn-overrides')"><b>刷新 CN Override</b><span>重新探測 Youku 等 CN 特例 IP。</span></button>
          <button class="task-card" onclick="openTab('services')"><b>查看 SmartDNS / AdGuard</b><span>到進階頁檢查 service 狀態。</span></button>
        </div>
      </section>
    </div>
    <div id="split" class="view">
      <section>
        <div class="section-head"><h2>AI/CN 分流</h2><button onclick="loadUiSummary()">刷新摘要</button></div>
        <div id="splitProfileCards" class="profile-grid"></div>
      </section>
      <section>
        <h2>出口模式</h2>
        <div class="grid">
          <div>
            <h2>AI</h2>
            <div class="field"><label>出口模式</label><select id="aiEgressMode"><option value="ipsec">IPsec</option><option value="xray">Xray</option></select></div>
            <div class="field"><label>Xray URI</label><textarea id="aiXrayUri" placeholder="vless:// / vmess:// / trojan:// / ss://"></textarea></div>
            <div class="field"><label>Raw Xray outbound JSON</label><textarea id="aiXrayJson" placeholder='{"protocol":"vless",...}'></textarea></div>
            <div class="row"><button onclick="testEgress('ai')">測試 AI Xray</button><button class="primary" onclick="applyEgress('ai')">套用 AI 出口</button></div>
          </div>
          <div>
            <h2>CN</h2>
            <div class="field"><label>出口模式</label><select id="cnEgressMode"><option value="ipsec">IPsec</option><option value="xray">Xray</option></select></div>
            <div class="field"><label>Xray URI</label><textarea id="cnXrayUri" placeholder="vless:// / vmess:// / trojan:// / ss://"></textarea></div>
            <div class="field"><label>Raw Xray outbound JSON</label><textarea id="cnXrayJson" placeholder='{"protocol":"trojan",...}'></textarea></div>
            <div class="row"><button onclick="testEgress('cn')">測試 CN Xray</button><button class="primary" onclick="applyEgress('cn')">套用 CN 出口</button></div>
          </div>
        </div>
      </section>
      <section>
        <h2>Domain / Geosite</h2>
        <div class="help-card">
          <h3>點樣用</h3>
          <p>輸入 <b>domain</b> 例如 <code>example.com</code> 會加入自訂分流；輸入 <b>geosite source</b> 例如 <code>openai</code>、<code>anthropic</code>、<code>bilibili</code> 會加入或移除內建來源。Meta AI 預設只用 <code>meta.ai</code>；不要加入 <code>meta</code>，否則 Facebook/Instagram 也會走 AI 出口。</p>
          <ul class="mini-list">
            <li>AI：OpenAI / Claude / Meta 等，只回 IPv4，按出口模式走 IPsec 或 Xray。</li>
            <li>CN：Youku / Bilibili / iQiyi 等，只回 IPv4，按出口模式走 IPsec 或 Xray。</li>
            <li>唔確定生效未：輸入 domain 後按「Trace 生效路徑」。</li>
          </ul>
        </div>
        <div class="grid">
          <div class="field"><label>分類</label><select id="domainProfile"><option value="ai">AI</option><option value="cn">CN</option></select></div>
          <div class="field"><label>SRS source / geosite / domain</label><textarea id="domainValue" placeholder="例如 meta.ai 或 example.com；可逐行批量貼上"></textarea><div class="form-hint">Meta AI 用 meta.ai；如果見到 AI 內建來源有 meta，建議移除。</div></div>
        </div>
        <div class="row"><button class="primary" onclick="rulesDomain('add')">新增</button><button class="danger" onclick="rulesDomain('remove')">移除</button><button onclick="rulesRebuild()">只重建並套用 SRS</button><button onclick="traceDomainValue(domainValue.value.split(/\\s+/)[0])">Trace 生效路徑</button></div>
        <div class="output-note">操作結果會顯示在下方；成功後會自動刷新「目前清單」。</div>
      </section>
      <section><h2>目前清單</h2><div id="domainsStructured" class="domain-sections"></div><details style="margin-top:12px"><summary>查看原始檔案內容</summary><pre id="domainsText"></pre></details></section>
      <section><h2>操作結果</h2><pre id="splitOutput"></pre></section>
    </div>
    <div id="config" class="view">
      <section>
        <div class="section-head"><h2>常用設定</h2><button class="primary" onclick="saveConfig()">儲存進階 config 並修正設定</button></div>
        <div class="help-card">
          <h3>常用設定只放日常會改的項目</h3>
          <p>一般只需要改 SOCKS、IPsec 帳密、自動更新時間。完整 config.env 放在下方「進階原始 config」，未清楚用途前不要改。</p>
        </div>
      </section>
      <section>
        <div class="grid">
          <div>
            <h2>SOCKS 接入</h2>
            <p class="muted">供手機、Xray VM 或其他設備用 SOCKS 代理接入。</p>
            <div class="field"><label>Listen</label><input id="socksListen"></div>
            <div class="field"><label>Port</label><input id="socksPort"></div>
            <button onclick="setSocks()">更新 SOCKS</button>
          </div>
          <div>
            <h2>IPsec 帳密</h2>
            <p class="muted">只影響使用 IPsec 出口模式的 AI/CN profile。</p>
            <div class="field"><label>分類</label><select id="ipsecProfile"><option value="ai">AI</option><option value="cn">CN</option></select></div>
            <div class="field"><label>Username</label><input id="ipsecUser"></div>
            <div class="field"><label>Password</label><input id="ipsecPass" type="password"></div>
            <button onclick="setIpsec()">更新 IPsec</button>
          </div>
          <div>
            <h2>自動更新</h2>
            <p class="muted">每日保守更新 Debian 套件、GitHub release 同 geosite/SRS。</p>
            <div class="field"><label>每日時間 HH:MM</label><input id="updateTime"></div>
            <button onclick="setUpdateTime()">更新時間</button>
          </div>
          <div>
            <h2>管理界面帳號密碼</h2>
            <p class="muted">用戶名固定為 admin；修改後下一次操作需要重新登入。</p>
            <div class="field"><label>新密碼</label><input id="webPassword" type="password" autocomplete="new-password"></div>
            <button onclick="setWebPassword()">更新管理密碼</button>
          </div>
          <div>
            <h2>MSS 狀態</h2>
            <p class="muted">MSS 會寫入 config.env 及 nftables；按校準後兩邊會同步。</p>
            <div class="field"><label>目前 IPSEC_TCP_MSS</label><input id="mssCurrent" readonly></div>
            <button onclick="mssCalibrate()">校準並套用 MSS</button>
          </div>
          <div>
            <h2>本機 .local / Codex 連線</h2>
            <p class="muted">如果 Codex 手機 App 連本機 .local 名稱偶發失敗，可把 Mac 的 LAN IP 綁定到 .local 名稱。</p>
            <div class="field"><label>Host.local</label><input id="localHostName" placeholder="example-host.local"></div>
            <div class="field"><label>IPv4</label><input id="localHostIp" placeholder="192.0.2.10"></div>
            <div class="row"><button onclick="setLocalHost()">套用本機名稱</button><button onclick="testLocalName()">測試本機名稱</button></div>
          </div>
        </div>
      </section>
      <section><h2>操作結果</h2><pre id="configOutput"></pre></section>
      <section class="config-advanced">
        <details>
          <summary>進階原始 config.env</summary>
          <div id="configGroups" class="config-groups"></div>
        </details>
      </section>
    </div>
    <div id="services" class="view">
      <section>
        <div class="section-head"><h2>服務狀態</h2><button onclick="loadStatus()">刷新</button></div>
        <div id="servicesTable"></div>
      </section>
      <section><h2>IPsec / 路由摘要</h2><pre id="statusText"></pre></section>
    </div>
    <div id="wizard" class="view">
      <section>
        <div class="row" style="justify-content:space-between"><h2>安裝精靈 / 設定驗證器</h2><button onclick="loadWizardSchema()">載入 schema</button></div>
        <div class="help-card">
          <h3>用途</h3>
          <p>精靈會先驗證，不會直接覆蓋 production。新安裝或想整理 config 時，先貼上 config.env，按「驗證」，通過後才按「套用」。</p>
        </div>
        <div class="field"><label>config.env</label><textarea id="wizardConfig" placeholder="貼上 config.env，或按載入 schema 參考欄位"></textarea></div>
        <div class="row"><button onclick="validateWizard()">驗證</button><button class="primary" onclick="applyWizard()">套用</button></div>
        <pre id="wizardOutput"></pre>
      </section>
    </div>
    <div id="update" class="view">
      <section>
        <div class="row" style="justify-content:space-between"><h2>Release / Update Channel</h2><button onclick="loadUpdateStatus()">刷新</button></div>
        <div class="help-card">
          <h3>點樣揀</h3>
          <ul class="mini-list">
            <li><b>stable：一般使用</b>，只追最新穩定 release。</li>
            <li><b>beta</b>：追 prerelease，適合測試新功能。</li>
            <li><b>pinned</b>：固定版本，例如上一版最穩時使用；要填 Pinned version。</li>
          </ul>
        </div>
        <div class="grid">
          <div class="field"><label>Channel</label><select id="updateChannel"><option value="stable">stable</option><option value="beta">beta</option><option value="pinned">pinned</option></select></div>
          <div class="field"><label>Pinned version</label><input id="updateVersion" placeholder="例如 v1.2.3"></div>
        </div>
        <div class="row"><button class="primary" onclick="runUpdate()">執行更新</button></div>
        <pre id="updateOutput"></pre>
      </section>
    </div>
    <div id="diagnostics" class="view">
      <section>
        <h2>已消㾗診斷工單 / Support Bundle</h2>
        <div class="grid">
          <div class="field"><label>Log 範圍</label><select id="bundleLogs"><option value="standard">standard</option><option value="minimal">minimal</option><option value="full">full</option></select></div>
        </div>
        <div class="row"><button class="primary" onclick="supportBundle()">生成診斷包</button></div>
        <pre id="diagnosticsOutput"></pre>
      </section>
    </div>
    <div id="maintenance" class="view">
      <section>
        <h2>維護動作</h2>
        <div class="row">
          <button onclick="runAction('test')">測試</button>
          <button onclick="runAction('doctor')">Doctor</button>
          <button onclick="runAction('fix')">修正設定</button>
          <button onclick="runAction('test-dns')">測試 DNS</button>
          <button onclick="runAction('test-ipsec')">測試 IPsec</button>
          <button onclick="runAction('refresh-nftsets')">刷新 AI/CN IP 快取</button>
          <button onclick="runAction('refresh-cn-overrides')">刷新 CN Override</button>
          <button onclick="runAction('update-geosite')">更新 geosite/SRS</button>
          <button onclick="runAction('mss-calibrate')">MSS 校準</button>
          <button onclick="runAction('update-software')">更新 Debian / GitHub release</button>
          <button onclick="runAction('backup')">備份</button>
        </div>
        <div class="row" style="margin-top:12px">
          <input id="traceDomain" placeholder="trace-domain，例如 chatgpt.com">
          <button onclick="traceDomainAction()">Trace domain</button>
        </div>
      </section>
      <section><h2>輸出</h2><pre id="output"></pre></section>
    </div>
  </main>
<script>
const configKeys = CONFIG_KEYS_PLACEHOLDER;
function openTab(tab) {
  document.querySelectorAll('.tabs button').forEach(b => b.setAttribute('aria-selected','false'));
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const btn = document.querySelector(`.tabs button[data-tab="${tab}"]`);
  if (btn) btn.setAttribute('aria-selected','true');
  const view = document.getElementById(tab);
  if (view) view.classList.add('active');
}
document.querySelectorAll('.tabs button').forEach(btn => btn.addEventListener('click', () => {
  openTab(btn.dataset.tab);
}));
async function api(path, opts={}) {
  const res = await fetch(path, Object.assign({headers:{'content-type':'application/json'}}, opts));
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
function escapeHtml(value) {
  return String(value || '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
function outputText(data) {
  return typeof data === 'string' ? data : JSON.stringify(data, null, 2);
}
function writeOutput(target, data) {
  const node = typeof target === 'string' ? document.getElementById(target) : target;
  if (node) node.textContent = outputText(data);
}
function activeOutputTarget() {
  if (document.getElementById('daily-test')?.classList.contains('active')) return 'dailyOutput';
  if (document.getElementById('split')?.classList.contains('active')) return 'splitOutput';
  if (document.getElementById('config')?.classList.contains('active')) return 'configOutput';
  if (document.getElementById('wizard')?.classList.contains('active')) return 'wizardOutput';
  if (document.getElementById('update')?.classList.contains('active')) return 'updateOutput';
  if (document.getElementById('diagnostics')?.classList.contains('active')) return 'diagnosticsOutput';
  return 'output';
}
function showOutput(data) { writeOutput('output', data); }
function setPanelOutput(data, target='output') {
  const text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  writeOutput(target, text);
  writeOutput('output', text);
  const daily = document.getElementById('dailyOutput');
  if (daily) daily.textContent = text;
}
async function runWithOutput(target, task) {
  writeOutput(target, '處理中...');
  try {
    const data = await task();
    writeOutput(target, data);
    return data;
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    writeOutput(target, '操作失敗：\n' + message);
    return {ok:false, output:message};
  }
}
function badgeClass(state) {
  if (state === 'ok' || state === true || state === '正常' || state === 'active') return 'ok';
  if (state === 'bad' || state === false || state === '異常' || state === 'failed') return 'bad';
  return 'warn';
}
function renderSummaryCards(cards) {
  const host = document.getElementById('summaryCards');
  host.innerHTML = (cards || []).map(card => `<div class="summary-card ${badgeClass(card.state)}"><small>${card.label}</small><strong>${card.value}</strong><small>${card.detail || ''}</small></div>`).join('');
}
function renderWarnings(warnings) {
  const host = document.getElementById('warningList');
  if (!warnings || !warnings.length) {
    host.innerHTML = '<div class="empty-state">暫時無需要處理的問題。</div>';
    return;
  }
  host.innerHTML = warnings.map(w => `<div class="warning-item"><b>${escapeHtml(w.title)}</b><br><span>${escapeHtml(w.detail)}</span>${w.next ? `<br><small><b>建議下一步：</b>${escapeHtml(w.next)}</small>` : ''}</div>`).join('');
}
function renderProfiles(profiles, target='profileCards') {
  const host = document.getElementById(target);
  if (!host) return;
  host.innerHTML = (profiles || []).map(p => `<div class="profile-card"><h3>${p.name}</h3><div class="row"><span class="badge ${badgeClass(p.state)}">${p.status}</span><span class="badge">${p.egress}</span><span class="badge">${p.ip_policy}</span></div><p class="muted">${p.dns_policy}</p><small>${p.detail || ''}</small></div>`).join('');
}
function renderDnsSummary(data) {
  const host = document.getElementById('dnsSummary');
  if (!host) return;
  const cards = [
    {label:'DNS 去廣告', value:data.adguard || '未知', detail:'AdGuard Home 負責過濾同 querylog', state:data.adguard_state || 'warn'},
    {label:'DNS Cache', value:data.cache || 'SmartDNS', detail:'SmartDNS 作唯一 cache 權威', state:data.cache_state || 'ok'},
    {label:'AI/CN DNS', value:'只回 IPv4', detail:'避免 AI/CN AAAA 外洩', state:'ok'},
    {label:'Default DNS', value:'IPv4 + IPv6', detail:'default 才同時支援 A/AAAA', state:'ok'}
  ];
  host.innerHTML = cards.map(card => `<div class="summary-card ${badgeClass(card.state)}"><small>${card.label}</small><strong>${card.value}</strong><small>${card.detail}</small></div>`).join('');
}
async function loadUiSummary() {
  const data = await api('/api/ui/summary');
  renderSummaryCards(data.cards);
  renderWarnings(data.warnings);
  renderProfiles(data.profiles, 'profileCards');
  renderProfiles(data.profiles, 'splitProfileCards');
  renderDnsSummary(data.dns || {});
}
async function loadStatus() {
  const data = await api('/api/status');
  document.getElementById('servicesTable').innerHTML = '<table><thead><tr><th>服務</th><th>狀態</th><th>啟用</th></tr></thead><tbody>' + data.services.map(s => `<tr><td>${s.name}</td><td><span class="status ${s.active}"><span class="dot"></span>${s.active}</span></td><td>${s.enabled}</td></tr>`).join('') + '</tbody></table>';
  document.getElementById('statusText').textContent = data.summary;
}
async function loadTraffic() {
  const data = await api('/api/traffic');
  document.getElementById('trafficText').textContent = data.text;
}
function drawChart(id, points, key, label, color) {
  const canvas = document.getElementById(id);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.clientWidth || 320;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = '#f8fafc';
  ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = '#d7dde6';
  ctx.strokeRect(0.5, 0.5, w - 1, h - 1);
  ctx.fillStyle = '#17202a';
  ctx.font = '12px system-ui';
  ctx.fillText(label, 10, 18);
  if (!points.length) return;
  const vals = points.map(p => Number(p[key]) || 0);
  const max = Math.max(...vals, 1);
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.beginPath();
  vals.forEach((v, i) => {
    const x = 10 + (w - 20) * (points.length === 1 ? 0 : i / (points.length - 1));
    const y = h - 12 - (h - 38) * (v / max);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.fillStyle = '#687385';
  ctx.fillText(String(vals[vals.length - 1].toFixed ? vals[vals.length - 1].toFixed(2) : vals[vals.length - 1]), 10, h - 10);
}
async function loadMetrics() {
  const data = await api('/api/metrics/history');
  const points = data.samples || [];
  drawChart('conntrackChart', points, 'conntrack_usage_ratio', 'conntrack usage', '#0b5cad');
  drawChart('latencyChart', points, 'dns_latency_ms', 'DNS latency ms', '#9a6700');
  drawChart('profileChart', points, 'ai_nftset_count', 'AI nftset entries', '#137a3a');
  drawChart('ipsecChart', points, 'ipsec_ai_up', 'AI IPsec up', '#b42318');
}
async function loadConnections() {
  const data = await api('/api/connections');
  const rows = data.connections.map(c => `<tr><td>${c.client}</td><td>${c.domain || '<span class="muted">(unknown)</span>'}</td><td>${c.domain_source}</td><td>${c.destination}</td><td>${c.protocol}</td><td>${c.ip_version}</td><td>${c.profile}</td><td>${c.profile_source}</td><td>${c.state}</td></tr>`).join('');
  document.getElementById('connectionsTable').innerHTML = `<table><thead><tr><th>Client</th><th>Domain</th><th>Domain source</th><th>Destination</th><th>Proto</th><th>IP</th><th>出口</th><th>判斷來源</th><th>狀態</th></tr></thead><tbody>${rows || '<tr><td colspan="9" class="muted">沒有活躍連線</td></tr>'}</tbody></table>`;
}
async function loadConfig() {
  const data = await api('/api/config');
  renderConfigGroups(data);
  document.getElementById('socksListen').value = data.SINGBOX_SOCKS_LISTEN || '';
  document.getElementById('socksPort').value = data.SINGBOX_SOCKS_PORT || '';
  document.getElementById('updateTime').value = data.DNSCOMPLEX_UPDATE_TIME || '';
  document.getElementById('mssCurrent').value = data.IPSEC_TCP_MSS || '';
  aiEgressMode.value = data.AI_EGRESS_MODE || 'ipsec';
  cnEgressMode.value = data.CN_EGRESS_MODE || 'ipsec';
  aiXrayUri.value = data.AI_XRAY_URI || '';
  cnXrayUri.value = data.CN_XRAY_URI || '';
  aiXrayJson.value = data.AI_XRAY_OUTBOUND_JSON || '';
  cnXrayJson.value = data.CN_XRAY_OUTBOUND_JSON || '';
}
function configGroupName(key) {
  if (key.includes('IPSEC') || key.includes('MSS')) return 'IPsec / MSS';
  if (key.includes('DNS') || key.includes('SMARTDNS') || key.includes('ADGUARD')) return 'DNS / 去廣告';
  if (key.includes('XRAY') || key.includes('EGRESS')) return 'Xray / 出口模式';
  if (key.includes('GEOSITE') || key.includes('NFTSET') || key.includes('SAMPLE') || key.includes('SUPPORT')) return '分流清單';
  if (key.includes('SOCKS') || key.includes('HTTP') || key.includes('WEB')) return '接入 / 管理界面';
  if (key.includes('UPDATE') || key.includes('GITHUB')) return '更新';
  if (key.includes('HA_') || key.includes('PROMETHEUS') || key.includes('METRICS')) return 'HA / 監控';
  if (key.includes('LAN') || key.includes('WAN') || key.includes('ROUTEROS') || key.includes('TRANSIT')) return '網絡 / RouterOS';
  return '進階';
}
function renderConfigGroups(data) {
  const host = document.getElementById('configGroups');
  if (!host) return;
  const groups = {};
  configKeys.forEach(key => {
    const group = configGroupName(key);
    if (!groups[group]) groups[group] = [];
    groups[group].push(key);
  });
  host.innerHTML = '';
  Object.entries(groups).forEach(([name, keys]) => {
    const details = document.createElement('details');
    details.className = 'domain-box';
    const summary = document.createElement('summary');
    summary.textContent = name;
    details.appendChild(summary);

    const grid = document.createElement('div');
    grid.className = 'config-input-grid';
    keys.forEach(key => {
      const wrap = document.createElement('div');
      wrap.className = 'field';
      const label = document.createElement('label');
      label.textContent = key;
      const value = data[key] || '';
      const input = document.createElement(value.length > 70 ? 'textarea' : 'input');
      input.id = 'cfg_' + key;
      input.setAttribute('data-config-key', key);
      input.value = value;
      wrap.appendChild(label);
      wrap.appendChild(input);
      grid.appendChild(wrap);
    });
    details.appendChild(grid);
    host.appendChild(details);
  });
}
async function loadDomains() {
  const data = await api('/api/domains');
  document.getElementById('domainsText').textContent = data.text;
  renderDomainSections(data.sections || []);
}
function renderDomainSections(sections) {
  const host = document.getElementById('domainsStructured');
  if (!host) return;
  host.innerHTML = (sections || []).map(section => {
    const items = (section.items || []).length ? section.items.map(item => `<span class="pill">${escapeHtml(item)}</span>`).join('') : '<span class="muted">(空)</span>';
    return `<div class="domain-box"><h3>${escapeHtml(section.title)}</h3><p class="muted">${escapeHtml(section.help || '')}</p><div class="pill-list">${items}</div></div>`;
  }).join('');
}
async function saveConfig() {
  const payload = {};
  document.querySelectorAll('[data-config-key]').forEach(input => {
    payload[input.getAttribute('data-config-key')] = input.value;
  });
  await runWithOutput('configOutput', () => api('/api/config', {method:'POST', body: JSON.stringify(payload)}));
  await refreshAll();
}
async function runAction(action) {
  await runWithOutput(activeOutputTarget(), () => api('/api/action', {method:'POST', body: JSON.stringify({action})}));
  await refreshAll();
}
async function domainAction(action) {
  await runWithOutput('splitOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action, profile:domainProfile.value, value:domainValue.value})}));
  await refreshAll();
}
async function rulesDomain(action) {
  await runWithOutput('splitOutput', () => api('/api/rules/domain', {method:'POST', body: JSON.stringify({action, profile:domainProfile.value, value:domainValue.value})}));
  await refreshAll();
}
async function rulesRebuild() {
  await runWithOutput('splitOutput', () => api('/api/rules/rebuild', {method:'POST', body: JSON.stringify({})}));
  await refreshAll();
}
async function testEgress(profile) {
  const upper = profile === 'ai' ? 'ai' : 'cn';
  await runWithOutput('splitOutput', () => api('/api/egress/test', {method:'POST', body: JSON.stringify({
    profile,
    uri: document.getElementById(upper + 'XrayUri').value,
    outbound_json: document.getElementById(upper + 'XrayJson').value
  })}));
}
async function applyEgress(profile) {
  const upper = profile === 'ai' ? 'ai' : 'cn';
  await runWithOutput('splitOutput', () => api('/api/egress/apply', {method:'POST', body: JSON.stringify({
    profile,
    mode: document.getElementById(upper + 'EgressMode').value,
    uri: document.getElementById(upper + 'XrayUri').value,
    outbound_json: document.getElementById(upper + 'XrayJson').value
  })}));
  await refreshAll();
}
async function setSocks() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'set-socks', listen:socksListen.value, port:socksPort.value})}));
  await refreshAll();
}
async function setIpsec() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'set-ipsec', profile:ipsecProfile.value, user:ipsecUser.value, password:ipsecPass.value})}));
}
async function setUpdateTime() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'set-update-time', value:updateTime.value})}));
  await refreshAll();
}
async function setWebPassword() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'set-web-password', password:webPassword.value})}));
  webPassword.value = '';
}
async function mssCalibrate() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'mss-calibrate'})}));
  await refreshAll();
}
async function setLocalHost() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'set-local-host', host:localHostName.value, ip:localHostIp.value})}));
}
async function testLocalName() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'test-local-name', host:localHostName.value})}));
}
async function traceDomainAction() {
  await runWithOutput('output', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'trace-domain', value:traceDomain.value})}));
}
async function traceDomainValue(value) {
  if (!value) return;
  const target = document.getElementById('splitOutput') && document.getElementById('split').classList.contains('active') ? 'splitOutput' : 'dailyOutput';
  await runWithOutput(target, () => api('/api/action', {method:'POST', body: JSON.stringify({action:'trace-domain', value})}));
}
async function loadWizardSchema() {
  const data = await runWithOutput('wizardOutput', () => api('/api/wizard/schema'));
  if (!wizardConfig.value) wizardConfig.value = data.template || '';
}
async function validateWizard() {
  await runWithOutput('wizardOutput', () => api('/api/wizard/validate', {method:'POST', body: JSON.stringify({config:wizardConfig.value})}));
}
async function applyWizard() {
  await runWithOutput('wizardOutput', () => api('/api/wizard/apply', {method:'POST', body: JSON.stringify({config:wizardConfig.value})}));
  await refreshAll();
}
async function loadUpdateStatus() {
  const data = await runWithOutput('updateOutput', () => api('/api/update/status'));
  updateChannel.value = data.channel || 'stable';
  updateVersion.value = data.pinned_version || '';
}
async function runUpdate() {
  await runWithOutput('updateOutput', () => api('/api/update/run', {method:'POST', body: JSON.stringify({channel:updateChannel.value, version:updateVersion.value})}));
  await refreshAll();
}
async function supportBundle() {
  await runWithOutput('diagnosticsOutput', () => api('/api/support-bundle', {method:'POST', body: JSON.stringify({include_logs:bundleLogs.value})}));
}
async function refreshAll() { await Promise.all([loadUiSummary(), loadStatus(), loadTraffic(), loadConnections(), loadConfig(), loadDomains(), loadMetrics()]); }
refreshAll().catch(err => showOutput(String(err)));
</script>
</body>
</html>"""

def parse_config():
    data = {}
    if not os.path.exists(CONFIG):
        return data
    with open(CONFIG, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            try:
                data[key] = shlex.split(value, posix=True)[0] if value else ""
            except ValueError:
                data[key] = value.strip("'\"")
    return data

def quote_value(value):
    return "'" + str(value).replace("'", "'\\''") + "'"

def write_config(updated):
    current = parse_config()
    for k, v in updated.items():
        if k not in CONFIG_KEYS:
            continue
        value = str(v)
        if k in SECRET_KEYS and value == MASKED_SECRET:
            continue
        current[k] = value
    lines = []
    seen = set()
    if os.path.exists(CONFIG):
        with open(CONFIG, "r", encoding="utf-8") as fh:
            for raw in fh:
                if "=" in raw and not raw.lstrip().startswith("#"):
                    key = raw.split("=", 1)[0].strip()
                    if key in current:
                        lines.append(f"{key}={quote_value(current[key])}\n")
                        seen.add(key)
                        continue
                lines.append(raw)
    for key in CONFIG_KEYS:
        if key in current and key not in seen:
            lines.append(f"{key}={quote_value(current[key])}\n")
    tmp = CONFIG + ".webtmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG)

def safe_config():
    cfg = parse_config()
    safe = {}
    for key in CONFIG_KEYS:
        value = cfg.get(key, "")
        if key in SECRET_KEYS and value:
            safe[key] = MASKED_SECRET
        else:
            safe[key] = value
    return safe

def redact_text(text):
    patterns = [
        (r"(AI_IPSEC_USERNAME|CN_IPSEC_USERNAME|AI_IPSEC_PASSWORD|CN_IPSEC_PASSWORD|DNSCOMPLEX_WEB_PASSWORD|AI_XRAY_URI|CN_XRAY_URI|AI_XRAY_OUTBOUND_JSON|CN_XRAY_OUTBOUND_JSON|GITHUB_TOKEN|GH_TOKEN|TOKEN|USERNAME|PASSWORD|SECRET|PSK|COOKIE|SESSION)=([^\s]+)", r"\1=[REDACTED_SECRET]"),
        (r"(vless|vmess|trojan|ss)://[^\s]+", r"\1://[REDACTED_XRAY_URI]"),
        (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "[REDACTED_UUID]"),
        (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "[REDACTED_IPV4]"),
        (r"\b(?:10|127)\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b", "[REDACTED_IPV4]"),
        (r"\b172\.(?:1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}\b", "[REDACTED_IPV4]"),
        (r"\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b", "[REDACTED_IPV4]"),
        (r"\bfd[0-9a-fA-F:]*:[0-9a-fA-F:]*\b", "[REDACTED_IPV6]"),
        (r"\b[\w.-]+\.local\b", "[REDACTED_HOSTNAME]"),
    ]
    redacted = text
    for pattern, repl in patterns:
        redacted = re.sub(pattern, repl, redacted)
    return redacted

def wizard_template():
    return shell_output([DNSCOMPLEX, "wizard"], 10)

def wizard_schema():
    return {
        "profiles": ["ai", "cn", "default"],
        "deploy_modes": ["routeros-policy", "vlan-gateway"],
        "egress_modes": ["ipsec", "xray"],
        "update_channels": ["stable", "beta", "pinned"],
        "required_routeros_policy": ["WAN_IFACE", "ROUTEROS_LAN_IPV4", "LINUX_LAN_IPV4", "LAN_CLIENT_IPV4_CIDR"],
        "required_ipsec": ["AI_IPSEC_USERNAME", "AI_IPSEC_PASSWORD", "CN_IPSEC_USERNAME", "CN_IPSEC_PASSWORD"],
        "template": wizard_template(),
    }

def validate_config_text(text):
    with tempfile.NamedTemporaryFile("w+", delete=False) as fh:
        fh.write(text)
        path = fh.name
    try:
        return run([DNSCOMPLEX, "validate-config", "--json", path], 60)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

def apply_config_text(text):
    validation = validate_config_text(text)
    if not validation.get("ok"):
        return {"ok": False, "code": validation.get("code", 1), "output": validation.get("output", "")}
    tmp = CONFIG + ".wizardtmp"
    backup = CONFIG + ".wizardbak"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        if not text.endswith("\n"):
            fh.write("\n")
    os.chmod(tmp, 0o600)
    if os.path.exists(CONFIG):
        with open(CONFIG, "r", encoding="utf-8", errors="replace") as src, open(backup, "w", encoding="utf-8") as dst:
            dst.write(src.read())
        os.chmod(backup, 0o600)
    os.replace(tmp, CONFIG)
    result = run([DNSCOMPLEX, "fix"], 180)
    if not result.get("ok") and os.path.exists(backup):
        os.replace(backup, CONFIG)
        rollback = run([DNSCOMPLEX, "fix"], 180)
        result["output"] += "\nrollback:\n" + rollback.get("output", "")
    elif os.path.exists(backup):
        os.unlink(backup)
    return result

def update_status():
    cfg = parse_config()
    log_path = cfg.get("DNSCOMPLEX_UPDATE_LAST_LOG", "/var/log/dnscomplex/update-latest.log")
    log_text = ""
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            log_text = "".join(fh.readlines()[-80:])
    return {
        "channel": cfg.get("DNSCOMPLEX_UPDATE_CHANNEL", "stable"),
        "pinned_version": cfg.get("DNSCOMPLEX_PINNED_VERSION", ""),
        "github_release_policy": cfg.get("GITHUB_RELEASE_POLICY", "latest"),
        "last_update_log": log_path,
        "last_update_output": redact_text(log_text),
    }

def run(args, timeout=120):
    proc = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return {"ok": proc.returncode == 0, "code": proc.returncode, "output": proc.stdout[-12000:]}

def shell_output(args, timeout=20):
    try:
        return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout).stdout
    except Exception as exc:
        return str(exc)

def service_state(name):
    active = shell_output(["systemctl", "is-active", name]).strip()
    enabled = shell_output(["systemctl", "is-enabled", name]).strip()
    return {"name": name, "active": active, "enabled": enabled}

def last_update_log():
    cfg = parse_config()
    path = cfg.get("DNSCOMPLEX_UPDATE_LAST_LOG", "/var/log/dnscomplex/update-latest.log")
    if not os.path.exists(path):
        return f"Last update log: {path} (missing)"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()[-80:]
        return "Last update log: " + path + "\n" + "".join(lines)
    except OSError as exc:
        return f"Last update log: {path} ({exc})"

def smartdns_diagnostics():
    lines = [
        "SmartDNS wrapper:",
        shell_output(["readlink", "-f", "/usr/sbin/smartdns"], 5).strip(),
        shell_output(["ls", "-l", "/usr/sbin/smartdns"], 5).strip(),
        "SmartDNS enabled symlink:",
        shell_output(["ls", "-l", "/etc/systemd/system/multi-user.target.wants/smartdns.service"], 5).strip(),
    ]
    return "\n".join(lines)

def ipv6_diagnostics():
    cfg = parse_config()
    lines = [
        "IPv6 diagnostics:",
        f"DEPLOY_MODE={cfg.get('DEPLOY_MODE', '')}",
        f"DEFAULT_IPV6_MODE={cfg.get('DEFAULT_IPV6_MODE', '')}",
        f"DEFAULT_DNS_STRATEGY={cfg.get('DEFAULT_DNS_STRATEGY', 'prefer_ipv6')}",
        "IPv6 default routes:",
        shell_output(["ip", "-6", "route", "show", "default"], 5).strip(),
        "RA services on this VM:",
        "dnsmasq=" + shell_output(["systemctl", "is-active", "dnsmasq"], 5).strip(),
        "radvd=" + shell_output(["systemctl", "is-active", "radvd"], 5).strip(),
    ]
    if cfg.get("DEPLOY_MODE") == "routeros-policy":
        lines.append("routeros-policy note: this VM intentionally does not advertise IPv6 RA. Clients that only set IPv4 gateway to this VM still receive IPv6 default-router information from RouterOS RA.")
    return "\n".join(lines)

def domains_text():
    paths = [
        "/var/lib/dnscomplex/geosite/ai.sources",
        "/var/lib/dnscomplex/geosite/ai.custom",
        "/var/lib/dnscomplex/geosite/ai-support.sources",
        "/var/lib/dnscomplex/geosite/cn-video.sources",
        "/var/lib/dnscomplex/geosite/cn-video.custom",
        "/etc/dnscomplex/ai.domains",
        "/etc/dnscomplex/cn-video.domains",
    ]
    parts = []
    for path in paths:
        parts.append(f"## {path}")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                parts.append(fh.read().strip())
        else:
            parts.append("(missing)")
    return "\n\n".join(parts)

def read_list_file(path):
    if not os.path.exists(path):
        return []
    items = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            value = line.strip()
            if value and not value.startswith("#"):
                items.append(value)
    return items

def domains_model():
    return {
        "sections": [
            {
                "title": "AI 內建來源",
                "help": "例如 openai、anthropic；Meta AI 使用 AI 支援 domain 的 meta.ai，避免 Facebook/Instagram 走 AI。",
                "items": read_list_file("/var/lib/dnscomplex/geosite/ai.sources"),
            },
            {
                "title": "AI 自訂項目",
                "help": "手動加入的 AI domain 或額外 geosite source。",
                "items": read_list_file("/var/lib/dnscomplex/geosite/ai.custom"),
            },
            {
                "title": "AI 支援 domain",
                "help": "只在確定 app 依賴需要同走 AI 出口時才加入。",
                "items": read_list_file("/var/lib/dnscomplex/geosite/ai-support.sources"),
            },
            {
                "title": "CN 內建來源",
                "help": "中國大陸視頻/直播/OTT curated profile。",
                "items": read_list_file("/var/lib/dnscomplex/geosite/cn-video.sources"),
            },
            {
                "title": "CN 自訂項目",
                "help": "手動加入的 CN domain 或額外 geosite source。",
                "items": read_list_file("/var/lib/dnscomplex/geosite/cn-video.custom"),
            },
        ],
        "text": domains_text(),
    }

def egress_test(payload):
    profile = payload.get("profile", "")
    if profile not in {"ai", "cn"}:
        return {"ok": False, "code": 2, "output": "invalid profile"}
    uri = payload.get("uri", "")
    outbound_json = payload.get("outbound_json", "")
    with tempfile.NamedTemporaryFile("w+", delete=False) as fh:
        out = fh.name
    try:
        args = ["/usr/local/lib/dnscomplex-xray/render.py", "--config", CONFIG, "--profile", profile, "--output", out]
        if outbound_json and outbound_json != MASKED_SECRET:
            args.extend(["--json", outbound_json])
        elif uri and uri != MASKED_SECRET:
            args.extend(["--uri", uri])
        rendered = run(args, 30)
        if not rendered["ok"]:
            return rendered
        return run(["xray", "run", "-test", "-format=json", "-config", out], 30)
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass

def egress_apply(payload):
    profile = payload.get("profile", "")
    mode = payload.get("mode", "")
    if profile not in {"ai", "cn"} or mode not in {"ipsec", "xray"}:
        return {"ok": False, "code": 2, "output": "invalid profile or mode"}
    outputs = []
    outbound_json = payload.get("outbound_json", "")
    uri = payload.get("uri", "")
    if outbound_json and outbound_json != MASKED_SECRET:
        with tempfile.NamedTemporaryFile("w+", delete=False) as fh:
            fh.write(outbound_json)
            json_path = fh.name
        try:
            outputs.append(run([DNSCOMPLEX, "set-xray-json", profile, json_path], 180))
        finally:
            try:
                os.unlink(json_path)
            except OSError:
                pass
    elif uri and uri != MASKED_SECRET:
        outputs.append(run([DNSCOMPLEX, "set-xray-uri", profile, uri], 180))
    outputs.append(run([DNSCOMPLEX, "set-egress", profile, mode], 180))
    ok = all(item.get("ok") for item in outputs)
    return {"ok": ok, "code": 0 if ok else 1, "output": "\n".join(item.get("output", "") for item in outputs)}

def read_dns_name(buf, offset, depth=0):
    labels = []
    jumped = False
    end = offset
    if depth > 20:
        raise ValueError("dns compression loop")
    while offset < len(buf):
        length = buf[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise ValueError("truncated dns pointer")
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            labels.extend(read_dns_name(buf, pointer, depth + 1)[0])
            offset += 2
            if not jumped:
                end = offset
            jumped = True
            break
        offset += 1
        labels.append(buf[offset:offset + length].decode("utf-8", "ignore"))
        offset += length
        if not jumped:
            end = offset
    return labels, end

def dns_answer_ips(encoded):
    ips = []
    try:
        buf = base64.b64decode(encoded)
    except (binascii.Error, TypeError):
        return ips
    if len(buf) < 12:
        return ips
    qdcount = int.from_bytes(buf[4:6], "big")
    ancount = int.from_bytes(buf[6:8], "big")
    offset = 12
    try:
        for _ in range(qdcount):
            _, offset = read_dns_name(buf, offset)
            offset += 4
        for _ in range(ancount):
            _, offset = read_dns_name(buf, offset)
            if offset + 10 > len(buf):
                break
            rtype = int.from_bytes(buf[offset:offset + 2], "big")
            rdlength = int.from_bytes(buf[offset + 8:offset + 10], "big")
            offset += 10
            rdata = buf[offset:offset + rdlength]
            offset += rdlength
            if rtype == 1 and len(rdata) == 4:
                ips.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif rtype == 28 and len(rdata) == 16:
                ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
    except Exception:
        return ips
    return ips

def dns_ip_domain_map(limit=6000):
    mapping = {}
    path = "/opt/AdGuardHome/data/querylog.json"
    if not os.path.exists(path):
        return mapping
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()[-limit:]
    except OSError:
        return mapping
    for raw in lines:
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        host = item.get("QH") or item.get("question", {}).get("host") or item.get("question", {}).get("name")
        if not host:
            continue
        for ip in dns_answer_ips(item.get("Answer", "")):
            mapping.setdefault(ip, host)
    return mapping

def nft_set_ips(name):
    text = shell_output(["nft", "list", "set", "inet", "dnscomplex", name], 10)
    return set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))

def classify_destination(ip, ai_ips, cn_ips):
    if ip in ai_ips:
        return "AI", "nftset:ai4"
    if ip in cn_ips:
        return "CN", "nftset:cn4"
    return "default", "route-default"

def parse_conntrack_line(line):
    parts = line.split()
    if not parts:
        return None
    proto = parts[0]
    state = ""
    kv = []
    for part in parts:
        if "=" in part:
            kv.append(part)
        elif part.isupper() and part not in {"UNREPLIED", "ASSURED"}:
            state = part
    data = {}
    for part in kv:
        key, value = part.split("=", 1)
        if key not in data:
            data[key] = value
    src = data.get("src", "")
    dst = data.get("dst", "")
    dport = data.get("dport", "")
    if not src or not dst:
        return None
    try:
        src_ip = ipaddress.ip_address(src)
        dst_ip = ipaddress.ip_address(dst)
    except ValueError:
        return None
    if src_ip.is_loopback or dst_ip.is_loopback or src_ip == dst_ip:
        return None
    if dst_ip.is_private or dst_ip.is_multicast or dst_ip.is_link_local:
        return None
    return {
        "client": src,
        "dst": dst,
        "destination": f"{dst}:{dport}" if dport else dst,
        "protocol": proto,
        "ip_version": "IPv6" if dst_ip.version == 6 else "IPv4",
        "state": state or "-",
    }

def active_connections():
    output = shell_output(["conntrack", "-L"], 12)
    ip_to_domain = dns_ip_domain_map()
    ai_ips = nft_set_ips("ai4")
    cn_ips = nft_set_ips("cn4")
    seen = set()
    rows = []
    for line in output.splitlines():
        conn = parse_conntrack_line(line)
        if not conn:
            continue
        key = (conn["client"], conn["destination"], conn["protocol"])
        if key in seen:
            continue
        seen.add(key)
        dst = conn["dst"]
        conn["domain"] = ip_to_domain.get(dst, "")
        conn["domain_source"] = "AdGuard querylog" if conn["domain"] else "unknown"
        conn["profile"], conn["profile_source"] = classify_destination(dst, ai_ips, cn_ips)
        rows.append(conn)
    rows.sort(key=lambda item: (item["profile"], item["client"], item["domain"], item["destination"]))
    return rows[:300]

def metrics_current():
    out = shell_output(["/usr/local/lib/dnscomplex-metrics/exporter.py", "--sample"], 15)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"error": out}

def metrics_history(limit=720):
    path = "/var/lib/dnscomplex/metrics.sqlite3"
    if not os.path.exists(path):
        return []
    try:
        with sqlite3.connect(path) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "select ts, conntrack_usage_ratio, dns_latency_ms, ai_nftset_count, cn_nftset_count, ipsec_ai_up, ipsec_cn_up, adguard_cache_enabled from samples order by ts desc limit ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]
    except Exception as exc:
        return [{"error": str(exc)}]

def service_active(name):
    return shell_output(["systemctl", "is-active", name], 5).strip() == "active"

def ui_summary():
    cfg = parse_config()
    health_raw = shell_output([DNSCOMPLEX, "health", "--json"], 15)
    try:
        health = json.loads(health_raw)
    except json.JSONDecodeError:
        health = {"status": "degraded", "error": health_raw}

    adguard_ok = service_active("AdGuardHome.service")
    smartdns_ok = service_active("smartdns.service")
    singbox_ok = service_active("sing-box.service")
    nft_ok = service_active("nftables.service")
    xray_ok = service_active("xray-dnscomplex.service")
    ai_mode = cfg.get("AI_EGRESS_MODE", "ipsec")
    cn_mode = cfg.get("CN_EGRESS_MODE", "ipsec")
    ipsec_ok = bool(health.get("ipsec_ok", False))
    conntrack = float(health.get("conntrack_usage_percent", 0) or 0)
    dns_latency = health.get("dns_latency_ms", "-")
    default_ipv6 = cfg.get("DEFAULT_IPV6_MODE", "auto")

    cards = [
        {"label": "上網狀態", "value": "正常" if health.get("status") == "healthy" else "需檢查", "detail": f"DNS {dns_latency}ms / conntrack {conntrack:.2f}%", "state": "ok" if health.get("status") == "healthy" else "bad"},
        {"label": "DNS 去廣告", "value": "啟用" if adguard_ok and smartdns_ok else "異常", "detail": "AdGuard 過濾，SmartDNS cache", "state": "ok" if adguard_ok and smartdns_ok else "bad"},
        {"label": "AI 分流", "value": ai_mode.upper(), "detail": "只走 IPv4，避免 AAAA 外洩", "state": "ok" if (ai_mode == "xray" and xray_ok) or (ai_mode == "ipsec" and ipsec_ok) else "warn"},
        {"label": "CN 分流", "value": cn_mode.upper(), "detail": "只走 IPv4，SmartDNS 寫 nftset", "state": "ok" if (cn_mode == "xray" and xray_ok) or (cn_mode == "ipsec" and ipsec_ok) else "warn"},
        {"label": "IPv6 / Default", "value": default_ipv6, "detail": "default 可用 IPv4 + IPv6", "state": "ok" if default_ipv6 in {"auto", "on"} else "warn"},
    ]

    warnings = []
    if not singbox_ok:
        warnings.append({"title": "sing-box 未正常運行", "detail": "TUN / SOCKS / 分流會受影響。", "next": "到「進階 > 進階維護」按 Doctor，再按修正設定。"})
    if not adguard_ok or not smartdns_ok:
        warnings.append({"title": "DNS 服務異常", "detail": "AdGuard 或 SmartDNS 未 active，手機可能會解析失敗。", "next": "到「日常 > 上網測試」按測試 DNS；失敗再到「進階維護」按修正設定。"})
    if not nft_ok:
        warnings.append({"title": "nftables 異常", "detail": "AI/CN 目的 IP policy 可能不生效。", "next": "到「進階 > 進階維護」按修正設定，然後刷新 AI/CN IP 快取。"})
    if (ai_mode == "ipsec" or cn_mode == "ipsec") and not ipsec_ok:
        warnings.append({"title": "IPsec 未完全連線", "detail": "使用 IPsec 的 AI/CN profile 可能未能分流。", "next": "到「日常 > 上網測試」按測試 AI/CN IPsec；如帳密改過，到常用設定更新。"})
    if conntrack >= 70:
        warnings.append({"title": "Conntrack 使用率偏高", "detail": f"目前 {conntrack:.2f}%，大量設備使用時需要處理容量。", "next": "到「日常 > 流量趨勢」查看走勢，必要時擴容或調整 conntrack。"})
    if cfg.get("ADGUARD_DNS_CACHE_MODE", "off") != "off":
        warnings.append({"title": "AdGuard cache 被開啟", "detail": "建議由 SmartDNS 作唯一 DNS cache，避免 double-cache。", "next": "到常用設定的進階 config 將 ADGUARD_DNS_CACHE_MODE 設為 off。"})

    profiles = [
        {"name": "AI", "status": "正常" if cards[2]["state"] == "ok" else "需檢查", "state": cards[2]["state"], "egress": ai_mode, "ip_policy": "只 IPv4", "dns_policy": "AI SmartDNS 只回 A 記錄並寫入 ai4 nftset", "detail": "OpenAI / Claude / Meta 等 domain 使用此 profile。"},
        {"name": "CN", "status": "正常" if cards[3]["state"] == "ok" else "需檢查", "state": cards[3]["state"], "egress": cn_mode, "ip_policy": "只 IPv4", "dns_policy": "CN SmartDNS 只回 A 記錄並寫入 cn4 nftset", "detail": "Youku / Bilibili / iQiyi 等視頻站使用此 profile。"},
        {"name": "Default", "status": "正常" if health.get("status") == "healthy" else "需檢查", "state": "ok" if health.get("status") == "healthy" else "warn", "egress": "RouterOS", "ip_policy": "IPv4 + IPv6", "dns_policy": "Default SmartDNS 可回 A/AAAA", "detail": "不在 AI/CN 清單的網站走 default。"},
    ]

    dns = {
        "adguard": "啟用" if adguard_ok else "異常",
        "adguard_state": "ok" if adguard_ok else "bad",
        "cache": "SmartDNS",
        "cache_state": "ok" if cfg.get("ADGUARD_DNS_CACHE_MODE", "off") == "off" else "warn",
    }
    return {"cards": cards, "warnings": warnings, "profiles": profiles, "dns": dns}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def session_token(self, password):
        return hashlib.sha256(("dnscomplex-web:" + password).encode("utf-8")).hexdigest()

    def cookie_ok(self, password):
        cookie = self.headers.get("Cookie", "")
        expected = self.session_token(password)
        for item in cookie.split(";"):
            if "=" not in item:
                continue
            key, value = item.strip().split("=", 1)
            if key == "dnscomplex_session" and value == expected:
                return True
        return False

    def basic_ok(self, password):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        except Exception:
            return False
        supplied = decoded.split(":", 1)[1] if ":" in decoded else ""
        return supplied == password

    def authed(self):
        cfg = parse_config()
        password = cfg.get("DNSCOMPLEX_WEB_PASSWORD", "")
        if not password:
            return False
        if self.cookie_ok(password):
            self._set_session_cookie = False
            return True
        if self.basic_ok(password):
            self._set_session_cookie = True
            self._session_password = password
            return True
        return False

    def maybe_set_session_cookie(self):
        if getattr(self, "_set_session_cookie", False):
            token = self.session_token(getattr(self, "_session_password", ""))
            self.send_header("Set-Cookie", f"dnscomplex_session={token}; Path=/; SameSite=Strict; HttpOnly")

    def require_auth(self):
        if self.authed():
            return True
        if self.path.startswith("/api/"):
            self.send_json({"error": "unauthorized"}, 401)
            return False
        self.send_login_page()
        return False

    def send_auth_challenge(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="dnscomplex"')
        self.end_headers()

    def send_html(self, html, code=200):
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.maybe_set_session_cookie()
        self.end_headers()
        self.wfile.write(body)

    def send_login_page(self, error=""):
        error_html = f'<div class="login-error">{html.escape(error)}</div>' if error else ""
        self.send_html(f'''<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>dnscomplex 登入</title>
  <style>
    body {{ margin:0; min-height:100vh; display:grid; place-items:center; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#f6f8fb; color:#111827; }}
    form {{ width:min(360px, calc(100vw - 32px)); background:white; border:1px solid #d8dee8; border-radius:8px; padding:24px; box-shadow:0 12px 32px rgba(15,23,42,.12); }}
    h1 {{ margin:0 0 6px; font-size:24px; }}
    p {{ margin:0 0 20px; color:#64748b; }}
    label {{ display:block; font-size:13px; font-weight:700; margin:14px 0 6px; }}
    input {{ width:100%; box-sizing:border-box; border:1px solid #cbd5e1; border-radius:6px; padding:10px 12px; font-size:15px; }}
    button {{ width:100%; margin-top:18px; border:0; border-radius:6px; padding:11px 14px; background:#2563eb; color:white; font-weight:700; font-size:15px; cursor:pointer; }}
    .login-error {{ margin:14px 0 0; padding:10px 12px; border:1px solid #fecaca; border-radius:6px; background:#fef2f2; color:#991b1b; }}
  </style>
</head>
<body>
  <form method="post" action="/login">
    <h1>dnscomplex</h1>
    <p>登入管理介面</p>
    <label for="username">用戶名稱</label>
    <input id="username" name="username" value="admin" autocomplete="username">
    <label for="password">密碼</label>
    <input id="password" name="password" type="password" autocomplete="current-password" autofocus>
    {error_html}
    <button type="submit">登入</button>
  </form>
</body>
</html>''')

    def handle_login(self):
        cfg = parse_config()
        password = cfg.get("DNSCOMPLEX_WEB_PASSWORD", "")
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length > 0 else ""
        content_type = self.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                payload = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                payload = {}
        else:
            parsed = urllib.parse.parse_qs(raw)
            payload = {key: values[0] if values else "" for key, values in parsed.items()}
        if payload.get("username", "admin") == "admin" and payload.get("password", "") == password and password:
            self._set_session_cookie = True
            self._session_password = password
            self.send_response(303)
            self.send_header("Location", "/")
            self.maybe_set_session_cookie()
            self.end_headers()
            return
        self.send_login_page("登入資料不正確", 401)

    def send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.maybe_set_session_cookie()
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("content-length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        if self.path == "/login":
            self.send_login_page()
            return
        if not self.require_auth():
            return
        if self.path == "/":
            html = HTML.replace("CONFIG_KEYS_PLACEHOLDER", json.dumps(CONFIG_KEYS))
            self.send_html(html)
            return
        if self.path == "/api/status":
            summary = "\n".join([
                shell_output([DNSCOMPLEX, "status"], 20),
                smartdns_diagnostics(),
                ipv6_diagnostics(),
                "Timers:",
                shell_output(["systemctl", "list-timers", "dnscomplex-*.timer", "--no-pager"], 20),
                "Update log:",
                last_update_log(),
            ])
            self.send_json({"services": [service_state(s) for s in SERVICES], "summary": summary})
            return
        if self.path == "/api/config":
            self.send_json(safe_config())
            return
        if self.path == "/api/ui/summary":
            self.send_json(ui_summary())
            return
        if self.path == "/api/wizard/schema":
            self.send_json(wizard_schema())
            return
        if self.path == "/api/update/status":
            self.send_json(update_status())
            return
        if self.path.startswith("/api/trace-domain"):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            domain = (query.get("domain") or [""])[0]
            if not domain:
                self.send_json({"ok": False, "output": "missing domain"}, 400)
                return
            self.send_json(run([DNSCOMPLEX, "trace-domain", domain], 120))
            return
        if self.path == "/api/domains":
            self.send_json(domains_model())
            return
        if self.path == "/api/traffic":
            text = "\n".join([
                "## ipsec links",
                shell_output(["ip", "-s", "link", "show", "ipsec-ai"], 10),
                shell_output(["ip", "-s", "link", "show", "ipsec-cn"], 10),
                "## nft dnscomplex",
                shell_output(["nft", "list", "table", "inet", "dnscomplex"], 20),
                "## strongSwan",
                shell_output(["swanctl", "--list-sas"], 20),
            ])
            self.send_json({"text": text[-20000:]})
            return
        if self.path == "/api/connections":
            self.send_json({"connections": active_connections()})
            return
        if self.path == "/api/metrics/current":
            self.send_json(metrics_current())
            return
        if self.path == "/api/metrics/history":
            self.send_json({"samples": metrics_history()})
            return
        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/login":
            self.handle_login()
            return
        if not self.require_auth():
            return
        try:
            payload = self.read_json()
            if self.path == "/api/config":
                write_config(payload)
                result = run([DNSCOMPLEX, "fix"], 180)
                self.send_json(result)
                return
            if self.path == "/api/wizard/validate":
                result = validate_config_text(payload.get("config", ""))
                result["output"] = redact_text(result.get("output", ""))
                self.send_json(result)
                return
            if self.path == "/api/wizard/apply":
                result = apply_config_text(payload.get("config", ""))
                result["output"] = redact_text(result.get("output", ""))
                self.send_json(result)
                return
            if self.path == "/api/update/run":
                args = [DNSCOMPLEX, "update-software"]
                channel = payload.get("channel", "")
                version = payload.get("version", "")
                if channel:
                    args.extend(["--channel", channel])
                if version:
                    args.extend(["--version", version])
                result = run(args, 900)
                result["output"] = redact_text(result.get("output", ""))
                self.send_json(result)
                return
            if self.path == "/api/support-bundle":
                include_logs = payload.get("include_logs", "standard")
                result = run([DNSCOMPLEX, "support-bundle", "--include-logs", include_logs], 300)
                result["output"] = redact_text(result.get("output", ""))
                self.send_json(result)
                return
            if self.path == "/api/action":
                action = payload.get("action", "")
                if action in {"test", "fix", "doctor", "test-dns", "test-ipsec", "refresh-nftsets", "refresh-cn-overrides", "update-geosite", "update-software", "backup", "mss-calibrate"}:
                    self.send_json(run([DNSCOMPLEX, action], 600))
                    return
                if action == "test-xray":
                    profile = payload.get("profile", "")
                    args = [DNSCOMPLEX, "test-xray"] + ([profile] if profile else [])
                    self.send_json(run(args, 180))
                    return
                if action == "set-egress":
                    self.send_json(run([DNSCOMPLEX, "set-egress", payload.get("profile", ""), payload.get("mode", "")], 180))
                    return
                if action == "trace-domain":
                    value = payload.get("value", "")
                    if not value:
                        self.send_json({"ok": False, "output": "missing domain"}, 400)
                        return
                    self.send_json(run([DNSCOMPLEX, "trace-domain", value], 120))
                    return
                if action in {"add-domain", "remove-domain"}:
                    profile = payload.get("profile", "")
                    value = payload.get("value", "")
                    if profile not in {"ai", "cn"} or not value:
                        self.send_json({"ok": False, "output": "invalid profile or value"}, 400)
                        return
                    self.send_json(run([DNSCOMPLEX, action, profile, value], 180))
                    return
                if action == "set-socks":
                    self.send_json(run([DNSCOMPLEX, "set-socks", payload.get("listen", ""), str(payload.get("port", ""))], 120))
                    return
                if action == "set-ipsec":
                    profile = payload.get("profile", "")
                    if profile not in {"ai", "cn"}:
                        self.send_json({"ok": False, "output": "invalid profile"}, 400)
                        return
                    self.send_json(run([DNSCOMPLEX, "set-ipsec", profile, payload.get("user", ""), payload.get("password", "")], 180))
                    return
                if action == "set-web-password":
                    password = payload.get("password", "")
                    self.send_json(run([DNSCOMPLEX, "set-web-password", password], 120))
                    return
                if action == "set-local-host":
                    self.send_json(run([DNSCOMPLEX, "set-local-host", payload.get("host", ""), payload.get("ip", "")], 120))
                    return
                if action == "test-local-name":
                    self.send_json(run([DNSCOMPLEX, "test-local-name", payload.get("host", "")], 120))
                    return
                if action == "set-update-time":
                    value = payload.get("value", "")
                    if not re.match(r"^([01][0-9]|2[0-3]):[0-5][0-9]$", value):
                        self.send_json({"ok": False, "output": "invalid HH:MM"}, 400)
                        return
                    self.send_json(run([DNSCOMPLEX, "set-update-time", value], 120))
                    return
            if self.path == "/api/egress/test":
                self.send_json(egress_test(payload))
                return
            if self.path == "/api/egress/apply":
                self.send_json(egress_apply(payload))
                return
            if self.path in {"/api/rules/domain", "/api/rules/geosite"}:
                action = payload.get("action", "add")
                profile = payload.get("profile", "")
                values = [v.strip() for v in re.split(r"[\r\n]+", payload.get("value", "")) if v.strip()]
                if action not in {"add", "remove"} or profile not in {"ai", "cn"} or not values:
                    self.send_json({"ok": False, "output": "invalid action/profile/value"}, 400)
                    return
                outputs = []
                cmd = "add-domain" if action == "add" else "remove-domain"
                for value in values:
                    outputs.append(run([DNSCOMPLEX, cmd, profile, value], 180))
                ok = all(item.get("ok") for item in outputs)
                self.send_json({"ok": ok, "code": 0 if ok else 1, "output": "\n".join(item.get("output", "") for item in outputs)})
                return
            if self.path == "/api/rules/rebuild":
                self.send_json(run([DNSCOMPLEX, "update-geosite"], 600))
                return
            self.send_json({"error": "not found"}, 404)
        except Exception as exc:
            self.send_json({"ok": False, "output": str(exc)}, 500)

def main():
    cfg = parse_config()
    listen = cfg.get("DNSCOMPLEX_WEB_LISTEN", "127.0.0.1")
    port = int(cfg.get("DNSCOMPLEX_WEB_PORT", "8088"))
    server = ThreadingHTTPServer((listen, port), Handler)
    print(f"dnscomplex-web listening on http://{listen}:{port}", flush=True)
    server.serve_forever()

if __name__ == "__main__":
    main()
PY
  chmod_target 0755 /usr/local/lib/dnscomplex-web/app.py

  write_file /etc/systemd/system/dnscomplex-web.service <<'EOF'
[Unit]
Description=dnscomplex web management interface
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/lib/dnscomplex-web/app.py
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

enable_services() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  local ipsec_unit ipsec_enabled=0
  apply_runtime_network_settings
  systemctl daemon-reload
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    systemctl enable --now nftables
  else
    systemctl enable --now systemd-networkd nftables dnsmasq radvd
  fi
  systemctl restart nftables || true
  systemctl enable --now dnscomplex-ipsec-ifaces dnscomplex-routing dnscomplex-health.timer dnscomplex-update.timer dnscomplex-cn-overrides.timer dnscomplex-nftset-refresh.timer dnscomplex-metrics-sample.timer
  for ipsec_unit in strongswan-swanctl strongswan-starter strongswan ipsec; do
    if systemctl list-unit-files "${ipsec_unit}.service" >/dev/null 2>&1; then
      systemctl enable --now "$ipsec_unit" && ipsec_enabled=1 && break
    fi
  done
  [[ "$ipsec_enabled" == "1" ]] || warn "no strongSwan systemd unit found; IPsec may need manual service setup"
  systemctl enable --now smartdns AdGuardHome sing-box xray-dnscomplex
  systemctl enable --now dnscomplex-web
  systemctl enable --now dnscomplex-metrics
  systemctl restart smartdns AdGuardHome sing-box xray-dnscomplex || true
  systemctl restart dnscomplex-web dnscomplex-metrics || true
}

render_all() {
  save_runtime_config
  render_network
  apply_runtime_network_settings
  resolve_default_ipv6_mode
  render_geosite_seeds
  render_local_hosts
  render_smartdns
  render_adguard
  render_adguard_service
  render_swanctl
  render_strongswan_resolve_plugin
  render_ipsec_ca_store
  render_xray_support
  render_singbox
  render_nftables
  render_ipsec_services
  render_routeros
  render_management_script
  render_metrics_exporter
  render_web_interface
}

main() {
  parse_args "$@"
  load_config
  collect_interactive_config
  validate_config
  require_debian13
  require_root
  install_packages
  render_all
  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run render complete under ${DNSCOMPLEX_ROOT:-/}"
  else
    dnscomplex update-geosite
    enable_services
    dnscomplex routes up || true
    dnscomplex refresh-nftsets || true
    log "installed. Run: dnscomplex test"
    log "RouterOS commands: dnscomplex routeros-print"
  fi
}

main "$@"
