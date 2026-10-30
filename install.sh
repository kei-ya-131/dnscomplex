#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

DNSCOMPLEX_VERSION="0.3.0"
DNSCOMPLEX_ROOT="${DNSCOMPLEX_ROOT:-}"
CONFIG_PATH=""
DRY_RUN=0
ASSUME_YES=0

AI_IPSEC_SERVER_DEFAULT="vpn-ai.example.net"
CN_IPSEC_SERVER_DEFAULT="vpn-cn.example.net"
SMARTDNS_DEFAULT_PORT=6053
SMARTDNS_AI_PORT=6054
SMARTDNS_CN_PORT=6055
SINGBOX_DNS_LISTEN="127.0.0.1"
SINGBOX_DNS_PORT=1053
SINGBOX_LOG_LEVEL="warn"
SINGBOX_SOCKS_LISTEN=""
SINGBOX_SOCKS_PORT=""
SINGBOX_HTTP_LISTEN="0.0.0.0"
SINGBOX_HTTP_PORT=1081
XRAY_ENABLED=1
XRAY_LISTEN_HOST="127.0.0.1"
XRAY_AI_SOCKS_PORT=16054
XRAY_CN_SOCKS_PORT=16055
AI_EGRESS_MODE="ipsec"
CN_EGRESS_MODE="ipsec"
AI_QUIC_POLICY="allow"
CN_QUIC_POLICY="reject"
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
DNSCOMPLEX_IPSEC_BOOT_TIMEOUT=90
AI_MARK="0x301"
CN_MARK="0x351"
AI_MARK_DEC="769"
CN_MARK_DEC="849"
SINGBOX_AUTO_REDIRECT_INPUT_MARK="0x2023"
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK="0x2024"
SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC="8227"
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC="8228"
IPSEC_DATAPLANE_AI_MARK="0x3A1"
IPSEC_DATAPLANE_CN_MARK="0x3F1"
# Read by the generated runtime manager after installer rendering.
# shellcheck disable=SC2034
IPSEC_DATAPLANE_AI_MARK_DEC="929"
# shellcheck disable=SC2034
IPSEC_DATAPLANE_CN_MARK_DEC="1009"
PROFILE_DATAPLANE_PROBE_SHA256="37521f4ff6775f7c04eff1179b3c325789a6f3d3eb112e0ab70b27a934004fab"
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
CN_SAMPLE_DOMAINS_DEFAULT="bilibili.com iqiyi.com youku.com douyin.com kuaishou.com acfun.cn mgtv.com v.qq.com tv.cctv.com"
CN_NFTSET_REFRESH_DOMAINS_DEFAULT="$CN_SAMPLE_DOMAINS_DEFAULT"
CN_STATIC_A_OVERRIDES_DEFAULT="youku.com=47.246.99.254"
CN_OVERRIDE_PROBE_DOMAINS_DEFAULT="youku.com=youku.com,www.youku.com"
CN_OVERRIDE_PROBE_RESOLVERS_DEFAULT="223.5.5.5 119.29.29.29 1.1.1.1 8.8.8.8"
LOCAL_DOMAIN_IPV6_POLICY="ipv4_only"

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
  AI_QUIC_POLICY=reject|allow CN_QUIC_POLICY=reject|allow
  AI_XRAY_OUTBOUND_JSON CN_XRAY_OUTBOUND_JSON XRAY_LISTEN_HOST XRAY_AI_SOCKS_PORT XRAY_CN_SOCKS_PORT
  LOCAL_DOMAIN_IPV6_POLICY=ipv4_only|allow
  SINGBOX_DNS_LISTEN SINGBOX_DNS_PORT SINGBOX_LOG_LEVEL=trace|debug|info|warn|error
  DNSCOMPLEX_WEB_LISTEN DNSCOMPLEX_WEB_PORT DNSCOMPLEX_WEB_PASSWORD DNSCOMPLEX_UPDATE_TIME
  DNSCOMPLEX_NFTSET_REFRESH_INTERVAL DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT
  IPSEC_TCP_MSS DNSCOMPLEX_IPSEC_BOOT_TIMEOUT
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

validate_egress_profile_values() {
  local name value dec_name dec_value ai_table cn_table marks=""
  for name in AI_MARK CN_MARK SINGBOX_AUTO_REDIRECT_INPUT_MARK SINGBOX_AUTO_REDIRECT_OUTPUT_MARK \
      IPSEC_DATAPLANE_AI_MARK IPSEC_DATAPLANE_CN_MARK; do
    value=${!name:-}
    [[ "$value" =~ ^(0[xX][0-9a-fA-F]{1,8}|0|[1-9][0-9]{0,9})$ ]] || {
      printf 'error: %s must be a uint32 mark in decimal or hexadecimal\n' "$name" >&2
      return 1
    }
    value=$((value))
    ((value > 0 && value <= 4294967295)) || {
      printf 'error: %s must be nonzero uint32\n' "$name" >&2
      return 1
    }
    case " $marks " in
      *" $value "*)
        printf 'error: %s conflicts with another reserved mark\n' "$name" >&2
        return 1
        ;;
    esac
    marks="$marks $value"
    case "$name" in
      AI_MARK) dec_name=AI_MARK_DEC ;;
      CN_MARK) dec_name=CN_MARK_DEC ;;
      SINGBOX_AUTO_REDIRECT_INPUT_MARK) dec_name=SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC ;;
      SINGBOX_AUTO_REDIRECT_OUTPUT_MARK) dec_name=SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC ;;
      IPSEC_DATAPLANE_AI_MARK) dec_name=IPSEC_DATAPLANE_AI_MARK_DEC ;;
      IPSEC_DATAPLANE_CN_MARK) dec_name=IPSEC_DATAPLANE_CN_MARK_DEC ;;
    esac
    dec_value=${!dec_name:-}
    if [[ ! "$dec_value" =~ ^[0-9]{1,10}$ ]] || ((10#$dec_value != value)); then
      printf 'error: %s must match %s\n' "$dec_name" "$name" >&2
      return 1
    fi
  done
  [[ "${AI_TABLE:-}" =~ ^[0-9]{1,10}$ && "${CN_TABLE:-}" =~ ^[0-9]{1,10}$ ]] || {
    printf 'error: AI_TABLE and CN_TABLE must be numeric routing table ids\n' >&2
    return 1
  }
  ai_table=$((10#${AI_TABLE}))
  cn_table=$((10#${CN_TABLE}))
  for value in "$ai_table" "$cn_table"; do
    ((value > 0 && value <= 4294967295 && value != 253 && value != 254 && value != 255)) || {
      printf 'error: profile routing tables cannot be local/main/default/reserved\n' >&2
      return 1
    }
  done
  ((ai_table != cn_table)) || {
    printf 'error: AI_TABLE and CN_TABLE must be distinct\n' >&2
    return 1
  }
}

curl_bounded() {
  curl --connect-timeout 10 --max-time 180 \
    --retry 2 --retry-delay 2 --retry-all-errors "$@"
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
  : "${IPSEC_REMOTE_ID:=vpn.example.net}"
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
  : "${LOCAL_DOMAIN_IPV6_POLICY:=ipv4_only}"
  : "${DEPLOY_MODE:=vlan-gateway}"
  : "${LAN_IPV6_GATEWAY:=$(ipv6_gateway_from_prefix "${LAN_IPV6_PREFIX:-fd00:88::/64}")}"
  if [[ -z "${SINGBOX_SOCKS_LISTEN:-}" ]]; then
    if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
      SINGBOX_SOCKS_LISTEN=${LINUX_LAN_IPV4:-}
    else
      SINGBOX_SOCKS_LISTEN=0.0.0.0
    fi
  fi
  if [[ -z "${SINGBOX_SOCKS_PORT:-}" ]]; then
    if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
      SINGBOX_SOCKS_PORT=10800
    else
      SINGBOX_SOCKS_PORT=1080
    fi
  fi
  : "${SINGBOX_HTTP_LISTEN:=0.0.0.0}"
  : "${SINGBOX_HTTP_PORT:=1081}"
  : "${XRAY_ENABLED:=1}"
  : "${XRAY_LISTEN_HOST:=127.0.0.1}"
  : "${XRAY_AI_SOCKS_PORT:=16054}"
  : "${XRAY_CN_SOCKS_PORT:=16055}"
  : "${AI_EGRESS_MODE:=ipsec}"
  : "${CN_EGRESS_MODE:=ipsec}"
  : "${AI_QUIC_POLICY:=allow}"
  : "${CN_QUIC_POLICY:=reject}"
  : "${AI_XRAY_URI:=}"
  : "${CN_XRAY_URI:=}"
  : "${AI_XRAY_OUTBOUND_JSON:=}"
  : "${CN_XRAY_OUTBOUND_JSON:=}"
  : "${APPLE_PRIVATE_RELAY_BLOCK:=1}"
  : "${SINGBOX_DNS_LISTEN:=127.0.0.1}"
  : "${SINGBOX_DNS_PORT:=1053}"
  : "${SINGBOX_LOG_LEVEL:=warn}"
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
  : "${DNSCOMPLEX_IPSEC_BOOT_TIMEOUT:=90}"
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
  prompt_var SINGBOX_SOCKS_LISTEN "SOCKS listen address" "$([[ "$DEPLOY_MODE" == "routeros-policy" ]] && printf '%s' "$LINUX_LAN_IPV4" || printf '0.0.0.0')"
  prompt_var SINGBOX_SOCKS_PORT "SOCKS listen port" "$([[ "$DEPLOY_MODE" == "routeros-policy" ]] && printf '10800' || printf '1080')"
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
  ((SINGBOX_SOCKS_PORT >= 1 && SINGBOX_SOCKS_PORT <= 65535)) || die "SINGBOX_SOCKS_PORT must be 1-65535"
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    [[ "$SINGBOX_SOCKS_LISTEN" == "${LINUX_LAN_IPV4%%/*}" ]] ||
      die "routeros-policy SOCKS listen must match LINUX_LAN_IPV4"
    ((SINGBOX_SOCKS_PORT == 10800)) ||
      die "routeros-policy SOCKS port must be 10800"
  fi
  [[ "$XRAY_AI_SOCKS_PORT" =~ ^[0-9]+$ ]] || die "XRAY_AI_SOCKS_PORT must be numeric"
  [[ "$XRAY_CN_SOCKS_PORT" =~ ^[0-9]+$ ]] || die "XRAY_CN_SOCKS_PORT must be numeric"
  [[ "$DNSCOMPLEX_WEB_PORT" =~ ^[0-9]+$ ]] || die "DNSCOMPLEX_WEB_PORT must be numeric"
  [[ "$DNSCOMPLEX_METRICS_PORT" =~ ^[0-9]+$ ]] || die "DNSCOMPLEX_METRICS_PORT must be numeric"
  [[ "$IPSEC_TCP_MSS" =~ ^[0-9]+$ ]] || die "IPSEC_TCP_MSS must be numeric"
  [[ "$DNSCOMPLEX_IPSEC_BOOT_TIMEOUT" =~ ^[0-9]+$ ]] || die "DNSCOMPLEX_IPSEC_BOOT_TIMEOUT must be numeric"
  case "$SINGBOX_LOG_LEVEL" in trace|debug|info|warn|error) ;; *) die "SINGBOX_LOG_LEVEL must be trace, debug, info, warn, or error" ;; esac
  ((DNSCOMPLEX_WEB_PORT >= 1 && DNSCOMPLEX_WEB_PORT <= 65535)) || die "DNSCOMPLEX_WEB_PORT must be 1-65535"
  ((XRAY_AI_SOCKS_PORT >= 1 && XRAY_AI_SOCKS_PORT <= 65535)) || die "XRAY_AI_SOCKS_PORT must be 1-65535"
  ((XRAY_CN_SOCKS_PORT >= 1 && XRAY_CN_SOCKS_PORT <= 65535)) || die "XRAY_CN_SOCKS_PORT must be 1-65535"
  ((DNSCOMPLEX_METRICS_PORT >= 1 && DNSCOMPLEX_METRICS_PORT <= 65535)) || die "DNSCOMPLEX_METRICS_PORT must be 1-65535"
  ((IPSEC_TCP_MSS >= 536 && IPSEC_TCP_MSS <= 1460)) || die "IPSEC_TCP_MSS must be 536-1460"
  ((DNSCOMPLEX_IPSEC_BOOT_TIMEOUT >= 15 && DNSCOMPLEX_IPSEC_BOOT_TIMEOUT <= 110)) || die "DNSCOMPLEX_IPSEC_BOOT_TIMEOUT must be 15-110 seconds"
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
  case "$AI_QUIC_POLICY" in reject|allow) ;; *) die "AI_QUIC_POLICY must be reject or allow" ;; esac
  case "$CN_QUIC_POLICY" in reject|allow) ;; *) die "CN_QUIC_POLICY must be reject or allow" ;; esac
  case "$LOCAL_DOMAIN_IPV6_POLICY" in ipv4_only|allow) ;; *) die "LOCAL_DOMAIN_IPV6_POLICY must be ipv4_only or allow" ;; esac
  case "$XRAY_ENABLED" in 0|1) ;; *) die "XRAY_ENABLED must be 0 or 1" ;; esac
  validate_egress_profile_values || die "invalid egress profile marks or routing tables"
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

acquire_installer_maintenance_lock() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  local lock_file=${DNSCOMPLEX_MAINTENANCE_LOCK:-/run/lock/dnscomplex-maintenance.lock}
  local old_umask
  command -v flock >/dev/null 2>&1 ||
    die "flock is required before running the installer"
  mkdir -p "$(dirname "$lock_file")"
  old_umask=$(umask)
  umask 077
  if ! exec 8>"$lock_file"; then
    umask "$old_umask"
    die "could not open maintenance lock: $lock_file"
  fi
  umask "$old_umask"
  chmod 0600 "$lock_file"
  flock -w 120 8 ||
    die "another dnscomplex maintenance operation is already running"
  export DNSCOMPLEX_MAINTENANCE_LOCK_HELD=1
  export DNSCOMPLEX_MAINTENANCE_LOCK="$lock_file"
  local operations helper transaction
  operations=$(target_path /var/lib/dnscomplex-operations)
  helper=$(target_path /usr/local/libexec/dnscomplex-operation)
  for transaction in "$(target_path /var/lib/dnscomplex-restore)"/transaction.op.*; do
    [[ -e "$transaction" || -L "$transaction" ]] || continue
    die "operation journal must be recovered/cleaned before recovery-helper replacement"
  done
  if [[ -e "$operations" || -L "$operations" ]]; then
    if [[ -f "$helper" && ! -L "$helper" ]]; then
      DNSCOMPLEX_FS_ROOT="$DNSCOMPLEX_ROOT" python3 "$helper" gate || die "unresolved operation blocks installer recovery-helper replacement"
    else
      # A first upgrade from Task2 may retain terminal records without the new
      # helper. Validate that read-only format before installing its successor.
      python3 - "$operations" <<'LEGACY_OPERATION_GATE' || die "unresolved/unsafe operation store requires recovery before installation"
import json
import os
from pathlib import Path
import re
import stat
import sys

def private(path, directory=False):
    value=path.lstat()
    if value.st_uid != os.geteuid() or value.st_mode & 0o077 or not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)):
        raise SystemExit(1)
root=Path(sys.argv[1]); private(root,True)
for directory in root.iterdir():
    private(directory,True)
    if re.fullmatch(r'\.operation-(?:submit|create)\.[a-f0-9]{32}',directory.name): continue
    if not re.fullmatch('[a-f0-9]{32}',directory.name): raise SystemExit(1)
    path=directory/'manifest.json'; private(path)
    value=json.loads(path.read_text())
    if value.get('schema_version') != 1 or value.get('phase') not in ('committed','rolled-back'): raise SystemExit(1)
LEGACY_OPERATION_GATE
    fi
  fi
}

release_installer_maintenance_lock() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  if ( : >&8 ) 2>/dev/null; then
    flock -u 8 || true
    exec 8>&-
  fi
  unset DNSCOMPLEX_MAINTENANCE_LOCK_HELD
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

write_file_atomic() (
  local target temp
  target=$(target_path "$1")
  mkdir -p "$(dirname "$target")"
  temp=$(mktemp "${target}.XXXXXX") || exit 1
  trap 'rm -f "$temp"' EXIT
  cat >"$temp" || exit 1
  bash -n "$temp" || exit 1
  chmod 0755 "$temp" || exit 1
  mv -f "$temp" "$target"
)

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

disable_systemd_ssh_generator() {
  local target
  target=$(target_path /etc/systemd/system-generators/systemd-ssh-generator)
  mkdir -p "$(dirname "$target")"
  if [[ -d "$target" && ! -L "$target" ]]; then
    die "$target is a directory; cannot mask systemd-ssh-generator"
  fi
  ln -sfn /dev/null "$target"
}

apply_systemd_ssh_generator_disable() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl stop sshd-unix-local.socket sshd-vsock.socket sshd-unix-export.socket 2>/dev/null || true
  systemctl reset-failed sshd-unix-local.socket sshd-vsock.socket sshd-unix-export.socket 2>/dev/null || true
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
  asset=$(curl_bounded -fsSL "https://api.github.com/repos/$repo/releases/latest" |
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

# Narrow Apple Intelligence/Siri endpoints from Apple's enterprise network list.
# Keep CDN providers and other Apple/iCloud services on the default classifier.
apple_ai_support_sources() {
  cat <<'EOF'
full:guzzoni.apple.com
domain:smoot.apple.com
full:apple-relay.cloudflare.com
full:apple-relay.fastly-edge.com
full:cp4.cloudflare.com
full:apple-relay.apple.com
EOF
}

apple_ai_support_domains() {
  apple_ai_support_sources | sed 's/^[^:]*://'
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
  local group_option=""
  local exclude_default=""
  # SmartDNS puts an unqualified upstream in the implicit default group.
  # Keep named profile groups explicit and isolated from that default group.
  if [[ "$group" != "default" ]]; then
    group_option=" -group $group"
    exclude_default=" -exclude-default-group"
  fi
  case "$upstream" in
    h3://*)
      printf 'server-h3 %s%s%s\n' "$upstream" "$group_option" "$exclude_default"
      ;;
    https://*|http://*)
      printf 'server-https %s%s -alpn http/1.1%s\n' "$upstream" "$group_option" "$exclude_default"
      ;;
    tls://*)
      printf 'server-tls %s%s%s\n' "$upstream" "$group_option" "$exclude_default"
      ;;
    quic://*|doq://*)
      printf 'server-quic %s%s%s\n' "$upstream" "$group_option" "$exclude_default"
      ;;
    tcp://*)
      printf 'server-tcp %s%s%s\n' "${upstream#tcp://}" "$group_option" "$exclude_default"
      ;;
    *)
      printf 'server %s%s%s\n' "$upstream" "$group_option" "$exclude_default"
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
LOCAL_DOMAIN_IPV6_POLICY='$LOCAL_DOMAIN_IPV6_POLICY'
SMARTDNS_DEFAULT_PORT='$SMARTDNS_DEFAULT_PORT'
SMARTDNS_AI_PORT='$SMARTDNS_AI_PORT'
SMARTDNS_CN_PORT='$SMARTDNS_CN_PORT'
SINGBOX_DNS_PORT='$SINGBOX_DNS_PORT'
SINGBOX_DNS_LISTEN='$SINGBOX_DNS_LISTEN'
SINGBOX_LOG_LEVEL='$SINGBOX_LOG_LEVEL'
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
AI_QUIC_POLICY='$AI_QUIC_POLICY'
CN_QUIC_POLICY='$CN_QUIC_POLICY'
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
DNSCOMPLEX_IPSEC_BOOT_TIMEOUT='$DNSCOMPLEX_IPSEC_BOOT_TIMEOUT'
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
    ca-certificates curl jq tar unzip iproute2 nftables conntrack dnsmasq radvd kmod \
    strongswan-swanctl strongswan-charon libcharon-extra-plugins libstrongswan-extra-plugins \
    cron dnsutils python3 coreutils util-linux
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
  curl_bounded -fsSL -o "$tmp/smartdns.deb" "$asset"
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
  [[ -x /usr/local/lib/smartdns/run-smartdns ]] || {
    warn "SmartDNS wrapper missing: /usr/local/lib/smartdns/run-smartdns"
    return 1
  }
  ln -sfn /usr/local/lib/smartdns/run-smartdns /usr/sbin/smartdns || return $?
}

ensure_smartdns_enabled() {
  systemctl enable smartdns >/dev/null 2>&1 || true
}

install_singbox_release() {
  local arch asset tmp
  arch=$(linux_arch)
  tmp=$(mktemp -d)
  asset=$(github_latest_asset_url "SagerNet/sing-box" "sing-box_.*_linux_${arch}\\.deb$")
  curl_bounded -fsSL -o "$tmp/sing-box.deb" "$asset"
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
  curl_bounded -fsSL -o "$tmp/AdGuardHome.tar.gz" "$asset"
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
  curl_bounded -fsSL -o "$tmp/xray.zip" "$asset"
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
        authority = first(qs, "authority", "")
        if service or authority:
            settings["grpcSettings"] = {}
            if service:
                settings["grpcSettings"]["serviceName"] = service
            if authority:
                settings["grpcSettings"]["authority"] = authority
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
    elif uri:
        outbound = parse_uri(uri, tag)
    else:
        outbound = {"tag": tag, "protocol": "freedom", "settings": {}}
    if cfg.get(f"{upper}_EGRESS_MODE", "ipsec") == "xray":
        mark_name = f"{upper}_MARK"
        mark_text = cfg.get(mark_name, "0x301" if profile == "ai" else "0x351")
        try:
            mark = int(mark_text, 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{mark_name} must be decimal or hexadecimal") from exc
        if mark <= 0 or mark > 0xffffffff:
            raise ValueError(f"{mark_name} must be a nonzero uint32")
        stream = outbound.setdefault("streamSettings", {})
        if not isinstance(stream, dict):
            raise ValueError("streamSettings must be a JSON object")
        sockopt = stream.setdefault("sockopt", {})
        if not isinstance(sockopt, dict):
            raise ValueError("streamSettings.sockopt must be a JSON object")
        if "mark" in sockopt:
            custom = sockopt["mark"]
            try:
                custom_mark = int(custom, 0) if isinstance(custom, str) else int(custom)
            except (TypeError, ValueError) as exc:
                raise ValueError("streamSettings.sockopt.mark must be an integer") from exc
            if custom_mark != mark:
                raise ValueError(
                    f"{upper}_XRAY_OUTBOUND_JSON sockopt.mark conflicts with {mark_name}"
                )
        sockopt["mark"] = mark
    return outbound


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
    parser.add_argument("--uri-file")
    parser.add_argument("--json-file")
    args = parser.parse_args()
    if args.uri_file:
        with open(args.uri_file, encoding="utf-8") as source: args.uri = source.read()
    if args.json_file:
        with open(args.json_file, encoding="utf-8") as source: args.json = source.read()
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
After=network-online.target nftables.service
Wants=network-online.target nftables.service

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
ExecStartPost=/usr/local/sbin/dnscomplex egress-ready xray
ExecStopPost=/usr/local/sbin/dnscomplex egress-ready clear-xray
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

render_network() {
  write_file /etc/modules-load.d/dnscomplex.conf <<'EOF'
nf_conntrack
EOF

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
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.$WAN_IFACE.send_redirects = 0
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

configure_nsswitch_resolver_ownership() {
  [[ "$DEPLOY_MODE" == "routeros-policy" ]] || return 0
  local target tmp
  target=$(target_path /etc/nsswitch.conf)
  [[ -f "$target" ]] || return 0
  tmp=$(mktemp)
  awk '
    $1 == "hosts:" {
      output = "hosts:"
      saw_dns = 0
      comment = ""
      for (i = 2; i <= NF; i++) {
        if ($i ~ /^#/) {
          for (j = i; j <= NF; j++) {
            comment = comment (comment == "" ? "" : " ") $j
          }
          break
        }
        if ($i == "resolve") {
          if (i < NF && $(i + 1) ~ /^\[/) {
            i++
          }
          continue
        }
        if ($i == "dns") {
          saw_dns = 1
        }
        output = output " " $i
      }
      if (!saw_dns) {
        output = output " dns"
      }
      if (comment != "") {
        output = output " " comment
      }
      print output
      next
    }
    { print }
  ' "$target" >"$tmp"
  install -m 0644 "$tmp" "$target"
  rm -f "$tmp"
}

apply_runtime_network_settings() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  modprobe nf_conntrack
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
  sysctl -w net.ipv6.conf.default.forwarding=1 >/dev/null
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
    sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null
  fi
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
    if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
      sysctl -w "net.ipv4.conf.$WAN_IFACE.send_redirects=0" >/dev/null
    fi
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
$(apple_ai_support_sources)
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
$(apple_ai_support_domains)
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
EOF
    if [[ "${DEFAULT_IPV6_ACTIVE:-1}" == "0" ]]; then
      printf 'force-qtype-SOA 65\n'
    fi
    if [[ "${LOCAL_DOMAIN_IPV6_POLICY:-ipv4_only}" == "ipv4_only" ]]; then
      printf 'address /local/#6\n'
    fi
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

prepare_smartdns_preflight_config() {
  local source_config=$1 safe_config=$2 private_cache=$3
  [[ -f "$source_config" && ! -L "$source_config" ]] || return 1
  awk '
    /^[[:space:]]*#/ { print; next }
    {
      trimmed = $0
      sub(/^[[:space:]]*/, "", trimmed)
      split(trimmed, fields, /[[:space:]]+/)
      directive = tolower(fields[1])
      if (directive == "conf-file" || directive == "include" || directive ~ /^include[-_]/ ||
          directive ~ /^(cache-persist|cache-file|log-file|audit-file)=/) {
        unsafe_config = 1
        next
      }
      if (directive == "cache-persist" || directive == "cache-file" ||
          directive == "log-file" || directive == "audit-file") next
      print
    }
    END { if (unsafe_config) exit 42 }
  ' "$source_config" >"$safe_config" || return 1
  cat >>"$safe_config" <<EOF
cache-persist no
cache-file $private_cache
log-file $private_cache.log
audit-file $private_cache.audit
EOF
  chmod 0600 "$safe_config"
}

validate_rendered_smartdns() {
  local source_config work_dir safe_config output rc
  source_config=$(target_path /etc/smartdns/smartdns.conf)
  work_dir=$(mktemp -d /tmp/dnscomplex-smartdns-preflight.XXXXXX) || die "cannot create private SmartDNS preflight directory"
  chmod 0700 "$work_dir" || { rm -rf -- "$work_dir"; die "cannot protect SmartDNS preflight directory"; }
  safe_config="$work_dir/smartdns.conf"
  output="$work_dir/preflight.log"
  if ! prepare_smartdns_preflight_config "$source_config" "$safe_config" "$work_dir/smartdns.cache"; then
    rm -rf -- "$work_dir"
    die "SmartDNS preflight config is unreadable or has an unsupported include/side-effect directive"
  fi
  set +e
  timeout 2 unshare --net -- smartdns -f -c "$safe_config" -p - >"$output" 2>&1
  rc=$?
  set -e
  if [[ "$rc" != "124" ]]; then
    cat "$output" >&2
    rm -rf -- "$work_dir"
    die "SmartDNS configuration preflight failed"
  fi
  rm -rf -- "$work_dir"
}

render_local_hosts() {
  local target tmp
  target=$(target_path /etc/dnscomplex/local-hosts)
  if [[ ! -e "$target" ]]; then
    write_file /etc/dnscomplex/local-hosts <<'EOF'
# Optional local DNS overrides for .local/Codex callbacks.
# Example:
# 192.0.2.10 example-host.local
EOF
  fi
  tmp=$(mktemp)
  awk 'tolower($0) !~ /macbook-?air[.]local/' "$target" >"$tmp"
  install -m 0644 "$tmp" "$target"
  rm -f "$tmp"
}

write_adguard_allow_rules() {
  local domain
  {
    split_words "${AI_SAMPLE_DOMAINS:-}"
    split_words "${AI_SUPPORT_DOMAINS:-}"
    apple_ai_support_domains
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
http:
  pprof:
    port: 6060
    enabled: false
  doh:
    routes:
      - GET /dns-query
      - POST /dns-query
      - GET /dns-query/{ClientID}
      - POST /dns-query/{ClientID}
    insecure_enabled: false
  address: 127.0.0.1:3000
  session_ttl: 30d
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
schema_version: 34
EOF
  } | write_file /etc/AdGuardHome/AdGuardHome.yaml
  rm -f "$allow_rules"
}

render_adguard_service() {
  write_file /etc/systemd/system/AdGuardHome.service <<'EOF'
[Unit]
Description=AdGuard Home DNS filtering server
Requires=dnscomplex-network-ready.service
After=dnscomplex-network-ready.service

[Service]
Type=simple
DynamicUser=false
ExecStart=/opt/AdGuardHome/AdGuardHome --web-addr 127.0.0.1:3000 -c /etc/AdGuardHome/AdGuardHome.yaml -w /opt/AdGuardHome
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

  write_file /etc/strongswan.d/charon/agent.conf <<'EOF'
agent {
    # EAP credentials are stored in swanctl.conf; no SSH agent key is used.
    load = no
}
EOF

  write_file /etc/strongswan.d/charon/tpm.conf <<'EOF'
tpm {
    # This VM has no TPM-backed IPsec key, so probing the TPM is unnecessary.
    load = no
}
EOF

  write_file /etc/strongswan.d/charon/dhcp.conf <<'EOF'
dhcp {
    # The peers return virtual IPv4 addresses in IKEv2 configuration payloads.
    # Loading this plugin would unnecessarily bind UDP/68 beside dhcpcd.
    load = no
}
EOF

  write_file /etc/strongswan.d/swanctl.conf <<'EOF'
swanctl {
    # Older releases load daemon-only plugins into this client by default.
    # Use the credential-parser set adopted upstream for newer releases.
    load = test-vectors aesni aes rc2 sha2 sha1 md5 mgf1 rdrand random x509 pubkey pkcs1 pkcs7 pkcs12 dnskey sshkey pem openssl gcrypt pkcs8 af-alg gmp curve25519 hmac kdf drbg
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
          "mask.apple-dns.net"
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
  local source safe outbound reject=""
  outbound=$(profile_outbound_tag ai)
  [[ "${AI_EGRESS_MODE:-ipsec}" == "xray" && "${AI_QUIC_POLICY:-allow}" == "reject" ]] && reject=1
  while IFS= read -r source; do
    [[ -n "$source" ]] || continue
    safe=$(rule_set_safe_name "$source")
    if [[ "$reject" == "1" ]]; then
      printf '      {"rule_set":"geosite-ai-%s","network":"udp","port":443,"action":"reject"},\n' "$safe"
    fi
    cat <<EOF
      {
        "rule_set": "geosite-ai-$safe",
        "action": "route",
        "outbound": "$outbound"
      },
EOF
  done < <(split_words "$AI_GEOSITE_SOURCES")
  if [[ "$reject" == "1" ]]; then
    printf '      {"rule_set":"geosite-ai-support","network":"udp","port":443,"action":"reject"},\n'
  fi
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
        "server": "smartdns-ai"
      },
EOF
  done < <(split_words "$AI_GEOSITE_SOURCES")
  cat <<'EOF'
      {
        "rule_set": "geosite-ai-support",
        "action": "route",
        "server": "smartdns-ai"
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
    "level": "$SINGBOX_LOG_LEVEL",
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
$(if [[ "$CN_EGRESS_MODE" == "xray" && "$CN_QUIC_POLICY" == "reject" ]]; then printf '      {"rule_set":"geosite-cn-video","network":"udp","port":443,"action":"reject"},\n'; fi)
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
        "server": "smartdns-cn"
      }
    ],
    "final": "smartdns-default",
    "strategy": "$DEFAULT_DNS_STRATEGY"
  }
}
EOF
}

render_nft_profile_prerouting_rules() {
  local lan_if=$1 profile=$2 set_name=$3 mark=$4 mode=$5 quic_policy=$6
  local quic_rule=""
  if [[ "$quic_policy" == "reject" ]]; then
    quic_rule="    iifname \"$lan_if\" ip daddr @$set_name udp dport 443 counter reject with icmp type port-unreachable comment \"dnscomplex-${profile}-quic-reject\""
  fi
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
$quic_rule
    iifname "$lan_if" ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop"
EOF
  else
    cat <<EOF
    iifname "$lan_if" ip daddr 255.255.255.255 meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop"
$quic_rule
    iifname "$lan_if" ip daddr @$set_name meta l4proto { icmp, tcp, udp } ct mark set $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK meta mark set $mark counter comment "dnscomplex-${profile}-preroute"
EOF
  fi
}

render_nft_profile_restore_rules() {
  local lan_if=$1 profile=$2 set_name=$3 mark=$4 mode=$5 quic_policy=$6
  local quic_rule=""
  if [[ "$quic_policy" == "reject" ]]; then
    quic_rule="    iifname \"$lan_if\" ip daddr @$set_name udp dport 443 counter reject with icmp type port-unreachable comment \"dnscomplex-${profile}-quic-reject-restore\""
  fi
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
$quic_rule
    iifname "$lan_if" ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop-restore"
EOF
  else
    cat <<EOF
$quic_rule
    iifname "$lan_if" ip daddr @$set_name meta l4proto { icmp, tcp, udp } meta mark set $mark counter comment "dnscomplex-${profile}-policy-restore"
EOF
  fi
}

render_nft_lan_alias_prerouting_rules() {
  local lan_if=$1
  cat <<EOF
    iifname "$lan_if" ip daddr @lan_alias_config_ready4 meta l4proto { tcp, udp } ct mark != $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK return comment "dnscomplex-lan-alias-fresh-flow"
EOF
}

render_nft_lan_alias_output_rules() {
  if [[ "${LAN_ALIAS_RENDER_OWNED:-0}" == "1" ]]; then
    printf '    ip saddr 198.18.255.254 ip daddr != @lan_alias_ready4 counter drop comment "dnscomplex-lan-alias-owned-source-guard"\n'
  fi
  cat <<EOF
    ip saddr @lan_alias_source4 ip daddr != @lan_alias_ready4 counter drop comment "dnscomplex-lan-alias-not-ready"
    ip saddr @lan_alias_source4 ip daddr @ai4 ip daddr != @ai_ready4 counter drop comment "dnscomplex-lan-alias-ai-not-ready"
    ip saddr @lan_alias_source4 ip daddr @cn4 ip daddr != @cn_ready4 counter drop comment "dnscomplex-lan-alias-cn-not-ready"
    ip saddr @lan_alias_source4 meta mark set $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK counter comment "dnscomplex-lan-alias-default-mark"
EOF
  if [[ "$AI_QUIC_POLICY" == "reject" ]]; then
    printf '    ip saddr @lan_alias_source4 ip daddr @ai4 udp dport 443 counter reject with icmp type port-unreachable comment "dnscomplex-lan-alias-quic-reject-ai"\n'
  fi
  if [[ "$AI_EGRESS_MODE" == "ipsec" ]]; then
    printf '    ip saddr @lan_alias_source4 ip daddr @ai4 meta l4proto { tcp, udp } meta mark set %s counter comment "dnscomplex-lan-alias-classified-ai"\n' "$AI_MARK"
  fi
  if [[ "$CN_QUIC_POLICY" == "reject" ]]; then
    printf '    ip saddr @lan_alias_source4 ip daddr @cn4 udp dport 443 counter reject with icmp type port-unreachable comment "dnscomplex-lan-alias-quic-reject-cn"\n'
  fi
  if [[ "$CN_EGRESS_MODE" == "ipsec" ]]; then
    printf '    ip saddr @lan_alias_source4 ip daddr @cn4 meta l4proto { tcp, udp } meta mark set %s counter comment "dnscomplex-lan-alias-classified-cn"\n' "$CN_MARK"
  fi
  printf '    ip saddr @lan_alias_source4 counter accept comment "dnscomplex-lan-alias-default-output"\n'
}

render_nft_lan_alias_default_snat_rule() {
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    printf '    oifname "%s" ip saddr @lan_alias_source4 counter snat ip to %s comment "dnscomplex-lan-alias-snat-default"\n' "$WAN_IFACE" "$LINUX_LAN_IPV4"
  else
    printf '    oifname "%s" ip saddr @lan_alias_source4 counter masquerade comment "dnscomplex-lan-alias-snat-default"\n' "$WAN_IFACE"
  fi
}

render_nft_classified_output_rules() {
  local profile=$1 mark=$2 quic_policy=$3 mode=$4
  [[ "$mode" == "ipsec" ]] || return 0
  local selector="oifname \"ipsec-${profile}\"" quic_rule=""
  if [[ "$quic_policy" == "reject" ]]; then
    quic_rule="    $selector udp dport 443 counter reject with icmp type port-unreachable comment \"dnscomplex-${profile}-classified-quic-reject\""
  fi
  cat <<EOF
    $selector meta nfproto ipv6 counter drop comment "dnscomplex-${profile}-classified-ipv6-drop"
    $selector ip daddr != @${profile}_ready4 counter drop comment "dnscomplex-${profile}-classified-not-ready"
$quic_rule
    $selector counter meta mark set $mark accept comment "dnscomplex-${profile}-classified-output"
EOF
}

render_nft_profile_output_rules() {
  local profile=$1 set_name=$2 mark=$3 mode=$4 quic_policy=$5
  local quic_rule=""
  if [[ "$quic_policy" == "reject" ]]; then
    quic_rule="    ip daddr @$set_name udp dport 443 counter reject with icmp type port-unreachable comment \"dnscomplex-${profile}-quic-reject-output\""
  fi
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
$quic_rule
    ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop-output"
EOF
  else
    cat <<EOF
$quic_rule
    ip daddr @$set_name meta l4proto { icmp, tcp, udp } meta mark set $mark
EOF
  fi
}

render_nft_xray_transport_output_rules() {
  local profile=$1 mark=$2 mode=$3
  [[ "$mode" == "xray" ]] || return 0
  cat <<EOF
    ip saddr != 198.18.255.254 meta mark $mark ip daddr @${profile}_ready4 counter meta mark set $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK accept comment "dnscomplex-${profile}-xray-underlay-ready4"
    meta mark $mark ip6 daddr @${profile}_ready6 counter meta mark set $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK accept comment "dnscomplex-${profile}-xray-underlay-ready6"
    ip saddr != 198.18.255.254 meta mark $mark counter drop comment "dnscomplex-${profile}-xray-underlay-not-ready"
EOF
}

render_nft_profile_dataplane_probe_output_rule() {
  local profile=$1 mode=$2 probe_mark resolver_ip profile_mark
  [[ "$mode" == "ipsec" ]] || return 0
  case "$profile" in
    ai)
      probe_mark=$IPSEC_DATAPLANE_AI_MARK
      profile_mark=$AI_MARK
      resolver_ip=104.16.248.249
      ;;
    cn)
      probe_mark=$IPSEC_DATAPLANE_CN_MARK
      profile_mark=$CN_MARK
      resolver_ip=223.6.6.6
      ;;
    *) return 1 ;;
  esac
  printf -v probe_mark '0x%x' "$((probe_mark))"
  printf -v profile_mark '0x%x' "$((profile_mark))"
  printf '    ip saddr @%s_probe_vip4 oifname "ipsec-%s" ip daddr %s tcp dport 443 meta mark %s counter meta mark set %s accept comment "dnscomplex-%s-dataplane-probe"\n' \
    "$profile" "$profile" "$resolver_ip" "$probe_mark" "$profile_mark" "$profile"
}

render_routeros_default_snat_rule() {
  local lan_if=$1
  [[ "$DEPLOY_MODE" == "routeros-policy" ]] || return 0
  cat <<EOF
    oifname "$lan_if" ip saddr $LAN_CLIENT_IPV4_CIDR ip daddr != { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } counter snat ip to $LINUX_LAN_IPV4 comment "dnscomplex-routeros-default-snat"
EOF
}

render_nftables() {
  local lan_if="${WAN_IFACE}.${LAN_VLAN_ID:-}"
  LAN_ALIAS_RENDER_OWNED=0
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    lan_if="$WAN_IFACE"
  fi
  if [[ "$DRY_RUN" != "1" ]]; then
    local alias_helper alias_state alias_config
    alias_helper=$(target_path /usr/local/libexec/dnscomplex-lan-alias)
    alias_state=$(target_path /var/lib/dnscomplex/lan-alias.json)
    alias_config=$(target_path /etc/sing-box/config.json)
    if [[ -e "$alias_state" || -L "$alias_state" ]]; then
      [[ -x "$alias_helper" ]] || die "LAN alias ownership state exists but its validator is missing"
      python3 "$alias_helper" verify-owner --state "$alias_state" --config "$alias_config" ||
        die "LAN alias ownership could not be verified before rendering nft rules"
      LAN_ALIAS_RENDER_OWNED=1
    fi
  fi
  write_file /etc/nftables.d/dnscomplex.nft <<EOF
table inet dnscomplex {
  set ai4 {
    type ipv4_addr
    flags timeout
    size 262144
  }

  set cn4 {
    type ipv4_addr
    flags timeout
    size 262144
  }

  set ai_ready4 {
    type ipv4_addr
    flags interval
  }

  set cn_ready4 {
    type ipv4_addr
    flags interval
  }

  set ai_probe_vip4 {
    type ipv4_addr
    flags interval
  }

  set cn_probe_vip4 {
    type ipv4_addr
    flags interval
  }

  set lan_alias_source4 {
    type ipv4_addr
    flags interval
$(if [[ "$LAN_ALIAS_RENDER_OWNED" == "1" ]]; then printf '    elements = { 198.18.255.254 }\n'; fi)
  }

  set lan_alias_ready4 {
    type ipv4_addr
    flags interval
  }

  set lan_alias_config_ready4 {
    type ipv4_addr
    flags interval
  }

  set ai_ready6 {
    type ipv6_addr
    flags interval
  }

  set cn_ready6 {
    type ipv6_addr
    flags interval
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
$(render_nft_lan_alias_prerouting_rules "$lan_if")
    iifname "$lan_if" ip daddr @ai4 ip daddr != @ai_ready4 counter drop comment "dnscomplex-ai-not-ready"
    iifname "$lan_if" ip daddr @cn4 ip daddr != @cn_ready4 counter drop comment "dnscomplex-cn-not-ready"
$(render_nft_profile_prerouting_rules "$lan_if" ai ai4 "$AI_MARK" "$AI_EGRESS_MODE" "$AI_QUIC_POLICY")
$(render_nft_profile_prerouting_rules "$lan_if" cn cn4 "$CN_MARK" "$CN_EGRESS_MODE" "$CN_QUIC_POLICY")
  }

  chain prerouting_policy_restore {
    type filter hook prerouting priority filter; policy accept;
    iifname "$lan_if" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept
    iifname "$lan_if" ip daddr @lan_alias_config_ready4 meta l4proto { tcp, udp } ct mark != $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK return comment "dnscomplex-lan-alias-fresh-flow-restore"
$(render_nft_profile_restore_rules "$lan_if" ai ai4 "$AI_MARK" "$AI_EGRESS_MODE" "$AI_QUIC_POLICY")
$(render_nft_profile_restore_rules "$lan_if" cn cn4 "$CN_MARK" "$CN_EGRESS_MODE" "$CN_QUIC_POLICY")
  }

  chain forward {
    type filter hook forward priority filter; policy accept;
    tcp flags syn tcp option maxseg size > $IPSEC_TCP_MSS tcp option maxseg size set $IPSEC_TCP_MSS
  }

  chain output {
    type route hook output priority mangle; policy accept;
$(render_nft_profile_dataplane_probe_output_rule ai "$AI_EGRESS_MODE")
$(render_nft_profile_dataplane_probe_output_rule cn "$CN_EGRESS_MODE")
$(render_nft_xray_transport_output_rules ai "$AI_MARK" "$AI_EGRESS_MODE")
$(render_nft_xray_transport_output_rules cn "$CN_MARK" "$CN_EGRESS_MODE")
$(render_nft_lan_alias_output_rules)
    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept
    udp dport { 500, 4500 } accept comment "dnscomplex-ipsec-underlay"
$(render_nft_classified_output_rules ai "$AI_MARK" "$AI_QUIC_POLICY" "$AI_EGRESS_MODE")
$(render_nft_classified_output_rules cn "$CN_MARK" "$CN_QUIC_POLICY" "$CN_EGRESS_MODE")
    meta mark $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK counter accept comment "dnscomplex-domain-default-output"
    ip daddr @ai4 ip daddr != @ai_ready4 counter drop comment "dnscomplex-ai-not-ready-output"
    ip daddr @cn4 ip daddr != @cn_ready4 counter drop comment "dnscomplex-cn-not-ready-output"
$(render_nft_profile_output_rules ai ai4 "$AI_MARK" "$AI_EGRESS_MODE" "$AI_QUIC_POLICY")
$(render_nft_profile_output_rules cn cn4 "$CN_MARK" "$CN_EGRESS_MODE" "$CN_QUIC_POLICY")
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
$(render_nft_lan_alias_default_snat_rule "$lan_if")
$(render_routeros_default_snat_rule "$lan_if")
  }
}
EOF

  write_file /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.nft"
EOF
}

render_restore_recovery() {
  write_file /usr/local/libexec/dnscomplex-restore-recover <<'RECOVERY'
#!/usr/bin/env bash
set -uo pipefail
IFS=$'\n\t'

STATE_DIR=${DNSCOMPLEX_RESTORE_STATE_DIR:-/var/lib/dnscomplex-restore}
OPERATION_HELPER=${DNSCOMPLEX_OPERATION_HELPER:-${DNSCOMPLEX_FS_ROOT:-}/usr/local/libexec/dnscomplex-operation}

operation_journal_event() {
  local transaction=$1 event=$2 name
  name=$(basename -- "$transaction")
  [[ "$name" == transaction.op.* ]] || return 0
  name=${name#transaction.op.}
  [[ "$name" =~ ^[a-f0-9]{32}$ && -f "$OPERATION_HELPER" && ! -L "$OPERATION_HELPER" ]] || return 1
  if [[ "$event" == validate ]]; then
    if ! python3 "$OPERATION_HELPER" validate-journal "$name" "$transaction"; then
      python3 "$OPERATION_HELPER" journal-failed "$name" || true
      return 1
    fi
  else
    python3 "$OPERATION_HELPER" journal-result "$name" "$event"
  fi
}

warn() {
  printf '[dnscomplex-restore-recover] %s\n' "$*" >&2
}

path_exists() {
  [[ -e "$1" || -L "$1" ]]
}

durable_sync_path() {
  local path=$1
  sync -f "$path" 2>/dev/null || sync
}

finalize_transaction_cleanup() {
  local transaction=$1 finalized
  finalized="$STATE_DIR/cleanup.$(basename -- "$transaction")"
  if [[ -e "$finalized" || -L "$finalized" ]]; then
    warn "cleanup destination already exists: $finalized"
    return 1
  fi
  mv -- "$transaction" "$finalized" || return 1
  durable_sync_path "$STATE_DIR" || return 1
  if ! rm -rf -- "$finalized"; then
    warn "deferred cleanup remains at $finalized"
    return 0
  fi
  durable_sync_path "$STATE_DIR"
}

service_unit_allowed() {
  case "$1" in
    systemd-networkd.service|nftables.service|dnsmasq.service|radvd.service|systemd-resolved.service|\
strongswan-swanctl.service|strongswan-starter.service|strongswan.service|ipsec.service|\
smartdns.service|AdGuardHome.service|sing-box.service|xray-dnscomplex.service|\
dnscomplex-network-ready.service|dnscomplex-ipsec-ifaces.service|dnscomplex-ipsec-ready.service|\
dnscomplex-routing.service|dnscomplex-health.timer|dnscomplex-update.timer|\
dnscomplex-cn-overrides.timer|dnscomplex-nftset-refresh.timer|dnscomplex-metrics.service|\
dnscomplex-metrics-sample.timer|dnscomplex-web.service|sshd-unix-local.socket|\
sshd-vsock.socket|sshd-unix-export.socket)
      return 0
      ;;
    *) return 1 ;;
  esac
}

restore_service_units_in_order() {
  cat <<'EOF'
systemd-networkd.service
nftables.service
dnsmasq.service
radvd.service
systemd-resolved.service
dnscomplex-ipsec-ifaces.service
strongswan-swanctl.service
strongswan-starter.service
strongswan.service
ipsec.service
dnscomplex-network-ready.service
dnscomplex-ipsec-ready.service
dnscomplex-routing.service
smartdns.service
AdGuardHome.service
sing-box.service
xray-dnscomplex.service
dnscomplex-health.timer
dnscomplex-update.timer
dnscomplex-cn-overrides.timer
dnscomplex-nftset-refresh.timer
dnscomplex-metrics.service
dnscomplex-metrics-sample.timer
dnscomplex-web.service
sshd-unix-local.socket
sshd-vsock.socket
sshd-unix-export.socket
EOF
}

quiesce_units() {
  cat <<'EOF'
dnscomplex-network-ready.service
dnscomplex-health.timer
dnscomplex-health.service
dnscomplex-update.timer
dnscomplex-update.service
dnscomplex-cn-overrides.timer
dnscomplex-cn-overrides.service
dnscomplex-nftset-refresh.timer
dnscomplex-nftset-refresh.service
dnscomplex-metrics-sample.timer
dnscomplex-metrics-sample.service
dnscomplex-metrics.service
dnscomplex-web.service
smartdns.service
AdGuardHome.service
sing-box.service
xray-dnscomplex.service
dnscomplex-routing.service
dnscomplex-ipsec-ready.service
strongswan-swanctl.service
strongswan-starter.service
strongswan.service
ipsec.service
dnscomplex-ipsec-ifaces.service
EOF
}

quiesce_service_state_units() {
  local unit state
  command -v systemctl >/dev/null 2>&1 || return 0
  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    state=$(systemctl is-active "$unit" 2>/dev/null || true)
    case "$state" in
      active|activating|reloading|deactivating)
        systemctl stop "$unit" || return 1
        state=$(systemctl is-active "$unit" 2>/dev/null || true)
        case "$state" in
          active|activating|reloading|deactivating)
            warn "$unit remained active during recovery"
            return 1
            ;;
        esac
        ;;
    esac
  done < <(quiesce_units)
}

restore_service_state_file() {
  local state_file=$1 unit enabled active extra failed=0
  [[ -e "$state_file" || -L "$state_file" ]] || {
    warn "service-state file is missing: $state_file"
    return 1
  }
  [[ -f "$state_file" && ! -L "$state_file" ]] || {
    warn "unsafe service-state file: $state_file"
    return 1
  }
  [[ -s "$state_file" ]] || return 0
  command -v systemctl >/dev/null 2>&1 || return 0

  while IFS=$'\t' read -r unit enabled active extra; do
    [[ "$unit" =~ ^[A-Za-z0-9@_.:-]+$ &&
       -n "$enabled" && -n "$active" && -z "${extra:-}" ]] || {
      warn "unsafe service-state row in $state_file"
      failed=1
      continue
    }
    service_unit_allowed "$unit" || {
      warn "unmanaged service-state unit in $state_file: $unit"
      failed=1
      continue
    }
  done <"$state_file"
  [[ "$failed" == "0" ]] || return 1

  systemctl daemon-reload || failed=1
  while IFS=$'\t' read -r unit enabled active extra; do
    case "$enabled" in
      enabled)
        systemctl unmask "$unit" >/dev/null 2>&1 || true
        systemctl enable "$unit" || failed=1
        ;;
      enabled-runtime)
        systemctl unmask "$unit" >/dev/null 2>&1 || true
        systemctl enable --runtime "$unit" || failed=1
        ;;
      disabled)
        systemctl unmask "$unit" >/dev/null 2>&1 || true
        systemctl disable "$unit" || failed=1
        ;;
      masked) systemctl mask "$unit" || failed=1 ;;
      masked-runtime) systemctl mask --runtime "$unit" || failed=1 ;;
      static|indirect|generated|alias|linked|linked-runtime|transient|unknown) ;;
      *)
        warn "unsafe service enablement for $unit"
        failed=1
        ;;
    esac
  done <"$state_file"

  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    enabled=$(awk -F '\t' -v target="$unit" '$1 == target { print $2; exit }' "$state_file")
    active=$(awk -F '\t' -v target="$unit" '$1 == target { print $3; exit }' "$state_file")
    [[ -n "$enabled" && -n "$active" ]] || continue
    case "$active" in
      active|activating|reloading)
        systemctl restart "$unit" || failed=1
        ;;
      inactive|failed|deactivating|maintenance|unknown)
        systemctl stop "$unit" || failed=1
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        ;;
      *)
        warn "unsafe service activity for $unit"
        failed=1
        ;;
    esac
  done < <(restore_service_units_in_order)
  [[ "$failed" == "0" ]]
}

recover_transaction() {
  local transaction=$1 mode=${2:-all}
  local status dst slot had_old extra before candidate entry
  local dst_parent dst_base slot_parent slot_base previous previous_dst previous_slot
  local failed=0 index previous_index entries_count=0 services_needed=0 files_done=0
  local -a entries=()
  [[ "$mode" == "all" || "$mode" == "files" || "$mode" == "services" ]] || return 2
  case "$transaction" in
    "$STATE_DIR"/transaction.*) ;;
    *)
      warn "refusing transaction outside $STATE_DIR: $transaction"
      return 1
      ;;
  esac
  if [[ -L "$transaction" ]]; then
    warn "transaction path must not be a symlink: $transaction"
    return 1
  fi
  [[ -e "$transaction" ]] || return 0
  [[ -d "$transaction" ]] || {
    warn "transaction path must be a directory: $transaction"
    return 1
  }
  operation_journal_event "$transaction" validate || return 1
  [[ -f "$transaction/entries.tsv" && ! -L "$transaction/entries.tsv" ]] || {
    warn "transaction journal is missing: $transaction"
    return 1
  }
  while IFS= read -r entry || [[ -n "$entry" ]]; do
    entries[entries_count]=$entry
    entries_count=$((entries_count + 1))
  done <"$transaction/entries.tsv"
  for ((index = 0; index < entries_count; index++)); do
    IFS=$'\t' read -r status dst slot had_old extra <<<"${entries[index]}"
    if [[ ( "$status" != "present" && "$status" != "absent" ) ||
          "$dst" != /* || "$dst" == "/" ||
          "$dst" == *$'\t'* || "$dst" == *$'\n'* ||
          "$dst" == *"//"* || "$dst" == *"/./"* ||
          "$dst" == *"/../"* || "$dst" == */. || "$dst" == */.. ||
          "$slot" != /* || "$slot" == *$'\t'* || "$slot" == *$'\n'* ||
          "$slot" == *"//"* || "$slot" == *"/./"* ||
          "$slot" == *"/../"* || "$slot" == */. || "$slot" == */.. ||
          ( "$had_old" != "0" && "$had_old" != "1" ) ||
          -n "${extra:-}" ]]; then
      warn "unsafe transaction row in $transaction"
      return 1
    fi
    dst_parent=$(dirname -- "$dst")
    dst_base=$(basename -- "$dst")
    slot_parent=$(dirname -- "$slot")
    slot_base=$(basename -- "$slot")
    if [[ "$slot_parent" != "$dst_parent" ||
          "$slot_base" != ".dnscomplex-restore.${dst_base}."?* ||
          ( -e "$slot" && ( ! -d "$slot" || -L "$slot" ) ) ]]; then
      warn "unsafe transaction staging path in $transaction"
      return 1
    fi
    for ((previous_index = 0; previous_index < index; previous_index++)); do
      previous=${entries[previous_index]}
      IFS=$'\t' read -r _ previous_dst previous_slot _ _ <<<"$previous"
      if [[ "$dst" == "$previous_dst" || "$slot" == "$previous_slot" ]]; then
        warn "duplicate transaction destination or staging path in $transaction"
        return 1
      fi
    done
  done
  if [[ -e "$transaction/committed" || -L "$transaction/committed" ]]; then
    [[ -f "$transaction/committed" && ! -L "$transaction/committed" ]] || {
      warn "unsafe commit marker in $transaction"
      return 1
    }
    for ((index = 0; index < entries_count; index++)); do
      IFS=$'\t' read -r status dst slot had_old extra <<<"${entries[index]}"
      rm -rf -- "$slot" || return 1
      durable_sync_path "$(dirname -- "$slot")" || return 1
    done
    operation_journal_event "$transaction" committed || return 1
    finalize_transaction_cleanup "$transaction"
    return
  fi

  if [[ -e "$transaction/services-quiescing" ||
        -L "$transaction/services-quiescing" ]]; then
    [[ -f "$transaction/services-quiescing" &&
       ! -L "$transaction/services-quiescing" ]] || {
      warn "unsafe service-quiesce marker in $transaction"
      return 1
    }
    services_needed=1
  fi
  if [[ -e "$transaction/files-recovered" ||
        -L "$transaction/files-recovered" ]]; then
    [[ -f "$transaction/files-recovered" &&
       ! -L "$transaction/files-recovered" ]] || {
      warn "unsafe file-recovery marker in $transaction"
      return 1
    }
    files_done=1
  fi

  if [[ "$services_needed" == "1" && "$mode" != "files" ]]; then
    quiesce_service_state_units || return 1
  fi

  if [[ "$mode" == "services" ]]; then
    [[ "$files_done" == "1" ]] || {
      warn "service recovery requested before file recovery: $transaction"
      return 1
    }
    if [[ "$services_needed" == "1" ]]; then
      restore_service_state_file "$transaction/pre-service-state.tsv" || return 1
    fi
    operation_journal_event "$transaction" rolled-back || return 1
    finalize_transaction_cleanup "$transaction"
    return
  fi

  if [[ "$files_done" == "0" ]]; then
    for ((index = entries_count - 1; index >= 0; index--)); do
      IFS=$'\t' read -r status dst slot had_old extra <<<"${entries[index]}"
      before="$slot/before"
      candidate="$slot/candidate"
      if path_exists "$before"; then
        if ! rm -rf -- "$dst" || ! mkdir -p -- "$(dirname "$dst")" ||
           ! mv -- "$before" "$dst"; then
          warn "could not restore $dst from $before"
          failed=1
          continue
        fi
        durable_sync_path "$(dirname -- "$dst")" || failed=1
      elif [[ "$had_old" == "0" ]]; then
        rm -rf -- "$dst" || {
          warn "could not remove newly restored path $dst"
          failed=1
          continue
        }
        durable_sync_path "$(dirname -- "$dst")" || failed=1
      elif ! path_exists "$dst"; then
        warn "original path is missing and has no rollback copy: $dst"
        failed=1
        continue
      fi
      rm -rf -- "$candidate" 2>/dev/null || true
    done
    [[ "$failed" == "0" ]] || return 1
    for ((index = 0; index < entries_count; index++)); do
      IFS=$'\t' read -r status dst slot had_old extra <<<"${entries[index]}"
      rm -rf -- "$slot" || return 1
      durable_sync_path "$(dirname -- "$slot")" || return 1
    done
    : >"$transaction/files-recovered"
    chmod 0600 "$transaction/files-recovered" || return 1
    durable_sync_path "$transaction" || return 1
  fi

  if [[ "$mode" == "files" && "$services_needed" == "1" ]]; then
    operation_journal_event "$transaction" recovering || return 1
    return 0
  fi
  if [[ "$services_needed" == "1" ]]; then
    restore_service_state_file "$transaction/pre-service-state.tsv" || return 1
  fi
  operation_journal_event "$transaction" rolled-back || return 1
  finalize_transaction_cleanup "$transaction"
}

main() {
  local transaction mode=files lock_file
  lock_file=${DNSCOMPLEX_MAINTENANCE_LOCK:-${DNSCOMPLEX_FS_ROOT:-}/run/lock/dnscomplex-maintenance.lock}
  if [[ "${1:-}" != "--check" && "${DNSCOMPLEX_MAINTENANCE_LOCK_HELD:-0}" != 1 ]]; then
    mkdir -p -- "$(dirname -- "$lock_file")" || return 1
    exec 8>"$lock_file" || return 1
    chmod 0600 "$lock_file" || return 1
    flock -w 120 8 || return 1
    export DNSCOMPLEX_MAINTENANCE_LOCK_HELD=1
  fi
  if [[ "${DNSCOMPLEX_MAINTENANCE_LOCK_HELD:-0}" == 1 ]]; then
    ( : >&8 ) 2>/dev/null || return 1
  fi
  if [[ "${1:-}" == "--check" ]]; then
    [[ $# -eq 1 ]] || return 2
    for transaction in bash basename chmod dirname flock mkdir mv rm sync systemctl; do
      command -v "$transaction" >/dev/null 2>&1 || {
        warn "required recovery command is unavailable: $transaction"
        return 1
      }
    done
    return 0
  fi
  [[ ! -L "$STATE_DIR" ]] || {
    warn "restore state directory must not be a symlink"
    return 1
  }
  mkdir -p -- "$STATE_DIR" || return 1
  [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || {
    warn "restore state path must be a directory"
    return 1
  }
  chmod 0700 "$STATE_DIR" || return 1
  if [[ "${1:-}" == "--transaction" ]]; then
    [[ $# -eq 2 ]] || return 2
    recover_transaction "$2" all
    return
  fi
  case "${1:-}" in
    --files) mode=files ;;
    --services) mode=services ;;
    "") mode=files ;;
    *) return 2 ;;
  esac
  [[ $# -le 1 ]] || return 2
  shopt -s nullglob
  for transaction in "$STATE_DIR"/cleanup.transaction.*; do
    rm -rf -- "$transaction" || {
      warn "could not remove deferred cleanup path: $transaction"
      return 1
    }
    durable_sync_path "$STATE_DIR" || return 1
  done
  for transaction in "$STATE_DIR"/transaction.*; do
    recover_transaction "$transaction" "$mode" || return 1
  done
  if [[ -f "$OPERATION_HELPER" ]]; then
    python3 "$OPERATION_HELPER" boot-sync || return 1
  fi
}

main "$@"
RECOVERY
  chmod_target 0755 /usr/local/libexec/dnscomplex-restore-recover

  write_file /etc/systemd/system/dnscomplex-restore-recovery.service <<'EOF'
[Unit]
Description=Recover an interrupted dnscomplex restore transaction
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target network-pre.target dnscomplex-network-ready.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/dnscomplex-restore-recover --files

[Install]
RequiredBy=sysinit.target
EOF

  write_file /etc/systemd/system/dnscomplex-restore-services.service <<'EOF'
[Unit]
Description=Restore dnscomplex service state after interrupted restore
Requires=dnscomplex-restore-recovery.service
After=basic.target dnscomplex-restore-recovery.service
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/dnscomplex-restore-recover --services

[Install]
RequiredBy=multi-user.target
EOF
}

render_operation_lifecycle() {
  write_file /usr/local/libexec/dnscomplex-operation <<'OPERATION_HELPER'
#!/usr/bin/env python3
"""Fixed dnscomplex writer lifecycle. Payload and recovery data never enter argv."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import tarfile

ROOT = Path(os.environ.get('DNSCOMPLEX_FS_ROOT') or '/')
OPERATIONS = ROOT / 'var/lib/dnscomplex-operations'
RESTORE = ROOT / 'var/lib/dnscomplex-restore'
LOCK = Path(os.environ.get('DNSCOMPLEX_MAINTENANCE_LOCK', str(ROOT / 'run/lock/dnscomplex-maintenance.lock')))
MANAGER = ROOT / 'usr/local/sbin/dnscomplex'
RECOVERY = ROOT / 'usr/local/libexec/dnscomplex-restore-recover'
ACTIONS = frozenset(('config','wizard-apply','egress-apply','domain-batch','set-xray-uri','set-xray-json','rules-domain','rules-geosite','fix',
    'refresh-nftsets','refresh-cn-overrides','update-geosite','mss-calibrate','set-egress',
    'set-socks','set-ipsec','set-web-password','set-local-host','set-update-time','add-domain','remove-domain','test-xray'))
TERMINAL = ('committed','rolled-back')

class OperationBusy(ValueError):
    pass


def sync(path):
    fd = os.open(path, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def private(path, directory=False):
    value = path.lstat()
    if value.st_uid != os.geteuid() or value.st_mode & 0o077 or not (
            stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)):
        raise ValueError('unsafe operation material')


def mkdir(path):
    # Reject symlinks in every existing ancestor before creating anything.
    for parent in (path, *path.parents):
        if parent.is_symlink(): raise ValueError('unsafe operation ancestry')
    created=not path.exists()
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    private(path, True)
    if created:
        sync(path); sync(path.parent)


def write(path, data):
    fd, name = tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(data, out, sort_keys=True)
            out.write('\n'); out.flush(); os.fsync(out.fileno())
        os.replace(temp, path); sync(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def read(path):
    private(path)
    return json.loads(path.read_text())


def digest(path):
    private(path)
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''): value.update(block)
    return value.hexdigest()


def tree_digest(path):
    value = hashlib.sha256()
    def visit(item, rel):
        info = item.lstat()
        value.update((rel + ':' + oct(stat.S_IMODE(info.st_mode)) + ':').encode())
        if item.is_symlink(): value.update(b'L' + os.readlink(item).encode())
        elif item.is_dir():
            value.update(b'D')
            for child in sorted(item.iterdir()): visit(child, rel + '/' + child.name)
        elif item.is_file():
            value.update(b'F')
            with item.open('rb') as stream:
                for block in iter(lambda: stream.read(1024*1024), b''): value.update(block)
        else: raise ValueError('unsafe snapshot entry')
    visit(path, '.')
    return value.hexdigest()


def location(oid):
    if not re.fullmatch('[a-f0-9]{32}', oid): raise ValueError('invalid operation ID')
    private(OPERATIONS, True)
    directory = OPERATIONS / oid
    private(directory, True)
    return directory


def record(oid):
    directory = location(oid)
    value = read(directory / 'manifest.json')
    if (value.get('schema_version') != 1 or value.get('id') != oid or
            value.get('owner_unit') != 'dnscomplex-operation@' + oid + '.service' or
            value.get('action') not in ACTIONS): raise ValueError('invalid operation owner/schema')
    if value.get('phase') not in ('queued','preparing','prepared','applying','rolling-back','recovering','recovery-required','manual-intervention','committed','rolled-back'):
        raise ValueError('invalid phase')
    if not isinstance(value.get('deadline'),int) or isinstance(value.get('deadline'),bool):
        raise ValueError('invalid deadline')
    if value.get('error_code','') not in ('','START_FAILED','PREPARE_FAILED','CANDIDATE_FAILED','MISSING_JOURNAL','RECOVERY_FAILED','RECOVERY_INTERRUPTED','MONITORING_WARNING'):
        raise ValueError('invalid safe error code')
    if value.get('rollback_state','not-started') not in ('not-started','not-needed','running','verified','failed'):
        raise ValueError('invalid rollback state')
    return value


def update(oid, **changes):
    value = record(oid)
    if value['phase'] in TERMINAL: return value
    value.update(changes)
    write(location(oid) / 'manifest.json', value)
    return value


@contextlib.contextmanager
def locked(path, wait=True):
    for parent in (path.parent, *path.parent.parents):
        if parent.is_symlink(): raise ValueError('unsafe lock ancestry')
    path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        private(path)
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        yield fd
    finally: os.close(fd)


def staging_name(name):
    return re.fullmatch(r'\.operation-(?:submit|create)\.[a-f0-9]{32}', name) is not None


def operation_directories():
    private(OPERATIONS,True)
    for directory in OPERATIONS.iterdir():
        private(directory,True)
        if staging_name(directory.name): continue
        if not re.fullmatch('[a-f0-9]{32}',directory.name): raise ValueError('unknown operation entry')
        yield directory


def cleanup_staging():
    # Only a caller holding the maintenance lock may reclaim these unpublished
    # server-generated directories. Never remove a visible malformed record.
    removed=False
    for directory in OPERATIONS.iterdir():
        if staging_name(directory.name):
            private(directory,True)
            shutil.rmtree(directory); removed=True
    if removed: sync(OPERATIONS)


def gate(own=None):
    if not OPERATIONS.exists(): return
    private(OPERATIONS, True)
    for directory in operation_directories():
        private(directory, True)
        value = read(directory / 'manifest.json')
        if directory.name == own:
            if value.get('schema_version') != 1 or value.get('id') != own or value.get('phase') not in ('queued','preparing','prepared','applying','rolling-back','recovering'):
                raise ValueError('invalid inherited operation ownership')
            continue
        if value.get('phase') not in TERMINAL: raise OperationBusy('unresolved operation blocks mutation')


def systemctl(*args):
    return subprocess.check_output(['systemctl', *args], text=True, stderr=subprocess.DEVNULL,
                                   start_new_session=True,timeout=20).strip()


def status(oid):
    value = record(oid)
    phase = value['phase']
    ok = True if phase == 'committed' else False if phase in ('rolled-back','manual-intervention') else None
    return dict(operation_id=oid, action=value['action'], phase=phase, ok=ok,
                deadline=value['deadline'], rollback_state=value.get('rollback_state','not-started'),
                error_code=value.get('error_code',''), message={
                    'committed':('Operation committed; monitoring repair reported a warning.' if value.get('error_code') == 'MONITORING_WARNING' else 'Operation committed.'), 'rolled-back':'Operation rolled back.',
                    'manual-intervention':'Recovery requires operator intervention.',
                    'recovery-required':'Recovery is pending.'}.get(phase,'Operation in progress.'))


def submit(action, payload, *, announce=None):
    if action in ('refresh-nftsets','refresh-cn-overrides'): raise ValueError('runtime refresh requires scoped execution')
    if action not in ACTIONS or not isinstance(payload, dict): raise ValueError('invalid operation action')
    if len(json.dumps(payload).encode()) > 1024*1024: raise ValueError('payload too large')
    mkdir(OPERATIONS)
    with locked(LOCK, False):
        cleanup_staging()
        # An interrupted previous submit can be resumed by an ordinary CLI/API
        # mutation; recovery must not depend on a web restart.
        resume()
        gate()
        oid = uuid.uuid4().hex
        directory = OPERATIONS / oid
        staging = OPERATIONS / ('.operation-submit.'+oid)
        mkdir(staging)
        write(staging / 'payload.json', payload)
        write(staging / 'manifest.json', dict(schema_version=1,id=oid,action=action,phase='queued',
            owner_unit='dnscomplex-operation@'+oid+'.service',deadline=int(time.time())+300,
            rollback_state='not-started',error_code='',candidate_sha256=digest(staging/'payload.json')))
        sync(staging)
        if directory.exists() or directory.is_symlink(): raise ValueError('operation ID collision')
        os.rename(staging,directory)
        sync(OPERATIONS)
        try:
            if announce is not None: announce(oid)
            systemctl('start','dnscomplex-operation-guard@'+oid+'.timer')
        except BaseException:
            # No writer start has been attempted: even an uncertain guard start
            # cannot mutate state. A safely terminal record cannot poison gate.
            update(oid, phase='rolled-back', rollback_state='not-needed', error_code='START_FAILED')
            (directory / 'payload.json').unlink(missing_ok=True)
            raise
        # From this point a failed/interrupted start may already have launched
        # the writer. Preserve queued ownership and its independently armed guard.
        systemctl('--no-block','start','dnscomplex-operation@'+oid+'.service')
    return status(oid)


def manager(function, *args, lock_fd):
    env = dict(os.environ, DNSCOMPLEX_FS_ROOT=str(ROOT), DNSCOMPLEX_MAINTENANCE_LOCK=str(LOCK),
               DNSCOMPLEX_MAINTENANCE_LOCK_HELD='1', DNSCOMPLEX_OPERATION_INTERNAL='1')
    # fd8 is inherited by CLI descendants; $0 remains the installed manager.
    return subprocess.run(['bash','-c','exec 8<&"$1"; shift; exec bash "$@"','_',str(lock_fd),str(MANAGER),
        'operation-internal',function,*map(str,args)],env=env,pass_fds=(lock_fd,),
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode


def prepare(oid, lock_fd):
    directory = location(oid)
    original = record(oid)
    mkdir(RESTORE)
    # Freeze recovery semantics before backup; neither is in the managed BASE tree.
    for source, name in ((RECOVERY,'restore-recover'), (Path(__file__),'operation-helper.py')):
        shutil.copyfile(source, directory / name); os.chmod(directory / name,0o600); sync(directory / name)
    if manager('operation_prepare_cmd',directory,original['action'],lock_fd=lock_fd):
        raise ValueError('baseline preparation failed')
    value = read(directory / 'manifest.json')
    value.update({key:original[key] for key in ('id','action','owner_unit','deadline','error_code','candidate_sha256')})
    value['helper_sha256'] = digest(directory / 'restore-recover')
    value['operation_helper_sha256'] = digest(directory / 'operation-helper.py')
    write(directory / 'manifest.json',value)
    # Archive was already validated by the emitted manager. Extract locally again
    # under that same validator to produce the existing recovery-journal ABI.
    if manager('operation_journal_cmd',directory,lock_fd=lock_fd):
        raise ValueError('journal preparation failed')
    journal = RESTORE / ('.operation-prep.'+oid)
    value = record(oid)
    value.update(journal_sha256=digest(journal / 'entries.tsv'), snapshots={})
    for row in (journal / 'entries.tsv').read_text().splitlines():
        _, dst, slot, had_old = row.split('\t')
        if had_old == '1': value['snapshots'][dst] = tree_digest(Path(slot) / 'before')
    write(directory / 'manifest.json',value)
    os.rename(journal, RESTORE / ('transaction.op.'+oid))
    sync(RESTORE)


def validate_journal(oid, journal):
    value = record(oid)
    directory = location(oid)
    if journal != RESTORE / ('transaction.op.'+oid): raise ValueError('invalid journal path')
    private(journal, True)
    if value.get('archive',{}).get('path') != 'backup.tar.gz': raise ValueError('invalid archive path')
    if digest(directory / 'backup.tar.gz') != value['archive']['sha256']: raise ValueError('corrupt archive')
    if digest(directory / 'restore-recover') != value['helper_sha256']: raise ValueError('corrupt helper')
    if digest(directory / 'operation-helper.py') != value['operation_helper_sha256']: raise ValueError('corrupt helper')
    if digest(journal / 'entries.tsv') != value['journal_sha256']: raise ValueError('corrupt journal')
    if not (journal / 'files-recovered').exists() and not (journal / 'committed').exists():
        for row in (journal / 'entries.tsv').read_text().splitlines():
            _, dst, slot, old = row.split('\t')
            if old == '1':
                before = Path(slot) / 'before'
                if tree_digest(before if before.exists() or before.is_symlink() else Path(dst)) != value['snapshots'][dst]:
                    raise ValueError('corrupt baseline snapshot')
    return value


def cleanup_preparation(oid):
    prep=RESTORE/('.operation-prep.'+oid)
    if not prep.exists(): return
    private(prep,True)
    directory=location(oid); value=record(oid)
    archive=directory/'backup.tar.gz'
    if value.get('archive',{}).get('path') != archive.name or digest(archive) != value['archive']['sha256']:
        raise ValueError('cannot clean an unverified preparation')
    # Validated baseline destinations bound cleanup, including a slot created
    # just before a power loss prevented its entries.tsv row from being written.
    with tarfile.open(archive,'r:gz') as source:
        member=next(item for item in source.getmembers() if item.name.removeprefix('./') == '.dnscomplex-backup/manifest.tsv')
        rows=source.extractfile(member).read().decode().splitlines()
    slots=[]
    for row in rows:
        _,rel=row.split('\t')
        path=Path(rel)
        if path.is_absolute() or '..' in path.parts or str(path) != rel:
            raise ValueError('unsafe preparation destination')
        dst=ROOT/path
        for slot in dst.parent.glob('.dnscomplex-restore.'+dst.name+'.op.'+oid+'.*'):
            private(slot,True); slots.append(slot)
    for slot in slots: shutil.rmtree(slot); sync(slot.parent)
    shutil.rmtree(prep); sync(RESTORE)


def cleanup(oid, stop_timer=True):
    directory = location(oid)
    cleanup_preparation(oid)
    for name in ('arguments','payload.json','candidate.env','candidate.json','domain-batch.json','xray-outbound.json','xray-uri','backup.tar.gz','custom-config','custom-target.json','restore-recover','operation-helper.py','repair-monitoring-warning'):
        (directory / name).unlink(missing_ok=True)
    sync(directory)
    if not stop_timer: return
    try: systemctl('--no-block','stop','dnscomplex-operation-guard@'+oid+'.timer')
    except (OSError,subprocess.SubprocessError): pass


def worker(oid):
    directory = location(oid)
    with locked(directory / 'operation.lock'), locked(LOCK) as fd:
        value = record(oid)
        if value['phase'] in TERMINAL: return 0
        if value['phase'] != 'queued': raise ValueError('operation already started')
        gate(oid)
        update(oid,phase='preparing',deadline=int(time.time())+300)
        try: prepare(oid,fd)
        except (OSError,ValueError,KeyError,subprocess.SubprocessError):
            # Preparation never mutates managed files; visible journals are recovered.
            update(oid,phase='recovery-required',error_code='PREPARE_FAILED')
            return 1
        journal = RESTORE / ('transaction.op.'+oid)
        update(oid,phase='applying')
        # services marker is already durable before journal publication.
        rc = manager('operation_dispatch_cmd',directory,value['action'],lock_fd=fd)
        if rc == 0: rc = manager('operation_postcheck_cmd',directory,value['action'],lock_fd=fd)
        if rc != 0:
            update(oid,phase='recovery-required',error_code='CANDIDATE_FAILED',candidate_rc=rc)
            return rc
        warning = directory / 'repair-monitoring-warning'
        safe_warning = ''
        if warning.exists():
            private(warning)
            if value['action'] != 'fix' or warning.read_text() != 'monitoring\n':
                raise ValueError('invalid repair warning')
            safe_warning = 'MONITORING_WARNING'
        marker = journal / 'committed'
        marker.touch(mode=0o600); sync(marker); sync(journal)
        # The commit marker is the durable commit point; boot honors it after power loss.
        update(oid,phase='committed',rollback_state='not-needed',error_code=safe_warning)
        env = dict(os.environ,DNSCOMPLEX_RESTORE_STATE_DIR=str(RESTORE),DNSCOMPLEX_OPERATION_HELPER=str(directory/'operation-helper.py'),DNSCOMPLEX_MAINTENANCE_LOCK_HELD='1')
        subprocess.run(['bash','-c','exec 8<&"$1"; shift; exec bash "$@"','_',str(fd),str(directory/'restore-recover'),'--transaction',str(journal)],env=env,pass_fds=(fd,),check=True)
        cleanup(oid)
        return 0


def writer_stopped(oid):
    state = systemctl('show','--property=ActiveState','--value','dnscomplex-operation@'+oid+'.service')
    if state not in ('inactive','failed'): return False
    group = systemctl('show','--property=ControlGroup','--value','dnscomplex-operation@'+oid+'.service')
    if not group: return True
    if not group.startswith('/') or '..' in Path(group).parts: raise ValueError('invalid cgroup')
    path = Path('/sys/fs/cgroup') / group.lstrip('/')
    if not path.exists(): return True
    return all(not file.read_text().strip() for file in path.rglob('cgroup.procs'))


def recover(oid):
    directory = location(oid)
    with locked(directory / 'operation.lock'), locked(LOCK) as fd:
        value = record(oid)
        if value['phase'] in TERMINAL: return 0
        if not writer_stopped(oid): return 1
        journal = RESTORE / ('transaction.op.'+oid)
        if not journal.exists():
            if value['phase'] in ('queued','preparing','prepared') or value.get('error_code') == 'PREPARE_FAILED':
                update(oid,phase='rolled-back',rollback_state='not-needed'); cleanup(oid); return 0
            update(oid,phase='manual-intervention',rollback_state='failed',error_code='MISSING_JOURNAL'); return 1
        try:
            validate_journal(oid,journal)
            update(oid,phase='recovering',rollback_state='running')
            env = dict(os.environ,DNSCOMPLEX_RESTORE_STATE_DIR=str(RESTORE),DNSCOMPLEX_OPERATION_HELPER=str(directory/'operation-helper.py'),DNSCOMPLEX_MAINTENANCE_LOCK=str(LOCK),DNSCOMPLEX_MAINTENANCE_LOCK_HELD='1')
            # Frozen helper also validates the linked journal; the inherited lock is fd8.
            result = subprocess.run(['bash','-c','exec 8<&"$1"; shift; exec bash "$@"','_',str(fd),str(directory/'restore-recover'),'--transaction',str(journal)],
                env=env,pass_fds=(fd,))
            if result.returncode: raise ValueError('journal recovery failed')
            if record(oid)['phase'] not in TERMINAL: update(oid,phase='rolled-back',rollback_state='verified')
            cleanup(oid); return 0
        except (OSError,ValueError,KeyError,subprocess.SubprocessError):
            update(oid,phase='manual-intervention',rollback_state='failed',error_code='RECOVERY_FAILED'); return 1


def queue_recovery(oid):
    if record(oid)['phase'] not in (*TERMINAL,'manual-intervention'):
        systemctl('--no-block','start','dnscomplex-operation-recovery@'+oid+'.service')


def guard(oid):
    if record(oid)['phase'] in (*TERMINAL,'manual-intervention'): return 0
    systemctl('stop','dnscomplex-operation@'+oid+'.service')
    # Queue the independently bounded recovery unit. Never restore in the timer.
    queue_recovery(oid)
    return 0


def journal_result(oid, phase):
    value = record(oid)
    if value['phase'] in TERMINAL: return
    if phase not in ('recovering','rolled-back','committed'): raise ValueError('invalid recovery result')
    update(oid,phase=phase,rollback_state='verified' if phase == 'rolled-back' else 'running')


def resume():
    if not OPERATIONS.exists(): return
    private(OPERATIONS,True)
    for directory in operation_directories():
        private(directory,True)
        previous=read(directory/'manifest.json')
        if 'owner_unit' not in previous and previous.get('schema_version') == 1: continue
        value=record(directory.name)
        if value['phase'] == 'queued':
            systemctl('start','dnscomplex-operation-guard@'+directory.name+'.timer')
            systemctl('--no-block','start',value['owner_unit'])
        elif value['phase'] not in (*TERMINAL,'manual-intervention') and writer_stopped(directory.name):
            queue_recovery(directory.name)


def boot_sync():
    if not OPERATIONS.exists(): return
    for directory in operation_directories():
        private(directory,True)
        previous=read(directory/'manifest.json')
        if previous.get('schema_version') == 1 and 'owner_unit' not in previous:
            if previous.get('phase') in TERMINAL: continue
            if previous.get('id') == directory.name and previous.get('phase') == 'prepared' and not (RESTORE/('transaction.op.'+directory.name)).exists():
                previous.update(phase='rolled-back',rollback_state='not-needed')
                write(directory/'manifest.json',previous)
                for name in ('backup.tar.gz','custom-config','custom-target.json'):
                    (directory/name).unlink(missing_ok=True)
                sync(directory)
                continue
            raise ValueError('unresolved synchronous operation requires recovery')
        value = record(directory.name)
        journal = RESTORE/('transaction.op.'+directory.name)
        if value['phase'] in ('queued','preparing','prepared') and not journal.exists():
            update(directory.name,phase='rolled-back',rollback_state='not-needed')
        if record(directory.name)['phase'] in TERMINAL and not journal.exists(): cleanup(directory.name,stop_timer=False)


def arguments(directory, action):
    if directory != location(directory.name) or action != record(directory.name)['action']:
        raise ValueError('invalid dispatch ownership')
    payload = read(directory / 'payload.json')
    fields = {'set-egress':('profile','mode'),'set-socks':('listen','port'),
        'test-xray':('profile',),'set-ipsec':('profile','user','password'),'set-web-password':('password',),
        'set-local-host':('host','ip'),'set-update-time':('value',),
        'add-domain':('profile','value'),'remove-domain':('profile','value'),
        'egress-apply':()}
    if action == 'config':
        write(directory / 'candidate.json',payload); values=[]
    elif action == 'wizard-apply':
        text=payload.get('config','')
        if not isinstance(text,str): raise ValueError('invalid config')
        path=directory / 'candidate.env'
        with open(path,'x',opener=lambda p,f:os.open(p,f,0o600)) as out:
            out.write(text + ('\n' if not text.endswith('\n') else '')); out.flush(); os.fsync(out.fileno())
        values=[]
    elif action in ('rules-domain','rules-geosite','domain-batch'):
        batch = payload if action == 'domain-batch' else dict(profile=payload.get('profile'),action=payload.get('action','add'),values=[v.strip() for v in str(payload.get('value','')).splitlines() if v.strip()])
        write(directory / 'domain-batch.json',batch); values=[]
    elif action == 'fix':
        if set(payload)-{'action','strict'} or not isinstance(payload.get('strict',False),bool): raise ValueError('invalid repair options')
        values=['--strict'] if payload.get('strict') else []
    elif action == 'set-xray-uri': values=[payload.get('profile',''),payload.get('uri','')]
    elif action == 'set-xray-json':
        write(directory / 'xray-outbound.json',payload.get('outbound_json'))
        values=[payload.get('profile',''),str(directory / 'xray-outbound.json')]
    else: values=[str(payload.get(key,'')) for key in fields.get(action,())]
    if any('\x00' in value for value in values): raise ValueError('invalid argument')
    for value in values: sys.stdout.buffer.write(value.encode()+b'\x00')


def capture_cli_file(path, *, as_json=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>1048576: raise ValueError('invalid CLI input')
        data=stream.read(1048577)
    value=json.loads(data) if as_json else data.decode('utf-8')
    if as_json and not isinstance(value,dict): raise ValueError('invalid CLI object')
    return value


def cli_payload(command, args):
    fields={'set-egress':('profile','mode'),'set-socks':('listen','port'),
        'set-ipsec':('profile','user','password'),'set-web-password':('password',),
        'set-local-host':('host','ip'),'set-update-time':('value',),
        'add-domain':('profile','value'),'remove-domain':('profile','value'),
        'set-xray-uri':('profile','uri'),'mss-calibrate':(),'update-geosite':()}
    if command == 'fix':
        if args not in ([],['--strict']): raise ValueError('invalid repair options')
        return 'fix', {'strict':True} if args else {}
    if command in ('apply-config-json','apply-egress-json','apply-domain-rules-json','apply-config','set-xray-json'):
        count=2 if command=='set-xray-json' else 1
        if len(args)!=count: raise ValueError('invalid CLI arguments')
        value=capture_cli_file(args[-1],as_json=command!='apply-config')
        if command=='apply-config': return 'wizard-apply',dict(config=value)
        if command=='set-xray-json': return 'set-xray-json',dict(profile=args[0],outbound_json=value)
        return {'apply-config-json':'config','apply-egress-json':'egress-apply','apply-domain-rules-json':'domain-batch'}[command],value
    if command not in fields or len(args)!=len(fields[command]): raise ValueError('invalid CLI action')
    return command,dict(zip(fields[command],args))


@contextlib.contextmanager
def cli_handoff_signals():
    pending=[]
    previous={number:signal.getsignal(number) for number in (signal.SIGINT,signal.SIGTERM)}
    def defer(number, frame): pending.append(number)
    try:
        for number in previous: signal.signal(number,defer)
        yield
    finally:
        for number,handler in previous.items(): signal.signal(number,handler)
        if pending and sys.exc_info()[0] is None:
            if pending[0] == signal.SIGINT: raise KeyboardInterrupt()
            raise SystemExit(128+pending[0])


def cli(command, args):
    action,payload=cli_payload(command,args)
    # Defer interactive termination only through durable ID + bounded handoff.
    # systemctl children use their own session, so terminal Ctrl-C cannot kill
    # the handoff client before the independent writer/guard has been scheduled.
    with cli_handoff_signals():
        value=submit(action,payload,announce=lambda oid:print('operation_id='+oid,flush=True))
        oid=value['operation_id']
    # The caller owns no maintenance fd while waiting. Interrupting this process
    # never stops the independent writer/guard; the printed ID remains queryable.
    deadline=time.monotonic()+660
    while time.monotonic()<deadline:
        value=status(oid)
        if value['phase'] in (*TERMINAL,'manual-intervention'):
            print('operation_id='+oid+' phase='+value['phase'],flush=True)
            return 0 if value['phase']=='committed' else 1
        time.sleep(.5)
    print('Operation still owned by systemd; inspect operation_id='+oid,file=sys.stderr)
    return 1


def main():
    action, *args = sys.argv[1:]
    if action == 'cli':
        values=sys.stdin.buffer.read(1048577)
        if len(values)>1048576 or not values.endswith(b'\0'): raise ValueError('invalid CLI input')
        return cli(args[0],values[:-1].decode().split('\0') if values!=b'\0' else [])
    elif action == 'submit': print(json.dumps(submit(args[0],json.load(sys.stdin))))
    elif action == 'status': print(json.dumps(status(args[0])))
    elif action == 'gate': gate(os.environ.get('DNSCOMPLEX_OPERATION_ID'))
    elif action == 'worker': return worker(args[0])
    elif action == 'recover': return recover(args[0])
    elif action == 'queue-recovery': queue_recovery(args[0])
    elif action == 'recovery-stopped':
        if record(args[0])['phase'] not in TERMINAL:
            update(args[0],phase='manual-intervention',rollback_state='failed',error_code='RECOVERY_INTERRUPTED')
    elif action == 'guard': return guard(args[0])
    elif action == 'validate-journal': validate_journal(args[0],Path(args[1]))
    elif action == 'journal-result': journal_result(*args)
    elif action == 'journal-failed': update(args[0],phase='manual-intervention',rollback_state='failed',error_code='RECOVERY_FAILED')
    elif action == 'boot-sync': boot_sync()
    elif action == 'resume': resume()
    elif action == 'arguments': arguments(Path(args[0]),args[1])
    else: raise ValueError('invalid operation command')
    return 0

if __name__ == '__main__':
    try: sys.exit(main())
    except (OperationBusy,BlockingIOError): print('Operation busy or recovery pending.',file=sys.stderr); sys.exit(3)
    except FileNotFoundError: print('Operation not found.',file=sys.stderr); sys.exit(4)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('Operation validation or execution failed.',file=sys.stderr); sys.exit(1)
OPERATION_HELPER
  chmod_target 0755 /usr/local/libexec/dnscomplex-operation
  write_file /etc/systemd/system/dnscomplex-operation@.service <<'EOF'
[Unit]
Description=dnscomplex persistent operation writer
OnFailure=dnscomplex-operation-recovery@%i.service

[Service]
Type=exec
ExecStart=/usr/bin/python3 /usr/local/libexec/dnscomplex-operation worker %i
ExecStopPost=/usr/bin/python3 /usr/local/libexec/dnscomplex-operation queue-recovery %i
RuntimeMaxSec=300
TimeoutStopSec=15
KillMode=control-group
EOF
  write_file /etc/systemd/system/dnscomplex-operation-recovery@.service <<'EOF'
[Unit]
Description=Recover dnscomplex persistent operation
After=dnscomplex-operation@%i.service

[Service]
Type=exec
ExecStart=/usr/bin/python3 /usr/local/libexec/dnscomplex-operation recover %i
RuntimeMaxSec=150
TimeoutStopSec=15
KillMode=control-group
ExecStopPost=/usr/bin/python3 /usr/local/libexec/dnscomplex-operation recovery-stopped %i
EOF
  write_file /etc/systemd/system/dnscomplex-operation-guard@.timer <<'EOF'
[Unit]
Description=Outer deadline for dnscomplex persistent operation

[Timer]
OnActiveSec=510
AccuracySec=1s
Unit=dnscomplex-operation-guard@%i.service
EOF
  write_file /etc/systemd/system/dnscomplex-operation-guard@.service <<'EOF'
[Unit]
Description=Stop expired dnscomplex writer and queue recovery

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/libexec/dnscomplex-operation guard %i
TimeoutStartSec=30
EOF
}

render_logging_policy() {
  write_file /etc/systemd/journald.conf.d/dnscomplex.conf <<'EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=1536M
SystemMaxFileSize=64M
SystemKeepFree=1G
RuntimeMaxUse=64M
MaxRetentionSec=30day
RateLimitIntervalSec=30s
RateLimitBurst=10000
EOF
}

render_ipsec_services() {
  write_file /etc/systemd/system/smartdns.service.d/dnscomplex.conf <<'EOF'
[Unit]
StartLimitIntervalSec=60s
StartLimitBurst=5

[Service]
Restart=always
RestartSec=2s
TimeoutStopSec=5s
EOF

  write_file /etc/systemd/system/sing-box.service.d/dnscomplex.conf <<'EOF'
[Unit]
Requires=dnscomplex-network-ready.service
After=dnscomplex-network-ready.service

[Service]
# sing-box 1.13 tries systemd-resolved integration even when resolved is
# intentionally disabled.  Keep that no-op private to this service.
BindReadOnlyPaths=/usr/bin/true:/usr/bin/resolvectl
EOF

  write_file /etc/systemd/system/dnscomplex-network-ready.service <<'EOF'
[Unit]
Description=dnscomplex wait for the configured network underlay
After=network-online.target
Wants=network-online.target
Before=dnscomplex-ipsec-ready.service dnscomplex-web.service sing-box.service AdGuardHome.service
Upholds=dnscomplex-ipsec-ready.service sing-box.service AdGuardHome.service dnscomplex-web.service
StartLimitIntervalSec=5min
StartLimitBurst=4

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=DNSCOMPLEX_SERVICE_MODE=1
ExecStart=/usr/local/sbin/dnscomplex network-ready
TimeoutStartSec=120s
Restart=on-failure
RestartSec=15s

[Install]
WantedBy=multi-user.target
EOF

  write_file /etc/systemd/system/dnscomplex-ipsec-ifaces.service <<EOF
[Unit]
Description=dnscomplex route-based IPsec XFRM interfaces
Before=strongswan.service strongswan-swanctl.service
After=systemd-networkd.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=DNSCOMPLEX_SERVICE_MODE=1
ExecStart=/usr/local/sbin/dnscomplex ipsec-ifaces up
ExecStop=/usr/local/sbin/dnscomplex ipsec-ifaces down

[Install]
WantedBy=multi-user.target
EOF

  write_file /etc/systemd/system/dnscomplex-ipsec-ready.service <<EOF
[Unit]
Description=dnscomplex wait for selected IPsec egress
After=dnscomplex-network-ready.service dnscomplex-ipsec-ifaces.service strongswan-starter.service strongswan-swanctl.service strongswan.service ipsec.service
Requires=dnscomplex-network-ready.service dnscomplex-ipsec-ifaces.service
Before=dnscomplex-routing.service
OnSuccess=dnscomplex-routing.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=DNSCOMPLEX_SERVICE_MODE=1
ExecStart=/usr/local/sbin/dnscomplex ipsec-ready
TimeoutStartSec=120s

[Install]
WantedBy=multi-user.target
EOF

  write_file /etc/systemd/system/dnscomplex-routing.service <<EOF
[Unit]
Description=dnscomplex policy routing
Requires=dnscomplex-ipsec-ready.service
After=network-online.target nftables.service dnscomplex-ipsec-ifaces.service dnscomplex-ipsec-ready.service
Wants=network-online.target nftables.service
PartOf=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=DNSCOMPLEX_SERVICE_MODE=1
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
ExecStart=/usr/local/sbin/dnscomplex watchdog
TimeoutStartSec=45s
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
Description=dnscomplex verified geosite data update

[Service]
Type=oneshot
Environment=DNSCOMPLEX_TIMER_MODE=1
ExecStart=/usr/local/sbin/dnscomplex update-geosite
EOF

  write_file /etc/systemd/system/dnscomplex-update.timer <<EOF
[Unit]
Description=Run dnscomplex verified geosite data update daily

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
Environment=DNSCOMPLEX_TIMER_MODE=1
ExecStart=/usr/local/sbin/dnscomplex refresh-cn-overrides
EOF

  write_file /etc/systemd/system/dnscomplex-cn-overrides.timer <<'EOF'
[Unit]
Description=Run dnscomplex CN override refresh periodically

[Timer]
OnCalendar=*-*-* 00/6:00:00
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
Environment=DNSCOMPLEX_TIMER_MODE=1
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
# Existing RouterOS DoH: validate its public CA chain before enabling verification.
# Cloudflare 1.1.1.1 currently requires SSL.com Root Certification Authority ECC.
# Obtain it from a trusted CA store and confirm certificate DER SHA256:
# 3417bb06cc6007da1b961c920b8ab4ce3fad820e4aa30b9acbc4a74ebdcebc65
# Import the public CA (no private key), trusted=yes, trust-store=dns,fetch on 7.24.
# Then test new DNS queries with a timed rollback before committing:
# /ip/dns/set verify-doh-cert=yes
# Keep the existing DoH endpoint; do not forward all RouterOS DNS to this VM
# without independent bootstrap DNS, or a RouterOS/VM resolver loop may result.
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
# Existing RouterOS DoH: validate its public CA chain before enabling verification.
# Cloudflare 1.1.1.1 currently requires SSL.com Root Certification Authority ECC.
# Obtain it from a trusted CA store and confirm certificate DER SHA256:
# 3417bb06cc6007da1b961c920b8ab4ce3fad820e4aa30b9acbc4a74ebdcebc65
# Import the public CA (no private key), trusted=yes, trust-store=dns,fetch on 7.24.
# Then test new DNS queries with a timed rollback before committing:
# /ip/dns/set verify-doh-cert=yes
# Keep the existing DoH endpoint; do not forward all RouterOS DNS to this VM
# without independent bootstrap DNS, or a RouterOS/VM resolver loop may result.
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


render_lan_alias_runtime() {
  write_file /usr/local/libexec/dnscomplex-lan-alias <<'LAN_ALIAS'
"""Fail-closed selector prototype for one operator-reserved LAN source alias.

This module only validates snapshots and returns the configured candidate. It
does not inspect the host, allocate another address, modify routes, or install
an address. Production integration must supply fresh `ip -j` snapshots and an
ownership state written by its own lifecycle manager. A claimed state must
contain exact `address`, `interface`, `label`, and `outbound_tag` fields.
"""

import copy
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import stat
import subprocess
import time
import tempfile


DEFAULT_POOL = "198.18.255.0/24"
DEFAULT_CANDIDATE = "198.18.255.254"
RFC2544_POOL = ipaddress.ip_network("198.18.0.0/15")
OWNER_LABEL = "lo:dc-alias"
OWNER_INTERFACE = "lo"
OWNER_OUTBOUND_TAG = "lan-legacy-alias"
TUN_INTERFACE = "dnscomplex0"
TUN_ROUTE_TABLE = "2022"
BROAD_TUN_ROUTE_PREFIX = 15


class AliasSelectionError(ValueError):
    """Raised when the configured alias cannot be proven safe to use."""


class DeadlineExceeded(AliasSelectionError):
    """Raised when a watchdog-scoped helper operation runs out of budget."""


class RestartClientTimedOut(DeadlineExceeded):
    """The systemctl client timed out; the service manager may still restart."""


COMMAND_DEADLINE_MS = None
CLEANUP_ATTEMPTED = False
CONFIG_PROOF_INVALID = False


def _load_json(value, name):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError) as exc:
            raise AliasSelectionError(f"invalid {name} JSON") from exc
    if not isinstance(value, (dict, list)):
        raise AliasSelectionError(f"invalid {name} document")
    return value


def _network(value, name):
    if not isinstance(value, str):
        raise AliasSelectionError(f"invalid {name}")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except (TypeError, ValueError) as exc:
        raise AliasSelectionError(f"invalid {name}") from exc
    if network.version != 4:
        raise AliasSelectionError(f"{name} must be IPv4")
    return network


def _state(state):
    state = _load_json(state, "ownership state")
    if not isinstance(state, dict):
        raise AliasSelectionError("ownership state must be an object")
    address = state.get("address")
    label = state.get("label")
    interface = state.get("interface")
    outbound_tag = state.get("outbound_tag")
    if address is not None:
        if not isinstance(address, str):
            raise AliasSelectionError("invalid owned address in state")
        try:
            address = str(ipaddress.ip_address(address))
        except (TypeError, ValueError) as exc:
            raise AliasSelectionError("invalid owned address in state") from exc
        if ipaddress.ip_address(address).version != 4:
            raise AliasSelectionError("owned address in state must be IPv4")
    for name, value in (("label", label), ("interface", interface), ("outbound tag", outbound_tag)):
        if value is not None and not isinstance(value, str):
            raise AliasSelectionError(f"invalid ownership {name} in state")
    ownership_values = (address, label, interface, outbound_tag)
    if any(value is not None for value in ownership_values) and any(
        value is None for value in ownership_values
    ):
        raise AliasSelectionError("persisted alias ownership state is incomplete")
    return address, label, interface, outbound_tag


def _check_fakeip_configuration(config):
    """Reject any fake-IP marker until its pool schema is explicitly supported."""
    stack = [config]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                normalized = str(key).lower().replace("-", "_")
                if "fakeip" in normalized or "fake_ip" in normalized:
                    raise AliasSelectionError("fake-IP configuration is unsupported or opaque")
                if normalized == "type" and isinstance(value, str) and value.lower() == "fakeip":
                    raise AliasSelectionError("fake-IP configuration is unsupported or opaque")
                stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)


def _check_singbox(config, candidate, ownership_claimed):
    if not isinstance(config, dict):
        raise AliasSelectionError("sing-box config must be an object")
    inbounds = config.get("inbounds")
    outbounds = config.get("outbounds")
    if not isinstance(inbounds, list) or not isinstance(outbounds, list):
        raise AliasSelectionError("sing-box inbounds/outbounds must be arrays")

    _check_fakeip_configuration(config)

    for inbound in inbounds:
        if not isinstance(inbound, dict):
            raise AliasSelectionError("invalid sing-box inbound")
        if inbound.get("type") != "tun":
            continue
        addresses = inbound.get("address")
        if not isinstance(addresses, list):
            raise AliasSelectionError("TUN address configuration is opaque")
        for value in addresses:
            if not isinstance(value, str):
                raise AliasSelectionError("invalid TUN interface address")
            try:
                network = ipaddress.ip_network(value, strict=False)
            except (TypeError, ValueError) as exc:
                raise AliasSelectionError("invalid TUN interface address") from exc
            if network.version == 6:
                continue
            if candidate in network:
                raise AliasSelectionError("candidate overlaps a sing-box TUN interface address")

    alias_tag_entries = []
    alias_bind_matches = 0
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            raise AliasSelectionError("invalid sing-box outbound")
        if outbound.get("tag") == OWNER_OUTBOUND_TAG:
            alias_tag_entries.append(outbound)
        bind = outbound.get("inet4_bind_address")
        if bind in (None, ""):
            continue
        if not isinstance(bind, str):
            raise AliasSelectionError("opaque outbound bind address")
        try:
            address = ipaddress.ip_address(bind)
        except (TypeError, ValueError) as exc:
            raise AliasSelectionError("opaque outbound bind address") from exc
        if address.version != 4:
            raise AliasSelectionError("IPv4 outbound bind address is not IPv4")
        if address == candidate:
            owned_bind = (
                ownership_claimed
                and outbound.get("tag") == OWNER_OUTBOUND_TAG
                and outbound.get("type") == "direct"
            )
            if not owned_bind:
                raise AliasSelectionError("candidate collides with an unowned sing-box outbound bind address")
            alias_bind_matches += 1

    if not ownership_claimed:
        if alias_tag_entries:
            raise AliasSelectionError("alias outbound exists without matching ownership state")
    elif (
        len(alias_tag_entries) != 1
        or alias_tag_entries[0].get("type") != "direct"
        or alias_tag_entries[0].get("inet4_bind_address") != str(candidate)
        or alias_bind_matches != 1
    ):
        raise AliasSelectionError("owned alias outbound does not exactly match state and candidate")


def _check_addresses(addresses, candidate, owned_address, owned_interface, owned_label):
    if not isinstance(addresses, list):
        raise AliasSelectionError("ip address snapshot must be an array")
    exact_owned_seen = False
    exact_owned_count = 0
    for interface in addresses:
        if not isinstance(interface, dict) or not isinstance(interface.get("ifname"), str):
            raise AliasSelectionError("invalid interface in ip address snapshot")
        if "addr_info" not in interface:
            continue
        addr_info = interface["addr_info"]
        if not isinstance(addr_info, list):
            raise AliasSelectionError("invalid interface address list")
        for entry in addr_info:
            if not isinstance(entry, dict):
                raise AliasSelectionError("invalid address entry")
            family = entry.get("family")
            if family == "inet6":
                continue
            if family != "inet":
                raise AliasSelectionError("unknown address family in interface snapshot")
            try:
                if not isinstance(entry.get("local"), str):
                    raise TypeError("address literal must be a string")
                address = ipaddress.ip_address(entry["local"])
                prefixlen = int(entry["prefixlen"])
            except (KeyError, TypeError, ValueError) as exc:
                raise AliasSelectionError("invalid IPv4 interface address") from exc
            if address.version != 4 or not 0 <= prefixlen <= 32:
                raise AliasSelectionError("invalid IPv4 interface prefix")
            network = ipaddress.ip_network(f"{address}/{prefixlen}", strict=False)
            if candidate not in network:
                continue
            label = entry.get("label")
            is_owned = (
                interface["ifname"] == OWNER_INTERFACE
                and owned_interface == OWNER_INTERFACE
                and address == candidate
                and prefixlen == 32
                and label == OWNER_LABEL
                and owned_address == str(candidate)
                and owned_label == OWNER_LABEL
            )
            if is_owned:
                exact_owned_seen = True
                exact_owned_count += 1
                if exact_owned_count > 1:
                    raise AliasSelectionError("duplicate owned alias address entries")
            else:
                raise AliasSelectionError("candidate overlaps an unowned interface address")
    return exact_owned_seen


def _check_routes(routes, candidate, ownership_claimed, owned_address_seen,
                  allow_tun_route_exclusion_transition=False):
    if not isinstance(routes, list):
        raise AliasSelectionError("ip route snapshot must be an array")
    owned_local_route_seen = False
    for route in routes:
        if not isinstance(route, dict):
            raise AliasSelectionError("invalid route entry")
        destination = route.get("dst")
        if destination in (None, "default"):
            continue
        try:
            parsed_destination = ipaddress.ip_network(destination, strict=False)
        except (TypeError, ValueError) as exc:
            raise AliasSelectionError("invalid route destination") from exc
        if parsed_destination.version == 6:
            continue
        network = _network(destination, "route destination")
        if network.prefixlen == 0:
            continue
        if candidate not in network:
            continue
        table = str(route.get("table", "main"))
        tun_owned = route.get("dev") == TUN_INTERFACE and table == TUN_ROUTE_TABLE
        if tun_owned and network.prefixlen <= BROAD_TUN_ROUTE_PREFIX:
            continue
        if tun_owned and allow_tun_route_exclusion_transition:
            continue
        is_owned_local_address_route = (
            ownership_claimed
            and owned_address_seen
            and network.prefixlen == 32
            and network.network_address == candidate
            and route.get("dev") == OWNER_INTERFACE
            and table == "local"
            and route.get("type") == "local"
        )
        if is_owned_local_address_route:
            owned_local_route_seen = True
            continue
        raise AliasSelectionError("candidate overlaps a specific non-owned route")
    if ownership_claimed and owned_address_seen and not owned_local_route_seen:
        raise AliasSelectionError("owned loopback address is missing its kernel local route")


def select_alias(
    addr_json,
    routes_json,
    singbox_config,
    state_owned,
    *,
    pool=DEFAULT_POOL,
    candidate=DEFAULT_CANDIDATE,
    allow_tun_route_exclusion_transition=False,
):
    """Return the sole configured candidate if snapshots prove it unclaimed.

    The candidate must be within an operator-selected subnet of RFC 2544's
    198.18.0.0/15 block. Conflicts fail closed; this function never scans for a
    replacement. An already-present address is accepted only when its exact
    loopback /32, interface label, and persisted ownership state all agree.
    """
    addresses = _load_json(addr_json, "ip address")
    routes = _load_json(routes_json, "ip route")
    config = _load_json(singbox_config, "sing-box config")
    owned_address, owned_label, owned_interface, owned_outbound_tag = _state(state_owned)
    pool_network = _network(pool, "reserved pool")
    if not isinstance(candidate, str):
        raise AliasSelectionError("candidate must be an IPv4 literal")
    try:
        candidate_address = ipaddress.ip_address(candidate)
    except (TypeError, ValueError) as exc:
        raise AliasSelectionError("candidate must be an IPv4 literal") from exc
    if candidate_address.version != 4:
        raise AliasSelectionError("candidate must be IPv4")
    if not pool_network.subnet_of(RFC2544_POOL):
        raise AliasSelectionError("pool must be contained in the RFC 2544 benchmark block")
    if candidate_address not in pool_network:
        raise AliasSelectionError("candidate is outside the configured pool")
    if pool_network.prefixlen > 30:
        raise AliasSelectionError("reserved pool must leave room for a host address")
    last_host = ipaddress.ip_address(int(pool_network.broadcast_address) - 1)
    if candidate_address != last_host:
        raise AliasSelectionError("candidate must be the configured pool's final usable address")
    if owned_address is not None and (
        owned_address != str(candidate_address)
        or owned_label != OWNER_LABEL
        or owned_interface != OWNER_INTERFACE
        or owned_outbound_tag != OWNER_OUTBOUND_TAG
    ):
        raise AliasSelectionError("persisted ownership does not match the selected address and owner fields")

    ownership_claimed = owned_address is not None
    _check_singbox(config, candidate_address, ownership_claimed)
    owned_address_seen = _check_addresses(
        addresses, candidate_address, owned_address, owned_interface, owned_label
    )
    transition_exclusion = (
        allow_tun_route_exclusion_transition and
        _has_exact_tun_alias_route_exclusion(config, str(candidate_address))
    )
    _check_routes(routes, candidate_address, ownership_claimed, owned_address_seen,
                  allow_tun_route_exclusion_transition=transition_exclusion)

    if owned_address_seen and (owned_address != str(candidate_address) or owned_label != OWNER_LABEL):
        raise AliasSelectionError("installed address ownership does not match the selected candidate")
    return str(candidate_address)

STATE_SCHEMA = 1
STATE_DEFAULT = pathlib.Path("/var/lib/dnscomplex/lan-alias.json")
CONFIG_DEFAULT = pathlib.Path("/etc/sing-box/config.json")
NFT_TABLE = "dnscomplex"
READY_SET = "lan_alias_ready4"
CONFIG_READY_SET = "lan_alias_config_ready4"
SOURCE_SET = "lan_alias_source4"
STRICT_OCTET = r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
STRICT_IPV4 = rf"^({STRICT_OCTET}\.){{3}}{STRICT_OCTET}$"


def _run(argv, *, input_text=None, check=True):
    timeout = None
    if COMMAND_DEADLINE_MS is not None:
        remaining = COMMAND_DEADLINE_MS / 1000.0 - time.monotonic()
        if remaining <= 0:
            raise DeadlineExceeded(f"watchdog deadline expired before {argv[0]}")
        timeout = remaining
    try:
        result = subprocess.run(argv, input=input_text, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if len(argv) >= 2 and argv[0] == "systemctl" and argv[1] == "restart":
            raise RestartClientTimedOut(
                f"{argv[0]} restart client timed out; backend restart state is unknown"
            ) from exc
        raise DeadlineExceeded(f"watchdog deadline expired during {argv[0]}") from exc
    if check and result.returncode:
        raise AliasSelectionError(f"command failed: {argv[0]} ({result.stderr.strip()})")
    return result


def _load_state(path):
    path = pathlib.Path(path)
    if path.is_symlink():
        raise AliasSelectionError("alias ownership state must not be a symlink")
    if not path.exists():
        return None
    info = path.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise AliasSelectionError("alias ownership state must be root-owned mode 0600")
    state = _load_json(path.read_text(encoding="utf-8"), "ownership state")
    if not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA or state.get("status") != "owned":
        raise AliasSelectionError("alias ownership state is partial or has an unsupported schema")
    expected = {
        "address": DEFAULT_CANDIDATE,
        "interface": OWNER_INTERFACE,
        "label": OWNER_LABEL,
        "outbound_tag": OWNER_OUTBOUND_TAG,
        "pool": DEFAULT_POOL,
    }
    for key, value in expected.items():
        if state.get(key) != value:
            raise AliasSelectionError(f"alias ownership state has mismatched {key}")
    return state


def _write_state(path, state):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise AliasSelectionError("alias ownership state must not be a symlink")
    fd, name = tempfile.mkstemp(prefix=".lan-alias.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _ensure_tun_alias_route_exclusion(config, candidate):
    inbounds = config.get("inbounds") if isinstance(config, dict) else None
    if not isinstance(inbounds, list):
        raise AliasSelectionError("sing-box TUN inbounds are not editable")
    tun_matches = [entry for entry in inbounds if isinstance(entry, dict) and
                   entry.get("type") == "tun" and entry.get("tag") == "tun-in"]
    if len(tun_matches) != 1:
        raise AliasSelectionError("sing-box tun-in inbound is missing or ambiguous")
    inbound = tun_matches[0]
    if inbound.get("interface_name") != TUN_INTERFACE or inbound.get("auto_route") is not True:
        raise AliasSelectionError("sing-box tun-in auto-route ownership is not verifiable")
    exclusions = inbound.get("route_exclude_address", [])
    if not isinstance(exclusions, list):
        raise AliasSelectionError("sing-box TUN route exclusions are not editable")
    for value in exclusions:
        if not isinstance(value, str):
            raise AliasSelectionError("sing-box TUN route exclusion is opaque")
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise AliasSelectionError("sing-box TUN route exclusion is invalid") from exc
    exact = f"{candidate}/32"
    if exact not in exclusions:
        exclusions.append(exact)
    return config


def _has_exact_tun_alias_route_exclusion(config, candidate):
    inbounds = config.get("inbounds") if isinstance(config, dict) else None
    if not isinstance(inbounds, list):
        return False
    tun_matches = [entry for entry in inbounds if isinstance(entry, dict) and
                   entry.get("type") == "tun" and entry.get("tag") == "tun-in"]
    if len(tun_matches) != 1:
        return False
    inbound = tun_matches[0]
    return (inbound.get("interface_name") == TUN_INTERFACE and
            inbound.get("auto_route") is True and
            f"{candidate}/32" in inbound.get("route_exclude_address", []))


def _ensure_route_and_outbound(config, candidate):
    if not isinstance(config, dict) or not isinstance(config.get("outbounds"), list):
        raise AliasSelectionError("sing-box config is not editable")
    if not isinstance(config.get("route"), dict) or not isinstance(config["route"].get("rules"), list):
        raise AliasSelectionError("sing-box route rules are not editable")
    _ensure_tun_alias_route_exclusion(config, candidate)
    outbounds = config["outbounds"]
    matches = [entry for entry in outbounds if isinstance(entry, dict) and entry.get("tag") == OWNER_OUTBOUND_TAG]
    expected = {"type": "direct", "tag": OWNER_OUTBOUND_TAG, "inet4_bind_address": candidate}
    if matches and (len(matches) != 1 or matches[0] != expected):
        raise AliasSelectionError("lan-legacy-alias tag is occupied by a foreign or modified outbound")
    if not matches:
        outbounds.append(expected)

    route_rules = config["route"]["rules"]
    logical = {"type": "logical", "mode": "and", "rules": [
        {"inbound": ["tun-in"]},
        {"domain_regex": [".+"]},
        {"domain_regex": [STRICT_IPV4], "invert": True},
        {"domain_regex": [".*:.*"], "invert": True},
    ], "action": "route", "outbound": "default"}
    raw = {"inbound": ["tun-in"], "network": ["tcp", "udp"],
           "ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": OWNER_OUTBOUND_TAG}
    owned_rules = [logical, raw]
    found_logical = sum(rule == logical for rule in route_rules)
    found_raw = sum(rule == raw for rule in route_rules)
    if found_logical > 1 or found_raw > 1:
        raise AliasSelectionError("duplicate LAN alias route rules are ambiguous")
    if found_logical and not found_raw or found_raw and not found_logical:
        raise AliasSelectionError("partial LAN alias route rules are ambiguous")
    private_indexes = [i for i, rule in enumerate(route_rules)
                       if isinstance(rule, dict) and rule.get("ip_is_private") is True]
    profile_indexes = [i for i, rule in enumerate(route_rules)
                       if isinstance(rule, dict) and (
                           rule.get("rule_set") == "geosite-cn-video" or
                           (isinstance(rule.get("rule_set"), str) and
                            rule["rule_set"].startswith("geosite-ai-"))
                       )]
    if not found_logical:
        # These rules follow existing AI and CN-video rules, then private IPs;
        # unknown hostnames stay on default before the IPv4 hint fallback.
        insert_at = private_indexes[-1] + 1 if private_indexes else len(route_rules)
        if any(index >= insert_at for index in profile_indexes):
            raise AliasSelectionError("AI/CN domain rules must precede LAN alias fallback rules")
        route_rules[insert_at:insert_at] = owned_rules
    else:
        logical_index = route_rules.index(logical)
        raw_index = route_rules.index(raw)
        if raw_index != logical_index + 1:
            raise AliasSelectionError("LAN alias hostname and raw-IP routes are not adjacent")
        if any(index > logical_index for index in private_indexes + profile_indexes):
            raise AliasSelectionError("LAN alias fallback precedes a protected domain/private route")
    return config


def _config_has_complete_alias(config, candidate):
    expected = copy.deepcopy(config)
    _ensure_route_and_outbound(expected, candidate)
    return expected == config


def _singbox_main_pid():
    active = _run(["systemctl", "is-active", "--quiet", "sing-box"], check=False)
    if active.returncode != 0:
        raise AliasSelectionError("sing-box is not active")
    result = _run(["systemctl", "show", "-p", "MainPID", "--value", "sing-box"],
                  check=False)
    if result.returncode != 0 or not result.stdout.strip().isdigit():
        raise AliasSelectionError("sing-box MainPID could not be verified")
    pid = int(result.stdout.strip(), 10)
    if pid < 2:
        raise AliasSelectionError("sing-box has no running main process")
    return pid


def _loaded_config_matches(config_path, state):
    if not isinstance(state, dict):
        return False
    try:
        current_hash = hashlib.sha256(pathlib.Path(config_path).read_bytes()).hexdigest()
        current_pid = _singbox_main_pid()
    except (OSError, AliasSelectionError):
        return False
    return (state.get("loaded_config_sha256") == current_hash and
            state.get("loaded_main_pid") == current_pid)


def _restart_singbox():
    result = _run(["systemctl", "restart", "sing-box"], check=False)
    if result.returncode != 0:
        raise AliasSelectionError("sing-box restart failed")
    return _singbox_main_pid()


def _atomic_config(config_path, config, *, restart=True):
    config_path = pathlib.Path(config_path)
    original = config_path.read_bytes()
    candidate = (json.dumps(config, indent=2, ensure_ascii=False) + "\n").encode()
    if original == candidate:
        return False
    fd, temp_name = tempfile.mkstemp(prefix=".sing-box-lan-alias.", dir=config_path.parent)
    backup_name = None
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(candidate)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_name, stat.S_IMODE(config_path.stat().st_mode))
        _run(["sing-box", "check", "-c", temp_name])
        backup_fd, backup_name = tempfile.mkstemp(prefix=".sing-box-lan-alias-backup.", dir=config_path.parent)
        with os.fdopen(backup_fd, "wb") as stream:
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(backup_name, stat.S_IMODE(config_path.stat().st_mode))
        os.replace(temp_name, config_path)
        if restart:
            try:
                result = _run(["systemctl", "restart", "sing-box"], check=False)
            except RestartClientTimedOut:
                # systemd may already have accepted the request. Keep the
                # candidate and leave readiness closed; issuing a second
                # restart here would escape the expired watchdog budget.
                raise
            try:
                if result.returncode:
                    raise AliasSelectionError("sing-box restart command failed")
                _singbox_main_pid()
            except AliasSelectionError as restart_exc:
                os.replace(backup_name, config_path)
                backup_name = None
                recovery = _run(["systemctl", "restart", "sing-box"], check=False)
                try:
                    if recovery.returncode:
                        raise AliasSelectionError("restart command failed")
                    _singbox_main_pid()
                except AliasSelectionError:
                    raise AliasSelectionError(
                        f"{restart_exc}; previous config restored but service recovery could not be verified"
                    ) from restart_exc
                raise AliasSelectionError(
                    f"{restart_exc}; previous config restored and service recovered"
                ) from restart_exc
        return True
    finally:
        for name in (temp_name, backup_name):
            if name:
                try:
                    os.unlink(name)
                except FileNotFoundError:
                    pass


def _set_alias_gate(candidate, *, open_gate):
    _set_ready_gate(READY_SET, open_gate=open_gate)


def _set_config_gate(*, open_gate):
    _set_ready_gate(CONFIG_READY_SET, open_gate=open_gate)


def _set_ready_gate(set_name, *, open_gate):
    commands = [f"flush set inet {NFT_TABLE} {set_name}"]
    if open_gate:
        commands.extend([
            f"add element inet {NFT_TABLE} {set_name} {{ 0.0.0.0/0 }}",
        ])
    batch = "\n".join(commands) + "\n"
    _run(["nft", "-c", "-f", "-"], input_text=batch)
    _run(["nft", "-f", "-"], input_text=batch)


def _verify_alias_gate(*, open_gate):
    _verify_ready_gate(READY_SET, open_gate=open_gate)


def _verify_config_gate(*, open_gate):
    _verify_ready_gate(CONFIG_READY_SET, open_gate=open_gate)


def _verify_ready_gate(set_name, *, open_gate):
    result = _run(["nft", "-j", "list", "set", "inet", NFT_TABLE, set_name])
    data = json.loads(result.stdout)
    for item in data.get("nftables", []):
        entry = item.get("set")
        if not isinstance(entry, dict):
            continue
        if entry.get("family") != "inet" or entry.get("table") != NFT_TABLE or entry.get("name") != set_name or entry.get("type") != "ipv4_addr":
            continue
        elements = entry.get("elem", [])
        if open_gate and elements == [{"prefix": {"addr": "0.0.0.0", "len": 0}}]:
            return
        if not open_gate and not elements:
            return
    raise AliasSelectionError(f"LAN alias gate {set_name} wildcard did not verify")


def _alias_gate_is_open():
    return _ready_gate_is_open(READY_SET)


def _config_gate_is_open():
    return _ready_gate_is_open(CONFIG_READY_SET)


def _ready_gate_is_open(set_name):
    result = _run(["nft", "-j", "list", "set", "inet", NFT_TABLE, set_name])
    data = json.loads(result.stdout)
    for item in data.get("nftables", []):
        entry = item.get("set")
        if isinstance(entry, dict) and entry.get("family") == "inet" and entry.get("table") == NFT_TABLE and entry.get("name") == set_name and entry.get("type") == "ipv4_addr":
            return entry.get("elem", []) == [{"prefix": {"addr": "0.0.0.0", "len": 0}}]
    raise AliasSelectionError(f"LAN alias gate {set_name} is missing or malformed")


def _set_elements(set_name):
    result = _run(["nft", "-j", "list", "set", "inet", NFT_TABLE, set_name])
    data = json.loads(result.stdout)
    for item in data.get("nftables", []):
        entry = item.get("set")
        if isinstance(entry, dict) and entry.get("family") == "inet" and entry.get("table") == NFT_TABLE and entry.get("name") == set_name and entry.get("type") == "ipv4_addr":
            return entry.get("elem", [])
    raise AliasSelectionError(f"LAN alias nft set {set_name} is missing or malformed")


def _source_set_is_singleton(elements, candidate):
    # nft 1.1.x serializes ipv4_addr set elements as plain strings.
    return isinstance(elements, list) and elements == [candidate]


def _ensure_source_set(candidate):
    current = _set_elements(SOURCE_SET)
    if _source_set_is_singleton(current, candidate):
        return
    if current:
        raise AliasSelectionError("LAN alias source set contains foreign or duplicate elements")
    _run(["nft", "add", "element", "inet", NFT_TABLE, SOURCE_SET, "{", candidate, "}"])
    if not _source_set_is_singleton(_set_elements(SOURCE_SET), candidate):
        raise AliasSelectionError("LAN alias source set failed verification")


def _ensure_owned_source_guard(candidate):
    chain = _run(["nft", "-a", "list", "chain", "inet", NFT_TABLE, "output"]).stdout
    comment = '"dnscomplex-lan-alias-owned-source-guard"'
    anchors = []
    owned = []
    for line in chain.splitlines():
        if comment in line:
            owned.append(line)
        if '"dnscomplex-lan-alias-not-ready"' in line:
            anchors.append(line)
    expected = ["ip", "saddr", candidate, "ip", "daddr", "!=", "@lan_alias_ready4",
                "drop", "comment", comment]
    def tokens(line):
        fields = line.split("#", 1)[0].split()
        result = []
        index = 0
        while index < len(fields):
            if fields[index] == "counter" and index + 4 < len(fields) and fields[index + 1] == "packets" and fields[index + 3] == "bytes":
                index += 5
                continue
            result.append(fields[index])
            index += 1
        return result
    anchor_line = anchors[0] if len(anchors) == 1 else ""
    if len(owned) == 1 and tokens(owned[0]) == expected:
        if anchor_line and chain.splitlines().index(owned[0]) < chain.splitlines().index(anchor_line):
            return
        raise AliasSelectionError("LAN alias source guard is after set-based alias classification")
    if owned:
        raise AliasSelectionError("LAN alias source guard comment is occupied by a foreign rule")
    handle_match = re.search(r"# handle ([0-9]+)$", anchor_line)
    if len(anchors) != 1 or not handle_match:
        raise AliasSelectionError("LAN alias source classifier anchor is missing or ambiguous")
    anchor = handle_match.group(1)
    _run(["nft", "insert", "rule", "inet", NFT_TABLE, "output", "position", anchor,
          "ip", "saddr", candidate, "ip", "daddr", "!=", "@lan_alias_ready4",
          "counter", "drop", "comment", "dnscomplex-lan-alias-owned-source-guard"])
    chain = _run(["nft", "-a", "list", "chain", "inet", NFT_TABLE, "output"]).stdout
    matches = [line for line in chain.splitlines() if comment in line and tokens(line) == expected]
    if len(matches) != 1:
        raise AliasSelectionError("LAN alias source guard failed verification")


def _nft_rule_tokens(line):
    fields = line.split("#", 1)[0].split()
    result = []
    index = 0
    while index < len(fields):
        if (fields[index] == "counter" and index + 4 < len(fields) and
                fields[index + 1] == "packets" and fields[index + 3] == "bytes"):
            index += 5
            continue
        result.append(fields[index])
        index += 1
    return result


def _verify_tagged_rule_set(text, expected, ordered_comments, prefix):
    lines = text.splitlines()
    expected_comments = set(expected)
    found = {}
    for line in lines:
        for comment in expected_comments:
            if f'"{comment}"' in line:
                found.setdefault(comment, []).append(line)
    for comment, wanted in expected.items():
        matches = found.get(comment, [])
        if (len(matches) != 1 or
                _normalize_nft_rule_tokens(_nft_rule_tokens(matches[0])) !=
                _normalize_nft_rule_tokens(wanted)):
            raise AliasSelectionError(f"LAN alias nft rule {comment} is missing, duplicated, or modified")
    alias_comments = set()
    for line in lines:
        match = re.search(r'comment "([^"]+)"', line)
        if match and match.group(1).startswith(prefix):
            alias_comments.add(match.group(1))
    if alias_comments != expected_comments:
        raise AliasSelectionError("LAN alias nft chain contains unexpected or missing owned rules")
    positions = [lines.index(found[comment][0]) for comment in ordered_comments]
    if positions != sorted(positions):
        raise AliasSelectionError("LAN alias nft rules are out of fail-closed policy order")


def _canonical_mark(value):
    try:
        numeric = int(str(value), 0)
    except (TypeError, ValueError) as exc:
        raise AliasSelectionError("invalid nft mark passed to LAN alias verifier") from exc
    if not 0 < numeric <= 0xFFFFFFFF:
        raise AliasSelectionError("nft mark is outside uint32 range")
    return hex(numeric)


def _normalize_nft_mark_tokens(tokens):
    """Normalize only nft's zero-padded hexadecimal mark rendering."""
    normalized = list(tokens)
    for index, token in enumerate(normalized):
        if (token.lower().startswith("0x") and
                ((index >= 1 and normalized[index - 1] == "mark") or
                 (index >= 2 and normalized[index - 2:index] == ["mark", "set"]) or
                 (index >= 3 and normalized[index - 3:index] == ["ct", "mark", "!="]))):
            try:
                normalized[index] = _canonical_mark(token)
            except AliasSelectionError:
                pass
    return normalized


def _normalize_nft_rule_tokens(tokens):
    normalized = _normalize_nft_mark_tokens(tokens)
    inside_set = False
    for index, token in enumerate(normalized):
        if token == "{":
            inside_set = True
        elif token == "}":
            inside_set = False
        elif inside_set and token.endswith(","):
            normalized[index] = token[:-1]
    needle = ["reject", "with", "icmp", "type", "port-unreachable"]
    for index in range(len(normalized) - len(needle) + 1):
        if normalized[index:index + len(needle)] == needle:
            del normalized[index + 3]
            break
    return normalized


def _verify_alias_output_before_terminal_rules(output):
    lines = output.splitlines()
    alias_positions = [index for index, line in enumerate(lines)
                       if 'comment "dnscomplex-lan-alias-' in line]
    if not alias_positions:
        raise AliasSelectionError("LAN alias output classifier is missing")
    last_alias = max(alias_positions)
    terminal_patterns = (
        'udp dport { 500, 4500 } accept comment "dnscomplex-ipsec-underlay"',
        'comment "dnscomplex-domain-default-output"',
    )
    for pattern in terminal_patterns:
        positions = [index for index, line in enumerate(lines) if pattern in line]
        if len(positions) != 1 or positions[0] <= last_alias:
            raise AliasSelectionError("terminal output accept precedes the complete LAN alias policy")
    private_accepts = [index for index, line in enumerate(lines)
                       if _private_output_accept_matches(line)]
    if len(private_accepts) != 1 or private_accepts[0] <= last_alias:
        raise AliasSelectionError("terminal output accept precedes the complete LAN alias policy")
    for index, line in enumerate(lines):
        if 'comment "dnscomplex-' in line and "-xray-underlay-" in line and index < last_alias:
            tokens = _nft_rule_tokens(line)
            safe_v4_exclusion = ["ip", "saddr", "!=", "198.18.255.254"]
            safe_v6 = ["ip6", "daddr"]
            if not any(tokens[pos:pos + len(safe_v4_exclusion)] == safe_v4_exclusion
                       for pos in range(len(tokens))) and not any(
                           tokens[pos:pos + len(safe_v6)] == safe_v6
                           for pos in range(len(tokens))
                       ):
                raise AliasSelectionError(
                    "Xray transport terminal rule can match the LAN alias source"
                )


def _private_output_accept_matches(line):
    tokens = _nft_rule_tokens(line)
    if tokens[:3] != ["ip", "daddr", "{"]:
        return False
    try:
        end = tokens.index("}", 3)
        if tokens[end + 1:] != ["accept"]:
            return False
        networks = [ipaddress.ip_network(token.rstrip(","), strict=True)
                    for token in tokens[3:end]]
        if not networks or any(network.version != 4 for network in networks):
            return False
    except (ValueError, IndexError):
        return False
    expected = (
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    )
    canonical = tuple(str(network) for network in ipaddress.collapse_addresses(networks))
    expected_canonical = tuple(
        str(network) for network in ipaddress.collapse_addresses(
            ipaddress.ip_network(value) for value in expected
        )
    )
    return canonical == expected_canonical


def _verify_xray_transport_output_rules(output, policy):
    expected = {}
    for profile in ("ai", "cn"):
        prefix = f"dnscomplex-{profile}-xray-underlay-"
        if policy[f"{profile}_mode"] == "xray":
            mark = _canonical_mark(policy[f"{profile}_mark"])
            expected[prefix + "ready4"] = [
                "ip", "saddr", "!=", "198.18.255.254", "meta", "mark", mark,
                "ip", "daddr", f"@{profile}_ready4", "meta", "mark", "set",
                _canonical_mark(policy["auto_mark"]), "accept", "comment",
                f'"{prefix}ready4"',
            ]
            expected[prefix + "ready6"] = [
                "meta", "mark", mark, "ip6", "daddr", f"@{profile}_ready6",
                "meta", "mark", "set", _canonical_mark(policy["auto_mark"]),
                "accept", "comment", f'"{prefix}ready6"',
            ]
            expected[prefix + "not-ready"] = [
                "ip", "saddr", "!=", "198.18.255.254", "meta", "mark", mark,
                "drop", "comment", f'"{prefix}not-ready"',
            ]
    lines = output.splitlines()
    expected_comments = set(expected)
    for comment, wanted in expected.items():
        matches = [line for line in lines if f'"{comment}"' in line]
        if (len(matches) != 1 or
                _normalize_nft_rule_tokens(_nft_rule_tokens(matches[0])) != wanted):
            raise AliasSelectionError(f"Xray transport rule {comment} is missing or modified")
    actual_comments = set()
    for line in lines:
        match = re.search(r'comment "([^"]+)"', line)
        if match and re.fullmatch(r"dnscomplex-(ai|cn)-xray-underlay-(ready4|ready6|not-ready)",
                                  match.group(1)):
            actual_comments.add(match.group(1))
    if actual_comments != expected_comments:
        raise AliasSelectionError("Xray transport output rules do not match the selected profiles")


def _verify_live_nft_policy(candidate, policy):
    lan_interface = policy["lan_interface"]
    output = _run(["nft", "-a", "list", "chain", "inet", NFT_TABLE, "output"]).stdout
    _verify_xray_transport_output_rules(output, policy)
    auto_mark = _canonical_mark(policy["auto_mark"])
    source = "@lan_alias_source4"
    expected_output = {
        "dnscomplex-lan-alias-owned-source-guard": [
            "ip", "saddr", candidate, "ip", "daddr", "!=", "@lan_alias_ready4",
            "drop", "comment", '"dnscomplex-lan-alias-owned-source-guard"'],
        "dnscomplex-lan-alias-not-ready": [
            "ip", "saddr", source, "ip", "daddr", "!=", "@lan_alias_ready4",
            "drop", "comment", '"dnscomplex-lan-alias-not-ready"'],
        "dnscomplex-lan-alias-ai-not-ready": [
            "ip", "saddr", source, "ip", "daddr", "@ai4", "ip", "daddr", "!=",
            "@ai_ready4", "drop", "comment", '"dnscomplex-lan-alias-ai-not-ready"'],
        "dnscomplex-lan-alias-cn-not-ready": [
            "ip", "saddr", source, "ip", "daddr", "@cn4", "ip", "daddr", "!=",
            "@cn_ready4", "drop", "comment", '"dnscomplex-lan-alias-cn-not-ready"'],
        "dnscomplex-lan-alias-default-mark": [
            "ip", "saddr", source, "meta", "mark", "set", auto_mark,
            "comment", '"dnscomplex-lan-alias-default-mark"'],
    }
    if policy["ai_quic"] == "reject":
        expected_output["dnscomplex-lan-alias-quic-reject-ai"] = [
            "ip", "saddr", source, "ip", "daddr", "@ai4", "udp", "dport", "443",
            "reject", "with", "icmp", "type", "port-unreachable", "comment",
            '"dnscomplex-lan-alias-quic-reject-ai"']
    if policy["ai_mode"] == "ipsec":
        expected_output["dnscomplex-lan-alias-classified-ai"] = [
            "ip", "saddr", source, "ip", "daddr", "@ai4", "meta", "l4proto", "{",
            "tcp", "udp", "}", "meta", "mark", "set", _canonical_mark(policy["ai_mark"]),
            "comment", '"dnscomplex-lan-alias-classified-ai"']
    if policy["cn_quic"] == "reject":
        expected_output["dnscomplex-lan-alias-quic-reject-cn"] = [
            "ip", "saddr", source, "ip", "daddr", "@cn4", "udp", "dport", "443",
            "reject", "with", "icmp", "type", "port-unreachable", "comment",
            '"dnscomplex-lan-alias-quic-reject-cn"']
    if policy["cn_mode"] == "ipsec":
        expected_output["dnscomplex-lan-alias-classified-cn"] = [
            "ip", "saddr", source, "ip", "daddr", "@cn4", "meta", "l4proto", "{",
            "tcp", "udp", "}", "meta", "mark", "set", _canonical_mark(policy["cn_mark"]),
            "comment", '"dnscomplex-lan-alias-classified-cn"']
    expected_output["dnscomplex-lan-alias-default-output"] = [
        "ip", "saddr", source, "accept", "comment", '"dnscomplex-lan-alias-default-output"']
    order = [
        "dnscomplex-lan-alias-owned-source-guard",
        "dnscomplex-lan-alias-not-ready",
        "dnscomplex-lan-alias-ai-not-ready",
        "dnscomplex-lan-alias-cn-not-ready",
        "dnscomplex-lan-alias-default-mark",
    ]
    for profile in ("ai", "cn"):
        quic = f"dnscomplex-lan-alias-quic-reject-{profile}"
        classified = f"dnscomplex-lan-alias-classified-{profile}"
        if quic in expected_output:
            order.append(quic)
        if classified in expected_output:
            order.append(classified)
    order.append("dnscomplex-lan-alias-default-output")
    _verify_tagged_rule_set(output, expected_output, order, "dnscomplex-lan-alias-")
    _verify_alias_output_before_terminal_rules(output)

    _verify_ready_set_shape(CONFIG_READY_SET)
    prerouting = _run(["nft", "-a", "list", "chain", "inet", NFT_TABLE,
                       "prerouting"]).stdout
    restore = _run(["nft", "-a", "list", "chain", "inet", NFT_TABLE,
                    "prerouting_policy_restore"]).stdout
    preroute_rules = {
        "dnscomplex-lan-alias-fresh-flow": [
            "iifname", f'"{lan_interface}"', "ip", "daddr", "@lan_alias_config_ready4",
            "meta", "l4proto", "{", "tcp", "udp", "}", "ct", "mark", "!=", auto_mark,
            "return", "comment", '"dnscomplex-lan-alias-fresh-flow"'],
    }
    restore_rules = {
        "dnscomplex-lan-alias-fresh-flow-restore": [
            "iifname", f'"{lan_interface}"', "ip", "daddr", "@lan_alias_config_ready4",
            "meta", "l4proto", "{", "tcp", "udp", "}", "ct", "mark", "!=", auto_mark,
            "return", "comment", '"dnscomplex-lan-alias-fresh-flow-restore"'],
    }
    _verify_tagged_rule_set(prerouting, preroute_rules,
                            ["dnscomplex-lan-alias-fresh-flow"],
                            "dnscomplex-lan-alias-fresh-flow")
    _verify_tagged_rule_set(restore, restore_rules,
                            ["dnscomplex-lan-alias-fresh-flow-restore"],
                            "dnscomplex-lan-alias-fresh-flow-restore")

    postrouting = _run(["nft", "-a", "list", "chain", "inet", NFT_TABLE,
                        "postrouting"]).stdout
    default_comment = "dnscomplex-lan-alias-snat-default"
    if policy["default_snat_kind"] == "snat":
        default_rule = ["oifname", f'"{policy["default_snat_interface"]}"', "ip", "saddr",
                        source, "snat", "ip", "to", policy["default_snat_address"],
                        "comment", f'"{default_comment}"']
    else:
        default_rule = ["oifname", f'"{policy["default_snat_interface"]}"', "ip", "saddr",
                        source, "masquerade", "comment", f'"{default_comment}"']
    expected_nat = {default_comment: default_rule}
    nat_order = [default_comment]
    for profile in ("ai", "cn"):
        comment = f"dnscomplex-lan-alias-snat-{profile}"
        matches = [line for line in postrouting.splitlines() if f'"{comment}"' in line]
        if len(matches) > 1:
            raise AliasSelectionError(f"LAN alias {profile} SNAT rule is duplicated")
        expected_vip = policy.get(f"{profile}_vip", "")
        if policy[f"{profile}_mode"] == "ipsec" and expected_vip and len(matches) != 1:
            raise AliasSelectionError(f"LAN alias {profile} SNAT rule is missing")
        if (policy[f"{profile}_mode"] != "ipsec" or not expected_vip) and matches:
            raise AliasSelectionError(f"LAN alias {profile} SNAT rule exists without a ready IPsec VIP")
        if matches:
            device = f'"ipsec-{profile}"'
            tokens = _nft_rule_tokens(matches[0])
            if (len(tokens) != 11 or tokens[:8] != ["oifname", device, "ip", "saddr",
                    source, "snat", "ip", "to"] or
                    not re.fullmatch(STRICT_IPV4, tokens[8]) or tokens[9:] != [
                        "comment", f'"{comment}"']):
                raise AliasSelectionError(f"LAN alias {profile} SNAT rule is modified")
            expected_vip = policy.get(f"{profile}_vip", "")
            if not expected_vip or tokens[8] != expected_vip:
                raise AliasSelectionError(f"LAN alias {profile} SNAT VIP is stale or unverifiable")
            expected_nat[comment] = tokens
            nat_order.append(comment)
    _verify_tagged_rule_set(postrouting, expected_nat, nat_order,
                            "dnscomplex-lan-alias-snat-")


def _bootstrap_missing_ipsec_alias_snat(candidate, policy):
    if not _source_set_is_singleton(_set_elements(SOURCE_SET), candidate):
        raise AliasSelectionError("LAN alias source set is not verified before SNAT bootstrap")
    if _alias_gate_is_open():
        _set_alias_gate(candidate, open_gate=False)
    _verify_alias_gate(open_gate=False)

    command = ["nft", "-a", "list", "chain", "inet", NFT_TABLE, "postrouting"]
    output = _run(command).stdout
    for profile in ("ai", "cn"):
        if policy[f"{profile}_mode"] != "ipsec":
            continue
        vip = policy.get(f"{profile}_vip", "")
        if not vip:
            continue
        try:
            ipaddress.IPv4Address(vip)
        except ipaddress.AddressValueError as exc:
            raise AliasSelectionError(f"invalid {profile} VIP for LAN alias SNAT") from exc
        comment = f"dnscomplex-lan-alias-snat-{profile}"
        marker = f'comment "{comment}"'
        if any(marker in line for line in output.splitlines()):
            # Existing, stale, duplicate, or modified rules require the normal
            # ownership-aware watchdog repair and strict readback below.
            continue
        rule = ["oifname", f'"ipsec-{profile}"', "ip", "saddr", "@lan_alias_source4",
                "snat", "ip", "to", vip, "comment", f'"{comment}"']
        _run(["nft", "add", "rule", "inet", NFT_TABLE, "postrouting",
              "oifname", f"ipsec-{profile}", "ip", "saddr", "@lan_alias_source4",
              "snat", "ip", "to", vip, "comment", comment])
        output = _run(command).stdout
        matches = [line for line in output.splitlines() if marker in line]
        if (len(matches) != 1 or
                _normalize_nft_rule_tokens(_nft_rule_tokens(matches[0])) != rule):
            raise AliasSelectionError(f"new {profile} LAN alias SNAT did not verify")


def _close_readiness_gates(candidate):
    failures = []
    for name, setter, verifier in (
        ("LAN alias", _set_alias_gate, _verify_alias_gate),
        ("domain config", _set_config_gate, _verify_config_gate),
    ):
        try:
            if name == "LAN alias":
                setter(candidate, open_gate=False)
            else:
                setter(open_gate=False)
            verifier(open_gate=False)
        except Exception as exc:
            failures.append(f"{name} readiness could not be verified closed: {exc}")
    if failures:
        raise AliasSelectionError("; ".join(failures))


def _close_watchdog_readiness_gates():
    """Close raw readiness within one shared, independent one-second window."""
    global COMMAND_DEADLINE_MS, CLEANUP_ATTEMPTED
    if CLEANUP_ATTEMPTED:
        return
    CLEANUP_ATTEMPTED = True
    previous_deadline = COMMAND_DEADLINE_MS
    COMMAND_DEADLINE_MS = time.monotonic_ns() // 1_000_000 + 1000
    raw_error = None
    config_error = None
    try:
        try:
            _set_alias_gate(DEFAULT_CANDIDATE, open_gate=False)
            _verify_alias_gate(open_gate=False)
        except Exception as exc:
            raw_error = exc
        if raw_error is not None or CONFIG_PROOF_INVALID:
            try:
                _set_config_gate(open_gate=False)
                _verify_config_gate(open_gate=False)
            except Exception as exc:
                config_error = exc
        if raw_error is not None:
            detail = f"raw readiness could not be verified closed: {raw_error}"
            if config_error is not None:
                detail += f"; domain config readiness could not be verified closed: {config_error}"
            raise AliasSelectionError(detail) from raw_error
        if config_error is not None:
            raise AliasSelectionError(
                f"domain config readiness could not be verified closed: {config_error}"
            ) from config_error
    finally:
        COMMAND_DEADLINE_MS = previous_deadline


def _reconcile_fastpath_gates(candidate, *, loaded_config, keep_closed=False):
    source_ready = False
    try:
        source_ready = _source_set_is_singleton(_set_elements(SOURCE_SET), candidate)
    except Exception:
        source_ready = False
    if keep_closed:
        _close_readiness_gates(candidate)
        return loaded_config and source_ready
    try:
        alias_ready = _alias_gate_is_open()
    except Exception:
        alias_ready = False

    if not (source_ready and alias_ready):
        try:
            _set_alias_gate(candidate, open_gate=False)
            _verify_alias_gate(open_gate=False)
        except Exception as raw_close_error:
            config_close_error = None
            try:
                _set_config_gate(open_gate=False)
                _verify_config_gate(open_gate=False)
            except Exception as exc:
                config_close_error = exc
            detail = f"LAN alias readiness could not be verified closed: {raw_close_error}"
            if config_close_error is not None:
                detail += f"; domain config readiness also failed to close: {config_close_error}"
            raise AliasSelectionError(detail) from raw_close_error
        if loaded_config and not _config_gate_is_open():
            _set_config_gate(open_gate=True)
            _verify_config_gate(open_gate=True)
        return False

    if loaded_config and not _config_gate_is_open():
        _set_config_gate(open_gate=True)
        _verify_config_gate(open_gate=True)
    return loaded_config and _config_gate_is_open()


def _verify_ready_set_shape(set_name):
    result = _run(["nft", "-j", "list", "set", "inet", NFT_TABLE, set_name])
    data = json.loads(result.stdout)
    found = []
    for item in data.get("nftables", []):
        entry = item.get("set")
        if isinstance(entry, dict) and entry.get("family") == "inet" and \
           entry.get("table") == NFT_TABLE and entry.get("name") == set_name and \
           entry.get("type") == "ipv4_addr":
            found.append(entry.get("elem", []))
    if len(found) != 1 or found[0] not in ([], [{"prefix": {"addr": "0.0.0.0", "len": 0}}]):
        raise AliasSelectionError(f"LAN alias readiness set {set_name} has an invalid shape")


def _verify_owned_address(addresses, candidate):
    return _check_addresses(addresses, ipaddress.ip_address(candidate), candidate,
                            OWNER_INTERFACE, OWNER_LABEL)


def _remove_new_address(candidate):
    addresses = json.loads(_run(["ip", "-j", "address", "show"]).stdout)
    if _verify_owned_address(addresses, candidate):
        _run(["ip", "address", "del", f"{candidate}/32", "dev", OWNER_INTERFACE])


def verify_owner(config_path=CONFIG_DEFAULT, state_path=STATE_DEFAULT):
    state = _load_state(state_path)
    if state is None:
        return False
    config = _load_json(pathlib.Path(config_path).read_text(encoding="utf-8"), "sing-box config")
    addresses = json.loads(_run(["ip", "-j", "address", "show"]).stdout)
    routes = json.loads(_run(["ip", "-j", "route", "show", "table", "all"]).stdout)
    trial = copy.deepcopy(config)
    _ensure_route_and_outbound(trial, state["address"])
    select_alias(addresses, routes, trial, state)
    return True


def reconcile(config_path=CONFIG_DEFAULT, state_path=STATE_DEFAULT, policy=None,
              keep_closed=False):
    global CONFIG_PROOF_INVALID
    if policy is None:
        policy = {
            "ai_mode": "ipsec", "cn_mode": "ipsec", "ai_mark": "0x301",
            "cn_mark": "0x351", "auto_mark": "0x2024", "ai_quic": "reject",
            "cn_quic": "reject", "default_snat_interface": "eth0",
            "default_snat_kind": "snat", "default_snat_address": "192.168.50.200",
            "lan_interface": "eth0", "ai_vip": "", "cn_vip": "",
        }
    config_path = pathlib.Path(config_path)
    state_path = pathlib.Path(state_path)
    try:
        state = _load_state(state_path)
    except Exception:
        CONFIG_PROOF_INVALID = True
        if COMMAND_DEADLINE_MS is not None:
            _close_watchdog_readiness_gates()
        else:
            _close_readiness_gates(DEFAULT_CANDIDATE)
        raise
    if keep_closed:
        CONFIG_PROOF_INVALID = True
        _close_readiness_gates(state["address"] if state is not None else DEFAULT_CANDIDATE)
    loaded_config = state is not None and _loaded_config_matches(config_path, state)
    CONFIG_PROOF_INVALID = keep_closed or not loaded_config
    initial_alias_claim = state is None
    if not loaded_config and not keep_closed:
        _set_config_gate(open_gate=False)
        _verify_config_gate(open_gate=False)

    if state is not None:
        fastpath_candidate = None
        try:
            stable_config = _load_json(config_path.read_text(encoding="utf-8"), "sing-box config")
            stable_addresses = json.loads(_run(["ip", "-j", "address", "show"]).stdout)
            stable_routes = json.loads(_run(["ip", "-j", "route", "show", "table", "all"]).stdout)
            if loaded_config and _config_has_complete_alias(stable_config, state["address"]):
                select_alias(stable_addresses, stable_routes, stable_config, state)
                _ensure_owned_source_guard(state["address"])
                _verify_live_nft_policy(state["address"], policy)
                fastpath_candidate = state["address"]
        except Exception:
            pass
        if fastpath_candidate is not None and _reconcile_fastpath_gates(
            fastpath_candidate, loaded_config=loaded_config, keep_closed=keep_closed
        ):
            return
    _set_alias_gate(DEFAULT_CANDIDATE, open_gate=False)
    _verify_alias_gate(open_gate=False)

    added_address = False
    candidate = None
    state_written = False
    try:
        config = _load_json(config_path.read_text(encoding="utf-8"), "sing-box config")
        addresses = json.loads(_run(["ip", "-j", "address", "show"]).stdout)
        routes = json.loads(_run(["ip", "-j", "route", "show", "table", "all"]).stdout)
        if state is None:
            transition_config = copy.deepcopy(config)
            _ensure_tun_alias_route_exclusion(transition_config, DEFAULT_CANDIDATE)
            candidate = select_alias(
                addresses, routes, transition_config, {},
                allow_tun_route_exclusion_transition=True,
            )
        else:
            candidate = state["address"]
            trial = copy.deepcopy(config)
            _ensure_route_and_outbound(trial, candidate)
            select_alias(addresses, routes, trial, state,
                         allow_tun_route_exclusion_transition=True)

        owned_before = state is not None and _verify_owned_address(addresses, candidate)
        if not owned_before:
            _run(["ip", "address", "add", f"{candidate}/32", "dev", OWNER_INTERFACE, "label", OWNER_LABEL])
            added_address = True
        fresh_addresses = json.loads(_run(["ip", "-j", "address", "show"]).stdout)
        fresh_routes = json.loads(_run(["ip", "-j", "route", "show", "table", "all"]).stdout)
        claimed_state = {"schema": STATE_SCHEMA, "status": "owned", "pool": DEFAULT_POOL,
                         "address": candidate, "interface": OWNER_INTERFACE,
                         "label": OWNER_LABEL, "outbound_tag": OWNER_OUTBOUND_TAG}
        if loaded_config:
            claimed_state["loaded_config_sha256"] = state["loaded_config_sha256"]
            claimed_state["loaded_main_pid"] = state["loaded_main_pid"]
        wanted = copy.deepcopy(config)
        _ensure_route_and_outbound(wanted, candidate)
        select_alias(fresh_addresses, fresh_routes, wanted, claimed_state,
                     allow_tun_route_exclusion_transition=True)
        try:
            _write_state(state_path, claimed_state)
        except Exception:
            if added_address:
                _remove_new_address(candidate)
                added_address = False
            raise
        state_written = True

        # Install the exact persistent source quarantine before publishing a
        # sing-box outbound that can create alias-bound sockets.
        _ensure_owned_source_guard(candidate)
        _ensure_source_set(candidate)
        if not _config_has_complete_alias(config, candidate):
            CONFIG_PROOF_INVALID = True
            _set_config_gate(open_gate=False)
            _verify_config_gate(open_gate=False)
        try:
            config_changed = _atomic_config(config_path, wanted)
            if not config_changed and not loaded_config:
                _run(["sing-box", "check", "-c", str(config_path)])
                _restart_singbox()
        except Exception:
            raise
        fresh_config = _load_json(config_path.read_text(encoding="utf-8"), "sing-box config")
        if not _config_has_complete_alias(fresh_config, candidate):
            raise AliasSelectionError("sing-box alias outbound/routes did not verify after publication")
        fresh_addresses = json.loads(_run(["ip", "-j", "address", "show"]).stdout)
        fresh_routes = json.loads(_run(["ip", "-j", "route", "show", "table", "all"]).stdout)
        select_alias(fresh_addresses, fresh_routes, fresh_config, claimed_state)
        claimed_state["loaded_config_sha256"] = hashlib.sha256(
            config_path.read_bytes()
        ).hexdigest()
        claimed_state["loaded_main_pid"] = _singbox_main_pid()
        _write_state(state_path, claimed_state)
        state_written = True
        CONFIG_PROOF_INVALID = False
        if initial_alias_claim:
            _bootstrap_missing_ipsec_alias_snat(candidate, policy)
        _verify_live_nft_policy(candidate, policy)
        if keep_closed:
            _close_readiness_gates(candidate)
            return
        if not _config_gate_is_open():
            _set_config_gate(open_gate=True)
            _verify_config_gate(open_gate=True)
        _set_alias_gate(candidate, open_gate=True)
        _verify_alias_gate(open_gate=True)
    except Exception as exc:
        failure = exc
        if added_address and not state_written:
            try:
                _remove_new_address(candidate)
            except Exception as rollback_exc:
                failure = AliasSelectionError(
                    f"{exc}; newly added alias address rollback failed: {rollback_exc}"
                )
        if COMMAND_DEADLINE_MS is not None:
            try:
                _close_watchdog_readiness_gates()
            except Exception as close_exc:
                raise AliasSelectionError(f"{failure}; {close_exc}") from exc
            raise failure
        try:
            _set_alias_gate(DEFAULT_CANDIDATE, open_gate=False)
            _verify_alias_gate(open_gate=False)
        except Exception as close_exc:
            config_close_error = None
            try:
                _set_config_gate(open_gate=False)
                _verify_config_gate(open_gate=False)
            except Exception as config_exc:
                config_close_error = config_exc
            detail = f"{failure}; alias readiness could not be verified closed: {close_exc}"
            if config_close_error is not None:
                detail += f"; domain config readiness also failed to close: {config_close_error}"
            raise AliasSelectionError(detail) from exc
        raise failure


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("reconcile", "close", "verify-owner", "state-owned"))
    parser.add_argument("--config", default=str(CONFIG_DEFAULT))
    parser.add_argument("--state", default=str(STATE_DEFAULT))
    parser.add_argument("--ai-mode", choices=("ipsec", "xray"), default="ipsec")
    parser.add_argument("--cn-mode", choices=("ipsec", "xray"), default="ipsec")
    parser.add_argument("--ai-mark", default="0x301")
    parser.add_argument("--cn-mark", default="0x351")
    parser.add_argument("--auto-mark", default="0x2024")
    parser.add_argument("--ai-quic", choices=("reject", "allow"), default="allow")
    parser.add_argument("--cn-quic", choices=("reject", "allow"), default="reject")
    parser.add_argument("--default-snat-interface", default="eth0")
    parser.add_argument("--default-snat-kind", choices=("snat", "masquerade"), default="snat")
    parser.add_argument("--default-snat-address", default="192.168.50.200")
    parser.add_argument("--lan-interface", default="eth0")
    parser.add_argument("--ai-vip", default="")
    parser.add_argument("--cn-vip", default="")
    parser.add_argument("--keep-closed", action="store_true")
    args = parser.parse_args()
    global COMMAND_DEADLINE_MS, CLEANUP_ATTEMPTED, CONFIG_PROOF_INVALID
    CLEANUP_ATTEMPTED = False
    CONFIG_PROOF_INVALID = False
    watchdog_deadline = os.environ.get("DNSCOMPLEX_WATCHDOG_DEADLINE_MS", "")
    if args.command == "reconcile" and watchdog_deadline:
        if not re.fullmatch(r"[1-9][0-9]{0,15}", watchdog_deadline):
            print("dnscomplex-lan-alias: invalid watchdog deadline", file=sys.stderr)
            return 1
        COMMAND_DEADLINE_MS = int(watchdog_deadline)
        CONFIG_PROOF_INVALID = True
    try:
        if args.command == "close":
            _set_alias_gate(DEFAULT_CANDIDATE, open_gate=False)
            _verify_alias_gate(open_gate=False)
            _set_config_gate(open_gate=False)
            _verify_config_gate(open_gate=False)
        elif args.command == "verify-owner":
            if not verify_owner(args.config, args.state):
                return 1
        elif args.command == "state-owned":
            return 0 if _load_state(args.state) is not None else 1
        else:
            reconcile(args.config, args.state, {
                "ai_mode": args.ai_mode, "cn_mode": args.cn_mode,
                "ai_mark": args.ai_mark, "cn_mark": args.cn_mark,
                "auto_mark": args.auto_mark, "ai_quic": args.ai_quic,
                "cn_quic": args.cn_quic,
                "default_snat_interface": args.default_snat_interface,
                "default_snat_kind": args.default_snat_kind,
                "default_snat_address": args.default_snat_address,
                "lan_interface": args.lan_interface,
                "ai_vip": args.ai_vip,
                "cn_vip": args.cn_vip,
            }, keep_closed=args.keep_closed)
    except Exception as exc:
        if args.command == "reconcile" and COMMAND_DEADLINE_MS is not None:
            try:
                _close_watchdog_readiness_gates()
            except Exception as close_exc:
                print(f"dnscomplex-lan-alias: {exc}; {close_exc}", file=sys.stderr)
                return 1
        print(f"dnscomplex-lan-alias: {exc}", file=sys.stderr)
        return 2 if args.command == "state-owned" else 1
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main())

LAN_ALIAS
  chmod_target 0755 /usr/local/libexec/dnscomplex-lan-alias
}

render_management_script() {
  write_file_atomic /usr/local/sbin/dnscomplex <<'MANAGER'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

DNSCOMPLEX_ROOT=${DNSCOMPLEX_ROOT:-}
FS_ROOT=${DNSCOMPLEX_FS_ROOT:-$DNSCOMPLEX_ROOT}
# The operation helper passes ROOT=/ on a live host; keep its default target canonical.
CONFIG=${DNSCOMPLEX_CONFIG:-${FS_ROOT%/}/etc/dnscomplex/config.env}
BASE=${DNSCOMPLEX_BASE:-${FS_ROOT}/var/lib/dnscomplex}
RUN_DIR=${DNSCOMPLEX_RUN_DIR:-${FS_ROOT}/run/dnscomplex}
MAINTENANCE_LOCK=${DNSCOMPLEX_MAINTENANCE_LOCK:-${FS_ROOT}/run/lock/dnscomplex-maintenance.lock}
LOCAL_HOSTS="${FS_ROOT}/etc/dnscomplex/local-hosts"
GEO_DIR=$BASE/geosite
DLC_DIR=$GEO_DIR/domain-list-community

die() {
  printf '[dnscomplex] ERROR: %s\n' "$*" >&2
  exit 1
}

validate_egress_profile_values() {
  local name value dec_name dec_value ai_table cn_table marks=""
  for name in AI_MARK CN_MARK SINGBOX_AUTO_REDIRECT_INPUT_MARK SINGBOX_AUTO_REDIRECT_OUTPUT_MARK \
      IPSEC_DATAPLANE_AI_MARK IPSEC_DATAPLANE_CN_MARK; do
    value=${!name:-}
    [[ "$value" =~ ^(0[xX][0-9a-fA-F]{1,8}|0|[1-9][0-9]{0,9})$ ]] || return 1
    value=$((value))
    ((value > 0 && value <= 4294967295)) || return 1
    case " $marks " in *" $value "*) return 1 ;; esac
    marks="$marks $value"
    case "$name" in
      AI_MARK) dec_name=AI_MARK_DEC ;;
      CN_MARK) dec_name=CN_MARK_DEC ;;
      SINGBOX_AUTO_REDIRECT_INPUT_MARK) dec_name=SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC ;;
      SINGBOX_AUTO_REDIRECT_OUTPUT_MARK) dec_name=SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC ;;
      IPSEC_DATAPLANE_AI_MARK) dec_name=IPSEC_DATAPLANE_AI_MARK_DEC ;;
      IPSEC_DATAPLANE_CN_MARK) dec_name=IPSEC_DATAPLANE_CN_MARK_DEC ;;
    esac
    dec_value=${!dec_name:-}
    [[ "$dec_value" =~ ^[0-9]{1,10}$ ]] && ((10#$dec_value == value)) || return 1
  done
  [[ "${AI_TABLE:-}" =~ ^[0-9]{1,10}$ && "${CN_TABLE:-}" =~ ^[0-9]{1,10}$ ]] || return 1
  ai_table=$((10#${AI_TABLE})); cn_table=$((10#${CN_TABLE}))
  for value in "$ai_table" "$cn_table"; do
    ((value > 0 && value <= 4294967295 && value != 253 && value != 254 && value != 255)) || return 1
  done
  ((ai_table != cn_table))
}

log() {
  printf '[dnscomplex] %s\n' "$*"
}

warn() {
  printf '[dnscomplex] WARN: %s\n' "$*" >&2
}

curl_bounded() {
  curl --connect-timeout 10 --max-time 180 \
    --retry 2 --retry-delay 2 --retry-all-errors "$@"
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
  : "${SMARTDNS_DEFAULT_PORT:=6053}"
  : "${SMARTDNS_AI_PORT:=6054}"
  : "${SMARTDNS_CN_PORT:=6055}"
  if [[ -z "${SINGBOX_SOCKS_LISTEN:-}" ]]; then
    if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
      SINGBOX_SOCKS_LISTEN=${LINUX_LAN_IPV4:-}
    else
      SINGBOX_SOCKS_LISTEN=0.0.0.0
    fi
  fi
  if [[ -z "${SINGBOX_SOCKS_PORT:-}" ]]; then
    if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
      SINGBOX_SOCKS_PORT=10800
    else
      SINGBOX_SOCKS_PORT=1080
    fi
  fi
  : "${SINGBOX_DNS_LISTEN:=127.0.0.1}"
  : "${SINGBOX_DNS_PORT:=1053}"
  : "${SINGBOX_LOG_LEVEL:=warn}"
  : "${SINGBOX_HTTP_LISTEN:=0.0.0.0}"
  : "${SINGBOX_HTTP_PORT:=1081}"
  : "${XRAY_ENABLED:=1}"
  : "${XRAY_LISTEN_HOST:=127.0.0.1}"
  : "${XRAY_AI_SOCKS_PORT:=16054}"
  : "${XRAY_CN_SOCKS_PORT:=16055}"
  : "${AI_EGRESS_MODE:=ipsec}"
  : "${CN_EGRESS_MODE:=ipsec}"
  : "${AI_QUIC_POLICY:=allow}"
  : "${CN_QUIC_POLICY:=reject}"
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
  : "${DNSCOMPLEX_IPSEC_BOOT_TIMEOUT:=90}"
  : "${APPLE_PRIVATE_RELAY_BLOCK:=1}"
  : "${AI_GEOSITE_SOURCES:=openai anthropic}"
  : "${AI_SUPPORT_DOMAINS:=meta.ai}"
  : "${AI_NFTSET_REFRESH_DOMAINS:=chatgpt.com ios.chat.openai.com openai.com api.openai.com oaistatic.com oaiusercontent.com files.oaiusercontent.com cdn.oaistatic.com persistent.oaistatic.com cdn.openai.com anthropic.com claude.ai claude.com meta.ai}"
  : "${SING_GEOSITE_RULESET_BASE_URL:=https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set}"
  : "${CN_VIDEO_SOURCES:=acfun bilibili douyin douyu gitv hunantv huya iqiyi kuaishou le pptv youku wasu v.qq.com video.qq.com tencentvideo.com cibntv.net}"
  : "${AI_SAMPLE_DOMAINS:=openai.com anthropic.com claude.ai meta.ai}"
  : "${CN_SAMPLE_DOMAINS:=bilibili.com iqiyi.com youku.com douyin.com kuaishou.com acfun.cn mgtv.com v.qq.com tv.cctv.com}"
  : "${CN_NFTSET_REFRESH_DOMAINS:=$CN_SAMPLE_DOMAINS}"
  : "${CN_STATIC_A_OVERRIDES:=}"
  : "${CN_OVERRIDE_PROBE_DOMAINS:=youku.com=youku.com,www.youku.com}"
  : "${CN_OVERRIDE_PROBE_RESOLVERS:=223.5.5.5 119.29.29.29 1.1.1.1 8.8.8.8}"
  : "${CN_OVERRIDE_PROBE_TIMEOUT:=8}"
  : "${LOCAL_DOMAIN_IPV6_POLICY:=ipv4_only}"
  migrate_ai_meta_sample_domains
  : "${AI_MARK:=0x301}"
  : "${CN_MARK:=0x351}"
  : "${AI_MARK_DEC:=769}"
  : "${CN_MARK_DEC:=849}"
  : "${SINGBOX_AUTO_REDIRECT_INPUT_MARK:=0x2023}"
  : "${SINGBOX_AUTO_REDIRECT_OUTPUT_MARK:=0x2024}"
  : "${SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC:=8227}"
  : "${SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC:=8228}"
  : "${IPSEC_DATAPLANE_AI_MARK:=0x3A1}"
  : "${IPSEC_DATAPLANE_CN_MARK:=0x3F1}"
  : "${IPSEC_DATAPLANE_AI_MARK_DEC:=929}"
  : "${IPSEC_DATAPLANE_CN_MARK_DEC:=1009}"
  : "${AI_TABLE:=301}"
  : "${CN_TABLE:=351}"
  : "${AI_XFRM_ID:=301}"
  : "${CN_XFRM_ID:=351}"
  validate_egress_profile_values || die "invalid egress profile marks or routing tables"
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
LOCAL_DOMAIN_IPV6_POLICY
SMARTDNS_DEFAULT_PORT
SMARTDNS_AI_PORT
SMARTDNS_CN_PORT
SINGBOX_DNS_LISTEN
SINGBOX_DNS_PORT
SINGBOX_LOG_LEVEL
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
AI_QUIC_POLICY
CN_QUIC_POLICY
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
DNSCOMPLEX_IPSEC_BOOT_TIMEOUT
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

# Narrow Apple Intelligence/Siri endpoints from Apple's enterprise network list.
# Keep CDN providers and other Apple/iCloud services on the default classifier.
apple_ai_support_sources() {
  cat <<'EOF'
full:guzzoni.apple.com
domain:smoot.apple.com
full:apple-relay.cloudflare.com
full:apple-relay.fastly-edge.com
full:cp4.cloudflare.com
full:apple-relay.apple.com
EOF
}

apple_ai_support_domains() {
  apple_ai_support_sources | sed 's/^[^:]*://'
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

valid_local_hostname() {
  local host
  host=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  [[ "$host" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.local$ ]]
}

valid_ipv4() {
  local ip=$1 octet
  local -a octets=()
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r -a octets <<<"$ip"
  (( ${#octets[@]} == 4 )) || return 1
  for octet in "${octets[@]}"; do
    (( 10#$octet <= 255 )) || return 1
  done
}

write_adguard_upstream_rules() {
  printf "    - '%s:%s'\n" "$SINGBOX_DNS_LISTEN" "$SINGBOX_DNS_PORT"
}

write_adguard_allow_rules() {
  local domain
  {
    split_words "${AI_SAMPLE_DOMAINS:-}"
    split_words "${AI_SUPPORT_DOMAINS:-}"
    apple_ai_support_domains
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
    /^  (bogus_nxdomain|blocked_response_ttl|user_rules):/ && !inserted {
      printf "%s", block
      inserted = 1
    }
    /^user_rules:/ && !inserted {
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

normalize_adguard_http_config() {
  local input=$1
  local output=$2
  if grep -q '^http:[[:space:]]*$' "$input"; then
    awk '
      /^http:[[:space:]]*$/ {
        in_http = 1
        saw_address = 0
        print
        next
      }
      in_http && /^[^[:space:]#]/ {
        if (!saw_address) {
          print "  address: 127.0.0.1:3000"
        }
        in_http = 0
      }
      in_http && /^  address:/ {
        if (!saw_address) {
          print "  address: 127.0.0.1:3000"
          saw_address = 1
        }
        next
      }
      $1 == "bind_host:" || $1 == "bind_port:" { next }
      { print }
      END {
        if (in_http && !saw_address) {
          print "  address: 127.0.0.1:3000"
        }
      }
    ' "$input" >"$output"
  else
    {
      cat <<'EOF'
http:
  pprof:
    port: 6060
    enabled: false
  address: 127.0.0.1:3000
  session_ttl: 30d
EOF
      awk '$1 != "bind_host:" && $1 != "bind_port:" { print }' "$input"
    } >"$output"
  fi
}

render_adguard_runtime() {
  local tmp rules allow_rules merged normalized adguard_config
  adguard_config=$(fs_path /etc/AdGuardHome/AdGuardHome.yaml)
  tmp=$(mktemp)
  rules=$(mktemp)
  allow_rules=$(mktemp)
  merged=$(mktemp)
  normalized=$(mktemp)
  write_adguard_upstream_rules >"$rules"
  write_adguard_allow_rules >"$allow_rules"

  if [[ -s "$adguard_config" ]] && grep -q '^  upstream_dns:' "$adguard_config"; then
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
    ' "$adguard_config" >"$tmp"
  else
    {
      cat <<EOF
http:
  pprof:
    port: 6060
    enabled: false
  doh:
    routes:
      - GET /dns-query
      - POST /dns-query
      - GET /dns-query/{ClientID}
      - POST /dns-query/{ClientID}
    insecure_enabled: false
  address: 127.0.0.1:3000
  session_ttl: 30d
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
schema_version: 34
EOF
    } >"$tmp"
  fi

  normalize_adguard_http_config "$tmp" "$normalized"
  mv "$normalized" "$tmp"
  normalize_adguard_cache_config "$tmp" "$tmp.cache"
  mv "$tmp.cache" "$tmp"
  merge_adguard_user_rules "$tmp" "$merged" "$allow_rules"
  install -m 0644 "$merged" "$adguard_config"
  rm -f "$tmp" "$rules" "$allow_rules" "$merged" "$normalized"
}

apply_runtime_network_settings() {
  modprobe nf_conntrack
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
    curl_bounded -fsSL "$url" | jq 'map(select(.draft == false)) | .[0]'
  else
    curl_bounded -fsSL "$url"
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
      smartdns -v 2>&1 | grep -Eo 'Release[0-9]+([.][0-9]+)*' | head -n1
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
  printf "%s='" "$name" || return $?
  printf "%s" "$value" | sed "s/'/'\\\\''/g" || return $?
  printf "'\n"
}

write_config_values() {
	    write_env_var DNSCOMPLEX_VERSION "${DNSCOMPLEX_VERSION:-0.3.0}" || return $?
    write_env_var DEPLOY_MODE "${DEPLOY_MODE:-vlan-gateway}" || return $?
	    write_env_var WAN_IFACE "$WAN_IFACE" || return $?
    write_env_var TRANSIT_VLAN_ID "${TRANSIT_VLAN_ID:-}" || return $?
    write_env_var LAN_VLAN_ID "${LAN_VLAN_ID:-}" || return $?
    write_env_var ROUTEROS_TRANSIT_IPV4 "${ROUTEROS_TRANSIT_IPV4:-}" || return $?
    write_env_var LINUX_TRANSIT_IPV4 "${LINUX_TRANSIT_IPV4:-}" || return $?
    write_env_var TRANSIT_IPV4_CIDR "${TRANSIT_IPV4_CIDR:-}" || return $?
    write_env_var ROUTEROS_TRANSIT_IPV6 "${ROUTEROS_TRANSIT_IPV6:-}" || return $?
    write_env_var LINUX_TRANSIT_IPV6 "${LINUX_TRANSIT_IPV6:-}" || return $?
    write_env_var TRANSIT_IPV6_CIDR "${TRANSIT_IPV6_CIDR:-}" || return $?
    write_env_var ROUTEROS_LAN_IPV4 "${ROUTEROS_LAN_IPV4:-}" || return $?
    write_env_var LINUX_LAN_IPV4 "${LINUX_LAN_IPV4:-}" || return $?
    write_env_var LAN_CLIENT_IPV4_CIDR "${LAN_CLIENT_IPV4_CIDR:-}" || return $?
    write_env_var LAN_IPV4_CIDR "${LAN_IPV4_CIDR:-}" || return $?
    write_env_var LAN_DHCP_START "${LAN_DHCP_START:-}" || return $?
    write_env_var LAN_DHCP_END "${LAN_DHCP_END:-}" || return $?
    write_env_var LAN_IPV6_PREFIX "${LAN_IPV6_PREFIX:-}" || return $?
    write_env_var LAN_IPV6_GATEWAY "${LAN_IPV6_GATEWAY:-}" || return $?
    write_env_var AI_IPSEC_SERVER "$AI_IPSEC_SERVER" || return $?
    write_env_var CN_IPSEC_SERVER "$CN_IPSEC_SERVER" || return $?
    write_env_var IPSEC_REMOTE_ID "$IPSEC_REMOTE_ID" || return $?
    write_env_var AI_IPSEC_USERNAME "$AI_IPSEC_USERNAME" || return $?
    write_env_var AI_IPSEC_PASSWORD "$AI_IPSEC_PASSWORD" || return $?
    write_env_var CN_IPSEC_USERNAME "$CN_IPSEC_USERNAME" || return $?
	    write_env_var CN_IPSEC_PASSWORD "$CN_IPSEC_PASSWORD" || return $?
	    write_env_var DEFAULT_DNS_UPSTREAMS "$DEFAULT_DNS_UPSTREAMS" || return $?
	    write_env_var DEFAULT_DNS_STRATEGY "$DEFAULT_DNS_STRATEGY" || return $?
	    write_env_var DEFAULT_IPV6_MODE "$DEFAULT_IPV6_MODE" || return $?
    write_env_var AI_DNS_UPSTREAMS "$AI_DNS_UPSTREAMS" || return $?
    write_env_var CN_DNS_UPSTREAMS "$CN_DNS_UPSTREAMS" || return $?
    write_env_var AI_GEOSITE_SOURCES "$AI_GEOSITE_SOURCES" || return $?
    write_env_var AI_SUPPORT_DOMAINS "$AI_SUPPORT_DOMAINS" || return $?
    write_env_var AI_NFTSET_REFRESH_DOMAINS "$AI_NFTSET_REFRESH_DOMAINS" || return $?
    write_env_var SING_GEOSITE_RULESET_BASE_URL "$SING_GEOSITE_RULESET_BASE_URL" || return $?
    write_env_var CN_VIDEO_SOURCES "$CN_VIDEO_SOURCES" || return $?
    write_env_var AI_SAMPLE_DOMAINS "$AI_SAMPLE_DOMAINS" || return $?
    write_env_var CN_SAMPLE_DOMAINS "$CN_SAMPLE_DOMAINS" || return $?
    write_env_var CN_NFTSET_REFRESH_DOMAINS "$CN_NFTSET_REFRESH_DOMAINS" || return $?
    write_env_var CN_STATIC_A_OVERRIDES "$CN_STATIC_A_OVERRIDES" || return $?
    write_env_var CN_OVERRIDE_PROBE_DOMAINS "$CN_OVERRIDE_PROBE_DOMAINS" || return $?
    write_env_var CN_OVERRIDE_PROBE_RESOLVERS "$CN_OVERRIDE_PROBE_RESOLVERS" || return $?
    write_env_var LOCAL_DOMAIN_IPV6_POLICY "$LOCAL_DOMAIN_IPV6_POLICY" || return $?
    write_env_var SMARTDNS_DEFAULT_PORT "$SMARTDNS_DEFAULT_PORT" || return $?
    write_env_var SMARTDNS_AI_PORT "$SMARTDNS_AI_PORT" || return $?
    write_env_var SMARTDNS_CN_PORT "$SMARTDNS_CN_PORT" || return $?
    write_env_var SINGBOX_DNS_LISTEN "$SINGBOX_DNS_LISTEN" || return $?
    write_env_var SINGBOX_DNS_PORT "$SINGBOX_DNS_PORT" || return $?
    write_env_var SINGBOX_LOG_LEVEL "$SINGBOX_LOG_LEVEL" || return $?
    write_env_var SINGBOX_SOCKS_LISTEN "$SINGBOX_SOCKS_LISTEN" || return $?
    write_env_var SINGBOX_SOCKS_PORT "$SINGBOX_SOCKS_PORT" || return $?
    write_env_var SINGBOX_HTTP_LISTEN "$SINGBOX_HTTP_LISTEN" || return $?
    write_env_var SINGBOX_HTTP_PORT "$SINGBOX_HTTP_PORT" || return $?
    write_env_var XRAY_ENABLED "$XRAY_ENABLED" || return $?
    write_env_var XRAY_LISTEN_HOST "$XRAY_LISTEN_HOST" || return $?
    write_env_var XRAY_AI_SOCKS_PORT "$XRAY_AI_SOCKS_PORT" || return $?
    write_env_var XRAY_CN_SOCKS_PORT "$XRAY_CN_SOCKS_PORT" || return $?
    write_env_var AI_EGRESS_MODE "$AI_EGRESS_MODE" || return $?
    write_env_var CN_EGRESS_MODE "$CN_EGRESS_MODE" || return $?
    write_env_var AI_QUIC_POLICY "$AI_QUIC_POLICY" || return $?
    write_env_var CN_QUIC_POLICY "$CN_QUIC_POLICY" || return $?
    write_env_var AI_XRAY_URI "$AI_XRAY_URI" || return $?
    write_env_var CN_XRAY_URI "$CN_XRAY_URI" || return $?
    write_env_var AI_XRAY_OUTBOUND_JSON "$AI_XRAY_OUTBOUND_JSON" || return $?
    write_env_var CN_XRAY_OUTBOUND_JSON "$CN_XRAY_OUTBOUND_JSON" || return $?
    write_env_var DNSCOMPLEX_WEB_LISTEN "$DNSCOMPLEX_WEB_LISTEN" || return $?
    write_env_var DNSCOMPLEX_WEB_PORT "$DNSCOMPLEX_WEB_PORT" || return $?
	    write_env_var DNSCOMPLEX_WEB_PASSWORD "$DNSCOMPLEX_WEB_PASSWORD" || return $?
	    write_env_var DNSCOMPLEX_METRICS_LISTEN "$DNSCOMPLEX_METRICS_LISTEN" || return $?
	    write_env_var DNSCOMPLEX_METRICS_PORT "$DNSCOMPLEX_METRICS_PORT" || return $?
	    write_env_var DNSCOMPLEX_UPDATE_TIME "$DNSCOMPLEX_UPDATE_TIME" || return $?
	    write_env_var DNSCOMPLEX_UPDATE_LAST_LOG "$DNSCOMPLEX_UPDATE_LAST_LOG" || return $?
	    write_env_var DNSCOMPLEX_UPDATE_CHANNEL "$DNSCOMPLEX_UPDATE_CHANNEL" || return $?
	    write_env_var DNSCOMPLEX_PINNED_VERSION "$DNSCOMPLEX_PINNED_VERSION" || return $?
	    write_env_var GITHUB_RELEASE_POLICY "$GITHUB_RELEASE_POLICY" || return $?
	    write_env_var DNSCOMPLEX_NFTSET_REFRESH_INTERVAL "$DNSCOMPLEX_NFTSET_REFRESH_INTERVAL" || return $?
    write_env_var DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT "$DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT" || return $?
    write_env_var ADGUARD_DNS_CACHE_MODE "$ADGUARD_DNS_CACHE_MODE" || return $?
    write_env_var HA_MODE "$HA_MODE" || return $?
    write_env_var HA_PRIMARY_IP "$HA_PRIMARY_IP" || return $?
    write_env_var HA_SECONDARY_IP "$HA_SECONDARY_IP" || return $?
    write_env_var HA_HEALTH_URL "$HA_HEALTH_URL" || return $?
    write_env_var HA_FAILOVER_POLICY "$HA_FAILOVER_POLICY" || return $?
    write_env_var PROMETHEUS_MODE "$PROMETHEUS_MODE" || return $?
    write_env_var IPSEC_TCP_MSS "$IPSEC_TCP_MSS" || return $?
    write_env_var DNSCOMPLEX_IPSEC_BOOT_TIMEOUT "$DNSCOMPLEX_IPSEC_BOOT_TIMEOUT" || return $?
    write_env_var APPLE_PRIVATE_RELAY_BLOCK "$APPLE_PRIVATE_RELAY_BLOCK" || return $?
    write_env_var AI_MARK "$AI_MARK" || return $?
    write_env_var CN_MARK "$CN_MARK" || return $?
	    write_env_var AI_MARK_DEC "$AI_MARK_DEC" || return $?
	    write_env_var CN_MARK_DEC "$CN_MARK_DEC" || return $?
	    write_env_var SINGBOX_AUTO_REDIRECT_INPUT_MARK "$SINGBOX_AUTO_REDIRECT_INPUT_MARK" || return $?
	    write_env_var SINGBOX_AUTO_REDIRECT_OUTPUT_MARK "$SINGBOX_AUTO_REDIRECT_OUTPUT_MARK" || return $?
	    write_env_var SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC "$SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC" || return $?
	    write_env_var SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC "$SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC" || return $?
	    write_env_var AI_TABLE "$AI_TABLE" || return $?
    write_env_var CN_TABLE "$CN_TABLE" || return $?
    write_env_var AI_XFRM_ID "$AI_XFRM_ID" || return $?
    write_env_var CN_XFRM_ID "$CN_XFRM_ID" || return $?
}

write_config_cmd() {
  need_root || return $?
  local tmp rc=0
  mkdir -p "$(dirname "$CONFIG")" || return $?
  tmp=$(mktemp "$(dirname "$CONFIG")/.config.env.XXXXXX") || return $?
  write_config_values >"$tmp" || rc=$?
  if ((rc == 0)); then chmod 0600 "$tmp" || rc=$?; fi
  if ((rc == 0)); then mv -f "$tmp" "$CONFIG" || rc=$?; fi
  rm -f -- "$tmp"
  return "$rc"
}

usage() {
  cat <<'EOF'
Usage: dnscomplex <command> [args]

Commands:
  status [--verbose]
  test
  health [--json]
  watchdog
  fix
  doctor
  update-geosite
  apply-domain-rules-json PATH
  add-domain ai|cn DOMAIN_OR_GEOSITE
  remove-domain ai|cn DOMAIN_OR_GEOSITE
  set-socks LISTEN PORT
  set-ipsec ai|cn USER PASSWORD
  set-web-password PASSWORD
  set-local-host HOST.local IPv4
  test-local-name HOST.local
  set-egress ai|cn ipsec|xray
  apply-egress-json PATH
  set-xray-uri ai|cn URI
  set-xray-json ai|cn JSON_FILE
  test-xray [ai|cn]
  xray-status
  egress-ready xray|clear-xray
  render-xray
  set-update-time HH:MM
  refresh-nftsets
  refresh-cn-overrides [DOMAIN ...]
  trace-domain DOMAIN
  probe-egress --profile default|ai|cn --protocol tcp|udp-echo|mtproto --host HOST [--port PORT] [--timeout SECONDS]
  test-dns
  test-ipsec
  mss-calibrate
  routeros-print
  update-software --allow-unverified-release-assets [--channel stable|beta|pinned] [--version VERSION]
  system-update --acknowledge-no-os-rollback
  metrics-sample
  soak [--duration 30m] [--clients 50] [--dns-qps 50] [--profiles ai,cn,default] [--idle-resume] [--output-json PATH]
  wizard
  validate-config [--json] ENV_FILE
  apply-config ENV_FILE
  apply-config-json JSON_FILE
  render-config [--redacted]
  support-bundle [--output PATH] [--include-logs minimal|standard|full]
  backup [OUTPUT_TAR_GZ]
  restore INPUT_TAR_GZ
  network-ready
  ipsec-ready
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
  printf 'deploy_mode=%s default_ipv6_mode=%s default_dns_strategy=%s adguard_cache=%s ha_mode=%s primary=%s secondary=%s ai_egress=%s cn_egress=%s ai_quic=%s cn_quic=%s local_ipv6=%s update_channel=%s pinned_version=%s github_policy=%s\n' \
    "$DEPLOY_MODE" "$DEFAULT_IPV6_MODE" "$DEFAULT_DNS_STRATEGY" "$ADGUARD_DNS_CACHE_MODE" "$HA_MODE" "${HA_PRIMARY_IP:-}" "${HA_SECONDARY_IP:-}" "$AI_EGRESS_MODE" "$CN_EGRESS_MODE" "$AI_QUIC_POLICY" "$CN_QUIC_POLICY" "$LOCAL_DOMAIN_IPV6_POLICY" "$DNSCOMPLEX_UPDATE_CHANNEL" "${DNSCOMPLEX_PINNED_VERSION:-}" "$GITHUB_RELEASE_POLICY"
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
    dnscomplex-network-ready.service \
    dnscomplex-ipsec-ifaces.service \
    dnscomplex-ipsec-ready.service \
    dnscomplex-routing.service \
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
  fix_smartdns_wrapper || return $?
  ensure_smartdns_enabled || return $?
  systemctl restart smartdns sing-box AdGuardHome || return $?
  if ! wait_dns_ready; then
    warn "DNS stack restarted but did not answer readiness probe within 10 seconds"
    return 1
  fi
}

prepare_smartdns_preflight_config() {
  local source_config=$1 safe_config=$2 private_cache=$3
  [[ -f "$source_config" && ! -L "$source_config" ]] || return 1
  awk '
    /^[[:space:]]*#/ { print; next }
    {
      trimmed = $0
      sub(/^[[:space:]]*/, "", trimmed)
      split(trimmed, fields, /[[:space:]]+/)
      directive = tolower(fields[1])
      if (directive == "conf-file" || directive == "include" || directive ~ /^include[-_]/ ||
          directive ~ /^(cache-persist|cache-file|log-file|audit-file)=/) {
        unsafe_config = 1
        next
      }
      if (directive == "cache-persist" || directive == "cache-file" ||
          directive == "log-file" || directive == "audit-file") next
      print
    }
    END { if (unsafe_config) exit 42 }
  ' "$source_config" >"$safe_config" || return 1
  cat >>"$safe_config" <<EOF
cache-persist no
cache-file $private_cache
log-file $private_cache.log
audit-file $private_cache.audit
EOF
  chmod 0600 "$safe_config"
}

validate_smartdns_config_cmd() {
  local config_file work_dir safe_config output rc
  config_file=${1:-$(fs_path /etc/smartdns/smartdns.conf)}
  work_dir=$(mktemp -d /tmp/dnscomplex-smartdns-preflight.XXXXXX) || die "cannot create private SmartDNS preflight directory"
  chmod 0700 "$work_dir" || { rm -rf -- "$work_dir"; die "cannot protect SmartDNS preflight directory"; }
  safe_config="$work_dir/smartdns.conf"
  output="$work_dir/preflight.log"
  if ! prepare_smartdns_preflight_config "$config_file" "$safe_config" "$work_dir/smartdns.cache"; then
    rm -rf -- "$work_dir"
    die "SmartDNS preflight config is unreadable or has an unsupported include/side-effect directive"
  fi
  set +e
  timeout 2 unshare --net -- smartdns -f -c "$safe_config" -p - >"$output" 2>&1
  rc=$?
  set -e
  if [[ "$rc" != "124" ]]; then
    cat "$output" >&2
    rm -rf -- "$work_dir"
    die "SmartDNS configuration preflight failed"
  fi
  rm -rf -- "$work_dir"
}

remove_macbook_air_local_override() {
  [[ -f /etc/dnscomplex/local-hosts ]] || return 0
  local tmp
  tmp=$(mktemp)
  awk 'tolower($0) !~ /macbook-?air[.]local/' /etc/dnscomplex/local-hosts >"$tmp"
  install -m 0644 "$tmp" /etc/dnscomplex/local-hosts
  rm -f "$tmp"
}

download_geosite_source() {
  mkdir -p "$GEO_DIR"
  local tmp
  tmp=$(mktemp -d)
  curl_bounded -fsSL -o "$tmp/dlc.zip" https://github.com/v2fly/domain-list-community/archive/refs/heads/master.zip
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
    if ! curl_bounded -fsSL -o "$tmp" "$url"; then
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

  # Typed raw sources use the same exact/suffix semantics as DLC file entries.
  case "$source" in
    full:*) printf '%s\n' "${source#full:}" >>"$out_exact"; return 0 ;;
    domain:*) printf '%s\n' "${source#domain:}" >>"$out_suffix"; return 0 ;;
  esac

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
  local ai_domains cn_domains ai_seed
  ai_domains=$(fs_path /etc/dnscomplex/ai.domains)
  cn_domains=$(fs_path /etc/dnscomplex/cn-video.domains)
  ai_seed=$(fs_path /etc/dnscomplex/ai.seed-domains)
  mkdir -p "$(dirname "$ai_domains")"
  {
    [[ -f "$ai_seed" ]] && cat "$ai_seed"
    [[ -f "$GEO_DIR/ai-support.domains" ]] && cat "$GEO_DIR/ai-support.domains"
    split_words "${AI_NFTSET_REFRESH_DOMAINS:-}"
  } | sort -u >"$ai_domains"
  install -m 0644 "$GEO_DIR/cn-video.domains" "$cn_domains"
}

sync_geosite_sources_from_config() {
  mkdir -p "$GEO_DIR"
  split_words "${AI_GEOSITE_SOURCES:-}" >"$GEO_DIR/ai.sources"
  {
    split_words "${AI_SUPPORT_DOMAINS:-}"
    apple_ai_support_sources
  } | sort -u >"$GEO_DIR/ai-support.sources"
  split_words "${CN_VIDEO_SOURCES:-}" >"$GEO_DIR/cn-video.sources"
}

sync_domain_seed_files_from_config() {
  local ai_seed cn_seed
  ai_seed=$(fs_path /etc/dnscomplex/ai.seed-domains)
  cn_seed=$(fs_path /etc/dnscomplex/cn-video.seed-domains)
  mkdir -p "$(dirname "$ai_seed")"
  split_words "${AI_SAMPLE_DOMAINS:-}" >"$ai_seed"
  split_words "${CN_SAMPLE_DOMAINS:-}" >"$cn_seed"
}

geosite_artifact_manifest() {
  local stage_geo=$1 live_geo=$2 source safe path
  cat <<'EOF'
etc/dnscomplex/config.env
etc/dnscomplex/ai.seed-domains
etc/dnscomplex/cn-video.seed-domains
etc/dnscomplex/ai.domains
etc/dnscomplex/cn-video.domains
etc/AdGuardHome/AdGuardHome.yaml
var/lib/dnscomplex/geosite/ai.sources
var/lib/dnscomplex/geosite/ai-support.sources
var/lib/dnscomplex/geosite/cn-video.sources
var/lib/dnscomplex/geosite/ai-support.suffix
var/lib/dnscomplex/geosite/ai-support.exact
var/lib/dnscomplex/geosite/ai-support.keyword
var/lib/dnscomplex/geosite/ai-support.regex
var/lib/dnscomplex/geosite/ai-support.domains
var/lib/dnscomplex/geosite/ai-support.json
var/lib/dnscomplex/geosite/geosite-ai-support.srs
var/lib/dnscomplex/geosite/cn-video.suffix
var/lib/dnscomplex/geosite/cn-video.exact
var/lib/dnscomplex/geosite/cn-video.keyword
var/lib/dnscomplex/geosite/cn-video.regex
var/lib/dnscomplex/geosite/cn-video.domains
var/lib/dnscomplex/geosite/cn-video.json
var/lib/dnscomplex/geosite/geosite-cn-video.srs
var/lib/dnscomplex/geosite/domain-list-community
EOF
  for source in ${AI_GEOSITE_SOURCES:-}; do
    safe=$(rule_set_safe_name "$source")
    printf 'var/lib/dnscomplex/geosite/geosite-ai-%s.srs\n' "$safe"
  done
  for path in "$stage_geo"/geosite-ai-*.srs "$live_geo"/geosite-ai-*.srs; do
    [[ -e "$path" || -L "$path" ]] || continue
    printf 'var/lib/dnscomplex/geosite/%s\n' "${path##*/}"
  done
}

geosite_artifact_fingerprint() {
  python3 - "$1" <<'PY'
import hashlib
import json
import os
import stat
import sys

root = sys.argv[1]
if not os.path.lexists(root):
    print("absent")
    raise SystemExit(0)
rows = []
def add(path, rel):
    info = os.lstat(path)
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        kind, value = "link", os.readlink(path)
    elif stat.S_ISREG(info.st_mode):
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        kind, value = "file", digest.hexdigest()
    elif stat.S_ISDIR(info.st_mode):
        kind, value = "dir", ""
    else:
        kind, value = "other", ""
    rows.append((rel, kind, value, mode, info.st_uid, info.st_gid))
    if kind == "dir":
        for name in sorted(os.listdir(path)):
            add(os.path.join(path, name), os.path.join(rel, name))
add(root, ".")
print(json.dumps(rows, separators=(",", ":")))
PY
}

geosite_candidate_config() {
  local live_config=$1 stage_root=$2 output=$3 stage_geo="$2/var/lib/dnscomplex/geosite"
  [[ -s "$live_config" ]] || die "sing-box config missing during geosite preflight"
  mkdir -p "$(dirname "$output")"
  jq --arg old "/var/lib/dnscomplex/geosite/" --arg new "$stage_geo/" '
    (.route.rule_set[]? | select(.type == "local") | .path) |=
      (if startswith($old) then $new + ltrimstr($old) else . end)
  ' "$live_config" >"$output"
}

geosite_publish_artifact() {
  local stage_root=$1 live_root=$2 rel=$3 source="$1/$3" target="$2/$3"
  local parent temp old
  if [[ ! -e "$source" && ! -L "$source" ]]; then
    if [[ -e "$target" || -L "$target" ]]; then
      parent=$(dirname "$target")
      old=$(mktemp -d "$parent/.geosite-remove.XXXXXX") || return 1
      rmdir "$old" || return 1
      mv -- "$target" "$old" || return 1
      rm -rf -- "$old" || return 1
    fi
    return 0
  fi
  parent=$(dirname "$target")
  mkdir -p "$parent" || return 1
  if [[ -d "$source" && ! -L "$source" ]]; then
    temp=$(mktemp -d "$parent/.geosite-publish.XXXXXX") || return 1
    cp -a -- "$source" "$temp/item" || { rm -rf -- "$temp"; return 1; }
    if [[ -e "$target" || -L "$target" ]]; then
      old="$parent/.geosite-old.$$"
      [[ ! -e "$old" && ! -L "$old" ]] || { rm -rf -- "$temp"; return 1; }
      mv -- "$target" "$old" || { rm -rf -- "$temp"; return 1; }
      if ! mv -- "$temp/item" "$target"; then
        mv -- "$old" "$target" || true
        rm -rf -- "$temp"
        return 1
      fi
      rm -rf -- "$old"
    else
      mv -- "$temp/item" "$target" || { rm -rf -- "$temp"; return 1; }
    fi
    rmdir "$temp"
  else
    temp=$(mktemp "$parent/.geosite-publish.XXXXXX") || return 1
    cp -a -- "$source" "$temp" || { rm -f -- "$temp"; return 1; }
    mv -f -- "$temp" "$target" || { rm -f -- "$temp"; return 1; }
  fi
}

geosite_restore_snapshot() {
  local snapshot=$1 live_root=$2 manifest=$3 rel target source
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    target="$live_root/$rel"
    source="$snapshot/$rel"
    rm -rf -- "$target" || return 1
    if [[ -e "$source" || -L "$source" ]]; then
      mkdir -p "$(dirname "$target")" || return 1
      cp -a -- "$source" "$target" || return 1
    fi
  done < <(awk '{ row[NR] = $0 } END { for (i = NR; i > 0; i--) print row[i] }' "$manifest")
}

geosite_prune_obsolete_remote_rulesets() {
  local path source safe keep
  for path in "$GEO_DIR"/geosite-ai-*.srs; do
    [[ -e "$path" || -L "$path" ]] || continue
    keep=0
    [[ "${path##*/}" == "geosite-ai-support.srs" ]] && keep=1
    while IFS= read -r source || [[ -n "$source" ]]; do
      source=$(printf '%s\n' "$source" | trim_line)
      [[ -n "$source" ]] || continue
      safe=$(rule_set_safe_name "$source")
      [[ "${path##*/}" == "geosite-ai-$safe.srs" ]] && keep=1
    done <"$GEO_DIR/ai.sources"
    (( keep == 1 )) || rm -f -- "$path"
  done
}

geosite_update_transaction() (
  set -e
  local prepare_only=0 live_fs_root=${FS_ROOT:-} live_config=${CONFIG:-}
  local live_base=${BASE:-} live_geo=${GEO_DIR:-} live_dlc=${DLC_DIR:-}
  local live_root stage_dir stage_root candidate_config manifest_file snapshot
  local rel changed=0 rc=0 copy_rel
  [[ "${1:-}" == "--prepare-only" ]] && prepare_only=1
  live_root=${live_fs_root:-/}
  live_root=${live_root%/}
  [[ -n "$live_root" ]] || live_root=/
  mkdir -p "$live_base"
  stage_dir=$(mktemp -d "$live_base/.geosite-transaction.XXXXXX")
  stage_root="$stage_dir/root"
  mkdir -p "$stage_root"
  trap 'rm -rf -- "$stage_dir"' EXIT

  for copy_rel in etc/dnscomplex etc/AdGuardHome etc/sing-box etc/smartdns var/lib/dnscomplex/geosite; do
    if [[ -e "$live_root/$copy_rel" || -L "$live_root/$copy_rel" ]]; then
      mkdir -p "$(dirname "$stage_root/$copy_rel")"
      cp -a -- "$live_root/$copy_rel" "$stage_root/$copy_rel"
    fi
  done
  mkdir -p "$stage_root/etc/dnscomplex" "$stage_root/etc/AdGuardHome" \
    "$stage_root/etc/sing-box" "$stage_root/etc/smartdns" \
    "$stage_root/var/lib/dnscomplex/geosite"

  FS_ROOT=$stage_root
  CONFIG="$stage_root/etc/dnscomplex/config.env"
  BASE="$stage_root/var/lib/dnscomplex"
  GEO_DIR="$BASE/geosite"
  DLC_DIR="$GEO_DIR/domain-list-community"

  sync_geosite_sources_from_config
  sync_domain_seed_files_from_config
  write_config_cmd
  download_sing_geosite_ai_rule_sets
  download_geosite_source
  compile_profile ai-support "$GEO_DIR/ai-support.sources" "$GEO_DIR/ai.custom"
  compile_profile cn-video "$GEO_DIR/cn-video.sources" "$GEO_DIR/cn-video.custom"
  geosite_prune_obsolete_remote_rulesets
  install_domain_files
  render_adguard_runtime

  candidate_config="$stage_root/etc/sing-box/geosite-preflight.json"
  geosite_candidate_config "$live_root/etc/sing-box/config.json" "$stage_root" "$candidate_config"
  sing-box check -c "$candidate_config"
  /opt/AdGuardHome/AdGuardHome --check-config -c "$stage_root/etc/AdGuardHome/AdGuardHome.yaml"
  validate_smartdns_config_cmd

  manifest_file="$stage_dir/artifacts.txt"
  geosite_artifact_manifest "$GEO_DIR" "$live_geo" | awk 'NF && !seen[$0]++' | sort >"$manifest_file"
  snapshot="$stage_dir/snapshot"
  mkdir -p "$snapshot"
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    if [[ -e "$live_root/$rel" || -L "$live_root/$rel" ]]; then
      mkdir -p "$(dirname "$snapshot/$rel")"
      cp -a -- "$live_root/$rel" "$snapshot/$rel"
    fi
    if [[ "$(geosite_artifact_fingerprint "$stage_root/$rel")" != \
          "$(geosite_artifact_fingerprint "$live_root/$rel")" ]]; then
      changed=1
    fi
  done <"$manifest_file"

  if (( changed == 0 )); then
    if (( prepare_only == 0 )); then
      FS_ROOT=$live_fs_root
      CONFIG=$live_config
      BASE=$live_base
      GEO_DIR=$live_geo
      DLC_DIR=$live_dlc
      refresh_nftsets_cmd || warn "nftset refresh failed after geosite update"
    fi
    return 0
  fi

  FS_ROOT=$live_fs_root
  CONFIG=$live_config
  BASE=$live_base
  GEO_DIR=$live_geo
  DLC_DIR=$live_dlc
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    if ! geosite_publish_artifact "$stage_root" "$live_root" "$rel"; then
      rc=1
      break
    fi
  done <"$manifest_file"
  if (( rc == 0 && prepare_only == 0 )); then
    restart_dns_stack || rc=$?
  fi
  if (( rc != 0 )); then
    geosite_restore_snapshot "$snapshot" "$live_root" "$manifest_file" || {
      warn "geosite rollback failed; previous artifacts may need manual recovery"
      return 1
    }
    if (( prepare_only == 0 )); then
      restart_dns_stack || {
        warn "geosite rollback restored files but previous DNS stack did not recover"
        return 1
      }
    fi
    return "$rc"
  fi
  if (( prepare_only == 0 )); then
    refresh_nftsets_cmd || warn "nftset refresh failed after geosite update"
  fi
)

update_geosite_candidate_cmd() {
  load_config || return $?
  geosite_update_transaction "${1:-}"
}

update_geosite_cmd() {
  need_root || return $?
  local mode="${1:-}"
  [[ $# -le 1 && ( -z "$mode" || "$mode" == --prepare-only ) ]] || die "usage: update-geosite [--prepare-only]"
  if [[ "$mode" == --prepare-only ]]; then
    state_transaction_manager_cmd update_geosite_candidate_cmd "$mode"
  else
    state_transaction_cmd update-geosite state_transaction_manager_cmd update_geosite_candidate_cmd "$mode"
  fi
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

# Every row is captured and validated before creating a transaction or writing sources.
apply_domain_rules_json_cmd() (
  need_root || return $?
  [[ $# -eq 1 ]] || die "usage: dnscomplex apply-domain-rules-json PATH"
  local stage profile action value
  local -a values=()
  stage=$(mktemp -d) || return $?
  chmod 0700 "$stage" || return $?
  # shellcheck disable=SC2064 # Capture private path before locals unwind.
  trap "rm -rf -- $(printf '%q' "$stage")" EXIT
  python3 - "$1" "$stage/values" <<'DOMAIN_BATCH' || return $?
import json, os, re, stat, sys
try:
    fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>1048576: raise ValueError()
        value=json.loads(stream.read(1048577))
    if not isinstance(value,dict) or set(value)!={'profile','action','values'}: raise ValueError()
    if value['profile'] not in ('ai','cn') or value['action'] not in ('add','remove'): raise ValueError()
    values=value['values']
    if not isinstance(values,list) or not 1<=len(values)<=4096: raise ValueError()
    normalized=[]
    for item in values:
        if not isinstance(item,str) or item!=item.strip() or not item: raise ValueError()
        item=item.lower()
        domain=item.split(':',1)[1] if item.startswith(('full:','domain:')) else item
        if '.' in item:
            if len(domain)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in domain.split('.')): raise ValueError()
        elif not re.fullmatch(r'[a-z0-9][a-z0-9_@!:+-]{0,127}',item): raise ValueError()
        if item not in normalized: normalized.append(item)
    with open(sys.argv[2],'xb',opener=lambda p,f:os.open(p,f,0o600)) as out:
        for item in [value['profile'],value['action'],*normalized]: out.write(item.encode()+b'\0')
except (ValueError,TypeError,OSError): raise SystemExit('invalid domain batch')
DOMAIN_BATCH
  while IFS= read -r -d '' value; do values+=("$value"); done <"$stage/values"
  profile=${values[0]}; action=${values[1]}
  state_transaction_cmd "domain batch $profile" apply_domain_rules_candidate_cmd "$profile" "$action" "${values[@]:2}"
)

apply_domain_rules_candidate_cmd() {
  local profile=$1 action=$2 file tmp value sources support
  shift 2
  file=$(profile_file "$profile") || return $?
  mkdir -p "$(dirname "$file")" || return $?
  tmp=$(mktemp "$(dirname "$file")/.custom.XXXXXX") || return $?
  if [[ -f "$file" ]]; then cat "$file" >"$tmp" || { rm -f "$tmp"; return 1; }; fi
  if [[ "$profile" == ai ]]; then sources=$AI_GEOSITE_SOURCES; else sources=$CN_VIDEO_SOURCES; fi
  support=$AI_SUPPORT_DOMAINS
  for value in "$@"; do
    if [[ "$action" == add ]]; then
      if [[ "$value" == *.* ]]; then
        if ! grep -Fxq -- "$value" "$tmp"; then printf '%s\n' "$value" >>"$tmp" || return $?; fi
      else
        sources=$(add_list_item "$sources" "$value" | xargs) || return $?
      fi
    else
      # awk succeeds for an empty result; grep's no-match status is not an error.
      awk -v value="$value" '$0 != value' "$tmp" >"$tmp.next" || return $?
      mv -f "$tmp.next" "$tmp" || return $?
      sources=$(remove_list_item "$sources" "$value" | xargs) || return $?
      [[ "$profile" != ai ]] || support=$(remove_list_item "$support" "$value" | xargs) || return $?
    fi
  done
  chmod 0644 "$tmp" || return $?
  mv -f "$tmp" "$file" || return $?
  if [[ "$profile" == ai ]]; then AI_GEOSITE_SOURCES=$sources; AI_SUPPORT_DOMAINS=$support; else CN_VIDEO_SOURCES=$sources; fi
  write_config_cmd || return $?
  if [[ "$profile" == ai ]]; then unset AI_GEOSITE_SOURCES AI_SUPPORT_DOMAINS; else unset CN_VIDEO_SOURCES; fi
  load_config || return $?
  if [[ "$profile" == ai ]]; then
    [[ "$AI_GEOSITE_SOURCES" == "$sources" && "$AI_SUPPORT_DOMAINS" == "$support" ]] || return 1
  else
    [[ "$CN_VIDEO_SOURCES" == "$sources" ]] || return 1
  fi
  # Fresh shell retains geosite's fail-fast staging even in a synchronous callback.
  state_transaction_manager_cmd update_geosite_candidate_cmd
}

domain_rule_alias_cmd() (
  local action=$1 profile=$2 value=$3 stage
  stage=$(mktemp) || return $?
  # shellcheck disable=SC2064 # Capture private path before locals unwind.
  trap "rm -f -- $(printf '%q' "$stage")" EXIT
  (umask 077; printf '%s\0' "$profile" "$action" "$value") | python3 -c 'import json,sys; p,a,v=sys.stdin.buffer.read().decode().split("\0")[:3]; json.dump(dict(profile=p,action=a,values=[v]),sys.stdout)' >"$stage" || return $?
  apply_domain_rules_json_cmd "$stage"
)

add_domain_cmd() {
  [[ $# -eq 2 ]] || die "usage: dnscomplex add-domain ai|cn DOMAIN_OR_GEOSITE"
  domain_rule_alias_cmd add "$@"
}

remove_domain_cmd() {
  [[ $# -eq 2 ]] || die "usage: dnscomplex remove-domain ai|cn DOMAIN_OR_GEOSITE"
  domain_rule_alias_cmd remove "$@"
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

rewrite_smartdns_static_overrides() (
  local target=${1:-} source=${2:-} tmp filtered override domain line
  [[ -n "$target" ]] || target=$(fs_path /etc/smartdns/smartdns.conf)
  [[ -n "$source" ]] || source=$target
  tmp=$(mktemp) || return $?
  filtered=$(mktemp) || return $?
  # shellcheck disable=SC2064 # Capture private path before locals unwind.
  trap "rm -f -- $(printf '%q' "$tmp") $(printf '%q' "$filtered")" EXIT
  cp -- "$source" "$tmp" || return $?
  while IFS= read -r override; do
    [[ -n "$override" ]] || continue
    domain=${override%%=*}
    awk -v domain="$domain" 'index($0,"address /" domain "/")!=1 && index($0,"address /-." domain "/")!=1' "$tmp" >"$filtered" || return $?
    cat "$filtered" >"$tmp" || return $?
  done < <(tr ' ' '\n' <<<"$CN_STATIC_A_OVERRIDES")
  while IFS= read -r override; do smartdns_static_address_line "$override"; done < <(tr ' ' '\n' <<<"$CN_STATIC_A_OVERRIDES") >>"$tmp" || return $?
  atomic_publish_file_cmd "$tmp" "$target" 0644
)

refresh_cn_overrides_apply_cmd() (
  # This scoped rollback never restores nftables/IPsec/another profile.
  local target stage rc=0 rollback_rc=0 expected=$CN_STATIC_A_OVERRIDES
  target=$(fs_path /etc/smartdns/smartdns.conf) || return $?
  stage=$(mktemp -d) || return $?
  # shellcheck disable=SC2064 # Capture private path before locals unwind.
  trap "rm -rf -- $(printf '%q' "$stage")" EXIT
  cp -- "$CONFIG" "$stage/config.before" || return $?
  cp -- "$target" "$stage/smartdns.before" || return $?
  rewrite_smartdns_static_overrides "$stage/smartdns.candidate" "$target" || return $?
  validate_smartdns_config_cmd "$stage/smartdns.candidate" || return $?
  write_config_cmd || rc=$?
  if ((rc == 0)); then atomic_publish_file_cmd "$stage/smartdns.candidate" "$target" 0644 || rc=$?; fi
  if ((rc == 0)); then systemctl restart smartdns || rc=$?; fi
  if ((rc == 0)); then systemctl is-active --quiet smartdns || rc=$?; fi
  if ((rc == 0)); then cmp -s "$stage/smartdns.candidate" "$target" || rc=$?; fi
  if ((rc == 0)); then
    unset CN_STATIC_A_OVERRIDES
    load_config || rc=$?
    [[ "$CN_STATIC_A_OVERRIDES" == "$expected" ]] || rc=1
  fi
  if ((rc != 0)); then
    atomic_publish_file_cmd "$stage/config.before" "$CONFIG" 0600 || rollback_rc=1
    atomic_publish_file_cmd "$stage/smartdns.before" "$target" 0644 || rollback_rc=1
    systemctl restart smartdns || rollback_rc=1
    systemctl is-active --quiet smartdns || rollback_rc=1
    if ((rollback_rc != 0)); then
      warn "CN scoped rollback needs operator recovery"
      return 70
    fi
    return "$rc"
  fi
)

valid_refresh_timeout() {
  [[ "$DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT" =~ ^[0-9]+(ms|s|m|h|d)?$ ]]
}

public_ipv4() {
  local ip=$1 a b c d
  IFS=. read -r a b c d <<<"$ip"
  [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] || return 1
  ((a >= 1 && a <= 223 && b >= 0 && b <= 255 && c >= 0 && c <= 255 && d >= 0 && d <= 255)) || return 1
  ((a == 10 || a == 127)) && return 1
  ((a == 100 && b >= 64 && b <= 127)) && return 1
  ((a == 169 && b == 254)) && return 1
  ((a == 172 && b >= 16 && b <= 31)) && return 1
  ((a == 192 && b == 0 && c == 0)) && return 1
  ((a == 192 && b == 0 && c == 2)) && return 1
  ((a == 192 && b == 168)) && return 1
  ((a == 192 && b == 88 && c == 99)) && return 1
  ((a == 198 && (b == 18 || b == 19))) && return 1
  ((a == 198 && b == 51 && c == 100)) && return 1
  ((a == 203 && b == 0 && c == 113)) && return 1
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

refresh_nftset_group() (
  local profile=$1
  local port=$2
  local set_name=$3
  local domain output ip domains=0 answered=0 added=0 no_answer=0
  local candidates="" batch="" freshness="" all_present outcome=1

  cleanup_nftset_refresh() {
    [[ -z "$candidates" ]] || rm -f -- "$candidates"
    [[ -z "$batch" ]] || rm -f -- "$batch"
    [[ -z "$freshness" ]] || rm -f -- "$freshness"
  }
  trap cleanup_nftset_refresh EXIT HUP INT TERM

  if ! mkdir -p "$RUN_DIR" "$BASE"; then
    warn "$profile nftset refresh could not prepare state directories"
    return 1
  fi
  if ! candidates=$(mktemp "$RUN_DIR/.nftset-${profile}.candidates.XXXXXX"); then
    warn "$profile nftset refresh could not allocate candidate state"
    return 1
  fi
  if ! batch=$(mktemp "$RUN_DIR/.nftset-${profile}.batch.XXXXXX"); then
    warn "$profile nftset refresh could not allocate transaction state"
    return 1
  fi

  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    domains=$((domains + 1))
    output=$(dig +time=2 +tries=1 +short "@127.0.0.1" -p "$port" A "$domain" 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' || true)
    if [[ -z "$output" ]]; then
      no_answer=$((no_answer + 1))
      continue
    fi
    answered=$((answered + 1))
    while IFS= read -r ip; do
      [[ -n "$ip" ]] || continue
      public_ipv4 "$ip" || continue
      printf '%s\n' "$ip" >>"$candidates" || return 1
    done <<<"$output"
  done < <(nftset_refresh_domain_stream "$profile")

  if ! sort -u -o "$candidates" "$candidates"; then
    warn "$profile nftset candidates could not be sorted"
    return 1
  fi
  if [[ "$answered" == "0" || ! -s "$candidates" ]]; then
    warn "$profile nftset refresh had zero usable answers; keeping last-known-good elements"
    return 1
  fi

  while IFS= read -r ip; do
    if ! nft get element inet dnscomplex "$set_name" "{ $ip }" >/dev/null 2>&1; then
      printf 'add element inet dnscomplex %s { %s timeout %s }\n' \
        "$set_name" "$ip" "$DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT" >>"$batch" || return 1
      added=$((added + 1))
    fi
  done <"$candidates"

  if [[ -s "$batch" ]]; then
    outcome=2 # Once apply is attempted, failure cannot claim unchanged runtime.
    if ! nft -f "$batch"; then
      all_present=1
      while IFS= read -r ip; do
        if ! nft get element inet dnscomplex "$set_name" "{ $ip }" >/dev/null 2>&1; then
          all_present=0
          break
        fi
      done <"$candidates"
      if [[ "$all_present" == "0" ]]; then
        warn "$profile nftset apply failed; runtime outcome is unverified"
        return 2
      fi
    fi
  fi

  if ! freshness=$(mktemp "$BASE/.nftset-${profile}.freshness.XXXXXX") ||
     ! date +%s >"$freshness" ||
     ! mv -f -- "$freshness" "$BASE/nftset-${profile}.last_refresh"; then
    warn "$profile nftset freshness state could not be updated"
    return "$outcome"
  fi
  log "refreshed $profile nftset: domains=$domains answered=$answered new_ips=$added no_answer=$no_answer"
)

refresh_nftsets_cmd() {
  need_root
  command -v dig >/dev/null 2>&1 || die "install dnsutils for dig"
  command -v nft >/dev/null 2>&1 || die "install nftables"
  valid_refresh_timeout || die "DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT must look like 30m, 2h, or 3600s"
  nft list table inet dnscomplex >/dev/null 2>&1 || die "nftables dnscomplex table is missing"
  local failed=0 profile port set_name result
  for profile in ai cn; do
    if [[ "$profile" == ai ]]; then port=$SMARTDNS_AI_PORT; set_name=ai4; else port=$SMARTDNS_CN_PORT; set_name=cn4; fi
    if refresh_nftset_group "$profile" "$port" "$set_name"; then
      printf '%s: success\n' "$profile"
    else
      result=$?; failed=1
      case "$result" in
        1) printf '%s: kept_previous\n' "$profile" ;;
        *) printf '%s: failed (runtime applied or outcome unverified; inspect freshness)\n' "$profile" ;;
      esac
    fi
  done
  return "$failed"
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
  local override domain ip selected current failed=0 changed=0
  local -a outcomes=() fallbacks=()
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
    current=$(cn_override_current_ip "$domain" || true)
    while IFS= read -r ip; do
      [[ -n "$ip" ]] || continue
      if probe_cn_override_ip "$domain" "$ip"; then
        selected=$ip
        break
      fi
    done < <(cn_override_candidate_ips "$domain" | awk '!seen[$0]++')

    if [[ -n "$selected" ]]; then
      if [[ "$selected" != "$current" ]]; then
        replace_cn_static_override "$domain" "$selected"
        changed=1
        outcomes+=("$domain: success")
        if [[ -n "$current" ]]; then fallbacks+=("$domain: kept_previous"); else fallbacks+=("$domain: failed"); fi
      else
        outcomes+=("$domain: success"); fallbacks+=("$domain: success")
      fi
    elif [[ -n "$current" ]]; then
      outcomes+=("$domain: kept_previous"); fallbacks+=("$domain: kept_previous")
    else
      outcomes+=("$domain: failed"); fallbacks+=("$domain: failed"); failed=1
    fi
  done

  if [[ "$changed" == "1" ]]; then
    if refresh_cn_overrides_apply_cmd; then :; else
      local apply_rc=$?
      if ((apply_rc == 70)); then
        for domain in "${domains[@]}"; do printf '%s: failed\n' "$domain"; done
        printf 'cn: failed; operator recovery required\n'
      else
        printf '%s\n' "${fallbacks[@]}"
        printf 'cn: failed; scoped config/runtime rollback attempted\n'
      fi
      return 1
    fi
  fi
  printf '%s\n' "${outcomes[@]}"
  return "$failed"
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
  if ! sas=$(timeout --signal=TERM --kill-after=1s 8s \
    swanctl --list-sas 2>/dev/null); then
    warn "StrongSwan SA state could not be queried"
    return 1
  fi
  if [[ "${AI_EGRESS_MODE:-ipsec}" == "ipsec" ]]; then
    required=1
    ipsec_profile_runtime_ready ai "$sas" || failed=1
  fi
  if [[ "${CN_EGRESS_MODE:-ipsec}" == "ipsec" ]]; then
    required=1
    ipsec_profile_runtime_ready cn "$sas" || failed=1
  fi
  if [[ "$required" == "0" ]]; then
    log "AI/CN egress are not using IPsec; skipping IPsec test"
    return 0
  fi
  [[ "$failed" == "0" ]]
}

mss_calibrate_cmd() (
  need_root || return $?
  local mtu_ai mtu_cn recommended target candidate
  mtu_ai=$(ip link show ipsec-ai 2>/dev/null | awk '/mtu/ {for (i=1;i<=NF;i++) if ($i=="mtu") print $(i+1)}' | head -n1)
  mtu_cn=$(ip link show ipsec-cn 2>/dev/null | awk '/mtu/ {for (i=1;i<=NF;i++) if ($i=="mtu") print $(i+1)}' | head -n1)
  mtu_ai=${mtu_ai:-1400}; mtu_cn=${mtu_cn:-1400}
  [[ "$mtu_ai" =~ ^[0-9]{3,5}$ && "$mtu_cn" =~ ^[0-9]{3,5}$ ]] || return 2
  recommended=$(mss_recommended_value "$((10#$mtu_ai - 60))" "$((10#$mtu_cn - 60))") || return $?
  target=$(fs_path /etc/nftables.d/dnscomplex.nft) || return $?
  candidate=$(mktemp) || return $?
  # shellcheck disable=SC2064 # Capture private path before locals unwind.
  trap "rm -f -- $(printf '%q' "$candidate")" EXIT
  python3 - "$target" "$candidate" "$recommended" <<'MSS_CANDIDATE' || return $?
from pathlib import Path
import re,sys
source,target,value=sys.argv[1:]
text=Path(source).read_text()
pattern=r'tcp flags syn tcp option maxseg size(?: > [0-9]+ tcp option maxseg size)? set [0-9]+'
# This deployment renders one global forward cap. Missing/duplicate caps are unsafe.
if len(re.findall(pattern,text)) != 1: raise SystemExit('expected exactly one MSS cap')
result,count=re.subn(pattern,f'tcp flags syn tcp option maxseg size > {value} tcp option maxseg size set {value}',text)
if count != 1: raise SystemExit('MSS candidate did not update expected cap')
Path(target).write_text(result)
MSS_CANDIDATE
  nft -c -f "$candidate" || return $?
  state_transaction_cmd mss-calibrate mss_apply_candidate_cmd "$recommended" "$candidate" "$target"
)

mss_apply_candidate_cmd() (
  local expected=$1 candidate=$2 target=$3 stage
  stage=$(mktemp -d) || return $?
  # shellcheck disable=SC2064 # Capture private path before locals unwind.
  trap "rm -rf -- $(printf '%q' "$stage")" EXIT
  # Replace only the rendered global forward cap. Restarting nftables would
  # flush classification/readiness sets and disrupt unrelated healthy profiles.
  nft -a list chain inet dnscomplex forward >"$stage/runtime.before" || return $?
  python3 - "$stage/runtime.before" "$stage/delta.nft" "$expected" <<'MSS_DELTA' || return $?
from pathlib import Path
import re,sys
source,target,value=sys.argv[1:]
pattern=r'^\s*tcp flags syn tcp option maxseg size(?: > [0-9]+ tcp option maxseg size)? set [0-9]+\s+# handle ([0-9]+)\s*$'
handles=re.findall(pattern,Path(source).read_text(),re.M)
if len(handles)!=1: raise SystemExit('expected exactly one owned runtime MSS rule with handle')
Path(target).write_text(f'replace rule inet dnscomplex forward handle {handles[0]} tcp flags syn tcp option maxseg size > {value} tcp option maxseg size set {value}\n')
MSS_DELTA
  nft -c -f "$stage/delta.nft" || return $?
  atomic_publish_file_cmd "$candidate" "$target" 0644 || return $?
  IPSEC_TCP_MSS=$expected
  write_config_cmd || return $?
  nft -f "$stage/delta.nft" || return $?
  unset IPSEC_TCP_MSS
  load_config || return $?
  [[ "$IPSEC_TCP_MSS" == "$expected" ]] || return 1
  cmp -s "$candidate" "$target" || return 1
  nft -a list chain inet dnscomplex forward >"$stage/runtime.after" || return $?
  python3 - "$stage/runtime.after" "$stage/delta.nft" "$expected" <<'MSS_READBACK' || return $?
from pathlib import Path
import re,sys
runtime,delta,value=sys.argv[1:]
handle=re.search(r' handle ([0-9]+) ',Path(delta).read_text()).group(1)
pattern=r'^\s*tcp flags syn tcp option maxseg size(?: > ([0-9]+) tcp option maxseg size)? set ([0-9]+)\s+# handle ([0-9]+)\s*$'
caps=re.findall(pattern,Path(runtime).read_text(),re.M)
if caps != [(value,value,handle)]: raise SystemExit('runtime MSS readback did not match candidate handle/value')
MSS_READBACK
  log "applied IPSEC_TCP_MSS=$expected"
)

mss_recommended_value() {
  local ai=$1 cn=$2 value
  value=$ai
  ((cn < value)) && value=$cn
  ((value > 1360)) && value=1360
  ((value < 536)) && value=536
  printf '%s\n' "$value"
}

profile_uses_ipsec() {
  case "$1" in
    ai) [[ "${AI_EGRESS_MODE:-ipsec}" == "ipsec" ]] ;;
    cn) [[ "${CN_EGRESS_MODE:-ipsec}" == "ipsec" ]] ;;
    *) return 1 ;;
  esac
}

profile_egress_mode() {
  case "$1" in
    ai) printf '%s\n' "${AI_EGRESS_MODE:-ipsec}" ;;
    cn) printf '%s\n' "${CN_EGRESS_MODE:-ipsec}" ;;
    *) return 1 ;;
  esac
}

profile_egress_gate_set() {
  case "$1" in
    ai) printf 'ai_ready4 ai_ready6\n' ;;
    cn) printf 'cn_ready4 cn_ready6\n' ;;
    *) return 1 ;;
  esac
}

profile_egress_gate_clear() {
  local profile=$1 set4 set6
  IFS=' ' read -r set4 set6 < <(profile_egress_gate_set "$profile") || return 1
  nft -f - <<EOF
flush set inet dnscomplex $set4
flush set inet dnscomplex $set6
EOF
}

profile_egress_gate_verify_closed() {
  local profile=$1 set4 set6
  IFS=' ' read -r set4 set6 < <(profile_egress_gate_set "$profile") || return 1
  nft -j list table inet dnscomplex | jq -e --arg set4 "$set4" --arg set6 "$set6" '
    .nftables as $entries |
    all([$set4, $set6][];
      . as $name |
      any($entries[]?;
        (.set? // {}) as $set |
        $set.family == "inet" and $set.table == "dnscomplex" and
        $set.name == $name and (($set.elem // []) | length) == 0))
  ' >/dev/null
}

clear_selected_ipsec_egress_gates() {
  local profile failed=0
  for profile in ai cn; do
    profile_uses_ipsec "$profile" || continue
    if ! profile_egress_gate_clear "$profile"; then
      warn "$profile egress gate could not be closed while IPsec state was unavailable"
      failed=1
    fi
  done
  return "$failed"
}

profile_egress_gate_open() {
  local profile=$1 set4 set6
  IFS=' ' read -r set4 set6 < <(profile_egress_gate_set "$profile") || return 1
  nft -f - <<EOF
flush set inet dnscomplex $set4
flush set inet dnscomplex $set6
add element inet dnscomplex $set4 { 0.0.0.0/0 }
$(if [[ "$(profile_egress_mode "$profile")" == "xray" ]]; then printf 'add element inet dnscomplex %s { ::/0 }\n' "$set6"; fi)
EOF
}

profile_egress_gate_set_is_open() {
  local set_name=$1 set_type=$2 wildcard=$3
  nft -j list set inet dnscomplex "$set_name" 2>/dev/null |
    jq -e --arg name "$set_name" --arg type "$set_type" --arg wildcard "$wildcard" '
      any(.nftables[]?;
        (.set? // {}) as $set |
        $set.family == "inet" and
        $set.table == "dnscomplex" and
        $set.name == $name and
        $set.type == $type and
        any($set.elem[]?;
          (.prefix? // {}) as $prefix |
          $prefix.addr == $wildcard and $prefix.len == 0))
    ' >/dev/null 2>&1
}

profile_egress_gate_is_open() {
  local profile=$1 set4 set6
  IFS=' ' read -r set4 set6 < <(profile_egress_gate_set "$profile") || return 1
  profile_egress_gate_set_is_open "$set4" ipv4_addr 0.0.0.0 || return 1
  if [[ "$(profile_egress_mode "$profile")" == "xray" ]]; then
    profile_egress_gate_set_is_open "$set6" ipv6_addr :: || return 1
  fi
}

egress_ready_cmd() {
  need_root
  local action=${1:-} profile mode failed=0
  case "$action" in
    xray)
      for profile in ai cn; do
        mode=$(profile_egress_mode "$profile")
        if [[ "$mode" == "xray" ]]; then
          if systemctl is-active --quiet xray-dnscomplex; then
            profile_egress_gate_open "$profile" || failed=1
          else
            profile_egress_gate_clear "$profile"
            failed=1
          fi
        fi
      done
      return "$failed"
      ;;
    clear-xray)
      for profile in ai cn; do
        mode=$(profile_egress_mode "$profile")
        if [[ "$mode" == "xray" ]]; then
          profile_egress_gate_clear "$profile"
        fi
      done
      ;;
    *)
      die "usage: dnscomplex egress-ready xray|clear-xray"
      ;;
  esac
}

ipsec_deadline_remaining() {
  local deadline=$1 now
  now=$(date +%s)
  REPLY=$((deadline - now))
  ((REPLY > 0))
}

wait_for_ipsec_underlay() {
  local deadline=$1 iface expected gateway addresses parsed_addresses routes
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    iface=$WAN_IFACE
    expected=${LINUX_LAN_IPV4%%/*}
    gateway=${ROUTEROS_LAN_IPV4%%/*}
  else
    iface="${WAN_IFACE}.${TRANSIT_VLAN_ID}"
    expected=${LINUX_TRANSIT_IPV4%%/*}
    gateway=${ROUTEROS_TRANSIT_IPV4%%/*}
  fi

  while true; do
    addresses=$(ip -4 -o addr show dev "$iface" scope global 2>/dev/null || true)
    parsed_addresses=$(awk '{split($4, address, "/"); print address[1]}' <<<"$addresses")
    routes=$(ip -4 route show default 2>/dev/null || true)
    if grep -Fxq "$expected" <<<"$parsed_addresses" &&
      awk -v gateway="$gateway" -v iface="$iface" '
        $1 == "default" {
          route_gateway = ""
          route_iface = ""
          for (i = 2; i <= NF; i++) {
            if ($i == "via" && i < NF) {
              route_gateway = $(i + 1)
            } else if ($i == "dev" && i < NF) {
              route_iface = $(i + 1)
            }
          }
          if (route_gateway == gateway && route_iface == iface) {
            found = 1
          }
        }
        END { exit(found ? 0 : 1) }
      ' <<<"$routes"; then
      log "IPsec underlay ready: $iface has $expected via $gateway"
      return 0
    fi
    if ! ipsec_deadline_remaining "$deadline"; then
      warn "timed out waiting for $expected and default route via $gateway on $iface"
      return 1
    fi
    sleep 1
  done
}

network_ready_cmd() {
  need_root
  local timeout_seconds=${DNSCOMPLEX_IPSEC_BOOT_TIMEOUT:-90}
  local deadline
  [[ "$timeout_seconds" =~ ^[0-9]+$ ]] && ((timeout_seconds >= 1 && timeout_seconds <= 110)) ||
    die "DNSCOMPLEX_IPSEC_BOOT_TIMEOUT must be 1-110 seconds at runtime"
  deadline=$(($(date +%s) + timeout_seconds))
  wait_for_ipsec_underlay "$deadline"
}

wait_for_swanctl_vici() {
  local deadline=$1 probe_timeout
  while true; do
    ipsec_deadline_remaining "$deadline" || {
      warn "timed out waiting for the strongSwan VICI daemon"
      return 1
    }
    probe_timeout=$REPLY
    ((probe_timeout > 2)) && probe_timeout=2
    if timeout --signal=TERM --kill-after=1s "${probe_timeout}s" \
      swanctl --stats >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
}

ipsec_sa_state_from_sas() {
  local profile=$1
  awk -v profile="$profile" '
    function valid_ipv4(value, octets, count, field) {
      count = split(value, octets, ".")
      if (count != 4) {
        return 0
      }
      for (field = 1; field <= 4; field++) {
        if (octets[field] !~ /^[0-9]+$/ ||
            octets[field] + 0 < 0 || octets[field] + 0 > 255) {
          return 0
        }
      }
      if (octets[1] + 0 == 0 || octets[1] + 0 == 127 ||
          octets[1] + 0 >= 224 ||
          (octets[1] + 0 == 169 && octets[2] + 0 == 254)) {
        return 0
      }
      return 1
    }

    function reset_section() {
      in_profile = 0
      established = 0
      installed = 0
      vip = ""
    }

    function finish_section() {
      if (!in_profile || !established) {
        return
      }
      any_ike = 1
      if (installed) {
        any_child = 1
      }
      if (vip != "") {
        any_vip = 1
      }
      if (installed && vip != "" && ready_vip == "") {
        ready_vip = vip
      }
    }

    BEGIN {
      reset_section()
    }

    /^[^[:space:]]/ {
      finish_section()
      reset_section()
      if ($1 == profile ":") {
        in_profile = 1
        established = ($0 ~ /, ESTABLISHED([,[:space:]]|$)/)
      }
      next
    }

    in_profile {
      if ($1 == profile ":" &&
          $0 ~ /, INSTALLED([,[:space:]]|$)/) {
        installed = 1
      }
      if ($1 == "local") {
        remainder = $0
        while (match(remainder, /\[[^][]+\]/)) {
          candidate = substr(remainder, RSTART + 1, RLENGTH - 2)
          if (valid_ipv4(candidate)) {
            vip = candidate
          }
          remainder = substr(remainder, RSTART + RLENGTH)
        }
      }
    }

    END {
      finish_section()
      printf "%d|%d|%d|%s\n", any_ike, any_child, any_vip, ready_vip
    }
  '
}

read_ipsec_sa_state() {
  local profile=$1 sas=$2 state
  state=$(ipsec_sa_state_from_sas "$profile" <<<"$sas") || return 1
  IFS='|' read -r \
    IPSEC_STATE_IKE_ESTABLISHED \
    IPSEC_STATE_CHILD_INSTALLED \
    IPSEC_STATE_VIP_VALID \
    IPSEC_STATE_READY_VIP <<<"$state"
  IPSEC_STATE_IKE_ESTABLISHED=${IPSEC_STATE_IKE_ESTABLISHED:-0}
  IPSEC_STATE_CHILD_INSTALLED=${IPSEC_STATE_CHILD_INSTALLED:-0}
  IPSEC_STATE_VIP_VALID=${IPSEC_STATE_VIP_VALID:-0}
  IPSEC_STATE_READY_VIP=${IPSEC_STATE_READY_VIP:-}
}

ipsec_vip_from_sas() {
  local profile=$1 sas
  sas=$(cat)
  read_ipsec_sa_state "$profile" "$sas" || return 1
  [[ "$IPSEC_STATE_IKE_ESTABLISHED" == "1" &&
     "$IPSEC_STATE_CHILD_INSTALLED" == "1" &&
     "$IPSEC_STATE_VIP_VALID" == "1" &&
     -n "$IPSEC_STATE_READY_VIP" ]] || return 1
  printf '%s\n' "$IPSEC_STATE_READY_VIP"
}

ipsec_installed_from_sas() {
  local profile=$1 sas
  sas=$(cat)
  read_ipsec_sa_state "$profile" "$sas" || return 1
  [[ "$IPSEC_STATE_IKE_ESTABLISHED" == "1" &&
     "$IPSEC_STATE_CHILD_INSTALLED" == "1" ]]
}

ipsec_interface_is_up() {
  local device=$1 output
  output=$(ip -o link show dev "$device" 2>/dev/null) || return 1
  grep -Eq '<([^>]*,)?UP(,[^>]*)?>' <<<"$output"
}

inspect_ipsec_policy_rule() {
  local expected_mark=$1 expected_table=$2 expected_priority=$3
  local rules line priority_token mark_token table_token
  local priority_value mark_value mask_value table_value field
  local negated rule_matches selector_unrestricted action_unmodified
  local expected_mark_value expected_table_value expected_priority_value
  local -a fields
  IPSEC_RULE_EXACT_COUNT=0
  IPSEC_RULE_HIGHER_CONFLICT=0
  IPSEC_RULE_SAME_PRIORITY_STALE=0
  IPSEC_RULE_MARK_CONFLICT=0
  [[ "$expected_mark" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ &&
     "$expected_table" =~ ^[0-9]+$ &&
     "$expected_priority" =~ ^[0-9]+$ ]] || return 1
  expected_mark_value=$((expected_mark))
  expected_table_value=$((10#$expected_table))
  expected_priority_value=$((10#$expected_priority))
  rules=$(ip rule show 2>/dev/null) || return 1
  while IFS= read -r line; do
    IFS=$' \t' read -r -a fields <<<"$line"
    ((${#fields[@]} > 0)) || continue
    priority_token=${fields[0]%:}
    mark_token=""
    table_token=""
    negated=0
    selector_unrestricted=1
    action_unmodified=1
    for ((field = 1; field < ${#fields[@]}; field++)); do
      case "${fields[field]}" in
        not)
          if ((negated == 1)); then
            action_unmodified=0
          fi
          negated=1
          ;;
        from|to)
          if ((field + 1 >= ${#fields[@]})); then
            selector_unrestricted=0
            action_unmodified=0
            continue
          fi
          field=$((field + 1))
          [[ "${fields[field]}" == "all" ]] || selector_unrestricted=0
          ;;
        fwmark)
          if ((field + 1 >= ${#fields[@]})); then
            action_unmodified=0
            continue
          fi
          [[ -z "$mark_token" ]] || action_unmodified=0
          field=$((field + 1))
          mark_token=${fields[field]}
          ;;
        lookup|table)
          if ((field + 1 >= ${#fields[@]})); then
            action_unmodified=0
            continue
          fi
          [[ -z "$table_token" ]] || action_unmodified=0
          field=$((field + 1))
          table_token=${fields[field]}
          ;;
        proto|protocol)
          if ((field + 1 >= ${#fields[@]})); then
            action_unmodified=0
            continue
          fi
          field=$((field + 1))
          ;;
        tos|dsfield|iif|oif|uidrange|ipproto|sport|dport|tun_id)
          selector_unrestricted=0
          if ((field + 1 >= ${#fields[@]})); then
            action_unmodified=0
            continue
          fi
          field=$((field + 1))
          ;;
        l3mdev)
          selector_unrestricted=0
          ;;
        suppress_prefixlength|suppress_ifgroup|goto|nat|realms)
          action_unmodified=0
          if ((field + 1 < ${#fields[@]})); then
            field=$((field + 1))
          fi
          ;;
        blackhole|unreachable|prohibit|nop)
          action_unmodified=0
          ;;
        *)
          action_unmodified=0
          ;;
      esac
    done
    [[ "$priority_token" =~ ^[0-9]+$ ]] || continue
    priority_value=$((10#$priority_token))
    if [[ -z "$mark_token" ]]; then
      if ((priority_value == expected_priority_value)); then
        IPSEC_RULE_SAME_PRIORITY_STALE=1
      fi
      continue
    fi
    mark_value=${mark_token%%/*}
    if [[ "$mark_token" == */* ]]; then
      mask_value=${mark_token#*/}
    else
      mask_value=0xffffffff
    fi
    if [[ ! "$mark_value" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ||
          ! "$mask_value" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ]]; then
      if ((priority_value == expected_priority_value)); then
        IPSEC_RULE_SAME_PRIORITY_STALE=1
      fi
      continue
    fi
    mark_value=$((mark_value))
    mask_value=$((mask_value))
    if ! ((mark_value >= 0 && mark_value <= 0xffffffff &&
          mask_value >= 0 && mask_value <= 0xffffffff)); then
      if ((priority_value == expected_priority_value)); then
        IPSEC_RULE_SAME_PRIORITY_STALE=1
      fi
      continue
    fi
    if (((expected_mark_value & mask_value) == (mark_value & mask_value))); then
      rule_matches=1
    else
      rule_matches=0
    fi
    if ((negated == 1)); then
      if ((rule_matches == 0 || selector_unrestricted == 0)); then
        rule_matches=1
      else
        rule_matches=0
      fi
    fi
    if ((priority_value < expected_priority_value && rule_matches == 1)); then
      IPSEC_RULE_HIGHER_CONFLICT=1
    fi
    if [[ "$table_token" =~ ^[0-9]+$ ]]; then
      table_value=$((10#$table_token))
      if ((priority_value == expected_priority_value &&
           negated == 0 &&
           selector_unrestricted == 1 &&
           action_unmodified == 1 &&
           mark_value == expected_mark_value &&
           mask_value == 0xffffffff &&
           table_value == expected_table_value)); then
        IPSEC_RULE_EXACT_COUNT=$((IPSEC_RULE_EXACT_COUNT + 1))
        continue
      fi
    fi
    if ((rule_matches == 1)); then
      IPSEC_RULE_MARK_CONFLICT=1
    fi
    if ((priority_value == expected_priority_value)); then
      IPSEC_RULE_SAME_PRIORITY_STALE=1
    fi
  done <<<"$rules"
}

ipsec_policy_rule_present() {
  inspect_ipsec_policy_rule "$@" || return 1
  [[ "$IPSEC_RULE_EXACT_COUNT" == "1" &&
     "$IPSEC_RULE_HIGHER_CONFLICT" == "0" &&
     "$IPSEC_RULE_SAME_PRIORITY_STALE" == "0" &&
     "$IPSEC_RULE_MARK_CONFLICT" == "0" ]]
}

ipsec_probe_policy_priority() {
  case "$1" in
    ai) printf '10201\n' ;;
    cn) printf '10251\n' ;;
    *) return 1 ;;
  esac
}

ipsec_probe_policy_rule_present() {
  local profile=$1 mode mark table priority
  mode=$(profile_egress_mode "$profile") || return 1
  [[ "$mode" == ipsec ]] || return 1
  case "$profile" in
    ai) mark=$IPSEC_DATAPLANE_AI_MARK; table=$AI_TABLE ;;
    cn) mark=$IPSEC_DATAPLANE_CN_MARK; table=$CN_TABLE ;;
    *) return 1 ;;
  esac
  priority=$(ipsec_probe_policy_priority "$profile") || return 1
  ipsec_policy_rule_present "$mark" "$table" "$priority"
}

sync_ipsec_probe_policy_rule() {
  local profile=$1 vip=${2:-} mode mark table priority attempt
  mode=$(profile_egress_mode "$profile") || return 1
  case "$profile" in
    ai) mark=$IPSEC_DATAPLANE_AI_MARK; table=$AI_TABLE ;;
    cn) mark=$IPSEC_DATAPLANE_CN_MARK; table=$CN_TABLE ;;
    *) return 1 ;;
  esac
  priority=$(ipsec_probe_policy_priority "$profile") || return 1
  if ! inspect_ipsec_policy_rule "$mark" "$table" "$priority"; then
    warn "could not inspect $profile dataplane probe policy rule"
    return 1
  fi
  if [[ "$IPSEC_RULE_HIGHER_CONFLICT" == "1" ||
        "$IPSEC_RULE_SAME_PRIORITY_STALE" == "1" ||
        "$IPSEC_RULE_MARK_CONFLICT" == "1" || "$IPSEC_RULE_EXACT_COUNT" -gt 1 ]]; then
    warn "$profile dataplane probe fwmark rule conflicts with an existing policy rule"
    return 1
  fi
  if [[ "$mode" != ipsec || -z "$vip" ]]; then
    if [[ "$IPSEC_RULE_EXACT_COUNT" == 1 ]]; then
      ip rule del fwmark "$mark" table "$table" priority "$priority" || return 1
      inspect_ipsec_policy_rule "$mark" "$table" "$priority" || return 1
      [[ "$IPSEC_RULE_EXACT_COUNT" == 0 && "$IPSEC_RULE_HIGHER_CONFLICT" == 0 &&
         "$IPSEC_RULE_SAME_PRIORITY_STALE" == 0 && "$IPSEC_RULE_MARK_CONFLICT" == 0 ]] || return 1
    fi
    return 0
  fi
  if [[ "$IPSEC_RULE_EXACT_COUNT" == 0 ]]; then
    ip rule add fwmark "$mark" table "$table" priority "$priority" || {
      warn "could not install $profile dataplane probe fwmark rule"
      return 1
    }
  fi
  ipsec_policy_rule_present "$mark" "$table" "$priority" || {
    warn "$profile dataplane probe fwmark rule did not verify"
    return 1
  }
}

ipsec_policy_priority_present() {
  local expected_priority=$1 rules
  rules=$(ip rule show 2>/dev/null) || return 1
  awk -v expected="${expected_priority}:" '
    $1 == expected { found = 1 }
    END { exit(found ? 0 : 1) }
  ' <<<"$rules"
}

ipsec_policy_route_matches() {
  local table=$1 device=$2 vip=$3 routes
  [[ -n "$vip" ]] || return 1
  routes=$(ip route show table "$table" 2>/dev/null) || return 1
  awk -v expected_device="$device" -v expected_vip="$vip" '
    $1 == "default" {
      device = ""
      source = ""
      for (field = 1; field <= NF; field++) {
        if ($field == "dev" && field < NF) {
          device = $(field + 1)
        }
        if ($field == "src" && field < NF) {
          source = $(field + 1)
        }
      }
      if (device == expected_device && source == expected_vip) {
        found = 1
      }
    }
    END { exit(found ? 0 : 1) }
  ' <<<"$routes"
}

ipsec_profile_runtime_ready() {
  local profile=$1 sas=$2 mark table priority device failed=0
  case "$profile" in
    ai)
      mark=$AI_MARK
      table=$AI_TABLE
      priority=10301
      device=ipsec-ai
      ;;
    cn)
      mark=$CN_MARK
      table=$CN_TABLE
      priority=10351
      device=ipsec-cn
      ;;
    *)
      warn "unknown IPsec profile: $profile"
      return 1
      ;;
  esac

  read_ipsec_sa_state "$profile" "$sas" || return 1
  if [[ "$IPSEC_STATE_IKE_ESTABLISHED" != "1" ]]; then
    warn "$profile IPsec IKE_SA is not established"
    failed=1
  fi
  if [[ "$IPSEC_STATE_CHILD_INSTALLED" != "1" ]]; then
    warn "$profile IPsec CHILD_SA is not installed"
    failed=1
  fi
  if [[ "$IPSEC_STATE_VIP_VALID" != "1" ||
        -z "$IPSEC_STATE_READY_VIP" ]]; then
    warn "$profile IPsec virtual IPv4 is missing or invalid"
    failed=1
  fi
  if ! ipsec_interface_is_up "$device"; then
    warn "$device interface is missing or down"
    failed=1
  fi
  if ! ipsec_policy_rule_present "$mark" "$table" "$priority"; then
    warn "$profile IPsec fwmark policy rule is missing"
    failed=1
  fi
  if ! ipsec_policy_route_matches "$table" "$device" \
       "$IPSEC_STATE_READY_VIP"; then
    warn "$profile IPsec default route does not use $device with its virtual IPv4 source"
    failed=1
  fi
  [[ "$failed" == "0" ]]
}

ipsec_profile_sa_ready() {
  local profile=$1 sas=$2 device
  case "$profile" in
    ai) device=ipsec-ai ;;
    cn) device=ipsec-cn ;;
    *) return 1 ;;
  esac
  read_ipsec_sa_state "$profile" "$sas" || return 1
  [[ "$IPSEC_STATE_IKE_ESTABLISHED" == "1" &&
     "$IPSEC_STATE_CHILD_INSTALLED" == "1" &&
     "$IPSEC_STATE_VIP_VALID" == "1" &&
     -n "$IPSEC_STATE_READY_VIP" ]] || return 1
  ipsec_interface_is_up "$device"
}

ipsec_profile_dataplane_identity() {
  local profile=$1 vip=$2 sas=$3
  {
    printf '%s\n' "$vip"
    awk -v profile="$profile" '
      /^[^[:space:]]/ { keep = ($1 == profile ":") }
      keep && $1 == profile ":" && $2 ~ /^#[0-9]+,/ {
        if ($3 == "ESTABLISHED,") {
          print $1, $2, $3, $4
        } else if ($0 ~ /, INSTALLED,/) {
          print $1, $2, $4, $5, $6, $7
        }
      }
    ' <<<"$sas"
  } | sha256sum | awk '{print $1}'
}

profile_dataplane_success_path() {
  printf '%s/profile-dataplane-%s.success\n' "$RUN_DIR" "$1"
}

profile_dataplane_clear_evidence() {
  rm -f -- "$(profile_dataplane_success_path "$1")"
}

profile_dataplane_close_and_forget() {
  local profile=$1 state_path
  profile_egress_gate_clear "$profile" || return 1
  profile_egress_gate_verify_closed "$profile" || return 1
  profile_dataplane_clear_evidence "$profile" || return 1
  state_path=$(profile_dataplane_success_path "$profile") || return 1
  [[ ! -e "$state_path" ]]
}

ipsec_probe_output_rule_matches() {
  local profile=$1 probe_mark profile_mark resolver
  case "$profile" in
    ai) probe_mark=$IPSEC_DATAPLANE_AI_MARK; profile_mark=$AI_MARK; resolver=104.16.248.249 ;;
    cn) probe_mark=$IPSEC_DATAPLANE_CN_MARK; profile_mark=$CN_MARK; resolver=223.6.6.6 ;;
    *) return 1 ;;
  esac
  nft -j list chain inet dnscomplex output | jq -e \
    --arg profile "$profile" --arg resolver "$resolver" \
    --argjson probe_mark "$((probe_mark))" --argjson profile_mark "$((profile_mark))" '
    [.nftables[]?.rule? | select(.comment == ("dnscomplex-" + $profile + "-dataplane-probe"))] as $rules |
    ($rules | length) == 1 and
    ($rules[0] | .family == "inet" and .table == "dnscomplex" and .chain == "output") and
    ($rules[0].expr | map(select(has("counter") | not))) == [
      {match:{op:"==",left:{payload:{protocol:"ip",field:"saddr"}},right:("@" + $profile + "_probe_vip4")}},
      {match:{op:"==",left:{meta:{key:"oifname"}},right:("ipsec-" + $profile)}},
      {match:{op:"==",left:{payload:{protocol:"ip",field:"daddr"}},right:$resolver}},
      {match:{op:"==",left:{payload:{protocol:"tcp",field:"dport"}},right:443}},
      {match:{op:"==",left:{meta:{key:"mark"}},right:$probe_mark}},
      {mangle:{key:{meta:{key:"mark"}},value:$profile_mark}},
      {accept:null}
    ]
  ' >/dev/null
}

profile_dataplane_probe_observe() {
  local profile=$1 vip=$2 sas=$3 identity state_path old_vip old_identity old_count
  local was_open=0 probe_path probe_mark resolver tls_name query_domain
  local output status count temp fresh_sas probe_rc probe_timeout capture_timeout fresh_identity retry_budget
  [[ "$(profile_egress_mode "$profile")" == ipsec ]] || return 0
  case "$profile" in
    ai)
      probe_mark=$IPSEC_DATAPLANE_AI_MARK_DEC
      local other_probe_mark=$IPSEC_DATAPLANE_CN_MARK
      resolver=104.16.248.249
      tls_name=cloudflare-dns.com
      query_domain=openai.com
      ;;
    cn)
      probe_mark=$IPSEC_DATAPLANE_CN_MARK_DEC
      local other_probe_mark=$IPSEC_DATAPLANE_AI_MARK
      resolver=223.6.6.6
      tls_name=dns.alidns.com
      query_domain=youku.com
      ;;
    *) return 1 ;;
  esac
  identity=$(ipsec_profile_dataplane_identity "$profile" "$vip" "$sas") || return 1
  state_path=$(profile_dataplane_success_path "$profile")
  old_vip=""
  old_identity=""
  old_count=0
  if [[ -r "$state_path" ]]; then
    IFS=' ' read -r old_vip old_identity old_count <"$state_path" || true
    if [[ "$old_vip" != "$vip" ]]; then
      old_vip=""
      old_identity=""
      old_count=0
    elif [[ ! "$old_count" =~ ^[1-9][0-9]{0,2}$ ]]; then
      old_identity=""
      old_count=0
    elif [[ "$old_identity" != "$identity" ]]; then
      old_identity=""
      old_count=0
    elif ((old_count > 2)); then
      old_count=2
    fi
  fi
  if profile_egress_gate_is_open "$profile"; then
    was_open=1
  fi
  if [[ "$was_open" == 1 && "$old_vip" != "$vip" ]]; then
    profile_egress_gate_clear "$profile" || {
      warn "$profile dataplane VIP changed but its readiness gate could not be closed"
      profile_dataplane_clear_evidence "$profile"
      return 1
    }
    was_open=0
  fi
  if ! ipsec_probe_vip_set_matches "$profile" "$vip"; then
    profile_egress_gate_clear "$profile" || warn "$profile dataplane gate could not be closed for VIP set drift"
    profile_dataplane_clear_evidence "$profile"
    warn "$profile dataplane probe source VIP is not synchronized"
    return 1
  fi
  probe_path=$(fs_path /usr/local/lib/dnscomplex/profile-dataplane-probe.py)
  if [[ ! -x "$probe_path" ]]; then
    profile_egress_gate_clear "$profile" || warn "$profile dataplane gate could not be closed without its probe helper"
    profile_dataplane_clear_evidence "$profile"
    warn "$profile dataplane probe helper is missing"
    return 1
  fi
  probe_timeout=$(watchdog_timeout_value 5) || return 1
  capture_timeout=$(watchdog_timeout_value 6) || return 1
  if output=$(watchdog_capture 6 "$probe_path" \
      --profile "$profile" --mode ipsec --vip "$vip" --device "ipsec-$profile" \
      --probe-mark "$probe_mark" \
      --reserved-mark "$AI_MARK" --reserved-mark "$CN_MARK" \
      --reserved-mark "$SINGBOX_AUTO_REDIRECT_INPUT_MARK" \
      --reserved-mark "$SINGBOX_AUTO_REDIRECT_OUTPUT_MARK" \
      --reserved-mark "$other_probe_mark" \
      --resolver-ip "$resolver" --tls-name "$tls_name" \
      --query-domain "$query_domain" --timeout "$probe_timeout" 2>/dev/null); then
    :
  else
    probe_rc=$?
    profile_egress_gate_clear "$profile" || {
      warn "$profile dataplane gate could not be closed after probe failure"
      return 1
    }
    profile_dataplane_clear_evidence "$profile" || return 1
    warn "$profile IPsec dataplane TLS probe failed"
    # Only a completed, full-budget connect-only result can be isolated.
    # Unknown helper failures and the watchdog's own deadline remain global.
    if [[ "$probe_rc" == 1 && "$probe_timeout" == 5.000 && "$capture_timeout" == 6.000 ]] &&
       python3 -c 'import json,sys; p=json.load(sys.stdin); sys.exit(0 if p.get("status")=="fail" and p.get("profile")==sys.argv[1] and p.get("phase")=="connect" and p.get("reason")=="connect_attempts_exhausted" and type(p.get("connect_attempts")) is int and p["connect_attempts"]==3 and type(p.get("elapsed_ms")) is int and 0<=p["elapsed_ms"]<=5000 else 1)' "$profile" <<<"$output" 2>/dev/null &&
       ipsec_probe_output_rule_matches "$profile" &&
       profile_egress_gate_verify_closed "$profile" &&
       watchdog_timeout_value 1 >/dev/null; then
      return 2
    fi
    return 1
  fi
  status=$(python3 -c 'import json,sys; p=json.load(sys.stdin); print(p.get("status", "fail"),p.get("profile", ""))' \
    <<<"$output" 2>/dev/null || printf 'fail unknown')
  if [[ "$status" != "pass $profile" ]]; then
    profile_egress_gate_clear "$profile" || warn "$profile dataplane gate could not be closed after invalid probe result"
    profile_dataplane_clear_evidence "$profile"
    warn "$profile IPsec dataplane TLS probe returned an invalid result"
    return 1
  fi
  if ! fresh_sas=$(watchdog_capture 5 swanctl --list-sas 2>/dev/null); then
    profile_dataplane_close_and_forget "$profile" || warn "$profile dataplane gate or evidence could not be verified after its SA changed"
    warn "$profile IPsec dataplane identity changed during its probe"
    return 1
  fi
  if ! ipsec_profile_sa_ready "$profile" "$fresh_sas" || [[ "$IPSEC_STATE_READY_VIP" != "$vip" ]]; then
    profile_dataplane_close_and_forget "$profile" || warn "$profile dataplane gate or evidence could not be verified after its SA changed"
    warn "$profile IPsec dataplane identity changed during its probe"
    return 1
  fi
  fresh_identity=$(ipsec_profile_dataplane_identity "$profile" "$vip" "$fresh_sas") || {
    profile_dataplane_close_and_forget "$profile" || warn "$profile dataplane gate or evidence could not be verified after its SA changed"
    warn "$profile IPsec dataplane identity could not be read after its probe"
    return 1
  }
  if [[ -z "$fresh_identity" ]]; then
    profile_dataplane_close_and_forget "$profile" || warn "$profile dataplane gate or evidence could not be verified after its SA changed"
    warn "$profile IPsec dataplane identity was empty after its probe"
    return 1
  fi
  if [[ "$fresh_identity" != "$identity" ]]; then
    if ! profile_dataplane_close_and_forget "$profile"; then
      warn "$profile dataplane gate or prior proof could not be verified closed after its SA changed"
      return 1
    fi
    warn "$profile IPsec dataplane identity changed during its probe"
    # AI identity changes retain the existing global fail-closed behavior.
    [[ "$profile" == cn ]] || return 1
    # A retry is safe only with the same ready VIP and the full bounded probe,
    # SA readback, and closure reserve still available in the shared budget.
    retry_budget=$(watchdog_timeout_value 17) || return 1
    [[ "$retry_budget" == 17.000 ]] || return 1
    identity=$fresh_identity
    old_vip=$vip
    old_identity=""
    old_count=0
    was_open=0
    probe_timeout=$(watchdog_timeout_value 5) || return 1
    capture_timeout=$(watchdog_timeout_value 6) || return 1
    if output=$(watchdog_capture 6 "$probe_path" \
        --profile "$profile" --mode ipsec --vip "$vip" --device "ipsec-$profile" \
        --probe-mark "$probe_mark" \
        --reserved-mark "$AI_MARK" --reserved-mark "$CN_MARK" \
        --reserved-mark "$SINGBOX_AUTO_REDIRECT_INPUT_MARK" \
        --reserved-mark "$SINGBOX_AUTO_REDIRECT_OUTPUT_MARK" \
        --reserved-mark "$other_probe_mark" \
        --resolver-ip "$resolver" --tls-name "$tls_name" \
        --query-domain "$query_domain" --timeout "$probe_timeout" 2>/dev/null); then
      status=$(python3 -c 'import json,sys; p=json.load(sys.stdin); print(p.get("status", "fail"),p.get("profile", ""))' \
        <<<"$output" 2>/dev/null || printf 'fail unknown')
      if [[ "$status" != "pass $profile" ]]; then
        profile_dataplane_close_and_forget "$profile" || warn "$profile dataplane gate or evidence could not be verified after retry returned an invalid result"
        warn "$profile IPsec dataplane retry returned an invalid result"
        return 1
      fi
    else
      probe_rc=$?
      profile_dataplane_close_and_forget "$profile" || {
        warn "$profile dataplane gate or evidence could not be verified after retry failure"
        return 1
      }
      warn "$profile IPsec dataplane retry failed"
      # Preserve the existing narrowly checked connect-only local-failure
      # contract. Unknown retries still fail the whole watchdog cycle.
      if [[ "$probe_rc" == 1 && "$probe_timeout" == 5.000 && "$capture_timeout" == 6.000 ]] &&
         python3 -c 'import json,sys; p=json.load(sys.stdin); sys.exit(0 if p.get("status")=="fail" and p.get("profile")==sys.argv[1] and p.get("phase")=="connect" and p.get("reason")=="connect_attempts_exhausted" and type(p.get("connect_attempts")) is int and p["connect_attempts"]==3 and type(p.get("elapsed_ms")) is int and 0<=p["elapsed_ms"]<=5000 else 1)' "$profile" <<<"$output" 2>/dev/null &&
         ipsec_probe_output_rule_matches "$profile" &&
         profile_egress_gate_verify_closed "$profile" &&
         watchdog_timeout_value 1 >/dev/null; then
        return 2
      fi
      return 1
    fi
    if ! fresh_sas=$(watchdog_capture 5 swanctl --list-sas 2>/dev/null) ||
       ! ipsec_profile_sa_ready "$profile" "$fresh_sas" ||
       [[ "$IPSEC_STATE_READY_VIP" != "$vip" ]]; then
      profile_dataplane_close_and_forget "$profile" || warn "$profile dataplane gate or evidence could not be verified after retry SA change"
      warn "$profile IPsec dataplane SA or VIP changed after retry"
      return 1
    fi
    fresh_identity=$(ipsec_profile_dataplane_identity "$profile" "$vip" "$fresh_sas") || fresh_identity=""
    if [[ -z "$fresh_identity" || "$fresh_identity" != "$identity" ]]; then
      profile_dataplane_close_and_forget "$profile" || warn "$profile dataplane gate or evidence could not be verified after retry identity change"
      warn "$profile IPsec dataplane identity changed again during its retry"
      return 1
    fi
  fi
  if [[ "$old_vip" == "$vip" && "$old_identity" == "$identity" ]]; then
    count=$((old_count + 1))
  else
    count=1
  fi
  ((count > 2)) && count=2
  temp=$(mktemp "$RUN_DIR/.profile-dataplane-${profile}.XXXXXX") || {
    profile_egress_gate_clear "$profile" || true
    profile_dataplane_clear_evidence "$profile"
    return 1
  }
  if ! printf '%s %s %s\n' "$vip" "$identity" "$count" >"$temp" ||
     ! chmod 0600 "$temp" || ! mv -f "$temp" "$state_path"; then
    rm -f -- "$temp"
    profile_egress_gate_clear "$profile" || warn "$profile dataplane gate could not be closed after evidence write failure"
    profile_dataplane_clear_evidence "$profile"
    warn "$profile dataplane success evidence could not be committed"
    return 1
  fi
  if ((count >= 2)) && [[ "$was_open" != 1 ]]; then
    profile_egress_gate_open "$profile" || {
      profile_egress_gate_clear "$profile" || warn "$profile dataplane gate could not be closed after open failure"
      profile_dataplane_clear_evidence "$profile"
      warn "$profile dataplane gate could not be opened after two successful probes"
      return 1
    }
  fi
  if ((count >= 2)) || [[ "$was_open" == 1 ]]; then
    profile_egress_gate_is_open "$profile" || return 1
  else
    profile_egress_gate_verify_closed "$profile" || return 1
  fi
}

ipsec_child_ready() {
  local child=$1 sas vip
  sas=$(timeout --signal=TERM --kill-after=1s 5s swanctl --list-sas 2>/dev/null || true)
  grep -Eq "^${child}: #[0-9]+, ESTABLISHED" <<<"$sas" || return 1
  vip=$(ipsec_vip_from_sas "$child" <<<"$sas")
  [[ -n "$vip" ]]
}

run_swanctl_bounded() {
  local timeout_seconds=$1 output rc
  shift
  mkdir -p "$RUN_DIR"
  output=$(mktemp "$RUN_DIR/.swanctl.XXXXXX") || return 1
  chmod 0600 "$output"
  if timeout --signal=TERM --kill-after=5s "${timeout_seconds}s" \
    swanctl "$@" >"$output" 2>&1; then
    rm -f "$output"
    return 0
  else
    rc=$?
  fi
  cat "$output" >&2
  rm -f "$output"
  return "$rc"
}

ipsec_ready_cmd() {
  need_root
  local timeout_seconds=${DNSCOMPLEX_IPSEC_BOOT_TIMEOUT:-90}
  local deadline profile selected=0 remaining
  [[ "$timeout_seconds" =~ ^[0-9]+$ ]] && ((timeout_seconds >= 1 && timeout_seconds <= 110)) ||
    die "DNSCOMPLEX_IPSEC_BOOT_TIMEOUT must be 1-110 seconds at runtime"

  for profile in ai cn; do
    if profile_uses_ipsec "$profile"; then
      profile_egress_gate_clear "$profile"
      selected=1
    fi
  done
  if [[ "$selected" == "0" ]]; then
    log "no IPsec egress profile selected; readiness check skipped"
    return 0
  fi

  deadline=$(($(date +%s) + timeout_seconds))
  wait_for_ipsec_underlay "$deadline" || return 1
  wait_for_swanctl_vici "$deadline" || return 1
  ipsec_deadline_remaining "$deadline" || {
    warn "IPsec readiness deadline expired before configuration load"
    return 1
  }
  remaining=$REPLY
  if ! run_swanctl_bounded "$remaining" --load-all --noprompt; then
    warn "strongSwan configuration could not be loaded"
    return 1
  fi

  for profile in ai cn; do
    profile_uses_ipsec "$profile" || continue
    if ! ipsec_child_ready "$profile"; then
      ipsec_deadline_remaining "$deadline" || {
        warn "$profile IPsec readiness deadline expired before initiation"
        return 1
      }
      remaining=$REPLY
      if ! run_swanctl_bounded "$remaining" --initiate --child "$profile"; then
        warn "$profile IPsec child could not be initiated"
        return 1
      fi
    fi
    while ! ipsec_child_ready "$profile"; do
      if ! ipsec_deadline_remaining "$deadline"; then
        warn "$profile IPsec child did not obtain an established SA and virtual IPv4"
        return 1
      fi
      sleep 1
    done
    log "$profile IPsec child is established with a virtual IPv4"
  done
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
      profile_uses_ipsec ai && profile_egress_gate_clear ai
      profile_uses_ipsec cn && profile_egress_gate_clear cn
      ip link del ipsec-ai 2>/dev/null || true
      ip link del ipsec-cn 2>/dev/null || true
      ;;
    *)
      die "usage: dnscomplex ipsec-ifaces up|down"
      ;;
  esac
}

ipsec_vip() {
  local child=$1 sas
  if ((WATCHDOG_DEADLINE_MS > 0)); then
    if ! sas=$(watchdog_capture 5 swanctl --list-sas 2>/dev/null); then
      return 1
    fi
  else
    if ! sas=$(timeout --signal=TERM --kill-after=1s 5s \
      swanctl --list-sas 2>/dev/null); then
      return 1
    fi
  fi
  ipsec_vip_from_sas "$child" <<<"$sas"
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

ipsec_nat_profile_matches() {
  local profile=$1 vip=$2 device set_name comment rules
  case "$profile" in
    ai)
      device=ipsec-ai
      set_name=ai4
      comment=dnscomplex-ai-snat
      ;;
    cn)
      device=ipsec-cn
      set_name=cn4
      comment=dnscomplex-cn-snat
      ;;
    *) return 1 ;;
  esac
  rules=$(nft -a list chain inet dnscomplex postrouting 2>/dev/null) || return 1
  awk -v device="$device" -v set_name="$set_name" -v vip="$vip" \
      -v comment="$comment" '
    BEGIN {
      expected[1] = "oifname"
      expected[2] = "\"" device "\""
      expected[3] = "ip"
      expected[4] = "daddr"
      expected[5] = "@" set_name
      expected[6] = "snat"
      expected[7] = "ip"
      expected[8] = "to"
      expected[9] = vip
      expected[10] = "comment"
      expected[11] = "\"" comment "\""
    }
    {
      owned = 0
      for (i = 1; i <= NF; i++) {
        if ($i == "#") break
        if ($i == "comment" && $(i + 1) == "\"" comment "\"") owned = 1
      }
      if (!owned) next
      n = 0
      for (i = 1; i <= NF; i++) {
        if ($i == "#") break
        if ($i == "counter" && $(i + 1) == "packets" &&
            $(i + 2) ~ /^[0-9]+$/ && $(i + 3) == "bytes" &&
            $(i + 4) ~ /^[0-9]+$/) {
          i += 4
          continue
        }
        token[++n] = $i
      }
      count++
      if (n == 11) {
        exact = 1
        for (i = 1; i <= 11; i++) {
          if (token[i] != expected[i]) exact = 0
        }
      } else {
        exact = 0
      }
      if (exact) {
        matches++
      }
      delete token
    }
    END { exit(count == 1 && matches == 1 ? 0 : 1) }
  ' <<<"$rules"
}

ipsec_nat_profile_remove() {
  local profile=$1 comment rules handles handle remaining
  case "$profile" in
    ai) comment=dnscomplex-ai-snat ;;
    cn) comment=dnscomplex-cn-snat ;;
    *) return 1 ;;
  esac
  rules=$(nft -a list chain inet dnscomplex postrouting 2>/dev/null) || return 1
  handles=$(awk -v expected="\"$comment\"" '
    {
      for (i = 1; i < NF; i++) {
        if ($i == "comment" && $(i + 1) == expected) {
          print $NF
          break
        }
      }
    }
  ' <<<"$rules")
  while read -r handle; do
    [[ -n "$handle" ]] || continue
    nft delete rule inet dnscomplex postrouting handle "$handle" || return 1
  done <<<"$handles"
  rules=$(nft -a list chain inet dnscomplex postrouting 2>/dev/null) || return 1
  remaining=$(awk -v expected="\"$comment\"" '
    {
      for (i = 1; i < NF; i++) {
        if ($i == "comment" && $(i + 1) == expected) {
          count++
          break
        }
      }
    }
    END { print count + 0 }
  ' <<<"$rules") || return 1
  [[ "$remaining" == 0 ]]
}

lan_alias_nat_state_status() {
  local state helper rc
  state=$(fs_path /var/lib/dnscomplex/lan-alias.json) || return 1
  if [[ ! -e "$state" && ! -L "$state" ]]; then
    return 1
  fi
  [[ -f "$state" && ! -L "$state" ]] || return 2
  helper=$(fs_path /usr/local/libexec/dnscomplex-lan-alias) || return 2
  [[ -x "$helper" ]] || return 2
  if python3 "$helper" state-owned --state "$state" >/dev/null 2>&1; then
    return 0
  else
    rc=$?
  fi
  [[ "$rc" == 1 ]] && return 1
  return 2
}

lan_alias_nat_is_owned() {
  lan_alias_nat_state_status
}

lan_alias_nat_invalid_state_fail_closed() {
  local profile=$1
  if ! profile_egress_gate_clear "$profile"; then
    warn "$profile egress gate could not be closed while LAN alias ownership state was invalid"
  fi
  warn "LAN alias ownership state is invalid; refusing alias SNAT changes for $profile"
  return 1
}

ipsec_alias_nat_profile_state() {
  local profile=$1 rules device comment state
  case "$profile" in
    ai) device=ipsec-ai; comment=dnscomplex-lan-alias-snat-ai ;;
    cn) device=ipsec-cn; comment=dnscomplex-lan-alias-snat-cn ;;
    *) return 1 ;;
  esac
  rules=$(nft -a list chain inet dnscomplex postrouting 2>/dev/null) || return 1
  state=$(awk -v device="$device" -v comment="\"$comment\"" '
    {
      if ($0 !~ comment) next
      count++
      n = 0
      for (i = 1; i <= NF; i++) {
        if ($i == "#") break
        if ($i == "counter" && $(i + 1) == "packets" && $(i + 2) ~ /^[0-9]+$/ && $(i + 3) == "bytes" && $(i + 4) ~ /^[0-9]+$/) {
          i += 4
          continue
        }
        token[++n] = $i
      }
      if (n == 11 && token[1] == "oifname" && token[2] == "\"" device "\"" &&
          token[3] == "ip" && token[4] == "saddr" && token[5] == "@lan_alias_source4" &&
          token[6] == "snat" && token[7] == "ip" && token[8] == "to" &&
          token[9] ~ /^([0-9]{1,3}[.]){3}[0-9]{1,3}$/ &&
          token[10] == "comment" && token[11] == comment) {
      valid++
      vip = token[9]
      if ($NF ~ /^[0-9]+$/) {
        handles = handles (handles == "" ? "" : ",") $NF
      } else {
        handles = handles (handles == "" ? "" : ",") "invalid"
      }
      }
      delete token
    }
    END { printf "%d|%d|%s|%s\n", count + 0, valid + 0, vip, handles }
  ' <<<"$rules") || return 1
  IFS='|' read -r IPSEC_ALIAS_NAT_COUNT IPSEC_ALIAS_NAT_VALID IPSEC_ALIAS_NAT_VIP IPSEC_ALIAS_NAT_HANDLE <<<"$state"
  [[ "$IPSEC_ALIAS_NAT_COUNT" =~ ^[0-9]+$ && "$IPSEC_ALIAS_NAT_VALID" =~ ^[0-9]+$ ]] || return 1
  [[ "$IPSEC_ALIAS_NAT_COUNT" == "$IPSEC_ALIAS_NAT_VALID" ]]
}

ipsec_alias_nat_profile_matches() {
  local profile=$1 vip=$2
  ipsec_alias_nat_profile_state "$profile" || return 1
  [[ "$IPSEC_ALIAS_NAT_COUNT" == 1 && "$IPSEC_ALIAS_NAT_VIP" == "$vip" ]]
}

ipsec_alias_nat_profile_remove() {
  local profile=$1 handle state_rc
  if lan_alias_nat_state_status; then
    :
  else
    state_rc=$?
    case "$state_rc" in
      1) return 0 ;;
      *) lan_alias_nat_invalid_state_fail_closed "$profile"; return 1 ;;
    esac
  fi
  ipsec_alias_nat_profile_state "$profile" || return 1
  [[ "$IPSEC_ALIAS_NAT_COUNT" != 0 ]] || return 0
  local -a handles=()
  IFS=',' read -r -a handles <<<"$IPSEC_ALIAS_NAT_HANDLE"
  for handle in "${handles[@]}"; do
    [[ "$handle" =~ ^[0-9]+$ ]] || return 1
    nft delete rule inet dnscomplex postrouting handle "$handle" || return 1
  done
  ipsec_alias_nat_profile_state "$profile" || return 1
  [[ "$IPSEC_ALIAS_NAT_COUNT" == 0 ]]
}

sync_ipsec_alias_nat_profile() {
  local profile=$1 vip=$2 device state_rc
  case "$profile" in
    ai) device=ipsec-ai ;;
    cn) device=ipsec-cn ;;
    *) return 1 ;;
  esac
  if lan_alias_nat_state_status; then
    :
  else
    state_rc=$?
    case "$state_rc" in
      1) return 0 ;;
      *) lan_alias_nat_invalid_state_fail_closed "$profile"; return 1 ;;
    esac
  fi
  if ipsec_alias_nat_profile_matches "$profile" "$vip"; then
    return 0
  fi
  ipsec_alias_nat_profile_remove "$profile" || return 1
  nft add rule inet dnscomplex postrouting oifname "$device" \
    ip saddr @lan_alias_source4 snat ip to "$vip" \
    comment "dnscomplex-lan-alias-snat-$profile" || return 1
  ipsec_alias_nat_profile_matches "$profile" "$vip"
}

ipsec_bind_profile_matches() {
  local profile=$1 vip=$2 config_path count current tag
  tag="${profile}-ipsec"
  config_path="${FS_ROOT:-}/etc/sing-box/config.json"
  command -v jq >/dev/null 2>&1 || return 1
  [[ -f "$config_path" ]] || return 1
  count=$(jq --arg tag "$tag" '[.outbounds[]? | select(.tag == $tag)] | length' \
    "$config_path") || return 1
  [[ "$count" == "1" ]] || return 1
  current=$(jq -r --arg tag "$tag" \
    '.outbounds[] | select(.tag == $tag) | .inet4_bind_address // ""' \
    "$config_path") || return 1
  [[ "$current" == "$vip" ]]
}

ipsec_probe_vip_set_matches() {
  local profile=$1 vip=$2 set_name
  case "$profile" in
    ai) set_name=ai_probe_vip4 ;;
    cn) set_name=cn_probe_vip4 ;;
    *) return 1 ;;
  esac
  nft -j list set inet dnscomplex "$set_name" 2>/dev/null |
    jq -e --arg name "$set_name" --arg vip "$vip" '
      any(.nftables[]?;
        (.set? // {}) as $set |
        $set.family == "inet" and $set.table == "dnscomplex" and
        $set.name == $name and $set.type == "ipv4_addr" and
        (($set.elem // []) | map(
          if type == "string" then .
          elif type == "object" and (.prefix? | type == "object") and
               .prefix.len == 32 then .prefix.addr
          else "<invalid>" end
        )) == (if $vip == "" then [] else [$vip] end))
    ' >/dev/null 2>&1
}

sync_ipsec_probe_vip_profile() {
  local profile=$1 vip=$2 set_name
  case "$profile" in
    ai) set_name=ai_probe_vip4 ;;
    cn) set_name=cn_probe_vip4 ;;
    *) return 1 ;;
  esac
  [[ "$(profile_egress_mode "$profile")" == "ipsec" ]] || return 0
  ipsec_probe_vip_set_matches "$profile" "$vip" && return 0
  profile_egress_gate_clear "$profile" || {
    warn "$profile egress gate could not be closed before dataplane probe VIP update"
    return 1
  }
  nft -f - <<EOF
flush set inet dnscomplex $set_name
$(if [[ -n "$vip" ]]; then printf 'add element inet dnscomplex %s { %s }\n' "$set_name" "$vip"; fi)
EOF
  ipsec_probe_vip_set_matches "$profile" "$vip" || {
    warn "$profile dataplane probe VIP set did not verify"
    return 1
  }
}

sync_ipsec_nat_profile() {
  local profile=$1 vip="" device set_name comment
  if ! nft list chain inet dnscomplex postrouting >/dev/null 2>&1; then
    nft add chain inet dnscomplex postrouting \
      '{ type nat hook postrouting priority srcnat; policy accept; }' || return 1
  fi
  case "$profile" in
    ai)
      device=ipsec-ai
      set_name=ai4
      comment=dnscomplex-ai-snat
      ;;
    cn)
      device=ipsec-cn
      set_name=cn4
      comment=dnscomplex-cn-snat
      ;;
    *) return 1 ;;
  esac
  vip=$(ipsec_vip "$profile" || true)
  if [[ -z "$vip" ]]; then
    profile_egress_gate_clear "$profile" || return 1
    sync_ipsec_probe_vip_profile "$profile" "" || return 1
    ipsec_alias_nat_profile_remove "$profile" || return 1
    ipsec_nat_profile_remove "$profile" || {
      warn "$profile IPsec SNAT rule could not be removed while its VIP is missing"
      return 1
    }
    return 0
  fi
  if ipsec_nat_profile_matches "$profile" "$vip"; then
    sync_ipsec_alias_nat_profile "$profile" "$vip" || return $?
    sync_ipsec_probe_vip_profile "$profile" "$vip"
    return $?
  fi
  profile_egress_gate_clear "$profile" || return 1
  ipsec_nat_profile_remove "$profile" || {
    warn "$profile IPsec SNAT rule could not be removed"
    return 1
  }
  if ! nft add rule inet dnscomplex postrouting oifname "$device" \
    ip daddr "@$set_name" snat ip to "$vip" comment "$comment"; then
    warn "$profile IPsec SNAT rule could not be installed"
    return 1
  fi
  ipsec_nat_profile_matches "$profile" "$vip" || {
    warn "$profile IPsec SNAT rule did not verify after installation"
    return 1
  }
  sync_ipsec_alias_nat_profile "$profile" "$vip" || return $?
  sync_ipsec_probe_vip_profile "$profile" "$vip"
}

sync_ipsec_nat() {
  local profile failed=0
  for profile in ai cn; do
    profile_uses_ipsec "$profile" || continue
    sync_ipsec_nat_profile "$profile" || failed=1
  done
  return "$failed"
}

sync_singbox_ipsec_bind_addresses() {
  local only_profile=${1:-} config_path="${FS_ROOT:-}/etc/sing-box/config.json"
  local ai_vip="" cn_vip="" ai_tag_count cn_tag_count current_ai current_cn
  local tmp backup needs_update=0
  command -v jq >/dev/null 2>&1 || {
    warn "jq is required to reconcile sing-box IPsec bind addresses"
    return 1
  }
  [[ -f "$config_path" ]] || {
    warn "sing-box config is missing while reconciling IPsec bind addresses"
    return 1
  }
  jq -e '.outbounds | type == "array"' "$config_path" >/dev/null 2>&1 || {
    warn "sing-box config could not be read while reconciling IPsec bind addresses"
    return 1
  }
  case "$only_profile" in
    ""|ai|cn) ;;
    *) warn "unknown IPsec bind-address profile: $only_profile"; return 1 ;;
  esac
  if [[ -z "$only_profile" || "$only_profile" == ai ]]; then
    if [[ "${AI_EGRESS_MODE:-ipsec}" == ipsec ]]; then
      ai_vip=$(ipsec_vip ai) || return 1
    fi
  fi
  if [[ -z "$only_profile" || "$only_profile" == cn ]]; then
    if [[ "${CN_EGRESS_MODE:-ipsec}" == ipsec ]]; then
      cn_vip=$(ipsec_vip cn) || return 1
    fi
  fi
  [[ -n "$ai_vip" || -n "$cn_vip" ]] || return 0

  ai_tag_count=$(jq '[.outbounds[]? | select(.tag == "ai-ipsec")] | length' \
    "$config_path") || return 1
  cn_tag_count=$(jq '[.outbounds[]? | select(.tag == "cn-ipsec")] | length' \
    "$config_path") || return 1
  if [[ -n "$ai_vip" && "$ai_tag_count" != 1 ]] ||
     [[ -n "$cn_vip" && "$cn_tag_count" != 1 ]]; then
    warn "sing-box config must contain exactly one outbound for each selected IPsec profile"
    return 1
  fi
  current_ai=$(jq -r '.outbounds[] | select(.tag=="ai-ipsec") | .inet4_bind_address // ""' "$config_path") || return 1
  current_cn=$(jq -r '.outbounds[] | select(.tag=="cn-ipsec") | .inet4_bind_address // ""' "$config_path") || return 1
  [[ -n "$ai_vip" && "$current_ai" != "$ai_vip" ]] && needs_update=1
  [[ -n "$cn_vip" && "$current_cn" != "$cn_vip" ]] && needs_update=1
  [[ "$needs_update" == "1" ]] || return 0

  tmp=$(mktemp "${config_path}.tmp.XXXXXX") || return 1
  backup=$(mktemp "${config_path}.bak.XXXXXX") || { rm -f "$tmp"; return 1; }
  if ! cp -p "$config_path" "$backup"; then
    rm -f "$tmp" "$backup"
    warn "sing-box config backup could not be created"
    return 1
  fi
  if ! jq --arg ai "$ai_vip" --arg cn "$cn_vip" '
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
  ' "$config_path" >"$tmp"; then
    rm -f "$tmp" "$backup"
    warn "sing-box config could not be rendered with the new IPsec bind address"
    return 1
  fi
  if ! sing-box check -c "$tmp"; then
    rm -f "$tmp" "$backup"
    warn "sing-box rejected the reconciled IPsec bind-address config"
    return 1
  fi
  if ! install -m 0644 "$tmp" "$config_path"; then
    if cp -p "$backup" "$config_path"; then
      rm -f "$backup"
    else
      warn "previous sing-box config remains recoverable at $backup"
    fi
    rm -f "$tmp"
    warn "reconciled sing-box config could not be installed"
    return 1
  fi
  if ! systemctl restart sing-box; then
    if cp -p "$backup" "$config_path"; then
      systemctl restart sing-box || warn "sing-box did not restart with the previous config"
      rm -f "$backup"
    else
      warn "previous sing-box config remains recoverable at $backup"
    fi
    rm -f "$tmp"
    warn "sing-box could not restart after IPsec bind-address reconciliation"
    return 1
  fi
  rm -f "$tmp" "$backup"
}

ensure_policy_route_profile() {
  local profile=$1 mode mark table priority device vip attempt
  case "$profile" in
    ai)
      mode=${AI_EGRESS_MODE:-ipsec}
      mark=$AI_MARK
      table=$AI_TABLE
      priority=10301
      device=ipsec-ai
      ;;
    cn)
      mode=${CN_EGRESS_MODE:-ipsec}
      mark=$CN_MARK
      table=$CN_TABLE
      priority=10351
      device=ipsec-cn
      ;;
    *)
      warn "unknown policy-route profile: $profile"
      return 1
      ;;
  esac

  case "$mode" in
    xray)
      local ipv6_rules ipv6_line ipv6_field ipv6_mark ipv6_value ipv6_mask
      ipv6_rules=$(ip -6 rule show 2>/dev/null) || {
        warn "could not inspect IPv6 policy rules before selecting $profile Xray egress"
        return 1
      }
      while IFS= read -r ipv6_line; do
        local -a ipv6_fields
        IFS=$' \t' read -r -a ipv6_fields <<<"$ipv6_line"
        for ((ipv6_field = 0; ipv6_field + 1 < ${#ipv6_fields[@]}; ipv6_field++)); do
          [[ "${ipv6_fields[ipv6_field]}" == fwmark ]] || continue
          ipv6_mark=${ipv6_fields[ipv6_field + 1]%%/*}
          ipv6_mask=0xffffffff
          [[ "${ipv6_fields[ipv6_field + 1]}" == */* ]] && ipv6_mask=${ipv6_fields[ipv6_field + 1]#*/}
          [[ "$ipv6_mark" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ &&
             "$ipv6_mask" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ]] || {
            warn "could not safely inspect an IPv6 fwmark policy rule"
            return 1
          }
          ipv6_value=$((ipv6_mark)); ipv6_mask=$((ipv6_mask))
          if (((mark & ipv6_mask) == (ipv6_value & ipv6_mask))); then
            warn "$profile Xray mark conflicts with an IPv6 policy rule"
            return 1
          fi
        done
      done <<<"$ipv6_rules"
      if ! inspect_ipsec_policy_rule "$mark" "$table" "$priority"; then
        warn "could not inspect policy rules before selecting $profile Xray egress"
        return 1
      fi
      if [[ "$IPSEC_RULE_HIGHER_CONFLICT" == "1" ||
            "$IPSEC_RULE_SAME_PRIORITY_STALE" == "1" ||
            "$IPSEC_RULE_MARK_CONFLICT" == "1" ]]; then
        warn "$profile Xray egress conflicts with a foreign fwmark policy rule"
        return 1
      fi
      for ((attempt = 0; attempt < 16 && IPSEC_RULE_EXACT_COUNT > 0; attempt++)); do
        if ! ip rule del fwmark "$mark" table "$table" priority "$priority"; then
          warn "could not remove the owned $profile IPsec policy rule for Xray egress"
          return 1
        fi
        if ! inspect_ipsec_policy_rule "$mark" "$table" "$priority"; then
          warn "could not verify removal of the owned $profile IPsec policy rule"
          return 1
        fi
        [[ "$IPSEC_RULE_HIGHER_CONFLICT" == "0" &&
           "$IPSEC_RULE_SAME_PRIORITY_STALE" == "0" &&
           "$IPSEC_RULE_MARK_CONFLICT" == "0" ]] || {
          warn "$profile Xray egress conflicts with a foreign fwmark policy rule"
          return 1
        }
      done
      if ((IPSEC_RULE_EXACT_COUNT != 0)); then
        warn "too many owned $profile IPsec policy rules remain for Xray egress"
        return 1
      fi
      sync_ipsec_probe_policy_rule "$profile" "" || return 1
      return 0
      ;;
    ipsec) ;;
    *)
      warn "$profile has invalid egress mode: $mode"
      return 1
      ;;
  esac

  if ! inspect_ipsec_policy_rule "$mark" "$table" "$priority"; then
    warn "could not inspect policy rules for $profile"
    return 1
  fi
  if [[ "$IPSEC_RULE_HIGHER_CONFLICT" == "1" ]]; then
    warn "$profile has a higher-priority fwmark rule that conflicts with dnscomplex"
    return 1
  fi
  if [[ "$IPSEC_RULE_EXACT_COUNT" != "1" ||
        "$IPSEC_RULE_SAME_PRIORITY_STALE" == "1" ]]; then
    for ((attempt = 0; attempt < 16; attempt++)); do
      ipsec_policy_priority_present "$priority" || break
      if ! ip rule del priority "$priority"; then
        warn "could not remove the stale $profile policy rule"
        return 1
      fi
    done
    if ipsec_policy_priority_present "$priority"; then
      warn "too many stale rules remain at $profile policy priority $priority"
      return 1
    fi
    if ! ip rule add fwmark "$mark" table "$table" priority "$priority"; then
      warn "could not install the $profile policy rule"
      return 1
    fi
    if ! ipsec_policy_rule_present "$mark" "$table" "$priority"; then
      warn "the $profile policy rule did not become authoritative"
      return 1
    fi
  fi

  vip=$(ipsec_vip "$profile" || true)
  if [[ -n "$vip" ]]; then
    if ! ip route replace default dev "$device" src "$vip" table "$table"; then
      warn "could not install the $profile policy route"
      return 1
    fi
  elif ! ip route replace default dev "$device" table "$table"; then
    warn "could not install the $profile policy route"
    return 1
  fi
  sync_ipsec_probe_policy_rule "$profile" "$vip"
}

routes_cmd() {
  need_root
  local action=${1:-} profile mode
  case "$action" in
    up)
      profile_egress_gate_clear ai
      profile_egress_gate_clear cn
      ensure_policy_route_profile ai || return 1
      ensure_policy_route_profile cn || return 1
      sync_ipsec_nat || return 1
      sync_singbox_ipsec_bind_addresses || return 1
      repair_policy_routes_if_needed || return 1
      lan_alias_reconcile_cmd || return 1
      ;;
    down)
      lan_alias_close_cmd || return 1
      profile_egress_gate_clear ai
      profile_egress_gate_clear cn
      sync_ipsec_probe_policy_rule ai "" || return 1
      sync_ipsec_probe_policy_rule cn "" || return 1
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
  if [[ "${1:-}" == "--strict" ]]; then
    shift
    [[ $# -eq 0 ]] || die "usage: dnscomplex fix [--strict]"
    state_transaction_manager_cmd legacy_reconcile_cmd
    return
  fi
  [[ $# -eq 0 ]] || die "usage: dnscomplex fix [--strict]"
  state_transaction_cmd "repair" state_transaction_manager_cmd fix_cmd --strict
}

doctor_cmd() {
  local failed=0 missing failed_units
  local health_output health_status
  health_output=$(health_checks_json || true)
  health_status=$(printf '%s\n' "$health_output" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","unknown"))' 2>/dev/null || printf unknown)
  printf '[health] status=%s\n' "$health_status"
  HEALTH_JSON="$health_output" python3 - <<'PY' || true
import json
import os
import sys
try:
    data = json.loads(os.environ.get("HEALTH_JSON", "{}"))
except Exception:
    sys.exit(0)
for reason in data.get("failure_reasons", []):
    print("[health][reason] " + reason)
for action in data.get("recommended_actions", []):
    print("[health][action] " + action)
PY
  [[ "$health_status" == "unhealthy" ]] && failed=1

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
  printf '[quic] AI_QUIC_POLICY=%s CN_QUIC_POLICY=%s. allow preserves UDP/443 services; choose reject only for a verified UDP blackhole and applications with TCP fallback.\n' "$AI_QUIC_POLICY" "$CN_QUIC_POLICY"
  return "$failed"
}

probe_egress_cmd() {
  need_root
  DNSCOMPLEX_PROBE_DEFAULT_MARK="$SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC" \
  DNSCOMPLEX_PROBE_AI_MARK="$AI_MARK" DNSCOMPLEX_PROBE_CN_MARK="$CN_MARK" \
    python3 "$(fs_path /usr/local/lib/dnscomplex/probe-egress.py)" "$@"
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

health_checks_json() {
  DNSCOMPLEX_HEALTH_RUN_DIR="$RUN_DIR" python3 - "$CONFIG" <<'PY'
import json
import ipaddress
import hashlib
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import time

CONFIG = sys.argv[1]
FS_ROOT = os.environ.get("DNSCOMPLEX_FS_ROOT", "").rstrip("/")

def fs_path(path):
    if FS_ROOT and path.startswith("/"):
        return FS_ROOT + path
    return path

def parse_config():
    cfg = {}
    try:
        with open(CONFIG, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                cfg[key] = value.strip().strip("'\"")
    except FileNotFoundError:
        pass
    return cfg

def run(cmd, timeout=5):
    try:
        return subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            cmd, 124, exc.stdout or "", exc.stderr or ""
        )
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))

def service_active(name):
    return run(["systemctl", "is-active", "--quiet", name], 4).returncode == 0

def dig_query(domain, qtype="A", port="53", timeout=3):
    start = time.monotonic()
    proc = run(["dig", "+time=2", "+tries=1", "+short", qtype, domain, "@127.0.0.1", "-p", str(port)], timeout)
    elapsed = (time.monotonic() - start) * 1000
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return proc.returncode == 0 and bool(lines), lines, elapsed

def test_socks_listener(listen, port):
    host = listen or "127.0.0.1"
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            return True, f"{listen}:{port} reachable via {host}:{port}"
    except Exception as exc:
        return False, f"{listen}:{port} unreachable: {exc}"

def tcp_connectivity(host, family, timeout=3.0):
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        address = (host, 443, 0, 0) if family == socket.AF_INET6 else (host, 443)
        sock.connect(address)
        return True
    except OSError:
        return False
    finally:
        if sock is not None:
            sock.close()

def profile_dataplane_identity(profile, vip, sa_output):
    rows = [vip]
    keep = False
    for raw in sa_output.splitlines():
        if raw and not raw[0].isspace():
            keep = raw.split(None, 1)[0] == profile + ":"
        tokens = raw.split()
        if not keep or len(tokens) < 2 or tokens[0] != profile + ":" or not re.fullmatch(r"#[0-9]+,", tokens[1]):
            continue
        if len(tokens) >= 4 and tokens[2] == "ESTABLISHED,":
            rows.append(" ".join(tokens[:4]))
        elif ", INSTALLED," in raw and len(tokens) >= 7:
            rows.append(" ".join((tokens[0], tokens[1], tokens[3], tokens[4], tokens[5], tokens[6])))
    return hashlib.sha256(("\n".join(rows) + "\n").encode("utf-8")).hexdigest()

def valid_ipsec_vip(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    first = int(str(address).split(".", 1)[0])
    return not (
        address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or first >= 224
    )

def ipsec_sa_state(sas, profile):
    result = {
        "ike_established": False,
        "child_installed": False,
        "vip_valid": False,
        "ready_vip": "",
    }
    section = None

    def finish_section():
        nonlocal section
        if not section or not section["established"]:
            return
        result["ike_established"] = True
        result["child_installed"] |= section["installed"]
        result["vip_valid"] |= bool(section["vip"])
        if section["installed"] and section["vip"] and not result["ready_vip"]:
            result["ready_vip"] = section["vip"]

    for raw in sas.splitlines():
        if raw and not raw[0].isspace():
            finish_section()
            first = raw.split(None, 1)[0]
            if first == profile + ":":
                section = {
                    "established": bool(
                        re.search(r", ESTABLISHED(?:,|\s|$)", raw)
                    ),
                    "installed": False,
                    "vip": "",
                }
            else:
                section = None
            continue
        if section is None:
            continue
        stripped = raw.lstrip()
        first = stripped.split(None, 1)[0] if stripped else ""
        if first == profile + ":" and re.search(
            r", INSTALLED(?:,|\s|$)", stripped
        ):
            section["installed"] = True
        if first == "local":
            for candidate in re.findall(r"\[([^][]+)\]", stripped):
                if valid_ipsec_vip(candidate):
                    section["vip"] = str(ipaddress.IPv4Address(candidate))
    finish_section()
    return result

def ipsec_interface_up(device):
    proc = run(["ip", "-o", "link", "show", "dev", device], 4)
    if proc.returncode != 0:
        return False
    match = re.search(r"<([^>]*)>", proc.stdout)
    return bool(match and "UP" in match.group(1).split(","))

def ipsec_policy_rule_present(
    rules, expected_mark, expected_table, expected_priority
):
    try:
        mark_number = int(expected_mark, 0)
        table_number = int(expected_table, 10)
        priority_number = int(expected_priority, 10)
    except ValueError:
        return False
    exact_count = 0
    higher_conflict = False
    same_priority_stale = False
    for line in rules.splitlines():
        tokens = line.split()
        try:
            actual_priority = int(tokens[0].rstrip(":"), 10)
        except (ValueError, IndexError):
            continue
        mark_token = None
        table_token = None
        negated = False
        selector_unrestricted = True
        action_unmodified = True
        index = 1
        while index < len(tokens):
            token = tokens[index]
            if token == "not":
                if negated:
                    action_unmodified = False
                negated = True
                index += 1
                continue
            if token in ("from", "to"):
                if index + 1 >= len(tokens):
                    selector_unrestricted = False
                    action_unmodified = False
                    break
                selector_unrestricted = (
                    selector_unrestricted and tokens[index + 1] == "all"
                )
                index += 2
                continue
            if token == "fwmark":
                if index + 1 >= len(tokens):
                    action_unmodified = False
                    break
                if mark_token is not None:
                    action_unmodified = False
                mark_token = tokens[index + 1]
                index += 2
                continue
            if token in ("lookup", "table"):
                if index + 1 >= len(tokens):
                    action_unmodified = False
                    break
                if table_token is not None:
                    action_unmodified = False
                table_token = tokens[index + 1]
                index += 2
                continue
            if token in ("proto", "protocol"):
                if index + 1 >= len(tokens):
                    action_unmodified = False
                    break
                index += 2
                continue
            if token in (
                "tos",
                "dsfield",
                "iif",
                "oif",
                "uidrange",
                "ipproto",
                "sport",
                "dport",
                "tun_id",
            ):
                selector_unrestricted = False
                if index + 1 >= len(tokens):
                    action_unmodified = False
                    break
                index += 2
                continue
            if token == "l3mdev":
                selector_unrestricted = False
                index += 1
                continue
            if token in (
                "suppress_prefixlength",
                "suppress_ifgroup",
                "goto",
                "nat",
                "realms",
            ):
                action_unmodified = False
                index += 2
                continue
            if token in ("blackhole", "unreachable", "prohibit", "nop"):
                action_unmodified = False
                index += 1
                continue
            action_unmodified = False
            index += 1
        try:
            mark_parts = mark_token.split("/", 1)
            actual_mark = int(mark_parts[0], 0)
            actual_mask = (
                int(mark_parts[1], 0) if len(mark_parts) == 2 else 0xFFFFFFFF
            )
        except (AttributeError, ValueError):
            if actual_priority == priority_number:
                same_priority_stale = True
            continue
        if not (
            0 <= actual_mark <= 0xFFFFFFFF
            and 0 <= actual_mask <= 0xFFFFFFFF
        ):
            if actual_priority == priority_number:
                same_priority_stale = True
            continue
        rule_matches = (
            (mark_number & actual_mask) == (actual_mark & actual_mask)
        )
        if negated:
            rule_matches = not rule_matches or not selector_unrestricted
        if (
            actual_priority < priority_number
            and rule_matches
        ):
            higher_conflict = True
        try:
            actual_table = int(table_token, 10)
        except (TypeError, ValueError):
            if actual_priority == priority_number:
                same_priority_stale = True
            continue
        if (
            actual_priority == priority_number
            and not negated
            and selector_unrestricted
            and action_unmodified
            and actual_mark == mark_number
            and actual_mask == 0xFFFFFFFF
            and actual_table == table_number
        ):
            exact_count += 1
        elif actual_priority == priority_number:
            same_priority_stale = True
    return (
        exact_count == 1
        and not higher_conflict
        and not same_priority_stale
    )

def ipsec_policy_route_matches(table, device, vip):
    if not vip:
        return False
    proc = run(["ip", "route", "show", "table", str(table)], 4)
    if proc.returncode != 0:
        return False
    for line in proc.stdout.splitlines():
        tokens = line.split()
        if not tokens or tokens[0] != "default":
            continue
        try:
            actual_device = tokens[tokens.index("dev") + 1]
            actual_source = tokens[tokens.index("src") + 1]
        except (ValueError, IndexError):
            continue
        if actual_device == device and actual_source == vip:
            return True
    return False

def ipsec_runtime_state(sas, rules, profile, mark, table, priority):
    state = ipsec_sa_state(sas, profile)
    device = "ipsec-" + profile
    state["interface_up"] = ipsec_interface_up(device)
    state["policy_rule"] = ipsec_policy_rule_present(
        rules, mark, table, priority
    )
    state["route_source_matches"] = ipsec_policy_route_matches(
        table, device, state["ready_vip"]
    )
    state["ok"] = all(
        state[name]
        for name in (
            "ike_established",
            "child_installed",
            "vip_valid",
            "interface_up",
            "policy_rule",
            "route_source_matches",
        )
    ) and bool(state["ready_vip"])
    return state

def nft_count(set_name):
    proc = run(["nft", "list", "set", "inet", "dnscomplex", set_name], 5)
    if proc.returncode != 0:
        return -1
    return len(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", proc.stdout)))

def file_age(path):
    try:
        return max(0, int(time.time() - os.stat(path).st_mtime))
    except FileNotFoundError:
        return None

def int_file(path, default=0):
    try:
        return int(open(path, "r", encoding="utf-8").read().strip())
    except Exception:
        return default

def memory_usage_percent():
    total = available = 0
    try:
        with open("/proc/meminfo", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    available = int(line.split()[1])
    except Exception:
        return 0.0
    if total <= 0:
        return 0.0
    return round(((total - available) / total) * 100, 2)

def add_check(checks, name, ok, severity, detail, action, core=False, value=None):
    status = "ok" if ok else ("fail" if severity == "critical" else "warn")
    item = {"name": name, "status": status, "severity": severity, "detail": detail, "recommended_action": action, "core": core}
    if value is not None:
        item["value"] = value
    checks.append(item)

cfg = parse_config()
checks = []
services = []
core_failed = False
warned = False
failure_reasons = []
recommended_actions = []

core_services = ["sing-box.service", "smartdns.service", "AdGuardHome.service", "nftables.service"]
if cfg.get("XRAY_ENABLED", "1") == "1" or cfg.get("AI_EGRESS_MODE", "ipsec") == "xray" or cfg.get("CN_EGRESS_MODE", "ipsec") == "xray":
    core_services.append("xray-dnscomplex.service")
for service in core_services:
    ok = service_active(service)
    services.append({"name": service, "ok": ok})
    add_check(checks, "service-" + service, ok, "critical", f"{service} active={ok}", f"systemctl restart {service}", core=True)

socks_listen = cfg.get("SINGBOX_SOCKS_LISTEN", "127.0.0.1")
socks_port = cfg.get("SINGBOX_SOCKS_PORT", "1080")
socks_ok, socks_detail = test_socks_listener(socks_listen, socks_port)
add_check(checks, "singbox-socks-listener", socks_ok, "critical", socks_detail, "check SINGBOX_SOCKS_LISTEN/SINGBOX_SOCKS_PORT and restart sing-box", core=True)

listener_specs = [
    ("smartdns-default-listener", "example.com", "A", cfg.get("SMARTDNS_DEFAULT_PORT", "6053")),
    ("smartdns-ai-listener", "openai.com", "A", cfg.get("SMARTDNS_AI_PORT", "6054")),
    ("smartdns-cn-listener", "youku.com", "A", cfg.get("SMARTDNS_CN_PORT", "6055")),
]
latencies = []
successes = 0
for name, domain, qtype, port in listener_specs:
    ok, _lines, ms = dig_query(domain, qtype, port)
    latencies.append(ms)
    successes += 1 if ok else 0
    add_check(checks, name, ok, "critical", f"{domain} {qtype} via port {port} in {ms:.1f}ms", "restart SmartDNS and check upstream DNS", core=True, value=round(ms, 2))

adguard_cache_ok = True
try:
    adguard_yaml = open("/etc/AdGuardHome/AdGuardHome.yaml", "r", encoding="utf-8", errors="replace").read()
    cache_enabled = "  cache_enabled: true" in adguard_yaml
    cache_size_match = __import__("re").search(r"(?m)^  cache_size:\s*(\d+)", adguard_yaml)
    cache_size = int(cache_size_match.group(1)) if cache_size_match else 0
    adguard_cache_ok = not (cfg.get("ADGUARD_DNS_CACHE_MODE", "off") == "off" and (cache_enabled or cache_size != 0))
except Exception:
    adguard_cache_ok = False
add_check(checks, "adguard-cache-policy", adguard_cache_ok, "warning", f"AdGuard cache policy ok={adguard_cache_ok}", "keep ADGUARD_DNS_CACHE_MODE=off so SmartDNS is the single cache authority")

for name, domain, port in [
    ("ai-aaaa-suppression", "openai.com", cfg.get("SMARTDNS_AI_PORT", "6054")),
    ("cn-aaaa-suppression", "youku.com", cfg.get("SMARTDNS_CN_PORT", "6055")),
]:
    _ok, lines, _ms = dig_query(domain, "AAAA", port)
    leaked = any(":" in line for line in lines)
    add_check(checks, name, not leaked, "critical", f"{domain} AAAA leaked={leaked}", "AI/CN SmartDNS listeners must keep -force-aaaa-soa", core=True)

for profile in ["ai", "cn"]:
    key = f"{profile.upper()}_QUIC_POLICY"
    default_policy = "allow" if profile == "ai" else "reject"
    policy = cfg.get(key, default_policy)
    valid_policy = policy in ("allow", "reject")
    add_check(
        checks,
        f"{profile}-quic-policy",
        valid_policy,
        "warning",
        f"{key}={policy if valid_policy else 'unsupported'} (policy configuration only; UDP reachability not tested)",
        f"set {key} to allow or reject (policy configuration only; UDP reachability not tested)",
    )

local_ipv6_policy = cfg.get("LOCAL_DOMAIN_IPV6_POLICY", "ipv4_only")
smartdns_conf = ""
try:
    smartdns_conf = open("/etc/smartdns/smartdns.conf", "r", encoding="utf-8", errors="replace").read()
except Exception:
    pass
add_check(
    checks,
    "local-domain-ipv6-policy",
    local_ipv6_policy == "allow" or "address /local/#6" in smartdns_conf,
    "warning",
    f"LOCAL_DOMAIN_IPV6_POLICY={local_ipv6_policy}",
    "keep LOCAL_DOMAIN_IPV6_POLICY=ipv4_only so iOS/Codex .local callbacks use IPv4 instead of timing out on Mac IPv6",
)

icloud_gateway_ok, _icloud_gateway_lines, icloud_gateway_ms = dig_query(
    "gateway.icloud.com", "A", "53"
)
add_check(
    checks,
    "icloud-gateway-dns",
    icloud_gateway_ok,
    "critical",
    f"gateway.icloud.com A resolvable={icloud_gateway_ok} in {icloud_gateway_ms:.1f}ms",
    "remove gateway.icloud.com from Private Relay DNS rejects and restart sing-box",
    core=True,
    value=round(icloud_gateway_ms, 2),
)

if cfg.get("DEPLOY_MODE") == "routeros-policy":
    lan_if = cfg.get("WAN_IFACE", "")
    lan_cidr = cfg.get("LAN_CLIENT_IPV4_CIDR", "")
    lan_ip = cfg.get("LINUX_LAN_IPV4", "")
    postrouting = run(["nft", "list", "chain", "inet", "dnscomplex", "postrouting"], 5)
    postrouting_text = postrouting.stdout if postrouting.returncode == 0 else ""
    default_snat_ok = all(
        token and token in postrouting_text
        for token in (
            "dnscomplex-routeros-default-snat",
            f'oifname "{lan_if}"',
            f"ip saddr {lan_cidr}",
            f"snat ip to {lan_ip}",
        )
    )
    add_check(
        checks,
        "routeros-default-snat",
        default_snat_ok,
        "critical",
        f"symmetric default egress SNAT present={default_snat_ok} interface={lan_if} source={lan_cidr} address={lan_ip}",
        "run dnscomplex apply-nft; default RouterOS-policy traffic requires symmetric return through this host",
        core=True,
    )

    redirect_paths = {
        "all": fs_path("/proc/sys/net/ipv4/conf/all/send_redirects"),
        "default": fs_path("/proc/sys/net/ipv4/conf/default/send_redirects"),
        lan_if: fs_path(f"/proc/sys/net/ipv4/conf/{lan_if}/send_redirects"),
    }
    redirect_values = {name: int_file(path, -1) for name, path in redirect_paths.items()}
    send_redirects_ok = all(value == 0 for value in redirect_values.values())
    add_check(
        checks,
        "routeros-send-redirects",
        send_redirects_ok,
        "critical",
        " ".join(f"{name}={value}" for name, value in redirect_values.items()),
        "run sysctl --system; RouterOS-policy mode must not redirect clients away from symmetric forwarding",
        core=True,
    )

default_domains = ["example.com", "cloudflare.com", "google.com", "youtube.com", "openai.com"]
dns_latencies = []
dns_success = 0
for domain in default_domains:
    ok, _lines, ms = dig_query(domain, "A", "53")
    dns_latencies.append(ms)
    dns_success += 1 if ok else 0
dns_p50 = statistics.median(dns_latencies) if dns_latencies else 0.0
dns_p95 = sorted(dns_latencies)[min(len(dns_latencies) - 1, int(len(dns_latencies) * 0.95))] if dns_latencies else 0.0
dns_success_ratio = dns_success / max(1, len(default_domains))
add_check(checks, "dns-success-ratio", dns_success_ratio >= 0.98, "warning", f"success_ratio={dns_success_ratio:.2f}", "check AdGuard, SmartDNS, and upstream DNS", value=round(dns_success_ratio, 4))
add_check(checks, "dns-p95-latency", dns_p95 < 500, "warning", f"p95={dns_p95:.1f}ms", "inspect SmartDNS upstream latency and cache health", value=round(dns_p95, 2))

nft_ages = {}
for profile, set_name, freshness_name in [("ai", "ai4", "nftset-ai-freshness"), ("cn", "cn4", "nftset-cn-freshness")]:
    count = nft_count(set_name)
    age = file_age(f"/var/lib/dnscomplex/nftset-{profile}.last_refresh")
    nft_ages[profile] = age
    add_check(checks, f"nftset-{profile}-count", count > 0, "warning", f"{set_name} entries={count}", "run dnscomplex refresh-nftsets", value=count)
    stale = age is not None and age <= 7200
    add_check(checks, freshness_name, stale, "warning", f"last_refresh_age_seconds={age}", "run dnscomplex refresh-nftsets and check timer", value=-1 if age is None else age)

sas_proc = run(["swanctl", "--list-sas"], 8)
sas = sas_proc.stdout if sas_proc.returncode == 0 else ""
rules_proc = run(["ip", "rule", "show"], 5)
rules = rules_proc.stdout if rules_proc.returncode == 0 else ""
ipsec_ok = True
for profile in ["ai", "cn"]:
    mode = cfg.get(f"{profile.upper()}_EGRESS_MODE", "ipsec")
    if mode == "ipsec":
        if profile == "ai":
            mark = cfg.get("AI_MARK", "0x301")
            table = cfg.get("AI_TABLE", "301")
            priority = "10301"
        else:
            mark = cfg.get("CN_MARK", "0x351")
            table = cfg.get("CN_TABLE", "351")
            priority = "10351"
        state = ipsec_runtime_state(
            sas, rules, profile, mark, table, priority
        )
        ok = state["ok"]
        ipsec_ok = ipsec_ok and ok
        detail = (
            f"ike_established={state['ike_established']} "
            f"child_installed={state['child_installed']} "
            f"vip_valid={state['vip_valid']} "
            f"vip={state['ready_vip'] or 'none'} "
            f"interface_up={state['interface_up']} "
            f"policy_rule={state['policy_rule']} "
            f"route_source_matches={state['route_source_matches']}"
        )
        add_check(checks, f"{profile}-ipsec-selected-egress", ok, "critical", detail, "run dnscomplex test-ipsec; inspect local UDP 500/4500 underlay/firewall before updating IPsec credentials", core=True)
        probe_path = os.path.join(
            os.environ.get("DNSCOMPLEX_HEALTH_RUN_DIR", "/run/dnscomplex"),
            f"profile-dataplane-{profile}.success",
        )
        probe_vip = ""
        probe_identity = ""
        probe_count = 0
        probe_age = None
        try:
            stat = os.stat(probe_path, follow_symlinks=False)
            if not os.path.isfile(probe_path) or os.path.islink(probe_path):
                raise OSError("not a regular proof file")
            with open(probe_path, "r", encoding="ascii") as proof_fh:
                fields = proof_fh.read(256).strip().split()
            if len(fields) != 3:
                raise ValueError("invalid proof shape")
            probe_vip, probe_identity, count_text = fields
            probe_count = int(count_text)
            probe_age = max(0, int(time.time() - stat.st_mtime))
        except (OSError, UnicodeError, ValueError):
            probe_vip = ""
        gate_open = False
        gate_proc = run(["nft", "-j", "list", "set", "inet", "dnscomplex", f"{profile}_ready4"], 3)
        try:
            gate_json = json.loads(gate_proc.stdout) if gate_proc.returncode == 0 else {}
            for entry in gate_json.get("nftables", []):
                gate_set = entry.get("set", {})
                if (gate_set.get("family") == "inet" and
                    gate_set.get("table") == "dnscomplex" and
                    gate_set.get("name") == f"{profile}_ready4" and
                    gate_set.get("type") == "ipv4_addr"):
                    gate_open = any(
                        isinstance(element, dict) and
                        element.get("prefix", {}).get("addr") == "0.0.0.0" and
                        element.get("prefix", {}).get("len") == 0
                        for element in gate_set.get("elem", [])
                    )
                    break
        except (json.JSONDecodeError, TypeError, AttributeError):
            gate_open = False
        proof_fresh = (
            bool(probe_vip) and probe_vip == state["ready_vip"] and
            probe_identity == profile_dataplane_identity(profile, state["ready_vip"], sas) and
            probe_count >= 2 and probe_age is not None and probe_age <= 180
        )
        if not probe_vip:
            proof_state = "missing"
        elif not proof_fresh:
            proof_state = "stale"
        else:
            proof_state = "cached"
        probe_ok = proof_fresh and gate_open
        probe_detail = (
            f"proof={proof_state} gate={'open' if gate_open else 'closed'} "
            f"age_seconds={probe_age if probe_age is not None else 'unknown'} "
            f"successes={probe_count} vip={probe_vip or 'none'}"
        )
        add_check(
            checks,
            f"{profile}-ipsec-dataplane-probe",
            probe_ok,
            "warning" if gate_open else "critical",
            probe_detail,
            "run dnscomplex watchdog; dataplane proof must be fresh and the profile readiness gate open",
            core=not gate_open,
        )
    elif mode == "xray":
        ok = service_active("xray-dnscomplex.service")
        add_check(checks, f"{profile}-xray-selected-egress", ok, "critical", f"{profile} Xray selected and service up={ok}", f"dnscomplex test-xray {profile}", core=True)

ipv4_targets = ["93.184.216.34", "104.16.132.229"]
ipv4_reachable = next(
    (host for host in ipv4_targets if tcp_connectivity(host, socket.AF_INET)),
    None,
)
add_check(
    checks,
    "default-ipv4-connectivity",
    ipv4_reachable is not None,
    "critical",
    f"TCP/443 reachable={ipv4_reachable is not None} target={ipv4_reachable or ','.join(ipv4_targets)}",
    "check RouterOS/default IPv4 route, firewall, and upstream Internet connectivity",
    core=True,
)

ipv6_mode = cfg.get("DEFAULT_IPV6_MODE", "auto")
if ipv6_mode == "off":
    add_check(checks, "default-ipv6-connectivity", True, "info", "DEFAULT_IPV6_MODE=off", "enable default IPv6 only when RouterOS/default path supports it")
else:
    ipv6_targets = [
        "2606:2800:220:1:248:1893:25c8:1946",
        "2606:4700::6810:84e5",
    ]
    ipv6_reachable = next(
        (host for host in ipv6_targets if tcp_connectivity(host, socket.AF_INET6)),
        None,
    )
    add_check(
        checks,
        "default-ipv6-connectivity",
        ipv6_reachable is not None,
        "warning",
        f"TCP/443 reachable={ipv6_reachable is not None} target={ipv6_reachable or ','.join(ipv6_targets)}",
        "check RouterOS RA/default IPv6 route, firewall, and upstream Internet connectivity",
    )

ct_count = int_file("/proc/sys/net/netfilter/nf_conntrack_count")
ct_max = max(int_file("/proc/sys/net/netfilter/nf_conntrack_max", 1), 1)
ct_pct = round((ct_count / ct_max) * 100, 2)
add_check(checks, "conntrack-capacity", ct_pct < 85, "critical" if ct_pct >= 85 else "warning", f"conntrack={ct_count}/{ct_max} ({ct_pct:.2f}%)", "increase conntrack capacity or reduce stale flows", core=ct_pct >= 85, value=ct_pct)

disk = shutil.disk_usage("/")
disk_pct = round((disk.used / disk.total) * 100, 2)
mem_pct = memory_usage_percent()
add_check(checks, "disk-root-usage", disk_pct < 90, "warning", f"root disk usage={disk_pct:.2f}%", "clean logs/backups or expand disk", value=disk_pct)
add_check(checks, "memory-usage", mem_pct < 90, "warning", f"memory usage={mem_pct:.2f}%", "inspect service memory and VM sizing", value=mem_pct)

failed_units = run(["systemctl", "--failed", "--plain", "--no-legend"], 5).stdout.strip().splitlines()
dnscomplex_failed = [line.split()[0] for line in failed_units if line and line.split()[0].startswith(("dnscomplex", "sing-box", "smartdns", "AdGuardHome", "strongswan", "nftables", "xray"))]
add_check(checks, "failed-systemd-units", not dnscomplex_failed, "warning", "failed_units=" + ",".join(dnscomplex_failed), "systemctl reset-failed; dnscomplex doctor", value=len(dnscomplex_failed))

for item in checks:
    if item["status"] != "ok":
        warned = True
        failure_reasons.append(f"{item['name']}: {item['detail']}")
        if item["recommended_action"] not in recommended_actions:
            recommended_actions.append(item["recommended_action"])
        if item["core"] and item["severity"] == "critical":
            core_failed = True

status = "unhealthy" if core_failed else ("degraded" if warned else "healthy")
result = {
    "status": status,
    "services": services,
    "dns_latency_ms": round(dns_p50, 2),
    "dns_latency_p95_ms": round(dns_p95, 2),
    "dns_success_ratio": round(dns_success_ratio, 4),
    "conntrack_usage_percent": ct_pct,
    "adguard_cache_ok": adguard_cache_ok,
    "ipsec_ok": ipsec_ok,
    "ha_mode": cfg.get("HA_MODE", "single"),
    "ha_primary_ip": cfg.get("HA_PRIMARY_IP", ""),
    "ha_secondary_ip": cfg.get("HA_SECONDARY_IP", ""),
    "checks": checks,
    "failure_reasons": failure_reasons,
    "recommended_actions": recommended_actions,
    "nftset_age_seconds": nft_ages,
    "disk_usage_percent": disk_pct,
    "memory_usage_percent": mem_pct,
}
print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
PY
}

health_json_cmd() {
  local output status
  output=$(health_checks_json)
  printf '%s\n' "$output"
  status=$(printf '%s\n' "$output" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","unhealthy"))' 2>/dev/null || printf unhealthy)
  [[ "$status" != "unhealthy" ]]
}

smartdns_probe() {
  local domain=$1 port=$2 timeout_seconds=${3:-2}
  if ((WATCHDOG_DEADLINE_MS > 0)); then
    watchdog_capture "$timeout_seconds" dig "+time=${timeout_seconds}" +tries=1 +short A \
      "$domain" @127.0.0.1 -p "$port" 2>/dev/null |
      watchdog_backend_call 2 grep -Eq '^[0-9]+([.][0-9]+){3}$'
    return $?
  fi
  timeout --signal=TERM --kill-after=0.5s "${timeout_seconds}s" \
    dig "+time=${timeout_seconds}" +tries=1 +short A "$domain" @127.0.0.1 -p "$port" 2>/dev/null |
    grep -Eq '^[0-9]+([.][0-9]+){3}$'
}

smartdns_listener_round() {
  local deadline_ms=${1:-0} now remaining_ms probe_timeout=2 temp="" success=0 pid
  local -a pids=()
  if ((deadline_ms > 0)); then
    now=$(monotonic_millis)
    ((now < deadline_ms)) || return 2
    remaining_ms=$((deadline_ms - now))
    # A one-second probe may need another half-second for timeout escalation.
    # Do not launch a round unless the deadline still has scheduling margin.
    ((remaining_ms >= 2500)) || return 2
    probe_timeout=1
  fi

  if ! temp=$(mktemp -d "$RUN_DIR/.smartdns-probe.XXXXXX"); then
    warn "could not allocate SmartDNS probe state"
    return 3
  fi
  (
    if smartdns_probe example.com "$SMARTDNS_DEFAULT_PORT" "$probe_timeout"; then
      printf 'ok\n' >"$temp/default"
    else
      printf 'failed\n' >"$temp/default"
    fi
  ) &
  pids+=("$!")
  (
    if smartdns_probe openai.com "$SMARTDNS_AI_PORT" "$probe_timeout"; then
      printf 'ok\n' >"$temp/ai"
    else
      printf 'failed\n' >"$temp/ai"
    fi
  ) &
  pids+=("$!")
  (
    if smartdns_probe youku.com "$SMARTDNS_CN_PORT" "$probe_timeout"; then
      printf 'ok\n' >"$temp/cn"
    else
      printf 'failed\n' >"$temp/cn"
    fi
  ) &
  pids+=("$!")

  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  for profile in default ai cn; do
    [[ -r "$temp/$profile" ]] && grep -Fxq ok "$temp/$profile" && success=$((success + 1))
  done
  rm -rf "$temp"
  case "$success" in
    3) return 0 ;;
    0) return 2 ;;
    *) return 1 ;;
  esac
}

direct_dns_available() {
  local server
  for server in 1.1.1.1 223.5.5.5; do
    if ((WATCHDOG_DEADLINE_MS > 0)); then
      if watchdog_capture 2 dig +time=2 +tries=1 +short A example.com "@$server" 2>/dev/null |
          watchdog_backend_call 2 grep -Eq '^[0-9]+([.][0-9]+){3}$'; then
        return 0
      fi
    elif dig +time=2 +tries=1 +short A example.com "@$server" 2>/dev/null |
        grep -Eq '^[0-9]+([.][0-9]+){3}$'; then
      return 0
    fi
  done
  return 1
}

wait_smartdns_listeners() {
  local deadline_ms now result
  # Leave half a second for scheduler jitter while enforcing a 15-second
  # external bound from the completed systemctl restart.
  deadline_ms=$(( $(monotonic_millis) + 14500 ))
  if ((WATCHDOG_DEADLINE_MS > 0 && WATCHDOG_DEADLINE_MS < deadline_ms)); then
    deadline_ms=$WATCHDOG_DEADLINE_MS
  fi
  while :; do
    now=$(monotonic_millis)
    ((deadline_ms - now >= 2500)) || break
    if smartdns_listener_round "$deadline_ms"; then
      return 0
    else
      result=$?
    fi
    [[ "$result" != "3" ]] || return 1
    sleep 0.05
  done
  return 1
}

monotonic_millis() {
  if ((WATCHDOG_DEADLINE_MS > 0)); then
    timeout --signal=TERM --kill-after=0.5s 1s \
      python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)'
  else
    python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)'
  fi
}

WATCHDOG_DEADLINE_MS=0
WATCHDOG_HARD_DEADLINE_MS=0
WATCHDOG_FAILCLOSED=0
WATCHDOG_PROFILE_PROBE_FAILED=0

watchdog_backend_call() {
  local maximum=$1
  shift
  if ((WATCHDOG_DEADLINE_MS > 0)); then
    watchdog_capture "$maximum" "$@"
  else
    command "$@"
  fi
}

# These wrappers are inert outside watchdog execution. During watchdog
# execution, each backend command inherits the shared monotonic deadline.
systemctl() { watchdog_backend_call 5 systemctl "$@"; }
ip() { watchdog_backend_call 3 ip "$@"; }
nft() { watchdog_backend_call 3 nft "$@"; }
jq() { watchdog_backend_call 2 jq "$@"; }
sing-box() { watchdog_backend_call 5 sing-box "$@"; }
swanctl() { watchdog_backend_call 5 swanctl "$@"; }
dig() { watchdog_backend_call 3 dig "$@"; }
python3() { watchdog_backend_call 2 python3 "$@"; }
date() { watchdog_backend_call 2 date "$@"; }
sleep() { watchdog_backend_call 2 sleep "$@"; }

watchdog_budget_start() {
  local now
  now=$(monotonic_millis) || return 1
  # Keep five seconds in reserve for gate closure, logs, and clean exit before
  # dnscomplex-health.service reaches its 45-second systemd deadline.
  WATCHDOG_DEADLINE_MS=$((now + 40000))
  WATCHDOG_HARD_DEADLINE_MS=$((now + 44500))
  WATCHDOG_FAILCLOSED=0
  WATCHDOG_PROFILE_PROBE_FAILED=0
}

watchdog_timeout_value() {
  local maximum=$1 now remaining_ms allowed_ms deadline
  [[ "$maximum" =~ ^[1-9][0-9]*$ ]] || return 1
  if ((WATCHDOG_DEADLINE_MS <= 0)); then
    printf '%s.000\n' "$maximum"
    return 0
  fi
  now=$(monotonic_millis) || return 1
  deadline=$WATCHDOG_DEADLINE_MS
  if ((WATCHDOG_FAILCLOSED == 1 && WATCHDOG_HARD_DEADLINE_MS > 0)); then
    deadline=$WATCHDOG_HARD_DEADLINE_MS
  fi
  remaining_ms=$((deadline - now - 750))
  ((remaining_ms > 0)) || return 1
  allowed_ms=$((maximum * 1000))
  ((remaining_ms < allowed_ms)) && allowed_ms=$remaining_ms
  printf '%d.%03d\n' "$((allowed_ms / 1000))" "$((allowed_ms % 1000))"
}

watchdog_capture() {
  local maximum=$1 timeout_value
  shift
  timeout_value=$(watchdog_timeout_value "$maximum") || return 124
  timeout --signal=TERM --kill-after=0.5s "${timeout_value}s" "$@"
}

watchdog_run() {
  watchdog_capture "$@"
}

watchdog_unit_activity() {
  local unit=$1 state rc
  if state=$(watchdog_capture 3 systemctl is-active "$unit" 2>/dev/null); then
    rc=0
  else
    rc=$?
  fi
  if [[ "$rc" == 0 && "$state" == active ]]; then
    return 0
  fi
  if [[ "$rc" == 3 && ( "$state" == inactive || "$state" == failed ) ]]; then
    return 1
  fi
  warn "$unit activity state is unknown (status=$rc state=${state:-empty})"
  return 2
}

watchdog_fail_closed() {
  local profile set4 set6 batch="" sets_json="[]" live cleanup_failed=0
  local -a evidence_paths=()
  WATCHDOG_FAILCLOSED=1
  for profile in ai cn; do
    profile_uses_ipsec "$profile" || continue
    IFS=' ' read -r set4 set6 < <(profile_egress_gate_set "$profile") || return 1
    batch+="flush set inet dnscomplex $set4"$'\n'
    batch+="flush set inet dnscomplex $set6"$'\n'
    evidence_paths+=("$(profile_dataplane_success_path "$profile")")
    case "$sets_json" in
      '[]') sets_json="[\"$set4\",\"$set6\"]" ;;
      *) sets_json="${sets_json%]},\"$set4\",\"$set6\"]" ;;
    esac
  done
  [[ -n "$batch" ]] || return 0
  if ! watchdog_run 2 nft -f - <<<"$batch"; then
    warn "watchdog fail-closed nft batch failed"
    return 1
  fi
  if ! watchdog_capture 1 rm -f -- "${evidence_paths[@]}"; then
    warn "watchdog could not invalidate profile dataplane success evidence"
    cleanup_failed=1
  fi
  if ! live=$(watchdog_capture 1 nft -j list table inet dnscomplex); then
    warn "watchdog could not read back the fail-closed nft table"
    return 1
  fi
  if ! watchdog_capture 1 jq -e --argjson sets "$sets_json" '
    .nftables as $entries |
    all($sets[];
      . as $name |
      any($entries[]?;
        (.set? // {}) as $set |
        $set.family == "inet" and $set.table == "dnscomplex" and
        $set.name == $name and (($set.elem // []) | length) == 0))
  ' <<<"$live" >/dev/null; then
    warn "watchdog fail-closed readiness gate readback failed"
    return 1
  fi
  [[ "$cleanup_failed" == 0 ]]
}

read_smartdns_restart_epoch() {
  local value=""
  REPLY=0
  [[ -r "$RUN_DIR/smartdns.last_restart" ]] || return 0
  IFS= read -r value <"$RUN_DIR/smartdns.last_restart" || value=""
  if [[ ! "$value" =~ ^[0-9]{1,10}$ ]]; then
    warn "ignoring invalid SmartDNS restart timestamp"
    return 0
  fi
  REPLY=$((10#$value))
}

write_smartdns_restart_epoch() {
  local timestamp=$1
  (
    local temp=""
    cleanup_restart_epoch_temp() {
      [[ -z "$temp" ]] || rm -f -- "$temp"
    }
    trap cleanup_restart_epoch_temp EXIT HUP INT TERM
    umask 077
    temp=$(mktemp "$RUN_DIR/.smartdns.last_restart.XXXXXX") || return 1
    printf '%s\n' "$timestamp" >"$temp" || return 1
    chmod 0600 "$temp" || return 1
    mv -f "$temp" "$RUN_DIR/smartdns.last_restart" || return 1
    temp=""
  )
}

ipsec_child_established() {
  local child=$1 sas
  if ! sas=$(watchdog_capture 5 swanctl --list-sas 2>/dev/null); then
    return 2
  fi
  ipsec_vip_from_sas "$child" <<<"$sas" >/dev/null
}

ipsec_retry_state_path() {
  printf '%s/ipsec-%s.retry\n' "$RUN_DIR" "$1"
}

read_ipsec_retry_state() {
  local profile=$1 path attempts="" next=""
  IPSEC_RETRY_ATTEMPTS=0
  IPSEC_RETRY_NEXT=0
  path=$(ipsec_retry_state_path "$profile")
  [[ -r "$path" ]] || return 0
  IFS=' ' read -r attempts next <"$path" || true
  if [[ ! "$attempts" =~ ^[0-9]{1,3}$ || ! "$next" =~ ^[0-9]{1,12}$ ]]; then
    warn "discarding invalid $profile IPsec retry state"
    rm -f -- "$path"
    return 0
  fi
  IPSEC_RETRY_ATTEMPTS=$((10#$attempts))
  IPSEC_RETRY_NEXT=$((10#$next))
}

ipsec_retry_due() {
  local profile=$1 now
  read_ipsec_retry_state "$profile"
  now=$(date +%s)
  ((IPSEC_RETRY_NEXT <= now))
}

record_ipsec_retry_failure() {
  local profile=$1 now attempts delay next path temp
  read_ipsec_retry_state "$profile"
  attempts=$((IPSEC_RETRY_ATTEMPTS + 1))
  ((attempts > 99)) && attempts=99
  case "$attempts" in
    1) delay=60 ;;
    2) delay=120 ;;
    3) delay=300 ;;
    4) delay=600 ;;
    *) delay=900 ;;
  esac
  now=$(date +%s)
  next=$((now + delay))
  path=$(ipsec_retry_state_path "$profile")
  temp=$(mktemp "$RUN_DIR/.ipsec-${profile}.retry.XXXXXX") || return 1
  printf '%s %s\n' "$attempts" "$next" >"$temp" || {
    rm -f -- "$temp"
    return 1
  }
  chmod 0600 "$temp"
  mv -f "$temp" "$path"
  warn "$profile IPsec retry deferred for ${delay}s after attempt $attempts"
}

clear_ipsec_retry_state() {
  rm -f -- "$(ipsec_retry_state_path "$1")"
}

ipsec_connection_loaded() {
  local child=$1 connections
  if ! connections=$(watchdog_capture 5 swanctl --list-conns 2>/dev/null); then
    return 2
  fi
  grep -Eq "^${child}:([[:space:]]|$)" <<<"$connections"
}

repair_ipsec_children_if_needed() {
  command -v swanctl >/dev/null 2>&1 || return 0
  local child mode connection_status config_loaded=0 failed=0 sa_status
  IPSEC_CHILDREN_REPAIRED=0
  for child in ai cn; do
    case "$child" in
      ai) mode=${AI_EGRESS_MODE:-ipsec} ;;
      cn) mode=${CN_EGRESS_MODE:-ipsec} ;;
    esac
    if [[ "$mode" != "ipsec" ]]; then
      clear_ipsec_retry_state "$child"
      continue
    fi
    if ipsec_child_established "$child"; then
      clear_ipsec_retry_state "$child"
      continue
    else
      sa_status=$?
    fi
    if [[ "$sa_status" == 2 ]]; then
      warn "StrongSwan state could not be queried while repairing $child IPsec"
      clear_selected_ipsec_egress_gates || return 1
      failed=1
    fi

    if ! profile_egress_gate_clear "$child"; then
      warn "$child egress gate could not be closed before IPsec repair"
      failed=1
      continue
    fi
    ipsec_retry_due "$child" || continue

    if ipsec_connection_loaded "$child"; then
      connection_status=0
    else
      connection_status=$?
    fi
    if [[ "$connection_status" == "2" ]]; then
      warn "strongSwan connection state could not be queried"
      return 1
    fi
    if [[ "$connection_status" == "1" && "$config_loaded" == "0" ]]; then
      if ! watchdog_run 10 swanctl --load-all --noprompt >/dev/null 2>&1; then
        warn "strongSwan configuration could not be reloaded"
        return 1
      fi
      config_loaded=1
    fi

    if ! watchdog_run 15 swanctl --initiate --child "$child" >/dev/null 2>&1; then
      warn "$child IPsec peer did not accept an initiation request"
      record_ipsec_retry_failure "$child" || return 1
      continue
    fi
    if ipsec_child_established "$child"; then
      clear_ipsec_retry_state "$child"
      IPSEC_CHILDREN_REPAIRED=1
    else
      sa_status=$?
      if [[ "$sa_status" == 2 ]]; then
        warn "StrongSwan state could not be queried while verifying $child IPsec"
        clear_selected_ipsec_egress_gates || return 1
        failed=1
      fi
      warn "$child IPsec child did not become installed with a virtual IPv4"
      record_ipsec_retry_failure "$child" || return 1
      continue
    fi
  done
  return "$failed"
}

repair_policy_routes_if_needed() {
  if ((WATCHDOG_DEADLINE_MS > 0)); then
    type -P ip >/dev/null 2>&1 || {
      warn "iproute2 is unavailable while reconciling policy routes"
      return 1
    }
  else
    command -v ip >/dev/null 2>&1 || return 0
  fi
  local profile mode mark table priority device vip sas fresh_sas failed=0 alias_state_rc
  local probe_rc local_probe_failed=0
  local has_ipsec=0
  local route_matches nat_matches alias_nat_matches bind_matches probe_vip_matches drift
  if ! ip rule show >/dev/null 2>&1; then
    warn "policy routes could not be inspected"
    return 1
  fi
  for profile in ai cn; do
    if profile_uses_ipsec "$profile"; then
      has_ipsec=1
    fi
  done
  sas=""
  if [[ "$has_ipsec" == 1 ]]; then
    if ! sas=$(watchdog_capture 8 swanctl --list-sas 2>/dev/null); then
      warn "StrongSwan state could not be inspected while reconciling routes"
      clear_selected_ipsec_egress_gates || true
      for profile in ai cn; do
        profile_uses_ipsec "$profile" || continue
        profile_dataplane_clear_evidence "$profile"
        sync_ipsec_probe_vip_profile "$profile" "" || true
      done
      return 1
    fi
  fi

  # Close every IPsec gate that will need repair before changing either
  # profile's shared sing-box configuration or restarting sing-box.
  for profile in ai cn; do
    case "$profile" in
      ai)
        mode=${AI_EGRESS_MODE:-ipsec}
        mark=$AI_MARK
        table=$AI_TABLE
        priority=10301
        device=ipsec-ai
        ;;
      cn)
        mode=${CN_EGRESS_MODE:-ipsec}
        mark=$CN_MARK
        table=$CN_TABLE
        priority=10351
        device=ipsec-cn
        ;;
    esac
    [[ "$mode" == ipsec ]] || continue
    if ! ipsec_profile_sa_ready "$profile" "$sas"; then
      profile_egress_gate_clear "$profile" || {
        warn "$profile egress gate could not be closed while IPsec was not ready"
        failed=1
      }
      profile_dataplane_clear_evidence "$profile"
      sync_ipsec_probe_vip_profile "$profile" "" || failed=1
      continue
    fi
    vip=$IPSEC_STATE_READY_VIP
    route_matches=1
    if ! ipsec_policy_rule_present "$mark" "$table" "$priority" ||
       ! ipsec_probe_policy_rule_present "$profile" ||
       ! ipsec_policy_route_matches "$table" "$device" "$vip"; then
      route_matches=0
    fi
    nat_matches=0
    ipsec_nat_profile_matches "$profile" "$vip" && nat_matches=1
    probe_vip_matches=0
    ipsec_probe_vip_set_matches "$profile" "$vip" && probe_vip_matches=1
    alias_nat_matches=1
    if lan_alias_nat_state_status; then
      alias_nat_matches=0
      ipsec_alias_nat_profile_matches "$profile" "$vip" && alias_nat_matches=1
    else
      alias_state_rc=$?
      if [[ "$alias_state_rc" == 2 ]]; then
        warn "$profile LAN alias ownership state is invalid"
        profile_egress_gate_clear "$profile" || warn "$profile egress gate could not be closed for invalid LAN alias state"
        failed=1
        continue
      fi
    fi
    bind_matches=0
    ipsec_bind_profile_matches "$profile" "$vip" && bind_matches=1
    if [[ "$route_matches" != 1 || "$nat_matches" != 1 ||
          "$alias_nat_matches" != 1 || "$bind_matches" != 1 ||
          "$probe_vip_matches" != 1 ]]; then
      profile_egress_gate_clear "$profile" || {
        warn "$profile egress gate could not be closed before IPsec reconciliation"
        failed=1
      }
    fi
  done
  if [[ "$failed" != 0 ]]; then
    return 1
  fi

  for profile in ai cn; do
    case "$profile" in
      ai)
        mode=${AI_EGRESS_MODE:-ipsec}
        mark=$AI_MARK
        table=$AI_TABLE
        priority=10301
        device=ipsec-ai
        ;;
      cn)
        mode=${CN_EGRESS_MODE:-ipsec}
        mark=$CN_MARK
        table=$CN_TABLE
        priority=10351
        device=ipsec-cn
        ;;
    esac
    if [[ "$mode" == "xray" ]]; then
      profile_dataplane_clear_evidence "$profile"
      if systemctl is-active --quiet xray-dnscomplex; then
        profile_egress_gate_is_open "$profile" || profile_egress_gate_open "$profile" || failed=1
      else
        profile_egress_gate_clear "$profile"
        failed=1
      fi
      continue
    fi
    if ! ipsec_profile_sa_ready "$profile" "$sas"; then
      profile_egress_gate_clear "$profile" || {
        warn "$profile egress gate could not be closed while IPsec was not ready"
        failed=1
        continue
      }
      profile_dataplane_clear_evidence "$profile"
      sync_ipsec_probe_vip_profile "$profile" "" || failed=1
      if [[ -z "$(ipsec_vip "$profile" || true)" ]]; then
        sync_ipsec_nat_profile "$profile" || failed=1
      fi
      continue
    fi
    vip=$IPSEC_STATE_READY_VIP
    route_matches=1
    if ! ipsec_policy_rule_present "$mark" "$table" "$priority" ||
       ! ipsec_probe_policy_rule_present "$profile" ||
       ! ipsec_policy_route_matches "$table" "$device" "$vip"; then
      route_matches=0
    fi
    nat_matches=0
    ipsec_nat_profile_matches "$profile" "$vip" && nat_matches=1
    probe_vip_matches=0
    ipsec_probe_vip_set_matches "$profile" "$vip" && probe_vip_matches=1
    alias_nat_matches=1
    if lan_alias_nat_state_status; then
      alias_nat_matches=0
      ipsec_alias_nat_profile_matches "$profile" "$vip" && alias_nat_matches=1
    else
      alias_state_rc=$?
      if [[ "$alias_state_rc" == 2 ]]; then
        warn "$profile LAN alias ownership state is invalid"
        profile_egress_gate_clear "$profile" || warn "$profile egress gate could not be closed for invalid LAN alias state"
        failed=1
        continue
      fi
    fi
    bind_matches=0
    ipsec_bind_profile_matches "$profile" "$vip" && bind_matches=1
    drift=0
    [[ "$route_matches" == 1 && "$nat_matches" == 1 &&
       "$alias_nat_matches" == 1 && "$bind_matches" == 1 &&
       "$probe_vip_matches" == 1 ]] || drift=1

    if [[ "$drift" == 1 ]]; then
      profile_egress_gate_clear "$profile" || {
        warn "$profile egress gate could not be closed before IPsec reconciliation"
        failed=1
        continue
      }
    fi
    if [[ "$route_matches" == 0 ]]; then
      if ! ensure_policy_route_profile "$profile" ||
         ! ipsec_policy_rule_present "$mark" "$table" "$priority" ||
         ! ipsec_policy_route_matches "$table" "$device" "$vip"; then
        warn "$profile policy route is missing and could not be repaired"
        failed=1
        continue
      fi
    fi
    if [[ "$nat_matches" == 0 ]]; then
      sync_ipsec_nat_profile "$profile" || {
        failed=1
        continue
      }
    fi
    if [[ "$alias_nat_matches" == 0 ]]; then
      sync_ipsec_alias_nat_profile "$profile" "$vip" || {
        warn "$profile LAN alias SNAT could not be reconciled"
        failed=1
        continue
      }
    fi
    if [[ "$probe_vip_matches" == 0 ]]; then
      sync_ipsec_probe_vip_profile "$profile" "$vip" || {
        warn "$profile dataplane probe VIP set could not be reconciled"
        failed=1
        continue
      }
    fi
    if [[ "$bind_matches" == 0 ]]; then
      sync_singbox_ipsec_bind_addresses "$profile" || {
        failed=1
        continue
      }
    fi
    if lan_alias_nat_state_status; then
      alias_state_rc=0
    else
      alias_state_rc=$?
    fi
    if [[ "$alias_state_rc" == 2 ]]; then
      warn "$profile LAN alias ownership state became invalid during IPsec reconciliation"
      profile_egress_gate_clear "$profile" || warn "$profile egress gate could not be closed for invalid LAN alias state"
      failed=1
      continue
    fi
    if ! ipsec_policy_rule_present "$mark" "$table" "$priority" ||
       ! ipsec_probe_policy_rule_present "$profile" ||
       ! ipsec_policy_route_matches "$table" "$device" "$vip" ||
       ! ipsec_probe_vip_set_matches "$profile" "$vip" ||
       ! ipsec_nat_profile_matches "$profile" "$vip" ||
       { [[ "$alias_state_rc" == 0 ]] && ! ipsec_alias_nat_profile_matches "$profile" "$vip"; } ||
       ! ipsec_bind_profile_matches "$profile" "$vip"; then
      warn "$profile IPsec route, SNAT, LAN alias SNAT, or sing-box bind address failed verification"
      failed=1
      continue
    fi
    if ! fresh_sas=$(watchdog_capture 8 swanctl --list-sas 2>/dev/null); then
      profile_egress_gate_clear "$profile" ||
        warn "$profile egress gate could not be closed after a failed SA recheck"
      warn "$profile IPsec SA state could not be rechecked before opening its gate"
      failed=1
      continue
    fi
    if ! ipsec_profile_sa_ready "$profile" "$fresh_sas" ||
       [[ "$IPSEC_STATE_READY_VIP" != "$vip" ]]; then
      profile_egress_gate_clear "$profile" ||
        warn "$profile egress gate could not be closed after its VIP changed during reconciliation"
      warn "$profile IPsec VIP changed or became unavailable during reconciliation"
      failed=1
      continue
    fi
    if profile_dataplane_probe_observe "$profile" "$vip" "$fresh_sas"; then
      :
    else
      probe_rc=$?
      if [[ "$probe_rc" == 2 ]]; then
        local_probe_failed=1
      else
        failed=1
      fi
    fi
  done
  [[ "$failed" == 0 ]] || return 1
  [[ "$local_probe_failed" == 0 ]] || return 2
  return "$failed"
}

restart_watchdog_unit_if_inactive() {
  local unit=$1 state
  if watchdog_unit_activity "$unit"; then
    return 0
  else
    state=$?
  fi
  if [[ "$state" != 1 ]]; then
    return 1
  fi
  if ! watchdog_run 5 systemctl restart "$unit"; then
    warn "$unit is inactive and could not be restarted"
    return 1
  fi
}

watchdog_locked_body() {
  local unit now last first_round second_round route_rc
  for unit in nftables smartdns AdGuardHome sing-box; do
    restart_watchdog_unit_if_inactive "$unit" || return 1
  done
  if [[ "${XRAY_ENABLED:-1}" == "1" ]]; then
    restart_watchdog_unit_if_inactive xray-dnscomplex || return 1
  fi
  repair_ipsec_children_if_needed || return 1
  if repair_policy_routes_if_needed; then
    :
  else
    route_rc=$?
    if [[ "$route_rc" == 2 ]]; then
      WATCHDOG_PROFILE_PROBE_FAILED=1
    else
      return 1
    fi
  fi
  lan_alias_reconcile_cmd || return 1

  if smartdns_listener_round "$WATCHDOG_DEADLINE_MS"; then
    return 0
  else
    first_round=$?
  fi
  if [[ "$first_round" == "3" ]]; then
    warn "SmartDNS listener probes could not be initialized"
    return 1
  fi
  watchdog_run 2 sleep 2 || return 1
  if smartdns_listener_round "$WATCHDOG_DEADLINE_MS"; then
    return 0
  else
    second_round=$?
  fi
  if [[ "$second_round" == "3" ]]; then
    warn "SmartDNS listener probes could not be initialized"
    return 1
  fi
  if [[ "$first_round" != "2" || "$second_round" != "2" ]]; then
    warn "SmartDNS listeners are partially unavailable or changing state; skipping resolver restart"
    return 1
  fi
  if ! direct_dns_available; then
    warn "SmartDNS listeners and direct DNS positive controls are unavailable; external outage suspected"
    return 1
  fi

  now=$(date +%s)
  read_smartdns_restart_epoch
  last=$REPLY
  if ((last > now)); then
    warn "future SmartDNS restart timestamp clamped to the current time"
    last=$now
    write_smartdns_restart_epoch "$last" || return 1
  fi
  if ((now - last < 600)); then
    warn "SmartDNS remains unresponsive inside the 600-second restart cooldown"
    return 1
  fi

  write_smartdns_restart_epoch "$now" || return 1
  if ! watchdog_run 5 systemctl restart smartdns; then
    warn "SmartDNS restart command failed; retaining cooldown timestamp"
    return 1
  fi
  wait_smartdns_listeners || {
    warn "SmartDNS restart did not restore all listeners"
    return 1
  }
  if ! watchdog_run 3 systemctl start --no-block dnscomplex-nftset-refresh.service; then
    warn "DNS nftset refresh service could not be queued"
    return 1
  fi
}

watchdog_locked_cmd() {
  local rc
  if ! watchdog_budget_start; then
    warn "monotonic watchdog deadline could not be initialized"
    WATCHDOG_FAILCLOSED=1
    watchdog_fail_closed || warn "watchdog failed to prove egress gates closed"
    return 1
  fi
  if watchdog_locked_body; then
    # A known profile-local outage has already closed and verified its gates.
    # Other profiles completed reconciliation and all later checks passed.
    [[ "$WATCHDOG_PROFILE_PROBE_FAILED" == 0 ]] || return 1
    return 0
  else
    rc=$?
  fi
  watchdog_fail_closed || warn "watchdog failed to prove egress gates closed"
  return "$rc"
}

watchdog_cmd() {
  need_root
  local watchdog_lock old_umask rc
  mkdir -p "$RUN_DIR"
  command -v flock >/dev/null 2>&1 || die "flock is required for the SmartDNS watchdog"
  watchdog_lock="$RUN_DIR/smartdns-watchdog.lock"
  old_umask=$(umask)
  umask 077
  exec 9>"$watchdog_lock"
  umask "$old_umask"
  if ! flock -n 9; then
    warn "SmartDNS watchdog is already running; coalescing invocation"
    exec 9>&-
    return 0
  fi
  if ! acquire_maintenance_lock --skip-busy; then
    warn "another dnscomplex maintenance operation is already running; skipping watchdog"
    exec 9>&-
    return 0
  fi
  if watchdog_locked_cmd; then
    rc=0
  else
    rc=$?
  fi
  exec 9>&-
  return "$rc"
}

health_cmd() {
  if [[ "${1:-}" == "--json" ]]; then
    health_json_cmd
    return $?
  fi
  watchdog_cmd
}

atomic_publish_file_cmd() {
  local source=$1 target=$2 mode=$3 staged
  mkdir -p "$(dirname "$target")" || return $?
  staged=$(mktemp "$(dirname "$target")/.candidate.XXXXXX") || return $?
  install -m "$mode" "$source" "$staged" || { rm -f -- "$staged"; return 1; }
  mv -f -- "$staged" "$target" || { rm -f -- "$staged"; return 1; }
}

write_update_timer_cmd() (
  need_root || return $?
  [[ "$DNSCOMPLEX_UPDATE_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "DNSCOMPLEX_UPDATE_TIME must be HH:MM"
  local stage target
  stage=$(mktemp -d) || return $?
  # shellcheck disable=SC2064 # Capture private path before locals unwind.
  trap "rm -rf -- $(printf '%q' "$stage")" EXIT
  target=$(fs_path /etc/systemd/system/dnscomplex-update.timer) || return $?
  cat >"$stage/dnscomplex-update.timer" <<EOF
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
  systemd-analyze verify "$stage/dnscomplex-update.timer" || return $?
  atomic_publish_file_cmd "$stage/dnscomplex-update.timer" "$target" 0644 || return $?
  systemctl daemon-reload || return $?
  systemctl enable --now dnscomplex-update.timer || return $?
  systemctl restart dnscomplex-update.timer || return $?
  systemctl is-active --quiet dnscomplex-update.timer || return $?
  systemctl show --property=TimersCalendar --value dnscomplex-update.timer | grep -Fq -- "$DNSCOMPLEX_UPDATE_TIME:00" || return 1
  cmp -s "$stage/dnscomplex-update.timer" "$target"
)

set_update_time_candidate_cmd() {
  local expected=$1
  DNSCOMPLEX_UPDATE_TIME=$expected
  write_update_timer_cmd || return $?
  write_config_cmd || return $?
  unset DNSCOMPLEX_UPDATE_TIME
  load_config || return $?
  [[ "$DNSCOMPLEX_UPDATE_TIME" == "$expected" ]]
}

set_update_time_cmd() {
  need_root || return $?
  [[ $# -eq 1 && "$1" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "usage: dnscomplex set-update-time HH:MM"
  state_transaction_cmd set-update-time set_update_time_candidate_cmd "$1"
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

set_local_host_candidate_cmd() (
  local host=$1 ip=$2 tmp
  mkdir -p "$(dirname "$LOCAL_HOSTS")" || return $?
  tmp=$(mktemp "$(dirname "$LOCAL_HOSTS")/.hosts.XXXXXX") || return $?
  # shellcheck disable=SC2064 # Capture private path before locals unwind.
  trap "rm -f -- $(printf '%q' "$tmp")" EXIT
  if [[ -f "$LOCAL_HOSTS" ]]; then
    awk -v host="$host" 'tolower($2) != tolower(host)' "$LOCAL_HOSTS" >"$tmp" || return $?
  fi
  printf '%s %s\n' "$ip" "$host" >>"$tmp" || return $?
  # Entire candidate is data; malformed inherited entries must not be republished.
  python3 - "$tmp" <<'LOCAL_CANDIDATE' || return $?
import ipaddress,re,sys
for line in open(sys.argv[1]):
    if not line.strip() or line.lstrip().startswith('#'): continue
    fields=line.split()
    if len(fields)!=2 or not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.local',fields[1]): raise SystemExit('invalid local hosts candidate')
    ipaddress.IPv4Address(fields[0])
LOCAL_CANDIDATE
  atomic_publish_file_cmd "$tmp" "$LOCAL_HOSTS" 0644 || return $?
  restart_dns_stack || return $?
  cmp -s "$tmp" "$LOCAL_HOSTS" || return 1
  dig +time=2 +tries=1 +short A "$host" @127.0.0.1 -p 53 | grep -Fxq -- "$ip" || return 1
  log "local host override applied: $host -> $ip"
)

set_local_host_cmd() {
  need_root || return $?
  [[ $# -eq 2 ]] || die "usage: dnscomplex set-local-host HOST.local IPv4"
  local host=$1 ip=$2 normalized_host
  normalized_host=$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')
  valid_local_hostname "$host" || die "host must be a single valid .local DNS hostname"
  case "$normalized_host" in macbook-air.local|macbookair.local) die "MacBookAir .local addresses should follow mDNS or RouterOS DHCP/DNS, not dnscomplex static local-hosts" ;; esac
  valid_ipv4 "$ip" || die "IPv4 address required with octets in range 0-255"
  state_transaction_cmd set-local-host set_local_host_candidate_cmd "$host" "$ip"
}

test_local_name_cmd() {
  [[ $# -eq 1 ]] || die "usage: dnscomplex test-local-name HOST.local"
  local host=$1
  dig +time=2 +tries=1 "$host" @127.0.0.1 -p 53 A +noall +answer +authority || true
}

socks_runtime_ready_cmd() {
  local listen=$1 port=$2
  systemctl is-active --quiet sing-box || return $?
  python3 - "$listen" "$port" <<'SOCKS_READY'
import socket,sys,time
host=sys.argv[1]
if host in ('0.0.0.0','::'): host='::1' if ':' in host else '127.0.0.1'
for attempt in range(10):
    try:
        with socket.create_connection((host,int(sys.argv[2])),timeout=1) as stream:
            stream.settimeout(1); stream.sendall(b'\x05\x01\x00')
            if stream.recv(2)==b'\x05\x00': raise SystemExit(0)
    except OSError: pass
    time.sleep(.5)
raise SystemExit(1)
SOCKS_READY
}

set_socks_candidate_cmd() {
  local listen=$1 port=$2 candidate=$3 target=$4
  atomic_publish_file_cmd "$candidate" "$target" 0644 || return $?
  SINGBOX_SOCKS_LISTEN=$listen; SINGBOX_SOCKS_PORT=$port
  write_config_cmd || return $?
  systemctl restart sing-box || return $?
  socks_runtime_ready_cmd "$listen" "$port" || return $?
  unset SINGBOX_SOCKS_LISTEN SINGBOX_SOCKS_PORT
  load_config || return $?
  [[ "$SINGBOX_SOCKS_LISTEN" == "$listen" && "$SINGBOX_SOCKS_PORT" == "$port" ]] || return 1
  cmp -s "$candidate" "$target"
}

set_socks_cmd() (
  need_root || return $?
  [[ $# -eq 2 ]] || die "usage: dnscomplex set-socks LISTEN PORT"
  local listen=$1 port=$2 expected_listen target tmp
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || die "SOCKS port must be 1-65535"
  port=$((10#$port))
  python3 - "$listen" <<'SOCKS_ADDRESS' || return $?
import ipaddress,sys
ipaddress.ip_address(sys.argv[1])
SOCKS_ADDRESS
  if [[ "${DEPLOY_MODE:-}" == routeros-policy ]]; then
    expected_listen=${LINUX_LAN_IPV4:-}; expected_listen=${expected_listen%%/*}
    [[ -n "$expected_listen" && "$listen" == "$expected_listen" && "$port" == 10800 ]] || die "routeros-policy SOCKS requires LINUX_LAN_IPV4 and port 10800"
  fi
  target=$(fs_path /etc/sing-box/config.json) || return $?
  # Both persisted fields and rendered inbound must match for a true no-op.
  if [[ "$SINGBOX_SOCKS_LISTEN" == "$listen" && "$SINGBOX_SOCKS_PORT" == "$port" ]] &&
     jq -e --arg listen "$listen" --argjson port "$port" '[.inbounds[]? | select(.tag=="socks-in")] | length==1 and .[0].listen==$listen and .[0].listen_port==$port' "$target" >/dev/null; then return 0; fi
  tmp=$(mktemp) || return $?
  # shellcheck disable=SC2064 # Capture private path before locals unwind.
  trap "rm -f -- $(printf '%q' "$tmp")" EXIT
  jq --arg listen "$listen" --argjson port "$port" '(.inbounds[] | select(.tag=="socks-in") | .listen)=$listen | (.inbounds[] | select(.tag=="socks-in") | .listen_port)=$port' "$target" >"$tmp" || return $?
  jq -e --arg listen "$listen" --argjson port "$port" '[.inbounds[]? | select(.tag=="socks-in")] | length==1 and .[0].listen==$listen and .[0].listen_port==$port' "$tmp" >/dev/null || return 1
  sing-box check -c "$tmp" || return $?
  state_transaction_cmd set-socks set_socks_candidate_cmd "$listen" "$port" "$tmp" "$target"
)

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
    python3 -m json.tool "$file" >/dev/null || return $?
    warn "xray binary is not installed; only JSON syntax was validated"
  fi
}

render_xray_config_cmd() {
  need_root || return $?
  local tmp renderer target rc=0
  renderer=$(fs_path /usr/local/lib/dnscomplex-xray/render.py) || return $?
  target=$(fs_path /usr/local/etc/xray/config.json) || return $?
  [[ -x "$renderer" ]] || die "Xray renderer is missing"
  tmp=$(mktemp) || return $?
  "$renderer" --config "$CONFIG" --output "$tmp" || rc=$?
  if ((rc == 0)); then xray_test_config_file "$tmp" || rc=$?; fi
  if ((rc == 0)); then install -m 0600 "$tmp" "$target" || rc=$?; fi
  rm -f -- "$tmp"
  return "$rc"
}

lan_alias_helper_cmd() {
  local command_name=$1 helper state config default_snat_kind=masquerade default_snat_address=${LINUX_LAN_IPV4:-192.168.50.200}
  local lan_if="${WAN_IFACE:-eth0}.${LAN_VLAN_ID:-}" ai_vip="" cn_vip="" helper_deadline
  local -a deadline_env=()
  local -a helper_command=()
  shift
  helper=$(fs_path /usr/local/libexec/dnscomplex-lan-alias)
  state=$(fs_path /var/lib/dnscomplex/lan-alias.json)
  config=$(fs_path /etc/sing-box/config.json)
  if [[ ! -x "$helper" ]]; then
    if [[ -e "$state" || -L "$state" ]]; then
      die "tracked LAN alias helper is missing while ownership state exists"
    fi
    return 0
  fi
  if [[ "${DEPLOY_MODE:-}" == "routeros-policy" ]]; then
    default_snat_kind=snat
    lan_if="${WAN_IFACE:-eth0}"
  fi
  if [[ "$command_name" == "reconcile" ]]; then
    [[ "${AI_EGRESS_MODE:-ipsec}" == "ipsec" ]] && ai_vip=$(ipsec_vip ai || true)
    [[ "${CN_EGRESS_MODE:-ipsec}" == "ipsec" ]] && cn_vip=$(ipsec_vip cn || true)
    if ((WATCHDOG_DEADLINE_MS > 0)); then
      # Reserve the final second for one raw-readiness close/readback attempt.
      helper_deadline=$((WATCHDOG_DEADLINE_MS - 1250))
      ((helper_deadline > 0)) || helper_deadline=1
      deadline_env=("DNSCOMPLEX_WATCHDOG_DEADLINE_MS=$helper_deadline")
    fi
  fi
  helper_command=(env "${deadline_env[@]}" python3 "$helper" "$command_name" --state "$state" --config "$config" \
    --ai-mode "${AI_EGRESS_MODE:-ipsec}" --cn-mode "${CN_EGRESS_MODE:-ipsec}" \
    --ai-mark "${AI_MARK:-0x301}" --cn-mark "${CN_MARK:-0x351}" \
    --auto-mark "${SINGBOX_AUTO_REDIRECT_OUTPUT_MARK:-0x2024}" \
    --ai-quic "${AI_QUIC_POLICY:-allow}" --cn-quic "${CN_QUIC_POLICY:-reject}" \
    --default-snat-interface "${WAN_IFACE:-eth0}" \
    --default-snat-kind "$default_snat_kind" \
    --default-snat-address "$default_snat_address" \
    --lan-interface "$lan_if" --ai-vip "$ai_vip" --cn-vip "$cn_vip" "$@")
  if ((WATCHDOG_DEADLINE_MS > 0)); then
    watchdog_run 12 "${helper_command[@]}"
  else
    "${helper_command[@]}"
  fi
}

lan_alias_close_cmd() {
  lan_alias_helper_cmd close
}

lan_alias_reconcile_cmd() {
  lan_alias_helper_cmd reconcile
}

lan_alias_verify_owner_cmd() {
  lan_alias_helper_cmd verify-owner
}

write_singbox_egress_cmd() {
  need_root || return $?
  lan_alias_close_cmd || return $?
  command -v jq >/dev/null 2>&1 || die "jq is required"
  local ai_out cn_out tmp config rc=0
  config=$(fs_path /etc/sing-box/config.json) || return $?
  [[ -f "$config" ]] || die "sing-box config is missing"
  ai_out=$(profile_outbound_tag ai) || return $?
  cn_out=$(profile_outbound_tag cn) || return $?
  tmp=$(mktemp) || return $?
  jq --arg ai "$ai_out" --arg cn "$cn_out" '
    (.route.rules[]? | select(.action == "route" and (.rule_set? | type == "string") and ((.rule_set | startswith("geosite-ai-")) or .rule_set == "geosite-ai-support")).outbound) = $ai |
    (.route.rules[]? | select(.action == "route" and .rule_set? == "geosite-cn-video").outbound) = $cn
  ' "$config" >"$tmp" || rc=$?
  if ((rc == 0)); then sing-box check -c "$tmp" || rc=$?; fi
  if ((rc == 0)); then install -m 0644 "$tmp" "$config" || rc=$?; fi
  rm -f -- "$tmp"
  return "$rc"
}

runtime_nft_prerouting_rules() {
  local lan_if=$1 profile=$2 set_name=$3 mark=$4 mode=$5 quic_policy=$6
  local quic_rule=""
  if [[ "$quic_policy" == "reject" ]]; then
    quic_rule="    iifname \"$lan_if\" ip daddr @$set_name udp dport 443 counter reject with icmp type port-unreachable comment \"dnscomplex-${profile}-quic-reject\""
  fi
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
$quic_rule
    iifname "$lan_if" ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop"
EOF
  else
    cat <<EOF
    iifname "$lan_if" ip daddr 255.255.255.255 meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop"
$quic_rule
    iifname "$lan_if" ip daddr @$set_name meta l4proto { icmp, tcp, udp } ct mark set $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK meta mark set $mark counter comment "dnscomplex-${profile}-preroute"
EOF
  fi
}

runtime_nft_restore_rules() {
  local lan_if=$1 profile=$2 set_name=$3 mark=$4 mode=$5 quic_policy=$6
  local quic_rule=""
  if [[ "$quic_policy" == "reject" ]]; then
    quic_rule="    iifname \"$lan_if\" ip daddr @$set_name udp dport 443 counter reject with icmp type port-unreachable comment \"dnscomplex-${profile}-quic-reject-restore\""
  fi
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
$quic_rule
    iifname "$lan_if" ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop-restore"
EOF
  else
    cat <<EOF
$quic_rule
    iifname "$lan_if" ip daddr @$set_name meta l4proto { icmp, tcp, udp } meta mark set $mark counter comment "dnscomplex-${profile}-policy-restore"
EOF
  fi
}

runtime_nft_lan_alias_prerouting_rules() {
  local lan_if=$1
  cat <<EOF
    iifname "$lan_if" ip daddr @lan_alias_config_ready4 meta l4proto { tcp, udp } ct mark != $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK return comment "dnscomplex-lan-alias-fresh-flow"
EOF
}

runtime_nft_lan_alias_restore_rules() {
  local lan_if=$1
  cat <<EOF
    iifname "$lan_if" ip daddr @lan_alias_config_ready4 meta l4proto { tcp, udp } ct mark != $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK return comment "dnscomplex-lan-alias-fresh-flow-restore"
EOF
}

runtime_nft_lan_alias_output_rules() {
  if [[ "${LAN_ALIAS_RENDER_OWNED:-0}" == "1" ]]; then
    printf '    ip saddr 198.18.255.254 ip daddr != @lan_alias_ready4 counter drop comment "dnscomplex-lan-alias-owned-source-guard"\n'
  fi
  cat <<EOF
    ip saddr @lan_alias_source4 ip daddr != @lan_alias_ready4 counter drop comment "dnscomplex-lan-alias-not-ready"
    ip saddr @lan_alias_source4 ip daddr @ai4 ip daddr != @ai_ready4 counter drop comment "dnscomplex-lan-alias-ai-not-ready"
    ip saddr @lan_alias_source4 ip daddr @cn4 ip daddr != @cn_ready4 counter drop comment "dnscomplex-lan-alias-cn-not-ready"
    ip saddr @lan_alias_source4 meta mark set $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK counter comment "dnscomplex-lan-alias-default-mark"
EOF
  if [[ "$AI_QUIC_POLICY" == "reject" ]]; then
    printf '    ip saddr @lan_alias_source4 ip daddr @ai4 udp dport 443 counter reject with icmp type port-unreachable comment "dnscomplex-lan-alias-quic-reject-ai"\n'
  fi
  if [[ "$AI_EGRESS_MODE" == "ipsec" ]]; then
    printf '    ip saddr @lan_alias_source4 ip daddr @ai4 meta l4proto { tcp, udp } meta mark set %s counter comment "dnscomplex-lan-alias-classified-ai"\n' "$AI_MARK"
  fi
  if [[ "$CN_QUIC_POLICY" == "reject" ]]; then
    printf '    ip saddr @lan_alias_source4 ip daddr @cn4 udp dport 443 counter reject with icmp type port-unreachable comment "dnscomplex-lan-alias-quic-reject-cn"\n'
  fi
  if [[ "$CN_EGRESS_MODE" == "ipsec" ]]; then
    printf '    ip saddr @lan_alias_source4 ip daddr @cn4 meta l4proto { tcp, udp } meta mark set %s counter comment "dnscomplex-lan-alias-classified-cn"\n' "$CN_MARK"
  fi
  printf '    ip saddr @lan_alias_source4 counter accept comment "dnscomplex-lan-alias-default-output"\n'
}

runtime_nft_lan_alias_default_snat_rule() {
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    printf '    oifname "%s" ip saddr @lan_alias_source4 counter snat ip to %s comment "dnscomplex-lan-alias-snat-default"\n' "$WAN_IFACE" "$LINUX_LAN_IPV4"
  else
    printf '    oifname "%s" ip saddr @lan_alias_source4 counter masquerade comment "dnscomplex-lan-alias-snat-default"\n' "$WAN_IFACE"
  fi
}

runtime_nft_classified_output_rules() {
  local profile=$1 mark=$2 quic_policy=$3 mode=$4
  [[ "$mode" == "ipsec" ]] || return 0
  local selector="oifname \"ipsec-${profile}\"" quic_rule=""
  if [[ "$quic_policy" == "reject" ]]; then
    quic_rule="    $selector udp dport 443 counter reject with icmp type port-unreachable comment \"dnscomplex-${profile}-classified-quic-reject\""
  fi
  cat <<EOF
    $selector meta nfproto ipv6 counter drop comment "dnscomplex-${profile}-classified-ipv6-drop"
    $selector ip daddr != @${profile}_ready4 counter drop comment "dnscomplex-${profile}-classified-not-ready"
$quic_rule
    $selector counter meta mark set $mark accept comment "dnscomplex-${profile}-classified-output"
EOF
}

runtime_nft_output_rules() {
  local profile=$1 set_name=$2 mark=$3 mode=$4 quic_policy=$5
  local quic_rule=""
  if [[ "$quic_policy" == "reject" ]]; then
    quic_rule="    ip daddr @$set_name udp dport 443 counter reject with icmp type port-unreachable comment \"dnscomplex-${profile}-quic-reject-output\""
  fi
  if [[ "$mode" == "xray" ]]; then
    cat <<EOF
$quic_rule
    ip daddr @$set_name meta l4proto icmp drop comment "dnscomplex-${profile}-xray-icmp-drop-output"
EOF
  else
    cat <<EOF
$quic_rule
    ip daddr @$set_name meta l4proto { icmp, tcp, udp } meta mark set $mark
EOF
  fi
}

runtime_nft_xray_transport_output_rules() {
  local profile=$1 mark=$2 mode=$3
  [[ "$mode" == "xray" ]] || return 0
  cat <<EOF
    ip saddr != 198.18.255.254 meta mark $mark ip daddr @${profile}_ready4 counter meta mark set $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK accept comment "dnscomplex-${profile}-xray-underlay-ready4"
    meta mark $mark ip6 daddr @${profile}_ready6 counter meta mark set $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK accept comment "dnscomplex-${profile}-xray-underlay-ready6"
    ip saddr != 198.18.255.254 meta mark $mark counter drop comment "dnscomplex-${profile}-xray-underlay-not-ready"
EOF
}

runtime_nft_profile_dataplane_probe_output_rule() {
  local profile=$1 mode=$2 probe_mark resolver_ip profile_mark
  [[ "$mode" == "ipsec" ]] || return 0
  case "$profile" in
    ai)
      probe_mark=$IPSEC_DATAPLANE_AI_MARK
      profile_mark=$AI_MARK
      resolver_ip=104.16.248.249
      ;;
    cn)
      probe_mark=$IPSEC_DATAPLANE_CN_MARK
      profile_mark=$CN_MARK
      resolver_ip=223.6.6.6
      ;;
    *) return 1 ;;
  esac
  printf -v probe_mark '0x%x' "$((probe_mark))"
  printf -v profile_mark '0x%x' "$((profile_mark))"
  printf '    ip saddr @%s_probe_vip4 oifname "ipsec-%s" ip daddr %s tcp dport 443 meta mark %s counter meta mark set %s accept comment "dnscomplex-%s-dataplane-probe"\n' \
    "$profile" "$profile" "$resolver_ip" "$probe_mark" "$profile_mark" "$profile"
}

runtime_routeros_default_snat_rule() {
  local lan_if=$1
  [[ "$DEPLOY_MODE" == "routeros-policy" ]] || return 0
  cat <<EOF
    oifname "$lan_if" ip saddr $LAN_CLIENT_IPV4_CIDR ip daddr != { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } counter snat ip to $LINUX_LAN_IPV4 comment "dnscomplex-routeros-default-snat"
EOF
}

write_nftables_runtime_cmd() {
  need_root || return $?
  local LAN_ALIAS_RENDER_OWNED=0 alias_state
  lan_alias_close_cmd || return $?
  alias_state=$(fs_path /var/lib/dnscomplex/lan-alias.json)
  if [[ -e "$alias_state" || -L "$alias_state" ]]; then
    lan_alias_verify_owner_cmd || die "LAN alias owner state failed verification before nft reload"
    LAN_ALIAS_RENDER_OWNED=1
  fi
  local lan_if="${WAN_IFACE}.${LAN_VLAN_ID:-}"
  [[ "$DEPLOY_MODE" == "routeros-policy" ]] && lan_if="$WAN_IFACE"
  mkdir -p "$(fs_path /etc/nftables.d)" || return $?
  # Expand rules before writing: a failed command substitution in a heredoc
  # does not make cat fail, even with errexit enabled.
  local -a nft_rules=()
  nft_rules[0]=$(if [[ "$LAN_ALIAS_RENDER_OWNED" == "1" ]]; then printf '    elements = { 198.18.255.254 }\n'; fi) || return $?
  nft_rules[1]=$(runtime_nft_lan_alias_prerouting_rules "$lan_if") || return $?
  nft_rules[2]=$(runtime_nft_prerouting_rules "$lan_if" ai ai4 "$AI_MARK" "$AI_EGRESS_MODE" "$AI_QUIC_POLICY") || return $?
  nft_rules[3]=$(runtime_nft_prerouting_rules "$lan_if" cn cn4 "$CN_MARK" "$CN_EGRESS_MODE" "$CN_QUIC_POLICY") || return $?
  nft_rules[4]=$(runtime_nft_lan_alias_restore_rules "$lan_if") || return $?
  nft_rules[5]=$(runtime_nft_restore_rules "$lan_if" ai ai4 "$AI_MARK" "$AI_EGRESS_MODE" "$AI_QUIC_POLICY") || return $?
  nft_rules[6]=$(runtime_nft_restore_rules "$lan_if" cn cn4 "$CN_MARK" "$CN_EGRESS_MODE" "$CN_QUIC_POLICY") || return $?
  nft_rules[7]=$(runtime_nft_profile_dataplane_probe_output_rule ai "$AI_EGRESS_MODE") || return $?
  nft_rules[8]=$(runtime_nft_profile_dataplane_probe_output_rule cn "$CN_EGRESS_MODE") || return $?
  nft_rules[9]=$(runtime_nft_xray_transport_output_rules ai "$AI_MARK" "$AI_EGRESS_MODE") || return $?
  nft_rules[10]=$(runtime_nft_xray_transport_output_rules cn "$CN_MARK" "$CN_EGRESS_MODE") || return $?
  nft_rules[11]=$(runtime_nft_lan_alias_output_rules) || return $?
  nft_rules[12]=$(runtime_nft_classified_output_rules ai "$AI_MARK" "$AI_QUIC_POLICY" "$AI_EGRESS_MODE") || return $?
  nft_rules[13]=$(runtime_nft_classified_output_rules cn "$CN_MARK" "$CN_QUIC_POLICY" "$CN_EGRESS_MODE") || return $?
  nft_rules[14]=$(runtime_nft_output_rules ai ai4 "$AI_MARK" "$AI_EGRESS_MODE" "$AI_QUIC_POLICY") || return $?
  nft_rules[15]=$(runtime_nft_output_rules cn cn4 "$CN_MARK" "$CN_EGRESS_MODE" "$CN_QUIC_POLICY") || return $?
  nft_rules[16]=$(runtime_nft_lan_alias_default_snat_rule "$lan_if") || return $?
  nft_rules[17]=$(runtime_routeros_default_snat_rule "$lan_if") || return $?
  cat >"$(fs_path /etc/nftables.d/dnscomplex.nft)" <<EOF || return $?
table inet dnscomplex {
  set ai4 {
    type ipv4_addr
    flags timeout
    size 262144
  }

  set cn4 {
    type ipv4_addr
    flags timeout
    size 262144
  }

  set ai_ready4 {
    type ipv4_addr
    flags interval
  }

  set cn_ready4 {
    type ipv4_addr
    flags interval
  }

  set ai_probe_vip4 {
    type ipv4_addr
    flags interval
  }

  set cn_probe_vip4 {
    type ipv4_addr
    flags interval
  }

  set lan_alias_source4 {
    type ipv4_addr
    flags interval
${nft_rules[0]}
  }

  set lan_alias_ready4 {
    type ipv4_addr
    flags interval
  }

  set lan_alias_config_ready4 {
    type ipv4_addr
    flags interval
  }

  set ai_ready6 {
    type ipv6_addr
    flags interval
  }

  set cn_ready6 {
    type ipv6_addr
    flags interval
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
${nft_rules[1]}
    iifname "$lan_if" ip daddr @ai4 ip daddr != @ai_ready4 counter drop comment "dnscomplex-ai-not-ready"
    iifname "$lan_if" ip daddr @cn4 ip daddr != @cn_ready4 counter drop comment "dnscomplex-cn-not-ready"
${nft_rules[2]}
${nft_rules[3]}
  }

  chain prerouting_policy_restore {
    type filter hook prerouting priority filter; policy accept;
    iifname "$lan_if" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept
${nft_rules[4]}
${nft_rules[5]}
${nft_rules[6]}
  }

  chain forward {
    type filter hook forward priority filter; policy accept;
    tcp flags syn tcp option maxseg size > $IPSEC_TCP_MSS tcp option maxseg size set $IPSEC_TCP_MSS
  }

  chain output {
    type route hook output priority mangle; policy accept;
${nft_rules[7]}
${nft_rules[8]}
${nft_rules[9]}
${nft_rules[10]}
${nft_rules[11]}
    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept
    udp dport { 500, 4500 } accept comment "dnscomplex-ipsec-underlay"
${nft_rules[12]}
${nft_rules[13]}
    meta mark $SINGBOX_AUTO_REDIRECT_OUTPUT_MARK counter accept comment "dnscomplex-domain-default-output"
    ip daddr @ai4 ip daddr != @ai_ready4 counter drop comment "dnscomplex-ai-not-ready-output"
    ip daddr @cn4 ip daddr != @cn_ready4 counter drop comment "dnscomplex-cn-not-ready-output"
${nft_rules[14]}
${nft_rules[15]}
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
${nft_rules[16]}
${nft_rules[17]}
  }
}
EOF
  cat >"$(fs_path /etc/nftables.conf)" <<'EOF' || return $?
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.nft"
EOF
  nft -c -f "$(fs_path /etc/nftables.conf)" || return $?
  systemctl restart nftables || return $?
}

apply_egress_stack_cmd() {
  need_root || return $?
  local only_profile=${1:-}
  render_xray_config_cmd || return $?
  write_singbox_egress_cmd || return $?
  write_nftables_runtime_cmd || return $?
  systemctl daemon-reload || return $?
  systemctl enable --now xray-dnscomplex || return $?
  systemctl restart xray-dnscomplex sing-box || return $?
  if [[ -n "$only_profile" ]]; then
    [[ "$only_profile" == ai || "$only_profile" == cn ]] || return 2
    if profile_uses_ipsec "$only_profile"; then
      swanctl --initiate --child "$only_profile" --timeout 30 >/dev/null 2>&1 || return $?
    fi
    ensure_policy_route_profile "$only_profile" || return $?
    if profile_uses_ipsec "$only_profile"; then
      sync_ipsec_nat_profile "$only_profile" || return $?
      sync_singbox_ipsec_bind_addresses "$only_profile" || return $?
    fi
  else
    "$0" ipsec-ready || return $?
    "$0" routes up || return $?
  fi
}

apply_egress_candidate_cmd() {
  local profile=$1 mode=$2 uri=$3 json=$4 expected_uri expected_json
  [[ "$profile" == ai || "$profile" == cn ]] || return 2
  [[ "$mode" == ipsec || "$mode" == xray ]] || return 2
  [[ -z "$uri" || -z "$json" ]] || return 2
  case "$profile" in
    ai)
      if [[ -n "$uri" ]]; then AI_XRAY_URI=$uri; AI_XRAY_OUTBOUND_JSON=""; fi
      if [[ -n "$json" ]]; then AI_XRAY_OUTBOUND_JSON=$json; AI_XRAY_URI=""; fi
      AI_EGRESS_MODE=$mode; expected_uri=${AI_XRAY_URI:-}; expected_json=${AI_XRAY_OUTBOUND_JSON:-}
      ;;
    cn)
      if [[ -n "$uri" ]]; then CN_XRAY_URI=$uri; CN_XRAY_OUTBOUND_JSON=""; fi
      if [[ -n "$json" ]]; then CN_XRAY_OUTBOUND_JSON=$json; CN_XRAY_URI=""; fi
      CN_EGRESS_MODE=$mode; expected_uri=${CN_XRAY_URI:-}; expected_json=${CN_XRAY_OUTBOUND_JSON:-}
      ;;
  esac
  write_config_cmd || return $?
  apply_egress_stack_cmd "$profile" || return $?
  case "$profile" in
    ai) unset AI_EGRESS_MODE AI_XRAY_URI AI_XRAY_OUTBOUND_JSON ;;
    cn) unset CN_EGRESS_MODE CN_XRAY_URI CN_XRAY_OUTBOUND_JSON ;;
  esac
  load_config || return $?
  case "$profile" in
    ai) [[ "$AI_EGRESS_MODE" == "$mode" && "$AI_XRAY_URI" == "$expected_uri" && "$AI_XRAY_OUTBOUND_JSON" == "$expected_json" ]] || return 1 ;;
    cn) [[ "$CN_EGRESS_MODE" == "$mode" && "$CN_XRAY_URI" == "$expected_uri" && "$CN_XRAY_OUTBOUND_JSON" == "$expected_json" ]] || return 1 ;;
  esac
  operation_postcheck_selected_profile_cmd "$profile"
}

apply_egress_json_cmd() (
  need_root || return $?
  [[ $# -eq 1 ]] || die "usage: dnscomplex apply-egress-json PATH"
  local stage profile mode uri json renderer rc=0
  stage=$(mktemp -d) || return $?
  chmod 0700 "$stage" || return $?
  trap 'rm -rf -- "$stage"' EXIT
  # Open once, then use only this immutable private copy and Bash variables.
  python3 - "$1" "$stage" <<'EGRESS_PAYLOAD' || return $?
import json, os, stat, sys
try:
    fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1048576: raise ValueError()
        data=stream.read(1048577)
    value=json.loads(data)
    if not isinstance(value,dict) or set(value)-{'profile','mode','uri','outbound_json'}: raise ValueError()
    profile=value.get('profile'); mode=value.get('mode')
    if profile not in ('ai','cn') or mode not in ('ipsec','xray'): raise ValueError()
    uri=value.get('uri',''); outbound=value.get('outbound_json','')
    if not isinstance(uri,str) or not isinstance(outbound,(str,dict)): raise ValueError()
    if uri == '********': uri=''
    if outbound == '********': outbound=''
    if uri and outbound: raise ValueError()
    if outbound:
        parsed=json.loads(outbound) if isinstance(outbound,str) else outbound
        if not isinstance(parsed,dict): raise ValueError()
        outbound=json.dumps(parsed,separators=(',',':'))
    for name,text in (('profile',profile),('mode',mode),('uri',uri),('outbound_json',outbound)):
        if '\x00' in text: raise ValueError()
        with open(os.path.join(sys.argv[2],name),'x',opener=lambda p,f:os.open(p,f,0o600)) as out: out.write(text)
except (ValueError,TypeError,OSError):
    raise SystemExit('invalid egress candidate')
EGRESS_PAYLOAD
  profile=$(cat "$stage/profile") || return $?
  mode=$(cat "$stage/mode") || return $?
  uri=$(cat "$stage/uri") || return $?
  json=$(cat "$stage/outbound_json") || return $?
  renderer=$(fs_path /usr/local/lib/dnscomplex-xray/render.py) || return $?
  if [[ -n "$uri" ]]; then
    "$renderer" --config "$CONFIG" --profile "$profile" --uri-file "$stage/uri" --output "$stage/rendered.json" >/dev/null 2>&1 || rc=$?
  elif [[ -n "$json" ]]; then
    "$renderer" --config "$CONFIG" --profile "$profile" --json-file "$stage/outbound_json" --output "$stage/rendered.json" >/dev/null 2>&1 || rc=$?
  elif [[ "$mode" == xray ]]; then
    case "$profile" in
      ai) [[ -n "$AI_XRAY_URI" || -n "$AI_XRAY_OUTBOUND_JSON" ]] || return 2 ;;
      cn) [[ -n "$CN_XRAY_URI" || -n "$CN_XRAY_OUTBOUND_JSON" ]] || return 2 ;;
    esac
    "$renderer" --config "$CONFIG" --profile "$profile" --output "$stage/rendered.json" >/dev/null 2>&1 || rc=$?
  fi
  if [[ -n "$uri" || -n "$json" || "$mode" == xray ]]; then
    [[ -f "$stage/rendered.json" ]] || return 1
    xray_test_config_file "$stage/rendered.json" >/dev/null 2>&1 || rc=$?
  fi
  ((rc == 0)) || return "$rc"
  state_transaction_cmd "set-egress $profile $mode" apply_egress_candidate_cmd "$profile" "$mode" "$uri" "$json"
)

set_egress_candidate_cmd() {
  apply_egress_candidate_cmd "$1" "$2" "" ""
}

set_egress_cmd() {
  need_root
  [[ $# -eq 2 ]] || die "usage: dnscomplex set-egress ai|cn ipsec|xray"
  local profile=$1 mode=$2
  [[ "$profile" == ai || "$profile" == cn ]] || die "profile must be ai or cn"
  [[ "$mode" == "ipsec" || "$mode" == "xray" ]] || die "mode must be ipsec or xray"
  if [[ "$mode" == "xray" ]]; then
    case "$profile" in
      ai) [[ -n "${AI_XRAY_URI:-}" || -n "${AI_XRAY_OUTBOUND_JSON:-}" ]] || die "set Xray URI/JSON before switching AI to xray" ;;
      cn) [[ -n "${CN_XRAY_URI:-}" || -n "${CN_XRAY_OUTBOUND_JSON:-}" ]] || die "set Xray URI/JSON before switching CN to xray" ;;
      *) ;;
    esac
  fi
  state_transaction_cmd "set-egress $profile $mode" set_egress_candidate_cmd "$profile" "$mode"
}

set_xray_uri_candidate_cmd() {
  local mode
  mode=$(profile_egress_mode "$1") || return $?
  apply_egress_candidate_cmd "$1" "$mode" "$2" ""
}

set_xray_uri_cmd() {
  need_root || return $?
  [[ $# -eq 2 ]] || die "usage: dnscomplex set-xray-uri ai|cn URI"
  local profile=$1 uri=$2 tmp renderer rc=0
  [[ "$profile" == "ai" || "$profile" == "cn" ]] || die "profile must be ai or cn"
  tmp=$(mktemp) || return $?
  renderer=$(fs_path /usr/local/lib/dnscomplex-xray/render.py) || return $?
  if [[ "${DNSCOMPLEX_OPERATION_ID:-}" =~ ^[a-f0-9]{32}$ ]]; then
    local uri_file
    uri_file="$(fs_path /var/lib/dnscomplex-operations)/$DNSCOMPLEX_OPERATION_ID/xray-uri"
    (umask 077; printf '%s' "$uri" >"$uri_file") || return $?
    "$renderer" --config "$CONFIG" --profile "$profile" --uri-file "$uri_file" --output "$tmp" || rc=$?
  else
    "$renderer" --config "$CONFIG" --profile "$profile" --uri "$uri" --output "$tmp" || rc=$?
  fi
  if ((rc == 0)); then xray_test_config_file "$tmp" || rc=$?; fi
  rm -f -- "$tmp"
  ((rc == 0)) || return "$rc"
  state_transaction_cmd "set-xray-uri $profile" set_xray_uri_candidate_cmd "$profile" "$uri"
}

set_xray_json_candidate_cmd() {
  local mode
  mode=$(profile_egress_mode "$1") || return $?
  apply_egress_candidate_cmd "$1" "$mode" "" "$2"
}

set_xray_json_cmd() {
  need_root || return $?
  [[ $# -eq 2 ]] || die "usage: dnscomplex set-xray-json ai|cn JSON_FILE"
  local profile=$1 file=$2 json tmp renderer rc=0
  [[ "$profile" == "ai" || "$profile" == "cn" ]] || die "profile must be ai or cn"
  [[ -r "$file" ]] || die "JSON file not readable: $file"
  json=$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), separators=(",", ":")))' "$file") || return $?
  tmp=$(mktemp) || return $?
  renderer=$(fs_path /usr/local/lib/dnscomplex-xray/render.py) || return $?
  if [[ "${DNSCOMPLEX_OPERATION_ID:-}" =~ ^[a-f0-9]{32}$ ]]; then
    "$renderer" --config "$CONFIG" --profile "$profile" --json-file "$file" --output "$tmp" || rc=$?
  else
    "$renderer" --config "$CONFIG" --profile "$profile" --json "$json" --output "$tmp" || rc=$?
  fi
  if ((rc == 0)); then xray_test_config_file "$tmp" || rc=$?; fi
  rm -f -- "$tmp"
  ((rc == 0)) || return "$rc"
  state_transaction_cmd "set-xray-json $profile" set_xray_json_candidate_cmd "$profile" "$json"
}

test_xray_cmd() (
  local profile=${1:-} tmp renderer port selected
  local -a profiles=(ai cn)
  case "$profile" in
    ""|ai|cn) ;;
    *) die "usage: dnscomplex test-xray [ai|cn]" ;;
  esac
  # Render and validate privately: diagnostics never publish or restart services.
  renderer=$(fs_path /usr/local/lib/dnscomplex-xray/render.py) || return $?
  [[ -x "$renderer" ]] || die "Xray renderer is missing"
  tmp=$(mktemp) || return $?
  chmod 0600 "$tmp" || return $?
  # shellcheck disable=SC2064 # Capture private path before locals unwind.
  trap "rm -f -- $(printf '%q' "$tmp")" EXIT
  "$renderer" --config "$CONFIG" --output "$tmp" || return $?
  xray_test_config_file "$tmp" || return $?
  if ! systemctl is-active --quiet xray-dnscomplex 2>/dev/null; then
    warn "xray-dnscomplex.service is not active; connectivity was not verified"
    return 1
  fi
  command -v curl >/dev/null 2>&1 || { warn "curl is required for connectivity verification"; return 1; }
  [[ -z "$profile" ]] || profiles=("$profile")
  for selected in "${profiles[@]}"; do
    [[ "$selected" == "ai" ]] && port=$XRAY_AI_SOCKS_PORT || port=$XRAY_CN_SOCKS_PORT
    if ! curl --socks5-hostname "$XRAY_LISTEN_HOST:$port" -4 -fsS --connect-timeout 6 --max-time 15 -o /dev/null https://www.cloudflare.com/cdn-cgi/trace; then
      warn "Xray $selected local SOCKS connectivity probe failed"
      return 1
    fi
    log "Xray $selected stored configuration syntax and local SOCKS connectivity probe passed"
  done
)

xray_status_cmd() {
  printf 'xray_enabled=%s ai_egress=%s cn_egress=%s listen=%s ai_port=%s cn_port=%s\n' \
    "$XRAY_ENABLED" "$AI_EGRESS_MODE" "$CN_EGRESS_MODE" "$XRAY_LISTEN_HOST" "$XRAY_AI_SOCKS_PORT" "$XRAY_CN_SOCKS_PORT"
  print_unit_state xray-dnscomplex.service
  if command -v xray >/dev/null 2>&1; then
    xray version | head -n1
  fi
}

write_swanctl_cmd() {
  need_root || return $?
  local tmp local_ip="${LINUX_TRANSIT_IPV4:-}"
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    local_ip="$LINUX_LAN_IPV4"
  fi
  local ai_user cn_user ai_pass cn_pass
  ai_user=${AI_IPSEC_USERNAME//\\/\\\\}; ai_user=${ai_user//\"/\\\"}
  cn_user=${CN_IPSEC_USERNAME//\\/\\\\}; cn_user=${cn_user//\"/\\\"}
  ai_pass=${AI_IPSEC_PASSWORD//\\/\\\\}; ai_pass=${ai_pass//\"/\\\"}
  cn_pass=${CN_IPSEC_PASSWORD//\\/\\\\}; cn_pass=${cn_pass//\"/\\\"}
  tmp=$(mktemp) || return $?
  chmod 0600 "$tmp" || return $?
  cat >"$tmp" <<EOF || return $?
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
      eap_id = "$ai_user"
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
      eap_id = "$cn_user"
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
    id = "$ai_user"
    secret = "$ai_pass"
  }
  eap-cn {
    id = "$cn_user"
    secret = "$cn_pass"
  }
}
EOF
  install -m 0600 "$tmp" "$(fs_path /etc/swanctl/swanctl.conf)" || { local rc=$?; rm -f -- "$tmp"; return "$rc"; }
  rm -f "$tmp"
}

ipsec_selected_ike_ids_cmd() {
  local profile=$1
  awk -v p="$profile" '$0 ~ ("^" p ":") && $1 == p ":" && $2 ~ /^#[0-9]+,$/ { gsub(/[^0-9]/,"",$2); print $2 }'
}

set_ipsec_candidate_cmd() {
  local profile=$1 user=$2 pass=$3 sas before after
  sas=$(timeout --signal=TERM --kill-after=1s 5s swanctl --list-sas 2>/dev/null) || return $?
  before=$(ipsec_selected_ike_ids_cmd "$profile" <<<"$sas") || return $?
  case "$profile" in
    ai) AI_IPSEC_USERNAME=$user; AI_IPSEC_PASSWORD=$pass ;;
    cn) CN_IPSEC_USERNAME=$user; CN_IPSEC_PASSWORD=$pass ;;
  esac
  write_swanctl_cmd || return $?
  write_config_cmd || return $?
  # No --clear: eap-ai/eap-cn replace their own VICI unique shared-key IDs.
  # Never restart the daemon or terminate the other profile's IKE_SA.
  swanctl --load-all --noprompt >/dev/null 2>&1 || return $?
  if [[ -n "$before" ]]; then
    swanctl --terminate --ike "$profile" --timeout 15 >/dev/null 2>&1 || return $?
  fi
  sas=$(timeout --signal=TERM --kill-after=1s 5s swanctl --list-sas 2>/dev/null) || return $?
  after=$(ipsec_selected_ike_ids_cmd "$profile" <<<"$sas") || return $?
  [[ -z "$after" ]] || { warn "selected IPsec authentication context did not close"; return 1; }
  swanctl --initiate --child "$profile" --timeout 30 >/dev/null 2>&1 || return $?
  sas=$(timeout --signal=TERM --kill-after=1s 5s swanctl --list-sas 2>/dev/null) || return $?
  after=$(ipsec_selected_ike_ids_cmd "$profile" <<<"$sas") || return $?
  [[ -n "$after" ]] || return 1
  local id
  while IFS= read -r id; do
    [[ -z "$id" ]] || ! grep -Fxq -- "$id" <<<"$before" || return 1
  done <<<"$after"
  ensure_policy_route_profile "$profile" || return $?
  sync_ipsec_nat_profile "$profile" || return $?
  sync_singbox_ipsec_bind_addresses "$profile" || return $?
  operation_postcheck_ipsec_profile_cmd "$profile" || return $?
  case "$profile" in
    ai) unset AI_IPSEC_USERNAME AI_IPSEC_PASSWORD ;;
    cn) unset CN_IPSEC_USERNAME CN_IPSEC_PASSWORD ;;
  esac
  load_config || return $?
  case "$profile" in
    ai) [[ "${AI_IPSEC_USERNAME:-}" == "$user" && "${AI_IPSEC_PASSWORD:-}" == "$pass" ]] ;;
    cn) [[ "${CN_IPSEC_USERNAME:-}" == "$user" && "${CN_IPSEC_PASSWORD:-}" == "$pass" ]] ;;
  esac
}

set_ipsec_cmd() {
  need_root || return $?
  [[ $# -eq 3 ]] || die "usage: dnscomplex set-ipsec ai|cn USER PASSWORD"
  local profile=$1 user=$2 pass=$3 old_user old_pass
  [[ "$profile" == ai || "$profile" == cn ]] || die "profile must be ai or cn"
  if [[ "$pass" == "-" ]]; then
    read -r -s -p "IPsec password: " pass || return $?
    printf '\n'
  fi
  [[ -n "$user" && -n "$pass" && "$user" != *$'\n'* && "$pass" != *$'\n'* &&
     "$user" != *$'\r'* && "$pass" != *$'\r'* ]] || die "invalid IPsec credentials"
  case "$profile" in
    ai) old_user=$AI_IPSEC_USERNAME; old_pass=$AI_IPSEC_PASSWORD ;;
    cn) old_user=$CN_IPSEC_USERNAME; old_pass=$CN_IPSEC_PASSWORD ;;
  esac
  if [[ "$user" == "$old_user" && "$pass" == "$old_pass" ]]; then
    case "$profile" in
      ai) unset AI_IPSEC_USERNAME AI_IPSEC_PASSWORD ;;
      cn) unset CN_IPSEC_USERNAME CN_IPSEC_PASSWORD ;;
    esac
    load_config || return $?
    case "$profile" in
      ai) [[ "${AI_IPSEC_USERNAME:-}" == "$user" && "${AI_IPSEC_PASSWORD:-}" == "$pass" ]] || return 1 ;;
      cn) [[ "${CN_IPSEC_USERNAME:-}" == "$user" && "${CN_IPSEC_PASSWORD:-}" == "$pass" ]] || return 1 ;;
    esac
    operation_postcheck_ipsec_profile_cmd "$profile"
    return $?
  fi
  state_transaction_cmd "set-ipsec $profile" set_ipsec_candidate_cmd "$profile" "$user" "$pass"
}

json_escape() {
  jq -Rs . <<<"${1:-}" | sed 's/^"//; s/"$//'
}

validate_loaded_config() {
  local errors=0 ports port_seen="" port name cidr expected_socks_listen
  validate_egress_profile_values || { printf 'error: invalid egress profile marks or routing tables\n'; errors=$((errors + 1)); }
  case "${DEPLOY_MODE:-}" in vlan-gateway|routeros-policy) ;; *) printf 'error: DEPLOY_MODE must be vlan-gateway or routeros-policy\n'; errors=$((errors + 1)) ;; esac
  case "${DEFAULT_DNS_STRATEGY:-prefer_ipv6}" in prefer_ipv4|prefer_ipv6) ;; *) printf 'error: DEFAULT_DNS_STRATEGY must be prefer_ipv4 or prefer_ipv6\n'; errors=$((errors + 1)) ;; esac
  case "${DEFAULT_IPV6_MODE:-auto}" in auto|on|off) ;; *) printf 'error: DEFAULT_IPV6_MODE must be auto, on, or off\n'; errors=$((errors + 1)) ;; esac
  case "${ADGUARD_DNS_CACHE_MODE:-off}" in off|small|large) ;; *) printf 'error: ADGUARD_DNS_CACHE_MODE must be off, small, or large\n'; errors=$((errors + 1)) ;; esac
  case "${DNSCOMPLEX_UPDATE_CHANNEL:-stable}" in stable|beta|pinned) ;; *) printf 'error: DNSCOMPLEX_UPDATE_CHANNEL must be stable, beta, or pinned\n'; errors=$((errors + 1)) ;; esac
  case "${GITHUB_RELEASE_POLICY:-latest}" in latest|pinned) ;; *) printf 'error: GITHUB_RELEASE_POLICY must be latest or pinned\n'; errors=$((errors + 1)) ;; esac
  case "${LOCAL_DOMAIN_IPV6_POLICY:-ipv4_only}" in ipv4_only|allow) ;; *) printf 'error: LOCAL_DOMAIN_IPV6_POLICY must be ipv4_only or allow\n'; errors=$((errors + 1)) ;; esac
  if [[ "${DNSCOMPLEX_UPDATE_CHANNEL:-stable}" == "pinned" || "${GITHUB_RELEASE_POLICY:-latest}" == "pinned" ]]; then
    [[ -n "${DNSCOMPLEX_PINNED_VERSION:-}" ]] || { printf 'error: DNSCOMPLEX_PINNED_VERSION is required for pinned update policy\n'; errors=$((errors + 1)); }
  fi
  for name in SINGBOX_SOCKS_PORT SINGBOX_HTTP_PORT SINGBOX_DNS_PORT SMARTDNS_DEFAULT_PORT SMARTDNS_AI_PORT SMARTDNS_CN_PORT DNSCOMPLEX_WEB_PORT DNSCOMPLEX_METRICS_PORT XRAY_AI_SOCKS_PORT XRAY_CN_SOCKS_PORT; do
    port=${!name:-}
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || { printf 'error: %s must be port 1-65535\n' "$name"; errors=$((errors + 1)); continue; }
    port=$((10#$port))
    if grep -Eq "(^| )${port}( |$)" <<<"$port_seen"; then
      printf 'error: duplicate listen port around %s\n' "$name"
      errors=$((errors + 1))
    fi
    port_seen="$port_seen $port"
  done
  case "${AI_EGRESS_MODE:-ipsec}" in ipsec|xray) ;; *) printf 'error: AI_EGRESS_MODE must be ipsec or xray\n'; errors=$((errors + 1)) ;; esac
  case "${CN_EGRESS_MODE:-ipsec}" in ipsec|xray) ;; *) printf 'error: CN_EGRESS_MODE must be ipsec or xray\n'; errors=$((errors + 1)) ;; esac
  case "${AI_QUIC_POLICY:-allow}" in reject|allow) ;; *) printf 'error: AI_QUIC_POLICY must be reject or allow\n'; errors=$((errors + 1)) ;; esac
  case "${CN_QUIC_POLICY:-reject}" in reject|allow) ;; *) printf 'error: CN_QUIC_POLICY must be reject or allow\n'; errors=$((errors + 1)) ;; esac
  expected_socks_listen=${LINUX_LAN_IPV4:-}
  expected_socks_listen=${expected_socks_listen%%/*}
  if [[ "${DEPLOY_MODE:-}" == "routeros-policy" &&
        ( -z "$expected_socks_listen" ||
          "${SINGBOX_SOCKS_LISTEN:-}" != "$expected_socks_listen" ) ]]; then
    printf 'error: routeros-policy SOCKS listen must match LINUX_LAN_IPV4\n'
    errors=$((errors + 1))
  fi
  if [[ "${DEPLOY_MODE:-}" == "routeros-policy" &&
        "${SINGBOX_SOCKS_PORT:-}" != "10800" ]]; then
    printf 'error: routeros-policy SOCKS port must be 10800\n'
    errors=$((errors + 1))
  fi
  if [[ "${AI_EGRESS_MODE:-ipsec}" == "xray" ]]; then
    [[ -n "${AI_XRAY_URI:-}" || -n "${AI_XRAY_OUTBOUND_JSON:-}" ]] || { printf 'error: AI xray mode requires AI_XRAY_URI or AI_XRAY_OUTBOUND_JSON\n'; errors=$((errors + 1)); }
  fi
  if [[ "${CN_EGRESS_MODE:-ipsec}" == "xray" ]]; then
    [[ -n "${CN_XRAY_URI:-}" || -n "${CN_XRAY_OUTBOUND_JSON:-}" ]] || { printf 'error: CN xray mode requires CN_XRAY_URI or CN_XRAY_OUTBOUND_JSON\n'; errors=$((errors + 1)); }
  fi
  for cidr in "${LAN_IPV4_CIDR:-}" "${TRANSIT_IPV4_CIDR:-}" "${LAN_CLIENT_IPV4_CIDR:-}"; do
    [[ -z "$cidr" ]] && continue
    python3 - "$cidr" <<'PY' >/dev/null 2>&1 || { printf 'error: invalid IPv4 CIDR\n'; errors=$((errors + 1)); }
import ipaddress, sys
ipaddress.ip_interface(sys.argv[1])
PY
  done
  for cidr in "${LAN_IPV6_PREFIX:-}" "${TRANSIT_IPV6_CIDR:-}"; do
    [[ -z "$cidr" ]] && continue
    python3 - "$cidr" <<'PY' >/dev/null 2>&1 || { printf 'error: invalid IPv6 CIDR/prefix\n'; errors=$((errors + 1)); }
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

normalize_config_candidate_cmd() {
  local helper
  helper=$(fs_path /usr/local/lib/dnscomplex-config/candidate.py)
  python3 "$helper" --input "$1" --output "$2"
}

validate_normalized_config_cmd() {
  local file=$1
  (
    # Only parser-generated assignments inside a private directory reach here.
    CONFIG="$file"
    load_config >/dev/null 2>&1 || exit 1
    validate_loaded_config
  )
}

validate_config_file_cmd() {
  local json=0 file output rc=0
  if [[ "${1:-}" == "--json" ]]; then
    json=1
    shift
  fi
  [[ $# -eq 1 ]] || die "usage: dnscomplex validate-config [--json] ENV_FILE"
  file=$1
  output=$(
    set -e
    work=$(mktemp -d) || exit 1
    # shellcheck disable=SC2064 # Capture path before function-local scope unwinds.
    trap "rm -rf -- $(printf '%q' "$work")" EXIT
    normalize_config_candidate_cmd "$file" "$work/config.env" 2>&1 || exit 1
    validate_normalized_config_cmd "$work/config.env"
  ) || rc=$?
  if [[ "$json" == "1" ]]; then
    jq -n --argjson ok "$([[ "$rc" == "0" ]] && printf true || printf false)" --arg output "$output" '{ok:$ok, output:$output}'
  elif [[ "$rc" == "0" ]]; then
    printf 'config valid\n'
  else
    printf '%s\n' "$output"
  fi
  return "$rc"
}

apply_config_candidate_cmd() {
  local source_file=$1 config_dir staged="" rc=0
  config_dir=$(dirname "$CONFIG")
  mkdir -p "$config_dir" || return 1
  staged=$(mktemp "$config_dir/.config.env.apply.XXXXXX") || return 1
  install -m 0600 "$source_file" "$staged" || {
    rc=$?
    rm -f -- "$staged"
    return "$rc"
  }
  mv -f "$staged" "$CONFIG" || {
    rc=$?
    rm -f -- "$staged"
    return "$rc"
  }
  staged=""
  "$0" fix --strict
  rc=$?
  [[ "$rc" == "0" ]] || return "$rc"
  log "configuration applied and repaired"
}

apply_config_file_cmd() {
  need_root
  acquire_maintenance_lock
  [[ $# -eq 1 ]] || die "usage: dnscomplex apply-config ENV_FILE"
  (
    local work
    work=$(mktemp -d) || exit 1
    # shellcheck disable=SC2064 # Capture path before function-local scope unwinds.
    trap "rm -rf -- $(printf '%q' "$work")" EXIT
    normalize_config_candidate_cmd "$1" "$work/config.env" || exit 1
    validate_normalized_config_cmd "$work/config.env" || exit 1
    state_transaction_cmd "config apply" apply_config_candidate_cmd "$work/config.env"
  )
}

apply_config_json_cmd() {
  need_root
  acquire_maintenance_lock
  [[ $# -eq 1 ]] || die "usage: dnscomplex apply-config-json JSON_FILE"
  (
    local work helper
    work=$(mktemp -d) || exit 1
    # shellcheck disable=SC2064 # Capture path before function-local scope unwinds.
    trap "rm -rf -- $(printf '%q' "$work")" EXIT
    helper=$(fs_path /usr/local/lib/dnscomplex-config/candidate.py)
    # Preflight the existing file as data before merging; never repair or
    # overwrite an incompatible source. Both inputs are captured once safely.
    python3 "$helper" --input "$CONFIG" --updates "$1" --output "$work/config.env" || exit 1
    apply_config_file_cmd "$work/config.env"
  )
}

redact_stream() {
  local redactor
  local -a args
  redactor=$(fs_path /usr/local/lib/dnscomplex-redact/redact.py)
  [[ -x "$redactor" ]] || die "redaction helper is unavailable"
  args=("$redactor")
  if [[ -r "$CONFIG" ]]; then
    args+=(--config "$CONFIG")
  fi
  python3 "${args[@]}"
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
ROUTEROS_LAN_IPV4=192.168.50.253
LINUX_LAN_IPV4=192.168.50.200
LAN_CLIENT_IPV4_CIDR=192.168.50.0/24
LAN_IPV6_PREFIX=fd00:88::/64
DEFAULT_IPV6_MODE=auto
SINGBOX_SOCKS_LISTEN=192.168.50.200
SINGBOX_SOCKS_PORT=10800
DNSCOMPLEX_WEB_LISTEN=192.168.50.200
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

support_bundle_cmd() (
  need_root
  local output="" include_logs=standard tmp rel
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
  trap 'rm -rf -- "$tmp"' EXIT
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
  systemctl --no-pager --plain status \
    sing-box smartdns AdGuardHome xray-dnscomplex dnscomplex-web dnscomplex-metrics \
    strongswan strongswan-swanctl strongswan-starter \
    dnscomplex-network-ready dnscomplex-ipsec-ifaces dnscomplex-ipsec-ready \
    dnscomplex-routing dnscomplex-health dnscomplex-cn-overrides \
    dnscomplex-nftset-refresh dnscomplex-metrics-sample \
    >"$tmp/raw/systemctl-status.txt" 2>&1 || true
  systemctl --failed --no-pager --plain >"$tmp/raw/systemctl-failed.txt" 2>&1 || true
  systemctl show sing-box smartdns AdGuardHome strongswan-swanctl \
    -p ActiveState -p SubState -p NRestarts -p MemoryCurrent -p CPUUsageNSec \
    >"$tmp/raw/systemctl-resources.txt" 2>&1 || true
  systemctl list-timers 'dnscomplex-*.timer' --no-pager >"$tmp/raw/timers.txt" 2>&1 || true
  journalctl --disk-usage >"$tmp/raw/journal-disk-usage.txt" 2>&1 || true
  journalctl --list-boots --no-pager >"$tmp/raw/journal-available-ranges.txt" 2>&1 || true
  nft list table inet dnscomplex >"$tmp/raw/nft-dnscomplex.txt" 2>&1 || true
  ip xfrm state >"$tmp/raw/ip-xfrm-state.txt" 2>&1 || true
  ip xfrm policy >"$tmp/raw/ip-xfrm-policy.txt" 2>&1 || true
  ip rule show >"$tmp/raw/ip-rules.txt" 2>&1 || true
  ip route show table all >"$tmp/raw/ip-routes.txt" 2>&1 || true
  timeout 10 swanctl --list-sas >"$tmp/raw/swanctl-sas.txt" 2>&1 || true
  timeout 10 swanctl --list-conns >"$tmp/raw/swanctl-conns.txt" 2>&1 || true
  conntrack -S >"$tmp/raw/conntrack-stats.txt" 2>&1 || true
  "$0" metrics-sample >"$tmp/raw/metrics-sample.json" 2>&1 || true
  [[ -r "$BASE/routeros.rsc" ]] && cp "$BASE/routeros.rsc" "$tmp/raw/routeros.rsc"
  render_config_cmd --redacted >"$tmp/raw/config.env.redacted" 2>&1 || true
  if [[ "$include_logs" != "minimal" ]]; then
    if [[ "$include_logs" == "full" ]]; then
      journalctl -u dnscomplex-web -u dnscomplex-metrics -u sing-box -u smartdns -u AdGuardHome \
        -u strongswan -u strongswan-swanctl -u strongswan-starter \
        -u dnscomplex-network-ready -u dnscomplex-ipsec-ifaces -u dnscomplex-ipsec-ready \
        -u dnscomplex-routing -u dnscomplex-health -u dnscomplex-cn-overrides \
        -u dnscomplex-nftset-refresh -u dnscomplex-metrics-sample \
        --since "24 hours ago" --lines=100000 --no-pager >"$tmp/raw/journal.txt" 2>&1 || true
    else
      journalctl -u dnscomplex-web -u dnscomplex-metrics -u sing-box -u smartdns -u AdGuardHome \
        -u strongswan -u strongswan-swanctl -u strongswan-starter \
        -u dnscomplex-network-ready -u dnscomplex-ipsec-ifaces -u dnscomplex-ipsec-ready \
        -u dnscomplex-routing -u dnscomplex-health -u dnscomplex-cn-overrides \
        -u dnscomplex-nftset-refresh -u dnscomplex-metrics-sample \
        --since "24 hours ago" --lines=20000 --no-pager >"$tmp/raw/journal.txt" 2>&1 || true
    fi
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
  log "support bundle written: $output"
)

install_smartdns_release() {
  local arch asset tmp
  arch=$(smartdns_arch)
  tmp=$(mktemp -d)
  asset=$(github_latest_asset_url "pymumu/smartdns" "${arch}-debian-all\\.deb$")
  curl_bounded -fsSL -o "$tmp/smartdns.deb" "$asset"
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
  [[ -x /usr/local/lib/smartdns/run-smartdns ]] || {
    warn "SmartDNS wrapper missing: /usr/local/lib/smartdns/run-smartdns"
    return 1
  }
  ln -sfn /usr/local/lib/smartdns/run-smartdns /usr/sbin/smartdns || return $?
}

ensure_smartdns_enabled() {
  systemctl enable smartdns >/dev/null 2>&1 || true
}

install_singbox_release() {
  local arch asset tmp
  arch=$(linux_arch)
  tmp=$(mktemp -d)
  asset=$(github_latest_asset_url "SagerNet/sing-box" "sing-box_.*_linux_${arch}\\.deb$")
  curl_bounded -fsSL -o "$tmp/sing-box.deb" "$asset"
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
  curl_bounded -fsSL -o "$tmp/AdGuardHome.tar.gz" "$asset"
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
  curl_bounded -fsSL -o "$tmp/xray.zip" "$asset"
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

rollback_component_update() {
  local before=$1 binary_rc config_rc
  update_software_stage "rollback application binaries and managed configuration"
  set +e
  restore_release_binaries "$before/bin"
  binary_rc=$?
  restore_cmd "$before/dnscomplex-pre-update.tar.gz"
  config_rc=$?
  set -e
  if [[ "$binary_rc" != "0" || "$config_rc" != "0" ]]; then
    warn "application rollback incomplete: binaries_rc=$binary_rc config_rc=$config_rc"
    return 1
  fi
  log "application rollback completed"
}

acquire_maintenance_lock() {
  local lock_dir old_umask busy_mode=0 wait_mode=0 option
  while [[ $# -gt 0 ]]; do
    option=$1
    shift
    case "$option" in
      --skip-busy) busy_mode=1 ;;
      --wait) wait_mode=1 ;;
      *) die "unknown maintenance lock option: $option" ;;
    esac
  done
  if [[ "${DNSCOMPLEX_MAINTENANCE_LOCK_HELD:-0}" == "1" ]]; then
    if ( : >&8 ) 2>/dev/null; then
      return 0
    fi
    die "maintenance lock state is set without an inherited lock descriptor"
  fi

  command -v flock >/dev/null 2>&1 || die "flock is required for maintenance operations"
  lock_dir=$(dirname "$MAINTENANCE_LOCK")
  mkdir -p "$lock_dir"
  old_umask=$(umask)
  umask 077
  if ! exec 8>"$MAINTENANCE_LOCK"; then
    umask "$old_umask"
    die "could not open maintenance lock: $MAINTENANCE_LOCK"
  fi
  umask "$old_umask"
  chmod 0600 "$MAINTENANCE_LOCK"
  if [[ "$wait_mode" == "1" ]]; then
    if ! flock -w 180 8; then
      exec 8>&-
      die "timed out waiting for the dnscomplex maintenance lock"
    fi
  elif ! flock -n 8; then
    exec 8>&-
    [[ "$busy_mode" == "1" ]] && return 1
    die "another dnscomplex maintenance operation is already running"
  fi
  export DNSCOMPLEX_MAINTENANCE_LOCK_HELD=1
}

persistent_mutator_command() {
  case "${1:-}" in
    health)
      [[ "${2:-}" != "--json" ]]
      ;;
    watchdog|network-ready|ipsec-ready|ipsec-ifaces|routes|fix|update-geosite|apply-domain-rules-json|add-domain|remove-domain|set-socks|set-ipsec|set-web-password|set-local-host|set-egress|apply-egress-json|set-xray-uri|set-xray-json|render-xray|set-update-time|refresh-nftsets|refresh-cn-overrides|mss-calibrate|update-software|system-update|apply-config|apply-config-json|backup|restore)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

internal_service_command() {
  [[ "${DNSCOMPLEX_SERVICE_MODE:-0}" == "1" ]] || return 1
  case "${1:-}" in
    network-ready|ipsec-ready|ipsec-ifaces|routes) return 0 ;;
    *) return 1 ;;
  esac
}

timer_service_command() {
  [[ "${DNSCOMPLEX_TIMER_MODE:-0}" == "1" ]] || return 1
  case "${1:-}" in
    update-geosite|refresh-nftsets|refresh-cn-overrides) return 0 ;;
    *) return 1 ;;
  esac
}

fs_path() {
  local path=$1
  [[ "$path" == /* ]] || die "fs_path requires an absolute path"
  if [[ -z "$FS_ROOT" || "$FS_ROOT" == "/" ]]; then
    printf '%s\n' "$path"
  else
    printf '%s%s\n' "${FS_ROOT%/}" "$path"
  fi
}

managed_backup_paths() {
  cat <<'EOF'
etc/dnscomplex
etc/sing-box
etc/smartdns
etc/AdGuardHome
etc/swanctl
etc/strongswan.d/charon/resolve.conf
etc/strongswan.d/charon/agent.conf
etc/strongswan.d/charon/tpm.conf
etc/strongswan.d/charon/dhcp.conf
etc/strongswan.d/swanctl.conf
etc/nftables.conf
etc/nftables.d/dnscomplex.nft
etc/modules-load.d/dnscomplex.conf
etc/sysctl.d/90-dnscomplex.conf
etc/dhcpcd.conf
etc/nsswitch.conf
etc/resolv.conf
usr/local/libexec/dnscomplex-lan-alias
etc/systemd/network/10-dnscomplex-vlans.netdev
etc/systemd/network/10-dnscomplex-trunk.network
etc/systemd/network/20-dnscomplex-transit.network
etc/systemd/network/30-dnscomplex-lan.network
etc/dnsmasq.d/dnscomplex.conf
etc/radvd.conf
etc/systemd/system-generators/systemd-ssh-generator
etc/systemd/journald.conf.d/dnscomplex.conf
etc/systemd/system/smartdns.service.d/dnscomplex.conf
etc/systemd/system/sing-box.service.d/dnscomplex.conf
etc/systemd/system/AdGuardHome.service
etc/systemd/system/xray-dnscomplex.service
etc/systemd/system/dnscomplex-network-ready.service
etc/systemd/system/dnscomplex-ipsec-ifaces.service
etc/systemd/system/dnscomplex-ipsec-ready.service
etc/systemd/system/dnscomplex-routing.service
etc/systemd/system/dnscomplex-health.service
etc/systemd/system/dnscomplex-health.timer
etc/systemd/system/dnscomplex-update.service
etc/systemd/system/dnscomplex-update.timer
etc/systemd/system/dnscomplex-cn-overrides.service
etc/systemd/system/dnscomplex-cn-overrides.timer
etc/systemd/system/dnscomplex-nftset-refresh.service
etc/systemd/system/dnscomplex-nftset-refresh.timer
etc/systemd/system/dnscomplex-metrics.service
etc/systemd/system/dnscomplex-metrics-sample.service
etc/systemd/system/dnscomplex-metrics-sample.timer
etc/systemd/system/dnscomplex-web.service
usr/local/libexec/dnscomplex-operation
usr/local/libexec/dnscomplex-restore-recover
etc/systemd/system/dnscomplex-operation@.service
etc/systemd/system/dnscomplex-operation-recovery@.service
etc/systemd/system/dnscomplex-operation-guard@.service
etc/systemd/system/dnscomplex-operation-guard@.timer
etc/prometheus/dnscomplex.rules.yml
usr/bin/sing-box
usr/sbin/smartdns
usr/local/bin/xray
usr/local/share/xray
usr/local/etc/xray
usr/local/lib/smartdns
usr/local/lib/dnscomplex-xray
usr/local/lib/dnscomplex-soak
usr/local/lib/dnscomplex-metrics
usr/local/lib/dnscomplex-web
usr/local/lib/dnscomplex-config
usr/local/lib/dnscomplex-redact
usr/local/sbin/dnscomplex
opt/AdGuardHome
var/lib/smartdns
var/lib/dnscomplex
EOF
}

optional_backup_paths() {
  cat <<'EOF'
usr/local/libexec/dnscomplex-operation
usr/local/libexec/dnscomplex-restore-recover
etc/systemd/system/dnscomplex-operation@.service
etc/systemd/system/dnscomplex-operation-recovery@.service
etc/systemd/system/dnscomplex-operation-guard@.service
etc/systemd/system/dnscomplex-operation-guard@.timer
usr/local/lib/dnscomplex-config
usr/local/lib/dnscomplex-redact
EOF
}

legacy_backup_paths() {
  cat <<'EOF'
etc/dnscomplex
etc/sing-box
etc/smartdns
etc/AdGuardHome
etc/swanctl
etc/nftables.d/dnscomplex.nft
usr/local/libexec/dnscomplex-lan-alias
var/lib/dnscomplex
EOF
}

managed_service_units() {
  cat <<'EOF'
systemd-networkd.service
nftables.service
dnsmasq.service
radvd.service
systemd-resolved.service
strongswan-swanctl.service
strongswan-starter.service
strongswan.service
ipsec.service
smartdns.service
AdGuardHome.service
sing-box.service
xray-dnscomplex.service
dnscomplex-network-ready.service
dnscomplex-ipsec-ifaces.service
dnscomplex-ipsec-ready.service
dnscomplex-routing.service
dnscomplex-health.timer
dnscomplex-update.timer
dnscomplex-cn-overrides.timer
dnscomplex-nftset-refresh.timer
dnscomplex-metrics.service
dnscomplex-metrics-sample.timer
dnscomplex-web.service
sshd-unix-local.socket
sshd-vsock.socket
sshd-unix-export.socket
EOF
}

restore_service_units_in_order() {
  cat <<'EOF'
systemd-networkd.service
nftables.service
dnsmasq.service
radvd.service
systemd-resolved.service
dnscomplex-ipsec-ifaces.service
strongswan-swanctl.service
strongswan-starter.service
strongswan.service
ipsec.service
dnscomplex-network-ready.service
dnscomplex-ipsec-ready.service
dnscomplex-routing.service
smartdns.service
AdGuardHome.service
sing-box.service
xray-dnscomplex.service
dnscomplex-health.timer
dnscomplex-update.timer
dnscomplex-cn-overrides.timer
dnscomplex-nftset-refresh.timer
dnscomplex-metrics.service
dnscomplex-metrics-sample.timer
dnscomplex-web.service
sshd-unix-local.socket
sshd-vsock.socket
sshd-unix-export.socket
EOF
}

service_state_supported() {
  command -v systemctl >/dev/null 2>&1 || return 1
  [[ -z "$FS_ROOT" || "$FS_ROOT" == "/" ||
     "${DNSCOMPLEX_FORCE_SERVICE_STATE:-0}" == "1" ]]
}

snapshot_service_state() {
  local destination=$1 unit load_state enabled active
  : >"$destination"
  service_state_supported || return 0
  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    load_state=$(systemctl show --property=LoadState --value "$unit" 2>/dev/null || true)
    [[ "$load_state" == "loaded" ]] || continue
    enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    enabled=${enabled%%$'\n'*}
    case "$enabled" in
      enabled|enabled-runtime|disabled|static|indirect|generated|alias|linked|linked-runtime|masked|masked-runtime|transient) ;;
      *) enabled=unknown ;;
    esac
    active=$(systemctl is-active "$unit" 2>/dev/null || true)
    active=${active%%$'\n'*}
    case "$active" in
      active|inactive|failed|activating|deactivating|reloading|maintenance) ;;
      *) active=unknown ;;
    esac
    printf '%s\t%s\t%s\n' "$unit" "$enabled" "$active" >>"$destination"
  done < <(managed_service_units)
}

validate_backup_archive() {
  local archive=$1
  python3 - "$archive" <<'PY'
import pathlib
import posixpath
import sys
import tarfile

archive_path = sys.argv[1]
seen = set()
members = []
total_size = 0
try:
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            raw_name = member.name
            name = raw_name
            while name.startswith("./"):
                name = name[2:]
            name = name.rstrip("/")
            if name in ("", "."):
                continue
            path = pathlib.PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe archive path: {raw_name}")
            if posixpath.normpath(name) != name:
                raise ValueError(f"non-canonical archive path: {raw_name}")
            if name in seen:
                raise ValueError(f"duplicate archive path: {raw_name}")
            if member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                raise ValueError(f"unsupported archive entry: {raw_name}")
            if not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError(f"unsupported archive entry type: {raw_name}")
            seen.add(name)
            members.append((name, member.issym()))
            total_size += member.size
            if len(members) > 200_000 or total_size > 8 * 1024**3:
                raise ValueError("backup archive exceeds safety limits")
except (OSError, tarfile.TarError, ValueError) as exc:
    raise SystemExit(f"invalid backup archive: {exc}")

symlinks = {name for name, is_symlink in members if is_symlink}
for name, _ in members:
    parts = pathlib.PurePosixPath(name).parts
    for index in range(1, len(parts)):
        if "/".join(parts[:index]) in symlinks:
            raise SystemExit(f"archive path descends through a symlink: {name}")
PY
}

snapshot_copy() {
  local stage=$1 rel=$2 src dst
  src=$(fs_path "/$rel")
  dst="$stage/$rel"
  [[ -e "$src" || -L "$src" ]] || return 0
  mkdir -p "$(dirname "$dst")"
  cp -a "$src" "$dst"
}

validate_service_state_snapshot() {
  local state_file=$1 unit enabled active extra allowed_file recorded_file
  [[ -f "$state_file" && ! -L "$state_file" ]] ||
    die "backup service-state snapshot is missing or unsafe"
  allowed_file=$(mktemp "$(dirname "$state_file")/.allowed-units.XXXXXX")
  recorded_file=$(mktemp "$(dirname "$state_file")/.recorded-units.XXXXXX")
  managed_service_units >"$allowed_file"
  while IFS=$'\t' read -r unit enabled active extra; do
    [[ -n "$unit" && -n "$enabled" && -n "$active" && -z "${extra:-}" ]] ||
      die "backup service-state snapshot contains a malformed row"
    grep -Fxq -- "$unit" "$allowed_file" ||
      die "backup service-state snapshot contains an unmanaged unit: $unit"
    if grep -Fxq -- "$unit" "$recorded_file"; then
      die "backup service-state snapshot contains a duplicate unit: $unit"
    fi
    printf '%s\n' "$unit" >>"$recorded_file"
    case "$enabled" in
      enabled|enabled-runtime|disabled|static|indirect|generated|alias|linked|linked-runtime|masked|masked-runtime|transient|unknown) ;;
      *) die "backup service-state snapshot has invalid enablement for $unit" ;;
    esac
    case "$active" in
      active|inactive|failed|activating|deactivating|reloading|maintenance|unknown) ;;
      *) die "backup service-state snapshot has invalid activity for $unit" ;;
    esac
  done <"$state_file"
  rm -f -- "$allowed_file" "$recorded_file"
}

validate_backup_manifest() {
  local stage=$1
  local manifest="$stage/.dnscomplex-backup/manifest.tsv"
  local format="$stage/.dnscomplex-backup/format"
  local mode=${2:-standard}
  local status rel extra allowed_file optional_file recorded_file

  [[ "$mode" == "standard" || "$mode" == "legacy-migration" ]] ||
    die "unsupported backup validation mode"

  [[ -f "$format" && ! -L "$format" ]] || die "backup format marker is missing or unsafe"
  [[ "$(<"$format")" == "2" ]] || die "unsupported dnscomplex backup format"
  [[ -f "$manifest" && ! -L "$manifest" ]] || die "backup manifest is missing or unsafe"
  [[ -f "$stage/.dnscomplex-backup/service-state.tsv" &&
     ! -L "$stage/.dnscomplex-backup/service-state.tsv" ]] ||
    die "backup service-state snapshot is missing or unsafe"
  validate_service_state_snapshot "$stage/.dnscomplex-backup/service-state.tsv"

  allowed_file=$(mktemp "$stage/.dnscomplex-backup/.allowed-paths.XXXXXX")
  optional_file=$(mktemp "$stage/.dnscomplex-backup/.optional-paths.XXXXXX")
  recorded_file=$(mktemp "$stage/.dnscomplex-backup/.recorded-paths.XXXXXX")
  managed_backup_paths >"$allowed_file"
  optional_backup_paths >"$optional_file"

  while IFS=$'\t' read -r status rel extra; do
    [[ -n "$status" && -n "$rel" && -z "${extra:-}" ]] ||
      die "backup manifest contains a malformed row"
    case "$status" in
      present|absent) ;;
      overlay|preserve)
        [[ "$mode" == "legacy-migration" ]] ||
          die "backup manifest contains an invalid state for $rel"
        ;;
      *) die "backup manifest contains an invalid state for $rel" ;;
    esac
    grep -Fxq -- "$rel" "$allowed_file" ||
      die "backup manifest contains an unmanaged path: $rel"
    if grep -Fxq -- "$rel" "$recorded_file"; then
      die "backup manifest contains a duplicate path: $rel"
    fi
    printf '%s\n' "$rel" >>"$recorded_file"
    if [[ "$status" == "present" ]]; then
      [[ -e "$stage/$rel" || -L "$stage/$rel" ]] ||
        die "backup manifest marks a missing path as present: $rel"
    elif [[ -e "$stage/$rel" || -L "$stage/$rel" ]]; then
      if [[ "$status" == "overlay" &&
            -d "$stage/$rel" && ! -L "$stage/$rel" ]]; then
        :
      else
        die "backup manifest marks an unaccepted path as archived: $rel"
      fi
    fi
  done <"$manifest"

  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    if ! grep -Fxq -- "$rel" "$recorded_file"; then
      grep -Fxq -- "$rel" "$optional_file" ||
        die "backup manifest omits managed path: $rel"
    fi
  done <"$allowed_file"
  rm -f -- "$allowed_file" "$optional_file" "$recorded_file"
}

restore_service_state() {
  local state_file=$1 unit enabled active extra
  local failed=0
  validate_service_state_snapshot "$state_file"
  service_state_supported || {
    warn "service state was not applied because this is an offline filesystem root"
    return 0
  }

  systemctl daemon-reload || failed=1
  while IFS=$'\t' read -r unit enabled active extra; do
    [[ -n "$unit" ]] || continue
    case "$enabled" in
      enabled)
        systemctl unmask "$unit" >/dev/null 2>&1 || true
        systemctl enable "$unit" || failed=1
        ;;
      enabled-runtime)
        systemctl unmask "$unit" >/dev/null 2>&1 || true
        systemctl enable --runtime "$unit" || failed=1
        ;;
      disabled)
        systemctl unmask "$unit" >/dev/null 2>&1 || true
        systemctl disable "$unit" || failed=1
        ;;
      masked)
        systemctl mask "$unit" || failed=1
        ;;
      masked-runtime)
        systemctl mask --runtime "$unit" || failed=1
        ;;
      static|indirect|generated|alias|linked|linked-runtime|transient|unknown)
        ;;
      *)
        die "backup service-state snapshot has invalid enablement for $unit"
        ;;
    esac

  done <"$state_file"

  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    enabled=$(awk -F '\t' -v target="$unit" '$1 == target { print $2; exit }' "$state_file")
    active=$(awk -F '\t' -v target="$unit" '$1 == target { print $3; exit }' "$state_file")
    [[ -n "$enabled" && -n "$active" ]] || continue
    case "$active" in
      active|activating|reloading)
        systemctl restart "$unit" || failed=1
        ;;
      inactive|failed|deactivating|maintenance|unknown)
        systemctl stop "$unit" || failed=1
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        ;;
      *)
        die "backup service-state snapshot has invalid activity for $unit"
        ;;
    esac
  done < <(restore_service_units_in_order)
  [[ "$failed" == "0" ]] || die "one or more restored service states could not be applied"
}

restore_quiesce_units() {
  cat <<'EOF'
dnscomplex-network-ready.service
dnscomplex-health.timer
dnscomplex-health.service
dnscomplex-update.timer
dnscomplex-update.service
dnscomplex-cn-overrides.timer
dnscomplex-cn-overrides.service
dnscomplex-nftset-refresh.timer
dnscomplex-nftset-refresh.service
dnscomplex-metrics-sample.timer
dnscomplex-metrics-sample.service
dnscomplex-metrics.service
dnscomplex-web.service
smartdns.service
AdGuardHome.service
sing-box.service
xray-dnscomplex.service
dnscomplex-routing.service
dnscomplex-ipsec-ready.service
strongswan-swanctl.service
strongswan-starter.service
strongswan.service
ipsec.service
dnscomplex-ipsec-ifaces.service
EOF
}

durable_sync_path() {
  local path=$1
  sync -f "$path" 2>/dev/null || sync
}

restore_state_directory() {
  fs_path /var/lib/dnscomplex-restore
}

restore_recovery_helper() {
  fs_path /usr/local/libexec/dnscomplex-restore-recover
}

verify_restore_recovery_helper() {
  local helper
  helper=$(restore_recovery_helper)
  [[ -x "$helper" ]] ||
    die "restore recovery helper is unavailable: $helper"
  "$helper" --check ||
    die "restore recovery helper self-check failed: $helper"
}

run_restore_recovery() {
  local transaction=$1 helper state_dir
  helper=$(restore_recovery_helper)
  state_dir=$(restore_state_directory)
  [[ -x "$helper" ]] || {
    warn "restore recovery helper is unavailable: $helper"
    return 1
  }
  DNSCOMPLEX_RESTORE_STATE_DIR="$state_dir" \
    "$helper" --transaction "$transaction"
}

quiesce_restore_services() {
  local unit state
  service_state_supported || return 0
  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    state=$(systemctl is-active "$unit" 2>/dev/null || true)
    case "$state" in
      active|activating|reloading|deactivating)
        systemctl stop "$unit" ||
          die "could not stop $unit before restore"
        state=$(systemctl is-active "$unit" 2>/dev/null || true)
        case "$state" in
          active|activating|reloading|deactivating)
            die "$unit remained active during restore"
            ;;
        esac
        ;;
    esac
  done < <(restore_quiesce_units)
}

restore_v2_backup() (
  set -eE
  local stage=$1 mode=${2:-standard}
  local rel status journal_status extra src dst parent base slot had_old
  local state_dir transaction="" entries manifest
  DNSCOMPLEX_ACTIVE_RESTORE_TRANSACTION=""
  manifest="$stage/.dnscomplex-backup/manifest.tsv"

  restore_transaction_exit() {
    local rc=$? recovery_rc=0
    local active_transaction=${DNSCOMPLEX_ACTIVE_RESTORE_TRANSACTION:-}
    trap - EXIT HUP INT TERM
    if [[ -n "$active_transaction" && -d "$active_transaction" ]]; then
      run_restore_recovery "$active_transaction" || recovery_rc=$?
    fi
    if [[ "$recovery_rc" != "0" ]]; then
      warn "restore rollback is incomplete; recovery journal retained at $active_transaction"
      exit 1
    fi
    exit "$rc"
  }
  trap restore_transaction_exit EXIT
  trap 'exit 130' HUP INT TERM

  validate_backup_manifest "$stage" "$mode"
  verify_restore_recovery_helper
  state_dir=$(restore_state_directory)
  [[ ! -L "$state_dir" ]] || die "restore state directory must not be a symlink"
  mkdir -p -- "$state_dir"
  chmod 0700 "$state_dir"
  transaction=$(mktemp -d "$state_dir/transaction.XXXXXX")
  DNSCOMPLEX_ACTIVE_RESTORE_TRANSACTION=$transaction
  chmod 0700 "$transaction"
  entries="$transaction/entries.tsv"
  : >"$entries"
  chmod 0600 "$entries"
  snapshot_service_state "$transaction/pre-service-state.tsv"
  chmod 0600 "$transaction/pre-service-state.tsv"
  durable_sync_path "$transaction"

  : >"$transaction/services-quiescing"
  chmod 0600 "$transaction/services-quiescing"
  durable_sync_path "$transaction"
  quiesce_restore_services

  while IFS=$'\t' read -r status rel extra; do
    src="$stage/$rel"
    dst=$(fs_path "/$rel")
    [[ "$dst" != "/" && -n "$dst" &&
       "$dst" != *$'\t'* && "$dst" != *$'\n'* ]] ||
      die "refusing unsafe restore destination"
    parent=$(dirname "$dst")
    base=$(basename "$dst")
    mkdir -p -- "$parent"
    slot=$(mktemp -d "$parent/.dnscomplex-restore.${base}.XXXXXX")
    chmod 0700 "$slot"
    had_old=0
    [[ -e "$dst" || -L "$dst" ]] && had_old=1
    journal_status=$status
    case "$status" in
      overlay) journal_status=present ;;
      preserve)
        if [[ "$had_old" == "1" ]]; then
          journal_status=present
        else
          journal_status=absent
        fi
        ;;
    esac
    printf '%s\t%s\t%s\t%s\n' \
      "$journal_status" "$dst" "$slot" "$had_old" >>"$entries"
    durable_sync_path "$entries"
    case "$status" in
      present)
        cp -a -- "$src" "$slot/candidate"
        ;;
      overlay)
        if [[ "$had_old" == "1" ]]; then
          [[ -d "$dst" && ! -L "$dst" ]] ||
            die "legacy directory overlay requires a current directory: $dst"
          cp -a -- "$dst" "$slot/candidate"
        else
          mkdir -p -- "$slot/candidate"
        fi
        cp -a -- "$src/." "$slot/candidate/"
        ;;
      preserve)
        if [[ "$had_old" == "1" ]]; then
          cp -a -- "$dst" "$slot/candidate"
        fi
        ;;
      absent) ;;
      *) die "unsupported restore state after validation: $status" ;;
    esac
    durable_sync_path "$slot"
  done <"$manifest"

  while IFS=$'\t' read -r status dst slot had_old extra; do
    if [[ "$had_old" == "1" ]]; then
      mv -- "$dst" "$slot/before"
      durable_sync_path "$slot"
    fi
    if [[ "$status" == "present" ]]; then
      mv -- "$slot/candidate" "$dst"
    fi
    durable_sync_path "$(dirname "$dst")"
  done <"$entries"

  if [[ "$mode" == "legacy-migration" ]]; then
    legacy_reconcile_cmd ||
      die "legacy backup reconciliation failed"
  fi
  restore_service_state "$stage/.dnscomplex-backup/service-state.tsv"
  : >"$transaction/committed"
  chmod 0600 "$transaction/committed"
  durable_sync_path "$transaction"
  run_restore_recovery "$transaction"
  transaction=""
  DNSCOMPLEX_ACTIVE_RESTORE_TRANSACTION=""
  trap - EXIT HUP INT TERM
)

validate_legacy_backup_stage() {
  local stage=$1 allowed_file
  allowed_file=$(mktemp "$(dirname "$stage")/.legacy-allowed.XXXXXX")
  legacy_backup_paths >"$allowed_file"
  python3 - "$stage" "$allowed_file" <<'PY'
import os
import sys

stage, allowed_path = sys.argv[1:3]
with open(allowed_path, "r", encoding="utf-8") as fh:
    allowed = tuple(line.strip() for line in fh if line.strip())

for root, dirs, files in os.walk(stage, followlinks=False):
    for name in dirs + files:
        path = os.path.join(root, name)
        rel = os.path.relpath(path, stage).replace(os.sep, "/")
        accepted = any(
            rel == item
            or rel.startswith(item + "/")
            or item.startswith(rel + "/")
            for item in allowed
        )
        if not accepted:
            raise SystemExit(f"legacy backup contains an unmanaged path: {rel}")
PY
  rm -f -- "$allowed_file"
}

convert_legacy_backup_stage() {
  local legacy_stage=$1 converted=$2 rel src dst status
  validate_legacy_backup_stage "$legacy_stage"
  mkdir -p "$converted/.dnscomplex-backup"
  printf '2\n' >"$converted/.dnscomplex-backup/format"
  : >"$converted/.dnscomplex-backup/manifest.tsv"
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    src="$legacy_stage/$rel"
    if [[ -e "$src" || -L "$src" ]]; then
      dst="$converted/$rel"
      mkdir -p "$(dirname "$dst")"
      cp -a -- "$src" "$dst"
      if [[ -d "$src" && ! -L "$src" ]]; then
        status=overlay
      else
        status=present
      fi
    else
      status=preserve
    fi
    printf '%s\t%s\n' "$status" "$rel" \
      >>"$converted/.dnscomplex-backup/manifest.tsv"
  done < <(managed_backup_paths)
  snapshot_service_state "$converted/.dnscomplex-backup/service-state.tsv"
  validate_backup_manifest "$converted" legacy-migration
}

repair_monitoring_warning_cmd() {
  warn "repair monitoring reported a warning"
  if [[ "${DNSCOMPLEX_OPERATION_INTERNAL:-0}" == 1 && "${DNSCOMPLEX_OPERATION_ID:-}" =~ ^[a-f0-9]{32}$ ]]; then
    local marker
    marker="$(fs_path /var/lib/dnscomplex-operations)/$DNSCOMPLEX_OPERATION_ID/repair-monitoring-warning"
    [[ -d "${marker%/*}" && ! -L "$marker" ]] || return 1
    if [[ ! -e "$marker" ]]; then
      (umask 077; set -C; printf 'monitoring\n' >"$marker") || return $?
    fi
  fi
}

legacy_reconcile_cmd() {
  local key unit
  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    unset "$key"
  done < <(config_schema_keys)
  load_config
  migrate_config_cmd
  remove_macbook_air_local_override
  apply_runtime_network_settings
  render_xray_config_cmd
  write_singbox_egress_cmd
  write_nftables_runtime_cmd
  render_adguard_runtime
  write_update_timer_cmd
  systemctl daemon-reload
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    systemctl restart nftables
    for unit in dnsmasq.service radvd.service systemd-resolved.service; do
      if unit_exists "$unit"; then
        systemctl disable --now "$unit"
      fi
    done
  else
    systemctl restart systemd-networkd dnsmasq radvd nftables
  fi
  restart_ipsec_service
  systemctl restart dnscomplex-ipsec-ifaces
  systemctl enable --now xray-dnscomplex
  systemctl restart xray-dnscomplex sing-box
  systemctl enable --now dnscomplex-metrics dnscomplex-metrics-sample.timer || repair_monitoring_warning_cmd
  systemctl restart dnscomplex-metrics || repair_monitoring_warning_cmd
  "${BASH_SOURCE[0]}" ipsec-ready
  "${BASH_SOURCE[0]}" routes up
  systemctl reset-failed \
    dnscomplex-network-ready \
    dnscomplex-ipsec-ready \
    dnscomplex-routing
  systemctl restart \
    dnscomplex-network-ready \
    dnscomplex-ipsec-ready \
    dnscomplex-routing
  restart_dns_stack
  test_cmd
}

sqlite_backup() {
  local source=$1 destination=$2
  python3 - "$source" "$destination" <<'PY'
import os
import sqlite3
import sys
import urllib.parse

source, destination = sys.argv[1:3]
os.makedirs(os.path.dirname(destination), exist_ok=True)
uri = "file:" + urllib.parse.quote(source) + "?mode=ro"
src = sqlite3.connect(uri, uri=True, timeout=30)
dst = sqlite3.connect(destination, timeout=30)
try:
    with dst:
        src.backup(dst)
    if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise SystemExit("SQLite backup integrity check failed")
finally:
    dst.close()
    src.close()
PY
}

update_software_impl() {
  need_root
  local before component_rc rollback_rc
  UPDATED_SERVICES=()
  before=$(mktemp -d)
  update_software_stage "backup current config and release binaries"
  if ! backup_cmd "$before/dnscomplex-pre-update.tar.gz"; then
    rm -rf "$before"
    die "software update stopped because the pre-update backup failed"
  fi
  if ! backup_release_binaries "$before/bin"; then
    rm -rf "$before"
    die "software update stopped because release binaries could not be backed up"
  fi
  set +e
  (
    set -e
    write_config_cmd
    update_software_stage "manually approved unverified GitHub release assets channel=${DNSCOMPLEX_UPDATE_CHANNEL:-stable} policy=${GITHUB_RELEASE_POLICY:-latest} pinned=${DNSCOMPLEX_PINNED_VERSION:-}"
    update_release_if_needed sing-box SagerNet/sing-box sing-box install_singbox_release
    update_release_if_needed smartdns pymumu/smartdns smartdns install_smartdns_release
    update_release_if_needed AdGuardHome AdguardTeam/AdGuardHome AdGuardHome install_adguardhome_release
    update_release_if_needed xray XTLS/Xray-core xray-dnscomplex install_xray_release
    update_software_stage "dnscomplex installer/schema validation"
    "$0" validate-config "$CONFIG"
    update_software_stage "config validation"
    sing-box check -c /etc/sing-box/config.json
    xray run -test -format=json -config /usr/local/etc/xray/config.json
    nft -c -f /etc/nftables.conf
    if ((${#UPDATED_SERVICES[@]} > 0)); then
      update_software_stage "restart changed services: ${UPDATED_SERVICES[*]}"
      systemctl restart "${UPDATED_SERVICES[@]}"
    else
      update_software_stage "no GitHub component changed; no service restart needed"
    fi
    update_software_stage "restore selected egress readiness"
    "$0" ipsec-ready
    "$0" routes up
    update_software_stage "post-update health validation"
    "$0" test
  )
  component_rc=$?
  set -e
  if [[ "$component_rc" != "0" ]]; then
    warn "dnscomplex component update failed with status $component_rc; starting application rollback"
    rollback_rc=0
    rollback_component_update "$before" || rollback_rc=$?
    rm -rf "$before"
    if [[ "$rollback_rc" != "0" ]]; then
      die "software component update failed and application rollback was incomplete"
    fi
    die "software component update failed and application changes were rolled back"
  fi
  rm -rf "$before"
}

update_software_cmd() {
  need_root
  acquire_maintenance_lock
  local requested_channel="" requested_version="" allow_unverified=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --allow-unverified-release-assets)
        allow_unverified=1
        shift
        ;;
      --channel)
        requested_channel=${2:-}
        shift 2
        ;;
      --version)
        requested_version=${2:-}
        shift 2
        ;;
      *)
        die "usage: dnscomplex update-software --allow-unverified-release-assets [--channel stable|beta|pinned] [--version VERSION]"
        ;;
    esac
  done
  [[ "$allow_unverified" == "1" ]] ||
    die "GitHub release assets are not covered by a uniform trusted signature chain; rerun manually with --allow-unverified-release-assets only after reviewing the selected upstream releases"
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

system_update_impl() {
  need_root
  export DEBIAN_FRONTEND=noninteractive
  update_software_stage "Debian apt update (external VM rollback required)"
  apt-get update ||
    die "Debian apt metadata update failed; no dnscomplex rollback was attempted"
  update_software_stage "Debian apt upgrade (external VM rollback required)"
  apt-get \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    upgrade -y --with-new-pkgs ||
    die "Debian package update failed and may be partially applied; inspect apt/dpkg state or restore the external VM snapshot"
  update_software_stage "post-system-update dnscomplex validation"
  test_cmd ||
    die "Debian package update completed but dnscomplex validation failed; no OS rollback was attempted"
}

system_update_cmd() {
  need_root
  acquire_maintenance_lock
  [[ $# -eq 1 && "$1" == "--acknowledge-no-os-rollback" ]] ||
    die "usage: dnscomplex system-update --acknowledge-no-os-rollback (create an external VM snapshot first)"
  system_update_impl
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
  local duration=30m clients=50 dns_qps=50 profiles=ai,cn,default idle_resume=0 output_json=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --duration) duration=$2; shift 2 ;;
      --clients) clients=$2; shift 2 ;;
      --dns-qps) dns_qps=$2; shift 2 ;;
      --profiles) profiles=$2; shift 2 ;;
      --idle-resume) idle_resume=1; shift ;;
      --output-json) output_json=$2; shift 2 ;;
      *) die "unknown soak option: $1" ;;
    esac
  done
  [[ "$clients" =~ ^[0-9]+$ ]] || die "--clients must be numeric"
  [[ "$dns_qps" =~ ^[0-9]+$ ]] || die "--dns-qps must be numeric"
  mkdir -p /var/log/dnscomplex
  local args=(/usr/local/lib/dnscomplex-soak/runner.py --duration "$duration" --clients "$clients" --dns-qps "$dns_qps" --profiles "$profiles")
  [[ "$idle_resume" == "1" ]] && args+=(--idle-resume)
  [[ -n "$output_json" ]] && args+=(--output-json "$output_json")
  "${args[@]}"
}

backup_cmd() {
  need_root
  local output=${1:-"/var/backups/dnscomplex-$(date +%Y%m%d-%H%M%S).tar.gz"}
  local output_dir output_base
  acquire_maintenance_lock
  output_dir=$(dirname "$output")
  output_base=$(basename "$output")
  mkdir -p "$output_dir"

  (
    set -e
    local stage="" verify="" temp_output="" rel live_db archived_db
    local present_count=0
    local -a archive_paths=()
    cleanup_backup_stage() {
      [[ -z "$stage" ]] || rm -rf -- "$stage"
      [[ -z "$verify" ]] || rm -rf -- "$verify"
      [[ -z "$temp_output" ]] || rm -f -- "$temp_output"
    }
    trap cleanup_backup_stage EXIT
    trap 'exit 1' HUP INT TERM

    stage=$(mktemp -d)
    verify=$(mktemp -d)
    temp_output=$(mktemp "$output_dir/.${output_base}.XXXXXX")

    mkdir -p "$stage/.dnscomplex-backup"
    printf '2\n' >"$stage/.dnscomplex-backup/format"
    : >"$stage/.dnscomplex-backup/manifest.tsv"
    while IFS= read -r rel; do
      [[ -n "$rel" ]] || continue
      snapshot_copy "$stage" "$rel"
      if [[ -e "$stage/$rel" || -L "$stage/$rel" ]]; then
        printf 'present\t%s\n' "$rel" >>"$stage/.dnscomplex-backup/manifest.tsv"
        archive_paths+=("./$rel")
        present_count=$((present_count + 1))
      else
        printf 'absent\t%s\n' "$rel" >>"$stage/.dnscomplex-backup/manifest.tsv"
      fi
    done < <(managed_backup_paths)
    snapshot_service_state "$stage/.dnscomplex-backup/service-state.tsv"
    archive_paths=("./.dnscomplex-backup" "${archive_paths[@]}")

    rm -f \
      "$stage/var/lib/dnscomplex/metrics.sqlite3-wal" \
      "$stage/var/lib/dnscomplex/metrics.sqlite3-shm" \
      "$stage/var/lib/dnscomplex/metrics.sqlite3-journal"
    live_db=$(fs_path /var/lib/dnscomplex/metrics.sqlite3)
    archived_db="$stage/var/lib/dnscomplex/metrics.sqlite3"
    if [[ -f "$live_db" ]]; then
      rm -f "$archived_db"
      sqlite_backup "$live_db" "$archived_db"
    fi

    ((present_count > 0)) || die "no dnscomplex state was available to back up"
    validate_backup_manifest "$stage"
    tar -czf "$temp_output" -C "$stage" -- "${archive_paths[@]}"
    validate_backup_archive "$temp_output"
    if tar -tzf "$temp_output" | grep -Eq 'metrics[.]sqlite3-(wal|shm|journal)$'; then
      die "backup archive contains transient SQLite sidecar files"
    fi
    if [[ -f "$archived_db" ]]; then
      tar -xzf "$temp_output" -C "$verify" ./var/lib/dnscomplex/metrics.sqlite3
      python3 - "$verify/var/lib/dnscomplex/metrics.sqlite3" <<'PY'
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
try:
    result = db.execute("PRAGMA integrity_check").fetchone()[0]
finally:
    db.close()
if result != "ok":
    raise SystemExit("archived SQLite integrity check failed")
PY
    fi
    chmod 0600 "$temp_output"
    mv -f "$temp_output" "$output"
    temp_output=""
  )
  log "backup written: $output"
}

restore_cmd() {
  need_root
  [[ $# -eq 1 ]] || die "usage: dnscomplex restore INPUT_TAR_GZ"
  [[ -f "$1" && ! -L "$1" ]] || die "backup archive must be a regular file"
  acquire_maintenance_lock
  (
    set -e
    local workspace="" stage="" archive_copy="" converted=""
    cleanup_restore_stage() {
      [[ -z "${workspace:-}" ]] || rm -rf -- "$workspace"
    }
    trap cleanup_restore_stage EXIT
    workspace=$(mktemp -d)
    stage="$workspace/content"
    archive_copy="$workspace/input.tar.gz"
    mkdir -p "$stage"
    cp -- "$1" "$archive_copy"
    chmod 0600 "$archive_copy"
    validate_backup_archive "$archive_copy"
    tar -xzf "$archive_copy" -C "$stage"
    if [[ -e "$stage/.dnscomplex-backup/format" ||
          -L "$stage/.dnscomplex-backup/format" ]]; then
      restore_v2_backup "$stage"
    else
      converted="$workspace/converted"
      convert_legacy_backup_stage "$stage" "$converted"
      restore_v2_backup "$converted" legacy-migration
    fi
  )
}

# Operation records are deliberately outside managed_backup_paths: restoring BASE
# must never replace the recovery material for the operation doing the restore.
state_operation_record_cmd() {
  python3 - "$@" <<'OPERATION_RECORD'
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import uuid


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def regular(path):
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise ValueError("recovery material must be a regular file")


def digest(path):
    regular(path)
    with path.open('rb') as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
        os.fsync(stream.fileno())
    return value.hexdigest()


def save(directory, record):
    path = directory / 'manifest.json.tmp'
    with open(path, 'w', encoding='utf-8', opener=lambda p, f: os.open(p, f, 0o600)) as out:
        json.dump(record, out, sort_keys=True)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())
    os.replace(path, directory / 'manifest.json')
    sync_dir(directory)


try:
    action, location, *args = sys.argv[1:]
    directory = Path(location)
    if action == 'create':
        # Fail closed on unsafe ancestry, malformed records, and unresolved work.
        for ancestor in (directory, *list(directory.parents)[:3]):
            if ancestor.is_symlink():
                raise ValueError('operation directory ancestry must not contain symlinks')
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        sync_dir(directory.parent)
        for prior in directory.iterdir():
            if re.fullmatch(r'\.operation-(?:submit|create)\.[a-f0-9]{32}',prior.name):
                value=prior.lstat()
                if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or value.st_mode & 0o077:
                    raise ValueError('unsafe operation staging')
                shutil.rmtree(prior)
                sync_dir(directory)
                continue
            if prior.is_symlink() or not prior.is_dir():
                raise ValueError('unsafe operation record')
            regular(prior / 'manifest.json')
            record = json.loads((prior / 'manifest.json').read_text())
            if record.get('schema_version') != 1 or record.get('phase') not in ('committed', 'rolled-back'):
                raise ValueError('unresolved operation blocks a new state transaction')
        if shutil.disk_usage(directory).free < 1024 * 1024:
            raise ValueError('insufficient operation storage space')
        operation = directory / ('.operation-create.'+uuid.uuid4().hex)
        operation.mkdir(mode=0o700)
        sync_dir(directory)
        print(operation)
    elif action == 'prepare':
        label, target, default = args
        operation_id=directory.name.removeprefix('.operation-create.')
        if not re.fullmatch('[a-f0-9]{32}',operation_id): raise ValueError('invalid operation ID')
        published=directory.parent/operation_id
        archive = directory / 'backup.tar.gz'
        os.chmod(archive, 0o600)
        archive_sha = digest(archive)
        custom = {'enabled': target != default, 'had_original': False}
        if custom['enabled']:
            target_path = Path(target)
            if target_path.is_symlink() or (target_path.exists() and not target_path.is_file()):
                raise ValueError('unsafe custom config path')
            target_file = directory / 'custom-target.json'
            with open(target_file, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as out:
                json.dump(target, out)
                out.flush()
                os.fsync(out.fileno())
            custom['target_file'] = target_file.name
            if target_path.exists():
                snapshot = directory / 'custom-config'
                shutil.copyfile(target_path, snapshot)
                os.chmod(snapshot, 0o600)
                custom.update(had_original=True, snapshot=snapshot.name, sha256=digest(snapshot))
        safe_label = label if re.fullmatch(r'(?:set-egress (?:ai|cn) (?:ipsec|xray)|set-xray-(?:uri|json) (?:ai|cn)|config apply)', label) else 'state-change'
        inherited = {}
        if (directory / 'manifest.json').exists():
            regular(directory / 'manifest.json')
            previous = json.loads((directory / 'manifest.json').read_text())
            inherited = {key: previous[key] for key in ('action','owner_unit','deadline','error_code') if key in previous}
        save(directory, {**inherited, 'schema_version': 1, 'id': operation_id, 'label': safe_label,
                         'phase': 'prepared', 'archive': {'path': archive.name, 'sha256': archive_sha},
                         'custom_config': custom, 'candidate_rc': None, 'rollback_rc': None,
                         'custom_config_rc': None, 'rollback_state': 'not-started'})
        if directory != published:
            if published.exists() or published.is_symlink(): raise ValueError('operation ID collision')
            os.rename(directory,published)
            sync_dir(published.parent)
    else:
        regular(directory / 'manifest.json')
        record = json.loads((directory / 'manifest.json').read_text())
        if action == 'verify':
            if digest(directory / record['archive']['path']) != record['archive']['sha256']:
                raise ValueError('rollback archive integrity check failed')
            custom = record['custom_config']
            if custom.get('had_original') and digest(directory / custom['snapshot']) != custom['sha256']:
                raise ValueError('custom config snapshot integrity check failed')
        elif action == 'phase':
            phase, candidate_rc, rollback_rc, config_rc = args
            if phase not in ('applying', 'rolling-back', 'rolled-back', 'committed', 'recovery-required'):
                raise ValueError('invalid operation phase')
            record.update(phase=phase, candidate_rc=int(candidate_rc), rollback_rc=int(rollback_rc),
                          custom_config_rc=int(config_rc), rollback_state={
                              'rolling-back': 'running', 'rolled-back': 'verified',
                              'recovery-required': 'failed'}.get(phase, 'not-started'))
            save(directory, record)
        elif action == 'restore-custom':
            custom = record['custom_config']
            if custom['enabled']:
                regular(directory / custom['target_file'])
                target = Path(json.loads((directory / custom['target_file']).read_text()))
                if target.is_symlink():
                    raise ValueError('custom config target became a symlink')
                if custom['had_original']:
                    snapshot = directory / custom['snapshot']
                    if digest(snapshot) != custom['sha256']:
                        raise ValueError('custom config snapshot integrity check failed')
                    shutil.copyfile(snapshot, target)
                    os.chmod(target, 0o600)
                    if digest(target) != custom['sha256']:
                        raise ValueError('custom config restore verification failed')
                else:
                    target.unlink(missing_ok=True)
                sync_dir(target.parent)
        elif action == 'cleanup':
            if record['phase'] not in ('committed', 'rolled-back'):
                raise ValueError('cannot discard unresolved recovery material')
            for name in ('backup.tar.gz', 'custom-config', 'custom-target.json'):
                (directory / name).unlink(missing_ok=True)
            sync_dir(directory)
        else:
            raise ValueError('invalid operation record action')
except (OSError, ValueError, KeyError, TypeError) as error:
    # Never include candidate data, raw labels, custom paths, or exception values.
    print('operation record validation/storage failed: ' + type(error).__name__, file=sys.stderr)
    raise SystemExit(1)
OPERATION_RECORD
}

state_transaction_verify_backup_cmd() (
  set -e
  local archive=$1 stage=""
  trap '[[ -z "$stage" ]] || rm -rf -- "$stage"' EXIT
  validate_backup_archive "$archive"
  stage=$(mktemp -d)
  tar -xzf "$archive" -C "$stage"
  validate_backup_manifest "$stage"
  # Ensure recovery can at least stage the uncompressed data before mutation.
  python3 - "$archive" "$(fs_path /var/lib/dnscomplex-operations)" <<'BACKUP_SPACE'
import shutil
import sys
import tarfile
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    required = sum(member.size for member in archive.getmembers()) * 2 + 1024 * 1024
if shutil.disk_usage(sys.argv[2]).free < required:
    raise SystemExit('insufficient free space for transaction recovery')
BACKUP_SPACE
)

state_transaction_manager_cmd() {
  # A fresh shell is essential: an enclosing `if` suppresses errexit throughout
  # functions/subshells, including the existing backup and restore implementations.
  # Recovery must not source the possibly broken candidate config.
  DNSCOMPLEX_CONFIG="$CONFIG" DNSCOMPLEX_FS_ROOT="$FS_ROOT" \
    DNSCOMPLEX_BASE="$BASE" DNSCOMPLEX_RUN_DIR="$RUN_DIR" \
    DNSCOMPLEX_MAINTENANCE_LOCK="$MAINTENANCE_LOCK" \
    bash -c 'source "$1"; shift; "$@"' _ "${BASH_SOURCE[0]}" "$@"
}

operation_prepare_cmd() {
  local operation=$1 action=$2 config_target
  acquire_maintenance_lock || return $?
  verify_restore_recovery_helper || return $?
  config_target=$(fs_path /etc/dnscomplex/config.env) || return $?
  [[ "$CONFIG" == "$config_target" ]] || return 2
  state_transaction_manager_cmd backup_cmd "$operation/backup.tar.gz" || return $?
  state_transaction_manager_cmd state_transaction_verify_backup_cmd "$operation/backup.tar.gz" || return $?
  state_operation_record_cmd prepare "$operation" "$action" "$CONFIG" "$config_target"
}

operation_journal_cmd() (
  set -e
  local operation=$1 stage transaction manifest status rel extra dst parent slot
  local state_dir
  state_dir=$(fs_path /var/lib/dnscomplex-restore)
  stage=$(mktemp -d)
  trap 'rm -rf -- "$stage"' EXIT
  validate_backup_archive "$operation/backup.tar.gz"
  tar -xzf "$operation/backup.tar.gz" -C "$stage"
  validate_backup_manifest "$stage"
  mkdir -p -- "$state_dir"
  chmod 0700 "$state_dir"
  transaction="$state_dir/.operation-prep.${operation##*/}"
  mkdir -m 0700 -- "$transaction"
  : >"$transaction/entries.tsv"
  chmod 0600 "$transaction/entries.tsv"
  cp -- "$stage/.dnscomplex-backup/service-state.tsv" "$transaction/pre-service-state.tsv"
  chmod 0600 "$transaction/pre-service-state.tsv"
  manifest="$stage/.dnscomplex-backup/manifest.tsv"
  while IFS=$'\t' read -r status rel extra; do
    dst=$(fs_path "/$rel")
    parent=$(dirname -- "$dst")
    # Existing symlink ancestry would redirect live mutation outside the managed root.
    python3 - "$parent" <<'CHECK_OPERATION_PARENT'
from pathlib import Path
import sys
path = Path(sys.argv[1])
if any(parent.is_symlink() for parent in (path, *path.parents)):
    raise SystemExit('unsafe managed path ancestry')
CHECK_OPERATION_PARENT
    mkdir -p -- "$parent"
    slot=$(mktemp -d "$parent/.dnscomplex-restore.$(basename -- "$dst").op.${operation##*/}.XXXXXX")
    chmod 0700 "$slot"
    if [[ "$status" == "present" ]]; then
      cp -a -- "$stage/$rel" "$slot/before"
      printf 'present\t%s\t%s\t1\n' "$dst" "$slot" >>"$transaction/entries.tsv"
    else
      printf 'absent\t%s\t%s\t0\n' "$dst" "$slot" >>"$transaction/entries.tsv"
    fi
    durable_sync_path "$slot"
  done <"$manifest"
  : >"$transaction/services-quiescing"
  chmod 0600 "$transaction/services-quiescing"
  durable_sync_path "$transaction/entries.tsv"
  durable_sync_path "$transaction/pre-service-state.tsv"
  durable_sync_path "$transaction"
  # Python records snapshot hashes, then atomically publishes the complete journal.
)

operation_dispatch_cmd() {
  local operation=$1 action=$2 arguments="$1/arguments"
  local -a values=()
  load_config
  python3 "$(fs_path /usr/local/libexec/dnscomplex-operation)" arguments "$operation" "$action" >"$arguments" || return $?
  chmod 0600 "$arguments"
  mapfile -d '' -t values <"$arguments"
  rm -f -- "$arguments"
  export DNSCOMPLEX_OPERATION_ID="${operation##*/}"
  case "$action" in
    config) apply_config_json_cmd "$operation/candidate.json" ;;
    wizard-apply) apply_config_file_cmd "$operation/candidate.env" ;;
    egress-apply) apply_egress_json_cmd "$operation/payload.json" ;;
    rules-domain|rules-geosite|domain-batch)
      apply_domain_rules_json_cmd "$operation/domain-batch.json"
      ;;
    fix|set-xray-uri|set-xray-json|update-geosite|mss-calibrate|set-egress|set-socks|set-ipsec|set-web-password|set-local-host|set-update-time|add-domain|remove-domain|test-xray)
      "${action//-/_}_cmd" "${values[@]}"
      ;;
    *) return 2 ;;
  esac
}

operation_postcheck_ipsec_profile_cmd() {
  local profile=$1 sas vip
  sas=$(timeout --signal=TERM --kill-after=1s 5s swanctl --list-sas 2>/dev/null) || return $?
  ipsec_profile_runtime_ready "$profile" "$sas" || return $?
  vip=$IPSEC_STATE_READY_VIP
  profile_dataplane_probe_observe "$profile" "$vip" "$sas" || return $?
  profile_dataplane_probe_observe "$profile" "$vip" "$sas" || return $?
  profile_egress_gate_is_open "$profile"
}

operation_postcheck_selected_profile_cmd() {
  local profile=$1 mode sas vip port
  [[ "$profile" == ai || "$profile" == cn ]] || return 2
  mode=$(profile_egress_mode "$profile") || return $?
  if [[ "$mode" == ipsec ]]; then
    operation_postcheck_ipsec_profile_cmd "$profile"
  else
    [[ "$profile" == ai ]] && port=$XRAY_AI_SOCKS_PORT || port=$XRAY_CN_SOCKS_PORT
    systemctl is-active --quiet xray-dnscomplex || return $?
    curl --socks5-hostname "$XRAY_LISTEN_HOST:$port" -4 -fsS --connect-timeout 6 --max-time 12 \
      -o /dev/null https://www.cloudflare.com/cdn-cgi/trace
  fi
}

operation_postcheck_cmd() {
  local operation=$1 action=$2 profile unit
  load_config || return $?
  validate_loaded_config || return $?
  # Candidate callbacks already require persisted field readback before returning.
  case "$action" in
    set-ipsec)
      profile=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("profile",""))' "$operation/payload.json") || return $?
      operation_postcheck_ipsec_profile_cmd "$profile"
      ;;
    set-egress|egress-apply|set-xray-uri|set-xray-json)
      profile=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("profile",""))' "$operation/payload.json") || return $?
      operation_postcheck_selected_profile_cmd "$profile"
      ;;
    config|wizard-apply|fix)
      validate_smartdns_config_cmd || return $?
      sing-box check -c /etc/sing-box/config.json || return $?
      xray run -test -format=json -config /usr/local/etc/xray/config.json || return $?
      nft -c -f /etc/nftables.conf || return $?
      for unit in nftables smartdns AdGuardHome sing-box; do
        systemctl is-active --quiet "$unit" || return $?
      done
      ;;
    *) return 0 ;;
  esac
}

state_transaction_cmd() {
  local label=$1 callback=$2 operation archive config_target command_name operation_id
  local rc=0 rollback_rc=0 config_rc=0
  shift 2
  [[ -n "$label" && -n "$callback" ]] || die "state transaction requires a label and callback"
  acquire_maintenance_lock || return $?
  if [[ "${DNSCOMPLEX_OPERATION_ID:-}" =~ ^[a-f0-9]{32}$ ]]; then
    "$callback" "$@"
    return $?
  fi
  for command_name in bash python3 tar cp mv rm mkdir chmod mktemp sync; do
    command -v "$command_name" >/dev/null 2>&1 || return 1
  done
  verify_restore_recovery_helper || return $?
  config_target=$(fs_path /etc/dnscomplex/config.env) || return $?
  operation=$(state_operation_record_cmd create "$(fs_path /var/lib/dnscomplex-operations)") || return $?
  operation_id=${operation##*/}
  operation_id=${operation_id#.operation-create.}
  local DNSCOMPLEX_OPERATION_ID=$operation_id
  export DNSCOMPLEX_OPERATION_ID
  archive="$operation/backup.tar.gz"
  state_transaction_manager_cmd backup_cmd "$archive" || rc=$?
  if ((rc == 0)); then
    state_transaction_manager_cmd state_transaction_verify_backup_cmd "$archive" || rc=$?
  fi
  if ((rc == 0)); then
    state_operation_record_cmd prepare "$operation" "$label" "$CONFIG" "$config_target" || rc=$?
    # prepare publishes a complete synchronous record by atomic rename.
    if [[ -d "${operation%/*}/$operation_id" ]]; then
      operation="${operation%/*}/$operation_id"
      archive="$operation/backup.tar.gz"
    fi
  fi
  if ((rc != 0)); then
    # No callback has run: removing an incomplete preparation cannot lose live state.
    rm -rf -- "$operation"
    return "$rc"
  fi
  state_operation_record_cmd phase "$operation" applying 0 0 0 || return $?
  ( "$callback" "$@" ) || rc=$?
  if ((rc == 0)); then
    state_operation_record_cmd phase "$operation" committed 0 0 0 || rc=$?
    if ((rc == 0)); then
      state_operation_record_cmd cleanup "$operation" || warn "committed operation recovery cleanup deferred"
      return 0
    fi
  fi

  warn "state change failed; restoring the pre-change state"
  state_operation_record_cmd phase "$operation" rolling-back "$rc" 0 0 || rollback_rc=$?
  if ((rollback_rc == 0)); then
    state_operation_record_cmd verify "$operation" || rollback_rc=$?
  fi
  if ((rollback_rc == 0)); then
    state_transaction_manager_cmd restore_cmd "$archive" || rollback_rc=$?
  fi
  state_operation_record_cmd restore-custom "$operation" || config_rc=$?
  if ((rollback_rc == 0 && config_rc == 0)); then
    state_operation_record_cmd phase "$operation" rolled-back "$rc" 0 0 || rollback_rc=$?
  fi
  if ((rollback_rc != 0 || config_rc != 0)); then
    state_operation_record_cmd phase "$operation" recovery-required "$rc" "$rollback_rc" "$config_rc" || true
    warn "rollback incomplete; recovery material retained at /var/lib/dnscomplex-operations/${operation##*/}"
    return "$rc"
  fi
  state_operation_record_cmd cleanup "$operation" || warn "rolled-back operation recovery cleanup deferred"
  return "$rc"
}

test_cmd() {
  test_dns_cmd || return $?
  test_ipsec_cmd || return $?
  validate_smartdns_config_cmd || return $?
  /opt/AdGuardHome/AdGuardHome --check-config -c /etc/AdGuardHome/AdGuardHome.yaml || return $?
  sing-box check -c /etc/sing-box/config.json || return $?
  xray run -test -format=json -config /usr/local/etc/xray/config.json || return $?
  nft -c -f /etc/nftables.conf || return $?
  log "dnscomplex read-only diagnostics completed; StrongSwan runtime checked without loading credentials (candidate authentication not tested)"
}

operation_cli_bridge_eligible_cmd() {
  [[ -z "$FS_ROOT" || "$FS_ROOT" == / ]] || return 1
  [[ "$CONFIG" == /etc/dnscomplex/config.env && "${DNSCOMPLEX_OPERATION_INTERNAL:-0}" != 1 &&
     -z "${DNSCOMPLEX_OPERATION_ID:-}" && "${DNSCOMPLEX_SERVICE_MODE:-0}" != 1 &&
     "${DNSCOMPLEX_MAINTENANCE_LOCK_HELD:-0}" != 1 ]] || return 1
  case "${1:-}" in
    fix|update-geosite|apply-domain-rules-json|add-domain|remove-domain|set-socks|set-ipsec|set-web-password|set-local-host|set-egress|apply-egress-json|set-xray-uri|set-xray-json|set-update-time|mss-calibrate|apply-config|apply-config-json) ;;
    *) return 1 ;;
  esac
  [[ "${DNSCOMPLEX_TIMER_MODE:-0}" != 1 || "$1" == update-geosite ]] || return 1
  # Installer's explicit prepare-only mode remains an offline preparation seam.
  [[ "$1" != update-geosite || $# == 1 ]] || return 1
}

operation_cli_bridge_cmd() {
  local command=$1 helper
  shift
  need_root || return $?
  helper=$(fs_path /usr/local/libexec/dnscomplex-operation) || return $?
  [[ -f "$helper" ]] || die "operation helper is required for live persistent mutations"
  local -a args=("$@")
  if [[ "$command" == set-ipsec && ${#args[@]} == 3 && "${args[2]}" == - ]]; then
    read -r -s -p "IPsec password: " 'args[2]'; printf '\n'
  elif [[ "$command" == set-web-password && ${#args[@]} == 1 && "${args[0]}" == - ]]; then
    read -r -s -p "Web password: " 'args[0]'; printf '\n'
  fi
  # printf is a shell builtin. Secrets cross stdin, never an added child argv.
  printf '%s\0' "${args[@]}" | python3 "$helper" cli "$command"
}

main() {
  local cmd=${1:-help}
  if [[ "$cmd" == operation-internal && "${DNSCOMPLEX_OPERATION_INTERNAL:-0}" == 1 ]]; then
    shift
    case "${1:-}" in
      operation_prepare_cmd|operation_journal_cmd|operation_dispatch_cmd|operation_postcheck_cmd)
        local function=$1
        umask 077
        shift
        "$function" "$@"
        return $?
        ;;
      *) return 2 ;;
    esac
  fi
  if operation_cli_bridge_eligible_cmd "$@"; then
    operation_cli_bridge_cmd "$@"
    return $?
  fi
  if internal_service_command "$@"; then
    :
  elif timer_service_command "$@"; then
    acquire_maintenance_lock --wait
  elif persistent_mutator_command "$@" &&
       [[ "$cmd" != "watchdog" && "$cmd" != "health" ]]; then
    acquire_maintenance_lock
  fi
  if persistent_mutator_command "$@" && ! internal_service_command "$@"; then
    local operation_helper
    operation_helper=$(fs_path /usr/local/libexec/dnscomplex-operation)
    if [[ -f "$operation_helper" ]]; then
      python3 "$operation_helper" gate || die "unresolved operation blocks this mutation"
    fi
  fi
  load_config
  shift || true
  case "$cmd" in
    status) status_cmd "$@" ;;
    test) test_cmd "$@" ;;
    health) health_cmd "$@" ;;
    watchdog) watchdog_cmd "$@" ;;
    fix) fix_cmd "$@" ;;
    doctor) doctor_cmd "$@" ;;
    update-geosite) update_geosite_cmd "$@" ;;
    apply-domain-rules-json) apply_domain_rules_json_cmd "$@" ;;
    add-domain) add_domain_cmd "$@" ;;
    remove-domain) remove_domain_cmd "$@" ;;
    set-socks) set_socks_cmd "$@" ;;
    set-ipsec) set_ipsec_cmd "$@" ;;
    set-web-password) set_web_password_cmd "$@" ;;
    set-local-host) set_local_host_cmd "$@" ;;
    test-local-name) test_local_name_cmd "$@" ;;
    set-egress) set_egress_cmd "$@" ;;
    apply-egress-json) apply_egress_json_cmd "$@" ;;
    set-xray-uri) set_xray_uri_cmd "$@" ;;
    set-xray-json) set_xray_json_cmd "$@" ;;
    test-xray) test_xray_cmd "$@" ;;
    xray-status) xray_status_cmd "$@" ;;
    egress-ready) egress_ready_cmd "$@" ;;
    render-xray) render_xray_config_cmd "$@" ;;
    set-update-time) set_update_time_cmd "$@" ;;
    refresh-nftsets) refresh_nftsets_cmd "$@" ;;
    refresh-cn-overrides) refresh_cn_overrides_cmd "$@" ;;
    trace-domain) trace_domain_cmd "$@" ;;
    probe-egress) probe_egress_cmd "$@" ;;
    test-dns) test_dns_cmd "$@" ;;
    test-ipsec) test_ipsec_cmd "$@" ;;
    mss-calibrate) mss_calibrate_cmd "$@" ;;
    routeros-print) routeros_print_cmd "$@" ;;
    update-software) update_software_cmd "$@" ;;
    system-update) system_update_cmd "$@" ;;
    metrics-sample) metrics_sample_cmd "$@" ;;
    soak) soak_cmd "$@" ;;
    wizard) wizard_cmd "$@" ;;
    validate-config) validate_config_file_cmd "$@" ;;
    apply-config) apply_config_file_cmd "$@" ;;
    apply-config-json) apply_config_json_cmd "$@" ;;
    render-config) render_config_cmd "$@" ;;
    support-bundle) support_bundle_cmd "$@" ;;
    backup) backup_cmd "$@" ;;
    restore) restore_cmd "$@" ;;
    network-ready) network_ready_cmd "$@" ;;
    ipsec-ready) ipsec_ready_cmd "$@" ;;
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

render_egress_probe() {
  write_file /usr/local/lib/dnscomplex/probe-egress.py <<'EGRESS_PROBE'
#!/usr/bin/env python3
"""Bounded, read-only data-plane diagnostic for the generated sing-box routes."""

import argparse
import ipaddress
import json
import math
import os
import platform
import secrets
import socket
import struct
import subprocess
import sys
import time


RESOLVER_PORTS = {"default": 6053, "ai": 6054, "cn": 6055}
PROFILE_MARKS = {"default": 8228, "ai": 769, "cn": 849}
MAX_TIMEOUT = 5.0
MAX_DNS_ANSWERS = 16
MAX_MTPROTO_BODY = 4096
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
SO_MARK = getattr(socket, "SO_MARK", 36)


class ProbeFailure(Exception):
    def __init__(self, phase, reason):
        super().__init__(reason)
        self.phase = phase
        self.reason = reason


def _result(status, profile, protocol, phase, reason, **fields):
    descriptions = {
        "tcp": "TCP connect only; this does not establish application-level success.",
        "udp-echo": "Pass requires this endpoint to echo the probe nonce; ordinary QUIC servers do not.",
        "mtproto": "Pass requires an abridged MTProto resPQ response with auth_key_id=0 and the matching nonce.",
    }
    return {"status": status, "profile": profile, "protocol": protocol,
            "phase": phase, "reason": reason, **({"description": descriptions[protocol]} if protocol in descriptions else {}), **fields}


def _profile_mark(profile):
    value = os.environ.get("DNSCOMPLEX_PROBE_" + profile.upper() + "_MARK")
    if value is None:
        return PROFILE_MARKS[profile]
    try:
        mark = int(value, 10 if value.isdecimal() else 0)
    except (ValueError, TypeError):
        raise ProbeFailure("config", "invalid_profile_mark")
    if not 0 < mark <= 0xffffffff:
        raise ProbeFailure("config", "invalid_profile_mark")
    return mark if mark <= 0x7fffffff else struct.pack("=I", mark)


def _remaining(deadline, clock, phase="deadline"):
    remaining = deadline - clock()
    if remaining <= 0:
        raise ProbeFailure(phase, "deadline_exceeded")
    return remaining


def _load_config(path, deadline, clock):
    _remaining(deadline, clock)
    try:
        with open(path, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except (OSError, ValueError):
        raise ProbeFailure("config", "config_unavailable_or_invalid")
    _remaining(deadline, clock)
    if not isinstance(data, dict):
        raise ProbeFailure("config", "config_unavailable_or_invalid")
    return data


def _outbound_selection(config, profile):
    if profile == "default":
        route = config.get("route")
        if not isinstance(route, dict) or route.get("final") != "default":
            raise ProbeFailure("config", "default_route_unavailable")
        tag = "default"
    else:
        route = config.get("route")
        rules = route.get("rules") if isinstance(route, dict) else None
        if not isinstance(rules, list):
            raise ProbeFailure("config", "route_selector_unavailable")
        ipsec_tag, xray_tag = profile + "-ipsec", profile + "-xray"
        selected = set()
        for rule in rules:
            if isinstance(rule, dict) and rule.get("action") == "route":
                outbound = rule.get("outbound")
                if outbound in (ipsec_tag, xray_tag):
                    selected.add(outbound)
        if len(selected) != 1:
            reason = "selected_egress_ambiguous" if selected else "route_selector_unavailable"
            raise ProbeFailure("config", reason)
        tag = selected.pop()
        if tag == xray_tag:
            raise ProbeFailure("selection", "selected_egress_not_ipsec")

    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        raise ProbeFailure("config", "outbound_unavailable")
    matches = [item for item in outbounds if isinstance(item, dict) and item.get("tag") == tag]
    if len(matches) != 1:
        raise ProbeFailure("config", "outbound_unavailable")
    outbound = matches[0]
    if profile == "default":
        if outbound.get("type") != "direct" or outbound.get("detour"):
            raise ProbeFailure("selection", "default_outbound_unsupported")
        raw_device = outbound.get("bind_interface")
        if raw_device is not None and (not isinstance(raw_device, str) or not raw_device):
            raise ProbeFailure("config", "default_bind_interface_invalid")
        source4 = _safe_source_address(outbound.get("inet4_bind_address"), 4)
        source6 = _safe_source_address(outbound.get("inet6_bind_address"), 6)
        return outbound, raw_device, source4, source6
    expected = "ipsec-" + profile
    device = outbound.get("bind_interface")
    if outbound.get("type") != "direct" or device != expected:
        raise ProbeFailure("selection", "selected_egress_not_ipsec")
    raw_vip = outbound.get("inet4_bind_address")
    vip = _safe_source_address(raw_vip, 4, vip=True)
    return outbound, device, vip, None


def _safe_source_address(value, version, vip=False):
    if value is None:
        if vip:
            raise ProbeFailure("config", "selected_profile_vip_unavailable")
        return None
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise ProbeFailure("config", "selected_profile_vip_unavailable" if vip else "default_bind_address_invalid")
    if address.version != version:
        raise ProbeFailure("config", "selected_profile_vip_unavailable" if vip else "default_bind_address_invalid")
    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
        raise ProbeFailure("config", "unsafe_vip" if vip else "default_bind_address_unsafe")
    return str(address)


def _dns_family(config, profile):
    if profile in ("ai", "cn"):
        return socket.AF_INET, "ipv4_only"
    route = config.get("route")
    resolver = route.get("default_domain_resolver") if isinstance(route, dict) else None
    strategy = resolver.get("strategy") if isinstance(resolver, dict) else None
    if not strategy:
        strategy = config.get("dns", {}).get("strategy") if isinstance(config.get("dns"), dict) else None
    if strategy in ("ipv4_only", "prefer_ipv4"):
        return socket.AF_INET, str(strategy)
    if strategy in ("ipv6_only", "prefer_ipv6"):
        return socket.AF_INET6, str(strategy)
    raise ProbeFailure("config", "default_dns_family_ambiguous")


def _dig_resolver(host, family, port, deadline, clock):
    query_type = "A" if family == socket.AF_INET else "AAAA"
    remaining = _remaining(deadline, clock)
    command = ["dig", "+time=1", "+tries=1", "+short", query_type,
               host, "@127.0.0.1", "-p", str(port)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=remaining, check=False)
    except subprocess.TimeoutExpired:
        raise ProbeFailure("dns", "deadline_exceeded")
    except OSError:
        raise ProbeFailure("dns", "resolver_unavailable")
    _remaining(deadline, clock)
    if completed.returncode != 0:
        raise ProbeFailure("dns", "resolution_failed")
    answers = []
    for line in completed.stdout.splitlines():
        try:
            address = ipaddress.ip_address(line.strip())
        except ValueError:
            continue
        if address.version == (4 if family == socket.AF_INET else 6):
            answers.append(str(address))
        if len(answers) >= MAX_DNS_ANSWERS:
            break
    if not answers:
        raise ProbeFailure("dns", "no_address_answer")
    return answers


def _is_ip_literal(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _mtproto_frame(body):
    if len(body) % 4 or len(body) // 4 >= (1 << 24):
        raise ValueError("bad frame size")
    words = len(body) // 4
    if words < 127:
        return bytes([words]) + body
    return b"\x7f" + words.to_bytes(3, "little") + body


def _mtproto_read_frame(sock, deadline, clock):
    first = _recv_exact(sock, 1, deadline, clock, "mtproto")
    if first == b"\x7f":
        raw_len = _recv_exact(sock, 3, deadline, clock, "mtproto")
        words = int.from_bytes(raw_len, "little")
    else:
        words = first[0]
    if words < 1 or words * 4 > MAX_MTPROTO_BODY:
        raise ProbeFailure("mtproto", "invalid_frame_length")
    return _recv_exact(sock, words * 4, deadline, clock, "mtproto")


def _recv_exact(sock, size, deadline, clock, phase):
    chunks = bytearray()
    while len(chunks) < size:
        sock.settimeout(_remaining(deadline, clock))
        try:
            part = sock.recv(size - len(chunks))
        except (socket.timeout, TimeoutError):
            raise ProbeFailure(phase, "deadline_exceeded" if deadline <= clock() else "response_timeout")
        if not part:
            raise ProbeFailure(phase, "truncated_response")
        chunks.extend(part)
    return bytes(chunks)


def _probe_mtproto(sock, deadline, clock, nonce):
    sock.settimeout(_remaining(deadline, clock))
    sock.sendall(b"\xef")
    msg_id = int(time.time() * (1 << 32)) & ~3
    request_data = struct.pack("<I", 0xbe7e8ef1) + nonce
    body = struct.pack("<Q", 0) + struct.pack("<Q", msg_id) + struct.pack("<I", len(request_data)) + request_data
    sock.sendall(_mtproto_frame(body))
    response = _mtproto_read_frame(sock, deadline, clock)
    if len(response) < 8 + 8 + 4:
        raise ProbeFailure("mtproto", "invalid_frame_length")
    auth_key_id = struct.unpack_from("<Q", response, 0)[0]
    if auth_key_id != 0:
        raise ProbeFailure("mtproto", "nonzero_auth_key_id")
    data_length = struct.unpack_from("<I", response, 16)[0]
    if data_length != len(response) - 20 or data_length < 4:
        raise ProbeFailure("mtproto", "invalid_message_data_length")
    constructor = struct.unpack_from("<I", response, 20)[0]
    if constructor != 0x05162463:
        raise ProbeFailure("mtproto", "unexpected_constructor")
    if data_length < 4 + 16 + 16:
        raise ProbeFailure("mtproto", "truncated_res_pq")
    if response[24:40] != nonce:
        raise ProbeFailure("mtproto", "nonce_mismatch")
    offset = 56
    if len(response) <= offset:
        raise ProbeFailure("mtproto", "truncated_res_pq")
    first = response[offset]
    if first < 254:
        pq_length, prefix = first, 1
    elif first == 254:
        if len(response) < offset + 4:
            raise ProbeFailure("mtproto", "truncated_res_pq")
        pq_length, prefix = int.from_bytes(response[offset + 1:offset + 4], "little"), 4
    else:
        raise ProbeFailure("mtproto", "invalid_res_pq")
    pq_start = offset + prefix
    pq_end = pq_start + pq_length
    padded_end = offset + ((prefix + pq_length + 3) & ~3)
    if pq_length == 0 or padded_end > len(response):
        raise ProbeFailure("mtproto", "truncated_res_pq")
    if any(response[pq_end:padded_end]):
        raise ProbeFailure("mtproto", "invalid_res_pq")
    if padded_end + 8 > len(response):
        raise ProbeFailure("mtproto", "truncated_res_pq")
    vector_id, count = struct.unpack_from("<II", response, padded_end)
    if vector_id != 0x1CB5C415 or not 1 <= count <= 64:
        raise ProbeFailure("mtproto", "invalid_res_pq")
    if padded_end + 8 + count * 8 != len(response):
        raise ProbeFailure("mtproto", "truncated_res_pq")


def run_probe(profile, protocol, host, port=443, timeout=5, config_path="/etc/sing-box/config.json",
              *, is_linux=None, euid=None, monotonic=None, socket_factory=None, resolver=None,
              nonce_factory=None):
    clock = monotonic or time.monotonic
    started = clock()
    try:
        budget = min(float(timeout), MAX_TIMEOUT)
    except (TypeError, ValueError):
        budget = MAX_TIMEOUT
    if not math.isfinite(budget) or budget <= 0:
        return _result("unsupported", profile, protocol, "arguments", "invalid_timeout")
    deadline = started + budget
    if profile not in RESOLVER_PORTS or protocol not in ("tcp", "udp-echo", "mtproto"):
        return _result("unsupported", profile, protocol, "arguments", "invalid_profile_or_protocol")
    if not isinstance(host, str) or not host or any(c.isspace() for c in host):
        return _result("unsupported", profile, protocol, "arguments", "explicit_host_required")
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 0
    if not 1 <= port <= 65535:
        return _result("unsupported", profile, protocol, "arguments", "invalid_port")
    linux = platform.system() == "Linux" if is_linux is None else bool(is_linux)
    root = os.geteuid() == 0 if euid is None and hasattr(os, "geteuid") else euid == 0
    if not linux:
        return _result("unsupported", profile, protocol, "platform", "linux_required")
    if not root:
        return _result("unsupported", profile, protocol, "platform", "root_required")
    try:
        mark = _profile_mark(profile)
        config = _load_config(config_path, deadline, clock)
        outbound, device, source4, source6 = _outbound_selection(config, profile)
        preferred_family, strategy = _dns_family(config, profile)
        literal = _is_ip_literal(host)
        if literal:
            family = socket.AF_INET if literal.version == 4 else socket.AF_INET6
            if (profile in ("ai", "cn") or strategy in ("ipv4_only", "ipv6_only")) and family != preferred_family:
                raise ProbeFailure("dns", "target_family_mismatch")
            families = [family]
        else:
            families = [preferred_family]
            if profile == "default" and strategy == "prefer_ipv4":
                families.append(socket.AF_INET6)
            elif profile == "default" and strategy == "prefer_ipv6":
                families.append(socket.AF_INET)
        factory = socket_factory or socket.socket
        last_failure = None
        for family in families:
            _remaining(deadline, clock)
            if literal:
                addresses = [str(literal)]
            else:
                try:
                    port_resolver = RESOLVER_PORTS[profile]
                    if resolver:
                        addresses = resolver(host, family, port_resolver, deadline, clock)
                    else:
                        addresses = _dig_resolver(host, family, port_resolver, deadline, clock)
                    _remaining(deadline, clock, "dns")
                except ProbeFailure as failure:
                    last_failure = failure
                    if failure.reason == "deadline_exceeded":
                        raise
                    continue
            if not addresses:
                last_failure = ProbeFailure("dns", "no_address_answer")
                continue
            for address in addresses[:MAX_DNS_ANSWERS]:
                _remaining(deadline, clock, "connect")
                target = ipaddress.ip_address(address)
                sock_family = socket.AF_INET if target.version == 4 else socket.AF_INET6
                if sock_family != family:
                    last_failure = ProbeFailure("dns", "target_family_mismatch")
                    continue
                sock_type = socket.SOCK_STREAM if protocol in ("tcp", "mtproto") else socket.SOCK_DGRAM
                try:
                    sock = factory(sock_family, sock_type)
                except (OSError, TimeoutError):
                    last_failure = ProbeFailure("connect", "deadline_exceeded" if deadline <= clock() else "connect_failed")
                    if last_failure.reason == "deadline_exceeded":
                        raise last_failure
                    continue
                try:
                    connected = False
                    sock.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
                    if device:
                        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, device.encode() + b"\0")
                    source = source4 if sock_family == socket.AF_INET else source6
                    if source:
                        bind_address = (source, 0) if sock_family == socket.AF_INET else (source, 0, 0, 0)
                        sock.bind(bind_address)
                    sock.settimeout(_remaining(deadline, clock, "connect"))
                    target_address = (str(target), port, 0, 0) if sock_family == socket.AF_INET6 else (str(target), port)
                    sock.connect(target_address)
                    connected = True
                    _remaining(deadline, clock, "connect")
                    common = {"dns_family": "ipv4" if sock_family == socket.AF_INET else "ipv6",
                              "resolver_port": RESOLVER_PORTS[profile], "strategy": strategy}
                    if protocol == "tcp":
                        return _result("pass", profile, protocol, "connect", "tcp_connected_only", **common)
                    if protocol == "udp-echo":
                        nonce = (nonce_factory or (lambda: secrets.token_bytes(16)))()
                        sock.settimeout(_remaining(deadline, clock))
                        sock.sendall(nonce)
                        sock.settimeout(_remaining(deadline, clock, "udp_echo"))
                        try:
                            echoed = sock.recv(len(nonce) + 1)
                        except (socket.timeout, TimeoutError):
                            raise ProbeFailure("udp_echo", "deadline_exceeded" if deadline <= clock() else "response_timeout")
                        if echoed != nonce:
                            raise ProbeFailure("udp_echo", "echo_mismatch")
                        return _result("pass", profile, protocol, "udp_echo", "nonce_echoed", **common)
                    nonce = (nonce_factory or (lambda: secrets.token_bytes(16)))()
                    _probe_mtproto(sock, deadline, clock, nonce)
                    return _result("pass", profile, protocol, "mtproto", "res_pq_validated", **common)
                except ProbeFailure:
                    raise
                except (OSError, TimeoutError):
                    if connected:
                        phase = "mtproto" if protocol == "mtproto" else "udp_echo" if protocol == "udp-echo" else "connect"
                        raise ProbeFailure(phase, "deadline_exceeded" if deadline <= clock() else "socket_io_failed")
                    reason = "deadline_exceeded" if deadline <= clock() else "connect_failed"
                    last_failure = ProbeFailure("connect", reason)
                    if reason == "deadline_exceeded":
                        raise last_failure
                finally:
                    try:
                        sock.close()
                    except OSError:
                        pass
        if last_failure:
            raise last_failure
        raise ProbeFailure("connect", "connect_failed")
    except ProbeFailure as failure:
        status = "unsupported" if failure.reason in {
            "selected_egress_not_ipsec", "selected_egress_ambiguous", "route_selector_unavailable",
            "default_dns_family_ambiguous", "default_route_unavailable", "default_outbound_unsupported",
            "invalid_profile_mark", "unsafe_vip", "default_bind_address_unsafe", "default_bind_address_invalid",
            "default_bind_interface_invalid", "selected_profile_vip_unavailable", "linux_required", "root_required"
        } else "fail"
        return _result(status, profile, protocol, failure.phase, failure.reason)
    except Exception:
        return _result("fail", profile, protocol, "internal", "probe_error")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=tuple(RESOLVER_PORTS), required=True)
    parser.add_argument("--protocol", choices=("tcp", "udp-echo", "mtproto"), required=True)
    parser.add_argument("--host", required=True, help="Explicit destination host or IP; no default destination is used.")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=float, default=5, help="Total probe deadline, capped at 5 seconds.")
    parser.add_argument("--config", default="/etc/sing-box/config.json")
    args = parser.parse_args(argv)
    result = run_probe(args.profile, args.protocol, args.host, args.port, args.timeout, args.config)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
EGRESS_PROBE
  chmod_target 0755 /usr/local/lib/dnscomplex/probe-egress.py
  write_file /usr/local/lib/dnscomplex/profile-dataplane-probe.py <<'PROFILE_DATAPLANE_PROBE'
#!/usr/bin/env python3
"""Bounded, read-only TLS DoH check using explicit IPsec profile context.

The caller must include every site-specific reserved mark in reserved_marks.
This utility never chooses marks or changes routes, gates, or firewall state.
"""

import argparse
import errno
import ipaddress
import json
import math
import platform
import secrets
import socket
import ssl
import struct
import sys
import time


MAX_TIMEOUT = 5.0
MAX_CONNECT_ATTEMPTS = 3
CONNECT_ATTEMPT_TIMEOUT = 1.0
MAX_HTTP_HEADER_BYTES = 16 * 1024
MAX_DNS_MESSAGE_BYTES = 4096
SO_MARK = getattr(socket, "SO_MARK", 36)
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
PROFILE_MARKS = {"ai": 769, "cn": 849, "default": 8228}
APPROVED_PROBE_ENDPOINTS = {
    "ai": ("104.16.248.249", "cloudflare-dns.com", "openai.com"),
    "cn": ("223.6.6.6", "dns.alidns.com", "youku.com"),
}


class ProbeFailure(Exception):
    def __init__(self, phase, reason, **fields):
        super().__init__(reason)
        self.phase = phase
        self.reason = reason
        self.fields = fields


def _result(status, profile, phase, reason, started, clock, **fields):
    safe_profile = profile if profile in ("ai", "cn") else "unknown"
    elapsed_ms = max(0, int((clock() - started) * 1000))
    return {"status": status, "profile": safe_profile, "phase": phase,
            "reason": reason, "elapsed_ms": elapsed_ms, **fields}


def _remaining(deadline, clock, phase):
    value = deadline - clock()
    if value <= 0:
        raise ProbeFailure(phase, "deadline_exceeded")
    return value


def _close_socket(sock):
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass


def _normalize_domain(value, reason):
    if not isinstance(value, str) or not value or any(ch.isspace() for ch in value):
        raise ProbeFailure("arguments", reason)
    value = value.rstrip(".")
    if not value:
        raise ProbeFailure("arguments", reason)
    try:
        encoded = value.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        raise ProbeFailure("arguments", reason)
    if len(encoded) > 253:
        raise ProbeFailure("arguments", reason)
    labels = encoded.split(".")
    if any(not label or len(label) > 63 or label[0] == "-" or label[-1] == "-" or
           any(not (c.isascii() and (c.isalnum() or c == "-")) for c in label)
           for label in labels):
        raise ProbeFailure("arguments", reason)
    return encoded


def _validate_context(profile, mode, vip, device, probe_mark, resolver_ip, tls_name, query_domain, reserved_marks=()):
    if profile not in ("ai", "cn"):
        raise ProbeFailure("arguments", "profile_must_be_ai_or_cn")
    if mode == "xray":
        raise ProbeFailure("selection", "selected_egress_not_ipsec")
    if mode != "ipsec":
        raise ProbeFailure("arguments", "unsupported_egress_mode")
    if device != "ipsec-" + profile:
        raise ProbeFailure("selection", "profile_context_mismatch")
    try:
        source = ipaddress.ip_address(vip)
    except (ValueError, TypeError):
        raise ProbeFailure("arguments", "invalid_profile_vip")
    if (source.version != 4 or source.is_unspecified or source.is_loopback or
            source.is_multicast or source.is_link_local):
        raise ProbeFailure("arguments", "invalid_profile_vip")
    if isinstance(probe_mark, bool):
        raise ProbeFailure("arguments", "invalid_probe_identity")
    if not isinstance(probe_mark, int):
        raise ProbeFailure("arguments", "invalid_probe_identity")
    mark = probe_mark
    blocked_marks = set(PROFILE_MARKS.values())
    try:
        for value in reserved_marks:
            if isinstance(value, bool):
                raise ValueError
            reserved = int(value)
            if not isinstance(value, int) or not 0 < reserved <= 0xffffffff:
                raise ValueError
            blocked_marks.add(reserved)
    except (TypeError, ValueError, OverflowError):
        raise ProbeFailure("arguments", "invalid_probe_identity")
    if mark <= 0 or mark > 0x7fffffff or mark in blocked_marks:
        raise ProbeFailure("arguments", "invalid_probe_identity")
    try:
        destination = ipaddress.ip_address(resolver_ip)
    except (ValueError, TypeError):
        raise ProbeFailure("arguments", "invalid_resolver_address")
    if destination.version != 4 or not destination.is_global:
        raise ProbeFailure("arguments", "invalid_resolver_address")
    tls_host = _normalize_domain(tls_name, "invalid_tls_name")
    query = _normalize_domain(query_domain, "invalid_query_domain")
    try:
        ipaddress.ip_address(tls_host)
    except ValueError:
        pass
    else:
        raise ProbeFailure("arguments", "invalid_tls_name")
    try:
        ipaddress.ip_address(query)
    except ValueError:
        pass
    else:
        raise ProbeFailure("arguments", "invalid_query_domain")
    if (str(destination), tls_host, query) != APPROVED_PROBE_ENDPOINTS[profile]:
        raise ProbeFailure("selection", "unapproved_probe_endpoint")
    return str(source), mark, str(destination), tls_host, query


def _encode_dns_query(query_domain, txid):
    labels = query_domain.split(".")
    qname = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question, tuple(label.encode("ascii").lower() for label in labels)


def _read_dns_name(message, offset):
    labels = []
    position = offset
    next_offset = None
    visited = set()
    wire_length = 0
    while True:
        if position >= len(message) or position in visited:
            raise ProbeFailure("dns", "malformed_dns_name")
        visited.add(position)
        length = message[position]
        if length & 0xC0 == 0xC0:
            if position + 1 >= len(message):
                raise ProbeFailure("dns", "truncated_dns_name")
            pointer = ((length & 0x3F) << 8) | message[position + 1]
            if pointer >= position:
                raise ProbeFailure("dns", "malformed_dns_name")
            if next_offset is None:
                next_offset = position + 2
            position = pointer
            continue
        if length & 0xC0:
            raise ProbeFailure("dns", "malformed_dns_name")
        position += 1
        if length == 0:
            return tuple(labels), next_offset if next_offset is not None else position
        if length > 63 or position + length > len(message):
            raise ProbeFailure("dns", "truncated_dns_name")
        wire_length += length + 1
        if wire_length > 255:
            raise ProbeFailure("dns", "malformed_dns_name")
        labels.append(message[position:position + length].lower())
        position += length


def _verify_dns_response(message, txid, expected_question):
    if len(message) < 12 or len(message) > MAX_DNS_MESSAGE_BYTES:
        raise ProbeFailure("dns", "truncated_dns_message" if len(message) < 12 else "dns_message_too_large")
    response_id, flags, questions, answers, authorities, additional = struct.unpack_from("!HHHHHH", message, 0)
    if response_id != txid:
        raise ProbeFailure("dns", "transaction_id_mismatch")
    if not (flags & 0x8000) or flags & 0x7800 or flags & 0x0200:
        raise ProbeFailure("dns", "invalid_dns_response_flags")
    if flags & 0x000F:
        raise ProbeFailure("dns", "dns_rcode_nonzero")
    if questions != 1:
        raise ProbeFailure("dns", "invalid_question_count")
    question_name, offset = _read_dns_name(message, 12)
    if offset + 4 > len(message):
        raise ProbeFailure("dns", "truncated_dns_question")
    qtype, qclass = struct.unpack_from("!HH", message, offset)
    if question_name != expected_question or qtype != 1 or qclass != 1:
        raise ProbeFailure("dns", "question_mismatch")
    offset += 4

    answer_count = 0
    total_records = answers + authorities + additional
    if total_records > 256:
        raise ProbeFailure("dns", "too_many_dns_records")
    for index in range(total_records):
        _owner, offset = _read_dns_name(message, offset)
        if offset + 10 > len(message):
            raise ProbeFailure("dns", "truncated_dns_record")
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", message, offset)
        offset += 10
        end = offset + rdlength
        if end > len(message):
            raise ProbeFailure("dns", "truncated_dns_record")
        if index < answers and rtype == 1 and rclass == 1:
            if rdlength != 4:
                raise ProbeFailure("dns", "invalid_a_record")
            answer_count += 1
        offset = end
    if offset != len(message):
        raise ProbeFailure("dns", "trailing_dns_data")
    if answers == 0 or answer_count == 0:
        raise ProbeFailure("dns", "no_a_answer")
    return answer_count


def _read_http_response(sock, deadline, clock):
    header = bytearray()
    delimiter = b"\r\n\r\n"
    while not header.endswith(delimiter):
        if len(header) >= MAX_HTTP_HEADER_BYTES:
            raise ProbeFailure("http", "response_headers_too_large")
        sock.settimeout(_remaining(deadline, clock, "http"))
        try:
            chunk = sock.recv(1)
        except (socket.timeout, TimeoutError):
            raise ProbeFailure("http", "deadline_exceeded" if clock() >= deadline else "response_timeout")
        except OSError:
            raise ProbeFailure("http", "response_read_failed")
        if not chunk:
            raise ProbeFailure("http", "truncated_http_headers")
        header.extend(chunk)

    lines = bytes(header[:-4]).split(b"\r\n")
    try:
        status_line = lines[0].decode("ascii")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or parts[0] not in ("HTTP/1.0", "HTTP/1.1"):
            raise ValueError
        status = int(parts[1])
    except (UnicodeError, ValueError, IndexError):
        raise ProbeFailure("http", "invalid_http_status_line")
    if status != 200:
        raise ProbeFailure("http", "unexpected_http_status")

    headers = {}
    for line in lines[1:]:
        if not line or line[:1] in (b" ", b"\t") or b":" not in line:
            raise ProbeFailure("http", "invalid_http_header")
        name, value = line.split(b":", 1)
        try:
            key = name.decode("ascii").strip().lower()
            text = value.decode("ascii").strip()
        except UnicodeError:
            raise ProbeFailure("http", "invalid_http_header")
        if not key or key in headers:
            raise ProbeFailure("http", "duplicate_http_header")
        headers[key] = text
    if "transfer-encoding" in headers:
        raise ProbeFailure("http", "unsupported_http_transfer_encoding")
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/dns-message":
        raise ProbeFailure("http", "unexpected_http_content_type")
    content_length = headers.get("content-length", "")
    if not content_length.isdecimal():
        raise ProbeFailure("http", "invalid_http_content_length")
    body_size = int(content_length)
    if body_size > MAX_DNS_MESSAGE_BYTES:
        raise ProbeFailure("http", "response_body_too_large")
    if body_size < 12:
        raise ProbeFailure("http", "truncated_dns_message")
    body = bytearray()
    while len(body) < body_size:
        sock.settimeout(_remaining(deadline, clock, "http"))
        try:
            chunk = sock.recv(min(4096, body_size - len(body)))
        except (socket.timeout, TimeoutError):
            raise ProbeFailure("http", "deadline_exceeded" if clock() >= deadline else "response_timeout")
        except OSError:
            raise ProbeFailure("http", "response_read_failed")
        if not chunk:
            raise ProbeFailure("http", "truncated_http_body")
        body.extend(chunk)
    return bytes(body)


def _query_doh(sock, tls_name, query, expected_question, deadline, clock, txid):
    request = (
        f"POST /dns-query HTTP/1.1\r\nHost: {tls_name}\r\n"
        "Accept: application/dns-message\r\n"
        "Content-Type: application/dns-message\r\n"
        f"Content-Length: {len(query)}\r\nConnection: close\r\n\r\n"
    ).encode("ascii") + query
    sock.settimeout(_remaining(deadline, clock, "http"))
    try:
        sock.sendall(request)
    except (socket.timeout, TimeoutError):
        raise ProbeFailure("http", "deadline_exceeded" if clock() >= deadline else "request_send_timeout")
    except OSError:
        raise ProbeFailure("http", "request_send_failed")
    message = _read_http_response(sock, deadline, clock)
    _remaining(deadline, clock, "dns")
    return _verify_dns_response(message, txid, expected_question)


def run_probe(profile, mode, vip, device, probe_mark, resolver_ip, tls_name, query_domain,
              *, timeout=5.0, reserved_marks=(), is_linux=None, euid=None, monotonic=None,
              socket_factory=None, ssl_context_factory=None, id_factory=None):
    clock = monotonic or time.monotonic
    started = clock()
    try:
        budget = min(float(timeout), MAX_TIMEOUT)
    except (TypeError, ValueError, OverflowError):
        budget = MAX_TIMEOUT
    if not math.isfinite(budget) or budget <= 0:
        return _result("unsupported", profile, "arguments", "invalid_timeout", started, clock)
    deadline = started + budget
    try:
        source, mark, destination, tls_host, query_name = _validate_context(
            profile, mode, vip, device, probe_mark, resolver_ip, tls_name, query_domain, reserved_marks
        )
        linux = platform.system() == "Linux" if is_linux is None else bool(is_linux)
        root = (getattr(__import__("os"), "geteuid", lambda: -1)() == 0
                if euid is None else euid == 0)
        if not linux:
            raise ProbeFailure("platform", "linux_required")
        if not root:
            raise ProbeFailure("platform", "root_required")
        _remaining(deadline, clock, "connect")
        txid = int((id_factory or (lambda: secrets.randbelow(65536)))())
        if not 0 <= txid <= 65535:
            raise ProbeFailure("arguments", "invalid_transaction_id")
        query, expected_question = _encode_dns_query(query_name, txid)
        factory = socket_factory or socket.socket
        raw = None
        tls = None
        phase = "socket_setup"
        try:
            last_connect_failure = None
            connected = False
            attempt_limit = MAX_CONNECT_ATTEMPTS if profile == "cn" else 1
            for attempt in range(attempt_limit):
                phase = "socket_setup"
                raw = factory(socket.AF_INET, socket.SOCK_STREAM, 0)
                raw.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
                raw.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, device.encode("ascii") + b"\0")
                raw.bind((source, 0))
                phase = "connect"
                try:
                    remaining = _remaining(deadline, clock, "connect")
                except ProbeFailure:
                    if profile == "cn" and attempt:
                        raise ProbeFailure("connect", "deadline_exceeded", connect_attempts=attempt)
                    raise
                raw.settimeout(min(CONNECT_ATTEMPT_TIMEOUT, remaining) if profile == "cn" else remaining)
                try:
                    raw.connect((destination, 443))
                except (socket.timeout, TimeoutError):
                    if profile != "cn":
                        raise ProbeFailure("connect", "deadline_exceeded" if clock() >= deadline else
                                            "operation_timeout")
                    last_connect_failure = "connect_timeout"
                except OSError as exc:
                    if profile == "cn" and (isinstance(exc, ConnectionRefusedError) or
                                             exc.errno == errno.ECONNREFUSED):
                        last_connect_failure = "connect_refused"
                    elif profile == "cn" and exc.errno == errno.ETIMEDOUT:
                        last_connect_failure = "connect_timeout"
                    else:
                        raise ProbeFailure("connect", "deadline_exceeded" if clock() >= deadline else
                                            "connect_failed")
                else:
                    connected = True
                    break
                _close_socket(raw)
                raw = None
                attempts_made = attempt + 1
                if clock() >= deadline:
                    raise ProbeFailure("connect", "deadline_exceeded", connect_attempts=attempts_made)
                if attempt + 1 >= attempt_limit:
                    raise ProbeFailure("connect", "connect_attempts_exhausted",
                                       connect_attempts=attempts_made)
            if not connected:
                raise ProbeFailure("connect", last_connect_failure or "connect_failed")
            _remaining(deadline, clock, "tls")
            context = (ssl_context_factory or ssl.create_default_context)()
            phase = "tls"
            raw.settimeout(_remaining(deadline, clock, "tls"))
            tls = context.wrap_socket(raw, server_hostname=tls_host)
            raw = None
            _remaining(deadline, clock, "tls")
            phase = "http"
            answer_count = _query_doh(tls, tls_host, query, expected_question, deadline, clock, txid)
            return _result("pass", profile, "dns", "verified_doh_answer", started, clock,
                           answer_count=answer_count)
        except ProbeFailure:
            raise
        except ssl.SSLCertVerificationError:
            raise ProbeFailure("tls", "certificate_verification_failed")
        except ssl.SSLError:
            raise ProbeFailure("tls", "tls_handshake_failed")
        except (socket.timeout, TimeoutError):
            raise ProbeFailure(phase, "deadline_exceeded" if clock() >= deadline else "operation_timeout")
        except OSError:
            reason = "deadline_exceeded" if clock() >= deadline else ("tls_handshake_failed" if phase == "tls" else "socket_setup_failed" if phase == "socket_setup" else "connect_failed")
            raise ProbeFailure(phase, reason)
        finally:
            if tls is not None:
                try:
                    tls.close()
                except OSError:
                    pass
            if raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass
    except ProbeFailure as failure:
        unsupported = failure.reason in {
            "profile_must_be_ai_or_cn", "selected_egress_not_ipsec", "unsupported_egress_mode",
            "profile_context_mismatch", "unapproved_probe_endpoint", "invalid_profile_vip", "invalid_probe_identity",
            "invalid_resolver_address", "invalid_tls_name", "invalid_query_domain",
            "linux_required", "root_required",
        }
        return _result("unsupported" if unsupported else "fail", profile,
                       failure.phase, failure.reason, started, clock, **failure.fields)
    except Exception:
        return _result("fail", profile, "internal", "probe_error", started, clock)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("ai", "cn"), required=True)
    parser.add_argument("--mode", choices=("ipsec", "xray"), required=True)
    parser.add_argument("--vip", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--probe-mark", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--reserved-mark", action="append", default=[], type=lambda value: int(value, 0),
                        help="additional runtime marks that the probe identity must not reuse")
    parser.add_argument("--resolver-ip", required=True)
    parser.add_argument("--tls-name", required=True)
    parser.add_argument("--query-domain", required=True)
    parser.add_argument("--timeout", type=float, default=MAX_TIMEOUT)
    args = parser.parse_args(argv)
    result = run_probe(args.profile, args.mode, args.vip, args.device, args.probe_mark,
                       args.resolver_ip, args.tls_name, args.query_domain,
                       timeout=args.timeout, reserved_marks=args.reserved_mark)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
PROFILE_DATAPLANE_PROBE
  chmod_target 0755 /usr/local/lib/dnscomplex/profile-dataplane-probe.py
  local probe_target
  probe_target=$(target_path /usr/local/lib/dnscomplex/profile-dataplane-probe.py)
  [[ "$(sha256sum "$probe_target" | awk '{print $1}')" == "$PROFILE_DATAPLANE_PROBE_SHA256" ]] ||
    die "rendered profile dataplane probe does not match its reviewed SHA-256"
}

render_xui_sniffing_repair() {
  write_file /usr/local/lib/dnscomplex/repair-xui-sniffing.py <<'XUI_REPAIR'
#!/usr/bin/env python3
"""Apply narrowly selected X-UI database repairs. This tool never restarts services."""
import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import time


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key in xrayTemplateConfig")
        result[key] = value
    return result


def _backup_database(conn, database, suffix):
    backup = database + suffix + str(time.time_ns()) + ".bak"
    fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        with sqlite3.connect(backup) as copy:
            conn.backup(copy)
        os.chmod(backup, 0o600)
    except Exception:
        try:
            os.unlink(backup)
        except OSError:
            pass
        raise
    return backup


TESTED_MOBILE_API_DESTINATIONS = (
    "c2c.cdn.wechat.com",
    "edith.xiaohongshu.com",
    "rec.xiaohongshu.com",
)


def repair(database, tag, preserve_domains=(), preserve_original_ip=False):
    if not isinstance(preserve_original_ip, bool):
        raise ValueError("preserve_original_ip must be a boolean")
    requested = []
    for domain in preserve_domains:
        name = domain.lower() if isinstance(domain, str) else ""
        if len(name) > 253 or not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", name
        ):
            raise ValueError("exact DNS hostname required for destination preservation")
        requested.append("full:" + name)
    database = os.path.abspath(database)
    if not os.path.isfile(database):
        raise ValueError("existing x-ui database required")
    conn = sqlite3.connect(database)
    try:
        rows = conn.execute("SELECT id, sniffing FROM inbounds WHERE tag=?", (tag,)).fetchall()
        if len(rows) != 1:
            raise ValueError("exactly one matching inbound required")
        ident, raw = rows[0]
        sniff = json.loads(raw)
        if not sniff.get("enabled") or sniff.get("metadataOnly") or "tls" not in sniff.get("destOverride", []):
            raise ValueError("enabled TLS payload sniffing required")
        excluded = sniff.get("domainsExcluded", [])
        if not isinstance(excluded, list):
            raise ValueError("domainsExcluded must be an array")
        excluded = excluded + [name for name in dict.fromkeys(requested) if name not in excluded]
        if sniff.get("routeOnly", False) is preserve_original_ip and excluded == sniff.get("domainsExcluded", []):
            return None
        backup = _backup_database(conn, database, ".sniffing-")
        sniff["routeOnly"] = preserve_original_ip
        if requested:
            sniff["domainsExcluded"] = excluded
        with conn:
            result = conn.execute("UPDATE inbounds SET sniffing=? WHERE id=? AND sniffing=?",
                                  (json.dumps(sniff), ident, raw))
            if result.rowcount != 1:
                raise ValueError("inbound changed concurrently; retry after reviewing it")
        return backup
    finally:
        conn.close()


def repair_policy(database, dry_run=False):
    """Explicitly change only level-0 idle/half-close policy; never restart X-UI."""
    if not isinstance(dry_run, bool):
        raise ValueError("dry_run must be a boolean")
    database = os.path.abspath(database)
    if not os.path.isfile(database):
        raise ValueError("existing x-ui database required")
    conn = sqlite3.connect(database, timeout=3)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(settings)")}
        if not {"id", "key", "value"}.issubset(columns):
            raise ValueError("x-ui settings schema is unsupported")
        rows = conn.execute("SELECT id, value FROM settings WHERE key=?",
                            ("xrayTemplateConfig",)).fetchall()
        if len(rows) != 1 or not isinstance(rows[0][1], str):
            raise ValueError("exactly one xrayTemplateConfig row required")
        row_id, original = rows[0]
        try:
            config = json.loads(original, object_pairs_hook=_unique_json)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError("xrayTemplateConfig JSON is invalid") from exc
        if not isinstance(config, dict):
            raise ValueError("xrayTemplateConfig must be a JSON object")
        policy = config.get("policy")
        levels = policy.get("levels") if isinstance(policy, dict) else None
        level0 = levels.get("0") if isinstance(levels, dict) else None
        if not isinstance(level0, dict):
            raise ValueError("policy.levels.0 must be an object")
        if (level0.get("connIdle"), level0.get("uplinkOnly"), level0.get("downlinkOnly")) == (1200, 30, 30):
            return None
        config["policy"]["levels"]["0"].update(
            {"connIdle": 1200, "uplinkOnly": 30, "downlinkOnly": 30})
        candidate = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
        if dry_run:
            return "dry-run"
        backup = _backup_database(conn, database, ".policy-")
        try:
            conn.execute("BEGIN IMMEDIATE")
            result = conn.execute(
                "UPDATE settings SET value=? WHERE id=? AND key=? AND value=?",
                (candidate, row_id, "xrayTemplateConfig", original))
            if result.rowcount != 1:
                conn.rollback()
                raise ValueError("xrayTemplateConfig changed concurrently; retry after review")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return backup
    finally:
        conn.close()


def verify_policy_config(path):
    """Read-only check of the generated Xray policy; never echo config contents."""
    try:
        with open(path, encoding="utf-8") as stream:
            config = json.load(stream, object_pairs_hook=_unique_json)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("generated Xray config is unavailable or invalid") from exc
    policy = config.get("policy") if isinstance(config, dict) else None
    levels = policy.get("levels") if isinstance(policy, dict) else None
    level0 = levels.get("0") if isinstance(levels, dict) else None
    if not isinstance(level0, dict):
        raise ValueError("generated policy.levels.0 is unavailable")
    names = ("connIdle", "uplinkOnly", "downlinkOnly")
    values = tuple(level0.get(name) for name in names)
    if all(type(value) is int for value in values) and values == (1200, 30, 30):
        return values
    safe = tuple(str(value) if type(value) is int and 0 <= value <= 86400 else "invalid"
                 for value in values)
    raise ValueError("generated policy mismatch: " + " ".join(
        name + "=" + value for name, value in zip(names, safe)))


XPANEL_SOURCE_ORIGINAL_SHA256 = "062f0c914950cf97988663364ebf688a6b09dd770359531008439d35c851bef0"
XPANEL_SOURCE_PATCHED_SHA256 = "5fd40480ef929f64d947c9e202ccd6cceba630fc05594a4755f27a17ad6200f1"
XPANEL_SOURCE_OLD_BLOCK = (
    "\t// uplinkOnly 和 downlinkOnly 设置为 0 代表不限速，这是 level 0 用户的默认行为。\n"
    "\t// statsUserUplink 和 statsUserDownlink 确保用户的流量能够被统计。\n"
    "\tlevel0[\"handshake\"] = 4\n"
    "\tlevel0[\"connIdle\"] = 300\n"
    "\tlevel0[\"uplinkOnly\"] = 0\n"
    "\tlevel0[\"downlinkOnly\"] = 0\n"
).encode("utf-8")
XPANEL_SOURCE_NEW_BLOCK = (
    "\t// uplinkOnly 和 downlinkOnly 是单向连接超时；保留模板的显式值。\n"
    "\t// statsUserUplink 和 statsUserDownlink 确保用户的流量能够被统计。\n"
    "\tlevel0[\"handshake\"] = 4\n"
    "\tif _, exists := level0[\"connIdle\"]; !exists {\n"
    "\t\tlevel0[\"connIdle\"] = 300\n"
    "\t}\n"
    "\tif _, exists := level0[\"uplinkOnly\"]; !exists {\n"
    "\t\tlevel0[\"uplinkOnly\"] = 0\n"
    "\t}\n"
    "\tif _, exists := level0[\"downlinkOnly\"]; !exists {\n"
    "\t\tlevel0[\"downlinkOnly\"] = 0\n"
    "\t}\n"
).encode("utf-8")


def _read_source_snapshot(path):
    path = os.path.abspath(os.fspath(path))
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("source must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = os.lstat(path)
        identity = (before.st_dev, before.st_ino)
        if (not stat.S_ISREG(opened.st_mode) or identity != (opened.st_dev, opened.st_ino) or
                identity != (current.st_dev, current.st_ino) or stat.S_ISLNK(current.st_mode)):
            raise ValueError("source changed concurrently; retry after review")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            raise ValueError("source file exceeds the supported size")
        return path, data, opened
    finally:
        os.close(fd)


def _verify_source_snapshot(path, expected, snapshot):
    current_path, current, current_stat = _read_source_snapshot(path)
    if (current_path != path or current != expected or
            (current_stat.st_dev, current_stat.st_ino) != (snapshot.st_dev, snapshot.st_ino)):
        raise ValueError("source changed concurrently; retry after review")


def _write_source_backup(path, original):
    backup = path + ".xpanel-policy-" + str(time.time_ns()) + ".bak"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(backup, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(original)
            stream.flush()
            os.fsync(fd)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    except Exception:
        try:
            os.unlink(backup)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    _fsync_directory(os.path.dirname(path))
    return backup


def _fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_replace_source(path, original, candidate, snapshot):
    parent = os.path.dirname(path)
    basename = os.path.basename(path)
    fd, temp_path = tempfile.mkstemp(prefix="." + basename + ".xpanel-policy-", dir=parent)
    try:
        try:
            os.fchown(fd, snapshot.st_uid, snapshot.st_gid)
        except PermissionError:
            if (os.geteuid() == 0 or os.geteuid() != snapshot.st_uid or
                    os.getegid() != snapshot.st_gid):
                raise
        os.fchmod(fd, stat.S_IMODE(snapshot.st_mode))
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(candidate)
            stream.flush()
            os.fsync(fd)
        _verify_source_snapshot(path, original, snapshot)
        os.replace(temp_path, path)
        _fsync_directory(parent)
        _readback_path, actual, _readback_stat = _read_source_snapshot(path)
        if _source_sha256(actual) != XPANEL_SOURCE_PATCHED_SHA256:
            raise ValueError("patched source readback did not match the approved SHA-256")
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _source_sha256(data):
    return hashlib.sha256(data).hexdigest()


def patch_xpanel_source(path, dry_run=False):
    if not isinstance(dry_run, bool):
        raise ValueError("dry_run must be a boolean")
    path, original, snapshot = _read_source_snapshot(path)
    source_hash = _source_sha256(original)
    if source_hash == XPANEL_SOURCE_PATCHED_SHA256:
        return None
    if source_hash != XPANEL_SOURCE_ORIGINAL_SHA256:
        raise ValueError("unsupported source SHA-256; only the pinned v26.6.18 files are accepted")
    if original.count(XPANEL_SOURCE_OLD_BLOCK) != 1:
        raise ValueError("pinned source policy block did not match exactly once")
    candidate = original.replace(XPANEL_SOURCE_OLD_BLOCK, XPANEL_SOURCE_NEW_BLOCK, 1)
    if _source_sha256(candidate) != XPANEL_SOURCE_PATCHED_SHA256:
        raise ValueError("candidate source SHA-256 did not match the approved patch")
    if dry_run:
        return "dry-run"
    backup = _write_source_backup(path, original)
    _atomic_replace_source(path, original, candidate, snapshot)
    return backup


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database")
    parser.add_argument("--tag")
    parser.add_argument("--preserve-destination", action="append", default=[], metavar="DOMAIN")
    parser.add_argument("--preserve-tested-mobile-api-destinations", action="store_true",
                        help="Opt in to preserve the original destination for the three verified mobile API hosts.")
    parser.add_argument("--preserve-original-ip", action="store_true",
                        help="Keep the client destination while the downstream proxy routes by sniffed domains.")
    parser.add_argument("--policy-level0-idle-1200", action="store_true",
                        help="Opt in to level-0 connIdle=1200 and uplinkOnly/downlinkOnly=30.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview the explicit level-0 policy repair without writing or backing up.")
    parser.add_argument("--verify-generated-config", metavar="PATH",
                        help="Read-only verify generated level-0 policy values.")
    parser.add_argument("--patch-xpanel-source", metavar="FILE",
                        help="Opt in to patch only the pinned official X-Panel v26.6.18 source file; build and controlled publish remain separate.")
    args = parser.parse_args()
    if args.preserve_tested_mobile_api_destinations and (
            args.preserve_destination or args.preserve_original_ip or
            args.policy_level0_idle_1200 or args.patch_xpanel_source is not None or
            args.verify_generated_config is not None):
        parser.error("--preserve-tested-mobile-api-destinations conflicts with other repair modes or custom destinations")
    if args.patch_xpanel_source is not None:
        if (args.database is not None or args.tag is not None or args.preserve_destination or
                args.preserve_original_ip or args.policy_level0_idle_1200 or
                args.verify_generated_config is not None):
            parser.error("--patch-xpanel-source is mutually exclusive with database, sniffing, policy, and verify options")
        try:
            result = patch_xpanel_source(args.patch_xpanel_source, args.dry_run)
        except ValueError as exc:
            parser.error(str(exc))
        if result == "dry-run":
            print("would patch pinned X-Panel v26.6.18 source; build the same release and use controlled publish; no build or restart performed")
        elif result:
            print("patched X-Panel v26.6.18 source; backup=" + result + "; build the same release and use controlled publish; no build or restart performed")
        else:
            print("already patched; build the same release and use controlled publish; no build or restart performed")
        raise SystemExit(0)
    if args.verify_generated_config is not None:
        if (not args.policy_level0_idle_1200 or args.database is not None or args.dry_run or
                args.tag is not None or
                args.preserve_destination or args.preserve_original_ip):
            parser.error("--verify-generated-config requires the policy opt-in and is read-only")
        try:
            values = verify_policy_config(args.verify_generated_config)
        except ValueError as exc:
            parser.error(str(exc))
        print("generated level-0 policy verified: connIdle={} uplinkOnly={} downlinkOnly={}".format(*values))
        raise SystemExit(0)
    if not args.database:
        parser.error("--database is required for database changes")
    if args.policy_level0_idle_1200:
        if args.tag or args.preserve_destination or args.preserve_original_ip:
            parser.error("policy repair is a separate operation; omit sniffing options")
        backup = repair_policy(args.database, args.dry_run)
        if backup == "dry-run":
            print("would update persistent level-0 policy; no service restart performed")
        elif backup:
            print("template updated, runtime unverified; generator may override; verify after controlled restart; backup=" + backup)
        else:
            print("already configured")
        raise SystemExit(0)
    else:
        if args.dry_run:
            parser.error("--dry-run requires --policy-level0-idle-1200")
        if not args.tag:
            parser.error("--tag is required for sniffing repair")
        preserve_domains = (TESTED_MOBILE_API_DESTINATIONS
                           if args.preserve_tested_mobile_api_destinations
                           else args.preserve_destination)
        backup = repair(args.database, args.tag, preserve_domains, args.preserve_original_ip)
    print("updated; backup=" + backup if backup else "already configured")
XUI_REPAIR
  chmod_target 0755 /usr/local/lib/dnscomplex/repair-xui-sniffing.py
}

render_soak_runner() {
  write_file /usr/local/lib/dnscomplex-soak/runner.py <<'PY'
#!/usr/bin/env python3
import argparse
import concurrent.futures
import contextlib
import fcntl
import json
import os
import random
import re
import signal
import statistics
import subprocess
import sys
import time
import threading
import uuid
from datetime import datetime

DNSCOMPLEX = "/usr/local/sbin/dnscomplex"
LOCK_PATH = "/run/lock/dnscomplex-soak.lock"
LOG_DIR = "/var/log/dnscomplex"
MAX_PENDING = 256
MAX_SAMPLES = 10000
OWNED_PROCESSES = set()
OWNED_LOCK = threading.RLock()
STOPPING = threading.Event()

def terminate_owned(signum, frame):
    STOPPING.set()
    with OWNED_LOCK: processes = tuple(OWNED_PROCESSES)
    for proc in processes:
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
    raise SystemExit(128 + signum)

DOMAINS = {
    "ai": ["chatgpt.com", "openai.com", "claude.ai", "meta.ai"],
    "cn": ["youku.com", "bilibili.com", "iqiyi.com"],
    "default": ["example.com", "cloudflare.com", "youtube.com", "google.com"],
}

def parse_duration(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,10}[smhd]?", value):
        raise ValueError("duration must be 1–3600 seconds (s/m/h/d suffix allowed)")
    unit = value[-1]
    seconds = int(value[:-1] if unit in "smhd" else value) * {"s":1,"m":60,"h":3600,"d":86400}.get(unit,1)
    if not 1 <= seconds <= 3600:
        raise ValueError("duration must be 1–3600 seconds")
    return seconds

def validate_limits(duration, clients, dns_qps):
    seconds = parse_duration(duration)
    for name, value, maximum in [("clients", clients, 256), ("dns_qps", dns_qps, 100)]:
        if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,10}", str(value)) or not 1 <= int(value) <= maximum:
            raise ValueError(f"{name} must be 1–{maximum}")
    return seconds

@contextlib.contextmanager
def singleton(path=LOCK_PATH):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)

@contextlib.contextmanager
def exclusive_outputs(summary_path):
    # Reserve both paths before any probe. An existing result is never truncated.
    log_path = summary_path[:-5] + ".log" if summary_path.endswith(".json") else summary_path + ".log"
    created = []
    try:
        for path in (log_path, summary_path):
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            created.append((path, fd))
    except BaseException:
        for path, fd in created:
            os.close(fd)
            os.unlink(path)
        raise
    with os.fdopen(created[1][1], "w", encoding="utf-8") as summary, os.fdopen(created[0][1], "w", encoding="utf-8") as log:
        yield summary, log, log_path

def run(cmd, timeout=10):
    if STOPPING.is_set(): raise InterruptedError("soak is stopping")
    proc = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    with OWNED_LOCK: OWNED_PROCESSES.add(proc)
    try:
        if STOPPING.is_set(): raise InterruptedError("soak is stopping")
        stdout, stderr = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
    except BaseException:
        # Only this diagnostic's process group is owned by the runner.
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        proc.communicate(timeout=2)
        raise
    finally:
        with OWNED_LOCK: OWNED_PROCESSES.discard(proc)

def dig_domain(domain):
    start = time.monotonic()
    try:
        proc = run(["dig", "+time=2", "+tries=1", "+short", "A", domain, "@127.0.0.1", "-p", "53"], 5)
        ok = proc.returncode == 0 and any(line.strip() for line in proc.stdout.splitlines())
    except (OSError, subprocess.SubprocessError):
        ok = False
    return {"domain": domain, "ok": ok, "latency_ms": (time.monotonic() - start) * 1000}

def percentile(values, pct):
    if not values:
        return 0.0
    values = sorted(values)
    return values[min(len(values) - 1, int((len(values) - 1) * pct))]

def profile_for_domain(domain):
    for profile, domains in DOMAINS.items():
        if domain in domains:
            return profile
    return "default"

def health_status():
    try:
        proc = run([DNSCOMPLEX, "health", "--json"], 20)
        return json.loads(proc.stdout or "{}")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return {"status": "unhealthy"}

def idle_resume():
    result = {"ran": True, "ok": True, "checks": []}
    refresh = run([DNSCOMPLEX, "refresh-nftsets"], 120)
    result["ok"] = refresh.returncode == 0
    for domain, expected in [("chatgpt.com", "AI"), ("claude.ai", "AI"), ("meta.ai", "AI"), ("youku.com", "CN"), ("youtube.com", "default")]:
        proc = run([DNSCOMPLEX, "trace-domain", domain], 60)
        ok = proc.returncode == 0 and f"profile={expected}" in proc.stdout
        result["checks"].append({"domain": domain, "expected": expected, "ok": ok})
        result["ok"] = result["ok"] and ok
    return result

def run_load(seconds, clients, qps, profiles, domains, log, pool):
    deadline = time.monotonic() + seconds
    pending = {}
    latencies = []
    requests = successes = failures = 0
    profile_failures = {profile: 0 for profile in profiles}
    health_consecutive = health_max = 0
    next_health = time.monotonic()
    domain_index = 0

    def collect(done):
        nonlocal successes, failures
        for future in done:
            domain = pending.pop(future)
            try: item = future.result()
            except Exception: item = {"domain":domain,"ok":False,"latency_ms":0}
            seen = successes + failures + 1
            if len(latencies) < MAX_SAMPLES:
                latencies.append(item["latency_ms"])
            else:
                index = random.randrange(seen)
                if index < MAX_SAMPLES: latencies[index] = item["latency_ms"]
            if item["ok"]: successes += 1
            else:
                failures += 1
                profile = profile_for_domain(domain)
                profile_failures[profile] = profile_failures.get(profile, 0) + 1
            log.write(json.dumps(item, ensure_ascii=False) + "\n")

    while time.monotonic() < deadline:
        collect({future for future in pending if future.done()})
        if len(pending) >= MAX_PENDING:
            done, _ = concurrent.futures.wait(pending, timeout=min(.1, max(0, deadline-time.monotonic())), return_when=concurrent.futures.FIRST_COMPLETED)
            collect(done)
            continue
        now = time.monotonic()
        if now >= next_health:
            health = health_status()
            health_consecutive = health_consecutive + 1 if health.get("status") == "unhealthy" else 0
            health_max = max(health_max, health_consecutive)
            next_health = time.monotonic() + 10
        if time.monotonic() >= deadline: break
        domain = domains[domain_index % len(domains)]
        domain_index += 1
        pending[pool.submit(dig_domain, domain)] = domain
        requests += 1
        time.sleep(min(1 / qps, max(0, deadline-time.monotonic())))
    while pending:
        done, _ = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
        collect(done)
    return {
        "requests":requests, "successes":successes, "failures":failures,
        "success_ratio":round(successes / max(1, requests), 6),
        "sample_count":len(latencies), "percentile_method":"reservoir_sample_estimate",
        "latency_p50_ms":round(statistics.median(latencies), 2) if latencies else 0,
        "latency_p95_ms":round(percentile(latencies, .95), 2),
        "profile_failures":profile_failures, "health_consecutive_unhealthy_max":health_max,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", default="30m")
    parser.add_argument("--clients", default=50)
    parser.add_argument("--dns-qps", default=50)
    parser.add_argument("--profiles", default="ai,cn,default")
    parser.add_argument("--idle-resume", action="store_true")
    parser.add_argument("--output-json", default="")
    args = parser.parse_args()
    try: seconds = validate_limits(args.duration, args.clients, args.dns_qps)
    except ValueError as exc: parser.error(str(exc))
    args.clients, args.dns_qps = int(args.clients), int(args.dns_qps)
    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    if not profiles or any(profile not in DOMAINS for profile in profiles): parser.error("invalid profiles")
    domains = [domain for profile in profiles for domain in DOMAINS[profile]]
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, terminate_owned)
    try:
        with singleton():
            if not args.output_json: os.makedirs(LOG_DIR, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex
            summary_path = args.output_json or os.path.join(LOG_DIR, f"soak-{stamp}.json")
            with exclusive_outputs(summary_path) as (out, log, log_path):
                idle_result = idle_resume() if args.idle_resume else {"ran":False,"ok":True,"checks":[]}
                log.write(f"start={datetime.now().isoformat()} duration={args.duration} clients={args.clients} dns_qps={args.dns_qps} profiles={args.profiles}\n")
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.clients) as pool:
                    try: summary = run_load(seconds,args.clients,args.dns_qps,profiles,domains,log,pool)
                    except BaseException:
                        pool.shutdown(wait=True, cancel_futures=True)
                        raise
                log.write(f"end={datetime.now().isoformat()} requests={summary['requests']} successes={summary['successes']} failures={summary['failures']}\n")
                summary.update(duration=args.duration,clients=args.clients,dns_qps=args.dns_qps,profiles=args.profiles,
                    idle_resume=args.idle_resume,idle_resume_result=idle_result,log=log_path,summary=summary_path,
                    limitation="synthetic DNS/profile load test; not a full emulation of real mobile devices or all app traffic")
                if summary["successes"] + summary["failures"] == 0: summary["error_code"] = "NO_PROBES_COMPLETED"
                json.dump(summary,out,ensure_ascii=False,indent=2); out.write("\n")
            print(json.dumps(summary,ensure_ascii=False))
            return 0 if summary["successes"] > 0 and summary["failures"] == 0 and idle_result["ok"] and summary["health_consecutive_unhealthy_max"] < 3 else 1
    except BlockingIOError:
        print("soak busy: another run owns the singleton lock",file=sys.stderr); return 3
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"soak failed: {type(exc).__name__}",file=sys.stderr); return 1

if __name__ == "__main__":
    raise SystemExit(main())
PY
  chmod_target 0755 /usr/local/lib/dnscomplex-soak/runner.py
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
DNSCOMPLEX = os.environ.get("DNSCOMPLEX_MANAGER", "/usr/local/sbin/dnscomplex")

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

def dns_sample(domains=None):
    domains = domains or ["example.com", "cloudflare.com", "google.com", "youtube.com", "openai.com"]
    latencies = []
    successes = 0
    for domain in domains:
        proc = run(["dig", "+time=2", "+tries=1", "+stats", "A", domain, "@127.0.0.1", "-p", "53"], 5)
        ok = proc.returncode == 0 and bool(proc.stdout.strip())
        if ok:
            successes += 1
        latency = 0.0
        for line in proc.stdout.splitlines():
            if "Query time:" in line:
                try:
                    latency = float(line.split()[3])
                except Exception:
                    latency = 0.0
        latencies.append(latency)
    latencies = sorted(latencies)
    p50 = latencies[len(latencies) // 2] if latencies else 0.0
    p95 = latencies[min(len(latencies) - 1, int((len(latencies) - 1) * 0.95))] if latencies else 0.0
    return {"success_ratio": successes / max(1, len(domains)), "p50": p50, "p95": p95}

def nft_count(set_name):
    proc = run(["nft", "list", "set", "inet", "dnscomplex", set_name], 5)
    return len(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", proc.stdout)))

def nftset_age(profile):
    path = f"/var/lib/dnscomplex/nftset-{profile}.last_refresh"
    try:
        return max(0, int(time.time() - os.stat(path).st_mtime))
    except FileNotFoundError:
        return -1

def health_snapshot():
    proc = run([DNSCOMPLEX, "health", "--json"], 20)
    try:
        payload = json.loads(proc.stdout or "{}")
    except Exception:
        payload = {}
    return payload

def ipsec_up(child, snapshot=None):
    payload = snapshot if snapshot is not None else health_snapshot()
    check_name = f"{child}-ipsec-selected-egress"
    for item in payload.get("checks", []):
        if item.get("name") == check_name:
            return 1 if item.get("status") == "ok" else 0
    return 0

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

def health_status_value(snapshot=None):
    payload = snapshot if snapshot is not None else health_snapshot()
    status = payload.get("status", "unhealthy")
    return {"healthy": 0, "degraded": 1, "unhealthy": 2}.get(status, 2)

def active_connection_metrics():
    proc = run(["conntrack", "-L"], 10)
    profile_counts = {"ai": 0, "cn": 0, "default": 0}
    ipv4 = ipv6 = 0
    for line in proc.stdout.splitlines():
        if "ipv6" in line:
            ipv6 += 1
        else:
            ipv4 += 1
        if "mark=0x301" in line:
            profile_counts["ai"] += 1
        elif "mark=0x351" in line:
            profile_counts["cn"] += 1
        else:
            profile_counts["default"] += 1
    total = ipv4 + ipv6
    return {
        "profile_connections_ai": profile_counts["ai"],
        "profile_connections_cn": profile_counts["cn"],
        "profile_connections_default": profile_counts["default"],
        "ipv6_connection_ratio": ipv6 / total if total else 0.0,
    }

def service_restart_count(name):
    proc = run(["systemctl", "show", name, "-p", "NRestarts", "--value"], 5)
    try:
        return int((proc.stdout or "0").strip() or "0")
    except Exception:
        return 0

def collect():
    cfg = parse_config()
    health = health_snapshot()
    count = read_int("/proc/sys/net/netfilter/nf_conntrack_count")
    max_count = max(read_int("/proc/sys/net/netfilter/nf_conntrack_max", 1), 1)
    dns = dns_sample()
    connections = active_connection_metrics()
    data = {
        "ts": int(time.time()),
        "conntrack_count": count,
        "conntrack_max": max_count,
        "conntrack_usage_ratio": count / max_count,
        "dns_latency_ms": dns["p50"],
        "dns_latency_p95_ms": dns["p95"],
        "dns_success_ratio": dns["success_ratio"],
        "ai_nftset_count": nft_count("ai4"),
        "cn_nftset_count": nft_count("cn4"),
        "ai_nftset_age_seconds": nftset_age("ai"),
        "cn_nftset_age_seconds": nftset_age("cn"),
        "ipsec_ai_up": ipsec_up("ai", health),
        "ipsec_cn_up": ipsec_up("cn", health),
        "xray_up": service_up("xray-dnscomplex.service"),
        "health_status": health_status_value(health),
        "adguard_cache_enabled": adguard_cache_enabled(),
        "ha_mode": cfg.get("HA_MODE", "single"),
    }
    data.update(connections)
    for service in SERVICES:
        data["service_" + service.replace(".", "_").replace("-", "_")] = service_up(service)
        data["service_restarts_" + service.replace(".", "_").replace("-", "_")] = service_restart_count(service)
    return data

def ensure_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    columns = {
        "ts": "integer primary key",
        "conntrack_usage_ratio": "real",
        "dns_latency_ms": "real",
        "dns_latency_p95_ms": "real",
        "dns_success_ratio": "real",
        "ai_nftset_count": "integer",
        "cn_nftset_count": "integer",
        "ai_nftset_age_seconds": "integer",
        "cn_nftset_age_seconds": "integer",
        "ipsec_ai_up": "integer",
        "ipsec_cn_up": "integer",
        "xray_up": "integer",
        "health_status": "integer",
        "adguard_cache_enabled": "integer",
        "profile_connections_ai": "integer",
        "profile_connections_cn": "integer",
        "profile_connections_default": "integer",
        "ipv6_connection_ratio": "real",
        "schema_version": "integer",
    }
    with sqlite3.connect(DB) as con:
        con.execute("create table if not exists samples (ts integer primary key)")
        existing = {row[1] for row in con.execute("pragma table_info(samples)")}
        for name, kind in columns.items():
            if name not in existing and name != "ts":
                con.execute(f"alter table samples add column {name} {kind}")

def sample():
    ensure_db()
    data = collect()
    data["schema_version"] = 2
    columns = [
        "ts", "conntrack_usage_ratio", "dns_latency_ms", "dns_latency_p95_ms", "dns_success_ratio",
        "ai_nftset_count", "cn_nftset_count", "ai_nftset_age_seconds", "cn_nftset_age_seconds",
        "ipsec_ai_up", "ipsec_cn_up", "xray_up", "health_status", "adguard_cache_enabled",
        "profile_connections_ai", "profile_connections_cn", "profile_connections_default",
        "ipv6_connection_ratio", "schema_version",
    ]
    with sqlite3.connect(DB) as con:
        con.execute(
            "insert or replace into samples (" + ",".join(columns) + ") values (" + ",".join(["?"] * len(columns)) + ")",
            tuple(data.get(column, 0) for column in columns),
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
        "# HELP dnscomplex_dns_latency_p95_ms Local DNS p95 latency in milliseconds.",
        "# TYPE dnscomplex_dns_latency_p95_ms gauge",
        f"dnscomplex_dns_latency_p95_ms {data['dns_latency_p95_ms']}",
        "# HELP dnscomplex_dns_success_ratio Local DNS synthetic success ratio.",
        "# TYPE dnscomplex_dns_success_ratio gauge",
        f"dnscomplex_dns_success_ratio {data['dns_success_ratio']}",
        f"dnscomplex_nftset_entries{{profile=\"ai\"}} {data['ai_nftset_count']}",
        f"dnscomplex_nftset_entries{{profile=\"cn\"}} {data['cn_nftset_count']}",
        f"dnscomplex_nftset_age_seconds{{profile=\"ai\"}} {data['ai_nftset_age_seconds']}",
        f"dnscomplex_nftset_age_seconds{{profile=\"cn\"}} {data['cn_nftset_age_seconds']}",
        f"dnscomplex_ipsec_up{{profile=\"ai\"}} {data['ipsec_ai_up']}",
        f"dnscomplex_ipsec_up{{profile=\"cn\"}} {data['ipsec_cn_up']}",
        f"dnscomplex_xray_up {data['xray_up']}",
        f"dnscomplex_health_status {data['health_status']}",
        f"dnscomplex_adguard_cache_enabled {data['adguard_cache_enabled']}",
        f"dnscomplex_profile_connections{{profile=\"ai\"}} {data['profile_connections_ai']}",
        f"dnscomplex_profile_connections{{profile=\"cn\"}} {data['profile_connections_cn']}",
        f"dnscomplex_profile_connections{{profile=\"default\"}} {data['profile_connections_default']}",
        f"dnscomplex_ipv6_connection_ratio {data['ipv6_connection_ratio']}",
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
Environment=DNSCOMPLEX_TIMER_MODE=1
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
        expr: dnscomplex_dns_latency_p95_ms > 500
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: dnscomplex DNS p95 latency is high
      - alert: DnscomplexDnsSuccessLow
        expr: dnscomplex_dns_success_ratio < 0.98
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: dnscomplex DNS synthetic success ratio is low
      - alert: DnscomplexNftsetStale
        expr: dnscomplex_nftset_age_seconds > 7200
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: dnscomplex AI/CN nftset refresh is stale
      - alert: DnscomplexHealthUnhealthy
        expr: dnscomplex_health_status >= 2
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: dnscomplex health is unhealthy
      - alert: DnscomplexDefaultIpv6Broken
        expr: dnscomplex_ipv6_connection_ratio == 0
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: dnscomplex has no observed IPv6 default traffic
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

render_redactor() {
  write_file /usr/local/lib/dnscomplex-redact/redact.py <<'PY'
#!/usr/bin/env python3
import argparse
import os
import re
import shlex
import sys

REDACTED = "[REDACTED_SECRET]"
EXACT_SECRET_KEYS = {
    "AI_IPSEC_USERNAME",
    "AI_IPSEC_PASSWORD",
    "CN_IPSEC_USERNAME",
    "CN_IPSEC_PASSWORD",
    "DNSCOMPLEX_WEB_PASSWORD",
    "AI_XRAY_URI",
    "CN_XRAY_URI",
    "AI_XRAY_OUTBOUND_JSON",
    "CN_XRAY_OUTBOUND_JSON",
    "GITHUB_TOKEN",
    "GH_TOKEN",
}
SECRET_KEY_WORDS = (
    "PASSWORD",
    "PASSWD",
    "USERNAME",
    "TOKEN",
    "SECRET",
    "PSK",
    "COOKIE",
    "SESSION",
    "AUTHORIZATION",
)
ASSIGNMENT_RE = re.compile(
    r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.*?)(?:\r?\n)?$"
)
SECRET_KEY_PATTERN = (
    r"(?:password|passwd|username|token|secret|psk|cookie|session|authorization|"
    r"ai_ipsec_username|cn_ipsec_username|ai_ipsec_password|cn_ipsec_password|"
    r"dnscomplex_web_password|ai_xray_uri|cn_xray_uri|"
    r"ai_xray_outbound_json|cn_xray_outbound_json|github_token|gh_token)"
)
JSON_SECRET_RE = re.compile(
    rf'(?i)("{SECRET_KEY_PATTERN}"\s*:\s*)'
    r'("(?:\\.|[^"\\])*"|[^,}\r\n]*)'
)
INLINE_SECRET_RE = re.compile(
    rf"(?im)(^|[\s,;])({SECRET_KEY_PATTERN})(\s*[=:]\s*)"
    r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\r\n]*)"
)


def is_secret_key(key):
    upper = key.upper()
    return upper in EXACT_SECRET_KEYS or any(word in upper for word in SECRET_KEY_WORDS)


def assignment_block(lines, start):
    match = ASSIGNMENT_RE.match(lines[start])
    if not match:
        return start, None, None
    logical = match.group(4)
    end = start
    while True:
        try:
            parts = shlex.split(logical, comments=False, posix=True)
            return end, match, " ".join(parts)
        except ValueError:
            end += 1
            if end >= len(lines):
                return len(lines) - 1, match, None
            logical += "\n" + lines[end].rstrip("\r\n")


def secret_values(text):
    lines = text.splitlines(keepends=True)
    values = []
    index = 0
    while index < len(lines):
        end, match, value = assignment_block(lines, index)
        if match and is_secret_key(match.group(2)) and value:
            values.append(value)
        index = end + 1 if match else index + 1
    return values


def redact_assignments(text):
    lines = text.splitlines(keepends=True)
    output = []
    index = 0
    while index < len(lines):
        end, match, _ = assignment_block(lines, index)
        if not match or not is_secret_key(match.group(2)):
            output.append(lines[index])
            index += 1
            continue
        block = lines[index : end + 1]
        newline_count = sum(line.count("\n") for line in block)
        output.append(
            match.group(1)
            + match.group(2)
            + match.group(3)
            + REDACTED
            + ("\n" * newline_count)
        )
        index = end + 1
    return "".join(output)


def redact(text, config_text=""):
    literals = secret_values(config_text) + secret_values(text)
    for value in sorted({item for item in literals if len(item) >= 4}, key=len, reverse=True):
        text = text.replace(value, REDACTED)
    text = redact_assignments(text)
    text = JSON_SECRET_RE.sub(lambda match: match.group(1) + f'"{REDACTED}"', text)
    text = INLINE_SECRET_RE.sub(
        lambda match: match.group(1) + match.group(2) + match.group(3) + REDACTED,
        text,
    )
    patterns = [
        # XFRM session keys are independent of config credentials. Keep the
        # algorithm and ICV length for diagnosis, never export the key bytes.
        (
            r"(?im)^(\s*(?:auth(?:-trunc)?|enc|aead)\s+\S+\s+)0x[0-9a-f]+",
            r"\1[REDACTED_XFRM_KEY]",
        ),
        (r"(?i)\b(vless|vmess|trojan|ss)://[^\s'\"<>]+", r"\1://[REDACTED_XRAY_URI]"),
        (
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            "[REDACTED_UUID]",
        ),
        (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "[REDACTED_IPV4]"),
        (r"\bfd[0-9a-fA-F:]*:[0-9a-fA-F:]*\b", "[REDACTED_IPV6]"),
        (r"\b[\w.-]+\.local\b", "[REDACTED_HOSTNAME]"),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    args = parser.parse_args()
    config_text = ""
    if args.config and os.path.isfile(args.config):
        with open(args.config, "r", encoding="utf-8", errors="replace") as handle:
            config_text = handle.read()
    sys.stdout.write(redact(sys.stdin.read(), config_text))


if __name__ == "__main__":
    main()
PY
  chmod_target 0755 /usr/local/lib/dnscomplex-redact/redact.py
}

render_config_parser() {
  write_file /usr/local/lib/dnscomplex-config/candidate.py <<'CONFIG_PARSER'
#!/usr/bin/env python3
"""Parse the supported config.env assignment format as data, without a shell."""
import argparse
import json
import os
import re
import stat
import sys

# Kept in schema order; contract tests compare this with manager config_schema_keys.
SCHEMA_KEYS = (
    'DNSCOMPLEX_VERSION',
    'DEPLOY_MODE',
    'WAN_IFACE',
    'TRANSIT_VLAN_ID',
    'LAN_VLAN_ID',
    'ROUTEROS_TRANSIT_IPV4',
    'LINUX_TRANSIT_IPV4',
    'TRANSIT_IPV4_CIDR',
    'ROUTEROS_TRANSIT_IPV6',
    'LINUX_TRANSIT_IPV6',
    'TRANSIT_IPV6_CIDR',
    'ROUTEROS_LAN_IPV4',
    'LINUX_LAN_IPV4',
    'LAN_CLIENT_IPV4_CIDR',
    'LAN_IPV4_CIDR',
    'LAN_DHCP_START',
    'LAN_DHCP_END',
    'LAN_IPV6_PREFIX',
    'LAN_IPV6_GATEWAY',
    'AI_IPSEC_SERVER',
    'CN_IPSEC_SERVER',
    'IPSEC_REMOTE_ID',
    'AI_IPSEC_USERNAME',
    'AI_IPSEC_PASSWORD',
    'CN_IPSEC_USERNAME',
    'CN_IPSEC_PASSWORD',
    'DEFAULT_DNS_UPSTREAMS',
    'DEFAULT_DNS_STRATEGY',
    'DEFAULT_IPV6_MODE',
    'AI_DNS_UPSTREAMS',
    'CN_DNS_UPSTREAMS',
    'AI_GEOSITE_SOURCES',
    'AI_SUPPORT_DOMAINS',
    'AI_NFTSET_REFRESH_DOMAINS',
    'SING_GEOSITE_RULESET_BASE_URL',
    'CN_VIDEO_SOURCES',
    'AI_SAMPLE_DOMAINS',
    'CN_SAMPLE_DOMAINS',
    'CN_NFTSET_REFRESH_DOMAINS',
    'CN_STATIC_A_OVERRIDES',
    'CN_OVERRIDE_PROBE_DOMAINS',
    'CN_OVERRIDE_PROBE_RESOLVERS',
    'LOCAL_DOMAIN_IPV6_POLICY',
    'SMARTDNS_DEFAULT_PORT',
    'SMARTDNS_AI_PORT',
    'SMARTDNS_CN_PORT',
    'SINGBOX_DNS_LISTEN',
    'SINGBOX_DNS_PORT',
    'SINGBOX_LOG_LEVEL',
    'SINGBOX_SOCKS_LISTEN',
    'SINGBOX_SOCKS_PORT',
    'SINGBOX_HTTP_LISTEN',
    'SINGBOX_HTTP_PORT',
    'XRAY_ENABLED',
    'XRAY_LISTEN_HOST',
    'XRAY_AI_SOCKS_PORT',
    'XRAY_CN_SOCKS_PORT',
    'AI_EGRESS_MODE',
    'CN_EGRESS_MODE',
    'AI_QUIC_POLICY',
    'CN_QUIC_POLICY',
    'AI_XRAY_URI',
    'CN_XRAY_URI',
    'AI_XRAY_OUTBOUND_JSON',
    'CN_XRAY_OUTBOUND_JSON',
    'DNSCOMPLEX_WEB_LISTEN',
    'DNSCOMPLEX_WEB_PORT',
    'DNSCOMPLEX_WEB_PASSWORD',
    'DNSCOMPLEX_METRICS_LISTEN',
    'DNSCOMPLEX_METRICS_PORT',
    'DNSCOMPLEX_UPDATE_TIME',
    'DNSCOMPLEX_UPDATE_LAST_LOG',
    'DNSCOMPLEX_UPDATE_CHANNEL',
    'DNSCOMPLEX_PINNED_VERSION',
    'GITHUB_RELEASE_POLICY',
    'DNSCOMPLEX_NFTSET_REFRESH_INTERVAL',
    'DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT',
    'ADGUARD_DNS_CACHE_MODE',
    'HA_MODE',
    'HA_PRIMARY_IP',
    'HA_SECONDARY_IP',
    'HA_HEALTH_URL',
    'HA_FAILOVER_POLICY',
    'PROMETHEUS_MODE',
    'IPSEC_TCP_MSS',
    'DNSCOMPLEX_IPSEC_BOOT_TIMEOUT',
    'APPLE_PRIVATE_RELAY_BLOCK',
    'AI_MARK',
    'CN_MARK',
    'AI_MARK_DEC',
    'CN_MARK_DEC',
    'SINGBOX_AUTO_REDIRECT_INPUT_MARK',
    'SINGBOX_AUTO_REDIRECT_OUTPUT_MARK',
    'SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC',
    'SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC',
    'AI_TABLE',
    'CN_TABLE',
    'AI_XFRM_ID',
    'CN_XFRM_ID',
)
# The wizard also serves as installer input. This one legacy installer flag is
# supported metadata, not a new runtime schema key to persist during migration.
INSTALLER_METADATA_KEYS = ('DNSCOMPLEX_NONINTERACTIVE',)
ALLOWED_KEYS = SCHEMA_KEYS + INSTALLER_METADATA_KEYS

SECRET_KEYS = {
    'AI_IPSEC_USERNAME', 'AI_IPSEC_PASSWORD', 'CN_IPSEC_USERNAME',
    'CN_IPSEC_PASSWORD', 'DNSCOMPLEX_WEB_PASSWORD', 'AI_XRAY_URI',
    'CN_XRAY_URI', 'AI_XRAY_OUTBOUND_JSON', 'CN_XRAY_OUTBOUND_JSON',
}


class CandidateError(ValueError):
    """Diagnostics contain location/key only, never candidate values or paths."""


def _snapshot(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def read_snapshot(path):
    """Read one non-symlink regular file and reject changes during capture."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise CandidateError('config input must be a regular file')
        chunks = []
        while True:
            data = os.read(fd, 65536)
            if not data:
                break
            chunks.append(data)
        if (_snapshot(before) != _snapshot(os.fstat(fd)) or
                _snapshot(before) != _snapshot(os.lstat(path))):
            raise CandidateError('config input changed during capture')
        return b''.join(chunks)
    except OSError:
        raise CandidateError('config input unavailable or unsafe') from None
    finally:
        if fd is not None:
            os.close(fd)


def parse_env_file(path, allowed_keys):
    """Accept comments and single assignments with literal shell quoting.

    Quotes may concatenate (including write_env_var's '\\'' apostrophe escape).
    Single quoted values may span lines. Expansions are forbidden outside single
    quotes unless escaped. No shell interpreter is used to read the input.
    """
    raw = read_snapshot(path)
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        raise CandidateError('config input must be UTF-8') from None
    if '\0' in text:
        raise CandidateError(f'line {text[:text.index(chr(0))].count(chr(10)) + 1}: NUL is forbidden')
    result = {}
    pos, line, length = 0, 1, len(text)
    allowed = set(allowed_keys)
    while pos < length:
        while pos < length and text[pos] in ' \t\n':
            line += text[pos] == '\n'
            pos += 1
        if pos == length:
            break
        if text[pos] == '#':
            while pos < length and text[pos] != '\n':
                pos += 1
            continue
        start_line = line
        match = re.match(r'([A-Za-z_][A-Za-z0-9_]*)=', text[pos:])
        if not match:
            raise CandidateError(f'line {line}: expected assignment')
        key = match.group(1)
        # Unknown input identifiers may themselves contain sensitive data.
        if key not in allowed:
            raise CandidateError(f'line {line}: unsupported config key')
        if key in result:
            raise CandidateError(f'line {line}: duplicate key {key}')
        pos += len(match.group())
        value = []
        while pos < length and text[pos] not in ' \t\n':
            char = text[pos]
            if char == "'":
                end = text.find("'", pos + 1)
                if end < 0:
                    raise CandidateError(f'line {start_line}: unterminated quote for {key}')
                value.append(text[pos + 1:end])
                line += text[pos + 1:end].count('\n')
                pos = end + 1
            elif char == '"':
                pos += 1
                while pos < length and text[pos] != '"':
                    char = text[pos]
                    if char in '$`':
                        raise CandidateError(f'line {line}: expansion forbidden for {key}')
                    if char == '\\' and pos + 1 < length:
                        following = text[pos + 1]
                        if following in '\\$`"\n':
                            pos += 2
                            if following == '\n':
                                line += 1
                            else:
                                value.append(following)
                            continue
                    value.append(char)
                    line += char == '\n'
                    pos += 1
                if pos == length:
                    raise CandidateError(f'line {start_line}: unterminated quote for {key}')
                pos += 1
            elif char == '\\':
                if pos + 1 == length or text[pos + 1] == '\n':
                    raise CandidateError(f'line {line}: invalid escape for {key}')
                value.append(text[pos + 1])
                pos += 2
            elif char in '$`;;&|()<>}{*?[]~!' or ord(char) < 32:
                raise CandidateError(f'line {line}: shell syntax forbidden for {key}')
            else:
                value.append(char)
                pos += 1
        result[key] = ''.join(value)
        # After a value only horizontal space, an optional comment and EOL.
        spaced = False
        while pos < length and text[pos] in ' \t':
            spaced = True
            pos += 1
        if spaced and pos < length and text[pos] == '#':
            while pos < length and text[pos] != '\n':
                pos += 1
        if pos < length and text[pos] != '\n':
            raise CandidateError(f'line {line}: trailing syntax for {key}')
    return result


def write_normalized(path, values):
    # Caller supplies a fresh path inside its private temporary directory.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            for key in ALLOWED_KEYS:
                if key in values:
                    value = values[key].replace("'", "'\\''")
                    stream.write(f"{key}='{value}'\n")
    except BaseException:
        os.unlink(path)
        raise


def _json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise CandidateError('config JSON contains a duplicate key')
        value[key] = item
    return value


def merge_updates(current, update_path):
    try:
        updates = json.loads(read_snapshot(update_path), object_pairs_hook=_json_object)
    except (ValueError, UnicodeError):
        raise CandidateError('invalid config JSON update') from None
    if not isinstance(updates, dict):
        raise CandidateError('config JSON update must be an object')
    for key, value in updates.items():
        if key not in ALLOWED_KEYS:
            raise CandidateError('unsupported config JSON key')
        if isinstance(value, (dict, list)):
            raise CandidateError(f'config value must be scalar: {key}')
        if key in SECRET_KEYS and value == '********':
            continue
        value = '' if value is None else str(value)
        if '\0' in value:
            raise CandidateError(f'NUL is forbidden: {key}')
        try:
            value.encode('utf-8')
        except UnicodeError:
            raise CandidateError(f'invalid Unicode: {key}') from None
        current[key] = value
    return current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--updates')
    args = parser.parse_args()
    try:
        values = parse_env_file(args.input, ALLOWED_KEYS)
        if args.updates:
            values = merge_updates(values, args.updates)
        write_normalized(args.output, values)
    except (CandidateError, OSError):
        exc = sys.exc_info()[1]
        print(str(exc) if isinstance(exc, CandidateError) else 'config output unavailable or unsafe', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
CONFIG_PARSER
  chmod_target 0755 /usr/local/lib/dnscomplex-config/candidate.py
}

render_web_interface() {
  write_file /usr/local/lib/dnscomplex-web/app.py <<'PY'
#!/usr/bin/env python3
import base64
import binascii
import hashlib
import html
import ipaddress
import json
import os
import re
import socket
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG = "/etc/dnscomplex/config.env"
DNSCOMPLEX = "/usr/local/sbin/dnscomplex"
REDACTOR = "/usr/local/lib/dnscomplex-redact/redact.py"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dnscomplex-config"))
from candidate import ALLOWED_KEYS, parse_env_file

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
    "LOCAL_DOMAIN_IPV6_POLICY",
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
    "AI_QUIC_POLICY",
    "CN_QUIC_POLICY",
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
        <div class="section-head"><h2>營運健康中心</h2><button onclick="loadOpsHealth()">刷新</button></div>
        <div id="opsHealth" class="warning-list"></div>
        <div class="row" style="margin-top:12px">
          <button onclick="runSmokeSoak()">執行 1 分鐘 smoke soak</button>
          <button onclick="loadSoakStatus()">查看最近 soak summary</button>
        </div>
        <pre id="soakSummary"></pre>
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
            <div class="row"><button onclick="testEgress('ai')">AI 候選設定語法檢查</button><button class="primary" onclick="applyEgress('ai')">套用 AI 出口</button></div>
          </div>
          <div>
            <h2>CN</h2>
            <div class="field"><label>出口模式</label><select id="cnEgressMode"><option value="ipsec">IPsec</option><option value="xray">Xray</option></select></div>
            <div class="field"><label>Xray URI</label><textarea id="cnXrayUri" placeholder="vless:// / vmess:// / trojan:// / ss://"></textarea></div>
            <div class="field"><label>Raw Xray outbound JSON</label><textarea id="cnXrayJson" placeholder='{"protocol":"trojan",...}'></textarea></div>
            <div class="row"><button onclick="testEgress('cn')">CN 候選設定語法檢查</button><button class="primary" onclick="applyEgress('cn')">套用 CN 出口</button></div>
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
            <p class="muted">每日只更新域名／geosite／SRS；不更新作業系統或核心。</p>
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
            <h2>本機 .local 名稱</h2>
            <p class="muted">行動裝置的 .local 名稱應跟 mDNS 或 RouterOS DHCP/DNS；此處只適合固定基建主機，不要寫死會變更 IP 的裝置。</p>
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
        <div class="row" style="justify-content:space-between"><h2>規則資料更新</h2><button onclick="loadUpdateStatus()">刷新</button></div>
        <div class="help-card">
          <h3>自動更新範圍</h3>
          <p>每日排程只更新域名／geosite／SRS 規則資料。作業系統與 release 元件需要先建立 VM 復原點，再由終端明確執行。</p>
        </div>
        <div class="row"><button class="primary" onclick="runUpdate()">更新域名／geosite／SRS</button></div>
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
          <button onclick="runAction('update-geosite')">更新域名／geosite／SRS</button>
          <button onclick="runAction('mss-calibrate')">MSS 校準</button>
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
let uiOperationBusy = false;
const dirtyFields = new Set();
const fieldRevisions = new Map();
function markDirty(event) {
  if (event.target && event.target.id) {
    const id = event.target.id;
    dirtyFields.add(id);
    fieldRevisions.set(id, (fieldRevisions.get(id) || 0) + 1);
  }
}
document.addEventListener('input', markDirty);
document.addEventListener('change', markDirty);
function refreshConfigField(id, value) {
  const field = document.getElementById(id);
  if (field && !dirtyFields.has(id)) field.value = value;
}
function retainedOperationId() {
  const id = localStorage.getItem('dnscomplexOperation');
  return id && /^[a-f0-9]{32}$/.test(id) ? id : null;
}
async function api(path, opts={}) {
  const res = await fetch(path, Object.assign({headers:{'content-type':'application/json'}}, opts));
  if (!res.ok) throw new Error(await res.text());
  const data = await res.json();
  if (res.status === 202 && data.operation_id) {
    localStorage.setItem('dnscomplexOperation', data.operation_id);
    return pollOperation(data.operation_id);
  }
  return data;
}
async function pollOperation(id) {
  for (;;) {
    const res = await fetch('/api/operations/' + encodeURIComponent(id));
    if (!res.ok) {
      const error = new Error(res.status === 401
        ? '請重新登入，再重新載入此頁以查詢同一操作：' + id + '；請勿重送變更。'
        : '操作狀態暫不可用；重新連線將查詢同一操作：' + id + '；請勿重送變更。');
      error.operationPending = true;
      throw error;
    }
    const data = await res.json();
    if (data.ok !== null) {
      localStorage.removeItem('dnscomplexOperation');
      return Object.assign({output:data.message},data);
    }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
}

function escapeHtml(value) {
  return String(value || '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
function outputText(data) {
  if (typeof data === 'string') return data;
  let state = '';
  if (data?.partial) state = '部分刷新：請查看各 profile 結果，失敗項可能保留先前資料或已有部分 runtime 變更。';
  else if (data?.phase === 'manual-intervention') state = '需人工恢復：恢復資料已保留。';
  else if (data?.phase === 'recovery-required' || data?.phase === 'recovering' || data?.phase === 'rolling-back') state = '處理中：正在恢復，尚未確認完成。';
  else if (data?.phase === 'rolled-back') state = '失敗已回復。';
  else if (data?.phase === 'committed') state = data.error_code === 'MONITORING_WARNING' ? '已提交，但監控修復有警告；未宣稱網絡健康。' : '已提交。';
  else if (data?.ok === null) state = '處理中：尚未確認結果。';
  else if (data?.ok === false) state = '操作失敗；回復狀態請查看結果。';
  else if (data?.ok === true) state = data.check === 'candidate-syntax' ? '候選設定語法檢查通過；未驗證遠端連線。' : '檢查／操作已完成。';
  return (state ? state + '\n' : '') + JSON.stringify(data, null, 2);
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
async function runWithOutput(target, task, resume=false, submittedFields=[]) {
  if (uiOperationBusy) return {ok:false, busy:true};
  if (!resume && retainedOperationId()) {
    writeOutput(target, '已有待確認操作；請重新登入或重新載入此頁查詢結果，請勿重送變更。');
    return {ok:null, pending:true};
  }
  const submitted = submittedFields.map(id => {
    const field = document.getElementById(id);
    return [id, field?.value, fieldRevisions.get(id) || 0];
  });
  uiOperationBusy = true;
  const buttons = Array.from(document.querySelectorAll('button')).map(button => [button, button.disabled]);
  buttons.forEach(([button]) => { button.disabled = true; });
  writeOutput(target, '處理中...');
  try {
    const data = await task();
    if (data.ok === true) {
      submitted.forEach(([id, value, revision]) => {
        if ((fieldRevisions.get(id) || 0) === revision && document.getElementById(id)?.value === value) dirtyFields.delete(id);
      });
    }
    writeOutput(target, data);
    return data;
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    const pending = err?.operationPending || retainedOperationId();
    writeOutput(target, (pending ? '操作結果待確認：\n' : '操作失敗：\n') + message);
    return {ok:pending ? null : false, pending:!!pending, output:message};
  } finally {
    buttons.forEach(([button, disabled]) => { button.disabled = disabled; });
    uiOperationBusy = false;
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
function renderOpsHealth(data) {
  const host = document.getElementById('opsHealth');
  if (!host) return;
  const checks = data.checks || [];
  const failed = checks.filter(c => c.status !== 'ok').slice(0, 8);
  if (!failed.length) {
    host.innerHTML = `<div class="summary-card ok"><small>Health</small><strong>${escapeHtml(data.status || 'healthy')}</strong><small>所有核心檢查暫時正常。</small></div>`;
    return;
  }
  host.innerHTML = failed.map(c => `<div class="warning-item"><b>${escapeHtml(c.name)}</b> <span class="badge ${badgeClass(c.status === 'fail' ? 'bad' : 'warn')}">${escapeHtml(c.status)}</span><br><span>${escapeHtml(c.detail || '')}</span><br><small><b>建議：</b>${escapeHtml(c.recommended_action || '')}</small></div>`).join('');
}
async function loadOpsHealth() {
  const data = await api('/api/ops/health');
  renderOpsHealth(data);
}
async function loadSoakStatus() {
  const data = await api('/api/ops/soak/status');
  document.getElementById('soakSummary').textContent = outputText(data);
}
async function runSmokeSoak() {
  await runWithOutput('soakSummary', () => api('/api/ops/soak/run', {method:'POST', body: JSON.stringify({duration:'1m', clients:50, dns_qps:20, profiles:'ai,cn,default'})}));
  await loadSoakStatus();
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
  drawChart('latencyChart', points, 'dns_latency_p95_ms', 'DNS p95 latency ms', '#9a6700');
  drawChart('profileChart', points, 'profile_connections_ai', 'AI active connections', '#137a3a');
  drawChart('ipsecChart', points, 'health_status', 'health status 0/1/2', '#b42318');
}
async function loadConnections() {
  const data = await api('/api/connections');
  const rows = data.connections.map(c => `<tr><td>${c.client}</td><td>${c.domain || '<span class="muted">(unknown)</span>'}</td><td>${c.domain_source}</td><td>${c.destination}</td><td>${c.protocol}</td><td>${c.ip_version}</td><td>${c.profile}</td><td>${c.profile_source}</td><td>${c.state}</td></tr>`).join('');
  document.getElementById('connectionsTable').innerHTML = `<table><thead><tr><th>Client</th><th>Domain</th><th>Domain source</th><th>Destination</th><th>Proto</th><th>IP</th><th>出口</th><th>判斷來源</th><th>狀態</th></tr></thead><tbody>${rows || '<tr><td colspan="9" class="muted">沒有活躍連線</td></tr>'}</tbody></table>`;
}
async function loadConfig() {
  const data = await api('/api/config');
  renderConfigGroups(data);
  const fields = {socksListen:'SINGBOX_SOCKS_LISTEN', socksPort:'SINGBOX_SOCKS_PORT',
    updateTime:'DNSCOMPLEX_UPDATE_TIME', mssCurrent:'IPSEC_TCP_MSS',
    aiEgressMode:'AI_EGRESS_MODE', cnEgressMode:'CN_EGRESS_MODE',
    aiXrayUri:'AI_XRAY_URI', cnXrayUri:'CN_XRAY_URI',
    aiXrayJson:'AI_XRAY_OUTBOUND_JSON', cnXrayJson:'CN_XRAY_OUTBOUND_JSON'};
  Object.entries(fields).forEach(([id, key]) => refreshConfigField(id, data[key] || (id.endsWith('EgressMode') ? 'ipsec' : '')));
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
  if (host.dataset.loaded) {
    configKeys.forEach(key => refreshConfigField('cfg_' + key, data[key] || ''));
    return;
  }
  host.dataset.loaded = '1';
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
  await runWithOutput('configOutput', () => api('/api/config', {method:'POST', body: JSON.stringify(payload)}), false, configKeys.map(key => 'cfg_' + key));
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
  })}), false, [upper + 'EgressMode', upper + 'XrayUri', upper + 'XrayJson']);
  await refreshAll();
}
async function setSocks() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'set-socks', listen:socksListen.value, port:socksPort.value})}), false, ['socksListen', 'socksPort']);
  await refreshAll();
}
async function setIpsec() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'set-ipsec', profile:ipsecProfile.value, user:ipsecUser.value, password:ipsecPass.value})}), false, ['ipsecProfile', 'ipsecUser', 'ipsecPass']);
}
async function setUpdateTime() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'set-update-time', value:updateTime.value})}), false, ['updateTime']);
  await refreshAll();
}
async function setWebPassword() {
  const submitted = webPassword.value;
  const revision = fieldRevisions.get('webPassword') || 0;
  const result = await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'set-web-password', password:submitted})}), false, ['webPassword']);
  if (result.ok === true && (fieldRevisions.get('webPassword') || 0) === revision && webPassword.value === submitted) webPassword.value = '';
}
async function mssCalibrate() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'mss-calibrate'})}));
  await refreshAll();
}
async function setLocalHost() {
  await runWithOutput('configOutput', () => api('/api/action', {method:'POST', body: JSON.stringify({action:'set-local-host', host:localHostName.value, ip:localHostIp.value})}), false, ['localHostName', 'localHostIp']);
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
  await runWithOutput('wizardOutput', () => api('/api/wizard/apply', {method:'POST', body: JSON.stringify({config:wizardConfig.value})}), false, ['wizardConfig']);
  await refreshAll();
}
async function loadUpdateStatus() {
  await runWithOutput('updateOutput', () => api('/api/update/status'));
}
async function runUpdate() {
  await runWithOutput('updateOutput', () => api('/api/update/run', {method:'POST', body: '{}'}));
  await refreshAll();
}
async function supportBundle() {
  await runWithOutput('diagnosticsOutput', () => api('/api/support-bundle', {method:'POST', body: JSON.stringify({include_logs:bundleLogs.value})}));
}
async function refreshAll() { await Promise.all([loadUiSummary(), loadOpsHealth(), loadSoakStatus(), loadStatus(), loadTraffic(), loadConnections(), loadConfig(), loadDomains(), loadMetrics()]); }
const pendingOperation = localStorage.getItem('dnscomplexOperation');
if (pendingOperation && /^[a-f0-9]{32}$/.test(pendingOperation)) {
  runWithOutput('output', () => pollOperation(pendingOperation), true);
}
refreshAll().catch(err => showOutput(String(err)));
</script>
</body>
</html>"""

def parse_config():
    if not os.path.exists(CONFIG):
        return {}
    return parse_env_file(CONFIG, ALLOWED_KEYS)

def write_config(updated):
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        json.dump(updated, fh, ensure_ascii=False)
        path = fh.name
    try:
        os.chmod(path, 0o600)
        return run([DNSCOMPLEX, "apply-config-json", path], 300)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

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
    args = [sys.executable, REDACTOR]
    if os.path.isfile(CONFIG):
        args.extend(["--config", CONFIG])
    try:
        proc = subprocess.run(
            args,
            input=text,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "[REDACTION_FAILED]"
    if proc.returncode != 0:
        return "[REDACTION_FAILED]"
    return proc.stdout

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
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write(text)
        if not text.endswith("\n"):
            fh.write("\n")
        path = fh.name
    try:
        os.chmod(path, 0o600)
        return run([DNSCOMPLEX, "apply-config", path], 300)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

def bounded_log_tail(path, limit, max_bytes=4*1024*1024, max_line_bytes=65536):
    """Read a fixed tail window. Skip its partial first line and oversized lines.

    The cap deliberately returns fewer recent records when lines/window exceed
    the budget; a huge or unterminated record cannot trigger a full-file scan.
    """
    if limit <= 0: return []
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        start = max(0, size-max_bytes)
        fh.seek(start)
        data = fh.read(max_bytes)
    if start:
        boundary = data.find(b"\n")
        data = data[boundary+1:] if boundary >= 0 else b""
    lines = data.splitlines(keepends=True)[-limit:]
    return [line.decode("utf-8", "replace") for line in lines if len(line) <= max_line_bytes]

def validate_soak_limits(duration, clients, dns_qps):
    # Use the final executable's validator so web and direct CLI share limits.
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dnscomplex-soak", "runner.py")
    spec = importlib.util.spec_from_file_location("dnscomplex_soak_limits", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_limits(duration, clients, dns_qps)

def update_status():
    cfg = parse_config()
    log_path = cfg.get("DNSCOMPLEX_UPDATE_LAST_LOG", "/var/log/dnscomplex/update-latest.log")
    log_text = ""
    if os.path.exists(log_path):
        log_text = "".join(bounded_log_tail(log_path, 80, max_bytes=512*1024))
    return {
        "channel": cfg.get("DNSCOMPLEX_UPDATE_CHANNEL", "stable"),
        "pinned_version": cfg.get("DNSCOMPLEX_PINNED_VERSION", ""),
        "github_release_policy": cfg.get("GITHUB_RELEASE_POLICY", "latest"),
        "last_update_log": log_path,
        "last_update_output": redact_text(log_text),
    }

def run(args, timeout=120):
    proc = subprocess.Popen(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        output, _ = proc.communicate(timeout=timeout)
        return {"ok": proc.returncode == 0, "code": proc.returncode, "output": output[-12000:]}
    except subprocess.TimeoutExpired:
        try: os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: proc.communicate(timeout=2)
        except subprocess.TimeoutExpired: pass
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        proc.communicate(timeout=2)
        return {"ok": False, "code": 124, "output": "Diagnostic deadline exceeded; owned processes stopped."}

OPERATION_HELPER = "/usr/local/libexec/dnscomplex-operation"
PERSISTENT_ACTIONS = {"fix","update-geosite","mss-calibrate",
    "set-egress","set-socks","set-ipsec","set-web-password","set-local-host","set-update-time","add-domain","remove-domain"}
OPERATION_PATHS = {"/api/config":"config", "/api/wizard/apply":"wizard-apply",
    "/api/update/run":"update-geosite", "/api/egress/apply":"egress-apply",
    "/api/rules/domain":"rules-domain", "/api/rules/geosite":"rules-geosite", "/api/rules/rebuild":"update-geosite"}

class OperationConflict(ValueError):
    pass

def operation_submit(action, payload):
    proc = subprocess.run([sys.executable,OPERATION_HELPER,"submit",action],
        input=json.dumps(payload),text=True,capture_output=True,timeout=20)
    if proc.returncode == 3: raise OperationConflict("Operation busy or recovery pending; no automatic retry.")
    if proc.returncode: raise ValueError("Operation could not be safely submitted; no automatic retry.")
    return json.loads(proc.stdout)

def operation_status(operation_id):
    if not re.fullmatch(r"[a-f0-9]{32}", operation_id): return None
    proc = subprocess.run([sys.executable,OPERATION_HELPER,"status",operation_id],
        text=True,capture_output=True,timeout=5)
    if proc.returncode == 4: return None
    if proc.returncode: raise ValueError("Operation status unavailable.")
    return json.loads(proc.stdout)

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
        lines = bounded_log_tail(path, 80, max_bytes=512*1024)
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
        result = run(["xray", "run", "-test", "-format=json", "-config", out], 30)
        result["check"] = "candidate-syntax"
        result["output"] = ("候選設定語法檢查通過；未驗證遠端連線。" if result["ok"] else "候選設定語法檢查失敗；未驗證遠端連線。") + "\n" + redact_text(result.get("output", ""))
        return result
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass

def egress_apply(payload):
    # Compatibility entry point: the same lifecycle owns the entire candidate.
    return operation_submit("egress-apply", payload)

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
        lines = bounded_log_tail(path, limit)
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
    out = shell_output([DNSCOMPLEX, "metrics-sample"], 30)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"error": out}

def metrics_history(limit=720):
    path = "/var/lib/dnscomplex/metrics.sqlite3"
    if not os.path.exists(path):
        return []
    metrics_current()
    try:
        with sqlite3.connect(path) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "select ts, conntrack_usage_ratio, dns_latency_ms, dns_latency_p95_ms, dns_success_ratio, ai_nftset_count, cn_nftset_count, ai_nftset_age_seconds, cn_nftset_age_seconds, ipsec_ai_up, ipsec_cn_up, xray_up, health_status, adguard_cache_enabled, profile_connections_ai, profile_connections_cn, profile_connections_default, ipv6_connection_ratio, schema_version from samples order by ts desc limit ?",
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

def ops_health():
    raw = shell_output([DNSCOMPLEX, "health", "--json"], 20)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"status": "unhealthy", "failure_reasons": [raw], "recommended_actions": ["run dnscomplex doctor"]}

def latest_soak_summary():
    import glob
    files = sorted(glob.glob("/var/log/dnscomplex/soak-*.json"), key=os.path.getmtime, reverse=True)
    if not files:
        return {"ok": True, "latest": None, "message": "no soak summary found"}
    path = files[0]
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        data["path"] = path
        return {"ok": True, "latest": data}
    except Exception as exc:
        return {"ok": False, "latest": {"path": path, "error": str(exc)}}

class RequestInputError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message

class DeadlineReader:
    """The only socket reader: one absolute budget for request line, headers and body."""
    def __init__(self, connection, timeout):
        self.connection = connection
        self.deadline = time.monotonic() + timeout
        self.buffer = bytearray()
    def receive(self, size):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0: raise RequestInputError(408, "request input deadline exceeded")
        self.connection.settimeout(remaining)
        try: return self.connection.recv(size)
        except (socket.timeout, TimeoutError): raise RequestInputError(408, "request input deadline exceeded")
    def readline(self, size=65537):
        while True:
            end = self.buffer.find(b"\n") + 1
            if end or len(self.buffer) >= size:
                end = min(end or size, size)
                result = bytes(self.buffer[:end]); del self.buffer[:end]
                return result
            data = self.receive(min(8192, size-len(self.buffer)))
            if not data:
                result = bytes(self.buffer); self.buffer.clear(); return result
            self.buffer.extend(data)
    def read(self, size):
        result = bytearray(self.buffer[:size]); del self.buffer[:size]
        while len(result) < size:
            data = self.receive(min(8192, size-len(result)))
            if not data: break
            result.extend(data)
        return bytes(result)
    def finish_input(self):
        # Response writes have their own finite inactivity limit. No timer can
        # interrupt a valid operation once its complete input has been received.
        self.connection.settimeout(15)
    def close(self):
        self.buffer.clear()

class BoundedHTTPServer(ThreadingHTTPServer):
    max_requests = 16
    daemon_threads = True
    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(self.max_requests)
        super().__init__(*args, **kwargs)
    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(.1)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError: pass
            finally: self.shutdown_request(request)
            return
        try: super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise
    def process_request_thread(self, request, client_address):
        try: super().process_request_thread(request, client_address)
        finally: self.slots.release()

class Handler(BaseHTTPRequestHandler):
    input_timeout = 15
    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = DeadlineReader(self.connection, self.input_timeout)
    def handle_one_request(self):
        # One admitted connection handles one request, including rejection paths.
        try: super().handle_one_request()
        except RequestInputError as exc:
            self.request_version = getattr(self, "request_version", "HTTP/1.0")
            self.requestline = getattr(self, "requestline", "")
            self.command = getattr(self, "command", None)
            self.input_error(exc)
        finally: self.close_connection = True
    def parse_request(self):
        result = super().parse_request()
        if result and self.command != "POST": self.rfile.finish_input()
        return result
    def input_error(self, exc):
        self.close_connection = True
        self.rfile.finish_input()
        self.send_json({"ok":False,"error":exc.message}, exc.code)
    def read_body(self, maximum):
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get_all("Transfer-Encoding") or len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
            raise RequestInputError(400, "one decimal Content-Length required; transfer encoding unsupported")
        length = int(lengths[0])
        if length > maximum: raise RequestInputError(413, "request body too large")
        raw = self.rfile.read(length)
        if len(raw) != length: raise RequestInputError(400, "incomplete request body")
        self.rfile.finish_input()
        try: return raw.decode("utf-8")
        except UnicodeDecodeError: raise RequestInputError(400, "invalid UTF-8 body")
    def json_object(self, raw):
        try: payload = json.loads(raw)
        except (ValueError, RecursionError): raise RequestInputError(400, "invalid JSON body")
        if not isinstance(payload, dict): raise RequestInputError(400, "JSON object required")
        return payload

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

    def send_login_page(self, error="", code=200):
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
</html>''', code)

    def handle_login(self):
        cfg = parse_config()
        password = cfg.get("DNSCOMPLEX_WEB_PASSWORD", "")
        raw = self.read_body(16*1024)
        content_type = self.headers.get("content-type", "")
        if "application/json" in content_type:
            payload = self.json_object(raw)
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
        return self.json_object(self.read_body(1024*1024))

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
        if self.path.startswith("/api/operations/"):
            try:
                result = operation_status(self.path[len("/api/operations/"):])
                self.send_json(result if result is not None else {"error":"not found"}, 200 if result is not None else 404)
            except (ValueError, OSError, subprocess.SubprocessError):
                self.send_json({"error":"operation status unavailable"},503)
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
        if self.path == "/api/ops/health":
            self.send_json(ops_health())
            return
        if self.path == "/api/ops/soak/status":
            self.send_json(latest_soak_summary())
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
            try: self.handle_login()
            except RequestInputError as exc: self.input_error(exc)
            return
        if not self.require_auth():
            return
        try:
            payload = self.read_json()
            action = OPERATION_PATHS.get(self.path)
            if self.path == "/api/action" and payload.get("action") in PERSISTENT_ACTIONS:
                action = payload["action"]
            if action:
                self.send_json(operation_submit(action,payload),202)
                return
            if self.path == "/api/config":
                result = write_config(payload)
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
                result = run([DNSCOMPLEX, "update-geosite"], 900)
                result["output"] = redact_text(result.get("output", ""))
                self.send_json(result)
                return
            if self.path == "/api/support-bundle":
                include_logs = payload.get("include_logs", "standard")
                result = run([DNSCOMPLEX, "support-bundle", "--include-logs", include_logs], 300)
                result["output"] = redact_text(result.get("output", ""))
                self.send_json(result)
                return
            if self.path == "/api/ops/soak/run":
                try: validate_soak_limits(payload.get("duration", "1m"), payload.get("clients", 50), payload.get("dns_qps", 20))
                except ValueError as exc:
                    self.send_json({"ok":False,"output":str(exc)},400)
                    return
                args = [
                    DNSCOMPLEX,
                    "soak",
                    "--duration", str(payload.get("duration", "1m")),
                    "--clients", str(payload.get("clients", 50)),
                    "--dns-qps", str(payload.get("dns_qps", 20)),
                    "--profiles", str(payload.get("profiles", "ai,cn,default")),
                ]
                if payload.get("idle_resume"):
                    args.append("--idle-resume")
                result = run(args, 7200)
                result["output"] = redact_text(result.get("output", ""))
                self.send_json(result)
                return
            if self.path == "/api/action":
                action = payload.get("action", "")
                if action in {"refresh-nftsets", "refresh-cn-overrides"}:
                    result=run([DNSCOMPLEX,action],120)
                    result["partial"]=(not result["ok"] or "kept_previous" in result.get("output",""))
                    result["message"]="Partial refresh or failure; inspect per-profile outcomes. Failed items may have applied runtime changes." if result["partial"] else "Runtime refresh complete."
                    result["output"]=result["message"]+"\n"+redact_text(result.get("output",""))
                    self.send_json(result)
                    return
                if action in {"test", "fix", "doctor", "test-dns", "test-ipsec", "update-geosite", "backup", "mss-calibrate"}:
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
        except RequestInputError as exc:
            self.input_error(exc)
        except OperationConflict:
            self.send_json({"ok":False,"error_code":"BUSY","output":"Operation busy or recovery pending; no automatic retry."},409)
        except Exception as exc:
            self.send_json({"ok": False, "output": str(exc)}, 500)

def main():
    subprocess.run([sys.executable,OPERATION_HELPER,"resume"],timeout=20,check=False)
    cfg = parse_config()
    listen = cfg.get("DNSCOMPLEX_WEB_LISTEN", "127.0.0.1")
    port = int(cfg.get("DNSCOMPLEX_WEB_PORT", "8088"))
    server = BoundedHTTPServer((listen, port), Handler)
    print(f"dnscomplex-web listening on http://{listen}:{port}", flush=True)
    server.serve_forever()

if __name__ == "__main__":
    main()
PY
  chmod_target 0755 /usr/local/lib/dnscomplex-web/app.py

  write_file /etc/systemd/system/dnscomplex-web.service <<'EOF'
[Unit]
Description=dnscomplex web management interface
Requires=dnscomplex-network-ready.service
After=dnscomplex-network-ready.service

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
  apply_systemd_ssh_generator_disable
  apply_runtime_network_settings
  systemctl daemon-reload
  systemctl restart systemd-journald
  journalctl --rotate || true
  journalctl --vacuum-size=512M || true
  systemctl enable --now dnscomplex-restore-recovery.service
  systemctl enable --now dnscomplex-restore-services.service
  if [[ "$DEPLOY_MODE" == "routeros-policy" ]]; then
    systemctl enable --now nftables
  else
    systemctl enable --now systemd-networkd nftables dnsmasq radvd
  fi
  systemctl restart nftables
  systemctl enable --now dnscomplex-network-ready
  systemctl enable --now dnscomplex-ipsec-ifaces
  for ipsec_unit in strongswan-swanctl strongswan-starter strongswan ipsec; do
    if systemctl list-unit-files "${ipsec_unit}.service" >/dev/null 2>&1; then
      if systemctl enable --now "$ipsec_unit" && systemctl restart "$ipsec_unit"; then
        ipsec_enabled=1
        break
      fi
    fi
  done
  [[ "$ipsec_enabled" == "1" ]] || warn "no strongSwan systemd unit found; IPsec may need manual service setup"
  systemctl enable dnscomplex-ipsec-ready dnscomplex-routing
  systemctl enable --now \
    dnscomplex-health.timer \
    dnscomplex-update.timer \
    dnscomplex-cn-overrides.timer \
    dnscomplex-nftset-refresh.timer \
    dnscomplex-metrics-sample.timer
  systemctl reset-failed dnscomplex-ipsec-ready dnscomplex-routing
  systemctl restart dnscomplex-ipsec-ready || warn "selected external IPsec egress is currently unavailable; fail-closed recovery will continue from the health timer"
  systemctl restart dnscomplex-routing || warn "policy routing is waiting for selected IPsec egress readiness"
  systemctl restart dnscomplex-health.timer \
    dnscomplex-update.timer \
    dnscomplex-cn-overrides.timer \
    dnscomplex-nftset-refresh.timer \
    dnscomplex-metrics-sample.timer
  systemctl reset-failed \
    dnscomplex-health \
    dnscomplex-update \
    dnscomplex-cn-overrides \
    dnscomplex-nftset-refresh \
    dnscomplex-metrics-sample
  systemctl enable --now smartdns AdGuardHome sing-box xray-dnscomplex
  systemctl enable --now dnscomplex-web
  systemctl enable --now dnscomplex-metrics
  systemctl restart smartdns AdGuardHome sing-box xray-dnscomplex
  systemctl restart dnscomplex-web dnscomplex-metrics
}

validate_rendered_install() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  local swan_file=/etc/swanctl/swanctl.conf
  local -a python_files=(
    /usr/local/libexec/dnscomplex-operation
    /usr/local/lib/dnscomplex-config/candidate.py
    /usr/local/lib/dnscomplex-metrics/exporter.py
    /usr/local/lib/dnscomplex-redact/redact.py
    /usr/local/lib/dnscomplex-soak/runner.py
    /usr/local/lib/dnscomplex-web/app.py
    /usr/local/lib/dnscomplex-xray/render.py
  )
  local -a unit_files=(
    /etc/systemd/system/dnscomplex-operation@.service
    /etc/systemd/system/dnscomplex-operation-recovery@.service
    /etc/systemd/system/dnscomplex-operation-guard@.service
    /etc/systemd/system/dnscomplex-operation-guard@.timer
    /etc/systemd/system/AdGuardHome.service
    /etc/systemd/system/dnscomplex-cn-overrides.service
    /etc/systemd/system/dnscomplex-cn-overrides.timer
    /etc/systemd/system/dnscomplex-health.service
    /etc/systemd/system/dnscomplex-health.timer
    /etc/systemd/system/dnscomplex-ipsec-ifaces.service
    /etc/systemd/system/dnscomplex-ipsec-ready.service
    /etc/systemd/system/dnscomplex-metrics-sample.service
    /etc/systemd/system/dnscomplex-metrics-sample.timer
    /etc/systemd/system/dnscomplex-metrics.service
    /etc/systemd/system/dnscomplex-network-ready.service
    /etc/systemd/system/dnscomplex-nftset-refresh.service
    /etc/systemd/system/dnscomplex-nftset-refresh.timer
    /etc/systemd/system/dnscomplex-restore-recovery.service
    /etc/systemd/system/dnscomplex-restore-services.service
    /etc/systemd/system/dnscomplex-routing.service
    /etc/systemd/system/dnscomplex-update.service
    /etc/systemd/system/dnscomplex-update.timer
    /etc/systemd/system/dnscomplex-web.service
    /etc/systemd/system/xray-dnscomplex.service
  )

  log "preflight: validate rendered configuration before service changes"
  bash -n /usr/local/sbin/dnscomplex
  python3 -m py_compile "${python_files[@]}"
  validate_rendered_smartdns
  /opt/AdGuardHome/AdGuardHome --check-config -c /etc/AdGuardHome/AdGuardHome.yaml
  sing-box check -c /etc/sing-box/config.json
  xray run -test -format=json -config /usr/local/etc/xray/config.json
  nft -c -f /etc/nftables.conf
  python3 - "$swan_file" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
depth = 0
quoted = False
escaped = False
for char in text:
    if escaped:
        escaped = False
        continue
    if quoted and char == "\\":
        escaped = True
        continue
    if char == '"':
        quoted = not quoted
        continue
    if quoted:
        if char == "\n":
            raise SystemExit("newline inside quoted swanctl value")
        continue
    if char == "{":
        depth += 1
    elif char == "}":
        depth -= 1
        if depth < 0:
            raise SystemExit("unbalanced swanctl closing brace")
if quoted or depth:
    raise SystemExit("unbalanced swanctl configuration")
for required in ("connections {", "secrets {", "ai {", "cn {"):
    if required not in text:
        raise SystemExit(f"missing swanctl section: {required}")
PY
  systemd-analyze verify "${unit_files[@]}" smartdns.service sing-box.service
  log "preflight: rendered configuration valid"
}

close_existing_lan_alias_before_render() {
  [[ "$DRY_RUN" == "1" ]] && return 0
  local helper state config
  helper=$(target_path /usr/local/libexec/dnscomplex-lan-alias)
  state=$(target_path /var/lib/dnscomplex/lan-alias.json)
  config=$(target_path /etc/sing-box/config.json)
  if [[ -e "$state" || -L "$state" ]]; then
    [[ -x "$helper" ]] || die "LAN alias ownership state exists but its validator is missing; refusing to replace sing-box config"
    python3 "$helper" close --config "$config" --state "$state" ||
      die "could not close and verify LAN alias readiness before replacing configuration"
  elif [[ -x "$helper" ]]; then
    # A leftover readiness marker without ownership state is inconsistent. Let
    # the helper close it before any base renderer can replace its config.
    python3 "$helper" close --config "$config" --state "$state" ||
      die "could not close stale LAN alias readiness before replacing configuration"
  fi
}

render_all() {
  save_runtime_config
  disable_systemd_ssh_generator
  render_network
  configure_dhcpcd_resolver_ownership
  configure_nsswitch_resolver_ownership
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
  render_lan_alias_runtime
  render_singbox
  render_nftables
  render_restore_recovery
  render_operation_lifecycle
  render_logging_policy
  render_ipsec_services
  render_routeros
  render_management_script
  render_xui_sniffing_repair
  render_egress_probe
  render_soak_runner
  render_metrics_exporter
  render_redactor
  render_config_parser
  render_web_interface
}

main() {
  parse_args "$@"
  load_config
  collect_interactive_config
  validate_config
  require_debian13
  require_root
  acquire_installer_maintenance_lock
  close_existing_lan_alias_before_render
  install_packages
  render_all
  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run render complete under ${DNSCOMPLEX_ROOT:-/}"
  else
    DNSCOMPLEX_TIMER_MODE=1 dnscomplex update-geosite --prepare-only
    validate_rendered_install
    release_installer_maintenance_lock
    enable_services
    DNSCOMPLEX_TIMER_MODE=1 dnscomplex update-geosite
    dnscomplex watchdog || warn "runtime remains degraded after installation; health timer will continue bounded recovery"
    DNSCOMPLEX_TIMER_MODE=1 dnscomplex refresh-nftsets
    dnscomplex test || warn "local configuration is valid but one or more external egress checks remain degraded"
    log "installed; local configuration validated"
    log "RouterOS commands: dnscomplex routeros-print"
  fi
}

main "$@"
