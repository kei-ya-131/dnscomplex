#!/usr/bin/env bash
# Regression: render/apply/calibrate must never raise a peer's lower MSS.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed "s/CHANGE_ME_AI_USER/test-ai/; s/CHANGE_ME_AI_PASSWORD/test-ai-pass/; s/CHANGE_ME_CN_USER/test-cn/; s/CHANGE_ME_CN_PASSWORD/test-cn-pass/; s/SINGBOX_SOCKS_PORT=1080$/SINGBOX_SOCKS_PORT=10800/" "$repo/examples/routeros-policy.config.env" > "$tmp/config.env"
DNSCOMPLEX_ROOT="$tmp/root" bash "$repo/install.sh" --dry-run --config "$tmp/config.env" >"$tmp/render.log" 2>&1 || { cat "$tmp/render.log"; exit 1; }
python3 - "$tmp/root/etc/nftables.d/dnscomplex.nft" <<'PY'
import re, sys
text=open(sys.argv[1]).read()
rules=[s.strip() for s in text.splitlines() if 'tcp option maxseg size set' in s]
assert rules, 'no MSS rules rendered'
for rule in rules:
    set_value=int(re.search(r'size set (\d+)',rule)[1])
    guard=re.search(r'maxseg size > (\d+)',rule)
    for offered in (536,set_value-1,set_value,set_value+1,1460):
        result=set_value if (guard is None or offered>int(guard[1])) else offered
        assert result<=offered, f'MSS raised {offered} -> {result}: {rule}'
PY
# Invoke actual runtime calibration on a temporary config. Only external
# commands / absolute live paths are redirected; calibration body stays real.
python3 - "$tmp/root/usr/local/sbin/dnscomplex" "$tmp/calibrate.sh" "$tmp/live.nft" <<'PY'
import sys
text=open(sys.argv[1]).read()
# Source the emitted manager so calibration keeps its actual fs_path, transaction
# callback, atomic publish and persisted/runtime readback dependencies.
open(sys.argv[2],'w').write(text)
PY
cat > "$tmp/live.nft" <<'EOF_RULE'
tcp flags syn tcp option maxseg size > 1200 tcp option maxseg size set 1200
EOF_RULE
cp "$tmp/live.nft" "$tmp/runtime.nft"
DNS_TEST_NFT_RUNTIME="$tmp/runtime.nft" DNS_TEST_NFT_FILE="$tmp/live.nft" bash -c '
source "$1"
need_root() { :; }; log() { :; }; warn() { :; }
CONFIG="$2.config"; printf "IPSEC_TCP_MSS=1200\n" >"$CONFIG"
write_config_cmd() { printf "IPSEC_TCP_MSS=%s\n" "$IPSEC_TCP_MSS" >"$CONFIG"; }
load_config() { source "$CONFIG"; }
fs_path() { printf "%s\n" "$DNS_TEST_NFT_FILE"; }
state_transaction_cmd() { shift; local callback=$1; shift; "$callback" "$@"; }
systemctl() { :; }
nft() {
  case "$1" in
    -c) :;;
    -a) sed "s/size set [0-9][0-9]*/& # handle 17/" "$DNS_TEST_NFT_RUNTIME";;
    -f)
      value=$(awk "{for(i=1;i<=NF;i++) if(\$i==\"set\") print \$(i+1)}" "$2")
      printf "tcp flags syn tcp option maxseg size > %s tcp option maxseg size set %s\n" "$value" "$value" >"$DNS_TEST_NFT_RUNTIME"
      ;;
    *) return 1;;
  esac
}
ip() { printf "1: ipsec mtu %s up\n" "$test_mtu"; }
test_mtu=1400; mss_calibrate_cmd
grep -q "size > 1340 tcp option maxseg size set 1340" "$2" || { echo "calibration left stale guard" >&2; exit 1; }
test_mtu=1260; mss_calibrate_cmd
grep -q "size > 1200 tcp option maxseg size set 1200" "$2" || { echo "second calibration left stale guard" >&2; exit 1; }
' _ "$tmp/calibrate.sh" "$tmp/live.nft"
printf 'MSS regression: ok\n'
