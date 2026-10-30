#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

extract_function() {
  local source=$1 name=$2
  awk -v name="$name" '$0 ~ "^" name "\\(\\) \\{$" {copy=1} copy {print} copy && /^}$/ {exit}' "$source"
}
awk '/write_file_atomic .*dnscomplex <<.MANAGER./ {inside=1; next} inside && /^MANAGER$/ {exit} inside {print}' \
  "$repo_root/install.sh" >"$tmp/manager.sh"
[[ -s "$tmp/manager.sh" ]] || { echo "could not extract generated manager" >&2; exit 1; }

cat >"$tmp/source.conf" <<'EOF'
bind 127.0.0.1:6053 -group default
server 127.0.0.1:5300 -group default
cache-persist yes
cache-file /var/lib/smartdns/dnscomplex.cache
log-file /var/log/smartdns/smartdns.log
audit-file /var/log/smartdns/audit.log
# conf-file /etc/smartdns/ignored.conf
EOF
cat >"$tmp/timeout" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == 2 ]] || exit 91; shift
[[ "$1" == unshare ]] || exit 92; shift
[[ "$1" == --net ]] || exit 93; shift
[[ "$1" == -- ]] || exit 94; shift
[[ "$1" == smartdns ]] || exit 95; shift
config=
while (($#)); do
  if [[ "$1" == -c ]]; then shift; config=$1; break; fi
  shift
done
[[ -f "$config" ]] || exit 96
cp "$config" "$CAPTURE_CONFIG"
printf 'called\n' >>"$CALLS"
grep -Fq 'bind 127.0.0.1:6053 -group default' "$config" || exit 97
grep -Fq 'cache-persist no' "$config" || exit 98
private_cache=$(awk '$1 == "cache-file" { print $2; exit }' "$config")
[[ "$private_cache" == /tmp/dnscomplex-smartdns-preflight.*/smartdns.cache ]] || exit 99
grep -Fq "log-file $private_cache.log" "$config" || exit 100
grep -Fq "audit-file $private_cache.audit" "$config" || exit 101
if grep -Eq '/var/lib/smartdns|/var/log/smartdns' "$config"; then exit 102; fi
exit 124
EOF
chmod 700 "$tmp/timeout"
export TEST_CONFIG="$tmp/source.conf"
export CAPTURE_CONFIG="$tmp/captured.conf" CALLS="$tmp/calls" PATH="$tmp:$PATH"

for source in "$repo_root/install.sh" "$tmp/manager.sh"; do
  functions="$tmp/functions.sh"; : >"$functions"
  extract_function "$source" prepare_smartdns_preflight_config >>"$functions"
  if [[ "$source" == "$repo_root/install.sh" ]]; then
    extract_function "$source" validate_rendered_smartdns >>"$functions"
    test_function=validate_rendered_smartdns
    setup='target_path(){ printf "%s\n" "$TEST_CONFIG"; }'
  else
    extract_function "$source" validate_smartdns_config_cmd >>"$functions"
    test_function=validate_smartdns_config_cmd
    setup='fs_path(){ printf "%s\n" "$TEST_CONFIG"; }'
  fi
  [[ -s "$functions" ]] || { echo "missing preflight functions in $source" >&2; exit 1; }
  : >"$CALLS"
  bash -c "die(){ echo \"die: \$*\" >&2; exit 1; }; $setup; source '$functions'; $test_function"
  grep -Fq 'server 127.0.0.1:5300 -group default' "$CAPTURE_CONFIG"
  [[ $(grep -c '^cache-persist no$' "$CAPTURE_CONFIG") == 1 ]]
  [[ $(grep -c '^cache-file ' "$CAPTURE_CONFIG") == 1 ]]
  private_cache=$(awk '$1 == "cache-file" { print $2; exit }' "$CAPTURE_CONFIG")
  [[ $(grep -Fc "log-file $private_cache.log" "$CAPTURE_CONFIG") == 1 ]]
  [[ $(grep -Fc "audit-file $private_cache.audit" "$CAPTURE_CONFIG") == 1 ]]
  ! grep -Eq '/var/lib/smartdns|/var/log/smartdns' "$CAPTURE_CONFIG"
  grep -Fq '# conf-file /etc/smartdns/ignored.conf' "$CAPTURE_CONFIG"
  if awk '/^[[:space:]]*#/ {next} tolower($1) == "conf-file" || tolower($1) == "include" {found=1} END {exit found ? 0 : 1}' "$CAPTURE_CONFIG"; then
    echo "active include directive survived sanitization" >&2; exit 1
  fi

  printf 'conf-file /etc/smartdns/uncontrolled.conf\n' >>"$TEST_CONFIG"
  before=$(wc -l <"$CALLS")
  if bash -c "die(){ exit 73; }; $setup; source '$functions'; $test_function"; then
    echo "validator accepted a configuration include from $source" >&2; exit 1
  fi
  [[ $(wc -l <"$CALLS") == "$before" ]] || { echo "include reached SmartDNS" >&2; exit 1; }
  printf 'cache-file=/var/lib/smartdns/unexpected.cache\n' >>"$TEST_CONFIG"
  if bash -c "die(){ exit 73; }; $setup; source '$functions'; $test_function"; then
    echo "validator accepted an unexpected side-effect directive format from $source" >&2; exit 1
  fi
  [[ $(wc -l <"$CALLS") == "$before" ]] || { echo "side-effect directive reached SmartDNS" >&2; exit 1; }
  sed '$d' "$TEST_CONFIG" >"$tmp/source.restored"
  sed '$d' "$tmp/source.restored" >"$tmp/source.restored.2"
  mv "$tmp/source.restored.2" "$TEST_CONFIG"
done
echo "SmartDNS preflight cache-isolation tests passed"
