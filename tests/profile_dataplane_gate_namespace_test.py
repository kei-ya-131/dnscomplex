#!/usr/bin/env python3
"""Isolated Linux wire check for profile probe exceptions and runtime gates.

This test applies the candidate installer's rendered nft table in a private
network namespace, populates probe VIP sets through the candidate manager, and
executes the candidate-installed DoH helper against controlled TLS peers. The
veth-backed ``ipsec-ai``/``ipsec-cn`` links model profile egress only; there is
no IKE/XFRM peer and no production route or gate is changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time


AI = {"vip": "10.250.1.10", "resolver": "104.16.248.249",
      "tls": "cloudflare-dns.com", "query": "openai.com", "mark": 929,
      "fwmark": 769, "table": 301, "profile": "ai"}
CN = {"vip": "10.251.1.10", "resolver": "223.6.6.6",
      "tls": "dns.alidns.com", "query": "youku.com", "mark": 1009,
      "fwmark": 849, "table": 351, "profile": "cn"}
DEFAULT_MARK = 8228
MAX_SECONDS = 90


def run(argv, *, input_text=None, timeout=8, check=True, env=None):
    result = subprocess.run(argv, input=input_text, capture_output=True, text=True,
                           timeout=timeout, env=env)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv!r}\n{result.stderr[-1800:]}")
    return result


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_probe_sha(installer: Path) -> str:
    source = installer.read_text(encoding="utf-8")
    matches = re.findall(r'^PROFILE_DATAPLANE_PROBE_SHA256="([0-9a-f]{64})"$', source, re.M)
    if len(matches) != 1:
        raise AssertionError("candidate installer must pin exactly one profile probe module SHA")
    return matches[0]


def render_candidate(installer: Path, root: Path) -> tuple[Path, Path, Path]:
    """Run actual nft/runtime/probe asset renderers under a disposable rootfs."""
    source = installer.read_text(encoding="utf-8")
    lines = source.rstrip().splitlines()
    if not lines or lines[-1] != 'main "$@"':
        raise AssertionError("candidate installer entrypoint shape changed; refusing unsafe source")
    offline = root / "installer-offline.sh"
    offline.write_text("\n".join(lines[:-1]) + "\n# fixture: main is intentionally omitted\n",
                       encoding="utf-8")
    offline.chmod(0o600)
    render_root = root / "render-root"
    render_root.mkdir(mode=0o700)
    output = render_root / "etc/nftables.d/dnscomplex.nft"
    shell = r'''source "$1"
DEPLOY_MODE=routeros-policy
WAN_IFACE=ens18
LAN_VLAN_ID=
LAN_CLIENT_IPV4_CIDR=198.18.1.0/24
LINUX_LAN_IPV4=198.18.1.1
AI_EGRESS_MODE=ipsec
CN_EGRESS_MODE=ipsec
AI_QUIC_POLICY=reject
CN_QUIC_POLICY=reject
AI_MARK=0x301
CN_MARK=0x351
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=0x2024
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC=8228
DRY_RUN=1
DNSCOMPLEX_ROOT="$2"
render_nftables
render_management_script
render_egress_probe
'''
    run(["bash", "-c", shell, "candidate-render", str(offline), str(render_root)], timeout=15)
    if not output.is_file():
        raise AssertionError("candidate renderer did not emit the production nft table")
    config = render_root / "etc/dnscomplex/config.env"
    config.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.write_text("DEPLOY_MODE=routeros-policy\nWAN_IFACE=ens18\nAI_EGRESS_MODE=ipsec\nCN_EGRESS_MODE=ipsec\n",
                      encoding="utf-8")
    config.chmod(0o600)
    rendered = output.read_text(encoding="utf-8")
    module = render_root / "usr/local/lib/dnscomplex/profile-dataplane-probe.py"
    manager = render_root / "usr/local/sbin/dnscomplex"
    if not manager.is_file() or not os.access(manager, os.X_OK):
        raise AssertionError("candidate did not render an executable private runtime manager")
    if not module.is_file():
        raise AssertionError("candidate installer did not render the private probe helper target")
    if sha256(module) != extract_probe_sha(installer):
        raise AssertionError("candidate-rendered private probe helper did not match installer SHA pin")
    if not os.access(module, os.X_OK):
        raise AssertionError("candidate-rendered private probe helper is not executable")
    ai_rule = 'comment "dnscomplex-ai-dataplane-probe"'
    cn_rule = 'comment "dnscomplex-cn-dataplane-probe"'
    if ai_rule not in rendered or cn_rule not in rendered:
        raise AssertionError("actual renderer omitted an IPsec probe exception")
    chain = rendered.split("  chain output {", 1)[1].split("\n  }", 1)[0]
    expected_rules = (
        'ip saddr @ai_probe_vip4 oifname "ipsec-ai" ip daddr 104.16.248.249 tcp dport 443 meta mark 0x3a1 counter meta mark set 0x301 accept comment "dnscomplex-ai-dataplane-probe"',
        'ip saddr @cn_probe_vip4 oifname "ipsec-cn" ip daddr 223.6.6.6 tcp dport 443 meta mark 0x3f1 counter meta mark set 0x351 accept comment "dnscomplex-cn-dataplane-probe"',
    )
    for label, expected in zip((ai_rule, cn_rule), expected_rules):
        if chain.lower().count(expected) != 1:
            raise AssertionError(f"unexpected production probe rule predicate: expected exactly {expected!r}")
        if chain.index(label) > chain.index('comment "dnscomplex-ai-not-ready-output"'):
            raise AssertionError("probe exception must precede closed profile readiness gates")
    return output, module, manager


def manager_sync(manager: Path, root: Path, profile: str, vip: str):
    shell = r'''DNSCOMPLEX_ROOT="$2"
DNSCOMPLEX_CONFIG="$2/etc/dnscomplex/config.env"
DNSCOMPLEX_FS_ROOT="$2"
source "$1"
load_config
sync_ipsec_probe_vip_profile "$3" "$4"
'''
    result = run(["bash", "-c", shell, "candidate-vip-sync", str(manager), str(root), profile, vip],
                 timeout=8, check=False)
    if result.returncode:
        raise RuntimeError("candidate's own probe VIP manager failed: " + result.stderr[-1200:])


def runtime_observe(manager: Path, root: Path, private_bin: Path,
                    profile: str, vip: str, *, trust_file: Path, expect_success: bool):
    """Call the candidate's actual observer; only swanctl metadata is shimmed."""
    shell = r'''set -Eeuo pipefail
DNSCOMPLEX_ROOT="$2"
DNSCOMPLEX_CONFIG="$2/etc/dnscomplex/config.env"
DNSCOMPLEX_FS_ROOT="$2"
PATH="$3:$PATH"
export DNSCOMPLEX_ROOT DNSCOMPLEX_CONFIG DNSCOMPLEX_FS_ROOT PATH
source "$1"
load_config
export DNSCOMPLEX_TEST_SAS DNSCOMPLEX_TEST_SWANCTL_CALLS
sas=$(swanctl --list-sas)
profile_dataplane_probe_observe "$4" "$5" "$sas"
'''
    result = run(["bash", "-c", shell, "candidate-runtime-observer", str(manager),
                  str(root), str(private_bin), profile, vip], timeout=10, check=False,
                 env=dict(os.environ, SSL_CERT_FILE=str(trust_file)))
    if expect_success and result.returncode:
        raise RuntimeError(f"candidate runtime observer failed for {profile}: rc={result.returncode}; "
                           f"stdout={result.stdout[-1000:]!r}; stderr={result.stderr[-1600:]!r}")
    if not expect_success and result.returncode == 0:
        raise AssertionError(f"candidate runtime observer accepted failing DoH response for {profile}")
    return result


def read_profile_gate_open(profile: str) -> bool:
    value = json.loads(run(["nft", "-j", "list", "set", "inet", "dnscomplex",
                            f"{profile}_ready4"]).stdout)
    for entry in value.get("nftables", []):
        gate = entry.get("set", {})
        if gate.get("name") == f"{profile}_ready4":
            return any(isinstance(element, dict) and
                       element.get("prefix", {}).get("addr") == "0.0.0.0" and
                       element.get("prefix", {}).get("len") == 0
                       for element in gate.get("elem", []))
    raise AssertionError(f"candidate-owned readiness set {profile}_ready4 is missing")


def assert_profile_proof(root: Path, profile: str, vip: str, expected_count: int) -> str:
    proof = root / "run/dnscomplex" / f"profile-dataplane-{profile}.success"
    fields = proof.read_text(encoding="ascii").strip().split()
    if (len(fields) != 3 or fields[0] != vip or not re.fullmatch(r"[0-9a-f]{64}", fields[1]) or
            fields[2] != str(expected_count)):
        raise AssertionError(f"runtime proof mismatch for {profile}, expected count {expected_count}: {fields!r}")
    return fields[1]


def install_swanctl_metadata_shim(render_root: Path, root: Path) -> Path:
    """Provide stable test SA metadata while forbidding any mutating swanctl action."""
    private_bin = render_root / "test-bin"
    private_bin.mkdir(mode=0o700)
    metadata = root / "controlled-sas.txt"
    metadata.write_text(
        "ai: #1531, ESTABLISHED, IKEv2, rekeying in 9 mins\n"
        "  local 198.18.2.1[4500] [10.250.1.10]\n"
        "  ai: #1531, reqid 1, INSTALLED, TUNNEL, ESP, SPIs\n"
        "cn: #1532, ESTABLISHED, IKEv2, rekeying in 9 mins\n"
        "  local 198.18.3.1[4500] [10.251.1.10]\n"
        "  cn: #1532, reqid 2, INSTALLED, TUNNEL, ESP, SPIs\n",
        encoding="ascii")
    calls = root / "swanctl-calls.log"
    shim = private_bin / "swanctl"
    shim.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >>\"$DNSCOMPLEX_TEST_SWANCTL_CALLS\"\n"
        "case \"$*\" in\n"
        "  '--list-sas') cat \"$DNSCOMPLEX_TEST_SAS\" ;;\n"
        "  *) exit 97 ;;\n"
        "esac\n",
        encoding="ascii")
    shim.chmod(0o700)
    # Set the paths in the private runtime's profile-specific env file. They
    # are fixture-only variables consumed by this executable metadata shim.
    config = render_root / "etc/dnscomplex/config.env"
    config.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.touch(mode=0o600, exist_ok=True)
    with config.open("a", encoding="ascii") as stream:
        stream.write(f"\nDNSCOMPLEX_TEST_SAS={metadata}\nDNSCOMPLEX_TEST_SWANCTL_CALLS={calls}\n")
    (render_root / "run/dnscomplex").mkdir(mode=0o700, parents=True, exist_ok=True)
    return private_bin


def verify_runtime_observer_lifecycle(manager: Path, render_root: Path,
                                      private_bin: Path, root: Path):
    """Exercise real observer/gate transitions over the controlled veth/TLS peers."""
    for item in (AI, CN):
        profile, vip = item["profile"], item["vip"]
        if read_profile_gate_open(profile):
            raise AssertionError(f"{profile} readiness gate did not start closed")

        before = len(peer_events(root))
        trust_file = root / f"{profile}.crt"
        runtime_observe(manager, render_root, private_bin, profile, vip,
                        trust_file=trust_file, expect_success=True)
        identity_first = assert_profile_proof(render_root, profile, vip, 1)
        if read_profile_gate_open(profile):
            raise AssertionError(f"{profile} gate opened after only one successful observation")

        runtime_observe(manager, render_root, private_bin, profile, vip,
                        trust_file=trust_file, expect_success=True)
        identity_second = assert_profile_proof(render_root, profile, vip, 2)
        if identity_second != identity_first or not read_profile_gate_open(profile):
            raise AssertionError(f"{profile} gate did not open after two same-identity observations")
        runtime_observe(manager, render_root, private_bin, profile, vip,
                        trust_file=trust_file, expect_success=True)
        if assert_profile_proof(render_root, profile, vip, 2) != identity_first or not read_profile_gate_open(profile):
            raise AssertionError(f"{profile} open-gate evidence did not remain capped at two successes")

        (root / f"{profile}.mode").write_text("wrong-id", encoding="ascii")
        runtime_observe(manager, render_root, private_bin, profile, vip,
                        trust_file=trust_file, expect_success=False)
        (root / f"{profile}.mode").unlink()
        if read_profile_gate_open(profile):
            raise AssertionError(f"{profile} gate stayed open after controlled DoH failure")
        proof = render_root / "run/dnscomplex" / f"profile-dataplane-{profile}.success"
        if proof.exists():
            raise AssertionError(f"{profile} success evidence remained after controlled DoH failure")

        runtime_observe(manager, render_root, private_bin, profile, vip,
                        trust_file=trust_file, expect_success=True)
        recovery_first = assert_profile_proof(render_root, profile, vip, 1)
        if recovery_first != identity_first or read_profile_gate_open(profile):
            raise AssertionError(f"{profile} recovery did not restart its same-identity two-success sequence")
        runtime_observe(manager, render_root, private_bin, profile, vip,
                        trust_file=trust_file, expect_success=True)
        recovery_second = assert_profile_proof(render_root, profile, vip, 2)
        if recovery_second != identity_first or not read_profile_gate_open(profile):
            raise AssertionError(f"{profile} gate did not reopen after two recovery observations")

        observed = peer_events(root, at_least=before + 6)
        if not all(event.get("profile") == profile and event.get("source") == vip
                   for event in observed[before:]):
            raise AssertionError(f"{profile} observer lifecycle escaped its selected VIP/TLS peer")
        print("RUNTIME_OBSERVER_GATE_LIFECYCLE", profile,
              "closed->one-success-closed->two-success-open->DoH-failure-closed->two-recovery-open",
              flush=True)

    calls_file = root / "swanctl-calls.log"
    calls = calls_file.read_text(encoding="ascii").splitlines()
    # Six observer invocations per profile make six initial metadata reads;
    # five successful DoH calls each trigger one fresh read. A failing DoH
    # returns before the fresh-SA comparison, for twenty-two reads total.
    if len(calls) != 22 or any(call != "--list-sas" for call in calls):
        raise AssertionError(f"observer must only re-read stable SA metadata; swanctl calls={calls!r}")
    print("SYNTHETIC_SA_METADATA_READ_ONLY", f"list_sas_calls={len(calls)}", flush=True)


def route_manager_sync(manager: Path, root: Path):
    """Run actual candidate policy manager; only the unavailable SA lookup is shimmed."""
    shell = r'''set -Eeuxo pipefail
DNSCOMPLEX_ROOT="$2"
DNSCOMPLEX_CONFIG="$2/etc/dnscomplex/config.env"
DNSCOMPLEX_FS_ROOT="$2"
source "$1"
load_config
ipsec_vip() {
  case "$1" in
    ai) printf '%s\n' 10.250.1.10 ;;
    cn) printf '%s\n' 10.251.1.10 ;;
    *) return 1 ;;
  esac
}
ensure_policy_route_profile ai
ensure_policy_route_profile cn
ipsec_probe_policy_rule_present ai
ipsec_probe_policy_rule_present cn
ipsec_policy_route_matches "$AI_TABLE" ipsec-ai 10.250.1.10
ipsec_policy_route_matches "$CN_TABLE" ipsec-cn 10.251.1.10
ai_probe_route=$(ip -j -4 route get 104.16.248.249 from 10.250.1.10 mark "$IPSEC_DATAPLANE_AI_MARK")
cn_probe_route=$(ip -j -4 route get 223.6.6.6 from 10.251.1.10 mark "$IPSEC_DATAPLANE_CN_MARK")
ai_profile_route=$(ip -j -4 route get 104.16.248.249 from 10.250.1.10 mark "$AI_MARK")
cn_profile_route=$(ip -j -4 route get 223.6.6.6 from 10.251.1.10 mark "$CN_MARK")
route_json_matches() {
  local json=$1 destination=$2 source=$3 device=$4 table=$5 mark_num=$6 mark_hex=$7
  printf '%s\n' "$json" | jq -e \
    --arg destination "$destination" --arg source "$source" --arg device "$device" \
    --arg table "$table" --arg mark_hex "$mark_hex" --argjson mark_num "$mark_num" '
      if length != 1 then false else
        .[0] as $route |
        $route.dst == $destination and
        $route.from == $source and
        $route.dev == $device and
        ($route.table == $table or $route.table == ($table | tonumber)) and
        ($route.mark == $mark_num or $route.mark == ($mark_num | tostring) or $route.mark == $mark_hex)
      end' >/dev/null
}
route_json_matches "$ai_probe_route" 104.16.248.249 10.250.1.10 ipsec-ai 301 929 0x3a1
route_json_matches "$cn_probe_route" 223.6.6.6 10.251.1.10 ipsec-cn 351 1009 0x3f1
route_json_matches "$ai_profile_route" 104.16.248.249 10.250.1.10 ipsec-ai 301 769 0x301
route_json_matches "$cn_profile_route" 223.6.6.6 10.251.1.10 ipsec-cn 351 849 0x351
'''
    result = run(["bash", "-c", shell, "candidate-route-sync", str(manager), str(root)], timeout=8, check=False)
    if result.returncode:
        # All addresses/config here are synthetic fixture data. Keep the shell
        # trace and both streams so a set -e failure identifies the exact
        # manager command instead of looking like an empty-stderr failure.
        raise RuntimeError(
            "candidate's actual profile/probe route manager failed"
            f" (rc={result.returncode})\n"
            f"stdout tail:\n{result.stdout[-3000:]}\n"
            f"xtrace/stderr tail:\n{result.stderr[-6000:]}"
        )


def controlled_peer(root: Path):
    """Namespace child: private TLS DoH peers and a default-route control peer."""
    (root / "peer.pid").write_text(str(os.getpid()))
    until = time.monotonic() + 15
    while not (root / "configured").exists():
        if time.monotonic() >= until:
            raise TimeoutError("parent did not configure the isolated peer links")
        time.sleep(.02)

    def serve_tls(profile):
        item = AI if profile == "ai" else CN
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / f"{profile}.crt", root / f"{profile}.key")
        endpoints = [(item["resolver"], 443), (item["resolver"], 444)]
        if profile == "ai":
            endpoints.append(("104.16.248.250", 443))
        listeners = []
        for address, port in endpoints:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((address, port)); listener.listen(8); listener.settimeout(.15)
            listeners.append((listener, address, port))
        (root / f"{profile}.ready").write_text("ready")
        while not (root / "stop").exists():
            for listener, address, port in listeners:
                try:
                    raw, remote = listener.accept()
                except socket.timeout:
                    continue
                try:
                    with context.wrap_socket(raw, server_side=True) as conn:
                        data = b""
                        while b"\r\n\r\n" not in data and len(data) <= 16384:
                            chunk = conn.recv(4096)
                            if not chunk: break
                            data += chunk
                        header, _, body = data.partition(b"\r\n\r\n")
                        lengths = [int(line.split(b":", 1)[1].strip())
                                   for line in header.split(b"\r\n")
                                   if line.lower().startswith(b"content-length:")]
                        if len(lengths) != 1 or not 12 <= lengths[0] <= 4096:
                            raise ValueError("invalid DoH request length")
                        while len(body) < lengths[0]:
                            chunk = conn.recv(lengths[0] - len(body))
                            if not chunk: break
                            body += chunk
                        if len(body) != lengths[0] or len(body) < 17:
                            raise ValueError("truncated DoH request")
                        question = body[12:]
                        response = body[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question
                        response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("203.0.113.10")
                        mode_path = root / f"{profile}.mode"
                        if mode_path.exists() and mode_path.read_text().strip() == "wrong-id":
                            response = bytes((response[0] ^ 1,)) + response[1:]
                        packet = (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: "
                                  + str(len(response)).encode() + b"\r\nConnection: close\r\n\r\n" + response)
                        conn.sendall(packet)
                        with (root / "peer-events.jsonl").open("a", encoding="utf-8") as out:
                            out.write(json.dumps({"profile": profile, "address": address, "port": port,
                                                  "source": remote[0]}, sort_keys=True) + "\n")
                except (OSError, ssl.SSLError, ValueError):
                    raw.close()
        for listener, *_ in listeners: listener.close()

    def default_control():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("198.18.1.2", 8443)); listener.listen(8); listener.settimeout(.15)
        (root / "default.ready").write_text("ready")
        while not (root / "stop").exists():
            try: conn, remote = listener.accept()
            except socket.timeout: continue
            with conn:
                conn.sendall(b"default-control")
                with (root / "peer-events.jsonl").open("a", encoding="utf-8") as out:
                    out.write(json.dumps({"profile": "default", "source": remote[0]}, sort_keys=True) + "\n")
        listener.close()

    threads = [threading.Thread(target=serve_tls, args=("ai",), daemon=True),
               threading.Thread(target=serve_tls, args=("cn",), daemon=True),
               threading.Thread(target=default_control, daemon=True)]
    for thread in threads: thread.start()
    for thread in threads: thread.join(timeout=80)


def wait_ready(path: Path, child, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists(): return
        if child.poll() is not None:
            raise RuntimeError("controlled peer exited before ready")
        time.sleep(.025)
    raise TimeoutError(f"controlled peer readiness timeout: {path.name}")


def peer_events(root: Path, *, at_least=0, seconds=2):
    path = root / "peer-events.jsonl"
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            records = [json.loads(line) for line in path.read_text().splitlines() if line]
            if len(records) >= at_least:
                return records
        time.sleep(.01)
    return [json.loads(line) for line in path.read_text().splitlines() if line] if path.exists() else []


def set_namespace_topology(peer_pid: str):
    peer_ns = ["nsenter", "-t", peer_pid, "-n"]
    run(["ip", "link", "set", "lo", "up"])
    run(peer_ns + ["ip", "link", "set", "lo", "up"])
    links = [("ipsec-ai", "peer-ai", "198.18.2", "198.18.2.1", "198.18.2.2"),
             ("ipsec-cn", "peer-cn", "198.18.3", "198.18.3.1", "198.18.3.2"),
             ("wan0", "peer-wan", "198.18.1", "198.18.1.1", "198.18.1.2")]
    for dev, peerdev, _net, local, remote in links:
        run(["ip", "link", "add", dev, "type", "veth", "peer", "name", peerdev])
        run(["ip", "link", "set", peerdev, "netns", peer_pid])
        run(["ip", "addr", "add", local + "/30", "dev", dev])
        run(["ip", "link", "set", dev, "up"])
        run(peer_ns + ["ip", "addr", "add", remote + "/30", "dev", peerdev])
        run(peer_ns + ["ip", "link", "set", peerdev, "up"])
    for item, peerdev, remote, local in [(AI, "peer-ai", "198.18.2.2", "198.18.2.1"),
                                         (CN, "peer-cn", "198.18.3.2", "198.18.3.1")]:
        run(["ip", "addr", "add", item["vip"] + "/32", "dev", "lo"])
        run(peer_ns + ["ip", "route", "add", item["vip"] + "/32", "via", local, "dev", peerdev])
    run(["ip", "addr", "add", "10.250.1.11/32", "dev", "lo"])
    run(["ip", "route", "add", "default", "via", "198.18.1.2", "dev", "wan0"])
    for item, peerdev in ((AI, "peer-ai"), (CN, "peer-cn")):
        run(peer_ns + ["ip", "addr", "add", item["resolver"] + "/32", "dev", peerdev])
    run(peer_ns + ["ip", "addr", "add", "104.16.248.250/32", "dev", "peer-ai"])
    run(peer_ns + ["ip", "route", "add", "10.250.1.0/24", "via", "198.18.2.1", "dev", "peer-ai"])


def invoke_probe(module: Path, item, *, trust_file: Path, overrides=(), timeout=2):
    command = [sys.executable, str(module), "--profile", item["profile"], "--mode", "ipsec",
               "--vip", item["vip"], "--device", "ipsec-" + item["profile"],
               "--probe-mark", str(item["mark"]), "--resolver-ip", item["resolver"],
               "--tls-name", item["tls"], "--query-domain", item["query"], "--timeout", str(timeout)]
    for mark in (769, 849, 8228, 0x601): command += ["--reserved-mark", str(mark)]
    command += list(overrides)
    env = dict(os.environ, SSL_CERT_FILE=str(trust_file))
    result = subprocess.run(command, capture_output=True, text=True, timeout=8, env=env)
    try: diagnostic = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"probe CLI did not emit JSON: rc={result.returncode} stderr={result.stderr[-1000:]}") from exc
    return result, diagnostic


def raw_connect(address, port, *, source, device, mark, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), mark)
        sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_BINDTODEVICE", 25), device.encode() + b"\0")
        sock.bind((source, 0)); sock.settimeout(timeout); sock.connect((address, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def start_default_egress_capture():
    """Count only resolver-destined TCP/443 packets leaving the WAN veth."""
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    capture.bind(("wan0", 0)); capture.settimeout(.1)
    stopped = threading.Event()
    counts = {AI["resolver"]: 0, CN["resolver"]: 0}

    def observe():
        while not stopped.is_set():
            try: frame = capture.recv(4096)
            except socket.timeout: continue
            except OSError:
                if stopped.is_set(): return
                raise
            if len(frame) < 34 or struct.unpack_from("!H", frame, 12)[0] != 0x0800:
                continue
            ip_offset = 14
            if frame[ip_offset] >> 4 != 4: continue
            ip_header = (frame[ip_offset] & 0x0f) * 4
            if ip_header < 20 or frame[ip_offset + 9] != socket.IPPROTO_TCP:
                continue
            destination = socket.inet_ntoa(frame[ip_offset + 16:ip_offset + 20])
            tcp_offset = ip_offset + ip_header
            if destination not in counts or len(frame) < tcp_offset + 4:
                continue
            if struct.unpack_from("!H", frame, tcp_offset + 2)[0] == 443:
                counts[destination] += 1

    thread = threading.Thread(target=observe, daemon=True)
    thread.start()
    return capture, stopped, thread, counts


def stop_default_egress_capture(capture, stopped, thread):
    stopped.set(); capture.close(); thread.join(timeout=1)


def inner(installer: Path, host_main_pid: str | None, host_config_sha: str | None,
          host_guard_path: Path, host_guard_sha: str,
          installed_cli_path: Path, installed_cli_sha: str):
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("isolated child shares the host network namespace")
    assert_host_unchanged(host_main_pid, host_config_sha)
    if host_installer_sha(host_guard_path) != host_guard_sha:
        raise AssertionError("host installer guard changed before isolated wire run")
    if host_installer_sha(installed_cli_path) != installed_cli_sha:
        raise AssertionError("installed dnscomplex CLI changed before isolated wire run")
    with tempfile.TemporaryDirectory(prefix="dnscomplex-profile-gate-wire-") as temp:
        root = Path(temp); root.chmod(0o700)
        for profile, hostname in (("ai", AI["tls"]), ("cn", CN["tls"])):
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", "/CN=" + hostname, "-addext", "subjectAltName=DNS:" + hostname,
                 "-keyout", str(root / f"{profile}.key"), "-out", str(root / f"{profile}.crt")], timeout=10)
        peer = subprocess.Popen(["unshare", "--net", "--fork", sys.executable,
                                 str(Path(__file__).resolve()), "--peer", str(root)],
                                start_new_session=True)
        try:
            wait_ready(root / "peer.pid", peer)
            peer_pid = (root / "peer.pid").read_text().strip()
            set_namespace_topology(peer_pid)
            nft_path, installed_module, manager = render_candidate(installer, root)
            print("PRIVATE_INSTALLED_PROBE", "sha256=" + sha256(installed_module),
                  "mode=" + oct(installed_module.stat().st_mode & 0o777), flush=True)
            route_manager_sync(manager, root / "render-root")
            print("PRODUCTION_ROUTE_MANAGER", "reserved-mark-to-profile-table verified", flush=True)
            run(["nft", "-f", str(nft_path)], timeout=10)
            # Let the production manager close each profile's ready set and add
            # its one verified VIP element through the real atomic set helper.
            manager_sync(manager, root / "render-root", "ai", AI["vip"])
            manager_sync(manager, root / "render-root", "cn", CN["vip"])
            # The ruleset is the rendered production table; ensure the helper
            # VIP memberships are exactly the selected identities.
            for name, vip in (("ai_probe_vip4", AI["vip"]), ("cn_probe_vip4", CN["vip"])):
                value = json.loads(run(["nft", "-j", "list", "set", "inet", "dnscomplex", name]).stdout)
                sets = [entry["set"] for entry in value["nftables"]
                        if isinstance(entry.get("set"), dict) and entry["set"].get("name") == name]
                if len(sets) != 1:
                    raise AssertionError(f"expected one candidate-owned set {name}")
                elements = sets[0].get("elem", [])
                normalized = []
                for element in elements:
                    if isinstance(element, str): normalized.append(element)
                    elif isinstance(element, dict) and isinstance(element.get("prefix"), dict):
                        normalized.append(element["prefix"].get("addr", "<invalid>"))
                    elif isinstance(element, dict) and isinstance(element.get("elem"), dict):
                        normalized.append(element["elem"].get("val", "<invalid>"))
                    else: normalized.append("<invalid>")
                if normalized != [vip]:
                    raise AssertionError(f"candidate manager set membership mismatch for {name}: {normalized!r}")
            for name in ("ai_ready4", "cn_ready4"):
                value = json.loads(run(["nft", "-j", "list", "set", "inet", "dnscomplex", name]).stdout)
                sets = [entry["set"] for entry in value["nftables"]
                        if isinstance(entry.get("set"), dict) and entry["set"].get("name") == name]
                if len(sets) != 1 or sets[0].get("elem", []):
                    raise AssertionError(f"fixture did not begin with the real {name} readiness gate closed")
            private_bin = install_swanctl_metadata_shim(root / "render-root", root)
            (root / "configured").write_text("ready")
            wait_ready(root / "ai.ready", peer); wait_ready(root / "cn.ready", peer); wait_ready(root / "default.ready", peer)
            wan_capture, capture_stop, capture_thread, wan_probe_counts = start_default_egress_capture()
            for item in (AI, CN):
                result, diagnostic = invoke_probe(installed_module, item, trust_file=root / f"{item['profile']}.crt")
                if result.returncode or diagnostic.get("status") != "pass":
                    raise AssertionError(f"candidate DoH helper did not pass actual rendered exception for {item['profile']}: {diagnostic}")
                print("PRODUCTION_RENDERED_CLOSED_GATE_DOH", item["profile"], json.dumps(diagnostic, sort_keys=True), flush=True)
            xray = subprocess.run([sys.executable, str(installed_module), "--profile", "ai", "--mode", "xray",
                                   "--vip", AI["vip"], "--device", "ipsec-ai", "--probe-mark", str(AI["mark"]),
                                   "--resolver-ip", AI["resolver"], "--tls-name", AI["tls"],
                                   "--query-domain", AI["query"], "--timeout", "1"],
                                  capture_output=True, text=True, timeout=4,
                                  env=dict(os.environ, SSL_CERT_FILE=str(root / "ai.crt")))
            xray_result = json.loads(xray.stdout)
            if xray.returncode == 0 or xray_result.get("status") != "unsupported":
                raise AssertionError(f"Xray mode was not explicitly unsupported: {xray_result}")
            print("XRAY_UNSUPPORTED_NO_FALLBACK", json.dumps(xray_result, sort_keys=True), flush=True)
            wrong_device = subprocess.run([sys.executable, str(installed_module), "--profile", "ai", "--mode", "ipsec",
                                           "--vip", AI["vip"], "--device", "wan0", "--probe-mark", str(AI["mark"]),
                                           "--resolver-ip", AI["resolver"], "--tls-name", AI["tls"],
                                           "--query-domain", AI["query"], "--timeout", "1"],
                                          capture_output=True, text=True, timeout=4,
                                          env=dict(os.environ, SSL_CERT_FILE=str(root / "ai.crt")))
            wrong_device_result = json.loads(wrong_device.stdout)
            if wrong_device.returncode == 0 or wrong_device_result.get("status") != "unsupported":
                raise AssertionError(f"wrong device was not explicitly unsupported: {wrong_device_result}")
            print("WRONG_DEVICE_UNSUPPORTED_NO_FALLBACK", json.dumps(wrong_device_result, sort_keys=True), flush=True)
            # Exact tuple is required: wrong source/mark/destination/port must
            # fail under the rendered closed profile gate, with no WAN peer.
            negatives = [
                ("wrong-source", AI["resolver"], 443, "10.250.1.11", "ipsec-ai", AI["mark"]),
                ("wrong-mark", AI["resolver"], 443, AI["vip"], "ipsec-ai", 930),
                ("wrong-destination", "104.16.248.250", 443, AI["vip"], "ipsec-ai", AI["mark"]),
                ("wrong-port", AI["resolver"], 444, AI["vip"], "ipsec-ai", AI["mark"]),
            ]
            for label, address, port, source, device, mark in negatives:
                if raw_connect(address, port, source=source, device=device, mark=mark):
                    raise AssertionError(f"closed production profile gate accepted {label}")
                print("CLOSED_GATE_NEGATIVE", label, flush=True)
            before_failure = len(peer_events(root))
            (root / "ai.mode").write_text("wrong-id")
            failed, failure = invoke_probe(installed_module, AI, trust_file=root / "ai.crt", timeout=1)
            if failed.returncode == 0 or failure.get("status") != "fail" or failure.get("phase") != "dns":
                raise AssertionError(f"bad controlled DNS answer did not remain a failure: {failure}")
            (root / "ai.mode").unlink()
            after_failure = peer_events(root, at_least=before_failure + 1)
            if len(after_failure) <= before_failure or not any(e.get("profile") == "ai" and e.get("source") == AI["vip"]
                                                               for e in after_failure[before_failure:]):
                raise AssertionError("controlled failing DoH probe did not stay on the exact AI path")
            verify_runtime_observer_lifecycle(manager, root / "render-root", private_bin, root)
            default = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            default.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), DEFAULT_MARK)
            default.settimeout(2); default.connect(("198.18.1.2", 8443))
            if default.recv(64) != b"default-control": raise AssertionError("default positive control response mismatch")
            default.close()
            events = peer_events(root, at_least=before_failure + 2)
            for item in (AI, CN):
                if not any(event.get("profile") == item["profile"] and event.get("source") == item["vip"]
                           for event in events):
                    raise AssertionError(f"controlled peer did not observe expected VIP source for {item['profile']}")
            if any(event.get("profile") == "default" and event.get("source") in (AI["vip"], CN["vip"])
                   for event in events):
                raise AssertionError("profile probe traffic leaked to the default peer")
            counters = json.loads(run(["nft", "-j", "list", "table", "inet", "dnscomplex"]).stdout)["nftables"]
            counts = {}
            for record in counters:
                rule = record.get("rule")
                if not isinstance(rule, dict): continue
                comment = rule.get("comment")
                if comment:
                    counts[comment] = sum(entry.get("counter", {}).get("packets", 0)
                                          for entry in rule.get("expr", []) if isinstance(entry, dict))
            for comment in ("dnscomplex-ai-dataplane-probe", "dnscomplex-cn-dataplane-probe"):
                if counts.get(comment, 0) < 1:
                    raise AssertionError(f"production exception counter did not increment: {comment}: {counts}")
            if counts.get("dnscomplex-ai-classified-not-ready", 0) < len(negatives):
                raise AssertionError("wrong source/mark/destination/port did not hit the closed AI gate counter: " + json.dumps(counts))
            if counts.get("dnscomplex-domain-default-output", 0) < 1:
                raise AssertionError("default positive control did not hit the rendered default accept counter")
            print("PRODUCTION_NFT_EXCEPTION_COUNTERS", json.dumps(counts, sort_keys=True), flush=True)
            stop_default_egress_capture(wan_capture, capture_stop, capture_thread)
            wan_capture = None
            if any(wan_probe_counts.values()):
                raise AssertionError("AI/CN probe packets leaked onto default WAN egress: " + json.dumps(wan_probe_counts))
            print("DEFAULT_EGRESS_PROBE_CAPTURE", json.dumps(wan_probe_counts, sort_keys=True), flush=True)
            print("PASS: actual renderer + profile route manager + installed helper + runtime observer gates; "
                  "controlled TLS peers and synthetic SA metadata; veth models IPsec, not XFRM/SA", flush=True)
        finally:
            if "wan_capture" in locals() and wan_capture is not None:
                stop_default_egress_capture(wan_capture, capture_stop, capture_thread)
            (root / "stop").write_text("stop")
            try:
                peer.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # unshare --fork leaves a namespace child alongside the
                # unshare parent. Signal the private process group so both
                # are terminated; escalate without an unbounded wait.
                try:
                    os.killpg(peer.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    peer.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(peer.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        peer.wait(timeout=2)
                    except subprocess.TimeoutExpired as exc:
                        raise RuntimeError("private peer process group survived SIGKILL") from exc
    assert_host_unchanged(host_main_pid, host_config_sha)
    if host_installer_sha(host_guard_path) != host_guard_sha:
        raise AssertionError("isolated wire run changed host installer guard")
    if host_installer_sha(installed_cli_path) != installed_cli_sha:
        raise AssertionError("isolated wire run changed installed dnscomplex CLI")


def assert_host_unchanged(pid, config_sha):
    if pid is None:
        return
    current = run(["systemctl", "show", "--property=MainPID", "--value", "sing-box"], timeout=5).stdout.strip()
    current_sha = sha256(Path("/etc/sing-box/config.json"))
    if current != pid or current_sha != config_sha:
        raise AssertionError("isolated test changed host sing-box MainPID or config bytes")


def host_installer_sha(path: Path) -> str:
    if not path.is_file():
        raise RuntimeError(f"host installer guard file is unavailable: {path}")
    return sha256(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-installer", type=Path)
    parser.add_argument("--expected-installer-sha256")
    parser.add_argument("--module", type=Path,
                        help="the candidate installer-pinned external profile dataplane probe helper")
    parser.add_argument("--expected-module-sha256")
    parser.add_argument("--inner", action="store_true")
    parser.add_argument("--peer", type=Path)
    parser.add_argument("--host-main-pid")
    parser.add_argument("--host-config-sha256")
    parser.add_argument("--host-installer-guard", type=Path, default=Path("/root/install.sh"))
    parser.add_argument("--host-installer-guard-sha256")
    parser.add_argument("--host-installed-cli", type=Path, default=Path("/usr/local/sbin/dnscomplex"))
    parser.add_argument("--host-installed-cli-sha256")
    args = parser.parse_args()
    if args.peer:
        controlled_peer(args.peer)
        return 0
    if not args.candidate_installer or not args.expected_installer_sha256 or not args.module:
        parser.error("--candidate-installer, --expected-installer-sha256 and --module are required")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.expected_installer_sha256):
        parser.error("--expected-installer-sha256 must be a full SHA256")
    actual_installer = sha256(args.candidate_installer)
    if actual_installer.lower() != args.expected_installer_sha256.lower():
        raise SystemExit(f"candidate installer SHA mismatch: expected {args.expected_installer_sha256}, got {actual_installer}")
    pinned_module = extract_probe_sha(args.candidate_installer)
    actual_module = sha256(args.module)
    expected_module = args.expected_module_sha256 or pinned_module
    if actual_module != pinned_module or actual_module.lower() != expected_module.lower():
        raise SystemExit("candidate helper SHA mismatch against installer pin/expected module SHA")
    print("FROZEN_INSTALLER_SHA256", actual_installer, flush=True)
    print("FROZEN_PROFILE_PROBE_SHA256", actual_module, flush=True)
    if args.peer:
        controlled_peer(args.peer); return 0
    if not args.inner:
        system = platform.system()
        if system != "Linux":
            raise SystemExit("Linux namespace wire test required; static renderer check is not counted as PASS")
        for executable in ("timeout", "unshare", "nsenter", "ip", "nft", "openssl", "bash", "jq"):
            if not shutil.which(executable): raise SystemExit(f"required isolated test tool missing: {executable}")
        host_pid = run(["systemctl", "show", "--property=MainPID", "--value", "sing-box"], timeout=5).stdout.strip()
        if not host_pid.isdigit() or int(host_pid) <= 0:
            raise SystemExit("active host sing-box MainPID required for guard")
        config_path = Path("/etc/sing-box/config.json")
        host_config_sha = sha256(config_path)
        host_installer_sha_before = host_installer_sha(args.host_installer_guard)
        host_cli_sha_before = host_installer_sha(args.host_installed_cli)
        command = ["unshare", "--net", "--mount", "--propagation", "private", "--fork",
                   sys.executable, str(Path(__file__).resolve()),
                   "--candidate-installer", str(args.candidate_installer.resolve()),
                   "--expected-installer-sha256", actual_installer,
                   "--module", str(args.module.resolve()), "--expected-module-sha256", actual_module,
                   "--inner", "--host-main-pid", host_pid, "--host-config-sha256", host_config_sha,
                   "--host-installer-guard", str(args.host_installer_guard.resolve()),
                   "--host-installer-guard-sha256", host_installer_sha_before,
                   "--host-installed-cli", str(args.host_installed_cli.resolve()),
                   "--host-installed-cli-sha256", host_cli_sha_before]
        process = subprocess.Popen(command, start_new_session=True)

        def interrupt(_signum, _frame):
            raise SystemExit("termination requested; stopping private namespace process group")

        previous_term = signal.signal(signal.SIGTERM, interrupt)
        try:
            returncode = process.wait(timeout=MAX_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL); process.wait()
            raise SystemExit(f"{MAX_SECONDS}s bound exceeded; private namespace process group terminated")
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
            raise
        finally:
            signal.signal(signal.SIGTERM, previous_term)
            assert_host_unchanged(host_pid, host_config_sha)
            if host_installer_sha(args.host_installer_guard) != host_installer_sha_before:
                raise AssertionError("isolated test changed the host installer guard file")
            if host_installer_sha(args.host_installed_cli) != host_cli_sha_before:
                raise AssertionError("isolated test changed the installed dnscomplex CLI")
            if sha256(args.candidate_installer) != actual_installer or sha256(args.module) != actual_module:
                raise AssertionError("frozen candidate installer or helper changed during isolated test")
        return returncode
    if not args.host_installer_guard_sha256:
        parser.error("--host-installer-guard-sha256 is required for --inner")
    if not args.host_installed_cli_sha256:
        parser.error("--host-installed-cli-sha256 is required for --inner")
    inner(args.candidate_installer.resolve(), args.host_main_pid, args.host_config_sha256,
          args.host_installer_guard.resolve(),
          args.host_installer_guard_sha256, args.host_installed_cli.resolve(),
          args.host_installed_cli_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
