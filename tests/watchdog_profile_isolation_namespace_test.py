#!/usr/bin/env python3
"""Extend the existing private gate fixture with actual watchdog fault isolation.

Run explicitly under unshare --net --mount; the fixture rejects host netns.
TLS peers, SA metadata, service status, NAT and application binds are synthetic;
the rendered manager, sockets, routes, nft gates and deadlines are real.
"""
import importlib.util
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gate", ROOT / "tests/profile_dataplane_gate_namespace_test.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
original = gate.verify_runtime_observer_lifecycle


def run_cn_identity_transition(manager, render_root, private_bin, root, *, initial_sas,
                               snapshots, seed_proof):
    metadata = root / "controlled-sas.txt"
    metadata.write_text(initial_sas, encoding="ascii")
    snapshot_paths = []
    for index, content in enumerate(snapshots, 1):
        path = root / f"cn-rekey-snapshot-{index}.txt"
        path.write_text(content, encoding="ascii")
        snapshot_paths.append(path)
    helper = render_root / "usr/local/lib/dnscomplex/profile-dataplane-probe.py"
    shell = r'''set -Eeuo pipefail
export DNSCOMPLEX_ROOT="$2" DNSCOMPLEX_CONFIG="$2/etc/dnscomplex/config.env" DNSCOMPLEX_FS_ROOT="$2"
export PATH="$3:$PATH"
source "$1"
load_config
export DNSCOMPLEX_TEST_SAS DNSCOMPLEX_TEST_SWANCTL_CALLS
rm -f -- "$REKEY_COUNTER"
eval "$(declare -f watchdog_capture | sed '1s/^watchdog_capture/watchdog_capture_original/')"
watchdog_capture() {
  local maximum=$1 rc count name next_snapshot
  shift
  if [[ "${1:-}" == "$REKEY_PROBE_PATH" ]]; then
    watchdog_capture_original "$maximum" "$@"; rc=$?
    if [[ "$rc" == 0 ]]; then
      count=0
      [[ -r "$REKEY_COUNTER" ]] && count=$(cat "$REKEY_COUNTER")
      count=$((count + 1))
      printf '%s\n' "$count" >"$REKEY_COUNTER"
      name="REKEY_SNAPSHOT_${count}"
      next_snapshot=${!name-}
      if [[ -n "$next_snapshot" ]]; then
        cp -- "$next_snapshot" "$DNSCOMPLEX_TEST_SAS"
      fi
    fi
    return "$rc"
  fi
  watchdog_capture_original "$maximum" "$@"
}
if [[ "$REKEY_SEED_PROOF" == 1 ]]; then
  seed_sas=$(swanctl --list-sas)
  seed_identity=$(ipsec_profile_dataplane_identity cn 10.251.1.10 "$seed_sas")
  printf '10.251.1.10 %s 2\n' "$seed_identity" >"$(profile_dataplane_success_path cn)"
  chmod 0600 "$(profile_dataplane_success_path cn)"
fi
sas=$(swanctl --list-sas)
if profile_dataplane_probe_observe cn 10.251.1.10 "$sas"; then rc=0; else rc=$?; fi
final_sas=$(swanctl --list-sas)
final_identity=$(ipsec_profile_dataplane_identity cn 10.251.1.10 "$final_sas")
printf 'CN_REKEY_RESULT rc=%s identity=%s\n' "$rc" "$final_identity"
'''
    env = dict(os.environ, SSL_CERT_FILE=str(root / "cn.crt"),
               REKEY_PROBE_PATH=str(helper), REKEY_COUNTER=str(root / "cn-rekey-count"),
               REKEY_SEED_PROOF="1" if seed_proof else "0")
    for index, path in enumerate(snapshot_paths, 1):
        env[f"REKEY_SNAPSHOT_{index}"] = str(path)
    result = gate.run(["bash", "-c", shell, "cn-identity-transition", str(manager),
                       str(render_root), str(private_bin)], check=False, timeout=18, env=env)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"CN identity transition shell failed unexpectedly: rc={result.returncode}; "
                           f"stdout={result.stdout[-1200:]!r}; stderr={result.stderr[-1800:]!r}")
    return result


def verify_cn_rekey_retry(manager, render_root, private_bin, root):
    vip = gate.CN["vip"]
    cn_metadata = (root / "controlled-sas.txt").read_text(encoding="ascii")
    versions = [cn_metadata]
    for index in range(1, 4):
        previous_id = 1531 + index
        versions.append(versions[-1].replace(f"cn: #{previous_id}", f"cn: #{previous_id + 1}"))
    if versions[1] == versions[0] or versions[2] == versions[1] or versions[3] == versions[2]:
        raise AssertionError("could not construct distinct synthetic CN SA identity snapshots")
    old_identity = gate.assert_profile_proof(render_root, "cn", vip, 2)
    ai_proof = gate.assert_profile_proof(render_root, "ai", gate.AI["vip"], 2)
    if not gate.read_profile_gate_open("ai") or not gate.read_profile_gate_open("cn"):
        raise AssertionError("rekey fixture requires both profile gates initially open")

    before = len(gate.peer_events(root))
    first = run_cn_identity_transition(manager, render_root, private_bin, root,
                                       initial_sas=versions[0], snapshots=[versions[1]],
                                       seed_proof=True)
    if "CN_REKEY_RESULT rc=0" not in first.stdout:
        raise AssertionError(f"same-VIP rekey retry did not succeed: {first.stdout[-1200:]}; {first.stderr[-1800:]}")
    new_identity = gate.assert_profile_proof(render_root, "cn", vip, 1)
    if new_identity == old_identity:
        raise AssertionError("synthetic CN rekey did not change the proof identity")
    if gate.read_profile_gate_open("cn"):
        raise AssertionError("successful rekey retry must leave CN readiness closed at count one")
    if gate.assert_profile_proof(render_root, "ai", gate.AI["vip"], 2) != ai_proof or not gate.read_profile_gate_open("ai"):
        raise AssertionError("CN rekey retry changed AI proof or readiness")
    observed = gate.peer_events(root, at_least=before + 2)
    cn_events = [event for event in observed[before:]
                 if event.get("profile") == "cn" and event.get("source") == vip]
    if len(cn_events) != 2:
        raise AssertionError(f"expected exactly one original and one retry DoH probe: {cn_events!r}")
    print("NATIVE_CN_REKEY_RETRY", "old-proof-discarded", "retry-once", "new-count=1",
          "cn-closed", "ai-open", flush=True)

    before = len(gate.peer_events(root))
    second = run_cn_identity_transition(manager, render_root, private_bin, root,
                                        initial_sas=versions[1], snapshots=[], seed_proof=False)
    if "CN_REKEY_RESULT rc=0" not in second.stdout:
        raise AssertionError(f"stable follow-up probe did not succeed: {second.stdout[-1200:]}; {second.stderr[-1800:]}")
    if gate.assert_profile_proof(render_root, "cn", vip, 2) != new_identity or not gate.read_profile_gate_open("cn"):
        raise AssertionError("next stable observation did not open CN at count two for the new identity")
    if gate.assert_profile_proof(render_root, "ai", gate.AI["vip"], 2) != ai_proof or not gate.read_profile_gate_open("ai"):
        raise AssertionError("stable CN follow-up changed AI proof or readiness")
    observed = gate.peer_events(root, at_least=before + 1)
    cn_events = [event for event in observed[before:]
                 if event.get("profile") == "cn" and event.get("source") == vip]
    if len(cn_events) != 1:
        raise AssertionError(f"stable follow-up should issue exactly one CN probe: {cn_events!r}")
    print("NATIVE_CN_REKEY_NEXT_CYCLE", "stable-new-identity", "count=2", "cn-open", "ai-open", flush=True)

    before = len(gate.peer_events(root))
    third = run_cn_identity_transition(manager, render_root, private_bin, root,
                                       initial_sas=versions[1], snapshots=[versions[2], versions[3]],
                                       seed_proof=True)
    if "CN_REKEY_RESULT rc=1" not in third.stdout:
        raise AssertionError(f"second identity change did not return observer-fatal rc=1: {third.stdout[-1200:]}; {third.stderr[-1800:]}")
    if gate.read_profile_gate_open("cn") or (render_root / "run/dnscomplex/profile-dataplane-cn.success").exists():
        raise AssertionError("second CN identity change did not retain closed gate and discard proof")
    if gate.assert_profile_proof(render_root, "ai", gate.AI["vip"], 2) != ai_proof or not gate.read_profile_gate_open("ai"):
        raise AssertionError("second CN identity change disturbed healthy AI readiness")
    observed = gate.peer_events(root, at_least=before + 2)
    cn_events = [event for event in observed[before:]
                 if event.get("profile") == "cn" and event.get("source") == vip]
    if len(cn_events) != 2:
        raise AssertionError(f"second identity change should stop after the single retry: {cn_events!r}")
    print("NATIVE_CN_REKEY_SECOND_CHANGE", "observer-fatal-rc1", "cn-closed", "ai-open-at-observer-boundary", flush=True)


def verify(manager, render_root, private_bin, root):
    original(manager, render_root, private_bin, root)
    verify_cn_rekey_retry(manager, render_root, private_bin, root)
    peer_pid = (root / "peer.pid").read_text().strip()
    peer_command = ["nsenter", "-t", peer_pid, "-n", "nft"]
    gate.run(peer_command + ["-f", "-"], input_text='''add table inet cn_failure
add chain inet cn_failure input { type filter hook input priority -300; policy accept; }
add rule inet cn_failure input ip daddr 223.6.6.6 tcp dport 443 drop
''')
    shell = r'''set -Eeuo pipefail
export DNSCOMPLEX_ROOT="$2" DNSCOMPLEX_CONFIG="$2/etc/dnscomplex/config.env" DNSCOMPLEX_FS_ROOT="$2"
export PATH="$3:$PATH"
source "$1"
load_config
export DNSCOMPLEX_TEST_SAS DNSCOMPLEX_TEST_SWANCTL_CALLS
restart_watchdog_unit_if_inactive() { :; }
repair_ipsec_children_if_needed() { :; }
ipsec_nat_profile_matches() { :; }
ipsec_bind_profile_matches() { :; }
lan_alias_nat_state_status() { return 1; }
lan_alias_reconcile_cmd() { [[ "$TEST_FAULT" == normal ]]; }
smartdns_listener_round() { return 0; }
watchdog_locked_cmd
'''
    try:
        for fault in ("normal", "later-failure"):
            result = gate.run(["bash", "-c", shell, "native-isolation", str(manager),
                               str(render_root), str(private_bin)], check=False, timeout=18,
                              env=dict(os.environ, TEST_FAULT=fault,
                                       SSL_CERT_FILE=str(root / "ai.crt")))
            if result.returncode != 1:
                raise AssertionError(f"watchdog did not report outage: rc={result.returncode}; {result.stderr[-1500:]}")
            ai_open = gate.read_profile_gate_open("ai")
            cn_open = gate.read_profile_gate_open("cn")
            if ai_open != (fault == "normal") or cn_open:
                raise AssertionError(f"wrong isolation gates: fault={fault}, ai={ai_open}, cn={cn_open}; {result.stderr[-1500:]}")
            proofs = render_root / "run/dnscomplex"
            if (proofs / "profile-dataplane-cn.success").exists():
                raise AssertionError("CN failed probe retained its proof")
            if fault == "normal":
                gate.assert_profile_proof(render_root, "ai", gate.AI["vip"], 2)
            elif (proofs / "profile-dataplane-ai.success").exists():
                raise AssertionError("global failure retained AI proof")
            print("NATIVE_WATCHDOG_ISOLATION", fault, f"ai_open={ai_open}", f"cn_open={cn_open}", flush=True)
    finally:
        gate.run(peer_command + ["delete", "table", "inet", "cn_failure"])


if __name__ == "__main__":
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise SystemExit("requires private network namespace")
    gate.verify_runtime_observer_lifecycle = verify
    pid = subprocess.check_output(["systemctl", "show", "sing-box", "-p", "MainPID", "--value"], text=True).strip()
    config = gate.sha256(Path("/etc/sing-box/config.json"))
    guard = Path("/root/install.sh")
    cli = Path("/usr/local/sbin/dnscomplex")
    gate.inner(ROOT / "install.sh", pid, config, guard, gate.sha256(guard), cli, gate.sha256(cli))
