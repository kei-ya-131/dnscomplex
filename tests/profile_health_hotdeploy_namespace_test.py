#!/usr/bin/env python3
"""Private Linux integration for the profile-health NFT publisher.

The fixture publishes frozen 856 health assets over a rendered 75e nft
baseline. nft, routes, probe sockets, TLS peers, conntrack and Sing-box run in
an isolated network namespace/private root. The adapter's only fake backend is
systemd metadata: its MainPID is the real private Sing-box child, while health
timer state lives in this fixture and no host systemctl mutation is possible.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"
BASELINE_INSTALLER = ROOT / "output/domain-repair/install-75e99856-checkpoint.sh"
PUBLISHER_PATH = ROOT / "tools/profile_health_hotdeploy.py"
HOST_ADAPTER_PATH = ROOT / "tools/profile_health_host_adapter.py"
NFT_DELTA_PATH = ROOT / "tools/profile_health_nft_delta.py"
GATE_FIXTURE_PATH = ROOT / "tests/profile_dataplane_gate_namespace_test.py"
NFT_RENDER_FIXTURE_PATH = ROOT / "tests/profile_health_nft_delta_namespace_test.py"

INSTALLER_SHA = "856be53885775e98076a0a6e2611e2de27028970d7cde3bb3b714def77a5896f"
BASELINE_INSTALLER_SHA = "75e99856d22eda2290184101e741a0594b96ad5b65b47ef6f9c81300a8f73d34"
PROBE_SHA = "d74f866c368ddc31dd0e71bb39cb92afb566d5b24e7941687482bcbc100f4ba1"
PUBLISHER_SHA = "5a544d5e3ec3d59080db97702a4746fff64880db1419ecb5fc791b279067b593"
HOST_ADAPTER_SHA = "5e2ed5348e372d2a42709c5ce16212d377ab7d74b9f167d4382f0b7ea71f9752"
NFT_DELTA_SHA = "444c76e45ef05a0a63391fd33b7895df6e3ec95cb03c5477fc2f77bbba14aa3a"
GATE_FIXTURE_SHA = "30915efefc5c8d6eb15af5589edcc2d40f9d91d39a6788f128b7b14cf5088ed8"
NFT_RENDER_FIXTURE_SHA = "1e2373f7e80ba53efc7b8a029d51796af6c6cd20bfc24389894c7751722b98d8"

TARGETS = (
    "/root/install.sh",
    "/usr/local/sbin/dnscomplex",
    "/usr/local/libexec/dnscomplex-lan-alias",
    "/usr/local/lib/dnscomplex/profile-dataplane-probe.py",
    "/etc/nftables.d/dnscomplex.nft",
)
MODES = {"ai": "ipsec", "cn": "ipsec"}
VIPS = {"ai": "10.250.1.10", "cn": "10.251.1.10"}


def sha256(value: bytes | Path) -> str:
    data = value.read_bytes() if isinstance(value, Path) else value
    return hashlib.sha256(data).hexdigest()


def load_pinned(name: str, path: Path, expected: str):
    if path.is_symlink() or not path.is_file():
        raise AssertionError(f"pinned dependency {name} is not a regular file")
    actual = sha256(path)
    if actual != expected:
        raise AssertionError(f"pinned dependency {name} SHA mismatch: {actual}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load pinned dependency {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_product_modules():
    delta = load_pinned("health_delta_wire", NFT_DELTA_PATH, NFT_DELTA_SHA)
    publisher = load_pinned("health_hotdeploy_wire", PUBLISHER_PATH, PUBLISHER_SHA)
    adapter = load_pinned("health_host_adapter_wire", HOST_ADAPTER_PATH, HOST_ADAPTER_SHA)
    gate = load_pinned("health_gate_wire_dependency", GATE_FIXTURE_PATH, GATE_FIXTURE_SHA)
    nft_fixture = load_pinned("health_nft_renderer_wire_dependency", NFT_RENDER_FIXTURE_PATH,
                              NFT_RENDER_FIXTURE_SHA)
    return delta, publisher, adapter, gate, nft_fixture


def run(argv, *, input_text=None, timeout=12, env=None, check=True):
    result = subprocess.run(list(argv), input=input_text, capture_output=True, text=True,
                            timeout=timeout, env=dict(env) if env else None)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv!r}\n{result.stderr[-3000:]}")
    return result


def _bundle(root: Path, *, initial_nft_json: dict, baseline_nft: str,
            candidate_nft: str, candidate_manager: bytes, candidate_lan: bytes,
            candidate_probe: bytes, bundle_module):
    installer = INSTALLER.read_bytes()
    baseline_installer = BASELINE_INSTALLER.read_bytes()
    baseline_manager = bundle_module._extract_heredoc(
        baseline_installer, bundle_module.MANAGER_START, "MANAGER", "baseline manager")
    baseline_lan = bundle_module._extract_heredoc(
        baseline_installer, bundle_module.LAN_HELPER_START, "LAN_ALIAS", "baseline LAN helper")
    if sha256(installer) != INSTALLER_SHA or sha256(candidate_probe) != PROBE_SHA:
        raise AssertionError("candidate assets do not match their immutable source pins")
    if sha256(baseline_installer) != BASELINE_INSTALLER_SHA:
        raise AssertionError("baseline installer changed after pin verification")

    contents = (installer, candidate_manager, candidate_lan, candidate_probe,
                b"")
    old_contents = (baseline_installer, baseline_manager, baseline_lan, None,
                    baseline_nft.encode("utf-8"))
    modes = (0o755, 0o755, 0o755, 0o755, 0o644)
    files = []
    for target, new, old, mode in zip(TARGETS, contents, old_contents, modes):
        target_path = root / target.lstrip("/")
        if old is None:
            target_path.unlink(missing_ok=True)
            preimage_sha = preimage_mode = preimage_uid = preimage_gid = None
        else:
            target_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            target_path.write_bytes(old)
            target_path.chmod(mode)
            info = target_path.stat()
            preimage_sha = sha256(old)
            preimage_mode, preimage_uid, preimage_gid = (
                info.st_mode & 0o777, info.st_uid, info.st_gid)
        # The NFT file candidate is filled after the exact compiler merge.
        files.append({"target": target, "content_b64": base64.b64encode(new).decode("ascii"),
                      "mode": mode, "uid": 0, "gid": 0,
                      "preimage_sha256": preimage_sha, "preimage_mode": preimage_mode,
                      "preimage_uid": preimage_uid, "preimage_gid": preimage_gid})

    compiled = bundle_module._load_delta().compile_delta(
        initial_nft_json, baseline_nft, candidate_nft, INSTALLER_SHA, MODES, VIPS)
    nft_entry = next(item for item in files if item["target"] == TARGETS[-1])
    nft_entry["content_b64"] = base64.b64encode(compiled["persistent"].encode()).decode("ascii")
    bundle = {"version": 1, "installer_sha256": INSTALLER_SHA, "files": files,
              "nft": {"candidate_renderer": candidate_nft,
                      "preview_live_json": initial_nft_json,
                      "profile_modes": MODES, "profile_vips": VIPS}}
    return json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode(), compiled


def _prepare_private_config(root: Path, certificate_bundle: Path):
    config_env = root / "etc/dnscomplex/config.env"
    config_env.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_env.write_text(
        "DEPLOY_MODE=routeros-policy\nWAN_IFACE=ens18\nAI_EGRESS_MODE=ipsec\nCN_EGRESS_MODE=ipsec\n"
        "AI_MARK=0x301\nCN_MARK=0x351\nAI_TABLE=301\nCN_TABLE=351\n"
        "AI_QUIC_POLICY=reject\nCN_QUIC_POLICY=reject\n"
        "SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=0x2024\nLINUX_LAN_IPV4=198.18.1.1\n"
        "LAN_CLIENT_IPV4_CIDR=198.18.1.0/24\n",
        encoding="ascii")
    config_env.chmod(0o600)
    metadata = root / "controlled-sas.txt"
    metadata.write_text(
        "ai: #1531, ESTABLISHED, IKEv2, rekeying in 9 mins\n"
        "  local 198.18.2.1[4500] [10.250.1.10]\n"
        "  ai: #1531, reqid 1, INSTALLED, TUNNEL, ESP, SPIs\n"
        "cn: #1532, ESTABLISHED, IKEv2, rekeying in 9 mins\n"
        "  local 198.18.3.1[4500] [10.251.1.10]\n"
        "  cn: #1532, reqid 2, INSTALLED, TUNNEL, ESP, SPIs\n", encoding="ascii")
    calls = root / "swanctl-calls.log"
    private_bin = root / "test-bin"
    private_bin.mkdir(mode=0o700)
    swanctl = private_bin / "swanctl"
    swanctl.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >>\"$DNSCOMPLEX_TEST_SWANCTL_CALLS\"\n"
        "case \"$*\" in '--list-sas') cat \"$DNSCOMPLEX_TEST_SAS\" ;; *) exit 97 ;; esac\n",
        encoding="ascii")
    swanctl.chmod(0o700)
    (root / "run/dnscomplex").mkdir(mode=0o700, parents=True, exist_ok=True)
    singbox_config = {
        "log": {"disabled": True},
        "inbounds": [{"type": "socks", "tag": "private-health-control",
                       "listen": "127.0.0.1", "listen_port": 19555}],
        "outbounds": [
            {"type": "direct", "tag": "ai-ipsec", "inet4_bind_address": VIPS["ai"]},
            {"type": "direct", "tag": "cn-ipsec", "inet4_bind_address": VIPS["cn"]},
            {"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}}
    singbox_path = root / "etc/sing-box/config.json"
    singbox_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    singbox_path.write_text(json.dumps(singbox_config, sort_keys=True) + "\n", encoding="utf-8")
    singbox_path.chmod(0o644)
    # Ensure the actual private Sing-box process trusts only these ephemeral
    # test peers; the adapter runner gets the same bundle via SSL_CERT_FILE.
    certificate_bundle.write_bytes((certificate_bundle.parent / "ai.crt").read_bytes() +
                                   (certificate_bundle.parent / "cn.crt").read_bytes())
    return private_bin, metadata, calls, singbox_path


def _host_runner(root: Path, private_bin: Path, ca_bundle: Path, singbox_process,
                 timer_state: dict, systemctl_calls: list[str], nft_ack_lost: bool):
    class Result:
        def __init__(self, returncode, stdout="", stderr=""):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr
    fault_used = {"value": False}

    def runner(argv, *, input_text=None, env=None, timeout=15):
        argv = tuple(str(value) for value in argv)
        environ = dict(os.environ if env is None else env)
        environ.update({"FS_ROOT": str(root), "DNSCOMPLEX_FS_ROOT": str(root),
                       "DNSCOMPLEX_ROOT": str(root),
                       "DNSCOMPLEX_CONFIG": str(root / "etc/dnscomplex/config.env"),
                       "DNSCOMPLEX_TEST_SAS": str(root / "controlled-sas.txt"),
                       "DNSCOMPLEX_TEST_SWANCTL_CALLS": str(root / "swanctl-calls.log"),
                       "SSL_CERT_FILE": str(ca_bundle),
                       "PATH": str(private_bin) + ":" + environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")})
        if argv and argv[0] == "systemctl":
            systemctl_calls.append(" ".join(argv[1:]))
            verb = argv[1] if len(argv) > 1 else ""
            if verb in {"restart", "try-restart", "reload", "daemon-reload", "reload-or-restart"}:
                return Result(97, "", "forbidden private test systemctl mutation: " + verb)
            if verb == "is-active" and len(argv) >= 4:
                unit = argv[-1]
                if unit == "sing-box":
                    active = singbox_process.poll() is None
                elif unit == "dnscomplex-health.timer":
                    active = bool(timer_state["active"])
                elif unit == "dnscomplex-health.service":
                    active = False
                else:
                    return Result(4, "", "unknown private test unit")
                return Result(0 if active else 3)
            if verb == "show" and argv[-1:] == ("sing-box",):
                if singbox_process.poll() is not None:
                    return Result(1, "", "private Sing-box child is not alive")
                return Result(0, str(singbox_process.pid) + "\n")
            if verb == "stop" and argv[-1:] == ("dnscomplex-health.timer",):
                timer_state["active"] = False
                return Result(0)
            if verb == "start" and argv[-1:] == ("dnscomplex-health.timer",):
                timer_state["active"] = True
                return Result(0)
            return Result(97, "", "unrecognized private systemctl command")
        if argv and argv[0] == "bash" and len(argv) >= 3 and argv[1] == "-c":
            command = argv[2].replace(
                "source /usr/local/sbin/dnscomplex",
                f'source "{root}/usr/local/sbin/dnscomplex"')
            argv = (argv[0], argv[1], command, *argv[3:])
        lose_ack = (nft_ack_lost and not fault_used["value"] and argv == ("nft", "-f", "-") and
                    input_text and "add set inet dnscomplex ai_probe_vip4" in input_text)
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_text is not None else None,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   env=environ, start_new_session=True)
        try:
            stdout, stderr = process.communicate(input=input_text,
                                                 timeout=max(1.0, min(float(timeout), 180.0)))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=0.2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
            return Result(124, stdout, stderr or "bounded runner timeout")
        if lose_ack and process.returncode == 0:
            fault_used["value"] = True
            return Result(1, stdout, "fixture injected lost acknowledgement after nft transaction committed")
        return Result(process.returncode, stdout, stderr)

    runner.fault_used = fault_used
    return runner


def _nft_set_elements(nft_json: dict, name: str):
    rows = [item["set"] for item in nft_json.get("nftables", [])
            if isinstance(item, dict) and isinstance(item.get("set"), dict) and
            item["set"].get("name") == name]
    if len(rows) != 1:
        raise AssertionError(f"expected exactly one NFT set {name}")
    return rows[0].get("elem", [])


def _gate_state_v4_v6(profile):
    nft = json.loads(run(["nft", "-j", "list", "table", "inet", "dnscomplex"]).stdout)
    v4 = _nft_set_elements(nft, profile + "_ready4")
    v6 = _nft_set_elements(nft, profile + "_ready6")
    return (any("0.0.0.0" in json.dumps(x) for x in v4),
            any('"::"' in json.dumps(x) for x in v6))


def _has_exact_probe_policy_rule(output: str, *, mark: int, priority: int, table: int) -> bool:
    try:
        rows = json.loads(output)
    except json.JSONDecodeError as exc:
        raise AssertionError("ip -j rule show returned malformed JSON") from exc
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            row_priority = int(row.get("priority"))
            row_table = int(row.get("table"))
            raw_mark = row.get("fwmark")
            if isinstance(raw_mark, int):
                row_mark, mask = raw_mark, 0xffffffff
            elif isinstance(raw_mark, str):
                parts = raw_mark.split("/", 1)
                row_mark = int(parts[0], 0)
                mask = int(parts[1], 0) if len(parts) == 2 else 0xffffffff
            else:
                continue
        except (TypeError, ValueError):
            continue
        if (row_priority == priority and row_table == table and row_mark == mark and
                mask == 0xffffffff):
            return True
    return False


def _seed_protected_conntrack(adapter_module):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(2)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(2); client.connect(listener.getsockname())
    server, _peer = listener.accept()
    listener.close()
    records = adapter_module._LAN.stable_conntrack(
        run(["conntrack", "-L", "-o", "extended,id"]).stdout)
    if not records:
        client.close(); server.close()
        raise AssertionError("could not establish a live private conntrack control before publication")
    return client, server, records


def _candidate_bundle(root: Path, baseline_nft: str, candidate_nft: str,
                      initial_json: dict, candidate_manager: bytes,
                      candidate_lan: bytes, candidate_probe: bytes,
                      publisher_module):
    bundle, compiled = _bundle(root, initial_nft_json=initial_json,
                               baseline_nft=baseline_nft, candidate_nft=candidate_nft,
                               candidate_manager=candidate_manager, candidate_lan=candidate_lan,
                               candidate_probe=candidate_probe, bundle_module=publisher_module)
    return bundle, compiled


def _preimage_manifest(root: Path):
    result = {}
    for target in TARGETS:
        path = root / target.lstrip("/")
        if path.exists():
            info = path.stat()
            result[target] = (sha256(path), info.st_mode & 0o777, info.st_uid, info.st_gid)
        else:
            result[target] = None
    return result


def _inner(case: str, host_guards: dict[str, str]):
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("private publisher fixture shares the host network namespace")
    delta, publisher, host_adapter_module, gate, nft_fixture = _load_product_modules()
    if sha256(INSTALLER) != INSTALLER_SHA or sha256(BASELINE_INSTALLER) != BASELINE_INSTALLER_SHA:
        raise AssertionError("source installers changed after pin check")

    with tempfile.TemporaryDirectory(prefix="dnscomplex-health-publish-wire-") as temp_dir:
        temp = Path(temp_dir); temp.chmod(0o700)
        for profile, item in (("ai", gate.AI), ("cn", gate.CN)):
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", "/CN=" + item["tls"], "-addext", "subjectAltName=DNS:" + item["tls"],
                 "-keyout", str(temp / f"{profile}.key"), "-out", str(temp / f"{profile}.crt")], timeout=12)
        ca_bundle = temp / "controlled-ca.pem"
        peer = subprocess.Popen(["unshare", "--net", "--fork", sys.executable,
                                 str(GATE_FIXTURE_PATH), "--peer", str(temp)],
                                start_new_session=True)
        singbox = None
        control_sockets = []
        try:
            gate.wait_ready(temp / "peer.pid", peer)
            gate.set_namespace_topology((temp / "peer.pid").read_text().strip())
            # The TLS peer waits until both sides of the veth topology exist.
            # Publish readiness only after routes/addresses have been installed.
            (temp / "configured").write_text("ready", encoding="ascii")
            gate.wait_ready(temp / "ai.ready", peer)
            gate.wait_ready(temp / "cn.ready", peer)
            gate.wait_ready(temp / "default.ready", peer)
            nft_path, installed_probe, rendered_candidate_manager = gate.render_candidate(INSTALLER, temp)
            root = temp / "render-root"
            candidate_nft = nft_path.read_text(encoding="utf-8")
            candidate_manager = rendered_candidate_manager.read_bytes()
            # The gate fixture renderer emits NFT, probe helper and manager;
            # obtain the fourth managed asset directly from the pinned 856
            # installer's exact embedded heredoc.
            candidate_lan = publisher._extract_heredoc(
                INSTALLER.read_bytes(), publisher.LAN_HELPER_START,
                "LAN_ALIAS", "candidate LAN helper")
            candidate_probe = installed_probe.read_bytes()
            if (sha256(candidate_probe) != PROBE_SHA or not os.access(installed_probe, os.X_OK) or
                    not os.access(rendered_candidate_manager, os.X_OK)):
                raise AssertionError("candidate renderer did not install pinned executable health assets")

            baseline_path = temp / "baseline.nft"
            baseline_nft = nft_fixture.render_nft(BASELINE_INSTALLER, baseline_path)
            # Private host filesystem preimages are the actual embedded 75e
            # assets; candidate 856 bytes remain in memory for the bundle.
            root_install = root / "root/install.sh"
            root_install.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            root_install.write_bytes(BASELINE_INSTALLER.read_bytes()); root_install.chmod(0o755)
            baseline_manager = publisher._extract_heredoc(
                BASELINE_INSTALLER.read_bytes(), publisher.MANAGER_START, "MANAGER", "baseline manager")
            baseline_lan = publisher._extract_heredoc(
                BASELINE_INSTALLER.read_bytes(), publisher.LAN_HELPER_START, "LAN_ALIAS", "baseline LAN helper")
            manager_path = root / "usr/local/sbin/dnscomplex"
            manager_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            manager_path.write_bytes(baseline_manager); manager_path.chmod(0o755)
            lan_path = root / "usr/local/libexec/dnscomplex-lan-alias"
            lan_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            lan_path.write_bytes(baseline_lan); lan_path.chmod(0o755)
            nft_include = root / "etc/nftables.d/dnscomplex.nft"
            nft_include.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            nft_include.write_text(baseline_nft, encoding="utf-8"); nft_include.chmod(0o644)
            (root / "usr/local/lib/dnscomplex").mkdir(mode=0o755, parents=True, exist_ok=True)
            installed_probe.unlink(missing_ok=True)  # helper is an absent 75e preimage

            private_bin, sas_path, swanctl_calls, singbox_config = _prepare_private_config(
                root, ca_bundle)
            # Private real sing-box 1.14 child, loopback-only inbound. The
            # adapter's fake service manager must report this actual live PID.
            singbox_bin = shutil.which("sing-box")
            if not singbox_bin:
                raise AssertionError("private wire requires an installed sing-box executable")
            run([singbox_bin, "check", "-c", str(singbox_config)], timeout=8)
            singbox = subprocess.Popen([singbox_bin, "run", "-c", str(singbox_config)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            until = time.monotonic() + 6
            while time.monotonic() < until:
                if singbox.poll() is not None:
                    stdout, stderr = singbox.communicate()
                    raise RuntimeError("private Sing-box child exited: " + stderr.decode(errors="replace")[-1200:])
                probe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                probe_sock.settimeout(.15)
                try:
                    if probe_sock.connect_ex(("127.0.0.1", 19555)) == 0:
                        probe_sock.close()
                        break
                finally:
                    probe_sock.close()
                time.sleep(.04)
            else:
                raise TimeoutError("private Sing-box listener did not become ready")

            # Load the frozen 75e table and establish only the normal profile
            # policy/NAT/bind state needed by the current watchdog checks.
            gate.run(["nft", "-f", str(nft_include)], timeout=10)
            config_env = root / "etc/dnscomplex/config.env"
            # Paths injected by this adapter runner are test variables, not
            # config schema entries, so keep the private source config clean.
            current_env = os.environ.copy()
            current_env.update({"DNSCOMPLEX_ROOT": str(root), "DNSCOMPLEX_FS_ROOT": str(root),
                                "DNSCOMPLEX_CONFIG": str(config_env),
                                "DNSCOMPLEX_TEST_SAS": str(sas_path),
                                "DNSCOMPLEX_TEST_SWANCTL_CALLS": str(swanctl_calls),
                                "PATH": str(private_bin) + ":" + current_env.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")})
            setup_body = r'''set -Eeuo pipefail
source "$1"
load_config
sas=$(swanctl --list-sas)
ensure_policy_route_profile ai
ensure_policy_route_profile cn
sync_ipsec_nat_profile ai
sync_ipsec_nat_profile cn
for profile in ai cn; do
 vip=$(ipsec_vip "$profile")
 ipsec_profile_runtime_ready "$profile" "$sas"
 ipsec_nat_profile_matches "$profile" "$vip"
 ipsec_bind_profile_matches "$profile" "$vip"
done
'''
            setup = subprocess.run(["bash", "-c", setup_body, "profile-health-base", str(manager_path)],
                                   capture_output=True, text=True, timeout=15, env=current_env)
            if setup.returncode:
                raise RuntimeError("75e normal profile setup failed: " + setup.stderr[-3000:])
            for name, wildcard in (("ai_ready4", "0.0.0.0/0"), ("cn_ready4", "0.0.0.0/0")):
                gate.run(["nft", "add", "element", "inet", "dnscomplex", name,
                          "{", wildcard, "}"])
            # IPv6 readiness is intentionally closed for IPsec profiles.
            for name, wildcard in (("ai_ready6", "::/0"), ("cn_ready6", "::/0")):
                gate.run(["nft", "delete", "element", "inet", "dnscomplex", name,
                          "{", wildcard, "}"], check=False)
            gate.run(["nft", "add", "element", "inet", "dnscomplex", "ai4",
                      "{", "203.0.113.77", "timeout", "1h", "}"])
            systemctl_calls: list[str] = []
            timer_state = {"active": True}
            runner = _host_runner(root, private_bin, ca_bundle, singbox,
                                  timer_state, systemctl_calls, nft_ack_lost=(case == "lost-ack"))
            adapter = host_adapter_module.ProfileHealthHostAdapter.for_test(
                fs_root=root, runner=runner, apply=True)
            # Confirm 75e gates are realistically open before publication.
            if _gate_state_v4_v6("ai") != (True, False) or _gate_state_v4_v6("cn") != (True, False):
                raise AssertionError("private baseline must start with IPv4 readiness open and IPv6 closed")
            control_client, control_server, ct_before = _seed_protected_conntrack(host_adapter_module)
            control_sockets.extend((control_client, control_server))
            live_before = adapter.read_live_nft_json()
            candidate_bundle, compiled = _candidate_bundle(
                root, baseline_nft, candidate_nft, live_before, candidate_manager,
                candidate_lan, candidate_probe, publisher)
            bundle_sha = sha256(candidate_bundle)
            backup_parent = root / "var/lib/dnscomplex-health-backups"
            backup_parent.mkdir(mode=0o700, parents=True)

            gate_peer_root = temp
            # Make adapter TLS verification trust the generated controlled CA.
            observations = []
            observe_attempts = []
            original_observe = adapter.observe
            def observed(profile, vip, timeout_seconds):
                observe_attempts.append((profile, vip))
                result = original_observe(profile, vip, timeout_seconds)
                observations.append((profile, result.get("count"), _gate_state_v4_v6(profile)))
                return result
            adapter.observe = observed

            if case == "probe-failure":
                (gate_peer_root / "ai.mode").write_text("wrong-id", encoding="ascii")
            old_manifest = _preimage_manifest(root)
            original_singbox_pid = singbox.pid
            original_config_sha = sha256(singbox_config)
            if case == "success":
                result = publisher.apply_candidate(
                    candidate_bundle, bundle_sha, adapter=adapter, fs_root=root,
                    backup_parent=backup_parent, lock_path=root / "run/lock/maintenance.lock")
                if result.get("profiles_verified") != ["ai", "cn"] or result.get("singbox_restart_count") != 0:
                    raise AssertionError("publisher did not confirm both profiles without a restart")
                if observations != [("ai", 1, (False, False)), ("ai", 2, (True, False)),
                                    ("cn", 1, (False, False)), ("cn", 2, (True, False))]:
                    raise AssertionError(f"IPv4-only gates did not follow the exact two-success warmup: {observations!r}")
                for profile in ("ai", "cn"):
                    if _gate_state_v4_v6(profile) != (True, False):
                        raise AssertionError(f"successful {profile} gate must open IPv4 only")
                if runner.fault_used["value"]:
                    raise AssertionError("unexpected nft lost-ack injection in success case")
                events = gate.peer_events(temp, at_least=4)
                for profile in ("ai", "cn"):
                    if sum(event.get("profile") == profile and event.get("source") == VIPS[profile]
                           for event in events) < 2:
                        raise AssertionError(f"actual controlled TLS peer did not receive two {profile} source-VIP probes")
                nft_after = adapter.read_live_nft_json()
                delta.verify_applied(nft_after, compiled["expected_rules"], compiled["expected_sets"])
                if not any("203.0.113.77" in json.dumps(row) for row in _nft_set_elements(nft_after, "ai4")):
                    raise AssertionError("unrelated dynamic ai4 domain marker changed during publish")
                table = root / "etc/nftables.d/dnscomplex.nft"
                if table.read_bytes() != compiled["persistent"].encode():
                    raise AssertionError("published persistent NFT file differs from compiler output")
                if singbox.poll() is not None or sha256(singbox_config) != original_config_sha:
                    raise AssertionError("private Sing-box process/config changed during successful publication")
                if any(any(token in call.split() for token in ("restart", "reload", "try-restart"))
                       for call in systemctl_calls):
                    raise AssertionError(f"systemd restart/reload command was attempted: {systemctl_calls!r}")
                if timer_state["active"] is not True:
                    raise AssertionError("private health timer state was not restored after success")
                ct_after = host_adapter_module._LAN.stable_conntrack(
                    runner(("conntrack", "-L", "-o", "extended,id")).stdout)
                for ident, record in ct_before.items():
                    if ident not in ct_after or ct_after[ident]["identity"] != record["identity"]:
                        raise AssertionError("preexisting private conntrack control changed during publish")
                if not (root / "run/dnscomplex/profile-dataplane-ai.success").is_file() or \
                        not (root / "run/dnscomplex/profile-dataplane-cn.success").is_file():
                    raise AssertionError("success observer proofs were not written under the private root")
                print("HEALTH_PUBLISH_NATIVE_SUCCESS", json.dumps({"profiles": result["profiles_verified"],
                      "observe_gates": observations, "singbox_pid": singbox.pid,
                      "timer_restored": timer_state["active"], "ct_preserved": len(ct_before),
                      "probe_rule_comments": [row["rule"].get("comment") for row in nft_after["nftables"]
                          if isinstance(row, dict) and isinstance(row.get("rule"), dict) and
                          row["rule"].get("comment", "").endswith("-dataplane-probe")]}, sort_keys=True), flush=True)
            else:
                before_targets = old_manifest.copy()
                before_live = adapter.read_live_nft_json()
                failure_message = None
                try:
                    publisher.apply_candidate(
                        candidate_bundle, bundle_sha, adapter=adapter, fs_root=root,
                        backup_parent=backup_parent, lock_path=root / "run/lock/maintenance.lock")
                except publisher.HealthHotdeployError as exc:
                    failure_message = str(exc)
                    print("HEALTH_PUBLISH_INJECTED_ERROR", json.dumps({
                        "case": case, "error": failure_message}, sort_keys=True), flush=True)
                if failure_message is None:
                    raise AssertionError("injected publisher failure unexpectedly committed")
                if case == "lost-ack" and not runner.fault_used["value"]:
                    raise AssertionError("lost-NFT-ack path was not reached")
                for profile in ("ai", "cn"):
                    if _gate_state_v4_v6(profile) != (False, False):
                        raise AssertionError(f"failed {profile} transaction must leave both readiness families closed")
                after_manifest = _preimage_manifest(root)
                if after_manifest != before_targets:
                    raise AssertionError("publisher did not restore exact private file preimages after failure")
                after_live = adapter.read_live_nft_json()
                if any(isinstance(row, dict) and isinstance(row.get("set"), dict) and
                       row["set"].get("name") in ("ai_probe_vip4", "cn_probe_vip4")
                       for row in after_live["nftables"]):
                    raise AssertionError("owned probe sets remained after exact failed-transaction rollback; "
                                         f"publisher error: {failure_message}")
                if any(isinstance(row, dict) and isinstance(row.get("rule"), dict) and
                       row["rule"].get("comment", "").endswith("-dataplane-probe")
                       for row in after_live["nftables"]):
                    raise AssertionError("owned probe rules remained after exact failed-transaction rollback; "
                                         f"publisher error: {failure_message}")
                rules = run(["ip", "-j", "-4", "rule", "show"]).stdout
                for profile, mark, priority, table_id in (("ai", 929, 10201, 301),
                                                          ("cn", 1009, 10251, 351)):
                    if _has_exact_probe_policy_rule(rules, mark=mark, priority=priority,
                                                    table=table_id):
                        raise AssertionError(f"owned {profile} probe policy rule survived rollback")
                if not timer_state["active"]:
                    raise AssertionError("private health timer did not return to its active preimage")
                if singbox.poll() is not None or singbox.pid != original_singbox_pid or \
                        sha256(singbox_config) != original_config_sha:
                    raise AssertionError("private Sing-box process/config changed during failed publication")
                if any(any(token in call.split() for token in ("restart", "reload", "try-restart"))
                       for call in systemctl_calls):
                    raise AssertionError(f"systemd restart/reload command was attempted: {systemctl_calls!r}")
                current_ct = host_adapter_module._LAN.stable_conntrack(
                    runner(("conntrack", "-L", "-o", "extended,id")).stdout)
                for ident, record in ct_before.items():
                    if ident not in current_ct or current_ct[ident]["identity"] != record["identity"]:
                        raise AssertionError("preexisting private conntrack control changed during rollback")
                # Existing domain/profile state and normal output/NAT rules
                # remain. Gate sets intentionally differ: failures never
                # restore prior readiness.
                if not any("203.0.113.77" in json.dumps(row) for row in _nft_set_elements(after_live, "ai4")):
                    raise AssertionError("unrelated dynamic ai4 domain marker changed during rollback")
                if case == "probe-failure":
                    if not observe_attempts or observe_attempts[0][0] != "ai":
                        raise AssertionError("controlled DNS failure did not reach the production observer")
                    failed_events = gate.peer_events(temp, at_least=1)
                    if not any(event.get("profile") == "ai" and event.get("source") == VIPS["ai"]
                               for event in failed_events):
                        raise AssertionError("failed AI DoH request did not reach its controlled TLS peer")
                if case == "lost-ack" and observations:
                    raise AssertionError("lost NFT acknowledgement should roll back before any probe observation")
                if _gate_state_v4_v6("ai") != (False, False) or _gate_state_v4_v6("cn") != (False, False):
                    raise AssertionError("failure rollback did not keep selected IPv4/IPv6 gates closed")
                # Require NFT table baseline rules/comments to remain. Their
                # packet counters may naturally differ only if observations ran.
                comments_before = {item["rule"].get("comment") for item in before_live["nftables"]
                                   if isinstance(item, dict) and isinstance(item.get("rule"), dict)}
                comments_after = {item["rule"].get("comment") for item in after_live["nftables"]
                                  if isinstance(item, dict) and isinstance(item.get("rule"), dict)}
                if comments_before - comments_after:
                    raise AssertionError("baseline NFT rule comments disappeared during rollback")
                print("HEALTH_PUBLISH_NATIVE_ROLLBACK", json.dumps({"case": case,
                      "nft_ack_lost": runner.fault_used["value"], "observations": observations,
                      "observe_attempts": observe_attempts,
                      "gates": {p: _gate_state_v4_v6(p) for p in ("ai", "cn")},
                      "timer_restored": timer_state["active"], "ct_preserved": len(ct_before),
                      "probe_assets_absent": True, "singbox_pid": singbox.pid}, sort_keys=True), flush=True)
        finally:
            for sock in control_sockets:
                try: sock.close()
                except OSError: pass
            if singbox is not None and singbox.poll() is None:
                try: os.killpg(singbox.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                try: singbox.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try: os.killpg(singbox.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    singbox.wait(timeout=2)
            (temp / "stop").write_text("stop")
            if peer.poll() is None:
                try: peer.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try: os.killpg(peer.pid, signal.SIGTERM)
                    except ProcessLookupError: pass
                    try: peer.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        try: os.killpg(peer.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                        peer.wait(timeout=2)


def _host_snapshot():
    paths = (Path("/root/install.sh"), Path("/usr/local/sbin/dnscomplex"),
             Path("/etc/sing-box/config.json"))
    hashes = {}
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise unittest.SkipTest(f"host guard path is unavailable: {path}")
        hashes[str(path)] = sha256(path)
    service = run(["systemctl", "is-active", "--quiet", "sing-box"], check=False)
    if service.returncode:
        raise unittest.SkipTest("active host sing-box is required for no-touch guard")
    pid = run(["systemctl", "show", "--property=MainPID", "--value", "sing-box"]).stdout.strip()
    if not pid.isdigit() or int(pid) < 2:
        raise unittest.SkipTest("host sing-box MainPID is unavailable")
    return {**hashes, "pid": pid}


def _assert_host_snapshot(expected):
    after = _host_snapshot()
    if after != expected:
        raise AssertionError("isolated health publish changed host Sing-box/installer guards")


class ProfileHealthHotdeployNamespaceTest(unittest.TestCase):
    def _run_case(self, case):
        if platform.system() != "Linux":
            self.skipTest("health publish native wire requires Linux")
        required = ("unshare", "nsenter", "ip", "nft", "openssl", "bash", "jq",
                    "conntrack", "ss", "sing-box", "timeout")
        missing = [name for name in required if shutil.which(name) is None]
        if missing:
            self.skipTest("missing native health publish tools: " + ", ".join(missing))
        outer_guard = _host_snapshot()
        netns = subprocess.run(["unshare", "--net", "true"], check=False,
                               capture_output=True, text=True)
        if netns.returncode:
            self.skipTest("network namespace capability unavailable: " + netns.stderr.strip())
        command = ["unshare", "--net", "--mount", "--propagation", "private", "--fork",
                   sys.executable, str(Path(__file__).resolve()), "--inner", "--case", case]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, start_new_session=True)
        try:
            output, _ = process.communicate(timeout=105)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait(timeout=3)
            _assert_host_snapshot(outer_guard)
            self.fail(f"private health publisher wire exceeded 105s ({case})")
        # Check host invariants even when the private integration fails; a
        # failing assertion must not suppress the no-touch evidence.
        _assert_host_snapshot(outer_guard)
        self.assertEqual(process.returncode, 0, output[-10000:])
        self.assertIn("HEALTH_PUBLISH_NATIVE_", output)
        print(output, end="", flush=True)

    def test_real_private_process_and_two_success_warmup_transaction(self):
        self._run_case("success")

    def test_controlled_doh_failure_restores_assets_and_leaves_gates_closed(self):
        self._run_case("probe-failure")

    def test_committed_nft_with_lost_ack_uses_exact_undo(self):
        self._run_case("lost-ack")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--inner", action="store_true")
    parser.add_argument("--case", choices=("success", "probe-failure", "lost-ack"))
    args, unittest_args = parser.parse_known_args()
    if args.inner:
        if not args.case:
            raise SystemExit("--inner requires --case")
        _inner(args.case, {})
    else:
        sys.argv = [sys.argv[0], *unittest_args]
        unittest.main()
