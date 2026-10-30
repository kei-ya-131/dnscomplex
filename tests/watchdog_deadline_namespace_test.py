#!/usr/bin/env python3
"""Actual 40s watchdog deadline vs the 45s service timeout in a private netns.

Uses the frozen installer renderer/manager and real nft/ip commands. Only
systemd and strongSwan metadata are private fixture shims; a delayed
``systemctl is-active`` intentionally tests the backend call before route/gate
reconciliation. No provider endpoint or host service is contacted.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"
GATE_FIXTURE = ROOT / "tests/profile_dataplane_gate_namespace_test.py"
DEFAULT_INSTALLER_SHA = "856be53885775e98076a0a6e2611e2de27028970d7cde3bb3b714def77a5896f"
INSTALLER_SHA = DEFAULT_INSTALLER_SHA
GATE_FIXTURE_SHA = "30915efefc5c8d6eb15af5589edcc2d40f9d91d39a6788f128b7b14cf5088ed8"
AI_VIP = "10.250.1.10"
CN_VIP = "10.251.1.10"
SERVICE_TIMEOUT_SECONDS = 45
WATCHDOG_BUDGET_MS = 40_000
BURN_SECONDS = 37


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_gate_fixture():
    if GATE_FIXTURE.is_symlink() or not GATE_FIXTURE.is_file():
        raise AssertionError("pinned gate fixture is not a regular file")
    actual = sha256(GATE_FIXTURE)
    if actual != GATE_FIXTURE_SHA:
        raise AssertionError(f"pinned gate fixture SHA mismatch: {actual}")
    spec = importlib.util.spec_from_file_location("watchdog_gate_fixture", GATE_FIXTURE)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load pinned gate fixture")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _health_unit_block(installer: Path) -> str:
    text = installer.read_text(encoding="utf-8")
    marker = "write_file /etc/systemd/system/dnscomplex-health.service <<'EOF'\n"
    if text.count(marker) != 1:
        raise AssertionError("expected one frozen health service renderer")
    block = text.split(marker, 1)[1].split("\nEOF", 1)[0]
    if "TimeoutStartSec=45s" not in block or "ExecStart=/usr/local/sbin/dnscomplex watchdog" not in block:
        raise AssertionError("frozen service unit no longer has its 45s watchdog contract")
    return block


def _gate_wildcard(profile: str, family: int) -> bool:
    set_name = f"{profile}_ready{family}"
    raw = subprocess.run(["nft", "-j", "list", "set", "inet", "dnscomplex", set_name],
                         capture_output=True, text=True, timeout=4, check=True).stdout
    value = json.loads(raw)
    sets = [entry["set"] for entry in value.get("nftables", [])
            if isinstance(entry, dict) and isinstance(entry.get("set"), dict) and
            entry["set"].get("name") == set_name]
    if len(sets) != 1:
        raise AssertionError(f"missing or ambiguous readiness set {set_name}")
    expected = "0.0.0.0" if family == 4 else "::"
    return any(isinstance(item, dict) and isinstance(item.get("prefix"), dict) and
               item["prefix"].get("addr") == expected and
               item["prefix"].get("len") == 0 for item in sets[0].get("elem", []))


def _pid_snapshot(pid: int) -> tuple[str, str] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    # comm is parenthesized and can contain spaces; split after the last ')'.
    tail = raw.rsplit(")", 1)[1].strip().split()
    return (tail[0], tail[19]) if len(tail) > 19 else None


def _is_live(pid: int, start_ticks: str) -> bool:
    snapshot = _pid_snapshot(pid)
    return snapshot is not None and snapshot[0] != "Z" and snapshot[1] == start_ticks


def _stop_pids(pids: list[tuple[int, str]]) -> None:
    for pid, start_ticks in pids:
        if _is_live(pid, start_ticks):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    time.sleep(.05)
    for pid, start_ticks in pids:
        if _is_live(pid, start_ticks):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def _host_snapshot():
    guarded = (Path("/root/install.sh"), Path("/usr/local/sbin/dnscomplex"),
               Path("/etc/sing-box/config.json"))
    hashes = {}
    for path in guarded:
        if path.is_symlink() or not path.is_file():
            raise unittest.SkipTest(f"host guard path unavailable: {path}")
        hashes[str(path)] = sha256(path)
    service = subprocess.run(["systemctl", "is-active", "--quiet", "sing-box"], check=False)
    if service.returncode:
        raise unittest.SkipTest("active host sing-box required for no-touch guard")
    result = subprocess.run(["systemctl", "show", "--property=MainPID", "--value", "sing-box"],
                            capture_output=True, text=True, check=True)
    pid = result.stdout.strip()
    if not pid.isdigit() or int(pid) < 2:
        raise unittest.SkipTest("host sing-box MainPID unavailable")
    return {**hashes, "pid": pid}


def _assert_host_snapshot(expected):
    if _host_snapshot() != expected:
        raise AssertionError("private watchdog test changed host installer/manager/Sing-box state")


def _inner(expected_installer_sha: str):
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("watchdog fixture is not isolated from host network namespace")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_installer_sha):
        raise AssertionError("installer SHA must be an exact lowercase SHA-256")
    installer_bytes = INSTALLER.read_bytes()
    actual_installer_sha = hashlib.sha256(installer_bytes).hexdigest()
    if actual_installer_sha != expected_installer_sha:
        raise AssertionError(f"frozen installer SHA mismatch: {actual_installer_sha}")
    gate = load_gate_fixture()

    with tempfile.TemporaryDirectory(prefix="dnscomplex-watchdog-budget-") as temp_raw:
        temp = Path(temp_raw); temp.chmod(0o700)
        pinned_installer = temp / "install-pinned.sh"
        pinned_installer.write_bytes(installer_bytes)
        pinned_installer.chmod(0o600)
        _health_unit_block(pinned_installer)
        for profile, item in (("ai", gate.AI), ("cn", gate.CN)):
            gate.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                      "-subj", "/CN=" + item["tls"], "-addext", "subjectAltName=DNS:" + item["tls"],
                      "-keyout", str(temp / f"{profile}.key"), "-out", str(temp / f"{profile}.crt")], timeout=12)

        peer = subprocess.Popen(["unshare", "--net", "--fork", sys.executable,
                                 str(GATE_FIXTURE), "--peer", str(temp)], start_new_session=True)
        capture = None
        capture_stop = None
        capture_thread = None
        peer_group_stopped = False
        try:
            gate.wait_ready(temp / "peer.pid", peer)
            gate.set_namespace_topology((temp / "peer.pid").read_text().strip())
            (temp / "configured").write_text("ready", encoding="ascii")
            for name in ("ai.ready", "cn.ready", "default.ready"):
                gate.wait_ready(temp / name, peer)

            nft_path, _probe_module, manager = gate.render_candidate(pinned_installer, temp)
            root = temp / "render-root"
            private_bin = gate.install_swanctl_metadata_shim(root, temp)
            # Actual candidate table and route manager; no host source or
            # systemctl path is used from this private runtime.
            gate.route_manager_sync(manager, root)
            gate.run(["nft", "-f", str(nft_path)], timeout=10)
            gate.manager_sync(manager, root, "ai", AI_VIP)
            gate.manager_sync(manager, root, "cn", CN_VIP)
            for profile in ("ai", "cn"):
                gate.run(["nft", "add", "element", "inet", "dnscomplex",
                          f"{profile}_ready4", "{", "0.0.0.0/0", "}"])
                if not _gate_wildcard(profile, 4) or _gate_wildcard(profile, 6):
                    raise AssertionError(f"bad initial {profile} IPv4-only gate state")

            calls_path = temp / "systemctl.log"
            pids_path = temp / "systemctl.pids"
            forbidden_path = temp / "systemctl-unexpected.log"
            systemctl = private_bin / "systemctl"
            systemctl.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >>\"$DNSCOMPLEX_TEST_SYSTEMCTL_LOG\"\n"
                "case \"$*\" in\n"
                "  'is-active --quiet nftables'|'is-active nftables')\n"
                "    printf '%s %s\\n' \"$$\" \"$(awk '{print $22}' /proc/$$/stat)\" >>\"$DNSCOMPLEX_TEST_SYSTEMCTL_PIDS\"\n"
                "    sleep 60 >/dev/null 2>&1 &\n"
                "    child=$!\n"
                "    printf '%s %s\\n' \"$child\" \"$(awk '{print $22}' /proc/$child/stat)\" >>\"$DNSCOMPLEX_TEST_SYSTEMCTL_PIDS\"\n"
                "    wait \"$child\"\n"
                "    exit 0\n"
                "    ;;\n"
                "  *) printf '%s\\n' \"$*\" >>\"$DNSCOMPLEX_TEST_SYSTEMCTL_UNEXPECTED\"; exit 97 ;;\n"
                "esac\n", encoding="ascii")
            systemctl.chmod(0o700)
            env = dict(os.environ)
            env.update({"DNSCOMPLEX_ROOT": str(root), "DNSCOMPLEX_FS_ROOT": str(root),
                        "DNSCOMPLEX_CONFIG": str(root / "etc/dnscomplex/config.env"),
                        "DNSCOMPLEX_TEST_SYSTEMCTL_LOG": str(calls_path),
                        "DNSCOMPLEX_TEST_SYSTEMCTL_PIDS": str(pids_path),
                        "DNSCOMPLEX_TEST_SYSTEMCTL_UNEXPECTED": str(forbidden_path),
                        "PATH": str(private_bin) + os.pathsep + env.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")})
            resolved = subprocess.run(["bash", "-c", "command -v systemctl"], env=env,
                                      capture_output=True, text=True, check=True).stdout.strip()
            if resolved != str(systemctl):
                raise AssertionError("private PATH did not resolve the systemctl shim first")

            capture, capture_stop, capture_thread, wan_counts = gate.start_default_egress_capture()
            deadline_path = temp / "watchdog-deadline-ms"
            budget_start_path = temp / "watchdog-budget-start-ms"
            shell = r'''set -Eeuo pipefail
source "$1"
load_config
original=$(declare -f monotonic_millis)
original=${original/monotonic_millis/monotonic_millis_original}
eval "$original"
monotonic_millis() {
  local value
  value=$(monotonic_millis_original) || return
  if [[ ${DNSCOMPLEX_TEST_TRACE_WATCHDOG_START:-0} == 1 && ! -e "$DNSCOMPLEX_TEST_BUDGET_START_FILE" ]]; then
    printf '%s\n' "$value" >"$DNSCOMPLEX_TEST_BUDGET_START_FILE"
  fi
  printf '%s\n' "$value"
}
original=$(declare -f watchdog_budget_start)
original=${original/watchdog_budget_start/watchdog_budget_start_original}
eval "$original"
watchdog_budget_start() {
  export DNSCOMPLEX_TEST_TRACE_WATCHDOG_START=1
  watchdog_budget_start_original || { unset DNSCOMPLEX_TEST_TRACE_WATCHDOG_START; return 1; }
  unset DNSCOMPLEX_TEST_TRACE_WATCHDOG_START
  printf '%s\n' "$WATCHDOG_DEADLINE_MS" >"$DNSCOMPLEX_TEST_DEADLINE_FILE"
  command sleep "$DNSCOMPLEX_TEST_BURN_SECONDS"
}
watchdog_cmd
'''
            env.update({"DNSCOMPLEX_TEST_DEADLINE_FILE": str(deadline_path),
                        "DNSCOMPLEX_TEST_BUDGET_START_FILE": str(budget_start_path),
                        "DNSCOMPLEX_TEST_BURN_SECONDS": str(BURN_SECONDS)})
            timeout_bin = shutil.which("timeout")
            if not timeout_bin:
                raise AssertionError("GNU timeout is required to model TimeoutStartSec=45s")
            started = time.monotonic()
            process = subprocess.Popen([timeout_bin, "--signal=TERM", "--kill-after=1s",
                                         f"{SERVICE_TIMEOUT_SECONDS}s", "bash", "-c", shell,
                                         "watchdog-deadline-fixture", str(manager)],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, env=env, start_new_session=True)
            try:
                output, _ = process.communicate(timeout=SERVICE_TIMEOUT_SECONDS + 3)
            except subprocess.TimeoutExpired:
                try: os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                try: process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.wait(timeout=2)
                raise AssertionError("outer harness exceeded 48s while modeling systemd 45s timeout")
            elapsed = time.monotonic() - started
            start_ms = deadline_ms = budget_elapsed_ms = None
            timestamp_errors = []
            try:
                start_ms = int(budget_start_path.read_text().strip())
            except (OSError, ValueError) as exc:
                timestamp_errors.append(f"actual watchdog budget start unavailable: {exc}")
            try:
                deadline_ms = int(deadline_path.read_text().strip())
            except (OSError, ValueError) as exc:
                timestamp_errors.append(f"watchdog deadline unavailable: {exc}")
            if start_ms is not None:
                budget_elapsed_ms = time.monotonic_ns() // 1_000_000 - start_ms

            # Snapshot every safety property before asserting. A red run should
            # carry enough evidence to distinguish the 45s kill, open gates,
            # fallback traffic, and surviving backend children.
            gates = {}
            gate_read_errors = {}
            for profile in ("ai", "cn"):
                try:
                    gates[profile] = (_gate_wildcard(profile, 4), _gate_wildcard(profile, 6))
                except Exception as exc:
                    gates[profile] = "unavailable"
                    gate_read_errors[profile] = f"{type(exc).__name__}: {exc}"
            if capture is not None:
                gate.stop_default_egress_capture(capture, capture_stop, capture_thread)
                capture = None
            events = gate.peer_events(temp, seconds=.25)
            calls = calls_path.read_text().splitlines() if calls_path.exists() else []
            recorded_pids = [tuple(map(int, line.split())) for line in pids_path.read_text().splitlines()
                             if len(line.split()) == 2] if pids_path.exists() else []
            live_pids = [(pid, str(start_ticks)) for pid, start_ticks in recorded_pids
                         if _is_live(pid, str(start_ticks))]
            result = {"elapsed_seconds": round(elapsed, 3), "budget_start_ms": start_ms,
                      "deadline_ms": deadline_ms, "budget_elapsed_ms": budget_elapsed_ms,
                      "budget_ms": (deadline_ms - start_ms
                                    if deadline_ms is not None and start_ms is not None else None),
                      "timestamp_errors": timestamp_errors, "gate_read_errors": gate_read_errors,
                      "service_timeout_seconds": SERVICE_TIMEOUT_SECONDS, "watchdog_rc": process.returncode,
                      "gate_state": gates, "default_wan_probe_packets": wan_counts,
                      "peer_events": events, "backend_calls": calls, "backend_pids": recorded_pids,
                      "late_children": live_pids,
                      "unexpected_systemctl": forbidden_path.read_text().splitlines() if forbidden_path.exists() else [],
                      "swanctl_calls": (temp / "swanctl-calls.log").read_text().splitlines()
                          if (temp / "swanctl-calls.log").exists() else [],
                      "output_tail": output[-1600:]}
            print("WATCHDOG_40S_BUDGET_45S_SERVICE", json.dumps(result, sort_keys=True), flush=True)
            failures = []
            failures.extend(timestamp_errors)
            if start_ms is not None and deadline_ms is not None and deadline_ms - start_ms != WATCHDOG_BUDGET_MS:
                failures.append(f"watchdog deadline delta {deadline_ms - start_ms}ms != {WATCHDOG_BUDGET_MS}ms")
            if process.returncode == 124:
                failures.append("45s service timeout killed watchdog before internal failure")
            if process.returncode == 0:
                failures.append("watchdog accepted delayed systemctl backend as healthy")
            if elapsed < 38 or elapsed >= SERVICE_TIMEOUT_SECONDS:
                failures.append(f"watchdog elapsed {elapsed:.3f}s outside expected 38..45s budget window")
            if gates != {"ai": (False, False), "cn": (False, False)}:
                failures.append(f"delayed backend left profile gates open: {gates!r}")
            if result["unexpected_systemctl"]:
                failures.append("unexpected systemctl verb escaped private backend shim")
            if not calls or calls[0] not in ("is-active --quiet nftables", "is-active nftables"):
                failures.append(f"private backend invocation mismatch: {calls!r}")
            if events:
                failures.append(f"watchdog emitted controlled-peer/default fallback traffic: {events!r}")
            if any(wan_counts.values()):
                failures.append(f"profile resolver probe escaped over default WAN: {wan_counts!r}")
            if result["swanctl_calls"]:
                failures.append("watchdog reached swanctl despite the stalled first service check")
            if live_pids:
                _stop_pids(live_pids)
                failures.append(f"late systemctl backend children survived: {live_pids!r}")
            if failures:
                raise AssertionError("; ".join(failures) + "; evidence=" + json.dumps(result, sort_keys=True))
        finally:
            if capture is not None:
                gate.stop_default_egress_capture(capture, capture_stop, capture_thread)
            (temp / "stop").write_text("stop")
            if peer.poll() is None:
                try: peer.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try: os.killpg(peer.pid, signal.SIGTERM)
                    except ProcessLookupError: pass
                    try: peer.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        try: os.killpg(peer.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                        peer.wait(timeout=2)


class WatchdogDeadlineNamespaceTest(unittest.TestCase):
    def test_real_40s_deadline_precedes_45s_service_timeout_and_closes_gates(self):
        if platform.system() != "Linux":
            self.skipTest("watchdog backend deadline wire requires Linux")
        required = ("unshare", "nsenter", "ip", "nft", "openssl", "bash", "jq", "timeout")
        missing = [name for name in required if shutil.which(name) is None]
        if missing:
            self.skipTest("missing watchdog namespace tools: " + ", ".join(missing))
        if sha256(INSTALLER) != INSTALLER_SHA:
            self.fail("frozen installer SHA mismatch")
        host_before = _host_snapshot()
        capability = subprocess.run(["unshare", "--net", "true"], check=False,
                                    capture_output=True, text=True)
        if capability.returncode:
            self.skipTest("private network namespace unavailable: " + capability.stderr.strip())
        outer = subprocess.Popen(["unshare", "--net", "--mount", "--propagation", "private",
                                  "--fork", sys.executable, str(Path(__file__).resolve()), "--inner",
                                  "--installer-sha", INSTALLER_SHA],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                 start_new_session=True)
        try:
            output, _ = outer.communicate(timeout=SERVICE_TIMEOUT_SECONDS + 20)
        except subprocess.TimeoutExpired:
            try: os.killpg(outer.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try: outer.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try: os.killpg(outer.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                outer.wait(timeout=2)
            _assert_host_snapshot(host_before)
            self.fail("outer private watchdog fixture exceeded its bounded 65s cap")
        _assert_host_snapshot(host_before)
        self.assertEqual(outer.returncode, 0, output[-8000:])
        self.assertIn("WATCHDOG_40S_BUDGET_45S_SERVICE", output)
        print(output, end="", flush=True)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--inner", action="store_true")
    parser.add_argument("--installer-sha", default=DEFAULT_INSTALLER_SHA)
    args, unittest_args = parser.parse_known_args()
    INSTALLER_SHA = args.installer_sha
    if args.inner:
        _inner(INSTALLER_SHA)
    else:
        sys.argv = [sys.argv[0], *unittest_args]
        unittest.main()
