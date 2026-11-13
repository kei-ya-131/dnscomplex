#!/usr/bin/env python3
"""Fixed-command host adapter for the profile-health-only publisher.

The production constructor is read-only. Mutations require an explicitly
enabled adapter on the real root filesystem and the host network namespace;
isolated tests must opt in through ``for_test`` with their own runner.
"""
from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable


class HostAdapterError(RuntimeError):
    pass


class Result:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


_ROOT = Path(__file__).resolve().parents[1]
_LAN_SPEC = importlib.util.spec_from_file_location(
    "_profile_health_lan_adapter", _ROOT / "tools/lan_alias_host_adapter.py")
_LAN = importlib.util.module_from_spec(_LAN_SPEC)
sys.modules[_LAN_SPEC.name] = _LAN
_LAN_SPEC.loader.exec_module(_LAN)
_HOT_SPEC = importlib.util.spec_from_file_location(
    "_profile_health_hotdeploy", _ROOT / "tools/profile_health_hotdeploy.py")
_HOT = importlib.util.module_from_spec(_HOT_SPEC)
sys.modules[_HOT_SPEC.name] = _HOT
_HOT_SPEC.loader.exec_module(_HOT)
_NFT_SPEC = importlib.util.spec_from_file_location(
    "_profile_health_nft_delta", _ROOT / "tools/profile_health_nft_delta.py")
_NFT = importlib.util.module_from_spec(_NFT_SPEC)
sys.modules[_NFT_SPEC.name] = _NFT
_NFT_SPEC.loader.exec_module(_NFT)

PROFILES = {
    "ai": {"mark": 929, "table": 301, "priority": 10201,
           "resolver": "104.16.248.249", "device": "ipsec-ai", "set": "ai_probe_vip4",
           "comment": "dnscomplex-ai-dataplane-probe"},
    "cn": {"mark": 1009, "table": 351, "priority": 10251,
           "resolver": "223.6.6.6", "device": "ipsec-cn", "set": "cn_probe_vip4",
           "comment": "dnscomplex-cn-dataplane-probe"},
}
MANAGER_PATH = "/usr/local/sbin/dnscomplex"
INSTALLER_PATH = "/root/install.sh"
NFT_PATH = "/etc/nftables.d/dnscomplex.nft"
PROTECTED_CONFIG = "/etc/sing-box/config.json"
PROOF_PATHS = {name: f"/run/dnscomplex/profile-dataplane-{name}.success"
               for name in PROFILES}
MANAGED_TARGETS = {
    "/root/install.sh", MANAGER_PATH,
    "/usr/local/libexec/dnscomplex-lan-alias",
    "/usr/local/lib/dnscomplex/profile-dataplane-probe.py", NFT_PATH,
}
_MANAGER_PREFIX = "set -euo pipefail\nsource /usr/local/sbin/dnscomplex\nload_config\n"
_SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_BASELINE_INSTALLER_SHA256 = "75e99856d22eda2290184101e741a0594b96ad5b65b47ef6f9c81300a8f73d34"
_BASELINE_MANAGER_SHA256 = "c20e06ebd954e2ec9fea6f255bbbc39d2c68c765b2320c380d322a41cefd49e2"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def profile_dataplane_identity(profile: str, vip: str, sas: str) -> str:
    if profile not in PROFILES or not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", vip):
        raise HostAdapterError("invalid profile/VIP for SA identity")
    try:
        ipaddress.IPv4Address(vip)
    except ValueError as exc:
        raise HostAdapterError("invalid profile VIP for SA identity") from exc
    selected = []
    keep = False
    for line in sas.splitlines():
        if line and not line[0].isspace():
            keep = line.split(None, 1)[0] == f"{profile}:"
        if not keep:
            continue
        fields = line.split()
        if len(fields) >= 4 and fields[0] == f"{profile}:" and re.fullmatch(r"#[0-9]+,", fields[1]):
            if fields[2] == "ESTABLISHED,":
                selected.append(" ".join(fields[:4]))
            elif ", INSTALLED," in line and len(fields) >= 7:
                selected.append(" ".join((fields[0], fields[1], fields[3], fields[4], fields[5], fields[6])))
    if not selected:
        raise HostAdapterError("current IPsec profile has no stable SA identity")
    return _sha((vip + "\n" + "\n".join(selected) + "\n").encode())


def parse_success_proof(profile: str, raw: bytes, *, vip: str, identity: str,
                        now: float, mtime: float, max_age: float = 180.0,
                        minimum_count: int = 2) -> dict:
    if isinstance(minimum_count, bool) or minimum_count not in (1, 2):
        raise HostAdapterError("success proof minimum count must be 1 or 2")
    valid = False
    count = None
    try:
        text = raw.decode("ascii")
        match = re.fullmatch(r"((?:[0-9]{1,3}\.){3}[0-9]{1,3}) ([0-9a-f]{64}) ([12])\n", text)
        if match:
            proof_vip, proof_identity, count_text = match.groups()
            count = int(count_text)
            valid = (profile in PROFILES and proof_vip == vip and
                     proof_identity == identity and count >= minimum_count and
                     0 <= now - mtime <= max_age)
    except (UnicodeDecodeError, ValueError):
        pass
    return {"valid": bool(valid), "vip": vip, "identity": identity,
            "count": count, "proof_bytes": raw}


class ProfileHealthHostAdapter:
    EXECUTABLES = frozenset({"bash", "conntrack", "ip", "nft", "ss", "swanctl",
                             "systemctl", "timeout", "python3"})

    def __init__(self, *, apply: bool = False, fs_root: str | Path = "/",
                 runner: Callable | None = None, _test_only: bool = False):
        self.root = Path(fs_root).resolve()
        self.apply_enabled = bool(apply)
        self._test_only = bool(_test_only)
        if self.root != Path("/") and not self._test_only:
            raise HostAdapterError("private root requires explicit for_test factory")
        if self.apply_enabled and not self._test_only:
            self._guard_production_apply()
        self.runner = runner or self._run_process
        self.readonly = _LAN.LanAliasHostAdapter(
            apply=self.apply_enabled, fs_root=self.root, runner=self.runner,
            require_root=not self._test_only)
        self._last_modes = None
        self._last_vips = None
        self._last_delta = None
        self._owned_state = None
        self._selected_transaction_profiles = ()

    @classmethod
    def for_test(cls, *, fs_root, runner, apply=False):
        if runner is None:
            raise HostAdapterError("test adapter requires an explicit isolated runner")
        return cls(apply=apply, fs_root=fs_root, runner=runner, _test_only=True)

    @staticmethod
    def _guard_production_apply():
        if os.geteuid() != 0:
            raise HostAdapterError("apply requires effective uid 0")
        try:
            self_ns = os.stat("/proc/self/ns/net")
            host_ns = os.stat("/proc/1/ns/net")
        except OSError as exc:
            raise HostAdapterError("cannot prove host network namespace; apply refused") from exc
        if (self_ns.st_dev, self_ns.st_ino) != (host_ns.st_dev, host_ns.st_ino):
            raise HostAdapterError("apply is refused outside the host network namespace")

    @staticmethod
    def _run_process(argv, *, input_text=None, env=None, timeout=15):
        import signal
        safe_env = {"PATH": _SAFE_PATH, "LC_ALL": "C"}
        if env is not None:
            safe_env.update(env)
        process = subprocess.Popen(list(argv), stdin=subprocess.PIPE if input_text is not None else None,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   env=safe_env, start_new_session=True)
        try:
            stdout, stderr = process.communicate(input=input_text,
                                                 timeout=max(0.05, min(float(timeout), 180)))
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                process.kill()
            except PermissionError as group_exc:
                process.kill()
                process.communicate()
                raise HostAdapterError(
                    "timed-out command descendants could not be proven terminated") from group_exc
            time.sleep(0.15)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError as group_exc:
                process.kill()
                process.communicate()
                raise HostAdapterError(
                    "timed-out command descendants could not be proven terminated") from group_exc
            process.communicate()
            raise HostAdapterError(f"bounded command timed out: {argv[0]}") from exc
        return Result(process.returncode, stdout, stderr)

    def _run(self, argv, *, input_text=None, env=None, mutate=False, check=True, timeout=15):
        if not argv or argv[0] not in self.EXECUTABLES:
            raise HostAdapterError("executable outside fixed health-adapter allowlist")
        if mutate and not self.apply_enabled:
            raise HostAdapterError("read-only adapter refuses mutation")
        result = self.runner(tuple(argv), input_text=input_text, env=env, timeout=timeout)
        if check and result.returncode:
            raise HostAdapterError(f"{argv[0]} failed: {result.stderr.strip()}")
        return result

    def _path(self, path):
        allowed = MANAGED_TARGETS | {PROTECTED_CONFIG, "/etc/dnscomplex/config.env"} | set(PROOF_PATHS.values())
        if path not in allowed:
            raise HostAdapterError(f"path outside profile-health read allowlist: {path}")
        target = self.root
        for part in Path(path.lstrip("/")).parts:
            target = target / part
            try:
                if stat.S_ISLNK(target.lstat().st_mode):
                    raise HostAdapterError(f"symlink in profile-health path: {path}")
            except FileNotFoundError:
                pass
        return target

    def _manager_bytes(self):
        installer = self._read_regular(INSTALLER_PATH, required_mode=0o755)
        manager = self._read_regular(MANAGER_PATH, required_mode=0o755)
        extracted = _HOT._extract_heredoc(installer, _HOT.MANAGER_START, "MANAGER", "manager")
        if _sha(extracted) != _sha(manager):
            raise HostAdapterError("installed manager does not match its installer preimage")
        if (_sha(installer), _sha(manager)) not in {
                (_HOT.INSTALLER_SHA256, "406a5c2ced177b59ba062a8f868c27cce4ac4037c5d29a3e995223c2541ea796"),
                (_BASELINE_INSTALLER_SHA256, _BASELINE_MANAGER_SHA256)}:
            raise HostAdapterError("manager runtime is outside the two reviewed source pins")
        return manager

    def _read_regular(self, target, *, required_mode=None):
        path = self._path(target)
        try:
            before = path.lstat()
        except FileNotFoundError as exc:
            raise HostAdapterError(f"required managed file is missing: {target}") from exc
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino) or \
                    (required_mode is not None and stat.S_IMODE(info.st_mode) != required_mode) or \
                    (self.readonly.require_root and info.st_uid != 0):
                raise HostAdapterError(f"managed file type, mode, or owner is invalid: {target}")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                return stream.read()
        finally:
            os.close(fd)

    def _read_proof(self, profile):
        path = self._path(PROOF_PATHS[profile])
        try:
            before = path.lstat()
        except FileNotFoundError:
            raise
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino) or \
                    stat.S_IMODE(info.st_mode) != 0o600 or \
                    (self.readonly.require_root and info.st_uid != 0):
                raise HostAdapterError(f"{profile} success evidence has unsafe type, ownership, or mode")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(256)
            if len(raw) >= 256:
                raise HostAdapterError(f"{profile} success evidence exceeds its size bound")
            return raw, info
        finally:
            os.close(fd)

    def _manager(self, body: str, *, timeout=15, check=True):
        self._manager_bytes()
        env = {"PATH": _SAFE_PATH, "LC_ALL": "C"}
        if self.root != Path("/"):
            env["FS_ROOT"] = str(self.root)
        env.pop("DNSCOMPLEX_RUN_DIR", None)
        env.pop("BASH_ENV", None)
        return self._run(("bash", "-c", _MANAGER_PREFIX + body),
                         timeout=timeout, check=check, env=env)

    def _ensure_apply(self):
        if not self.apply_enabled:
            raise HostAdapterError("read-only adapter refuses mutation")
        if not self._test_only:
            if self.root != Path("/"):
                raise HostAdapterError("production mutation is limited to the real root filesystem")
            self._guard_production_apply()

    def profile_modes(self):
        modes = self.readonly.profile_modes()
        self._last_modes = modes
        return modes

    def current_profile_vips(self):
        modes = self.profile_modes()
        selected = [name for name in ("ai", "cn") if modes[name] == "ipsec"]
        if not selected:
            raise HostAdapterError("no selected IPsec profile has a current VIP")
        sas = self.readonly._sas()
        try:
            all_vips = _LAN.parse_swanctl_vips(sas)
        except HostAdapterError:
            # Xray profiles have no SA section; parse only the selected profiles.
            all_vips = _parse_selected_sas_vips(sas, selected)
        result = {name: all_vips[name] if modes[name] == "ipsec" else "" for name in ("ai", "cn")}
        self._last_vips = result
        return result

    def capture_protected_state(self):
        state = self.readonly.capture_protected_state()
        config_path = self._path(PROTECTED_CONFIG)
        state["singbox_config_sha256"] = _sha(config_path.read_bytes())
        state["singbox_mainpid"] = state["singbox_pid"]
        state["lan_alias_sets"] = self._alias_set_state(self.read_live_nft_json())
        return state

    def verify_protected_state(self, snapshot):
        adjusted = dict(snapshot)
        expected_gates = dict(snapshot["gates"])
        modes = self.profile_modes()
        for profile in self._selected_transaction_profiles:
            expected_gates[f"{profile}4"] = True
            expected_gates[f"{profile}6"] = modes[profile] == "xray"
        adjusted["gates"] = expected_gates
        self.readonly.verify_protected_state(adjusted)
        if _sha(self._path(PROTECTED_CONFIG).read_bytes()) != snapshot["singbox_config_sha256"]:
            raise HostAdapterError("Sing-box config changed during health-only transaction")
        if self._alias_set_state(self.read_live_nft_json()) != snapshot["lan_alias_sets"]:
            raise HostAdapterError("LAN alias source/readiness sets changed during health-only transaction")
        return True

    def verify_service_unchanged(self, snapshot):
        if self.readonly._pid() != snapshot["singbox_mainpid"]:
            raise HostAdapterError("Sing-box MainPID changed during health-only transaction")
        if _sha(self._path(PROTECTED_CONFIG).read_bytes()) != snapshot["singbox_config_sha256"]:
            raise HostAdapterError("Sing-box config changed during health-only transaction")
        if self._alias_set_state(self.read_live_nft_json()) != snapshot["lan_alias_sets"]:
            raise HostAdapterError("LAN alias source/readiness sets changed during health-only transaction")
        return True

    def capture_old_readiness(self, profiles):
        modes = self.profile_modes()
        vips = self.current_profile_vips()
        sas = self.readonly._sas()
        nft = self.read_live_nft_json()
        result = {}
        for profile in profiles:
            vip = vips[profile]
            identity = profile_dataplane_identity(profile, vip, sas)
            gate4 = self.readonly._gate(f"{profile}_ready4", "0.0.0.0")
            gate6 = self.readonly._gate(f"{profile}_ready6", "::")
            gate_open = gate4 and (gate6 if modes[profile] == "xray" else not gate6)
            try:
                raw, info = self._read_proof(profile)
                proof = parse_success_proof(profile, raw, vip=vip, identity=identity,
                                            now=time.time(), mtime=info.st_mtime)
            except FileNotFoundError:
                proof = {"valid": False, "vip": vip, "identity": identity,
                         "count": None, "proof_bytes": None}
            result[profile] = {"open": gate_open, **proof}
        return result

    def check_policy_conflicts(self, profiles):
        self._validate_profiles(profiles)
        modes = self.profile_modes()
        rules = self._ip_rules()
        for profile in profiles:
            if modes[profile] != "ipsec":
                raise HostAdapterError(f"{profile} profile is not selected for IPsec health")
            cfg = PROFILES[profile]
            exact = [rule for rule in rules if _rule_matches(rule, cfg)]
            if len(exact) > 1:
                raise HostAdapterError(f"duplicate {profile} probe policy rule")
            for rule in rules:
                if rule in exact:
                    continue
                if _rule_priority(rule) == cfg["priority"] or _rule_mark(rule) == cfg["mark"]:
                    raise HostAdapterError(f"conflicting {profile} probe policy rule")

    def read_persistent_nft(self):
        return self.readonly.read_persistent_nft()

    def read_live_nft_json(self):
        return self.readonly.read_live_nft_json()

    @staticmethod
    def _alias_set_state(live):
        if not isinstance(live, dict) or not isinstance(live.get("nftables"), list):
            raise HostAdapterError("live nft JSON schema is invalid")
        result = {}
        for name in _LAN.ALIAS_SETS:
            matches = [entry["set"] for entry in live["nftables"]
                       if isinstance(entry, dict) and isinstance(entry.get("set"), dict) and
                       (entry["set"].get("family"), entry["set"].get("table"),
                        entry["set"].get("name")) == ("inet", "dnscomplex", name)]
            if len(matches) > 1:
                raise HostAdapterError(f"LAN alias set is ambiguous: {name}")
            if not matches:
                result[name] = None
                continue
            value = dict(matches[0])
            value.pop("handle", None)
            result[name] = value
        return result

    def check_nft(self, transaction, persistent):
        self.readonly.check_nft(transaction, persistent)

    def stop_health_timer_and_wait(self, timeout_seconds):
        self._ensure_apply()
        timer_active = self._unit_active("dnscomplex-health.timer")
        service_active = self._unit_active("dnscomplex-health.service")
        state = {"timer_was_active": timer_active, "service_was_active": service_active,
                 "service_idle": False}
        try:
            if timer_active:
                stopped = self._run(("systemctl", "stop", "dnscomplex-health.timer"),
                                    mutate=True, check=False)
                if stopped.returncode:
                    return state
            deadline = time.monotonic() + max(0.0, min(float(timeout_seconds), 45.0))
            while True:
                if not self._unit_active("dnscomplex-health.service"):
                    state["service_idle"] = True
                    return state
                if time.monotonic() >= deadline:
                    return state
                time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
        except BaseException as failure:
            if timer_active:
                try:
                    self.restore_health_timer(state)
                except BaseException as restore_failure:
                    raise HostAdapterError(
                        f"health service state polling failed ({failure}); "
                        f"prior timer restore failed ({restore_failure})") from failure
            raise

    def _unit_active(self, unit):
        if unit not in ("dnscomplex-health.timer", "dnscomplex-health.service"):
            raise HostAdapterError("unit outside health timer/service allowlist")
        result = self._run(("systemctl", "is-active", "--quiet", unit), check=False)
        if result.returncode == 0:
            return True
        if result.returncode == 3:
            return False
        raise HostAdapterError(f"cannot prove systemd state for {unit}")

    def restore_health_timer(self, prior_state):
        self._ensure_apply()
        if not isinstance(prior_state, dict):
            raise HostAdapterError("invalid health timer preimage")
        if prior_state.get("timer_was_active") and not self._unit_active("dnscomplex-health.timer"):
            self._run(("systemctl", "start", "dnscomplex-health.timer"), mutate=True)
        if prior_state.get("timer_was_active") and not self._unit_active("dnscomplex-health.timer"):
            raise HostAdapterError("health timer did not restore to its prior active state")

    def close_profile_gates(self, profiles):
        self._require_mutable_profiles(profiles)
        self._selected_transaction_profiles = tuple(profiles)
        for profile in profiles:
            self._manager(f"profile_egress_gate_clear {profile}\n", timeout=10)

    def close_profile_gates_for_rollback(self, profiles):
        self.close_profile_gates(profiles)

    def verify_gates(self, profiles, *, opened):
        self._validate_profiles(profiles)
        modes = self.profile_modes()
        for profile in profiles:
            gate4 = self.readonly._gate(f"{profile}_ready4", "0.0.0.0")
            gate6 = self.readonly._gate(f"{profile}_ready6", "::")
            expected = (bool(opened), bool(opened) and modes[profile] == "xray")
            if (gate4, gate6) != expected:
                raise HostAdapterError(f"{profile} readiness gate state did not verify")

    def capture_owned_state(self):
        self._ensure_apply()
        rules = self._ip_rules()
        owned = {}
        for profile in PROFILES:
            cfg = PROFILES[profile]
            owned[profile] = [dict(item) for item in rules if _rule_matches(item, cfg)]
            if len(owned[profile]) > 1:
                raise HostAdapterError(f"duplicate preexisting {profile} probe policy rules")
        self._owned_state = owned
        return owned

    def publish_candidate_files(self, file_plans):
        self._ensure_apply()
        if not isinstance(file_plans, list) or any(not isinstance(item, dict) for item in file_plans) or \
                {item.get("target") for item in file_plans} != (MANAGED_TARGETS - {NFT_PATH}) or \
                len(file_plans) != len(MANAGED_TARGETS) - 1:
            raise HostAdapterError("candidate code file list differs from the exact allowlist")
        for item in file_plans:
            target = item.get("target")
            if target not in MANAGED_TARGETS - {NFT_PATH}:
                raise HostAdapterError("candidate code target outside fixed allowlist")
            if not isinstance(item.get("candidate_bytes"), bytes) or \
                    item.get("candidate_mode") != _HOT.TARGET_MODES[target] or \
                    item.get("candidate_uid") != 0 or item.get("candidate_gid") != 0:
                raise HostAdapterError(f"candidate bytes or metadata are not approved: {target}")
            path = self._path(target)
            try:
                current = path.read_bytes()
                info = path.stat()
            except FileNotFoundError:
                current, info = None, None
            if (None if current is None else _sha(current)) != item.get("preimage_sha256"):
                raise HostAdapterError(f"candidate preimage changed: {target}")
            meta = (None, None, None) if info is None else (
                stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
            expected = (item.get("preimage_mode"), item.get("preimage_uid"), item.get("preimage_gid"))
            if meta != expected:
                raise HostAdapterError(f"candidate preimage metadata changed: {target}")
            self._atomic_write(target, item["candidate_bytes"], item["candidate_mode"],
                               item["candidate_uid"], item["candidate_gid"])

    def publish_persistent_nft(self, persistent):
        self._ensure_apply()
        path = self._path(NFT_PATH)
        previous = getattr(self.readonly, "persistent_snapshot", None)
        if previous is not None and path.read_bytes() != previous:
            raise HostAdapterError("persistent nft include changed after guarded read")
        info = path.stat()
        self._atomic_write(NFT_PATH, persistent.encode(), stat.S_IMODE(info.st_mode),
                           info.st_uid, info.st_gid)

    def _atomic_write(self, target, data, mode, uid, gid):
        path = self._path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_name(f".{path.name}.profile-health-{os.getpid()}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temp_path, flags, 0o600)
        try:
            os.fchmod(fd, mode)
            if os.geteuid() == 0:
                os.fchown(fd, uid, gid)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            if path.is_symlink():
                raise HostAdapterError(f"write target became symlink: {target}")
            os.replace(temp_path, path)
            dfd = os.open(path.parent, os.O_RDONLY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
        finally:
            try: os.close(fd)
            except OSError: pass

    def apply_probe_nft(self, transaction, undo):
        self._ensure_apply()
        self._run(("nft", "-f", "-"), input_text=transaction + "\n", mutate=True)
        modes = self.profile_modes()
        vips = self._last_vips or self.current_profile_vips()
        self._last_delta = {
            "undo": undo, "transaction": transaction,
            "expected_rules": [
                {"chain": "output", "comment": PROFILES[p]["comment"], "handle": None,
                 "expression": _NFT._expected_rule_text(p)}
                for p in PROFILES if modes[p] == "ipsec" and
                PROFILES[p]["comment"] in transaction],
            "expected_sets": {PROFILES[p]["set"]:
                              ([vips[p]] if modes[p] == "ipsec" and vips[p] else [])
                              for p in PROFILES},
        }

    def sync_probe_policy(self, profile, vip):
        self._require_mutable_profiles((profile,))
        self._valid_vip(vip)
        self._manager(f"sync_ipsec_probe_policy_rule {profile} {vip}\n")
        self._verify_policy_rule(profile, vip)
        self._verify_route_get(profile, vip)
        cfg = PROFILES[profile]
        return {"profile": profile, "verified": True, "priority": cfg["priority"],
                "mark": cfg["mark"], "table": cfg["table"],
                "route_device": cfg["device"], "route_source": vip}

    def sync_probe_vip(self, profile, vip):
        self._require_mutable_profiles((profile,))
        self._valid_vip(vip)
        self._manager(f"sync_ipsec_probe_vip_profile {profile} {vip}\n")
        found = self._set_addresses(PROFILES[profile]["set"])
        if found != [vip]:
            raise HostAdapterError(f"{profile} probe VIP set did not synchronize")
        return {"profile": profile, "verified": True,
                "set": PROFILES[profile]["set"], "vip": vip}

    def clear_old_success_proof(self, profiles):
        self._require_mutable_profiles(profiles)
        for profile in profiles:
            self._manager(f"profile_dataplane_clear_evidence {profile}\n")
            if self._path(PROOF_PATHS[profile]).exists():
                raise HostAdapterError(f"{profile} old dataplane proof still exists")

    def observe(self, profile, vip, timeout_seconds):
        self._validate_profiles((profile,)); self._valid_vip(vip)
        limit = max(0.05, min(float(timeout_seconds), 5.0))
        budget_ms = max(1, int(limit * 1000))
        body = (f"WATCHDOG_DEADLINE_MS=$(( $(monotonic_millis) + {budget_ms} ))\n"
                f"sas=$(timeout --signal=TERM --kill-after=1s \"$(watchdog_timeout_value 5)\" swanctl --list-sas)\n"
                f"profile_dataplane_probe_observe {profile} {vip} \"$sas\"\n"
                f"identity=$(ipsec_profile_dataplane_identity {profile} {vip} \"$sas\")\n"
                f"printf '%s\\n' \"$identity\"\n")
        result = self._manager(body, timeout=limit + 2)
        identity = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        try:
            raw, info = self._read_proof(profile)
        except FileNotFoundError as exc:
            raise HostAdapterError(f"{profile} source observer did not commit evidence") from exc
        proof = parse_success_proof(profile, raw, vip=vip, identity=identity,
                                    now=time.time(), mtime=info.st_mtime,
                                    minimum_count=1)
        if not proof["valid"]:
            raise HostAdapterError(f"{profile} source observer evidence failed strict validation")
        return {"status": "pass", "profile": profile, "vip": vip,
                "identity": identity, "count": proof["count"]}

    def verify_probe_effects(self, profile, vip):
        self._validate_profiles((profile,)); self._valid_vip(vip)
        cfg = PROFILES[profile]
        addresses = self._set_addresses(cfg["set"])
        if addresses != [vip]:
            raise HostAdapterError(f"{profile} probe VIP set mismatch")
        live = self.read_live_nft_json()
        if not self._last_delta:
            raise HostAdapterError("probe NFT delta was not recorded")
        _NFT.verify_applied(live, self._last_delta["expected_rules"],
                            self._last_delta["expected_sets"])
        self._verify_policy_rule(profile, vip)
        self._verify_route_get(profile, vip)
        self.verify_gates((profile,), opened=True)
        packets = _probe_counter_packets(live, cfg["comment"])
        if packets <= 0:
            raise HostAdapterError(f"{profile} probe rule has no observed packets")
        return {"profile": profile, "verified": True, "vip": vip,
                "counter_packets": packets, "route_get": True,
                "readiness_open": True}

    def verify_current_profile_state(self, vips, profiles):
        self._validate_profiles(profiles)
        if self.current_profile_vips() != vips:
            return {"vips": self.current_profile_vips(), "ready": False}
        body = ["sas=$(timeout --signal=TERM --kill-after=1s 5s swanctl --list-sas)"]
        for profile in profiles:
            body.extend((f"ipsec_profile_runtime_ready {profile} \"$sas\"",
                         f"ipsec_nat_profile_matches {profile} {vips[profile]}",
                         f"ipsec_bind_profile_matches {profile} {vips[profile]}"))
        try:
            self._manager("\n".join(body) + "\nprintf 'READY\\n'\n")
            self.verify_gates(profiles, opened=False)
        except (HostAdapterError, _LAN.HostAdapterError):
            return {"vips": self.current_profile_vips(), "ready": False}
        if self.current_profile_vips() != vips:
            return {"vips": self.current_profile_vips(), "ready": False}
        return {"vips": dict(vips), "ready": True}

    def verify_rollback(self, snapshot):
        adjusted = dict(snapshot)
        expected_gates = dict(snapshot["gates"])
        for profile in self._selected_transaction_profiles:
            expected_gates[f"{profile}4"] = False
            expected_gates[f"{profile}6"] = False
        adjusted["gates"] = expected_gates
        closed_sets = {f"{profile}_ready{family}"
                       for profile in self._selected_transaction_profiles
                       for family in ("4", "6")}
        expected_sets = {}
        for name, state in snapshot["sets"].items():
            if name in closed_sets:
                closed = dict(state)
                closed["elements"] = {}
                expected_sets[name] = closed
            else:
                expected_sets[name] = state
        adjusted["sets"] = expected_sets
        self.readonly.verify_protected_state(adjusted)
        if _sha(self._path(PROTECTED_CONFIG).read_bytes()) != snapshot["singbox_config_sha256"]:
            raise HostAdapterError("Sing-box config changed during health rollback")
        if self._alias_set_state(self.read_live_nft_json()) != snapshot["lan_alias_sets"]:
            raise HostAdapterError("LAN alias sets changed during health rollback")

    def undo_probe_policy(self, profiles, owned_state):
        self._require_mutable_profiles(profiles)
        if not isinstance(owned_state, dict):
            raise HostAdapterError("missing exact probe policy preimage")
        rules = self._ip_rules()
        for profile in profiles:
            cfg = PROFILES[profile]
            before = owned_state.get(profile)
            if not isinstance(before, list) or len(before) > 1:
                raise HostAdapterError(f"invalid {profile} probe policy preimage")
            matching = [rule for rule in rules if _rule_matches(rule, cfg)]
            if before:
                if matching != before:
                    raise HostAdapterError(f"preexisting {profile} probe policy rule changed")
                continue
            if len(matching) > 1:
                raise HostAdapterError(f"ambiguous owned {profile} probe policy rule")
            if matching:
                self._run(("ip", "rule", "del", "fwmark", str(cfg["mark"]),
                           "table", str(cfg["table"]), "priority", str(cfg["priority"])), mutate=True)
        after = self._ip_rules()
        for profile in profiles:
            cfg = PROFILES[profile]
            if owned_state[profile]:
                if [rule for rule in after if _rule_matches(rule, cfg)] != owned_state[profile]:
                    raise HostAdapterError(f"preexisting {profile} policy rule failed restore verification")
            elif any(_rule_matches(rule, cfg) for rule in after):
                raise HostAdapterError(f"owned {profile} policy rule remains after undo")

    def undo_probe_nft(self, undo):
        self._ensure_apply()
        fresh = self.read_live_nft_json()
        _output, live_sets, rules_by_chain = _NFT._live_inventory(fresh)
        set_names = {item["set"] for item in PROFILES.values()}
        rule_comments = {item["comment"] for item in PROFILES.values()}
        found_sets = {entry.get("name") for entry in live_sets if entry.get("name") in set_names}
        found_comments = {rule.get("comment") for chain in rules_by_chain.values() for rule in chain
                          if rule.get("comment") in rule_comments}
        if not found_sets and not found_comments:
            return
        transaction = _NFT.build_undo(fresh, {"undo": undo})
        if transaction:
            self._run(("nft", "-f", "-"),
                      input_text="\n".join(transaction) + "\n", mutate=True)
            after = self.read_live_nft_json()
            _output, sets_after, rules_after = _NFT._live_inventory(after)
            owned_names = {item["set"] for item in PROFILES.values()}
            owned_comments = {item["comment"] for item in PROFILES.values()}
            if any(entry.get("name") in owned_names for entry in sets_after) or any(
                    rule.get("comment") in owned_comments
                    for rows in rules_after.values() for rule in rows):
                raise HostAdapterError("owned profile probe NFT assets remain after exact undo")

    def restore_preimages(self, backup):
        self._ensure_apply()
        if not isinstance(backup, dict) or not isinstance(backup.get("backup_dir"), str):
            raise HostAdapterError("invalid private preimage backup descriptor")
        manifest = backup.get("manifest")
        if not isinstance(manifest, dict) or manifest.get("version") != 1 or \
                not isinstance(manifest.get("files"), list):
            raise HostAdapterError("backup descriptor has no verified manifest")
        backup_dir = Path(backup["backup_dir"])
        try:
            backup_info = backup_dir.lstat()
        except OSError as exc:
            raise HostAdapterError("private rollback backup is unavailable") from exc
        if not stat.S_ISDIR(backup_info.st_mode) or stat.S_IMODE(backup_info.st_mode) != 0o700 or \
                backup_info.st_uid != os.geteuid():
            raise HostAdapterError("private rollback backup ownership or mode is unsafe")
        if {record.get("target") for record in manifest["files"] if isinstance(record, dict)} != MANAGED_TARGETS or \
                len(manifest["files"]) != len(MANAGED_TARGETS):
            raise HostAdapterError("backup manifest differs from the exact target allowlist")
        for record in manifest["files"]:
            target = record.get("target") if isinstance(record, dict) else None
            if target not in MANAGED_TARGETS:
                raise HostAdapterError("backup target outside the exact allowlist")
            path = self._path(target)
            if record.get("preimage_exists"):
                payload_name = record.get("backup_payload")
                if not isinstance(payload_name, str) or not re.fullmatch(r"payload/[0-9]{4}", payload_name):
                    raise HostAdapterError("backup payload path is invalid")
                payload = backup_dir / payload_name
                raw = payload.read_bytes()
                if _sha(raw) != record.get("preimage_sha256"):
                    raise HostAdapterError("backup payload digest mismatch")
                self._atomic_write(target, raw, record["preimage_mode"],
                                   record["preimage_uid"], record["preimage_gid"])
            else:
                if path.is_symlink():
                    raise HostAdapterError("rollback target became a symlink")
                path.unlink(missing_ok=True)
            self._verify_file_preimage(path, record)

    @staticmethod
    def _verify_file_preimage(path, record):
        if not record["preimage_exists"]:
            if path.exists():
                raise HostAdapterError("absent preimage was not restored")
            return
        info = path.stat()
        if _sha(path.read_bytes()) != record["preimage_sha256"] or \
                (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) != (
                    record["preimage_mode"], record["preimage_uid"], record["preimage_gid"]):
            raise HostAdapterError("file preimage bytes or metadata failed restore verification")

    def _ip_rules(self):
        try:
            data = json.loads(self._run(("ip", "-j", "rule", "show")).stdout)
        except json.JSONDecodeError as exc:
            raise HostAdapterError("ip rule JSON is invalid") from exc
        if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
            raise HostAdapterError("ip rule JSON schema is invalid")
        return data

    def _verify_policy_rule(self, profile, vip):
        cfg = PROFILES[profile]
        matches = [rule for rule in self._ip_rules() if _rule_matches(rule, cfg)]
        if len(matches) != 1:
            raise HostAdapterError(f"{profile} probe policy rule failed exact readback")
        route = self._run(("ip", "-4", "route", "show", "table", str(cfg["table"]))).stdout
        if not _default_route_matches(route, cfg["device"], vip):
            raise HostAdapterError(f"{profile} probe table route does not use current VIP and XFRM device")

    def _verify_route_get(self, profile, vip):
        cfg = PROFILES[profile]
        output = self._run(("ip", "-j", "-4", "route", "get", cfg["resolver"], "from", vip,
                            "mark", str(cfg["mark"]))).stdout
        if not _route_get_matches(output, cfg["device"], vip, cfg["table"],
                                  cfg["mark"], cfg["resolver"]):
            raise HostAdapterError(f"{profile} probe route-get did not select current XFRM path")

    def _set_addresses(self, name):
        data = self._run(("nft", "-j", "list", "set", "inet", "dnscomplex", name)).stdout
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as exc:
            raise HostAdapterError(f"{name} nft JSON is invalid") from exc
        return _LAN._set_elems(parsed, name)

    def _require_mutable_profiles(self, profiles):
        self._ensure_apply(); self._validate_profiles(profiles)
        modes = self.profile_modes()
        if any(modes[name] != "ipsec" for name in profiles):
            raise HostAdapterError("profile health mutations are limited to selected IPsec profiles")

    @staticmethod
    def _validate_profiles(profiles):
        if not isinstance(profiles, (tuple, list)) or not profiles or any(p not in PROFILES for p in profiles):
            raise HostAdapterError("invalid selected profile list")

    @staticmethod
    def _valid_vip(vip):
        try:
            address = ipaddress.IPv4Address(vip)
        except (ValueError, TypeError) as exc:
            raise HostAdapterError("invalid IPv4 VIP") from exc
        if str(address) != vip or address.is_unspecified or address.is_loopback or address.is_multicast:
            raise HostAdapterError("invalid IPv4 VIP")


def _parse_selected_sas_vips(text, selected):
    result = {}
    profile = None
    established = installed = False
    locals_ = []

    def flush():
        if profile in selected and established and installed:
            candidates = set()
            for value in locals_:
                try:
                    address = ipaddress.ip_address(value)
                    if address.version == 4 and not (address.is_unspecified or address.is_loopback or
                            address.is_multicast or address.is_link_local):
                        candidates.add(str(address))
                except ValueError:
                    pass
            if len(candidates) == 1:
                result[profile] = candidates.pop()

    for line in text.splitlines():
        if line and not line[0].isspace():
            flush(); profile = None; established = installed = False; locals_ = []
            match = re.match(r"^(ai|cn):\s+#\d+,\s+ESTABLISHED(?:,|\s|$)", line)
            if match:
                profile, established = match[1], True
        elif profile:
            if re.match(rf"^\s+{profile}:\s+#\d+.*?,\s+INSTALLED(?:,|\s|$)", line):
                installed = True
            if re.match(r"^\s+local(?:\s|$)", line):
                locals_.extend(re.findall(r"\[([^][]+)\]", line))
    flush()
    if any(profile not in result for profile in selected):
        raise HostAdapterError("selected IPsec profiles need one established installed IPv4 VIP")
    return result


def _rule_matches(rule, cfg):
    if not isinstance(rule, dict): return False
    if set(rule) - {"priority", "fwmark", "mark", "table", "protocol", "src", "dst"}:
        return False
    if any(rule.get(key, "all") != "all" for key in ("src", "dst")):
        return False
    priority = rule.get("priority")
    raw_mark = rule.get("fwmark", rule.get("mark"))
    mark = _rule_mark(rule)
    table = rule.get("table")
    try:
        mask = str(raw_mark).split("/", 1)[1] if isinstance(raw_mark, str) and "/" in raw_mark else "0xffffffff"
        return int(priority) == cfg["priority"] and int(mark) == cfg["mark"] and \
            int(table) == cfg["table"] and int(mask, 0) == 0xFFFFFFFF
    except (TypeError, ValueError):
        return False


def _rule_priority(rule):
    try: return int(rule.get("priority"))
    except (AttributeError, TypeError, ValueError): return None


def _rule_mark(rule):
    if not isinstance(rule, dict): return None
    value = rule.get("fwmark", rule.get("mark"))
    if value is None: return None
    try:
        return int(str(value).split("/", 1)[0], 0)
    except ValueError:
        return None


def _default_route_matches(text, device, vip):
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] != "default": continue
        values = dict(zip(fields[1::2], fields[2::2]))
        if values.get("dev") == device and values.get("src") == vip:
            return True
    return False


def _route_get_matches(text, device, vip, table, mark, destination):
    try:
        rows = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        return False
    row = rows[0]
    try:
        actual_table = int(row.get("table"))
        actual_mark = row.get("mark")
        actual_mark = int(str(actual_mark), 0) if isinstance(actual_mark, str) else int(actual_mark)
    except (TypeError, ValueError):
        return False
    return row.get("dst") == destination and row.get("from") == vip and row.get("dev") == device and \
        actual_table == table and actual_mark == mark


def _probe_counter_packets(live, comment):
    if not isinstance(live, dict) or not isinstance(live.get("nftables"), list):
        raise HostAdapterError("live nft JSON schema is invalid")
    matches = []
    for item in live["nftables"]:
        rule = item.get("rule") if isinstance(item, dict) else None
        if isinstance(rule, dict) and rule.get("comment") == comment:
            expr = rule.get("expr", [])
            counters = [node.get("counter") for node in expr
                        if isinstance(node, dict) and isinstance(node.get("counter"), dict)]
            if len(counters) != 1:
                raise HostAdapterError("probe rule counter is missing or ambiguous")
            packets = counters[0].get("packets")
            if isinstance(packets, bool) or not isinstance(packets, int) or packets < 0:
                raise HostAdapterError("probe rule counter value is malformed")
            if packets == 0:
                raise HostAdapterError("probe rule has not observed any packets")
            matches.append(packets)
    if len(matches) != 1:
        raise HostAdapterError("probe rule comment is missing or ambiguous")
    return matches[0]


if __name__ == "__main__":
    raise SystemExit("profile-health host adapter has no CLI")
