#!/usr/bin/env python3
"""Review and transactionally publish the profile data-plane health assets.

The CLI is preview-only. Mutations are available only through ``apply_candidate``
with an explicit adapter supplied by a separately reviewed caller. The function
never restarts sing-box, reloads the nft table, flushes conntrack, or initiates
IPsec SAs.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class HealthHotdeployError(RuntimeError):
    """Candidate or host state cannot be proven safe for health-only publish."""


INSTALLER_SHA256 = "856be53885775e98076a0a6e2611e2de27028970d7cde3bb3b714def77a5896f"
PROBE_SHA256 = "d74f866c368ddc31dd0e71bb39cb92afb566d5b24e7941687482bcbc100f4ba1"
TARGETS = (
    "/root/install.sh",
    "/usr/local/sbin/dnscomplex",
    "/usr/local/libexec/dnscomplex-lan-alias",
    "/usr/local/lib/dnscomplex/profile-dataplane-probe.py",
    "/etc/nftables.d/dnscomplex.nft",
)
TARGET_MODES = {
    "/root/install.sh": 0o755,
    "/usr/local/sbin/dnscomplex": 0o755,
    "/usr/local/libexec/dnscomplex-lan-alias": 0o755,
    "/usr/local/lib/dnscomplex/profile-dataplane-probe.py": 0o755,
    "/etc/nftables.d/dnscomplex.nft": 0o644,
}
MANAGER_START = "write_file_atomic /usr/local/sbin/dnscomplex <<'MANAGER'"
LAN_HELPER_START = "write_file /usr/local/libexec/dnscomplex-lan-alias <<'LAN_ALIAS'"
MAX_TRANSACTION_SECONDS = 180.0
TIMER_WAIT_SECONDS = 45.0
MAX_OBSERVATION_SECONDS = 5.0
_DELTA = None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HealthHotdeployError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_delta():
    global _DELTA
    if _DELTA is None:
        path = Path(__file__).resolve().with_name("profile_health_nft_delta.py")
        spec = importlib.util.spec_from_file_location("_profile_health_nft_delta", path)
        if spec is None or spec.loader is None:
            raise HealthHotdeployError("cannot load profile health nft delta compiler")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _DELTA = module
    return _DELTA


def _target_path(root: Path, target: str) -> Path:
    if target not in TARGETS:
        raise HealthHotdeployError(f"target is outside the exact health asset allowlist: {target!r}")
    path = root
    for part in Path(target.lstrip("/")).parts:
        path = path / part
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise HealthHotdeployError(f"target path contains a symlink: {target}")
    return path


def _file_snapshot(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"exists": False, "sha256": None, "mode": None,
                "uid": None, "gid": None, "bytes": None}
    if not stat.S_ISREG(info.st_mode):
        raise HealthHotdeployError(f"target is not a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise HealthHotdeployError(f"target changed while opening: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            content = stream.read()
    finally:
        os.close(fd)
    return {"exists": True, "sha256": _sha(content), "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid, "gid": info.st_gid, "bytes": content}


def _extract_heredoc(source: bytes, marker: str, end: str, label: str) -> bytes:
    try:
        lines = source.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise HealthHotdeployError("candidate installer is not UTF-8") from exc
    starts = [index for index, line in enumerate(lines) if line.strip() == marker]
    if len(starts) != 1:
        raise HealthHotdeployError(f"candidate installer must contain one {label} asset")
    start = starts[0] + 1
    stops = [index for index in range(start, len(lines)) if lines[index].strip() == end]
    if not stops:
        raise HealthHotdeployError(f"candidate installer {label} asset is unterminated")
    value = "".join(lines[start:stops[0]]).encode("utf-8")
    if not value.endswith(b"\n"):
        raise HealthHotdeployError(f"candidate installer {label} asset is incomplete")
    return value


def _validate_modes(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"ai", "cn"}:
        raise HealthHotdeployError("profile_modes must contain exactly ai and cn")
    if any(value[name] not in ("ipsec", "xray") for name in ("ai", "cn")):
        raise HealthHotdeployError("profile_modes contains an unsupported egress mode")
    if not any(value[name] == "ipsec" for name in ("ai", "cn")):
        raise HealthHotdeployError("health publish requires at least one selected IPsec profile")
    return dict(value)


def _validate_vips(value: Any, modes: dict[str, str]) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"ai", "cn"}:
        raise HealthHotdeployError("profile_vips must contain exactly ai and cn")
    result = {}
    for profile in ("ai", "cn"):
        vip = value[profile]
        if not isinstance(vip, str):
            raise HealthHotdeployError(f"{profile} profile VIP must be a string")
        if modes[profile] == "ipsec" and not vip:
            raise HealthHotdeployError(f"selected {profile} IPsec profile has no current VIP")
        result[profile] = vip
    selected = [result[p] for p in ("ai", "cn") if modes[p] == "ipsec"]
    if len(selected) == 2 and selected[0] == selected[1]:
        raise HealthHotdeployError("selected IPsec profiles must have distinct current VIPs")
    return result


def _decode_bundle(bundle_bytes: bytes, expected_sha256: str) -> dict[str, Any]:
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or \
            _sha(bundle_bytes) != expected_sha256:
        raise HealthHotdeployError("health bundle SHA256 does not match reviewed digest")
    try:
        bundle = json.loads(bundle_bytes, object_pairs_hook=_json_no_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HealthHotdeployError("health bundle is not valid UTF-8 JSON") from exc
    if not isinstance(bundle, dict) or set(bundle) != {"version", "installer_sha256", "files", "nft"} or \
            bundle.get("version") != 1:
        raise HealthHotdeployError("unsupported health bundle schema")
    if bundle.get("installer_sha256") != INSTALLER_SHA256:
        raise HealthHotdeployError("bundle is not pinned to the frozen 856 installer")
    return bundle


def _bundle_files(bundle: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    entries = bundle.get("files")
    if not isinstance(entries, list) or len(entries) != len(TARGETS):
        raise HealthHotdeployError("bundle must include exactly the five reviewed targets")
    by_target = {}
    for item in entries:
        if not isinstance(item, dict) or set(item) != {
                "target", "content_b64", "mode", "uid", "gid", "preimage_sha256",
                "preimage_mode", "preimage_uid", "preimage_gid"}:
            raise HealthHotdeployError("health bundle file entry has an unsupported schema")
        target = item["target"]
        if target not in TARGET_MODES or target in by_target:
            raise HealthHotdeployError(f"duplicate or foreign target: {target!r}")
        if item["mode"] != TARGET_MODES[target] or \
                isinstance(item["uid"], bool) or item["uid"] != 0 or \
                isinstance(item["gid"], bool) or item["gid"] != 0:
            raise HealthHotdeployError(f"candidate ownership or mode is not approved for {target}")
        preimage = item["preimage_sha256"]
        if preimage is not None and (not isinstance(preimage, str) or
                                     not re.fullmatch(r"[0-9a-f]{64}", preimage)):
            raise HealthHotdeployError(f"invalid preimage digest for {target}")
        try:
            content = base64.b64decode(item["content_b64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise HealthHotdeployError(f"invalid base64 content for {target}") from exc
        path = _target_path(root, target)
        snapshot = _file_snapshot(path)
        if snapshot["sha256"] != preimage:
            raise HealthHotdeployError(f"target preimage changed: {target}")
        expected_metadata = (item["preimage_mode"], item["preimage_uid"], item["preimage_gid"])
        actual_metadata = (snapshot["mode"], snapshot["uid"], snapshot["gid"])
        if expected_metadata != actual_metadata:
            raise HealthHotdeployError(f"target preimage metadata changed: {target}")
        by_target[target] = {
            "target": target, "candidate_bytes": content,
            "candidate_sha256": _sha(content), "candidate_mode": item["mode"],
            "candidate_uid": item["uid"], "candidate_gid": item["gid"],
            "preimage_sha256": preimage, "preimage_exists": snapshot["exists"],
            "preimage_mode": snapshot["mode"], "preimage_uid": snapshot["uid"],
            "preimage_gid": snapshot["gid"], "_preimage_bytes": snapshot["bytes"],
        }
    if set(by_target) != set(TARGETS):
        raise HealthHotdeployError("bundle target set differs from the reviewed allowlist")
    files = [by_target[target] for target in TARGETS]
    content = {item["target"]: item["candidate_bytes"] for item in files}
    installer = content["/root/install.sh"]
    if _sha(installer) != INSTALLER_SHA256:
        raise HealthHotdeployError("candidate installer bytes do not match the frozen 856 pin")
    if _extract_heredoc(installer, MANAGER_START, "MANAGER", "manager") != content["/usr/local/sbin/dnscomplex"]:
        raise HealthHotdeployError("candidate manager does not match the pinned installer")
    if _extract_heredoc(installer, LAN_HELPER_START, "LAN_ALIAS", "LAN alias helper") != \
            content["/usr/local/libexec/dnscomplex-lan-alias"]:
        raise HealthHotdeployError("candidate LAN helper does not match the pinned installer")
    probe_hashes = re.findall(rb'^PROFILE_DATAPLANE_PROBE_SHA256="([0-9a-f]{64})"$', installer, re.M)
    if len(probe_hashes) != 1 or probe_hashes[0].decode() != PROBE_SHA256 or \
            _sha(content["/usr/local/lib/dnscomplex/profile-dataplane-probe.py"]) != PROBE_SHA256:
        raise HealthHotdeployError("candidate probe helper does not match the frozen d74 asset pin")
    return files


def _compile(bundle: dict[str, Any], files: list[dict[str, Any]], *, live_json: Any,
             persistent_text: str, profile_modes: dict[str, str], profile_vips: dict[str, str],
             compare_vip_snapshot: bool = True):
    nft = bundle.get("nft")
    if not isinstance(nft, dict) or set(nft) != {
            "candidate_renderer", "preview_live_json", "profile_modes", "profile_vips"}:
        raise HealthHotdeployError("NFT candidate has an unsupported schema")
    renderer = nft.get("candidate_renderer")
    if not isinstance(renderer, str) or not renderer.strip():
        raise HealthHotdeployError("bundle has no full candidate nft renderer")
    if _validate_modes(nft.get("profile_modes")) != profile_modes:
        raise HealthHotdeployError("bundle profile modes differ from current strict config")
    pinned_vips = _validate_vips(nft.get("profile_vips"), profile_modes)
    if compare_vip_snapshot and pinned_vips != profile_vips:
        raise HealthHotdeployError("bundle profile VIP snapshot differs from preview snapshot")
    try:
        compiled = _load_delta().compile_delta(
            live_json, persistent_text, renderer, INSTALLER_SHA256,
            profile_modes, profile_vips)
    except Exception as exc:
        raise HealthHotdeployError(f"fresh profile health NFT plan is unsafe: {exc}") from exc
    nft_file = next(item for item in files if item["target"] == "/etc/nftables.d/dnscomplex.nft")
    if compiled["persistent"].encode("utf-8") != nft_file["candidate_bytes"]:
        raise HealthHotdeployError("candidate persistent NFT include differs from exact compiler merge")
    return compiled


def build_preview(bundle_bytes: bytes, expected_sha256: str, *, fs_root: Path | str = "/") -> dict[str, Any]:
    """Verify a frozen asset bundle and its offline NFT candidate without writes."""
    bundle = _decode_bundle(bundle_bytes, expected_sha256)
    root = Path(fs_root).resolve()
    files = _bundle_files(bundle, root)
    modes = _validate_modes(bundle["nft"].get("profile_modes") if isinstance(bundle["nft"], dict) else None)
    vips = _validate_vips(bundle["nft"].get("profile_vips") if isinstance(bundle["nft"], dict) else None, modes)
    nft_preimage = next(item for item in files if item["target"] == "/etc/nftables.d/dnscomplex.nft")
    if not nft_preimage["preimage_exists"] or nft_preimage["_preimage_bytes"] is None:
        raise HealthHotdeployError("existing persistent dnscomplex nft include is required")
    try:
        persistent = nft_preimage["_preimage_bytes"].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HealthHotdeployError("persistent nft preimage is not UTF-8") from exc
    compiled = _compile(bundle, files, live_json=bundle["nft"]["preview_live_json"],
                        persistent_text=persistent, profile_modes=modes, profile_vips=vips)
    return {"bundle_sha256": expected_sha256, "installer_sha256": INSTALLER_SHA256,
            "profile_modes": modes, "profile_vips": vips, "files": files,
            "compiled": compiled}


def create_backup(bundle_bytes: bytes, expected_sha256: str, *, fs_root: Path | str = "/",
                  backup_parent: Path | str) -> dict[str, Any]:
    """Store exact file preimages and ownership metadata in a private backup."""
    preview = build_preview(bundle_bytes, expected_sha256, fs_root=fs_root)
    parent = Path(backup_parent)
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not stat.S_ISDIR(parent.lstat().st_mode):
        raise HealthHotdeployError("backup parent must be a directory")
    parent.chmod(0o700)
    backup = Path(tempfile.mkdtemp(prefix="dnscomplex-profile-health-", dir=parent))
    backup.chmod(0o700)
    try:
        payload_dir = backup / "payload"
        payload_dir.mkdir(mode=0o700)
        records = []
        for index, item in enumerate(preview["files"]):
            record = {key: item[key] for key in (
                "target", "preimage_exists", "preimage_sha256", "preimage_mode",
                "preimage_uid", "preimage_gid")}
            if item["preimage_exists"]:
                payload = payload_dir / f"{index:04d}"
                fd = os.open(payload, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(item["_preimage_bytes"])
                    stream.flush()
                    os.fsync(stream.fileno())
                record["backup_payload"] = f"payload/{index:04d}"
            else:
                record["backup_payload"] = None
            records.append(record)
        manifest = {"version": 1, "bundle_sha256": expected_sha256,
                    "files": records, "nft_undo": preview["compiled"]["undo"]}
        data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = backup / ".manifest.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, backup / "manifest.json")
        fd = os.open(backup, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return {"backup_dir": str(backup), "manifest_sha256": _sha(data), "manifest": manifest}
    except Exception as exc:
        shutil.rmtree(backup, ignore_errors=True)
        if isinstance(exc, HealthHotdeployError):
            raise
        raise HealthHotdeployError(f"private preimage backup failed: {exc}") from exc


@contextmanager
def maintenance_lock(path: Path | str) -> Iterator[None]:
    lock = Path(path)
    lock.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise HealthHotdeployError("maintenance lock is not a regular file")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise HealthHotdeployError("another dnscomplex maintenance operation holds the lock") from exc
        yield
    finally:
        os.close(fd)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise HealthHotdeployError("profile health observation exceeded the shared 180-second deadline")
    return remaining


def _selected_profiles(modes: dict[str, str]) -> list[str]:
    return [profile for profile in ("ai", "cn") if modes[profile] == "ipsec"]


def _verify_result(result: Any, profile: str, vip: str, expected_identity: str | None,
                   expected_count: int) -> str:
    if not isinstance(result, dict) or result.get("status") != "pass" or \
            result.get("profile") != profile or result.get("vip") != vip or \
            result.get("count") != expected_count:
        raise HealthHotdeployError(f"{profile} observer did not produce successful pass {expected_count}")
    identity = result.get("identity")
    if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{64}", identity):
        raise HealthHotdeployError(f"{profile} observer returned an invalid stable SA identity")
    if expected_identity is not None and identity != expected_identity:
        raise HealthHotdeployError(f"{profile} SA identity changed between successful observations")
    return identity


def _verify_policy_sync(result: Any, profile: str, vip: str) -> None:
    expected = {"ai": (10201, 929, 301), "cn": (10251, 1009, 351)}[profile]
    if not isinstance(result, dict) or result.get("verified") is not True or \
            result.get("profile") != profile or result.get("priority") != expected[0] or \
            result.get("mark") != expected[1] or result.get("table") != expected[2] or \
            result.get("route_device") != "ipsec-" + profile or result.get("route_source") != vip:
        raise HealthHotdeployError(f"{profile} probe policy rule/current route did not verify exactly")


def _verify_probe_vip_sync(result: Any, profile: str, vip: str) -> None:
    if not isinstance(result, dict) or result.get("verified") is not True or \
            result.get("profile") != profile or result.get("set") != profile + "_probe_vip4" or \
            result.get("vip") != vip:
        raise HealthHotdeployError(f"{profile} probe VIP set did not verify as the exact singleton")


def _verify_probe_effects(result: Any, profile: str, vip: str) -> None:
    count = result.get("counter_packets") if isinstance(result, dict) else None
    if not isinstance(result, dict) or result.get("verified") is not True or \
            result.get("profile") != profile or result.get("vip") != vip or \
            isinstance(count, bool) or not isinstance(count, int) or count < 1 or \
            result.get("route_get") is not True or result.get("readiness_open") is not True:
        raise HealthHotdeployError(f"{profile} probe counter, route, or readiness readback did not verify")


def _classify_nft_delta(live_json: Any, compiled: dict[str, Any]) -> str:
    """Classify a possibly ambiguous atomic nft batch as absent, complete, or partial."""
    delta = _load_delta()
    data = delta._nft_json(live_json)
    _output, sets, rules_by_chain = delta._live_inventory(data)
    owned_set_names = {item["set"] for item in delta.PROFILES.values()}
    owned_comments = {item["comment"] for item in delta.PROFILES.values()}
    present_sets = [entry for entry in sets if entry.get("name") in owned_set_names]
    present_comments = [rule.get("comment")
                        for rows in rules_by_chain.values() for rule in rows
                        if rule.get("comment") in owned_comments]
    if not present_sets and not present_comments:
        return "absent"
    try:
        delta.verify_applied(live_json, compiled["expected_rules"], compiled["expected_sets"])
    except Exception:
        return "partial"
    return "complete"


def _apply_candidate_locked(bundle_bytes: bytes, expected_sha256: str, *, adapter,
                    fs_root: Path | str = "/", backup_parent: Path | str,
                    lock_path: Path | str = "/run/lock/dnscomplex-maintenance.lock") -> dict[str, Any]:
    """Apply through an explicit reviewed adapter; no built-in host mutator exists."""
    with maintenance_lock(lock_path):
        preview = build_preview(bundle_bytes, expected_sha256, fs_root=fs_root)
        bundle = _decode_bundle(bundle_bytes, expected_sha256)
        modes = _validate_modes(adapter.profile_modes())
        if modes != preview["profile_modes"]:
            raise HealthHotdeployError("current profile modes changed after bundle preview")
        profiles = _selected_profiles(modes)
        protected = adapter.capture_protected_state()
        old_vips = adapter.current_profile_vips()
        old_vips = _validate_vips(old_vips, modes)
        adapter.check_policy_conflicts(profiles)
        persistent = adapter.read_persistent_nft()
        nft_file = next(item for item in preview["files"]
                        if item["target"] == "/etc/nftables.d/dnscomplex.nft")
        if persistent.encode("utf-8") != nft_file["_preimage_bytes"]:
            raise HealthHotdeployError("persistent nft include changed after preview")
        fresh_live = adapter.read_live_nft_json()
        compiled = _compile(bundle, preview["files"], live_json=fresh_live,
                             persistent_text=persistent, profile_modes=modes,
                             profile_vips=old_vips, compare_vip_snapshot=False)
        adapter.check_nft(compiled["transaction"], compiled["persistent"])
        backup = create_backup(bundle_bytes, expected_sha256, fs_root=fs_root,
                               backup_parent=backup_parent)
        timer_state = None
        critical_started = False
        nft_attempted = False
        policy_attempted = False
        files_attempted = False
        owned_state = {}
        try:
            timer_state = adapter.stop_health_timer_and_wait(TIMER_WAIT_SECONDS)
            if not isinstance(timer_state, dict) or timer_state.get("service_idle") is not True:
                raise HealthHotdeployError("health service did not exit within the bounded wait")
            critical_started = True
            adapter.close_profile_gates(profiles)
            adapter.verify_gates(profiles, opened=False)
            owned_state = adapter.capture_owned_state()
            code_files = [item for item in preview["files"]
                          if item["target"] != "/etc/nftables.d/dnscomplex.nft"]
            files_attempted = True
            adapter.publish_candidate_files(code_files)
            adapter.publish_persistent_nft(compiled["persistent"])
            nft_attempted = True
            adapter.apply_probe_nft(compiled["transaction"], compiled["undo"])
            if _classify_nft_delta(adapter.read_live_nft_json(), compiled) != "complete":
                raise HealthHotdeployError("probe NFT batch did not verify as a complete atomic delta")
            for profile in profiles:
                current = adapter.current_profile_vips()
                current = _validate_vips(current, modes)
                if current != old_vips:
                    raise HealthHotdeployError("profile VIP changed during health-only publication")
                policy_attempted = True
                _verify_policy_sync(adapter.sync_probe_policy(profile, current[profile]),
                                    profile, current[profile])
                _verify_probe_vip_sync(adapter.sync_probe_vip(profile, current[profile]),
                                       profile, current[profile])
            adapter.clear_old_success_proof(profiles)
            deadline = time.monotonic() + MAX_TRANSACTION_SECONDS
            for profile in profiles:
                vip = old_vips[profile]
                identity = None
                for count in (1, 2):
                    if _remaining(deadline) <= 0:
                        raise HealthHotdeployError("profile health shared deadline expired")
                    if adapter.current_profile_vips() != old_vips:
                        raise HealthHotdeployError("profile VIP changed during health observation")
                    result = adapter.observe(profile, vip,
                                             timeout_seconds=min(MAX_OBSERVATION_SECONDS, _remaining(deadline)))
                    _remaining(deadline)
                    identity = _verify_result(result, profile, vip, identity, count)
                    if adapter.current_profile_vips() != old_vips:
                        raise HealthHotdeployError("profile VIP changed during health observation")
                    adapter.verify_gates([profile], opened=(count == 2))
                _verify_probe_effects(adapter.verify_probe_effects(profile, vip), profile, vip)
            adapter.verify_gates(profiles, opened=True)
            if adapter.verify_protected_state(protected) is not True:
                raise HealthHotdeployError("protected DNS/conntrack/sing-box state did not verify unchanged")
            if adapter.verify_service_unchanged(protected) is not True:
                raise HealthHotdeployError("sing-box service/config changed during health-only publish")
            adapter.restore_health_timer(timer_state)
            timer_state = None
            return {"bundle_sha256": preview["bundle_sha256"],
                    "backup_dir": backup["backup_dir"], "profiles_verified": profiles,
                    "profile_vips": old_vips, "singbox_restart_count": 0}
        except BaseException as failure:
            rollback_errors = []
            can_rollback = False
            if critical_started:
                try:
                    adapter.close_profile_gates_for_rollback(profiles)
                    adapter.verify_gates(profiles, opened=False)
                    can_rollback = True
                except BaseException as exc:
                    can_rollback = False
                    rollback_errors.append(f"profile gate close: {exc}")
            if can_rollback:
                if policy_attempted:
                    try:
                        adapter.undo_probe_policy(profiles, owned_state)
                    except BaseException as exc:
                        rollback_errors.append(f"owned policy-rule undo: {exc}")
                if nft_attempted:
                    try:
                        nft_state = _classify_nft_delta(adapter.read_live_nft_json(), compiled)
                    except BaseException as exc:
                        nft_state = "unknown"
                        rollback_errors.append(f"probe NFT outcome cannot be classified: {exc}")
                    if nft_state == "complete":
                        try:
                            adapter.undo_probe_nft(compiled["undo"])
                        except BaseException as exc:
                            rollback_errors.append(f"owned nft undo: {exc}")
                    elif nft_state == "partial":
                        rollback_errors.append("probe NFT batch left partial or foreign state; exact undo is unsafe")
                if files_attempted:
                    try:
                        adapter.restore_preimages(backup)
                    except BaseException as exc:
                        rollback_errors.append(f"file preimage restore: {exc}")
                try:
                    current_vips = _validate_vips(adapter.current_profile_vips(), modes)
                    current_state = adapter.verify_current_profile_state(current_vips, profiles)
                    if not isinstance(current_state, dict) or current_state.get("ready") is not True or \
                            current_state.get("vips") != current_vips:
                        raise HealthHotdeployError("current normal profile route/NAT/bind snapshot did not verify")
                    adapter.verify_gates(profiles, opened=False)
                    adapter.verify_rollback(protected)
                except BaseException as exc:
                    rollback_errors.append(f"current profile/readiness remains unverified: {exc}")
                # A failed transaction always leaves selected gates closed. The
                # previous proof belongs to the old publisher epoch and is never
                # used to reopen gates; the restored watchdog must re-observe.
                try:
                    adapter.close_profile_gates_for_rollback(profiles)
                    adapter.verify_gates(profiles, opened=False)
                except BaseException as exc:
                    rollback_errors.append(f"final fail-closed verification: {exc}")
            elif critical_started:
                rollback_errors.append("profile readiness closure could not be proven; rollback halted")
            if timer_state is not None:
                try:
                    adapter.restore_health_timer(timer_state)
                    timer_state = None
                except BaseException as exc:
                    rollback_errors.append(f"health timer restore: {exc}")
            if rollback_errors:
                raise HealthHotdeployError(
                    f"health publish failed ({failure}); rollback incomplete; backup retained at "
                    f"{backup['backup_dir']}: {'; '.join(rollback_errors)}") from failure
            if critical_started:
                detail = "owned preimages were restored and selected gates remain closed for watchdog re-observation"
            else:
                detail = "aborted before profile gates or target assets were changed"
            raise HealthHotdeployError(
                f"health publish failed; {detail}; backup retained at {backup['backup_dir']}: {failure}") from failure



def apply_candidate(bundle_bytes: bytes, expected_sha256: str, *, adapter,
                    fs_root: Path | str = "/", backup_parent: Path | str,
                    lock_path: Path | str = "/run/lock/dnscomplex-maintenance.lock") -> dict[str, Any]:
    """Apply only through an explicit separately reviewed adapter."""
    try:
        return _apply_candidate_locked(bundle_bytes, expected_sha256, adapter=adapter,
                                       fs_root=fs_root, backup_parent=backup_parent,
                                       lock_path=lock_path)
    except HealthHotdeployError:
        raise
    except Exception as exc:
        raise HealthHotdeployError(f"health publisher adapter/preflight failed: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    parser.add_argument("--apply", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.apply:
        parser.error("CLI apply is intentionally unavailable; use a separately reviewed root adapter")
    try:
        raw = args.bundle.read_bytes()
        preview = build_preview(raw, args.sha256, fs_root=args.root)
        print(json.dumps({"mode": "dry-run-preview", "apply": "not requested",
                          "bundle_sha256": preview["bundle_sha256"],
                          "installer_sha256": preview["installer_sha256"],
                          "profiles": preview["profile_modes"],
                          "assets": [{"target": item["target"],
                                      "candidate_sha256": item["candidate_sha256"],
                                      "preimage_sha256": item["preimage_sha256"],
                                      "preimage_mode": item["preimage_mode"],
                                      "preimage_uid": item["preimage_uid"],
                                      "preimage_gid": item["preimage_gid"]}
                                     for item in preview["files"]],
                          "nft_command_count": len([line for line in
                              preview["compiled"]["transaction"].splitlines() if line]),
                          "singbox_restart_count": 0}, sort_keys=True))
        return 0
    except (OSError, HealthHotdeployError) as exc:
        print(f"profile-health-hotdeploy: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
