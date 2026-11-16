#!/usr/bin/env python3
"""Guarded preview and private backup staging for a LAN-alias hotdeploy.

This utility intentionally does not install files, restart sing-box, or mutate
nftables. It verifies a reviewed bundle and target preimages, creates a private
metadata-preserving backup when explicitly requested, and exposes a strict
owned-nft undo planner for a later separately-reviewed apply layer.
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
import shlex
import shutil
import stat
import sys
import tempfile
import ipaddress
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any, Iterator


class HotdeployError(ValueError):
    """Candidate bundle or current host state cannot be proven safe."""


TARGETS = frozenset({
    "/root/install.sh",
    "/usr/local/sbin/dnscomplex",
    "/usr/local/libexec/dnscomplex-lan-alias",
    "/etc/sing-box/config.json",
    "/etc/nftables.d/dnscomplex.nft",
    "/var/lib/dnscomplex/lan-alias.json",
})
ALIAS_PREFIX = "dnscomplex-lan-alias-"
ALIAS_SETS = {
    "lan_alias_source4", "lan_alias_ready4", "lan_alias_config_ready4",
}
ALIAS_CHAINS = {
    "output", "prerouting", "prerouting_policy_restore", "postrouting",
}
ALLOWED_MODES = {0o600, 0o644, 0o700, 0o755}
_DELTA_COMPILER = None


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HotdeployError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _safe_relative_target(root: Path, target: str) -> Path:
    if not isinstance(target, str) or target not in TARGETS:
        raise HotdeployError(f"target is outside the reviewed allowlist: {target!r}")
    path = root / target.lstrip("/")
    current = root
    for component in Path(target.lstrip("/")).parts:
        current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise HotdeployError(f"target path contains a symlink: {target}")
    return path


def _file_snapshot(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"existed": False, "sha256": None, "mode": None,
                "uid": None, "gid": None, "bytes": None}
    if not stat.S_ISREG(info.st_mode):
        raise HotdeployError(f"target is not a regular file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or \
                (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise HotdeployError(f"target changed while opening: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read()
    finally:
        os.close(fd)
    return {"existed": True, "sha256": sha256(data),
            "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
            "gid": info.st_gid, "bytes": data}


def _load_delta_compiler():
    global _DELTA_COMPILER
    if _DELTA_COMPILER is None:
        module_path = Path(__file__).resolve().with_name("lan_alias_nft_delta.py")
        spec = importlib.util.spec_from_file_location("_lan_alias_hotdeploy_delta", module_path)
        if spec is None or spec.loader is None:
            raise HotdeployError("cannot load the reviewed nft delta compiler")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _DELTA_COMPILER = module
    return _DELTA_COMPILER


def _has_top_level_semicolon(line: str) -> bool:
    quoted = False
    escaped = False
    brace_depth = 0
    for char in line:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
        elif char == ";" and brace_depth == 0:
            return True
    return False


def _validate_nft_transaction(transaction: Any, undo: dict[str, Any]) -> list[str]:
    if not isinstance(transaction, str) or not transaction.strip():
        raise HotdeployError("bundle has no additive nft transaction")
    lines = [line.strip() for line in transaction.splitlines() if line.strip()]
    set_names = []
    rule_comments = []
    for line in lines:
        if _has_top_level_semicolon(line):
            raise HotdeployError("nft transaction contains multiple commands on one line")
        if re.match(r"^add set inet dnscomplex\b", line):
            match = re.match(r"^add set inet dnscomplex ([A-Za-z0-9_]+) \{", line)
            if not match or match.group(1) not in ALIAS_SETS:
                raise HotdeployError(f"nft transaction contains a foreign set: {line!r}")
            set_names.append(match.group(1))
        elif re.match(r"^(?:add|insert) rule inet dnscomplex\b", line):
            match = re.match(
                r"^(?:add|insert) rule inet dnscomplex ([A-Za-z0-9_]+)(?: position [0-9]+)?\b",
                line)
            comment_match = re.search(r'\bcomment "([^"]+)"\s*$', line)
            if not match or match.group(1) not in ALIAS_CHAINS or not comment_match or \
                    not comment_match.group(1).startswith(ALIAS_PREFIX):
                raise HotdeployError(f"nft transaction contains a foreign or unowned rule: {line!r}")
            rule_comments.append((match.group(1), comment_match.group(1)))
        else:
            raise HotdeployError(f"nft transaction contains a non-additive command: {line!r}")
        if re.search(r"\b(?:flush|delete|replace)\b", line):
            raise HotdeployError(f"nft transaction contains a forbidden mutation: {line!r}")
    if len(set_names) != len(ALIAS_SETS) or set(set_names) != ALIAS_SETS:
        raise HotdeployError("nft transaction must add each exact alias set once")
    expected_rules = [(rule["chain"], rule["comment"]) for rule in undo["rules"]]
    if len(rule_comments) != len(expected_rules) or set(rule_comments) != set(expected_rules):
        raise HotdeployError("nft transaction rules do not correspond exactly to the undo manifest")
    return lines


def _validate_undo_shape(undo: Any) -> dict[str, Any]:
    if not isinstance(undo, dict) or undo.get("family") != "inet" or \
            undo.get("table") != "dnscomplex":
        raise HotdeployError("undo manifest must target inet dnscomplex only")
    rules = undo.get("rules")
    sets = undo.get("sets")
    if not isinstance(rules, list) or not isinstance(sets, list):
        raise HotdeployError("undo manifest has invalid rules/sets")
    comments = set()
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("family") != "inet" or \
                rule.get("table") != "dnscomplex" or rule.get("chain") not in ALIAS_CHAINS:
            raise HotdeployError("undo manifest contains a non-owned rule target")
        comment = rule.get("comment")
        expression = rule.get("rule")
        if not isinstance(comment, str) or not comment.startswith(ALIAS_PREFIX) or \
                comment in comments or not isinstance(expression, str) or \
                f'comment "{comment}"' not in expression:
            raise HotdeployError("undo manifest has invalid or duplicate owned rule comments")
        comments.add(comment)
    names = [item.get("name") for item in sets if isinstance(item, dict)]
    if len(names) != len(sets) or set(names) != ALIAS_SETS or len(names) != len(ALIAS_SETS):
        raise HotdeployError("undo manifest must name each exact alias-owned set once")
    if any(not item.get("delete_only_if_empty_after_owned_elements_removed") for item in sets):
        raise HotdeployError("undo manifest does not require empty alias-owned sets")
    return undo


def build_preview(bundle_bytes: bytes, expected_sha256: str, *,
                  fs_root: Path | str = "/") -> dict[str, Any]:
    """Verify reviewed bundle digest, exact target allowlist, and host preimages."""
    actual_bundle_sha = sha256(bundle_bytes)
    if not isinstance(expected_sha256, str) or \
            not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or \
            actual_bundle_sha != expected_sha256:
        raise HotdeployError("candidate bundle SHA256 does not match reviewed digest")
    try:
        bundle = json.loads(bundle_bytes, object_pairs_hook=_json_no_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HotdeployError("candidate bundle is not valid UTF-8 JSON") from exc
    if not isinstance(bundle, dict) or bundle.get("version") != 1:
        raise HotdeployError("unsupported candidate bundle version")
    files = bundle.get("files")
    if not isinstance(files, list) or not files:
        raise HotdeployError("candidate bundle has no target files")
    root = Path(fs_root).resolve()
    seen = set()
    file_plans = []
    for entry in files:
        if not isinstance(entry, dict):
            raise HotdeployError("candidate file entry must be an object")
        target = entry.get("target")
        if isinstance(target, str) and target in seen:
            raise HotdeployError(f"duplicate target in bundle: {target}")
        if isinstance(target, str):
            seen.add(target)
        path = _safe_relative_target(root, target)
        encoded = entry.get("content_b64")
        if not isinstance(encoded, str):
            raise HotdeployError(f"candidate bytes missing for {target}")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise HotdeployError(f"candidate bytes are invalid base64 for {target}") from exc
        mode = entry.get("mode")
        if not isinstance(mode, int) or mode not in ALLOWED_MODES:
            raise HotdeployError(f"candidate mode is not allowlisted for {target}")
        preimage = entry.get("preimage_sha256")
        if preimage is not None and not re.fullmatch(r"[0-9a-f]{64}", str(preimage)):
            raise HotdeployError(f"invalid preimage SHA256 for {target}")
        snapshot = _file_snapshot(path)
        if snapshot["sha256"] != preimage:
            raise HotdeployError(f"target preimage changed: {target}")
        file_plans.append({
            "target": target, "candidate_sha256": sha256(content),
            "candidate_bytes": len(content), "candidate_mode": mode,
            "preimage_sha256": preimage, "preimage_exists": snapshot["existed"],
            "preimage_mode": snapshot["mode"], "preimage_uid": snapshot["uid"],
            "preimage_gid": snapshot["gid"], "_preimage_bytes": snapshot["bytes"],
            "_candidate_bytes": content,
        })
    nft = bundle.get("nft")
    if not isinstance(nft, dict):
        raise HotdeployError("candidate bundle has no nft plan")
    undo = _validate_undo_shape(nft.get("undo"))
    nft_files = [item for item in file_plans
                 if item["target"] == "/etc/nftables.d/dnscomplex.nft"]
    if len(nft_files) != 1 or not nft_files[0]["preimage_exists"]:
        raise HotdeployError("bundle must guard the existing persistent dnscomplex nft include")
    renderer = nft.get("candidate_renderer")
    if not isinstance(renderer, str):
        raise HotdeployError("bundle must include the full candidate nft renderer")
    try:
        compiled = _load_delta_compiler().compile_delta(
            renderer, nft.get("live_json"),
            nft_files[0]["_preimage_bytes"].decode("utf-8"),
            ai_vip=nft.get("ai_vip"), cn_vip=nft.get("cn_vip"))
    except Exception as exc:
        raise HotdeployError(f"compiler could not verify the nft plan: {exc}") from exc
    if (nft.get("transaction") != compiled["transaction"] or
            nft.get("persistent") != compiled["persistent"] or
            undo != compiled["undo"] or
            nft_files[0]["_candidate_bytes"] != compiled["persistent"].encode("utf-8")):
        raise HotdeployError("nft transaction, persistent include, and undo must match compiler output")
    nft_lines = _validate_nft_transaction(compiled["transaction"], compiled["undo"])
    return {"bundle_sha256": actual_bundle_sha, "files": file_plans,
            "nft_lines": nft_lines, "undo": undo}


def create_backup(bundle_bytes: bytes, expected_sha256: str, *,
                  fs_root: Path | str = "/", backup_parent: Path | str,
                  failpoint: str | None = None) -> dict[str, Any]:
    """Create a 0700 backup with exact preimage bytes and metadata; no target writes."""
    plan = build_preview(bundle_bytes, expected_sha256, fs_root=fs_root)
    parent = Path(backup_parent)
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode):
        raise HotdeployError("backup parent must be a real directory")
    parent.chmod(0o700)
    backup = Path(tempfile.mkdtemp(prefix="dnscomplex-lan-alias-", dir=parent))
    backup.chmod(0o700)
    try:
        payload_dir = backup / "payload"
        payload_dir.mkdir(mode=0o700)
        records = []
        for index, item in enumerate(plan["files"]):
            record = {key: item[key] for key in (
                "target", "preimage_exists", "preimage_sha256", "preimage_mode",
                "preimage_uid", "preimage_gid")}
            if item["preimage_exists"]:
                filename = f"{index:04d}"
                payload = payload_dir / filename
                fd = os.open(payload, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(item["_preimage_bytes"])
                    stream.flush()
                    os.fsync(stream.fileno())
                record["backup_payload"] = f"payload/{filename}"
            else:
                record["backup_payload"] = None
            records.append(record)
            if failpoint == "after-payload" and index == 0:
                raise OSError("injected backup failure after payload")
        if failpoint == "before-manifest":
            raise OSError("injected backup failure before manifest")
        manifest = {"version": 1, "bundle_sha256": plan["bundle_sha256"],
                    "files": records,
                    "nft_undo": plan["undo"]}
        manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = backup / ".manifest.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(manifest_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, backup / "manifest.json")
        directory_fd = os.open(backup, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return {"backup_dir": str(backup), "manifest_sha256": sha256(manifest_bytes),
                "manifest": manifest}
    except Exception as exc:
        shutil.rmtree(backup, ignore_errors=True)
        if isinstance(exc, HotdeployError):
            raise
        raise HotdeployError(f"private backup creation failed: {exc}") from exc


def _normalize_nft_tokens(tokens: list[str]) -> list[str]:
    normalized = []
    index = 0
    while index < len(tokens):
        if (tokens[index] == "counter" and index + 4 < len(tokens) and
                tokens[index + 1] == "packets" and tokens[index + 3] == "bytes"):
            normalized.append("counter")
            index += 5
        else:
            normalized.append(tokens[index])
            index += 1
    for index, token in enumerate(normalized):
        if (token.lower().startswith("0x") and
                ((index >= 1 and normalized[index - 1] == "mark") or
                 (index >= 2 and normalized[index - 2:index] == ["mark", "set"]) or
                 (index >= 3 and normalized[index - 3:index] == ["ct", "mark", "!="]))):
            try:
                value = int(token, 0)
            except ValueError:
                continue
            if 0 < value <= 0xFFFFFFFF:
                normalized[index] = hex(value)
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


def _listed_rule(line: str) -> tuple[str | None, int | None, list[str]]:
    match = re.search(r"\s+# handle (\d+)\s*$", line)
    if not match:
        return None, None, _normalize_nft_tokens(shlex.split(line))
    content = line[:match.start()].strip()
    tokens = shlex.split(content)
    comment = None
    if "comment" in tokens:
        index = tokens.index("comment")
        if index + 1 < len(tokens):
            comment = tokens[index + 1]
    return comment, int(match.group(1)), _normalize_nft_tokens(tokens)


def owned_undo_commands(undo_manifest: dict[str, Any],
                        chain_text: dict[str, str],
                        set_states: dict[str, dict[str, Any]]) -> list[str]:
    """Resolve and return exact owned deletes; never flush or delete nonempty sets."""
    manifest = _validate_undo_shape(undo_manifest)
    if set(chain_text) != ALIAS_CHAINS:
        raise HotdeployError("owned undo requires listings for every managed chain")
    if set(set_states) != ALIAS_SETS:
        raise HotdeployError("owned undo requires state for each exact alias set")
    expected_comments = {rule["comment"] for rule in manifest["rules"]}
    live_alias_comments = set()
    live_alias_rows = []
    for chain_name, listing in chain_text.items():
        for line in listing.splitlines():
            comment, handle, tokens = _listed_rule(line)
            if comment and comment.startswith(ALIAS_PREFIX):
                live_alias_comments.add(comment)
                live_alias_rows.append((chain_name, comment, handle, tokens))
    handles = []
    for rule in manifest["rules"]:
        chain = rule["chain"]
        expected = _normalize_nft_tokens(shlex.split(rule["rule"]))
        same_comment = [row for row in live_alias_rows if row[1] == rule["comment"]]
        if len(same_comment) != 1:
            raise HotdeployError(
                f"owned rule {chain}/{rule['comment']} is missing or comment is not unique")
        actual_chain, _comment, handle, actual = same_comment[0]
        if actual_chain != chain or handle is None or actual != expected:
            raise HotdeployError(
                f"owned rule {chain}/{rule['comment']} is changed or has no exact handle")
        handles.append((chain, handle))
    if live_alias_comments != expected_comments:
        raise HotdeployError("live managed chains contain unexpected or missing alias-owned rules")
    commands = [f"delete rule inet dnscomplex {chain} handle {handle}"
                for chain, handle in reversed(handles)]
    for item in manifest["sets"]:
        name = item["name"]
        state = set_states[name]
        if (not isinstance(state, dict) or state.get("name") != name or
                state.get("exists") is not True):
            raise HotdeployError(f"invalid live alias set state for {name}")
        if "elem" not in state:
            raise HotdeployError(f"cannot prove alias-owned set {name} is empty")
        elements = state.get("elem")
        if not isinstance(elements, list):
            raise HotdeployError(f"cannot prove alias-owned set {name} is empty")
        if elements:
            raise HotdeployError(f"refusing to delete nonempty alias-owned set {name}")
        commands.append(f"delete set inet dnscomplex {name}")
    return commands


def _owned_source_address(undo_manifest: dict[str, Any]) -> str:
    guards = [rule for rule in undo_manifest["rules"]
              if rule["comment"] == "dnscomplex-lan-alias-owned-source-guard"]
    if len(guards) != 1:
        raise HotdeployError("compiled undo manifest has no unique owned-source guard")
    tokens = shlex.split(guards[0]["rule"])
    try:
        index = tokens.index("saddr")
        return str(ipaddress.IPv4Address(tokens[index + 1]))
    except (ValueError, IndexError) as exc:
        raise HotdeployError("compiled owned-source guard has an invalid source address") from exc


def apply_candidate(bundle_bytes: bytes, expected_sha256: str, *, adapter,
                    fs_root: Path | str = "/", backup_parent: Path | str,
                    lock_path: Path | str = "/run/lock/dnscomplex-maintenance.lock") -> dict[str, Any]:
    """Run the hotdeploy state machine through an injected host adapter.

    The adapter owns OS command execution and must implement the named methods
    below. Preparation maps to ``reconcile --keep-closed``. The adapter then
    synchronizes current SA/VIP, bind, route and NAT state before invoking the
    ordinary reconcile path to activate. This API deliberately has no built-in
    host adapter or CLI apply path; production command wiring must be separately
    reviewed and exercised in Linux.
    """
    with maintenance_lock(lock_path):
        plan = build_preview(bundle_bytes, expected_sha256, fs_root=fs_root)
        bundle = json.loads(bundle_bytes)
        modes = adapter.profile_modes()
        if modes != {"ai": "ipsec", "cn": "ipsec"}:
            raise HotdeployError("hotdeploy requires both profiles in IPsec mode")
        protected = adapter.capture_protected_state()
        initial_vips = adapter.current_profile_vips()
        persistent_file = next(item for item in plan["files"]
                               if item["target"] == "/etc/nftables.d/dnscomplex.nft")
        current_persistent = adapter.read_persistent_nft()
        if current_persistent.encode("utf-8") != persistent_file["_preimage_bytes"]:
            raise HotdeployError("persistent nft include changed after preview preimage check")
        renderer = bundle["nft"]["candidate_renderer"]
        live_json = adapter.read_live_nft_json()
        try:
            compiled = _load_delta_compiler().compile_delta(
                renderer, live_json, current_persistent,
                ai_vip=initial_vips["ai"], cn_vip=initial_vips["cn"])
        except Exception as exc:
            raise HotdeployError(f"fresh live nft plan is unsafe: {exc}") from exc
        nft_lines = _validate_nft_transaction(compiled["transaction"], compiled["undo"])
        adapter.check_nft(compiled["transaction"], compiled["persistent"])
        backup = create_backup(bundle_bytes, expected_sha256, fs_root=fs_root,
                               backup_parent=backup_parent)
        nft_applied = False
        try:
            code_files = [item for item in plan["files"] if item["target"] not in {
                "/etc/sing-box/config.json", "/etc/nftables.d/dnscomplex.nft",
                "/var/lib/dnscomplex/lan-alias.json",
            }]
            adapter.publish_candidate_files(code_files)
            adapter.publish_persistent_nft(compiled["persistent"])
            # nft -f applies this as one atomic transaction. Treat invocation
            # errors conservatively because the command may have committed before
            # its caller observed an interruption.
            nft_applied = True
            adapter.apply_additive_nft(compiled["transaction"], compiled["undo"])
            preparation = adapter.prepare_alias_once_closed(initial_vips)
            if not isinstance(preparation, dict) or preparation.get("config_valid") is not True or \
                    preparation.get("singbox_restart_count") != 1 or \
                    preparation.get("readiness_closed") is not True or \
                    preparation.get("loaded_config_proven") is not True:
                raise HotdeployError(
                    "keep-closed reconcile must validate config, restart sing-box once, "
                    "prove loaded config, and keep readiness closed")
            current_vips = adapter.current_profile_vips()
            sync_result = adapter.sync_current_profile_state(current_vips)
            if not isinstance(sync_result, dict) or \
                    sync_result.get("runtime_vips") != current_vips or \
                    sync_result.get("persistent_vips") != current_vips:
                raise HotdeployError(
                    "current-VIP sync must verify runtime and persistent alias SNAT state")
            # Prove the synchronized VIP snapshot is still current before the
            # helper's ordinary reconcile is allowed to open readiness.
            adapter.verify_pre_activation(current_vips)
            activation = adapter.activate_alias(current_vips)
            if not isinstance(activation, dict) or activation.get("config_valid") is not True or \
                    activation.get("singbox_restart_count") != 0 or \
                    activation.get("loaded_config_fastpath") is not True or \
                    activation.get("readiness_open") is not True:
                raise HotdeployError(
                    "activation reconcile must prove the loaded-config fastpath, "
                    "avoid a second restart, and open readiness")
            if adapter.current_profile_vips() != current_vips:
                raise HotdeployError("profile VIP changed during activation; readiness must roll back closed")
            adapter.verify_active(current_vips)
            adapter.verify_protected_state(protected)
            return {"bundle_sha256": plan["bundle_sha256"],
                    "backup_dir": backup["backup_dir"],
                    "profile_vips": current_vips,
                    "nft_command_count": len(nft_lines)}
        except BaseException as failure:
            rollback_errors = []
            readiness_closed = not nft_applied
            may_restore_files = not nft_applied
            if nft_applied:
                try:
                    adapter.close_alias_readiness()
                    adapter.verify_alias_closed()
                    readiness_closed = True
                    may_restore_files = True
                    address = _owned_source_address(compiled["undo"])
                    adapter.remove_owned_alias_address(address)
                    adapter.remove_exact_owned_source_element(address)
                    chain_text, set_states = adapter.snapshot_owned_nft()
                    undo_commands = owned_undo_commands(
                        compiled["undo"], chain_text, set_states)
                    adapter.check_owned_nft_undo(undo_commands)
                    adapter.apply_owned_nft_undo(undo_commands)
                except BaseException as rollback_error:
                    may_restore_files = False
                    rollback_errors.append(f"owned nft/source rollback: {rollback_error}")
            if may_restore_files:
                try:
                    adapter.restore_preimages(backup)
                except BaseException as rollback_error:
                    rollback_errors.append(f"preimage restore: {rollback_error}")
            if readiness_closed:
                try:
                    current_vips = adapter.current_profile_vips()
                    adapter.sync_profile_snat_current_vips(current_vips)
                except BaseException as rollback_error:
                    try:
                        adapter.close_unready_profile_gates()
                    except BaseException as close_error:
                        rollback_errors.append(f"profile gate close: {close_error}")
                    rollback_errors.append(f"current-VIP SNAT: {rollback_error}")
                if nft_applied:
                    try:
                        adapter.verify_alias_absent()
                    except BaseException as rollback_error:
                        rollback_errors.append(f"alias absence verify: {rollback_error}")
                try:
                    adapter.verify_rollback(protected)
                except BaseException as rollback_error:
                    rollback_errors.append(f"rollback state verify: {rollback_error}")
            else:
                rollback_errors.append("readiness closure could not be proven; rollback halted")
            if rollback_errors:
                raise HotdeployError(
                    f"apply failed ({failure}); preimage/current-VIP rollback incomplete; "
                    f"backup retained at {backup['backup_dir']}: {'; '.join(rollback_errors)}"
                ) from failure
            raise HotdeployError(
                f"apply failed and preimages/current-VIP SNAT were restored; "
                f"backup retained at {backup['backup_dir']}: {failure}"
            ) from failure


@contextmanager
def maintenance_lock(path: Path | str) -> Iterator[None]:
    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise HotdeployError("maintenance lock is not a regular file")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise HotdeployError("another dnscomplex maintenance operation holds the lock") from exc
        yield
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path,
                        help="reviewed local candidate bundle JSON")
    parser.add_argument("--sha256", required=True,
                        help="reviewed SHA256 of the exact bundle bytes")
    parser.add_argument("--root", type=Path, default=Path("/"),
                        help=argparse.SUPPRESS)
    parser.add_argument("--lock", type=Path, default=Path("/run/lock/dnscomplex-maintenance.lock"),
                        help=argparse.SUPPRESS)
    parser.add_argument("--backup-parent", type=Path,
                        default=Path("/root/dnscomplex-lan-alias-backups"),
                        help=argparse.SUPPRESS)
    parser.add_argument("--backup", action="store_true",
                        help="stage a private preimage backup; still does not apply changes")
    args = parser.parse_args(argv)
    try:
        bundle_bytes = args.bundle.read_bytes()
        with maintenance_lock(args.lock):
            preview = build_preview(bundle_bytes, args.sha256, fs_root=args.root)
            if args.backup:
                if os.geteuid() != 0:
                    raise HotdeployError("backup staging requires root")
                result = create_backup(bundle_bytes, args.sha256, fs_root=args.root,
                                       backup_parent=args.backup_parent)
                print(json.dumps({"mode": "backup-staged", "bundle_sha256": preview["bundle_sha256"],
                                  "backup_dir": result["backup_dir"],
                                  "manifest_sha256": result["manifest_sha256"]}, sort_keys=True))
            else:
                print(json.dumps({
                    "mode": "dry-run-preview", "bundle_sha256": preview["bundle_sha256"],
                    "files": [{key: item[key] for key in (
                        "target", "candidate_sha256", "candidate_bytes", "candidate_mode",
                        "preimage_sha256", "preimage_exists", "preimage_mode", "preimage_uid",
                        "preimage_gid")} for item in preview["files"]],
                    "nft_command_count": len(preview["nft_lines"]),
                    "nft_transaction_sha256": sha256("\n".join(preview["nft_lines"]).encode()),
                    "owned_undo_rule_count": len(preview["undo"]["rules"]),
                    "owned_undo_set_count": len(preview["undo"]["sets"]),
                    "apply": "not implemented; this program does not mutate host state",
                }, sort_keys=True))
        return 0
    except (OSError, HotdeployError) as exc:
        print(f"lan-alias-hotdeploy: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
