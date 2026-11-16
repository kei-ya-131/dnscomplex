#!/usr/bin/env python3
"""Build a private, SHA-pinned LAN alias hotdeploy bundle from reviewed inputs.

This tool reads only an explicit private rootfs snapshot and caller-supplied
frozen installer/rendered nft/live nft/VIP inputs. It never invokes the
installer, renderer, host commands, or writes managed host targets.
"""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


class BundleError(ValueError):
    pass


MANAGER_START = "write_file_atomic /usr/local/sbin/dnscomplex <<'MANAGER'"
MANAGER_END = "MANAGER"
HELPER_START = "write_file /usr/local/libexec/dnscomplex-lan-alias <<'LAN_ALIAS'"
HELPER_END = "LAN_ALIAS"
TARGETS = (
    "/root/install.sh",
    "/usr/local/sbin/dnscomplex",
    "/usr/local/libexec/dnscomplex-lan-alias",
    "/etc/sing-box/config.json",
    "/etc/nftables.d/dnscomplex.nft",
    "/var/lib/dnscomplex/lan-alias.json",
)


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise BundleError(f"cannot load local utility: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _utilities():
    tools = Path(__file__).resolve().parent
    return (_load_module("_lan_alias_bundle_hotdeploy", tools / "lan_alias_hotdeploy.py"),
            _load_module("_lan_alias_bundle_delta", tools / "lan_alias_nft_delta.py"))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _expected_sha(value: str, actual: bytes, label: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", value) or _sha(actual) != value:
        raise BundleError(f"{label} SHA256 mismatch")


def _extract_heredoc(installer: bytes, start_marker: str, end_marker: str,
                     label: str) -> bytes:
    try:
        text = installer.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BundleError("frozen installer is not UTF-8") from exc
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.rstrip("\r\n").strip() == start_marker]
    if len(starts) != 1:
        raise BundleError(f"frozen installer must contain exactly one {label} heredoc")
    start = starts[0] + 1
    ends = [i for i in range(start, len(lines))
            if lines[i].rstrip("\r\n").strip() == end_marker]
    if not ends:
        raise BundleError(f"frozen installer has an unterminated {label} heredoc")
    body = "".join(lines[start:ends[0]]).encode("utf-8")
    if not body.endswith(b"\n"):
        raise BundleError(f"extracted {label} heredoc is incomplete")
    if label == "manager":
        if not body.startswith(b"#!/"):
            raise BundleError("extracted manager heredoc is not an executable shell source")
    else:
        try:
            module = ast.parse(body.decode("utf-8"))
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise BundleError("extracted LAN alias helper is not complete Python source") from exc
        has_main_guard = any(
            isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and
            isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__" and
            len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.Eq) and
            len(node.test.comparators) == 1 and isinstance(node.test.comparators[0], ast.Constant) and
            node.test.comparators[0].value == "__main__"
            for node in module.body)
        if ast.get_docstring(module) is None or not has_main_guard:
            raise BundleError("extracted LAN alias helper lacks its module docstring or CLI entry point")
    return body


def _read_candidate(path: Path, label: str, expected_sha: str) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BundleError(f"cannot read {label}: {exc}") from exc
    _expected_sha(expected_sha, data, label)
    return data


def _target_snapshot(root: Path, target: str, hotdeploy) -> dict[str, Any]:
    path = hotdeploy._safe_relative_target(root, target)
    try:
        return hotdeploy._file_snapshot(path)
    except OSError as exc:
        raise BundleError(f"cannot snapshot {target}: {exc}") from exc


def _private_root(path: Path | str) -> Path:
    root = Path(path)
    if not root.is_absolute():
        raise BundleError("private rootfs path must be absolute")
    try:
        info = root.lstat()
    except OSError as exc:
        raise BundleError(f"cannot inspect private rootfs: {exc}") from exc
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
            stat.S_IMODE(info.st_mode) & 0o077 or info.st_uid != os.geteuid()):
        raise BundleError("rootfs readback must be an invoking-user-owned private directory (0700)")
    return root.resolve()


def _validate_alias_state_preimage(snapshot: dict[str, Any]) -> None:
    if not snapshot["existed"]:
        return
    if snapshot["mode"] != 0o600 or snapshot["uid"] != os.geteuid():
        raise BundleError("existing alias owner state must be invoking-user-owned mode 0600")
    try:
        state = json.loads(snapshot["bytes"], object_pairs_hook=lambda pairs: _unique_object(pairs))
    except (json.JSONDecodeError, UnicodeDecodeError, BundleError) as exc:
        raise BundleError("existing alias owner state is malformed") from exc
    expected = {"schema": 1, "status": "owned", "address": "198.18.255.254",
                "interface": "lo", "label": "lo:dc-alias",
                "outbound_tag": "lan-legacy-alias", "pool": "198.18.255.0/24"}
    if not isinstance(state, dict) or any(state.get(key) != value for key, value in expected.items()):
        raise BundleError("existing alias owner state is not exact owned state")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BundleError("duplicate key in existing alias state")
        result[key] = value
    return result


def build_bundle(*, installer: bytes, installer_sha256: str,
                 candidate_renderer: bytes, renderer_sha256: str,
                 live_json: bytes, ai_vip: str, cn_vip: str,
                 fs_root: Path | str) -> tuple[bytes, dict[str, Any]]:
    """Create a version-1 bundle and safe metadata from exact frozen inputs."""
    _expected_sha(installer_sha256, installer, "frozen installer")
    _expected_sha(renderer_sha256, candidate_renderer, "candidate renderer")
    try:
        renderer_text = candidate_renderer.decode("utf-8")
        live_text = live_json.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BundleError("renderer or live nft JSON is not UTF-8") from exc
    manager = _extract_heredoc(installer, MANAGER_START, MANAGER_END, "manager")
    helper = _extract_heredoc(installer, HELPER_START, HELPER_END, "LAN alias helper")
    root = _private_root(fs_root)
    hotdeploy, delta = _utilities()
    snapshots = {target: _target_snapshot(root, target, hotdeploy) for target in TARGETS}
    for target in ("/etc/sing-box/config.json", "/etc/nftables.d/dnscomplex.nft"):
        if not snapshots[target]["existed"]:
            raise BundleError(f"required host preimage is missing: {target}")
    _validate_alias_state_preimage(snapshots["/var/lib/dnscomplex/lan-alias.json"])
    persistent_before = snapshots["/etc/nftables.d/dnscomplex.nft"]["bytes"]
    try:
        persistent_text = persistent_before.decode("utf-8")
        live_obj = json.loads(live_text)
        compiled = delta.compile_delta(renderer_text, live_obj, persistent_text,
                                       ai_vip=ai_vip, cn_vip=cn_vip)
    except Exception as exc:
        raise BundleError(f"could not compile strict additive nft delta: {exc}") from exc

    candidate_contents = {
        "/root/install.sh": installer,
        "/usr/local/sbin/dnscomplex": manager,
        "/usr/local/libexec/dnscomplex-lan-alias": helper,
        "/etc/sing-box/config.json": snapshots["/etc/sing-box/config.json"]["bytes"],
        "/etc/nftables.d/dnscomplex.nft": compiled["persistent"].encode("utf-8"),
        "/var/lib/dnscomplex/lan-alias.json": (
            snapshots["/var/lib/dnscomplex/lan-alias.json"]["bytes"]
            if snapshots["/var/lib/dnscomplex/lan-alias.json"]["existed"] else b""),
    }
    modes = {
        "/root/install.sh": 0o755,
        "/usr/local/sbin/dnscomplex": 0o755,
        "/usr/local/libexec/dnscomplex-lan-alias": 0o755,
        "/etc/sing-box/config.json": snapshots["/etc/sing-box/config.json"]["mode"],
        "/etc/nftables.d/dnscomplex.nft": snapshots["/etc/nftables.d/dnscomplex.nft"]["mode"],
        "/var/lib/dnscomplex/lan-alias.json": 0o600,
    }
    files = []
    for target in TARGETS:
        snap = snapshots[target]
        content = candidate_contents[target]
        files.append({"target": target, "content_b64": base64.b64encode(content).decode("ascii"),
                      "mode": modes[target], "preimage_sha256": snap["sha256"]})
    bundle = {
        "version": 1,
        "files": files,
        "nft": {
            "candidate_renderer": renderer_text,
            "live_json": live_obj,
            "ai_vip": ai_vip,
            "cn_vip": cn_vip,
            "transaction": compiled["transaction"],
            "persistent": compiled["persistent"],
            "undo": compiled["undo"],
        },
    }
    bundle_bytes = (json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n").encode()
    preview = hotdeploy.build_preview(bundle_bytes, _sha(bundle_bytes), fs_root=root)
    metadata = {
        "bundle_sha256": _sha(bundle_bytes),
        "bundle_bytes": len(bundle_bytes),
        "installer_sha256": installer_sha256,
        "renderer_sha256": renderer_sha256,
        "files": [{key: item[key] for key in ("target", "candidate_sha256", "candidate_bytes",
                                                 "candidate_mode", "preimage_sha256", "preimage_exists",
                                                 "preimage_mode")} for item in preview["files"]],
        "nft_transaction_sha256": _sha("\n".join(preview["nft_lines"]).encode()),
        "owned_undo_rule_count": len(preview["undo"]["rules"]),
        "owned_undo_set_count": len(preview["undo"]["sets"]),
        "mode": "bundle-preview-only",
    }
    return bundle_bytes, metadata


def _private_output_parent(path: Path) -> Path:
    if not path.is_absolute():
        raise BundleError("bundle output path must be absolute")
    parent = path.parent
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError as exc:
            raise BundleError("bundle output parent must already exist") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise BundleError("bundle output parent must contain no symlinks and be a directory")
    info = parent.stat()
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise BundleError("bundle output parent must be private (mode 0700 or stricter)")
    if info.st_uid != os.geteuid():
        raise BundleError("bundle output parent must be owned by the invoking user")
    return parent


def write_private_bundle(path: Path | str, data: bytes) -> str:
    output = Path(path)
    parent = _private_output_parent(output)
    if output.exists() or output.is_symlink():
        raise BundleError("bundle output already exists; refusing overwrite")
    fd, temporary_name = tempfile.mkstemp(prefix=".lan-alias-bundle-", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output, follow_symlinks=False)
        temporary.unlink()
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return _sha(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", required=True, type=Path)
    parser.add_argument("--installer-sha", required=True)
    parser.add_argument("--candidate-renderer", required=True, type=Path)
    parser.add_argument("--candidate-renderer-sha", required=True)
    parser.add_argument("--live-json", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path,
                        help="private rootfs/readback snapshot; never defaults to host root")
    parser.add_argument("--ai-vip", required=True)
    parser.add_argument("--cn-vip", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        bundle, metadata = build_bundle(
            installer=_read_candidate(args.installer, "frozen installer", args.installer_sha),
            installer_sha256=args.installer_sha,
            candidate_renderer=_read_candidate(args.candidate_renderer, "candidate renderer",
                                               args.candidate_renderer_sha),
            renderer_sha256=args.candidate_renderer_sha,
            live_json=args.live_json.read_bytes(), ai_vip=args.ai_vip, cn_vip=args.cn_vip,
            fs_root=args.root)
        metadata["output"] = str(args.output)
        metadata["bundle_sha256"] = write_private_bundle(args.output, bundle)
        print(json.dumps(metadata, sort_keys=True))
        return 0
    except (OSError, BundleError) as exc:
        print(f"lan-alias-bundle: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
