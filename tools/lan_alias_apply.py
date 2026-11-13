#!/usr/bin/env python3
"""Review and explicitly apply a SHA-pinned LAN-alias hotdeploy bundle.

Without --apply this command only validates and prints a redacted preview.
Applying requires root, the exact live D6 installer/manager preimage, an exact
bundle digest, and (for a non-/ filesystem root) a private network namespace.
All mutations and rollback remain in the reviewed hotdeploy state machine.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


BASELINE_INSTALLER_SHA256 = "d6a0c37f9b337900cc19369c8da64b5dfce1a24cb9a3366d9e3579ddd1ce8624"
MANAGER_START = "write_file_atomic /usr/local/sbin/dnscomplex <<'MANAGER'"
MANAGER_END = "MANAGER"
HELPER_START = "write_file /usr/local/libexec/dnscomplex-lan-alias <<'LAN_ALIAS'"
HELPER_END = "LAN_ALIAS"
_hotdeploy = None
_adapter = None


class ApplyCliError(RuntimeError):
    """Operator input or live-source guard failed before dispatch."""


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ApplyCliError(f"cannot load local module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _modules():
    global _hotdeploy, _adapter
    tools = Path(__file__).resolve().parent
    if _hotdeploy is None:
        _hotdeploy = _load_module("_lan_alias_apply_hotdeploy", tools / "lan_alias_hotdeploy.py")
    if _adapter is None:
        _adapter = _load_module("_lan_alias_apply_host_adapter", tools / "lan_alias_host_adapter.py")
    return _hotdeploy, _adapter


def in_private_netns() -> bool | None:
    """Return True/False, or None when namespace identity cannot be proven."""
    try:
        return os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
    except OSError:
        return None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _target(root: Path, target: str) -> Path:
    path = root
    for part in Path(target.lstrip("/")).parts:
        path = path / part
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ApplyCliError(f"live source path contains a symlink: {target}")
    return path


def _read_regular(root: Path, target: str) -> bytes:
    path = _target(root, target)
    try:
        info = path.lstat()
    except OSError as exc:
        raise ApplyCliError(f"required live source is unavailable: {target}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ApplyCliError(f"required live source is not a regular file: {target}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ApplyCliError(f"required live source changed while opening: {target}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ApplyCliError(f"required live source changed while opening: {target}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def _extract_heredoc(installer: bytes, start_marker: str, end_marker: str, label: str) -> bytes:
    try:
        lines = installer.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise ApplyCliError("installer source is not UTF-8") from exc
    starts = [i for i, line in enumerate(lines) if line.rstrip("\r\n").strip() == start_marker]
    if len(starts) != 1:
        raise ApplyCliError(f"installer must contain exactly one {label} heredoc")
    start = starts[0] + 1
    ends = [i for i in range(start, len(lines))
            if lines[i].rstrip("\r\n").strip() == end_marker]
    if not ends:
        raise ApplyCliError(f"installer {label} heredoc is unterminated")
    content = "".join(lines[start:ends[0]]).encode("utf-8")
    if not content.endswith(b"\n"):
        raise ApplyCliError(f"installer {label} heredoc is incomplete")
    return content


def validate_live_d6(fs_root: Path | str) -> None:
    """Require exact frozen D6 install/manager and no pre-existing alias owner."""
    root = Path(fs_root).resolve()
    installer = _read_regular(root, "/root/install.sh")
    if _sha(installer) != BASELINE_INSTALLER_SHA256:
        raise ApplyCliError("live /root/install.sh is not the pinned D6 baseline")
    manager = _extract_heredoc(installer, MANAGER_START, MANAGER_END, "manager")
    if _read_regular(root, "/usr/local/sbin/dnscomplex") != manager:
        raise ApplyCliError("live dnscomplex manager does not match the pinned D6 installer")
    helper = _target(root, "/usr/local/libexec/dnscomplex-lan-alias")
    state = _target(root, "/var/lib/dnscomplex/lan-alias.json")
    if helper.exists() or helper.is_symlink() or state.exists() or state.is_symlink():
        raise ApplyCliError("live filesystem already contains LAN-alias helper or owner state")


def _private_bundle(path: Path) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ApplyCliError(f"cannot read reviewed bundle: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ApplyCliError("reviewed bundle must be a regular non-symlink file")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ApplyCliError("reviewed bundle must have private permissions (0600 or stricter)")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ApplyCliError("reviewed bundle changed while opening") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ApplyCliError("reviewed bundle changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def _candidate_source_guard(plan: dict[str, Any], expected_installer_sha256: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_installer_sha256):
        raise ApplyCliError("candidate installer SHA256 must be 64 lowercase hex characters")
    entries = {item["target"]: item for item in plan["files"]}
    install_item = entries.get("/root/install.sh")
    manager_item = entries.get("/usr/local/sbin/dnscomplex")
    helper_item = entries.get("/usr/local/libexec/dnscomplex-lan-alias")
    if not install_item or not manager_item or not helper_item:
        raise ApplyCliError("bundle is missing reviewed installer/manager/helper targets")
    installer = install_item["_candidate_bytes"]
    actual = _sha(installer)
    if actual != expected_installer_sha256:
        raise ApplyCliError("candidate installer SHA256 does not match reviewed digest")
    manager = _extract_heredoc(installer, MANAGER_START, MANAGER_END, "manager")
    helper = _extract_heredoc(installer, HELPER_START, HELPER_END, "LAN alias helper")
    if manager != manager_item["_candidate_bytes"] or helper != helper_item["_candidate_bytes"]:
        raise ApplyCliError("bundle manager/helper do not match candidate installer heredocs")
    return actual


def _preview_json(preview: dict[str, Any], installer_sha: str) -> dict[str, Any]:
    return {
        "mode": "dry-run-preview",
        "apply": "not requested",
        "bundle_sha256": preview["bundle_sha256"],
        "candidate_installer_sha256": installer_sha,
        "files": [{key: item[key] for key in (
            "target", "candidate_sha256", "candidate_bytes", "candidate_mode",
            "preimage_sha256", "preimage_exists", "preimage_mode", "preimage_uid", "preimage_gid")}
            for item in preview["files"]],
        "nft_command_count": len(preview["nft_lines"]),
        "nft_transaction_sha256": _sha("\n".join(preview["nft_lines"]).encode()),
        "owned_undo_rule_count": len(preview["undo"]["rules"]),
        "owned_undo_set_count": len(preview["undo"]["sets"]),
    }


def run_operator(bundle_path: Path | str, bundle_sha256: str, installer_sha256: str, *,
                 fs_root: Path | str = "/", apply: bool = False,
                 adapter_factory=None) -> dict[str, Any]:
    """Run guarded preview/apply; adapter_factory is Python-only test wiring.

    Production CLI never exposes adapter injection. A non-host filesystem root
    may be applied only by a caller that explicitly supplies its private-safe
    adapter factory, normally from an isolated namespace harness.
    """
    root = Path(fs_root).resolve()
    if apply and os.geteuid() != 0:
        raise ApplyCliError("--apply requires root")
    if apply:
        private_netns = in_private_netns()
        if private_netns is None:
            raise ApplyCliError("cannot determine network namespace; refusing apply")
        if root == Path("/") and private_netns:
            raise ApplyCliError("host filesystem apply is forbidden from a private network namespace")
        if root != Path("/"):
            if adapter_factory is None:
                raise ApplyCliError("private filesystem apply requires an explicit Python adapter factory")
            if not private_netns:
                raise ApplyCliError("private filesystem apply requires a private network namespace")

    bundle_bytes = _private_bundle(Path(bundle_path))
    hotdeploy, adapter_module = _modules()
    validate_live_d6(root)
    preview = hotdeploy.build_preview(bundle_bytes, bundle_sha256, fs_root=root)
    installer_sha = _candidate_source_guard(preview, installer_sha256)
    if not apply:
        return _preview_json(preview, installer_sha)

    factory = adapter_factory if adapter_factory is not None else adapter_module.LanAliasHostAdapter
    adapter = factory(apply=True, fs_root=root, require_root=True)
    backup_parent = root / "root/dnscomplex-lan-alias-backups"
    lock_path = root / "run/lock/dnscomplex-maintenance.lock"
    result = hotdeploy.apply_candidate(bundle_bytes, preview["bundle_sha256"],
        adapter=adapter, fs_root=root, backup_parent=backup_parent, lock_path=lock_path)
    return {"mode": "applied", "bundle_sha256": preview["bundle_sha256"],
            "candidate_installer_sha256": installer_sha,
            "backup_dir": result["backup_dir"],
            "profile_vips": result["profile_vips"],
            "nft_command_count": result["nft_command_count"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path,
                        help="private reviewed candidate bundle JSON")
    parser.add_argument("--bundle-sha256", required=True,
                        help="reviewed SHA256 of the exact bundle bytes")
    parser.add_argument("--installer-sha256", required=True,
                        help="reviewed SHA256 of candidate /root/install.sh in the bundle")
    parser.add_argument("--fs-root", type=Path, default=Path("/"),
                        help="filesystem root; non-/ roots require an isolated network namespace")
    parser.add_argument("--apply", action="store_true",
                        help="explicitly apply after all source, bundle and host guards pass")
    args = parser.parse_args(argv)
    try:
        root = args.fs_root.resolve()
        if args.apply and root != Path("/"):
            raise ApplyCliError("CLI apply is restricted to the host filesystem root")
        result = run_operator(args.bundle, args.bundle_sha256, args.installer_sha256,
                              fs_root=root, apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        print(f"lan-alias-apply: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
