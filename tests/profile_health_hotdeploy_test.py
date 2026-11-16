#!/usr/bin/env python3
"""TDD contracts for the separate profile-health-only publisher."""
from __future__ import annotations

import base64
import contextlib
import io
import hashlib
import importlib.util
import json
import runpy
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = "856be53885775e98076a0a6e2611e2de27028970d7cde3bb3b714def77a5896f"
PROBE_PIN = "d74f866c368ddc31dd0e71bb39cb92afb566d5b24e7941687482bcbc100f4ba1"
PUBLISHER_PATH = ROOT / "tools" / "profile_health_hotdeploy.py"
SPEC = importlib.util.spec_from_file_location("profile_health_hotdeploy", PUBLISHER_PATH)
publisher = None
if PUBLISHER_PATH.is_file() and SPEC and SPEC.loader:
    publisher = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(publisher)
FIXTURE = runpy.run_path(str(ROOT / "tests" / "profile_health_nft_delta_test.py"))
delta = FIXTURE["delta"]
TARGETS = (
    "/root/install.sh",
    "/usr/local/sbin/dnscomplex",
    "/usr/local/libexec/dnscomplex-lan-alias",
    "/usr/local/lib/dnscomplex/profile-dataplane-probe.py",
    "/etc/nftables.d/dnscomplex.nft",
)
VIPS = {"ai": "10.250.1.10", "cn": "10.251.1.10"}
MODES = {"ai": "ipsec", "cn": "ipsec"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def heredoc(source: bytes, marker: str, end: str) -> bytes:
    lines = source.decode("utf-8").splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == marker]
    if len(starts) != 1:
        raise AssertionError(f"missing unique embedded asset: {marker}")
    start = starts[0] + 1
    stop = next((i for i in range(start, len(lines)) if lines[i].strip() == end), None)
    if stop is None:
        raise AssertionError(f"unterminated embedded asset: {marker}")
    return "".join(lines[start:stop]).encode("utf-8")


def make_bundle(root: Path, modes=None, vips=None, absent_targets=()) -> bytes:
    modes = dict(modes or MODES)
    vips = dict(vips or VIPS)
    installer = (ROOT / "install.sh").read_bytes()
    if sha(installer) != PIN:
        raise AssertionError("test requires immutable 856 installer preimage")
    manager = heredoc(installer, "write_file_atomic /usr/local/sbin/dnscomplex <<'MANAGER'", "MANAGER")
    lan_helper = heredoc(installer, "write_file /usr/local/libexec/dnscomplex-lan-alias <<'LAN_ALIAS'", "LAN_ALIAS")
    probe = (ROOT / "tools/profile_dataplane_probe.py").read_bytes()
    if sha(probe) != PROBE_PIN:
        raise AssertionError("test requires immutable d74 probe asset")
    renderer = FIXTURE["candidate"](modes["ai"], modes["cn"])
    live_json = FIXTURE["live_json"](modes["ai"], modes["cn"])
    persistent = FIXTURE["ProfileHealthNFTDeltaTest"].persistent(modes["ai"], modes["cn"])
    compiled = delta.compile_delta(live_json, persistent, renderer, PIN, modes, vips)
    contents = (installer, manager, lan_helper, probe, compiled["persistent"].encode("utf-8"))
    modes_bits = (0o755, 0o755, 0o755, 0o755, 0o644)
    files = []
    for target, content, mode in zip(TARGETS, contents, modes_bits):
        path = root / target.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        old = persistent.encode("utf-8") if target == TARGETS[-1] else ("preimage:" + target + "\n").encode()
        if target in absent_targets:
            old = None
            preimage_mode = preimage_uid = preimage_gid = None
            preimage_sha = None
        else:
            path.write_bytes(old)
            path.chmod(mode)
            info = path.stat()
            preimage_mode, preimage_uid, preimage_gid = (
                info.st_mode & 0o777, info.st_uid, info.st_gid)
            preimage_sha = sha(old)
        files.append({"target": target, "content_b64": base64.b64encode(content).decode("ascii"),
                      "mode": mode, "uid": 0, "gid": 0, "preimage_sha256": preimage_sha,
                      "preimage_mode": preimage_mode, "preimage_uid": preimage_uid,
                      "preimage_gid": preimage_gid})
    bundle = {"version": 1, "installer_sha256": PIN, "files": files,
              "nft": {"candidate_renderer": renderer, "preview_live_json": live_json,
                      "profile_modes": modes, "profile_vips": vips}}
    return json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ControlledRunner:
    """Explicit private test adapter; every side effect is observable and injected."""
    def __init__(self, *, modes=None, vips=None, fail=None, old_open=None, old_valid=True):
        self.modes = dict(modes or MODES)
        self.vips = dict(vips or VIPS)
        self.initial_vips = dict(self.vips)
        self.fail = fail
        self.old_valid = old_valid
        self.events = []
        self.gates = {p: bool((old_open or {}).get(p, False)) for p in ("ai", "cn")}
        self.observations = {"ai": 0, "cn": 0}
        self.protected = {"singbox_pid": 442, "singbox_config_sha256": "a" * 64,
                          "domain_sets_sha256": "b" * 64, "conntrack_sha256": "c" * 64}
        self.timer = {"timer_was_active": True, "service_was_active": True,
                      "service_idle": True}
        self.restarts = 0
        self.nft_applied = False

    def event(self, name):
        self.events.append(name)
        if self.fail == name:
            raise RuntimeError("injected failure at " + name)

    def profile_modes(self):
        self.event("modes")
        return dict(self.modes)

    def capture_protected_state(self):
        self.event("protected-before")
        return dict(self.protected)

    def current_profile_vips(self):
        self.event("vips")
        return dict(self.vips)

    def check_policy_conflicts(self, profiles):
        self.event("policy-conflicts")

    def read_persistent_nft(self):
        self.event("persistent")
        return FIXTURE["ProfileHealthNFTDeltaTest"].persistent(self.modes["ai"], self.modes["cn"])

    def read_live_nft_json(self):
        self.event("live-nft")
        live = FIXTURE["live_json"](self.modes["ai"], self.modes["cn"])
        if self.nft_applied == "complete":
            active = [p for p in ("ai", "cn") if self.modes[p] == "ipsec"]
            for profile in ("ai", "cn"):
                live["nftables"].append({"set": {"family": "inet", "table": "dnscomplex",
                    "name": profile + "_probe_vip4", "type": "ipv4_addr",
                    "flags": ["interval"],
                    "elem": [self.vips[profile]] if profile in active else []}})
            rules = []
            cfgs = {"ai": ("104.16.248.249", 929, 769, 90),
                    "cn": ("223.6.6.6", 1009, 849, 91)}
            for profile in active:
                resolver, mark, output_mark, handle = cfgs[profile]
                rules.append({"rule": {"family": "inet", "table": "dnscomplex",
                    "chain": "output", "comment": f"dnscomplex-{profile}-dataplane-probe",
                    "handle": handle, "expr": [
                        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                   "right": {"set": f"@{profile}_probe_vip4"}}},
                        {"match": {"op": "==", "left": {"meta": {"key": "oifname"}},
                                   "right": f"ipsec-{profile}"}},
                        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                                   "right": resolver}},
                        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                   "right": 443}},
                        {"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": mark}},
                        {"counter": {"packets": 0, "bytes": 0}},
                        {"mangle": {"key": {"meta": {"key": "mark"}}, "value": output_mark}},
                        {"accept": None}]}})
            anchor = next(i for i, item in enumerate(live["nftables"])
                          if item.get("rule", {}).get("comment", "").endswith("classified-ipv6-drop"))
            live["nftables"][anchor:anchor] = rules
        elif self.nft_applied == "partial":
            live["nftables"].append({"set": {"family": "inet", "table": "dnscomplex",
                "name": "ai_probe_vip4", "type": "ipv4_addr", "flags": ["interval"], "elem": []}})
        return live

    def check_nft(self, transaction, persistent):
        self.event("check-nft")

    def stop_health_timer_and_wait(self, timeout_seconds):
        self.event("stop-timer-wait")
        return {k: self.timer[k] for k in ("timer_was_active", "service_was_active", "service_idle")}

    def close_profile_gates(self, profiles):
        self.event("close-gates")
        for p in profiles:
            self.gates[p] = False

    def verify_gates(self, profiles, *, opened):
        self.event("verify-gates-open" if opened else "verify-gates-closed")
        if any(self.gates[p] is not opened for p in profiles):
            raise RuntimeError("readiness gate state mismatch")

    def capture_owned_state(self):
        self.event("backup-owned")
        return {"nft": "owned undo", "rules": "exact owned rules"}

    def publish_candidate_files(self, files):
        self.event("publish-files")

    def publish_persistent_nft(self, persistent):
        self.event("publish-nft-include")

    def apply_probe_nft(self, transaction, undo):
        self.event("apply-nft")
        if self.fail == "nft-reject":
            raise RuntimeError("atomic nft batch rejected before commit")
        if self.fail == "nft-partial":
            self.nft_applied = "partial"
            raise RuntimeError("unknown nft batch outcome")
        self.nft_applied = "complete"
        if self.fail == "nft-ack-lost":
            raise RuntimeError("nft batch committed but acknowledgement was lost")

    def sync_probe_policy(self, profile, vip):
        self.event("sync-policy-" + profile)
        if vip != self.vips[profile]:
            raise RuntimeError("probe policy used stale VIP")
        values = {"ai": (10201, 929, 301), "cn": (10251, 1009, 351)}[profile]
        return {"profile": profile, "verified": self.fail != "wrong-policy",
                "priority": values[0], "mark": values[1], "table": values[2],
                "route_device": "ipsec-" + profile, "route_source": vip}

    def sync_probe_vip(self, profile, vip):
        self.event("sync-vip-" + profile)
        if vip != self.vips[profile]:
            raise RuntimeError("probe VIP set used stale VIP")
        return {"profile": profile, "verified": True,
                "set": profile + "_probe_vip4", "vip": vip}

    def clear_old_success_proof(self, profiles):
        self.event("clear-old-proof")

    def observe(self, profile, vip, *, timeout_seconds):
        self.event("observe-" + profile)
        self.observations[profile] += 1
        if self.fail == "observer-result":
            return {"status": "fail", "profile": profile, "vip": vip,
                    "identity": "sa-identity", "count": self.observations[profile]}
        if self.observations[profile] >= 2:
            self.gates[profile] = True
        return {"status": "pass", "profile": profile, "vip": vip,
                "identity": "d" * 64, "count": self.observations[profile]}

    def verify_probe_effects(self, profile, vip):
        self.event("verify-probe-" + profile)
        return {"profile": profile, "verified": self.fail != "wrong-effects", "vip": vip,
                "counter_packets": 1 if self.fail != "wrong-effects" else 0,
                "route_get": True, "readiness_open": True}

    def verify_protected_state(self, expected):
        self.event("protected-after")
        if expected != self.protected:
            raise RuntimeError("protected state changed")
        return True

    def verify_service_unchanged(self, expected):
        self.event("service-unchanged")
        if self.restarts:
            raise RuntimeError("service restarted")
        return True

    def close_profile_gates_for_rollback(self, profiles):
        self.event("rollback-close-gates")
        for p in profiles:
            self.gates[p] = False

    def undo_probe_policy(self, profiles, owned_state):
        self.event("undo-policy")

    def undo_probe_nft(self, undo):
        self.event("undo-nft")
        self.nft_applied = "none"

    def restore_preimages(self, backup):
        self.event("restore-files")

    def verify_current_profile_state(self, vips, profiles):
        self.event("verify-current-profile-state")
        return {"vips": dict(vips), "ready": self.fail != "profile-state-drift"}

    def verify_rollback(self, expected):
        self.event("verify-rollback")
        if any(self.gates.values()):
            raise RuntimeError("rollback must leave selected readiness closed")

    def restore_health_timer(self, state):
        self.event("restore-timer")


class ProfileHealthHotdeployTest(unittest.TestCase):
    def test_publisher_module_exists(self):
        self.assertTrue(PUBLISHER_PATH.is_file(), "health-only publisher source is missing")

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_preview_verifies_pinned_assets_preimages_and_strict_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            preview = publisher.build_preview(raw, sha(raw), fs_root=root)
            self.assertEqual({item["target"] for item in preview["files"]}, set(TARGETS))
            self.assertEqual(preview["installer_sha256"], PIN)
            self.assertEqual(preview["profile_modes"], MODES)
            for mutate in (
                lambda b: b.update(installer_sha256="0" * 64),
                lambda b: b["files"].append(dict(b["files"][0])),
                lambda b: b["files"][0].update(target="/etc/passwd"),
                lambda b: b["files"][0].update(preimage_mode=0o600),
                lambda b: b["nft"].update(profile_modes={"ai": "unknown", "cn": "ipsec"}),
            ):
                candidate = json.loads(raw)
                mutate(candidate)
                changed = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
                with self.subTest(mutation=mutate):
                    with self.assertRaises(publisher.HealthHotdeployError):
                        publisher.build_preview(changed, sha(changed), fs_root=root)

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_backup_is_private_and_records_preimage_bytes_and_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            result = publisher.create_backup(raw, sha(raw), fs_root=root,
                backup_parent=Path(temp) / "backups")
            backup = Path(result["backup_dir"])
            self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
            manifest = json.loads((backup / "manifest.json").read_text())
            self.assertEqual(len(manifest["files"]), len(TARGETS))
            first = manifest["files"][0]
            self.assertEqual(first["preimage_mode"], 0o755)
            self.assertEqual(first["preimage_uid"], (root / TARGETS[0].lstrip("/")).stat().st_uid)
            self.assertEqual((backup / first["backup_payload"]).read_bytes(),
                             ("preimage:" + TARGETS[0] + "\n").encode())

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_backup_manifest_preserves_absent_asset_as_absent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            target = TARGETS[3]
            raw = make_bundle(root, absent_targets=(target,))
            backup = publisher.create_backup(raw, sha(raw), fs_root=root,
                backup_parent=Path(temp) / "backups")
            record = next(item for item in backup["manifest"]["files"] if item["target"] == target)
            self.assertIs(record["preimage_exists"], False)
            self.assertIsNone(record["backup_payload"])
            self.assertFalse((root / target.lstrip("/")).exists())

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_apply_uses_fresh_profile_vip_after_bundle_preview(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            rotated = {"ai": "10.250.1.11", "cn": VIPS["cn"]}
            adapter = ControlledRunner(vips=rotated)
            result = publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertEqual(result["profile_vips"], rotated)
            self.assertIn("sync-policy-ai", adapter.events)
            self.assertIn("sync-vip-ai", adapter.events)

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_apply_closes_gates_before_mutation_and_requires_two_same_identity_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner()
            result = publisher.apply_candidate(
                raw, sha(raw), adapter=adapter, fs_root=root,
                backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertEqual(adapter.observations, {"ai": 2, "cn": 2})
            self.assertEqual(adapter.gates, {"ai": True, "cn": True})
            self.assertEqual(adapter.restarts, 0)
            self.assertLess(adapter.events.index("stop-timer-wait"), adapter.events.index("close-gates"))
            self.assertLess(adapter.events.index("close-gates"), adapter.events.index("publish-files"))
            self.assertLess(adapter.events.index("clear-old-proof"), adapter.events.index("observe-ai"))
            self.assertEqual(adapter.events.count("restore-timer"), 1)
            self.assertEqual(result["profiles_verified"], ["ai", "cn"])

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_wrong_policy_rule_or_route_readback_never_reaches_observer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner(fail="wrong-policy")
            with self.assertRaises(publisher.HealthHotdeployError):
                publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                    backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertNotIn("observe-ai", adapter.events)
            self.assertFalse(any(adapter.gates.values()))

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_zero_probe_counter_or_unverified_route_never_commits_open_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner(fail="wrong-effects")
            with self.assertRaises(publisher.HealthHotdeployError):
                publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                    backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertFalse(any(adapter.gates.values()))
            self.assertIn("rollback-close-gates", adapter.events)

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_health_service_timeout_refuses_all_mutations(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner(old_open={"ai": True, "cn": True})
            adapter.timer["service_idle"] = False
            with self.assertRaises(publisher.HealthHotdeployError):
                publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                    backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertNotIn("close-gates", adapter.events)
            self.assertNotIn("publish-files", adapter.events)
            self.assertEqual(adapter.gates, {"ai": True, "cn": True})
            self.assertIn("restore-timer", adapter.events)

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_policy_rule_conflict_is_preflight_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner(fail="policy-conflicts")
            with self.assertRaisesRegex(publisher.HealthHotdeployError, "policy-conflicts"):
                publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                    backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertNotIn("stop-timer-wait", adapter.events)
            self.assertNotIn("close-gates", adapter.events)
            self.assertNotIn("publish-files", adapter.events)

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_rollback_profile_drift_stays_closed_and_reports_unverified_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner(fail="observer-result")
            adapter.fail = "profile-state-drift"
            # Fail during effect verification after probe operations, not preflight.
            original = adapter.verify_probe_effects
            def verify_probe(profile, vip):
                adapter.event("verify-probe-" + profile)
                raise RuntimeError("injected observer failure")
            adapter.verify_probe_effects = verify_probe
            with self.assertRaisesRegex(publisher.HealthHotdeployError, "rollback incomplete"):
                publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                    backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertFalse(any(adapter.gates.values()))
            self.assertIn("verify-current-profile-state", adapter.events)

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_observer_failure_rolls_back_owned_changes_and_keeps_unproven_gates_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner(fail="observer-result", old_open={"ai": True, "cn": True},
                                       old_valid=False)
            with self.assertRaises(publisher.HealthHotdeployError):
                publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                    backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertIn("rollback-close-gates", adapter.events)
            self.assertIn("undo-nft", adapter.events)
            self.assertIn("restore-files", adapter.events)
            self.assertEqual(adapter.gates, {"ai": False, "cn": False})
            self.assertIn("restore-timer", adapter.events)

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_vip_change_between_observations_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner()
            observe = adapter.observe

            def change_vip(profile, vip, *, timeout_seconds):
                result = observe(profile, vip, timeout_seconds=timeout_seconds)
                if profile == "ai" and adapter.observations[profile] == 1:
                    adapter.vips[profile] = "10.250.1.11"
                return result

            adapter.observe = change_vip
            with self.assertRaises(publisher.HealthHotdeployError):
                publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                    backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertIn("rollback-close-gates", adapter.events)
            self.assertFalse(adapter.gates["ai"])

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_rollback_keeps_all_selected_gates_closed_even_if_old_gate_was_open(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner(fail="observer-result", old_open={"ai": True, "cn": False})
            with self.assertRaisesRegex(publisher.HealthHotdeployError, "remain closed"):
                publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                    backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertEqual(adapter.gates, {"ai": False, "cn": False})
            self.assertIn("verify-current-profile-state", adapter.events)

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_nft_rejection_with_proven_absence_skips_unsafe_undo(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner(fail="nft-reject")
            with self.assertRaises(publisher.HealthHotdeployError) as caught:
                publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                    backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertNotIn("rollback incomplete", str(caught.exception))
            self.assertNotIn("undo-nft", adapter.events)
            self.assertIn("restore-files", adapter.events)
            self.assertEqual(adapter.gates, {"ai": False, "cn": False})

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_lost_nft_ack_with_exact_complete_delta_is_safely_undone(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner(fail="nft-ack-lost")
            with self.assertRaises(publisher.HealthHotdeployError) as caught:
                publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                    backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertNotIn("rollback incomplete", str(caught.exception))
            self.assertIn("undo-nft", adapter.events)
            self.assertEqual(adapter.nft_applied, "none")
            self.assertEqual(adapter.gates, {"ai": False, "cn": False})

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_partial_or_foreign_nft_outcome_fails_closed_without_broad_undo(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner(fail="nft-partial")
            with self.assertRaisesRegex(publisher.HealthHotdeployError, "rollback incomplete"):
                publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                    backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertNotIn("undo-nft", adapter.events)
            self.assertEqual(adapter.gates, {"ai": False, "cn": False})

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_shared_observer_deadline_is_enforced_after_slow_backend_returns(self):
        import time
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            adapter = ControlledRunner()
            observe = adapter.observe
            def slow(profile, vip, *, timeout_seconds):
                time.sleep(0.03)
                return observe(profile, vip, timeout_seconds=timeout_seconds)
            adapter.observe = slow
            prior = publisher.MAX_TRANSACTION_SECONDS
            publisher.MAX_TRANSACTION_SECONDS = 0.01
            try:
                with self.assertRaisesRegex(publisher.HealthHotdeployError, "deadline"):
                    publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                        backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            finally:
                publisher.MAX_TRANSACTION_SECONDS = prior
            self.assertEqual(adapter.gates, {"ai": False, "cn": False})
            self.assertIn("rollback-close-gates", adapter.events)

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_mixed_mode_only_publishes_and_observes_ipsec_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            modes = {"ai": "ipsec", "cn": "xray"}
            raw = make_bundle(root, modes=modes)
            adapter = ControlledRunner(modes=modes)
            result = publisher.apply_candidate(raw, sha(raw), adapter=adapter, fs_root=root,
                backup_parent=Path(temp) / "backups", lock_path=Path(temp) / "lock")
            self.assertEqual(result["profiles_verified"], ["ai"])
            self.assertEqual(adapter.observations, {"ai": 2, "cn": 0})

    @unittest.skipIf(publisher is None, "publisher source not implemented yet")
    def test_cli_defaults_to_readonly_preview_and_exposes_no_apply_switch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            raw = make_bundle(root)
            bundle = Path(temp) / "bundle.json"
            bundle.write_bytes(raw)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(publisher.main(["--bundle", str(bundle), "--sha256", sha(raw),
                    "--root", str(root)]), 0)
            self.assertEqual(json.loads(output.getvalue())["mode"], "dry-run-preview")
            self.assertFalse((Path(temp) / "lock").exists())
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit):
                publisher.main(["--bundle", str(bundle), "--sha256", sha(raw), "--apply"])
            self.assertIn("CLI apply is intentionally unavailable", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
