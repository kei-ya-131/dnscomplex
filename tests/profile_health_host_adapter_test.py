import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "profile_health_host_adapter", ROOT / "tools/profile_health_host_adapter.py")
adapter_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter_module
SPEC.loader.exec_module(adapter_module)


class ProfileHealthHostAdapterTest(unittest.TestCase):
    def test_private_root_requires_explicit_test_factory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(adapter_module.HostAdapterError):
                adapter_module.ProfileHealthHostAdapter(fs_root=directory)

    def test_default_adapter_is_read_only_and_has_no_command_side_effect(self):
        calls = []

        def runner(argv, *, input_text=None, env=None, timeout=15):
            calls.append((argv, input_text, env))
            return adapter_module.Result(0)

        with tempfile.TemporaryDirectory() as directory:
            host = adapter_module.ProfileHealthHostAdapter.for_test(
                fs_root=directory, runner=runner, apply=False)
            with self.assertRaisesRegex(adapter_module.HostAdapterError, "read-only"):
                host.close_profile_gates(("ai",))
        self.assertEqual(calls, [])

    def test_manager_uses_sanitized_environment_and_private_root(self):
        calls = []

        def runner(argv, *, input_text=None, env=None, timeout=15):
            calls.append((argv, env))
            return adapter_module.Result(0)

        with tempfile.TemporaryDirectory() as directory:
            adapter = adapter_module.ProfileHealthHostAdapter.for_test(
                fs_root=directory, runner=runner, apply=False)
            adapter._manager_bytes = lambda: b"fixture manager"
            adapter._manager("true")
        self.assertEqual(len(calls), 1)
        env = calls[0][1]
        self.assertEqual(Path(env["FS_ROOT"]), Path(directory).resolve())
        self.assertEqual(env["LC_ALL"], "C")
        self.assertEqual(env["PATH"], adapter_module._SAFE_PATH)
        self.assertNotIn("BASH_ENV", env)
        self.assertNotIn("DNSCOMPLEX_RUN_DIR", env)

    def test_profile_dataplane_identity_matches_installed_health_algorithm(self):
        sas = """ai: #10, ESTABLISHED, IKEv2
  ai: #10, reqid 10, INSTALLED, TUNNEL, ESP
cn: #11, ESTABLISHED, IKEv2
  cn: #11, reqid 11, INSTALLED, TUNNEL, ESP
"""
        identity = adapter_module.profile_dataplane_identity("ai", "10.6.0.2", sas)
        self.assertEqual(
            identity,
            "fc5634a3b9b6a71a142e65b7de83114e840e860dd9ded665afe00935202f28db")

    def test_success_proof_requires_current_vip_identity_count_and_freshness(self):
        identity = "a" * 64
        good = f"10.6.0.2 {identity} 2\n".encode("ascii")
        parsed = adapter_module.parse_success_proof(
            "ai", good, vip="10.6.0.2", identity=identity,
            now=200, mtime=150)
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["count"], 2)
        self.assertEqual(parsed["proof_bytes"], good)
        for raw, vip, expected_identity, mtime in (
            (good, "10.6.0.3", identity, 150),
            (good, "10.6.0.2", "b" * 64, 150),
            (f"10.6.0.2 {identity} 1\n".encode(), "10.6.0.2", identity, 150),
            (f"10.6.0.2  {identity} 2\n".encode(), "10.6.0.2", identity, 150),
            (good, "10.6.0.2", identity, 0),
            (b"bad\n", "10.6.0.2", identity, 150),
        ):
            with self.subTest(vip=vip, mtime=mtime):
                parsed = adapter_module.parse_success_proof(
                    "ai", raw, vip=vip, identity=expected_identity,
                    now=200, mtime=mtime)
                self.assertFalse(parsed["valid"])
        first_pass = adapter_module.parse_success_proof(
            "ai", f"10.6.0.2 {identity} 1\n".encode(), vip="10.6.0.2",
            identity=identity, now=200, mtime=150, minimum_count=1)
        self.assertTrue(first_pass["valid"])
        self.assertEqual(first_pass["count"], 1)

    def test_observe_delegates_to_frozen_manager_and_reads_its_proof(self):
        sas = "ai: #10, ESTABLISHED, IKEv2\n  ai: #10, reqid 10, INSTALLED, TUNNEL, ESP\n"
        identity = adapter_module.profile_dataplane_identity("ai", "10.6.0.2", sas)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = root / "run/dnscomplex/profile-dataplane-ai.success"
            proof.parent.mkdir(parents=True)
            proof.write_text(f"10.6.0.2 {identity} 1\n")
            proof.chmod(0o600)
            adapter = adapter_module.ProfileHealthHostAdapter.for_test(
                fs_root=root, runner=lambda *args, **kwargs: adapter_module.Result(0), apply=False)
            calls = []

            def manager(body, *, timeout=15, check=True):
                calls.append((body, timeout, check))
                return adapter_module.Result(0, identity + "\n")

            adapter._manager = manager
            first = adapter.observe("ai", "10.6.0.2", 4.2)
            adapter.verify_gates = lambda profiles, *, opened: self.assertFalse(opened)
            adapter.verify_gates(("ai",), opened=False)
            proof.write_text(f"10.6.0.2 {identity} 2\n")
            second = adapter.observe("ai", "10.6.0.2", 4.2)
        self.assertEqual(first, {"status": "pass", "profile": "ai", "vip": "10.6.0.2",
                                 "identity": identity, "count": 1})
        self.assertEqual(second, {"status": "pass", "profile": "ai", "vip": "10.6.0.2",
                                  "identity": identity, "count": 2})
        body, timeout, _check = calls[0]
        self.assertIn("WATCHDOG_DEADLINE_MS", body)
        self.assertIn("profile_dataplane_probe_observe ai 10.6.0.2", body)
        self.assertNotIn("profile_dataplane_probe.py --profile", body)
        self.assertLessEqual(timeout, 6.2)

    def test_apply_refuses_when_host_network_namespace_cannot_be_proven(self):
        with mock.patch.object(adapter_module.os, "geteuid", return_value=0), \
             mock.patch.object(adapter_module.os, "stat", side_effect=OSError("no proc namespace")):
            with self.assertRaisesRegex(adapter_module.HostAdapterError, "network namespace"):
                adapter_module.ProfileHealthHostAdapter(apply=True)

    def test_route_readback_requires_expected_device_and_source(self):
        self.assertTrue(adapter_module._default_route_matches(
            "default dev ipsec-ai src 10.6.0.2 proto static\n", "ipsec-ai", "10.6.0.2"))
        self.assertFalse(adapter_module._default_route_matches(
            "default dev ipsec-ai src 10.6.0.3\n", "ipsec-ai", "10.6.0.2"))
        good = '[{"dst":"104.16.248.249","from":"10.6.0.2","dev":"ipsec-ai","table":301,"mark":929}]'
        wrong_source = '[{"dst":"104.16.248.249","from":"10.6.0.3","dev":"ipsec-ai","table":301,"mark":929}]'
        wrong_dev = '[{"dst":"104.16.248.249","from":"10.6.0.2","dev":"ens18","table":301,"mark":929}]'
        self.assertTrue(adapter_module._route_get_matches(
            good, "ipsec-ai", "10.6.0.2", 301, 929, "104.16.248.249"))
        string_fields = '[{"dst":"104.16.248.249","from":"10.6.0.2","dev":"ipsec-ai","table":"301","mark":"0x3a1"}]'
        self.assertTrue(adapter_module._route_get_matches(
            string_fields, "ipsec-ai", "10.6.0.2", 301, 929, "104.16.248.249"))
        self.assertFalse(adapter_module._route_get_matches(
            wrong_source, "ipsec-ai", "10.6.0.2", 301, 929, "104.16.248.249"))
        self.assertFalse(adapter_module._route_get_matches(
            wrong_dev, "ipsec-ai", "10.6.0.2", 301, 929, "104.16.248.249"))
        self.assertFalse(adapter_module._route_get_matches(
            '[{"from":"10.6.0.2","dev":"ipsec-ai","table":301,"mark":929}]',
            "ipsec-ai", "10.6.0.2", 301, 929, "104.16.248.249"))

    def test_readiness_gate_readback_uses_mode_specific_ipv6_semantics(self):
        adapter = adapter_module.ProfileHealthHostAdapter.for_test(
            fs_root="/", runner=lambda *args, **kwargs: adapter_module.Result(0), apply=False)
        states = {"ai_ready4": True, "ai_ready6": False,
                  "cn_ready4": True, "cn_ready6": True}
        adapter.readonly._gate = lambda name, wildcard: states[name]
        adapter.profile_modes = lambda: {"ai": "ipsec", "cn": "xray"}
        adapter.verify_gates(("ai",), opened=True)
        adapter.verify_gates(("cn",), opened=True)
        states["ai_ready6"] = True
        with self.assertRaisesRegex(adapter_module.HostAdapterError, "gate state"):
            adapter.verify_gates(("ai",), opened=True)
        states.update(ai_ready4=False, ai_ready6=False, cn_ready4=False, cn_ready6=False)
        adapter.verify_gates(("ai", "cn"), opened=False)

    def test_protected_success_snapshot_keeps_ipsec_ipv6_gate_closed(self):
        adapter = adapter_module.ProfileHealthHostAdapter.for_test(
            fs_root="/", runner=lambda *args, **kwargs: adapter_module.Result(0), apply=False)
        adapter._selected_transaction_profiles = ("ai",)
        adapter.profile_modes = lambda: {"ai": "ipsec", "cn": "xray"}
        observed = {}
        adapter.readonly.verify_protected_state = lambda snapshot: observed.update(snapshot["gates"])
        adapter._path = lambda path: type("File", (), {"read_bytes": lambda self: b"cfg"})()
        adapter._alias_set_state = lambda _live: {}
        adapter.read_live_nft_json = lambda: {}
        snapshot = {"gates": {"ai4": False, "ai6": False, "cn4": True, "cn6": True},
                    "singbox_config_sha256": adapter_module._sha(b"cfg"),
                    "lan_alias_sets": {}}
        self.assertTrue(adapter.verify_protected_state(snapshot))
        self.assertEqual(observed, {"ai4": True, "ai6": False, "cn4": True, "cn6": True})

    def test_policy_rule_match_understands_json_hex_mark_and_mask(self):
        rule = {"priority": 10201, "fwmark": "0x3a1/0xffffffff", "table": 301}
        self.assertTrue(adapter_module._rule_matches(rule, adapter_module.PROFILES["ai"]))
        stale = dict(rule, priority=10202)
        self.assertFalse(adapter_module._rule_matches(stale, adapter_module.PROFILES["ai"]))

    def test_observer_command_timeout_kills_descendant_process_group(self):
        if sys.platform == "darwin":
            self.skipTest("managed macOS sandbox disallows signaling a private process group")
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "late-write"
            child = ("import pathlib,time; time.sleep(0.8); "
                     f"pathlib.Path({str(marker)!r}).write_text('late')")
            parent = ("import subprocess,sys,time; "
                      f"subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(4)")
            with self.assertRaisesRegex(adapter_module.HostAdapterError, "timed out"):
                adapter_module.ProfileHealthHostAdapter._run_process(
                    (sys.executable, "-c", parent), timeout=0.2)
            time.sleep(1)
            self.assertFalse(marker.exists(), "descendant survived timeout and wrote after rollback")

    def test_probe_counter_readback_requires_exact_unique_comment_and_positive_packets(self):
        rule = {"rule": {"comment": "dnscomplex-ai-dataplane-probe",
                         "expr": [{"counter": {"packets": 2, "bytes": 140}}]}}
        live = {"nftables": [rule]}
        self.assertEqual(adapter_module._probe_counter_packets(
            live, "dnscomplex-ai-dataplane-probe"), 2)
        with self.assertRaises(adapter_module.HostAdapterError):
            adapter_module._probe_counter_packets(
                {"nftables": [{"rule": {"comment": "dnscomplex-ai-dataplane-probe",
                                         "expr": [{"counter": {"packets": 0, "bytes": 0}}]}}]},
                "dnscomplex-ai-dataplane-probe")

    def test_probe_undo_treats_all_absent_owned_assets_as_not_applied(self):
        adapter = adapter_module.ProfileHealthHostAdapter.for_test(
            fs_root="/", runner=lambda *args, **kwargs: adapter_module.Result(0), apply=True)
        adapter.read_live_nft_json = lambda: {"nftables": [
            {"table": {"family": "inet", "name": "dnscomplex"}},
            {"chain": {"family": "inet", "table": "dnscomplex", "name": "output",
                        "type": "route", "hook": "output"}},
        ]}
        adapter.undo_probe_nft({"not": "consulted when no owned assets exist"})

    def test_probe_nft_undo_serializes_native_statement_list(self):
        adapter = adapter_module.ProfileHealthHostAdapter.for_test(
            fs_root="/", runner=lambda *args, **kwargs: adapter_module.Result(0), apply=True)
        adapter._ensure_apply = lambda: None
        live = {"nftables": []}
        inventory = [
            (None, [{"name": "ai_probe_vip4"}],
             {"output": [{"comment": "dnscomplex-ai-dataplane-probe"}]}),
            (None, [], {"output": []}),
        ]
        adapter.read_live_nft_json = lambda: live
        captured = []
        adapter._run = lambda argv, **kwargs: captured.append(kwargs["input_text"]) or \
            adapter_module.Result(0)
        statements = ["delete rule inet dnscomplex output handle 17",
                      "delete set inet dnscomplex ai_probe_vip4"]
        with mock.patch.object(adapter_module._NFT, "_live_inventory",
                               side_effect=inventory), \
             mock.patch.object(adapter_module._NFT, "build_undo", return_value=statements):
            adapter.undo_probe_nft({"owned": "assets"})
        self.assertEqual(captured, ["\n".join(statements) + "\n"])

    def test_rollback_protected_state_expects_only_selected_readiness_sets_closed(self):
        adapter = adapter_module.ProfileHealthHostAdapter.for_test(
            fs_root="/", runner=lambda *args, **kwargs: adapter_module.Result(0), apply=False)
        adapter._selected_transaction_profiles = ("ai",)
        adapter._path = lambda _path: type("File", (), {"read_bytes": lambda self: b"cfg"})()
        adapter._alias_set_state = lambda _live: {}
        adapter.read_live_nft_json = lambda: {}
        observed = {}
        adapter.readonly.verify_protected_state = lambda state: observed.update(state)
        snapshot = {
            "gates": {"ai4": True, "ai6": False, "cn4": True, "cn6": True},
            "singbox_config_sha256": adapter_module._sha(b"cfg"),
            "lan_alias_sets": {},
            "sets": {
                "ai_ready4": {"definition": "ai4-def", "elements": {"wildcard": {"timeout_ms": None}}},
                "ai_ready6": {"definition": "ai6-def", "elements": {}},
                "cn_ready4": {"definition": "cn4-def", "elements": {"wildcard": {"timeout_ms": None}}},
            },
        }
        adapter.verify_rollback(snapshot)
        self.assertEqual(observed["gates"], {"ai4": False, "ai6": False,
                                               "cn4": True, "cn6": True})
        self.assertEqual(observed["sets"]["ai_ready4"]["definition"], "ai4-def")
        self.assertEqual(observed["sets"]["ai_ready4"]["elements"], {})
        self.assertEqual(observed["sets"]["ai_ready6"]["elements"], {})
        self.assertEqual(observed["sets"]["cn_ready4"]["elements"],
                         snapshot["sets"]["cn_ready4"]["elements"])

    def test_timer_poll_failure_restores_previously_active_timer(self):
        adapter = adapter_module.ProfileHealthHostAdapter.for_test(
            fs_root="/", runner=lambda *args, **kwargs: adapter_module.Result(0), apply=True)
        adapter._ensure_apply = lambda: None
        calls = []
        adapter._run = lambda argv, **kwargs: calls.append(tuple(argv)) or adapter_module.Result(0)
        adapter._unit_active = mock.Mock(side_effect=[
            True, True, RuntimeError("systemd state unavailable"), False, True])
        with self.assertRaisesRegex(RuntimeError, "systemd state unavailable"):
            adapter.stop_health_timer_and_wait(1)
        self.assertIn(("systemctl", "stop", "dnscomplex-health.timer"), calls)
        self.assertIn(("systemctl", "start", "dnscomplex-health.timer"), calls)

    def test_timer_stop_lost_reply_restores_timer_before_rethrow(self):
        state = {"timer": True, "service": False}
        calls = []

        def runner(argv, *, input_text=None, env=None, timeout=15):
            argv = tuple(argv)
            calls.append(argv)
            if argv[:3] == ("systemctl", "is-active", "--quiet"):
                active = state["timer" if argv[3] == "dnscomplex-health.timer" else "service"]
                return adapter_module.Result(0 if active else 3)
            if argv == ("systemctl", "stop", "dnscomplex-health.timer"):
                state["timer"] = False
                raise RuntimeError("systemctl stop reply lost after stop")
            if argv == ("systemctl", "start", "dnscomplex-health.timer"):
                state["timer"] = True
                return adapter_module.Result(0)
            self.fail(f"unexpected command: {argv}")

        adapter = adapter_module.ProfileHealthHostAdapter.for_test(
            fs_root="/", runner=runner, apply=True)
        adapter._ensure_apply = lambda: None
        with self.assertRaisesRegex(RuntimeError, "reply lost after stop"):
            adapter.stop_health_timer_and_wait(1)
        self.assertTrue(state["timer"])
        self.assertIn(("systemctl", "start", "dnscomplex-health.timer"), calls)


if __name__ == "__main__":
    unittest.main()
