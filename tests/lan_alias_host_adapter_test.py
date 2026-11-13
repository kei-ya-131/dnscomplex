#!/usr/bin/env python3
import importlib.util
import hashlib
import json
import os
import sys
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
D6_INSTALLER_ENV = "DNSCOMPLEX_TEST_BASELINE_INSTALLER"
D6_INSTALLER_SHA256 = "d6a0c37f9b337900cc19369c8da64b5dfce1a24cb9a3366d9e3579ddd1ce8624"
SPEC = importlib.util.spec_from_file_location(
    "lan_alias_host_adapter", ROOT / "tools/lan_alias_host_adapter.py")
adapter_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter_module
SPEC.loader.exec_module(adapter_module)


class Runner:
    def __init__(self, fail=()):
        self.calls = []
        self.fail = set(fail)

    def __call__(self, argv, *, input_text=None, env=None):
        self.calls.append((tuple(argv), input_text, env))
        if argv in self.fail:
            return adapter_module.Result(1, "", "stub failure")
        if argv[:3] == ("nft", "-j", "list"):
            name = argv[-1]
            return adapter_module.Result(0, json.dumps({"nftables": [{"set": {
                "family": "inet", "table": "dnscomplex", "name": name,
                "type": "ipv4_addr", "elem": []}}]}))
        return adapter_module.Result(0, "")


def fake_root(path: Path):
    config = path / "etc/dnscomplex/config.env"
    config.parent.mkdir(parents=True)
    config.write_text("DEPLOY_MODE='vlan-gateway'\nWAN_IFACE='eth0'\nLAN_VLAN_ID='20'\nAI_EGRESS_MODE='ipsec'\nCN_EGRESS_MODE='ipsec'\nAI_MARK='0x301'\nCN_MARK='0x351'\nSINGBOX_AUTO_REDIRECT_OUTPUT_MARK='0x2024'\n")
    config.chmod(0o600)
    for target, body in (("etc/sing-box/config.json", b"{}\n"),
                         ("etc/nftables.d/dnscomplex.nft", b"table inet dnscomplex {}\n")):
        file = path / target
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(body)


class LanAliasHostAdapterTest(unittest.TestCase):
    def test_verify_alias_absent_accepts_removed_sets_rules_address_and_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fake_root(root)

            class AbsentRunner(Runner):
                def __call__(self, argv, *, input_text=None, env=None):
                    self.calls.append((tuple(argv), input_text, env))
                    if argv == ("nft", "-j", "-a", "list", "table", "inet", "dnscomplex"):
                        return adapter_module.Result(0, json.dumps({"nftables": [
                            {"set": {"family": "inet", "table": "dnscomplex",
                                     "name": "ai4", "elem": ["203.0.113.0/24"]}},
                            {"rule": {"family": "inet", "table": "dnscomplex",
                                      "chain": "output", "comment": "legacy-rule",
                                      "handle": 8, "expr": []}},
                        ]}))
                    if argv == ("ip", "-j", "address", "show"):
                        return adapter_module.Result(0, json.dumps([
                            {"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8}]}
                        ]))
                    return super().__call__(argv, input_text=input_text, env=env)

            adapter = adapter_module.LanAliasHostAdapter(
                fs_root=root, runner=AbsentRunner(), require_root=False)
            adapter.verify_alias_absent()

    def test_verify_alias_absent_rejects_each_partial_owned_residue(self):
        cases = (
            "set", "rule", "address", "state",
        )
        for residue in cases:
            with self.subTest(residue=residue), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); fake_root(root)
                nftables = []
                if residue == "set":
                    nftables.append({"set": {"family": "inet", "table": "dnscomplex",
                                              "name": "lan_alias_ready4", "elem": []}})
                if residue == "rule":
                    nftables.append({"rule": {"family": "inet", "table": "dnscomplex",
                                               "chain": "output",
                                               "comment": "dnscomplex-lan-alias-owned-source-guard",
                                               "handle": 99, "expr": []}})

                class ResidueRunner(Runner):
                    def __call__(self, argv, *, input_text=None, env=None):
                        self.calls.append((tuple(argv), input_text, env))
                        if argv == ("nft", "-j", "-a", "list", "table", "inet", "dnscomplex"):
                            return adapter_module.Result(0, json.dumps({"nftables": nftables}))
                        if argv == ("ip", "-j", "address", "show"):
                            addr_info = [{"local": "198.18.255.254", "prefixlen": 32,
                                          "label": "lo:dc-alias"}] if residue == "address" else []
                            return adapter_module.Result(0, json.dumps([
                                {"ifname": "lo", "addr_info": addr_info}
                            ]))
                        return super().__call__(argv, input_text=input_text, env=env)

                if residue == "state":
                    state = root / "var/lib/dnscomplex/lan-alias.json"
                    state.parent.mkdir(parents=True, exist_ok=True)
                    state.write_text("{}\n")
                adapter = adapter_module.LanAliasHostAdapter(
                    fs_root=root, runner=ResidueRunner(), require_root=False)
                with self.assertRaises(adapter_module.HostAdapterError):
                    adapter.verify_alias_absent()

    def test_rollback_snippet_works_with_real_d6_manager_when_alias_state_is_absent(self):
        installer_path = os.environ.get(D6_INSTALLER_ENV)
        if not installer_path:
            self.skipTest(
                f"set {D6_INSTALLER_ENV} to the verified D6 installer artifact "
                f"(SHA256 {D6_INSTALLER_SHA256}) to run this legacy-manager acceptance case")
        installer = Path(installer_path).read_bytes()
        self.assertEqual(hashlib.sha256(installer).hexdigest(), D6_INSTALLER_SHA256)
        lines = installer.decode().splitlines()
        start = next(i for i, line in enumerate(lines)
                     if line.strip() == "write_file_atomic /usr/local/sbin/dnscomplex <<'MANAGER'") + 1
        end = next(i for i in range(start, len(lines)) if lines[i].strip() == "MANAGER")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager = root / "dnscomplex-manager"
            manager.write_text("\n".join(lines[start:end]) + "\n")
            fakebin = root / "bin"
            fakebin.mkdir()
            nft = fakebin / "nft"
            nft.write_text("#!/bin/sh\ncat >/dev/null\nexit 0\n")
            nft.chmod(0o755)
            swanctl = fakebin / "swanctl"
            swanctl.write_text("#!/bin/sh\nexit 0\n")
            swanctl.chmod(0o755)
            timeout = fakebin / "timeout"
            timeout.write_text("#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do case \"$1\" in --signal=*|--kill-after=*|[0-9]*s) shift ;; *) break ;; esac; done\nexec \"$@\"\n")
            timeout.chmod(0o755)
            alias_state = root / "var/lib/dnscomplex/lan-alias.json"
            alias_state.parent.mkdir(parents=True)
            recovery = adapter_module.RECOVER_MANAGER.replace(
                "source /usr/local/sbin/dnscomplex", ": # already sourced from exact D6 fixture")
            script = """set -euo pipefail
source "$D6_MANAGER"
load_config() { AI_EGRESS_MODE=ipsec; CN_EGRESS_MODE=ipsec; }
ipsec_profile_sa_ready() { :; }
ensure_policy_route_profile() { :; }
sync_ipsec_nat_profile() { :; }
sync_singbox_ipsec_bind_addresses() { :; }
ipsec_vip_from_sas() { [[ "$1" == ai ]] && printf '10.6.0.2\\n' || printf '10.7.0.2\\n'; }
ipsec_profile_runtime_ready() { :; }
ipsec_nat_profile_matches() { :; }
ipsec_bind_profile_matches() { :; }
""" + recovery
            env = dict(os.environ, D6_MANAGER=str(manager), DNSCOMPLEX_FS_ROOT=str(root),
                       PATH=f"{fakebin}:{os.environ.get('PATH', '')}",
                       DNSCOMPLEX_RESTORE_AI_OPEN="0", DNSCOMPLEX_RESTORE_CN_OPEN="0")
            result = subprocess.run(("bash", "-c", script), env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(alias_state.exists())

    def test_config_parser_rejects_unknown_duplicate_and_multitoken_values(self):
        parse = adapter_module.parse_config_env
        self.assertEqual(parse("AI_EGRESS_MODE='ipsec'\n"), {"AI_EGRESS_MODE": "ipsec"})
        self.assertEqual(parse("DEFAULT_DNS_UPSTREAMS='https://resolver.example/dns tls://1.1.1.1'\n"), {})
        for text in ("bad-key=value\n", "PATH='/tmp'\n", "AI_EGRESS_MODE=x\nAI_EGRESS_MODE=y\n",
                     "AI_EGRESS_MODE='two words'\n", "UNUSED_SETTING=too many words\n",
                     "AI_EGRESS_MODE='unterminated\n"):
            with self.subTest(text=text), self.assertRaises(adapter_module.HostAdapterError):
                parse(text)
        with self.assertRaisesRegex(adapter_module.HostAdapterError, "duplicate"):
            parse("AI_DNS_UPSTREAMS='https://resolver.example/dns'\n"
                  "AI_DNS_UPSTREAMS='https://other.example/dns'\n")

    def test_config_parser_accepts_empty_optional_vlan_id_only(self):
        parse = adapter_module.parse_config_env
        self.assertEqual(parse("DEPLOY_MODE=routeros-policy\nLAN_VLAN_ID=\n"),
                         {"DEPLOY_MODE": "routeros-policy", "LAN_VLAN_ID": ""})
        with self.assertRaisesRegex(adapter_module.HostAdapterError, "config value"):
            parse("AI_EGRESS_MODE=\n")

    def test_config_parser_accepts_other_installer_managed_scalar_keys(self):
        parsed = adapter_module.parse_config_env(
            "LAN_CLIENT_IPV4_CIDR=192.168.50.0/24\nAI_MARK_DEC=769\nCN_MARK_DEC=849\n"
            "SINGBOX_AUTO_REDIRECT_INPUT_MARK=0x2023\n"
            "SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC=8227\n"
            "SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC=8228\nAI_TABLE=2023\nCN_TABLE=2024\n"
            "AI_IKE_REMOTE=198.51.100.1\nCN_IKE_REMOTE=198.51.100.2\n")
        self.assertEqual(parsed, {})
        self.assertNotIn("AI_IKE_REMOTE", parsed)

    def test_swanctl_parser_requires_one_established_installed_ipv4_per_profile(self):
        healthy = """ai: #10, ESTABLISHED, IKEv2
  local 192.0.2.1[4500] [10.6.0.2]
  ai: #10, reqid 10, INSTALLED, TUNNEL, ESP
cn: #11, ESTABLISHED, IKEv2
  local 192.0.2.2[4500] [10.7.0.2]
  cn: #11, reqid 11, INSTALLED, TUNNEL, ESP
"""
        self.assertEqual(adapter_module.parse_swanctl_vips(healthy),
                         {"ai": "10.6.0.2", "cn": "10.7.0.2"})
        for broken in (healthy.replace("INSTALLED", "ROUTED", 1),
                       healthy.replace("[10.6.0.2]", "[10.6.0.3] [10.6.0.2]")):
            with self.assertRaises(adapter_module.HostAdapterError):
                adapter_module.parse_swanctl_vips(broken)

    def test_conntrack_normalization_ignores_only_countdown_timeout(self):
        first = ("ipv4 2 udp 17 29 src=10.0.0.1 dst=192.0.2.1 sport=1 dport=2 "
                 "src=192.0.2.1 dst=10.0.0.1 sport=2 dport=1 mark=3 id=7")
        aged = first.replace("17 29", "17 1")
        self.assertEqual(adapter_module.stable_conntrack(first)["7"]["identity"],
                         adapter_module.stable_conntrack(aged)["7"]["identity"])
        self.assertEqual(adapter_module.stable_conntrack(first)["7"]["timeout_s"], 29)
        self.assertEqual(adapter_module.stable_conntrack(aged)["7"]["timeout_s"], 1)
        self.assertNotEqual(adapter_module.stable_conntrack(first),
                            adapter_module.stable_conntrack(first.replace("mark=3", "mark=4")))
        self.assertNotEqual(adapter_module.stable_conntrack(first),
                            adapter_module.stable_conntrack(first.replace("id=7", "id=8")))

    def test_singbox_socket_parser_requires_exact_connected_single_pid_ownership(self):
        rows = """tcp ESTAB 0 0 192.0.2.10:50001 198.51.100.80:443 users:(("sing-box",pid=123,fd=8))
udp ESTAB 0 0 [2001:db8::1]:53123 [2001:db8::2]:53 users:(("sing-box",pid=123,fd=9))
udp ESTAB 0 0 [fe80::1%eth0]:53124 [fe80::2%eth0]:53 users:(("sing-box",pid=123,fd=14))
tcp ESTAB 0 0 192.168.50.42:40000 203.0.113.20:443 users:(("other",pid=123,fd=10))
tcp LISTEN 0 128 192.0.2.10:8443 *:* users:(("sing-box",pid=123,fd=11))
tcp ESTAB 0 0 192.0.2.10:50002 198.51.100.81:443 users:(("sing-box",pid=123,fd=12),("worker",pid=456,fd=2))
tcp ESTAB 0 0 192.0.2.10:50003 198.51.100.82:443 users:(("sing-box",pid=999,fd=13))
"""
        parsed = adapter_module.parse_singbox_sockets(rows, 123)
        self.assertEqual(parsed, {
            ("tcp", "192.0.2.10", 50001, "198.51.100.80", 443),
            ("udp", "2001:db8::1", 53123, "2001:db8::2", 53),
        })

    def test_singbox_socket_parser_normalizes_only_valid_ipv4_bind_device_suffix(self):
        rows = '''tcp ESTAB 0 0 198.18.1.1%ens18:39004 198.18.1.2:19444 users:(("sing-box",pid=334933,fd=15))
tcp ESTAB 0 0 198.18.1.3%this-interface-name-is-too-long:39005 198.18.1.2:19444 users:(("sing-box",pid=334933,fd=16))
tcp ESTAB 0 0 198.18.1.4%ens18%extra:39006 198.18.1.2:19444 users:(("sing-box",pid=334933,fd=17))
tcp ESTAB 0 0 198.18.1.5%bad/if:39007 198.18.1.2:19444 users:(("sing-box",pid=334933,fd=18))
tcp ESTAB 0 0 [2001:db8::1%ens18]:39008 [2001:db8::2]:19444 users:(("sing-box",pid=334933,fd=19))
tcp ESTAB 0 0 198.18.1.6%ens18:39009 198.18.1.2:19444 users:(("other",pid=334933,fd=20))
'''
        self.assertEqual(adapter_module.parse_singbox_sockets(rows, 334933), {
            ("tcp", "198.18.1.1", 39004, "198.18.1.2", 19444),
        })

    def test_conntrack_identity_uses_tuples_mark_and_id_but_ignores_tcp_state(self):
        first = ("ipv4 2 tcp 6 30 SYN_SENT src=192.0.2.10 dst=198.51.100.80 "
                 "sport=50001 dport=443 src=198.51.100.80 dst=192.0.2.10 "
                 "sport=443 dport=50001 mark=8228 use=1 id=7")
        progressed = first.replace("30 SYN_SENT", "25 ESTABLISHED")
        one = adapter_module.stable_conntrack(first)["7"]
        two = adapter_module.stable_conntrack(progressed)["7"]
        self.assertEqual(one["identity"], two["identity"])
        self.assertEqual(one["timeout_s"], 30)
        self.assertNotEqual(one["identity"], adapter_module.stable_conntrack(
            progressed.replace("mark=8228", "mark=8229"))["7"]["identity"])
        self.assertNotEqual(one["identity"], adapter_module.stable_conntrack(
            progressed.replace("dst=198.51.100.80", "dst=198.51.100.81", 1))["7"]["identity"])

    def test_conntrack_identity_preserves_icmp_type_code_and_identifier_in_both_directions(self):
        icmp4 = ("ipv4 2 icmp 1 29 src=192.0.2.10 dst=198.51.100.80 type=8 code=0 id=123 "
                 "src=198.51.100.80 dst=192.0.2.10 type=0 code=0 id=123 mark=0 use=1 id=70")
        icmp6 = ("ipv6 10 icmpv6 58 29 src=2001:db8::1 dst=2001:db8::2 type=128 code=0 id=456 "
                 "src=2001:db8::2 dst=2001:db8::1 type=129 code=0 id=456 mark=0 use=1 id=71")
        four = adapter_module.stable_conntrack(icmp4)["70"]["identity"]
        six = adapter_module.stable_conntrack(icmp6)["71"]["identity"]
        self.assertEqual(four[4], ("192.0.2.10", "198.51.100.80", 8, 0, 123))
        self.assertEqual(four[5], ("198.51.100.80", "192.0.2.10", 0, 0, 123))
        self.assertEqual(six[4], ("2001:db8::1", "2001:db8::2", 128, 0, 456))
        self.assertEqual(six[5], ("2001:db8::2", "2001:db8::1", 129, 0, 456))
        changed = adapter_module.stable_conntrack(icmp4.replace("type=0 code=0 id=123", "type=0 code=1 id=123"))["70"]
        self.assertNotEqual(four, changed["identity"])

    def test_conntrack_identity_supports_observed_igmp_without_inventing_ports(self):
        igmp = ("ipv4 2 unknown 2 30 UNREPLIED src=192.0.2.10 dst=224.0.0.1 "
                "src=192.0.2.10 dst=224.0.0.1 mark=0 use=1 id=72")
        identity = adapter_module.stable_conntrack(igmp)["72"]["identity"]
        self.assertEqual(identity[2:4], ("igmp", 2))
        self.assertEqual(identity[1], 0)
        self.assertEqual(identity[4], ("192.0.2.10", "224.0.0.1"))
        self.assertEqual(identity[5], ("192.0.2.10", "224.0.0.1"))
        unknown = igmp.replace("unknown 2", "unknown 47")
        with self.assertRaisesRegex(adapter_module.HostAdapterError, "unsupported protocol"):
            adapter_module.stable_conntrack(unknown)
        zoned = igmp.replace(" UNREPLIED", " zone=17 UNREPLIED")
        self.assertEqual(adapter_module.stable_conntrack(zoned)["72"]["identity"][1], 17)
        bad_af_code = igmp.replace("ipv4 2", "ipv4 10")
        with self.assertRaisesRegex(adapter_module.HostAdapterError, "family code"):
            adapter_module.stable_conntrack(bad_af_code)

    def test_socket_correlation_skips_non_port_conntrack_tuples(self):
        igmp = ("ipv4 2 unknown 2 30 UNREPLIED src=192.0.2.10 dst=224.0.0.1 "
                "src=192.0.2.10 dst=224.0.0.1 mark=0 use=1 id=72")
        tcp = ("ipv4 2 tcp 6 30 ESTABLISHED src=192.0.2.10 dst=198.51.100.80 "
               "sport=50001 dport=443 src=198.51.100.80 dst=192.0.2.10 "
               "sport=443 dport=50001 mark=8228 use=1 id=73")
        sockets = {("tcp", "192.0.2.10", 50001, "198.51.100.80", 443)}
        parsed = adapter_module.stable_conntrack(igmp + "\n" + tcp)
        self.assertEqual(adapter_module.correlate_singbox_conntrack_ids(sockets, parsed), {"73"})

    def test_conntrack_socket_correlation_requires_exact_original_5tuple(self):
        ct = ("ipv4 2 tcp 6 30 ESTABLISHED src=192.0.2.10 dst=198.51.100.80 "
              "sport=50001 dport=443 src=198.51.100.80 dst=192.0.2.10 "
              "sport=443 dport=50001 mark=8228 id=7")
        sockets = adapter_module.parse_singbox_sockets(
            'tcp ESTAB 0 0 192.0.2.10:50001 198.51.100.80:443 users:(("sing-box",pid=123,fd=8))\n',
            123)
        self.assertEqual(adapter_module.correlate_singbox_conntrack_ids(
            sockets, adapter_module.stable_conntrack(ct)), {"7"})
        changed = adapter_module.stable_conntrack(ct.replace("dport=443", "dport=444", 1))
        self.assertEqual(adapter_module.correlate_singbox_conntrack_ids(sockets, changed), set())
        udp6 = ("ipv6 10 udp 17 30 src=2001:db8::1 dst=2001:db8::2 sport=53123 dport=53 "
                "src=2001:db8::2 dst=2001:db8::1 sport=53 dport=53123 mark=0 id=8")
        udp6_socket = adapter_module.parse_singbox_sockets(
            'udp ESTAB 0 0 [2001:db8::1]:53123 [2001:db8::2]:53 '
            'users:(("sing-box",pid=123,fd=9))\n', 123)
        self.assertEqual(adapter_module.correlate_singbox_conntrack_ids(
            udp6_socket, adapter_module.stable_conntrack(udp6)), {"8"})

    def test_protected_state_allows_natural_loss_of_local_proxy_socket_only(self):
        forwarded = ("ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.50.42 "
                     "dst=203.0.113.20 sport=44321 dport=443 src=203.0.113.20 "
                     "dst=192.168.50.42 sport=443 dport=443 mark=8228 use=1 id=100")
        # Router-originated socket tuple: sing-box may close this local underlay
        # socket when the required service restart replaces its process.
        local_proxy = ("ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 "
                       "dst=198.51.100.80 sport=50001 dport=443 src=198.51.100.80 "
                       "dst=192.0.2.10 sport=443 dport=50001 mark=0 use=1 id=200")

        class CaptureRunner:
            def __init__(self, before, after):
                self.before, self.after = before, after
                self.captures = 0
                self.pid = 123

            def __call__(self, argv, *, input_text=None, env=None):
                if argv == ("nft", "-j", "-a", "list", "table", "inet", "dnscomplex"):
                    entries = [forwarded_set]
                    return adapter_module.Result(0, json.dumps({"nftables": entries}))
                if argv[:3] == ("nft", "-j", "list"):
                    return adapter_module.Result(0, json.dumps({"nftables": [{"set": {
                        "family": "inet", "table": "dnscomplex", "name": argv[-1], "elem": []
                    }}]}))
                if argv[0] == "conntrack":
                    rows = self.before if self.captures == 0 else self.after
                    self.captures += 1
                    return adapter_module.Result(0, "\n".join(rows) + ("\n" if rows else ""))
                if argv[0] == "timeout":
                    return adapter_module.Result(0, "")
                if argv[:2] == ("systemctl", "is-active"):
                    return adapter_module.Result(0)
                if argv[:2] == ("systemctl", "show"):
                    return adapter_module.Result(0, f"{self.pid}\n")
                if argv == ("ss", "-H", "-tunap"):
                    return adapter_module.Result(0,
                        f'tcp ESTAB 0 0 192.0.2.10:50001 198.51.100.80:443 '
                        f'users:(("sing-box",pid={self.pid},fd=8))\n')
                raise AssertionError(f"unexpected read-only command: {argv}")

        forwarded_set = {"set": {"family": "inet", "table": "dnscomplex", "name": "ai4",
                                 "elem": ["203.0.113.0/24"]}}
        cases = ((None, True, False),
                 (local_proxy.replace("ESTABLISHED", "CLOSE_WAIT"), False, False),
                 (None, False, True))
        for progressed_or_closed, restart_recorded, expect_refusal in cases:
            with self.subTest(local_socket=progressed_or_closed,
                              restart_recorded=restart_recorded):
                after = [forwarded] + ([progressed_or_closed] if progressed_or_closed else [])
                runner = CaptureRunner([forwarded, local_proxy], after)
                adapter = adapter_module.LanAliasHostAdapter(runner=runner, require_root=False)
                baseline = adapter.capture_protected_state()
                if progressed_or_closed is None and restart_recorded:
                    runner.pid = 124
                    adapter._record_restart(123, 124)
                # Expected: the LAN-forwarded tuple remains exactly protected,
                # while a router-local sing-box socket may progress or close
                # when its owning process is restarted. Without restart evidence,
                # an otherwise active local CT entry remains protected.
                if expect_refusal:
                    with self.assertRaisesRegex(adapter_module.HostAdapterError,
                                                "conntrack entry changed"):
                        adapter.verify_protected_state(baseline)
                else:
                    adapter.verify_protected_state(baseline)

    def test_protected_state_still_rejects_natural_loss_of_forwarded_tuple(self):
        forwarded = ("ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.50.42 "
                     "dst=203.0.113.20 sport=44321 dport=443 src=203.0.113.20 "
                     "dst=192.168.50.42 sport=443 dport=443 mark=8228 use=1 id=100")

        class CaptureRunner:
            def __init__(self): self.captures = 0; self.pid = 123
            def __call__(self, argv, *, input_text=None, env=None):
                if argv == ("nft", "-j", "-a", "list", "table", "inet", "dnscomplex"):
                    return adapter_module.Result(0, json.dumps({"nftables": [
                        {"set": {"family": "inet", "table": "dnscomplex", "name": "ai4",
                                 "elem": ["203.0.113.0/24"]}}
                    ]}))
                if argv[:3] == ("nft", "-j", "list"):
                    return adapter_module.Result(0, json.dumps({"nftables": [{"set": {
                        "family": "inet", "table": "dnscomplex", "name": argv[-1], "elem": []
                    }}]}))
                if argv[0] == "conntrack":
                    self.captures += 1
                    return adapter_module.Result(0, forwarded + "\n" if self.captures == 1 else "")
                if argv[0] == "timeout": return adapter_module.Result(0, "")
                if argv[:2] == ("systemctl", "is-active"): return adapter_module.Result(0)
                if argv[:2] == ("systemctl", "show"): return adapter_module.Result(0, f"{self.pid}\n")
                if argv == ("ss", "-H", "-tunap"): return adapter_module.Result(0, "")
                raise AssertionError(f"unexpected read-only command: {argv}")

        adapter = adapter_module.LanAliasHostAdapter(runner=CaptureRunner(), require_root=False)
        baseline = adapter.capture_protected_state()
        with self.assertRaisesRegex(adapter_module.HostAdapterError, "conntrack entry changed"):
            adapter.verify_protected_state(baseline)

    def test_protected_state_allows_forwarded_conntrack_loss_only_after_captured_timeout(self):
        dns_udp = ("ipv4 2 udp 17 1 src=192.168.50.42 dst=203.0.113.53 sport=53123 dport=53 "
                   "src=203.0.113.53 dst=192.168.50.42 sport=53 dport=53123 mark=8228 id=300")

        class DnsRunner:
            def __init__(self): self.ct_reads = 0; self.pid = 123
            def __call__(self, argv, *, input_text=None, env=None):
                if argv == ("nft", "-j", "-a", "list", "table", "inet", "dnscomplex"):
                    return adapter_module.Result(0, json.dumps({"nftables": [{"set": {
                        "family": "inet", "table": "dnscomplex", "name": "ai4", "elem": []
                    }}]}))
                if argv[:3] == ("nft", "-j", "list"):
                    return adapter_module.Result(0, json.dumps({"nftables": [{"set": {
                        "family": "inet", "table": "dnscomplex", "name": argv[-1], "elem": []
                    }}]}))
                if argv[0] == "conntrack":
                    self.ct_reads += 1
                    return adapter_module.Result(0, dns_udp + "\n" if self.ct_reads == 1 else "")
                if argv[0] == "timeout": return adapter_module.Result(0, "")
                if argv[:2] == ("systemctl", "is-active"): return adapter_module.Result(0)
                if argv[:2] == ("systemctl", "show"): return adapter_module.Result(0, f"{self.pid}\n")
                if argv == ("ss", "-H", "-tunap"): return adapter_module.Result(0, "")
                raise AssertionError(f"unexpected read-only command: {argv}")

        adapter = adapter_module.LanAliasHostAdapter(runner=DnsRunner(), require_root=False)
        baseline = adapter.capture_protected_state()
        # Simulate a verified gap longer than the captured UDP CT remaining TTL.
        end = time.monotonic() - 2
        baseline["conntrack_capture_interval"] = (end - 0.01, end)
        adapter.verify_protected_state(baseline)

    def test_protected_state_allows_expired_timed_set_member_but_keeps_set(self):
        class ExpiringSetRunner:
            def __init__(self): self.captures = 0; self.pid = 123
            def __call__(self, argv, *, input_text=None, env=None):
                if argv == ("nft", "-j", "-a", "list", "table", "inet", "dnscomplex"):
                    elem = [{"elem": {"val": "203.0.113.0/24", "timeout": 1000,
                                      "expires": 1}}] if self.captures == 0 else []
                    return adapter_module.Result(0, json.dumps({"nftables": [{"set": {
                        "family": "inet", "table": "dnscomplex", "name": "ai4",
                        "type": "ipv4_addr", "flags": ["timeout"],
                        "elem": elem,
                    }}]}))
                if argv[:3] == ("nft", "-j", "list"):
                    return adapter_module.Result(0, json.dumps({"nftables": [{"set": {
                        "family": "inet", "table": "dnscomplex", "name": argv[-1], "elem": []
                    }}]}))
                if argv[0] == "conntrack":
                    self.captures += 1
                    return adapter_module.Result(0, "")
                if argv[0] == "timeout": return adapter_module.Result(0, "")
                if argv[:2] == ("systemctl", "is-active"): return adapter_module.Result(0)
                if argv[:2] == ("systemctl", "show"): return adapter_module.Result(0, f"{self.pid}\n")
                if argv == ("ss", "-H", "-tunap"): return adapter_module.Result(0, "")
                raise AssertionError(f"unexpected read-only command: {argv}")

        adapter = adapter_module.LanAliasHostAdapter(runner=ExpiringSetRunner(), require_root=False)
        baseline = adapter.capture_protected_state()
        time.sleep(0.01)
        adapter.verify_protected_state(baseline)

    def test_protected_set_snapshot_keeps_existing_members_but_excludes_owned_alias_sets(self):
        snapshot = {"nftables": [
            {"set": {"family": "inet", "table": "dnscomplex", "name": "ai4",
                     "elem": ["203.0.113.0/24", {"elem": "198.51.100.0/24", "expires": 9000}]}},
            {"set": {"family": "inet", "table": "dnscomplex", "name": "lan_alias_source4",
                     "elem": ["198.18.255.254"]}},
            {"set": {"family": "ip", "table": "dnscomplex", "name": "foreign",
                     "elem": ["192.0.2.0/24"]}},
        ]}
        protected = adapter_module._protected_sets(snapshot)
        self.assertEqual(protected["ai4"]["definition"],
                         (None, (), None, None, None, None, None, None, None))
        self.assertEqual(len(protected["ai4"]["elements"]), 2)
        self.assertNotIn("lan_alias_source4", protected)
        with self.assertRaisesRegex(adapter_module.HostAdapterError, "duplicated"):
            adapter_module._protected_sets({"nftables": [
                {"set": {"family": "inet", "table": "dnscomplex", "name": "ai4", "elem": []}},
                {"set": {"family": "inet", "table": "dnscomplex", "name": "ai4", "elem": []}},
        ]})

    def test_protected_set_snapshot_accepts_real_timeout_val_wrapper_and_records_remaining_ttl(self):
        snapshot = {"nftables": [{"set": {
            "family": "inet", "table": "dnscomplex", "name": "ai4",
            "type": "ipv4_addr", "flags": ["timeout"], "handle": 12,
            "elem": [{"elem": {"val": "203.0.113.0/24", "timeout": 86400000,
                                 "expires": 4172}}],
        }}]}
        protected = adapter_module._protected_sets(snapshot)
        self.assertEqual(protected["ai4"]["definition"],
                         ("ipv4_addr", ("timeout",), None, None,
                          None, None, None, 12, None))
        self.assertEqual(len(protected["ai4"]["elements"]), 1)
        self.assertEqual(next(iter(protected["ai4"]["elements"].values())),
                         {"timeout_ms": 86400000, "expires_ms": 4172})

    def test_protected_set_snapshot_rejects_malformed_timeout_wrapper_or_definition(self):
        base = {"family": "inet", "table": "dnscomplex", "name": "ai4",
                "type": "ipv4_addr", "flags": ["timeout"]}
        malformed = (
            {**base, "elem": [{"elem": {"val": "203.0.113.0/24", "timeout": "x",
                                          "expires": 10}}]},
            {**base, "elem": [{"elem": {"timeout": 86400000, "expires": 10}}]},
            {**base, "flags": "timeout", "elem": []},
            {**base, "timeout": -1, "elem": []},
            {**base, "unknown-definition-field": 1, "elem": []},
        )
        for entry in malformed:
            with self.subTest(entry=entry), self.assertRaises(adapter_module.HostAdapterError):
                adapter_module._protected_sets({"nftables": [{"set": entry}]})

    def test_nft_set_readback_treats_only_omitted_elem_as_empty(self):
        empty = {"nftables": [{"set": {"family": "inet", "table": "dnscomplex",
                                         "name": "lan_alias_ready4", "type": "ipv4_addr"}}]}
        self.assertEqual(adapter_module._set_elems(empty, "lan_alias_ready4"), [])
        for invalid in (
            {"nftables": [{"set": {"family": "inet", "table": "dnscomplex",
                                     "name": "lan_alias_ready4", "elem": None}}]},
            {"nftables": [{"set": {"family": "inet", "table": "dnscomplex",
                                     "name": "lan_alias_ready4", "elem": {}}}]},
            {"nftables": [{"set": {"family": "ip", "table": "dnscomplex",
                                     "name": "lan_alias_ready4"}}]},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(adapter_module.HostAdapterError):
                adapter_module._set_elems(invalid, "lan_alias_ready4")

    def test_command_runner_uses_argv_and_dry_run_blocks_every_mutator(self):
        runner = Runner()
        adapter = adapter_module.LanAliasHostAdapter(runner=runner)
        with self.assertRaisesRegex(adapter_module.HostAdapterError, "dry-run"):
            adapter._run(("nft", "-f", "-"), input_text="flush ruleset\n", mutate=True)
        self.assertEqual(runner.calls, [])
        adapter._run(("nft", "-j", "list", "table", "inet", "dnscomplex"))
        self.assertIsInstance(runner.calls[-1][0], tuple)
        self.assertNotIn("shell", runner.calls[-1][0])

    def test_host_path_boundary_rejects_foreign_and_symlink_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            adapter = adapter_module.LanAliasHostAdapter(fs_root=root, require_root=False)
            with self.assertRaises(adapter_module.HostAdapterError):
                adapter._path("/etc/passwd")
            (root / "etc").mkdir()
            (root / "etc/dnscomplex").symlink_to(root / "outside")
            with self.assertRaisesRegex(adapter_module.HostAdapterError, "symlink"):
                adapter._path("/etc/dnscomplex/config.env")

    def test_profile_mode_and_marks_are_parsed_without_shell_evaluation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fake_root(root)
            runner = Runner()
            adapter = adapter_module.LanAliasHostAdapter(fs_root=root, runner=runner, require_root=False)
            self.assertEqual(adapter.profile_modes(), {"ai": "ipsec", "cn": "ipsec"})
            cfg = root / "etc/dnscomplex/config.env"
            cfg.write_text(cfg.read_text().replace("AI_MARK='0x301'", "AI_MARK='0x100000000;touch /tmp/pwn'"))
            cfg.chmod(0o600)
            adapter.config = None
            with self.assertRaisesRegex(adapter_module.HostAdapterError, "config value|mark"):
                adapter.profile_modes()
            self.assertFalse(Path("/tmp/pwn").exists())

    def test_helper_argv_is_fixed_and_config_values_are_individual_arguments(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fake_root(root)
            adapter = adapter_module.LanAliasHostAdapter(fs_root=root, require_root=False)
            argv = adapter._helper_argv("reconcile", keep_closed=True)
            self.assertEqual(argv[:3], ("python3", "/usr/local/libexec/dnscomplex-lan-alias", "reconcile"))
            self.assertIn("--keep-closed", argv)
            self.assertEqual(argv[argv.index("--lan-interface") + 1], "eth0.20")
            self.assertEqual(argv[argv.index("--default-snat-kind") + 1], "masquerade")
            self.assertNotIn(";", argv)

    def test_candidate_publication_is_atomic_rootfs_scoped_and_apply_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fake_root(root)
            item = {"target": "/usr/local/libexec/dnscomplex-lan-alias",
                    "_candidate_bytes": b"new helper bytes\n", "candidate_mode": 0o755,
                    "preimage_sha256": None}
            dry = adapter_module.LanAliasHostAdapter(fs_root=root, require_root=False)
            with self.assertRaisesRegex(adapter_module.HostAdapterError, "dry-run"):
                dry.publish_candidate_files([item])
            adapter = adapter_module.LanAliasHostAdapter(
                apply=True, fs_root=root, require_root=False)
            adapter.publish_candidate_files([item])
            target = root / "usr/local/libexec/dnscomplex-lan-alias"
            self.assertEqual(target.read_bytes(), b"new helper bytes\n")
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)
            with self.assertRaisesRegex(adapter_module.HostAdapterError, "allowlist"):
                adapter.publish_candidate_files([{**item, "target": "/etc/passwd"}])

    def test_prepare_and_activation_require_one_restart_then_loaded_fastpath(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fake_root(root)
            config = root / "etc/sing-box/config.json"
            config.write_text('{"outbounds":[]}\n')
            state_path = root / "var/lib/dnscomplex/lan-alias.json"

            class StatefulRunner(Runner):
                def __init__(self):
                    super().__init__()
                    self.pid = 101
                    self.opened = False

                def __call__(self, argv, *, input_text=None, env=None):
                    self.calls.append((tuple(argv), input_text, env))
                    if argv[:2] == ("systemctl", "is-active"):
                        return adapter_module.Result(0)
                    if argv[:2] == ("systemctl", "show"):
                        return adapter_module.Result(0, f"{self.pid}\n")
                    if argv[:2] == ("python3", "/usr/local/libexec/dnscomplex-lan-alias"):
                        if "--keep-closed" in argv:
                            config.write_text('{"outbounds":[{"tag":"lan-legacy-alias"}]}\n')
                            self.pid = 202
                            state_path.parent.mkdir(parents=True, exist_ok=True)
                            state_path.write_text(json.dumps({"schema": 1, "status": "owned",
                                "address": "198.18.255.254", "interface": "lo", "label": "lo:dc-alias",
                                "outbound_tag": "lan-legacy-alias", "pool": "198.18.255.0/24",
                                "loaded_config_sha256": __import__("hashlib").sha256(config.read_bytes()).hexdigest(),
                                "loaded_main_pid": self.pid}))
                            state_path.chmod(0o600)
                        else:
                            self.opened = True
                        return adapter_module.Result(0)
                    if argv[:3] == ("nft", "-j", "list"):
                        name = argv[-1]
                        elems = ([{"prefix": {"addr": "0.0.0.0", "len": 0}}]
                                 if self.opened and name in ("lan_alias_ready4", "lan_alias_config_ready4")
                                 else (["198.18.255.254"] if self.opened and name == "lan_alias_source4" else []))
                        return adapter_module.Result(0, json.dumps({"nftables": [{"set": {
                            "family": "inet", "table": "dnscomplex", "name": name,
                            "type": "ipv4_addr", "elem": elems}}]}))
                    return adapter_module.Result(0)

            runner = StatefulRunner()
            adapter = adapter_module.LanAliasHostAdapter(
                apply=True, fs_root=root, runner=runner, require_root=False)
            adapter.initial_vips = {"ai": "10.6.0.2", "cn": "10.7.0.2"}
            prepared = adapter.prepare_alias_once_closed(adapter.initial_vips)
            self.assertTrue(prepared["readiness_closed"])
            self.assertEqual(adapter.activate_alias(adapter.initial_vips)["singbox_restart_count"], 0)
            helper_calls = [call[0] for call in runner.calls
                            if call[0][:2] == ("python3", "/usr/local/libexec/dnscomplex-lan-alias")]
            self.assertEqual(len(helper_calls), 2)
            self.assertIn("--keep-closed", helper_calls[0])
            self.assertNotIn("--keep-closed", helper_calls[1])

    def test_activation_rejects_a_second_mainpid(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fake_root(root)
            adapter = adapter_module.LanAliasHostAdapter(
                apply=True, fs_root=root, runner=Runner(), require_root=False)
            adapter.initial_vips = {"ai": "10.6.0.2", "cn": "10.7.0.2"}
            adapter.prepared_pid = 101
            adapter.prepared_hash = "0" * 64
            # Helper invocation and proof are stubbed; the fake new PID proves
            # the activation phase cannot silently claim a second restart.
            adapter._run = lambda *a, **k: None
            adapter._loaded_proof = lambda: ("0" * 64, 102)
            with self.assertRaisesRegex(adapter_module.HostAdapterError, "fastpath"):
                adapter.activate_alias(adapter.initial_vips)

    def test_close_attempts_both_alias_gates_even_if_helper_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fake_root(root)
            failed_helper = ("python3", "/usr/local/libexec/dnscomplex-lan-alias", "close",
                "--state", "/var/lib/dnscomplex/lan-alias.json", "--config", "/etc/sing-box/config.json",
                "--ai-mode", "ipsec", "--cn-mode", "ipsec", "--ai-mark", "0x301",
                "--cn-mark", "0x351", "--auto-mark", "0x2024", "--ai-quic", "reject",
                "--cn-quic", "reject", "--default-snat-interface", "eth0",
                "--default-snat-kind", "masquerade", "--default-snat-address", "192.168.50.200",
                "--lan-interface", "eth0.20", "--ai-vip", "", "--cn-vip", "")
            runner = Runner(fail=(failed_helper,))
            adapter = adapter_module.LanAliasHostAdapter(
                fs_root=root, runner=runner, apply=True, require_root=False)
            adapter.close_alias_readiness()
            flushed = [call[0][-1] for call in runner.calls if call[0][:2] == ("nft", "flush")]
            self.assertEqual(flushed, ["lan_alias_ready4", "lan_alias_config_ready4"])

    def test_persistent_vip_recovery_rewrites_only_exact_owned_snat_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fake_root(root)
            state_path = root / "var/lib/dnscomplex/lan-alias.json"
            state_path.parent.mkdir(parents=True)
            state_path.write_text(json.dumps({"schema": 1, "status": "owned",
                "address": "198.18.255.254", "interface": "lo", "label": "lo:dc-alias",
                "outbound_tag": "lan-legacy-alias", "pool": "198.18.255.0/24"}))
            state_path.chmod(0o600)
            include = root / "etc/nftables.d/dnscomplex.nft"
            original = (b"table inet dnscomplex {\n  # preserve this exact line\n"
                b'  oifname "ipsec-ai" ip saddr @lan_alias_source4 snat ip to 10.6.0.2 comment "dnscomplex-lan-alias-snat-ai"\n'
                b'  oifname "ipsec-cn" ip saddr @lan_alias_source4 snat ip to 10.7.0.2 comment "dnscomplex-lan-alias-snat-cn"\n}\n')
            include.write_bytes(original)
            adapter = adapter_module.LanAliasHostAdapter(apply=True, fs_root=root,
                runner=Runner(), require_root=False)
            adapter.expected_bytes["/etc/nftables.d/dnscomplex.nft"] = original
            self.assertTrue(adapter._sync_owned_persistent_alias_snat(
                {"ai": "10.6.0.9", "cn": "10.7.0.8"}))
            changed = include.read_bytes()
            expected = original.replace(b"10.6.0.2", b"10.6.0.9").replace(b"10.7.0.2", b"10.7.0.8")
            self.assertEqual(changed, expected)
            self.assertEqual(adapter.expected_bytes["/etc/nftables.d/dnscomplex.nft"], expected)

    def test_persistent_vip_recovery_rejects_foreign_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fake_root(root)
            state_path = root / "var/lib/dnscomplex/lan-alias.json"
            state_path.parent.mkdir(parents=True)
            state_path.write_text(json.dumps({"schema": 1, "status": "owned",
                "address": "198.18.255.254", "interface": "lo", "label": "lo:dc-alias",
                "outbound_tag": "lan-legacy-alias", "pool": "198.18.255.0/24"}))
            state_path.chmod(0o600)
            include = root / "etc/nftables.d/dnscomplex.nft"
            include.write_text('oifname "ipsec-ai" ip saddr @lan_alias_source4 snat ip to 10.6.0.2 comment "dnscomplex-lan-alias-snat-ai"\n')
            adapter = adapter_module.LanAliasHostAdapter(apply=True, fs_root=root,
                runner=Runner(), require_root=False)
            adapter.expected_bytes["/etc/nftables.d/dnscomplex.nft"] = b"other preimage\n"
            with self.assertRaisesRegex(adapter_module.HostAdapterError, "include changed"):
                adapter._sync_owned_persistent_alias_snat({"ai": "10.6.0.9", "cn": "10.7.0.8"})

    def test_recovery_program_never_calls_routes_up_or_flushes_nft_table(self):
        self.assertNotIn("routes up", adapter_module.RECOVER_MANAGER)
        self.assertNotIn("flush ruleset", adapter_module.RECOVER_MANAGER)
        self.assertNotIn("repair_policy_routes_if_needed", adapter_module.RECOVER_MANAGER)
        self.assertIn("ensure_policy_route_profile", adapter_module.RECOVER_MANAGER)
        self.assertIn("profile_egress_gate_clear", adapter_module.RECOVER_MANAGER)
        self.assertLess(adapter_module.RECOVER_MANAGER.index("profile_egress_gate_clear ai"),
                        adapter_module.RECOVER_MANAGER.index("ensure_policy_route_profile"))
        self.assertLess(adapter_module.RECOVER_MANAGER.index("sync_singbox_ipsec_bind_addresses"),
                        adapter_module.RECOVER_MANAGER.index("fresh_sas="))
        self.assertLess(adapter_module.RECOVER_MANAGER.index("ipsec_bind_profile_matches"),
                        adapter_module.RECOVER_MANAGER.index("profile_egress_gate_open ai"))


if __name__ == "__main__":
    unittest.main()
