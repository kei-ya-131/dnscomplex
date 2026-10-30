#!/usr/bin/env python3
"""Contracts for Xray underlay profile identity and fail-closed readiness."""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"


BASE_CONFIG = """\
DNSCOMPLEX_NONINTERACTIVE=1
WAN_IFACE=eth0
TRANSIT_VLAN_ID=10
LAN_VLAN_ID=20
ROUTEROS_TRANSIT_IPV4=10.255.10.1
LINUX_TRANSIT_IPV4=10.255.10.2
TRANSIT_IPV4_CIDR=10.255.10.2/30
ROUTEROS_TRANSIT_IPV6=fd00:10::1
LINUX_TRANSIT_IPV6=fd00:10::2
TRANSIT_IPV6_CIDR=fd00:10::2/64
LAN_IPV4_CIDR=192.168.88.1/24
LAN_DHCP_START=192.168.88.100
LAN_DHCP_END=192.168.88.250
LAN_IPV6_PREFIX=fd00:88::/64
SINGBOX_SOCKS_LISTEN=192.168.88.1
SINGBOX_SOCKS_PORT=2080
AI_IPSEC_USERNAME=ai-user
AI_IPSEC_PASSWORD=ai-pass
CN_IPSEC_USERNAME=cn-user
CN_IPSEC_PASSWORD=cn-pass
AI_EGRESS_MODE=xray
CN_EGRESS_MODE=xray
AI_XRAY_URI='vless://11111111-1111-4111-8111-111111111111@example.test:443?encryption=none&security=tls&type=grpc&serviceName=ai-gateway&sni=front.example&authority=front.example'
CN_XRAY_URI='vless://22222222-2222-4222-8222-222222222222@example.test:443?encryption=none&security=tls&type=ws&path=%2Fcn&sni=front.example&host=front.example'
"""


class XrayTransportProfileTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dnscomplex-xray-profile-")
        self.work = pathlib.Path(self.temp.name)
        self.config = self.work / "config.env"
        self.config.write_text(BASE_CONFIG)
        self.root = self.work / "root"
        self._render()
        self.renderer = self.root / "usr/local/lib/dnscomplex-xray/render.py"
        self.runtime = self.root / "usr/local/sbin/dnscomplex"

    def tearDown(self):
        self.temp.cleanup()

    def _render(self, config_text=None, root=None):
        if config_text is not None:
            self.config.write_text(config_text)
        root = root or self.root
        env = dict(os.environ, DNSCOMPLEX_ROOT=str(root))
        return subprocess.run(
            ["bash", str(INSTALLER), "--dry-run", "--config", str(self.config)],
            cwd=ROOT, env=env, text=True, capture_output=True,
        )

    def _xray(self, profile):
        rendered = subprocess.run(
            ["python3", str(self.renderer), "--config", str(self.config), "--profile", profile],
            text=True, capture_output=True, check=True,
        )
        outbounds = json.loads(rendered.stdout)["outbounds"]
        return next(outbound for outbound in outbounds if outbound["tag"] == f"xray-{profile}-out")

    def test_selected_uri_outbound_gets_its_profile_mark_without_losing_transport(self):
        ai = self._xray("ai")
        cn = self._xray("cn")
        self.assertEqual(ai["streamSettings"]["network"], "grpc")
        self.assertEqual(ai["streamSettings"]["grpcSettings"]["serviceName"], "ai-gateway")
        self.assertEqual(ai["streamSettings"]["grpcSettings"]["authority"], "front.example")
        self.assertEqual(ai["streamSettings"]["tlsSettings"]["serverName"], "front.example")
        self.assertEqual(ai["streamSettings"]["sockopt"]["mark"], 769)
        self.assertEqual(cn["streamSettings"]["network"], "ws")
        self.assertEqual(cn["streamSettings"]["wsSettings"]["path"], "/cn")
        self.assertEqual(cn["streamSettings"]["wsSettings"]["headers"]["Host"], "front.example")
        self.assertEqual(cn["streamSettings"]["sockopt"]["mark"], 849)

    def test_raw_json_preserves_nested_transport_and_rejects_conflicting_custom_mark(self):
        raw = json.dumps({
            "protocol": "vless", "settings": {"vnext": []},
            "streamSettings": {
                "network": "grpc", "grpcSettings": {"serviceName": "kept"},
                "sockopt": {"mark": 769, "interface": "lo", "dialerProxy": "transport"},
            },
        })
        result = self._render(BASE_CONFIG + "\nAI_XRAY_OUTBOUND_JSON='" + raw + "'\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        outbound = self._xray("ai")
        self.assertEqual(outbound["streamSettings"]["grpcSettings"]["serviceName"], "kept")
        self.assertEqual(outbound["streamSettings"]["sockopt"], {
            "mark": 769, "interface": "lo", "dialerProxy": "transport",
        })

        conflict = raw.replace('"mark": 769', '"mark": 849')
        self.config.write_text(BASE_CONFIG + "\nAI_XRAY_OUTBOUND_JSON='" + conflict + "'\n")
        rendered = subprocess.run(
            ["python3", str(self.renderer), "--config", str(self.config), "--profile", "ai"],
            text=True, capture_output=True,
        )
        self.assertNotEqual(rendered.returncode, 0, "custom mark collision must be explicit")
        self.assertIn("sockopt.mark", rendered.stderr)

    def test_nft_gate_render_uses_ai_allow_cn_reject_defaults_before_proxy_mark_accept(self):
        nft = (self.root / "etc/nftables.d/dnscomplex.nft").read_text()
        singbox = json.loads((self.root / "etc/sing-box/config.json").read_text())
        config = (self.root / "etc/dnscomplex/config.env").read_text()
        self.assertIn("AI_QUIC_POLICY='allow'", config)
        self.assertIn("CN_QUIC_POLICY='reject'", config)
        self.assertIn("set ai_ready6", nft)
        self.assertIn("set cn_ready6", nft)
        output = nft.split("chain output {", 1)[1]
        ai_mark_accept = output.index("dnscomplex-ai-xray-underlay-ready4")
        private_accept = output.index("ip daddr { 0.0.0.0/8")
        udp500_accept = output.index("udp dport { 500, 4500 }")
        self.assertLess(ai_mark_accept, private_accept)
        self.assertLess(ai_mark_accept, udp500_accept)
        self.assertIn("ip6 daddr @ai_ready6", nft)
        self.assertIn("ip6 daddr @cn_ready6", nft)
        rules = singbox["route"]["rules"]
        ai_rejects = [i for i, rule in enumerate(rules)
                      if rule.get("rule_set") == "geosite-ai-openai"
                      and rule.get("network") == "udp" and rule.get("port") == 443
                      and rule.get("action") == "reject"]
        ai_route = next(i for i, rule in enumerate(rules)
                        if rule.get("rule_set") == "geosite-ai-openai" and rule.get("action") == "route")
        cn_rejects = [i for i, rule in enumerate(rules)
                      if rule.get("rule_set") == "geosite-cn-video"
                      and rule.get("network") == "udp" and rule.get("port") == 443
                      and rule.get("action") == "reject"]
        cn_route = next(i for i, rule in enumerate(rules)
                        if rule.get("rule_set") == "geosite-cn-video" and rule.get("action") == "route")
        self.assertEqual(ai_rejects, [], "the default AI QUIC policy allows UDP/443")
        self.assertEqual(len(cn_rejects), 1, "the default CN QUIC policy rejects UDP/443")
        self.assertLess(ai_route, cn_rejects[0])
        self.assertLess(cn_rejects[0], cn_route)
        self.assertIn("ai_ready6", nft)
        self.assertIn("cn_ready6", nft)
        self.assertIn("tcp option maxseg size > 1200", nft)
        self.assertNotIn("tcp option maxseg size set 1500", nft)

    def test_profile_readiness_gate_updates_v4_and_v6_in_one_nft_transaction(self):
        log = self.work / "nft.calls"
        stub = self.work / "nft"
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$NFT_CALL_LOG"\ncat >> "$NFT_BATCH_LOG"\n')
        stub.chmod(0o755)
        script = r'''source "$1"
AI_EGRESS_MODE=xray
profile_egress_gate_open ai
profile_egress_gate_clear ai
'''
        batch = self.work / "nft.batch"
        env = dict(os.environ, PATH=str(self.work) + os.pathsep + os.environ["PATH"],
                   NFT_CALL_LOG=str(log), NFT_BATCH_LOG=str(batch))
        result = subprocess.run(["bash", "-c", script, "_", str(self.runtime)], env=env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = log.read_text().splitlines()
        self.assertEqual(calls, ["-f -", "-f -"], "open/clear must each be a single transaction")
        batch_text = batch.read_text()
        self.assertIn("ai_ready4", batch_text)
        self.assertIn("ai_ready6", batch_text)
        self.assertIn("add element inet dnscomplex ai_ready6 { ::/0 }", batch_text)
        self.assertEqual(batch_text.count("flush set inet dnscomplex ai_ready4"), 2)
        self.assertEqual(batch_text.count("flush set inet dnscomplex ai_ready6"), 2)

    def test_xray_gate_is_open_requires_both_families_but_ipsec_requires_v4(self):
        stub = self.work / "nft"
        calls = self.work / "nft-gate-query.calls"
        stub.write_text(r'''#!/bin/sh
printf '%s\n' "$*" >> "$NFT_QUERY_LOG"
case "$6" in
  ai_ready4) cat "$NFT_QUERY_V4" ;;
  ai_ready6) cat "$NFT_QUERY_V6" ;;
  *) exit 2 ;;
esac
''')
        stub.chmod(0o755)
        v4_fixture = self.work / "ready4.json"
        v6_fixture = self.work / "ready6-missing.json"
        v4_fixture.write_text(json.dumps({"nftables": [{"set": {
            "family": "inet", "table": "dnscomplex", "name": "ai_ready4",
            "type": "ipv4_addr", "elem": [{"prefix": {"addr": "0.0.0.0", "len": 0}}],
        }}]}))
        v6_fixture.write_text(json.dumps({"nftables": []}))
        script = r'''source "$1"
AI_MARK=0x301; AI_MARK_DEC=769; CN_MARK=0x351; CN_MARK_DEC=849
SINGBOX_AUTO_REDIRECT_INPUT_MARK=0x2023; SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC=8227
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=0x2024; SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC=8228
AI_TABLE=301; CN_TABLE=351
AI_EGRESS_MODE=xray
if profile_egress_gate_is_open ai; then exit 10; fi
AI_EGRESS_MODE=ipsec
profile_egress_gate_is_open ai
'''
        env = dict(os.environ, PATH=str(self.work) + os.pathsep + os.environ["PATH"],
                   NFT_QUERY_LOG=str(calls), NFT_QUERY_V4=str(v4_fixture),
                   NFT_QUERY_V6=str(v6_fixture))
        result = subprocess.run(["bash", "-c", script, "_", str(self.runtime)], env=env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        queried = calls.read_text().splitlines()
        self.assertEqual(queried.count("-j list set inet dnscomplex ai_ready4"), 2)
        self.assertEqual(queried.count("-j list set inet dnscomplex ai_ready6"), 1)

    def test_xray_gate_reads_exact_full_prefix_from_nft_json(self):
        nft = self.work / "nft"
        nft.write_text(r'''#!/bin/sh
if [ "$1" = "-j" ] && [ "$2" = "list" ] && [ "$3" = "set" ]; then
  cat "$NFT_JSON_FIXTURE"
  exit 0
fi
exit 2
''')
        nft.chmod(0o755)
        fixture = self.work / "nft.json"
        script = r'''source "$1"
AI_MARK=0x301; AI_MARK_DEC=769; CN_MARK=0x351; CN_MARK_DEC=849
SINGBOX_AUTO_REDIRECT_INPUT_MARK=0x2023; SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC=8227
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=0x2024; SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC=8228
AI_TABLE=301; CN_TABLE=351; AI_EGRESS_MODE=xray
profile_egress_gate_is_open ai
'''
        env = dict(os.environ, PATH=str(self.work) + os.pathsep + os.environ["PATH"],
                   NFT_JSON_FIXTURE=str(fixture))

        good = {"nftables": [
            {"metainfo": {"version": 1, "release_name": "test"}},
            {"set": {"family": "inet", "table": "dnscomplex", "name": "ai_ready4",
                      "type": "ipv4_addr", "flags": ["interval"],
                      "elem": [{"prefix": {"addr": "0.0.0.0", "len": 0}}]}},
            {"set": {"family": "inet", "table": "dnscomplex", "name": "ai_ready6",
                      "type": "ipv6_addr", "flags": ["interval"],
                      "elem": [{"prefix": {"addr": "::", "len": 0}}]}},
        ]}
        fixture.write_text(json.dumps(good))
        opened = subprocess.run(["bash", "-c", script, "_", str(self.runtime)], env=env)
        self.assertEqual(opened.returncode, 0, "complete v4/v6 wildcard gate should be open")

        missing_family = {"nftables": good["nftables"][:2]}
        fixture.write_text(json.dumps(missing_family))
        closed = subprocess.run(["bash", "-c", script, "_", str(self.runtime)], env=env)
        self.assertNotEqual(closed.returncode, 0, "missing ready6 set must stay closed")

        partial = json.loads(json.dumps(good))
        partial["nftables"][2]["set"]["elem"] = [{"prefix": {"addr": "::", "len": 64}}]
        fixture.write_text(json.dumps(partial))
        closed = subprocess.run(["bash", "-c", script, "_", str(self.runtime)], env=env)
        self.assertNotEqual(closed.returncode, 0, "partial IPv6 prefix must stay closed")

        wrong_metadata = json.loads(json.dumps(good))
        wrong_metadata["nftables"][2]["set"]["table"] = "foreign"
        fixture.write_text(json.dumps(wrong_metadata))
        closed = subprocess.run(["bash", "-c", script, "_", str(self.runtime)], env=env)
        self.assertNotEqual(closed.returncode, 0, "foreign-table set must stay closed")

        fixture.write_text("{malformed json")
        closed = subprocess.run(["bash", "-c", script, "_", str(self.runtime)], env=env,
                                text=True, capture_output=True)
        self.assertNotEqual(closed.returncode, 0, "malformed JSON must stay closed")

    def test_classifier_quic_policy_and_transport_gate_follow_selected_mode(self):
        cases = [
            ("ipsec", "reject", "allow", True, False, False),
            ("ipsec", "allow", "reject", False, True, False),
            ("xray", "reject", "allow", True, False, True),
            ("xray", "allow", "reject", False, True, True),
        ]
        for mode, ai_quic, cn_quic, ai_reject, cn_reject, has_transport in cases:
            with self.subTest(mode=mode, ai_quic=ai_quic, cn_quic=cn_quic):
                cfg = BASE_CONFIG + f"\nAI_EGRESS_MODE={mode}\nCN_EGRESS_MODE={mode}\nAI_QUIC_POLICY={ai_quic}\nCN_QUIC_POLICY={cn_quic}\n"
                root = self.work / f"{mode}-{ai_quic}-{cn_quic}"
                rendered = self._render(cfg, root)
                self.assertEqual(rendered.returncode, 0, rendered.stderr)
                nft = (root / "etc/nftables.d/dnscomplex.nft").read_text()
                sb = json.loads((root / "etc/sing-box/config.json").read_text())
                output = nft.split("chain output {", 1)[1]
                self.assertEqual("xray-underlay-ready4" in output, has_transport)
                ai_udp_rejects = [rule for rule in sb["route"]["rules"]
                                  if rule.get("rule_set") == "geosite-ai-openai"
                                  and rule.get("network") == "udp" and rule.get("port") == 443
                                  and rule.get("action") == "reject"]
                cn_udp_rejects = [rule for rule in sb["route"]["rules"]
                                  if rule.get("rule_set") == "geosite-cn-video"
                                  and rule.get("network") == "udp" and rule.get("port") == 443
                                  and rule.get("action") == "reject"]
                self.assertEqual(bool(ai_udp_rejects), ai_reject and mode == "xray")
                self.assertEqual(bool(cn_udp_rejects), cn_reject and mode == "xray")
                self.assertEqual("dnscomplex-ai-quic-reject-output" in output, ai_reject)
                self.assertEqual("dnscomplex-cn-quic-reject-output" in output, cn_reject)
                if mode == "ipsec":
                    self.assertEqual("dnscomplex-ai-classified-quic-reject" in output, ai_reject)
                    self.assertEqual("dnscomplex-cn-classified-quic-reject" in output, cn_reject)

    def test_installer_and_runtime_xray_underlay_helpers_render_identically(self):
        source = INSTALLER.read_text()
        start = source.index("render_nft_xray_transport_output_rules() {")
        end = source.index("\n}\n", start) + 3
        helper = self.work / "installer-xray-helper.sh"
        helper.write_text(source[start:end])
        installer = subprocess.run(
            ["bash", "-c", 'SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=0x2024; source "$1"; render_nft_xray_transport_output_rules ai 0x1001 xray', "_", str(helper)],
            text=True, capture_output=True, check=True,
        ).stdout
        runtime = subprocess.run(
            ["bash", "-c", 'SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=0x2024; source "$1"; ' +
             'runtime_nft_xray_transport_output_rules ai 0x1001 xray', "_", str(self.runtime)],
            text=True, capture_output=True, check=True,
        ).stdout
        self.assertEqual(installer, runtime)

    def test_xray_mode_removes_only_its_exact_stale_ipsec_rule(self):
        bin_dir = self.work / "bin"
        bin_dir.mkdir()
        calls = self.work / "ip.calls"
        ip = bin_dir / "ip"
        ip.write_text(r'''#!/bin/sh
case "$*" in
  "-6 rule show") ;;
  "rule show")
    [ -f "$IP_PROFILE_RULE_REMOVED" ] || printf '10301: from all fwmark 0x301 lookup 301\n'
    [ -f "$IP_PROBE_RULE_REMOVED" ] || printf '10201: from all fwmark 0x3a1 lookup 301\n'
    printf '10400: from all fwmark 0x999 lookup 999\n' ;;
  "rule del fwmark 0x301 table 301 priority 10301") printf '%s\n' "$*" >> "$IP_CALL_LOG"; touch "$IP_PROFILE_RULE_REMOVED" ;;
  "rule del fwmark 0x3A1 table 301 priority 10201") printf '%s\n' "$*" >> "$IP_CALL_LOG"; touch "$IP_PROBE_RULE_REMOVED" ;;
  "rule del priority 10301"|"route flush table 301") printf 'forbidden broad mutation\n' >&2; exit 44 ;;
  *) printf 'unexpected ip call: %s\n' "$*" >&2; exit 45 ;;
esac
''')
        ip.chmod(0o755)
        env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                   IP_CALL_LOG=str(calls),
                   IP_PROFILE_RULE_REMOVED=str(self.work / "profile-rule-removed"),
                   IP_PROBE_RULE_REMOVED=str(self.work / "probe-rule-removed"),
                   IP_RULES_FINAL=str(self.work / "ip.rules.final"))
        script = r'''source "$1"
AI_EGRESS_MODE=xray
CN_EGRESS_MODE=ipsec
AI_MARK=0x301
AI_MARK_DEC=769
CN_MARK=0x351
CN_MARK_DEC=849
AI_TABLE=301
CN_TABLE=351
SINGBOX_AUTO_REDIRECT_INPUT_MARK=0x2023
SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC=8227
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=0x2024
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC=8228
IPSEC_DATAPLANE_AI_MARK=0x3A1
IPSEC_DATAPLANE_AI_MARK_DEC=929
IPSEC_DATAPLANE_CN_MARK=0x3F1
IPSEC_DATAPLANE_CN_MARK_DEC=1009
ensure_policy_route_profile ai
ip rule show >"$IP_RULES_FINAL"
'''
        result = subprocess.run(["bash", "-c", script, "_", str(self.runtime)], env=env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.read_text().splitlines(),
                         ["rule del fwmark 0x301 table 301 priority 10301",
                          "rule del fwmark 0x3A1 table 301 priority 10201"])
        self.assertEqual((self.work / "ip.rules.final").read_text(),
                         "10400: from all fwmark 0x999 lookup 999\n",
                         "unrelated policy rules must survive both exact removals")

    def test_xray_mode_refuses_foreign_same_mark_rule_without_mutation(self):
        bin_dir = self.work / "foreign-bin"
        bin_dir.mkdir()
        calls = self.work / "foreign-ip.calls"
        ip = bin_dir / "ip"
        ip.write_text("#!/bin/sh\ncase \"$*\" in\n  '-6 rule show') ;;\n  'rule show') cat \"$IP_RULES_FIXTURE\" ;;\n  *) printf '%s\\n' \"$*\" >> \"$IP_CALL_LOG\" ;;\nesac\n")
        ip.chmod(0o755)
        script = r'''source "$1"
AI_EGRESS_MODE=xray
AI_MARK=0x301; AI_MARK_DEC=769
CN_MARK=0x351; CN_MARK_DEC=849
AI_TABLE=301; CN_TABLE=351
SINGBOX_AUTO_REDIRECT_INPUT_MARK=0x2023; SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC=8227
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=0x2024; SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC=8228
IPSEC_DATAPLANE_AI_MARK=0x3A1; IPSEC_DATAPLANE_AI_MARK_DEC=929
IPSEC_DATAPLANE_CN_MARK=0x3F1; IPSEC_DATAPLANE_CN_MARK_DEC=1009
ensure_policy_route_profile ai
'''
        foreign_rules = {
            "profile mark": "10400: from all fwmark 0x301 lookup 777\n",
            "dataplane probe mark": "10400: from all fwmark 0x3a1 lookup 777\n",
        }
        for label, rules in foreign_rules.items():
            with self.subTest(label=label):
                case_dir = self.work / label.replace(" ", "-")
                case_dir.mkdir()
                fixture = case_dir / "rules.txt"
                fixture.write_text(rules)
                case_calls = case_dir / "ip.calls"
                env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                           IP_CALL_LOG=str(case_calls), IP_RULES_FIXTURE=str(fixture))
                result = subprocess.run(["bash", "-c", script, "_", str(self.runtime)], env=env,
                                        text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertFalse(case_calls.exists(),
                                 "foreign profile/probe mark rules must remain untouched")

    def test_mark_and_table_collisions_are_rejected(self):
        invalid_configs = [
            BASE_CONFIG + "\nAI_MARK=0\nAI_MARK_DEC=0\n",
            BASE_CONFIG + "\nAI_MARK=0769\nAI_MARK_DEC=769\n",
            BASE_CONFIG + "\nAI_MARK=0x351\nAI_MARK_DEC=849\n",
            BASE_CONFIG + "\nAI_MARK=0x100000000\nAI_MARK_DEC=4294967296\n",
            BASE_CONFIG + "\nAI_MARK_DEC=770\n",
            BASE_CONFIG + "\nSINGBOX_AUTO_REDIRECT_OUTPUT_MARK=0x301\nSINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC=769\n",
            BASE_CONFIG + "\nSINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC=8226\n",
            BASE_CONFIG + "\nAI_TABLE=252\nCN_TABLE=252\n",
            BASE_CONFIG + "\nAI_TABLE=254\n",
        ]
        for idx, config in enumerate(invalid_configs):
            with self.subTest(idx=idx):
                result = self._render(config, self.work / f"invalid-{idx}")
                self.assertNotEqual(result.returncode, 0, result.stderr)
                if "AI_MARK=0769" in config:
                    self.assertIn("invalid egress profile marks or routing tables", result.stderr)

    def test_runtime_mark_validation_explicitly_rejects_leading_zero_decimal(self):
        script = r'''source "$1"
AI_MARK=0769; AI_MARK_DEC=769
CN_MARK=0x351; CN_MARK_DEC=849
SINGBOX_AUTO_REDIRECT_INPUT_MARK=0x2023; SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC=8227
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=0x2024; SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC=8228
AI_TABLE=301; CN_TABLE=351
if validate_egress_profile_values; then exit 11; fi
'''
        result = subprocess.run(["bash", "-c", script, "_", str(self.runtime)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
