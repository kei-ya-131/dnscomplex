import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "profile_health_nft_delta", ROOT / "tools/profile_health_nft_delta.py")
delta = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(delta)


PIN = "856be53885775e98076a0a6e2611e2de27028970d7cde3bb3b714def77a5896f"


def candidate(ai="ipsec", cn="ipsec"):
    rules = []
    if ai == "ipsec":
        rules.append('ip saddr @ai_probe_vip4 oifname "ipsec-ai" ip daddr 104.16.248.249 tcp dport 443 meta mark 0x3a1 counter meta mark set 0x301 accept comment "dnscomplex-ai-dataplane-probe"')
    if cn == "ipsec":
        rules.append('ip saddr @cn_probe_vip4 oifname "ipsec-cn" ip daddr 223.6.6.6 tcp dport 443 meta mark 0x3f1 counter meta mark set 0x351 accept comment "dnscomplex-cn-dataplane-probe"')
    if ai == "ipsec":
        rules.append('oifname "ipsec-ai" meta nfproto ipv6 counter drop comment "dnscomplex-ai-classified-ipv6-drop"')
    if cn == "ipsec":
        rules.append('oifname "ipsec-cn" meta nfproto ipv6 counter drop comment "dnscomplex-cn-classified-ipv6-drop"')
    rules.append('meta mark 0x2024 counter accept comment "dnscomplex-domain-default-output"')
    return '''table inet dnscomplex {
  set ai_probe_vip4 { type ipv4_addr; flags interval; }
  set cn_probe_vip4 { type ipv4_addr; flags interval; }
  chain output {
    type route hook output priority mangle; policy accept;
    %s
  }
}
''' % "\n    ".join(rules)


def live_json(ai="ipsec", cn="ipsec", extra_sets=None, extra_rules=None):
    rules = []
    for i, profile in enumerate(("ai", "cn")):
        mode = ai if profile == "ai" else cn
        if mode == "ipsec":
            rules.append({"rule": {"family": "inet", "table": "dnscomplex",
                                    "chain": "output",
                                    "comment": f"dnscomplex-{profile}-classified-ipv6-drop",
                                    "handle": 40 + i,
                                    "expr": [{"match": {"op": "==",
                                                           "left": {"meta": {"key": "nfproto"}},
                                                           "right": "ipv6"}},
                                             {"counter": {"packets": 0, "bytes": 0}},
                                             {"drop": None}]}})
    rules.append({"rule": {"family": "inet", "table": "dnscomplex", "chain": "output",
                            "comment": "dnscomplex-domain-default-output", "handle": 50,
                            "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}})
    rules.extend(extra_rules or [])
    sets = [{"set": {"family": "inet", "table": "dnscomplex", "name": "ai4",
                      "type": "ipv4_addr", "flags": ["timeout"], "elem": []}},
             {"set": {"family": "inet", "table": "dnscomplex", "name": "cn4",
                      "type": "ipv4_addr", "flags": ["timeout"], "elem": []}}]
    sets.extend(extra_sets or [])
    return {"nftables": [{"table": {"family": "inet", "name": "dnscomplex"}},
                         {"chain": {"family": "inet", "table": "dnscomplex", "name": "output",
                                    "type": "route", "hook": "output", "prio": -150,
                                    "policy": "accept"}}, *sets, *rules]}


class ProfileHealthNFTDeltaTest(unittest.TestCase):
    @staticmethod
    def persistent(ai="ipsec", cn="ipsec"):
        rules = []
        if ai == "ipsec":
            rules.append('    oifname "ipsec-ai" meta nfproto ipv6 counter drop comment "dnscomplex-ai-classified-ipv6-drop"')
        if cn == "ipsec":
            rules.append('    oifname "ipsec-cn" meta nfproto ipv6 counter drop comment "dnscomplex-cn-classified-ipv6-drop"')
        rules.append('    meta mark 0x2024 counter accept comment "dnscomplex-domain-default-output"')
        return '''table inet dnscomplex {
  set ai_ready4 { type ipv4_addr; flags interval; }
  set cn_ready4 { type ipv4_addr; flags interval; }
  set domain4 { type ipv4_addr; flags timeout; size 10000; }
  chain output {
    type route hook output priority mangle; policy accept;
%s
  }
}
''' % "\n".join(rules)

    def compile(self, ai="ipsec", cn="ipsec", vip_ai="10.250.1.10", vip_cn="10.251.1.10",
                snapshot=None, rendered=None, pin=PIN):
        return delta.compile_delta(snapshot or live_json(ai, cn),
                                   self.persistent(ai, cn),
                                   rendered or candidate(ai, cn), pin,
                                   {"ai": ai, "cn": cn}, {"ai": vip_ai, "cn": vip_cn})

    def test_compiles_exact_ipsec_rules_sets_and_first_classifier_order(self):
        result = self.compile()
        self.assertEqual(result["expected_sets"], {
            "ai_probe_vip4": ["10.250.1.10"], "cn_probe_vip4": ["10.251.1.10"]})
        self.assertEqual([r["comment"] for r in result["expected_rules"]], [
            "dnscomplex-ai-dataplane-probe", "dnscomplex-cn-dataplane-probe"])
        self.assertIn("insert rule inet dnscomplex output position 40", result["transaction"])
        self.assertIn("insert rule inet dnscomplex output position 40", result["transaction"])
        self.assertIn("add element inet dnscomplex ai_probe_vip4 { 10.250.1.10 }", result["transaction"])
        self.assertIn('comment "dnscomplex-ai-dataplane-probe"', result["persistent"])
        self.assertNotIn("flush table", result["transaction"])

    def test_xray_profile_gets_empty_set_and_no_probe_rule(self):
        result = self.compile(ai="xray", cn="ipsec", vip_ai="", vip_cn="10.251.1.10")
        self.assertEqual(result["expected_sets"], {
            "ai_probe_vip4": [], "cn_probe_vip4": ["10.251.1.10"]})
        self.assertEqual([r["comment"] for r in result["expected_rules"]],
                         ["dnscomplex-cn-dataplane-probe"])
        self.assertNotIn("dnscomplex-ai-dataplane-probe", result["transaction"])

    def test_all_xray_adds_only_empty_sets(self):
        result = self.compile(ai="xray", cn="xray", vip_ai="", vip_cn="")
        self.assertEqual(result["expected_sets"], {"ai_probe_vip4": [], "cn_probe_vip4": []})
        self.assertEqual(result["expected_rules"], [])
        self.assertNotIn("insert rule", result["transaction"])

    def test_undo_is_exact_and_requires_sets_empty(self):
        result = self.compile()
        self.assertEqual(result["undo"]["sets"], {
            "ai_probe_vip4": ["10.250.1.10"], "cn_probe_vip4": ["10.251.1.10"]})
        self.assertEqual(result["undo"]["rules"], [
            {"chain": "output", "comment": "dnscomplex-cn-dataplane-probe",
             "handle": None, "expression": result["expected_rules"][1]["expression"]},
            {"chain": "output", "comment": "dnscomplex-ai-dataplane-probe",
             "handle": None, "expression": result["expected_rules"][0]["expression"]}])
        self.assertIn("empty", result["undo"]["delete_policy"])

    def test_verifies_applied_vip_sets_and_nft_expression_semantics(self):
        result = self.compile()
        snapshot = live_json()
        snapshot["nftables"].extend([
            {"set": {"family": "inet", "table": "dnscomplex", "name": "ai_probe_vip4",
                     "type": "ipv4_addr", "flags": ["interval"], "elem": ["10.250.1.10"]}},
            {"set": {"family": "inet", "table": "dnscomplex", "name": "cn_probe_vip4",
                     "type": "ipv4_addr", "flags": ["interval"], "elem": [{"prefix": {"addr": "10.251.1.10", "len": 32}}]}}
        ])
        added_rules = []
        probe_rules = []
        for profile, handle in (("ai", 90), ("cn", 91)):
            cfg = delta.PROFILES[profile]
            added_rules.append({"rule": {
                "family": "inet", "table": "dnscomplex", "chain": "output",
                "comment": cfg["comment"], "handle": handle,
                "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"set": "@" + cfg["set"]}}},
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": cfg["device"]}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": cfg["resolver"]}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
                    {"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": cfg["probe_mark"]}},
                    {"counter": {"packets": 1, "bytes": 64}},
                    {"mangle": {"key": {"meta": {"key": "mark"}}, "value": cfg["profile_mark"]}},
                    {"accept": None}
                ]
            }})
        first_classifier = next(i for i, item in enumerate(snapshot["nftables"])
                                if isinstance(item, dict) and item.get("rule", {}).get("comment") ==
                                "dnscomplex-ai-classified-ipv6-drop")
        snapshot["nftables"][first_classifier:first_classifier] = added_rules
        delta.verify_applied(snapshot, result["expected_rules"], result["expected_sets"])
        undo = delta.build_undo(snapshot, result)
        self.assertEqual(undo[:2], ["delete rule inet dnscomplex output handle 91",
                                    "delete rule inet dnscomplex output handle 90"])
        self.assertEqual(undo[2:], [
            "delete element inet dnscomplex cn_probe_vip4 { 10.251.1.10 }",
            "delete set inet dnscomplex cn_probe_vip4",
            "delete element inet dnscomplex ai_probe_vip4 { 10.250.1.10 }",
            "delete set inet dnscomplex ai_probe_vip4"])
        self.assertFalse(any("flush" in command for command in undo))
        changed = json.loads(json.dumps(snapshot))
        cn_set = next(item["set"] for item in changed["nftables"]
                      if isinstance(item, dict) and item.get("set", {}).get("name") == "cn_probe_vip4")
        cn_set["elem"].append("10.251.1.11")
        with self.assertRaises(delta.DeltaError):
            delta.build_undo(changed, result)
        late = json.loads(json.dumps(snapshot))
        late["nftables"] = [item for item in late["nftables"]
                            if not (isinstance(item, dict) and
                                    item.get("rule", {}).get("comment", "").endswith("-dataplane-probe"))]
        late["nftables"].extend(added_rules)
        with self.assertRaises(delta.DeltaError):
            delta.verify_applied(late, result["expected_rules"], result["expected_sets"])
        ai_rule = next(item["rule"] for item in snapshot["nftables"]
                       if isinstance(item, dict) and item.get("rule", {}).get("comment") ==
                       "dnscomplex-ai-dataplane-probe")
        ai_rule["expr"][2]["match"]["right"] = "203.0.113.99"
        with self.assertRaises(delta.DeltaError):
            delta.verify_applied(snapshot, result["expected_rules"], result["expected_sets"])

    def test_rejects_extra_or_reordered_probe_statements_and_undo(self):
        result = self.compile()
        snapshot = live_json()
        snapshot["nftables"].extend([
            {"set": {"family": "inet", "table": "dnscomplex", "name": "ai_probe_vip4",
                     "type": "ipv4_addr", "flags": ["interval"], "elem": ["10.250.1.10"]}},
            {"set": {"family": "inet", "table": "dnscomplex", "name": "cn_probe_vip4",
                     "type": "ipv4_addr", "flags": ["interval"], "elem": ["10.251.1.10"]}},
        ])
        probe_rules = []
        for profile, handle in (("ai", 90), ("cn", 91)):
            cfg = delta.PROFILES[profile]
            rule = {"rule": {"family": "inet", "table": "dnscomplex", "chain": "output",
                             "comment": cfg["comment"], "handle": handle,
                             "expr": [
                                 {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"set": "@" + cfg["set"]}}},
                                 {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": cfg["device"]}},
                                 {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": cfg["resolver"]}},
                                 {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
                                 {"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": cfg["probe_mark"]}},
                                 {"counter": {"packets": 0, "bytes": 0}},
                                 {"mangle": {"key": {"meta": {"key": "mark"}}, "value": cfg["profile_mark"]}},
                                 {"accept": None},
                             ]}}
            probe_rules.append(rule)

        classifier_index = next(i for i, item in enumerate(snapshot["nftables"])
                                if isinstance(item, dict) and item.get("rule", {}).get("comment") ==
                                "dnscomplex-ai-classified-ipv6-drop")
        snapshot["nftables"][classifier_index:classifier_index] = probe_rules

        delta.verify_applied(snapshot, result["expected_rules"], result["expected_sets"])

        ai_rule = next(item["rule"] for item in snapshot["nftables"]
                       if isinstance(item, dict) and item.get("rule", {}).get("comment") ==
                       delta.PROFILES["ai"]["comment"])
        mutations = (
            lambda expr: expr.insert(-1, {"drop": None}),
            lambda expr: expr.insert(0, {"mangle": {"key": {"ct": {"key": "mark"}}, "value": 1}}),
            lambda expr: expr.insert(0, {"jump": {"target": "foreign"}}),
            lambda expr: expr.insert(0, {"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": 0}}),
            lambda expr: expr.insert(0, {"accept": None}),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                original = json.loads(json.dumps(ai_rule["expr"]))
                mutate(ai_rule["expr"])
                with self.assertRaises(delta.DeltaError):
                    delta.verify_applied(snapshot, result["expected_rules"], result["expected_sets"])
                with self.assertRaises(delta.DeltaError):
                    delta.build_undo(snapshot, result)
                ai_rule["expr"] = original

    def test_rejects_wrong_installer_pin(self):
        with self.assertRaises(delta.DeltaError):
            self.compile(pin="0" * 64)

    def test_rejects_live_probe_set_collision(self):
        snapshot = live_json(extra_sets=[{"set": {"family": "inet", "table": "dnscomplex",
                                                   "name": "ai_probe_vip4", "type": "ipv4_addr",
                                                   "elem": []}}])
        with self.assertRaises(delta.DeltaError):
            self.compile(snapshot=snapshot)

    def test_rejects_live_probe_rule_comment_collision(self):
        snapshot = live_json(extra_rules=[{"rule": {"family": "inet", "table": "dnscomplex",
                                                     "chain": "output",
                                                     "comment": "dnscomplex-ai-dataplane-probe",
                                                     "handle": 77, "expr": [{"accept": None}]}}])
        with self.assertRaises(delta.DeltaError):
            self.compile(snapshot=snapshot)

    def test_rejects_noncanonical_vip_and_profile_mode(self):
        for vip in ("0.0.0.0", "127.0.0.1", "224.0.0.1", "10.1.2.3/32", "bad"):
            with self.subTest(vip=vip), self.assertRaises(delta.DeltaError):
                self.compile(vip_ai=vip)
        with self.assertRaises(delta.DeltaError):
            self.compile(ai="mixed")

    def test_rejects_malformed_nft_snapshot_and_ambiguous_classifier(self):
        with self.assertRaises(delta.DeltaError):
            self.compile(snapshot={"nftables": []})
        duplicate = live_json(extra_rules=[{"rule": {"family": "inet", "table": "dnscomplex",
                                                      "chain": "output",
                                                      "comment": "dnscomplex-ai-classified-ipv6-drop",
                                                      "handle": 81, "expr": [{"drop": None}]}}])
        with self.assertRaises(delta.DeltaError):
            self.compile(snapshot=duplicate)

    def test_keeps_unknown_domain_rule_bytes_and_rejects_missing_classifier_anchor(self):
        baseline = self.persistent()
        baseline = baseline.replace('    meta mark 0x2024 counter accept comment "dnscomplex-domain-default-output"',
                                    '    ip daddr @customer4 counter accept comment "customer-domain-rule"\n'
                                    '    meta mark 0x2024 counter accept comment "dnscomplex-domain-default-output"')
        result = delta.compile_delta(live_json(), baseline, candidate(), PIN,
                                     {"ai": "ipsec", "cn": "ipsec"},
                                     {"ai": "10.250.1.10", "cn": "10.251.1.10"})
        self.assertIn('ip daddr @customer4 counter accept comment "customer-domain-rule"', result["persistent"])
        with self.assertRaises(delta.DeltaError):
            delta.compile_delta(live_json(), self.persistent(), candidate().replace(
                'comment "dnscomplex-ai-classified-ipv6-drop"', 'comment "customer-domain-rule"'),
                PIN, {"ai": "ipsec", "cn": "ipsec"},
                {"ai": "10.250.1.10", "cn": "10.251.1.10"})


if __name__ == "__main__":
    unittest.main()
