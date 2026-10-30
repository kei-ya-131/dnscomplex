import ast
import copy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"


def extract_policy_loop():
    source = INSTALLER.read_text(encoding="utf-8")
    marker = "health_checks_json() {\n  DNSCOMPLEX_HEALTH_RUN_DIR=\"$RUN_DIR\" python3 - \"$CONFIG\" <<'PY'\n"
    start = source.index(marker) + len(marker)
    end = source.index("\nPY\n}", start)
    module = ast.parse(source[start:end])
    for node in module.body:
        if not isinstance(node, ast.For) or not isinstance(node.target, ast.Name):
            continue
        if node.target.id != "profile" or not isinstance(node.iter, ast.List):
            continue
        if [ast.literal_eval(item) for item in node.iter.elts] == ["ai", "cn"]:
            return node
    raise AssertionError("could not find AI/CN QUIC policy loop in health heredoc")


def evaluate_policy_checks(config):
    checks = []

    def add_check(checks_arg, name, ok, severity, detail, action, **_kwargs):
        checks_arg.append({
            "name": name,
            "ok": ok,
            "severity": severity,
            "detail": detail,
            "action": action,
        })

    node = extract_policy_loop()
    code = compile(ast.Module(body=[node], type_ignores=[]), str(INSTALLER), "exec")
    exec(code, {"cfg": config, "checks": checks, "add_check": add_check})
    return {item["name"]: item for item in checks}


class QuicHealthPolicyTest(unittest.TestCase):
    def test_ai_allow_and_cn_reject_are_valid_configurations(self):
        checks = evaluate_policy_checks({"AI_QUIC_POLICY": "allow", "CN_QUIC_POLICY": "reject"})
        self.assertTrue(checks["ai-quic-policy"]["ok"])
        self.assertTrue(checks["cn-quic-policy"]["ok"])
        for check in checks.values():
            self.assertIn("policy", check["detail"].lower())
            self.assertIn("UDP reachability not tested", check["detail"])

    def test_profile_defaults_match_installer_defaults(self):
        checks = evaluate_policy_checks({})
        self.assertTrue(checks["ai-quic-policy"]["ok"])
        self.assertTrue(checks["cn-quic-policy"]["ok"])

    def test_both_legal_values_are_accepted_for_either_profile(self):
        checks = evaluate_policy_checks({"AI_QUIC_POLICY": "reject", "CN_QUIC_POLICY": "allow"})
        self.assertTrue(checks["ai-quic-policy"]["ok"])
        self.assertTrue(checks["cn-quic-policy"]["ok"])

    def test_invalid_values_warn_with_only_legal_configuration_action(self):
        checks = evaluate_policy_checks({"AI_QUIC_POLICY": "maybe", "CN_QUIC_POLICY": "drop"})
        for name, key in (("ai-quic-policy", "AI_QUIC_POLICY"), ("cn-quic-policy", "CN_QUIC_POLICY")):
            check = checks[name]
            self.assertFalse(check["ok"])
            self.assertEqual(check["severity"], "warning")
            self.assertIn(key, check["action"])
            self.assertIn("allow or reject", check["action"])
            self.assertIn("UDP reachability not tested", check["action"])

    def test_policy_validation_does_not_mutate_configuration(self):
        config = {"AI_QUIC_POLICY": "allow", "CN_QUIC_POLICY": "unsupported"}
        before = copy.deepcopy(config)
        evaluate_policy_checks(config)
        self.assertEqual(config, before)


if __name__ == "__main__":
    unittest.main()
