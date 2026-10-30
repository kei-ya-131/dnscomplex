"""Exercise the rendered manager's probe classification and watchdog boundary."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WatchdogProfileIsolationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        source = (ROOT / "install.sh").read_text()
        manager = source.split("<<'MANAGER'\n", 1)[1].split("\nMANAGER", 1)[0]
        self.manager = self.root / "manager.sh"
        self.manager.write_text(manager + "\n")

    def run_shell(self, script, **values):
        env = os.environ.copy()
        env.update(MANAGER=str(self.manager), TEST_ROOT=str(self.root), **values)
        result = subprocess.run(["bash", "-c", 'source "$MANAGER"\n' + script],
                                env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return json.loads(result.stdout.splitlines()[-1])

    def watchdog(self, route_rc="2", later_fail="0", budget_fail="0"):
        return self.run_shell(r'''
watchdog_budget_start() {
  WATCHDOG_PROFILE_PROBE_FAILED=0
  [[ "$BUDGET_FAIL" == 0 ]]
}
restart_watchdog_unit_if_inactive() { :; }
repair_ipsec_children_if_needed() { :; }
repair_policy_routes_if_needed() { return "$ROUTE_RC"; }
lan_alias_reconcile_cmd() { [[ "$LATER_FAIL" == 0 ]]; }
smartdns_listener_round() { return 0; }
watchdog_fail_closed() { : >"$TEST_ROOT/global-close"; }
if watchdog_locked_cmd; then rc=0; else rc=$?; fi
if [[ -e "$TEST_ROOT/global-close" ]]; then closed=true; else closed=false; fi
printf '{"rc":%s,"global_closed":%s}\n' "$rc" "$closed"
''', ROUTE_RC=route_rc, LATER_FAIL=later_fail, BUDGET_FAIL=budget_fail)

    def test_local_probe_failure_does_not_close_both_profiles(self):
        self.assertEqual(self.watchdog(), {"rc": 1, "global_closed": False})

    def test_fatal_route_failure_still_closes_all(self):
        self.assertEqual(self.watchdog(route_rc="1"), {"rc": 1, "global_closed": True})

    def test_later_failure_after_local_failure_still_closes_all(self):
        self.assertEqual(self.watchdog(later_fail="1"), {"rc": 1, "global_closed": True})

    def test_global_budget_failure_still_closes_all(self):
        self.assertEqual(self.watchdog(budget_fail="1"), {"rc": 1, "global_closed": True})

    def observe(self, *, payload=None, timeout="0", rule_ok="1", closed_ok="1", full_budget="1"):
        payload = payload or {"status": "fail", "profile": "cn", "phase": "connect",
                              "reason": "connect_attempts_exhausted", "elapsed_ms": 3000,
                              "connect_attempts": 3}
        helper = self.root / "probe"
        helper.write_text('#!/bin/bash\nprintf "%s\\n" "$PROBE_JSON"\nexit 1\n')
        helper.chmod(0o700)
        return self.run_shell(r'''
RUN_DIR="$TEST_ROOT"
IPSEC_DATAPLANE_CN_MARK_DEC=1009
IPSEC_DATAPLANE_AI_MARK=929
AI_MARK=769; CN_MARK=849
SINGBOX_AUTO_REDIRECT_INPUT_MARK=8227
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=8228
profile_egress_mode() { echo ipsec; }
ipsec_profile_dataplane_identity() { echo stable; }
profile_egress_gate_is_open() { return 1; }
ipsec_probe_vip_set_matches() { return 0; }
fs_path() { echo "$TEST_ROOT/probe"; }
profile_egress_gate_clear() { : >"$TEST_ROOT/closed"; }
profile_egress_gate_verify_closed() { [[ "$CLOSED_OK" == 1 ]]; }
ipsec_probe_output_rule_matches() { [[ "$RULE_OK" == 1 ]]; }
watchdog_timeout_value() {
  if [[ "$FULL_BUDGET" == 1 ]]; then echo "$1.000"; else echo 0.500; fi
}
watchdog_capture() {
  shift
  if [[ "${1:-}" == "$TEST_ROOT/probe" && "$CAPTURE_TIMEOUT" == 1 ]]; then return 124; fi
  "$@"
}
printf '10.251.1.15 stable 2\n' >"$RUN_DIR/profile-dataplane-cn.success"
if profile_dataplane_probe_observe cn 10.251.1.15 synthetic-sa; then rc=0; else rc=$?; fi
[[ -e "$TEST_ROOT/closed" ]] && closed=true || closed=false
[[ -e "$RUN_DIR/profile-dataplane-cn.success" ]] && proof=true || proof=false
printf '{"rc":%s,"closed":%s,"proof":%s}\n' "$rc" "$closed" "$proof"
''', PROBE_JSON=json.dumps(payload), CAPTURE_TIMEOUT=timeout, RULE_OK=rule_ok,
            CLOSED_OK=closed_ok, FULL_BUDGET=full_budget)

    def test_known_connect_failure_is_local_only_after_verified_closure(self):
        self.assertEqual(self.observe(), {"rc": 2, "closed": True, "proof": False})

    def test_capture_timeout_remains_fatal(self):
        self.assertEqual(self.observe(timeout="1")["rc"], 1)

    def test_wrong_profile_and_tls_failures_remain_fatal(self):
        for field, value in (("profile", "ai"), ("phase", "tls"), ("reason", "deadline_exceeded")):
            with self.subTest(field=field):
                payload = {"status": "fail", "profile": "cn", "phase": "connect",
                           "reason": "connect_attempts_exhausted", "elapsed_ms": 3000,
                           "connect_attempts": 3}
                payload[field] = value
                self.assertEqual(self.observe(payload=payload)["rc"], 1)

    def test_unknown_firewall_or_budget_is_not_local(self):
        for kwargs in ({"rule_ok": "0"}, {"closed_ok": "0"}, {"full_budget": "0"}):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.observe(**kwargs)["rc"], 1)

    def test_incomplete_or_malformed_attempt_contract_is_fatal(self):
        for field, value in (("connect_attempts", None), ("connect_attempts", True),
                             ("connect_attempts", 2), ("elapsed_ms", "3000"),
                             ("elapsed_ms", True), ("elapsed_ms", 5001), ("elapsed_ms", -1)):
            payload = {"status": "fail", "profile": "cn", "phase": "connect",
                       "reason": "connect_attempts_exhausted", "elapsed_ms": 3000,
                       "connect_attempts": 3}
            if value is None:
                payload.pop(field)
            else:
                payload[field] = value
            with self.subTest(field=field, value=value):
                self.assertEqual(self.observe(payload=payload)["rc"], 1)

    def test_route_repair_preserves_local_result_only_without_fatal_errors(self):
        for cn_rc, expected in (("0", 0), ("1", 1), ("2", 2)):
            with self.subTest(cn_rc=cn_rc):
                result = self.run_shell(r'''
AI_MARK=769; CN_MARK=849; AI_TABLE=301; CN_TABLE=351
ip() { :; }
profile_uses_ipsec() { return 0; }
watchdog_capture() { echo synthetic-sa; }
ipsec_profile_sa_ready() { IPSEC_STATE_READY_VIP=10.251.1.15; }
ipsec_policy_rule_present() { :; }
ipsec_probe_policy_rule_present() { :; }
ipsec_policy_route_matches() { :; }
ipsec_nat_profile_matches() { :; }
ipsec_probe_vip_set_matches() { :; }
lan_alias_nat_state_status() { return 1; }
ipsec_bind_profile_matches() { :; }
profile_dataplane_probe_observe() {
  if [[ "$1" == cn ]]; then return "$CN_RC"; fi
  return 0
}
if repair_policy_routes_if_needed; then rc=0; else rc=$?; fi
printf '{"rc":%s}\n' "$rc"
''', CN_RC=cn_rc)
                self.assertEqual(result["rc"], expected)

    def test_successful_same_vip_rekey_keeps_an_already_open_gate(self):
        helper = self.root / "probe"
        helper.write_text('#!/bin/bash\nprintf \'{"status":"pass","profile":"cn"}\\n\'\n')
        helper.chmod(0o700)
        result = self.run_shell(r'''
RUN_DIR="$TEST_ROOT"
IPSEC_DATAPLANE_CN_MARK_DEC=1009; IPSEC_DATAPLANE_AI_MARK=929
AI_MARK=769; CN_MARK=849
SINGBOX_AUTO_REDIRECT_INPUT_MARK=8227; SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=8228
profile_egress_mode() { echo ipsec; }
ipsec_profile_dataplane_identity() { echo new-identity; }
profile_egress_gate_is_open() { return 0; }
profile_egress_gate_verify_closed() { return 1; }
ipsec_probe_vip_set_matches() { return 0; }
profile_egress_gate_clear() { return 99; }
ipsec_profile_sa_ready() { IPSEC_STATE_READY_VIP=10.251.1.15; }
fs_path() { echo "$TEST_ROOT/probe"; }
watchdog_capture() {
  shift
  if [[ "$1" == swanctl ]]; then echo synthetic-sa; else "$@"; fi
}
printf '10.251.1.15 old-identity 2\n' >"$RUN_DIR/profile-dataplane-cn.success"
if profile_dataplane_probe_observe cn 10.251.1.15 synthetic-sa; then rc=0; else rc=$?; fi
printf '{"rc":%s}\n' "$rc"
''')
        self.assertEqual(result["rc"], 0)

    def observe_identity_switch(self, *, profile="cn", initial_gate="1", snapshots=None,
                                retry_budget="17.000", close_rc="0", close_verify="1",
                                probe_results=None, second_round=False):
        vip = "10.250.1.22" if profile == "ai" else "10.251.1.15"
        snapshots = snapshots or [f"new|{vip}|yes", f"new|{vip}|yes"]
        probe_results = probe_results or [
            {"status": "pass", "profile": profile},
            {"status": "pass", "profile": profile},
            {"status": "pass", "profile": profile},
        ]
        helper = self.root / "probe-rekey"
        helper.write_text(r'''#!/bin/bash
result_name="PROBE_RESULT_${PROBE_CALL}"
rc_name="PROBE_RC_${PROBE_CALL}"
result="${!result_name-}"
[[ -n "$result" ]] || result='{}'
printf '%s\n' "$result"
exit "${!rc_name-0}"
''')
        helper.chmod(0o700)
        values = {
            "PROFILE": profile, "TEST_VIP": vip, "INITIAL_GATE": initial_gate,
            "RETRY_BUDGET": retry_budget, "CLOSE_RC": close_rc,
            "CLOSE_VERIFY": close_verify,
            "INITIAL_SAS": f"old|{vip}|yes",
        }
        for index, snapshot in enumerate(snapshots, 1):
            values[f"SA_SNAPSHOT_{index}"] = snapshot
        for index, result in enumerate(probe_results, 1):
            values[f"PROBE_RESULT_{index}"] = json.dumps(result, separators=(",", ":"))
            values[f"PROBE_RC_{index}"] = "0" if result.get("status") == "pass" else "1"
        script = r'''
RUN_DIR="$TEST_ROOT"
IPSEC_DATAPLANE_AI_MARK_DEC=929; IPSEC_DATAPLANE_CN_MARK_DEC=1009
IPSEC_DATAPLANE_AI_MARK=929; IPSEC_DATAPLANE_CN_MARK=1009
AI_MARK=769; CN_MARK=849
SINGBOX_AUTO_REDIRECT_INPUT_MARK=8227; SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=8228
PROBE_CALL=0; SA_CALL=0; CLOSE_CALL=0; OPEN_CALL=0
GATE_OPEN=$INITIAL_GATE
profile_egress_mode() { echo ipsec; }
ipsec_profile_dataplane_identity() {
  IFS='|' read -r identity _ _ <<<"$3"
  printf '%s\n' "$identity"
}
ipsec_profile_sa_ready() {
  IFS='|' read -r _ IPSEC_STATE_READY_VIP ready <<<"$2"
  [[ "$ready" == yes ]]
}
profile_egress_gate_is_open() { [[ "$GATE_OPEN" == 1 ]]; }
profile_egress_gate_clear() {
  CLOSE_CALL=$((CLOSE_CALL + 1))
  [[ "$CLOSE_RC" == 0 ]] || return "$CLOSE_RC"
  GATE_OPEN=0
}
profile_egress_gate_verify_closed() { [[ "$CLOSE_VERIFY" == 1 && "$GATE_OPEN" == 0 ]]; }
profile_egress_gate_open() { OPEN_CALL=$((OPEN_CALL + 1)); GATE_OPEN=1; }
ipsec_probe_vip_set_matches() { return 0; }
ipsec_probe_output_rule_matches() { return 0; }
fs_path() { echo "$TEST_ROOT/probe-rekey"; }
watchdog_timeout_value() {
  case "$1" in 5) echo 5.000;; 6) echo 6.000;; 17) echo "$RETRY_BUDGET";; *) echo "$1.000";; esac
}
watchdog_capture() {
  local _limit=$1; shift
  if [[ "${1:-}" == swanctl ]]; then
    SA_CALL=0
    [[ -r "$TEST_ROOT/sa-counter" ]] && SA_CALL=$(cat "$TEST_ROOT/sa-counter")
    SA_CALL=$((SA_CALL + 1))
    printf '%s\n' "$SA_CALL" >"$TEST_ROOT/sa-counter"
    local name="SA_SNAPSHOT_${SA_CALL}"
    printf '%s\n' "${!name:-$INITIAL_SAS}"
    return 0
  fi
  if [[ "${1:-}" == "$TEST_ROOT/probe-rekey" ]]; then
    PROBE_CALL=0
    [[ -r "$TEST_ROOT/probe-counter" ]] && PROBE_CALL=$(cat "$TEST_ROOT/probe-counter")
    PROBE_CALL=$((PROBE_CALL + 1)); export PROBE_CALL
    printf '%s\n' "$PROBE_CALL" >"$TEST_ROOT/probe-counter"
    printf '%s\n' "$PROBE_CALL" >>"$TEST_ROOT/probe-calls"
    "$@"
    return $?
  fi
  "$@"
}
take_snapshot() {
  local probe_count=0
  [[ -r "$TEST_ROOT/probe-counter" ]] && probe_count=$(cat "$TEST_ROOT/probe-counter")
  if [[ -e "$RUN_DIR/profile-dataplane-$PROFILE.success" ]]; then
    proof=$(cat "$RUN_DIR/profile-dataplane-$PROFILE.success")
  else proof=missing; fi
  local sa_count=0
  [[ -r "$TEST_ROOT/sa-counter" ]] && sa_count=$(cat "$TEST_ROOT/sa-counter")
  printf '{"rc":%s,"gate_open":%s,"proof":"%s","probes":%s,"sa_calls":%s,"closes":%s,"opens":%s}' \
    "$1" "$GATE_OPEN" "$proof" "$probe_count" "$sa_count" "$CLOSE_CALL" "$OPEN_CALL"
}
rm -f "$TEST_ROOT/probe-counter" "$TEST_ROOT/sa-counter" "$TEST_ROOT/probe-calls" "$TEST_ROOT/sa-trace"
printf '%s old 2\n' "$TEST_VIP" >"$RUN_DIR/profile-dataplane-$PROFILE.success"
if profile_dataplane_probe_observe "$PROFILE" "$TEST_VIP" "$INITIAL_SAS"; then first_rc=0; else first_rc=$?; fi
first=$(take_snapshot "$first_rc")
if [[ "$SECOND_ROUND" == 1 ]]; then
  if profile_dataplane_probe_observe "$PROFILE" "$TEST_VIP" "new|$TEST_VIP|yes"; then second_rc=0; else second_rc=$?; fi
  second=$(take_snapshot "$second_rc")
else second=null; fi
printf '{"first":%s,"second":%s}\n' "$first" "$second"
'''
        return self.run_shell(script, SECOND_ROUND="1" if second_round else "0", **values)

    def test_cn_same_vip_rekey_reprobes_once_and_records_one_closed_success(self):
        vip = "10.251.1.15"
        result = self.observe_identity_switch(
            snapshots=[f"new|{vip}|yes", f"new|{vip}|yes"])
        self.assertEqual(result["first"]["rc"], 0)
        self.assertEqual(result["first"]["probes"], 2)
        self.assertEqual(result["first"]["closes"], 1)
        self.assertEqual(result["first"]["opens"], 0)
        self.assertFalse(result["first"]["gate_open"])
        self.assertEqual(result["first"]["proof"], f"{vip} new 1")

    def test_cn_retry_success_needs_next_stable_success_to_open_gate(self):
        vip = "10.251.1.15"
        result = self.observe_identity_switch(
            snapshots=[f"new|{vip}|yes", f"new|{vip}|yes", f"new|{vip}|yes"],
            second_round=True)
        self.assertEqual(result["first"]["proof"], f"{vip} new 1")
        self.assertFalse(result["first"]["gate_open"])
        self.assertEqual(result["second"]["rc"], 0)
        self.assertEqual(result["second"]["proof"], f"{vip} new 2")
        self.assertTrue(result["second"]["gate_open"])
        self.assertEqual(result["second"]["opens"], 1)

    def test_second_identity_change_remains_global_fail_closed(self):
        vip = "10.251.1.15"
        result = self.observe_identity_switch(
            snapshots=[f"new|{vip}|yes", f"other|{vip}|yes"])
        self.assertEqual(result["first"]["rc"], 1)
        self.assertEqual(result["first"]["probes"], 2)
        self.assertFalse(result["first"]["gate_open"])
        self.assertEqual(result["first"]["proof"], "missing")

    def test_retry_sa_or_vip_change_remains_global_fail_closed(self):
        vip = "10.251.1.15"
        for final_snapshot in ("new|10.251.1.16|yes", f"new|{vip}|no"):
            with self.subTest(final_snapshot=final_snapshot):
                result = self.observe_identity_switch(
                    snapshots=[f"new|{vip}|yes", final_snapshot])
                self.assertEqual(result["first"]["rc"], 1)
                self.assertEqual(result["first"]["probes"], 2)
                self.assertFalse(result["first"]["gate_open"])
                self.assertEqual(result["first"]["proof"], "missing")

    def test_new_vip_or_unready_sa_does_not_retry(self):
        for snapshot in ("new|10.251.1.16|yes", "new|10.251.1.15|no"):
            with self.subTest(snapshot=snapshot):
                result = self.observe_identity_switch(snapshots=[snapshot])
                self.assertEqual(result["first"]["rc"], 1)
                self.assertEqual(result["first"]["probes"], 1)
                self.assertFalse(result["first"]["gate_open"])
                self.assertEqual(result["first"]["proof"], "missing")

    def test_insufficient_retry_budget_does_not_retry(self):
        vip = "10.251.1.15"
        result = self.observe_identity_switch(
            snapshots=[f"new|{vip}|yes"], retry_budget="16.999")
        self.assertEqual(result["first"]["rc"], 1)
        self.assertEqual(result["first"]["probes"], 1)
        self.assertFalse(result["first"]["gate_open"])
        self.assertEqual(result["first"]["proof"], "missing")

    def test_ai_identity_change_keeps_existing_global_failure_behavior(self):
        result = self.observe_identity_switch(
            profile="ai", snapshots=["new|10.250.1.22|yes"])
        self.assertEqual(result["first"]["rc"], 1)
        self.assertEqual(result["first"]["probes"], 1)
        self.assertFalse(result["first"]["gate_open"])

    def test_gate_close_or_readback_failure_prevents_retry(self):
        vip = "10.251.1.15"
        for kwargs in ({"close_rc": "1"}, {"close_verify": "0"}):
            with self.subTest(kwargs=kwargs):
                result = self.observe_identity_switch(
                    snapshots=[f"new|{vip}|yes"], **kwargs)
                self.assertEqual(result["first"]["rc"], 1)
                self.assertEqual(result["first"]["probes"], 1)

    def test_retry_failure_keeps_existing_exact_connect_only_classifier(self):
        vip = "10.251.1.15"
        connect_only = {"status": "fail", "profile": "cn", "phase": "connect",
                        "reason": "connect_attempts_exhausted", "elapsed_ms": 3000,
                        "connect_attempts": 3}
        result = self.observe_identity_switch(
            snapshots=[f"new|{vip}|yes"],
            probe_results=[{"status": "pass", "profile": "cn"}, connect_only])
        self.assertEqual(result["first"]["rc"], 2)
        self.assertEqual(result["first"]["probes"], 2)
        self.assertFalse(result["first"]["gate_open"])
        self.assertEqual(result["first"]["proof"], "missing")

        tls_failure = {"status": "fail", "profile": "cn", "phase": "tls",
                       "reason": "handshake_failed", "elapsed_ms": 3000,
                       "connect_attempts": 1}
        result = self.observe_identity_switch(
            snapshots=[f"new|{vip}|yes"],
            probe_results=[{"status": "pass", "profile": "cn"}, tls_failure])
        self.assertEqual(result["first"]["rc"], 1)
        self.assertEqual(result["first"]["probes"], 2)
        self.assertFalse(result["first"]["gate_open"])
        self.assertEqual(result["first"]["proof"], "missing")

    def test_live_probe_rule_requires_exact_unique_context(self):
        def match(left, right):
            return {"match": {"op": "==", "left": left, "right": right}}
        rule = {"family": "inet", "table": "dnscomplex", "chain": "output",
                "comment": "dnscomplex-cn-dataplane-probe", "expr": [
                    match({"payload": {"protocol": "ip", "field": "saddr"}}, "@cn_probe_vip4"),
                    match({"meta": {"key": "oifname"}}, "ipsec-cn"),
                    match({"payload": {"protocol": "ip", "field": "daddr"}}, "223.6.6.6"),
                    match({"payload": {"protocol": "tcp", "field": "dport"}}, 443),
                    match({"meta": {"key": "mark"}}, 1009),
                    {"counter": {"packets": 1, "bytes": 80}},
                    {"mangle": {"key": {"meta": {"key": "mark"}}, "value": 849}},
                    {"accept": None}]}
        changed = json.loads(json.dumps(rule))
        changed["expr"][2]["match"]["right"] = "223.5.5.5"
        for rows, expected in (([{"rule": rule}], 0), ([], 1),
                               ([{"rule": rule}, {"rule": rule}], 1), ([{"rule": changed}], 1)):
            with self.subTest(expected=expected, rows=len(rows)):
                result = self.run_shell(r'''
IPSEC_DATAPLANE_CN_MARK=1009; CN_MARK=849
nft() { printf '%s\n' "$NFT_JSON"; }
if ipsec_probe_output_rule_matches cn; then rc=0; else rc=$?; fi
printf '{"rc":%s}\n' "$rc"
''', NFT_JSON=json.dumps({"nftables": rows}))
                self.assertEqual(result["rc"], expected)


if __name__ == "__main__":
    unittest.main()
