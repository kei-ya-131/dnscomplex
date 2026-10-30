#!/usr/bin/env python3
"""Actual emitted manager profile mutations with isolated OS boundaries."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

SOURCE=(Path(__file__).resolve().parents[1]/'install.sh').read_text()
MANAGER=SOURCE.split("<<'MANAGER'\n",1)[1].split('\nMANAGER\n',1)[0]

class ProfileMutation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.manager=self.root/'manager'; self.manager.write_text(MANAGER)
        self.config=self.root/'config.env'
        self.config.write_text("AI_EGRESS_MODE=ipsec\nCN_EGRESS_MODE=ipsec\nAI_XRAY_URI=old-uri\nAI_XRAY_OUTBOUND_JSON=''\nCN_XRAY_URI=cn-uri\nCN_XRAY_OUTBOUND_JSON=''\nAI_IPSEC_USERNAME=old-user\nAI_IPSEC_PASSWORD=old-secret\nCN_IPSEC_USERNAME=cn-user\nCN_IPSEC_PASSWORD=cn-secret\nDEFAULT_DNS_STRATEGY=prefer_ipv6\n")
        self.events=self.root/'events'
    def run_shell(self, body, **extra):
        env=dict(os.environ,DNSCOMPLEX_FS_ROOT=str(self.root),DNSCOMPLEX_CONFIG=str(self.config),EVENTS=str(self.events),**extra)
        script='source '+shlex.quote(str(self.manager))+'\n'+r'''
need_root() { :; }; acquire_maintenance_lock() { :; }
event() { printf '%s\n' "$*" >>"$EVENTS"; }
load_config
state_transaction_cmd() { shift; local cb=$1; shift; cp "$CONFIG" "$CONFIG.before"; if "$cb" "$@"; then return 0; else local rc=$?; cp "$CONFIG.before" "$CONFIG"; event rollback; return "$rc"; fi; }
write_config_cmd() { for key in AI_EGRESS_MODE CN_EGRESS_MODE AI_XRAY_URI AI_XRAY_OUTBOUND_JSON CN_XRAY_URI CN_XRAY_OUTBOUND_JSON AI_IPSEC_USERNAME AI_IPSEC_PASSWORD CN_IPSEC_USERNAME CN_IPSEC_PASSWORD DEFAULT_DNS_STRATEGY; do printf '%s=%q\n' "$key" "${!key}"; done >"$CONFIG"; event write; }
operation_postcheck_selected_profile_cmd() { event "probe $1"; [[ "${FAIL:-}" != probe ]]; }
xray_test_config_file() { [[ "${FAIL:-}" != syntax ]]; }
if [[ "${REAL_STACK:-0}" != 1 ]]; then
apply_egress_stack_cmd() { event stack; [[ "${FAIL:-}" != stack ]]; }
fi
''' + body
        return subprocess.run(['bash','-c',script],env=env,text=True,capture_output=True)
    def payload(self, **data):
        p=self.root/'payload.json'; p.write_text(json.dumps(data)); p.chmod(0o600); return shlex.quote(str(p))
    def test_atomic_egress_rolls_back_mode_and_outbound_on_apply_or_probe_failure(self):
        renderer=self.root/'usr/local/lib/dnscomplex-xray/render.py'; renderer.parent.mkdir(parents=True)
        renderer.write_text('#!/bin/sh\nwhile [ \"$1\" != \"--output\" ]; do shift; done\nprintf \"{}\" >\"$2\"\n'); renderer.chmod(0o700)
        for failure in ('stack','probe'):
            before=self.config.read_bytes()
            result=self.run_shell('if apply_egress_json_cmd '+self.payload(profile='ai',mode='xray',uri='new-secret-uri')+'; then exit 0; else exit $?; fi',FAIL=failure)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.config.read_bytes(),before)
            self.assertTrue(self.events.exists(),'atomic candidate never reached real mutation')
            self.assertIn('rollback',self.events.read_text()); self.events.unlink()
    def install_renderer(self):
        renderer=self.root/'usr/local/lib/dnscomplex-xray/render.py'; renderer.parent.mkdir(parents=True,exist_ok=True)
        renderer.write_text('#!/bin/sh\nwhile [ "$1" != "--output" ]; do shift; done\nprintf "{}" >"$2"\n'); renderer.chmod(0o700)
    def test_success_and_mask_reuse_preserve_other_profile_and_default(self):
        self.install_renderer()
        for payload in [dict(profile='ai',mode='xray',uri='new-secret-uri'),
                        dict(profile='ai',mode='ipsec',uri='********',outbound_json='********')]:
            result=self.run_shell('apply_egress_json_cmd '+self.payload(**payload))
            self.assertEqual(result.returncode,0,result.stderr)
            config=self.config.read_text()
            self.assertIn('AI_XRAY_URI=new-secret-uri',config)
            for expected in ('CN_XRAY_URI=cn-uri','CN_IPSEC_PASSWORD=cn-secret','DEFAULT_DNS_STRATEGY=prefer_ipv6'):
                self.assertIn(expected,config)
            self.assertNotIn('********',config)
    def test_malformed_json_and_syntax_failure_do_not_mutate(self):
        self.install_renderer()
        for data in [dict(profile='ai',mode='xray',outbound_json='{broken'),
                     dict(profile='ai',mode='xray',uri='bad-uri')]:
            self.events.unlink(missing_ok=True)
            result=self.run_shell('apply_egress_json_cmd '+self.payload(**data),FAIL='syntax')
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(self.events.exists())
    def test_readback_detects_successful_writer_that_did_not_save(self):
        self.install_renderer()
        before=self.config.read_bytes()
        result=self.run_shell('write_config_cmd() { event omitted; }; apply_egress_json_cmd '+self.payload(profile='ai',mode='xray',uri='new-secret-uri'))
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.config.read_bytes(),before)
        self.assertIn('rollback',self.events.read_text())
    def test_missing_renderer_output_cannot_commit(self):
        self.install_renderer()
        renderer=self.root/'usr/local/lib/dnscomplex-xray/render.py'; renderer.write_text('#!/bin/sh\nexit 0\n')
        result=self.run_shell('apply_egress_json_cmd '+self.payload(profile='ai',mode='xray',uri='uri'))
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.events.exists())
    def test_legacy_cli_candidate_callbacks_cannot_commit_failed_selected_postcheck(self):
        for callback,args in [('set_egress_candidate_cmd','ai xray'),('set_xray_uri_candidate_cmd','ai new-uri'),('set_xray_json_candidate_cmd',"ai '{}' ")]:
            self.events.unlink(missing_ok=True); before=self.config.read_bytes()
            result=self.run_shell('state_transaction_cmd synthetic '+callback+' '+args,FAIL='probe')
            self.assertNotEqual(result.returncode,0,callback)
            self.assertEqual(self.config.read_bytes(),before)
            self.assertIn('rollback',self.events.read_text())
    def test_invalid_legacy_profile_rejected_before_mutation(self):
        result=self.run_shell('set_egress_cmd invalid ipsec')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.events.exists())
    def test_selected_stack_failures_rollback_without_other_profile_readiness(self):
        for failure in ('init','route','nat','bind','probe'):
            self.events.unlink(missing_ok=True); before=self.config.read_bytes()
            body=r'''
render_xray_config_cmd() { :; }; write_singbox_egress_cmd() { :; }; write_nftables_runtime_cmd() { :; }; systemctl() { :; }
swanctl() { event "init $*"; [[ "$FAIL" != init ]]; }
ensure_policy_route_profile() { event "route $1"; [[ "$FAIL" != route ]]; }
sync_ipsec_nat_profile() { event "nat $1"; [[ "$FAIL" != nat ]]; }
sync_singbox_ipsec_bind_addresses() { event "bind $1"; [[ "$FAIL" != bind ]]; }
''' + 'apply_egress_json_cmd '+self.payload(profile='ai',mode='ipsec')
            result=self.run_shell(body,FAIL=failure,REAL_STACK='1')
            self.assertNotEqual(result.returncode,0,failure+result.stderr)
            self.assertEqual(self.config.read_bytes(),before)
            self.assertIn('rollback',self.events.read_text())
            self.assertNotIn('cn',self.events.read_text())
    def test_rejects_mutually_exclusive_candidates_before_mutation(self):
        result=self.run_shell('apply_egress_json_cmd '+self.payload(profile='ai',mode='xray',uri='uri',outbound_json='{}'))
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.events.exists())
    def test_selected_ike_parser_excludes_indented_children_and_retains_all_top_states(self):
        result=self.run_shell(r'''
ipsec_selected_ike_ids_cmd ai <<'SAS'
ai: #1, ESTABLISHED, IKEv2
  ai: #2, reqid 1, INSTALLED, TUNNEL
ai: #3, CONNECTING, IKEv2
  ai: #4, reqid 1, INSTALLING, TUNNEL
ai: #5, REKEYING, IKEv2
  ai: #6, reqid 1, INSTALLED, TUNNEL
cn: #9, ESTABLISHED, IKEv2
  cn: #10, reqid 2, INSTALLED, TUNNEL
SAS
''')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.splitlines(),['1','3','5'])
    def ipsec_fixture(self):
        return r'''
write_swanctl_cmd() { event swan-config; }
swanctl() {
  case "$1" in
    --list-sas)
      if [[ ! -e "$DNSCOMPLEX_FS_ROOT/terminated" || "${FAIL:-}" == stale ]]; then
        printf 'ai: #1, ESTABLISHED, IKEv2\n  ai: #2, reqid 1, INSTALLED, TUNNEL\n'
      elif [[ -e "$DNSCOMPLEX_FS_ROOT/initiated" ]]; then
        if [[ "${FAIL:-}" == reused ]]; then
          printf 'ai: #1, ESTABLISHED, IKEv2\n'
        else
          printf 'ai: #2, ESTABLISHED, IKEv2\n'
        fi
        printf '  ai: #3, reqid 1, INSTALLED, TUNNEL\n'
      elif [[ "${FAIL:-}" == connecting ]]; then
        printf 'ai: #5, CONNECTING, IKEv2\n'
      elif [[ "${FAIL:-}" == rekeying ]]; then
        printf 'ai: #6, REKEYING, IKEv2\n'
      fi
      printf 'cn: #9, ESTABLISHED, IKEv2\n  cn: #10, reqid 2, INSTALLED, TUNNEL\n'
      ;;
    --load-all) event load; printf 'old-secret new-secret'; [[ "${FAIL:-}" != load ]] ;;
    --terminate) event "$*"; touch "$DNSCOMPLEX_FS_ROOT/terminated" ;;
    --initiate) event "$*"; touch "$DNSCOMPLEX_FS_ROOT/initiated"; [[ "${FAIL:-}" != auth ]] ;;
  esac
}
timeout() { shift 3; "$@"; }
ensure_policy_route_profile() { event "route $1"; [[ "${FAIL:-}" != ready ]]; }
sync_ipsec_nat_profile() { event "nat $1"; }
sync_singbox_ipsec_bind_addresses() { event "bind $1"; }
operation_postcheck_ipsec_profile_cmd() { event "ipsec-probe $1"; [[ "${FAIL:-}" != probe ]]; }
if set_ipsec_cmd ai new-user new-secret; then exit 0; else exit $?; fi
'''
    def test_ipsec_load_auth_readiness_and_old_sa_cannot_commit(self):
        body=self.ipsec_fixture()
        for failure in ('load','auth','ready','probe','stale','reused'):
            for name in ('terminated','initiated'): (self.root/name).unlink(missing_ok=True)
            self.events.unlink(missing_ok=True); before=self.config.read_bytes()
            result=self.run_shell(body,FAIL=failure)
            self.assertNotEqual(result.returncode,0,failure+result.stderr)
            self.assertEqual(self.config.read_bytes(),before,failure)
            self.assertNotIn('old-secret',result.stdout+result.stderr)
            self.assertNotIn('new-secret',result.stdout+result.stderr)
            events=self.events.read_text()
            self.assertIn('rollback',events)
            self.assertNotIn('--ike cn',events)
            if failure=='load': self.assertNotIn('--initiate',events)
    def test_new_ike_id_matching_old_child_namespace_is_accepted_and_preserves_cn(self):
        result=self.run_shell(self.ipsec_fixture())
        self.assertEqual(result.returncode,0,result.stderr)
        events=self.events.read_text()
        self.assertIn('--terminate\n--ike\nai',events)
        self.assertIn('--initiate\n--child\nai',events)
        self.assertNotIn('cn\n--timeout',events)
        self.assertIn('CN_IPSEC_PASSWORD=cn-secret',self.config.read_text())
        self.assertIn('AI_IPSEC_PASSWORD=new-secret',self.config.read_text())
        self.assertNotIn('secret',result.stdout+result.stderr)
    def test_termination_rejects_remaining_non_established_selected_context(self):
        for state in ('connecting','rekeying'):
            for name in ('terminated','initiated'): (self.root/name).unlink(missing_ok=True)
            self.events.unlink(missing_ok=True); before=self.config.read_bytes()
            result=self.run_shell(self.ipsec_fixture(),FAIL=state)
            self.assertNotEqual(result.returncode,0,state)
            self.assertEqual(self.config.read_bytes(),before)
            self.assertIn('rollback',self.events.read_text())
            self.assertNotIn('--initiate',self.events.read_text())
            self.assertFalse((self.root/'initiated').exists())
    def test_same_credentials_only_verify_without_loading_or_terminating(self):
        body=self.ipsec_fixture().replace('ai new-user new-secret','ai old-user old-secret')
        result=self.run_shell(body)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.events.read_text(),'ipsec-probe ai\n')
    def test_ipsec_readback_rejects_missing_persisted_credentials(self):
        body=self.ipsec_fixture().replace('if set_ipsec_cmd', 'write_config_cmd() { printf "AI_EGRESS_MODE=ipsec\\nCN_EGRESS_MODE=ipsec\\n" >"$CONFIG"; }; if set_ipsec_cmd')
        result=self.run_shell(body)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('rollback',self.events.read_text())
    def test_strict_fix_failure_stays_strict_in_if_context_with_real_fresh_boundary(self):
        self.manager.write_text(MANAGER+'\nlegacy_reconcile_cmd() { (exit 41); printf continued >"$EVENTS"; }\n')
        result=self.run_shell('if fix_cmd --strict; then exit 0; else exit $?; fi')
        self.assertEqual(result.returncode,41,result.stderr)
        self.assertFalse(self.events.exists())
    def test_legacy_repair_child_commands_keep_manager_identity_in_fresh_source(self):
        manager=MANAGER.replace('if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then\n  main "$@"\nfi','')
        manager+=r'''
config_schema_keys() { :; }; load_config() { DEPLOY_MODE=vlan-gateway; }
migrate_config_cmd() { :; }; remove_macbook_air_local_override() { :; }
apply_runtime_network_settings() { :; }; render_xray_config_cmd() { :; }
write_singbox_egress_cmd() { :; }; write_nftables_runtime_cmd() { :; }
render_adguard_runtime() { :; }; write_update_timer_cmd() { :; }; systemctl() { :; }
restart_ipsec_service() { :; }; restart_dns_stack() { :; }; test_cmd() { :; }
main() { printf '%s\n' "$1" >>"$EVENTS"; }
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
'''
        self.manager.write_text(manager); self.manager.chmod(0o700)
        result=self.run_shell('if fix_cmd --strict; then exit 0; else exit $?; fi')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.events.read_text().splitlines(),['ipsec-ready','routes'])
    def test_monitoring_warning_handoff_is_private_and_fixed(self):
        oid='a'*32; directory=self.root/'var/lib/dnscomplex-operations'/oid
        directory.mkdir(parents=True,mode=0o700)
        result=self.run_shell('repair_monitoring_warning_cmd',DNSCOMPLEX_OPERATION_INTERNAL='1',DNSCOMPLEX_OPERATION_ID=oid)
        self.assertEqual(result.returncode,0,result.stderr)
        marker=directory/'repair-monitoring-warning'
        self.assertEqual(marker.read_text(),'monitoring\n')
        self.assertEqual(marker.stat().st_mode & 0o777,0o600)
        self.assertIn('monitoring',result.stderr)
    def test_default_fix_has_transaction_and_strict_child_boundary(self):
        result=self.run_shell(r'''
migrate_config_cmd() { :; }; remove_macbook_air_local_override() { :; }; apply_runtime_network_settings() { :; }
systemctl() { :; }; restart_ipsec_service() { :; }; write_update_timer_cmd() { :; }; render_adguard_runtime() { :; }; restart_dns_stack() { :; }
state_transaction_manager_cmd() { event "fresh $*"; return 41; }
if fix_cmd; then exit 0; else exit $?; fi
''')
        self.assertEqual(result.returncode,41,result.stderr)
        self.assertIn('fresh fix_cmd\n--strict',self.events.read_text())
        self.assertIn('rollback',self.events.read_text())

if __name__=='__main__': unittest.main()
