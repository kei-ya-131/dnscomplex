#!/usr/bin/env python3
"""Emitted manager mutators; native OS facilities are isolated, never /etc writes."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import sys
import types
import unittest

SOURCE=(Path(__file__).resolve().parents[1]/'install.sh').read_text()
MANAGER=SOURCE.split("<<'MANAGER'\n",1)[1].split('\nMANAGER\n',1)[0]
HELPER=SOURCE.split("<<'OPERATION_HELPER'\n",1)[1].split('\nOPERATION_HELPER\n',1)[0]
class Mutations(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve(); self.manager=self.root/'manager'; self.manager.write_text(MANAGER)
        self.config=self.root/'etc/dnscomplex/config.env'; self.config.parent.mkdir(parents=True)
        self.config.write_text("AI_GEOSITE_SOURCES=old-ai\nCN_VIDEO_SOURCES=old-cn\nAI_SUPPORT_DOMAINS=old.example\nSINGBOX_SOCKS_LISTEN=127.0.0.1\nSINGBOX_SOCKS_PORT=1080\nDNSCOMPLEX_UPDATE_TIME=03:00\nIPSEC_TCP_MSS=1200\n")
        self.geo=self.root/'var/lib/dnscomplex/geosite'; self.geo.mkdir(parents=True)
        (self.geo/'ai.custom').write_text('old.example\n'); (self.geo/'cn-video.custom').write_text('cn.example\n')
        self.sing=self.root/'etc/sing-box/config.json'; self.sing.parent.mkdir(); self.sing.write_text(json.dumps({'inbounds':[{'tag':'socks-in','listen':'127.0.0.1','listen_port':1080}]}))
        self.nft=self.root/'etc/nftables.d/dnscomplex.nft'; self.nft.parent.mkdir(); self.nft.write_text('table inet dnscomplex { chain forward {\n tcp flags syn tcp option maxseg size > 1200 tcp option maxseg size set 1200\n} }\n')
        self.runtime_rule=self.root/'runtime-rule'; self.runtime_rule.write_text(self.nft.read_text().replace('size set 1200','size set 1200 # handle 17'))
        self.events=self.root/'events'
    def shell(self,body,**extra):
        env=dict(os.environ,DNSCOMPLEX_FS_ROOT=str(self.root),DNSCOMPLEX_CONFIG=str(self.config),EVENTS=str(self.events),**extra)
        pre=r'''
IFS=$' \t\n'
need_root() { :; }; acquire_maintenance_lock() { :; }
event() { printf '%s\n' "$*" >>"$EVENTS"; }
load_config
write_config_cmd() { for key in AI_GEOSITE_SOURCES CN_VIDEO_SOURCES AI_SUPPORT_DOMAINS SINGBOX_SOCKS_LISTEN SINGBOX_SOCKS_PORT DNSCOMPLEX_UPDATE_TIME IPSEC_TCP_MSS; do printf '%s=%q\n' "$key" "${!key}"; done >"$CONFIG"; event write; }
state_transaction_cmd() { shift; local callback=$1 rc; shift; mkdir "$FS_ROOT/before"; cp -R "$FS_ROOT/etc" "$FS_ROOT/var" "$FS_ROOT/before/"; if "$callback" "$@"; then rc=0; else rc=$?; rm -rf "$FS_ROOT/etc" "$FS_ROOT/var"; cp -R "$FS_ROOT/before/etc" "$FS_ROOT/before/var" "$FS_ROOT/"; event rollback; fi; rm -rf "$FS_ROOT/before"; return "$rc"; }
state_transaction_manager_cmd() { "$@"; }
geosite_update_transaction() {
  event download; [[ "${FAIL:-}" != download ]] || return 41
  event compile; printf compiled >"$GEO_DIR/runtime"; [[ "${FAIL:-}" != compile ]] || return 41
  event publish; [[ "${FAIL:-}" != publish ]]
}
systemctl() { event "$*"; if [[ "$*" == *TimersCalendar* ]]; then printf 'OnCalendar=*-*-* %s:00\n' "$DNSCOMPLEX_UPDATE_TIME"; fi; [[ "${FAIL:-}" != restart || "$1" != restart ]]; }
sing-box() { event "$*"; [[ "${FAIL:-}" != check ]]; }
socks_runtime_ready_cmd() { event ready; [[ "${FAIL:-}" != ready ]]; }
restart_dns_stack() { event dns-restart; [[ "${FAIL:-}" != restart ]]; }
systemd-analyze() { event verify; [[ "${FAIL:-}" != verify ]]; }
ip() { printf '1: ipsec mtu 1400\n'; }
nft() {
  event "nft $*"
  if [[ "$1" == -a ]]; then cat "$FS_ROOT/runtime-rule"; fi
  [[ "${FAIL:-}" != check || "$1" != -c ]] || return 41
  [[ "${FAIL:-}" != apply || "$1" != -f ]] || return 41
  if [[ "$1" == -f ]]; then
    local value
    value=$(awk '{for(i=1;i<=NF;i++) if($i=="set") print $(i+1)}' "$2")
    sed -E "s/size > [0-9]+/size > $value/g; s/size set [0-9]+/size set $value/g" "$FS_ROOT/runtime-rule" >"$FS_ROOT/runtime-rule.next"
    mv "$FS_ROOT/runtime-rule.next" "$FS_ROOT/runtime-rule"
  fi
}
'''
        return subprocess.run(['bash','-c','source '+shlex.quote(str(self.manager))+'\n'+pre+body],env=env,text=True,capture_output=True)
    def payload(self,**data):
        path=self.root/'payload'; path.write_text(json.dumps(data)); return shlex.quote(str(path))
    def test_domain_batch_validates_all_before_writing(self):
        before=self.config.read_bytes()
        r=self.shell('apply_domain_rules_json_cmd '+self.payload(profile='ai',action='add',values=['valid.example','bad / value']))
        self.assertNotEqual(r.returncode,0); self.assertEqual(self.config.read_bytes(),before)
        self.assertFalse(self.events.exists())
    def test_domain_batch_compiles_once_and_preserves_cn(self):
        r=self.shell('apply_domain_rules_json_cmd '+self.payload(profile='ai',action='add',values=['one.example','two.example','new-source']))
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.events.read_text().count('compile\n'),1)
        self.assertEqual((self.geo/'cn-video.custom').read_text(),'cn.example\n')
        self.assertIn('two.example',(self.geo/'ai.custom').read_text()); self.assertIn('new-source',self.config.read_text())
    def test_failed_domain_download_compile_publish_restore_source_config_and_artifacts(self):
        for failure in ['download','compile','publish']:
            self.events.unlink(missing_ok=True)
            before=self.config.read_bytes(); custom=(self.geo/'ai.custom').read_bytes()
            r=self.shell('apply_domain_rules_json_cmd '+self.payload(profile='ai',action='add',values=['new.example','new-source']),FAIL=failure)
            self.assertNotEqual(r.returncode,0,failure+r.stderr); self.assertEqual(self.config.read_bytes(),before)
            self.assertEqual((self.geo/'ai.custom').read_bytes(),custom); self.assertFalse((self.geo/'runtime').exists())
            self.assertIn('rollback',self.events.read_text())
    def test_legacy_domain_alias_uses_one_batch(self):
        r=self.shell('add_domain_cmd cn new.example')
        self.assertEqual(r.returncode,0,r.stderr); self.assertEqual(self.events.read_text().count('compile\n'),1)
    def test_socks_check_restart_and_readiness_failures_restore_every_file(self):
        for failure in ['check','restart','ready']:
            self.events.unlink(missing_ok=True); before=(self.config.read_bytes(),self.sing.read_bytes())
            r=self.shell('if set_socks_cmd 127.0.0.2 1081; then exit 0; else exit $?; fi',FAIL=failure)
            self.assertNotEqual(r.returncode,0,failure+r.stderr)
            self.assertEqual((self.config.read_bytes(),self.sing.read_bytes()),before)
            if failure!='check': self.assertIn('rollback',self.events.read_text())
    def test_socks_unchanged_is_noop_and_routeros_restrictions_remain(self):
        r=self.shell('set_socks_cmd 127.0.0.1 1080'); self.assertEqual(r.returncode,0,r.stderr)
        self.assertFalse(self.events.exists())
        r=self.shell('DEPLOY_MODE=routeros-policy; LINUX_LAN_IPV4=192.168.50.180/24; set_socks_cmd 127.0.0.1 1081')
        self.assertNotEqual(r.returncode,0); self.assertFalse(self.events.exists())
    def test_local_host_restart_failure_is_not_success_and_file_restored(self):
        target=self.config.parent/'local-hosts'; target.write_text('192.0.2.1 old.local\n')
        r=self.shell('if set_local_host_cmd new.local 192.0.2.2; then exit 0; else exit $?; fi',FAIL='restart')
        self.assertNotEqual(r.returncode,0,r.stderr); self.assertEqual(target.read_text(),'192.0.2.1 old.local\n')
    def test_timer_preflight_and_restart_failures_restore_config_and_unit(self):
        unit=self.root/'etc/systemd/system/dnscomplex-update.timer'; unit.parent.mkdir(parents=True); unit.write_text('old timer')
        for failure in ['verify','restart']:
            before=self.config.read_bytes(); self.events.unlink(missing_ok=True)
            r=self.shell('if set_update_time_cmd 04:30; then exit 0; else exit $?; fi',FAIL=failure)
            self.assertNotEqual(r.returncode,0,failure+r.stderr); self.assertEqual(unit.read_text(),'old timer'); self.assertEqual(self.config.read_bytes(),before)
    def test_mss_missing_rule_and_nft_preflight_fail_before_publish(self):
        for content,failure in [('table inet dnscomplex {}\n',''),(self.nft.read_text(),'check')]:
            self.nft.write_text(content); before=self.config.read_bytes()
            r=self.shell('if mss_calibrate_cmd; then exit 0; else exit $?; fi',FAIL=failure)
            self.assertNotEqual(r.returncode,0,r.stderr); self.assertEqual(self.config.read_bytes(),before); self.assertEqual(self.nft.read_text(),content)
    def test_mss_native_apply_failure_restores_config_and_nft(self):
        before=(self.config.read_bytes(),self.nft.read_bytes(),self.runtime_rule.read_bytes())
        r=self.shell('if mss_calibrate_cmd; then exit 0; else exit $?; fi',FAIL='apply')
        self.assertNotEqual(r.returncode,0,r.stderr); self.assertEqual((self.config.read_bytes(),self.nft.read_bytes(),self.runtime_rule.read_bytes()),before)
    def helper(self):
        path=self.root/'operation.py'; path.write_text(HELPER)
        spec=importlib.util.spec_from_file_location('operation_mutation',path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module
    def test_cli_fixed_mapping_captures_files_and_legacy_xray_without_mode_read(self):
        m=self.helper(); self.assertTrue(hasattr(m,'cli_payload'),'missing fixed CLI adapter')
        self.assertEqual(m.cli_payload('fix',['--strict']),('fix',{'strict':True}))
        self.assertEqual(m.cli_payload('set-xray-uri',['cn','secret']),('set-xray-uri',{'profile':'cn','uri':'secret'}))
        self.assertEqual(m.cli_payload('apply-config-json',[self.payload_file({'SINGBOX_SOCKS_PORT':'1081'})]),('config',{'SINGBOX_SOCKS_PORT':'1081'}))
        with self.assertRaises(ValueError): m.cli_payload('fix',['--unknown'])
    def payload_file(self,value):
        p=self.root/'payload'; p.write_text(json.dumps(value)); return str(p)
    def test_cli_wait_keeps_same_id_and_returns_terminal_exit(self):
        m=self.helper(); self.assertTrue(hasattr(m,'cli'),'missing CLI bridge')
        calls=[]; m.submit=lambda action,payload,**kwargs: calls.append((action,payload)) or {'operation_id':'a'*32}
        phases=iter([{'phase':'applying'},{'phase':'committed'}]); m.status=lambda oid: dict(next(phases),operation_id=oid); m.time.sleep=lambda n:None
        self.assertEqual(m.cli('set-socks',['127.0.0.1','1080']),0); self.assertEqual(len(calls),1)
        m.status=lambda oid: {'phase':'rolled-back','operation_id':oid}; self.assertNotEqual(m.cli('fix',[]),0)
    def test_partial_refresh_reports_profiles_without_global_transaction(self):
        r=self.shell('DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT=30m; refresh_nftset_group() { event "refresh $1"; [[ "$1" == cn ]]; }; dig() { :; }; refresh_nftsets_cmd')
        self.assertNotEqual(r.returncode,0); self.assertIn('ai: kept_previous',r.stdout); self.assertIn('cn: success',r.stdout)
        self.assertNotIn('rollback',self.events.read_text())
    def test_cn_partial_failure_keeps_successful_selection_without_global_restore(self):
        r=self.shell(r'''CN_STATIC_A_OVERRIDES='old.example=192.0.2.1'; CN_OVERRIDE_PROBE_DOMAINS=''; dig() { :; }; curl() { :; }
cn_override_candidate_ips() { [[ "$1" != good.example ]] || printf '192.0.2.2\n'; }
probe_cn_override_ip() { :; }; refresh_cn_overrides_apply_cmd() { event scoped-publish; }
refresh_cn_overrides_cmd good.example missing.example old.example
''')
        self.assertNotEqual(r.returncode,0); self.assertIn('good.example: success',r.stdout)
        self.assertIn('missing.example: failed',r.stdout); self.assertIn('old.example: kept_previous',r.stdout)
        self.assertIn('scoped-publish',self.events.read_text()); self.assertNotIn('rollback',self.events.read_text())
    def test_live_bridge_route_is_before_lock_with_owner_and_custom_bypass(self):
        r=self.shell(r'''FS_ROOT=''; CONFIG=/etc/dnscomplex/config.env
operation_cli_bridge_cmd() { event "bridge $*"; }; acquire_maintenance_lock() { event lock; }; main set-socks 127.0.0.1 1080
''')
        self.assertEqual(r.returncode,0,r.stderr); self.assertEqual(self.events.read_text(),'bridge set-socks 127.0.0.1 1080\n')
        for setup in ['FS_ROOT=/offline','CONFIG=/custom/config.env','DNSCOMPLEX_OPERATION_INTERNAL=1','DNSCOMPLEX_OPERATION_ID='+('a'*32),'DNSCOMPLEX_SERVICE_MODE=1','DNSCOMPLEX_MAINTENANCE_LOCK_HELD=1']:
            r=self.shell('FS_ROOT=""; CONFIG=/etc/dnscomplex/config.env; '+setup+'; if operation_cli_bridge_eligible_cmd set-socks; then exit 9; else exit 0; fi')
            self.assertEqual(r.returncode,0,setup+r.stderr)
        r=self.shell('FS_ROOT=""; CONFIG=/etc/dnscomplex/config.env; DNSCOMPLEX_TIMER_MODE=1; operation_cli_bridge_eligible_cmd update-geosite')
        self.assertEqual(r.returncode,0,r.stderr)
    def test_concurrent_submission_and_pending_gate_keep_status_readable(self):
        m=self.helper(); m.OPERATIONS=self.root/'operations'; m.LOCK=self.root/'maintenance.lock'; m.systemctl=lambda *args:''
        first=m.submit('set-socks',{'listen':'127.0.0.1','port':'1080'})
        with self.assertRaises(ValueError): m.submit('set-socks',{'listen':'127.0.0.2','port':'1081'})
        self.assertEqual(m.status(first['operation_id'])['phase'],'queued')
        with m.locked(m.LOCK):
            with self.assertRaises(BlockingIOError): m.submit('fix',{})
            self.assertEqual(m.status(first['operation_id'])['phase'],'queued')
    def test_cli_secret_pipe_and_interruption_do_not_add_secret_child_argv_or_cancel(self):
        helper=self.root/'usr/local/libexec/dnscomplex-operation'; helper.parent.mkdir(parents=True)
        helper.write_text('import json,os,sys\nfrom pathlib import Path\nPath(os.environ["DNSCOMPLEX_FS_ROOT"],"capture").write_text(json.dumps(dict(argv=sys.argv[1:],data=sys.stdin.buffer.read().decode())))\n')
        r=self.shell('operation_cli_bridge_cmd set-ipsec ai user ultra-secret')
        self.assertEqual(r.returncode,0,r.stderr)
        capture=json.loads((self.root/'capture').read_text()); self.assertEqual(capture['argv'],['cli','set-ipsec'])
        self.assertIn('ultra-secret',capture['data']); self.assertNotIn('ultra-secret',r.stdout+r.stderr)
        m=self.helper(); m.submit=lambda *args,**kwargs:dict(operation_id='b'*32); m.status=lambda oid:dict(phase='applying')
        m.time.sleep=lambda n: (_ for _ in ()).throw(KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt): m.cli('fix',[])
    def test_runtime_actions_cannot_be_submitted_into_global_rollback(self):
        m=self.helper(); m.OPERATIONS=self.root/'operations'; m.LOCK=self.root/'maintenance.lock'
        for action in ['refresh-nftsets','refresh-cn-overrides']:
            with self.assertRaises(ValueError): m.submit(action,{})
    def test_cn_scoped_readback_detects_writer_omission(self):
        target=self.root/'etc/smartdns/smartdns.conf'; target.parent.mkdir(); target.write_text('before\n')
        before=self.config.read_bytes()
        r=self.shell(r'''CN_STATIC_A_OVERRIDES='good.example=192.0.2.2'
rewrite_smartdns_static_overrides() { printf candidate >"$1"; }; validate_smartdns_config_cmd() { :; }; write_config_cmd() { :; }
if refresh_cn_overrides_apply_cmd; then exit 0; else exit $?; fi
''')
        self.assertNotEqual(r.returncode,0); self.assertEqual(self.config.read_bytes(),before); self.assertEqual(target.read_text(),'before\n')
    def test_actual_domain_worker_journal_restores_sources_config_and_runtime_together(self):
        spec=importlib.util.spec_from_file_location('lifecycle_fixture',Path(__file__).with_name('web_operation_lifecycle_test.py'))
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        case=module.Lifecycle(); case.setUp(); self.addCleanup(case.doCleanups)
        mod,installed,config=case.actual_facilities()
        config.write_text((Path(__file__).resolve().parents[1]/"examples/routeros-policy.config.env").read_text().replace("SINGBOX_SOCKS_PORT=1080\n","SINGBOX_SOCKS_PORT=10800\n")+"\nAI_GEOSITE_SOURCES=old-ai\nCN_VIDEO_SOURCES=old-cn\nAI_SUPPORT_DOMAINS=old.example\n")
        geo=case.root/'var/lib/dnscomplex/geosite'; geo.mkdir(parents=True); custom=geo/'ai.custom'; custom.write_text('old.example\n')
        runtime=geo/'compiled.srs'; runtime.write_text('old-runtime')
        boundary='if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi'
        manager=mod.MANAGER.read_text().replace(boundary,r'''
update_geosite_candidate_cmd() { printf candidate >"$GEO_DIR/compiled.srs"; return 41; }
'''+boundary)
        mod.MANAGER.write_text(manager)
        before=config.read_bytes()
        oid=mod.submit('domain-batch',dict(profile='ai',action='add',values=['new.example','new-source']))['operation_id']
        result=subprocess.run(['python3',str(installed),'worker',oid],env=case.env,text=True,capture_output=True)
        self.assertEqual(result.returncode,41,result.stderr)
        self.assertIn('new.example',custom.read_text()); self.assertIn('new-source',config.read_text()); self.assertEqual(runtime.read_text(),'candidate')
        self.assertEqual(mod.status(oid)['phase'],'recovery-required')
        self.assertEqual(mod.recover(oid),0)
        self.assertEqual(config.read_bytes(),before); self.assertEqual(custom.read_text(),'old.example\n'); self.assertEqual(runtime.read_text(),'old-runtime')
        self.assertEqual(mod.status(oid)['phase'],'rolled-back')
    def test_web_busy_has_conflict_status_and_runtime_refresh_has_partial_message(self):
        web=SOURCE.split("write_file /usr/local/lib/dnscomplex-web/app.py <<'PY'\n",1)[1].split('\nPY\n',1)[0]
        path=self.root/'web.py'; path.write_text(web)
        candidate=types.ModuleType('candidate'); candidate.ALLOWED_KEYS=(); candidate.parse_env_file=lambda *args:{}
        previous=sys.modules.get('candidate'); sys.modules['candidate']=candidate
        spec=importlib.util.spec_from_file_location('mutation_web',path); m=importlib.util.module_from_spec(spec)
        try: spec.loader.exec_module(m)
        finally:
            if previous is None: sys.modules.pop('candidate',None)
            else: sys.modules['candidate']=previous
        class Reply:
            returncode=3; stdout=''; stderr='private contents'
        original=m.subprocess.run; self.addCleanup(setattr,m.subprocess,'run',original)
        m.subprocess.run=lambda *args,**kwargs: Reply()
        h=object.__new__(m.Handler); h.path='/api/action'; h.require_auth=lambda:True
        h.read_json=lambda:dict(action='set-socks',listen='127.0.0.1',port=1080)
        replies=[]; h.send_json=lambda data,status=200:replies.append((status,data)); h.do_POST()
        self.assertEqual(replies[0][0],409); self.assertEqual(replies[0][1]['error_code'],'BUSY'); self.assertNotIn('private',str(replies))
        h.read_json=lambda:dict(action='refresh-nftsets'); m.run=lambda *args:dict(ok=False,code=1,output='ai: kept_previous\ncn: success')
        h.do_POST(); self.assertTrue(replies[-1][1]['partial']); self.assertIn('Partial refresh',replies[-1][1]['message'])
    def test_domain_source_readback_rejects_writer_omission(self):
        before=self.config.read_bytes()
        r=self.shell('write_config_cmd() { event omitted; }; apply_domain_rules_json_cmd '+self.payload(profile='ai',action='add',values=['new-source']))
        self.assertNotEqual(r.returncode,0,r.stderr); self.assertEqual(self.config.read_bytes(),before)
        self.assertNotIn('compile',self.events.read_text())
    def test_private_derived_domain_and_legacy_outbound_are_cleaned_at_terminal(self):
        m=self.helper(); m.OPERATIONS=self.root/'operations'; m.LOCK=self.root/'maintenance.lock'; m.RESTORE=self.root/'restore'; m.systemctl=lambda *args:''
        oid=m.submit('domain-batch',dict(profile='ai',action='add',values=['synthetic.example']))['operation_id']
        directory=m.OPERATIONS/oid
        for name in ['domain-batch.json','xray-outbound.json']: m.write(directory/name,{'private':'secret'})
        m.update(oid,phase='rolled-back'); m.cleanup(oid,stop_timer=False)
        for name in ['domain-batch.json','xray-outbound.json']: self.assertFalse((directory/name).exists(),name)
    def test_cn_failed_scoped_rollback_does_not_claim_previous_state_verified(self):
        r=self.shell(r'''CN_STATIC_A_OVERRIDES='old.example=192.0.2.1'; CN_OVERRIDE_PROBE_DOMAINS=''; dig() { :; }; curl() { :; }
cn_override_candidate_ips() { printf '192.0.2.2\n'; }; probe_cn_override_ip() { :; }
refresh_cn_overrides_apply_cmd() { return 70; }; refresh_cn_overrides_cmd old.example
''')
        self.assertNotEqual(r.returncode,0); self.assertIn('old.example: failed',r.stdout)
        self.assertIn('operator recovery required',r.stdout); self.assertNotIn('kept_previous',r.stdout)
    def test_live_root_slash_initialization_preserves_canonical_default_config(self):
        env=dict(os.environ,DNSCOMPLEX_FS_ROOT='/'); env.pop('DNSCOMPLEX_CONFIG',None)
        r=subprocess.run(['bash','-c','source "$1"; printf "%s|%s" "$FS_ROOT" "$CONFIG"','_',str(self.manager)],env=env,text=True,capture_output=True)
        self.assertEqual(r.returncode,0,r.stderr); self.assertEqual(r.stdout,'/|/etc/dnscomplex/config.env')
        env['DNSCOMPLEX_CONFIG']='/custom/config.env'
        r=subprocess.run(['bash','-c','source "$1"; printf "%s" "$CONFIG"','_',str(self.manager)],env=env,text=True,capture_output=True)
        self.assertEqual(r.stdout,'/custom/config.env')
    def test_fix1_cli_real_signal_at_first_handoff_keeps_bounded_same_id_owner(self):
        path=self.root/'signal-operation.py'; path.write_text(HELPER)
        driver=self.root/'signal-driver.py'
        driver.write_text(r"""
import importlib.util,json,os,signal,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('signal_operation',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
root=Path(sys.argv[2]); m.ROOT=root; m.OPERATIONS=root/'operations'; m.RESTORE=root/'restore'; m.LOCK=root/'maintenance.lock'
calls=[]
def systemctl(*args):
    if not calls: os.kill(os.getpid(),int(sys.argv[3]))
    calls.append(args); return ''
m.systemctl=systemctl
try: m.cli('fix',[])
except BaseException: pass
before=list(calls); records=list(m.OPERATIONS.glob('[a-f0-9]'*32)); oid=records[0].name
m.systemctl=lambda *args:calls.append(args) or ''
try: m.submit('fix',{})
except m.OperationBusy: pass
resumed=calls[len(before):]
m.update(oid,phase='rolled-back'); later=m.submit('fix',{})
(root/'result.json').write_text(json.dumps(dict(oid=oid,phase=m.status(oid)['phase'],before=before,resumed=resumed,later=later['operation_id'])))
""")
        import signal
        for sig in (signal.SIGINT,signal.SIGTERM):
            target=self.root/str(sig); target.mkdir()
            r=subprocess.run(['python3',str(driver),str(path),str(target),str(sig)],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,0,r.stderr)
            value=json.loads((target/'result.json').read_text()); oid=value['oid']
            self.assertIn('operation_id='+oid,r.stdout)
            self.assertIn(['start','dnscomplex-operation-guard@'+oid+'.timer'],value['before'])
            self.assertIn(['--no-block','start','dnscomplex-operation@'+oid+'.service'],value['before'])
            self.assertIn(['--no-block','start','dnscomplex-operation@'+oid+'.service'],value['resumed'])
            self.assertNotEqual(value['later'],oid)
    def test_fix1_uncertain_writer_start_is_never_marked_terminal(self):
        m=self.helper(); m.OPERATIONS=self.root/'operations'; m.RESTORE=self.root/'restore'; m.LOCK=self.root/'maintenance.lock'
        def start(*args):
            if '--no-block' in args: raise subprocess.CalledProcessError(1,['systemctl'])
            return ''
        m.systemctl=start
        with self.assertRaises(subprocess.CalledProcessError): m.submit('fix',{})
        records=list(m.OPERATIONS.glob('[a-f0-9]'*32)); self.assertEqual(len(records),1)
        self.assertEqual(m.status(records[0].name)['phase'],'queued')
        calls=[]; m.systemctl=lambda *args:calls.append(args) or ''
        with self.assertRaises(m.OperationBusy): m.submit('fix',{})
        self.assertIn(('--no-block','start','dnscomplex-operation@'+records[0].name+'.service'),calls)
    def test_fix1_mss_success_preserves_classification_and_readiness_sets(self):
        state=self.root/'runtime-sets'; state.write_text('ai4 cn4 ai_ready4 cn_ready4 existing-elements')
        r=self.shell(r'''
systemctl() { event "$*"; if [[ "$*" == 'restart nftables' ]]; then : >"$FS_ROOT/runtime-sets"; fi; }
mss_calibrate_cmd
''')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(state.read_text(),'ai4 cn4 ai_ready4 cn_ready4 existing-elements')
        self.assertNotIn('restart nftables',self.events.read_text())
        self.assertIn('size > 1340 tcp option maxseg size set 1340 # handle 17',self.runtime_rule.read_text())
    def test_fix1_actual_refresh_metadata_failure_reports_applied_not_preserved(self):
        stamp=self.geo.parent/'nftset-ai.last_refresh'; stamp.write_text('previous-timestamp')
        r=self.shell(r'''
DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT=30m
source "$MANAGER_FOR_REFRESH"
IFS=$' \t\n'; need_root() { :; }
nftset_refresh_domain_stream() { printf 'synthetic.example\n'; }
dig() { printf '1.1.1.1\n'; }
nft() { case "$1" in get) return 1;; -f) event "applied $2";; list) :;; esac; }
date() { if [[ ! -e "$FS_ROOT/metadata-failed" ]]; then touch "$FS_ROOT/metadata-failed"; return 1; fi; printf '12345\n'; }
refresh_nftsets_cmd
''',MANAGER_FOR_REFRESH=str(self.manager))
        self.assertNotEqual(r.returncode,0,r.stderr)
        self.assertIn('ai: failed',r.stdout); self.assertNotIn('ai: kept_previous',r.stdout)
        self.assertIn('cn: success',r.stdout); self.assertEqual(self.events.read_text().count('applied '),2)
        self.assertEqual(stamp.read_text(),'previous-timestamp')
    def test_fix1_cli_before_writer_exception_is_safely_terminal_and_later_submit_works(self):
        import contextlib,io
        m=self.helper(); m.OPERATIONS=self.root/'operations'; m.RESTORE=self.root/'restore'; m.LOCK=self.root/'maintenance.lock'
        m.systemctl=lambda *args: (_ for _ in ()).throw(KeyboardInterrupt())
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(KeyboardInterrupt): m.cli('fix',[])
        records=list(m.OPERATIONS.glob('[a-f0-9]'*32)); oid=records[0].name
        self.assertIn('operation_id='+oid,output.getvalue())
        self.assertEqual(m.status(oid)['phase'],'rolled-back'); self.assertFalse((records[0]/'payload.json').exists())
        m.systemctl=lambda *args:''
        self.assertNotEqual(m.submit('fix',{})['operation_id'],oid)
    def test_fix1_mss_rejects_ambiguous_runtime_handle_before_publish(self):
        self.runtime_rule.write_text(self.runtime_rule.read_text()+'tcp flags syn tcp option maxseg size > 1200 tcp option maxseg size set 1200 # handle 18\n')
        before=(self.config.read_bytes(),self.nft.read_bytes(),self.runtime_rule.read_bytes())
        r=self.shell('if mss_calibrate_cmd; then exit 0; else exit $?; fi')
        self.assertNotEqual(r.returncode,0)
        self.assertEqual((self.config.read_bytes(),self.nft.read_bytes(),self.runtime_rule.read_bytes()),before)
        self.assertNotIn('nft -f ',self.events.read_text())
if __name__=='__main__': unittest.main()
