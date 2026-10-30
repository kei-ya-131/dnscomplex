#!/usr/bin/env python3
"""Task7: emitted diagnostics and actual browser JS; no native service mutation."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from web_operation_contract_test import web_module

SOURCE = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()
MANAGER = SOURCE.split("<<'MANAGER'\n", 1)[1].split('\nMANAGER\n', 1)[0]
JS = SOURCE.split('<script>\nconst configKeys =', 1)[1].split('</script>', 1)[0]
JS = 'const configKeys =' + JS.split('const pendingOperation =', 1)[0]
JS = JS.replace('CONFIG_KEYS_PLACEHOLDER', '["AI_EGRESS_MODE"]')

class Diagnostics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manager = self.root / 'manager'; self.manager.write_text(MANAGER)
        self.formal = self.root / 'usr/local/etc/xray/config.json'
        self.formal.parent.mkdir(parents=True); self.formal.write_text('formal untouched')
        self.events = self.root / 'events'
        renderer = self.root / 'usr/local/lib/dnscomplex-xray/render.py'
        renderer.parent.mkdir(parents=True)
        renderer.write_text('#!/bin/sh\nwhile [ "$1" != "--output" ]; do shift; done\nprintf "%s" "$2" >>"$EVENTS"\nprintf "{}" >"$2"\n')
        renderer.chmod(0o700)
    def shell(self, body):
        pre = r'''
CONFIG="$FS_ROOT/config.env"
XRAY_LISTEN_HOST=127.0.0.1; XRAY_AI_SOCKS_PORT=1081; XRAY_CN_SOCKS_PORT=1082
render_xray_config_cmd() { printf changed >"$FS_ROOT/usr/local/etc/xray/config.json"; }
xray_test_config_file() { [[ -s "$1" ]] && [[ $(stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1") == 600 ]]; }
systemctl() { [[ "${INACTIVE:-0}" == 0 ]]; }
curl() { printf '%s\n' "$2" >>"$FS_ROOT/probes"; [[ "${CURL_FAIL:-0}" == 0 ]]; }
'''
        return subprocess.run(['bash', '-c', 'source '+shlex.quote(str(self.manager))+'\n'+pre+body],
                              env=dict(os.environ, DNSCOMPLEX_FS_ROOT=str(self.root), EVENTS=str(self.events)),
                              text=True, capture_output=True)
    def test_saved_xray_probe_uses_private_candidate_without_formal_write(self):
        result = self.shell('test_xray_cmd ai')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.formal.read_text(), 'formal untouched')
        candidate = Path(self.events.read_text()); self.assertFalse(candidate.exists())
    def test_unspecified_saved_probe_checks_both_profiles_with_manager_ifs(self):
        result = self.shell('test_xray_cmd')
        self.assertEqual(result.returncode, 0, result.stderr)
        probes=(self.root/'probes').read_text().splitlines()
        self.assertEqual(len(probes), 2)
        self.assertIn('127.0.0.1:1081', probes[0])
        self.assertIn('127.0.0.1:1082', probes[1])
    def test_inactive_service_and_curl_failure_are_nonzero(self):
        for flag in ('INACTIVE', 'CURL_FAIL'):
            result = self.shell(flag+'=1; if test_xray_cmd ai; then exit 0; else exit $?; fi')
            self.assertNotEqual(result.returncode, 0, flag)
            self.assertEqual(self.formal.read_text(), 'formal untouched')
    def test_general_diagnostic_never_loads_credentials_and_stops_on_failure(self):
        body = r'''
test_dns_cmd() { return "${DNS_FAIL:-0}"; }; test_ipsec_cmd() { :; }
validate_smartdns_config_cmd() { :; }; sing-box() { :; }; xray() { :; }; nft() { :; }
swanctl() { printf 'credential reload' >>"$EVENTS"; return 0; }
# Isolate the fixed external binary path without executing it.
function /opt/AdGuardHome/AdGuardHome { :; }
if test_cmd; then exit 0; else exit $?; fi
'''
        result = self.shell(body); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.events.exists(), 'diagnostic reloaded live credentials')
        result = self.shell('DNS_FAIL=41\n'+body)
        self.assertEqual(result.returncode, 41, result.stderr)
    def test_candidate_api_explicitly_reports_syntax_only(self):
        mod = web_module(self.root)
        mod.run = lambda args, timeout: {'ok': True, 'code': 0, 'output': 'ok'}
        result = mod.egress_test({'profile': 'ai', 'uri': 'literal'})
        self.assertEqual(result.get('check'), 'candidate-syntax')
        self.assertIn('未驗證遠端連線', result['output'])
        self.assertNotIn('test-xray', mod.PERSISTENT_ACTIONS)
    def test_ui_copy_matches_update_and_candidate_capability(self):
        mod = web_module(self.root)
        self.assertTrue('候選設定語法檢查' in mod.HTML)
        self.assertTrue('每日保守更新 Debian' not in mod.HTML)
        self.assertTrue('更新域名／geosite／SRS' in mod.HTML)

class BrowserJS(unittest.TestCase):
    def js(self, body):
        harness = r'''
const assert = require('node:assert/strict');
const nodes = new Map(); const buttons = [{disabled:false}, {disabled:true}];
function node(id) { if (!nodes.has(id)) nodes.set(id,{id,value:'',textContent:'',innerHTML:'',dataset:{},classList:{contains:()=>false},getAttribute:k=>k==='data-config-key'?'AI_EGRESS_MODE':null}); return nodes.get(id); }
node('configGroups').dataset.loaded='1';
const listeners = {};
global.document = {getElementById:node,querySelectorAll:selector=>selector==='button'?buttons:selector==='[data-config-key]'?[node('cfg_AI_EGRESS_MODE')]:[],addEventListener:(name,cb)=>listeners[name]=cb};
const storage = new Map(); global.localStorage = {setItem:(k,v)=>storage.set(k,v),getItem:k=>storage.get(k),removeItem:k=>storage.delete(k)};
for (const id of ['aiEgressMode','cnEgressMode','aiXrayUri','cnXrayUri','aiXrayJson','cnXrayJson','webPassword']) global[id]=node(id);
global.setTimeout = callback => { callback(); return 1; };
'''
        script = harness+JS+'\n(async()=>{\n'+body+'\n})().catch(err=>{console.error(err); process.exitCode=1});'
        result = subprocess.run(['node','-e',script],text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
    def test_duplicate_click_does_not_submit_and_original_button_state_restored(self):
        self.js('''let release; let calls=0;
const first=runWithOutput('output',()=>{calls++;return new Promise(resolve=>release=resolve)});
assert.equal(buttons[0].disabled,true);
await runWithOutput('output',()=>{calls++;return {ok:true}});
assert.equal(calls,1); release({ok:true,phase:'committed'}); await first;
assert.equal(buttons[0].disabled,false); assert.equal(buttons[1].disabled,true);''')
    def test_failed_password_save_retains_value_and_success_clears(self):
        self.js('''webPassword.value='new-secret'; api=async()=>({ok:false,phase:'rolled-back'});
await setWebPassword(); assert.equal(webPassword.value,'new-secret');
api=async()=>({ok:true,phase:'committed'}); await setWebPassword(); assert.equal(webPassword.value,'');''')
    def test_dirty_fields_survive_refresh_including_inflight_response(self):
        self.js('''let release;
api=()=>new Promise(resolve=>release=resolve); const loading=loadConfig();
aiXrayUri.value='unsubmitted'; listeners.input({target:aiXrayUri});
release({AI_XRAY_URI:'stored'}); await loading; assert.equal(aiXrayUri.value,'unsubmitted');
node('cfg_AI_EGRESS_MODE').value='unsaved'; listeners.input({target:node('cfg_AI_EGRESS_MODE')});
renderConfigGroups({AI_EGRESS_MODE:'stored-mode'}); assert.equal(node('cfg_AI_EGRESS_MODE').value,'unsaved');
api=async()=>({AI_EGRESS_MODE:'stored-mode'}); refreshAll=loadConfig;
await saveConfig(); assert.equal(node('cfg_AI_EGRESS_MODE').value,'unsaved');''')
    def test_review_r1_committed_fields_refresh_across_forms_without_stale_overwrite(self):
        self.js('''let stored={AI_EGRESS_MODE:'ipsec'}; const saves=[];
api=async(path,opts)=>{
 if(opts?.method==='POST') {const body=JSON.parse(opts.body);
  if(path==='/api/config'){stored={...stored,...body}; saves.push(body.AI_EGRESS_MODE);}
  else if(path==='/api/egress/apply') stored.AI_EGRESS_MODE=body.mode;
  return {ok:true,phase:'committed'};}
 return {...stored};};
refreshAll=loadConfig; await loadConfig();
node('cfg_AI_EGRESS_MODE').value='xray'; listeners.input({target:node('cfg_AI_EGRESS_MODE')});
await saveConfig(); assert.equal(stored.AI_EGRESS_MODE,'xray');
aiEgressMode.value='ipsec'; listeners.change({target:aiEgressMode}); await applyEgress('ai');
assert.equal(stored.AI_EGRESS_MODE,'ipsec'); assert.equal(node('cfg_AI_EGRESS_MODE').value,'ipsec');
await saveConfig(); assert.equal(stored.AI_EGRESS_MODE,'ipsec'); assert.deepEqual(saves,['xray','ipsec']);''')
    def test_review_r1_failed_pending_and_after_submit_edits_remain_unsubmitted(self):
        self.js('''let release; const field=node('cfg_AI_EGRESS_MODE');
refreshAll=loadConfig;
for(const outcome of [{ok:false,phase:'rolled-back'},{ok:null,pending:true},{ok:true,phase:'committed'}]) {
 api=async(path,opts)=>opts?.method==='POST'?new Promise(resolve=>release=resolve):{AI_EGRESS_MODE:'stored'};
 field.value='submitted'; listeners.input({target:field}); const saving=saveConfig();
 if(outcome.ok===true) {field.value='edited-after-submit'; listeners.input({target:field});}
 // This other form was never submitted and must survive even a committed generic save.
 aiXrayUri.value='other-tab-unsaved'; listeners.input({target:aiXrayUri});
 release(outcome); await saving;
 assert.equal(field.value,outcome.ok===true?'edited-after-submit':'submitted');
 assert.equal(aiXrayUri.value,'other-tab-unsaved');
}
// An edit back to the same value is still a new revision; a successful response
// must not treat it as the original submission and overwrite it during refresh.
api=async(path,opts)=>opts?.method==='POST'?new Promise(resolve=>release=resolve):{AI_EGRESS_MODE:'normalized'};
field.value='submitted'; listeners.input({target:field}); const saving=saveConfig();
field.value='temporary'; listeners.input({target:field}); field.value='submitted'; listeners.input({target:field});
release({ok:true,phase:'committed'}); await saving; assert.equal(field.value,'submitted');''')
    def test_pending_warning_rollback_manual_and_partial_are_distinct(self):
        self.js('''for (const [data,label] of [[{ok:null,phase:'applying'},'處理中'],[{ok:true,phase:'committed'},'已提交'],[{ok:true,phase:'committed',error_code:'MONITORING_WARNING'},'警告'],[{ok:false,phase:'rolled-back'},'失敗已回復'],[{ok:false,phase:'manual-intervention'},'需人工恢復'],[{ok:false,partial:true},'部分刷新']]) {
writeOutput('output',data); assert.ok(node('output').textContent.includes(label),node('output').textContent);
}''')
    def test_401_keeps_only_operation_id_for_reauthentication_and_resumes_get(self):
        self.js('''const id='a'.repeat(32); let posts=0; let authenticated=false;
fetch=async(path,opts)=>{if(opts?.method==='POST'){posts++;return {ok:true,status:202,json:async()=>({operation_id:id})};}
return authenticated?{ok:true,status:200,json:async()=>({operation_id:id,ok:true,phase:'committed'})}:{ok:false,status:401};};
await runWithOutput('output',()=>api('/api/action',{method:'POST',body:JSON.stringify({password:'secret'})}));
assert.equal(storage.get('dnscomplexOperation'),id); assert.equal(posts,1);
assert.ok(node('output').textContent.includes('重新登入')); assert.ok(!node('output').textContent.includes('操作失敗'));
assert.deepEqual([...storage.entries()],[['dnscomplexOperation',id]]);
authenticated=true; const result=await pollOperation(id); assert.equal(result.phase,'committed'); assert.equal(posts,1); assert.equal(storage.size,0);''')

if __name__ == '__main__': unittest.main()
