#!/usr/bin/env python3
"""Emitted operation code: local files and real signals; no native systemd claims."""
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()

class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def emitted(self, tag):
        self.assertTrue("<<'" + tag + "'\n" in SOURCE, 'missing emitted lifecycle implementation')
        return SOURCE.split("<<'" + tag + "'\n", 1)[1].split('\n' + tag + '\n', 1)[0]

    def module(self):
        path = self.root / 'operation.py'
        path.write_text(self.emitted('OPERATION_HELPER'))
        spec = importlib.util.spec_from_file_location('operation_fixture', path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.ROOT = self.root
        mod.OPERATIONS = self.root / 'var/lib/dnscomplex-operations'
        mod.RESTORE = self.root / 'var/lib/dnscomplex-restore'
        mod.LOCK = self.root / 'run/lock/maintenance.lock'
        return mod

    def test_submission_is_private_fixed_action_and_read_only_status(self):
        mod = self.module()
        mod.systemctl = lambda *args: ''
        result = mod.submit('set-ipsec', {'profile':'ai', 'password':'secret'})
        oid = result['operation_id']
        self.assertRegex(oid, r'^[a-f0-9]{32}$')
        directory = mod.OPERATIONS / oid
        self.assertEqual((directory / 'payload.json').stat().st_mode & 0o777, 0o600)
        self.assertNotIn('secret', (directory / 'manifest.json').read_text())
        self.assertEqual(set(mod.status(oid)), {'operation_id','action','phase','ok','deadline','rollback_state','error_code','message'})
        with self.assertRaises(ValueError): mod.submit('fix',{})
        with self.assertRaises(ValueError): mod.submit('sh', {'command':'touch /tmp/unsafe'})
        with self.assertRaises(ValueError): mod.status('../escape')
        before = (directory / 'manifest.json').read_bytes()
        mod.status(oid)
        self.assertEqual(before, (directory / 'manifest.json').read_bytes())

    def test_systemd_writer_has_bounded_cgroup_recovery_and_clean_stop_hook(self):
        def emitted_unit(description):
            return SOURCE.split('Description=' + description, 1)[1].split('\nEOF', 1)[0]

        def seconds(unit, key):
            match = re.search(r'^' + re.escape(key) + r'=(\d+)s?$', unit, re.MULTILINE)
            self.assertIsNotNone(match, key + ' missing from emitted unit')
            return int(match.group(1))

        unit = emitted_unit('dnscomplex persistent operation writer')
        for text in ['Type=exec','KillMode=control-group','TimeoutStopSec=15','ExecStopPost=','OnFailure=']:
            self.assertIn(text, unit)
        self.assertNotIn('dnscomplex-web.service', unit)
        recovery = emitted_unit('Recover dnscomplex persistent operation')
        guard = emitted_unit('Outer deadline for dnscomplex persistent operation')
        writer_runtime = seconds(unit, 'RuntimeMaxSec')
        writer_stop = seconds(unit, 'TimeoutStopSec')
        recovery_runtime = seconds(recovery, 'RuntimeMaxSec')
        recovery_stop = seconds(recovery, 'TimeoutStopSec')
        guard_active = seconds(guard, 'OnActiveSec')
        self.assertEqual(writer_runtime, 300)
        self.assertEqual(recovery_runtime, 150)
        self.assertEqual(guard_active, 510)
        self.assertGreaterEqual(
            guard_active,
            writer_runtime + writer_stop + recovery_runtime + recovery_stop + 30,
            'guard must leave 30 seconds after bounded writer stop and recovery',
        )

    def facilities(self):
        mod = self.module()
        # Only OS facilities are faked. Backup, validation, journal, worker,
        # recovery and manifest handling use their real emitted implementations.
        mod.MANAGER = self.root / 'usr/local/sbin/dnscomplex'
        mod.RECOVERY = self.root / 'usr/local/libexec/dnscomplex-restore-recover'
        for path in (mod.MANAGER,mod.RECOVERY): path.parent.mkdir(parents=True,exist_ok=True)
        manager = SOURCE.split("<<'MANAGER'\n",1)[1].split('\nMANAGER\n',1)[0]
        manager = manager.replace('if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then\n  main "$@"\nfi', '')
        manager += r"""
need_root() { :; }
operation_dispatch_cmd() { printf changed >"$FS_ROOT/etc/sing-box/config.json"; touch "$FS_ROOT/wrote"; sleep "${FIXTURE_SLEEP:-0}"; return "${FIXTURE_RC:-0}"; }
operation_postcheck_cmd() { [[ ! -e "$FS_ROOT/postcheck-fail" ]]; }
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
"""
        mod.MANAGER.write_text(manager)
        mod.RECOVERY.write_text(self.emitted('RECOVERY')); mod.RECOVERY.chmod(0o700)
        installed = self.root / 'usr/local/libexec/dnscomplex-operation'
        installed.write_text(self.emitted('OPERATION_HELPER')); installed.chmod(0o700)
        self.target = self.root / 'etc/sing-box/config.json'
        self.target.parent.mkdir(parents=True); self.target.write_text('baseline')
        self.bin = self.root / 'bin'; self.bin.mkdir()
        for name,body in {'id':'echo 0', 'flock':'exit 0', 'systemctl':
                'echo "$*" >>"$DNSCOMPLEX_FS_ROOT/systemctl.log"; case "$*" in *ActiveState*) echo inactive;; *ControlGroup*) :;; is-active*) echo inactive;; esac'}.items():
            path=self.bin/name; path.write_text('#!/bin/sh\n'+body+'\n'); path.chmod(0o700)
        self.env=dict(os.environ,DNSCOMPLEX_FS_ROOT=str(self.root),PATH=str(self.bin)+os.pathsep+os.environ['PATH'])
        self.addCleanup(lambda: None)
        mod.systemctl=lambda *args: 'inactive' if 'ActiveState' in ' '.join(args) else ''
        # Imported module subprocesses need the same explicit offline environment.
        old=dict(os.environ); os.environ.update(self.env)
        self.addCleanup(lambda: (os.environ.clear(),os.environ.update(old)))
        return mod,installed

    def prepare_fixture(self):
        mod, installed=self.facilities()
        oid=mod.submit('fix',{})['operation_id']
        with mod.locked(mod.LOCK) as fd:
            mod.update(oid,phase='preparing')
            mod.prepare(oid,fd)
        return mod,installed,oid

    def test_prepared_no_write_and_duplicate_recovery_preserve_terminal(self):
        mod,_,oid=self.prepare_fixture()
        self.assertEqual(self.target.read_text(),'baseline')
        self.assertEqual(mod.recover(oid),0)
        self.assertEqual(mod.status(oid)['phase'],'rolled-back')
        manifest=(mod.OPERATIONS/oid/'manifest.json').read_bytes()
        self.assertEqual(mod.recover(oid),0)
        self.assertEqual(manifest,(mod.OPERATIONS/oid/'manifest.json').read_bytes())

    def test_partial_write_files_only_then_services_uses_existing_helper(self):
        mod,_,oid=self.prepare_fixture()
        self.target.write_text('partial candidate')
        journal=mod.RESTORE/('transaction.op.'+oid)
        env=dict(self.env,DNSCOMPLEX_RESTORE_STATE_DIR=str(mod.RESTORE))
        log=self.root/'systemctl.log'; log.unlink(missing_ok=True)
        result=subprocess.run(['bash',str(mod.RECOVERY),'--files'],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.target.read_text(),'baseline')
        self.assertTrue(journal.exists())
        self.assertFalse(log.exists(), 'early files recovery called systemctl')
        self.assertEqual(mod.status(oid)['ok'],None)
        result=subprocess.run(['bash',str(mod.RECOVERY),'--services'],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(journal.exists())
        self.assertEqual(mod.status(oid)['phase'],'rolled-back')

    def test_sigterm_sigkill_and_web_restart_leave_recoverable_record(self):
        for sig in (signal.SIGTERM,signal.SIGKILL):
            with self.subTest(sig=sig):
                # Each operation owns the actual process group killed by the fake
                # facility in place of Linux systemd KillMode=control-group.
                mod,installed=self.facilities()
                oid=mod.submit('fix',{})['operation_id']
                process=subprocess.Popen(['python3',str(installed),'worker',oid],env=dict(self.env,FIXTURE_SLEEP='30'),start_new_session=True)
                for _ in range(400):
                    if (self.root/'wrote').exists() or process.poll() is not None: break
                    time.sleep(.05)
                self.assertTrue((self.root/'wrote').exists(), 'writer never reached real mutation')
                # An unrelated web group restart cannot terminate the writer.
                web=subprocess.Popen(['sleep','30'],start_new_session=True)
                os.killpg(web.pid,signal.SIGTERM); web.wait()
                self.assertIsNone(process.poll())
                os.killpg(process.pid,sig); process.wait()
                self.assertNotEqual(mod.status(oid)['phase'],'committed')
                self.assertTrue((mod.OPERATIONS/oid/'backup.tar.gz').exists())
                self.assertEqual(mod.recover(oid),0)
                self.assertEqual(self.target.read_text(),'baseline')
                self.assertEqual(mod.status(oid)['phase'],'rolled-back')
                # Reset fixture for next signal while retaining cleanup callbacks.
                if sig == signal.SIGTERM:
                    import shutil
                    for path in list(self.root.iterdir()):
                        if path.is_dir(): shutil.rmtree(path)
                        else: path.unlink()

    def test_corrupt_archive_owner_and_journal_fail_before_restore(self):
        mod,_,oid=self.prepare_fixture()
        self.target.write_text('candidate')
        archive=mod.OPERATIONS/oid/'backup.tar.gz'
        journal=mod.RESTORE/('transaction.op.'+oid)/'entries.tsv'
        helper=mod.OPERATIONS/oid/'restore-recover'
        for path in (archive,journal,helper):
            baseline=path.read_bytes()
            path.write_bytes(b'corrupt')
            self.assertEqual(mod.recover(oid),1)
            self.assertEqual(self.target.read_text(),'candidate')
            self.assertEqual(mod.status(oid)['phase'],'manual-intervention')
            self.assertTrue(archive.exists())
            path.write_bytes(baseline)
            mod.update(oid,phase='prepared',rollback_state='not-started',error_code='')
        path=mod.OPERATIONS/oid/'manifest.json'
        value=json.loads(path.read_text()); value['owner_unit']='unrelated.service'; mod.write(path,value)
        with self.assertRaises(ValueError): mod.recover(oid)

    def test_same_writer_inner_transaction_cannot_publish_terminal_or_delete_archive(self):
        mod,_,oid=self.prepare_fixture()
        manager=mod.MANAGER
        archive=mod.OPERATIONS/oid/'backup.tar.gz'
        script='source "$1"; need_root(){ :; }; acquire_maintenance_lock(){ :; }; callback(){ printf changed >"$FS_ROOT/etc/sing-box/config.json"; }; state_transaction_cmd nested callback'
        result=subprocess.run(['bash','-c',script,'_',str(manager)],env=dict(self.env,DNSCOMPLEX_OPERATION_ID=oid),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(archive.exists())
        self.assertNotIn(mod.status(oid)['phase'],mod.TERMINAL)
        self.assertEqual(len(list(mod.OPERATIONS.iterdir())),1)
        self.assertEqual(mod.recover(oid),0)
        self.assertEqual(self.target.read_text(),'baseline')

    def test_commit_marker_crash_window_keeps_candidate_and_terminal_status(self):
        mod,_,oid=self.prepare_fixture()
        self.target.write_text('checked candidate')
        mod.update(oid,phase='applying')
        journal=mod.RESTORE/('transaction.op.'+oid)
        (journal/'committed').touch(mode=0o600)
        env=dict(self.env,DNSCOMPLEX_RESTORE_STATE_DIR=str(mod.RESTORE))
        result=subprocess.run(['bash',str(mod.RECOVERY),'--files'],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.target.read_text(),'checked candidate')
        self.assertEqual(mod.status(oid)['phase'],'committed')
        self.assertFalse(journal.exists())

    def test_owner_active_blocks_recovery_and_postcheck_failure_retains_archive(self):
        mod,installed=self.facilities()
        oid=mod.submit('fix',{})['operation_id']
        (self.root/'postcheck-fail').touch()
        result=subprocess.run(['python3',str(installed),'worker',oid],env=self.env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.target.read_text(),'changed')
        self.assertTrue((mod.OPERATIONS/oid/'backup.tar.gz').exists())
        mod.systemctl=lambda *args: 'active'
        self.assertEqual(mod.recover(oid),1)
        self.assertEqual(self.target.read_text(),'changed')
        mod.systemctl=lambda *args: 'inactive' if 'ActiveState' in ' '.join(args) else ''
        self.assertEqual(mod.recover(oid),0)
        self.assertEqual(self.target.read_text(),'baseline')

    def test_boot_sync_accepts_retained_legacy_task2_terminal_records(self):
        mod=self.module(); mod.mkdir(mod.OPERATIONS)
        directory=mod.OPERATIONS/('a'*32); mod.mkdir(directory)
        mod.write(directory/'manifest.json',{'schema_version':1,'id':directory.name,'phase':'committed'})
        try: mod.boot_sync()
        except ValueError: self.fail('legacy Task2 terminal record blocks boot recovery')
        self.assertTrue((directory/'manifest.json').exists())

    def test_http_authentication_async_submission_status_and_no_secret_echo(self):
        import base64, email.message, io, sys, types
        mod=self.module(); mod.systemctl=lambda *args:''
        candidate=types.ModuleType('candidate'); candidate.ALLOWED_KEYS=(); candidate.parse_env_file=lambda *args:{}
        old=sys.modules.get('candidate'); sys.modules['candidate']=candidate
        web=SOURCE.split("write_file /usr/local/lib/dnscomplex-web/app.py <<'PY'\n",1)[1].split('\nPY\n',1)[0]
        ns={'__name__':'fixture','__file__':str(self.root/'app.py')}
        try: exec(web,ns)
        finally:
            if old is None: sys.modules.pop('candidate',None)
            else: sys.modules['candidate']=old
        ns['parse_config']=lambda:{'DNSCOMPLEX_WEB_PASSWORD':'auth'}
        ns['operation_submit']=mod.submit
        def safe_status(oid):
            try: return mod.status(oid)
            except (FileNotFoundError,ValueError): return None
        ns['operation_status']=safe_status
        def request(method,path,body=None,auth=False):
            handler=ns['Handler'].__new__(ns['Handler']); handler.path=path
            handler.request_version='HTTP/1.1'; handler.command=method; handler.requestline=method+' '+path
            handler.headers=email.message.Message(); data=json.dumps(body or {}).encode()
            handler.headers['content-length']=str(len(data)); handler.headers['content-type']='application/json'
            if auth: handler.headers['Authorization']='Basic '+base64.b64encode(b'admin:auth').decode()
            class Input(io.BytesIO):
                def finish_input(self): pass  # Socket deadline is exercised by the loopback contract.
            handler.rfile=Input(data); handler.wfile=io.BytesIO()
            getattr(handler,'do_'+method)()
            header,payload=handler.wfile.getvalue().split(b'\r\n\r\n',1)
            return int(header.split()[1]),json.loads(payload)
        code,_=request('POST','/api/action',{'action':'set-ipsec','password':'never-echo'})
        self.assertEqual(code,401)
        self.assertFalse(mod.OPERATIONS.exists())
        code,value=request('POST','/api/action',{'action':'set-ipsec','password':'never-echo'},True)
        self.assertEqual(code,202)
        oid=value['operation_id']
        self.assertNotIn('never-echo',json.dumps(value))
        self.assertEqual(request('GET','/api/operations/'+oid)[0],401)
        self.assertEqual(request('GET','/api/operations/'+oid,auth=True)[0],200)
        self.assertEqual(request('GET','/api/operations/'+('b'*32),auth=True)[0],404)
        self.assertEqual(request('GET','/api/operations/../../etc/passwd',auth=True)[0],404)

    def test_web_start_resumes_queued_same_id_and_does_not_resubmit(self):
        mod=self.module(); calls=[]; mod.systemctl=lambda *args:calls.append(args) or ''
        oid=mod.submit('fix',{})['operation_id']; calls.clear()
        self.assertTrue(hasattr(mod,'resume'),'web restart has no queued-operation reconciliation')
        mod.resume()
        self.assertEqual(len(list(mod.OPERATIONS.iterdir())),1)
        self.assertIn(('--no-block','start','dnscomplex-operation@'+oid+'.service'),calls)

    def test_egress_handoff_keeps_single_private_payload_for_atomic_setter(self):
        import contextlib,io
        mod=self.module(); mod.systemctl=lambda *args:''
        payload={'profile':'ai','mode':'xray','outbound_json':'{"protocol":"vless"}','uri':'********'}
        oid=mod.submit('egress-apply',payload)['operation_id']; directory=mod.OPERATIONS/oid
        class Output:
            buffer=io.BytesIO()
        output=Output()
        with contextlib.redirect_stdout(output): mod.arguments(directory,'egress-apply')
        self.assertEqual(output.buffer.getvalue(),b'')
        self.assertEqual(json.loads((directory/'payload.json').read_text()),payload)
        self.assertFalse((directory/'xray-outbound.json').exists())

    def test_postcheck_is_action_scoped_and_selected_profile_failure_is_fatal(self):
        manager=SOURCE.split("<<'MANAGER'\n",1)[1].split('\nMANAGER\n',1)[0]
        path=self.root/'manager'; path.write_text(manager)
        script=r"""
source "$1"
load_config(){ :; }; validate_loaded_config(){ :; }
test_cmd(){ return 99; }
operation_postcheck_ipsec_profile_cmd(){ printf '%s' "$1" >"$ROOT/selected"; return 41; }
operation_postcheck_cmd "$ROOT" set-web-password || exit 88
operation_postcheck_cmd "$ROOT" set-ipsec
"""
        (self.root/'payload.json').write_text('{"profile":"cn"}')
        result=subprocess.run(['bash','-c',script,'_',str(path)],env=dict(os.environ,ROOT=str(self.root)),capture_output=True,text=True)
        self.assertEqual(result.returncode,41,result.stderr)
        self.assertEqual((self.root/'selected').read_text(),'cn')

    def test_successful_worker_commits_once_and_cleans_payload_after_postcheck(self):
        mod,installed=self.facilities()
        oid=mod.submit('fix',{})['operation_id']
        result=subprocess.run(['python3',str(installed),'worker',oid],env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.target.read_text(),'changed')
        self.assertEqual(mod.status(oid)['phase'],'committed')
        directory=mod.OPERATIONS/oid
        self.assertFalse((directory/'payload.json').exists())
        self.assertFalse((directory/'backup.tar.gz').exists())
        self.assertFalse((mod.RESTORE/('transaction.op.'+oid)).exists())
        before=(directory/'manifest.json').read_bytes()
        result=subprocess.run(['python3',str(installed),'worker',oid],env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(before,(directory/'manifest.json').read_bytes())

    def test_duplicate_recoverers_use_same_id_lock_and_cannot_race(self):
        mod,installed,oid=self.prepare_fixture()
        self.target.write_text('candidate')
        one=subprocess.Popen(['python3',str(installed),'recover',oid],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        two=subprocess.Popen(['python3',str(installed),'recover',oid],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        for process in (one,two):
            _,error=process.communicate(timeout=40)
            self.assertEqual(process.returncode,0,error.decode())
        self.assertEqual(self.target.read_text(),'baseline')
        self.assertEqual(mod.status(oid)['phase'],'rolled-back')

    def test_failed_services_phase_retains_package_and_reports_manual_intervention(self):
        mod,_,oid=self.prepare_fixture()
        journal=mod.RESTORE/('transaction.op.'+oid)
        (journal/'pre-service-state.tsv').write_text('dnscomplex-web.service\tdisabled\tactive\n')
        # This fixture models an active web unit in the saved service-state file.
        # Only the systemctl facility fails; actual files recovery has completed.
        systemctl=self.bin/'systemctl'
        systemctl.write_text('#!/bin/sh\ncase "$*" in *ActiveState*) echo inactive;; *ControlGroup*) :;; is-active*) echo inactive;; restart*) exit 42;; esac\n')
        self.target.write_text('candidate')
        self.assertEqual(mod.recover(oid),1)
        self.assertEqual(self.target.read_text(),'baseline')
        self.assertEqual(mod.status(oid)['phase'],'manual-intervention')
        self.assertTrue((journal/'files-recovered').exists())
        self.assertTrue((mod.OPERATIONS/oid/'backup.tar.gz').exists())

    def test_hidden_prep_crash_has_no_mutation_and_cleans_only_own_slots(self):
        mod,_,oid=self.prepare_fixture()
        journal=mod.RESTORE/('transaction.op.'+oid)
        hidden=mod.RESTORE/('.operation-prep.'+oid)
        journal.rename(hidden)
        slots=[Path(row.split('\t')[2]) for row in (hidden/'entries.tsv').read_text().splitlines()]
        self.assertTrue(any(slot.exists() for slot in slots))
        self.assertEqual(mod.recover(oid),0)
        self.assertEqual(self.target.read_text(),'baseline')
        self.assertFalse(hidden.exists())
        self.assertTrue(all(not slot.exists() for slot in slots))
        self.assertEqual(mod.status(oid)['phase'],'rolled-back')

    def test_auto_recovery_pending_is_processing_until_rollback_is_verified(self):
        mod=self.module(); mod.systemctl=lambda *args:''
        oid=mod.submit('fix',{})['operation_id']
        mod.update(oid,phase='recovery-required',error_code='CANDIDATE_FAILED')
        self.assertIsNone(mod.status(oid)['ok'],'client must keep polling through queued recovery')
        self.assertNotIn('operator intervention',mod.status(oid)['message'])

    def test_installer_accepts_legacy_terminal_store_but_refuses_orphan_operation_journal(self):
        import shlex
        function=SOURCE.split('acquire_installer_maintenance_lock() {',1)[1].split('\nrelease_installer_maintenance_lock()',1)[0]
        driver=self.root/'installer-gate'
        driver.write_text('acquire_installer_maintenance_lock() {'+function+r"""
target_path(){ printf '%s%s\n' "$DNSCOMPLEX_ROOT" "$1"; }
die(){ printf '%s\n' "$*" >&2; exit 1; }
flock(){ :; }
DRY_RUN=0
acquire_installer_maintenance_lock
""")
        directory=self.root/'var/lib/dnscomplex-operations'/('a'*32); directory.mkdir(parents=True,mode=0o700)
        directory.parent.chmod(0o700)
        manifest=directory/'manifest.json'; manifest.write_text('{"schema_version":1,"phase":"committed"}'); manifest.chmod(0o600)
        env=dict(os.environ,DNSCOMPLEX_ROOT=str(self.root),DNSCOMPLEX_MAINTENANCE_LOCK=str(self.root/'lock'))
        result=subprocess.run(['bash',str(driver)],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        journal=self.root/'var/lib/dnscomplex-restore'/('transaction.op.'+'a'*32); journal.mkdir(parents=True)
        result=subprocess.run(['bash',str(driver)],env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0,'orphan boot journal must freeze recovery helper replacement')

    def actual_facilities(self):
        mod,installed=self.facilities()
        manager=self.emitted('MANAGER').replace('if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then\n  main "$@"\nfi','')
        # macOS Bash3.2 lacks this Bash5 builtin; only the NUL array-read
        # facility is supplied. Dispatcher, mutators and main remain emitted code.
        manager+=r'''
if ! type mapfile >/dev/null 2>&1; then
# Bash3's quoted array slices incorrectly join entries when IFS omits space;
# use its default IFS to reproduce Bash5's separate quoted array arguments.
IFS=$' \t\n'
mapfile() {
  local name=${!#} index=0
  while IFS= read -r -d '' "$name[$index]"; do
    index=$((index+1))
  done
  unset "$name[$index]"
}
fi
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
'''
        mod.MANAGER.write_text(manager); mod.MANAGER.chmod(0o700)
        config=self.root/'etc/dnscomplex/config.env'; config.parent.mkdir(parents=True)
        config.write_text("WAN_IFACE=eth0\nAI_EGRESS_MODE=xray\nCN_EGRESS_MODE=xray\n")
        self.env['DNSCOMPLEX_CONFIG']=str(config); os.environ['DNSCOMPLEX_CONFIG']=str(config)
        return mod,installed,config

    def test_committed_fix_keeps_safe_monitoring_warning_after_cleanup(self):
        mod,installed=self.facilities()
        oid=mod.submit('fix',{})['operation_id']
        warning=mod.OPERATIONS/oid/'repair-monitoring-warning'
        warning.write_text('monitoring\n'); warning.chmod(0o600)
        result=subprocess.run(['python3',str(installed),'worker',oid],env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        status=mod.status(oid)
        self.assertTrue(status['ok'])
        self.assertEqual(status['error_code'],'MONITORING_WARNING')
        self.assertIn('monitoring',status['message'])
        self.assertFalse(warning.exists())

    def test_atomic_egress_dispatch_failure_restores_both_fields_with_one_id(self):
        mod,installed,config=self.actual_facilities()
        before="WAN_IFACE=eth0\nAI_EGRESS_MODE=ipsec\nAI_XRAY_URI=old-uri\nCN_EGRESS_MODE=xray\nCN_XRAY_URI=cn-uri\n"
        config.write_text(before)
        manager=mod.MANAGER.read_text()
        boundary='if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi'
        facilities=r'''
write_config_cmd() {
  printf 'WAN_IFACE=eth0\nAI_EGRESS_MODE=%s\nAI_XRAY_URI=%s\nAI_XRAY_OUTBOUND_JSON=%q\nCN_EGRESS_MODE=%s\nCN_XRAY_URI=%s\n' "$AI_EGRESS_MODE" "$AI_XRAY_URI" "$AI_XRAY_OUTBOUND_JSON" "$CN_EGRESS_MODE" "$CN_XRAY_URI" >"$CONFIG"
  printf '%s\n' "$DNSCOMPLEX_OPERATION_ID" >>"$FS_ROOT/writer-owners"
  ( : >&8 ) || return 87
}
xray_test_config_file() { :; }
apply_egress_stack_cmd() { return 41; }
'''
        mod.MANAGER.write_text(manager.replace(boundary,facilities+'\n'+boundary))
        renderer=self.root/'usr/local/lib/dnscomplex-xray/render.py'; renderer.parent.mkdir(parents=True)
        renderer.write_text('#!/bin/sh\nwhile [ "$1" != "--output" ]; do shift; done\nprintf "{}" >"$2"\n'); renderer.chmod(0o700)
        oid=mod.submit('egress-apply',{'profile':'ai','mode':'xray','uri':'new-secret-uri'})['operation_id']
        result=subprocess.run(['python3',str(installed),'worker',oid],env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode,41,result.stderr)
        self.assertIn('AI_EGRESS_MODE=xray',config.read_text())
        self.assertIn('AI_XRAY_URI=new-secret-uri',config.read_text())
        self.assertIn('CN_XRAY_URI=cn-uri',config.read_text())
        self.assertEqual((self.root/'writer-owners').read_text().splitlines(),[oid])
        self.assertEqual(len(list(mod.OPERATIONS.glob('*/manifest.json'))),1)
        self.assertEqual(mod.status(oid)['phase'],'recovery-required')
        self.assertEqual(mod.recover(oid),0)
        self.assertEqual(config.read_text(),before)
        self.assertEqual(mod.status(oid)['phase'],'rolled-back')
        self.assertNotIn('new-secret-uri',json.dumps(mod.status(oid))+result.stdout+result.stderr)

    def test_review_r1_real_dispatch_check_failure_stops_install_and_outer_recovers(self):
        mod,installed,config=self.actual_facilities()
        for name,body in {
            'jq':'printf "{}\\n"',
            'sing-box':'exit 41',
            'install':'echo install >>"$DNSCOMPLEX_FS_ROOT/mutations"; printf changed >"$DNSCOMPLEX_FS_ROOT/etc/sing-box/config.json"',
        }.items():
            path=self.bin/name; path.write_text('#!/bin/sh\n'+body+'\n'); path.chmod(0o700)
        oid=mod.submit('set-socks',{'listen':'127.0.0.1','port':'1080'})['operation_id']
        result=subprocess.run(['python3',str(installed),'worker',oid],env=self.env,capture_output=True,text=True)
        self.assertFalse((self.root/'mutations').exists(),'failed sing-box check reached install')
        self.assertEqual(result.returncode,41,result.stderr)
        self.assertEqual(mod.status(oid)['phase'],'recovery-required')
        self.assertTrue((mod.OPERATIONS/oid/'backup.tar.gz').exists())
        self.assertEqual(mod.recover(oid),0)
        self.assertEqual(mod.status(oid)['phase'],'rolled-back')
        self.assertEqual(self.target.read_text(),'baseline')

    def test_review_r1_real_rules_loop_stops_first_mutator_on_middle_failure(self):
        mod,_,_=self.actual_facilities()
        path=self.bin/'xargs'; path.write_text('#!/bin/sh\ncat >>"$DNSCOMPLEX_FS_ROOT/rule-attempts"\nexit 41\n'); path.chmod(0o700)
        path=self.bin/'mktemp'; path.write_text('#!/bin/sh\ncase "$*" in *.config.env.*) echo config-write >>"$DNSCOMPLEX_FS_ROOT/mutations";; esac\nexec /usr/bin/mktemp "$@"\n'); path.chmod(0o700)
        oid=mod.submit('rules-domain',{'profile':'ai','action':'add','value':'firstsource\nsecondsource'})['operation_id']
        mod.update(oid,phase='applying')
        with mod.locked(mod.LOCK) as fd:
            rc=mod.manager('operation_dispatch_cmd',mod.OPERATIONS/oid,'rules-domain',lock_fd=fd)
        self.assertFalse((self.root/'mutations').exists(),'rules failure reached write_config_cmd')
        self.assertEqual(rc,41)
        attempts=(self.root/'rule-attempts').read_text()
        self.assertIn('firstsource',attempts)
        self.assertNotIn('secondsource',attempts)

    def test_review_r2_sync_transaction_children_use_real_main_gate_same_id_and_fd8(self):
        mod,_,config=self.actual_facilities()
        path=self.bin/'id'
        path.write_text('#!/bin/sh\nif ( : >&8 ) 2>/dev/null; then echo "${DNSCOMPLEX_OPERATION_ID:-missing}:lock8" >>"$DNSCOMPLEX_FS_ROOT/child-owners"; fi\necho 0\n'); path.chmod(0o700)
        driver=self.root/'sync-driver'
        driver.write_text(r'''
source "$DNSCOMPLEX_FS_ROOT/usr/local/sbin/dnscomplex"
callback() {
  local output="$FS_ROOT/child-stderr"
  if "$FS_ROOT/usr/local/sbin/dnscomplex" fix --strict invalid-proof 2>"$output"; then return 61; fi
  grep -q 'usage: dnscomplex fix' "$output" || return 62
  "$FS_ROOT/usr/local/sbin/dnscomplex" ipsec-ready || return $?
  if "$FS_ROOT/usr/local/sbin/dnscomplex" routes invalid-proof 2>"$output"; then return 63; fi
  grep -q 'usage: dnscomplex routes' "$output" || return 64
  # A different pending operation must still block the same fresh child.
  local other="$FS_ROOT/var/lib/dnscomplex-operations/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  mkdir -m 0700 "$other"
  printf '%s\n' '{"schema_version":1,"id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","phase":"applying"}' >"$other/manifest.json"
  chmod 0600 "$other/manifest.json"
  if "$FS_ROOT/usr/local/sbin/dnscomplex" ipsec-ready 2>"$output"; then return 65; fi
  grep -q 'unresolved operation' "$output" || return 66
  rm -rf -- "$other"
}
state_transaction_cmd 'config apply' callback
''')
        result=subprocess.run(['bash',str(driver)],env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        paths=list(mod.OPERATIONS.glob('*/manifest.json'))
        self.assertEqual(len(paths),1)
        value=json.loads(paths[0].read_text()); self.assertEqual(value['phase'],'committed')
        owners=(self.root/'child-owners').read_text().splitlines()
        self.assertTrue(owners)
        self.assertTrue(all(line==value['id']+':lock8' for line in owners),owners)

    def test_review_r3_submit_interruption_points_are_scanner_safe_or_same_id_published(self):
        import re
        points=('mkdir','payload-before','payload-after','manifest-before','manifest-after','rename-before','rename-after','publish-fsync')
        for point in points:
            with self.subTest(point=point):
                mod=self.module(); case=self.root/point
                mod.ROOT=case; mod.OPERATIONS=case/'var/lib/dnscomplex-operations'; mod.RESTORE=case/'var/lib/dnscomplex-restore'; mod.LOCK=case/'run/lock/maintenance.lock'
                mod.mkdir(mod.OPERATIONS); calls=[]; mod.systemctl=lambda *args:calls.append(args) or ''
                mkdir,write,rename,sync=mod.mkdir,mod.write,mod.os.rename,mod.sync
                def fail(): raise OSError('injected interruption')
                def fault_mkdir(path):
                    mkdir(path)
                    if path.parent==mod.OPERATIONS and point=='mkdir': fail()
                def fault_write(path,data):
                    kind='payload' if path.name=='payload.json' else 'manifest'
                    if point==kind+'-before': fail()
                    write(path,data)
                    if point==kind+'-after': fail()
                def fault_rename(src,dst):
                    publish=Path(dst).parent==mod.OPERATIONS and re.fullmatch('[a-f0-9]{32}',Path(dst).name)
                    if publish and point=='rename-before': fail()
                    result=rename(src,dst)
                    if publish and point=='rename-after': fail()
                    return result
                def fault_sync(path):
                    sync(path)
                    if point=='publish-fsync' and path==mod.OPERATIONS and any(re.fullmatch('[a-f0-9]{32}',item.name) for item in path.iterdir()): fail()
                mod.mkdir=fault_mkdir; mod.write=fault_write; mod.os.rename=fault_rename; mod.sync=fault_sync
                try:
                    with self.assertRaises(OSError): mod.submit('fix',{})
                finally:
                    mod.mkdir=mkdir; mod.write=write; mod.os.rename=rename; mod.sync=sync
                visible=[item for item in mod.OPERATIONS.iterdir() if re.fullmatch('[a-f0-9]{32}',item.name)]
                try: mod.gate(); gate_blocked=False
                except ValueError: gate_blocked=True
                except FileNotFoundError: self.fail('unpublished submission poisoned gate')
                self.assertEqual(calls,[], 'unit was started before durable publication')
                try: mod.resume()
                except (OSError,ValueError): self.fail('unpublished submission poisoned resume')
                # Exercise the actual emitted early files entry point as well as
                # its Python scanner. Only flock is a fake OS facility here.
                helper=case/'usr/local/libexec/dnscomplex-operation'; helper.parent.mkdir(parents=True)
                helper.write_text(self.emitted('OPERATION_HELPER'))
                recovery=case/'restore-recovery'; recovery.write_text(self.emitted('RECOVERY'))
                fakebin=case/'bin'; fakebin.mkdir()
                flock=fakebin/'flock'; flock.write_text(chr(10).join(('#!/bin/sh','exit 0',''))); flock.chmod(0o700)
                env=dict(os.environ,DNSCOMPLEX_FS_ROOT=str(case),DNSCOMPLEX_RESTORE_STATE_DIR=str(mod.RESTORE),DNSCOMPLEX_MAINTENANCE_LOCK=str(mod.LOCK),DNSCOMPLEX_MAINTENANCE_LOCK_HELD='0',PATH=str(fakebin)+os.pathsep+os.environ['PATH'])
                result=subprocess.run(['bash',str(recovery),'--files'],env=env,capture_output=True,text=True)
                self.assertEqual(result.returncode,0,'unpublished submission poisoned boot files: '+result.stderr)
                if point in ('rename-after','publish-fsync'):
                    self.assertEqual(len(visible),1)
                    oid=visible[0].name
                    self.assertTrue(gate_blocked)
                    self.assertEqual(mod.status(oid)['phase'],'rolled-back')
                    self.assertIn(('--no-block','start','dnscomplex-operation@'+oid+'.service'),calls)
                else:
                    self.assertFalse(visible)
                    self.assertFalse(gate_blocked)
                    result=mod.submit('fix',{})
                    self.assertRegex(result['operation_id'],r'^[a-f0-9]{32}$')
                    self.assertEqual(len(list(mod.OPERATIONS.iterdir())),1,'private unpublished stages were not reclaimed under the maintenance lock')

    def test_review_r3_sync_create_stays_hidden_until_manifest_publish(self):
        import shlex
        mod,_,config=self.actual_facilities()
        prefix='source "$1"; shift; '
        result=subprocess.run(['bash','-c',prefix+'state_operation_record_cmd create "$1"','_',str(mod.MANAGER),str(mod.OPERATIONS)],env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        path=Path(result.stdout.strip())
        self.assertTrue(path.name.startswith('.operation-create.'),'sync create exposed a manifestless operation')
        mod.gate(); mod.resume(); mod.boot_sync()
        (path/'backup.tar.gz').write_text('fixture archive')
        result=subprocess.run(['bash','-c',prefix+'state_operation_record_cmd prepare "$1" "config apply" "$2" "$2"','_',str(mod.MANAGER),str(path),str(config)],env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        oid=path.name.removeprefix('.operation-create.')
        directory=mod.OPERATIONS/oid
        self.assertFalse(path.exists())
        self.assertEqual(json.loads((directory/'manifest.json').read_text())['id'],oid)
        mod.resume(); mod.boot_sync()
        self.assertEqual(json.loads((directory/'manifest.json').read_text())['phase'],'rolled-back')
        self.assertFalse((directory/'backup.tar.gz').exists())

    def test_review_r3_unknown_visible_manifestless_record_is_preserved_and_blocks(self):
        mod=self.module(); mod.mkdir(mod.OPERATIONS)
        directory=mod.OPERATIONS/('f'*32); mod.mkdir(directory)
        for scanner in (mod.gate,mod.resume,mod.boot_sync):
            with self.assertRaises((OSError,ValueError)): scanner()
            self.assertTrue(directory.exists())

    def test_diagnostic_timeout_kills_owned_process_group(self):
        web = SOURCE.split("write_file /usr/local/lib/dnscomplex-web/app.py <<'PY'\n",1)[1].split('\nPY\n',1)[0]
        start = web.index('def run(args, timeout=120):')
        end = web.index('\ndef shell_output', start)
        ns = {'subprocess':subprocess,'os':os,'signal':signal,'time':time}
        exec(web[start:end], ns)
        marker = self.root / 'leaked'
        try:
            result = ns['run'](['bash','-c',f'(sleep 1; touch "{marker}") & wait'], .05)
        except subprocess.TimeoutExpired:
            self.fail('diagnostic timeout has no bounded group cleanup')
        self.assertFalse(result['ok'])
        time.sleep(1.1)
        self.assertFalse(marker.exists(), 'diagnostic descendant outlived timeout')

if __name__ == '__main__': unittest.main()
