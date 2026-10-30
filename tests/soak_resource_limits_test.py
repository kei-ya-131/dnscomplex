#!/usr/bin/env python3
"""Runner limits with fake probes/clock and temporary process groups, no DNS load."""
import concurrent.futures
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
SOURCE=(Path(__file__).resolve().parents[1]/'install.sh').read_text()
RUNNER=SOURCE.split("/usr/local/lib/dnscomplex-soak/runner.py <<'PY'\n",1)[1].split('\nPY\n',1)[0]

class Limits(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name)
        self.path=self.root/'runner.py'; self.path.write_text(RUNNER)
        spec=importlib.util.spec_from_file_location('soak_fixture',self.path); self.m=importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
    def test_authoritative_limits_reject_instead_of_clamp(self):
        self.assertTrue(hasattr(self.m,'validate_limits'),'runner has no authoritative bounds')
        for args in [('1s',1,1),('1h',256,100),('3600',50,20)]: self.assertGreaterEqual(self.m.validate_limits(*args),1)
        for args in [('',1,1),('0s',1,1),('3601s',1,1),('1d',1,1),('+1s',1,1),('1.0m',1,1),('1ss',1,1),('9'*10000,1,1),('1s',0,1),('1s',257,1),('1s',1,0),('1s',1,101),('1s',True,1),('1s','1.0',1)]:
            with self.subTest(args=str(args)[:100]),self.assertRaises(ValueError): self.m.validate_limits(*args)
        for args in [['--duration','0s'],['--clients','257'],['--dns-qps','101']]:
            result=subprocess.run([sys.executable,str(self.path),*args],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0); self.assertNotIn('Traceback',result.stderr)
    def test_bounded_pending_reservoir_exact_counts_and_deadline(self):
        self.assertTrue(hasattr(self.m,'run_load'),'runner accumulates all futures until deadline')
        clock=[0.0]; submissions=[]; peak=[0]; pending=set()
        class Future:
            def __init__(self,domain): self.domain=domain; self.ok=len(submissions)%2==0
            def done(self): return False
            def result(self): pending.discard(self); return {'domain':self.domain,'ok':self.ok,'latency_ms':3}
        class Pool:
            def submit(self,fn,domain):
                submissions.append(clock[0]); f=Future(domain); pending.add(f); peak[0]=max(peak[0],len(pending)); return f
        def wait(fs,**kwargs):
            clock[0]+=.00001; return {next(iter(fs))},set(fs)-{next(iter(fs))}
        # Logical clock: 20k requests within 1h while futures stay unfinished until collected.
        def sleep(seconds): clock[0]+=seconds
        with patch.object(self.m.time,'monotonic',lambda:clock[0]),patch.object(self.m.time,'sleep',sleep),patch.object(self.m.concurrent.futures,'wait',wait):
            self.m.health_status=lambda:{'status':'healthy'}
            stats=self.m.run_load(201,1,100,['ai'],['chatgpt.com'],io.StringIO(),Pool())
        self.assertLessEqual(peak[0],256); self.assertGreater(stats['requests'],10000)
        self.assertEqual(stats['successes']+stats['failures'],stats['requests']); self.assertEqual(stats['requests'],len(submissions))
        self.assertLess(max(submissions),201); self.assertEqual(stats['sample_count'],10000); self.assertEqual(stats['percentile_method'],'reservoir_sample_estimate')
        self.assertEqual(len(pending),0); self.assertEqual(stats['successes'],len(submissions)//2); self.assertEqual(stats['failures'],(len(submissions)+1)//2)
    def test_output_collision_preserves_existing_files(self):
        self.assertTrue(hasattr(self.m,'exclusive_outputs'),'summary/log use truncating writes')
        summary=self.root/'result.json'; log=self.root/'result.log'
        for existing in [summary,log]:
            summary.unlink(missing_ok=True); log.unlink(missing_ok=True); existing.write_bytes(b'original')
            with self.assertRaises(FileExistsError):
                with self.m.exclusive_outputs(str(summary)): pass
            self.assertEqual(existing.read_bytes(),b'original')
            self.assertFalse((log if existing==summary else summary).exists())
        summary.unlink(missing_ok=True); log.unlink(missing_ok=True)
        with self.m.exclusive_outputs(str(summary)) as (out,logfile,logpath): out.write('{}'); logfile.write('run')
        self.assertEqual(summary.read_text(),'{}'); self.assertEqual(log.read_text(),'run')
    def test_slow_first_health_zero_probe_run_is_failure_without_extending_deadline(self):
        clock=[0.0]; submissions=[]
        class Pool:
            def submit(self,*args):
                submissions.append(clock[0]); raise AssertionError('probe submitted after deadline')
        def health(): clock[0]+=2; return {'status':'unhealthy'}
        self.m.health_status=health
        with patch.object(self.m.time,'monotonic',lambda:clock[0]):
            stats=self.m.run_load(1,1,1,['ai'],['chatgpt.com'],io.StringIO(),Pool())
            self.assertEqual(submissions,[]); self.assertEqual(clock[0],2)
            for key in ['requests','successes','failures','sample_count']: self.assertEqual(stats[key],0)
            self.assertEqual(stats['health_consecutive_unhealthy_max'],1)
            # Exercise the real main result contract, not only aggregation.
            clock[0]=0; output=io.StringIO(); original=self.m.singleton
            with patch.object(self.m,'singleton',lambda:original(str(self.root/'lock'))), patch.object(self.m.signal,'signal'), \
                 patch.object(self.m.sys,'argv',['runner','--duration','1s','--clients','1','--dns-qps','1','--output-json',str(self.root/'empty.json')]), \
                 patch.object(self.m.sys,'stdout',output):
                code=self.m.main()
            self.assertNotEqual(code,0)
            summary=json.loads(output.getvalue())
            self.assertEqual(summary['error_code'],'NO_PROBES_COMPLETED')
            for key in ['requests','successes','failures','sample_count']: self.assertEqual(summary[key],0)
            self.assertEqual(clock[0],2); self.assertEqual(submissions,[])
    def test_singleton_kernel_lock_releases_after_termination(self):
        self.assertTrue(hasattr(self.m,'singleton'),'no cross-entrypoint singleton')
        lock=self.root/'soak.lock'
        code=RUNNER.split('if __name__ == "__main__":',1)[0]+f'\nwith singleton({str(lock)!r}):\n print("ready",flush=True)\n time.sleep(30)\n'
        child=self.root/'owner.py'; child.write_text(code)
        proc=subprocess.Popen([sys.executable,str(child)],stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(),'ready')
            with self.assertRaises(BlockingIOError):
                with self.m.singleton(str(lock)): self.fail('second owner admitted')
        finally: proc.terminate(); proc.wait(timeout=2); proc.stdout.close()
        with self.m.singleton(str(lock)): pass
    def test_probe_timeout_stops_owned_descendants(self):
        pidfile=self.root/'child.pid'; script=self.root/'hang.py'
        script.write_text('import subprocess,time,sys\np=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"])\nopen(sys.argv[1],"w").write(str(p.pid))\ntime.sleep(30)\n')
        with self.assertRaises(subprocess.TimeoutExpired): self.m.run([sys.executable,str(script),str(pidfile)],.2)
        pid=int(pidfile.read_text())
        # On Linux an unreaped zombie can remain visible; it is no longer running.
        for _ in range(50):
            try:
                os.kill(pid,0)
                stat=Path(f'/proc/{pid}/stat')
                if stat.exists() and stat.read_text().split()[2]=='Z': break
            except ProcessLookupError: break
            time.sleep(.02)
        else: os.kill(pid,signal.SIGKILL); self.fail('owned probe descendant survived timeout')
    def test_main_singleton_precedes_idle_work_and_sigterm_cleans_owned_groups(self):
        bindir=self.root/'bin'; bindir.mkdir(); commands=self.root/'commands'; marker=self.root/'probe.pid'
        manager=bindir/'manager'
        manager.write_text('#!/bin/sh\necho "$*" >>'+str(commands)+"\necho '{\"status\":\"healthy\"}'\n"); manager.chmod(0o700)
        dig=bindir/'dig'
        dig.write_text('#!'+sys.executable+'\nimport subprocess,sys,time,os\np=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"])\nopen('+repr(str(marker))+',"w").write(str(p.pid))\ntime.sleep(30)\n'); dig.chmod(0o700)
        runner=RUNNER.replace('"/run/lock/dnscomplex-soak.lock"',repr(str(self.root/'lock'))).replace('"/usr/local/sbin/dnscomplex"',repr(str(manager)))
        self.path.write_text(runner)
        env=dict(os.environ,PATH=str(bindir)+os.pathsep+os.environ['PATH'])
        args=[sys.executable,str(self.path),'--duration','30s','--clients','1','--dns-qps','100','--output-json',str(self.root/'a.json')]
        proc=subprocess.Popen(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        child=None
        try:
            deadline=time.monotonic()+2
            while not marker.exists() and time.monotonic()<deadline: time.sleep(.01)
            self.assertTrue(marker.exists(),'stub probe was not reached'); child=int(marker.read_text())
            before=commands.read_bytes()
            result=subprocess.run(args[:-1]+[str(self.root/'b.json'),'--idle-resume'],env=env,capture_output=True,text=True,timeout=2)
            self.assertEqual(result.returncode,3,result.stderr); self.assertEqual(commands.read_bytes(),before)
            self.assertFalse((self.root/'b.json').exists())
            proc.terminate(); proc.communicate(timeout=2)
            self.assertNotEqual(proc.returncode,0)
            deadline=time.monotonic()+1
            while time.monotonic()<deadline:
                try:
                    os.kill(child,0)
                    stat=Path(f'/proc/{child}/stat')
                    if stat.exists() and stat.read_text().split()[2]=='Z': break
                except ProcessLookupError: break
                time.sleep(.02)
            else: self.fail('runner termination left owned diagnostic descendant alive')
            dig.write_text('#!/bin/sh\necho 192.0.2.1\n')
            result=subprocess.run([sys.executable,str(self.path),'--duration','1s','--clients','1','--dns-qps','1','--output-json',str(self.root/'c.json')],env=env,capture_output=True,text=True,timeout=3)
            self.assertEqual(result.returncode,0,result.stderr); summary=json.loads(result.stdout)
            self.assertEqual(summary['requests'],1); self.assertEqual(summary['successes'],1)
        finally:
            if proc.poll() is None: proc.kill(); proc.communicate(timeout=2)
            if child:
                try: os.kill(child,signal.SIGKILL)
                except ProcessLookupError: pass
    def test_cli_defaults_match_web_clients_and_no_maintenance_lock(self):
        manager=SOURCE.split("<<'MANAGER'\n",1)[1].split('\nMANAGER\n',1)[0]
        cmd=manager.split('soak_cmd() {',1)[1].split('\n}\n',1)[0]
        self.assertIn('clients=50',cmd); self.assertNotIn('acquire_maintenance_lock',cmd)
        self.assertIn('default=50',RUNNER)

if __name__=='__main__': unittest.main()
