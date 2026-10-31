#!/usr/bin/env python3
"""Real HTTP/process boundaries for the installer-emitted metrics exporter."""
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

SOURCE = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()


class MetricsBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / 'exporter.py'
        marker = "/usr/local/lib/dnscomplex-metrics/exporter.py <<'PY'\n"
        self.path.write_text(SOURCE.split(marker, 1)[1].split('\nPY\n', 1)[0])
        spec = importlib.util.spec_from_file_location('bounded_metrics', self.path)
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.m.DB = str(self.root / 'metrics.sqlite3')
        self.m.SNAPSHOT = str(self.root / 'metrics.json')
        self.m.SAMPLE_LOCK = str(self.root / 'sample.lock')
        self.m.CONFIG = str(self.root / 'config.env')
        self.calls = 0
        self.health = 'healthy'
        # External health/process work is replaced only below the sample boundary.
        self.m.run = self.fake_run

    def fake_run(self, args, timeout=5, **kwargs):
        if args[1:] == ['health', '--json']:
            return subprocess.CompletedProcess(args, 0 if self.health != 'unhealthy' else 1,
                                               json.dumps({'status': self.health, 'profiles': {}}))
        if args[0] == 'dig':
            return subprocess.CompletedProcess(args, 0, ';; Query time: 2 msec\n')
        if args[0] == 'conntrack':
            return subprocess.CompletedProcess(args, 0, 'ipv4 tcp mark=0x301\nipv6 udp mark=0x351\n')
        return subprocess.CompletedProcess(args, 0, '1\n')

    def sample(self):
        self.m.sample()

    def start(self):
        from http.server import ThreadingHTTPServer
        server_type = getattr(self.m, 'BoundedHTTPServer', ThreadingHTTPServer)
        self.server = server_type(('127.0.0.1', 0), self.m.Handler)
        self.errors = []
        self.server.handle_error = lambda *args: self.errors.append(sys.exc_info()[1])
        thread = threading.Thread(target=self.server.serve_forever, daemon=True); thread.start()
        def stop():
            self.server.shutdown(); self.server.server_close(); thread.join(3)
        self.addCleanup(stop)
        self.port = self.server.server_address[1]

    def get(self, path):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(f'http://127.0.0.1:{self.port}' + path, timeout=3) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            with exc: return exc.code, exc.read()

    def test_http_reads_actual_sample_without_collecting(self):
        self.sample()
        def unexpected_collect():
            self.calls += 1
            return {}  # Old handler must not turn this into a successful response.
        self.m.collect = unexpected_collect
        self.start()
        status, body = self.get('/current')
        self.assertEqual(status, 200)
        current = json.loads(body)
        self.assertEqual(current.get('profile_connections_ai'), 1, 'HTTP did not consume the sample product')
        self.assertEqual(current.get('profile_connections_cn'), 1)
        status, body = self.get('/metrics')
        self.assertEqual(status, 200)
        self.assertIn(b'dnscomplex_profile_connections{profile="ai"} 1', body)
        self.assertEqual(self.get('/healthz')[0], 200)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(lambda _: self.get('/current')[0], range(24))), [200] * 24)
        self.assertEqual(self.calls, 0, 'scrapes triggered work')

    def test_missing_stale_corrupt_snapshots_never_report_healthy(self):
        self.start()
        self.assertEqual(self.get('/current')[0], 503)
        self.sample()
        path = Path(self.m.SNAPSHOT)
        self.assertTrue(path.exists(), 'sample did not publish a snapshot')
        good = path.read_text()
        for content in ('{', '[]', good.replace('"healthy"', '"invalid-state"')):
            path.write_text(content)
            self.assertEqual(self.get('/healthz')[0], 503)
        path.write_text(good)
        old = time.time() - 120; os.utime(path, (old, old))
        self.assertEqual(self.get('/healthz')[0], 503)
        self.assertEqual(self.get('/metrics')[0], 503)

    def test_slow_headers_expire_and_slots_are_returned(self):
        self.sample(); self.m.Handler.input_timeout = .25; self.start()
        sock = socket.create_connection(('127.0.0.1', self.port), timeout=2)
        self.addCleanup(sock.close)
        sock.sendall(b'GET /current HTTP/1.1\r\nX-Drip: ')
        began = time.monotonic()
        for _ in range(12):
            try: sock.sendall(b'x')
            except OSError: break
            time.sleep(.04)
        sock.settimeout(1)
        try: response = sock.recv(8192)
        except ConnectionResetError: response = b''
        self.assertLess(time.monotonic() - began, 1)
        self.assertTrue(not response or b'408' in response)
        self.assertEqual(self.get('/current')[0], 200)
        self.assertEqual(self.errors, [], 'normal disconnect caused unhandled server errors')

    def test_orphan_writer_is_terminated_when_parent_exits(self):
        import signal
        spec = importlib.util.spec_from_file_location('orphan_metrics_process', self.path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        pidfile = self.root / 'child.pid'
        code = ('import pathlib,subprocess,sys; '
                'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(10)"]); '
                'pathlib.Path(sys.argv[1]).write_text(str(p.pid))')
        module.run([sys.executable, '-c', code, str(pidfile)], .2)
        pid = int(pidfile.read_text())
        try:
            state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()
            self.assertTrue(not state or state.startswith('Z'), 'child outlived the bounded collection')
        finally:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass

    def test_process_stdout_and_deadline_are_bounded_and_child_exits(self):
        # Use the real implementation, not fake_run, with a real producer.
        spec = importlib.util.spec_from_file_location('real_metrics_process', self.path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        result = module.run([sys.executable, '-c', 'import sys; sys.stdout.write("x" * (16*1024*1024))'], 2)
        self.assertNotEqual(result.returncode, 0, 'unbounded stdout was fully accepted')
        self.assertLessEqual(len(result.stdout.encode()), 8 * 1024 * 1024)
        began = time.monotonic()
        result = module.run([sys.executable, '-c', 'import time; time.sleep(10)'], .15)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - began, 2)

    def test_health_preserves_degraded_success_and_unhealthy_failure(self):
        self.start()
        for state, expected in [('healthy', 200), ('degraded', 200), ('unhealthy', 503)]:
            with self.subTest(state=state):
                self.health = state
                self.sample()
                code, body = self.get('/healthz')
                self.assertEqual(code, expected)
                self.assertEqual(json.loads(body)['status'], state)

    def test_sample_lock_prevents_a_second_process_collecting(self):
        # Hold the exact file lock in a separate process; --sample must only read
        # the prior real sample rather than invoke missing host binaries.
        self.sample()
        ready = self.root / 'lock-ready'
        code = ('import fcntl,os,pathlib,sys,time; '
                'f=open(sys.argv[1],"r+"); fcntl.flock(f,fcntl.LOCK_EX); '
                'pathlib.Path(sys.argv[2]).write_text("ready"); time.sleep(10)')
        holder = subprocess.Popen([sys.executable, '-c', code, self.m.SAMPLE_LOCK, str(ready)])
        self.addCleanup(lambda: holder.poll() is None and holder.kill())
        deadline = time.monotonic() + 2
        while not ready.exists():
            if time.monotonic() >= deadline: self.fail('lock holder did not start')
            time.sleep(.01)
        env = dict(os.environ, DNSCOMPLEX_METRICS_SNAPSHOT=self.m.SNAPSHOT,
                   DNSCOMPLEX_METRICS_SAMPLE_LOCK=self.m.SAMPLE_LOCK,
                   DNSCOMPLEX_MANAGER='/nonexistent-must-not-run')
        try:
            result = subprocess.run([sys.executable, str(self.path), '--sample'], env=env,
                                    capture_output=True, text=True, timeout=2)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['profile_connections_ai'], 1)
        finally:
            holder.terminate(); holder.wait(timeout=2)

    def test_saturated_http_slots_reject_then_recover(self):
        self.sample(); self.m.Handler.input_timeout = 2; self.start()
        sockets = []
        try:
            for _ in range(16):
                sock = socket.create_connection(('127.0.0.1', self.port), timeout=2)
                sock.sendall(b'GET /current HTTP/1.1\r\nX-Wait: '); sockets.append(sock)
            deadline = time.monotonic() + 1
            while self.server.slots._value != 0:
                if time.monotonic() >= deadline: self.fail('requests did not occupy server slots')
                time.sleep(.01)
            self.assertEqual(self.get('/current')[0], 503)
        finally:
            for sock in sockets: sock.close()
        deadline = time.monotonic() + 2
        while self.server.slots._value != 16:
            if time.monotonic() >= deadline: self.fail('slots leaked after disconnect')
            time.sleep(.01)
        self.assertEqual(self.get('/current')[0], 200)


if __name__ == '__main__':
    unittest.main()
