#!/usr/bin/env python3
"""Installer-emitted HTTP code; only loopback sockets and synthetic local files."""
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SOURCE = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()
def emitted(path):
    return SOURCE.split(path + " <<'PY'\n", 1)[1].split('\nPY\n', 1)[0]

def web_module(root):
    for name, code in [('dnscomplex-config/candidate.py', SOURCE.split("<<'CONFIG_PARSER'\n",1)[1].split('\nCONFIG_PARSER\n',1)[0]),
                       ('dnscomplex-soak/runner.py', emitted('/usr/local/lib/dnscomplex-soak/runner.py')),
                       ('dnscomplex-web/app.py', emitted('/usr/local/lib/dnscomplex-web/app.py'))]:
        path=root/'usr/local/lib'/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(code)
    spec=importlib.util.spec_from_file_location('http_fixture',path); mod=importlib.util.module_from_spec(spec)
    old=list(sys.path)
    try: spec.loader.exec_module(mod)
    finally: sys.path[:]=old
    return mod

class HTTPBounds(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name)
        self.m=web_module(self.root); self.calls=[]
        self.m.parse_config=lambda:{'DNSCOMPLEX_WEB_PASSWORD':'test'}
        self.m.redact_text=lambda value:value
        self.m.run=lambda *args:(self.calls.append(args) or {'ok':True,'output':'ok'})
        self.m.Handler.input_timeout=.2
        server_class=getattr(self.m,'BoundedHTTPServer',self.m.ThreadingHTTPServer)
        self.server=server_class(('127.0.0.1',0),self.m.Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.01},daemon=True); self.thread.start()
        self.addCleanup(self.stop)
    def stop(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)
    def sock(self):
        sock=socket.create_connection(self.server.server_address,timeout=2); self.addCleanup(sock.close); return sock
    def receive(self,sock):
        result=b''
        while True:
            try: data=sock.recv(65536)
            except ConnectionResetError: break  # unread rejected bytes can reset a closed socket
            if not data: break
            result+=data
        return result
    def request(self,headers,body=b'',path='/api/action',eof=False):
        sock=self.sock(); sock.sendall((f'POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46dGVzdA==\r\n'+headers+'\r\n').encode()+body)
        if eof: sock.shutdown(socket.SHUT_WR)
        return self.receive(sock)
    def test_rejects_missing_invalid_duplicate_and_transfer_length_before_cli(self):
        for headers in ['', 'Content-Length: -1\r\n','Content-Length: 1e6\r\n','Content-Length: +2\r\n','Content-Length: 2\r\nContent-Length: 2\r\n','Content-Length: 2\r\nTransfer-Encoding: chunked\r\n']:
            with self.subTest(headers=headers): self.assertIn(b' 400 ',self.request(headers,b'{}'))
        self.assertEqual(self.calls,[])
    def test_rejects_oversize_before_reading_body(self):
        for path,length in [('/login',16385),('/api/action',1048577)]:
            self.assertIn(b' 413 ',self.request(f'Content-Length: {length}\r\n',path=path))
        self.assertEqual(self.calls,[])
    def test_rejects_short_bad_json_and_nonobject(self):
        for body in [b'',b'{',b'[]',b'null',b'1',b'"value"',b'\xff']:
            with self.subTest(body=body): self.assertIn(b' 400 ',self.request(f'Content-Length: {len(body)}\r\n',body))
        self.assertIn(b' 400 ',self.request('Content-Length: 9\r\n',b'{}',eof=True))
        self.assertIn(b' 400 ',self.request('Content-Length: 2\r\nContent-Type: application/json\r\n',b'[]',path='/login'))
        self.assertEqual(self.calls,[])
    def test_json_decoder_resource_limits_are_400_close_without_cli(self):
        bodies=[b'{"value":'+b'1'*4301+b'}', b'{"value":'+b'['*1100+b'0'+b']'*1100+b'}']
        self.assertEqual([len(body) for body in bodies],[4311,2211])
        for path in ['/login','/api/action']:
            for body in bodies:
                with self.subTest(path=path,bytes=len(body)):
                    response=self.request(f'Content-Length: {len(body)}\r\nContent-Type: application/json\r\n',body,path=path)
                    self.assertIn(b' 400 ',response)
                    self.assertEqual(response.count(b'HTTP/1.0'),1)
        self.assertEqual(self.calls,[])
    def test_absolute_header_and_body_deadline(self):
        for initial in [b'POST /log',b'POST /login HTTP/1.1\r\nX-Test: ',b'POST /login HTTP/1.1\r\nContent-Length: 100\r\n\r\n']:
            sock=self.sock(); sock.sendall(initial)
            for _ in range(8):
                time.sleep(.04)
                try: sock.sendall(b'a')
                except OSError: break
            self.assertIn(b' 408 ',self.receive(sock))
        self.assertEqual(self.calls,[])
    def test_valid_long_operation_disarms_input_deadline(self):
        def run(*args): time.sleep(.3); self.calls.append(args); return {'ok':True}
        self.m.run=run
        body=b'{"action":"doctor"}'
        self.assertIn(b' 200 ',self.request(f'Content-Length: {len(body)}\r\n',body)); self.assertEqual(len(self.calls),1)
    def test_auth_and_login_behavior_remains(self):
        body=b'username=admin&password=test'
        self.assertIn(b' 303 ',self.request(f'Content-Length: {len(body)}\r\n',body,path='/login'))
        sock=self.sock(); sock.sendall(b'POST /api/action HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}')
        self.assertIn(b' 401 ',self.receive(sock)); self.assertEqual(self.calls,[])
    def test_soak_web_rejects_outside_limits_before_cli(self):
        for payload in [{'duration':'3601s'},{'clients':257},{'dns_qps':101},{'duration':''},{'clients':True}]:
            body=json.dumps(payload).encode()
            self.assertIn(b' 400 ',self.request(f'Content-Length: {len(body)}\r\n',body,path='/api/ops/soak/run'))
        self.assertEqual(self.calls,[])
    def test_admission_before_worker_and_releases_on_exception(self):
        self.assertTrue(hasattr(self.m,'BoundedHTTPServer'),'HTTP worker admission has no cap')
        entered=[]; release=threading.Event()
        class Block(self.m.BaseHTTPRequestHandler):
            def handle(self):
                entered.append(1); release.wait(2)
                raise ValueError('synthetic handler failure')
        server=self.m.BoundedHTTPServer(('127.0.0.1',0),Block); server.handle_error=lambda *args:None
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True); thread.start()
        sockets=[]
        try:
            for _ in range(16): sockets.append(socket.create_connection(server.server_address,timeout=1))
            deadline=time.monotonic()+1
            while len(entered)<16 and time.monotonic()<deadline: time.sleep(.005)
            extra=socket.create_connection(server.server_address,timeout=1); sockets.append(extra)
            self.assertIn(b' 503 ',extra.recv(1024)); self.assertEqual(len(entered),16)
            release.set()
            # Reacquire all capacity only after every exceptional worker returned.
            for _ in range(16): self.assertTrue(server.slots.acquire(timeout=1))
            for _ in range(16): server.slots.release()
            sockets.append(socket.create_connection(server.server_address,timeout=1))
            deadline=time.monotonic()+1
            while len(entered)<17 and time.monotonic()<deadline: time.sleep(.005)
            self.assertEqual(len(entered),17)
        finally:
            release.set()
            for sock in sockets: sock.close()
            server.shutdown(); server.server_close(); thread.join(2)
    def test_exact_body_boundaries_and_reject_pipelined_unread_body(self):
        body=b'password='+b'x'*(16384-len(b'password='))
        self.assertIn(b' 401 ',self.request(f'Content-Length: {len(body)}\r\n',body,path='/login'))
        body=json.dumps({'action':'doctor','padding':'x'*(1048576-35)},separators=(',',':')).encode()
        self.assertEqual(len(body),1048573)
        body=body[:-2]+b'xxx'+body[-2:]
        self.assertEqual(len(body),1048576)
        self.assertIn(b' 200 ',self.request(f'Content-Length: {len(body)}\r\n',body))
        sock=self.sock()
        sock.sendall(b'POST /login HTTP/1.1\r\nContent-Length: 16385\r\n\r\n'+b'x'*10+b'GET / HTTP/1.1\r\n\r\n')
        response=self.receive(sock)
        self.assertIn(b' 413 ',response); self.assertEqual(response.count(b'HTTP/1.0'),1)
        self.assertEqual(len(self.calls),1)
    def test_thread_start_failure_returns_capacity(self):
        self.assertTrue(hasattr(self.m,'BoundedHTTPServer'))
        with patch.object(self.m.threading.Thread,'start',side_effect=RuntimeError('synthetic start failure')):
            self.server.handle_error=lambda *args:None
            sock=self.sock(); sock.sendall(b'GET /login HTTP/1.0\r\n\r\n')
            self.receive(sock)
        for _ in range(16): self.assertTrue(self.server.slots.acquire(timeout=1))
        for _ in range(16): self.server.slots.release()
    def test_sparse_log_tail_has_fixed_io_and_skips_oversized_partial_lines(self):
        self.assertTrue(hasattr(self.m,'bounded_log_tail'),'web log consumers need bounded tail I/O')
        path=self.root/'querylog'
        with path.open('wb') as fh:
            fh.seek(900*1024*1024); fh.write(b'oversized\nold\nlast\n')
        reads=[]; original=open
        class Reader:
            def __init__(self,fh): self.fh=fh
            def __enter__(self): return self
            def __exit__(self,*args): self.fh.close()
            def seek(self,*args): return self.fh.seek(*args)
            def tell(self): return self.fh.tell()
            def read(self,n=-1): self.assert_bound(n); data=self.fh.read(n); reads.append(len(data)); return data
            def assert_bound(self,n):
                if not 0<=n<=4*1024*1024: raise AssertionError('unbounded read')
        with patch('builtins.open',lambda *args,**kwargs:Reader(original(*args,**kwargs))):
            self.assertEqual(self.m.bounded_log_tail(path,2),['old\n','last\n'])
        self.assertLessEqual(sum(reads),4*1024*1024)
        path.write_bytes(b'normal\n'+b'x'*70000+b'\nlast\n')
        self.assertEqual(self.m.bounded_log_tail(path,10),['normal\n','last\n'])
        self.assertNotIn('readlines()',emitted('/usr/local/lib/dnscomplex-web/app.py'))
        # Real mapping consumer keeps normal JSON records functional after a huge prefix.
        answer=bytes.fromhex('0000818000000001000000000000010001000000000004c0000201')
        record=json.dumps({'QH':'synthetic.example','Answer':self.m.base64.b64encode(answer).decode()})
        with path.open('wb') as fh:
            fh.seek(900*1024*1024); fh.write(('prefix\n'+record+'\n').encode())
        tail=self.m.bounded_log_tail
        self.m.bounded_log_tail=lambda unused,limit:tail(path,limit)
        with patch.object(self.m.os.path,'exists',return_value=True):
            self.assertEqual(self.m.dns_ip_domain_map(),{'192.0.2.1':'synthetic.example'})

if __name__=='__main__': unittest.main()
