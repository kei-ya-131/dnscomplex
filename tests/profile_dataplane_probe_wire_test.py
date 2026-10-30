#!/usr/bin/env python3
"""Controlled Linux TLS/DoH/socket identity wire; no production routes or gates.

The early nft exception is a fixture contract, not the production renderer.
Public resolver IPs exist only inside the private namespaces. No real provider
or DNS upstream is contacted. A private CA verifies real TLS hostname checks.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time


def run(*args):
    return subprocess.run(list(args), check=True, text=True, capture_output=True, timeout=8)


def wait_file(path, process, seconds=6):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError('controlled peer exited before readiness')
        time.sleep(.03)
    raise TimeoutError('controlled peer readiness timeout')


def peer(root):
    (root/'pid').write_text(str(os.getpid()))
    until = time.monotonic() + 15
    while not (root/'configured').exists():
        if time.monotonic() > until:
            raise TimeoutError('peer configure timeout')
        time.sleep(.02)
    def serve(profile, address, hostname):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(root/(profile+'.crt'), root/(profile+'.key'))
        listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, 443)); listener.listen(8); listener.settimeout(.2)
        (root/(profile+'.ready')).write_text('ready')
        while not (root/'stop').exists():
            try:
                raw, remote = listener.accept()
            except socket.timeout:
                continue
            raw.settimeout(3)
            try:
                with ctx.wrap_socket(raw, server_side=True) as connection:
                    received = b''
                    while b'\r\n\r\n' not in received:
                        part = connection.recv(4096)
                        if not part or len(received) > 16384:
                            raise ValueError('invalid request')
                        received += part
                    headers, query = received.split(b'\r\n\r\n', 1)
                    sizes = [int(line.split(b':',1)[1]) for line in headers.split(b'\r\n')
                             if line.lower().startswith(b'content-length:')]
                    if len(sizes) != 1 or not 12 <= sizes[0] <= 4096:
                        raise ValueError('invalid request length')
                    while len(query) < sizes[0]:
                        part = connection.recv(sizes[0]-len(query))
                        if not part: raise ValueError('short query')
                        query += part
                    if len(query) != sizes[0]: raise ValueError('extra query')
                    question = query[12:]
                    response = query[:2] + struct.pack('!HHHHH',0x8180,1,1,0,0) + question
                    response += b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('203.0.113.10')
                    mode_path = root/(profile+'.mode')
                    mode = mode_path.read_text().strip() if mode_path.exists() else 'good'
                    if mode == 'wrong-id': response = bytes([response[0]^1])+response[1:]
                    if mode == 'slow': time.sleep(1.2)
                    connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: '
                                       +str(len(response)).encode()+b'\r\nConnection: close\r\n\r\n'+response)
                    with (root/'peers.jsonl').open('a') as f:
                        f.write(json.dumps({'profile':profile,'source':remote[0],'mode':mode})+'\n')
            except (OSError, ssl.SSLError, ValueError):
                raw.close()
        listener.close()
    def default_server():
        listener=socket.socket(); listener.bind(('198.18.1.2',8443));listener.listen(4);listener.settimeout(.2)
        (root/'default.ready').write_text('ready')
        while not (root/'stop').exists():
            try: connection,_=listener.accept()
            except socket.timeout: continue
            with connection: connection.sendall(b'default-control')
        listener.close()
    threads=[threading.Thread(target=serve,args=('ai','104.16.248.249','cloudflare-dns.com')),
             threading.Thread(target=serve,args=('cn','223.6.6.6','dns.alidns.com')),
             threading.Thread(target=default_server)]
    for t in threads:t.start()
    for t in threads:t.join(timeout=75)


def inner(module_path):
    spec=importlib.util.spec_from_file_location('profile_probe',module_path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix='dnscomplex-profile-doh-wire-') as d:
        root=Path(d); os.chmod(root,0o700)
        for profile,hostname in [('ai','cloudflare-dns.com'),('cn','dns.alidns.com')]:
            run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-subj','/CN='+hostname,'-addext','subjectAltName=DNS:'+hostname,
                '-keyout',str(root/(profile+'.key')),'-out',str(root/(profile+'.crt')))
        process=subprocess.Popen(['unshare','--net','--fork','python3',str(Path(__file__).resolve()),'--peer',str(root)])
        try:
            wait_file(root/'pid',process); pid=(root/'pid').read_text()
            run('ip','link','set','lo','up')
            peer_cmd=['nsenter','-t',pid,'-n']
            run(*peer_cmd,'ip','link','set','lo','up')
            for dev,peerdev,net in [('ipsec-ai','peer-ai','198.18.2'),('ipsec-cn','peer-cn','198.18.3'),('wan0','peer-wan','198.18.1')]:
                run('ip','link','add',dev,'type','veth','peer','name',peerdev)
                run('ip','link','set',peerdev,'netns',pid)
                run('ip','addr','add',net+'.1/30','dev',dev);run('ip','link','set',dev,'up')
                run(*peer_cmd,'ip','addr','add',net+'.2/30','dev',peerdev);run(*peer_cmd,'ip','link','set',peerdev,'up')
            for profile,vip,address,net in [('ai','10.250.1.10','104.16.248.249','198.18.2'),('cn','10.251.1.10','223.6.6.6','198.18.3')]:
                run('ip','addr','add',vip+'/32','dev','lo')
                run('ip','route','add',address+'/32','via',net+'.2','dev','ipsec-'+profile,'src',vip)
                run(*peer_cmd,'ip','addr','add',address+'/32','dev','lo')
                run(*peer_cmd,'ip','route','add',vip+'/32','via',net+'.1','dev','peer-'+profile)
            run('ip','addr','add','10.250.1.11/32','dev','lo')
            run(*peer_cmd,'ip','route','add','10.250.1.11/32','via','198.18.2.1','dev','peer-ai')
            rules='''table inet fixture {
 chain output { type route hook output priority mangle; policy accept;
 meta mark 0xda01 ip saddr 10.250.1.10 oifname "ipsec-ai" ip daddr 104.16.248.249 tcp dport 443 counter meta mark set 769 accept comment "controlled-ai-probe"
 meta mark 0xdc01 ip saddr 10.251.1.10 oifname "ipsec-cn" ip daddr 223.6.6.6 tcp dport 443 counter meta mark set 849 accept comment "controlled-cn-probe"
 oifname { "ipsec-ai", "ipsec-cn" } counter drop comment "controlled-closed-profile-gates"
 }
}'''
            subprocess.run(['nft','-f','-'],input=rules,text=True,check=True,capture_output=True)
            (root/'configured').write_text('ready')
            for profile in ('ai','cn','default'):wait_file(root/(profile+'.ready'),process)
            def invoke(profile='ai',mark=None,vip=None,trust=True,timeout=.7):
                values={'ai':('10.250.1.10',0xda01,'104.16.248.249','cloudflare-dns.com','openai.com'),
                        'cn':('10.251.1.10',0xdc01,'223.6.6.6','dns.alidns.com','youku.com')}[profile]
                address,default_mark,destination,hostname,query=values
                factory=(lambda:ssl.create_default_context(cafile=str(root/(profile+'.crt')))) if trust else ssl.create_default_context
                return module.run_probe(profile,'ipsec',vip or address,'ipsec-'+profile,mark or default_mark,
                                        destination,hostname,query,timeout=timeout,ssl_context_factory=factory,
                                        reserved_marks=(769,849,8228,0x601))
            for profile in ('ai','cn'):
                result=invoke(profile);assert result['status']=='pass',result
                print('CONTROLLED_TLS_DOH',profile,json.dumps(result),flush=True)
            for label,kwargs in [('wrong-identity',{'mark':0xda02}),('wrong-source',{'vip':'10.250.1.11'}),
                                 ('wrong-profile-identity',{'profile':'cn','mark':0xda01})]:
                result=invoke(**kwargs);assert result['status']=='fail' and result['phase']=='connect',result
                assert result['elapsed_ms']<=1200,result
                print('CLOSED_GATE_NEGATIVE',label,json.dumps(result),flush=True)
            result=invoke(trust=False);assert result['status']=='fail' and result['phase']=='tls',result
            print('UNTRUSTED_TLS_NEGATIVE',json.dumps(result),flush=True)
            (root/'ai.mode').write_text('wrong-id')
            result=invoke();assert result['status']=='fail' and result['phase']=='dns',result
            print('DNS_ID_NEGATIVE',json.dumps(result),flush=True)
            (root/'ai.mode').write_text('slow')
            result=invoke(timeout=.4);assert result['status']=='fail' and result['elapsed_ms']<=1000,result
            print('SHARED_DEADLINE_NEGATIVE',json.dumps(result),flush=True)
            (root/'ai.mode').write_text('good')
            with socket.create_connection(('198.18.1.2',8443),1) as control:
                assert control.recv(128)==b'default-control'
            print('DEFAULT_CONTROL_PASS',flush=True)
            records=[json.loads(line) for line in (root/'peers.jsonl').read_text().splitlines()]
            assert any(r['profile']=='ai' and r['source']=='10.250.1.10' and r['mode']=='good' for r in records)
            assert any(r['profile']=='cn' and r['source']=='10.251.1.10' and r['mode']=='good' for r in records)
            counters=json.loads(run('nft','-j','list','table','inet','fixture').stdout)['nftables']
            actual={item['rule']['comment']:sum(e['counter']['packets'] for e in item['rule']['expr'] if 'counter'in e)
                    for item in counters if 'rule'in item and 'comment'in item['rule']}
            assert all(actual.get(name,0)>0 for name in ['controlled-ai-probe','controlled-cn-probe','controlled-closed-profile-gates']),actual
            print('NFT_IDENTITY_COUNTERS',json.dumps(actual),flush=True)
            print('CONTROLLED_PROFILE_DOH_WIRE_PASS; fixture exception only, not production health integration/provider/App proof',flush=True)
        finally:
            (root/'stop').write_text('stop')
            try:process.wait(timeout=4)
            except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=3)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--module',type=Path);parser.add_argument('--inner',action='store_true');parser.add_argument('--peer',type=Path)
    args=parser.parse_args()
    if args.peer:peer(args.peer)
    elif args.inner:inner(args.module)
    else:
        if not args.module:parser.error('--module required')
        result=subprocess.run(['timeout','--kill-after=3','70','unshare','--net','--mount','--propagation','private','--fork',
                               'python3',str(Path(__file__).resolve()),'--inner','--module',str(args.module.resolve())])
        raise SystemExit(result.returncode)
