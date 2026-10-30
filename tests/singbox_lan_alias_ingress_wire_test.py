#!/usr/bin/env python3
"""Bounded candidate wire test using production nft as an isolated baseline.

The source address below is fixture-only. This does not validate production
address allocation, collision handling, or alias lifecycle.
"""
import argparse,json,os,pathlib,re,signal,shutil,socket,struct,subprocess,sys,tempfile,threading,time
p=argparse.ArgumentParser();p.add_argument('--config',type=pathlib.Path,required=True);p.add_argument('--nft',type=pathlib.Path,required=True);p.add_argument('--sniffing-fixture',type=pathlib.Path,default=pathlib.Path(__file__).with_name('xray_sniffing_wire_test.py'));p.add_argument('--isolated',action='store_true');p.add_argument('--lan-ingress',action='store_true');a=p.parse_args()
if not a.isolated:
 cmd=['unshare','--net',sys.executable,str(pathlib.Path(__file__).resolve()),'--isolated','--config',str(a.config.resolve()),'--nft',str(a.nft.resolve())]
 cmd += ['--sniffing-fixture',str(a.sniffing_fixture.resolve())]
 if a.lan_ingress:cmd.append('--lan-ingress')
 proc=subprocess.Popen(cmd,start_new_session=True)
 try:sys.exit(proc.wait(timeout=110))
 except subprocess.TimeoutExpired:
  os.killpg(proc.pid,signal.SIGTERM)
  try:proc.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
  raise SystemExit('110s bound exceeded; isolated process group terminated')
if not a.lan_ingress:
 raise SystemExit('--lan-ingress is required for this candidate test')
def run(cmd):
 result=subprocess.run(cmd,capture_output=True,text=True,timeout=8)
 if result.returncode:
  if cmd and cmd[0]=='nft' and result.stderr:
   print('nft stderr:',result.stderr,file=sys.stderr,flush=True)
  raise subprocess.CalledProcessError(result.returncode,cmd,result.stdout,result.stderr)
 return result
peers=[];servers=[];sb=None;stop=threading.Event()
udp_hits_dir=pathlib.Path(tempfile.mkdtemp(prefix='dnscomplex-alias-udp-'))
udp_hits={tag:udp_hits_dir/(tag+'.count') for tag in ('default','ai','cn')}
for status_path in udp_hits.values():status_path.write_text('0')
server_code='''import socket,threading,sys
tag=sys.argv[1].encode()
status_path=sys.argv[2]
s=socket.socket();s.bind(("192.0.2.10",19443));s.listen()
def handle(c):
 with c:
  c.recv(8192);body=tag+b"|"+c.getpeername()[0].encode();c.sendall(b"HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Length: "+str(len(body)).encode()+b"\\r\\n\\r\\n"+body)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(("192.0.2.10",443))
def udp():
 while True:
  b,p=u.recvfrom(65535)
  try:count=int(open(status_path).read())
  except (OSError,ValueError):count=0
  with open(status_path,"w") as status:status.write(str(count+1))
  u.sendto(tag+b"|"+p[0].encode()+b"|"+b,p)
threading.Thread(target=udp,daemon=True).start()
print("ready",flush=True)
while True:
 c,_=s.accept();threading.Thread(target=handle,args=(c,),daemon=True).start()
'''
try:
 run(['ip','link','set','lo','up'])
 for n,(tag,iface,vip) in enumerate([('default','ens18',None),('ai','ipsec-ai','10.250.1.22'),('cn','ipsec-cn','10.251.1.10')],1):
  peer=subprocess.Popen(['unshare','--net','sleep','120'],stdout=subprocess.DEVNULL);peers.append(peer)
  for _ in range(100):
   if os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
   time.sleep(.01)
  ns=['nsenter','-t',str(peer.pid),'-n'];host=f'198.18.{n}.1';remote=f'198.18.{n}.2'
  run(['ip','link','add',iface,'type','veth','peer','name','peer'+str(n)])
  run(['ip','link','set','peer'+str(n),'netns',str(peer.pid)])
  run(['ip','addr','add',host+'/24','dev',iface]);run(['ip','link','set',iface,'up'])
  run(ns+['ip','link','set','lo','up']);run(ns+['ip','addr','add','192.0.2.10/32','dev','lo'])
  run(ns+['ip','addr','add',remote+'/24','dev','peer'+str(n)]);run(ns+['ip','link','set','peer'+str(n),'up'])
  run(['ip','route','add','192.0.2.10/32','via',remote,'dev',iface,'metric',str(n)])
  if vip:
   run(['ip','addr','add',vip+'/32','dev',iface]);run(ns+['ip','route','add',vip+'/32','via',host])
   mark=769 if tag=='ai' else 849;table=301 if tag=='ai' else 351
   run(['ip','rule','add','priority',str(10000+table),'fwmark',str(mark),'lookup',str(table)])
   run(['ip','route','add','default','via',remote,'dev',iface,'table',str(table)])
  else:run(['ip','route','add','default','via',remote,'dev',iface])
  proc=subprocess.Popen(ns+['python3','-u','-c',server_code,tag,str(udp_hits[tag])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);servers.append(proc)
  assert proc.stdout.readline().strip()=='ready'
 if a.lan_ingress:
  # Model a LAN client and the default exit on the same bridge as a real
  # single-interface policy router. Do not send through SOCKS or a /32 TUN route.
  run(['sysctl','-qw','net.ipv4.ip_forward=1'])
  run(['ip','addr','del','198.18.1.1/24','dev','ens18'])
  run(['ip','link','set','ens18','name','default-port'])
  run(['ip','link','add','ens18','type','bridge']);run(['ip','link','set','ens18','up'])
  run(['ip','link','set','default-port','master','ens18'])
  run(['ip','addr','add','198.18.1.1/24','dev','ens18'])
  run(['ip','route','replace','192.0.2.10/32','via','198.18.1.2','dev','ens18','metric','1'])
  run(['ip','route','replace','default','via','198.18.1.2','dev','ens18'])
  client=subprocess.Popen(['unshare','--net','sleep','120']);peers.append(client)
  for _ in range(100):
   if os.readlink(f'/proc/{client.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
   time.sleep(.01)
  client_ns=['nsenter','-t',str(client.pid),'-n']
  run(['ip','link','add','client-port','type','veth','peer','name','lan-client'])
  run(['ip','link','set','client-port','master','ens18']);run(['ip','link','set','client-port','up'])
  run(['ip','link','set','lan-client','netns',str(client.pid)])
  run(client_ns+['ip','link','set','lo','up']);run(client_ns+['ip','addr','add','198.18.1.3/24','dev','lan-client'])
  run(client_ns+['ip','link','set','lan-client','up']);run(client_ns+['ip','route','add','default','via','198.18.1.1'])
  for n,peer in [(2,peers[1]),(3,peers[2])]:
   run(['nsenter','-t',str(peer.pid),'-n','ip','route','add','198.18.1.0/24','via',f'198.18.{n}.1'])
 run(['nft','-f',str(a.nft)])
 for profile in ('ai4','cn4'):run(['nft','add','element','inet','dnscomplex',profile,'{','192.0.2.10','}'])
 source_cfg=json.loads(a.config.read_text())
 route_outbounds={r.get('outbound') for r in source_cfg.get('route',{}).get('rules',[]) if isinstance(r,dict) and r.get('action')=='route'}
 if not {'ai-ipsec','cn-ipsec'} <= route_outbounds:
  raise RuntimeError('candidate test requires selected dual-IPsec mode (ai-ipsec and cn-ipsec route selectors)')
 alias='198.18.255.254'
 run(['ip','addr','add',alias+'/32','dev','lo'])
 # Candidate ingress delta: bypass profile IP gates/marks for fresh TCP/UDP
 # and let sing-box's own redirect mark/conntrack machinery handle them.
 # Never pre-write 8228 here: sing-box treats that mark as already redirected.
 # Earlier private/DNS/DoH hard guards remain in front of this insertion.
 pre=run(['nft','-a','list','chain','inet','dnscomplex','prerouting']).stdout
 pre_match=re.search(r'comment "dnscomplex-ai-not-ready" # handle (\d+)',pre)
 restore_text=run(['nft','-a','list','chain','inet','dnscomplex','prerouting_policy_restore']).stdout
 restore_match=re.search(r'comment "dnscomplex-ai-(?:quic-reject-restore|xray-icmp-drop-restore|policy-restore)" # handle (\d+)',restore_text)
 if not pre_match or not restore_match:
  raise RuntimeError('actual dual-IPsec production nft first profile restore rule not found')
 for proto in ('tcp','udp'):
  rule=['iifname','ens18','meta','l4proto',proto,'counter','return','comment','alias-candidate-redirect']
  run(['nft','insert','rule','inet','dnscomplex','prerouting','position',pre_match.group(1)]+rule)
  restore=['iifname','ens18','meta','l4proto',proto,'counter','return','comment','alias-candidate-restore']
  run(['nft','insert','rule','inet','dnscomplex','prerouting_policy_restore','position',restore_match.group(1)]+restore)
 output_text=run(['nft','-a','list','chain','inet','dnscomplex','output']).stdout
 run(['nft','add','chain','inet','dnscomplex','alias_candidate'])
 for profile,mark in (('ai',769),('cn',849)):
  run(['nft','add','rule','inet','dnscomplex','alias_candidate','ip','saddr',alias,'ip','daddr','@'+profile+'4','ip','daddr','!=','@'+profile+'_ready4','counter','drop'])
 for profile in ('ai','cn'):
  if f'dnscomplex-{profile}-quic-reject-output' in output_text:
   run(['nft','add','rule','inet','dnscomplex','alias_candidate','ip','saddr',alias,'ip','daddr','@'+profile+'4','udp','dport','443','counter','reject','with','icmp','type','port-unreachable'])
 for profile,mark in (('ai',769),('cn',849)):
  for proto in ('tcp','udp'):
   run(['nft','add','rule','inet','dnscomplex','alias_candidate','ip','saddr',alias,'ip','daddr','@'+profile+'4','meta','l4proto',proto,'counter','meta','mark','set',str(mark)])
 run(['nft','add','rule','inet','dnscomplex','alias_candidate','return'])
 run(['nft','insert','rule','inet','dnscomplex','output','jump','alias_candidate'])
 for device,vip in (('ipsec-ai','10.250.1.22'),('ipsec-cn','10.251.1.10')):
  run(['nft','add','rule','inet','dnscomplex','postrouting','ip','saddr',alias,'oifname',device,'snat','to',vip])
 run(['nft','add','rule','inet','dnscomplex','postrouting','ip','saddr',alias,'oifname','ens18','snat','to','198.18.1.1'])
 dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('127.0.0.1',0));dns.settimeout(.1)
 def nameserver():
  while not stop.is_set():
   try:packet,peer=dns.recvfrom(4096)
   except socket.timeout:continue
   pos=12
   while packet[pos]:pos+=packet[pos]+1
   question=packet[12:pos+5];qt=struct.unpack('!H',packet[pos+1:pos+3])[0]
   answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('192.0.2.10') if qt==1 else b''
   dns.sendto(packet[:2]+struct.pack('!HHHHH',0x8180,1,bool(answer),0,0)+question+answer,peer)
 threading.Thread(target=nameserver,daemon=True).start()
 with tempfile.TemporaryDirectory() as d:
  d=pathlib.Path(d);c=json.loads(a.config.read_text());sets=[]
  routed_outbounds={r.get('outbound') for r in c['route']['rules'] if isinstance(r,dict) and r.get('action')=='route'}
  if any(profile+'-xray' in routed_outbounds for profile in ('ai','cn')):
   raise RuntimeError('this candidate runner only models the selected dual-IPsec profile mode')
  for tag,domain in [('geosite-ai-openai','ai.fixture.test'),('geosite-ai-anthropic','anthropic.fixture.test'),('geosite-ai-support','support.fixture.test'),('geosite-cn-video','video.fixture.test')]:
   path=d/(tag+'.json');path.write_text(json.dumps({'version':2,'rules':[{'domain':[domain]}]}));sets.append({'type':'local','tag':tag,'format':'source','path':str(path)})
  c['route']['rule_set']=sets;c['log']={'level':'debug'}
  # Supply the virtual IPs created above; fresh dry-run configs have no
  # negotiated VIP, whereas the live config used by this fixture already did.
  for tag,vip in [('ai-ipsec','10.250.1.22'),('cn-ipsec','10.251.1.10')]:
   next(o for o in c['outbounds'] if o['tag']==tag)['inet4_bind_address']=vip
  c['outbounds'].append({'type':'direct','tag':'lan-legacy-alias','inet4_bind_address':alias})
  ipv4_octet=r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
  strict_ipv4=rf'^({ipv4_octet}\.){{3}}{ipv4_octet}$'
  c['route']['rules'] += [
   {'type':'logical','mode':'and','rules':[{'inbound':['tun-in']},{'network':['tcp','udp']},{'domain_regex':['.+']},{'domain_regex':[strict_ipv4],'invert':True}],
    'action':'route','outbound':'default'},
   {'inbound':['tun-in'],'network':['tcp','udp'],'ip_cidr':['0.0.0.0/0'],'action':'route','outbound':'lan-legacy-alias'},
  ]
  c['inbounds']=[next(i for i in c['inbounds'] if i['type']=='tun'),{'type':'socks','tag':'socks-in','listen':'127.0.0.1','listen_port':19680}]
  c['inbounds'][0]['route_exclude_address']+=['127.0.0.0/8','198.18.0.0/15']
  for ds in c['dns']['servers']:ds.update(server='127.0.0.1',server_port=dns.getsockname()[1])
  path=d/'config.json';path.write_text(json.dumps(c));run(['sing-box','check','-c',str(path)])
  with open(d/'log','w+') as log:
   sb=subprocess.Popen(['sing-box','run','-c',str(path)],stdout=log,stderr=log);time.sleep(.5);assert sb.poll() is None
   def check(host,want):
    r=subprocess.run(['curl','--noproxy','','--proxy','socks5h://127.0.0.1:19680','--max-time','2','-sS',f'http://{host}:19443/'],capture_output=True,text=True)
    got=r.stdout if r.returncode==0 else None;print(host,'exit',got,'expected',want,flush=True)
    if got!=want:
     log.flush();log.seek(0);print(log.read());raise AssertionError(r.stderr)
   if a.lan_ingress:
    assert 'ens18' in c['inbounds'][0].get('include_interface',[]),'requires the real ens18 LAN ingress fixture'
    def check_lan(host,want):
     r=subprocess.run(client_ns+['curl','--noproxy','*','--resolve',host+':19443:192.0.2.10','--max-time','2','-sS','http://'+host+':19443/'],capture_output=True,text=True,timeout=3)
     got=r.stdout if r.returncode==0 else None
     print('LAN Host',host,'exit',got,'expected',want,flush=True)
     if got!=want:
      print(run(['nft','list','chain','inet','dnscomplex','prerouting']).stdout,flush=True)
      log.flush();log.seek(0);print(log.read());raise AssertionError(r.stderr)
    def check_raw_no_host(want):
     script='import socket; s=socket.create_connection(("192.0.2.10",19443),2); s.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n"); b=b""; exec("while True:\\n d=s.recv(4096)\\n if not d: break\\n b+=d"); print(b.split(b"\\r\\n\\r\\n",1)[-1].decode())'
     r=subprocess.run(client_ns+['python3','-c',script],capture_output=True,text=True,timeout=3)
     got=r.stdout.strip() if r.returncode==0 else None
     print('LAN raw/no Host exit',got,'expected',want,flush=True)
     assert got==want,r.stderr
    def load_rfc9001_initial():
     # Read the independent published Appendix A.2 golden vector used by the
     # existing controlled Xray wire test; no packet-builder helper is shared.
     source=a.sniffing_fixture.read_text()
     tree=__import__('ast').parse(source)
     assignment=next(n for n in tree.body if isinstance(n,__import__('ast').Assign) and any(isinstance(t,__import__('ast').Name) and t.id=='RFC9001_CLIENT_INITIAL' for t in n.targets))
     call=assignment.value;assert isinstance(call,__import__('ast').Call) and isinstance(call.func,__import__('ast').Attribute) and call.func.attr=='fromhex'
     return bytes.fromhex(call.args[0].value)
    def udp443_failure_diagnostics():
     print('UDP443_DIAGNOSTIC: sing-box route/sniff/error excerpts (bounded, credentials redacted)',flush=True)
     log.flush();log.seek(0)
     lines=log.read().splitlines()
     relevant=[line for line in lines if re.search(r'(?i)(sniff|route|tun-in|udp|error|warn|quic)',line)]
     for line in relevant[-80:]:
      print(re.sub(r'(?i)["\']?(password|passwd|secret|token|private[_-]?key)["\']?\s*[:=]\s*["\']?[^\s,"\']+',r'\1=[REDACTED]',line),flush=True)
     if not relevant:print('SINGBOX_LOG: no matching diagnostic lines',flush=True)
     for chain in ('prerouting','prerouting_policy_restore','output','alias_candidate'):
      try:print(f'NFT_CHAIN {chain}:\n'+run(['nft','-a','list','chain','inet','dnscomplex',chain]).stdout,flush=True)
      except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:print(f'NFT_CHAIN {chain}: unavailable ({exc})',flush=True)
     for tag,status_path in udp_hits.items():
      try:count=status_path.read_text().strip()
      except OSError:count='unavailable'
      print(f'UDP_PEER_RECEIVED tag={tag} count={count}',flush=True)
    def check_lan_udp443(payload,expected_prefix=None,timeout=2):
     script='import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(float(sys.argv[2])); s.sendto(bytes.fromhex(sys.argv[1]),("192.0.2.10",443));\ntry:\n b,_=s.recvfrom(4096); print(b.hex())\nexcept TimeoutError: print("TIMEOUT")'
     r=subprocess.run(client_ns+['python3','-c',script,payload.hex(),str(timeout)],capture_output=True,text=True,timeout=3)
     got=bytes.fromhex(r.stdout.strip()) if r.returncode==0 and r.stdout.strip()!='TIMEOUT' else None
     ok=(got is None) if expected_prefix is None else got is not None and got.startswith(expected_prefix) and got.endswith(payload)
     print('LAN UDP/443', 'response' if got else 'no response', 'expected', expected_prefix.decode(errors='replace') if expected_prefix else 'blocked/no echo',flush=True)
     if not ok:
      if expected_prefix is not None:udp443_failure_diagnostics()
      raise AssertionError(f'UDP/443 echo mismatch: rc={r.returncode}, stderr={r.stderr[:300]!r}')
    # Shared IP is present in both production profile sets. Known Host policy
    # remains selected by sing-box and each profile readiness gate independently.
    check_lan('ordinary.fixture.test','default|198.18.1.1')
    check_lan('unknown.fixture.test','default|198.18.1.1')
    check_lan('ai.fixture.test',None);check_lan('video.fixture.test',None)
    # The RFC 9001 Client Initial carries example.com SNI. This only verifies
    # destination classification and the controlled UDP echo path, not QUIC.
    golden=load_rfc9001_initial()
    check_lan_udp443(golden,b'default|198.18.1.1|')
    run(['nft','add','element','inet','dnscomplex','ai_ready4','{','0.0.0.0/0','}'])
    check_lan('ai.fixture.test','ai|10.250.1.22');check_lan('video.fixture.test',None);check_lan('ordinary.fixture.test','default|198.18.1.1')
    run(['nft','add','element','inet','dnscomplex','cn_ready4','{','0.0.0.0/0','}'])
    check_lan('video.fixture.test','cn|10.251.1.10');check_lan('unknown.fixture.test','default|198.18.1.1')
    # Raw/no-domain alias flows keep legacy IP-hint semantics: both matching
    # gates must be ready and CN wins last when ai4/cn4 overlap.
    check_raw_no_host('cn|10.251.1.10')
    raw_udp443=b'\xc0\x00\x00\x00\x01raw-udp443-no-sni'
    if 'dnscomplex-ai-quic-reject-output' in output_text or 'dnscomplex-cn-quic-reject-output' in output_text:
     check_lan_udp443(raw_udp443,None,timeout=.35)
    run(['nft','flush','set','inet','dnscomplex','ai_ready4'])
    check_raw_no_host(None);check_lan('video.fixture.test','cn|10.251.1.10')
    run(['nft','add','element','inet','dnscomplex','ai_ready4','{','0.0.0.0/0','}'])
    run(['nft','flush','set','inet','dnscomplex','cn_ready4'])
    check_raw_no_host(None);check_lan('ai.fixture.test','ai|10.250.1.22')
    print('PASS: production nft baseline + bounded source-alias LAN candidate; see parity gaps below',flush=True)
    print('PARITY_GAP: fixture alias address collision/fakeIP/route-address lifecycle not validated',flush=True)
    print('PARITY_GAP: alias missing and nft candidate rule installation failure are not simulated',flush=True)
    print('BLOCKER: old established ct-mark 8228 flows across restore-rule replacement are untested; do not deploy until transition is tested',flush=True)
    print('PARITY_GAP: only dual-IPsec fixture mode; Xray/mixed, IPv6, AI/CN SNI UDP443, and arbitrary QUIC application behavior are unverified',flush=True)
    raise SystemExit(0)
finally:
 stop.set()
 for proc in ([sb] if sb else [])+servers+peers:
  if proc.poll() is None:proc.terminate()
 for proc in ([sb] if sb else [])+servers+peers:
  try:proc.wait(timeout=3)
  except subprocess.TimeoutExpired:proc.kill();proc.wait()
 shutil.rmtree(udp_hits_dir,ignore_errors=True)
