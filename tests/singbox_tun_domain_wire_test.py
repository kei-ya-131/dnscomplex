#!/usr/bin/env python3
"""Linux root integration: actual TUN, SOCKS and three independent same-IP exits.

Runs inside unshare --net; peer namespaces use process handles, no host routes,
services or named namespaces are modified. Uses the supplied actual configs.
Optional --lan-ingress exercises raw LAN traffic before sniffing (known RED
regression until the LAN IP-hint/fallback policy is resolved). --lan-open-gates
checks the same ingress with both profile gates open.
"""
import argparse,json,os,pathlib,socket,struct,subprocess,sys,tempfile,threading,time
p=argparse.ArgumentParser();p.add_argument('--config',type=pathlib.Path,required=True);p.add_argument('--nft',type=pathlib.Path,required=True);p.add_argument('--isolated',action='store_true');p.add_argument('--lan-ingress',action='store_true');p.add_argument('--lan-open-gates',action='store_true');a=p.parse_args()
if not a.isolated:
 cmd=['unshare','--net',sys.executable,str(pathlib.Path(__file__).resolve()),'--isolated','--config',str(a.config.resolve()),'--nft',str(a.nft.resolve())]
 if a.lan_ingress:cmd.append('--lan-ingress')
 if a.lan_open_gates:cmd.append('--lan-open-gates')
 sys.exit(subprocess.run(cmd,timeout=110).returncode)
def run(cmd):return subprocess.run(cmd,check=True,capture_output=True,text=True)
peers=[];servers=[];sb=None;stop=threading.Event()
server_code='''import socket,threading,sys
body=sys.argv[1].encode()
s=socket.socket();s.bind(("192.0.2.10",19443));s.listen()
def handle(c):
 with c:
  c.recv(8192);c.sendall(b"HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Length: "+str(len(body)).encode()+b"\\r\\n\\r\\n"+body)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(("192.0.2.10",443))
def udp():
 while True:
  b,p=u.recvfrom(65535);u.sendto(b,p)
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
  proc=subprocess.Popen(ns+['python3','-u','-c',server_code,tag],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);servers.append(proc)
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
 if a.lan_open_gates:
  assert a.lan_ingress,'--lan-open-gates requires --lan-ingress'
  for profile in ('ai_ready4','cn_ready4'):run(['nft','add','element','inet','dnscomplex',profile,'{','0.0.0.0/0','}'])
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
  for tag,domain in [('geosite-ai-openai','ai.fixture.test'),('geosite-ai-anthropic','anthropic.fixture.test'),('geosite-ai-support','support.fixture.test'),('geosite-cn-video','video.fixture.test')]:
   path=d/(tag+'.json');path.write_text(json.dumps({'version':2,'rules':[{'domain':[domain]}]}));sets.append({'type':'local','tag':tag,'format':'source','path':str(path)})
  c['route']['rule_set']=sets;c['log']={'level':'debug'}
  # Supply the virtual IPs created above; fresh dry-run configs have no
  # negotiated VIP, whereas the live config used by this fixture already did.
  for tag,vip in [('ai-ipsec','10.250.1.22'),('cn-ipsec','10.251.1.10')]:
   next(o for o in c['outbounds'] if o['tag']==tag)['inet4_bind_address']=vip
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
    assert 'ens18' in c['inbounds'][0].get('include_interface',[]),'use a routeros-policy config whose actual LAN interface is ens18'
    def check_lan(host,want):
     r=subprocess.run(client_ns+['curl','--noproxy','*','--resolve',host+':19443:192.0.2.10','--max-time','2','-sS','http://'+host+':19443/'],capture_output=True,text=True,timeout=3)
     got=r.stdout if r.returncode==0 else None
     print('raw LAN auto_redirect',host,'exit',got,'expected',want,flush=True)
     if got!=want:
      print(run(['nft','list','chain','inet','dnscomplex','prerouting']).stdout,flush=True)
      log.flush();log.seek(0);print(log.read());raise AssertionError(r.stderr)
    for host,want in [('ordinary.fixture.test','default'),('weixin.fixture.test','default'),('meituan.fixture.test','default'),('ai.fixture.test','ai' if a.lan_open_gates else None),('video.fixture.test','cn' if a.lan_open_gates else None)]:check_lan(host,want)
    print('PASS: raw LAN auto_redirect known-domain profile checks',flush=True)
    raise SystemExit(0)
   check('ordinary.fixture.test','default');check('weixin.fixture.test','default');check('meituan.fixture.test','default');check('192.0.2.10','default')
   check('ai.fixture.test',None);check('video.fixture.test',None)
   run(['nft','add','element','inet','dnscomplex','ai_ready4','{','0.0.0.0/0','}'])
   check('ai.fixture.test','ai');check('video.fixture.test',None);check('ordinary.fixture.test','default')
   run(['nft','add','element','inet','dnscomplex','cn_ready4','{','0.0.0.0/0','}'])
   check('video.fixture.test','cn')
   run(['ip','link','set','ipsec-ai','down'])
   check('ai.fixture.test',None);check('ordinary.fixture.test','default');check('video.fixture.test','cn')
   run(['ip','link','set','ipsec-ai','up']);check('ai.fixture.test','ai')
   run(['ip','addr','del','10.250.1.22/32','dev','ipsec-ai'])
   run(['ip','addr','add','10.250.1.23/32','dev','ipsec-ai'])
   run(['nsenter','-t',str(peers[1].pid),'-n','ip','route','add','10.250.1.23/32','via','198.18.2.1'])
   check('ai.fixture.test',None);check('ordinary.fixture.test','default')
   next(o for o in c['outbounds'] if o['tag']=='ai-ipsec')['inet4_bind_address']='10.250.1.23'
   sb.terminate();sb.wait(timeout=3);path.write_text(json.dumps(c))
   sb=subprocess.Popen(['sing-box','run','-c',str(path)],stdout=log,stderr=log);time.sleep(.5);assert sb.poll() is None
   check('ai.fixture.test','ai');check('video.fixture.test','cn')
   run(['nft','flush','set','inet','dnscomplex','ai_ready4'])
   check('ai.fixture.test',None);check('video.fixture.test','cn');check('ordinary.fixture.test','default')
   def udp443(iface,vip,want):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
     sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,iface.encode()+b'\0')
     sock.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,8228)
     if vip:sock.bind((vip,0))
     sock.settimeout(.5)
     try:sock.sendto(b'fixture',('192.0.2.10',443));ok=sock.recv(512)==b'fixture'
     except OSError:ok=False
     print(iface,'UDP443',ok,'expected',want,flush=True);assert ok==want
   udp443('ens18',None,True)
   udp443('ipsec-ai','10.250.1.23',False)
   udp443('ipsec-cn','10.251.1.10',False)
   # Exercise real SOCKS UDP relay including packets larger than the veth MTU.
   # Distinguishes proxy relay fragmentation from raw SO_MARK-only checks.
   with socket.create_connection(('127.0.0.1',19680),timeout=2) as ctl:
    ctl.sendall(b'\x05\x01\x00');assert ctl.recv(2)==b'\x05\x00'
    ctl.sendall(b'\x05\x03\x00\x01'+socket.inet_aton('127.0.0.1')+b'\x00\x00')
    def exact(n):
     b=b''
     while len(b)<n:
      chunk=ctl.recv(n-len(b));assert chunk;b+=chunk
     return b
    h=exact(4);assert h[:3]==b'\x05\x00\x00'
    if h[3]==1:relay=socket.inet_ntop(socket.AF_INET,exact(4))
    elif h[3]==4:relay=socket.inet_ntop(socket.AF_INET6,exact(16))
    else:raise AssertionError(h)
    port=struct.unpack('!H',exact(2))[0]
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
     u.settimeout(2)
     name=b'ordinary.fixture.test';header=b'\0\0\0\x03'+bytes([len(name)])+name+struct.pack('!H',443)
     for size in (20,1200,1400,2000,5000):
      payload=b'fixture'+b'x'*(size-7);u.sendto(header+payload,(relay,port));reply=u.recv(65535)
      assert reply[-size:]==payload,(size,len(reply));print('SOCKS UDP443 echo bytes',size,'PASS',flush=True)
   print('PASS: real TUN + three same-IP exits + independent readiness + UDP443 policy + SOCKS UDP sizes',flush=True)
finally:
 stop.set()
 for proc in ([sb] if sb else [])+servers+peers:
  proc.terminate()
 for proc in ([sb] if sb else [])+servers+peers:
  try:proc.wait(timeout=3)
  except subprocess.TimeoutExpired:proc.kill();proc.wait()
