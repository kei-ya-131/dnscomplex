#!/usr/bin/env python3
"""Bounded isolated test of targeted deletion for a live legacy ct-mark flow.

The old flow is created through the production rules and real sing-box TUN.
Only isolated namespace state is changed. Control conntrack entries are kept
to prove the exact migration selector does not flush unrelated flows.
"""
import argparse
import json
import os
import pathlib
import re
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

p=argparse.ArgumentParser()
p.add_argument('--config',type=pathlib.Path,required=True)
p.add_argument('--nft',type=pathlib.Path,required=True)
p.add_argument('--isolated',action='store_true')
a=p.parse_args()
source_config=json.loads(a.config.read_text())
selected={rule.get('outbound') for rule in source_config.get('route',{}).get('rules',[]) if isinstance(rule,dict) and rule.get('action')=='route'}
if not {'ai-ipsec','cn-ipsec'} <= selected:
 raise SystemExit('transition fixture requires the active dual-IPsec profile selectors')
if not a.isolated:
 cmd=['unshare','--net',sys.executable,str(pathlib.Path(__file__).resolve()),'--isolated','--config',str(a.config.resolve()),'--nft',str(a.nft.resolve())]
 proc=subprocess.Popen(cmd,start_new_session=True)
 try:sys.exit(proc.wait(timeout=110))
 except subprocess.TimeoutExpired:
  os.killpg(proc.pid,signal.SIGTERM)
  try:proc.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
  raise SystemExit('110s bound exceeded; isolated process group terminated')

def run(cmd,timeout=8):
 result=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
 if result.returncode:
  if cmd and cmd[0] in ('nft','conntrack') and result.stderr:
   print(cmd[0]+' stderr:',result.stderr,file=sys.stderr,flush=True)
  raise subprocess.CalledProcessError(result.returncode,cmd,result.stdout,result.stderr)
 return result

peers=[];servers=[];clients=[];captures=[];sb=None;stop=threading.Event()
status_dir=pathlib.Path(tempfile.mkdtemp(prefix='dnscomplex-ct-transition-'))
peer_counts={tag:status_dir/(tag+'.count') for tag in ('default','ai','cn')}
packet_logs={tag:status_dir/(tag+'.packets') for tag in ('default','ai','cn')}
for path in peer_counts.values():path.write_text('0')
for path in packet_logs.values():path.write_text('')
server_code='''import socket,threading,sys
tag=sys.argv[1].encode(); countfile=sys.argv[2]
countlock=threading.Lock()
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",19444));s.listen();print("ready",flush=True)
def handle(c):
 with c:
  buf=b""
  while True:
   while b"\\r\\n\\r\\n" not in buf:
    part=c.recv(4096)
    if not part:return
    buf+=part
   req,buf=buf.split(b"\\r\\n\\r\\n",1)
   peer=c.getpeername()[0]
   with countlock:
    try:n=int(open(countfile).read())
    except (OSError,ValueError):n=0
    with open(countfile,"w") as f:f.write(str(n+1))
   body=tag+b"|"+peer.encode()
   c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: "+str(len(body)).encode()+b"\\r\\nConnection: keep-alive\\r\\n\\r\\n"+body)
while True:
 c,_=s.accept();threading.Thread(target=handle,args=(c,),daemon=True).start()
'''
capture_code='''import socket,struct,sys
iface,path=sys.argv[1],sys.argv[2]
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind((iface,0));s.settimeout(.2);print("ready",flush=True)
while True:
 try:frame=s.recv(65535)
 except socket.timeout:continue
 if len(frame)<54 or frame[12:14]!=b"\\x08\\x00":continue
 ip=frame[14:];ihl=(ip[0]&15)*4
 if ip[9]!=6 or len(ip)<ihl+20:continue
 tcp=ip[ihl:];sport,dport=struct.unpack("!HH",tcp[:4])
 if sport!=19444 and dport!=19444:continue
 doff=(tcp[12]>>4)*4
 if b"ctprobe-transition-7f31" not in tcp[doff:]:continue
 src=socket.inet_ntoa(ip[12:16]);dst=socket.inet_ntoa(ip[16:20])
 with open(path,"a") as f:f.write(f"{src}:{sport}>{dst}:{dport}\\n")
'''
client_code='''import socket,sys
ip,port=sys.argv[1],int(sys.argv[2])
s=socket.create_connection((ip,port),3);s.settimeout(4)
print("PORT "+str(s.getsockname()[1]),flush=True)
def exchange(host):
 s.sendall(("GET /ctprobe-transition-7f31 HTTP/1.1\\r\\nHost: "+host+"\\r\\nConnection: keep-alive\\r\\n\\r\\n").encode())
 b=b""
 while b"\\r\\n\\r\\n" not in b:b+=s.recv(4096)
 h,b=b.split(b"\\r\\n\\r\\n",1);n=int(next(x.split(b":",1)[1] for x in h.split(b"\\r\\n") if x.lower().startswith(b"content-length:")))
 while len(b)<n:b+=s.recv(4096)
 return b[:n].decode()
for host in sys.stdin:
 host=host.strip()
 if host=="QUIT":break
 try:print(exchange(host),flush=True)
 except Exception as e:print("ERROR:"+type(e).__name__,flush=True);break
s.close()
'''

def start_persistent_client(ns,ip,port,host):
 proc=subprocess.Popen(ns+['python3','-u','-c',client_code,ip,str(port)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
 clients.append(proc)
 ready=proc.stdout.readline().strip()
 m=re.fullmatch(r'PORT (\d+)',ready)
 if not m:raise RuntimeError('client socket did not become ready: '+ready[:120])
 sport=int(m.group(1))
 body=request_client(proc,host)
 return proc,sport,body

def request_client(proc,host):
 proc.stdin.write(host+'\n');proc.stdin.flush()
 result=proc.stdout.readline().strip()
 if result.startswith('ERROR:'):return None
 return result

def count_peers():
 out={}
 for tag,path in peer_counts.items():
  try:out[tag]=int(path.read_text())
  except (OSError,ValueError):out[tag]=-1
 return out

def packet_count(tag,src,dst,sport,dport):
 expected=f'{src}:{sport}>{dst}:{dport}'
 try:return sum(1 for line in packet_logs[tag].read_text().splitlines() if line==expected)
 except OSError:return -1

def conntrack_rows(src,dst,sport,dport):
 result=run(['conntrack','-L','-p','tcp','--orig-src',src,'--orig-dst',dst,'--sport',str(sport),'--dport',str(dport),'-o','extended'])
 return [line for line in result.stdout.splitlines() if re.search(r'\bsrc='+re.escape(src)+r'\b',line) and re.search(r'\bdst='+re.escape(dst)+r'\b',line) and re.search(r'\bsport='+str(sport)+r'\b',line) and re.search(r'\bdport='+str(dport)+r'\b',line)]

def ctmark(rows):
 if not rows:return None
 m=re.search(r'\bmark=(\d+)',rows[0])
 return int(m.group(1)) if m else 0

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
  run(ns+['ip','link','set','lo','up']);run(ns+['ip','addr','add','192.0.2.10/32','dev','lo']);run(ns+['ip','addr','add','192.0.2.11/32','dev','lo'])
  run(ns+['ip','addr','add',remote+'/24','dev','peer'+str(n)]);run(ns+['ip','link','set','peer'+str(n),'up'])
  run(['ip','route','add','192.0.2.10/32','via',remote,'dev',iface,'metric',str(n)])
  if vip:
   run(['ip','addr','add',vip+'/32','dev',iface]);run(ns+['ip','route','add',vip+'/32','via',host])
   mark=769 if tag=='ai' else 849;table=301 if tag=='ai' else 351
   run(['ip','rule','add','priority',str(10000+table),'fwmark',str(mark),'lookup',str(table)])
   run(['ip','route','add','default','via',remote,'dev',iface,'table',str(table)])
  else:run(['ip','route','add','default','via',remote,'dev',iface])
  proc=subprocess.Popen(ns+['python3','-u','-c',server_code,tag,str(peer_counts[tag])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);servers.append(proc)
  if proc.stdout.readline().strip()!='ready':raise RuntimeError('peer server failed to start')
  cap=subprocess.Popen(ns+['python3','-u','-c',capture_code,'peer'+str(n),str(packet_logs[tag])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);captures.append(cap)
  if cap.stdout.readline().strip()!='ready':raise RuntimeError('peer packet observer failed to start')
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
 for n,peer in [(2,peers[1]),(3,peers[2])]:run(['nsenter','-t',str(peer.pid),'-n','ip','route','add','198.18.1.0/24','via',f'198.18.{n}.1'])
 run(['nft','-f',str(a.nft)])
 run(['nft','add','element','inet','dnscomplex','ai4','{','192.0.2.10',',','192.0.2.11','}'])
 run(['nft','add','element','inet','dnscomplex','cn4','{','192.0.2.10','}'])
 for profile in ('ai_ready4','cn_ready4'):run(['nft','add','element','inet','dnscomplex',profile,'{','0.0.0.0/0','}'])
 # Controlled local listener proves an unrelated, unmarked LAN conntrack.
 local_listener=socket.socket();local_listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);local_listener.bind(('198.18.1.1',19446));local_listener.listen()
 def local_accept():
  while not stop.is_set():
   try:local_listener.settimeout(.2);c,_=local_listener.accept()
   except socket.timeout:continue
   except OSError:return
   threading.Thread(target=lambda c: (c.recv(4096),c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nlocal')),args=(c,),daemon=True).start()
 threading.Thread(target=local_accept,daemon=True).start()
 dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('127.0.0.1',0));dns.settimeout(.1)
 def dns_server():
  while not stop.is_set():
   try:packet,addr=dns.recvfrom(4096)
   except socket.timeout:continue
   pos=12
   while packet[pos]:pos+=packet[pos]+1
   question=packet[12:pos+5];qt=int.from_bytes(packet[pos+1:pos+3],'big')
   answer=b'\xc0\x0c'+b'\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04'+socket.inet_aton('192.0.2.10') if qt==1 else b''
   dns.sendto(packet[:2]+b'\x81\x80'+b'\x00\x01'+len(answer and [1] or []).to_bytes(2,'big')+b'\x00\x00\x00\x00'+question+answer,addr)
 threading.Thread(target=dns_server,daemon=True).start()
 with tempfile.TemporaryDirectory() as temp:
  temp=pathlib.Path(temp);c=json.loads(a.config.read_text());sets=[]
  for tag,domain in [('geosite-ai-openai','ai.fixture.test'),('geosite-ai-anthropic','anthropic.fixture.test'),('geosite-ai-support','support.fixture.test'),('geosite-cn-video','video.fixture.test')]:
   path=temp/(tag+'.json');path.write_text(json.dumps({'version':2,'rules':[{'domain':[domain]}]}));sets.append({'type':'local','tag':tag,'format':'source','path':str(path)})
  c['route']['rule_set']=sets;c['log']={'level':'debug'}
  for tag,vip in [('ai-ipsec','10.250.1.22'),('cn-ipsec','10.251.1.10')]:next(o for o in c['outbounds'] if o['tag']==tag)['inet4_bind_address']=vip
  c['inbounds']=[next(i for i in c['inbounds'] if i.get('type')=='tun')]
  c['inbounds'][0]['route_exclude_address']+=['127.0.0.0/8','198.18.0.0/15']
  for ds in c['dns']['servers']:ds.update(server='127.0.0.1',server_port=dns.getsockname()[1])
  cfg=temp/'config.json';cfg.write_text(json.dumps(c));run(['sing-box','check','-c',str(cfg)])
  with open(temp/'singbox.log','w+') as log:
   sb=subprocess.Popen(['sing-box','run','-c',str(cfg)],stdout=log,stderr=log);time.sleep(.5)
   if sb.poll() is not None:raise RuntimeError('sing-box failed to start')
   # Baseline production classifier: live CN and AI connections plus controls.
   old_proc,old_sport,old_body=start_persistent_client(client_ns,'192.0.2.10',19444,'video.fixture.test')
   ai_proc,ai_sport,ai_body=start_persistent_client(client_ns,'192.0.2.11',19444,'ai.fixture.test')
   local_proc,local_sport,local_body=start_persistent_client(client_ns,'198.18.1.1',19446,'local.fixture.test')
   print('BASELINE_FLOW cn',old_sport,old_body,'ai',ai_sport,ai_body,'local',local_sport,local_body,flush=True)
   if old_body!='cn|198.18.1.3' or ai_body!='ai|198.18.1.3' or local_body!='local':raise AssertionError('baseline production routing controls did not select their actual kernel paths')
   # A Linux-router-originated connection is a separate control tuple.
   self_sock=socket.create_connection(('192.0.2.10',19444),3);self_sock.sendall(b'GET / HTTP/1.1\r\nHost: video.fixture.test\r\nConnection: keep-alive\r\n\r\n')
   self_sock.settimeout(4);response=b''
   while b'\r\n\r\n' not in response:response+=self_sock.recv(4096)
   head,body=response.split(b'\r\n\r\n',1);length=int(next(x.split(b':',1)[1] for x in head.split(b'\r\n') if x.lower().startswith(b'content-length:')))
   while len(body)<length:body+=self_sock.recv(4096)
   self_sport=self_sock.getsockname()[1];self_src=self_sock.getsockname()[0]
   print('SELF_ORIGIN',self_src,self_sport,body[:length].decode(),flush=True)
   old_rows=conntrack_rows('198.18.1.3','192.0.2.10',old_sport,19444)
   ai_rows=conntrack_rows('198.18.1.3','192.0.2.11',ai_sport,19444)
   local_rows=conntrack_rows('198.18.1.3','198.18.1.1',local_sport,19446)
   self_rows=conntrack_rows(self_src,'192.0.2.10',self_sport,19444)
   print('CONNTRACK_MARKS oldCN',ctmark(old_rows),'otherAI',ctmark(ai_rows),'unmarkedLAN',ctmark(local_rows),'selfOrigin',ctmark(self_rows),flush=True)
   if len(old_rows)!=1 or ctmark(old_rows)!=8228:raise AssertionError('real old CN flow lacks exact conntrack mark 8228')
   if len(ai_rows)!=1 or ctmark(ai_rows)!=8228:raise AssertionError('other live AI control tuple not found with mark 8228')
   if len(local_rows)!=1 or ctmark(local_rows)!=0:raise AssertionError('unmarked LAN control tuple not found')
   if len(self_rows)!=1:raise AssertionError('Linux self-origin control tuple not found')
   before=count_peers();old_packet_before={tag:packet_count(tag,'198.18.1.3','192.0.2.10',old_sport,19444) for tag in packet_logs};print('PEER_COUNTS before-candidate',before,'old-flow-packet-counts',old_packet_before,flush=True)
   # Candidate transition: bypass only profile prerouting/restore policy for
   # TCP/UDP; preserve shared guards and let sing-box retain its own marks.
   pre=run(['nft','-a','list','chain','inet','dnscomplex','prerouting']).stdout
   pre_match=re.search(r'comment "dnscomplex-ai-not-ready" # handle (\d+)',pre)
   restore_text=run(['nft','-a','list','chain','inet','dnscomplex','prerouting_policy_restore']).stdout
   restore_match=re.search(r'comment "dnscomplex-ai-(?:quic-reject-restore|xray-icmp-drop-restore|policy-restore)" # handle (\d+)',restore_text)
   if not pre_match or not restore_match:raise RuntimeError('first profile gate/restore rule comments absent')
   for proto in ('tcp','udp'):
    run(['nft','insert','rule','inet','dnscomplex','prerouting','position',pre_match.group(1),'iifname','ens18','meta','l4proto',proto,'counter','return','comment','legacy-transition-preroute'])
    run(['nft','insert','rule','inet','dnscomplex','prerouting_policy_restore','position',restore_match.group(1),'iifname','ens18','meta','l4proto',proto,'counter','return','comment','legacy-transition-restore'])
   old_proc.stdin.write('video.fixture.test\n');old_proc.stdin.flush();old_after=old_proc.stdout.readline().strip()
   after=count_peers();http_delta={tag:after[tag]-before[tag] for tag in before}
   packet_after={tag:packet_count(tag,'198.18.1.3','192.0.2.10',old_sport,19444) for tag in packet_logs}
   packet_delta={tag:packet_after[tag]-old_packet_before[tag] for tag in packet_after}
   if packet_delta['default']>0:old_outcome='DEFAULT-EXIT-PACKET-OBSERVED (possible legacy flow leak)'
   elif packet_delta['cn']>0:old_outcome='CN-EXIT-PACKET-OBSERVED (legacy flow stayed on CN)'
   elif packet_delta['ai']>0:old_outcome='AI-EXIT-PACKET-OBSERVED (legacy flow switched to AI)'
   else:old_outcome='NO-PEER-PACKET-OBSERVED (route/return outcome unresolved)'
   print('OLD_FLOW_AFTER_CANDIDATE',old_after,'http-server-request-delta',http_delta,'peer-tuple-packet-delta',packet_delta,'classification',old_outcome,flush=True)
   control_sport=65000
   run(['conntrack','-I','-p','tcp','--orig-src','198.18.1.3','--orig-dst','192.0.2.10','--sport',str(control_sport),'--dport','19445','--reply-src','192.0.2.10','--reply-dst','198.18.1.3','--reply-port-src','19445','--reply-port-dst',str(control_sport),'--state','ESTABLISHED','--timeout','600','--mark','849'])
   seeded=conntrack_rows('198.18.1.3','192.0.2.10',control_sport,19445)
   if len(seeded)!=1 or ctmark(seeded)!=849:raise AssertionError('other-mark conntrack control could not be seeded')
   # Exact tuple + mark deletion only. No conntrack table/mark-wide flush.
   predelete=conntrack_rows('198.18.1.3','192.0.2.10',old_sport,19444)
   if len(predelete)!=1 or ctmark(predelete)!=8228:raise AssertionError('old tuple no longer has ct mark 8228 at migration delete point')
   deleted=run(['conntrack','-D','-p','tcp','--orig-src','198.18.1.3','--orig-dst','192.0.2.10','--sport',str(old_sport),'--dport','19444','--mark','8228'])
   print('TARGETED_DELETE rc=0 stdout='+repr(deleted.stdout.strip())+' stderr='+repr(deleted.stderr.strip()),flush=True)
   if conntrack_rows('198.18.1.3','192.0.2.10',old_sport,19444):raise AssertionError('target old conntrack tuple remains after exact delete')
   # Control tuples survive: other profile flow, unmarked LAN flow and router-origin flow.
   if len(conntrack_rows('198.18.1.3','192.0.2.11',ai_sport,19444))!=1:raise AssertionError('targeted delete removed/changed other live AI flow')
   if len(conntrack_rows('198.18.1.3','198.18.1.1',local_sport,19446))!=1:raise AssertionError('targeted delete removed unmarked LAN flow')
   if len(conntrack_rows(self_src,'192.0.2.10',self_sport,19444))!=1:raise AssertionError('targeted delete removed router self-origin flow')
   if len(conntrack_rows('198.18.1.3','192.0.2.10',control_sport,19445))!=1:raise AssertionError('targeted delete removed other-mark control')
   # Reconnect after retiring the old tuple: fresh known-host routing must recover.
   new_proc,new_sport,new_body=start_persistent_client(client_ns,'192.0.2.10',19444,'video.fixture.test')
   if new_sport==old_sport or new_body!='cn|10.251.1.10':raise AssertionError('fresh tuple did not reclassify through CN')
   new_rows=conntrack_rows('198.18.1.3','192.0.2.10',new_sport,19444)
   if len(new_rows)!=1:raise AssertionError('fresh CN conntrack tuple not found')
   print('NEW_FLOW_SELECTED_CN',new_body,'ctmark',ctmark(new_rows),'(no required ctmark; TCP production DNAT path is authoritative)',flush=True)
   log.flush();log.seek(0)
   route_lines=[line for line in log.read().splitlines() if 'video.fixture.test' in line or 'cn-ipsec' in line]
   for line in route_lines[-20:]:print('SB_ROUTE',line[:500],flush=True)
   print('PASS: live legacy flow, exact tuple+mark deletion, surviving controls, and fresh CN reclassification',flush=True)
   print('LIMIT: this proves only isolated targeted conntrack deletion; it does not define a production helper scope or justify deleting all 8228/LAN flows',flush=True)
   print('LIMIT: old-flow post-candidate outcome is reported above; no production mode matrix, concurrency race, or installer migration path is tested',flush=True)
   raise SystemExit(0)
finally:
 stop.set()
 for proc in clients+captures+([sb] if sb else [])+servers+peers:
  if proc.poll() is None:proc.kill()
 for proc in clients+captures+([sb] if sb else [])+servers+peers:
  try:proc.wait(timeout=3)
  except subprocess.TimeoutExpired:proc.kill();proc.wait()
 shutil.rmtree(status_dir,ignore_errors=True)
