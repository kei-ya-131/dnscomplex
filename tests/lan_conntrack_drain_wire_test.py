#!/usr/bin/env python3
"""Bounded isolated test that legacy output-mark sockets drain naturally.

Uses the existing transition fixture topology, preserving marked old TCP/UDP
conntracks rather than deleting them. Fresh tuples still classify through real
sing-box TUN. QUIC uses RFC 9001's controlled example.com golden packet; this
does not establish QUIC application or real-provider success.
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
p.add_argument('--output-mark',type=int,default=8228,help='sing-box auto-redirect conntrack mark')
p.add_argument('--input-mark',type=str,default=None,help='fallback input mark when config has no auto_redirect_input_mark')
p.add_argument('--sniffing-fixture',type=pathlib.Path,default=pathlib.Path(__file__).with_name('xray_sniffing_wire_test.py'),help='source of RFC 9001 Appendix A.2 QUIC Initial bytes')
p.add_argument('--isolated',action='store_true')
a=p.parse_args()

def parse_mark(value):
 if isinstance(value,str):return int(value,0)
 return int(value)

source_config=json.loads(a.config.read_text())
tun_source=next((item for item in source_config.get('inbounds',[]) if item.get('type')=='tun'),{})
input_mark_source='config' if 'auto_redirect_input_mark' in tun_source else ('cli' if a.input_mark is not None else 'fixture-default')
input_mark=parse_mark(tun_source.get('auto_redirect_input_mark',a.input_mark if a.input_mark is not None else 8227))
selected={rule.get('outbound') for rule in source_config.get('route',{}).get('rules',[]) if isinstance(rule,dict) and rule.get('action')=='route'}
if not {'ai-ipsec','cn-ipsec'} <= selected:
 raise SystemExit('transition fixture requires the active dual-IPsec profile selectors')
if not a.isolated:
 cmd=['unshare','--net',sys.executable,str(pathlib.Path(__file__).resolve()),'--isolated','--config',str(a.config.resolve()),'--nft',str(a.nft.resolve()),'--output-mark',str(a.output_mark),'--input-mark',str(input_mark),'--sniffing-fixture',str(a.sniffing_fixture.resolve())]
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
udp_peer_counts={(tag,port):status_dir/(f'{tag}.udp.{port}.count')
                 for tag in ('default','ai','cn') for port in (19445,443)}
packet_logs={tag:status_dir/(tag+'.packets') for tag in ('default','ai','cn')}
for path in list(peer_counts.values())+list(udp_peer_counts.values()):path.write_text('0')
for path in packet_logs.values():path.write_text('')
server_code='''import json,socket,threading,sys
tag=sys.argv[1].encode(); countfile=sys.argv[2]; udp_countfiles=json.loads(sys.argv[3])
countlock=threading.Lock()
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",19444));s.listen()
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
def udp_echo(u,countfile):
 while True:
  data,addr=u.recvfrom(65535)
  with countlock:
   try:n=int(open(countfile).read())
   except (OSError,ValueError):n=0
   with open(countfile,"w") as f:f.write(str(n+1))
  body=tag+b"|"+addr[0].encode()+b"|"+data
  u.sendto(body,addr)
for service_ip in ("192.0.2.10","192.0.2.11"):
 for port in (19445,443):
  u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind((service_ip,port))
  threading.Thread(target=udp_echo,args=(u,udp_countfiles[str(port)]),daemon=True).start()
print("ready",flush=True)
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

udp_client_code='''import socket,sys
ip,port=sys.argv[1],int(sys.argv[2])
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5);s.connect((ip,port))
print("PORT "+str(s.getsockname()[1]),flush=True)
for line in sys.stdin:
 try:
  payload=bytes.fromhex(line.strip());s.send(payload);print(s.recv(65535).hex(),flush=True)
 except Exception as exc:print("ERROR:"+type(exc).__name__,flush=True)
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

def start_udp_client(ns,ip,port):
 proc=subprocess.Popen(ns+['python3','-u','-c',udp_client_code,ip,str(port)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
 clients.append(proc)
 ready=proc.stdout.readline().strip()
 match=re.fullmatch(r'PORT (\d+)',ready)
 if not match:raise RuntimeError('UDP client socket did not become ready: '+ready[:120])
 return proc,int(match.group(1))

def udp_peer_snapshot():
 out={}
 for (tag,port),path in udp_peer_counts.items():
  try:out[f'{tag}:{port}']=int(path.read_text())
  except (OSError,ValueError):out[f'{tag}:{port}']=-1
 return out

def udp_exchange(proc,payload):
 proc.stdin.write(payload.hex()+'\n');proc.stdin.flush()
 result=proc.stdout.readline().strip()
 if result.startswith('ERROR:'):raise RuntimeError('UDP fixture exchange failed: '+result+'; controlled-peer UDP receive counts='+repr(udp_peer_snapshot()))
 try:return bytes.fromhex(result)
 except ValueError as exc:raise RuntimeError('UDP fixture returned malformed hex') from exc

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

def conntrack_rows(src,dst,sport,dport,proto='tcp'):
 result=run(['conntrack','-L','-p',proto,'--orig-src',src,'--orig-dst',dst,'--sport',str(sport),'--dport',str(dport),'-o','extended'])
 return [line for line in result.stdout.splitlines() if re.search(r'\bsrc='+re.escape(src)+r'\b',line) and re.search(r'\bdst='+re.escape(dst)+r'\b',line) and re.search(r'\bsport='+str(sport)+r'\b',line) and re.search(r'\bdport='+str(dport)+r'\b',line)]

def ctmark(rows):
 if not rows:return None
 m=re.search(r'\bmark=(\d+)',rows[0])
 return int(m.group(1)) if m else 0

def load_quic_golden(path):
 source=path.read_text()
 match=re.search(r'(?ms)^RFC9001_CLIENT_INITIAL\s*=\s*bytes\.fromhex\("""(.*?)"""\)',source)
 if not match:raise RuntimeError('sniffing fixture has no RFC9001_CLIENT_INITIAL constant')
 packet=bytes.fromhex(match.group(1))
 if len(packet)!=1200:raise RuntimeError(f'RFC 9001 golden Initial length is {len(packet)}, expected 1200')
 return packet

def self_http_request(sock,host='video.fixture.test'):
 sock.sendall(('GET /ctprobe-transition-7f31 HTTP/1.1\r\nHost: '+host+'\r\nConnection: keep-alive\r\n\r\n').encode())
 sock.settimeout(4);response=b''
 while b'\r\n\r\n' not in response:response+=sock.recv(4096)
 head,body=response.split(b'\r\n\r\n',1)
 length=int(next(x.split(b':',1)[1] for x in head.split(b'\r\n') if x.lower().startswith(b'content-length:')))
 while len(body)<length:body+=sock.recv(4096)
 return body[:length].decode()

quic_initial=load_quic_golden(a.sniffing_fixture)

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
  udp_countfile_args=json.dumps({str(port):str(udp_peer_counts[(tag,port)]) for port in (19445,443)})
  proc=subprocess.Popen(ns+['python3','-u','-c',server_code,tag,str(peer_counts[tag]),udp_countfile_args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);servers.append(proc)
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
 def local_handle(c):
  with c:
   buf=b''
   while not stop.is_set():
    while b'\r\n\r\n' not in buf:
     part=c.recv(4096)
     if not part:return
     buf+=part
    _,buf=buf.split(b'\r\n\r\n',1)
    body=b'local'
    c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n'+body)
 def local_accept():
  while not stop.is_set():
   try:local_listener.settimeout(.2);c,_=local_listener.accept()
   except socket.timeout:continue
   except OSError:return
   threading.Thread(target=local_handle,args=(c,),daemon=True).start()
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
  actual_input_mark=parse_mark(c['inbounds'][0].get('auto_redirect_input_mark',input_mark))
  if actual_input_mark==a.output_mark:
   raise RuntimeError(f'configured input/output marks collide at {actual_input_mark}; fresh and legacy tuples cannot be distinguished')
  print('SING_BOX_AUTO_REDIRECT_MARKS',f'input={actual_input_mark}',f'input_source={input_mark_source}',f'output={a.output_mark}',flush=True)
  c['inbounds'][0]['route_exclude_address']+=['127.0.0.0/8','198.18.0.0/15']
  for ds in c['dns']['servers']:ds.update(server='127.0.0.1',server_port=dns.getsockname()[1])
  cfg=temp/'config.json';cfg.write_text(json.dumps(c));run(['sing-box','check','-c',str(cfg)])
  with open(temp/'singbox.log','w+') as log:
   sb=subprocess.Popen(['sing-box','run','-c',str(cfg)],stdout=log,stderr=log);time.sleep(.5)
   if sb.poll() is not None:raise RuntimeError('sing-box failed to start')
   # Baseline production classifier: live CN and AI connections plus controls.
   old_proc,old_sport,old_body=start_persistent_client(client_ns,'192.0.2.10',19444,'video.fixture.test')
   ai_proc,ai_sport,ai_body=start_persistent_client(client_ns,'192.0.2.11',19444,'ai.fixture.test')
   old_cn_udp,old_cn_udp_sport=start_udp_client(client_ns,'192.0.2.10',19445)
   old_ai_udp,old_ai_udp_sport=start_udp_client(client_ns,'192.0.2.11',19445)
   cn_udp_nonce=b'ctdrain-old-cn-before'
   ai_udp_nonce=b'ctdrain-old-ai-before'
   cn_udp_before=udp_exchange(old_cn_udp,cn_udp_nonce)
   ai_udp_before=udp_exchange(old_ai_udp,ai_udp_nonce)
   local_proc,local_sport,local_body=start_persistent_client(client_ns,'198.18.1.1',19446,'local.fixture.test')
   print('BASELINE_FLOW cn',old_sport,old_body,'ai',ai_sport,ai_body,'cnUDP',old_cn_udp_sport,cn_udp_before,'aiUDP',old_ai_udp_sport,ai_udp_before,'local',local_sport,local_body,flush=True)
   if (old_body!='cn|198.18.1.3' or ai_body!='ai|198.18.1.3' or
       cn_udp_before!=b'cn|198.18.1.3|'+cn_udp_nonce or ai_udp_before!=b'ai|198.18.1.3|'+ai_udp_nonce or
       local_body!='local'):
    raise AssertionError('baseline production routing controls did not select their actual kernel paths')
   # A Linux-router-originated connection is a separate control tuple.
   self_sock=socket.create_connection(('192.0.2.10',19444),3);self_body=self_http_request(self_sock)
   self_sport=self_sock.getsockname()[1];self_src=self_sock.getsockname()[0]
   print('SELF_ORIGIN',self_src,self_sport,self_body,flush=True)
   old_rows=conntrack_rows('198.18.1.3','192.0.2.10',old_sport,19444)
   ai_rows=conntrack_rows('198.18.1.3','192.0.2.11',ai_sport,19444)
   old_cn_udp_rows=conntrack_rows('198.18.1.3','192.0.2.10',old_cn_udp_sport,19445,'udp')
   old_ai_udp_rows=conntrack_rows('198.18.1.3','192.0.2.11',old_ai_udp_sport,19445,'udp')
   local_rows=conntrack_rows('198.18.1.3','198.18.1.1',local_sport,19446)
   self_rows=conntrack_rows(self_src,'192.0.2.10',self_sport,19444)
   print('CONNTRACK_MARKS oldCN',ctmark(old_rows),'oldCN-UDP',ctmark(old_cn_udp_rows),'otherAI',ctmark(ai_rows),'oldAI-UDP',ctmark(old_ai_udp_rows),'unmarkedLAN',ctmark(local_rows),'selfOrigin',ctmark(self_rows),flush=True)
   if len(old_rows)!=1 or ctmark(old_rows)!=a.output_mark:raise AssertionError('real old CN flow lacks configured output conntrack mark')
   if len(ai_rows)!=1 or ctmark(ai_rows)!=a.output_mark:raise AssertionError('other live AI control tuple not found with configured output mark')
   if len(old_cn_udp_rows)!=1 or ctmark(old_cn_udp_rows)!=a.output_mark:raise AssertionError('real old CN UDP flow lacks configured output conntrack mark')
   if len(old_ai_udp_rows)!=1 or ctmark(old_ai_udp_rows)!=a.output_mark:raise AssertionError('real old AI UDP flow lacks configured output conntrack mark')
   if len(local_rows)!=1 or ctmark(local_rows)!=0:raise AssertionError('unmarked LAN control tuple not found')
   if len(self_rows)!=1:raise AssertionError('Linux self-origin control tuple not found')
   before=count_peers()
   old_packet_before={tag:packet_count(tag,'198.18.1.3',dst,sport,19444)
                      for tag,sport,dst in [('cn',old_sport,'192.0.2.10'),('ai',ai_sport,'192.0.2.11')]}
   print('PEER_COUNTS before-candidate',before,'legacy-packet-counts',old_packet_before,flush=True)
   # Preserve all existing profile selectors. Return only fresh TCP/UDP
   # conntracks before profile gates/rules so sing-box can classify by domain;
   # old flows already marked with OUTPUTMARK continue through the old rules.
   pre=run(['nft','-a','list','chain','inet','dnscomplex','prerouting']).stdout
   pre_match=re.search(r'comment "dnscomplex-ai-not-ready" # handle (\d+)',pre)
   restore_text=run(['nft','-a','list','chain','inet','dnscomplex','prerouting_policy_restore']).stdout
   restore_match=re.search(r'comment "dnscomplex-ai-[^" ]+-restore" # handle (\d+)',restore_text)
   if not pre_match or not restore_match:raise RuntimeError('first profile gate/restore rule comments absent')
   for chain,position,comment in [('prerouting',pre_match.group(1),'legacy-drain-fresh-preroute'),
                                  ('prerouting_policy_restore',restore_match.group(1),'legacy-drain-fresh-restore')]:
    run(['nft','insert','rule','inet','dnscomplex',chain,'position',position,
         'iifname','ens18','meta','nfproto','ipv4','meta','l4proto','{','tcp',',','udp','}',
         'ct','mark','!=',str(a.output_mark),'counter','return','comment',comment])
   candidate_pre=run(['nft','-a','list','chain','inet','dnscomplex','prerouting']).stdout
   candidate_restore=run(['nft','-a','list','chain','inet','dnscomplex','prerouting_policy_restore']).stdout
   if candidate_pre.index('legacy-drain-fresh-preroute') > candidate_pre.index('dnscomplex-ai-not-ready'):
    raise AssertionError('fresh-flow prerouting return was not placed before profile gates')
   if candidate_restore.index('legacy-drain-fresh-restore') > candidate_restore.index('dnscomplex-ai-'):
    raise AssertionError('fresh-flow restore return was not placed before profile rules')
   inserted_rules=[line for line in (candidate_pre+candidate_restore).splitlines()
                   if 'legacy-drain-fresh-' in line]
   for line in inserted_rules:print('ISOLATED_RETURN_RULE',line.strip(),flush=True)
   if len(inserted_rules)!=2 or any('ct mark set' in line or 'meta mark set' in line for line in inserted_rules):
    raise AssertionError('fresh-flow exemption rules must not write conntrack or packet marks')
   for line in inserted_rules:
    proto_match=re.search(r'meta l4proto\s*\{([^}]*)\}',line)
    mark_match=re.search(r'\bct mark != (0x[0-9a-fA-F]+|[0-9]+)\b',line)
    if (not re.search(r'\biifname\s+"ens18"(?=\s|$)',line) or
        not re.search(r'\bmeta nfproto ipv4\b',line) or not proto_match or
        set(re.findall(r'\b(?:tcp|udp|icmp)\b',proto_match.group(1)))!={'tcp','udp'} or
        not mark_match or int(mark_match.group(1),16 if mark_match.group(1).lower().startswith('0x') else 10)!=a.output_mark or
        not re.search(r'\breturn\s+comment\s+"legacy-drain-fresh-',line)):
     raise AssertionError('candidate return rule differs from configured interface/family/protocol/mark/action scope')
   def return_counter(chain,comment):
    listing=run(['nft','-a','list','chain','inet','dnscomplex',chain]).stdout
    rule=next((line for line in listing.splitlines() if comment in line),None)
    if rule is None:raise RuntimeError(f'isolated nft return rule disappeared: {comment}')
    counter=re.search(r'counter packets (\d+)',rule)
    if counter is None:raise RuntimeError(f'isolated nft return rule has no packet counter: {comment}')
    value=int(counter.group(1));print('ISOLATED_RETURN_COUNTER',chain,comment,value,rule.strip(),flush=True)
    return value
   baseline_preroute_hits=return_counter('prerouting','legacy-drain-fresh-preroute')
   baseline_restore_hits=return_counter('prerouting_policy_restore','legacy-drain-fresh-restore')
   # Existing established sockets must continue on their original peer and
   # retain their mark/tuple, while LAN and router-origin controls still work.
   for label,proc,sport,host,dst,expected in [('old-CN',old_proc,old_sport,'video.fixture.test','192.0.2.10','cn|198.18.1.3'),
                                               ('old-AI',ai_proc,ai_sport,'ai.fixture.test','192.0.2.11','ai|198.18.1.3')]:
    body=request_client(proc,host)
    rows=conntrack_rows('198.18.1.3',dst,sport,19444)
    if body!=expected:raise AssertionError(f'{label} established socket changed egress or source: {body!r}')
    if len(rows)!=1 or ctmark(rows)!=a.output_mark:raise AssertionError(f'{label} conntrack did not retain configured output mark')
    print('LEGACY_SOCKET_RETAINED',label,'sport',sport,'body',body,'ctmark',ctmark(rows),flush=True)
   for label,proc,sport,dst,nonce in [('old-CN-UDP',old_cn_udp,old_cn_udp_sport,'192.0.2.10',b'ctdrain-old-cn-after'),
                                      ('old-AI-UDP',old_ai_udp,old_ai_udp_sport,'192.0.2.11',b'ctdrain-old-ai-after')]:
    body=udp_exchange(proc,nonce)
    rows=conntrack_rows('198.18.1.3',dst,sport,19445,'udp')
    expected=(('cn' if label=='old-CN-UDP' else 'ai')+'|198.18.1.3|').encode()+nonce
    if body!=expected:raise AssertionError(f'{label} tuple changed peer/source after candidate: {body!r}')
    if len(rows)!=1 or ctmark(rows)!=a.output_mark:raise AssertionError(f'{label} conntrack lost its configured output mark')
    print('LEGACY_UDP_TUPLE_RETAINED',label,'sport',sport,'body',body,'ctmark',ctmark(rows),flush=True)
   old_preroute_hits=return_counter('prerouting','legacy-drain-fresh-preroute')
   old_restore_hits=return_counter('prerouting_policy_restore','legacy-drain-fresh-restore')
   if (old_preroute_hits-baseline_preroute_hits) or (old_restore_hits-baseline_restore_hits):
    raise AssertionError('old OUTPUTMARK TCP/UDP packets incorrectly matched fresh-flow return rules')
   if request_client(local_proc,'local.fixture.test')!='local':raise AssertionError('local LAN control stopped responding')
   self_after=self_http_request(self_sock)
   if self_after!=self_body:raise AssertionError(f'router-origin persistent control changed: {self_after!r} != {self_body!r}')
   print('ROUTER_ORIGIN_RETAINED',self_body,flush=True)
   if len(conntrack_rows('198.18.1.3','198.18.1.1',local_sport,19446))!=1:raise AssertionError('local LAN control conntrack disappeared')
   if len(conntrack_rows(self_src,'192.0.2.10',self_sport,19444))!=1:raise AssertionError('router self-origin control conntrack disappeared')
   for tag,sport,dst in [('cn',old_sport,'192.0.2.10'),('ai',ai_sport,'192.0.2.11')]:
    if packet_count(tag,'198.18.1.3',dst,sport,19444) <= old_packet_before[tag]:
     raise AssertionError(f'legacy {tag} request was not observed on its original peer')
   pre_fresh_preroute_hits=return_counter('prerouting','legacy-drain-fresh-preroute')
   pre_fresh_restore_hits=return_counter('prerouting_policy_restore','legacy-drain-fresh-restore')
   # Re-use one destination in both IP sets. Fresh hostnames must route by the
   # sing-box classifier to default, AI, and CN despite that shared address.
   fresh=[]
   for label,host,expected in [('default','unknown.fixture.test','default|198.18.1.1'),
                               ('AI','ai.fixture.test','ai|10.250.1.22'),
                               ('CN','video.fixture.test','cn|10.251.1.10')]:
    proc,sport,body=start_persistent_client(client_ns,'192.0.2.10',19444,host)
    fresh.append((proc,sport,host))
    if body!=expected:raise AssertionError(f'fresh {label} flow did not use classifier-selected egress: {body!r}')
    rows=conntrack_rows('198.18.1.3','192.0.2.10',sport,19444)
    if len(rows)!=1:raise AssertionError(f'fresh {label} tuple missing from conntrack')
    print('FRESH_SHARED_IP_SELECTED',label,'host',host,'sport',sport,'body',body,'ctmark',ctmark(rows),flush=True)
   fresh_preroute_hits=return_counter('prerouting','legacy-drain-fresh-preroute')
   fresh_restore_hits=return_counter('prerouting_policy_restore','legacy-drain-fresh-restore')
   fresh_preroute_delta=fresh_preroute_hits-pre_fresh_preroute_hits
   fresh_restore_delta=fresh_restore_hits-pre_fresh_restore_hits
   if fresh_preroute_delta < 3:
    raise AssertionError('fresh shared-IP TCP tuples did not hit the prerouting return rule')
   if fresh_restore_delta == 0:
    print('LIMIT: no TCP packet reached the restore return rule in this topology; restore-hook wire behavior remains unverified.',flush=True)
   # A distinct fresh UDP tuple carries the RFC 9001 Appendix A.2 Initial
   # (example.com SNI) to the controlled echo peer. This is a routing probe,
   # not a QUIC handshake or application-success claim.
   quic_client,quic_sport=start_udp_client(client_ns,'192.0.2.10',443)
   quic_reply=udp_exchange(quic_client,quic_initial)
   quic_prefix=b'default|198.18.1.1|'
   if not quic_reply.startswith(quic_prefix) or quic_reply[len(quic_prefix):]!=quic_initial:
    raise AssertionError('RFC 9001 example.com Initial did not reach/return intact from the default controlled UDP peer')
   quic_rows=conntrack_rows('198.18.1.3','192.0.2.10',quic_sport,443,'udp')
   quic_ctmark=ctmark(quic_rows)
   if len(quic_rows)!=1 or quic_ctmark==a.output_mark or quic_ctmark not in (0,actual_input_mark):
    raise AssertionError(f'fresh QUIC UDP tuple mark {quic_ctmark!r} must be zero or configured input mark {actual_input_mark}, and must differ from legacy output mark {a.output_mark}: {quic_rows!r}')
   print('FRESH_QUIC_INITIAL_DEFAULT',f'bytes={len(quic_initial)}',f'sport={quic_sport}',f'ctmark={quic_ctmark}',f'input_mark={actual_input_mark}',f'mark_class={"input-mark" if quic_ctmark==actual_input_mark else "zero"}',f'echo_prefix={quic_reply[:len(quic_prefix)]!r}',f'echo_payload_matches_golden={quic_reply[len(quic_prefix):]==quic_initial}',flush=True)
   quic_preroute_hits=return_counter('prerouting','legacy-drain-fresh-preroute')
   quic_restore_hits=return_counter('prerouting_policy_restore','legacy-drain-fresh-restore')
   quic_preroute_delta=quic_preroute_hits-fresh_preroute_hits
   quic_restore_delta=quic_restore_hits-fresh_restore_hits
   if quic_preroute_delta < 1:raise AssertionError('fresh QUIC Initial did not hit the prerouting ct-mark return rule')
   print('FRESH_QUIC_RETURN_COUNTER_DELTA',f'preroute={quic_preroute_delta}',f'restore={quic_restore_delta}',flush=True)
   # Original old tuple entries are intentionally not deleted; natural drain
   # means they disappear only when sockets close / idle timeout expires.
   for label,sport,dst in [('old-CN',old_sport,'192.0.2.10'),('old-AI',ai_sport,'192.0.2.11')]:
    rows=conntrack_rows('198.18.1.3',dst,sport,19444)
    if len(rows)!=1 or ctmark(rows)!=a.output_mark:raise AssertionError(f'{label} tuple was flushed or changed during candidate test')
   print(f'OLD_CONNTRACKS_RETAINED cn={a.output_mark} ai={a.output_mark}; no conntrack deletion/flush performed',flush=True)
   print('LIMIT: UDP validation covers only preserved controlled echo tuples and RFC 9001 example.com Initial to an echo peer; no actual QUIC handshake/provider or random/no-SNI fallback behavior is claimed.',flush=True)
   log.flush();log.seek(0)
   all_log_lines=log.read().splitlines()
   sniff_lines=[line for line in all_log_lines if 'example.com' in line.lower() and ('sniff' in line.lower() or 'quic' in line.lower())]
   for line in sniff_lines[-10:]:print('SB_QUIC_SNIFF',line[:500],flush=True)
   if not sniff_lines:print('LIMIT: sing-box debug log exposed no explicit example.com/QUIC sniff line; packet echo and nft counters prove wire routing, but not the sniff log event.',flush=True)
   route_lines=[line for line in all_log_lines if 'video.fixture.test' in line or 'cn-ipsec' in line]
   for line in route_lines[-20:]:print('SB_ROUTE',line[:500],flush=True)
   print(f'PASS: legacy TCP/UDP tuples and mark-{a.output_mark} flows remained on original peers; fresh shared-IP TCP selected default/AI/CN; RFC9001 Initial reached controlled default UDP echo with ctmark={quic_ctmark} (configured input mark {actual_input_mark}); TCP return deltas preroute={fresh_preroute_delta}, restore={fresh_restore_delta}',flush=True)
   print('LIMIT: exemption rules are an isolated analogue, not production helper/installer parity; no production conntrack deletion is exercised',flush=True)
   print('LIMIT: production rule generation/order/idempotence, concurrent DNS/set updates, provider/application success, and other modes are unverified',flush=True)
   raise SystemExit(0)
finally:
 stop.set()
 for proc in clients+captures+([sb] if sb else [])+servers+peers:
  if proc.poll() is None:proc.kill()
 for proc in clients+captures+([sb] if sb else [])+servers+peers:
  try:proc.wait(timeout=3)
  except subprocess.TimeoutExpired:proc.kill();proc.wait()
 shutil.rmtree(status_dir,ignore_errors=True)
