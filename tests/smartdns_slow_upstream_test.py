#!/usr/bin/env python3
"""Controlled SmartDNS slow/blackhole upstream isolation; no production mutations."""
import argparse,concurrent.futures,pathlib,shutil,socket,struct,subprocess,tempfile,threading,time,unittest
parser=argparse.ArgumentParser();parser.add_argument('--installer',type=pathlib.Path,required=True);args=parser.parse_args()
source=args.installer.read_text();start=source.index('smartdns_upstream_line() {');end=source.index('\nsmartdns_static_address_line()',start);helper=source[start:end]
def upstream_line(address,group):
 return subprocess.check_output(['bash','-c',helper+'\nsmartdns_upstream_line "$1" "$2"','test',address,group],text=True)
def query(port,label,timeout=2):
 name=label+'.example';wire=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'
 packet=bytes.fromhex('123401000001000000000000')+wire+b'\x00\x01\x00\x01';start=time.monotonic()
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.settimeout(timeout);s.sendto(packet,('127.0.0.1',port));response,_=s.recvfrom(4096)
 assert len(response)>=16 and response[3]&15==0 and struct.unpack('!H',response[6:8])[0]==1
 return socket.inet_ntoa(response[-4:]),time.monotonic()-start
class SlowUpstreamTest(unittest.TestCase):
 @unittest.skipUnless(shutil.which('smartdns'),'SmartDNS binary required; skip is not wire acceptance')
 def test_slow_default_burst_and_blackhole_do_not_block_ai_cn_or_mix_answers(self):
  stop=threading.Event();seen=threading.Event();blackhole=threading.Event();sockets=[];threads=[];requests=[[],[],[]];delayed=[];lock=threading.Lock();proc=None
  def response(sock,client,packet,address,delay):
   if stop.wait(delay):return
   pos=12
   while packet[pos]:pos+=packet[pos]+1
   question=packet[12:pos+5];qtype=struct.unpack('!H',packet[pos+1:pos+3])[0]
   answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton(address) if qtype==1 else b''
   wire=packet[:2]+struct.pack('!HHHHH',0x8180,1,bool(answer),0,0)+question+answer
   try:sock.sendto(wire,client)
   except OSError:
    if not stop.is_set():raise
  def serve(sock,index,address):
   sock.settimeout(.1)
   while not stop.is_set():
    try:packet,client=sock.recvfrom(4096)
    except socket.timeout:continue
    pos=12;labels=[]
    while packet[pos]:n=packet[pos];labels.append(packet[pos+1:pos+1+n].decode());pos+=n+1
    name='.'.join(labels)
    with lock:requests[index].append(name)
    if index==0:
     seen.set()
     if blackhole.is_set():continue
    t=threading.Thread(target=response,args=(sock,client,packet,address,.8 if index==0 else .01),daemon=True)
    delayed.append(t);t.start()
  try:
   for index,address in enumerate(('192.0.2.10','198.51.100.20','203.0.113.30')):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));sockets.append(sock)
    thread=threading.Thread(target=serve,args=(sock,index,address),daemon=True);thread.start();threads.append(thread)
   listeners=[]
   for _ in range(3):
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));listeners.append(sock.getsockname()[1])
   with tempfile.TemporaryDirectory(prefix='dnscomplex-slow-dns-') as d:
    config=pathlib.Path(d)/'smartdns.conf';config.write_text('cache-size 0\ncache-persist no\nspeed-check-mode none\nresponse-mode fastest-response\n'+''.join(f'bind 127.0.0.1:{port} -group {group}\n' for port,group in zip(listeners,('default','ai','cn')))+''.join(upstream_line(f'127.0.0.1:{sock.getsockname()[1]}',group) for sock,group in zip(sockets,('default','ai','cn'))))
    with open(pathlib.Path(d)/'log','w+') as log:
     proc=subprocess.Popen([shutil.which('smartdns'),'-f','-c',str(config),'-p','-'],stdout=log,stderr=log)
     # Readiness queries are profile-local; do not rely on an arbitrary startup delay.
     deadline=time.monotonic()+4
     while True:
      if proc.poll() is not None:log.seek(0);self.fail('isolated process exited: '+log.read())
      try:query(listeners[1],'ready',.1);break
      except socket.timeout:
       if time.monotonic()>deadline:raise
     with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
      seen.clear();pending=[pool.submit(query,listeners[0],f'slow{i}',3) for i in range(6)]
      self.assertTrue(seen.wait(1),'slow upstream never received query')
      for port,answer,label in zip(listeners[1:],('198.51.100.20','203.0.113.30'),('ai-fast','cn-fast')):
       actual,elapsed=query(port,label,.5);self.assertEqual(actual,answer);self.assertLess(elapsed,.5)
      for future in pending:
       actual,elapsed=future.result(timeout=4);self.assertEqual(actual,'192.0.2.10');self.assertGreaterEqual(elapsed,.6);self.assertLess(elapsed,3)
      blackhole.set();seen.clear();missing=pool.submit(query,listeners[0],'missing-default',.7);self.assertTrue(seen.wait(1))
      for port,answer,label in zip(listeners[1:],('198.51.100.20','203.0.113.30'),('ai-with-drop','cn-with-drop')):
       self.assertEqual(query(port,label,.5)[0],answer)
      with self.assertRaises(socket.timeout):missing.result(timeout=2)
      blackhole.clear();self.assertEqual(query(listeners[0],'recovered-default',2)[0],'192.0.2.10')
     with lock:
      self.assertTrue(any(x.startswith('slow') for x in requests[0]));self.assertIn('missing-default.example',requests[0])
      for profile in requests[1:]:self.assertFalse(any(x.startswith(('slow','missing-default','recovered-default')) for x in profile),profile)
  finally:
   stop.set()
   if proc is not None:
    proc.terminate()
    try:proc.wait(timeout=2)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
   for thread in threads+delayed:thread.join(timeout=1)
   for sock in sockets:sock.close()
if __name__=='__main__':unittest.main(argv=[__file__])
