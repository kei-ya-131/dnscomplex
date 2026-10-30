#!/usr/bin/env python3
"""Root-only isolated wire test for sing-box TUN -> Xray SOCKS -> VLESS peers.

Run on a Linux host with sing-box, Xray, iproute2, nftables and curl installed:
  timeout 120 python3 tests/singbox_xray_domain_wire_test.py --config /path/to/rendered-xray-config.json

The production sing-box config and installed Xray renderer are read only. The
test creates all links, routes, nftables state, configs and processes inside a
private network namespace, and uses local Xray VLESS peers with independent
HTTP exits. It does not test any real remote provider.
"""
import argparse
import json
import os
import pathlib
import shlex
import socket
import struct
import secrets
import subprocess
import sys
import tempfile
import time
import uuid

P = argparse.ArgumentParser()
P.add_argument("--config", required=True, type=pathlib.Path, help="sing-box config rendered with both profiles selected as Xray")
P.add_argument("--xray-renderer", default="/usr/local/lib/dnscomplex-xray/render.py", type=pathlib.Path)
P.add_argument("--runtime-script", default="/usr/local/sbin/dnscomplex", type=pathlib.Path)
P.add_argument("--ipv6-underlay", action="store_true")
P.add_argument("--private-underlay", action="store_true")
P.add_argument("--quic-policy", choices=("reject","allow"), default="reject")
P.add_argument("--ai-mark", type=lambda x: int(x, 0), default=769)
P.add_argument("--cn-mark", type=lambda x: int(x, 0), default=849)
P.add_argument("--isolated", action="store_true")
A = P.parse_args()

if not A.isolated:
    cmd = ["unshare", "--net", sys.executable, str(pathlib.Path(__file__).resolve()),
           "--isolated", "--config", str(A.config.resolve()), "--xray-renderer", str(A.xray_renderer.resolve()),
           "--runtime-script", str(A.runtime_script.resolve()), "--ai-mark", str(A.ai_mark), "--cn-mark", str(A.cn_mark), "--quic-policy", A.quic_policy]
    if A.ipv6_underlay: cmd.append("--ipv6-underlay")
    if A.private_underlay: cmd.append("--private-underlay")
    raise SystemExit(subprocess.run(cmd, timeout=112).returncode)

def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=8, **kw)
    if r.returncode:
        raise RuntimeError(f"command failed ({r.returncode}): {cmd!r}\n{r.stderr}")
    return r

def wait_ready(proc, label):
    for _ in range(80):
        if proc.poll() is not None:
            raise RuntimeError(f"{label} exited early: {proc.stderr.read() if proc.stderr else ''}")
        time.sleep(.025)

children = []
try:
    run(["ip", "link", "set", "lo", "up"])
    # Main namespace owns three veth peers. Each peer hosts 192.0.2.10, so all
    # requests use exactly the same destination address while exits differ.
    tags = ("default", "ai", "cn")
    addrs = {"default": "198.18.1", "ai": "10.77.2" if A.private_underlay else "198.18.2", "cn": "10.77.3" if A.private_underlay else "198.18.3"}
    remote6 = {}
    peers = {}
    for idx, tag in enumerate(tags, 1):
        nsproc = subprocess.Popen(["unshare", "--net", "sleep", "115"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children.append(nsproc)
        for _ in range(100):
            if os.readlink(f"/proc/{nsproc.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                break
            time.sleep(.01)
        else:
            raise RuntimeError("could not create peer network namespace")
        nscmd = ["nsenter", "-t", str(nsproc.pid), "-n"]
        left, right = f"x{idx}host", f"x{idx}peer"
        run(["ip", "link", "add", left, "type", "veth", "peer", "name", right])
        run(["ip", "link", "set", right, "netns", str(nsproc.pid)])
        host, remote = addrs[tag] + ".1", addrs[tag] + ".2"
        run(["ip", "addr", "add", host + "/24", "dev", left]); run(["ip", "link", "set", left, "up"])
        run(nscmd + ["ip", "link", "set", "lo", "up"])
        run(nscmd + ["ip", "addr", "add", remote + "/24", "dev", right]); run(nscmd + ["ip", "link", "set", right, "up"])
        run(nscmd + ["ip", "addr", "add", "192.0.2.10/32", "dev", "lo"])
        if tag == "default":
            run(["ip", "route", "add", "default", "via", remote, "dev", left])
        if A.ipv6_underlay and tag != "default":
            host6, dest6 = f"fd00:18:{idx}::1", f"fd00:18:{idx}::2"
            run(["ip", "-6", "addr", "add", host6+"/64", "dev", left, "nodad"])
            run(nscmd+["ip", "-6", "addr", "add", dest6+"/64", "dev", right, "nodad"])
            remote6[tag] = dest6
        peers[tag] = (nsproc, nscmd, host, remote)

    # Per-peer HTTP responders identify the actual exit traversed.
    responder = r'''import socket,sys,threading
body=sys.argv[1].encode()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(("192.0.2.10",443))
def echo():
 while True:
  packet,addr=u.recvfrom(65535);u.sendto(body+b":"+packet,addr)
threading.Thread(target=echo,daemon=True).start()
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("192.0.2.10",19443));s.listen()
while True:
 c,_=s.accept()
 try:
  c.recv(8192);c.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body)
 finally:c.close()
'''
    for tag, (_, ns, _, _) in peers.items():
        p = subprocess.Popen(ns + ["python3", "-u", "-c", responder, tag], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        children.append(p); time.sleep(.05)

    with tempfile.TemporaryDirectory(prefix="dnscomplex-xray-wire-") as td:
        d = pathlib.Path(td)
        ident = str(uuid.uuid4())
        xray_servers={}
        # Real Xray servers in the AI/CN peer namespaces, each forwarding to
        # that namespace's local controlled HTTP endpoint.
        for tag in ("ai", "cn"):
            _, ns, host, remote = peers[tag]
            server_cfg = {"log":{"loglevel":"error"}, "dns":{"hosts":{n+".fixture.test":"192.0.2.10" for n in ("ai","anthropic","support","video","ordinary","weixin","meituan")}},
                          "inbounds":[{"listen":remote6.get(tag,remote),"port":19444,"protocol":"vless","settings":{"clients":[{"id":ident}],"decryption":"none"}}],
                          "outbounds":[{"protocol":"freedom","tag":"out","settings":{"domainStrategy":"UseIP"}}], "routing":{"rules":[]}}
            f = d / f"xray-{tag}-peer.json"; f.write_text(json.dumps(server_cfg))
            run(ns + ["xray", "run", "-test", "-format=json", "-config", str(f)])
            pf = open(d / f"xray-{tag}-peer.log", "w")
            p = subprocess.Popen(ns + ["xray", "run", "-config", str(f)], stdout=pf, stderr=pf, text=True)
            children.append(p); xray_servers[tag]=p; time.sleep(.1)

        actual = json.loads(A.config.read_text())
        selected = {r.get("outbound") for r in actual["route"]["rules"] if r.get("action") == "route"}
        if not {"ai-xray", "cn-xray"}.issubset(selected):
            raise RuntimeError("supplied config must select AI/CN Xray routes; this fixture does not rewrite domain decisions")
        cfg = json.loads(json.dumps(actual))
        cfg["inbounds"] = [next(i for i in cfg["inbounds"] if i.get("type") == "tun"),
                            {"type":"socks","tag":"wire-socks","listen":"127.0.0.1","listen_port":19680}]
        tun = cfg["inbounds"][0]
        tun["route_exclude_address"] = list(tun.get("route_exclude_address", [])) + ["127.0.0.0/8", "198.18.0.0/15", "10.77.0.0/16", "fd00:18::/48"]
        direct = dict(next(o for o in actual["outbounds"] if o.get("tag") == "default"))
        for key in ("bind_interface", "inet4_bind_address", "inet6_bind_address", "routing_mark"):
            direct.pop(key, None)
        cfg["outbounds"] = [direct]
        cfg["outbounds"][0]["tag"] = "default"
        for tag, peer_tag, port in (("ai-xray", "ai", 16054), ("cn-xray", "cn", 16055)):
            cfg["outbounds"].append({"type":"socks","tag":tag,"server":"127.0.0.1","server_port":port,"version":"5"})
        rulesets = []
        for rs, domain in (("geosite-ai-openai","ai.fixture.test"),("geosite-ai-anthropic","anthropic.fixture.test"),
                           ("geosite-ai-support","support.fixture.test"),("geosite-cn-video","video.fixture.test")):
            f=d/(rs+".json"); f.write_text(json.dumps({"version":2,"rules":[{"domain":[domain]}]}))
            rulesets.append({"type":"local","tag":rs,"format":"source","path":str(f)})
        cfg["route"]["rule_set"] = rulesets
        # Preserve the supplied Xray-mode classifier and App UDP policy unchanged.
        cfg["route"]["final"] = "default"

        # Render the real installed sidecar config, overriding only endpoints
        # with the local Xray VLESS fixtures. Thus SOCKS and VLESS are real Xray.
        renderer_env=d/"xray.env"
        renderer_env.write_text(f'AI_EGRESS_MODE="xray"\nCN_EGRESS_MODE="xray"\nAI_MARK="{hex(A.ai_mark)}"\nCN_MARK="{hex(A.cn_mark)}"\nAI_MARK_DEC="{A.ai_mark}"\nCN_MARK_DEC="{A.cn_mark}"\nSINGBOX_AUTO_REDIRECT_INPUT_MARK="0x2023"\nSINGBOX_AUTO_REDIRECT_OUTPUT_MARK="0x2024"\nSINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC="8227"\nSINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC="8228"\n')
        def peer_config(profile):
            dest=remote6.get(profile,peers[profile][3])
            addr=f"[{dest}]" if A.ipv6_underlay else dest
            return json.loads(subprocess.check_output([sys.executable,str(A.xray_renderer),"--config",str(renderer_env),"--profile",profile,"--uri",f"vless://{ident}@{addr}:19444?encryption=none"],text=True))
        xr=peer_config("ai");xr2=peer_config("cn")
        # Renderer output includes both profiles; combine the controlled URI
        # outbounds and retain its production SOCKS inbound/routing contract.
        xr["outbounds"] = [next(o for o in xr["outbounds"] if o["tag"] == "xray-ai-out"),
                            next(o for o in xr2["outbounds"] if o["tag"] == "xray-cn-out")]
        for inbound in xr["inbounds"]: inbound["listen"] = "127.0.0.1"
        xr["log"] = {"loglevel":"debug"}
        xr["inbounds"][0]["port"] = 16054; xr["inbounds"][1]["port"] = 16055
        xray_cfg=d/"xray-sidecar.json";xray_cfg.write_text(json.dumps(xr))
        run(["xray","run","-test","-format=json","-config",str(xray_cfg)])
        xlog=open(d/"xray-sidecar.log","w")
        xp=subprocess.Popen(["xray","run","-config",str(xray_cfg)],stdout=xlog,stderr=xlog,text=True);children.append(xp)

        # Local fixture DNS maps all names to the identical destination IP.
        dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(("127.0.0.1",0));dns.settimeout(.1)
        stop=False
        def dnsloop():
            while not stop:
                try: packet, addr=dns.recvfrom(4096)
                except socket.timeout: continue
                pos=12
                while packet[pos]: pos+=packet[pos]+1
                question=packet[12:pos+5]; qtype=int.from_bytes(packet[pos+1:pos+3],"big")
                ans=b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04"+socket.inet_aton("192.0.2.10") if qtype==1 else b""
                dns.sendto(packet[:2]+b"\x81\x80\x00\x01"+len(ans and [1] or []).to_bytes(2,"big")+b"\x00\x00\x00\x00"+question+ans,addr)
        import threading
        dt=threading.Thread(target=dnsloop,daemon=True);dt.start()
        cfg["dns"]["servers"] = [{"type":"udp","tag":"fixture-dns","server":"127.0.0.1","server_port":dns.getsockname()[1]}]
        cfg["dns"]["rules"] = []
        cfg["dns"]["final"] = "fixture-dns"
        cfg["route"]["default_domain_resolver"] = "fixture-dns"
        cfg["log"]={"level":"debug"}
        conf=d/"sing-box.json";conf.write_text(json.dumps(cfg))
        run(["sing-box","check","-c",str(conf)])
        # Invoke the read-only production Xray profile helper, and preserve the
        # current output-chain statement order around the relevant Xray slice.
        nft=d/"fixture.nft"
        prefix="source "+shlex.quote(str(A.runtime_script))+"; load_config; AI_EGRESS_MODE=xray; CN_EGRESS_MODE=xray; AI_MARK="+hex(A.ai_mark)+"; CN_MARK="+hex(A.cn_mark)+"; AI_MARK_DEC="+str(A.ai_mark)+"; CN_MARK_DEC="+str(A.cn_mark)+"; "
        def runtime(command):
            return subprocess.check_output(["bash","-c",prefix+command],text=True)
        ai_rules=runtime("runtime_nft_output_rules ai ai4 "+hex(A.ai_mark)+" xray reject")
        cn_rules=runtime("runtime_nft_output_rules cn cn4 "+hex(A.cn_mark)+" xray reject")
        transport_rules=runtime("if declare -F runtime_nft_xray_transport_output_rules >/dev/null; then runtime_nft_xray_transport_output_rules ai "+hex(A.ai_mark)+" xray; runtime_nft_xray_transport_output_rules cn "+hex(A.cn_mark)+" xray; fi")
        nft.write_text('''table inet dnscomplex {
 set ai4 { type ipv4_addr; flags interval; }
 set cn4 { type ipv4_addr; flags interval; }
 set ai_ready4 { type ipv4_addr; flags interval; }
 set cn_ready4 { type ipv4_addr; flags interval; }
 set ai_ready6 { type ipv6_addr; flags interval; }
 set cn_ready6 { type ipv6_addr; flags interval; }
 chain output {
  type route hook output priority mangle; policy accept;
'''+transport_rules+'''  ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept
  udp dport { 500, 4500 } accept comment "dnscomplex-ipsec-underlay"
  meta mark 0x2024 counter accept comment "dnscomplex-domain-default-output"
  ip daddr @ai4 ip daddr != @ai_ready4 counter drop comment "dnscomplex-ai-not-ready-output"
  ip daddr @cn4 ip daddr != @cn_ready4 counter drop comment "dnscomplex-cn-not-ready-output"
'''+ai_rules+cn_rules+''' }
}
''')
        run(["nft","-f",str(nft)])
        # Old owned IPv4 IPsec policy rules must not steer Xray socket marks
        # into a dead table. Preserve unreferenced table routes/foreign rules.
        for profile,mark,table,priority in (("ai",A.ai_mark,301,10301),("cn",A.cn_mark,351,10351)):
            run(["ip","rule","add","priority",str(priority),"fwmark",str(mark),"table",str(table)])
            run(["ip","route","add","blackhole","default","table",str(table)])
            runtime("ensure_policy_route_profile "+profile)
            text=run(["ip","rule","show"]).stdout
            assert not any(line.startswith(str(priority)+":") for line in text.splitlines()),"stale IPsec policy rule not removed"
            assert "blackhole default" in run(["ip","route","show","table",str(table)]).stdout,"unowned table route was deleted"
        print("mode-transition: old exact IPv4 policy rules removed; table routes preserved",flush=True)

        # This destination is classified into both profile sets; TCP VLESS
        # transport must still work, demonstrating the narrow Xray gate rules.
        elements = peers["ai"][3] + "," + peers["cn"][3]
        for setname in ("ai4","cn4"): run(["nft","add","element","inet","dnscomplex",setname,"{",elements,"}"])
        log=open(d/"singbox.log","w+")
        sb=subprocess.Popen(["sing-box","run","-c",str(conf)],stdout=log,stderr=log);children.append(sb)
        time.sleep(.5)
        if sb.poll() is not None: log.flush();log.seek(0);raise RuntimeError("sing-box failed: "+log.read())
        # Direct the controlled fixture destination into the real TUN device.
        # auto_redirect is enabled from the production config; this explicit
        # route makes TUN ingress deterministic without claiming to validate
        # the kernel's auto_redirect interception rule itself.
        run(["ip","route","replace","192.0.2.10/32","dev","dnscomplex0"])
        def check(host, want):
            got = observe(host)
            print(f"{host} => {got!r}; expected {want!r}",flush=True)
            assert got==want
        def observe(host):
            r=subprocess.run(["curl","--noproxy","*","--resolve",f"{host}:19443:192.0.2.10","--max-time","1","-sS",f"http://{host}:19443/"],capture_output=True,text=True,timeout=2)
            got=r.stdout if r.returncode==0 else None
            if got is None and r.stderr:
                print(f"{host} failed: {r.stderr.strip()}",flush=True)
            return got
        # Shared underlay VLESS addresses sit in both profile sets. Closed
        # gates must fail closed for AI/CN, while unrelated default traffic
        # must remain on direct egress.
        check("ordinary.fixture.test","default");check("weixin.fixture.test","default");check("meituan.fixture.test","default")
        check("ai.fixture.test",None);check("video.fixture.test",None)
        # Open the real nft readiness sets. Same destination IP proves that
        # the sing-box domain classifier, not destination address, chooses exit.
        runtime("profile_egress_gate_open ai")
        ai_only=observe("ai.fixture.test");cn_closed=observe("video.fixture.test")
        print(f"AI-ready/CN-closed: AI={ai_only!r}, CN={cn_closed!r}",flush=True)
        print("output gate counters (AI-ready/CN-closed):",run(["nft","list","chain","inet","dnscomplex","output"]).stdout,flush=True)
        runtime("profile_egress_gate_clear ai")
        runtime("profile_egress_gate_open cn")
        ai_closed=observe("ai.fixture.test");cn_only=observe("video.fixture.test")
        print(f"AI-closed/CN-ready: AI={ai_closed!r}, CN={cn_only!r}",flush=True)
        print("output gate counters (AI-closed/CN-ready):",run(["nft","list","chain","inet","dnscomplex","output"]).stdout,flush=True)
        runtime("profile_egress_gate_open ai")
        check("ai.fixture.test","ai");check("anthropic.fixture.test","ai");check("support.fixture.test","ai")
        check("video.fixture.test","cn");check("ordinary.fixture.test","default");check("weixin.fixture.test","default");check("meituan.fixture.test","default")
        if (ai_only,cn_closed,ai_closed,cn_only) != ("ai",None,None,"cn"):
            raise AssertionError(
                "cross-profile nft gate interference: with VLESS underlay peer IPs shared in ai4/cn4, "
                f"AI-ready/CN-closed yielded AI={ai_only!r}, CN={cn_closed!r}; "
                f"AI-closed/CN-ready yielded AI={ai_closed!r}, CN={cn_only!r}. "
                "See per-state nft output counters above."
            )
        def recv_exact(sock,n):
            data=b""
            while len(data)<n:
                part=sock.recv(n-len(data));assert part;data+=part
            return data
        def udp_result(host):
            with socket.create_connection(("127.0.0.1",19680),timeout=2) as control:
                control.sendall(b"\x05\x01\x00");assert recv_exact(control,2)==b"\x05\x00"
                control.sendall(b"\x05\x03\x00\x01"+bytes(4)+bytes(2))
                reply=recv_exact(control,4);assert reply[:2]==b"\x05\x00",reply
                if reply[3]==1:addr=socket.inet_ntoa(recv_exact(control,4))
                elif reply[3]==4:addr=socket.inet_ntop(socket.AF_INET6,recv_exact(control,16))
                else:raise AssertionError("unexpected UDP relay address")
                port=struct.unpack("!H",recv_exact(control,2))[0]
                if addr=="0.0.0.0":addr="127.0.0.1"
                nonce=secrets.token_bytes(20);name=host.encode()
                packet=b"\0\0\0\x03"+bytes([len(name)])+name+struct.pack("!H",443)+nonce
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    udp.settimeout(.7);udp.sendto(packet,(addr,port))
                    try:response,_=udp.recvfrom(65535)
                    except socket.timeout:return None
                assert response.endswith(nonce),"wrong UDP nonce"
                for tag in ("default","ai","cn"):
                    if response.endswith(tag.encode()+b":"+nonce):return tag
                raise AssertionError("missing UDP exit marker")
        for host,profile in (("ordinary.fixture.test","default"),("ai.fixture.test","ai"),("video.fixture.test","cn")):
            actual=udp_result(host);expected=profile if profile=="default" or A.quic_policy=="allow" else None
            print(f"App UDP443 {host} => {actual!r}; expected {expected!r}",flush=True)
            assert actual==expected,"App UDP443 profile policy mismatch"
        xray_servers["ai"].terminate();xray_servers["ai"].wait(timeout=2)
        check("ai.fixture.test",None);check("video.fixture.test","cn");check("ordinary.fixture.test","default")
        print("provider-down: selected AI fails without default fallback; CN/default unaffected",flush=True)
        print("wire-parameters:",json.dumps({"ipv6_underlay":A.ipv6_underlay,"private_underlay":A.private_underlay,"ai_mark":A.ai_mark,"cn_mark":A.cn_mark,"quic_policy":A.quic_policy}),flush=True)
        print("PASS: sing-box TUN ingress -> production Xray SOCKS renderer -> actual Xray VLESS peers; same-IP default/AI/CN; actual runtime nft output helpers/order; independent gates; AI/CN-shared underlay set; WeChat/Meituan/default remain default. Controlled local peer only; no provider validation.",flush=True)
        stop=True;dt.join(timeout=.3);dns.close();sb.terminate();sb.wait(timeout=3);log.close()
finally:
    for p in reversed(children):
        if p.poll() is None: p.terminate()
    for p in reversed(children):
        try: p.wait(timeout=2)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
