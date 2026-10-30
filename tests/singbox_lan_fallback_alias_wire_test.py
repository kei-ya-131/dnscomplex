#!/usr/bin/env python3
"""Isolated Linux prototype: route unknown TUN IPv4 by a source-alias hint.

This deliberately does not exercise LAN ingress or modify production files.
It asks whether a real sing-box TUN flow can bind a fixture-only source alias,
then let OUTPUT nftables map that metadata to the existing AI/CN/default exits.
All links, routes, nftables state, addresses, and processes live in a private
network namespace. Requires root, sing-box, iproute2, nftables, and curl.
"""
import argparse
import json
import os
import pathlib
import re
import select
import subprocess
import sys
import tempfile
import threading
import time

P = argparse.ArgumentParser()
P.add_argument("--config", required=True, type=pathlib.Path)
P.add_argument("--isolated", action="store_true")
A = P.parse_args()

if not A.isolated:
    command = ["unshare", "--net", sys.executable, str(pathlib.Path(__file__).resolve()),
               "--isolated", "--config", str(A.config.resolve())]
    raise SystemExit(subprocess.run(command, timeout=100).returncode)


def run(command, **kwargs):
    result = subprocess.run(command, check=True, capture_output=True, text=True,
                            timeout=8, **kwargs)
    return result


def wait_ns(process):
    for _ in range(100):
        if os.readlink(f"/proc/{process.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
            return
        time.sleep(.01)
    raise RuntimeError("could not create peer network namespace")


def route_probe(host=None, address="192.0.2.11", port=19443):
    """Send an actual TCP request that enters sing-box's TUN, never a fake mark."""
    import socket
    s = socket.create_connection((address, port), timeout=2)
    request = b"GET / HTTP/1.0\r\n\r\n" if host is None else (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    s.sendall(request)
    chunks = []
    while True:
        data = s.recv(4096)
        if not data:
            break
        chunks.append(data)
    s.close()
    body = b"".join(chunks).split(b"\r\n\r\n", 1)[-1]
    return body.decode(errors="replace")


def socks_probe():
    result = subprocess.run(
        ["curl", "--noproxy", "", "--proxy", "socks5h://127.0.0.1:19680",
         "--max-time", "2", "-sS", "http://192.0.2.10:19443/"],
        capture_output=True, text=True, timeout=3)
    return result.stdout if result.returncode == 0 else None


children = []
server_code = r'''import socket,sys,threading
tag=sys.argv[1]
for address in ("192.0.2.10", "192.0.2.11", "192.0.2.12"):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((address,19443));s.listen()
 def serve(listener):
  while True:
   c,_=listener.accept()
   try:
    request=c.recv(8192)
    body=(tag+"|"+c.getpeername()[0]).encode()
    c.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body)
   finally:c.close()
 threading.Thread(target=serve,args=(s,),daemon=True).start()
print("ready",flush=True)
threading.Event().wait()
'''

try:
    run(["ip", "link", "set", "lo", "up"])
    # The alias exists only inside this namespace. Three peers deliberately
    # answer on identical fixture destination addresses.
    peers = {}
    for idx, tag in enumerate(("default", "ai", "cn"), 1):
        process = subprocess.Popen(["unshare", "--net", "sleep", "100"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children.append(process)
        wait_ns(process)
        ns = ["nsenter", "-t", str(process.pid), "-n"]
        iface = f"alias{idx}"
        host, remote = f"198.18.{idx}.1", f"198.18.{idx}.2"
        run(["ip", "link", "add", iface, "type", "veth", "peer", "name", f"peer{idx}"])
        run(["ip", "link", "set", f"peer{idx}", "netns", str(process.pid)])
        run(["ip", "addr", "add", host + "/24", "dev", iface])
        run(["ip", "link", "set", iface, "up"])
        run(ns + ["ip", "link", "set", "lo", "up"])
        run(ns + ["ip", "addr", "add", "192.0.2.10/32", "dev", "lo"])
        run(ns + ["ip", "addr", "add", "192.0.2.11/32", "dev", "lo"])
        run(ns + ["ip", "addr", "add", "192.0.2.12/32", "dev", "lo"])
        run(ns + ["ip", "addr", "add", remote + "/24", "dev", f"peer{idx}"])
        run(ns + ["ip", "link", "set", f"peer{idx}", "up"])
        run(["ip", "route", "add", "192.0.2.10/32", "via", remote, "dev", iface, "metric", str(idx)])
        run(["ip", "route", "add", "192.0.2.12/32", "via", remote, "dev", iface, "metric", str(idx)])
        run(["ip", "route", "add", "192.0.2.11/32", "via", remote, "dev", iface, "metric", str(idx)])
        if tag == "default":
            run(["ip", "route", "add", "default", "via", remote, "dev", iface])
        else:
            mark, table, vip = (769, 301, "10.250.1.22") if tag == "ai" else (849, 351, "10.251.1.10")
            run(["ip", "addr", "add", vip + "/32", "dev", iface])
            run(ns + ["ip", "route", "add", vip + "/32", "via", host])
            run(["ip", "rule", "add", "priority", str(9000 + table), "fwmark", str(mark), "lookup", str(table)])
            run(["ip", "route", "add", "default", "via", remote, "dev", iface, "table", str(table)])
        proc = subprocess.Popen(ns + ["python3", "-u", "-c", server_code, tag],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children.append(proc)
        ready, _, _ = select.select([proc.stdout], [], [], 2)
        if not ready or proc.stdout.readline().strip() != "ready":
            raise RuntimeError(f"{tag} responder did not start")
        peers[tag] = (process, ns, iface, host, remote)

    run(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
    run(["ip", "addr", "add", "198.18.255.254/32", "dev", "lo"])
    # Existing table routes are local stand-ins for the two profile underlays.
    nft = r'''table inet alias_probe {
 set ai4 { type ipv4_addr; flags interval; elements = { 192.0.2.10, 192.0.2.12 } }
 set cn4 { type ipv4_addr; flags interval; elements = { 192.0.2.10, 192.0.2.12 } }
 set ai_ready4 { type ipv4_addr; flags interval; }
 set cn_ready4 { type ipv4_addr; flags interval; }
 chain legacyhint {
  ip daddr @ai4 ip daddr != @ai_ready4 drop
  ip daddr @cn4 ip daddr != @cn_ready4 drop
  ip daddr @ai4 udp dport 443 reject with icmp type admin-prohibited
  ip daddr @cn4 udp dport 443 reject with icmp type admin-prohibited
  ip daddr @ai4 meta mark set 769
  ip daddr @cn4 meta mark set 849
  return
 }
 chain output {
  type route hook output priority -151; policy accept;
  ip saddr 198.18.255.254 ip daddr 192.0.2.10 counter
  ip saddr 198.18.255.254 ip daddr 192.0.2.11 counter
  ip saddr 198.18.255.254 ip daddr 192.0.2.12 counter
  ip saddr 198.18.255.254 counter jump legacyhint
  ip saddr 10.250.1.22 ip daddr != @ai_ready4 drop
  ip saddr 10.251.1.10 ip daddr != @cn_ready4 drop
 }
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr 198.18.255.254 oifname "alias2" snat to 10.250.1.22
  ip saddr 198.18.255.254 oifname "alias3" snat to 10.251.1.10
  ip saddr 198.18.255.254 oifname "alias1" snat to 198.18.1.1
 }
}'''
    with tempfile.TemporaryDirectory(prefix="dnscomplex-alias-probe-") as temp:
        d = pathlib.Path(temp)
        nft_path = d / "alias.nft"
        nft_path.write_text(nft)
        run(["nft", "-f", str(nft_path)])
        actual = json.loads(A.config.read_text())
        cfg = json.loads(json.dumps(actual))
        tun = next(i for i in cfg["inbounds"] if i.get("type") == "tun")
        tun["route_exclude_address"] = list(tun.get("route_exclude_address", [])) + [
            "127.0.0.0/8", "198.18.0.0/15", "192.0.2.0/24"]
        cfg["inbounds"] = [tun, {"type": "socks", "tag": "probe-socks", "listen": "127.0.0.1", "listen_port": 19680}]
        output_mark = tun.get("auto_redirect_output_mark", 8228)
        output_mark = int(output_mark, 0) if isinstance(output_mark, str) else int(output_mark)
        run(["ip", "route", "add", "default", "via", peers["default"][4], "dev", peers["default"][2], "table", "200"])
        # Sing-box's output mark bypasses the fixture ingress route. Preserve
        # bound profile sources on their own fixture underlays, then send every
        # other marked direct socket through the normal default peer. If the
        # alias classifier's mark is overwritten, the AI/CN assertion fails.
        for priority, source, table in ((50, "10.250.1.22/32", "301"),
                                        (51, "10.251.1.10/32", "351")):
            run(["ip", "rule", "add", "priority", str(priority), "from", source,
                 "fwmark", str(output_mark), "lookup", table])
        run(["ip", "rule", "add", "priority", "52", "fwmark", str(output_mark), "lookup", "200"])
        alias = {"type": "direct", "tag": "legacy-hint", "inet4_bind_address": "198.18.255.254"}
        cfg["outbounds"] = [o for o in cfg["outbounds"] if o.get("tag") not in ("ai-ipsec", "cn-ipsec", "ai-xray", "cn-xray")]
        cfg["outbounds"].append(alias)
        # In the fixture, profile direct outbounds model the existing routing
        # marks and underlay VIPs. No alias mark or interface binding is used.
        for tag, mark, vip in (("ai-ipsec", 769, "10.250.1.22"), ("cn-ipsec", 849, "10.251.1.10")):
            profile = next((o for o in actual["outbounds"] if o.get("tag") == tag), None)
            if profile is None:
                profile = {"type": "direct", "tag": tag}
            profile = dict(profile)
            profile.update(type="direct", bind_interface=peers["ai" if tag == "ai-ipsec" else "cn"][2],
                           inet4_bind_address=vip)
            for key in ("routing_mark", "domain_resolver", "inet6_bind_address"):
                profile.pop(key, None)
            cfg["outbounds"].append(profile)
        assert all(k not in alias for k in ("routing_mark", "bind_interface")), "alias must carry source metadata only"
        # Preserve the production AI/CN rule-set order. Explicit known default
        # names precede the IPv4 fallback; SOCKS never matches that fallback.
        cfg["route"]["rule_set"] = []
        rule_sets = []
        for name, domain in (("geosite-ai-openai", "ai.fixture.test"),
                             ("geosite-ai-anthropic", "anthropic.fixture.test"),
                             ("geosite-ai-support", "support.fixture.test"),
                             ("geosite-cn-video", "video.fixture.test")):
            file = d / (name + ".json")
            file.write_text(json.dumps({"version": 2, "rules": [{"domain": [domain]}]}))
            rule_sets.append({"type": "local", "tag": name, "format": "source", "path": str(file)})
        cfg["route"]["rule_set"] = rule_sets
        rules = cfg["route"]["rules"]
        # Keep production classifier order and reject rules, only remapping
        # profile tags because this spike replaces Xray/IPsec egress with local
        # direct fixtures. Then preserve all hostname flows on default before
        # the strictly IPv4 TUN fallback (numeric Host and no-Host stay eligible).
        for rule in rules:
            if rule.get("outbound") == "ai-xray":
                rule["outbound"] = "ai-ipsec"
            elif rule.get("outbound") == "cn-xray":
                rule["outbound"] = "cn-ipsec"
        # Match domain-bearing TUN requests, then exclude only canonical IPv4
        # literals. This handles numeric, underscored, hyphenated and FQDN
        # spellings without maintaining a list of non-IP numeric hostname forms.
        ipv4_octet = r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
        strict_ipv4 = rf"^({ipv4_octet}\.){{3}}{ipv4_octet}$"
        cfg["route"]["rules"] = rules + [
            {"type": "logical", "mode": "and", "rules": [
                {"inbound": ["tun-in"]},
                {"domain_regex": [".+"]},
                {"domain_regex": [strict_ipv4], "invert": True},
            ],
             "action": "route", "outbound": "default"},
            {"inbound": ["tun-in"], "ip_cidr": ["0.0.0.0/0"],
             "action": "route", "outbound": "legacy-hint"},
        ]
        # Keep sniffing, DNS hijack, original default/final behavior, and DNS
        # fixture. Only names used by this test resolve to the peer IP.
        cfg["route"]["final"] = "default"
        for server in cfg["dns"]["servers"]:
            server.update(server="127.0.0.1", server_port=53)
        cfg["log"] = {"level": "debug"}
        config = d / "sing-box.json"
        config.write_text(json.dumps(cfg))
        run(["sing-box", "check", "-c", str(config)])
        log_path = d / "sing-box.log"
        with log_path.open("w+") as log:
            sb = subprocess.Popen(["sing-box", "run", "-c", str(config)], stdout=log, stderr=log)
            children.append(sb)
            time.sleep(.5)
            if sb.poll() is not None:
                log.flush(); log.seek(0)
                raise RuntimeError("sing-box failed:\n" + log.read())
            run(["ip", "route", "replace", "192.0.2.10/32", "dev", "dnscomplex0"])
            run(["ip", "route", "replace", "192.0.2.11/32", "dev", "dnscomplex0"])
            run(["ip", "route", "replace", "192.0.2.12/32", "dev", "dnscomplex0"])

            def check(label, action, want):
                try:
                    got = action()
                except (OSError, subprocess.SubprocessError):
                    got = None
                print(f"{label}: {got!r}; expected {want!r}", flush=True)
                assert got == want, f"{label}: got {got!r}, expected {want!r}"

            def alias_output_packets(destination=None):
                output_chain = run(["nft", "list", "chain", "inet", "alias_probe", "output"]).stdout
                dest = re.escape(destination) if destination else ""
                match = re.search(r"ip saddr 198\.18\.255\.254(?: ip daddr " + dest + r")? counter packets (\d+)", output_chain)
                assert match, "could not read alias-source nft counter"
                return int(match.group(1))

            def check_without_alias(label, action, want, destination="192.0.2.10"):
                before = alias_output_packets(destination)
                check(label, action, want)
                assert alias_output_packets(destination) == before, f"{label} incorrectly selected alias outbound"

            # Unknown raw IPv4 is the only traffic sent via the alias. The
            # unmapped address remains on default and keeps the legacy exit.
            check("raw unknown TUN / no Host", lambda: route_probe(), "default|198.18.1.1")
            assert alias_output_packets("192.0.2.11") > 0, "unknown raw IPv4 did not select alias outbound"
            check_without_alias("unknown hostname Host", lambda: route_probe("unknown.fixture.test", "192.0.2.10"), "default|198.18.1.1")
            check_without_alias("numeric non-IPv4 hostname Host", lambda: route_probe("123.456", "192.0.2.10"), "default|198.18.1.1")
            check_without_alias("numeric hostname with terminal dot", lambda: route_probe("123.456.", "192.0.2.10"), "default|198.18.1.1")
            check_without_alias("four-label non-IP hostname", lambda: route_probe("999.999.999.999", "192.0.2.10"), "default|198.18.1.1")
            check_without_alias("leading-zero numeric hostname", lambda: route_probe("192.0.2.010", "192.0.2.10"), "default|198.18.1.1")
            check_without_alias("four-label hostname with terminal dot", lambda: route_probe("192.0.2.10.", "192.0.2.10"), "default|198.18.1.1")
            check_without_alias("numeric hyphen hostname", lambda: route_probe("123-456", "192.0.2.10"), "default|198.18.1.1")
            check_without_alias("numeric underscore hostname", lambda: route_probe("123_456", "192.0.2.10"), "default|198.18.1.1")
            check_without_alias("hostname with terminal dot", lambda: route_probe("unknown.fixture.test.", "192.0.2.10"), "default|198.18.1.1")
            check_without_alias("known ordinary Host", lambda: route_probe("ordinary.fixture.test", "192.0.2.10"), "default|198.18.1.1")
            before_literal = alias_output_packets("192.0.2.12")
            check("valid IPv4 literal stays on alias while profile gates are closed",
                  lambda: route_probe("192.0.2.12", "192.0.2.12"), None)
            assert alias_output_packets("192.0.2.12") > before_literal, "valid IPv4 Host did not select alias outbound"
            # Known profile domains fail closed until their own readiness is set.
            check_without_alias("AI Host gate closed", lambda: route_probe("ai.fixture.test"), None)
            check_without_alias("CN Host gate closed", lambda: route_probe("video.fixture.test"), None)
            run(["nft", "add", "element", "inet", "alias_probe", "cn_ready4", "{", "0.0.0.0/0", "}"])
            check_without_alias("AI closed / CN open", lambda: route_probe("ai.fixture.test"), None)
            check_without_alias("CN-only Host", lambda: route_probe("video.fixture.test"), "cn|10.251.1.10")
            run(["nft", "add", "element", "inet", "alias_probe", "ai_ready4", "{", "0.0.0.0/0", "}"])
            check_without_alias("AI Host", lambda: route_probe("ai.fixture.test"), "ai|10.250.1.22")
            # Production per-IP policy evaluates both marks in order, so CN's
            # mark intentionally overwrites AI on an overlapping destination.
            check("literal Host header alias", lambda: route_probe("192.0.2.10", "192.0.2.10"), "cn|10.251.1.10")
            check("raw overlapping IP alias", lambda: route_probe(address="192.0.2.10"), "cn|10.251.1.10")
            run(["nft", "flush", "set", "inet", "alias_probe", "ai_ready4"])
            check("AI closed / CN open overlap", lambda: route_probe(address="192.0.2.10"), None)
            # SOCKS/IP traffic is outside the TUN inbound-only alias rule.
            check_without_alias("SOCKS unknown IP", socks_probe, "default|198.18.1.1")
            print("PASS: real sing-box TUN alias source hint, known-domain routing, independent gates, overlap priority, SOCKS default", flush=True)
finally:
    for process in reversed(children):
        if process.poll() is None:
            process.terminate()
    for process in reversed(children):
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
