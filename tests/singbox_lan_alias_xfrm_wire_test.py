#!/usr/bin/env python3
"""Isolated source-alias -> policy mark -> real XFRM -> SNAT/VIP wire test.

Linux/root only. Reads only the supplied sing-box TUN inbound as a template;
all addresses, ESP keys, XFRM states/policies, nftables, routes, and processes
created by this test exist in a private network namespace. Three independent
peers answer for the same inner destination IP. No production SA is read.
"""
import argparse
import json
import os
import pathlib
import re
import select
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time

P = argparse.ArgumentParser()
P.add_argument("--config", type=pathlib.Path, default=pathlib.Path("/etc/sing-box/config.json"))
P.add_argument("--runtime-script", type=pathlib.Path, default=pathlib.Path("/usr/local/sbin/dnscomplex"))
P.add_argument("--isolated", action="store_true")
A = P.parse_args()

if not A.isolated:
    raise SystemExit(subprocess.run(
        ["unshare", "--net", sys.executable, str(pathlib.Path(__file__).resolve()),
         "--isolated", "--config", str(A.config.resolve()),
         "--runtime-script", str(A.runtime_script.resolve())], timeout=108).returncode)


def run(command, timeout=8, redact_error=False):
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        if redact_error:
            raise RuntimeError("isolated XFRM setup command failed (test key arguments suppressed)")
        raise RuntimeError(f"command failed ({command[0]} ...), rc={result.returncode}: {result.stderr.strip()[:300]}")
    return result


def wait_ns(process):
    for _ in range(100):
        if os.readlink(f"/proc/{process.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
            return
        time.sleep(.01)
    raise RuntimeError("could not create peer network namespace")


def route_probe(address="192.0.2.10", port=19443):
    try:
        sock = socket.create_connection((address, port), timeout=1.5)
        sock.settimeout(1.5)
        sock.sendall(b"GET /probe HTTP/1.0\r\nConnection: close\r\n\r\n")
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        sock.close()
        response = b"".join(chunks)
        return response.split(b"\r\n\r\n", 1)[-1].decode(errors="replace") if response else None
    except (OSError, socket.timeout):
        return None


def xfrm_packets(namespace, spi):
    """Read only the packet counter for a test SPI; never emit state/key text."""
    text = run(namespace + ["ip", "-s", "xfrm", "state", "list"], timeout=4).stdout
    for item in re.split(r"(?m)(?=^src )", text):
        found = re.search(r"\bspi (0x[0-9a-fA-F]+)", item)
        if found and int(found.group(1), 16) == spi:
            current = re.search(r"lifetime current:\s*(?:bytes )?(\d+)\(bytes\),\s*(?:packets )?(\d+)\(packets\)", item)
            if current:
                return int(current.group(2))
    raise RuntimeError("could not read isolated test XFRM packet counter")


def add_test_sa(namespace, src, dst, spi, reqid, if_id, key):
    # Random throwaway 128-bit AES key + 32-bit salt, local to this fixture.
    command = namespace + ["ip", "xfrm", "state", "add", "src", src, "dst", dst,
                           "proto", "esp", "spi", hex(spi), "reqid", str(reqid), "mode", "tunnel",
                           "aead", "rfc4106(gcm(aes))", "0x" + key, "128", "if_id", hex(if_id)]
    run(command, redact_error=True)


def add_test_policy(namespace, direction, src, dst, outer_src, outer_dst, reqid, if_id):
    src_cidr = src if "/" in src else src + "/32"
    dst_cidr = dst if "/" in dst else dst + "/32"
    run(namespace + ["ip", "xfrm", "policy", "add", "dir", direction, "if_id", hex(if_id),
                     "src", src_cidr, "dst", dst_cidr, "tmpl", "src", outer_src,
                     "dst", outer_dst, "proto", "esp", "reqid", str(reqid), "mode", "tunnel"], redact_error=True)


def extract_runtime_functions(path, names, destination):
    """Copy only named pure shell helpers; never source the full runtime script."""
    source = path.read_text()
    selected = list(names)
    insert_at = selected.index("sync_ipsec_nat_profile") if "sync_ipsec_nat_profile" in selected else len(selected)
    # Newer candidates validate an existing owned SNAT rule and remove it
    # idempotently. Older installed runtimes have neither dependency, so retain
    # their original four-helper extraction unchanged.
    optional = ("ipsec_nat_profile_matches", "ipsec_nat_profile_remove")
    present_optional = [name for name in optional
                        if re.search(rf"(?m)^{re.escape(name)}\(\) \{{\s*$", source)]
    selected[insert_at:insert_at] = present_optional
    extracted = []
    for name in selected:
        match = re.search(rf"(?m)^{re.escape(name)}\(\) \{{\s*$", source)
        if not match:
            raise RuntimeError(f"runtime helper {name} was not found")
        end = re.search(r"(?m)^\}\s*$", source[match.end():])
        if not end:
            raise RuntimeError(f"runtime helper {name} had no closing brace")
        extracted.append(source[match.start():match.end() + end.end()])
    extracted.append('''
ipsec_vip() { printf '%s\\n' "${FIXTURE_VIP:-}"; }
warn() { return 0; }
''')
    destination.write_text("\n".join(extracted))
    return selected


def run_runtime_nat_helper(helper, profile, vip):
    env = os.environ.copy()
    env["FIXTURE_VIP"] = vip
    result = subprocess.run(["bash", "-c", f"source {shlex.quote(str(helper))}; sync_ipsec_nat_profile {shlex.quote(profile)}"],
                            check=False, capture_output=True, text=True, timeout=5, env=env)
    if result.returncode:
        raise RuntimeError(f"extracted runtime SNAT helper failed for {profile} (fixture; output suppressed)")


def snat_rule_count(profile):
    text = run(["nft", "-a", "list", "chain", "inet", "dnscomplex", "postrouting"]).stdout
    comment = f'dnscomplex-{profile}-snat'
    return sum(1 for line in text.splitlines() if f'comment "{comment}"' in line)


def nft_has_element(set_name, address):
    result = subprocess.run(["nft", "get", "element", "inet", "dnscomplex", set_name,
                             "{", address, "}"], capture_output=True, text=True, timeout=4)
    return result.returncode == 0


def main():
    if not A.runtime_script.is_file():
        raise RuntimeError("runtime helper script is missing")
    if not A.config.is_file():
        raise RuntimeError("sing-box template config is missing")
    original = json.loads(A.config.read_text())
    production_tun = next((x for x in original.get("inbounds", []) if x.get("type") == "tun"), None)
    if production_tun is None:
        raise RuntimeError("supplied config has no TUN inbound")
    # Retain just the production TUN data-plane contract; don't copy listeners,
    # credentials, remote providers, DNS servers, or production outbounds.
    allowed = {"type", "tag", "interface_name", "address", "mtu", "auto_route",
               "strict_route", "auto_redirect", "auto_redirect_input_mark",
               "auto_redirect_output_mark", "route_address", "route_exclude_address",
               "route_address_set", "route_exclude_address_set", "stack"}
    tun = {k: v for k, v in production_tun.items() if k in allowed}
    tun["tag"] = "tun-in"
    tun["route_exclude_address"] = list(tun.get("route_exclude_address", [])) + [
        "127.0.0.0/8", "198.18.0.0/15", "192.0.2.0/24", "10.250.0.0/16"]
    alias_ip = "198.18.255.254"
    dest_ip = "192.0.2.10"
    vip_ai_a, vip_ai_b, vip_cn = "10.250.1.10", "10.250.1.11", "10.250.2.10"
    profile_cfg = {
        "ai": {"if_id": 0x301, "reqid": 0x301, "mark": 769, "table": 301,
               "iface": "ipsec-ai", "vip": vip_ai_a, "rotated_vip": vip_ai_b, "spi_out": 0x301001, "spi_in": 0x301002},
        "cn": {"if_id": 0x351, "reqid": 0x351, "mark": 849, "table": 351,
               "iface": "ipsec-cn", "vip": vip_cn, "rotated_vip": vip_cn, "spi_out": 0x351001, "spi_in": 0x351002},
    }

    children = []
    netns_processes = []
    responder_code = r'''import socket,sys,threading
tag=sys.argv[1]
def serve():
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("192.0.2.10",19443));s.listen()
 while True:
  c,_=s.accept()
  try:
   c.recv(8192);body=(tag+"|"+c.getpeername()[0]).encode()
   c.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body)
  finally:c.close()
serve()
'''

    try:
        run(["ip", "link", "set", "lo", "up"])
        run(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
        run(["ip", "addr", "add", alias_ip + "/32", "dev", "lo"])
        for vip in (vip_ai_a, vip_ai_b, vip_cn):
            run(["ip", "addr", "add", vip + "/32", "dev", "lo"])

        exits = {}
        for idx, tag in enumerate(("default", "ai", "cn"), 1):
            sleeper = subprocess.Popen(["unshare", "--net", "sleep", "105"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(sleeper); netns_processes.append(sleeper); wait_ns(sleeper)
            ns = ["nsenter", "-t", str(sleeper.pid), "-n"]
            host, remote = f"198.18.{idx}.1", f"198.18.{idx}.2"
            underlay = f"uplink{idx}"
            peerdev = f"peer{idx}"
            run(["ip", "link", "add", underlay, "type", "veth", "peer", "name", peerdev])
            run(["ip", "link", "set", peerdev, "netns", str(sleeper.pid)])
            run(["ip", "addr", "add", host + "/24", "dev", underlay]); run(["ip", "link", "set", underlay, "up"])
            run(ns + ["ip", "link", "set", "lo", "up"])
            run(ns + ["ip", "addr", "add", remote + "/24", "dev", peerdev]); run(ns + ["ip", "link", "set", peerdev, "up"])
            run(ns + ["ip", "addr", "add", dest_ip + "/32", "dev", "lo"])
            if tag == "default":
                run(["ip", "route", "add", "default", "via", remote, "dev", underlay])
            else:
                p = profile_cfg[tag]
                xfrm_peer = "xfrm-peer"
                run(["ip", "link", "add", p["iface"], "type", "xfrm", "dev", underlay, "if_id", hex(p["if_id"])])
                run(["ip", "link", "set", p["iface"], "mtu", "1400", "up"])
                run(ns + ["ip", "link", "add", xfrm_peer, "type", "xfrm", "dev", peerdev, "if_id", hex(p["if_id"])])
                run(ns + ["ip", "link", "set", xfrm_peer, "mtu", "1400", "up"])
                for vip in sorted({p["vip"], p["rotated_vip"]}):
                    run(ns + ["ip", "route", "add", vip + "/32", "dev", xfrm_peer])
                # Match the production's broad local traffic selector rather
                # than constraining the source selector to a synthetic VIP.
                add_test_policy([], "out", "0.0.0.0/0", dest_ip, host, remote, p["reqid"], p["if_id"])
                add_test_policy(ns, "in", "0.0.0.0/0", dest_ip, host, remote, p["reqid"], p["if_id"])
                add_test_policy(ns, "out", dest_ip, "0.0.0.0/0", remote, host, p["reqid"], p["if_id"])
                add_test_policy([], "in", dest_ip, "0.0.0.0/0", remote, host, p["reqid"], p["if_id"])
                key_out, key_in = secrets.token_hex(20), secrets.token_hex(20)
                # Each direction has one peer SA and one matching local SA.
                add_test_sa([], host, remote, p["spi_out"], p["reqid"], p["if_id"], key_out)
                add_test_sa(ns, host, remote, p["spi_out"], p["reqid"], p["if_id"], key_out)
                add_test_sa([], remote, host, p["spi_in"], p["reqid"], p["if_id"], key_in)
                add_test_sa(ns, remote, host, p["spi_in"], p["reqid"], p["if_id"], key_in)
                run(["ip", "route", "add", "default", "dev", p["iface"], "table", str(p["table"])])
                run(["ip", "rule", "add", "priority", str(40 + idx), "fwmark", str(p["mark"]), "lookup", str(p["table"])])
            if tag != "default":
                child = subprocess.Popen(ns + ["python3", "-u", "-c", responder_code, tag],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                children.append(child)
                time.sleep(.05)
            else:
                child = subprocess.Popen(ns + ["python3", "-u", "-c", responder_code, tag],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                children.append(child); time.sleep(.05)
            exits[tag] = {"ns": ns, "host": host, "remote": remote, "dev": underlay}

        def render_nft():
            return f'''table inet dnscomplex {{
 set ai4 {{ type ipv4_addr; flags interval; elements = {{ {dest_ip} }} }}
 set cn4 {{ type ipv4_addr; flags interval; }}
 set ai_ready4 {{ type ipv4_addr; flags interval; }}
 set cn_ready4 {{ type ipv4_addr; flags interval; }}
 set ai_ready6 {{ type ipv6_addr; flags interval; }}
 set cn_ready6 {{ type ipv6_addr; flags interval; }}
 chain output {{
  type route hook output priority -151; policy accept;
  ip saddr {alias_ip} ip daddr @ai4 ip daddr != @ai_ready4 counter drop comment "ai-closed"
  ip saddr {alias_ip} ip daddr @cn4 ip daddr != @cn_ready4 counter drop comment "cn-closed"
  ip saddr {alias_ip} ip daddr @ai4 meta mark set 769 counter comment "ai-classify"
  ip saddr {alias_ip} ip daddr @cn4 meta mark set 849 counter comment "cn-classify"
 }}
}}'''

        with tempfile.TemporaryDirectory(prefix="dnscomplex-xfrm-alias-") as td:
            d = pathlib.Path(td)
            nft_file = d / "fixture.nft"
            nft_file.write_text(render_nft()); run(["nft", "-f", str(nft_file)])
            helper_file = d / "selected-runtime-helpers.sh"
            runtime_helper_names = extract_runtime_functions(
                A.runtime_script,
                ("profile_egress_gate_set", "profile_egress_gate_clear",
                 "delete_nft_rules_by_comment", "sync_ipsec_nat_profile"),
                helper_file)
            # Exercise the deployed helper bodies only inside this netns.
            # ipsec_vip is replaced with a fixture value; the full runtime is
            # never sourced, so it cannot touch live SA/config/services.
            run_runtime_nat_helper(helper_file, "ai", vip_ai_a)
            run_runtime_nat_helper(helper_file, "ai", vip_ai_a)
            if snat_rule_count("ai") != 1:
                raise AssertionError("production SNAT sync helper duplicated the AI fixture rule")
            print("runtime helper AI install x2: one dnscomplex-ai-snat rule", flush=True)
            run_runtime_nat_helper(helper_file, "cn", vip_cn)
            run_runtime_nat_helper(helper_file, "cn", vip_cn)
            if snat_rule_count("cn") != 1:
                raise AssertionError("production SNAT sync helper duplicated the CN fixture rule")
            print("runtime helper CN install x2: one dnscomplex-cn-snat rule", flush=True)
            # Default source-alias SNAT remains a narrow candidate analogue;
            # no production runtime helper currently covers this alias case.
            run(["nft", "add", "rule", "inet", "dnscomplex", "postrouting", "ip", "saddr", alias_ip,
                 "oifname", exits["default"]["dev"], "snat", "ip", "to", exits["default"]["host"],
                 "comment", "fixture-default-alias-snat"])
            tun_name = tun.get("interface_name", "dnscomplex0")
            # Add this after sing-box creates the interface; first generate a
            # minimal config containing no production credentials/outbounds.
            cfg = {
                "log": {"level": "warn"},
                "inbounds": [tun],
                "outbounds": [
                    {"type": "direct", "tag": "default"},
                    {"type": "direct", "tag": "source-alias", "inet4_bind_address": alias_ip},
                ],
                "route": {"rules": [{"inbound": ["tun-in"], "ip_cidr": ["0.0.0.0/0"],
                                      "action": "route", "outbound": "source-alias"}], "final": "default"},
                "dns": {"servers": [{"type": "local", "tag": "local"}], "final": "local"},
            }
            config = d / "sing-box.json"; config.write_text(json.dumps(cfg))
            run(["sing-box", "check", "-c", str(config)])
            output_mark = tun.get("auto_redirect_output_mark", 8228)
            output_mark = int(output_mark, 0) if isinstance(output_mark, str) else int(output_mark)
            run(["ip", "route", "add", "default", "via", exits["default"]["remote"],
                 "dev", exits["default"]["dev"], "table", "200"])
            # Sing-box's OUTPUT mark bypasses the fixture TUN route; profile
            # nft marks 769/849 take earlier rules, while unclassified marked
            # sockets use the default peer table.
            run(["ip", "rule", "add", "priority", "52", "fwmark", str(output_mark), "lookup", "200"])
            log_path = d / "sing-box.log"
            with log_path.open("w") as log:
                sb = subprocess.Popen(["sing-box", "run", "-c", str(config)], stdout=log, stderr=log)
                children.append(sb)
                for _ in range(80):
                    if sb.poll() is not None:
                        raise RuntimeError("sing-box exited during startup (private fixture config)")
                    try:
                        run(["ip", "link", "show", tun_name], timeout=1)
                        break
                    except RuntimeError:
                        time.sleep(.025)
                else:
                    raise RuntimeError("sing-box TUN interface was not created")
                run(["ip", "route", "replace", dest_ip + "/32", "dev", tun_name])

                def expect(label, got, wanted):
                    print(f"{label}: {got!r}; expected {wanted!r}", flush=True)
                    if got != wanted:
                        raise AssertionError(f"{label}: destination/response did not match fixture")

                ai_ns = exits["ai"]["ns"]
                cn_ns = exits["cn"]["ns"]
                ai = profile_cfg["ai"]
                cn = profile_cfg["cn"]
                base_default = xfrm_packets([], ai["spi_out"])

                # AI destination is present but not ready: OUTPUT must drop,
                # and neither default responder nor ESP SA may see fallback.
                closed = route_probe()
                expect("AI gate closed (no default fallback)", closed, None)
                if xfrm_packets([], ai["spi_out"]) != base_default:
                    raise AssertionError("closed AI gate unexpectedly emitted encrypted traffic")

                run(["nft", "add", "element", "inet", "dnscomplex", "ai_ready4", "{", dest_ip, "}"])
                ai_before_host = xfrm_packets([], ai["spi_out"])
                ai_before_peer = xfrm_packets(ai_ns, ai["spi_out"])
                expect("AI XFRM/SNAT controlled 200 response", route_probe(), "ai|" + vip_ai_a)
                if xfrm_packets([], ai["spi_out"]) <= ai_before_host or xfrm_packets(ai_ns, ai["spi_out"]) <= ai_before_peer:
                    raise AssertionError("AI ESP packet counters did not increase at both ends")
                print(f"AI ESP counters: host-out {ai_before_host}->{xfrm_packets([], ai['spi_out'])}; peer-in {ai_before_peer}->{xfrm_packets(ai_ns, ai['spi_out'])}", flush=True)

                # Simulate the profile VIP changing after renegotiation: update
                # the fixture NAT mapping and remove old local/peer VIP routes.
                run(["ip", "addr", "del", vip_ai_a + "/32", "dev", "lo"])
                run(exits["ai"]["ns"] + ["ip", "route", "del", vip_ai_a + "/32", "dev", "xfrm-peer"])
                run_runtime_nat_helper(helper_file, "ai", vip_ai_b)
                run_runtime_nat_helper(helper_file, "ai", vip_ai_b)
                if snat_rule_count("ai") != 1:
                    raise AssertionError("AI VIP rotation duplicated its runtime SNAT rule")
                if "ipsec_nat_profile_matches" in runtime_helper_names:
                    if nft_has_element("ai_ready4", dest_ip):
                        raise AssertionError("changed-VIP runtime helper did not close the AI readiness gate")
                    print("AI VIP runtime sync: gate closed before fixture re-open", flush=True)
                    run(["nft", "add", "element", "inet", "dnscomplex", "ai_ready4", "{", dest_ip, "}"])
                ai_before_rotate = xfrm_packets([], ai["spi_out"])
                expect("AI rotated fixture VIP", route_probe(), "ai|" + vip_ai_b)
                if xfrm_packets([], ai["spi_out"]) <= ai_before_rotate:
                    raise AssertionError("rotated AI VIP did not traverse ESP")

                # Empty fixture VIP follows the installed helper's real branch:
                # it deletes owned SNAT and calls the extracted gate-clear.
                run_runtime_nat_helper(helper_file, "ai", "")
                if snat_rule_count("ai") != 0:
                    raise AssertionError("missing-VIP helper left AI SNAT installed")
                if nft_has_element("ai_ready4", dest_ip) or not nft_has_element("ai4", dest_ip):
                    raise AssertionError("missing-VIP helper did not clear only the AI readiness gate")
                expect("AI runtime VIP missing (closed, no fallback)", route_probe(), None)

                # CN gets an independent readiness set and the same inner IP.
                run(["nft", "flush", "set", "inet", "dnscomplex", "ai4"])
                run(["nft", "add", "element", "inet", "dnscomplex", "cn4", "{", dest_ip, "}"])
                run(["nft", "add", "element", "inet", "dnscomplex", "cn_ready4", "{", dest_ip, "}"])
                cn_before = xfrm_packets([], cn["spi_out"])
                cn_peer_before = xfrm_packets(cn_ns, cn["spi_out"])
                expect("CN XFRM/SNAT controlled 200 response", route_probe(), "cn|" + vip_cn)
                cn_after, cn_peer_after = xfrm_packets([], cn["spi_out"]), xfrm_packets(cn_ns, cn["spi_out"])
                if cn_after <= cn_before or cn_peer_after <= cn_peer_before:
                    raise AssertionError("CN ESP packet counters did not increase at both ends")
                print(f"CN ESP counters: host-out {cn_before}->{cn_after}; peer-in {cn_peer_before}->{cn_peer_after}", flush=True)

                # Neither set membership means the very same inner IP takes
                # the cleartext default peer and keeps default source NAT.
                run(["nft", "flush", "set", "inet", "dnscomplex", "cn4"])
                default_result = route_probe()
                if default_result is None:
                    print("default path diagnostic (fixture only):", flush=True)
                    for cmd in (["ip", "route", "get", dest_ip, "from", alias_ip],
                                ["ip", "rule", "show"], ["ip", "-s", "link", "show", exits["default"]["dev"]],
                                ["nft", "list", "chain", "inet", "dnscomplex", "output"],
                                ["nft", "list", "chain", "inet", "dnscomplex", "postrouting"]):
                        print(run(cmd).stdout[:1600].strip(), flush=True)
                expect("default cleartext peer, same inner IP", default_result, "default|" + exits["default"]["host"])
                print("PASS: source-alias outbound crossed real encrypted XFRM SAs to independent AI/CN peers, received replies, used profile SNAT VIPs, rotated fixture VIP, failed closed when AI gate was closed, and fell to default only when no profile set selected the IP.", flush=True)
    finally:
        for process in reversed(children):
            if process.poll() is None:
                process.terminate()
        for process in reversed(children):
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()


main()
