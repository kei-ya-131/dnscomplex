#!/usr/bin/env python3
"""Actual Xray VLESS UDP -> SOCKS UDP -> sing-box QUIC sniffing wire test.

This is a bounded transport/routing fixture, not a provider or application
test. It reuses the pinned TCP fixture's config projection and the RFC 9001
Appendix A.2 Initial from xray_sniffing_wire_test.py. The same SNI is assigned
to AI, CN-video, or neither in isolated sing-box rule-set contents per trial.
The no-SNI negative control is deliberately non-QUIC random UDP.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import queue
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

DEST_IP = "192.0.2.10"
DEST_ALT_IP = "192.0.2.20"
PORT = 443
VIP = {"default": "198.18.1.254", "ai": "10.250.1.22", "cn": "10.251.1.10"}
SNI = "example.com"


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_tcp_helpers(args):
    """Reuse the frozen TCP fixture's pinned projection/topology helpers."""
    source = pathlib.Path(__file__).with_name("xray_to_singbox_sniff_wire_test.py")
    old_argv = sys.argv
    sys.argv = [str(source), "--xray", str(args.xray), "--xray-sha256", args.xray_sha256,
                "--sing-box", str(args.sing_box), "--sing-box-sha256", args.sing_box_sha256,
                "--config", str(args.config), "--config-sha256", args.config_sha256,
                "--isolated"]
    try:
        spec = importlib.util.spec_from_file_location("_frozen_tcp_fixture", source)
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load frozen TCP fixture helpers")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.argv = old_argv


def read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError("SOCKS peer closed early")
        data.extend(part)
    return bytes(data)


def parse_udp_header(packet: bytes) -> tuple[str, int]:
    if len(packet) < 7 or packet[:3] != b"\x00\x00\x00":
        raise ValueError("invalid SOCKS UDP datagram header")
    atyp = packet[3]
    pos = 4
    if atyp == 1:
        if len(packet) < pos + 6: raise ValueError("short IPv4 SOCKS UDP target")
        host = socket.inet_ntop(socket.AF_INET, packet[pos:pos + 4]); pos += 4
    elif atyp == 3:
        if len(packet) < pos + 1: raise ValueError("short domain SOCKS UDP target")
        size = packet[pos]; pos += 1
        if not size or len(packet) < pos + size + 2: raise ValueError("bad domain SOCKS UDP target")
        host = packet[pos:pos + size].decode("ascii"); pos += size
    elif atyp == 4:
        if len(packet) < pos + 18: raise ValueError("short IPv6 SOCKS UDP target")
        host = socket.inet_ntop(socket.AF_INET6, packet[pos:pos + 16]); pos += 16
    else:
        raise ValueError(f"unsupported SOCKS UDP ATYP {atyp}")
    port = struct.unpack("!H", packet[pos:pos + 2])[0]
    if not packet[pos + 2:]: raise ValueError("empty SOCKS UDP payload")
    return host, port


def udp_payload(packet: bytes) -> bytes:
    if len(packet) < 4 or packet[:3] != b"\x00\x00\x00":
        raise ValueError("invalid SOCKS UDP datagram header")
    atyp = packet[3]; pos = 4
    if atyp == 1: pos += 4
    elif atyp == 4: pos += 16
    elif atyp == 3:
        if len(packet) < pos + 1: raise ValueError("short SOCKS UDP domain")
        pos += 1 + packet[pos]
    else: raise ValueError("unsupported SOCKS UDP address type")
    pos += 2
    if len(packet) <= pos: raise ValueError("empty SOCKS UDP response payload")
    return packet[pos:]


def vless_udp_response(sock: socket.socket) -> bytes:
    """Read one VLESS response header and UDP packet payload."""
    version, addon_len = read_exact(sock, 2)
    if version != 0:
        raise ValueError("unexpected VLESS UDP response version")
    if addon_len:
        read_exact(sock, addon_len)
    size = struct.unpack("!H", read_exact(sock, 2))[0]
    if not size:
        raise ValueError("empty VLESS UDP response frame")
    return read_exact(sock, size)


def controlled_dns_answer(packet: bytes) -> tuple[str, int, bytes]:
    """Build a synthetic DNS answer without opening a socket."""
    if len(packet) < 17:
        raise ValueError("short DNS question")
    pos = 12; labels = []
    while True:
        if pos >= len(packet): raise ValueError("truncated DNS name")
        n = packet[pos]; pos += 1
        if not n: break
        if n > 63 or pos + n > len(packet): raise ValueError("invalid DNS label")
        labels.append(packet[pos:pos + n].decode("ascii")); pos += n
    if pos + 4 > len(packet): raise ValueError("truncated DNS question fields")
    qtype, qclass = struct.unpack("!HH", packet[pos:pos + 4])
    name = ".".join(labels).lower()
    answer = b""
    if name == SNI and qtype == 1 and qclass == 1:
        answer = (b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04" +
                  socket.inet_aton(DEST_ALT_IP))
    question = packet[12:pos + 4]
    counts = struct.pack("!HHHHH", 0x8180, 1, int(bool(answer)), 0, 0)
    return name, qtype, packet[:2] + counts + question + answer


def controlled_dns_server():
    """Answer example.com A with the controlled .20 marker and record questions."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0)); sock.settimeout(.2)
    stop = threading.Event()
    queries: list[tuple[str, int]] = []

    def serve():
        while not stop.is_set():
            try: packet, peer = sock.recvfrom(4096)
            except socket.timeout: continue
            except OSError: break
            try:
                name, qtype, response = controlled_dns_answer(packet)
                queries.append((name, qtype))
                sock.sendto(response, peer)
            except Exception:
                continue

    thread = threading.Thread(target=serve, daemon=True); thread.start()
    return sock, thread, stop, queries


def udp_payload_for_marker(fields: tuple[str, str, str, str, str]) -> bytes:
    return "|".join(fields).encode("ascii")


class SocksUdpForwardTap:
    """Observe Xray's UDP target while relaying a real SOCKS UDP association."""
    def __init__(self, upstream_port: int):
        self.upstream_port = upstream_port
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0)); self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.targets: queue.Queue[tuple[str, int]] = queue.Queue()
        self.errors: queue.Queue[BaseException] = queue.Queue()
        self.marker_observations: queue.Queue[tuple[str, str, str, str, str]] = queue.Queue()
        self.reply_sources: queue.Queue[tuple[str, int]] = queue.Queue()
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []
        self.accept_thread = threading.Thread(target=self._accept, daemon=True)
        self.accept_thread.start()

    def _accept(self):
        self.listener.settimeout(.2)
        while not self.stop.is_set():
            try: conn, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError: break
            thread = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            self.threads.append(thread); thread.start()

    def _serve(self, client: socket.socket):
        server_tcp = None
        relay = None
        try:
            client.settimeout(3)
            ver, nmethods = read_exact(client, 2)
            methods = read_exact(client, nmethods)
            if ver != 5 or 0 not in methods: raise ValueError("Xray SOCKS no-auth negotiation missing")
            client.sendall(b"\x05\x00")
            head = read_exact(client, 4)
            if head[:3] != b"\x05\x03\x00": raise ValueError("Xray did not request UDP ASSOCIATE")
            atyp = head[3]
            size = {1: 4, 4: 16}.get(atyp)
            if atyp == 3: size = read_exact(client, 1)[0]
            if size is None: raise ValueError("unsupported UDP ASSOCIATE address")
            read_exact(client, size + 2)

            server_tcp = socket.create_connection(("127.0.0.1", self.upstream_port), timeout=3)
            server_tcp.settimeout(3)
            server_tcp.sendall(b"\x05\x01\x00")
            if read_exact(server_tcp, 2) != b"\x05\x00": raise ValueError("sing-box SOCKS auth failed")
            server_tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            reply = read_exact(server_tcp, 4)
            if reply[:3] != b"\x05\x00\x00": raise ValueError("sing-box SOCKS UDP ASSOCIATE failed")
            if reply[3] == 1:
                host = socket.inet_ntop(socket.AF_INET, read_exact(server_tcp, 4))
            elif reply[3] == 4:
                host = socket.inet_ntop(socket.AF_INET6, read_exact(server_tcp, 16))
            else:
                raise ValueError("sing-box returned unsupported UDP relay address")
            port = struct.unpack("!H", read_exact(server_tcp, 2))[0]
            if host in ("0.0.0.0", "::"): host = "127.0.0.1"
            relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            relay.bind(("127.0.0.1", 0)); relay.settimeout(.2)
            client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", relay.getsockname()[1]))
            xray_udp = None
            deadline = time.monotonic() + 8
            while not self.stop.is_set() and time.monotonic() < deadline:
                try: packet, peer = relay.recvfrom(65535)
                except socket.timeout:
                    if client.fileno() < 0: break
                    continue
                target = parse_udp_header(packet)
                self.targets.put(target)
                xray_udp = peer
                relay.sendto(packet, (host, port))
                # A short, bounded relay window also returns any marker reply to Xray.
                until = time.monotonic() + .35
                while time.monotonic() < until:
                    try: answer, source = relay.recvfrom(65535)
                    except socket.timeout: continue
                    if source == (host, port) and xray_udp:
                        reply_source = parse_udp_header(answer)
                        fields = tuple(udp_payload(answer).decode("ascii").split("|", 4))
                        if len(fields) == 5:
                            self.marker_observations.put(fields)
                            self.reply_sources.put(reply_source)
                        relay.sendto(answer, xray_udp)
                        break
                    # A second Xray datagram is forwarded rather than dropped.
                    relay.sendto(answer, (host, port))
        except (OSError, EOFError, ValueError) as exc:
            self.errors.put(exc)
        finally:
            if relay is not None: relay.close()
            if server_tcp is not None: server_tcp.close()
            client.close()

    def close(self):
        self.stop.set(); self.listener.close(); self.accept_thread.join(timeout=1)
        for thread in self.threads: thread.join(timeout=1)


def vless_udp_request(identity: str, dest_port: int, payload: bytes) -> bytes:
    return (b"\x00" + uuid.UUID(identity).bytes + b"\x00\x02" + struct.pack("!H", dest_port)
            + b"\x01" + socket.inet_aton(DEST_IP) + struct.pack("!H", len(payload)) + payload)


def quic_initial():
    source = pathlib.Path(__file__).with_name("xray_sniffing_wire_test.py")
    spec = importlib.util.spec_from_file_location("_quic_golden", source)
    if spec is None or spec.loader is None: raise RuntimeError("could not load RFC 9001 golden packet")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    packet = module.RFC9001_CLIENT_INITIAL
    if len(packet) != 1200: raise RuntimeError("RFC 9001 fixture size changed")
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", type=pathlib.Path, required=True)
    parser.add_argument("--xray-sha256", required=True)
    parser.add_argument("--sing-box", type=pathlib.Path, required=True)
    parser.add_argument("--sing-box-sha256", required=True)
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--isolated", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    for path, digest, label in ((args.xray, args.xray_sha256, "Xray"),
                                (args.sing_box, args.sing_box_sha256, "sing-box"),
                                (args.config, args.config_sha256, "sing-box config")):
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise SystemExit(f"{label} SHA256 must be 64 lowercase hex characters")
        if sha256(path.resolve(strict=True)) != digest: raise SystemExit(f"{label} SHA256 mismatch")
    if not args.isolated:
        if os.geteuid() != 0: raise SystemExit("run as root to create an isolated network namespace")
        helpers = load_tcp_helpers(args)
        xv_result = helpers.run([str(helpers.XRAY), "version"], timeout=5)
        xv = (xv_result.stdout.strip() or xv_result.stderr.strip()).splitlines()[0]
        sv_result = helpers.run([str(helpers.SING_BOX), "version"], timeout=5)
        sv = (sv_result.stdout.strip() or sv_result.stderr.strip()).splitlines()[0]
        if "26.10.21" not in xv or "1.14.0" not in sv:
            raise SystemExit("binary version mismatch: expected Xray 26.10.21 and sing-box 1.14.0")
        if helpers.active_mainpid() is None: raise SystemExit("host sing-box MainPID is not verifiable")
        cfg_hash = sha256(args.config); pid = helpers.active_mainpid()
        cmd = ["unshare", "--net", sys.executable, str(pathlib.Path(__file__).resolve()),
               "--isolated", "--xray", str(args.xray), "--xray-sha256", args.xray_sha256,
               "--sing-box", str(args.sing_box), "--sing-box-sha256", args.sing_box_sha256,
               "--config", str(args.config), "--config-sha256", args.config_sha256]
        child = subprocess.Popen(cmd, start_new_session=True)
        try: status = child.wait(timeout=108)
        except subprocess.TimeoutExpired:
            try: os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try: child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                child.wait(timeout=2)
            raise SystemExit("isolated QUIC wire test exceeded 108-second total budget")
        if status: raise SystemExit(status)
        if sha256(args.config) != cfg_hash or helpers.active_mainpid() != pid:
            raise SystemExit("host guard changed: config digest or sing-box MainPID differs")
        print("HOST_GUARD: sing-box config digest and MainPID unchanged", flush=True)
        return

    h = load_tcp_helpers(args)
    required_helpers = ("run", "config_projection", "dns_server", "free_port", "wait_process",
                        "stop_process", "active_mainpid", "XRAY", "SING_BOX", "CONFIG")
    missing_helpers = [name for name in required_helpers if not hasattr(h, name)]
    if missing_helpers:
        raise RuntimeError(f"frozen TCP fixture helper API changed: {missing_helpers!r}")
    children = []; xray = sb = tap = None
    try:
        if os.geteuid() != 0: raise RuntimeError("isolated runner lost root privileges")
        h.run(["ip", "link", "set", "lo", "up"])
        # Three source-VIP marker exits share one destination address. Local /32s
        # keep this focused fixture independent of XFRM, policy routes and peers.
        for profile in ("default", "ai", "cn"):
            h.run(["ip", "addr", "add", VIP[profile] + "/32", "dev", "lo"])
        h.run(["ip", "addr", "add", DEST_IP + "/32", "dev", "lo"])
        h.run(["ip", "addr", "add", DEST_ALT_IP + "/32", "dev", "lo"])
        marker10_nonce = "marker10-" + uuid.uuid4().hex[:12]
        marker20_nonce = "marker20-" + uuid.uuid4().hex[:12]
        marker = r'''import socket,sys,threading
entries=[("192.0.2.10","marker10",sys.argv[1]),("192.0.2.20","marker20",sys.argv[2])]
def serve(ip,name,nonce):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((ip,443))
 while True:
  d,p=s.recvfrom(65535)
  body="%s|%s|%s|%s|%d"%(name,nonce,ip,p[0],len(d))
  s.sendto(body.encode("ascii"),p)
for ip,name,nonce in entries: threading.Thread(target=serve,args=(ip,name,nonce),daemon=True).start()
threading.Event().wait()
'''
        marker_proc = subprocess.Popen([sys.executable, "-u", "-c", marker, marker10_nonce, marker20_nonce],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children.append(marker_proc); time.sleep(.05)
        if marker_proc.poll() is not None:
            raise RuntimeError("controlled .10/.20 UDP marker listeners did not start")

        with tempfile.TemporaryDirectory(prefix="xray-sb-quic-") as temp:
            d = pathlib.Path(temp); os.chmod(d, 0o700)
            dns_sock, dns_thread, dns_stop, dns_queries = h.dns_server()
            dns_servers = [(dns_sock, dns_thread, dns_stop)]
            sb_port, xray_port = h.free_port(), h.free_port()
            ident = str(uuid.uuid4())
            xray = None
            tap = SocksUdpForwardTap(sb_port)

            def run_case(route_only: bool, selected: str | None, no_sni: bool = False,
                         readdress: bool = False):
                nonlocal sb, xray
                h.stop_process(xray); xray = None
                h.stop_process(sb); sb = None
                if readdress:
                    case_dns_sock, case_dns_thread, case_dns_stop, case_dns_queries = controlled_dns_server()
                    dns_servers.append((case_dns_sock, case_dns_thread, case_dns_stop))
                    resolver_port = case_dns_sock.getsockname()[1]
                else:
                    case_dns_queries = None
                    resolver_port = dns_sock.getsockname()[1]
                cfg, actual_tags = h.config_projection(h.CONFIG, d, sb_port, resolver_port)
                # The RFC packet carries example.com. Assign only fixture rule-set membership;
                # no production domain list or domain name is changed.
                profile_rule_sets = {profile: set() for profile in ("ai", "cn")}
                for rule in cfg["route"]["rules"]:
                    profile = "ai" if rule.get("outbound") == "ai-exit" else \
                              "cn" if rule.get("outbound") == "cn-exit" else None
                    selectors = rule.get("rule_set", [])
                    if isinstance(selectors, str): selectors = [selectors]
                    if profile and isinstance(selectors, list):
                        profile_rule_sets[profile].update(x for x in selectors if isinstance(x, str))
                if (not profile_rule_sets["ai"] or not profile_rule_sets["cn"] or
                        profile_rule_sets["ai"] & profile_rule_sets["cn"]):
                    raise RuntimeError("projected AI/CN-video rule-set selectors are missing or overlap")
                for item in cfg["route"]["rule_set"]:
                    path = pathlib.Path(item["path"])
                    domains = [SNI] if selected in ("ai", "cn") and item["tag"] in profile_rule_sets[selected] else []
                    path.write_text(json.dumps({"version": 5, "rules": ([{"domain": domains}] if domains else [])}))
                    path.chmod(0o600)
                for outbound in cfg["outbounds"]:
                    if isinstance(outbound, dict) and outbound.get("type") == "direct":
                        outbound.pop("bind_interface", None)
                sb_config = d / f"sb-{selected or 'default'}-{route_only}-{no_sni}.json"
                sb_config.write_text(json.dumps(cfg)); sb_config.chmod(0o600)
                h.run([str(h.SING_BOX), "check", "-c", str(sb_config)], timeout=8)
                sb = subprocess.Popen([str(h.SING_BOX), "run", "-c", str(sb_config)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                children.append(sb); h.wait_process(sb, "sing-box")

                xcfg = {"log": {"loglevel": "error"},
                        "inbounds": [{"tag": "wire-vless", "listen": "127.0.0.1", "port": xray_port,
                                      "protocol": "vless", "settings": {"clients": [{"id": ident}], "decryption": "none"},
                                      "sniffing": {"enabled": True, "destOverride": ["quic"],
                                                   "metadataOnly": False, "routeOnly": route_only}}],
                        "outbounds": [{"tag": "to-sing-box", "protocol": "socks", "settings": {
                            "servers": [{"address": "127.0.0.1", "port": tap.port}]}}],
                        "routing": {"rules": [{"type": "field", "inboundTag": ["wire-vless"],
                                                  "outboundTag": "to-sing-box"}]}}
                xcfg_path = d / f"xray-{route_only}-{selected or 'default'}-{no_sni}.json"
                xcfg_path.write_text(json.dumps(xcfg)); xcfg_path.chmod(0o600)
                h.run([str(h.XRAY), "run", "-test", "-format=json", "-config", str(xcfg_path)], timeout=8)
                xray = subprocess.Popen([str(h.XRAY), "run", "-config", str(xcfg_path)],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                children.append(xray)
                for _ in range(100):
                    if xray.poll() is not None: raise RuntimeError("isolated Xray exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", xray_port), timeout=.05): break
                    except OSError: time.sleep(.02)
                else: raise RuntimeError("isolated Xray VLESS listener did not become ready")

                packet = b"\x99\x88\x77\x66 no-sni udp" if no_sni else quic_initial()
                client_reply = None
                with socket.create_connection(("127.0.0.1", xray_port), timeout=3) as conn:
                    conn.settimeout(5 if readdress else 2)
                    conn.sendall(vless_udp_request(ident, PORT, packet))
                    if readdress:
                        client_reply = vless_udp_response(conn)
                    else:
                        conn.shutdown(socket.SHUT_WR)
                try: observed_target = tap.targets.get(timeout=5)
                except queue.Empty:
                    if not tap.errors.empty(): raise tap.errors.get()
                    raise AssertionError("Xray SOCKS UDP target was not observed")
                expected_target = (DEST_IP, PORT) if route_only or no_sni else (SNI, PORT)
                if not readdress and observed_target != expected_target:
                    raise AssertionError(f"SOCKS target {observed_target!r}, expected {expected_target!r}")
                # The per-profile marker receives only from the selected source VIP.
                expected_profile = selected or "default"
                deadline = time.monotonic() + 3
                received = None
                while time.monotonic() < deadline:
                    try: received = tap.marker_observations.get(timeout=.1); break
                    except queue.Empty: pass
                if received is None:
                    raise AssertionError("no same-IP marker exit received the relayed QUIC datagram")
                try: reply_source = tap.reply_sources.get(timeout=2)
                except queue.Empty: raise AssertionError("SOCKS UDP reply source header was not observed")
                expected_marker_name = "marker10"
                expected_marker_nonce = marker10_nonce
                if readdress:
                    if received[3] != VIP[expected_profile]:
                        raise AssertionError(f"selected egress source VIP mismatch: {received!r}")
                elif (received[0] != expected_marker_name or received[1] != expected_marker_nonce or
                      received[3] != VIP[expected_profile]):
                    raise AssertionError(f"selected marker/source mismatch: {received!r}")
                if not route_only and not no_sni:
                    dns_deadline = time.monotonic() + 2
                    while time.monotonic() < dns_deadline and SNI not in dns_queries:
                        time.sleep(.02)
                    if SNI not in dns_queries:
                        raise AssertionError("domain SOCKS target did not use the controlled sing-box resolver")
                mode = f"routeOnly={str(route_only).lower()}"
                case = "random-udp-no-sni" if no_sni else (selected or "unknown-sni-default")
                if not readdress:
                    print(f"{mode}/{case}: SOCKS target={observed_target[0]}:{observed_target[1]}; "
                          f"marker={received[0]} nonce={received[1]} source={received[3]} "
                          f"reply-source={reply_source[0]}:{reply_source[1]} PASS", flush=True)
                    return
                if received[0] == "marker10": expected_nonce = marker10_nonce
                elif received[0] == "marker20": expected_nonce = marker20_nonce
                else: raise AssertionError(f"unexpected controlled marker {received[0]!r}")
                if received[1] != expected_nonce:
                    raise AssertionError("controlled marker nonce mismatch")
                if client_reply != udp_payload_for_marker(received):
                    raise AssertionError("VLESS client UDP reply payload does not match the observed marker")
                q = [] if case_dns_queries is None else [
                    {"name": name, "qtype": "A" if qtype == 1 else str(qtype)}
                    for name, qtype in case_dns_queries]
                observed = {
                    "routeOnly": route_only,
                    "inbound_target": f"{DEST_IP}:{PORT}",
                    "socks_target": f"{observed_target[0]}:{observed_target[1]}",
                    "sing_box_dns_server_tag": "fixture-dns",
                    "dns_queries": q,
                    "sing_box_outbound_tag": "ai-exit",
                    "projected_source_outbound_tag": actual_tags["ai"],
                    "marker_listener": received[2],
                    "marker_nonce": received[1],
                    "sing_box_egress_source_vip": received[3],
                    "socks_reply_source": f"{reply_source[0]}:{reply_source[1]}",
                    "vless_client_reply_nonce": received[1],
                }
                print("READDRESS " + json.dumps(observed, sort_keys=True), flush=True)

            for route_only in (False, True):
                for selected in ("ai", "cn", None):
                    run_case(route_only, selected)
                run_case(route_only, None, no_sni=True)
            for route_only in (False, True):
                run_case(route_only, "ai", readdress=True)
            print("PASS: actual Xray 26.10.21 VLESS UDP -> SOCKS UDP tee -> sing-box 1.14 QUIC sniff -> same-IP AI/CN/default markers for routeOnly=false/true, plus controlled .10-to-.20 DNS readdress observations.", flush=True)
            print("LIMIT: the controlled RFC SNI is example.com with synthetic rule-set membership; no real domain-list membership, provider, VPN, or application result is claimed.", flush=True)
    finally:
        if tap is not None: tap.close()
        for server in locals().get("dns_servers", []):
            try:
                server[2].set(); server[0].close(); server[1].join(timeout=1)
            except Exception: pass
        if xray is not None: h.stop_process(xray)
        if sb is not None: h.stop_process(sb)
        for proc in reversed(children):
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=2)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=2)


if __name__ == "__main__":
    try: main()
    except subprocess.TimeoutExpired as exc:
        print(f"FAIL: bounded command timeout ({exc.cmd!r})", file=sys.stderr); raise SystemExit(1)
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        import traceback; traceback.print_exc(file=sys.stderr); raise SystemExit(1)
