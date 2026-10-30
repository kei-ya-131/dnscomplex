#!/usr/bin/env python3
"""Controlled Xray-to-sing-box sniffing wire test (HTTP Host/TLS SNI only).

Run on Linux 200 with explicit binary/config digests, for example:
  timeout 110 python3 tests/xray_to_singbox_sniff_wire_test.py \
    --xray /tmp/private/xray --xray-sha256 SHA256 \
    --sing-box /usr/bin/sing-box --sing-box-sha256 SHA256 \
    --config /etc/sing-box/config.json --config-sha256 SHA256

The live sing-box config is read locally and projected into a minimal temporary
config containing only the global sniff action, AI/CN domain route selectors,
and final default tag. No production credentials/endpoints are copied or
printed. All links, addresses, configs, nft state (none), and child processes
are confined to a private network namespace and cleaned up.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import queue
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid

DEST_IP = "192.0.2.10"
DEST_ALT_IP = "192.0.2.11"
PORT = 19443
VIP = {"default": "198.18.1.254", "ai": "10.250.1.22", "cn": "10.251.1.10"}
IFACE = {"default": "wire1h", "ai": "wire2h", "cn": "wire3h"}
GATEWAY = {"default": "198.18.1.2", "ai": "198.18.2.2", "cn": "198.18.3.2"}
TABLE = {"default": 3101, "ai": 3102, "cn": 3103}

P = argparse.ArgumentParser(description=__doc__)
P.add_argument("--xray", type=pathlib.Path, required=True)
P.add_argument("--xray-sha256", required=True)
P.add_argument("--sing-box", type=pathlib.Path, required=True)
P.add_argument("--sing-box-sha256", required=True)
P.add_argument("--config", type=pathlib.Path, required=True,
               help="200-local sing-box config; only route/sniff selector fields are used")
P.add_argument("--config-sha256", required=True)
P.add_argument("--isolated", action="store_true", help=argparse.SUPPRESS)
A = P.parse_args()


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify_input(path: pathlib.Path, expected: str, label: str) -> pathlib.Path:
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise SystemExit(f"{label} SHA256 must be 64 lowercase hex characters")
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or sha256(resolved) != expected:
        raise SystemExit(f"{label} SHA256 mismatch or not a regular file")
    return resolved


XRAY = verify_input(A.xray, A.xray_sha256, "Xray")
SING_BOX = verify_input(A.sing_box, A.sing_box_sha256, "sing-box")
CONFIG = verify_input(A.config, A.config_sha256, "sing-box config")


def mainpid() -> str | None:
    try:
        r = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", "sing-box"],
                           capture_output=True, text=True, timeout=3)
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip().isdigit() else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def active_mainpid() -> str | None:
    try:
        active = subprocess.run(["systemctl", "is-active", "--quiet", "sing-box"],
                                capture_output=True, timeout=3)
        pid = mainpid()
        return pid if active.returncode == 0 and pid is not None and int(pid) > 1 else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def config_projection(path: pathlib.Path, directory: pathlib.Path, socks_port: int,
                      dns_port: int) -> tuple[dict, dict[str, str]]:
    """Project only route/sniff selectors; never serialize source credentials."""
    try:
        src = json.loads(path.read_text())
        route = src["route"]
        source_rules = route["rules"]
    except Exception as exc:
        raise RuntimeError("could not parse the pinned sing-box routing config") from exc

    sniff = next((r for r in source_rules if r.get("action") == "sniff"), None)
    if sniff is None:
        raise RuntimeError("pinned config has no route sniff action")
    if sniff.get("inbound"):
        raise RuntimeError("sniff action is inbound-scoped; this fixture requires the observed global sniff rule")
    if not isinstance(src.get("dns"), dict) or not isinstance(src.get("outbounds"), list):
        raise RuntimeError("pinned config lacks expected DNS/outbound sections")

    # Recognize the actual selected profile outbound tags from domain rules.
    profile_routes: dict[str, list[dict]] = {"ai": [], "cn": []}
    profile_source_tags: dict[str, set[str]] = {"ai": set(), "cn": set()}
    def selector_tags(rule: dict) -> list[str]:
        value = rule.get("rule_set")
        if isinstance(value, str):
            return [value]
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return value
        return []

    for rule in source_rules:
        if rule.get("action") != "route" or not selector_tags(rule):
            continue
        rs = selector_tags(rule)
        outbound = rule.get("outbound")
        if any(tag.startswith("geosite-ai-") for tag in rs) and isinstance(outbound, str) and outbound.startswith("ai-"):
            profile = "ai"
        elif "geosite-cn-video" in rs and isinstance(outbound, str) and outbound.startswith("cn-"):
            profile = "cn"
        else:
            continue
        profile_routes[profile].append(rule)
        profile_source_tags[profile].add(outbound)
    if not profile_routes["ai"] or not profile_routes["cn"]:
        raise RuntimeError("pinned config lacks AI and CN-video domain route selectors")
    if route.get("final") != "default":
        raise RuntimeError("pinned config final outbound is not default")
    if any(len(tags) != 1 for tags in profile_source_tags.values()):
        raise RuntimeError("pinned config has ambiguous selected IPsec outbound tags")
    outbound_tags = {item.get("tag") for item in src["outbounds"] if isinstance(item, dict)}
    if "default" not in outbound_tags or any(next(iter(tags)) not in outbound_tags
                                               for tags in profile_source_tags.values()):
        raise RuntimeError("pinned config references an unavailable default/profile outbound")

    route_sets = route.get("rule_set", [])
    set_tags = {item.get("tag") for item in route_sets if isinstance(item, dict)}
    used_tags = {tag for group in profile_routes.values() for r in group for tag in selector_tags(r)}
    missing = used_tags - set_tags
    if missing:
        raise RuntimeError("pinned config route selector references a missing rule-set")

    # Create safe source-format rule sets with only controlled fixture names.
    fixture_sets = []
    ai_tags = {tag for r in profile_routes["ai"] for tag in selector_tags(r)}
    cn_tags = {tag for r in profile_routes["cn"] for tag in selector_tags(r)}
    for tag in sorted(used_tags):
        domains = []
        if tag in ai_tags:
            domains = ["ai.fixture.test"]
        elif tag in cn_tags:
            domains = ["video.fixture.test"]
        file = directory / f"{tag}.json"
        file.write_text(json.dumps({"version": 5, "rules": ([{"domain": domains}] if domains else [])}))
        file.chmod(0o600)
        fixture_sets.append({"type": "local", "tag": tag, "format": "source", "path": str(file)})

    # Preserve all route match selectors while replacing only profile outbounds.
    rules = [dict(sniff)]
    for rule in source_rules:
        if rule.get("action") == "route" and rule in profile_routes["ai"]:
            projected = {k: v for k, v in rule.items() if k not in ("outbound", "inbound")}
            if "inbound" in rule:
                raise RuntimeError("AI selector is inbound-scoped; refusing to broaden it in the fixture")
            projected.update({"action": "route", "outbound": "ai-exit"})
            rules.append(projected)
        elif rule.get("action") == "route" and rule in profile_routes["cn"]:
            projected = {k: v for k, v in rule.items() if k not in ("outbound", "inbound")}
            if "inbound" in rule:
                raise RuntimeError("CN selector is inbound-scoped; refusing to broaden it in the fixture")
            projected.update({"action": "route", "outbound": "cn-exit"})
            rules.append(projected)

    def direct(tag: str, profile: str) -> dict:
        return {"type": "direct", "tag": tag, "bind_interface": IFACE[profile],
                "inet4_bind_address": VIP[profile],
                "domain_resolver": {"server": "fixture-dns", "strategy": "ipv4_only"}}

    cfg = {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "wire-socks", "listen": "127.0.0.1",
                      "listen_port": socks_port}],
        "outbounds": [direct("default", "default"), direct("ai-exit", "ai"), direct("cn-exit", "cn")],
        "route": {"rules": rules, "rule_set": fixture_sets, "final": "default",
                  "default_domain_resolver": {"server": "fixture-dns", "strategy": "ipv4_only"}},
        "dns": {"servers": [{"type": "udp", "tag": "fixture-dns", "server": "127.0.0.1",
                               "server_port": dns_port}], "rules": [], "final": "fixture-dns"},
    }
    return cfg, {profile: next(iter(tags)) for profile, tags in profile_source_tags.items()}


def run(cmd: list[str], timeout: float = 5, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        # Commands are fixed tools with synthetic addresses; never dump configs.
        raise RuntimeError(f"command failed ({result.returncode}): {cmd!r}: {result.stderr[-1200:]}")
    return result


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def read_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise EOFError("peer closed early")
        data.extend(part)
    return bytes(data)


def tls_client_hello(server_name: str | None) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=server_name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    packet = outgoing.read()
    if not packet.startswith(b"\x16\x03"):
        raise RuntimeError("local TLS stack failed to build ClientHello")
    return packet


def vless_request(identity: str, dest_port: int, payload: bytes) -> bytes:
    packed = socket.inet_aton(DEST_IP)
    return b"\x00" + uuid.UUID(identity).bytes + b"\x00\x01" + struct.pack("!H", dest_port) + b"\x01" + packed + payload


class SocksTap:
    """Byte-preserving TCP tee; it observes but does not terminate SOCKS."""
    def __init__(self, upstream_port: int):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0)); self.listener.listen(16)
        self.port = self.listener.getsockname()[1]
        self.upstream_port = upstream_port
        self.targets: queue.Queue[tuple[str, int]] = queue.Queue()
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []
        self.accept_thread = threading.Thread(target=self._accept, daemon=True)
        self.accept_thread.start()

    @staticmethod
    def _parse_request(buf: bytearray):
        if len(buf) < 2:
            return None
        if buf[0] != 5:
            raise ValueError("Xray SOCKS client sent unexpected version")
        size = 2 + buf[1]
        if len(buf) < size + 4:
            return None
        ver, cmd, _rsv, atyp = buf[size:size + 4]
        if ver != 5 or cmd != 1:
            raise ValueError("expected Xray SOCKS CONNECT")
        pos = size + 4
        if atyp == 1:
            if len(buf) < pos + 4 + 2: return None
            host = socket.inet_ntoa(buf[pos:pos + 4]); pos += 4
        elif atyp == 3:
            if len(buf) < pos + 1: return None
            n = buf[pos]; pos += 1
            if len(buf) < pos + n + 2: return None
            host = bytes(buf[pos:pos + n]).decode("ascii"); pos += n
        elif atyp == 4:
            if len(buf) < pos + 16 + 2: return None
            host = socket.inet_ntop(socket.AF_INET6, buf[pos:pos + 16]); pos += 16
        else:
            raise ValueError("Xray SOCKS request has unsupported address type")
        return host, struct.unpack("!H", buf[pos:pos + 2])[0]

    def _accept(self):
        self.listener.settimeout(.2)
        while not self.stop.is_set():
            try: client, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError: break
            t = threading.Thread(target=self._serve, args=(client,), daemon=True)
            self.threads.append(t); t.start()

    def _serve(self, client: socket.socket):
        upstream = None
        try:
            upstream = socket.create_connection(("127.0.0.1", self.upstream_port), timeout=3)
            upstream.settimeout(None); client.settimeout(None)
            parsebuf = bytearray(); recorded = False
            def c2s():
                nonlocal recorded
                while True:
                    data = client.recv(65536)
                    if not data: break
                    if not recorded:
                        parsebuf.extend(data)
                        result = self._parse_request(parsebuf)
                        if result is not None:
                            self.targets.put(result); recorded = True
                    upstream.sendall(data)
                try: upstream.shutdown(socket.SHUT_WR)
                except OSError: pass
            def s2c():
                while True:
                    data = upstream.recv(65536)
                    if not data: break
                    client.sendall(data)
                try: client.shutdown(socket.SHUT_WR)
                except OSError: pass
            a = threading.Thread(target=c2s, daemon=True); b = threading.Thread(target=s2c, daemon=True)
            a.start(); b.start(); a.join(timeout=8); b.join(timeout=8)
        except (OSError, ValueError):
            pass
        finally:
            client.close()
            if upstream is not None: upstream.close()

    def close(self):
        self.stop.set(); self.listener.close(); self.accept_thread.join(timeout=1)
        for thread in self.threads: thread.join(timeout=1)


def wait_process(proc: subprocess.Popen, label: str):
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError(f"{label} exited before readiness (status {proc.returncode})")
        time.sleep(.02)
        # Startup readiness is confirmed by the first actual connection; this
        # loop merely catches an early process exit.
    if proc.poll() is not None:
        raise RuntimeError(f"{label} exited before readiness")


def stop_process(proc: subprocess.Popen | None):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try: proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait(timeout=2)


def dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0)); sock.settimeout(.2)
    stop = threading.Event()
    queries: list[str] = []
    def serve():
        while not stop.is_set():
            try: packet, peer = sock.recvfrom(4096)
            except socket.timeout: continue
            except OSError: break
            try:
                pos = 12; labels = []
                while packet[pos]:
                    n = packet[pos]; pos += 1
                    labels.append(packet[pos:pos+n].decode("ascii")); pos += n
                pos += 1
                qtype = struct.unpack("!H", packet[pos:pos+2])[0]
                name = ".".join(labels).lower(); queries.append(name)
                question = packet[12:pos+4]
                answer_ip = DEST_ALT_IP if name == "dns-alt.fixture.test" else DEST_IP
                answer = (b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04" + socket.inet_aton(answer_ip)) if qtype == 1 else b""
                counts = struct.pack("!HHHHH", 0x8180, 1, int(bool(answer)), 0, 0)
                sock.sendto(packet[:2] + counts + question + answer, peer)
            except Exception:
                continue
    thread = threading.Thread(target=serve, daemon=True); thread.start()
    return sock, thread, stop, queries


def main():
    if not A.isolated:
        if os.geteuid() != 0:
            raise SystemExit("run as root to create an isolated network namespace")
        xray_result = run([str(XRAY), "version"], timeout=5)
        sing_box_result = run([str(SING_BOX), "version"], timeout=5)
        xray_version = (xray_result.stdout.strip() or xray_result.stderr.strip()).splitlines()[0]
        sing_box_version = (sing_box_result.stdout.strip() or sing_box_result.stderr.strip()).splitlines()[0]
        if "26.9.9" not in xray_version or "1.14.0" not in sing_box_version:
            raise SystemExit("binary version mismatch: expected Xray 26.9.9 and sing-box 1.14.0")
        print(f"PINNED: Xray={xray_version}; sing-box={sing_box_version}; config-sha256={A.config_sha256}", flush=True)
        outer_hash = sha256(CONFIG)
        outer_pid = active_mainpid()
        if outer_pid is None:
            raise SystemExit("host sing-box is not active or MainPID cannot be verified")
        cmd = ["unshare", "--net", sys.executable, str(pathlib.Path(__file__).resolve()),
               "--isolated", "--xray", str(XRAY), "--xray-sha256", A.xray_sha256,
               "--sing-box", str(SING_BOX), "--sing-box-sha256", A.sing_box_sha256,
               "--config", str(CONFIG), "--config-sha256", A.config_sha256]
        result = subprocess.Popen(cmd, start_new_session=True)
        try:
            returncode = result.wait(timeout=108)
        except subprocess.TimeoutExpired:
            try: os.killpg(result.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try: result.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try: os.killpg(result.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                result.wait(timeout=2)
            raise SystemExit("isolated wire test exceeded 108-second total budget")
        if returncode:
            raise SystemExit(returncode)
        if sha256(CONFIG) != outer_hash or active_mainpid() != outer_pid:
            raise SystemExit("host guard changed: sing-box config digest or MainPID differs")
        print(f"HOST_GUARD: sing-box-config-sha256={outer_hash}; MainPID={outer_pid or 'unavailable'} unchanged", flush=True)
        return

    children: list[subprocess.Popen] = []
    xray: subprocess.Popen | None = None
    sb: subprocess.Popen | None = None
    tap: SocksTap | None = None
    dns_sock = None
    dns_thread = None
    dns_stop = None
    dns_queries: list[str] = []
    try:
        if os.geteuid() != 0:
            raise RuntimeError("isolated runner lost root privileges")
        if sha256(XRAY) != A.xray_sha256 or sha256(SING_BOX) != A.sing_box_sha256 or sha256(CONFIG) != A.config_sha256:
            raise RuntimeError("pinned input SHA256 changed before isolated execution")
        run(["ip", "link", "set", "lo", "up"])
        peers = {}
        for idx, profile in enumerate(("default", "ai", "cn"), 1):
            proc = subprocess.Popen(["unshare", "--net", "sleep", "115"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(proc)
            for _ in range(150):
                try:
                    if os.readlink(f"/proc/{proc.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                        break
                except OSError: pass
                time.sleep(.01)
            else: raise RuntimeError("could not create isolated egress peer namespace")
            ns = ["nsenter", "-t", str(proc.pid), "-n"]
            left, right = f"wire{idx}h", f"wire{idx}p"
            run(["ip", "link", "add", left, "type", "veth", "peer", "name", right])
            run(["ip", "link", "set", right, "netns", str(proc.pid)])
            host = f"198.18.{idx}.1"; remote = GATEWAY[profile]
            run(["ip", "addr", "add", host + "/24", "dev", left]); run(["ip", "link", "set", left, "up"])
            run(ns + ["ip", "link", "set", "lo", "up"])
            run(ns + ["ip", "addr", "add", remote + "/24", "dev", right]); run(ns + ["ip", "link", "set", right, "up"])
            run(ns + ["ip", "addr", "add", DEST_IP + "/32", "dev", "lo"])
            run(ns + ["ip", "addr", "add", DEST_ALT_IP + "/32", "dev", "lo"])
            vip = VIP[profile]
            run(["ip", "addr", "add", vip + "/32", "dev", left])
            run(ns + ["ip", "route", "add", vip + "/32", "via", host])
            table = TABLE[profile]
            run(["ip", "rule", "add", "priority", str(3100 + idx), "from", vip + "/32", "table", str(table)])
            run(["ip", "route", "add", f"198.18.{idx}.0/24", "dev", left, "table", str(table)])
            run(["ip", "route", "add", "default", "via", remote, "dev", left, "table", str(table)])
            route = run(["ip", "route", "get", DEST_IP, "from", vip]).stdout
            if f"dev {left}" not in route:
                raise RuntimeError(f"VIP source route did not select controlled {profile} peer")
            peers[profile] = (proc, ns, left, remote)

        responder = r'''import socket,sys,threading
body=sys.argv[1].encode()
def serve_listener(ip):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((ip,19443));s.listen(64)
 while True:
  c,_=s.accept()
  def serve(c):
   with c:
    c.settimeout(2)
    try:
     c.recv(8192); src=c.getpeername()[0]; dst=c.getsockname()[0]; payload=body+b"|"+src.encode()+b"|"+dst.encode()
     c.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "+str(len(payload)).encode()+b"\r\n\r\n"+payload)
    except OSError: pass
  threading.Thread(target=serve,args=(c,),daemon=True).start()
for ip in ("192.0.2.10","192.0.2.11"):
 threading.Thread(target=serve_listener,args=(ip,),daemon=True).start()
threading.Event().wait()
'''
        compile(responder, "<controlled-marker-peer>", "exec")
        for profile, (_, ns, _iface, _remote) in peers.items():
            p = subprocess.Popen(ns + ["python3", "-u", "-c", responder, profile],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(p); time.sleep(.04)

        with tempfile.TemporaryDirectory(prefix="xray-sb-sniff-") as temp:
            d = pathlib.Path(temp); os.chmod(d, 0o700)
            sb_port, xray_port = free_port(), free_port()
            dns_sock, dns_thread, dns_stop, dns_queries = dns_server()
            cfg, actual_tags = config_projection(CONFIG, d, sb_port, dns_sock.getsockname()[1])
            config_file = d / "sing-box.json"
            config_file.write_text(json.dumps(cfg)); config_file.chmod(0o600)
            run([str(SING_BOX), "check", "-c", str(config_file)], timeout=8)
            sb = subprocess.Popen([str(SING_BOX), "run", "-c", str(config_file)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(sb); wait_process(sb, "sing-box")
            # Actual SOCKS handshake is forwarded byte-for-byte to sing-box.
            tap = SocksTap(sb_port)
            ident = str(uuid.uuid4())

            def start_xray(route_only: bool):
                nonlocal xray
                stop_process(xray); xray = None
                xcfg = {"log": {"loglevel": "error"},
                        "inbounds": [{"tag": "wire-vless", "listen": "127.0.0.1", "port": xray_port,
                                      "protocol": "vless", "settings": {"clients": [{"id": ident}], "decryption": "none"},
                                      "sniffing": {"enabled": True,
                                                   "destOverride": ["http", "tls", "quic", "fakedns"],
                                                   "metadataOnly": False, "routeOnly": route_only,
                                                   "domainsExcluded": ["full:c2c.cdn.wechat.com"]}}],
                        "outbounds": [{"tag": "to-sing-box", "protocol": "socks", "settings": {
                            "servers": [{"address": "127.0.0.1", "port": tap.port}]}}],
                        "routing": {"rules": [{"type": "field", "inboundTag": ["wire-vless"],
                                                  "outboundTag": "to-sing-box"}]}}
                path = d / ("xray-routeonly-true.json" if route_only else "xray-routeonly-false.json")
                path.write_text(json.dumps(xcfg)); path.chmod(0o600)
                run([str(XRAY), "run", "-test", "-format=json", "-config", str(path)], timeout=8)
                xray = subprocess.Popen([str(XRAY), "run", "-config", str(path)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                children.append(xray)
                for _ in range(100):
                    if xray.poll() is not None: raise RuntimeError("isolated Xray exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", xray_port), timeout=.05): return
                    except OSError: time.sleep(.02)
                raise RuntimeError("isolated Xray VLESS listener did not become ready")

            def request(label: str, payload: bytes, expected_target: str, expected_profile: str,
                        expected_destination: str = DEST_IP):
                with socket.create_connection(("127.0.0.1", xray_port), timeout=3) as client:
                    client.settimeout(5)
                    client.sendall(vless_request(ident, PORT, payload))
                    ver, addon_len = read_exact(client, 2)
                    if ver != 0: raise AssertionError(f"unexpected VLESS response version for {label}")
                    if addon_len: read_exact(client, addon_len)
                    response = bytearray()
                    while True:
                        try: chunk = client.recv(4096)
                        except socket.timeout: break
                        if not chunk: break
                        response.extend(chunk)
                        if b"\r\n\r\n" in response and expected_profile.encode() in response: break
                try: target = tap.targets.get(timeout=3)
                except queue.Empty: raise AssertionError(f"SOCKS target observation missing for {label}")
                host, port = target
                body = bytes(response)
                want_body = (expected_profile + "|" + VIP[expected_profile] + "|" + expected_destination).encode()
                if host != expected_target or port != PORT:
                    raise AssertionError(f"{label}: Xray->SOCKS target {host}:{port}, expected {expected_target}:{PORT}")
                if want_body not in body:
                    raise AssertionError(f"{label}: selected exit/body/source mismatch; expected {want_body.decode()} marker")
                print(f"{label}: socks_target={host}:{port}; exit={expected_profile}; source={VIP[expected_profile]} PASS", flush=True)

            testcases = [
                ("meituan-http", b"GET / HTTP/1.1\r\nHost: api.meituan.com\r\nConnection: close\r\n\r\n", "api.meituan.com", "default"),
                ("wechat-http", b"GET / HTTP/1.1\r\nHost: weixin.fixture.test\r\nConnection: close\r\n\r\n", "weixin.fixture.test", "default"),
                ("c2c-exact-http", b"GET / HTTP/1.1\r\nHost: c2c.cdn.wechat.com\r\nConnection: close\r\n\r\n", DEST_IP, "default"),
                ("ai-http", b"GET / HTTP/1.1\r\nHost: ai.fixture.test\r\nConnection: close\r\n\r\n", "ai.fixture.test", "ai"),
                ("cn-video-http", b"GET / HTTP/1.1\r\nHost: video.fixture.test\r\nConnection: close\r\n\r\n", "video.fixture.test", "cn"),
                ("dns-alternate-ip", b"GET / HTTP/1.1\r\nHost: dns-alt.fixture.test\r\nConnection: close\r\n\r\n", "dns-alt.fixture.test", "default", DEST_ALT_IP),
                ("unknown-tls-sni", tls_client_hello("unlisted.fixture.invalid"), "unlisted.fixture.invalid", "default"),
                ("tls-no-sni", tls_client_hello(None), DEST_IP, "default"),
            ]
            for route_only in (False, True):
                start_xray(route_only)
                label = "routeOnly=true" if route_only else "routeOnly=false"
                print(f"MODE {label}; metadataOnly=false; Xray profile tags={actual_tags}", flush=True)
                for name, payload, target, profile, *alternate in testcases:
                    egress_destination = alternate[0] if alternate and not route_only else DEST_IP
                    request(label + "/" + name, payload, target if not route_only else DEST_IP,
                            profile, egress_destination)
                    if name == "dns-alternate-ip" and not route_only:
                        deadline = time.monotonic() + 2
                        while time.monotonic() < deadline and not any(
                                q.rstrip(".") == "dns-alt.fixture.test" for q in dns_queries):
                            time.sleep(.02)
                        if not any(q.rstrip(".") == "dns-alt.fixture.test" for q in dns_queries):
                            raise AssertionError("controlled DNS alternate-IP case did not query fixture DNS")

            if sha256(CONFIG) != A.config_sha256:
                raise RuntimeError("pinned sing-box config changed during isolated run")
            print("PASS: actual Xray 26.9.9 VLESS sniffing ingress -> byte-preserving SOCKS tee -> actual sing-box 1.14 SOCKS/global sniff -> same-IP VIP-bound default/AI/CN marker exits.", flush=True)
            print("LIMIT: profile membership uses controlled synthetic rule-set contents; live domain-list membership, IPsec/IKE, REALITY/Vision, remote provider, UDP/QUIC, and app success are unverified.", flush=True)
            dns_stop.set(); dns_sock.close(); dns_thread.join(timeout=1)
    finally:
        if dns_sock is not None:
            try:
                if dns_stop is not None: dns_stop.set()
                dns_sock.close()
                if dns_thread is not None: dns_thread.join(timeout=1)
            except Exception: pass
        if tap is not None: tap.close()
        stop_process(xray); stop_process(sb)
        for proc in reversed(children):
            stop_process(proc)


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired as exc:
        print(f"FAIL: bounded command timeout ({exc.cmd!r})", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        raise SystemExit(1)
