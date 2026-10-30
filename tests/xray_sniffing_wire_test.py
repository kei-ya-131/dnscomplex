#!/usr/bin/env python3
"""Controlled Xray sniffing wire test; observes only the downstream SOCKS address.

Run on Linux with Xray available, e.g. on 192.168.50.180:
  timeout 60 python3 tests/xray_sniffing_wire_test.py --xray /usr/local/x-ui/bin/xray-linux-amd64

Uses a generated UUID, no certificate, loopback listeners, and a temporary
config. TLS cases stop at the controlled SOCKS sink; they do not claim an
application TLS handshake or website response succeeded.
"""
import argparse
import ipaddress
import json
import os
import pathlib
import queue
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import uuid


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def read_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise EOFError(f"peer closed with {size-len(chunks)} bytes pending")
        chunks.extend(part)
    return bytes(chunks)


def tls_client_hello(server_name):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname=server_name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    data = outgoing.read()
    if not data.startswith(b"\x16\x03"):
        raise RuntimeError("Python TLS stack did not generate a ClientHello")
    return data


def parse_socks_address(sock):
    ver, cmd, _rsv, atyp = read_exact(sock, 4)
    if ver != 5 or cmd != 1:
        raise ValueError(f"unexpected SOCKS request header: {(ver, cmd, atyp)}")
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, read_exact(sock, 4))
    elif atyp == 3:
        size = read_exact(sock, 1)[0]
        host = read_exact(sock, size).decode("ascii")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, read_exact(sock, 16))
    else:
        raise ValueError(f"unknown SOCKS ATYP {atyp}")
    port = struct.unpack("!H", read_exact(sock, 2))[0]
    return host, port


def socks_sink(listener, observations, stop):
    listener.settimeout(.2)
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        with conn:
            conn.settimeout(2)
            try:
                ver, nmethods = read_exact(conn, 2)
                methods = read_exact(conn, nmethods)
                if ver != 5 or 0 not in methods:
                    raise ValueError("Xray did not negotiate SOCKS5 no-auth")
                conn.sendall(b"\x05\x00")
                host, port = parse_socks_address(conn)
                observations.put((host, port))
                # Accept the outbound so Xray can complete its routing path;
                # the test makes no TLS/app-success assertion at this sink.
                conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
                try:
                    conn.recv(8192)
                except (TimeoutError, socket.timeout):
                    pass
            except (EOFError, OSError, ValueError) as exc:
                observations.put(exc)


def vless_request(identity, dest_port, dest_ip, payload):
    packed = ipaddress.ip_address(dest_ip).packed
    atyp = b"\x01" if len(packed) == 4 else b"\x04"
    header = b"\x00" + uuid.UUID(identity).bytes + b"\x00" + b"\x01" + struct.pack("!H", dest_port) + atyp + packed
    return header + payload


def vless_udp_request(identity, dest_port, dest_ip, payload):
    packed = ipaddress.ip_address(dest_ip).packed
    atyp = b"\x01" if len(packed) == 4 else b"\x04"
    header = b"\x00" + uuid.UUID(identity).bytes + b"\x00" + b"\x02" + struct.pack("!H", dest_port) + atyp + packed
    return header + struct.pack("!H", len(payload)) + payload


def send_udp_case(vless_port, identity, initial_ip, dest_port, payload, observations):
    with socket.create_connection(("127.0.0.1", vless_port), timeout=2) as conn:
        conn.settimeout(3)
        conn.sendall(vless_udp_request(identity, dest_port, initial_ip, payload))
        conn.shutdown(socket.SHUT_WR)
    result = observations.get(timeout=5)
    if isinstance(result, BaseException):
        raise result
    return result


def await_vless(vless_port, child, log):
    for _ in range(80):
        if child.poll() is not None:
            log.flush(); log.seek(0)
            raise RuntimeError("Xray exited during startup: " + log.read())
        try:
            with socket.create_connection(("127.0.0.1", vless_port), timeout=.1):
                return
        except OSError:
            time.sleep(.025)
    log.flush(); log.seek(0)
    raise RuntimeError("Xray VLESS listener did not become ready; log=" + log.read())


def xray_config(identity, vless_port, sink_port, dest_overrides, excluded=()):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "sniff-wire-vless", "listen": "127.0.0.1", "port": vless_port,
            "protocol": "vless",
            "settings": {"clients": [{"id": identity}], "decryption": "none"},
            "sniffing": {
                "enabled": True, "destOverride": dest_overrides, "routeOnly": False,
                "domainsExcluded": list(excluded),
            },
        }],
        "outbounds": [{"tag": "sink", "protocol": "socks", "settings": {
            "servers": [{"address": "127.0.0.1", "port": sink_port}],
        }}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["sniff-wire-vless"], "outboundTag": "sink"}]},
    }


def stop_xray(child):
    if child is not None and child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill(); child.wait()


def send_case(vless_port, identity, initial_ip, dest_port, payload, observations):
    with socket.create_connection(("127.0.0.1", vless_port), timeout=2) as conn:
        conn.settimeout(3)
        conn.sendall(vless_request(identity, dest_port, initial_ip, payload))
        conn.shutdown(socket.SHUT_WR)
    result = observations.get(timeout=4)
    if isinstance(result, BaseException):
        raise result
    return result


def parse_socks_udp_address(packet):
    if len(packet) < 4 or packet[:3] != b"\x00\x00\x00":
        raise ValueError("invalid SOCKS5 UDP relay header")
    atyp = packet[3]
    offset = 4
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, packet[offset:offset + 4]); offset += 4
    elif atyp == 3:
        size = packet[offset]; offset += 1
        host = packet[offset:offset + size].decode("ascii"); offset += size
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, packet[offset:offset + 16]); offset += 16
    else:
        raise ValueError(f"unknown SOCKS UDP ATYP {atyp}")
    port = struct.unpack("!H", packet[offset:offset + 2])[0]
    return host, port


class SocksUdpSink:
    """Loopback SOCKS5 UDP ASSOCIATE endpoint that records actual target headers."""
    def __init__(self):
        self.tcp = socket.socket()
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", 0)); self.tcp.listen(8)
        self.port = self.tcp.getsockname()[1]
        self.observations = queue.Queue()
        self.stop = threading.Event()
        self.threads = []
        self.accept_thread = threading.Thread(target=self._accept, daemon=True)
        self.accept_thread.start()

    def _accept(self):
        self.tcp.settimeout(.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            self.threads.append(thread); thread.start()

    def _serve(self, conn):
        relay = None
        with conn:
            conn.settimeout(3)
            try:
                ver, nmethods = read_exact(conn, 2)
                methods = read_exact(conn, nmethods)
                if ver != 5 or 0 not in methods:
                    raise ValueError("Xray did not negotiate SOCKS5 no-auth")
                conn.sendall(b"\x05\x00")
                ver, cmd, _rsv, atyp = read_exact(conn, 4)
                if (ver, cmd) != (5, 3):
                    raise ValueError(f"expected SOCKS5 UDP ASSOCIATE, got {(ver, cmd)}")
                if atyp == 1:
                    read_exact(conn, 4)
                elif atyp == 4:
                    read_exact(conn, 16)
                elif atyp == 3:
                    read_exact(conn, read_exact(conn, 1)[0])
                else:
                    raise ValueError(f"unknown UDP ASSOCIATE ATYP {atyp}")
                read_exact(conn, 2)  # requested port
                relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                relay.bind(("127.0.0.1", 0)); relay.settimeout(.2)
                relay_port = relay.getsockname()[1]
                conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", relay_port))
                while not self.stop.is_set():
                    try:
                        datagram, _peer = relay.recvfrom(65535)
                    except socket.timeout:
                        continue
                    self.observations.put(parse_socks_udp_address(datagram))
            except (EOFError, OSError, ValueError) as exc:
                self.observations.put(exc)
            finally:
                if relay is not None:
                    relay.close()

    def close(self):
        self.stop.set()
        self.tcp.close()
        self.accept_thread.join(timeout=1)
        for thread in self.threads:
            thread.join(timeout=1)


RFC9001_CLIENT_INITIAL = bytes.fromhex("""
    c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
    d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
    1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
    8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
    30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
    457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
    4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
    4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
    485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
    059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
    7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
    9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
    be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
    68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
    c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
    f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
    291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
    25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
    14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
    ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
    e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
    c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
    203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
    cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
    fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
    a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
    90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
    162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
    40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
    6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
    8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
    be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
    54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
    760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
    f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
    056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
    7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
    e221af44860018ab0856972e194cd934
""")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--xray", type=pathlib.Path, default=pathlib.Path("/usr/local/bin/xray"))
    args = parser.parse_args()
    if not args.xray.is_file() or not os.access(args.xray, os.X_OK):
        raise SystemExit(f"Xray executable not found or not executable: {args.xray}")

    identity = str(uuid.uuid4())
    initial_ip, dest_port = "192.0.2.77", 443
    vless_port, sink_port = free_port(), free_port()
    while sink_port == vless_port:
        sink_port = free_port()
    sink = socket.socket()
    sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sink.bind(("127.0.0.1", sink_port)); sink.listen(16)
    observations = queue.Queue()
    stop = threading.Event()
    sink_thread = threading.Thread(target=socks_sink, args=(sink, observations, stop), daemon=True)
    sink_thread.start()
    udp_sink = SocksUdpSink()
    child = None

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "sniff-wire-vless", "listen": "127.0.0.1", "port": vless_port,
            "protocol": "vless",
            "settings": {"clients": [{"id": identity}], "decryption": "none"},
            "sniffing": {
                "enabled": True, "destOverride": ["http", "tls"], "routeOnly": False,
                "domainsExcluded": ["full:c2c.cdn.wechat.com"],
            },
        }],
        "outbounds": [{"tag": "sink", "protocol": "socks", "settings": {
            "servers": [{"address": "127.0.0.1", "port": sink_port}],
        }}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["sniff-wire-vless"], "outboundTag": "sink"}]},
    }

    try:
        with tempfile.TemporaryDirectory(prefix="xray-sniff-wire-") as tempdir:
            config_path = pathlib.Path(tempdir) / "config.json"
            config_path.write_text(json.dumps(config))
            subprocess.run([str(args.xray), "run", "-test", "-format=json", "-config", str(config_path)],
                           check=True, capture_output=True, text=True, timeout=8)
            log_path = pathlib.Path(tempdir) / "xray.log"
            log = open(log_path, "w+")
            child = subprocess.Popen([str(args.xray), "run", "-config", str(config_path)], stdout=log, stderr=log)
            for _ in range(80):
                if child.poll() is not None:
                    log.flush(); log.seek(0)
                    raise RuntimeError("Xray exited during startup: " + log.read())
                try:
                    with socket.create_connection(("127.0.0.1", vless_port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.025)
            else:
                raise RuntimeError("Xray VLESS listener did not become ready")

            cases = [
                ("http-host-override", b"GET /probe HTTP/1.1\r\nHost: api.meituan.com\r\nConnection: close\r\n\r\n", "api.meituan.com"),
                ("http-exact-full-exclusion", b"GET /probe HTTP/1.1\r\nHost: c2c.cdn.wechat.com\r\nConnection: close\r\n\r\n", initial_ip),
                ("tls-sni-override", tls_client_hello("service.fixture.invalid"), "service.fixture.invalid"),
                ("tls-exact-full-exclusion", tls_client_hello("c2c.cdn.wechat.com"), initial_ip),
                ("tls-subdomain-not-excluded", tls_client_hello("edge.c2c.cdn.wechat.com"), "edge.c2c.cdn.wechat.com"),
                ("tls-no-sni-keeps-original-ip", tls_client_hello(None), initial_ip),
                ("tls-unknown-sni-is-literal-not-guessed", tls_client_hello("unlisted.fixture.invalid"), "unlisted.fixture.invalid"),
            ]
            mismatches = []
            for label, payload, expected in cases:
                observed, observed_port = send_case(vless_port, identity, initial_ip, dest_port, payload, observations)
                ok = observed == expected and observed_port == dest_port
                print(f"{label}: SOCKS target={observed}:{observed_port}, expected={expected}:{dest_port}, {'PASS' if ok else 'FAIL'}", flush=True)
                if not ok:
                    mismatches.append((label, observed, observed_port, expected))
            log.close()
            if mismatches:
                raise AssertionError(f"Xray sniff address mismatches: {mismatches!r}")
            print("PASS: Xray 26.x real VLESS ingress sniffed HTTP Host/TLS SNI with routeOnly=false; exact full exclusion preserved original IP; no-SNI preserved IP; unknown SNI was passed literally, not guessed. SOCKS target evidence only; TLS application success was not tested.", flush=True)

            # QUIC uses a separately configured real Xray process to verify the
            # observed production destOverride set; the only exclusion here is
            # a fictional example.com control, not a production exception.
            stop_xray(child); child = None
            quic_cases = [
                ("quic-initial-sni-override", (), RFC9001_CLIENT_INITIAL, "example.com"),
                ("quic-fictional-full-exclusion", ("full:example.com",), RFC9001_CLIENT_INITIAL, initial_ip),
                ("random-udp-keeps-original-ip", (), b"\x99\x88\x77\x66random-udp-fixture", initial_ip),
            ]
            for index, (label, excluded, payload, expected) in enumerate(quic_cases):
                quic_config = xray_config(
                    identity, vless_port, udp_sink.port,
                    ["http", "tls", "quic", "fakedns"], excluded,
                )
                config_path.write_text(json.dumps(quic_config))
                subprocess.run([str(args.xray), "run", "-test", "-format=json", "-config", str(config_path)],
                               check=True, capture_output=True, text=True, timeout=8)
                quic_log = open(pathlib.Path(tempdir) / f"xray-quic-{index}.log", "w+")
                child = subprocess.Popen([str(args.xray), "run", "-config", str(config_path)], stdout=quic_log, stderr=quic_log)
                await_vless(vless_port, child, quic_log)
                observed, observed_port = send_udp_case(vless_port, identity, initial_ip, dest_port, payload, udp_sink.observations)
                ok = observed == expected and observed_port == dest_port
                print(f"{label}: SOCKS UDP target={observed}:{observed_port}, expected={expected}:{dest_port}, {'PASS' if ok else 'FAIL'}", flush=True)
                stop_xray(child); child = None
                quic_log.close()
                if not ok:
                    raise AssertionError(f"{label}: observed {(observed, observed_port)!r}, expected {(expected, dest_port)!r}")
            print("PASS: real Xray VLESS UDP preserved UDP packet framing through SOCKS UDP; RFC 9001 Appendix A.2 Client Initial (1200 bytes, SNI example.com) was overridden to example.com; a fictional full:example.com exclusion preserved 192.0.2.77; random UDP preserved 192.0.2.77. This proves only controlled destination rewriting, not QUIC application success or a real provider connection.", flush=True)
    finally:
        stop_xray(child)
        stop.set()
        sink.close()
        sink_thread.join(timeout=1)
        udp_sink.close()


if __name__ == "__main__":
    main()
