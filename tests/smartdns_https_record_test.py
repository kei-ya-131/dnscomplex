#!/usr/bin/env python3
"""Check default-group HTTPS/AAAA behavior from the real SmartDNS renderer.

The wire case uses a private SmartDNS process, local listener ports and a
controlled UDP DNS peer. It never reads or changes the host SmartDNS config.
"""
import pathlib
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import os
import json
from collections import Counter


ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"
BASE_CONFIG = """\
DNSCOMPLEX_NONINTERACTIVE=1
WAN_IFACE=eth0
TRANSIT_VLAN_ID=10
LAN_VLAN_ID=20
ROUTEROS_TRANSIT_IPV4=10.255.10.1
LINUX_TRANSIT_IPV4=10.255.10.2
TRANSIT_IPV4_CIDR=10.255.10.2/30
ROUTEROS_TRANSIT_IPV6=fd00:10::1
LINUX_TRANSIT_IPV6=fd00:10::2
TRANSIT_IPV6_CIDR=fd00:10::2/64
LAN_IPV4_CIDR=192.168.88.1/24
LAN_DHCP_START=192.168.88.100
LAN_DHCP_END=192.168.88.250
LAN_IPV6_PREFIX=fd00:88::/64
SINGBOX_SOCKS_LISTEN=192.168.88.1
SINGBOX_SOCKS_PORT=2080
AI_IPSEC_USERNAME=ai-user
AI_IPSEC_PASSWORD=ai-pass
CN_IPSEC_USERNAME=cn-user
CN_IPSEC_PASSWORD=cn-pass
"""
DOMAIN = "https-record.fixture.test"
ALPN = b"\x02h3\x02h2"
IPV6_HINT = socket.inet_pton(socket.AF_INET6, "2001:db8::1234")


def encode_name(name):
    return b"".join(bytes((len(label),)) + label.encode("ascii")
                    for label in name.rstrip(".").split(".")) + b"\0"


def read_name(packet, offset):
    labels = []
    while True:
        size = packet[offset]
        offset += 1
        if size == 0:
            return ".".join(labels), offset
        if size & 0xC0:
            raise ValueError("fixture accepts uncompressed query names only")
        labels.append(packet[offset:offset + size].decode("ascii"))
        offset += size


def skip_name(packet, offset):
    while True:
        size = packet[offset]
        offset += 1
        if size == 0:
            return offset
        if size & 0xC0 == 0xC0:
            return offset + 1
        offset += size


def answer_records(packet):
    qd = struct.unpack_from("!H", packet, 4)[0]
    an = struct.unpack_from("!H", packet, 6)[0]
    offset = 12
    for _ in range(qd):
        offset = skip_name(packet, offset) + 4
    result = []
    for _ in range(an):
        offset = skip_name(packet, offset)
        rrtype, rrclass, ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        result.append((rrtype, packet[offset:offset + rdlength]))
        offset += rdlength
    return result


class ControlledDnsPeer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.query_types = Counter()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        self.sock.settimeout(.1)
        while not self.stop.is_set():
            try:
                query, client = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                _, end = read_name(query, 12)
                qtype, qclass = struct.unpack_from("!HH", query, end)
                self.query_types[qtype] += 1
                question = query[12:end + 4]
                rdata = b""
                if qtype == 65:
                    # HTTPS priority=1, target=".", ALPN h3/h2 and address hints.
                    rdata = (struct.pack("!H", 1) + b"\0"
                             + struct.pack("!HH", 1, len(ALPN)) + ALPN
                             + struct.pack("!HH", 4, 8)
                             + socket.inet_aton("192.0.2.80") + socket.inet_aton("192.0.2.81")
                             + struct.pack("!HH", 6, len(IPV6_HINT)) + IPV6_HINT)
                elif qtype == 28:
                    rdata = IPV6_HINT
                elif qtype == 1:
                    rdata = socket.inet_aton("192.0.2.19")
                answer = (b"\xc0\x0c" + struct.pack("!HHIH", qtype, qclass, 60, len(rdata)) + rdata
                          if rdata else b"")
                header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, int(bool(answer)), 0, 0)
                self.sock.sendto(header + question + answer, client)
            except (ValueError, IndexError, struct.error):
                continue

    def close(self):
        self.stop.set()
        self.thread.join(timeout=1)
        self.sock.close()


class SmartDnsHttpsRecordTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dnscomplex-https-record-")
        self.root = pathlib.Path(self.temp.name) / "root"
        self.config_path = pathlib.Path(self.temp.name) / "config.env"

    def tearDown(self):
        self.temp.cleanup()

    def render(self, mode):
        self.config_path.write_text(BASE_CONFIG + f"\nDEFAULT_IPV6_MODE={mode}\n")
        result = subprocess.run(
            ["bash", str(INSTALLER), "--dry-run", "--config", str(self.config_path)],
            cwd=ROOT, env=dict(os.environ, DNSCOMPLEX_ROOT=str(self.root)),
            text=True, capture_output=True, timeout=45,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return (self.root / "etc/smartdns/smartdns.conf").read_text()

    def test_renderer_limits_global_https_suppression_to_inactive_default_ipv6(self):
        active = self.render("on")
        inactive = self.render("off")
        self.assertNotIn("force-qtype-SOA 65", active)
        self.assertIn("force-qtype-SOA 65", inactive)
        self.assertIn("bind 127.0.0.1:6054 -group ai -force-aaaa-soa -nftset", active)
        self.assertIn("bind 127.0.0.1:6055 -group cn -force-aaaa-soa -nftset", active)
        self.assertIn("bind 127.0.0.1:6054 -group ai -force-aaaa-soa -nftset", inactive)
        self.assertIn("bind 127.0.0.1:6055 -group cn -force-aaaa-soa -nftset", inactive)
        singbox = json.loads((self.root / "etc/sing-box/config.json").read_text())
        dns_rules = singbox["dns"]["rules"]
        for rule_set in ("geosite-ai-support", "geosite-cn-video"):
            self.assertTrue(any(rule.get("rule_set") == rule_set
                                and rule.get("query_type") == ["HTTPS", "SVCB"]
                                and rule.get("action") == "reject"
                                for rule in dns_rules),
                            f"existing {rule_set} HTTPS/SVCB reject changed")

    @unittest.skipUnless(shutil.which("smartdns"), "SmartDNS binary required for wire verification")
    def test_private_smartdns_preserves_https_when_ipv6_is_active_and_suppresses_when_off(self):
        peer = ControlledDnsPeer()
        try:
            active = self.render("on")
            inactive = self.render("off")
            for mode, text, want_https, want_aaaa in (
                ("on", active, True, True),
                ("off", inactive, False, False),
            ):
                with self.subTest(mode=mode):
                    self.assertEqual(self.query_private(text, peer, 65, want_https), want_https)
                    self.assertEqual(self.query_private(text, peer, 28, want_aaaa), want_aaaa)
        finally:
            peer.close()

    def query_private(self, rendered, peer, qtype, want_answer):
        with tempfile.TemporaryDirectory(prefix="dnscomplex-smartdns-instance-") as temp:
            d = pathlib.Path(temp)
            ports = []
            reservations = []
            for _ in range(3):
                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                probe.bind(("127.0.0.1", 0))
                reservations.append(probe)
                ports.append(probe.getsockname()[1])
            for probe in reservations:
                probe.close()
            lines = []
            bind_index = 0
            for line in rendered.splitlines():
                if line.startswith("bind 127.0.0.1:"):
                    line = re.sub(r"127\.0\.0\.1:\d+", f"127.0.0.1:{ports[bind_index]}", line, count=1)
                    bind_index += 1
                    line = re.sub(r" -nftset \S+", "", line)
                    lines.append(line)
                elif re.match(r"^server(?:-https|-h3|-tls|-quic|-tcp)? ", line):
                    continue
                elif line.startswith("hosts-file "):
                    hosts = d / "empty-hosts"
                    hosts.write_text("")
                    lines.append(f"hosts-file {hosts}")
                elif line.startswith("address /-."):
                    # Drop installer-generated public static overrides so the
                    # controlled peer is the only source for this wire case.
                    continue
                elif line.startswith("cache-size "):
                    lines.append("cache-size 0")
                elif line.startswith("cache-persist "):
                    lines.append("cache-persist no")
                elif line.startswith("cache-file "):
                    lines.append(f"cache-file {d / 'cache'}")
                else:
                    lines.append(line)
            lines.append(f"server 127.0.0.1:{peer.port} -group default")
            lines.append("speed-check-mode none")
            lines.append(f"log-file {d / 'smartdns.log'}")
            config = d / "smartdns.conf"
            config_text = "\n".join(lines) + "\n"
            self.assertNotIn("/etc/", config_text)
            self.assertNotIn("/var/lib/", config_text)
            self.assertNotIn("/var/log/", config_text)
            self.assertNotIn("conf-file ", config_text)
            self.assertNotIn("include ", config_text)
            self.assertNotIn("address /-.", config_text)
            self.assertIn("speed-check-mode none", config_text)
            self.assertIn(f"log-file {d / 'smartdns.log'}", config_text)
            config.write_text(config_text)
            log_path = d / "smartdns.stdout.log"
            with log_path.open("w+") as log:
                proc = subprocess.Popen([shutil.which("smartdns"), "-f", "-c", str(config), "-p", "-"],
                                        stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 4
                    while True:
                        if proc.poll() is not None:
                            log.seek(0)
                            self.fail("private SmartDNS exited: " + log.read()[-2000:])
                        try:
                            response = self.dns_query(ports[0], qtype)
                            break
                        except socket.timeout:
                            if time.monotonic() > deadline:
                                log.seek(0)
                                sockets = subprocess.run(
                                    ["ss", "-H", "-lunp"], text=True,
                                    capture_output=True, timeout=2,
                                )
                                matching_sockets = [row for row in sockets.stdout.splitlines()
                                                    if any(f":{port}" in row for port in ports)]
                                binds = [line for line in config_text.splitlines()
                                         if line.startswith(("bind ", "server "))]
                                self.fail("private SmartDNS query timed out; "
                                          f"peer qtype counts={dict(peer.query_types)}; "
                                          f"bind/upstream={binds!r}; listener_sockets={matching_sockets!r}; "
                                          + log.read()[-2000:])
                    rows = answer_records(response)
                    matching = [rdata for rrtype, rdata in rows if rrtype == qtype]
                    if want_answer:
                        self.assertEqual(len(matching), 1, f"expected one type {qtype} answer, got {rows!r}")
                        if qtype == 65:
                            self.assertIn(ALPN, matching[0])
                            self.assertIn(socket.inet_aton("192.0.2.80"), matching[0])
                            self.assertIn(socket.inet_aton("192.0.2.81"), matching[0])
                            self.assertIn(IPV6_HINT, matching[0])
                        else:
                            self.assertEqual(matching[0], IPV6_HINT)
                        return True
                    self.assertEqual(matching, [], f"type {qtype} should be suppressed: {rows!r}")
                    return False
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=2)

    @staticmethod
    def dns_query(port, qtype):
        ident = 0x7341
        packet = (struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
                  + encode_name(DOMAIN) + struct.pack("!HH", qtype, 1))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(.35)
            client.sendto(packet, ("127.0.0.1", port))
            reply, _ = client.recvfrom(4096)
        if len(reply) < 12 or struct.unpack_from("!H", reply)[0] != ident:
            raise AssertionError("invalid DNS response from private SmartDNS")
        return reply


if __name__ == "__main__":
    unittest.main()
