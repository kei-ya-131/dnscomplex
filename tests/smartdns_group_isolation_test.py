#!/usr/bin/env python3
"""Regression: profile DNS upstreams must not answer default-group queries.

Run on a host with SmartDNS for the wire-level regression; no production
configuration, cache, nftset or services are touched.
"""
import argparse
import pathlib
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest


parser = argparse.ArgumentParser()
parser.add_argument("--installer", type=pathlib.Path,
                    default=pathlib.Path(__file__).resolve().parents[1] / "install.sh")
args = parser.parse_args()
source = args.installer.read_text()
start = source.index("smartdns_upstream_line() {")
end = source.index("\nsmartdns_static_address_line()", start)
helper = source[start:end]


def upstream_line(upstream, group):
    return subprocess.check_output(
        ["bash", "-c", helper + '\nsmartdns_upstream_line "$1" "$2"',
         "test", upstream, group], text=True)


class GroupIsolationTest(unittest.TestCase):
    def test_profile_upstreams_are_excluded_for_every_transport(self):
        for upstream in ("1.1.1.1", "tcp://1.1.1.1", "tls://dns.example",
                         "https://dns.example/dns-query", "h3://dns.example",
                         "quic://dns.example", "doq://dns.example"):
            for group in ("ai", "cn"):
                with self.subTest(upstream=upstream, group=group):
                    rendered = upstream_line(upstream, group).split()
                    self.assertIn("-group", rendered)
                    self.assertIn(group, rendered)
                    self.assertIn("-exclude-default-group", rendered)
            default_line = upstream_line(upstream, "default").split()
            self.assertNotIn("-group", default_line)
            self.assertNotIn("-exclude-default-group", default_line)

    @unittest.skipUnless(shutil.which("smartdns") and shutil.which("ss"),
                         "native SmartDNS and ss are required for DNS wire test")
    def test_default_upstream_line_sends_one_upstream_query(self):
        stop = threading.Event()
        query_ids = []
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.bind(("127.0.0.1", 0))
        peer.settimeout(.05)
        peer_port = peer.getsockname()[1]

        def serve():
            while not stop.is_set():
                try:
                    packet, client = peer.recvfrom(4096)
                except socket.timeout:
                    continue
                query_ids.append(struct.unpack_from("!H", packet)[0])
                pos = 12
                while packet[pos]:
                    pos += packet[pos] + 1
                question = packet[12:pos + 5]
                answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.77")
                response = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + answer
                peer.sendto(response, client)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        listen_port = listener.getsockname()[1]
        listener.close()
        try:
            with tempfile.TemporaryDirectory(prefix="dnscomplex-default-fanout-") as temp:
                config = pathlib.Path(temp) / "smartdns.conf"
                config.write_text(
                    "cache-size 0\ncache-persist no\nspeed-check-mode none\n"
                    f"bind 127.0.0.1:{listen_port} -group default\n"
                    + upstream_line(f"127.0.0.1:{peer_port}", "default")
                    + f"log-file {pathlib.Path(temp) / 'smartdns.log'}\n"
                )
                with open(pathlib.Path(temp) / "stdout.log", "w+") as log:
                    proc = subprocess.Popen([shutil.which("smartdns"), "-f", "-c", str(config), "-p", "-"],
                                            stdout=log, stderr=subprocess.STDOUT)
                    try:
                        for _ in range(100):
                            if proc.poll() is not None:
                                log.seek(0)
                                self.fail("isolated SmartDNS exited: " + log.read())
                            listening = subprocess.run(["ss", "-H", "-lun"], text=True,
                                                       capture_output=True, timeout=1).stdout
                            if f":{listen_port}" in listening:
                                break
                            time.sleep(.05)
                        else:
                            self.fail("private SmartDNS listener did not become ready")
                        query = (bytes.fromhex("734101000001000000000000")
                                 + b"\x06fanout\x07example\x00\x00\x01\x00\x01")
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                            client.settimeout(3)
                            client.sendto(query, ("127.0.0.1", listen_port))
                            response, _ = client.recvfrom(4096)
                        self.assertEqual(struct.unpack_from("!H", response)[0], 0x7341)
                        self.assertEqual(struct.unpack_from("!H", response, 6)[0], 1)
                        time.sleep(.2)
                        self.assertEqual(len(query_ids), 1, f"upstream query IDs: {query_ids}")
                    finally:
                        proc.terminate()
                        try:
                            proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
        finally:
            stop.set()
            thread.join(timeout=1)
            peer.close()

    @unittest.skipUnless(shutil.which("smartdns"), "SmartDNS is required for DNS wire test")
    def test_faster_cn_upstream_cannot_supply_default_answer(self):
        # The CN server wins the race if renderer forgets to isolate it.
        # Three controlled upstreams return distinct documentation addresses.
        stop = threading.Event()
        upstreams = []
        threads = []

        def serve(sock, address, delay):
            sock.settimeout(0.1)
            while not stop.is_set():
                try:
                    packet, client = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                pos = 12
                while packet[pos]:
                    pos += packet[pos] + 1
                question = packet[12:pos + 5]
                qtype = struct.unpack("!H", packet[pos + 1:pos + 3])[0]
                answer = b""
                if qtype == 1:
                    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
                response = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0) + question + answer
                time.sleep(delay)
                sock.sendto(response, client)

        try:
            for address, delay in (("192.0.2.10", .15), ("198.51.100.20", 0), ("203.0.113.30", .05)):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                upstreams.append(sock)
                thread = threading.Thread(target=serve, args=(sock, address, delay), daemon=True)
                thread.start()
                threads.append(thread)
            listeners = []
            for _ in range(3):
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    listeners.append(sock.getsockname()[1])
            with tempfile.TemporaryDirectory(prefix="dnscomplex-dns-test-") as temp:
                config = pathlib.Path(temp) / "smartdns.conf"
                config.write_text(
                    "cache-size 0\ncache-persist no\nspeed-check-mode none\nresponse-mode fastest-response\n"
                    + "".join(f"bind 127.0.0.1:{port} -group {group}\n"
                              for port, group in zip(listeners, ("default", "cn", "ai")))
                    + "".join(upstream_line(f"127.0.0.1:{sock.getsockname()[1]}", group)
                              for sock, group in zip(upstreams, ("default", "cn", "ai")))
                    # Production uses the same DoH endpoints in default and AI.
                    # Excluding the AI entry must preserve explicit default membership.
                    + upstream_line(f"127.0.0.1:{upstreams[0].getsockname()[1]}", "ai"))
                with open(pathlib.Path(temp) / "log", "w+") as log:
                    proc = subprocess.Popen([shutil.which("smartdns"), "-f", "-c", str(config), "-p", "-"],
                                            stdout=log, stderr=log)
                    try:
                        time.sleep(.3)
                        if proc.poll() is not None:
                            log.seek(0)
                            self.fail("isolated SmartDNS exited: " + log.read())
                        for port, expected in zip(listeners, ("192.0.2.10", "198.51.100.20", "203.0.113.30")):
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                                client.settimeout(3)
                                query = bytes.fromhex("123401000001000000000000") + b"\x09isolation\x07example\x00\x00\x01\x00\x01"
                                client.sendto(query, ("127.0.0.1", port))
                                response, _ = client.recvfrom(4096)
                                self.assertEqual(response[3] & 15, 0)
                                self.assertEqual(struct.unpack("!H", response[6:8])[0], 1)
                                self.assertEqual(socket.inet_ntoa(response[-4:]), expected)
                    finally:
                        proc.terminate()
                        try:
                            proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=1)
            for sock in upstreams:
                sock.close()


if __name__ == "__main__":
    unittest.main(argv=["smartdns_group_isolation_test.py"])
