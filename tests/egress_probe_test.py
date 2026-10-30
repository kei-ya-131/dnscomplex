import json
import pathlib
import struct
import socket
import threading
import tempfile
import time
import unittest
from unittest import mock


INSTALLER = pathlib.Path(__file__).parents[1] / "install.sh"
source = INSTALLER.read_text().split("<<'EGRESS_PROBE'\n", 1)[1].split("\nEGRESS_PROBE", 1)[0]
import types
probe = types.ModuleType("egress_probe")
exec(compile(source, "probe-egress.py", "exec"), probe.__dict__)


def config_for(ai_tag="ai-ipsec", ai_bind="ipsec-ai", vip="10.10.10.2"):
    outbounds = [{"tag": "default", "type": "direct"}]
    if ai_tag:
        ob = {"tag": ai_tag, "type": "direct"}
        if ai_bind:
            ob["bind_interface"] = ai_bind
        if vip:
            ob["inet4_bind_address"] = vip
        outbounds.append(ob)
    return {"outbounds": outbounds, "route": {
        "default_domain_resolver": {"server": "smartdns-default", "strategy": "ipv4_only"},
        "final": "default",
        "rules": [{"action": "route", "outbound": ai_tag}] if ai_tag else [],
    }}


def default_config(strategy="ipv4_only", outbound=None):
    return {"outbounds": [outbound or {"tag": "default", "type": "direct"}], "route": {
        "final": "default", "default_domain_resolver": {"server": "smartdns-default", "strategy": strategy},
        "rules": [],
    }}


def golden_abridged_frame(payload):
    assert len(payload) % 4 == 0 and len(payload) // 4 < 127
    return bytes([len(payload) // 4]) + payload


def golden_res_pq(nonce, *, constructor=0x05162463, auth_key_id=0, server_nonce=b"s" * 16,
                  pq=b"\x01\x03\x01", fingerprints=(0x0102030405060708,)):
    pq_tl = bytes([len(pq)]) + pq
    pq_tl += b"\0" * ((-len(pq_tl)) % 4)
    vector = struct.pack("<II", 0x1CB5C415, len(fingerprints))
    vector += b"".join(struct.pack("<Q", value) for value in fingerprints)
    data = struct.pack("<I", constructor) + nonce + server_nonce + pq_tl + vector
    header = struct.pack("<Q", auth_key_id) + b"\x04\0\0\0\0\0\0\0" + struct.pack("<I", len(data))
    return golden_abridged_frame(header + data)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class FakeSocket:
    def __init__(self, clock, *, connect_delay=0, recv_data=b"", send_error=None, connect_error=None):
        self.clock = clock
        self.connect_delay = connect_delay
        self.recv_data = bytearray(recv_data)
        self.send_error = send_error
        self.connect_error = connect_error
        self.options = []
        self.timeout = None

    def setsockopt(self, *args):
        self.options.append(args)

    def bind(self, address):
        self.bound = address

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.destination = address
        if self.connect_error:
            raise self.connect_error
        if self.connect_delay > (self.timeout or 0):
            self.clock.now += self.timeout
            raise socket.timeout()
        self.clock.now += self.connect_delay

    def sendall(self, data):
        self.sent = getattr(self, "sent", b"") + data
        if self.send_error:
            raise self.send_error

    def recv(self, size):
        if not self.recv_data:
            return b""
        chunk = bytes(self.recv_data[:size])
        del self.recv_data[:size]
        return chunk

    def close(self):
        pass


class ProbeTests(unittest.TestCase):
    def run_probe(self, *, config=None, socket_obj=None, **kwargs):
        config_path = pathlib.Path(self.temp.name) / "config.json"
        config_path.write_text(json.dumps(config or config_for()))
        resolver = kwargs.pop("resolver", lambda *args: ["203.0.113.10"])
        socket_factory = kwargs.pop("socket_factory", lambda *args: socket_obj)
        return probe.run_probe(
            profile=kwargs.pop("profile", "ai"), protocol=kwargs.pop("protocol", "tcp"), host="probe.invalid", port=443,
            timeout=5, config_path=str(config_path), is_linux=True, euid=0,
            monotonic=self.clock, socket_factory=socket_factory,
            resolver=resolver, **kwargs,
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.clock = FakeClock()

    def tearDown(self):
        self.temp.cleanup()

    def test_custom_runtime_marks_are_used_and_invalid_marks_fail_before_socket(self):
        for profile, mark in (("default", "12345"), ("ai", "0x601"), ("cn", "0x651")):
            with self.subTest(profile=profile), mock.patch.dict(probe.os.environ, {"DNSCOMPLEX_PROBE_" + profile.upper() + "_MARK": mark}):
                sock = FakeSocket(self.clock)
                config = default_config() if profile == "default" else config_for(ai_tag=profile + "-ipsec", ai_bind="ipsec-" + profile)
                result = self.run_probe(profile=profile, config=config, socket_obj=sock)
                self.assertEqual(result["status"], "pass")
                self.assertIn((socket.SOL_SOCKET, probe.SO_MARK, int(mark, 0)), sock.options)
        with mock.patch.dict(probe.os.environ, {"DNSCOMPLEX_PROBE_AI_MARK": "bad"}):
            factory = mock.Mock(side_effect=AssertionError("must not create a socket"))
            result = self.run_probe(socket_factory=factory)
            self.assertEqual(result["status"], "unsupported")
            self.assertEqual(result["reason"], "invalid_profile_mark")
            factory.assert_not_called()

    def test_total_deadline_includes_dns_and_socket_attempts(self):
        sock = FakeSocket(self.clock, connect_delay=4.6)

        def slow_dns(host, family, resolver, deadline, clock):
            clock.now += 0.6
            return ["203.0.113.10", "203.0.113.11"]

        result = self.run_probe(socket_obj=sock, resolver=slow_dns)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["phase"], "connect")
        self.assertEqual(result["reason"], "deadline_exceeded")
        self.assertLessEqual(self.clock.now, 5.000001)

    def test_udp_echo_requires_exact_nonce_echo(self):
        sock = FakeSocket(self.clock, recv_data=b"different nonce")
        result = self.run_probe(socket_obj=sock, protocol="udp-echo")
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["phase"], "udp_echo")
        self.assertEqual(result["reason"], "echo_mismatch")

    def test_mtproto_rejects_wrong_nonce_and_constructor(self):
        for response in (golden_res_pq(b"x" * 16), golden_res_pq(b"n" * 16, constructor=0xDEADBEEF)):
            sock = FakeSocket(self.clock, recv_data=response)
            result = self.run_probe(socket_obj=sock, protocol="mtproto", nonce_factory=lambda: b"n" * 16)
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["phase"], "mtproto")
            self.assertIn(result["reason"], {"nonce_mismatch", "unexpected_constructor"})

    def test_mtproto_rejects_nonzero_auth_key_id(self):
        nonce = b"n" * 16
        result = self.run_probe(socket_obj=FakeSocket(self.clock, recv_data=golden_res_pq(nonce, auth_key_id=1)),
                                protocol="mtproto", nonce_factory=lambda: nonce)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["reason"], "nonzero_auth_key_id")

    def test_mtproto_rejects_malformed_length(self):
        sock = FakeSocket(self.clock, recv_data=b"\x7f\x01\x04\x00")
        result = self.run_probe(socket_obj=sock, protocol="mtproto", nonce_factory=lambda: b"n" * 16)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["phase"], "mtproto")
        self.assertEqual(result["reason"], "invalid_frame_length")

    def test_mtproto_rejects_mismatched_message_data_length(self):
        nonce = b"n" * 16
        valid = golden_res_pq(nonce)
        message = bytearray(valid[1:])
        struct.pack_into("<I", message, 16, len(message))
        result = self.run_probe(socket_obj=FakeSocket(self.clock, recv_data=bytes([len(message) // 4]) + message),
                                protocol="mtproto", nonce_factory=lambda: nonce)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["reason"], "invalid_message_data_length")

    def test_mtproto_passes_only_after_valid_res_pq(self):
        nonce = b"r" * 16
        sock = FakeSocket(self.clock, recv_data=golden_res_pq(nonce))
        result = self.run_probe(socket_obj=sock, protocol="mtproto", nonce_factory=lambda: nonce)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["reason"], "res_pq_validated")
        request = bytes(sock.sent)
        self.assertEqual(request[:2], b"\xef\x0a")
        payload = request[2:]
        self.assertEqual(payload[:8], b"\0" * 8)
        self.assertNotEqual(payload[8:16], b"\0" * 8)
        self.assertEqual(struct.unpack_from("<Q", payload, 8)[0] & 3, 0)
        self.assertEqual(struct.unpack_from("<I", payload, 16)[0], 20)
        self.assertEqual(payload[20:24], bytes.fromhex("f18e7ebe"))
        self.assertEqual(payload[24:40], nonce)

    def test_selected_profile_applies_interface_vip_and_mark_without_reporting_vip(self):
        sock = FakeSocket(self.clock)
        result = self.run_probe(socket_obj=sock)
        self.assertEqual(result["status"], "pass")
        self.assertIn((socket.SOL_SOCKET, probe.SO_MARK, 769), sock.options)
        self.assertIn((socket.SOL_SOCKET, probe.SO_BINDTODEVICE, b"ipsec-ai\0"), sock.options)
        self.assertEqual(sock.bound, ("10.10.10.2", 0))
        self.assertNotIn("10.10.10.2", json.dumps(result))

    def test_xray_selected_mode_is_unsupported_without_fallback(self):
        cfg = config_for(ai_tag="ai-xray", ai_bind=None, vip=None)
        sock = FakeSocket(self.clock)
        result = self.run_probe(config=cfg, socket_obj=sock)
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["reason"], "selected_egress_not_ipsec")
        self.assertIsNone(getattr(sock, "bound", None))
        self.assertIsNone(getattr(sock, "sent", None))

    def test_mtproto_request_matches_golden_layout_against_socketpair_responder(self):
        nonce = b"n" * 16
        client_endpoint, server_endpoint = socket.socketpair()
        observed = {}

        def recv_exact(conn, size):
            chunks = bytearray()
            while len(chunks) < size:
                part = conn.recv(size - len(chunks))
                if not part:
                    raise AssertionError("client closed before complete MTProto request")
                chunks.extend(part)
            return bytes(chunks)

        def serve():
            try:
                observed["abridged"] = recv_exact(server_endpoint, 1)
                observed["frame_len"] = recv_exact(server_endpoint, 1)
                observed["request"] = recv_exact(server_endpoint, observed["frame_len"][0] * 4)
                server_endpoint.sendall(golden_res_pq(nonce))
            except Exception as exc:
                observed["error"] = repr(exc)
            finally:
                server_endpoint.close()

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()

        class LocalSocket:
            def __init__(self, *args):
                self.sock = client_endpoint

            def setsockopt(self, *args):
                pass

            def bind(self, *args):
                pass

            def settimeout(self, *args):
                self.sock.settimeout(*args)

            def connect(self, *args):
                pass

            def sendall(self, *args):
                self.sock.sendall(*args)

            def recv(self, *args):
                return self.sock.recv(*args)

            def close(self):
                self.sock.close()

        config_path = pathlib.Path(self.temp.name) / "config.json"
        config_path.write_text(json.dumps(config_for()))
        result = probe.run_probe("ai", "mtproto", "probe.invalid", 443, 5, str(config_path),
                                 is_linux=True, euid=0, monotonic=time.monotonic,
                                 socket_factory=LocalSocket, resolver=lambda *args: ["127.0.0.1"],
                                 nonce_factory=lambda: nonce)
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertNotIn("error", observed)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(observed["abridged"], b"\xef")
        self.assertEqual(observed["frame_len"], b"\x0a")
        request = observed["request"]
        self.assertEqual(request[:8], b"\0" * 8)
        self.assertNotEqual(request[8:16], b"\0" * 8)
        self.assertEqual(struct.unpack_from("<Q", request, 8)[0] & 3, 0)
        self.assertEqual(struct.unpack_from("<I", request, 16)[0], 20)
        self.assertEqual(request[20:24], bytes.fromhex("f18e7ebe"))
        self.assertEqual(request[24:40], nonce)

    def test_mtproto_rejects_truncated_res_pq_tl_body(self):
        nonce = b"n" * 16
        data = struct.pack("<I", 0x05162463) + nonce + b"s" * 16 + b"\x03\x01\0\0"
        message = b"\0" * 8 + b"\x04\0\0\0\0\0\0\0" + struct.pack("<I", len(data)) + data
        result = self.run_probe(socket_obj=FakeSocket(self.clock, recv_data=golden_abridged_frame(message)),
                                protocol="mtproto", nonce_factory=lambda: nonce)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["phase"], "mtproto")
        self.assertEqual(result["reason"], "truncated_res_pq")

    def test_default_preferred_ipv6_falls_back_to_ipv4_with_same_profile_mark(self):
        sock = FakeSocket(self.clock)
        families = []

        def resolver(host, family, port, deadline, clock):
            families.append((family, port))
            if family == socket.AF_INET6:
                return []
            return ["192.0.2.12"]

        result = self.run_probe(profile="default", config=default_config("prefer_ipv6"),
                                socket_obj=sock, resolver=resolver)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(families, [(socket.AF_INET6, 6053), (socket.AF_INET, 6053)])
        self.assertIn((socket.SOL_SOCKET, probe.SO_MARK, 8228), sock.options)
        self.assertNotIn((socket.SOL_SOCKET, probe.SO_BINDTODEVICE, b"ipsec-ai\0"), sock.options)
        self.assertIsNone(getattr(sock, "bound", None))

    def test_default_preferred_ipv6_falls_back_after_connect_failure(self):
        sockets = [FakeSocket(self.clock, connect_error=OSError("no ipv6 route")), FakeSocket(self.clock)]
        used = []

        def resolver(host, family, port, deadline, clock):
            used.append((family, port))
            return ["2001:db8::12"] if family == socket.AF_INET6 else ["192.0.2.12"]

        result = self.run_probe(profile="default", config=default_config("prefer_ipv6"), resolver=resolver,
                                socket_factory=lambda *args: sockets.pop(0))
        self.assertEqual(result["status"], "pass")
        self.assertEqual(used, [(socket.AF_INET6, 6053), (socket.AF_INET, 6053)])

    def test_default_outbound_honors_bind_interface_and_source_address(self):
        sock = FakeSocket(self.clock)
        outbound = {"tag": "default", "type": "direct", "bind_interface": "wan0",
                    "inet4_bind_address": "192.0.2.4"}
        result = self.run_probe(profile="default", config=default_config("ipv4_only", outbound), socket_obj=sock)
        self.assertEqual(result["status"], "pass")
        self.assertIn((socket.SOL_SOCKET, probe.SO_BINDTODEVICE, b"wan0\0"), sock.options)
        self.assertEqual(sock.bound, ("192.0.2.4", 0))

    def test_default_detour_and_unsafe_profile_vips_are_unsupported(self):
        for outbound in (
            {"tag": "default", "type": "direct", "detour": "proxy"},
            {"tag": "default", "type": "socks", "server": "127.0.0.1", "server_port": 1},
        ):
            sock = FakeSocket(self.clock)
            result = self.run_probe(profile="default", config=default_config("ipv4_only", outbound), socket_obj=sock)
            self.assertEqual(result["status"], "unsupported")
            self.assertIsNone(getattr(sock, "sent", None))
        for vip in ("0.0.0.0", "127.0.0.1", "224.0.0.1", "169.254.1.1"):
            sock = FakeSocket(self.clock)
            result = self.run_probe(config=config_for(vip=vip), socket_obj=sock)
            self.assertEqual(result["status"], "unsupported")
            self.assertNotIn(vip, json.dumps(result))
            self.assertIsNone(getattr(sock, "bound", None))

    def test_dig_uses_ipv4_loopback_transport_even_for_aaaa_query(self):
        class Completed:
            returncode = 0
            stdout = "2001:db8::1\n"

        with mock.patch.object(probe.subprocess, "run", return_value=Completed()) as run:
            addresses = probe._dig_resolver("probe.invalid", socket.AF_INET6, 6053, 10.0, lambda: 0.0)
        self.assertEqual(addresses, ["2001:db8::1"])
        self.assertEqual(run.call_args.args[0], ["dig", "+time=1", "+tries=1", "+short", "AAAA",
                                                 "probe.invalid", "@127.0.0.1", "-p", "6053"])


if __name__ == "__main__":
    unittest.main()
