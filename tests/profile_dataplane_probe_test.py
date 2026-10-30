import importlib.util
import errno
import json
import pathlib
import socket
import ssl
import struct
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("profile_dataplane_probe", ROOT / "tools/profile_dataplane_probe.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)

QUESTION = b"\x06openai\x03com\x00\x00\x01\x00\x01"
WRONG_QUESTION = b"\x07example\x03com\x00\x00\x01\x00\x01"
CN_QUESTION = b"\x05youku\x03com\x00\x00\x01\x00\x01"


def dns_response(request, *, question=QUESTION, txid=None, answer=b"\xcb\x00\x71\x09", flags=0x8180):
    request_id = request[:2] if txid is None else txid
    header = request_id + struct.pack("!HHHHH", flags, 1, 1, 0, 0)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + answer
    return header + question + rr


class FakePeer:
    def __init__(self, *, mode="response", response_builder=dns_response):
        self.mode = mode
        self.response_builder = response_builder
        self.request_body = None
        self.http_request = None

    def make_response(self, request):
        self.http_request = request
        headers, body = request.split(b"\r\n\r\n", 1)
        self.request_body = body
        if self.mode == "eof-headers":
            return b""
        if self.mode == "oversized-header":
            return b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 20000
        if self.mode == "oversized-body":
            return (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                    b"Content-Length: 999999\r\n\r\n")
        if self.mode == "eof-body":
            return (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                    b"Content-Length: 100\r\n\r\nshort")
        payload = self.response_builder(body)
        return (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                + b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                + b"Connection: close\r\n\r\n" + payload)


class FakeSocket:
    def __init__(self, peer, records, *, connect_error=None):
        self.peer = peer
        self.records = records
        self.connect_error = connect_error
        self.response = b""
        self.offset = 0
        self.closed = False

    def setsockopt(self, level, option, value):
        self.records.append(("setsockopt", level, option, value))

    def bind(self, address):
        self.records.append(("bind", address))

    def settimeout(self, timeout):
        self.records.append(("timeout", timeout))

    def connect(self, address):
        self.records.append(("connect", address))
        if self.connect_error is not None:
            raise self.connect_error

    def sendall(self, data):
        self.records.append(("sendall", len(data)))
        self.response = self.peer.make_response(data)

    def recv(self, size):
        result = self.response[self.offset:self.offset + size]
        self.offset += len(result)
        return result

    def close(self):
        self.closed = True


class FakeTLSContext:
    def __init__(self, records, *, fail=False):
        self.records = records
        self.fail = fail

    def wrap_socket(self, sock, *, server_hostname):
        self.records.append(("tls_sni", server_hostname))
        if self.fail:
            raise ssl.SSLCertVerificationError("must not leak certificate details")
        return sock


class StepClock:
    def __init__(self, step):
        self.value = 0.0
        self.step = step

    def __call__(self):
        value = self.value
        self.value += self.step
        return value


class AdvancingClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class TimedOutSocket(FakeSocket):
    def __init__(self, records, clock):
        super().__init__(FakePeer(), records)
        self.clock = clock
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout
        self.records.append(("timeout", timeout))

    def connect(self, address):
        self.records.append(("connect", address))
        self.clock.advance(self.timeout)
        raise socket.timeout("synthetic timeout")


class ProfileDataplaneProbeTest(unittest.TestCase):
    def call_probe(self, peer, *, profile="ai", mode="ipsec", timeout=2, tls_fail=False,
                   clock=None, socket_factory=None):
        records = []
        context = FakeTLSContext(records, fail=tls_fail)
        result = probe.run_probe(
            profile=profile,
            mode=mode,
            vip="10.250.1.22" if profile == "ai" else "10.251.1.10",
            device="ipsec-" + profile,
            probe_mark=0x3A1 if profile == "ai" else 0x3F1,
            resolver_ip="104.16.248.249" if profile == "ai" else "223.6.6.6",
            tls_name="cloudflare-dns.com" if profile == "ai" else "dns.alidns.com",
            query_domain="openai.com" if profile == "ai" else "youku.com",
            timeout=timeout,
            is_linux=True,
            euid=0,
            socket_factory=socket_factory or (lambda *_args: FakeSocket(peer, records)),
            ssl_context_factory=lambda: context,
            monotonic=clock,
            id_factory=lambda: 0x5A3C,
        )
        return result, records

    def test_connect_timeout_retries_with_fresh_socket_then_completes_doh(self):
        peer = FakePeer(response_builder=lambda request: dns_response(request, question=CN_QUESTION))
        sockets = []
        socket_records = []
        def factory(*_args):
            records = []
            socket_records.append(records)
            sock = FakeSocket(peer, records,
                connect_error=socket.timeout("synthetic timeout") if not sockets else None)
            sockets.append(sock)
            return sock
        result, _ = self.call_probe(peer, profile="cn", socket_factory=factory)
        self.assertEqual((result["status"], result["phase"], result["answer_count"]),
                         ("pass", "dns", 1))
        self.assertEqual(len(sockets), 2)
        self.assertTrue(sockets[0].closed)
        self.assertTrue(all(sock.closed for sock in sockets))
        for records in socket_records:
            self.assertIn(("setsockopt", socket.SOL_SOCKET, probe.SO_MARK, 0x3F1), records)
            self.assertIn(("setsockopt", socket.SOL_SOCKET, probe.SO_BINDTODEVICE, b"ipsec-cn\x00"), records)
            self.assertIn(("bind", ("10.251.1.10", 0)), records)
            self.assertIn(("connect", ("223.6.6.6", 443)), records)

    def test_connect_timeout_retries_are_three_max_one_second_and_within_total_budget(self):
        peer = FakePeer()
        sockets = []
        def factory(*_args):
            sock = FakeSocket(peer, [], connect_error=socket.timeout("synthetic timeout"))
            sockets.append(sock)
            return sock
        result, records = self.call_probe(peer, profile="cn", timeout=5, socket_factory=factory)
        self.assertEqual((result["status"], result["profile"], result["phase"], result["reason"]),
                         ("fail", "cn", "connect", "connect_attempts_exhausted"))
        self.assertEqual(result["connect_attempts"], 3)
        self.assertEqual(len(sockets), 3)
        per_attempt = [r[1] for s in sockets for r in s.records if r[0] == "timeout"]
        self.assertEqual(len(per_attempt), 3)
        self.assertLessEqual(max(per_attempt), 1.0)
        self.assertLessEqual(result["elapsed_ms"], 5000)
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_connect_retry_duration_stays_below_five_second_global_deadline(self):
        clock = AdvancingClock()
        sockets = []
        def factory(*_args):
            sock = TimedOutSocket([], clock)
            sockets.append(sock)
            return sock
        result, _ = self.call_probe(FakePeer(), profile="cn", timeout=5, clock=clock, socket_factory=factory)
        timeouts = [sock.timeout for sock in sockets]
        self.assertEqual(len(sockets), 3)
        self.assertLessEqual(max(timeouts), 1.0)
        self.assertLessEqual(sum(timeouts), 3.0)
        self.assertLessEqual(clock.value, 3.0)
        self.assertLessEqual(result["elapsed_ms"], 3000)
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_ai_connect_keeps_single_attempt_and_full_remaining_timeout(self):
        sockets = []
        def factory(*_args):
            sock = FakeSocket(FakePeer(), [], connect_error=socket.timeout("synthetic timeout"))
            sockets.append(sock)
            return sock
        result, _ = self.call_probe(FakePeer(), profile="ai", timeout=4, socket_factory=factory)
        self.assertEqual((result["status"], result["phase"], result["reason"]),
                         ("fail", "connect", "operation_timeout"))
        self.assertEqual(len(sockets), 1)
        timeout = next(entry[1] for entry in sockets[0].records if entry[0] == "timeout")
        self.assertGreater(timeout, 1.0)
        self.assertLessEqual(timeout, 4.0)
        self.assertTrue(sockets[0].closed)

    def test_global_deadline_expiry_is_distinct_from_attempts_exhaustion(self):
        clock = AdvancingClock()
        sockets = []
        def factory(*_args):
            sock = TimedOutSocket([], clock)
            sockets.append(sock)
            return sock
        result, _ = self.call_probe(FakePeer(), profile="cn", timeout=2, clock=clock, socket_factory=factory)
        self.assertEqual((result["status"], result["phase"], result["reason"]),
                         ("fail", "connect", "deadline_exceeded"))
        self.assertEqual(result["connect_attempts"], 2)
        self.assertEqual(result["elapsed_ms"], 2000)

    def test_connection_refused_retries_but_other_connect_oserror_does_not(self):
        for exc, expected_attempts, expected_reason in (
                (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), 3, "connect_attempts_exhausted"),
                (OSError(errno.ENETUNREACH, "unreachable"), 1, "connect_failed")):
            sockets = []
            def factory(*_args):
                sock = FakeSocket(FakePeer(), [], connect_error=exc)
                sockets.append(sock)
                return sock
            result, _ = self.call_probe(FakePeer(), profile="cn", socket_factory=factory)
            self.assertEqual((result["status"], result["phase"], result["reason"]),
                             ("fail", "connect", expected_reason))
            self.assertEqual(len(sockets), expected_attempts)
            self.assertTrue(all(sock.closed for sock in sockets))

    def test_tls_and_dns_failures_do_not_retry_connect(self):
        sockets = []
        active_peer = [FakePeer()]
        def factory(*_args):
            sock = FakeSocket(active_peer[0], [])
            sockets.append(sock)
            return sock
        tls_result, _ = self.call_probe(FakePeer(), tls_fail=True, socket_factory=factory)
        self.assertEqual((tls_result["phase"], tls_result["reason"]),
                         ("tls", "certificate_verification_failed"))
        self.assertEqual(len(sockets), 1)
        sockets.clear()
        dns_peer = FakePeer(response_builder=lambda _request: b"\x00" * 11)
        active_peer[0] = dns_peer
        dns_result, _ = self.call_probe(dns_peer, socket_factory=factory)
        self.assertEqual((dns_result["phase"], dns_result["reason"]),
                         ("http", "truncated_dns_message"))
        self.assertEqual(len(sockets), 1)

    def test_valid_doh_query_checks_tls_name_dns_question_and_socket_context(self):
        peer = FakePeer()
        result, records = self.call_probe(peer)
        self.assertEqual((result["status"], result["phase"], result["answer_count"]),
                         ("pass", "dns", 1))
        expected_query = b"\x5a\x3c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + QUESTION
        self.assertEqual(peer.request_body, expected_query)
        self.assertIn(("tls_sni", "cloudflare-dns.com"), records)
        self.assertIn(("bind", ("10.250.1.22", 0)), records)
        self.assertIn(("setsockopt", socket.SOL_SOCKET, probe.SO_BINDTODEVICE, b"ipsec-ai\x00"), records)
        self.assertIn(("setsockopt", socket.SOL_SOCKET, probe.SO_MARK, 0x3A1), records)
        output = json.dumps(result)
        for secret in ("10.250.1.22", "104.16.248.249", "cloudflare-dns.com", "0x3a1"):
            self.assertNotIn(secret, output)

    def test_xray_mode_returns_unsupported_before_socket_creation(self):
        opened = []
        result = probe.run_probe("ai", "xray", "10.250.1.22", "ipsec-ai", 0x3A1,
                                 "104.16.248.249", "cloudflare-dns.com", "openai.com",
                                 is_linux=True, euid=0,
                                 socket_factory=lambda *args: opened.append(args))
        self.assertEqual((result["status"], result["reason"]),
                         ("unsupported", "selected_egress_not_ipsec"))
        self.assertEqual(opened, [])

    def test_truncated_and_malformed_dns_messages_fail(self):
        result, _ = self.call_probe(FakePeer(response_builder=lambda _request: b"\x00" * 11))
        self.assertEqual((result["status"], result["phase"], result["reason"]),
                         ("fail", "http", "truncated_dns_message"))
        result, _ = self.call_probe(FakePeer(response_builder=lambda request: dns_response(request)[:-2]))
        self.assertEqual((result["status"], result["phase"]), ("fail", "dns"))

    def test_wrong_question_and_transaction_id_fail(self):
        cases = (
            (lambda request: dns_response(request, question=WRONG_QUESTION), "question_mismatch"),
            (lambda request: dns_response(request, txid=b"\xff\xff"), "transaction_id_mismatch"),
        )
        for builder, reason in cases:
            result, _ = self.call_probe(FakePeer(response_builder=builder))
            self.assertEqual((result["status"], result["reason"]), ("fail", reason))

    def test_bad_rcode_and_answer_record_fail(self):
        def self_referential_answer(request):
            message = dns_response(request)
            return message[:29] + b"\xc0\x1d" + message[31:]

        cases = (
            (lambda request: dns_response(request, flags=0x8183), "dns_rcode_nonzero"),
            (lambda request: dns_response(request, answer=b"\x01\x02"), "truncated_dns_record"),
            (self_referential_answer, "malformed_dns_name"),
        )
        for builder, reason in cases:
            result, _ = self.call_probe(FakePeer(response_builder=builder))
            self.assertEqual((result["status"], result["reason"]), ("fail", reason))

    def test_certificate_verification_failure_is_redacted(self):
        result, _ = self.call_probe(FakePeer(), tls_fail=True)
        self.assertEqual((result["status"], result["phase"], result["reason"]),
                         ("fail", "tls", "certificate_verification_failed"))
        self.assertNotIn("must not leak", json.dumps(result))

    def test_http_eof_and_oversized_header_or_body_fail(self):
        cases = (("eof-headers", "truncated_http_headers"),
                 ("eof-body", "truncated_http_body"),
                 ("oversized-header", "response_headers_too_large"),
                 ("oversized-body", "response_body_too_large"))
        for mode, reason in cases:
            result, _ = self.call_probe(FakePeer(mode=mode))
            self.assertEqual((result["status"], result["phase"], result["reason"]),
                             ("fail", "http", reason))

    def test_single_monotonic_deadline_covers_all_phases(self):
        result, records = self.call_probe(FakePeer(), timeout=5, clock=StepClock(0.7))
        self.assertEqual(result["status"], "fail")
        self.assertEqual((result["phase"], result["reason"]), ("http", "deadline_exceeded"))
        self.assertTrue(any(record[0] == "sendall" for record in records))

    def test_timeout_argument_is_capped_to_five_seconds(self):
        result, records = self.call_probe(FakePeer(), timeout=20)
        self.assertEqual(result["status"], "pass")
        timeouts = [entry[1] for entry in records if entry[0] == "timeout"]
        self.assertTrue(timeouts)
        self.assertLessEqual(max(timeouts), 5.0)

    def test_unapproved_endpoint_and_custom_mark_collision_fail_closed(self):
        opened = []
        endpoint = probe.run_probe("ai", "ipsec", "10.250.1.22", "ipsec-ai", 0x3A1,
                                   "223.6.6.6", "dns.alidns.com", "youku.com",
                                   is_linux=True, euid=0,
                                   socket_factory=lambda *args: opened.append(args))
        self.assertEqual((endpoint["status"], endpoint["reason"]),
                         ("unsupported", "unapproved_probe_endpoint"))
        mark = probe.run_probe("ai", "ipsec", "10.250.1.22", "ipsec-ai", 0x3A1,
                               "104.16.248.249", "cloudflare-dns.com", "openai.com",
                               reserved_marks=(0x3A1,), is_linux=True, euid=0,
                               socket_factory=lambda *args: opened.append(args))
        self.assertEqual((mark["status"], mark["reason"]),
                         ("unsupported", "invalid_probe_identity"))
        self.assertEqual(opened, [])

    def test_profile_context_mismatch_and_reused_production_mark_fail_closed(self):
        opened = []
        cases = (
            ("ipsec", "ipsec-cn", 0x3A1, "profile_context_mismatch"),
            ("ipsec", "ipsec-ai", 769, "invalid_probe_identity"),
        )
        for mode, device, mark, reason in cases:
            result = probe.run_probe("ai", mode, "10.250.1.22", device, mark,
                                     "104.16.248.249", "cloudflare-dns.com", "openai.com",
                                     is_linux=True, euid=0,
                                     socket_factory=lambda *args: opened.append(args))
            self.assertEqual((result["status"], result["reason"]), ("unsupported", reason))
        reserved = probe.run_probe("ai", "ipsec", "10.250.1.22", "ipsec-ai", 0x3A1,
                                   "104.16.248.249", "cloudflare-dns.com", "openai.com",
                                   reserved_marks=(0x3A1,), is_linux=True, euid=0,
                                   socket_factory=lambda *args: opened.append(args))
        self.assertEqual((reserved["status"], reserved["reason"]),
                         ("unsupported", "invalid_probe_identity"))
        self.assertEqual(opened, [])


if __name__ == "__main__":
    unittest.main()
