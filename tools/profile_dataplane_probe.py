#!/usr/bin/env python3
"""Bounded, read-only TLS DoH check using explicit IPsec profile context.

The caller must include every site-specific reserved mark in reserved_marks.
This utility never chooses marks or changes routes, gates, or firewall state.
"""

import argparse
import errno
import ipaddress
import json
import math
import platform
import secrets
import socket
import ssl
import struct
import sys
import time


MAX_TIMEOUT = 5.0
MAX_CONNECT_ATTEMPTS = 3
CONNECT_ATTEMPT_TIMEOUT = 1.0
MAX_HTTP_HEADER_BYTES = 16 * 1024
MAX_DNS_MESSAGE_BYTES = 4096
SO_MARK = getattr(socket, "SO_MARK", 36)
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
PROFILE_MARKS = {"ai": 769, "cn": 849, "default": 8228}
APPROVED_PROBE_ENDPOINTS = {
    "ai": ("104.16.248.249", "cloudflare-dns.com", "openai.com"),
    "cn": ("223.6.6.6", "dns.alidns.com", "youku.com"),
}


class ProbeFailure(Exception):
    def __init__(self, phase, reason, **fields):
        super().__init__(reason)
        self.phase = phase
        self.reason = reason
        self.fields = fields


def _result(status, profile, phase, reason, started, clock, **fields):
    safe_profile = profile if profile in ("ai", "cn") else "unknown"
    elapsed_ms = max(0, int((clock() - started) * 1000))
    return {"status": status, "profile": safe_profile, "phase": phase,
            "reason": reason, "elapsed_ms": elapsed_ms, **fields}


def _remaining(deadline, clock, phase):
    value = deadline - clock()
    if value <= 0:
        raise ProbeFailure(phase, "deadline_exceeded")
    return value


def _close_socket(sock):
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass


def _normalize_domain(value, reason):
    if not isinstance(value, str) or not value or any(ch.isspace() for ch in value):
        raise ProbeFailure("arguments", reason)
    value = value.rstrip(".")
    if not value:
        raise ProbeFailure("arguments", reason)
    try:
        encoded = value.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        raise ProbeFailure("arguments", reason)
    if len(encoded) > 253:
        raise ProbeFailure("arguments", reason)
    labels = encoded.split(".")
    if any(not label or len(label) > 63 or label[0] == "-" or label[-1] == "-" or
           any(not (c.isascii() and (c.isalnum() or c == "-")) for c in label)
           for label in labels):
        raise ProbeFailure("arguments", reason)
    return encoded


def _validate_context(profile, mode, vip, device, probe_mark, resolver_ip, tls_name, query_domain, reserved_marks=()):
    if profile not in ("ai", "cn"):
        raise ProbeFailure("arguments", "profile_must_be_ai_or_cn")
    if mode == "xray":
        raise ProbeFailure("selection", "selected_egress_not_ipsec")
    if mode != "ipsec":
        raise ProbeFailure("arguments", "unsupported_egress_mode")
    if device != "ipsec-" + profile:
        raise ProbeFailure("selection", "profile_context_mismatch")
    try:
        source = ipaddress.ip_address(vip)
    except (ValueError, TypeError):
        raise ProbeFailure("arguments", "invalid_profile_vip")
    if (source.version != 4 or source.is_unspecified or source.is_loopback or
            source.is_multicast or source.is_link_local):
        raise ProbeFailure("arguments", "invalid_profile_vip")
    if isinstance(probe_mark, bool):
        raise ProbeFailure("arguments", "invalid_probe_identity")
    if not isinstance(probe_mark, int):
        raise ProbeFailure("arguments", "invalid_probe_identity")
    mark = probe_mark
    blocked_marks = set(PROFILE_MARKS.values())
    try:
        for value in reserved_marks:
            if isinstance(value, bool):
                raise ValueError
            reserved = int(value)
            if not isinstance(value, int) or not 0 < reserved <= 0xffffffff:
                raise ValueError
            blocked_marks.add(reserved)
    except (TypeError, ValueError, OverflowError):
        raise ProbeFailure("arguments", "invalid_probe_identity")
    if mark <= 0 or mark > 0x7fffffff or mark in blocked_marks:
        raise ProbeFailure("arguments", "invalid_probe_identity")
    try:
        destination = ipaddress.ip_address(resolver_ip)
    except (ValueError, TypeError):
        raise ProbeFailure("arguments", "invalid_resolver_address")
    if destination.version != 4 or not destination.is_global:
        raise ProbeFailure("arguments", "invalid_resolver_address")
    tls_host = _normalize_domain(tls_name, "invalid_tls_name")
    query = _normalize_domain(query_domain, "invalid_query_domain")
    try:
        ipaddress.ip_address(tls_host)
    except ValueError:
        pass
    else:
        raise ProbeFailure("arguments", "invalid_tls_name")
    try:
        ipaddress.ip_address(query)
    except ValueError:
        pass
    else:
        raise ProbeFailure("arguments", "invalid_query_domain")
    if (str(destination), tls_host, query) != APPROVED_PROBE_ENDPOINTS[profile]:
        raise ProbeFailure("selection", "unapproved_probe_endpoint")
    return str(source), mark, str(destination), tls_host, query


def _encode_dns_query(query_domain, txid):
    labels = query_domain.split(".")
    qname = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question, tuple(label.encode("ascii").lower() for label in labels)


def _read_dns_name(message, offset):
    labels = []
    position = offset
    next_offset = None
    visited = set()
    wire_length = 0
    while True:
        if position >= len(message) or position in visited:
            raise ProbeFailure("dns", "malformed_dns_name")
        visited.add(position)
        length = message[position]
        if length & 0xC0 == 0xC0:
            if position + 1 >= len(message):
                raise ProbeFailure("dns", "truncated_dns_name")
            pointer = ((length & 0x3F) << 8) | message[position + 1]
            if pointer >= position:
                raise ProbeFailure("dns", "malformed_dns_name")
            if next_offset is None:
                next_offset = position + 2
            position = pointer
            continue
        if length & 0xC0:
            raise ProbeFailure("dns", "malformed_dns_name")
        position += 1
        if length == 0:
            return tuple(labels), next_offset if next_offset is not None else position
        if length > 63 or position + length > len(message):
            raise ProbeFailure("dns", "truncated_dns_name")
        wire_length += length + 1
        if wire_length > 255:
            raise ProbeFailure("dns", "malformed_dns_name")
        labels.append(message[position:position + length].lower())
        position += length


def _verify_dns_response(message, txid, expected_question):
    if len(message) < 12 or len(message) > MAX_DNS_MESSAGE_BYTES:
        raise ProbeFailure("dns", "truncated_dns_message" if len(message) < 12 else "dns_message_too_large")
    response_id, flags, questions, answers, authorities, additional = struct.unpack_from("!HHHHHH", message, 0)
    if response_id != txid:
        raise ProbeFailure("dns", "transaction_id_mismatch")
    if not (flags & 0x8000) or flags & 0x7800 or flags & 0x0200:
        raise ProbeFailure("dns", "invalid_dns_response_flags")
    if flags & 0x000F:
        raise ProbeFailure("dns", "dns_rcode_nonzero")
    if questions != 1:
        raise ProbeFailure("dns", "invalid_question_count")
    question_name, offset = _read_dns_name(message, 12)
    if offset + 4 > len(message):
        raise ProbeFailure("dns", "truncated_dns_question")
    qtype, qclass = struct.unpack_from("!HH", message, offset)
    if question_name != expected_question or qtype != 1 or qclass != 1:
        raise ProbeFailure("dns", "question_mismatch")
    offset += 4

    answer_count = 0
    total_records = answers + authorities + additional
    if total_records > 256:
        raise ProbeFailure("dns", "too_many_dns_records")
    for index in range(total_records):
        _owner, offset = _read_dns_name(message, offset)
        if offset + 10 > len(message):
            raise ProbeFailure("dns", "truncated_dns_record")
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", message, offset)
        offset += 10
        end = offset + rdlength
        if end > len(message):
            raise ProbeFailure("dns", "truncated_dns_record")
        if index < answers and rtype == 1 and rclass == 1:
            if rdlength != 4:
                raise ProbeFailure("dns", "invalid_a_record")
            answer_count += 1
        offset = end
    if offset != len(message):
        raise ProbeFailure("dns", "trailing_dns_data")
    if answers == 0 or answer_count == 0:
        raise ProbeFailure("dns", "no_a_answer")
    return answer_count


def _read_http_response(sock, deadline, clock):
    header = bytearray()
    delimiter = b"\r\n\r\n"
    while not header.endswith(delimiter):
        if len(header) >= MAX_HTTP_HEADER_BYTES:
            raise ProbeFailure("http", "response_headers_too_large")
        sock.settimeout(_remaining(deadline, clock, "http"))
        try:
            chunk = sock.recv(1)
        except (socket.timeout, TimeoutError):
            raise ProbeFailure("http", "deadline_exceeded" if clock() >= deadline else "response_timeout")
        except OSError:
            raise ProbeFailure("http", "response_read_failed")
        if not chunk:
            raise ProbeFailure("http", "truncated_http_headers")
        header.extend(chunk)

    lines = bytes(header[:-4]).split(b"\r\n")
    try:
        status_line = lines[0].decode("ascii")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or parts[0] not in ("HTTP/1.0", "HTTP/1.1"):
            raise ValueError
        status = int(parts[1])
    except (UnicodeError, ValueError, IndexError):
        raise ProbeFailure("http", "invalid_http_status_line")
    if status != 200:
        raise ProbeFailure("http", "unexpected_http_status")

    headers = {}
    for line in lines[1:]:
        if not line or line[:1] in (b" ", b"\t") or b":" not in line:
            raise ProbeFailure("http", "invalid_http_header")
        name, value = line.split(b":", 1)
        try:
            key = name.decode("ascii").strip().lower()
            text = value.decode("ascii").strip()
        except UnicodeError:
            raise ProbeFailure("http", "invalid_http_header")
        if not key or key in headers:
            raise ProbeFailure("http", "duplicate_http_header")
        headers[key] = text
    if "transfer-encoding" in headers:
        raise ProbeFailure("http", "unsupported_http_transfer_encoding")
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/dns-message":
        raise ProbeFailure("http", "unexpected_http_content_type")
    content_length = headers.get("content-length", "")
    if not content_length.isdecimal():
        raise ProbeFailure("http", "invalid_http_content_length")
    body_size = int(content_length)
    if body_size > MAX_DNS_MESSAGE_BYTES:
        raise ProbeFailure("http", "response_body_too_large")
    if body_size < 12:
        raise ProbeFailure("http", "truncated_dns_message")
    body = bytearray()
    while len(body) < body_size:
        sock.settimeout(_remaining(deadline, clock, "http"))
        try:
            chunk = sock.recv(min(4096, body_size - len(body)))
        except (socket.timeout, TimeoutError):
            raise ProbeFailure("http", "deadline_exceeded" if clock() >= deadline else "response_timeout")
        except OSError:
            raise ProbeFailure("http", "response_read_failed")
        if not chunk:
            raise ProbeFailure("http", "truncated_http_body")
        body.extend(chunk)
    return bytes(body)


def _query_doh(sock, tls_name, query, expected_question, deadline, clock, txid):
    request = (
        f"POST /dns-query HTTP/1.1\r\nHost: {tls_name}\r\n"
        "Accept: application/dns-message\r\n"
        "Content-Type: application/dns-message\r\n"
        f"Content-Length: {len(query)}\r\nConnection: close\r\n\r\n"
    ).encode("ascii") + query
    sock.settimeout(_remaining(deadline, clock, "http"))
    try:
        sock.sendall(request)
    except (socket.timeout, TimeoutError):
        raise ProbeFailure("http", "deadline_exceeded" if clock() >= deadline else "request_send_timeout")
    except OSError:
        raise ProbeFailure("http", "request_send_failed")
    message = _read_http_response(sock, deadline, clock)
    _remaining(deadline, clock, "dns")
    return _verify_dns_response(message, txid, expected_question)


def run_probe(profile, mode, vip, device, probe_mark, resolver_ip, tls_name, query_domain,
              *, timeout=5.0, reserved_marks=(), is_linux=None, euid=None, monotonic=None,
              socket_factory=None, ssl_context_factory=None, id_factory=None):
    clock = monotonic or time.monotonic
    started = clock()
    try:
        budget = min(float(timeout), MAX_TIMEOUT)
    except (TypeError, ValueError, OverflowError):
        budget = MAX_TIMEOUT
    if not math.isfinite(budget) or budget <= 0:
        return _result("unsupported", profile, "arguments", "invalid_timeout", started, clock)
    deadline = started + budget
    try:
        source, mark, destination, tls_host, query_name = _validate_context(
            profile, mode, vip, device, probe_mark, resolver_ip, tls_name, query_domain, reserved_marks
        )
        linux = platform.system() == "Linux" if is_linux is None else bool(is_linux)
        root = (getattr(__import__("os"), "geteuid", lambda: -1)() == 0
                if euid is None else euid == 0)
        if not linux:
            raise ProbeFailure("platform", "linux_required")
        if not root:
            raise ProbeFailure("platform", "root_required")
        _remaining(deadline, clock, "connect")
        txid = int((id_factory or (lambda: secrets.randbelow(65536)))())
        if not 0 <= txid <= 65535:
            raise ProbeFailure("arguments", "invalid_transaction_id")
        query, expected_question = _encode_dns_query(query_name, txid)
        factory = socket_factory or socket.socket
        raw = None
        tls = None
        phase = "socket_setup"
        try:
            last_connect_failure = None
            connected = False
            attempt_limit = MAX_CONNECT_ATTEMPTS if profile == "cn" else 1
            for attempt in range(attempt_limit):
                phase = "socket_setup"
                raw = factory(socket.AF_INET, socket.SOCK_STREAM, 0)
                raw.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
                raw.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, device.encode("ascii") + b"\0")
                raw.bind((source, 0))
                phase = "connect"
                try:
                    remaining = _remaining(deadline, clock, "connect")
                except ProbeFailure:
                    if profile == "cn" and attempt:
                        raise ProbeFailure("connect", "deadline_exceeded", connect_attempts=attempt)
                    raise
                raw.settimeout(min(CONNECT_ATTEMPT_TIMEOUT, remaining) if profile == "cn" else remaining)
                try:
                    raw.connect((destination, 443))
                except (socket.timeout, TimeoutError):
                    if profile != "cn":
                        raise ProbeFailure("connect", "deadline_exceeded" if clock() >= deadline else
                                            "operation_timeout")
                    last_connect_failure = "connect_timeout"
                except OSError as exc:
                    if profile == "cn" and (isinstance(exc, ConnectionRefusedError) or
                                             exc.errno == errno.ECONNREFUSED):
                        last_connect_failure = "connect_refused"
                    elif profile == "cn" and exc.errno == errno.ETIMEDOUT:
                        last_connect_failure = "connect_timeout"
                    else:
                        raise ProbeFailure("connect", "deadline_exceeded" if clock() >= deadline else
                                            "connect_failed")
                else:
                    connected = True
                    break
                _close_socket(raw)
                raw = None
                attempts_made = attempt + 1
                if clock() >= deadline:
                    raise ProbeFailure("connect", "deadline_exceeded", connect_attempts=attempts_made)
                if attempt + 1 >= attempt_limit:
                    raise ProbeFailure("connect", "connect_attempts_exhausted",
                                       connect_attempts=attempts_made)
            if not connected:
                raise ProbeFailure("connect", last_connect_failure or "connect_failed")
            _remaining(deadline, clock, "tls")
            context = (ssl_context_factory or ssl.create_default_context)()
            phase = "tls"
            raw.settimeout(_remaining(deadline, clock, "tls"))
            tls = context.wrap_socket(raw, server_hostname=tls_host)
            raw = None
            _remaining(deadline, clock, "tls")
            phase = "http"
            answer_count = _query_doh(tls, tls_host, query, expected_question, deadline, clock, txid)
            return _result("pass", profile, "dns", "verified_doh_answer", started, clock,
                           answer_count=answer_count)
        except ProbeFailure:
            raise
        except ssl.SSLCertVerificationError:
            raise ProbeFailure("tls", "certificate_verification_failed")
        except ssl.SSLError:
            raise ProbeFailure("tls", "tls_handshake_failed")
        except (socket.timeout, TimeoutError):
            raise ProbeFailure(phase, "deadline_exceeded" if clock() >= deadline else "operation_timeout")
        except OSError:
            reason = "deadline_exceeded" if clock() >= deadline else ("tls_handshake_failed" if phase == "tls" else "socket_setup_failed" if phase == "socket_setup" else "connect_failed")
            raise ProbeFailure(phase, reason)
        finally:
            if tls is not None:
                try:
                    tls.close()
                except OSError:
                    pass
            if raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass
    except ProbeFailure as failure:
        unsupported = failure.reason in {
            "profile_must_be_ai_or_cn", "selected_egress_not_ipsec", "unsupported_egress_mode",
            "profile_context_mismatch", "unapproved_probe_endpoint", "invalid_profile_vip", "invalid_probe_identity",
            "invalid_resolver_address", "invalid_tls_name", "invalid_query_domain",
            "linux_required", "root_required",
        }
        return _result("unsupported" if unsupported else "fail", profile,
                       failure.phase, failure.reason, started, clock, **failure.fields)
    except Exception:
        return _result("fail", profile, "internal", "probe_error", started, clock)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("ai", "cn"), required=True)
    parser.add_argument("--mode", choices=("ipsec", "xray"), required=True)
    parser.add_argument("--vip", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--probe-mark", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--reserved-mark", action="append", default=[], type=lambda value: int(value, 0),
                        help="additional runtime marks that the probe identity must not reuse")
    parser.add_argument("--resolver-ip", required=True)
    parser.add_argument("--tls-name", required=True)
    parser.add_argument("--query-domain", required=True)
    parser.add_argument("--timeout", type=float, default=MAX_TIMEOUT)
    args = parser.parse_args(argv)
    result = run_probe(args.profile, args.mode, args.vip, args.device, args.probe_mark,
                       args.resolver_ip, args.tls_name, args.query_domain,
                       timeout=args.timeout, reserved_marks=args.reserved_mark)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
