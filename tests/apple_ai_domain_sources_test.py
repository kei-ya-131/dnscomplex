#!/usr/bin/env python3
"""Apple AI endpoints stay narrowly classified by the existing AI support set.

The installer dry-run exercises the real render path. The extracted runtime
manager then syncs and compiles the real support source list; only sing-box's
binary SRS compiler is stubbed so the test can inspect its JSON input.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest


REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / "install.sh"
_options = []
NATIVE_SRS = False
SING_BOX_BIN = None
_skip_next = False
for _index, _arg in enumerate(sys.argv[1:]):
    if _skip_next:
        _skip_next = False
        continue
    if _arg == "--native-srs":
        NATIVE_SRS = True
    elif _arg == "--sing-box":
        if _index + 2 > len(sys.argv) - 1:
            raise SystemExit("--sing-box requires a binary path")
        SING_BOX_BIN = sys.argv[_index + 2]
        _skip_next = True
    elif _arg.startswith("--sing-box="):
        SING_BOX_BIN = _arg.split("=", 1)[1]
    else:
        _options.append(_arg)
sys.argv = [sys.argv[0], *_options]
APPLE_TYPED_SOURCES = {
    "full:guzzoni.apple.com",
    "domain:smoot.apple.com",
    "full:apple-relay.cloudflare.com",
    "full:apple-relay.fastly-edge.com",
    "full:cp4.cloudflare.com",
    "full:apple-relay.apple.com",
}
APPLE_EXACT = {
    "guzzoni.apple.com",
    "apple-relay.cloudflare.com",
    "apple-relay.fastly-edge.com",
    "cp4.cloudflare.com",
    "apple-relay.apple.com",
}
CN_VIDEO_SOURCES = {
    "acfun", "bilibili", "douyin", "douyu", "gitv", "hunantv", "huya",
    "iqiyi", "kuaishou", "le", "pptv", "youku", "wasu", "v.qq.com",
    "video.qq.com", "tencentvideo.com", "cibntv.net",
}


class AppleAIDomainSources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native_binary = None
        cls.native_decompile_output_flag = None
        if NATIVE_SRS:
            binary = SING_BOX_BIN or shutil.which("sing-box")
            if not binary:
                raise RuntimeError("--native-srs needs sing-box on PATH or --sing-box=/path/to/sing-box")
            cls.native_binary = str(Path(binary).resolve())
            help_text = cls._sing_box_help("rule-set")
            if "compile" not in help_text or "decompile" not in help_text:
                raise RuntimeError("sing-box rule-set help does not advertise compile and decompile")
            compile_help = cls._sing_box_help("rule-set", "compile")
            decompile_help = cls._sing_box_help("rule-set", "decompile")
            if "--output" not in compile_help:
                raise RuntimeError("sing-box compile help lacks the --output flag used by runtime")
            if "--output" in decompile_help:
                cls.native_decompile_output_flag = "--output"
            elif "-o" in decompile_help:
                cls.native_decompile_output_flag = "-o"
            else:
                raise RuntimeError("sing-box decompile help exposes no output flag")

        cls.temp = tempfile.TemporaryDirectory(prefix="dnscomplex-apple-ai-sources-")
        cls.addClassCleanup(cls.temp.cleanup)
        base = Path(cls.temp.name)
        cls.root = base / "root"
        cls.config = base / "config.env"
        cls.manager = cls.root / "usr/local/sbin/dnscomplex"
        cls.config.write_text("""DNSCOMPLEX_NONINTERACTIVE=1
DEPLOY_MODE=routeros-policy
WAN_IFACE=eth0
ROUTEROS_LAN_IPV4=192.168.50.253
LINUX_LAN_IPV4=192.168.50.200
LAN_CLIENT_IPV4_CIDR=192.168.50.0/24
SINGBOX_SOCKS_LISTEN=192.168.50.200
SINGBOX_SOCKS_PORT=10800
AI_IPSEC_USERNAME=fixture-ai
AI_IPSEC_PASSWORD=fixture-ai-pass
CN_IPSEC_USERNAME=fixture-cn
CN_IPSEC_PASSWORD=fixture-cn-pass
AI_EGRESS_MODE=ipsec
CN_EGRESS_MODE=ipsec
AI_SUPPORT_DOMAINS=meta.ai
""")
        result = subprocess.run(
            ["bash", str(INSTALLER), "--dry-run", "--config", str(cls.config)],
            env={**os.environ, "DNSCOMPLEX_ROOT": str(cls.root)},
            capture_output=True,
            text=True,
            timeout=45,
        )
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def _sing_box_help(cls, *args):
        result = subprocess.run(
            [cls.native_binary, *args, "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode:
            raise RuntimeError(
                f"sing-box {' '.join(args)} --help failed: {result.stdout}{result.stderr}"
            )
        return result.stdout + result.stderr

    def test_renderer_keeps_exact_apple_ai_sources_with_custom_support_domain(self):
        geosite = self.root / "var/lib/dnscomplex/geosite"
        sources = set((geosite / "ai-support.sources").read_text().split())
        self.assertEqual(sources & APPLE_TYPED_SOURCES, APPLE_TYPED_SOURCES)
        self.assertIn("meta.ai", sources)
        ai_domains = set((self.root / "etc/dnscomplex/ai.domains").read_text().split())
        self.assertTrue(APPLE_EXACT | {"smoot.apple.com"} <= ai_domains)

        config = json.loads((self.root / "etc/sing-box/config.json").read_text())
        support_sets = [
            item for item in config["route"]["rule_set"]
            if item.get("tag") == "geosite-ai-support"
        ]
        self.assertEqual(len(support_sets), 1)
        routes = [
            rule for rule in config["route"]["rules"]
            if rule.get("rule_set") == "geosite-ai-support" and rule.get("action") == "route"
        ]
        self.assertEqual([rule.get("outbound") for rule in routes], ["ai-ipsec"])

        # Apple coverage must remain host-scoped; unrelated Apple/iCloud/CDN
        # services and the CN-video classifier retain their existing boundary.
        for rule in config["route"]["rules"]:
            for key in ("domain", "domain_suffix", "domain_keyword", "domain_regex"):
                values = rule.get(key, [])
                if isinstance(values, str):
                    values = [values]
                self.assertFalse(
                    set(values) & {"apple.com", "icloud.com", "cloudflare.com", "fastly.com"},
                    (key, values),
                )
        cn_sources = set((geosite / "cn-video.sources").read_text().split())
        self.assertEqual(cn_sources, CN_VIDEO_SOURCES)
        cn_routes = [
            rule for rule in config["route"]["rules"]
            if rule.get("action") == "route" and rule.get("outbound") == "cn-ipsec"
        ]
        self.assertEqual([rule.get("rule_set") for rule in cn_routes], ["geosite-cn-video"])

    def test_runtime_source_sync_keeps_apple_endpoints_with_user_domains(self):
        geosite = self.root / "var/lib/dnscomplex/geosite"
        script = r'''set -euo pipefail
source "$DNSCOMPLEX_TEST_MANAGER"
load_config
sync_geosite_sources_from_config
'''
        result = subprocess.run(
            ["bash", "-c", script],
            env={
                **os.environ,
                "DNSCOMPLEX_FS_ROOT": str(self.root),
                "DNSCOMPLEX_TEST_MANAGER": str(self.manager),
            },
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        sources = set((geosite / "ai-support.sources").read_text().split())
        self.assertEqual(sources & APPLE_TYPED_SOURCES, APPLE_TYPED_SOURCES)
        self.assertIn("meta.ai", sources)
        ai_domains = set((self.root / "etc/dnscomplex/ai.domains").read_text().split())
        self.assertTrue(APPLE_EXACT | {"smoot.apple.com"} <= ai_domains)

    def test_runtime_compiler_preserves_full_vs_suffix_semantics(self):
        geosite = self.root / "var/lib/dnscomplex/geosite"
        fakebin = Path(self.temp.name) / "bin"
        fakebin.mkdir(exist_ok=True)
        if self.native_binary:
            compiler = fakebin / "sing-box"
            compiler.symlink_to(self.native_binary)
        else:
            compiler = fakebin / "sing-box"
            compiler.write_text("""#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == rule-set && "$2" == compile && "$3" == --output ]]
cp -- "$5" "$4"
""")
            compiler.chmod(0o700)
        (geosite / "ai-support.sources").write_text(
            "\n".join(sorted(APPLE_TYPED_SOURCES | {"meta.ai"})) + "\n"
        )
        script = r'''set -euo pipefail
source "$DNSCOMPLEX_TEST_MANAGER"
load_config
compile_profile ai-support "$GEO_DIR/ai-support.sources" "$GEO_DIR/ai-support.custom"
'''
        result = subprocess.run(
            ["bash", "-c", script],
            env={
                **os.environ,
                "DNSCOMPLEX_FS_ROOT": str(self.root),
                "DNSCOMPLEX_TEST_MANAGER": str(self.manager),
                "PATH": f"{fakebin}:{os.environ.get('PATH', '')}",
            },
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        self.assertEqual(set((geosite / "ai-support.exact").read_text().split()), APPLE_EXACT)
        self.assertEqual(
            set((geosite / "ai-support.suffix").read_text().split()),
            {"meta.ai", "smoot.apple.com"},
        )
        self.assertEqual(
            set((geosite / "ai-support.domains").read_text().split()),
            APPLE_EXACT | {"meta.ai", "smoot.apple.com"},
        )
        rules = json.loads((geosite / "ai-support.json").read_text())["rules"][0]
        self.assertEqual(set(rules["domain"]), APPLE_EXACT)
        self.assertEqual(set(rules["domain_suffix"]), {"meta.ai", "smoot.apple.com"})
        if self.native_binary:
            decompiled = geosite / "ai-support.decompiled.json"
            result = subprocess.run(
                [
                    self.native_binary,
                    "rule-set",
                    "decompile",
                    str(geosite / "geosite-ai-support.srs"),
                    self.native_decompile_output_flag,
                    str(decompiled),
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            roundtrip = json.loads(decompiled.read_text())["rules"][0]
            self.assertEqual(set(roundtrip["domain"]), APPLE_EXACT)
            self.assertEqual(set(roundtrip["domain_suffix"]), {"meta.ai", "smoot.apple.com"})

    @unittest.skipUnless(NATIVE_SRS, "live local-SRS reload requires --native-srs")
    def test_native_local_srs_atomic_replace_reloads_routes_without_restart(self):
        binary = self.native_binary
        with tempfile.TemporaryDirectory(prefix="dnscomplex-apple-srs-live-") as temp_raw:
            temp = Path(temp_raw)
            peer_hits = []
            peer_lock = threading.Lock()

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    host = self.headers.get("Host", "")
                    with peer_lock:
                        peer_hits.append(host)
                    body = f"controlled-peer:{host}".encode("ascii")
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *_args):
                    pass

            peer = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            peer.daemon_threads = True
            peer_thread = threading.Thread(target=peer.serve_forever, daemon=True)
            peer_thread.start()
            self.addCleanup(peer.server_close)
            self.addCleanup(peer.shutdown)

            def free_port():
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.bind(("127.0.0.1", 0))
                    return sock.getsockname()[1]

            socks_port = free_port()
            exact_host = "guzzoni.apple.com"
            subdomain_host = "child.guzzoni.apple.com"
            unrelated_host = "unrelated.fixture.test"
            peer_port = peer.server_address[1]
            ruleset = temp / "apple-support.srs"

            def compile_source(filename, hosts):
                source = temp / filename
                output = temp / (filename + ".srs")
                source.write_text(json.dumps({
                    "version": 2,
                    "rules": [{"domain": hosts}],
                }))
                result = subprocess.run(
                    [binary, "rule-set", "compile", "--output", str(output), str(source)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(output.is_file())
                return output.read_bytes()

            original_srs = compile_source("apple-initial.json", [exact_host])
            replacement_srs = compile_source("apple-replacement.json", ["apple-relay.apple.com"])
            ruleset.write_bytes(original_srs)
            config = {
                "log": {"level": "error"},
                "inbounds": [{
                    "type": "socks",
                    "tag": "fixture-socks",
                    "listen": "127.0.0.1",
                    "listen_port": socks_port,
                }],
                "outbounds": [
                    {"type": "direct", "tag": "controlled-direct"},
                    {"type": "block", "tag": "default-block"},
                ],
                "route": {
                    "rules": [
                        {"action": "sniff"},
                        {"domain": [unrelated_host], "action": "route", "outbound": "controlled-direct"},
                        {"rule_set": ["apple-support"], "action": "route", "outbound": "controlled-direct"},
                    ],
                    "rule_set": [{
                        "type": "local",
                        "tag": "apple-support",
                        "format": "binary",
                        "path": str(ruleset),
                    }],
                    "final": "default-block",
                },
            }
            config_path = temp / "sing-box.json"
            config_path.write_text(json.dumps(config))
            checked = subprocess.run(
                [binary, "check", "-c", str(config_path)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

            process = subprocess.Popen(
                [binary, "run", "-c", str(config_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )

            def stop_process():
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)

            self.addCleanup(stop_process)

            def wait_socks():
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail(f"native sing-box exited during start (rc={process.returncode})")
                    try:
                        with socket.create_connection(("127.0.0.1", socks_port), timeout=0.2):
                            return
                    except OSError:
                        time.sleep(0.05)
                self.fail("native sing-box SOCKS listener did not start")

            def exact_read(sock, size):
                chunks = bytearray()
                while len(chunks) < size:
                    part = sock.recv(size - len(chunks))
                    if not part:
                        raise ConnectionError("SOCKS peer closed early")
                    chunks.extend(part)
                return bytes(chunks)

            def request(host):
                with socket.create_connection(("127.0.0.1", socks_port), timeout=2) as client:
                    client.settimeout(2)
                    client.sendall(b"\x05\x01\x00")
                    if exact_read(client, 2) != b"\x05\x00":
                        raise AssertionError("SOCKS no-auth negotiation failed")
                    client.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
                                   peer_port.to_bytes(2, "big"))
                    reply = exact_read(client, 10)
                    if reply[1] != 0:
                        return None
                    client.sendall(
                        f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii")
                    )
                    response = bytearray()
                    while True:
                        try:
                            part = client.recv(4096)
                        except (ConnectionError, OSError):
                            break
                        if not part:
                            break
                        response.extend(part)
                    if not response:
                        return None
                    return bytes(response)

            def expect_direct(host):
                response = request(host)
                self.assertIsNotNone(response, f"{host} was not routed to the local peer")
                self.assertIn(b"HTTP/1.0 200", response[:64])
                self.assertIn(f"controlled-peer:{host}".encode("ascii"), response)

            def expect_blocked(host):
                response = request(host)
                self.assertIsNone(response, f"{host} unexpectedly reached the direct peer")

            def replace_srs(data):
                staged = temp / f".apple-support-{time.monotonic_ns()}.srs"
                staged.write_bytes(data)
                os.replace(staged, ruleset)

            wait_socks()
            sing_box_pid = process.pid
            expect_direct(exact_host)
            expect_blocked(subdomain_host)
            expect_direct(unrelated_host)

            replace_srs(replacement_srs)
            deadline = time.monotonic() + 10
            response = request(exact_host)
            while True:
                if process.poll() is not None:
                    self.fail(f"sing-box exited after atomic SRS replacement (rc={process.returncode})")
                if response is None:
                    break
                if time.monotonic() >= deadline:
                    self.fail("local SRS replacement was not observed without restarting sing-box")
                time.sleep(0.1)
                response = request(exact_host)
            # Requests racing the asynchronous file watcher may still use the
            # old rule-set and reach the peer. Once the new block selection is
            # observed, require it to remain stable and stop peer traffic.
            with peer_lock:
                blocked_peer_hits = peer_hits.count(exact_host)
            for _ in range(3):
                time.sleep(0.1)
                expect_blocked(exact_host)
                with peer_lock:
                    self.assertEqual(peer_hits.count(exact_host), blocked_peer_hits)
            self.assertEqual(process.pid, sing_box_pid)
            expect_blocked(subdomain_host)
            expect_direct(unrelated_host)

            replace_srs(original_srs)
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    self.fail(f"sing-box exited after restoring the old SRS (rc={process.returncode})")
                response = request(exact_host)
                if response is not None and b"controlled-peer:guzzoni.apple.com" in response:
                    break
                if time.monotonic() >= deadline:
                    self.fail("restored local SRS did not restore the original exact-host route")
                time.sleep(0.1)
            self.assertEqual(process.pid, sing_box_pid)
            expect_blocked(subdomain_host)
            expect_direct(unrelated_host)
            with peer_lock:
                self.assertNotIn(subdomain_host, peer_hits)

if __name__ == "__main__":
    unittest.main()
