#!/usr/bin/env python3
"""Wire-test the frozen IPsec VIP bind-address sync helper in an isolated netns.

The helper is extracted by function body only. It receives a temporary FS_ROOT,
synthetic VIP provider, `sing-box` check wrapper, and `systemctl` shim. A real
sing-box SOCKS flow reaches a controlled peer over a veth; the peer reports the
actual TCP source address. No production SA, config, service, or route is read
or modified.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

P = argparse.ArgumentParser()
P.add_argument("--runtime-script", type=pathlib.Path, default=pathlib.Path("/tmp/dnscomplex-vip-candidate-install.sh"))
P.add_argument("--isolated", action="store_true")
A = P.parse_args()

if not A.isolated:
    raise SystemExit(subprocess.run(
        ["unshare", "--net", sys.executable, str(pathlib.Path(__file__).resolve()),
         "--isolated", "--runtime-script", str(A.runtime_script.resolve())], timeout=100).returncode)


def run(command, timeout=8, check=True, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({command[0]} ...), rc={result.returncode}: {result.stderr.strip()[:400]}")
    return result


def extract_bind_sync(runtime_script, destination):
    source = runtime_script.read_text()
    match = re.search(r"(?m)^sync_singbox_ipsec_bind_addresses\(\) \{\s*$", source)
    if not match:
        raise RuntimeError("frozen runtime has no sync_singbox_ipsec_bind_addresses helper")
    end = re.search(r"(?m)^\}\s*$", source[match.end():])
    if not end:
        raise RuntimeError("bind sync helper is unterminated")
    selected = source[match.start():match.end() + end.end()]
    destination.write_text(selected + r'''
ipsec_vip() {
  case "$1" in
    ai) printf '%s\n' "${FIXTURE_AI_VIP:-}" ;;
    cn) printf '%s\n' "${FIXTURE_CN_VIP:-}" ;;
    *) return 1 ;;
  esac
}
warn() { printf 'fixture warning: %s\n' "$*" >&2; }
''')


def wait_tcp(address, port, process=None, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError("fixture sing-box exited unexpectedly")
        try:
            with socket.create_connection((address, port), timeout=.1):
                return
        except OSError:
            time.sleep(.025)
    raise RuntimeError(f"fixture listener {address}:{port} did not become ready")


def socks_http_probe(proxy_port=19680):
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as sock:
        sock.settimeout(3)
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            raise RuntimeError("fixture SOCKS no-auth negotiation failed")
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("192.0.2.10") + (19443).to_bytes(2, "big"))
        reply = read_exact(sock, 4)
        if reply[:2] != b"\x05\x00":
            raise RuntimeError("fixture SOCKS CONNECT failed")
        atyp = reply[3]
        if atyp == 1:
            read_exact(sock, 4)
        elif atyp == 4:
            read_exact(sock, 16)
        elif atyp == 3:
            read_exact(sock, read_exact(sock, 1)[0])
        else:
            raise RuntimeError("fixture SOCKS response had invalid address type")
        read_exact(sock, 2)
        sock.sendall(b"GET /source-ip HTTP/1.0\r\nConnection: close\r\n\r\n")
        data = bytearray()
        while True:
            part = sock.recv(4096)
            if not part:
                break
            data.extend(part)
    return bytes(data).split(b"\r\n\r\n", 1)[-1].decode(errors="replace")


def read_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError("fixture socket closed mid-protocol")
        result.extend(chunk)
    return bytes(result)


class FixtureService:
    """systemctl-restart target that owns only the test sing-box process."""
    def __init__(self, sock_path, binary, config, log_path):
        self.sock_path = str(sock_path)
        self.binary = str(binary)
        self.config = str(config)
        self.log_path = str(log_path)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.sock_path)
        self.sock.listen(4)
        self.sock.settimeout(.1)
        self.process = None
        self.log_handles = []
        self.restart_calls = 0
        self.fail_consumed = False
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def start(self):
        log = open(self.log_path, "a")
        self.log_handles.append(log)
        self.process = subprocess.Popen([self.binary, "run", "-c", self.config], stdout=log, stderr=log)
        wait_tcp("127.0.0.1", 19680, self.process)

    def _restart(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()
        for log in self.log_handles:
            log.close()
        self.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    request = json.loads(conn.recv(4096))
                    if request.get("verb") != "restart" or request.get("unit") != "sing-box":
                        conn.sendall(b'{"status":1}'); continue
                    self.restart_calls += 1
                    should_fail = request.get("fail_once") is True and not self.fail_consumed
                    if should_fail:
                        self.fail_consumed = True
                        conn.sendall(b'{"status":1}')
                        continue
                    self._restart()
                    conn.sendall(b'{"status":0}')
                except Exception:
                    try:
                        conn.sendall(b'{"status":1}')
                    except OSError:
                        pass

    def close(self):
        self.stop.set(); self.sock.close(); self.thread.join(timeout=1)
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()


PEER_SERVER = r'''import socket
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("192.0.2.10",19443));s.listen();print("READY",flush=True)
while True:
 c,_=s.accept()
 try:
  c.recv(4096);body=c.getpeername()[0].encode()
  c.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body)
 finally:c.close()
'''


def main():
    if not A.runtime_script.is_file():
        raise RuntimeError("runtime installer/candidate is missing")
    runtime_hash = hashlib.sha256(A.runtime_script.read_bytes()).hexdigest()
    singbox = shutil.which("sing-box")
    if not singbox:
        raise RuntimeError("sing-box binary is unavailable")
    if not shutil.which("jq"):
        raise RuntimeError("jq is required by the bind sync helper")
    print(f"runtime installer SHA256: {runtime_hash}", flush=True)

    vip_old, vip_new, vip_reject = "10.250.1.10", "10.250.1.11", "10.250.1.12"
    children = []
    peer_ns = None
    service = None
    try:
        run(["ip", "link", "set", "lo", "up"])
        for vip in (vip_old, vip_new, vip_reject):
            run(["ip", "addr", "add", vip + "/32", "dev", "lo"])

        peer_ns = subprocess.Popen(["unshare", "--net", "sleep", "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children.append(peer_ns)
        for _ in range(100):
            if os.readlink(f"/proc/{peer_ns.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                break
            time.sleep(.01)
        else:
            raise RuntimeError("could not create HTTP peer namespace")
        peer = ["nsenter", "-t", str(peer_ns.pid), "-n"]
        run(["ip", "link", "add", "fixture0", "type", "veth", "peer", "name", "peer0"])
        run(["ip", "link", "set", "peer0", "netns", str(peer_ns.pid)])
        run(["ip", "addr", "add", "198.18.1.1/24", "dev", "fixture0"])
        run(["ip", "link", "set", "fixture0", "up"])
        run(peer + ["ip", "link", "set", "lo", "up"])
        run(peer + ["ip", "addr", "add", "198.18.1.2/24", "dev", "peer0"])
        run(peer + ["ip", "link", "set", "peer0", "up"])
        run(peer + ["ip", "addr", "add", "192.0.2.10/32", "dev", "lo"])
        run(peer + ["ip", "route", "add", "10.250.1.0/24", "via", "198.18.1.1", "dev", "peer0"])
        run(["ip", "route", "add", "192.0.2.10/32", "via", "198.18.1.2", "dev", "fixture0"])
        peer_proc = subprocess.Popen(peer + ["python3", "-u", "-c", PEER_SERVER], stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True)
        children.append(peer_proc)
        ready, _, _ = select.select([peer_proc.stdout], [], [], 2)
        if not ready or peer_proc.stdout.readline().strip() != "READY":
            raise RuntimeError("controlled HTTP source-observer did not start")

        with tempfile.TemporaryDirectory(prefix="dnscomplex-vip-bind-") as temp:
            root = pathlib.Path(temp) / "root"
            config_path = root / "etc/sing-box/config.json"
            config_path.parent.mkdir(parents=True)
            config = {
                "log": {"level": "error"},
                "inbounds": [{"type": "socks", "tag": "vip-wire-in", "listen": "127.0.0.1", "listen_port": 19680}],
                "outbounds": [
                    {"type": "direct", "tag": "default"},
                    {"type": "direct", "tag": "ai-ipsec", "bind_interface": "fixture0", "inet4_bind_address": vip_old},
                    {"type": "direct", "tag": "cn-ipsec", "bind_interface": "fixture0", "inet4_bind_address": vip_old},
                ],
                "route": {"rules": [{"inbound": ["vip-wire-in"], "action": "route", "outbound": "ai-ipsec"}], "final": "default"},
            }
            config_path.write_text(json.dumps(config, separators=(",", ":")))
            run([singbox, "check", "-c", str(config_path)])

            helper_path = pathlib.Path(temp) / "bind-sync-helper.sh"
            extract_bind_sync(A.runtime_script, helper_path)
            shim_dir = pathlib.Path(temp) / "bin"; shim_dir.mkdir()
            check_shim = shim_dir / "sing-box"
            check_shim.write_text("#!/bin/sh\nif [ \"${FIXTURE_FAIL_CHECK:-0}\" = 1 ]; then exit 41; fi\nexec \"$REAL_SINGBOX\" \"$@\"\n")
            check_shim.chmod(0o755)
            service_sock = pathlib.Path(temp) / "systemctl.sock"
            service_log = pathlib.Path(temp) / "sing-box.log"
            pidfile = pathlib.Path(temp) / "sing-box.pid"
            control_script = pathlib.Path(temp) / "systemctl-control.py"
            control_script.write_text('''import json,os,socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(os.environ["FIXTURE_SYSTEMCTL_SOCKET"])
s.sendall(json.dumps({"verb":sys.argv[1],"unit":sys.argv[2],"fail_once":os.environ.get("FIXTURE_FAIL_RESTART_ONCE")=="1"}).encode())
r=json.loads(s.recv(1024));sys.exit(r["status"])
''')
            systemctl_shim = shim_dir / "systemctl"
            systemctl_shim.write_text(f"#!/bin/sh\n[ \"$#\" = 2 ] && [ \"$1\" = restart ] && [ \"$2\" = sing-box ] || exit 2\nexec {shutil.which('python3')} {control_script} restart sing-box\n")
            systemctl_shim.chmod(0o755)
            service = FixtureService(service_sock, singbox, config_path, service_log)
            service.start(); children.append(service.process)

            base_env = os.environ.copy()
            base_env.update({
                "FS_ROOT": str(root), "AI_EGRESS_MODE": "ipsec", "CN_EGRESS_MODE": "xray",
                "FIXTURE_AI_VIP": vip_old, "FIXTURE_CN_VIP": "",
                "FIXTURE_SYSTEMCTL_SOCKET": str(service_sock), "FIXTURE_SINGBOX_PIDFILE": str(pidfile),
                "REAL_SINGBOX": singbox, "PATH": str(shim_dir) + os.pathsep + os.environ.get("PATH", ""),
            })

            def sync(vip, fail_check=False, fail_restart_once=False):
                env = base_env.copy(); env["FIXTURE_AI_VIP"] = vip
                env["FIXTURE_FAIL_CHECK"] = "1" if fail_check else "0"
                env["FIXTURE_FAIL_RESTART_ONCE"] = "1" if fail_restart_once else "0"
                cmd = 'source "$BIND_HELPER"; sync_singbox_ipsec_bind_addresses ai'
                env["BIND_HELPER"] = str(helper_path)
                return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=10, env=env)

            def expect(label, got, wanted):
                print(f"{label}: peer source={got!r}; expected {wanted!r}", flush=True)
                if got != wanted:
                    raise AssertionError(f"{label}: observed peer source differs")

            expect("initial old VIP", socks_http_probe(), vip_old)
            pid_initial = service.process.pid
            restarts_initial = service.restart_calls
            no_op = sync(vip_old)
            if no_op.returncode != 0 or service.process.pid != pid_initial or service.restart_calls != restarts_initial:
                raise AssertionError("stable VIP sync restarted or failed")
            expect("stable VIP no restart", socks_http_probe(), vip_old)
            print("stable VIP: PID and restart count unchanged", flush=True)

            rotated = sync(vip_new)
            if rotated.returncode != 0:
                raise RuntimeError("normal VIP rotation helper failed")
            expect("rotated VIP", socks_http_probe(), vip_new)
            print(f"rotation: sing-box process PID {pid_initial}->{service.process.pid}; real config check passed", flush=True)

            old_json = config_path.read_bytes()
            pid_before_check_fail = service.process.pid
            check_failure = sync(vip_reject, fail_check=True)
            if check_failure.returncode == 0 or b"rejected the reconciled IPsec bind-address config" not in check_failure.stderr.encode():
                raise AssertionError("forced sing-box check failure did not propagate")
            if config_path.read_bytes() != old_json or service.process.pid != pid_before_check_fail:
                raise AssertionError("sing-box check failure changed config or restarted service")
            if list(config_path.parent.glob("config.json.tmp.*")) or list(config_path.parent.glob("config.json.bak.*")):
                raise AssertionError("config-check failure left temp/backup files")
            expect("config-check failure rollback", socks_http_probe(), vip_new)
            print("config check failure: error propagated; original config/PID preserved", flush=True)

            pid_before_restart_fail = service.process.pid
            restart_calls_before = service.restart_calls
            restart_failure = sync(vip_reject, fail_restart_once=True)
            if restart_failure.returncode == 0 or b"could not restart after IPsec bind-address reconciliation" not in restart_failure.stderr.encode():
                raise AssertionError("forced systemctl restart failure did not propagate")
            if config_path.read_bytes() != old_json:
                raise AssertionError("restart failure did not restore previous config")
            if service.restart_calls != restart_calls_before + 2 or service.process.pid == pid_before_restart_fail:
                raise AssertionError("restart failure did not attempt one failed restart plus rollback restart")
            if list(config_path.parent.glob("config.json.tmp.*")) or list(config_path.parent.glob("config.json.bak.*")):
                raise AssertionError("restart rollback left temp/backup files")
            expect("restart failure rollback", socks_http_probe(), vip_new)
            print(f"restart failure: error propagated; config restored and old VIP active; restart attempts={service.restart_calls - restart_calls_before}", flush=True)
            print("PASS: frozen bind sync helper updated the real sing-box socket source VIP, skipped stable VIP restart, and rolled back config/service on check or restart failure.", flush=True)
    finally:
        if service is not None:
            service.close()
        for process in reversed(children):
            if process.poll() is None:
                process.terminate()
        for process in reversed(children):
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()


main()
