#!/usr/bin/env python3
"""Exercise installer/runtime AdGuard authentication without host services."""
import os
import base64
import json
from pathlib import Path
import socket
import subprocess
import shlex
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

import bcrypt
import yaml

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "fixture-adguard-initial-password"
HASH = bcrypt.hashpw(b"independent-password", bcrypt.gensalt(rounds=4)).decode()


class ConfigDumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def config_yaml(data):
    # Match AdGuard's block-list layout consumed by the existing renderer.
    return yaml.dump(data, Dumper=ConfigDumper, sort_keys=False)


class AdGuardAuthSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "config.env"
        text = (ROOT / "examples/routeros-policy.config.env").read_text()
        self.config.write_text(text + f"\nDNSCOMPLEX_WEB_PASSWORD='{PASSWORD}'\n")
        self.target = self.root / "etc/AdGuardHome/AdGuardHome.yaml"

    def render(self):
        return subprocess.run(["bash", str(ROOT / "install.sh"), "--dry-run", "--config", str(self.config)],
                              env=dict(os.environ, DNSCOMPLEX_ROOT=str(self.root)),
                              capture_output=True, text=True)

    def good_render(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        return yaml.safe_load(self.target.read_text())

    def runtime(self):
        manager = self.root / "usr/local/sbin/dnscomplex"
        return subprocess.run(["bash", "-c", 'source "$1"; load_config; render_adguard_runtime',
                               "_", str(manager)], env=dict(os.environ, DNSCOMPLEX_FS_ROOT=str(self.root)),
                              capture_output=True, text=True)

    def test_new_install_requires_real_bcrypt_login(self):
        data = self.good_render()
        self.assertEqual(len(data["users"]), 1, "installer leaves management unauthenticated")
        self.assertEqual(data["users"][0]["name"], "admin")
        encoded = data["users"][0]["password"].encode()
        self.assertTrue(bcrypt.checkpw(PASSWORD.encode(), encoded))
        self.assertFalse(bcrypt.checkpw(b"wrong-password", encoded))
        self.assertNotIn(PASSWORD, self.target.read_text())
        self.assertEqual(data["http"]["address"], "127.0.0.1:3000")
        self.assertEqual(data["dns"]["port"], 53)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)

    def test_reinstall_and_runtime_preserve_independent_accounts(self):
        self.good_render()
        users = [{"name": "owner", "password": HASH}, {"name": "operator", "password": HASH}]
        data = yaml.safe_load(self.target.read_text())
        data["users"] = users
        self.target.write_text(config_yaml(data))
        self.assertEqual(self.good_render()["users"], users, "reinstall resets existing users")
        for fallback in (False, True):
            with self.subTest(fallback=fallback):
                data = yaml.safe_load(self.target.read_text())
                if fallback:
                    data["dns"].pop("upstream_dns", None)
                self.target.write_text(config_yaml(data))
                result = self.runtime()
                self.assertEqual(result.returncode, 0, result.stderr)
                actual = yaml.safe_load(self.target.read_text())
                self.assertEqual(actual["users"], users)
                self.assertEqual(actual["dns"]["port"], 53)
                self.assertTrue(actual["user_rules"])
                self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)

    def test_runtime_repairs_legacy_empty_users(self):
        self.good_render()
        text = self.target.read_text()
        data = yaml.safe_load(text)
        data["users"] = []
        self.target.write_text(config_yaml(data))
        result = self.runtime()
        self.assertEqual(result.returncode, 0, result.stderr)
        users = yaml.safe_load(self.target.read_text())["users"]
        self.assertEqual(len(users), 1, "runtime leaves legacy installation unauthenticated")
        self.assertTrue(bcrypt.checkpw(PASSWORD.encode(), users[0]["password"].encode()))

    def test_invalid_or_duplicate_users_fail_without_overwrite(self):
        self.good_render()
        invalid = ["users: null\n", "users: invalid\n", "users: []\nusers: []\n",
                   "users:\n  - name: owner\n    password: plaintext\n",
                   "users:\n  - name: owner\n    name: duplicate\n    password: '" + HASH + "'\n"]
        for content in invalid:
            with self.subTest(content=content):
                self.target.write_text(content)
                result = self.render()
                self.assertNotEqual(result.returncode, 0, "invalid existing auth was silently reset")
                self.assertEqual(self.target.read_text(), content)
                self.assertNotIn(PASSWORD, result.stdout + result.stderr)

    def test_unusable_initial_password_rejected_before_managed_writes(self):
        for password in ('x' * 80, '密' * 25):
            with self.subTest(byte_length=len(password.encode())):
                self.config.write_text((ROOT / 'examples/routeros-policy.config.env').read_text() +
                                       f"\nDNSCOMPLEX_WEB_PASSWORD='{password}'\n")
                result = self.render()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'etc').exists(), 'invalid bootstrap partially changed managed files')
                self.assertNotIn(password, result.stdout + result.stderr)

    def test_existing_adguard_users_do_not_limit_web_password_length(self):
        self.good_render()
        data = yaml.safe_load(self.target.read_text())
        data['users'] = [{'name': 'owner', 'password': HASH}]
        self.target.write_text(config_yaml(data))
        self.config.write_text((ROOT / 'examples/routeros-policy.config.env').read_text() +
                               "\nDNSCOMPLEX_WEB_PASSWORD='" + 'x' * 80 + "'\n")
        self.assertEqual(self.good_render()['users'], data['users'])

    def test_existing_users_with_long_web_password_install_missing_yaml_before_check(self):
        data = self.good_render()
        data['users'] = [{'name': 'owner', 'password': HASH}]
        self.target.write_text(config_yaml(data))
        before = self.target.read_bytes()
        definitions = self.root / 'definitions.sh'
        definitions.write_text((ROOT / 'install.sh').read_text().rsplit('\nmain "$@"', 1)[0])
        commands = self.root / 'commands'
        commands.mkdir()
        installed = self.root / 'yaml-installed'
        apt_log = self.root / 'apt.log'
        # A new Debian dependency is unavailable until the package manager succeeds.
        # After that boundary, execute the real YAML parser and auth helper.
        (commands / 'python3').write_text(
            '#!/bin/sh\n'
            f'test -f {shlex.quote(str(installed))} || exit 1\n'
            f'exec {shlex.quote(sys.executable)} "$@"\n')
        (commands / 'apt-get').write_text(
            '#!/bin/sh\n'
            f'printf "%s\\n" "$*" >> {shlex.quote(str(apt_log))}\n'
            f'case "$*" in *install*python3-yaml*) touch {shlex.quote(str(installed))};; esac\n')
        for command in commands.iterdir():
            command.chmod(0o755)
        script = '''source "$1"
DRY_RUN=0
DNSCOMPLEX_ROOT="$2"
DNSCOMPLEX_WEB_PASSWORD="$3"
require_debian13() { :; }
require_root() { :; }
validate_adguard_bootstrap_password
'''
        result = subprocess.run(['bash', '-c', script, 'test', str(definitions), str(self.root), 'x' * 80],
                                env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH']),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed.exists())
        self.assertIn('python3-yaml', apt_log.read_text())
        self.assertEqual(self.target.read_bytes(), before, 'preflight modified existing users')

    @unittest.skipUnless(os.environ.get('ADGUARD_BINARY'), 'set ADGUARD_BINARY for actual AdGuard HTTP verification')
    def test_real_adguard_rejects_anonymous_and_accepts_existing_credentials(self):
        data = self.good_render()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        data['http']['address'] = f'127.0.0.1:{port}'
        data['dns']['bind_hosts'] = ['127.0.0.1']
        data['dns']['port'] = 0  # This test starts management only, never a host DNS listener.
        data['filters'] = []
        data['clients']['runtime_sources'] = {key: False for key in data['clients']['runtime_sources']}
        candidate = self.root / 'wire.yaml'; candidate.write_text(config_yaml(data))
        binary = os.environ['ADGUARD_BINARY']
        check = subprocess.run([binary, '--check-config', '-c', str(candidate)], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        log = open(self.root / 'adguard.log', 'wb'); self.addCleanup(log.close)
        (self.root / 'work').mkdir()
        proc = subprocess.Popen([binary, '--no-check-update', '-c', str(candidate), '-w', str(self.root / 'work')],
                                stdout=log, stderr=subprocess.STDOUT)
        def stop():
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
        self.addCleanup(stop)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def request(password=None):
            headers = {}
            if password is not None:
                headers['Authorization'] = 'Basic ' + base64.b64encode(('admin:' + password).encode()).decode()
            try:
                with opener.open(urllib.request.Request(f'http://127.0.0.1:{port}/control/status', headers=headers), timeout=2) as response:
                    return response.status
            except urllib.error.HTTPError as exc:
                return exc.code
        deadline = time.monotonic() + 10
        while True:
            try: anonymous = request(); break
            except urllib.error.URLError:
                if proc.poll() is not None or time.monotonic() >= deadline:
                    self.fail('AdGuard did not start: ' + (self.root / 'adguard.log').read_text())
                time.sleep(.05)
        self.assertIn(anonymous, (401, 403))
        self.assertEqual(request(PASSWORD), 200)
        self.assertIn(request('wrong-password'), (401, 403))
        if os.environ.get('SINGBOX_BINARY'):
            self.proxy_management(port)

    def proxy_management(self, target_port):
        # Project the actual SOCKS/private-direct pieces, omitting unrelated
        # unavailable IPsec and geosite dependencies. This is not a VLESS/LAN deployment test.
        source = json.loads((self.root / 'etc/sing-box/config.json').read_text())
        inbound = next(item for item in source['inbounds'] if item['tag'] == 'socks-in')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        inbound.update(listen='127.0.0.1', listen_port=port)
        config = {'inbounds': [inbound],
                  'outbounds': [item for item in source['outbounds'] if item['tag'] == 'default'],
                  'route': {'rules': [item for item in source['route']['rules'] if item.get('ip_is_private')],
                            'final': 'default'}}
        path = self.root / 'proxy.json'; path.write_text(json.dumps(config))
        log = open(self.root / 'proxy.log', 'wb'); self.addCleanup(log.close)
        proc = subprocess.Popen([os.environ['SINGBOX_BINARY'], 'run', '-c', str(path)], stdout=log, stderr=subprocess.STDOUT)
        def stop():
            if proc.poll() is None: proc.terminate(); proc.wait(timeout=5)
        self.addCleanup(stop)
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=1): break
            except OSError:
                if proc.poll() is not None or time.monotonic() >= deadline:
                    self.fail('SOCKS did not start: ' + (self.root / 'proxy.log').read_text())
                time.sleep(.05)
        for password, expected in [(None, b' 401 '), (PASSWORD, b' 200 ')]:
            with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
                def exact(size):
                    result = b''
                    while len(result) < size:
                        block = sock.recv(size - len(result))
                        if not block: raise AssertionError('SOCKS response ended early')
                        result += block
                    return result
                sock.sendall(b'\x05\x01\x00'); self.assertEqual(exact(2), b'\x05\x00')
                sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + target_port.to_bytes(2, 'big'))
                reply = exact(4); self.assertEqual(reply[:2], b'\x05\x00')
                exact((4 if reply[3] == 1 else 16) + 2)
                auth = '' if password is None else 'Authorization: Basic ' + base64.b64encode(('admin:' + password).encode()).decode() + '\r\n'
                sock.sendall(('GET /control/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n' + auth + '\r\n').encode())
                self.assertIn(expected, sock.recv(8192).split(b'\r\n', 1)[0])


if __name__ == "__main__":
    unittest.main()
