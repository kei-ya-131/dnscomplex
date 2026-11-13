"""Wire harness for the rendered watchdog with real IKEv2 and private services."""
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import threading
import time

from ipsec_rekey_fixture import CLIENT, wait_for_old_ai_drain

DESTINATIONS = {'ai': '192.0.2.11', 'cn': '192.0.2.12', 'default': '192.0.2.10'}
RESOLVERS = {'ai': '104.16.248.249', 'cn': '223.6.6.6'}

DOH = r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket, ssl, struct, sys

class DoH(BaseHTTPRequestHandler):
    def do_POST(self):
        query = self.rfile.read(int(self.headers['Content-Length']))
        answer = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:]
        answer += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton('203.0.113.10')
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)
        print(self.client_address[0], flush=True)

server = ThreadingHTTPServer((sys.argv[1], 443), DoH)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(sys.argv[2], sys.argv[3])
server.socket = tls.wrap_socket(server.socket, server_side=True)
print('ready', flush=True)
server.serve_forever()
'''


def start_resolver(run, processes, directory, namespace, profile, certificate, key):
    address = RESOLVERS[profile]
    run(namespace + ['ip', 'addr', 'add', address + '/32', 'dev', 'lo'])
    process = subprocess.Popen(namespace + ['python3', '-u', '-c', DOH,
                                            address, certificate, key],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    processes.append(process)
    assert process.stdout.readline().strip() == 'ready', profile
    # The watchdog makes only a few probes. Keep a bounded record for checks.
    path = directory / f'{profile}-doh.log'
    def collect():
        with path.open('w') as output:
            for line in process.stdout:
                output.write(line)
                output.flush()
    threading.Thread(target=collect, daemon=True).start()


class Watchdog:
    def __init__(self, fixture, root, config, proxy, certificate):
        self.fixture = fixture
        self.root = root
        self.config = config
        self.proxy_log = config.parent / 'log'
        self.proxy = proxy
        self.initial_pid = proxy.pid
        self.certificate = certificate
        self.restarts = []
        self.private_bin = fixture.directory / 'bin'
        self.private_bin.mkdir()
        self.pid_path = fixture.directory / 'sing-box.pid'
        self.pid_path.write_text(f'{proxy.pid}\n')
        self.restart_origins = fixture.directory / 'restart-origins.log'
        self.proxy_config = root / 'etc/sing-box/config.json'
        self.proxy_config.write_bytes(config.read_bytes())
        control_path = fixture.directory / 'service.sock'
        self.control = socket.socket(socket.AF_UNIX)
        self.control.bind(str(control_path))
        self.control.listen()
        self.control.settimeout(.1)
        self.stopped = threading.Event()
        self.worker = threading.Thread(target=self.serve, daemon=True)
        self.worker.start()
        client = fixture.daemons['client'].pid
        managed_swanctl = shlex.quote(str(root / 'etc/swanctl/swanctl.conf'))
        isolated_swanctl = shlex.quote(str(fixture.directory / 'client-swanctl/swanctl.conf'))
        self.install('swanctl', f'''#!/bin/sh
if [ "$*" = "--load-conns --file /etc/swanctl/swanctl.conf" ]; then
  cp {managed_swanctl} {isolated_swanctl} || exit 1
fi
exec nsenter -t {client} --mount --net --root /usr/sbin/swanctl "$@" --uri unix:///var/run/charon.vici
''')
        self.install('systemctl', f'''#!/bin/sh
case "$*" in
  "is-active nftables"|"is-active smartdns"|"is-active AdGuardHome"|"is-active sing-box") echo active; exit 0 ;;
  "is-active --quiet sing-box") exit 0 ;;
  "show -p MainPID --value sing-box") exec cat {shlex.quote(str(self.pid_path))} ;;
  "restart sing-box")
    cat "/proc/$PPID/comm" >>{shlex.quote(str(self.restart_origins))}
    exec python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); sys.exit(0 if s.recv(1)==b"0" else 1)' {shlex.quote(str(control_path))} ;;
  *) echo "unsupported isolated systemctl request: $*" >&2; exit 91 ;;
esac
''')

    def install(self, name, body):
        path = self.private_bin / name
        path.write_text(body)
        path.chmod(0o700)

    def serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.control.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                try:
                    self.proxy.terminate()
                    self.proxy.wait(timeout=2)
                    with (self.fixture.directory / 'proxy-restart.log').open('a') as log:
                        self.proxy = subprocess.Popen(
                            ['sing-box', 'run', '-c', str(self.proxy_config)], stdout=log, stderr=log)
                    self.fixture.processes.append(self.proxy)
                    self.restarts.append(self.proxy.pid)
                    self.pid_path.write_text(f'{self.proxy.pid}\n')
                    time.sleep(.12)
                    connection.sendall(b'0' if self.proxy.poll() is None else b'1')
                except (OSError, subprocess.TimeoutExpired):
                    connection.sendall(b'1')

    def close(self):
        self.stopped.set()
        self.worker.join(timeout=2)
        self.control.close()

    def run(self):
        manager = self.root / 'usr/local/sbin/dnscomplex'
        assert manager.is_file()
        env = dict(os.environ, PATH=f'{self.private_bin}:{os.environ["PATH"]}',
                   DNSCOMPLEX_FS_ROOT=str(self.root), SSL_CERT_FILE=self.certificate)
        # Only unrelated Xray supervision is disabled; the watchdog uses the
        # rendered alias helper and queries isolated DNS/DoH listeners.
        shell = r'''
set -Eeuo pipefail
source "$1"
load_config
XRAY_ENABLED=0
for name in profile_egress_gate_clear ensure_policy_route_profile sync_ipsec_probe_vip_profile sync_singbox_ipsec_bind_addresses profile_egress_gate_open lan_alias_reconcile_cmd; do
  definition=$(declare -f "$name")
  eval "_wire_${definition}"
  eval "$(cat <<EOF
$name() {
  printf 'WATCHDOG_EVENT begin %s %s\\n' '$name' "\$*" >&2
  local rc=0
  _wire_$name "\$@" || rc=\$?
  printf 'WATCHDOG_EVENT end %s %s rc=%s\\n' '$name' "\$*" "\$rc" >&2
  return "\$rc"
}
EOF
)"
done
watchdog_cmd
'''
        result = subprocess.run(['bash', '-c', shell, 'watchdog-test', str(manager)],
                                capture_output=True, text=True, env=env, timeout=46)
        print(f'{time.monotonic_ns()} watchdog rc={result.returncode} '
              f'proxy={self.proxy.pid} {result.stderr.strip()}', flush=True)
        assert result.returncode == 0, result
        return self.snapshot()

    def return_profile(self, profile, return_vip):
        manager = self.root / 'usr/local/sbin/dnscomplex'
        env = dict(os.environ, PATH=f'{self.private_bin}:{os.environ["PATH"]}',
                   DNSCOMPLEX_FS_ROOT=str(self.root), SSL_CERT_FILE=self.certificate)
        result = subprocess.run(
            ['bash', '-c', 'source "$1"; load_config; XRAY_ENABLED=0; ipsec_return_profile_cmd "$2" "$3"',
             'return-test', str(manager), profile, return_vip], capture_output=True, text=True, env=env, timeout=48)
        print(f'IPsec return rc={result.returncode} {result.stderr.strip()}', flush=True)
        return result.returncode

    def snapshot(self):
        status = {}
        for profile, table in (('ai', '301'), ('cn', '351')):
            route = self.fixture.run(['ip', 'route', 'show', 'table', table]).stdout.strip()
            vips = self.fixture.run(['nft', 'list', 'set', 'inet', 'dnscomplex',
                                     profile + '_probe_vip4']).stdout
            ready = self.fixture.run(['nft', 'list', 'set', 'inet', 'dnscomplex',
                                      profile + '_ready4']).stdout
            proof = self.root / f'run/dnscomplex/profile-dataplane-{profile}.success'
            status[profile] = (route, re.findall(r'\d+\.\d+\.\d+\.\d+', vips),
                               'elements = {' in ready, proof.read_text().strip() if proof.exists() else '')
        print(f'{time.monotonic_ns()} watchdog state {status}', flush=True)
        return status


def prepare_application_routes(run):
    # Static bind_address is what the shipped watchdog expects. The device
    # route in main is scoped to the bound socket; the watchdog owns fwmarks.
    for profile, address in DESTINATIONS.items():
        if profile == 'default':
            continue
        run(['ip', 'route', 'add', address + '/32', 'dev', 'ipsec-' + profile])
        # A connected socket with an explicit IPsec oif must also be able to
        # route to the other fixture address if the classifier gets it wrong.
        other = 'cn' if profile == 'ai' else 'ai'
        run(['ip', 'route', 'add', DESTINATIONS[other] + '/32', 'dev',
             'ipsec-' + profile, 'metric', '50'])
    # Prefer the normal route for an unbound outbound, even if misclassified.
    for address in DESTINATIONS.values():
        run(['ip', 'route', 'replace', address + '/32', 'via', '198.18.1.2', 'dev', 'ens18', 'metric', '0'])


def verify_watchdog(fixture, client_ns, certificate, watchdog, expect_drain=False):
    old_vip, new_vip = '10.250.1.22', '10.250.1.23'
    vips = {'ai': old_vip, 'cn': '10.251.1.10', 'default': '198.18.1.1'}
    run = fixture.run
    prepare_application_routes(run)

    for _ in range(2):
        state = watchdog.run()
    assert all(state[p][2] for p in ('ai', 'cn')), state
    assert (watchdog.root / 'var/lib/dnscomplex/lan-alias.json').is_file()
    watchdog.restarts.clear()  # Bootstrap may publish the alias and restart.
    watchdog.restart_origins.write_text('')
    baseline_pid = watchdog.proxy.pid
    if expect_drain:
        config = json.loads(watchdog.proxy_config.read_text())
        assert all('inet4_bind_address' not in outbound for outbound in config['outbounds']
                   if outbound['tag'] in ('ai-ipsec', 'cn-ipsec')), (
                       'watchdog installed a fixed source VIP and restarted sing-box during bootstrap')

    path = fixture.directory / 'watchdog-traffic.jsonl'
    stop = fixture.directory / 'watchdog-traffic.stop'
    drain = fixture.directory / 'watchdog-ai-drain'
    with path.open('w') as output:
        client = subprocess.Popen(client_ns + ['python3', '-u', '-c', CLIENT, certificate,
                                  str(stop), json.dumps(DESTINATIONS), str(drain)], stdout=output)
    fixture.processes.append(client)

    def observations():
        return [json.loads(line) for line in path.read_text().splitlines(keepends=True)
                if line.endswith('\n')]

    def await_traffic(since, expected, modes):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            rows = [row for row in observations() if isinstance(row, list)]
            if all(sum(start > since and profile == p and mode == m and result.startswith(f'{p}|{vip}|')
                       for start, _, profile, mode, result, _port in rows) >= 2
                   for p, vip in expected.items() for m in modes.get(p, ('old', 'new'))):
                return
            time.sleep(.02)
        raise AssertionError(f'expected traffic missing: {expected}; recent={rows[-20:]}')

    await_traffic(0, vips, {})
    initial_spi = fixture.wait_installed('ai', old_vip)
    cn_spi = fixture.wait_installed('cn', vips['cn'])
    first = time.monotonic_ns()
    fixture.swan('client', '--rekey', '--child', 'ai')
    rekey_spi = fixture.wait_installed('ai', old_vip, initial_spi)
    rekey_complete = time.monotonic_ns()
    for _ in range(2):
        state = watchdog.run()
    assert all(state[p][2] for p in ('ai', 'cn')), state
    assert not watchdog.restarts and watchdog.proxy.pid == baseline_pid
    assert fixture.packets(rekey_spi) > 0
    await_traffic(rekey_complete, vips, {})

    # Use a second IKE identity in the local peer, but expose the same profile
    # and child names to the rendered manager. The old IKE remains installed.
    old_sa = fixture.swan('client', '--list-sas', '--ike', 'ai')
    old_id = re.search(r'^ai: #(\d+),', old_sa, re.M)[1]
    config = fixture.directory / 'client-swanctl/swanctl.conf'
    if expect_drain:
        config.write_text(fixture.named_overlap_config)
        fixture.swan('client', '--load-conns', '--file', '/etc/swanctl/swanctl.conf')
        assert fixture.wait_installed('ai', old_vip) == rekey_spi
        fixture.initiate('ai-next', new_vip)
    else:
        contents = config.read_text()
        disabled = contents.replace('\nai {', '\nai-previous {', 1)
        replacement = disabled.replace('\nai-next {', '\nai {', 1).replace(
            '\n        ai-next {', '\n        ai {', 1)
        assert replacement != contents and '\nai {' in replacement
        config.write_text(replacement)
        fixture.swan('client', '--load-conns', '--file', '/etc/swanctl/swanctl.conf')
        fixture.initiate('ai', new_vip)
    overlap = time.monotonic_ns()
    combined = fixture.swan('client', '--list-sas')
    assert len(re.findall(r'^ai(?:-next)?: #\d+, ESTABLISHED', combined, re.M)) == 2, combined
    assert fixture.packets(rekey_spi) > 0
    if expect_drain:
        peer_nft = fixture.underlays['ai'][0] + ['nft']
        run(peer_nft + ['add', 'table', 'inet', 'reject_new_vip'])
        run(peer_nft + ['add', 'chain', 'inet', 'reject_new_vip', 'input',
                        '{ type filter hook input priority 0; policy accept; }'])
        run(peer_nft + ['add', 'rule', 'inet', 'reject_new_vip', 'input',
                        'ip', 'saddr', new_vip, 'ip', 'daddr', RESOLVERS['ai'],
                        'tcp', 'dport', '443', 'counter', 'reject', 'with', 'tcp', 'reset'])
        state = watchdog.run()
        assert state['ai'][1] == [old_vip] and state['ai'][2] and state['cn'][2], state
        assert not watchdog.restarts
        counters = run(peer_nft + ['list', 'chain', 'inet', 'reject_new_vip', 'input']).stdout
        assert re.search(r'packets [1-9]\d*', counters), counters
        print(f'{time.monotonic_ns()} rejected candidate proof kept the old VIP and both gates open', flush=True)
        await_traffic(overlap, vips, {})
        run(peer_nft + ['delete', 'table', 'inet', 'reject_new_vip'])

    switch_start = time.monotonic_ns()
    state = watchdog.run()
    selected = state['ai'][1]
    assert selected in ([old_vip], [new_vip]), state
    print(f'{overlap} overlapping IKEs; watchdog selected {selected[0]}', flush=True)
    if expect_drain:
        assert selected == [new_vip] and state['ai'][2] and state['cn'][2], state
        assert state['ai'][3].split()[-1] == '2', state
        switched = time.monotonic_ns()
        assert (fixture.directory / 'ai-doh.log').read_text().split().count(new_vip) == 2
        assert not watchdog.restarts
        await_traffic(switched, dict(vips, ai=new_vip), {'ai': ('new',)})
        await_traffic(switched, {'ai': old_vip}, {'ai': ('old',)})
        state = watchdog.run()
        assert re.search(rf'^ai: #{old_id}, ESTABLISHED',
                         fixture.swan('client', '--list-sas', '--ike', 'ai'), re.M)
        source_set = run(['nft', 'list', 'set', 'inet', 'dnscomplex', 'ai_tunnel_vip4']).stdout
        assert old_vip in source_set and new_vip in source_set, source_set
        wait_for_old_ai_drain(fixture, observations, drain)
        print(f'{time.monotonic_ns()} old AI client finished before watchdog retirement', flush=True)
        for _ in range(3):
            state = watchdog.run()
            combined = fixture.swan('client', '--list-sas', '--ike', 'ai')
            if not re.search(rf'^ai: #{old_id},', combined, re.M):
                break
        else:
            raise AssertionError('watchdog kept the old IKE after drain')
        source_set = run(['nft', 'list', 'set', 'inet', 'dnscomplex', 'ai_tunnel_vip4']).stdout
        assert old_vip not in source_set and new_vip in source_set, source_set
        assert fixture.wait_installed('ai-next', new_vip)
        print(f'{time.monotonic_ns()} watchdog retired only the drained IKE and pruned the source guard', flush=True)
    elif selected == [old_vip]:
        assert not watchdog.restarts
        await_traffic(overlap, vips, {})
        wait_for_old_ai_drain(fixture, observations, drain)
        print(f'{time.monotonic_ns()} old AI client finished before IKE retirement', flush=True)
        switch_start = time.monotonic_ns()
        fixture.swan('client', '--terminate', '--ike-id', old_id, '--timeout', '5')
        state = watchdog.run()
    else:
        switch_start = overlap
        print('watchdog switched before the original connection could drain', flush=True)
        rows = [row for row in observations() if isinstance(row, list)]
        assert any(row[2:4] == ['ai', 'old'] and '|' not in row[4] for row in rows), rows[-12:]
        assert len(re.findall(r'^ai: #\d+, ESTABLISHED',
                              fixture.swan('client', '--list-sas', '--ike', 'ai'), re.M)) == 2
        fixture.swan('client', '--terminate', '--ike-id', old_id, '--timeout', '5')
    for _ in range(2):
        state = watchdog.run()
    assert state['ai'][1] == [new_vip] and f'src {new_vip}' in state['ai'][0]
    assert all(state[p][2] for p in ('ai', 'cn')), state
    assert fixture.wait_installed('cn', vips['cn']) == cn_spi
    assert (fixture.directory / 'ai-doh.log').read_text().split().count(new_vip) >= 2
    await_traffic(time.monotonic_ns(), dict(vips, ai=new_vip),
                  {profile: ('new',) for profile in vips})
    end = time.monotonic_ns()
    stop.touch()
    assert client.wait(timeout=2) == 0

    totals = {}
    failures = {}
    in_rekey = set()
    wrong_exits = {}
    bypasses = {}
    stable = {}
    redirect_ports = set()
    if expect_drain:
        proxy_log = (watchdog.proxy_log if baseline_pid == watchdog.initial_pid else
                     fixture.directory / 'proxy-restart.log')
        redirect_ports = set(re.findall(
            r'inbound/tun\[tun-in\]: inbound redirect connection from 198\.18\.1\.3:(\d+)',
            proxy_log.read_text()))
    for row in observations():
        if not isinstance(row, list):
            continue
        start, finish, profile, mode, outcome, client_port = row
        if finish > end:
            continue
        key = profile, mode
        totals[key] = totals.get(key, 0) + 1
        if start < rekey_complete and finish > first:
            in_rekey.add(key)
        if '|' not in outcome:
            failures[key] = failures.get(key, 0) + 1
            assert finish >= switch_start, (key, outcome, 'before VIP switch')
            continue
        actual, vip, port = outcome.split('|')
        if expect_drain:
            assert str(client_port) in redirect_ports, (row, 'missing sing-box TUN ingress')
        if actual != profile:
            leak = profile, actual, mode
            wrong_exits[leak] = wrong_exits.get(leak, 0) + 1
            assert finish >= switch_start, (key, outcome, 'wrong exit before VIP switch')
            continue
        if profile == 'default' and vip == '198.18.1.3':
            assert finish >= switch_start, (key, outcome, 'TUN bypass before VIP switch')
            bypasses[key] = bypasses.get(key, 0) + 1
            continue
        assert vip == vips[profile] or (
            profile == 'ai' and vip == new_vip and finish >= switch_start
        ), (key, outcome)
        if mode == 'old':
            assert stable.setdefault(profile, port) == port, (key, outcome)
    assert len(in_rekey) == 6, in_rekey
    print(f'watchdog requests={totals}; interruptions={failures}; '
          f'wrong exits={wrong_exits}; default TUN bypass={bypasses}; '
          f'sing-box restarts={watchdog.restarts}', flush=True)
    if expect_drain:
        assert not failures and not wrong_exits and not bypasses, (failures, wrong_exits, bypasses)
        assert not watchdog.restarts and watchdog.proxy.pid == baseline_pid
        print(f'TUN ingress verified for every successful request ({sum(totals.values())})', flush=True)
        verify_return_after_retirement(fixture, client_ns, certificate, watchdog, vips, new_vip)

    else:
        assert watchdog.restarts, 'expected shipped static-bind restart during VIP reconciliation'
        print(f'restart callers={watchdog.restart_origins.read_text().splitlines()}', flush=True)


def verify_return_after_retirement(fixture, client_ns, certificate, watchdog, vips, candidate):
    generated = watchdog.root / 'etc/swanctl/swanctl.conf'
    generated.write_text((fixture.directory / 'client-swanctl/swanctl.conf').read_text())
    fixture.run(['nft', 'flush', 'set', 'inet', 'dnscomplex', 'ai_ready4'])
    assert watchdog.return_profile('ai', vips['ai']) == 75, 'temporarily closed gate aborted rollback'
    assert fixture.wait_installed('ai-next', candidate)
    assert watchdog.run()['ai'][2]
    path = fixture.directory / 'return-traffic.jsonl'
    stop = fixture.directory / 'return-traffic.stop'
    drain = fixture.directory / 'return-candidate-drain'
    with path.open('w') as output:
        client = subprocess.Popen(client_ns + ['python3', '-u', '-c', CLIENT, certificate,
                                  str(stop), json.dumps(DESTINATIONS), str(drain)], stdout=output)
    fixture.processes.append(client)

    def observations():
        return [json.loads(line) for line in path.read_text().splitlines(keepends=True)
                if line.endswith('\n')]

    def wait_for_traffic(since, fresh_vip):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            samples = [row for row in observations() if isinstance(row, list) and row[0] > since]
            if all(sum(row[2:4] == [profile, mode] and row[4].startswith(f'{profile}|{vip}|')
                       for row in samples) >= 2
                   for profile in vips for mode in ('old', 'new')
                   for vip in [vips[profile] if profile != 'ai' else
                               candidate if mode == 'old' else fresh_vip]):
                return
            time.sleep(.02)
        raise AssertionError(('return HTTPS evidence missing', fresh_vip, samples[-15:]))

    try:
        wait_for_traffic(0, candidate)
        before = fixture.swan('client', '--list-sas')
        assert not re.search(r'^ai: #', before, re.M), before
        candidate_id = re.search(r'^ai-next: #(\d+), ESTABLISHED', before, re.M)[1]
        assert watchdog.return_profile('ai', vips['ai']) == 75  # Establish the return IKE.
        assert f"vips = {vips['ai']}" in generated.read_text()
        status = watchdog.return_profile('ai', vips['ai'])      # Prove it and switch new flows.
        assert status == 75, 'return must be pending while candidate has a live socket'
        assert re.search(rf'^ai-next: #{candidate_id}, ESTABLISHED',
                         fixture.swan('client', '--list-sas'), re.M), 'candidate retired with a live LAN socket'
        state = watchdog.snapshot()
        assert state['ai'][1] == [vips['ai']] and state['ai'][3].split()[-1] == '2', state
        wait_for_traffic(time.monotonic_ns(), vips['ai'])
        fixture.swan('client', '--rekey', '--ike-id', candidate_id)
        sas = fixture.swan('client', '--list-sas')
        replacement_id = re.search(r'^ai-next: #(\d+), ESTABLISHED', sas, re.M)[1]
        assert replacement_id != candidate_id, sas
        print(f'Draining candidate IKE rekeyed {candidate_id} -> {replacement_id}', flush=True)
        assert watchdog.return_profile('ai', vips['ai']) == 75
        assert re.search(rf'^ai-next: #{replacement_id}, ESTABLISHED',
                         fixture.swan('client', '--list-sas'), re.M)
        wait_for_traffic(time.monotonic_ns(), vips['ai'])
        wait_for_old_ai_drain(fixture, observations, drain)
        for _ in range(3):
            status = watchdog.return_profile('ai', vips['ai'])
            if status == 0:
                break
            assert status == 75, status
        assert status == 0
        assert not re.search(r'^ai-next: #', fixture.swan('client', '--list-sas'), re.M)
        assert not watchdog.restarts
        stop.touch()
        assert client.wait(timeout=3) == 0
        samples = [row for row in observations() if isinstance(row, list)]
        proxy_log = (watchdog.proxy_log if watchdog.proxy.pid == watchdog.initial_pid else
                     fixture.directory / 'proxy-restart.log')
        redirects = set(re.findall(r'inbound/tun\[tun-in\]: inbound redirect connection from 198\.18\.1\.3:(\d+)',
                                   proxy_log.read_text()))
        unexpected = [row for row in samples if not row[4].startswith(row[2]+'|') or str(row[5]) not in redirects]
        assert not unexpected, unexpected[:10]
        assert all(row[4].split('|')[1] != '198.18.1.3' for row in samples)
        assert len({row[5] for row in samples if row[2:4] == ['ai', 'old']}) == 1
        print(f'IPsec return after retirement passed: {len(samples)} LAN HTTPS requests', flush=True)
        verify_return_while_draining(fixture, client_ns, certificate, watchdog, vips['ai'], candidate)
        for _ in range(5):
            status = watchdog.return_profile('ai', vips['ai'])
            if status == 0:
                break
            assert status == 75
        assert status == 0
        assert not (watchdog.root / 'run/dnscomplex/ipsec-ai-drain').exists()
        assert not re.search(r'^ai-next: #', fixture.swan('client', '--list-sas'), re.M)
        manager = watchdog.root / 'usr/local/sbin/dnscomplex'
        env = dict(os.environ, PATH=f'{watchdog.private_bin}:{os.environ["PATH"]}',
                   DNSCOMPLEX_FS_ROOT=str(watchdog.root), SSL_CERT_FILE=certificate)
        config = json.loads(watchdog.proxy_config.read_bytes())
        for outbound in config['outbounds']:
            if outbound['tag'] in ('ai-ipsec', 'cn-ipsec'):
                outbound['inet4_bind_address'] = vips[outbound['tag'].split('-')[0]]
        snapshot = watchdog.root / 'var/lib/dnscomplex/ipsec-bindings-before-upgrade.json'
        expected = (json.dumps(config, indent=2) + '\n').encode()
        snapshot.write_bytes(expected)
        result = subprocess.run([str(manager), 'restore', '--ipsec-bindings'], env=env,
                                capture_output=True, text=True, timeout=35)
        assert result.returncode == 0, result
        assert not snapshot.exists() and watchdog.proxy_config.read_bytes() == expected
        assert watchdog.proxy.poll() is None
        print('Binding rollback restored the snapshot byte for byte after candidate retirement', flush=True)

    finally:
        stop.touch()
        assert client.wait(timeout=3) == 0


def verify_return_while_draining(fixture, client_ns, certificate, watchdog, primary, candidate):
    stop = fixture.directory / 'return-live-primary.stop'
    path = fixture.directory / 'return-live-primary.jsonl'
    with path.open('w') as output:
        client = subprocess.Popen(client_ns + ['python3', '-u', '-c', CLIENT, certificate,
                                  str(stop), json.dumps(DESTINATIONS)], stdout=output)
    fixture.processes.append(client)
    try:
        deadline = time.monotonic() + 4
        while f'ai|{primary}|' not in path.read_text() and time.monotonic() < deadline:
            time.sleep(.02)
        assert f'ai|{primary}|' in path.read_text()
        fixture.initiate('ai-next', candidate)
        assert watchdog.run()['ai'][1] == [candidate]
        sas = fixture.swan('client', '--list-sas')
        primary_id = re.search(r'^ai: #(\d+), ESTABLISHED', sas, re.M)[1]
        result = watchdog.return_profile('ai', primary)
        assert result == 75
        assert watchdog.snapshot()['ai'][1] == [primary], 'return left new traffic on next while primary was draining'
        assert re.search(rf'^ai: #{primary_id}, ESTABLISHED',
                         fixture.swan('client', '--list-sas'), re.M), 'return retired the original primary'
        print('IPsec return while primary was draining passed', flush=True)
    finally:
        stop.touch()
        assert client.wait(timeout=3) == 0


def verify_binding_migration(fixture, client_ns, certificate, watchdog, interface_bindings):
    """Measure a planned proxy restart in each direction using the same IKEs."""
    run = fixture.run
    vips = {'ai': '10.250.1.22', 'cn': '10.251.1.10', 'default': '198.18.1.1'}
    assert interface_bindings == {'ai-ipsec': 'ipsec-ai', 'cn-ipsec': 'ipsec-cn'}
    prepare_application_routes(run)
    for _ in range(2):
        state = watchdog.run()
    assert all(state[p][2] for p in ('ai', 'cn')), state
    original = watchdog.proxy_config.read_bytes()
    candidate = json.loads(original)
    for outbound in candidate['outbounds']:
        tag = outbound['tag']
        if tag in interface_bindings:
            assert outbound['bind_interface'] == interface_bindings[tag]
            assert outbound.pop('inet4_bind_address') == vips[tag.split('-')[0]]
    candidate = (json.dumps(candidate, indent=2, ensure_ascii=False) + '\n').encode()
    initial_spi = {p: fixture.wait_installed(p, vips[p]) for p in ('ai', 'cn')}

    manager = watchdog.root / 'usr/local/sbin/dnscomplex'
    env = dict(os.environ, PATH=f'{watchdog.private_bin}:{os.environ["PATH"]}',
               DNSCOMPLEX_FS_ROOT=str(watchdog.root), SSL_CERT_FILE=certificate)
    invalid = fixture.directory / 'invalid-binding.json'
    invalid.write_text(json.dumps(dict(json.loads(original), log={'level': 'error'})))
    rejected = subprocess.run([str(manager), 'switch-ipsec-bindings', str(invalid)],
                              env=env, capture_output=True, text=True, timeout=15)
    assert rejected.returncode and 'changes settings outside' in rejected.stderr, rejected
    assert watchdog.proxy_config.read_bytes() == original
    assert 'dnscomplex_binding_switch' not in run(['nft', 'list', 'tables']).stdout
    print(run(['nft', 'list', 'tables']).stdout, flush=True)

    backup = watchdog.root / 'var/lib/dnscomplex/ipsec-bindings-before-upgrade.json'
    for label, command, config in (
        ('upgrade', 'update-software', candidate),
        ('rollback', 'restore', original),
    ):
        if label == 'rollback':
            active_config = watchdog.proxy_config.read_bytes()
            active_pid = watchdog.proxy.pid
            duplicate = subprocess.run(
                [str(manager), 'update-software', '--ipsec-bindings'], env=env,
                capture_output=True, text=True, timeout=15)
            assert duplicate.returncode and 'snapshot already exists' in duplicate.stderr, duplicate
            assert backup.read_bytes() == original

            stale = json.loads(original)
            next(item for item in stale['outbounds'] if item['tag'] == 'ai-ipsec')[
                'inet4_bind_address'] = '10.250.1.23'
            stale_bytes = json.dumps(stale).encode()
            backup.write_bytes(stale_bytes)
            try:
                rejected = subprocess.run(
                    [str(manager), 'restore', '--ipsec-bindings'], env=env,
                    capture_output=True, text=True, timeout=15)
                assert rejected.returncode and 'must match the active IPsec VIP' in rejected.stderr, rejected
                assert backup.read_bytes() == stale_bytes
                assert watchdog.proxy_config.read_bytes() == active_config
                assert watchdog.proxy.pid == active_pid and watchdog.proxy.poll() is None
                assert 'dnscomplex_binding_switch' not in run(['nft', 'list', 'tables']).stdout
            finally:
                backup.write_bytes(original)
            print('duplicate upgrade and stale rollback rejected before restart; snapshot preserved',
                  flush=True)
        path = fixture.directory / f'{label}.jsonl'
        stop = fixture.directory / f'{label}.stop'
        with path.open('w') as output:
            client = subprocess.Popen(client_ns + ['python3', '-u', '-c', CLIENT, certificate,
                                      str(stop), json.dumps(DESTINATIONS)], stdout=output)
        fixture.processes.append(client)

        def samples():
            return [json.loads(line) for line in path.read_text().splitlines(keepends=True)
                    if line.endswith('\n')]

        def wait_healthy(since, modes):
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                rows = samples()
                if all(sum(start >= since and profile == p and mode == m
                           and outcome.startswith(f'{p}|{vip}|')
                           for start, _, profile, mode, outcome, _ in rows) >= 5
                       for p, vip in vips.items() for m in modes):
                    return
                time.sleep(.02)
            raise AssertionError(f'{label}: expected healthy traffic missing: {rows[-20:]}')

        wait_healthy(0, ('new', 'old'))
        before = watchdog.proxy.pid
        restart_count = len(watchdog.restarts)
        switch = time.monotonic_ns()
        result = subprocess.run([str(manager), command, '--ipsec-bindings'],
                                env=env, capture_output=True, text=True, timeout=55)
        print(result.stdout + result.stderr, flush=True)
        assert result.returncode == 0, result
        assert len(watchdog.restarts) - restart_count == 1, watchdog.restarts
        assert 'dnscomplex_binding_switch' not in run(['nft', 'list', 'tables']).stdout
        state = watchdog.snapshot()
        assert all(state[p][2] for p in ('ai', 'cn')), state
        healthy = time.monotonic_ns()
        wait_healthy(healthy, ('new',))
        stop.touch()
        assert client.wait(timeout=2) == 0
        rows = samples()
        if label == 'upgrade':
            assert backup.read_bytes() == original
            assert backup.stat().st_mode & 0o777 == 0o600
            assert json.loads(watchdog.proxy_config.read_bytes()) == json.loads(config)
        else:
            assert watchdog.proxy_config.read_bytes() == original
            assert not backup.exists()
        assert watchdog.proxy.pid != before
        rules = run(['ip', '-4', 'rule', 'show']).stdout
        for profile, spi in initial_spi.items():
            assert fixture.wait_installed(profile, vips[profile]) == spi
            assert (f'oif ipsec-{profile}' in rules) == (label == 'upgrade')
        log = (fixture.directory / 'proxy-restart.log').read_text()
        if watchdog.proxy_log.exists():
            log += watchdog.proxy_log.read_text()
        redirects = set(re.findall(r'inbound/tun\[tun-in\]: inbound redirect connection from 198\.18\.1\.3:(\d+)', log))
        for profile, vip in vips.items():
            selected = [r for r in rows if r[2] == profile]
            failures = [r for r in selected if '|' not in r[4]]
            assert all(r[1] >= switch and r[0] < healthy for r in failures), failures
            wrong = [r for r in selected if '|' in r[4] and r[4].split('|')[0] != profile]
            bypass = [r for r in selected if '|' in r[4] and str(r[5]) not in redirects]
            wrong_source = [r for r in selected if '|' in r[4] and r[4].split('|')[1] != vip]
            assert not (wrong or bypass or wrong_source), (wrong[:3], bypass[:3], wrong_source[:3])
            affected = failures + wrong + bypass + wrong_source
            last_affected_ms = max(((r[1] - switch) / 1e6 for r in affected), default=0)
            recovery = next(r for r in selected if r[0] >= switch and r[3] == 'new'
                            and r[4].startswith(f'{profile}|{vip}|') and str(r[5]) in redirects)
            print(f'{label} {profile}: samples={len(selected)}, '
                  f'old_failed={sum(r[3] == "old" for r in failures)}, '
                  f'new_failed={sum(r[3] == "new" for r in failures)}, '
                  f'wrong_exit={len(wrong)}, bypass_TUN={len(bypass)}, wrong_source={len(wrong_source)}, '
                  f'last_affected_ms={last_affected_ms:.1f}, '
                  f'first_new_TUN_ms={(recovery[1]-switch)/1e6:.1f}', flush=True)
        print(f'{label}: proxy restarts={len(watchdog.restarts)-restart_count}, IKE SPIs unchanged', flush=True)
