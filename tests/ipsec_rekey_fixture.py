"""Real strongSwan peers for the isolated transparent HTTPS regression."""
import json
from pathlib import Path
import re
import subprocess
import time


class RekeyFixture:
    def __init__(self, directory, run, processes):
        self.directory = directory
        self.run = run
        self.processes = processes
        self.daemons = {}
        self.underlays = {}

    def xfrm_links(self, namespace, profile, number, underlay):
        interface_id = str(100 + number)
        for prefix, device, link in (
            ([], 'ipsec-' + profile, underlay),
            (namespace, 'xfrm-peer', f'peer{number}'),
        ):
            self.run(prefix + ['ip', 'link', 'add', device, 'type', 'xfrm',
                               'dev', link, 'if_id', interface_id])
            self.run(prefix + ['ip', 'link', 'set', device, 'mtu', '1400', 'up'])
        self.underlays[profile] = (namespace, number)

    def swan(self, daemon, *arguments):
        process = self.daemons[daemon]
        assert process.poll() is None, f'isolated charon {daemon} exited'
        command = ['nsenter', '-t', str(process.pid), '--mount', '--net', '--root',
                   'swanctl', *arguments, '--uri', 'unix:///var/run/charon.vici']
        result = subprocess.run(command, capture_output=True, text=True, timeout=8)
        if result.returncode:
            log = (self.directory / (daemon + '.log')).read_text()
            raise RuntimeError(f'{daemon} {arguments}: {result.stdout}\n{result.stderr}\n{log}')
        return result.stdout

    def start_daemon(self, name, namespace):
        config = self.directory / (name + '.conf')
        swanctl_dir = self.directory / (name + '-swanctl')
        swanctl_dir.mkdir()
        config.write_text('''
charon {
    install_routes = no
    load = random nonce aes sha1 sha2 hmac kdf gmp openssl kernel-netlink socket-default vici
}
''')
        log = self.directory / (name + '.log')
        # The standard paths resolve to private mounts and keep AppArmor active.
        with log.open('w') as output:
            daemon = subprocess.Popen(namespace + [
                'unshare', '--mount', '--propagation', 'private', 'sh', '-ec',
                'mount -t tmpfs tmpfs /run && '
                'mount --bind "$1" /etc/strongswan.conf && '
                'mount --bind "$2" /etc/swanctl && '
                'exec env -u STRONGSWAN_CONF /usr/lib/ipsec/charon',
                'fixture-charon', str(config), str(swanctl_dir),
            ], stdout=output, stderr=output)
        self.processes.append(daemon)
        self.daemons[name] = daemon
        path = Path(f'/proc/{daemon.pid}/root/run/charon.vici')
        production_run = Path('/run').stat()
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline and daemon.poll() is None:
            try:
                isolated_run = path.parent.stat()
                if ((isolated_run.st_dev, isolated_run.st_ino) !=
                        (production_run.st_dev, production_run.st_ino) and path.is_socket()):
                    return
            except FileNotFoundError:
                pass
            time.sleep(.025)
        raise RuntimeError(f'{name} did not start: {log.read_text()}')

    def configure(self, selectors=None, *, named_overlap=False):
        configurations = {'client': []}
        pools = {'client': []}
        self.start_daemon('client', [])
        for profile, (namespace, number) in self.underlays.items():
            self.start_daemon(profile, namespace)
            configurations[profile] = []
            pools[profile] = []
            connections = (('ai', '10.250.1.22'), ('ai-next', '10.250.1.23')) if profile == 'ai' else (
                ('cn', '10.251.1.10'),
            )
            for name, vip in connections:
                self.run(namespace + ['ip', 'route', 'add', vip + '/32', 'dev', 'xfrm-peer'])
                destinations = selectors[profile] if selectors else '192.0.2.10/32'
                for daemon, local, remote, local_ts, remote_ts, extra in (
                    ('client', 1, 2, 'dynamic', destinations, 'vips = 0.0.0.0'),
                    (profile, 2, 1, destinations, 'dynamic', f'pools = pool-{name}'),
                ):
                    start = 'start_action = start' if named_overlap and daemon == 'client' and name == 'ai' else ''
                    if named_overlap and daemon == 'client' and name == 'ai-next':
                        extra = f'vips = {vip}'
                    configurations[daemon].append(f'''
{name} {{
    version = 2
    local_addrs = 198.18.{number}.{local}
    remote_addrs = 198.18.{number}.{remote}
    proposals = aes128-sha256-modp2048
    rekey_time = 0
    {extra}
    local {{
        auth = psk
        id = {daemon}-{name}.fixture.test
    }}
    remote {{
        auth = psk
        id = {'client' if local == 2 else profile}-{name}.fixture.test
    }}
    children {{
        {name} {{
            local_ts = {local_ts}
            remote_ts = {remote_ts}
            esp_proposals = aes128gcm16
            if_id_in = {100 + number}
            if_id_out = {100 + number}
            rekey_time = 0
            {start}
        }}
    }}
}}
''')
                pools[profile].append(f'pool-{name} {{\n addrs = {vip}/32\n}}')
        for daemon in (*self.underlays, "client"):
            connections = configurations[daemon]
            config = self.directory / (daemon + '-swanctl') / 'swanctl.conf'
            full_config = (
                'connections {\n' + ''.join(connections) + '}\npools {\n'
                + '\n'.join(pools[daemon])
                + '\n}\nsecrets {\n ike-fixture {\n'
                ' secret = "isolated-regression-fixture-only"\n }\n}\n'
            )
            if named_overlap and daemon == 'client':
                self.named_overlap_config = full_config
                candidate, = [block for block in connections if block.startswith('\nai-next {')]
                full_config = full_config.replace(candidate, '', 1)
            config.write_text(full_config)
            self.swan(daemon, '--load-all', '--file', '/etc/swanctl/swanctl.conf')
        for name, vip in (('ai', '10.250.1.22'), ('cn', '10.251.1.10')):
            if named_overlap and name == 'ai':
                self.wait_installed(name, vip)
            else:
                self.initiate(name, vip)

    def initiate(self, name, vip):
        self.swan('client', '--initiate', '--child', name, '--timeout', '5')
        return self.wait_installed(name, vip)

    def wait_installed(self, name, vip, previous_spi=None):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            sas = self.swan('client', '--list-sas', '--ike', name)
            for block in re.split(r'(?m)^  (?=\S)', sas)[1:]:
                if not block.startswith(name + ':') or 'INSTALLED' not in block:
                    continue
                spi = re.search(r'\bout\s+([0-9a-f]+)', block)
                if spi and spi[1] != previous_spi and re.search(r'\blocal\s+' + re.escape(vip) + r'/32', block):
                    print(f'{name}: CHILD_SA installed VIP={vip} ESP-out={spi[1]}', flush=True)
                    return spi[1]
            time.sleep(.025)
        raise AssertionError(f'{name} VIP {vip} did not install with expected new SPI:\n{sas}')

    def packets(self, spi):
        # iproute2 output contains ephemeral key material. Report counters only.
        states = self.run(['ip', '-s', 'xfrm', 'state']).stdout
        for block in re.split(r'(?m)(?=^src )', states):
            if f'spi 0x{spi}' in block:
                counter = re.search(r'\b(\d+)\(packets\)', block)
                if counter:
                    return int(counter[1])
        raise AssertionError(f'outbound ESP SPI {spi} missing')


CLIENT = r'''
import concurrent.futures, http.client, json, os, socket, ssl, sys, time
from pathlib import Path

context = ssl.create_default_context(cafile=sys.argv[1])
stop_file = Path(sys.argv[2])
addresses = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
drain = Path(sys.argv[4]) if len(sys.argv) > 4 else None
domains = {'ai': 'ai.fixture.test', 'cn': 'video.fixture.test', 'default': 'ordinary.fixture.test'}

def probe(profile, mode):
    host = domains[profile]
    connection = http.client.HTTPSConnection(host, 19443, timeout=0.7, context=context)
    # Keep SNI and certificate checking while controlling fixture DNS.
    connection._create_connection = lambda address, *args: socket.create_connection(
        (addresses.get(profile, '192.0.2.10'), address[1]), *args)
    deadline = time.monotonic() + 60
    established = False
    while time.monotonic() < deadline and not stop_file.exists():
        if mode == 'old' and profile == 'ai' and drain and drain.exists():
            connection.close()
            os.write(1, b'"ai old closed by client"\n')
            return
        start = time.monotonic_ns()
        failed = False
        client_port = None
        try:
            if connection.sock is None:
                if mode == 'old' and established:
                    raise OSError('old connection closed')
                connection.connect()
            client_port = connection.sock.getsockname()[1]
            connection.request('GET', '/keepalive')
            response = connection.getresponse()
            body = response.read().decode()
            if response.status != 200:
                raise ValueError(f'HTTP {response.status}')
            established = True
            if mode == 'new':
                connection.close()
            outcome = body
        except (OSError, http.client.HTTPException, ValueError) as error:
            failed = True
            outcome = type(error).__name__
            if mode == 'new':
                connection.close()
        row = json.dumps([start, time.monotonic_ns(), profile, mode, outcome, client_port])
        os.write(1, (row + '\n').encode())
        if mode == 'old' and failed:
            return
        time.sleep(0.005)

with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    jobs = [pool.submit(probe, profile, mode) for profile in domains for mode in ('old', 'new')]
    for job in jobs:
        job.result()
'''


def wait_for_old_ai_drain(fixture, read_samples, drain):
    drain.touch()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        rows = read_samples()
        if 'ai old closed by client' in rows:
            last_old = [row for row in rows if isinstance(row, list)
                        and row[2:4] == ['ai', 'old']][-1]
            profile, _, port = last_old[4].split('|')
            assert profile == 'ai'
            namespace = fixture.underlays['ai'][0]
            if not fixture.run(namespace + ['ss', '-Htn', 'state', 'established',
                                            f'dport = :{port}']).stdout:
                return
        time.sleep(.02)
    raise AssertionError('old AI connection did not drain before IKE retirement')


def verify_real_rekey(run, fixture, client_ns, certificate, proxy, drain_old=False):
    old_vip, new_vip = '10.250.1.22', '10.250.1.23'
    vips = {'ai': old_vip, 'cn': '10.251.1.10', 'default': '198.18.1.1'}
    nft = ['nft']
    table = ['inet', 'dnscomplex']
    markers = {}

    def event(name):
        markers[name] = time.monotonic_ns()
        print(f'{markers[name]} {name}', flush=True)

    def route(profile, vip):
        device = 'ipsec-' + profile
        route_table = '301' if profile == 'ai' else '351'
        run(['ip', 'route', 'replace', 'default', 'dev', device,
             'src', vip, 'table', route_table])
        actual = run(['ip', 'route', 'get', '192.0.2.10', 'oif', device]).stdout
        assert f'src {vip}' in actual, actual

    for name in ('lan_alias_config_ready4', 'ai_ready4', 'cn_ready4'):
        run(nft + ['add', 'element'] + table + [name, '{', '0.0.0.0/0', '}'])
    run(nft + ['add', 'chain'] + table + [
        'fixture_source_guard', '{ type filter hook output priority -1; policy accept; }'])
    for profile, number, route_table in (('ai', 2, '301'), ('cn', 3, '351')):
        device = 'ipsec-' + profile
        run(['ip', 'rule', 'add', 'priority', str(12000 + number),
             'oif', device, 'lookup', route_table])
        run(nft + ['add', 'set'] + table + [
            f'fixture_{profile}_vip', '{ type ipv4_addr; }'])
        run(nft + ['add', 'element'] + table + [
            f'fixture_{profile}_vip', '{', vips[profile], '}'])
        run(nft + ['add', 'rule'] + table + ['fixture_source_guard',
            'oifname', device, 'ip', 'saddr', '!=', f'@fixture_{profile}_vip', 'counter', 'drop'])
        route(profile, vips[profile])

    samples_path = fixture.directory / 'traffic.jsonl'
    stop_file = fixture.directory / 'traffic.stop'
    drain = fixture.directory / 'traffic-ai-drain'
    with samples_path.open('w') as output:
        client = subprocess.Popen(client_ns + [
            'python3', '-u', '-c', CLIENT, certificate, str(stop_file), '{}', str(drain)],
                                  stdout=output)
    fixture.processes.append(client)

    def read_samples():
        return [json.loads(line) for line in samples_path.read_text().splitlines(keepends=True)
                if line.endswith('\n')]

    def samples():
        return [row for row in read_samples() if isinstance(row, list)]

    def await_samples(since, old_ai, new_ai):
        expected = {(profile, mode): (old_ai if mode == 'old' else new_ai)
                    if profile == 'ai' else vip
                    for profile, vip in vips.items() for mode in ('old', 'new')}
        if old_ai is None:
            del expected['ai', 'old']
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            counts = dict.fromkeys(expected, 0)
            for start, _, profile, mode, result, _port in samples():
                if start <= since or (profile, mode) not in expected:
                    continue
                vip = expected[profile, mode]
                if result.startswith(f'{profile}|{vip}|'):
                    counts[profile, mode] += 1
            if all(value >= 2 for value in counts.values()):
                return
            time.sleep(.025)
        raise AssertionError(f'missing expected samples: {counts}; recent={samples()[-12:]}')

    await_samples(0, old_vip, old_vip)
    initial_spi = fixture.wait_installed('ai', old_vip)
    cn_spi = fixture.wait_installed('cn', vips['cn'])
    cn_packets = fixture.packets(cn_spi)
    event('AI CHILD rekey requested')
    fixture.swan('client', '--rekey', '--child', 'ai')
    new_spi = fixture.wait_installed('ai', old_vip, initial_spi)
    event('AI CHILD rekey installed, same VIP')
    await_samples(markers['AI CHILD rekey installed, same VIP'], old_vip, old_vip)
    assert fixture.packets(new_spi) > 0, 'new ESP SA carried no outbound packets'

    event('AI replacement IKE requested')
    replacement_spi = fixture.initiate('ai-next', new_vip)
    assigned = run(['ip', '-4', '-o', 'addr', 'show']).stdout
    assert re.search(r'\binet ' + re.escape(new_vip) + r'/', assigned), assigned
    event('AI replacement VIP and CHILD installed')
    await_samples(markers['AI replacement VIP and CHILD installed'], old_vip, old_vip)

    run(nft + ['add', 'element'] + table + ['fixture_ai_vip', '{', new_vip, '}'])
    event('AI guard allows both installed VIPs')
    await_samples(markers['AI guard allows both installed VIPs'], old_vip, old_vip)
    route('ai', new_vip)
    event('AI preferred source switched to new VIP')
    await_samples(markers['AI preferred source switched to new VIP'], old_vip, new_vip)
    assert fixture.packets(replacement_spi) > 0, 'replacement ESP SA carried no outbound packets'
    if drain_old:
        wait_for_old_ai_drain(fixture, read_samples, drain)
        event('AI old connection finished and peer socket drained')

    event('AI old IKE retirement requested')
    fixture.swan('client', '--terminate', '--ike', 'ai', '--timeout', '5')
    assigned = run(['ip', '-4', '-o', 'addr', 'show']).stdout
    assert not re.search(r'\binet ' + re.escape(old_vip) + r'/', assigned), assigned
    event('AI old IKE retired and VIP removed')
    run(nft + ['delete', 'element'] + table + ['fixture_ai_vip', '{', old_vip, '}'])
    event('AI guard allows only new VIP')
    if not drain_old:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if any(end >= markers['AI old IKE retirement requested'] and p == 'ai'
                   and m == 'old' and '|' not in result
                   for _, end, p, m, result, _port in samples()):
                break
            time.sleep(.025)
        else:
            raise AssertionError('old AI TCP connection did not report retirement interruption')
    await_samples(markers['AI guard allows only new VIP'], None, new_vip)
    assert fixture.wait_installed('cn', vips['cn']) == cn_spi
    assert fixture.packets(cn_spi) > cn_packets
    assert proxy.poll() is None
    event('measurement end')
    stop_file.touch()
    assert client.wait(timeout=2) == 0, 'traffic sampler exited unsuccessfully'

    observations = samples()
    stable_connections = {}
    totals = {}
    maximum_ms = {}
    during_rekey = {}
    failures = []
    for start, end, profile, mode, result, _port in observations:
        if end > markers['measurement end']:
            continue
        key = profile, mode
        totals[key] = totals.get(key, 0) + 1
        if (start < markers['AI CHILD rekey installed, same VIP']
                and end > markers['AI CHILD rekey requested']):
            during_rekey[key] = during_rekey.get(key, 0) + 1
        fields = result.split('|')
        if len(fields) != 3:
            failures.append((profile, mode, result))
            assert profile == 'ai' and mode == 'old' and end >= markers['AI old IKE retirement requested'], result
            continue
        maximum_ms[key] = max(maximum_ms.get(key, 0), (end - start) / 1e6)
        actual_profile, vip, connection_id = fields
        assert actual_profile == profile, (profile, mode, result)
        if profile != 'ai':
            assert vip == vips[profile], result
        elif mode == 'old':
            assert vip == old_vip, result
        elif end <= markers['AI guard allows both installed VIPs']:
            assert vip == old_vip, result
        elif start >= markers['AI preferred source switched to new VIP']:
            assert vip == new_vip, result
        else:
            assert vip in (old_vip, new_vip), result
        if mode == 'old':
            assert stable_connections.setdefault(profile, connection_id) == connection_id, result
    assert len(failures) == (0 if drain_old else 1) and len(stable_connections) == 3, failures
    assert len(during_rekey) == 6, f'Insufficient traffic during the rekey: {during_rekey}'
    for key, total in sorted(totals.items()):
        print(f'{key}: requests={total}, overlapping_rekey={during_rekey[key]}, '
              f'max_success_ms={maximum_ms[key]:.1f}', flush=True)
    guard = run(nft + ['list', 'chain'] + table + ['fixture_source_guard']).stdout
    print(guard, flush=True)
    print(f'interruptions={failures}; wrong exits=0; same sing-box PID {proxy.pid}', flush=True)
