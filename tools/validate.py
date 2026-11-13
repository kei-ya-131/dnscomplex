#!/usr/bin/env python3
"""Bounded orchestration of existing public tests; no host service mutations."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


class Unavailable(ValueError):
    pass
CORE = (
    'web_operation_lifecycle', 'web_operation_contract', 'soak_resource_limits',
    'web_mutation_consistency', 'profile_mutation_safety', 'state_transaction_safety',
    'domain_split_contract', 'egress_probe', 'xray_transport_profile',
    'watchdog_profile_isolation', 'profile_dataplane_probe', 'geosite_live_publication', 'redaction_crypto',
    'quic_health_policy', 'validation_runner', 'vm_acceptance', 'trace_domain_diagnostics',
)
SERVICES = (
    ('apple_ai_domain_sources', ['--native-srs']),
    ('smartdns_group_isolation', []), ('smartdns_https_record', []),
    ('smartdns_slow_upstream', ['--installer', 'install.sh']),
    ('adguard_auth_safety', []),
)
SKIP = re.compile(r'^\s*(?:OK \(skipped=[1-9]\d*\)|SKIP(?:PED)?[: ]|.*\.\.\. skipped )', re.M)


def source_identity(root=ROOT):
    """Include dirty/untracked deliverables, independent of the commit label."""
    files = [root/'install.sh', root/'README.md', root/'examples/routeros-policy.config.env']
    for directory in ('tools', 'tests', '.github/workflows'):
        files.extend(p for p in (root/directory).rglob('*')
                     if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc')
    digest = hashlib.sha256()
    for path in sorted(set(files)):
        if path.exists():
            digest.update(str(path.relative_to(root)).encode()+b'\0')
            digest.update(path.read_bytes()+b'\0')
    return digest.hexdigest()


def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    # The leader can exit while grandchildren ignore TERM.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=3)


def run_step(name, argv, cwd, log_dir, timeout, max_log_bytes=16*1024*1024):
    log = Path(log_dir)/f'{name}.log'
    result = {'name': name, 'argv': list(map(str, argv)), 'log': str(log.resolve()),
              'status': 'FAIL', 'returncode': None, 'reason': ''}
    started = time.monotonic()
    with log.open('xb') as output:
        try:
            process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=True, stdin=subprocess.DEVNULL)
        except OSError as exc:
            output.write(str(exc).encode())
            result['reason'] = 'command-unavailable'
        else:
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            written = 0
            try:
                while selector.get_map():
                    if time.monotonic()-started >= timeout:
                        result['reason'] = 'timeout'
                        break
                    for key, _ in selector.select(min(.05, max(0, timeout-(time.monotonic()-started)))):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        available = max_log_bytes-written
                        output.write(data[:available]); written += min(len(data), available)
                        if len(data) > available:
                            result['reason'] = 'output-limit'
                            break
                    if result['reason']:
                        break
                if not result['reason'] and process.poll() is None:
                    try:
                        process.wait(timeout=max(.001, timeout-(time.monotonic()-started)))
                    except subprocess.TimeoutExpired:
                        result['reason'] = 'timeout'
                if not result['reason'] and time.monotonic()-started >= timeout:
                    result['reason'] = 'timeout'
            finally:
                selector.close()
                stop_group(process)
                process.stdout.close()
            result['returncode'] = process.returncode
    if log.stat().st_size > max_log_bytes:
        result['reason'] = result['reason'] or 'output-limit'
    text = log.read_bytes()[:max_log_bytes].decode(errors='replace')
    if not result['reason'] and result['returncode'] == 0:
        result['status'] = 'SKIP' if SKIP.search(text) else 'PASS'
        if result['status'] == 'SKIP':
            result['reason'] = 'nested-test-skipped'
    result['elapsed_seconds'] = round(time.monotonic()-started, 3)
    return result


def overall(results):
    if not results or any(r['status'] == 'FAIL' for r in results):
        return 'FAIL'
    return 'SKIP' if any(r['status'] == 'SKIP' for r in results) else 'PASS'


def preflight(suite):
    required = ['bash', 'python3', 'jq']
    if suite == 'core':
        required.append('node')
    if suite in ('native', 'services'):
        if platform.system() != 'Linux':
            raise ValueError(f'{suite} requires Debian 13 Linux; no native evidence collected')
        release = Path('/etc/os-release').read_text()
        fields = dict(line.split('=', 1) for line in release.splitlines() if '=' in line)
        if fields.get('ID', '').strip('"') != 'debian' or fields.get('VERSION_ID', '').strip('"') != '13':
            raise ValueError(f'{suite} acceptance requires Debian 13')
        if suite == 'native':
            required += ['unshare', 'nsenter', 'ip', 'nft', 'openssl', 'timeout']
        else:
            required += ['sing-box', 'smartdns', 'ss', '/opt/AdGuardHome/AdGuardHome']
    missing = [name for name in required if not shutil.which(name)]
    if missing:
        raise ValueError('missing tools: '+', '.join(missing))
    try:
        import bcrypt  # noqa: F401
        import yaml  # noqa: F401
    except ImportError as exc:
        raise ValueError('python3 requires bcrypt and yaml') from exc
    versions = {'python': sys.version.split()[0], 'platform': platform.platform()}
    for name in required:
        flag = '-Version' if name == 'ip' else ('-v' if name == 'smartdns' else '--version')
        if name == 'sing-box':
            flag = 'version'
        if name == 'openssl':
            flag = 'version'
        proc = subprocess.run([name, flag], capture_output=True, text=True, timeout=5)
        versions[name] = (proc.stdout+proc.stderr).splitlines()[:1]
    if suite == 'native':
        probe = subprocess.run(['unshare', '--net', '--mount', '--propagation', 'private',
                                'nft', 'list', 'tables'], capture_output=True, text=True, timeout=5)
        if probe.returncode:
            raise ValueError('private network/mount namespaces or nft capability unavailable: '+probe.stderr[:1000])
    return versions


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', required=True, choices=('core', 'native', 'services'))
    parser.add_argument('--output', type=Path, required=True, help='new private evidence directory')
    args = parser.parse_args(argv)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(args.output, 0o700)
    identity = source_identity()
    report = {'suite': args.suite, 'source_sha256': identity, 'status': 'FAIL', 'steps': [],
              'other_required_layers_not_run': [s for s in ('core', 'services', 'native', 'VM/LAN') if s != args.suite],
              'scope': {'core': 'public portable regression; service-binary tests are separate',
                        'services': 'real local sing-box SRS reload and SmartDNS wire; not provider/App acceptance',
                        'native': 'private nft readiness and fixture TLS/DoH wire only; not whole VM/provider/App acceptance'}[args.suite]}
    try:
        try:
            report['versions'] = preflight(args.suite)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            raise Unavailable(str(exc)) from exc
        if args.suite == 'core':
            commands = [('syntax', ['bash', '-n', 'install.sh'], 30),
                        ('installer-contract', ['bash', 'tests/install_contract_test.sh'], 1200)]
            commands += [(name, [sys.executable, f'tests/{name}_test.py'],
                          600 if name == 'web_operation_lifecycle' else 180) for name in CORE]
            commands += [('mss', ['bash', 'tests/nft_mss_test.sh'], 120),
                         ('smartdns-cache-preflight', ['bash', 'tests/smartdns_cache_preflight_test.sh'], 120)]
            for name, command, limit in commands:
                result = run_step(name, command, ROOT, args.output, limit)
                report['steps'].append(result)
                print(f'{result["status"]} {name}', flush=True)
                if result['status'] == 'FAIL':
                    break
        elif args.suite == 'services':
            for name, options in SERVICES:
                command = [sys.executable, f'tests/{name}_test.py', *options]
                if name == 'adguard_auth_safety':
                    command = ['env', 'ADGUARD_BINARY=/opt/AdGuardHome/AdGuardHome', *command]
                result = run_step(name, command,
                                  ROOT, args.output, 240)
                report['steps'].append(result)
                print(f'{result["status"]} {name}', flush=True)
                if result['status'] != 'PASS':
                    break
        else:
            with tempfile.TemporaryDirectory(prefix='dnscomplex-native-') as td:
                temporary = Path(td)
                config = temporary/'config.env'
                config.write_text((ROOT/'examples/routeros-policy.config.env').read_text()
                                  .replace('CHANGE_ME_AI_USER', 'fixture-ai')
                                  .replace('CHANGE_ME_AI_PASSWORD', 'fixture-ai-pass')
                                  .replace('CHANGE_ME_CN_USER', 'fixture-cn')
                                  .replace('CHANGE_ME_CN_PASSWORD', 'fixture-cn-pass'))
                render = temporary/'root'
                command = ['env', f'DNSCOMPLEX_ROOT={render}', 'bash', 'install.sh',
                           '--dry-run', '--config', str(config)]
                steps = [('render', command, 120),
                         ('readiness-wire', [sys.executable, 'tests/nft_readiness_gate_wire_test.py',
                                             '--runtime-script', str(render/'usr/local/sbin/dnscomplex')], 45),
                         ('doh-wire', [sys.executable, 'tests/profile_dataplane_probe_wire_test.py',
                                      '--module', str(render/'usr/local/lib/dnscomplex/profile-dataplane-probe.py')], 85)]
                for name, command, limit in steps:
                    result = run_step(name, command, ROOT, args.output, limit)
                    report['steps'].append(result)
                    print(f'{result["status"]} {name}', flush=True)
                    if result['status'] != 'PASS':
                        break
        report['status'] = overall(report['steps'])
    except Unavailable as exc:
        report.update(status='SKIP', error=str(exc))
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        report['error'] = str(exc)
    finally:
        if source_identity() != identity:
            report.update(status='FAIL', error='source changed during acceptance')
        (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'status': report['status'], 'report': str(args.output/'report.json')}))
    return 0 if report['status'] == 'PASS' else (2 if report['status'] == 'SKIP' else 1)


if __name__ == '__main__':
    raise SystemExit(main())
