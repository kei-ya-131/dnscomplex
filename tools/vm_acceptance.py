#!/usr/bin/env python3
"""Read-only VM acceptance collector. Never reboots, upgrades or injects faults."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate import ROOT, overall, preflight, run_step, source_identity

MANAGER = '/usr/local/sbin/dnscomplex'
CONFIG = '/etc/dnscomplex/config.env'
OPERATIONS = Path('/var/lib/dnscomplex-operations')
RESTORE = Path('/var/lib/dnscomplex-restore')
BINARIES = ('/usr/bin/sing-box', '/usr/sbin/smartdns', '/usr/local/bin/xray',
            '/opt/AdGuardHome/AdGuardHome')
CONFIGS = (CONFIG, '/etc/sing-box/config.json', '/etc/smartdns/smartdns.conf',
           '/etc/AdGuardHome/AdGuardHome.yaml', '/etc/nftables.d/dnscomplex.nft',
           '/etc/swanctl/swanctl.conf', '/usr/local/etc/xray/config.json',
           '/usr/local/lib/dnscomplex-config/candidate.py')


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            value.update(block)
    return value.hexdigest()


def write_new(path, record):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(Path(path).parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_private(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('evidence must be an owned private regular file')
    if info.st_size > 1024*1024:
        raise ValueError('evidence exceeds size limit')
    return json.loads(path.read_text())


def new_record(scenario, identity, boot_id, now, budget, operation=None):
    if scenario not in ('cold-boot', 'operation-interruption', 'component-rollback'):
        raise ValueError('unknown scenario')
    if not 60 <= budget <= 3600:
        raise ValueError('budget must be 60..3600 seconds')
    if scenario == 'operation-interruption':
        if not operation or operation.get('phase') != 'prepared':
            raise ValueError('capture a real operation in prepared phase before mutation')
        if not re.fullmatch('[a-f0-9]{32}', operation.get('id', '')):
            raise ValueError('invalid operation identity')
    return {'schema': 1, 'scenario': scenario, 'identity': identity, 'boot_id': boot_id,
            'started_at': now, 'deadline': now+budget, 'status': 'PENDING',
            'operation': operation}


def check_resume(record, identity, boot_id, now, operation=None):
    if record.get('schema') != 1 or record.get('status') != 'PENDING':
        raise ValueError('invalid or consumed record')
    if identity != record['identity']:
        raise ValueError('machine/source/config/binary identity changed')
    if not record['started_at'] <= now < record['deadline']:
        raise ValueError('acceptance deadline exceeded or clock moved backwards')
    if record['scenario'] != 'component-rollback' and boot_id == record['boot_id']:
        raise ValueError('boot ID did not change; whole-VM reboot not proven')
    if record['scenario'] == 'operation-interruption':
        before = record['operation']
        if (not operation or any(operation.get(k) != before.get(k)
                                 for k in ('id', 'action', 'candidate_sha256')) or
                operation.get('phase') != 'rolled-back' or operation.get('rollback_state') != 'verified'):
            raise ValueError('same operation must have a verified rollback')


def check_update_log(record, before, after, text):
    markers = ('starting application rollback', 'application rollback completed',
               'software component update failed and application changes were rolled back')
    if before == after or not all(marker in text for marker in markers) or 'rollback was incomplete' in text:
        raise ValueError('fresh completed component rollback evidence required')


def operation_record(oid):
    if not re.fullmatch('[a-f0-9]{32}', oid or ''):
        raise ValueError('a real operation ID is required')
    record = read_private(OPERATIONS/oid/'manifest.json')
    if record.get('id') != oid or record.get('owner_unit') != f'dnscomplex-operation@{oid}.service':
        raise ValueError('operation owner identity mismatch')
    return {key: record.get(key) for key in
            ('id', 'action', 'phase', 'candidate_sha256', 'rollback_state')}


def host_identity():
    source = (ROOT/'install.sh').read_text()
    expected = source.split("<<'MANAGER'\n", 1)[1].split('\nMANAGER\n', 1)[0]+'\n'
    if Path(MANAGER).read_bytes() != expected.encode():
        raise ValueError('installed manager differs from this installer source')
    return {'source': source_identity(), 'machine': sha('/etc/machine-id'),
            'files': {p: sha(p) for p in (*CONFIGS, *BINARIES, MANAGER)}}


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def validate_url(url):
    parsed = urlsplit(url)
    if parsed.scheme != 'http' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError('use a credential-free HTTP URL for this VM listener')
    return url


def validate_listener_urls(web, health, cfg, local_addresses):
    local = {ipaddress.ip_address(value) for value in local_addresses}
    for url, prefix, expected_path in ((web, 'DNSCOMPLEX_WEB', '/'),
                                        (health, 'DNSCOMPLEX_METRICS', '/healthz')):
        parsed = urlsplit(validate_url(url))
        try:
            host = ipaddress.ip_address(parsed.hostname)
            listen = ipaddress.ip_address(cfg[prefix+'_LISTEN'])
            port = int(cfg[prefix+'_PORT'])
        except (ValueError, KeyError):
            raise ValueError('listener must use a configured literal local IP/port') from None
        if (host not in local or (not listen.is_unspecified and host != listen) or
                host.version != listen.version or (parsed.port or 80) != port or
                parsed.path != expected_path):
            raise ValueError('HTTP evidence must target this VM configured listener and endpoint')


def host_config():
    spec = importlib.util.spec_from_file_location('vm_candidate', '/usr/local/lib/dnscomplex-config/candidate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.parse_env_file(CONFIG, module.ALLOWED_KEYS)


def local_addresses():
    output = subprocess.check_output(['ip', '-j', 'address', 'show'], timeout=5)
    if len(output) > 1024*1024:
        raise ValueError('local address inventory exceeds bound')
    return {address['local'] for interface in json.loads(output)
            for address in interface.get('addr_info', []) if 'local' in address}


def collect(directory, record, label):
    """Every command shares the original budget; no deadline reset on reboot."""
    commands = [
        ('health', [MANAGER, 'health', '--json'], 120),
        ('test', [MANAGER, 'test'], 120),
        ('web', ['curl', '--noproxy', '*', '--fail', '--silent', '--show-error',
                 '--max-time', '5', record['web_url']], 8),
        ('health-http', ['curl', '--noproxy', '*', '--fail', '--silent', '--show-error',
                         '--max-time', '5', record['health_url']], 8),
        ('jobs', ['systemctl', 'list-jobs', '--no-legend', '--no-pager'], 5),
    ]
    for profile, mode in record.get('egress_modes', {}).items():
        if mode == 'xray':
            commands.append(('xray-'+profile, [MANAGER, 'test-xray', profile], 60))
    results = []
    for name, command, cap in commands:
        remaining = record['deadline']-time.time()
        if remaining <= 0:
            raise ValueError('acceptance deadline exceeded')
        result = run_step(label+'-'+name, command, ROOT, directory, min(remaining, cap))
        results.append(result)
        if result['status'] != 'PASS':
            raise ValueError(f'{name} check failed; inspect {result["log"]}')
        if name == 'health':
            health = json.loads(Path(result['log']).read_text())
            if health.get('status') != 'healthy' or not health.get('checks'):
                raise ValueError('complete healthy runtime evidence required')
        if name == 'health-http':
            health = json.loads(Path(result['log']).read_text())
            if health.get('status') != 'healthy':
                raise ValueError('healthy HTTP sample required')
        if name == 'jobs' and re.search(r'dnscomplex|sing-box|smartdns|AdGuardHome|nftables|xray|strongswan', Path(result['log']).read_text()):
            raise ValueError('managed service job still running')
    for path in OPERATIONS.glob('*/manifest.json'):
        value = read_private(path)
        if value.get('phase') not in ('committed', 'rolled-back'):
            # The one prepared operation is allowed only in the pre-reboot capture.
            if label != 'before' or value.get('id') != (record.get('operation') or {}).get('id') or value.get('phase') != 'prepared':
                raise ValueError('unfinished operation/recovery remains')
    remaining_journals = list(RESTORE.glob('transaction.*')) + list(RESTORE.glob('cleanup.transaction.*'))
    allowed = 'transaction.op.'+(record.get('operation') or {}).get('id', '')
    if any(label != 'before' or path.name != allowed for path in remaining_journals):
        raise ValueError('recovery journal cleanup incomplete')
    if time.time() >= record['deadline']:
        raise ValueError('acceptance completed after deadline')
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prepare = sub.add_parser('prepare')
    prepare.add_argument('--scenario', choices=('cold-boot', 'operation-interruption', 'component-rollback'), required=True)
    prepare.add_argument('--output', type=Path, required=True)
    prepare.add_argument('--budget', type=int, default=900)
    prepare.add_argument('--operation-id')
    prepare.add_argument('--web-url', type=validate_url, required=True)
    prepare.add_argument('--health-url', type=validate_url, required=True)
    verify = sub.add_parser('verify')
    verify.add_argument('--record', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise ValueError('run as root on the designated disposable VM')
        versions = preflight('native')
        if args.action == 'prepare':
            args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
            os.chmod(args.output, 0o700)
            identity = host_identity()
            cfg = host_config()
            validate_listener_urls(args.web_url, args.health_url, cfg, local_addresses())
            operation = operation_record(args.operation_id) if args.scenario == 'operation-interruption' else None
            record = new_record(args.scenario, identity, boot_id(), time.time(), args.budget, operation)
            record.update(web_url=args.web_url, health_url=args.health_url, versions=versions)
            record['egress_modes'] = {p: cfg[p.upper()+'_EGRESS_MODE'] for p in ('ai', 'cn')}
            update_log = Path('/var/log/dnscomplex/update-latest.log')
            record['update_log_before'] = sha(update_log) if update_log.exists() else None
            record['before'] = collect(args.output, record, 'before')
            if host_identity() != identity:
                raise ValueError('identity changed during baseline collection')
            if operation and operation_record(operation['id']) != operation:
                raise ValueError('operation moved during baseline; use a controlled prepared-phase hold')
            write_new(args.output/'prepared.json', record)
            print(json.dumps({'status': 'PENDING', 'record': str(args.output/'prepared.json')}))
            return 0
        record = read_private(args.record)
        directory = args.record.parent/'verification'
        directory.mkdir(mode=0o700, exist_ok=False)  # one attempt; never overwrite evidence
        report = {'status': 'FAIL', 'scope': 'VM-local checks only; external LAN/RouterOS acceptance remains required'}
        try:
            identity = host_identity()
            validate_listener_urls(record['web_url'], record['health_url'], host_config(), local_addresses())
            operation = operation_record(record['operation']['id']) if record.get('operation') else None
            check_resume(record, identity, boot_id(), time.time(), operation)
            if record['scenario'] == 'component-rollback':
                update_log = Path('/var/log/dnscomplex/update-latest.log')
                if update_log.stat().st_size > 16*1024*1024:
                    raise ValueError('update log exceeds evidence bound')
                text = update_log.read_text(errors='replace')
                check_update_log(record, record['update_log_before'], sha(update_log), text)
                if update_log.stat().st_mtime < record['started_at']:
                    raise ValueError('rollback log predates baseline')
                # Keep the actual log privately, rather than a caller-provided success flag.
                write_new(directory/'component-rollback-log.json', {'text': text})
            report['steps'] = collect(directory, record, 'after')
            check_resume(record, host_identity(), boot_id(), time.time(), operation)
            report.update(status='PASS', boot_id=boot_id(), completed_at=time.time(),
                          prepared_sha256=sha(args.record), operation=operation)
        except (ValueError, OSError, KeyError) as exc:
            report['error'] = str(exc)
        write_new(directory/'result.json', report)
        print(json.dumps(report))
        return 0 if report['status'] == 'PASS' else 1
    except (ValueError, OSError, KeyError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
