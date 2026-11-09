#!/usr/bin/env python3
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


INSTALLER = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()


def unit(name):
    declaration = f'write_file /etc/systemd/system/{name} <<'
    return INSTALLER.split(declaration, 1)[1].split('\n', 1)[1].split('\nEOF\n', 1)[0]


class BootLifecycleTest(unittest.TestCase):
    def test_interface_service_orders_active_strongswan_backend(self):
        text = unit('dnscomplex-ipsec-ifaces.service')
        before = next(line for line in text.splitlines() if line.startswith('Before='))
        self.assertIn('strongswan-starter.service', before.removeprefix('Before=').split())

    def test_interface_service_deletes_links_only_when_systemd_is_not_shutting_down(self):
        text = unit('dnscomplex-ipsec-ifaces.service')
        stop = next(line for line in text.splitlines() if line.startswith('ExecStop='))
        argv = shlex.split(stop.removeprefix('ExecStop=').replace('$$', '$'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / 'calls'
            for state, expected in [('stopping', False), ('', False), ('running', True), ('degraded', True)]:
                with self.subTest(state=state):
                    systemctl = root / 'systemctl'
                    systemctl.write_text(f'#!/bin/sh\nprintf "%s\\n" {shlex.quote(state)}\nexit {0 if state == "running" else 1}\n')
                    manager = root / 'dnscomplex'
                    manager.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" > {shlex.quote(str(calls))}\n')
                    for script in (systemctl, manager):
                        script.chmod(0o700)
                    calls.unlink(missing_ok=True)
                    command = [a.replace('/usr/bin/systemctl', str(systemctl)).replace('/usr/local/sbin/dnscomplex', str(manager)) for a in argv]
                    subprocess.run(command, check=True, capture_output=True, timeout=5)
                    self.assertEqual(calls.exists(), expected)
                    if expected:
                        self.assertEqual(calls.read_text().strip(), 'ipsec-ifaces down')

    def test_metrics_timer_arms_initial_sample_without_persistent_stamp(self):
        timer = unit('dnscomplex-metrics-sample.timer').splitlines()
        self.assertIn('OnActiveSec=1s', timer)
        self.assertIn('OnUnitInactiveSec=15s', timer)
        self.assertNotIn('Persistent=true', timer)


if __name__ == '__main__':
    unittest.main()
