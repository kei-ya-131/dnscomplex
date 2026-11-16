#!/usr/bin/env python3
"""Record lifecycle tests; these do not stand in for a VM reboot."""
import importlib.util
import json
from pathlib import Path
import tempfile
import os
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class VmAcceptanceTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('vm_acceptance', ROOT/'tools/vm_acceptance.py')
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)
        self.identity = {'source': 'a'*64, 'config': 'b'*64, 'machine': 'machine-one'}

    def record(self, scenario='cold-boot', operation=None):
        return self.mod.new_record(scenario, self.identity, 'old-boot', 1000, 300, operation)

    def test_real_boot_change_required_for_reboot_scenarios(self):
        record = self.record()
        with self.assertRaisesRegex(ValueError, 'boot'):
            self.mod.check_resume(record, self.identity, 'old-boot', 1001)
        self.mod.check_resume(record, self.identity, 'new-boot', 1001)

    def test_fixed_deadline_cannot_be_reset_or_accept_late_success(self):
        record = self.record()
        for now in (999, 1300, 1301):
            with self.subTest(now=now), self.assertRaises(ValueError):
                self.mod.check_resume(record, self.identity, 'new-boot', now)

    def test_changed_machine_source_or_config_is_rejected(self):
        for key in self.identity:
            changed = dict(self.identity, **{key: 'changed'})
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'identity'):
                self.mod.check_resume(self.record(), changed, 'new-boot', 1001)

    def test_operation_proof_must_be_prepared_then_verified_rollback(self):
        before = {'id': 'a'*32, 'action': 'set-update-time', 'phase': 'prepared',
                  'candidate_sha256': 'c'*64, 'rollback_state': 'not-started'}
        record = self.record('operation-interruption', before)
        after = dict(before, phase='rolled-back', rollback_state='verified')
        self.mod.check_resume(record, self.identity, 'new-boot', 1001, after)
        for changes in ({'phase': 'committed'}, {'rollback_state': 'failed'},
                        {'candidate_sha256': 'd'*64}, {'id': 'b'*32}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.mod.check_resume(record, self.identity, 'new-boot', 1001, dict(after, **changes))
        with self.assertRaises(ValueError):
            self.record('operation-interruption')

    def test_component_rollback_requires_new_failure_log_and_exact_binaries(self):
        before = self.record('component-rollback')
        with self.assertRaises(ValueError):
            self.mod.check_update_log(before, 'old-hash', 'old-hash',
                                      'application rollback completed')
        self.mod.check_update_log(before, 'old-hash', 'new-hash',
                                 'starting application rollback\napplication rollback completed\nsoftware component update failed and application changes were rolled back')
        with self.assertRaises(ValueError):
            self.mod.check_update_log(before, 'old-hash', 'new-hash', 'software update completed')

    def test_evidence_is_exclusive_private_and_replay_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'record.json'
            record = self.record()
            self.mod.write_new(path, record)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                self.mod.write_new(path, record)
            record['status'] = 'PASS'
            with self.assertRaisesRegex(ValueError, 'consumed'):
                self.mod.check_resume(record, self.identity, 'new-boot', 1001)

    def test_collection_checks_real_child_exit_health_and_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); bins = root/'bin'; bins.mkdir()
            ops = root/'ops'; ops.mkdir()
            restore = root/'restore'; restore.mkdir()
            health = {'status': 'healthy', 'checks': [{'name': 'fixture', 'status': 'ok'}]}
            for name in ('manager', 'curl', 'systemctl'):
                script = bins/name
                script.write_text('#!/usr/bin/env python3\nimport json,sys\n'+
                                  ('print('+repr(json.dumps(health))+')\n' if name != 'systemctl' else 'pass\n'))
                script.chmod(0o700)
            record = self.mod.new_record('cold-boot', self.identity, 'old', time.time(), 60)
            record.update(web_url='http://127.0.0.1:8088/', health_url='http://127.0.0.1:9108/healthz')
            with patch.object(self.mod, 'MANAGER', str(bins/'manager')), \
                    patch.object(self.mod, 'OPERATIONS', ops), patch.object(self.mod, 'RESTORE', restore), \
                    patch.dict(os.environ, PATH=str(bins)+os.pathsep+os.environ['PATH']):
                passed = root/'pass'; passed.mkdir()
                self.assertEqual(len(self.mod.collect(passed, record, 'after')), 5)
                (restore/'transaction.unfinished').mkdir()
                failed = root/'fail'; failed.mkdir()
                with self.assertRaisesRegex(ValueError, 'cleanup'):
                    self.mod.collect(failed, record, 'after')
                (restore/'transaction.unfinished').rmdir()
                (bins/'manager').write_text('#!/bin/sh\nexit 7\n')
                exit_failure = root/'exit'; exit_failure.mkdir()
                with self.assertRaisesRegex(ValueError, 'health check failed'):
                    self.mod.collect(exit_failure, record, 'after')

    def test_http_evidence_must_match_local_configured_listener(self):
        cfg = {'DNSCOMPLEX_WEB_LISTEN': '192.0.2.2', 'DNSCOMPLEX_WEB_PORT': '8088',
               'DNSCOMPLEX_METRICS_LISTEN': '0.0.0.0', 'DNSCOMPLEX_METRICS_PORT': '9108'}
        local = {'127.0.0.1', '192.0.2.2'}
        self.mod.validate_listener_urls('http://192.0.2.2:8088/',
                                        'http://127.0.0.1:9108/healthz', cfg, local)
        for web, health in [('http://198.51.100.99:8088/', 'http://127.0.0.1:9108/healthz'),
                            ('http://192.0.2.2:8088/', 'http://192.0.2.2:9108/arbitrary'),
                            ('http://192.0.2.2:80/', 'http://192.0.2.2:9108/healthz')]:
            with self.subTest(web=web, health=health), self.assertRaises(ValueError):
                self.mod.validate_listener_urls(web, health, cfg, local)


if __name__ == '__main__':
    unittest.main()
