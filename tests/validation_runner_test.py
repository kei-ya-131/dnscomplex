#!/usr/bin/env python3
"""Exercise the acceptance runner through real child processes."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class ValidationRunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        spec = importlib.util.spec_from_file_location('validation_runner', ROOT / 'tools/validate.py')
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def step(self, code, timeout=3):
        name = 'child-'+str(len(list(self.root.glob('*.log'))))
        return self.mod.run_step(name, [sys.executable, '-c', code], ROOT, self.root, timeout)

    def test_pass_and_nonzero_failure_keep_exit_and_log(self):
        passed = self.step("print('real child')")
        self.assertEqual(passed['status'], 'PASS')
        self.assertIn('real child', Path(passed['log']).read_text())
        failed = self.step("import sys; print('original failure'); sys.exit(7)")
        self.assertEqual((failed['status'], failed['returncode']), ('FAIL', 7))

    def test_nested_unittest_skip_is_not_success(self):
        result = self.step("print('Ran 4 tests in 0.1s\\n\\nOK (skipped=1)')")
        self.assertEqual(result['status'], 'SKIP')
        self.assertNotEqual(self.mod.overall([result]), 'PASS')

    def test_timeout_stops_process_group(self):
        pidfile = self.root / 'pid'
        code = ('import subprocess,time; from pathlib import Path; '
                'p=subprocess.Popen(["sleep","20"]); '
                f'Path({str(pidfile)!r}).write_text(str(p.pid)); time.sleep(20)')
        started = time.monotonic()
        result = self.step(code, timeout=.3)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['reason'], 'timeout')
        self.assertLess(time.monotonic()-started, 5)
        # A surviving descendant must not be able to perform later writes.
        # Linux zombies are already exited and cannot execute work.
        pid = int(pidfile.read_text())
        stat = Path(f'/proc/{pid}/stat')
        if stat.exists():
            self.assertEqual(stat.read_text().rsplit(')', 1)[1].split()[0], 'Z')
        else:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_output_limit_is_failure(self):
        result = self.mod.run_step('large', [sys.executable, '-c', 'print("x"*20000)'],
                                   ROOT, self.root, 3, max_log_bytes=1024)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['reason'], 'output-limit')
        self.assertLessEqual(Path(result['log']).stat().st_size, 1024)

    def test_success_observed_after_deadline_is_not_accepted(self):
        result = self.step('import time; time.sleep(.08)', timeout=.06)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['reason'], 'timeout')

    def test_source_identity_covers_untracked_tools_and_tests(self):
        (self.root/'install.sh').write_text('installer')
        (self.root/'tools').mkdir()
        helper = self.root/'tools/new.py'
        helper.write_text('one')
        before = self.mod.source_identity(self.root)
        helper.write_text('two')
        self.assertNotEqual(before, self.mod.source_identity(self.root))

    def test_empty_suite_and_missing_command_fail_closed(self):
        self.assertEqual(self.mod.overall([]), 'FAIL')
        result = self.mod.run_step('missing', ['/no-such-dnscomplex-tool'], ROOT, self.root, 2)
        self.assertEqual(result['status'], 'FAIL')

    def test_unavailable_environment_writes_skip_report_and_nonzero(self):
        output = self.root/'unavailable'
        with patch.object(self.mod, 'preflight', side_effect=ValueError('no Linux')):
            code = self.mod.main(['--suite', 'native', '--output', str(output)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads((output/'report.json').read_text())['status'], 'SKIP')


if __name__ == '__main__':
    unittest.main()
