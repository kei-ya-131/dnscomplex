#!/usr/bin/env python3
"""Observe actual file modes before renderer writes/publishes secret bytes."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()


class SecretCreation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.installer = self.root / 'installer'
        self.installer.write_text(SOURCE.rsplit('\nmain "$@"', 1)[0])

    def test_installer_secrets_private_before_postwrite_chmod(self):
        config = Path(__file__).resolve().parents[1] / 'examples/routeros-policy.config.env'
        script = '''source "$1"
umask 022
CONFIG_PATH=$2; load_config
chmod_target() {
  python3 - "$DNSCOMPLEX_ROOT$2" <<'CHECK'
import os,stat,sys
path=sys.argv[1]
if path.endswith(('config.env','swanctl.conf')):
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, 'secret readable before chmod: '+path
CHECK
  local rc=$?; ((rc == 0)) || return "$rc"
  chmod "$1" "$DNSCOMPLEX_ROOT$2"
}
save_runtime_config
render_swanctl
'''
        result = subprocess.run(['bash', '-ec', script, '_', str(self.installer), str(config)],
                                env=dict(os.environ, DNSCOMPLEX_ROOT=str(self.root / 'root')),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def xray(self):
        path = self.root / 'xray.py'
        marker = "/usr/local/lib/dnscomplex-xray/render.py <<'PY'\n"
        path.write_text(SOURCE.split(marker, 1)[1].split('\nPY\n', 1)[0])
        spec = importlib.util.spec_from_file_location('secret_xray', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_failed_secret_write_keeps_original_even_in_conditional_caller(self):
        target = self.root / 'root/etc/dnscomplex/config.env'
        target.parent.mkdir(parents=True); target.write_text('previous-private-config\n'); target.chmod(0o600)
        config = Path(__file__).resolve().parents[1] / 'examples/routeros-policy.config.env'
        script = '''source "$1"
CONFIG_PATH=$2; load_config
cat() { printf partial-write; return 19; }
if save_runtime_config; then exit 99; fi
'''
        result = subprocess.run(['bash', '-ec', script, '_', str(self.installer), str(config)],
                                env=dict(os.environ, DNSCOMPLEX_ROOT=str(self.root / 'root')),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, 'failed write was reported successful')
        self.assertEqual(target.read_text(), 'previous-private-config\n')
        self.assertEqual(list(target.parent.iterdir()), [target], 'secret staging file leaked')

    def test_xray_private_at_first_write_and_cleans_on_failure(self):
        module = self.xray()
        config = self.root / 'config.env'; config.write_text('')
        output = self.root / 'config.json'
        original_open = open
        original_fdopen = os.fdopen
        def checked_open(path, mode='r', *args, **kwargs):
            stream = original_open(path, mode, *args, **kwargs)
            if 'w' in mode:
                try:
                    self.assertEqual(os.fstat(stream.fileno()).st_mode & 0o777, 0o600,
                                     'Xray temporary file readable before first write')
                except BaseException:
                    stream.close()
                    raise
            return stream
        def checked_fdopen(fd, *args, **kwargs):
            self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o600)
            return original_fdopen(fd, *args, **kwargs)
        argv = ['renderer', '--config', str(config), '--output', str(output)]
        previous = os.umask(0o022)
        try:
            with patch.object(sys, 'argv', argv), patch('builtins.open', checked_open), patch.object(module.os, 'fdopen', checked_fdopen):
                module.main()
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(json.loads(output.read_text())['outbounds']), 2)
            before = output.read_bytes()
            files_before = set(self.root.iterdir())
            with patch.object(sys, 'argv', argv), patch.object(module.os, 'replace', side_effect=OSError('synthetic publish failure')):
                with self.assertRaises(OSError): module.main()
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual(set(self.root.iterdir()), files_before, 'renderer leaked secret staging file')
        finally:
            os.umask(previous)


if __name__ == '__main__':
    unittest.main()
