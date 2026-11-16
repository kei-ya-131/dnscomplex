import importlib.util
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class RouterOSClientFailover(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = pathlib.Path(cls.tmp.name)
        env = dict(os.environ, DNSCOMPLEX_ROOT=str(cls.root))
        config = cls.root / 'config'
        config.write_text((ROOT/'examples/routeros-policy.config.env').read_text())
        subprocess.run(['bash',str(ROOT/'install.sh'),'--dry-run','--config',str(config)],env=env,
                       check=True,stdout=subprocess.DEVNULL)
        cls.helper = cls.root/'usr/local/lib/dnscomplex-routeros/client.py'

    def test_rendered_assets_scope_and_cleanup(self):
        self.assertTrue(self.helper.is_file(), str(self.helper))
        result=self.root/'profile'
        subprocess.run(['python3',str(self.helper),'render','--client','192.168.50.22',
                        '--mac','02:00:00:00:00:22','--rule','one-client','--table','toVM',
                        '--target','203.0.113.7','--host','example.com','--output',str(result)],check=True)
        install=(result/'install.rsc').read_text()
        remove=(result/'remove.rsc').read_text()
        self.assertIn('http://192.168.50.200:9108/healthz',install)
        self.assertIn('http://192.168.50.22:19119/client-health',install)
        self.assertIn('src-address=192.168.50.22 src-mac-address=02:00:00:00:00:22',install)
        self.assertIn('src-port=46528-46591',install)
        self.assertIn('place-before=$primary',install)
        self.assertIn('name="dnscomplex-client-health"',remove)
        scheduler = next(line for line in install.splitlines() if line.startswith('/system scheduler add'))
        profile = re.search(r'comment="([0-9a-f]{64})"', scheduler)[1]
        self.assertIn(f'and comment="{profile}\"', remove.splitlines()[1])
        self.assertIn('set $primary disabled=no',remove)
        self.assertNotIn('/ip dhcp-server',install+remove)

    def test_stale_and_failed_samples_fail_closed(self):
        self.assertTrue(self.helper.is_file(), str(self.helper))
        spec=importlib.util.spec_from_file_location('routeros_client',self.helper)
        mod=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        health=mod.Health()
        health.record((True,True,True),now=100)
        self.assertFalse(health.ready(now=100))
        health.record((True,True,True),now=102)
        self.assertTrue(health.ready(now=108))
        self.assertFalse(health.ready(now=108.01))
        health.record((True,True,False),now=109)
        health.record((True,True,True),now=110)
        self.assertFalse(health.ready(now=110))
        health.record((True,True,True),now=112)
        self.assertTrue(health.ready(now=112))

if __name__ == '__main__':
    unittest.main()
