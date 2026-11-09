#!/usr/bin/env python3
"""Actual emitted CLI with private rule files and mock dig/nft/core commands."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT/'install.sh').read_text()
MANAGER = SOURCE.split("<<'MANAGER'\n", 1)[1].split('\nMANAGER\n', 1)[0]


class TraceDomainDiagnosticsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manager = self.root/'manager'; self.manager.write_text(MANAGER)
        self.bin = self.root/'bin'; self.bin.mkdir()
        self.geo = self.root/'var/lib/dnscomplex/geosite'; self.geo.mkdir(parents=True)
        self.config = self.root/'etc/sing-box/config.json'; self.config.parent.mkdir(parents=True)
        self.rules = {
            'ai': [{'domain_suffix': ['example.ai']}, {'domain': ['exact.ai']}],
            'cn': [{'domain_suffix': ['video.example']}],
        }
        self.fixture = {'A': ['198.51.100.10'], 'AAAA': [], 'ai4': [], 'cn4': [],
                        'ai_ready4': [{'prefix': {'addr': '0.0.0.0', 'len': 0}}],
                        'cn_ready4': []}
        stub = '''#!/usr/bin/env python3
import json,os,pathlib,sys,resource
name=pathlib.Path(sys.argv[0]).name
data=json.loads(pathlib.Path(os.environ['TRACE_FIXTURE']).read_text())
with open(os.environ['TRACE_CALLS'],'a') as out: out.write(name+' '+json.dumps(sys.argv[1:])+'\\n')
if name=='dig':
 if data.get('dns_fail'): sys.exit(9)
 print('\\n'.join(data['AAAA' if 'AAAA' in sys.argv else 'A']))
elif name=='nft':
 if data.get('report_limit'):
  pathlib.Path(os.environ['TRACE_CALLS']+'.limit').write_text(str(resource.getrlimit(resource.RLIMIT_FSIZE)[0]))
 if data.get('nft_fail'): sys.exit(1)
 s=sys.argv[-1]
 print(json.dumps({'nftables':[{'set':{'family':'inet','table':'dnscomplex','name':s,'type':'ipv6_addr' if s.endswith('6') else 'ipv4_addr','elem':data.get(s,[])}}]}))
elif name=='sing-box':
 target=sys.argv[sys.argv.index('--output')+1]
 pathlib.Path(target).write_text(pathlib.Path(sys.argv[-1]).read_text())
else: sys.exit(95)
'''
        for name in ('dig', 'nft', 'sing-box'):
            path = self.bin/name; path.write_text(stub); path.chmod(0o700)

    def trace(self, domain):
        sets = []
        routes = []
        for profile in ('ai', 'cn'):
            tag = 'geosite-'+profile
            path = self.geo/(tag+'.srs')
            path.write_text(json.dumps({'version': 2, 'rules': self.rules[profile]}))
            sets.append({'type': 'local', 'tag': tag, 'format': 'binary',
                         'path': '/var/lib/dnscomplex/geosite/'+path.name})
            routes.append({'rule_set': tag, 'action': 'route', 'outbound': profile+'-ipsec'})
        self.config.write_text(json.dumps({'route': {'rule_set': sets, 'rules': routes, 'final': 'default'}}))
        fixture = self.root/'fixture.json'; fixture.write_text(json.dumps(self.fixture))
        env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                   DNSCOMPLEX_FS_ROOT=str(self.root), TRACE_FIXTURE=str(fixture),
                   TRACE_CALLS=str(self.root/'calls'))
        body = 'source "$1"; trace_domain_cmd "$2"'
        return subprocess.run(['bash', '-c', body, '_', str(self.manager), domain],
                              env=env, capture_output=True, text=True, timeout=30)

    def test_suffix_case_and_trailing_dot_match_domain_policy(self):
        result = self.trace('API.Example.AI.')
        self.assertEqual(result.returncode, 0, result.stderr+result.stdout)
        self.assertIn('profile=AI\n', result.stdout)
        self.assertIn('expected_outbound=ai-ipsec', result.stdout)
        self.assertIn('actual_outbound=unknown', result.stdout)

    def test_shared_ip_observation_never_reassigns_default_domain(self):
        self.fixture.update(ai4=['198.51.100.10'], cn4=['198.51.100.10'])
        result = self.trace('ordinary.example')
        self.assertIn('profile=default\n', result.stdout)
        self.assertIn('nftset[198.51.100.10]=AI,CN', result.stdout)
        self.assertIn('shared-ip', result.stdout)

    def test_exact_rule_does_not_match_child(self):
        self.assertIn('profile=AI\n', self.trace('exact.ai').stdout)
        self.assertIn('profile=default\n', self.trace('child.exact.ai').stdout)

    def test_overlap_keeps_configured_route_order_and_reports_both(self):
        self.rules['cn'].append({'domain_suffix': ['example.ai']})
        result = self.trace('api.example.ai')
        self.assertIn('profile=AI\n', result.stdout)
        self.assertIn('rule_overlap=AI,CN', result.stdout)

    def test_dns_failure_is_nonzero_with_action_and_no_connectivity_claim(self):
        self.fixture['dns_fail'] = True
        result = self.trace('example.ai')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('dns_status=unavailable', result.stdout)
        self.assertIn('recommended_action=', result.stdout)
        self.assertIn('actual_outbound=unknown', result.stdout)

    def test_closed_profile_gate_is_reported_without_repair(self):
        result = self.trace('video.example')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('profile_gate=closed', result.stdout)
        calls = (self.root/'calls').read_text()
        self.assertNotIn('restart', calls)
        self.assertNotIn('--load-all', calls)
        self.assertNotIn('"-f"', calls)

    def test_nft_error_is_unknown_not_closed_or_default(self):
        self.fixture['nft_fail'] = True
        result = self.trace('example.ai')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('profile_gate=unknown', result.stdout)
        self.assertIn('nftset[198.51.100.10]=unknown', result.stdout)

    def test_unknown_rule_semantics_do_not_guess_default(self):
        self.rules['ai'].insert(0, {'domain_regex': ['.*special.*']})
        result = self.trace('ordinary.example')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('profile=unknown\n', result.stdout)

    def test_unsupported_ip_or_domain_condition_is_not_treated_as_no_match(self):
        self.rules['ai'] = [{'domain': ['other.example'], 'ip_cidr': ['198.51.100.0/24']}]
        result = self.trace('ordinary.example')
        self.assertIn('profile=unknown\n', result.stdout)
        self.assertNotEqual(result.returncode, 0)

    def test_empty_regex_field_does_not_hide_default_or_later_cn_match(self):
        self.rules['ai'] = [{'domain_suffix': ['example.ai'], 'domain_regex': []}]
        self.assertIn('profile=default\n', self.trace('ordinary.example').stdout)
        self.assertIn('profile=CN\n', self.trace('video.example').stdout)

    def test_external_diagnostic_writers_have_hard_file_size_bound(self):
        self.fixture['report_limit'] = True
        self.trace('example.ai')
        limit = int((self.root/'calls.limit').read_text())
        self.assertGreater(limit, 0)
        self.assertLessEqual(limit, 8*1024*1024)

    def test_invalid_names_rejected_before_external_commands(self):
        for name in ('-bad', 'bad/name', 'a\nb', 'a..b', 'bad.example..', '192.0.2.1', 'a'*254):
            with self.subTest(name=name):
                result = self.trace(name)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root/'calls').exists())


if __name__ == '__main__':
    unittest.main()
