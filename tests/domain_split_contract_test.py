#!/usr/bin/env python3
"""Generated-config contract: AI/CN-video/default classification stays aligned.

This verifies the renderer's boundary, not live nft routing. Shared-IP wire
coverage is provided separately by the isolated sing-box/nft probes.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--installer', type=Path, default=Path(__file__).resolve().parents[1] / 'install.sh')
args = parser.parse_args()


class DomainSplitContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='dnscomplex-domain-contract-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.roots = {}
        for mode in ('ipsec', 'xray'):
            root = Path(cls.temp.name) / mode
            cfg = Path(cls.temp.name) / (mode + '.env')
            cfg.write_text('''DNSCOMPLEX_NONINTERACTIVE=1
DEPLOY_MODE=routeros-policy
WAN_IFACE=eth0
ROUTEROS_LAN_IPV4=192.168.50.253
LINUX_LAN_IPV4=192.168.50.200
LAN_CLIENT_IPV4_CIDR=192.168.50.0/24
SINGBOX_SOCKS_LISTEN=192.168.50.200
SINGBOX_SOCKS_PORT=10800
AI_IPSEC_USERNAME=fixture-ai
AI_IPSEC_PASSWORD=fixture-ai-pass
CN_IPSEC_USERNAME=fixture-cn
CN_IPSEC_PASSWORD=fixture-cn-pass
''' + f'AI_EGRESS_MODE={mode}\nCN_EGRESS_MODE={mode}\n')
            proc = subprocess.run(['bash', str(args.installer), '--dry-run', '--config', str(cfg)],
                                  env={**os.environ, 'DNSCOMPLEX_ROOT': str(root)},
                                  capture_output=True, text=True, timeout=30)
            if proc.returncode:
                raise AssertionError(proc.stdout + proc.stderr)
            cls.roots[mode] = root

    def test_ai_and_cn_video_use_matching_dns_and_selected_outbound(self):
        for mode, root in self.roots.items():
            config = json.loads((root/'etc/sing-box/config.json').read_text())
            for tag, profile in (('geosite-ai-openai','ai'), ('geosite-ai-anthropic','ai'),
                                 ('geosite-ai-support','ai'), ('geosite-cn-video','cn')):
                with self.subTest(mode=mode, tag=tag):
                    route = [r for r in config['route']['rules'] if r.get('rule_set') == tag and r.get('action') == 'route']
                    dns = [r for r in config['dns']['rules'] if r.get('rule_set') == tag and r.get('action') == 'route']
                    self.assertEqual([r['outbound'] for r in route], [f'{profile}-{mode}'])
                    self.assertEqual([r['server'] for r in dns], [f'smartdns-{profile}'])
            self.assertEqual(config['route']['final'], 'default')
            self.assertEqual(config['dns']['final'], 'smartdns-default')
            # A raw address has no domain match; private-address handling also
            # uses default. No IP-geolocation or blanket Chinese rule is allowed.
            routes = [r for r in config['route']['rules'] if r.get('action') == 'route']
            self.assertTrue(all('rule_set' in r or r.get('ip_is_private') is True for r in routes))
            cn_routes = [r for r in routes if r.get('outbound') == f'cn-{mode}']
            self.assertEqual([r.get('rule_set') for r in cn_routes], ['geosite-cn-video'])

    def test_non_video_mainland_and_non_ai_apple_have_no_expanded_classification(self):
        blocked_expansion = ('weixin.qq.com', 'servicewechat.com', 'meituan.com', 'meituan.net',
                             'sushiro.com', 'apple.com', 'icloud.com', 'cloudflare.com', 'fastly.com')
        for mode, root in self.roots.items():
            config = json.loads((root/'etc/sing-box/config.json').read_text())
            for rule in config['route']['rules']:
                for key in ('domain', 'domain_suffix', 'domain_keyword', 'domain_regex'):
                    values = rule.get(key, [])
                    if isinstance(values, str): values = [values]
                    self.assertFalse(any(x in values for x in blocked_expansion), (mode, rule))
            # The curated sources are the classifier inputs; renderer must not
            # silently introduce broad China/Apple geosite sets.
            tags = {r['tag'] for r in config['route']['rule_set']}
            self.assertEqual(tags, {'geosite-ai-openai', 'geosite-ai-anthropic',
                                    'geosite-ai-support', 'geosite-cn-video'})
            support = (root/'var/lib/dnscomplex/geosite/ai-support.sources')
            if support.exists():
                self.assertFalse(set(support.read_text().split()) & set(blocked_expansion))

    def test_domain_output_preserves_tun_auto_redirect_compatibility(self):
        for mode, root in self.roots.items():
            config = json.loads((root/'etc/sing-box/config.json').read_text())
            self.assertTrue(next(i for i in config['inbounds'] if i['type']=='tun')['auto_redirect'])
            self.assertTrue(all('routing_mark' not in o for o in config['outbounds']))
            nft = (root/'etc/nftables.d/dnscomplex.nft').read_text()
            self.assertIn('dnscomplex-domain-default-output', nft)
            if mode == 'ipsec':
                self.assertIn('oifname "ipsec-ai" ip daddr != @ai_ready4', nft)
                self.assertIn('oifname "ipsec-cn" ip daddr != @cn_ready4', nft)
                self.assertLess(nft.index('dnscomplex-ai-classified-not-ready'), nft.index('dnscomplex-domain-default-output'))
            else:
                self.assertNotIn('dnscomplex-ai-classified-output', nft)

    def test_profile_failure_has_no_default_detour(self):
        for mode, root in self.roots.items():
            config = json.loads((root/'etc/sing-box/config.json').read_text())
            for outbound in config['outbounds']:
                if outbound['tag'].startswith(('ai-', 'cn-')):
                    self.assertNotEqual(outbound.get('detour'), 'default')
            nft = (root/'etc/nftables.d/dnscomplex.nft').read_text()
            self.assertIn('dnscomplex-ai-not-ready', nft)
            self.assertIn('dnscomplex-cn-not-ready', nft)


if __name__ == '__main__':
    unittest.main(argv=['domain-contract'])
