#!/usr/bin/env python3
"""Support bundles must retain XFRM diagnostics without live SA key material."""
import pathlib,unittest
s=(pathlib.Path(__file__).resolve().parents[1]/'install.sh').read_text()
code=s.split("/usr/local/lib/dnscomplex-redact/redact.py <<'PY'\n",1)[1].split('\nPY\n',1)[0]
n={'__name__':'redaction_test'};exec(compile(code,'redact.py','exec'),n)
class CryptoRedaction(unittest.TestCase):
 def test_xfrm_session_keys_are_removed_without_losing_algorithm_and_icv(self):
  for kind,algorithm,icv in [('auth-trunc','hmac(sha256)','128'),('auth','hmac(sha1)',''),('enc','cbc(aes)',''),('aead','rfc4106(gcm(aes))','128')]:
   with self.subTest(kind=kind):
    key='0x'+'1234567890abcdef'*4
    source=f'    {kind} {algorithm} {key} {icv}\n    replay-window 32 flag af-unspec\n'
    out=n['redact'](source)
    self.assertNotIn(key,out);self.assertIn(algorithm,out);self.assertIn('replay-window 32',out)
    if icv:self.assertIn(icv,out)
    self.assertIn('[REDACTED_XFRM_KEY]',out)
 def test_non_secret_crypto_diagnostics_survive(self):
  source='    enc cipher_null\n    mode tunnel reqid 301\n    spi 0x12345678 replay-window 32\n'
  self.assertEqual(n['redact'](source),source)
if __name__=='__main__':unittest.main()
