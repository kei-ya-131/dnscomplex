#!/usr/bin/env python3
"""Exercise the installer-emitted manager and candidate parser without live services."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()
MANAGER = SOURCE.split("<<'MANAGER'\n", 1)[1].split('\nMANAGER\n', 1)[0]


class CandidateSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manager = self.root / 'manager'
        self.manager.write_text(MANAGER)
        helper = self.root / 'usr/local/lib/dnscomplex-config/candidate.py'
        helper.parent.mkdir(parents=True)
        marker = "/usr/local/lib/dnscomplex-config/candidate.py <<'CONFIG_PARSER'\n"
        if marker in SOURCE:
            helper.write_text(SOURCE.split(marker, 1)[1].split('\nCONFIG_PARSER\n', 1)[0])
        self.helper = helper
        self.env = dict(os.environ, DNSCOMPLEX_FS_ROOT=str(self.root))

    def shell(self, script, *args):
        return subprocess.run(['bash', '-c', 'source "$1"; shift; ' + script,
                               '_', str(self.manager), *map(str, args)],
                              env=self.env, text=True, capture_output=True)

    def test_validate_does_not_execute_candidate(self):
        marker = self.root / 'executed'
        attacks = [f'AI_IPSEC_PASSWORD=$(touch {marker})',
                   f'AI_IPSEC_PASSWORD=`touch {marker}`',
                   f"AI_IPSEC_PASSWORD='safe'; touch {marker}",
                   f'source {self.root / "payload"}',
                   f'f() {{ touch {marker}; }}; f']
        (self.root / 'payload').write_text(f'touch {marker}\n')
        for attack in attacks:
            with self.subTest(attack=attack):
                marker.unlink(missing_ok=True)
                candidate = self.root / 'candidate.env'
                candidate.write_text(attack + '\n')
                result = self.shell('validate_config_file_cmd "$1"', candidate)
                self.assertFalse(marker.exists(), 'validation executed the raw candidate')
                self.assertNotEqual(result.returncode, 0)

    def parser(self):
        spec = importlib.util.spec_from_file_location('candidate', self.helper)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_write_env_var_roundtrip_and_shell_safe_normalization(self):
        values = ['', "a'b\\c\"d", '$(touch NEVER)`echo nope`; source x',
                  'first\nsecond\n', '{"password":"a\\b","items":[1,2]}', '$x $((2+2))']
        for value in values:
            with self.subTest(value=value):
                generated = self.shell('write_env_var AI_IPSEC_PASSWORD "$1"', value)
                candidate = self.root / 'candidate.env'
                candidate.write_text(generated.stdout)
                module = self.parser()
                self.assertEqual(module.parse_env_file(candidate, {'AI_IPSEC_PASSWORD'}),
                                 {'AI_IPSEC_PASSWORD': value})
                output = self.root / 'normalized'
                output.unlink(missing_ok=True)
                result = subprocess.run(['python3', str(self.helper), '--input', str(candidate),
                                         '--output', str(output)], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                loaded = self.shell('source "$1"; printf %s "$AI_IPSEC_PASSWORD"', output)
                self.assertEqual(loaded.stdout, value)

    def test_rejects_invalid_data_without_secret_output(self):
        secret = 'UNIQUE_PRIVATE_VALUE'
        invalid = ['UNKNOWN=' + secret, 'AI_IPSEC_PASSWORD=x\nAI_IPSEC_PASSWORD=' + secret,
                   'AI_IPSEC_PASSWORD="' + secret, 'AI_IPSEC_PASSWORD=' + secret + '\0',
                   'AI_IPSEC_PASSWORD="$HOME"', 'AI_IPSEC_PASSWORD=$((1+2))',
                   'AI_IPSEC_PASSWORD=x extra', 'export AI_IPSEC_PASSWORD=x',
                   'AI_IPSEC_PASSWORD=x && true', 'AI_IPSEC_PASSWORD=<(echo x)']
        for raw in invalid:
            with self.subTest(raw=raw):
                candidate = self.root / 'candidate.env'
                candidate.write_text(raw)
                result = self.shell('validate_config_file_cmd "$1"', candidate)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(secret, result.stdout + result.stderr)

    def test_comments_quotes_and_escapes(self):
        candidate = self.root / 'candidate.env'
        candidate.write_text('# header\n\nAI_IPSEC_PASSWORD="a\\$b\\`c\\\\d\\\"e" # comment\nCN_IPSEC_PASSWORD=a\\ b\\;c\n')
        self.assertEqual(self.parser().parse_env_file(candidate, {'AI_IPSEC_PASSWORD', 'CN_IPSEC_PASSWORD'}),
                         {'AI_IPSEC_PASSWORD': 'a$b`c\\d"e', 'CN_IPSEC_PASSWORD': 'a b;c'})

    def test_symlink_rejected(self):
        target = self.root / 'target'
        target.write_text('AI_IPSEC_PASSWORD=x\n')
        candidate = self.root / 'candidate.env'
        candidate.symlink_to(target)
        result = self.shell('validate_config_file_cmd "$1"', candidate)
        self.assertNotEqual(result.returncode, 0)

    def test_source_change_during_capture_rejected(self):
        from unittest.mock import patch
        module = self.parser()
        candidate = self.root / 'candidate.env'
        candidate.write_text('AI_IPSEC_PASSWORD=before\n')
        original_read = module.os.read
        changed = False
        def read_and_change(fd, length):
            nonlocal changed
            data = original_read(fd, length)
            if not changed:
                changed = True
                candidate.write_text('AI_IPSEC_PASSWORD=after\n')
            return data
        with patch.object(module.os, 'read', side_effect=read_and_change):
            with self.assertRaises(module.CandidateError):
                module.parse_env_file(candidate, {'AI_IPSEC_PASSWORD'})

    def test_apply_uses_validated_snapshot(self):
        candidate = self.root / 'candidate.env'
        candidate.write_text("AI_IPSEC_PASSWORD='before'\n")
        installed = self.root / 'installed'
        result = self.shell('''need_root() { :; }; acquire_maintenance_lock() { :; }
validate_loaded_config() { printf "AI_IPSEC_PASSWORD='after'\\n" >"$RAW"; return 0; }
state_transaction_cmd() { shift; "$@"; }
apply_config_candidate_cmd() { cp "$1" "$INSTALLED"; }
RAW=$1 INSTALLED=$2 apply_config_file_cmd "$1"''', candidate, installed)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("'before'", installed.read_text())
        self.assertIn("'after'", candidate.read_text())

    def test_json_merge_preserves_multiline_and_masked_secrets(self):
        config = self.root / 'config.env'
        value = "one\ntwo'\\three\n"
        config.write_text(self.shell('write_env_var AI_IPSEC_PASSWORD "$1"', value).stdout)
        update = self.root / 'update.json'
        update.write_text(json.dumps({'AI_IPSEC_PASSWORD': '********', 'DNSCOMPLEX_UPDATE_TIME': '03:15'}))
        installed = self.root / 'installed'
        result = self.shell('''need_root() { :; }; acquire_maintenance_lock() { :; }
validate_loaded_config() { return 0; }
state_transaction_cmd() { shift; "$@"; }
apply_config_candidate_cmd() { cp "$1" "$INSTALLED"; }
CONFIG=$1 INSTALLED=$3 apply_config_json_cmd "$2"''', config, update, installed)
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = self.parser().parse_env_file(installed, self.parser().ALLOWED_KEYS)
        self.assertEqual(parsed['AI_IPSEC_PASSWORD'], value)
        self.assertEqual(parsed['DNSCOMPLEX_UPDATE_TIME'], '03:15')

    def test_json_merge_rejects_incompatible_current_config(self):
        config = self.root / 'config.env'
        config.write_text('AI_IPSEC_PASSWORD=bad; echo UNIQUE_PRIVATE_VALUE\n')
        update = self.root / 'update.json'
        update.write_text('{}')
        before = config.read_bytes()
        result = self.shell('''need_root() { :; }; acquire_maintenance_lock() { :; }
CONFIG=$1 apply_config_json_cmd "$2"''', config, update)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('UNIQUE_PRIVATE_VALUE', result.stdout + result.stderr)
        self.assertEqual(config.read_bytes(), before)

    def test_cli_json_validation_rejects_without_side_effects(self):
        marker = self.root / 'executed'
        candidate = self.root / 'candidate.env'
        candidate.write_text(f'AI_IPSEC_PASSWORD=$(touch {marker})\n')
        result = self.shell('validate_config_file_cmd --json "$1"', candidate)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)['ok'])
        self.assertFalse(marker.exists())

    def test_invalid_apply_never_enters_transaction(self):
        candidate = self.root / 'candidate.env'
        candidate.write_text('UNKNOWN=UNIQUE_PRIVATE_VALUE\n')
        marker = self.root / 'transaction'
        result = self.shell('''need_root() { :; }; acquire_maintenance_lock() { :; }
state_transaction_cmd() { touch "$TXN"; }
TXN=$2 apply_config_file_cmd "$1"''', candidate, marker)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertNotIn('UNIQUE_PRIVATE_VALUE', result.stdout + result.stderr)

    def test_json_update_rejects_duplicates_nul_and_invalid_unicode(self):
        config = self.root / 'config.env'
        config.write_text('AI_IPSEC_PASSWORD=before\n')
        update = self.root / 'update.json'
        cases = ['{"AI_IPSEC_PASSWORD":"a","AI_IPSEC_PASSWORD":"b"}',
                 '{"AI_IPSEC_PASSWORD":"UNIQUE_PRIVATE_VALUE\\u0000"}',
                 '{"AI_IPSEC_PASSWORD":"UNIQUE_PRIVATE_VALUE\\ud800"}']
        for raw in cases:
            with self.subTest(raw=raw):
                update.write_text(raw)
                result = subprocess.run(['python3', str(self.helper), '--input', str(config),
                                         '--updates', str(update), '--output', str(self.root / 'out')],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('UNIQUE_PRIVATE_VALUE', result.stdout + result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assertFalse((self.root / 'out').exists())

    def test_output_is_0600_even_with_restrictive_umask(self):
        candidate = self.root / 'candidate.env'
        candidate.write_text('AI_IPSEC_PASSWORD=before\n')
        output = self.root / 'normalized'
        result = subprocess.run(['bash', '-c', 'umask 0777; python3 "$1" --input "$2" --output "$3"',
                                 '_', str(self.helper), str(candidate), str(output)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_web_reads_same_multiline_literal_values(self):
        import sys
        app = self.root / 'usr/local/lib/dnscomplex-web/app.py'
        app.parent.mkdir(parents=True)
        app.write_text(SOURCE.split("/usr/local/lib/dnscomplex-web/app.py <<'PY'\n", 1)[1].split('\nPY\n', 1)[0])
        config = self.root / 'config.env'
        value = "first\nsecond'$(literal)\n"
        config.write_text(self.shell('write_env_var AI_IPSEC_PASSWORD "$1"', value).stdout)
        spec = importlib.util.spec_from_file_location('candidate_web_test', app)
        web = importlib.util.module_from_spec(spec)
        old_path = list(sys.path)
        try:
            spec.loader.exec_module(web)
            web.CONFIG = str(config)
            self.assertEqual(web.parse_config()['AI_IPSEC_PASSWORD'], value)
        finally:
            sys.path[:] = old_path
            sys.modules.pop('candidate', None)

    def test_semantic_errors_do_not_echo_candidate_values(self):
        candidate = self.root / 'candidate.env'
        candidate.write_text("LAN_IPV4_CIDR='UNIQUE_PRIVATE_VALUE'\nLAN_IPV6_PREFIX='UNIQUE_PRIVATE_VALUE'\n")
        result = self.shell('validate_config_file_cmd "$1"', candidate)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('UNIQUE_PRIVATE_VALUE', result.stdout + result.stderr)

    def test_numeric_semantic_errors_do_not_echo_candidate_values(self):
        candidate = self.root / 'candidate.env'
        candidate.write_text("SINGBOX_SOCKS_PORT='09999'\n")
        result = self.shell('validate_config_file_cmd "$1"', candidate)
        self.assertNotIn('09999', result.stdout + result.stderr)

    def test_wizard_output_validates_and_applies_without_modification(self):
        candidate = self.root / 'wizard.env'
        wizard = self.shell('wizard_cmd')
        self.assertEqual(wizard.returncode, 0, wizard.stderr)
        candidate.write_text(wizard.stdout)
        validation = self.shell('validate_config_file_cmd "$1"', candidate)
        self.assertEqual(validation.returncode, 0, validation.stdout + validation.stderr)
        installed = self.root / 'installed'
        apply = self.shell('''need_root() { :; }; acquire_maintenance_lock() { :; }
state_transaction_cmd() { shift; "$@"; }
apply_config_candidate_cmd() { cp "$1" "$INSTALLED"; }
INSTALLED=$2 apply_config_file_cmd "$1"''', candidate, installed)
        self.assertEqual(apply.returncode, 0, apply.stdout + apply.stderr)
        parsed = self.parser().parse_env_file(installed, self.parser().ALLOWED_KEYS)
        self.assertEqual(parsed['DNSCOMPLEX_NONINTERACTIVE'], '1')
        self.assertEqual(parsed['DEPLOY_MODE'], 'routeros-policy')

    def test_failed_candidate_paths_clean_private_temporary_directories(self):
        candidate = self.root / 'candidate.env'
        candidate.write_text('UNKNOWN=UNIQUE_PRIVATE_VALUE\n')
        update = self.root / 'update.json'
        update.write_text('{}')
        config = self.root / 'config.env'
        config.write_text('UNKNOWN=UNIQUE_PRIVATE_VALUE\n')
        temp_root = self.root / "private temp's"
        temp_root.mkdir()
        self.env['TMPDIR'] = str(temp_root)
        for script, args in [
            ('validate_config_file_cmd "$1"', [candidate]),
            ('apply_config_file_cmd "$1"', [candidate]),
            ('CONFIG=$1 apply_config_json_cmd "$2"', [config, update]),
        ]:
            with self.subTest(script=script):
                result = self.shell('need_root() { :; }; acquire_maintenance_lock() { :; }; ' + script, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('UNIQUE_PRIVATE_VALUE', result.stdout + result.stderr)
                self.assertNotIn('unbound variable', result.stderr)
                self.assertEqual(list(temp_root.iterdir()), [], 'private candidate directory leaked')

    def test_parser_schema_matches_manager(self):
        keys = set(self.shell('config_schema_keys').stdout.splitlines())
        module = self.parser()
        self.assertEqual(set(module.SCHEMA_KEYS), keys)
        self.assertEqual(set(module.ALLOWED_KEYS) - keys, {'DNSCOMPLEX_NONINTERACTIVE'})


if __name__ == '__main__':
    unittest.main()
