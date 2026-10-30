#!/usr/bin/env python3
"""Real emitted transaction/functions, isolated filesystem and command boundaries."""
import json
import os
import shlex
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()
MANAGER = SOURCE.split("<<'MANAGER'\n", 1)[1].split('\nMANAGER\n', 1)[0]


class TransactionSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manager = self.root / 'manager'
        self.manager.write_text(MANAGER)
        self.config = self.root / 'custom.env'
        self.config.write_text('before\n')
        self.events = self.root / 'events'
        self.env = dict(os.environ, DNSCOMPLEX_FS_ROOT=str(self.root),
                        DNSCOMPLEX_CONFIG=str(self.config), EVENTS=str(self.events))

    def shell(self, script, **env):
        driver = self.root / 'driver'
        driver.write_text(r'''#!/usr/bin/env bash
if [[ "${1:-}" == ipsec-ready || "${1:-}" == routes ]]; then
  step=$1; [[ "$step" != ipsec-ready ]] || step=ready
  printf '%s\n' "$step" >>"$EVENTS"
  [[ "$step" != "$FAIL" ]] || exit 41
  exit 0
fi
''' + 'source ' + shlex.quote(str(self.manager)) + '\n' + script)
        driver.chmod(0o700)
        return subprocess.run(['bash', str(driver)], env=dict(self.env, **env),
                              text=True, capture_output=True)

    def transaction(self, script, **env):
        return self.shell(r'''
need_root() { :; }; acquire_maintenance_lock() { :; }
verify_restore_recovery_helper() { :; }
event() { printf '%s\n' "$*" >>"$EVENTS"; }
backup_cmd() { printf 'backup' >"$1"; }
restore_cmd() { event restore; return "${RESTORE_RC:-0}"; }
state_transaction_manager_cmd() {
  case "$1" in
    backup_cmd) shift; backup_cmd "$@" ;;
    restore_cmd) shift; restore_cmd "$@" ;;
    state_transaction_verify_backup_cmd) return "${VERIFY_RC:-0}" ;;
    *) return 66 ;;
  esac
}
''' + script, **env)

    def records(self):
        return list((self.root / 'var/lib/dnscomplex-operations').glob('*/manifest.json'))

    def test_stack_failures_propagate_in_if_and_subshell_without_later_steps(self):
        steps = ['write', 'render', 'singbox', 'nft', 'reload', 'enable', 'restart', 'ready', 'routes']
        for context in ['if', 'subshell']:
            for failed in steps:
                with self.subTest(context=context, failed=failed):
                    self.events.unlink(missing_ok=True)
                    call = 'state_transaction_cmd "legacy stack" legacy_stack_candidate'
                    call = f'if {call}; then rc=0; else rc=$?; fi; exit "$rc"' if context == 'if' else f'( {call} )'
                    result = self.transaction(r'''
# Keep the unprofiled legacy stack's original nine fail-fast steps.
legacy_stack_candidate() { write_config_cmd || return $?; apply_egress_stack_cmd || return $?; }
step() { event "$1"; [[ "$1" != "$FAIL" ]] || return 41; }
write_config_cmd() { step write; }
render_xray_config_cmd() { step render; }
write_singbox_egress_cmd() { step singbox; }
write_nftables_runtime_cmd() { step nft; }
systemctl() { case "$1" in daemon-reload) step reload;; enable) step enable;; restart) step restart;; esac; }
''' + '\n' + call, FAIL=failed)
                    events = self.events.read_text().splitlines()
                    self.assertEqual(result.returncode, 41, result.stderr)
                    self.assertEqual(events, steps[:steps.index(failed) + 1] + ['restore'])

    def test_rollback_failure_retains_archive_custom_copy_manifest_and_original_status(self):
        result = self.transaction(r'''
candidate() { printf changed >"$CONFIG"; return 41; }
if state_transaction_cmd 'secret://USER:PASSWORD' candidate; then exit 0; else exit $?; fi
''', RESTORE_RC='42')
        self.assertEqual(result.returncode, 41, result.stderr)
        records = self.records()
        self.assertEqual(len(records), 1)
        record = json.loads(records[0].read_text())
        self.assertEqual(record['phase'], 'recovery-required')
        self.assertEqual(record['candidate_rc'], 41)
        self.assertEqual(record['rollback_rc'], 42)
        self.assertEqual((records[0].parent / record['archive']['path']).read_text(), 'backup')
        self.assertEqual((records[0].parent / 'custom-config').read_text(), 'before\n')
        self.assertNotIn('PASSWORD', records[0].read_text() + result.stderr)
        for path in [records[0], records[0].parent / 'custom-config', records[0].parent / 'backup.tar.gz']:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(records[0].parent.stat().st_mode & 0o777, 0o700)
        self.events.unlink()
        again = self.transaction('candidate() { event mutated; }; state_transaction_cmd synthetic candidate')
        self.assertNotEqual(again.returncode, 0)
        self.assertFalse(self.events.exists(), 'unresolved operation allowed a later writer')
        self.assertEqual(len(self.records()), 1)

    def test_terminal_results_remove_only_recovery_material(self):
        independent = self.root / 'independent.tar.gz'
        independent.write_text('keep')
        for failure, phase in [('0', 'committed'), ('41', 'rolled-back')]:
            result = self.transaction('candidate() { return "$CANDIDATE_RC"; }; state_transaction_cmd synthetic candidate',
                                      CANDIDATE_RC=failure)
            self.assertEqual(result.returncode, int(failure), result.stderr)
            records = [json.loads(p.read_text()) for p in self.records()]
            self.assertIn(phase, [r['phase'] for r in records])
            self.assertFalse(any(p.parent.joinpath('backup.tar.gz').exists() for p in self.records()))
        self.assertEqual(independent.read_text(), 'keep')

    def test_invalid_backup_rejected_before_candidate(self):
        result = self.transaction('candidate() { event mutated; }; state_transaction_cmd synthetic candidate', VERIFY_RC='43')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())

    def test_render_test_failure_stops_before_install_in_if_context(self):
        renderer = self.root / 'usr/local/lib/dnscomplex-xray/render.py'
        renderer.parent.mkdir(parents=True)
        renderer.write_text('#!/bin/sh\nexit "${RENDER_RC:-0}"\n')
        renderer.chmod(0o700)
        for render_rc, check_rc, expected in [('41', '0', 41), ('0', '42', 42)]:
            result = self.shell(r'''
need_root() { :; }
xray_test_config_file() { return "$CHECK_RC"; }
install() { printf installed >>"$EVENTS"; }
if render_xray_config_cmd; then exit 0; else exit $?; fi
''', RENDER_RC=render_rc, CHECK_RC=check_rc)
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertFalse(self.events.exists())

    def test_nft_render_and_check_failure_do_not_reload(self):
        self.config.write_text('WAN_IFACE=eth0\nDEPLOY_MODE=routeros-policy\nLAN_CLIENT_IPV4_CIDR=192.168.50.0/24\nLINUX_LAN_IPV4=192.168.50.200\n')
        for stage in ('render', 'check'):
            self.events.unlink(missing_ok=True)
            result = self.shell(r'''
load_config
need_root() { :; }; lan_alias_close_cmd() { :; }
runtime_nft_lan_alias_prerouting_rules() { [[ "$FAIL_STAGE" != render ]] || return 41; }
nft() { [[ "$FAIL_STAGE" != check ]] || return 42; }
systemctl() { printf reload >>"$EVENTS"; }
if write_nftables_runtime_cmd; then exit 0; else exit $?; fi
''', FAIL_STAGE=stage)
            self.assertEqual(result.returncode, 41 if stage == 'render' else 42, result.stderr)
            self.assertFalse(self.events.exists())

    def test_singbox_check_failure_does_not_install_or_reload(self):
        config = self.root / 'etc/sing-box/config.json'
        config.parent.mkdir(parents=True)
        config.write_text('before')
        result = self.shell(r'''
need_root() { :; }; lan_alias_close_cmd() { :; }
profile_outbound_tag() { printf tag; }
jq() { printf candidate; }
sing-box() { return 42; }
install() { printf installed >>"$EVENTS"; }
if write_singbox_egress_cmd; then exit 0; else exit $?; fi
''')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertFalse(self.events.exists())
        self.assertEqual(config.read_text(), 'before')

    def test_candidate_callbacks_stop_when_config_write_fails(self):
        for name, args in [('set_egress_candidate_cmd', 'ai ipsec'),
                           ('set_xray_uri_candidate_cmd', 'ai synthetic'),
                           ('set_xray_json_candidate_cmd', 'cn synthetic')]:
            result = self.shell(r'''
write_config_cmd() { return 43; }
apply_egress_stack_cmd() { printf applied >>"$EVENTS"; }
''' + f'if {name} {args}; then exit 0; else exit $?; fi')
            self.assertEqual(result.returncode, 43, result.stderr)
            self.assertFalse(self.events.exists())

    def test_config_serialization_failure_does_not_replace_config(self):
        before = (Path(__file__).resolve().parents[1] / 'examples/routeros-policy.config.env').read_text()
        self.config.write_text(before)
        result = self.shell(r'''load_config
need_root() { :; }
sed() { return 45; }
if write_config_cmd; then exit 0; else exit $?; fi
''')
        self.assertEqual(result.returncode, 45, result.stderr)
        self.assertEqual(self.config.read_text(), before)

    def test_tampered_archive_is_retained_and_never_restored(self):
        result = self.transaction(r'''
candidate() { printf corrupt >"$FS_ROOT"/var/lib/dnscomplex-operations/*/backup.tar.gz; return 41; }
state_transaction_cmd synthetic candidate
''')
        self.assertEqual(result.returncode, 41, result.stderr)
        self.assertFalse(self.events.exists(), 'tampered archive reached restore')
        record = json.loads(self.records()[0].read_text())
        self.assertEqual(record['phase'], 'recovery-required')
        self.assertTrue((self.records()[0].parent / 'backup.tar.gz').exists())

    def test_custom_restore_failure_preserves_all_recovery_material(self):
        result = self.transaction(r'''
candidate() { rm "$CONFIG"; mkdir "$CONFIG"; return 41; }
state_transaction_cmd synthetic candidate
''')
        self.assertEqual(result.returncode, 41, result.stderr)
        record = json.loads(self.records()[0].read_text())
        self.assertEqual(record['phase'], 'recovery-required')
        self.assertNotEqual(record['custom_config_rc'], 0)
        self.assertTrue((self.records()[0].parent / 'backup.tar.gz').exists())
        self.assertTrue((self.records()[0].parent / 'custom-config').exists())

    def test_real_backup_restore_in_fresh_shell_from_if_context(self):
        # Only system facilities are stubbed; candidate manager/backup/archive
        # validation/restore journal/recovery helper all run their emitted code.
        fakebin = self.root / 'bin'
        fakebin.mkdir()
        for name in ('flock', 'systemctl', 'id'):
            script = fakebin / name
            script.write_text('#!/bin/sh\nprintf 0\n' if name == 'id' else '#!/bin/sh\nexit 0\n')
            script.chmod(0o700)
        helper = self.root / 'usr/local/libexec/dnscomplex-restore-recover'
        helper.parent.mkdir(parents=True)
        helper.write_text(SOURCE.split("<<'RECOVERY'\n", 1)[1].split('\nRECOVERY\n', 1)[0])
        helper.chmod(0o700)
        self.config.write_text('WAN_IFACE=eth0\n')
        managed = self.root / 'etc/sing-box/config.json'
        managed.parent.mkdir(parents=True)
        managed.write_text('before')
        result = self.shell(r'''
need_root() { :; }
candidate() { printf changed >"$(fs_path /etc/sing-box/config.json)"; printf 'INVALID CONFIG (' >"$CONFIG"; return 41; }
if state_transaction_cmd synthetic candidate; then exit 0; else exit $?; fi
''', PATH=str(fakebin) + os.pathsep + os.environ['PATH'])
        self.assertEqual(result.returncode, 41, result.stderr)
        self.assertEqual(managed.read_text(), 'before')
        self.assertEqual(self.config.read_text(), 'WAN_IFACE=eth0\n')
        record = json.loads(self.records()[0].read_text())
        self.assertEqual(record['phase'], 'rolled-back')
        self.assertFalse((self.records()[0].parent / 'backup.tar.gz').exists())


if __name__ == '__main__':
    unittest.main()
