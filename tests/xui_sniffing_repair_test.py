import json
import hashlib
import inspect
import os
import stat
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

source = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
code = source.split("<<'XUI_REPAIR'\n", 1)[1].split("\nXUI_REPAIR", 1)[0]
namespace = {"__name__": "repair_test"}
exec(compile(code, "repair-xui-sniffing.py", "exec"), namespace)


class RepairTest(unittest.TestCase):
    def _policy_db(self, db, raw=None):
        before = {
            "policy": {"levels": {"0": {"connIdle": 300, "uplinkOnly": 0,
                "downlinkOnly": 0, "handshake": 4, "statsUserUplink": True,
                "statsUserDownlink": True, "statsUserOnline": True},
                "9": {"connIdle": 77, "handshake": 8}},
                "system": {"stats": {"inboundUplink": True}}},
            "inbounds": [{"tag": "vless-in", "settings": {"clients": [
                {"id": "synthetic-only", "level": 0}]}}],
            "routing": {"rules": [{"inboundTag": ["vless-in"], "outboundTag": "proxy"}]},
        }
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE settings(id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
            conn.execute("INSERT INTO settings(key,value) VALUES(?,?)",
                         ("xrayTemplateConfig", raw if raw is not None else json.dumps(before)))
        return before

    def test_policy_repair_changes_only_three_level0_timeouts_and_backup_restores(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "x-ui.db")
            before = self._policy_db(db)
            backup = namespace["repair_policy"](db)
            self.assertTrue(Path(backup).is_file())
            self.assertEqual(Path(backup).stat().st_mode & 0o777, 0o600)
            with sqlite3.connect(db) as conn:
                after = json.loads(conn.execute(
                    "SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0])
            expected = json.loads(json.dumps(before))
            expected["policy"]["levels"]["0"].update(
                connIdle=1200, uplinkOnly=30, downlinkOnly=30)
            self.assertEqual(after, expected)
            with sqlite3.connect(backup) as conn:
                original_raw = conn.execute(
                    "SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0]
            with sqlite3.connect(db) as conn:
                conn.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'", (original_raw,))
            with sqlite3.connect(db) as conn:
                restored = json.loads(conn.execute(
                    "SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0])
            self.assertEqual(restored, before)

    def test_policy_repair_is_idempotent_and_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "x-ui.db")
            before = self._policy_db(db)
            self.assertEqual(namespace["repair_policy"](db, dry_run=True), "dry-run")
            with sqlite3.connect(db) as conn:
                raw = conn.execute("SELECT value FROM settings").fetchone()[0]
            self.assertEqual(json.loads(raw), before)
            self.assertEqual(list(Path(directory).glob("*.policy-*.bak")), [])
            namespace["repair_policy"](db)
            self.assertIsNone(namespace["repair_policy"](db))

    def test_policy_repair_compare_and_swap_refuses_a_concurrent_row_change(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "x-ui.db")
            before = self._policy_db(db)
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TRIGGER refuse_update BEFORE UPDATE ON settings "
                             "BEGIN SELECT RAISE(IGNORE); END")
            with self.assertRaisesRegex(ValueError, "changed concurrently"):
                namespace["repair_policy"](db)
            with sqlite3.connect(db) as conn:
                raw = conn.execute("SELECT value FROM settings").fetchone()[0]
            self.assertEqual(json.loads(raw), before)

    def test_policy_repair_rejects_missing_duplicate_and_invalid_template_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "missing.db")
            with sqlite3.connect(missing) as conn:
                conn.execute("CREATE TABLE settings(id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
            with self.assertRaises(ValueError):
                namespace["repair_policy"](missing)
            invalid = str(Path(directory) / "invalid.db")
            self._policy_db(invalid, "{")
            with self.assertRaises(ValueError):
                namespace["repair_policy"](invalid)
            duplicated_key = str(Path(directory) / "duplicated-key.db")
            self._policy_db(duplicated_key,
                            '{"policy":{"levels":{"0":{"connIdle":300,"connIdle":900,'
                            '"uplinkOnly":0,"downlinkOnly":0}}}}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                namespace["repair_policy"](duplicated_key)
            duplicate = str(Path(directory) / "duplicate.db")
            self._policy_db(duplicate)
            with sqlite3.connect(duplicate) as conn:
                conn.execute("INSERT INTO settings(key,value) SELECT key,value FROM settings")
            with self.assertRaises(ValueError):
                namespace["repair_policy"](duplicate)

    def test_generated_config_verification_matches_or_reports_only_policy_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "generated.json"
            config = {"policy": {"levels": {"0": {
                "connIdle": 1200, "uplinkOnly": 30, "downlinkOnly": 30,
                "handshake": 4, "privateKey": "synthetic-secret-must-not-appear"}}},
                "inbounds": [{"settings": {"clients": [{"id": "synthetic-account"}]}}]}
            raw = json.dumps(config).encode()
            path.write_bytes(raw)
            stat_before = path.stat()
            self.assertEqual(namespace["verify_policy_config"](path), (1200, 30, 30))
            config["policy"]["levels"]["0"]["connIdle"] = 300
            path.write_text(json.dumps(config))
            try:
                namespace["verify_policy_config"](path)
            except ValueError as exc:
                message = str(exc)
                self.assertIn("connIdle=300", message)
                self.assertNotIn("synthetic-secret", message)
            else:
                self.fail("generated baseline policy must be rejected")
            stat_after = path.stat()
            self.assertEqual(stat_before.st_ino, stat_after.st_ino)
            self.assertEqual(json.loads(path.read_text()), config)

    def test_verify_cli_needs_opt_in_and_does_not_require_database(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = Path(directory) / "repair.py"
            helper.write_text(code)
            config_path = Path(directory) / "generated.json"
            config_path.write_text(json.dumps({"policy": {"levels": {"0": {
                "connIdle": 1200, "uplinkOnly": 30, "downlinkOnly": 30}}}}))
            ok = subprocess.run([sys.executable, str(helper), "--policy-level0-idle-1200",
                                 "--verify-generated-config", str(config_path)],
                                capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertIn("verified", ok.stdout)
            bad = subprocess.run([sys.executable, str(helper), "--verify-generated-config",
                                  str(config_path)], capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)
            conflict = subprocess.run([sys.executable, str(helper), "--database", "unused.db",
                                       "--policy-level0-idle-1200", "--tag", "",
                                       "--verify-generated-config", ""],
                                      capture_output=True, text=True)
            self.assertNotEqual(conflict.returncode, 0)
            self.assertNotIn("secret", conflict.stderr.lower())

    def test_preserves_unrelated_fields_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "x-ui.db")
            sniff = {"enabled": True, "routeOnly": True,
                     "destOverride": ["tls", "http"], "domainsExcluded": ["example.org"]}
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE inbounds(id INTEGER, tag TEXT, sniffing TEXT)")
                conn.executemany("INSERT INTO inbounds VALUES(?,?,?)",
                                 [(1, "target", json.dumps(sniff)), (2, "other", json.dumps(sniff))])
            backup = namespace["repair"](db, "target")
            self.assertTrue(Path(backup).is_file())
            with sqlite3.connect(db) as conn:
                rows = conn.execute("SELECT sniffing FROM inbounds ORDER BY id").fetchall()
            self.assertEqual(json.loads(rows[0][0]), dict(sniff, routeOnly=False))
            self.assertEqual(json.loads(rows[1][0]), sniff)
            self.assertIsNone(namespace["repair"](db, "target"))
            with sqlite3.connect(backup) as conn:
                self.assertEqual(json.loads(conn.execute("SELECT sniffing FROM inbounds WHERE id=1").fetchone()[0]), sniff)
            with self.assertRaises(ValueError):
                namespace["repair"](db, "missing")


    def test_exact_preserve_destination_with_sniffing_already_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "x-ui.db")
            sniff = {"enabled": True, "routeOnly": False,
                     "destOverride": ["tls", "quic"], "domainsExcluded": ["example.org"]}
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE inbounds(id INTEGER, tag TEXT, sniffing TEXT)")
                conn.execute("INSERT INTO inbounds VALUES(?,?,?)", (1, "target", json.dumps(sniff)))
            backup = namespace["repair"](db, "target", ["c2c.cdn.wechat.com"])
            self.assertTrue(Path(backup).is_file())
            with sqlite3.connect(db) as conn:
                value = json.loads(conn.execute("SELECT sniffing FROM inbounds").fetchone()[0])
            self.assertEqual(value, dict(sniff, domainsExcluded=["example.org", "full:c2c.cdn.wechat.com"]))
            self.assertIsNone(namespace["repair"](db, "target", ["c2c.cdn.wechat.com"]))
            for invalid in ("*.wechat.com", "domain:wechat.com", "wechat.com/", ""):
                with self.assertRaises(ValueError):
                    namespace["repair"](db, "target", [invalid])

    def test_explicit_preserve_original_ip_keeps_route_only_and_is_idempotent(self):
        self.assertIn("preserve_original_ip", inspect.signature(namespace["repair"]).parameters,
                      "repair needs an explicit preserve-original-IP option")
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "x-ui.db")
            sniff = {"enabled": True, "routeOnly": False,
                     "destOverride": ["tls", "quic"],
                     "domainsExcluded": ["example.org"], "metadataOnly": False}
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE inbounds(id INTEGER, tag TEXT, sniffing TEXT)")
                conn.execute("INSERT INTO inbounds VALUES(?,?,?)", (1, "target", json.dumps(sniff)))
            backup = namespace["repair"](db, "target", preserve_original_ip=True)
            self.assertTrue(Path(backup).is_file())
            with sqlite3.connect(db) as conn:
                actual = json.loads(conn.execute("SELECT sniffing FROM inbounds").fetchone()[0])
            self.assertEqual(actual, dict(sniff, routeOnly=True))
            with sqlite3.connect(backup) as conn:
                before = json.loads(conn.execute("SELECT sniffing FROM inbounds").fetchone()[0])
            self.assertEqual(before, sniff)
            self.assertIsNone(namespace["repair"](db, "target", preserve_original_ip=True))

    def test_mobile_api_destination_preset_preserves_only_three_exact_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "x-ui.db"
            sniff = {"enabled": True, "routeOnly": False,
                     "destOverride": ["tls", "quic"],
                     "domainsExcluded": ["example.org"],
                     "metadataOnly": False, "customField": {"keep": True}}
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE inbounds(id INTEGER, tag TEXT, sniffing TEXT)")
                conn.execute("INSERT INTO inbounds VALUES(?,?,?)", (1, "target", json.dumps(sniff)))
            helper = Path(directory) / "repair.py"
            helper.write_text(code)
            result = subprocess.run([
                sys.executable, str(helper), "--database", str(db), "--tag", "target",
                "--preserve-tested-mobile-api-destinations"],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            with sqlite3.connect(db) as conn:
                actual = json.loads(conn.execute("SELECT sniffing FROM inbounds").fetchone()[0])
            self.assertEqual(actual, {
                "enabled": True, "routeOnly": False, "destOverride": ["tls", "quic"],
                "domainsExcluded": ["example.org", "full:c2c.cdn.wechat.com",
                                    "full:edith.xiaohongshu.com", "full:rec.xiaohongshu.com"],
                "metadataOnly": False, "customField": {"keep": True},
            })
            backups = list(Path(directory).glob("*.sniffing-*.bak"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
            second = subprocess.run([
                sys.executable, str(helper), "--database", str(db), "--tag", "target",
                "--preserve-tested-mobile-api-destinations"],
                capture_output=True, text=True)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("already configured", second.stdout)
            self.assertEqual(list(Path(directory).glob("*.sniffing-*.bak")), backups)

    def test_mobile_api_destination_preset_requires_tag_without_database_write(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "x-ui.db"
            sniff = {"enabled": True, "routeOnly": False, "destOverride": ["tls"],
                     "domainsExcluded": ["example.org"]}
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE inbounds(id INTEGER, tag TEXT, sniffing TEXT)")
                conn.execute("INSERT INTO inbounds VALUES(?,?,?)", (1, "target", json.dumps(sniff)))
            before = db.read_bytes()
            helper = Path(directory) / "repair.py"
            helper.write_text(code)
            result = subprocess.run([
                sys.executable, str(helper), "--database", str(db),
                "--preserve-tested-mobile-api-destinations"],
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--tag is required", result.stderr)
            self.assertEqual(db.read_bytes(), before)
            self.assertEqual(list(Path(directory).glob("*.sniffing-*.bak")), [])

    def test_mobile_api_destination_preset_rejects_conflicting_modes_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "x-ui.db"
            sniff = {"enabled": True, "routeOnly": False, "destOverride": ["tls"],
                     "domainsExcluded": ["example.org"]}
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE inbounds(id INTEGER, tag TEXT, sniffing TEXT)")
                conn.execute("INSERT INTO inbounds VALUES(?,?,?)", (1, "target", json.dumps(sniff)))
            helper = Path(directory) / "repair.py"
            helper.write_text(code)
            conflict_args = [
                ["--preserve-original-ip"],
                ["--preserve-destination", "other.example"],
                ["--policy-level0-idle-1200"],
                ["--patch-xpanel-source", str(Path(directory) / "source.go")],
            ]
            for extra in conflict_args:
                with self.subTest(extra=extra):
                    result = subprocess.run([
                        sys.executable, str(helper), "--database", str(db), "--tag", "target",
                        "--preserve-tested-mobile-api-destinations", *extra],
                        capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("conflict", result.stderr.lower())
            with sqlite3.connect(db) as conn:
                actual = json.loads(conn.execute("SELECT sniffing FROM inbounds").fetchone()[0])
            self.assertEqual(actual, sniff)
            self.assertEqual(list(Path(directory).glob("*.sniffing-*.bak")), [])

    def _source_patch_pair(self):
        original_block = namespace["XPANEL_SOURCE_OLD_BLOCK"]
        patched_block = namespace["XPANEL_SOURCE_NEW_BLOCK"]
        source = b"package service\n" + original_block + b"\n// end\n"
        patched = source.replace(original_block, patched_block, 1)
        namespace["XPANEL_SOURCE_ORIGINAL_SHA256"] = hashlib.sha256(source).hexdigest()
        namespace["XPANEL_SOURCE_PATCHED_SHA256"] = hashlib.sha256(patched).hexdigest()
        return source, patched

    def test_xpanel_source_patch_preserves_only_known_policy_block_and_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            source, patched = self._source_patch_pair()
            path = Path(directory) / "web-service-xray.go"
            path.write_bytes(source)
            path.chmod(0o640)
            backup = namespace["patch_xpanel_source"](str(path))
            self.assertEqual(path.read_bytes(), patched)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            self.assertEqual(Path(backup).read_bytes(), source)
            self.assertEqual(stat.S_IMODE(Path(backup).stat().st_mode), 0o600)
            self.assertIsNone(namespace["patch_xpanel_source"](str(path)))
            self.assertEqual(list(Path(directory).glob("*.xpanel-policy-*.bak")), [Path(backup)])

    def test_xpanel_source_patch_dry_run_and_unknown_content_are_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            source, _patched = self._source_patch_pair()
            path = Path(directory) / "source.go"
            path.write_bytes(source)
            self.assertEqual(namespace["patch_xpanel_source"](str(path), dry_run=True), "dry-run")
            self.assertEqual(path.read_bytes(), source)
            self.assertEqual(list(Path(directory).glob("*.bak")), [])
            path.write_bytes(b"unknown source")
            with self.assertRaisesRegex(ValueError, "unsupported source SHA-256"):
                namespace["patch_xpanel_source"](str(path))
            self.assertEqual(path.read_bytes(), b"unknown source")
            self.assertEqual(list(Path(directory).glob("*.bak")), [])

    def test_xpanel_source_patch_rejects_symlink_and_nonregular_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source, _patched = self._source_patch_pair()
            target = Path(directory) / "target.go"
            target.write_bytes(source)
            link = Path(directory) / "link.go"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                namespace["patch_xpanel_source"](str(link), dry_run=True)
            with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                namespace["patch_xpanel_source"](directory, dry_run=True)
            self.assertEqual(target.read_bytes(), source)

    def test_xpanel_source_patch_refuses_compare_and_swap_race(self):
        with tempfile.TemporaryDirectory() as directory:
            source, _patched = self._source_patch_pair()
            path = Path(directory) / "source.go"
            path.write_bytes(source)
            verify = namespace["_verify_source_snapshot"]
            changed = b"concurrent source change\n"

            def race_then_verify(filename, expected, snapshot):
                Path(filename).write_bytes(changed)
                return verify(filename, expected, snapshot)

            namespace["_verify_source_snapshot"] = race_then_verify
            try:
                with self.assertRaisesRegex(ValueError, "changed concurrently"):
                    namespace["patch_xpanel_source"](str(path))
            finally:
                namespace["_verify_source_snapshot"] = verify
            self.assertEqual(path.read_bytes(), changed)

    def test_xpanel_source_cli_is_mutually_exclusive_with_policy_options(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = Path(directory) / "repair.py"
            helper.write_text(code)
            path = Path(directory) / "source.go"
            path.write_text("not touched")
            result = subprocess.run([sys.executable, str(helper), "--patch-xpanel-source", str(path),
                                     "--policy-level0-idle-1200"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mutually exclusive", result.stderr)
            self.assertEqual(path.read_text(), "not touched")

    def test_xpanel_source_cli_dry_run_needs_no_database_and_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            old_block = namespace["XPANEL_SOURCE_OLD_BLOCK"]
            new_block = namespace["XPANEL_SOURCE_NEW_BLOCK"]
            source = b"package service\n" + old_block + b"\n"
            patched = source.replace(old_block, new_block, 1)
            old_hash = hashlib.sha256(source).hexdigest()
            new_hash = hashlib.sha256(patched).hexdigest()
            helper_code = code.replace(namespace["XPANEL_SOURCE_ORIGINAL_SHA256"], old_hash)
            helper_code = helper_code.replace(namespace["XPANEL_SOURCE_PATCHED_SHA256"], new_hash)
            helper = Path(directory) / "repair.py"
            helper.write_text(helper_code)
            source_path = Path(directory) / "source.go"
            source_path.write_bytes(source)
            result = subprocess.run([sys.executable, str(helper), "--patch-xpanel-source",
                                     str(source_path), "--dry-run"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("build the same release", result.stdout)
            self.assertIn("no build or restart performed", result.stdout)
            self.assertEqual(source_path.read_bytes(), source)
            self.assertEqual(list(Path(directory).glob("*.bak")), [])


if __name__ == "__main__":
    unittest.main()
