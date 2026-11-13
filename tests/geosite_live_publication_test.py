"""Exercise the real staged geosite transaction with controlled build and service inputs."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
MANAGER = SOURCE.split("<<'MANAGER'\n", 1)[1].split("\nMANAGER", 1)[0]

class GeositeLivePublicationTest(unittest.TestCase):
    def run_update(self, adguard_changed=False, fail=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = root / "manager"
            manager.write_text(MANAGER)
            for name, content in (("etc/sing-box/config.json", "{}"),
                                  ("etc/AdGuardHome/AdGuardHome.yaml", "old"),
                                  ("var/lib/dnscomplex/geosite/geosite-cn-video.srs", "old")):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            config = root / "etc/AdGuardHome/AdGuardHome.yaml"
            inode = config.stat().st_ino
            script = r'''
source "$MANAGER"
sync_geosite_sources_from_config() { :; }
sync_domain_seed_files_from_config() { :; }
write_config_cmd() { :; }
download_sing_geosite_ai_rule_sets() { :; }
download_geosite_source() { :; }
compile_profile() { if [[ "$1" == cn-video ]]; then printf new >"$GEO_DIR/geosite-cn-video.srs"; fi; }
install_domain_files() { :; }
render_adguard_runtime() {
  if [[ "$CHANGE_ADGUARD" == 1 ]]; then printf new >"$FS_ROOT/etc/AdGuardHome/AdGuardHome.yaml"; fi
}
geosite_candidate_config() { cp "$1" "$3"; }
sing-box() { :; }
validate_smartdns_config_cmd() { :; }
geosite_artifact_manifest() {
  printf '%s\n' etc/AdGuardHome/AdGuardHome.yaml var/lib/dnscomplex/geosite/geosite-cn-video.srs
}
systemctl() { echo "$1 $2"; }
restart_dns_stack() { echo stack-restart; }
wait_dns_ready() {
  echo dns-ready
  if [[ "$FAIL" == 1 && $(cat "$FS_ROOT/etc/AdGuardHome/AdGuardHome.yaml") == new ]]; then return 1; fi
}
refresh_nftsets_cmd() { echo refresh; }
geosite_update_transaction
'''
            # Replace only the external AdGuard configuration validator with a fixture.
            script = script.replace('source "$MANAGER"', r'''
source "$MANAGER"
eval "$(declare -f geosite_update_transaction | sed 's|/opt/AdGuardHome/AdGuardHome|true|')"
''')
            proc = subprocess.run(["bash", "-c", script], text=True, capture_output=True, timeout=10,
                                  env=dict(os.environ, DNSCOMPLEX_FS_ROOT=tmp, MANAGER=str(manager),
                                           CHANGE_ADGUARD=str(int(adguard_changed)), FAIL=str(int(fail))))
            srs = root / "var/lib/dnscomplex/geosite/geosite-cn-video.srs"
            return proc, config.read_text(), srs.read_text(), config.stat().st_ino == inode

    def test_ruleset_update_keeps_dns_and_proxy_running(self):
        proc, config, srs, same_inode = self.run_update()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.splitlines(), ["dns-ready", "refresh"])
        self.assertEqual((config, srs, same_inode), ("old", "new", True))

    def test_changed_adguard_config_only_restarts_adguard(self):
        proc, config, srs, _ = self.run_update(adguard_changed=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.splitlines(), ["restart AdGuardHome", "dns-ready", "refresh"])
        self.assertEqual((config, srs), ("new", "new"))

    def test_failed_dns_readiness_restores_both_files(self):
        proc, config, srs, _ = self.run_update(adguard_changed=True, fail=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.splitlines(), ["restart AdGuardHome", "dns-ready",
                                                     "restart AdGuardHome", "dns-ready"])
        self.assertEqual((config, srs), ("old", "old"))

if __name__ == "__main__":
    unittest.main()
