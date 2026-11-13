"""Native nft compiler/apply/readback/undo proof in a private Linux netns.

The host test is a no-op unless Linux nftables and unshare are available. It
renders both frozen installer sources without running their main entrypoints.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CANDIDATE_INSTALLER = ROOT / "install.sh"
BASELINE_INSTALLER = ROOT / "output/domain-repair/install-75e99856-checkpoint.sh"
CANDIDATE_SHA = "856be53885775e98076a0a6e2611e2de27028970d7cde3bb3b714def77a5896f"
BASELINE_SHA = "75e99856d22eda2290184101e741a0594b96ad5b65b47ef6f9c81300a8f73d34"
SPEC = importlib.util.spec_from_file_location(
    "profile_health_nft_delta", ROOT / "tools/profile_health_nft_delta.py")
delta = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = delta
SPEC.loader.exec_module(delta)


def render_nft(installer: pathlib.Path, output: pathlib.Path) -> str:
    source = installer.read_text(encoding="utf-8")
    functions = list(re.finditer(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\) \{\s*$", source))
    names = [item.group(1) for item in functions]
    start = names.index("render_nft_profile_prerouting_rules")
    renderer = names.index("render_nftables")
    if renderer <= start or renderer + 1 >= len(functions):
        raise AssertionError("could not isolate actual renderer functions")
    snippet = source[functions[start].start():functions[renderer + 1].start()]
    harness = f'''set -euo pipefail
{snippet}
DRY_RUN=1
WAN_IFACE=ens18
LAN_VLAN_ID=22
DEPLOY_MODE=vlan-gateway
AI_EGRESS_MODE=ipsec
CN_EGRESS_MODE=ipsec
AI_QUIC_POLICY=reject
CN_QUIC_POLICY=reject
AI_MARK=0x301
CN_MARK=0x351
IPSEC_DATAPLANE_AI_MARK=0x3a1
IPSEC_DATAPLANE_CN_MARK=0x3f1
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK=0x2024
IPSEC_TCP_MSS=1200
LINUX_LAN_IPV4=192.0.2.2
LAN_CLIENT_IPV4_CIDR=192.0.2.0/24
write_file() {{
  if [[ "$1" == "/etc/nftables.d/dnscomplex.nft" ]]; then cat >"$NFT_OUTPUT"; else cat >/dev/null; fi
}}
die() {{ echo "$*" >&2; exit 1; }}
target_path() {{ printf '%s' "$1"; }}
render_nftables
'''
    env = dict(os.environ)
    env["NFT_OUTPUT"] = str(output)
    subprocess.run(["bash", "-c", harness], cwd=installer.parent, env=env,
                   check=True, capture_output=True, text=True)
    rendered = output.read_text(encoding="utf-8")
    if not rendered.startswith("table inet dnscomplex {"):
        raise AssertionError(f"{installer.name} did not render the dnscomplex table")
    return rendered


def run(argv: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(argv, check=False, capture_output=True, text=True, input=input_text)
    if result.returncode:
        raise AssertionError(f"command failed ({result.returncode}): {argv!r}\n{result.stderr}")
    return result.stdout


def table_json() -> dict:
    return json.loads(run(["nft", "-j", "list", "table", "inet", "dnscomplex"]))


def _stable_timeout_fields(value):
    if isinstance(value, dict):
        return {key: _stable_timeout_fields(child) for key, child in value.items()
                if key != "expires"}
    if isinstance(value, list):
        return [_stable_timeout_fields(child) for child in value]
    return value


def namespace_roundtrip() -> None:
    if hashlib.sha256(CANDIDATE_INSTALLER.read_bytes()).hexdigest() != CANDIDATE_SHA:
        raise AssertionError("candidate installer is not the frozen 856 source")
    if hashlib.sha256(BASELINE_INSTALLER.read_bytes()).hexdigest() != BASELINE_SHA:
        raise AssertionError("baseline installer is not the frozen 75e source")
    with tempfile.TemporaryDirectory(prefix="dnscomplex-health-nft-") as temp_name:
        temp = pathlib.Path(temp_name)
        baseline_path = temp / "baseline.nft"
        candidate_path = temp / "candidate.nft"
        baseline = render_nft(BASELINE_INSTALLER, baseline_path)
        candidate = render_nft(CANDIDATE_INSTALLER, candidate_path)
        run(["nft", "-f", "-"], input_text=baseline)
        initial = table_json()
        live_sets = [entry["set"] for entry in initial["nftables"]
                     if isinstance(entry, dict) and isinstance(entry.get("set"), dict)]
        if not any(item.get("name") == "ai4" for item in live_sets):
            raise AssertionError("75e baseline native table is missing ai4 dynamic set")
        # Seed an unrelated domain/profile element; the compiler and undo must
        # preserve native set contents as well as the table's other rules.
        run(["nft", "add", "element", "inet", "dnscomplex", "ai4",
             "{", "203.0.113.77", "timeout", "1h", "}"])
        run(["nft", "add", "element", "inet", "dnscomplex", "ai_ready4",
             "{", "203.0.113.78", "}"])
        baseline_state = table_json()
        compiled = delta.compile_delta(
            baseline_state, baseline, candidate, CANDIDATE_SHA,
            {"ai": "ipsec", "cn": "ipsec"},
            {"ai": "10.250.1.10", "cn": "10.251.1.10"})
        run(["nft", "-c", "-f", "-"], input_text=compiled["transaction"])
        run(["nft", "-f", "-"], input_text=compiled["transaction"])
        applied = table_json()
        delta.verify_applied(applied, compiled["expected_rules"], compiled["expected_sets"])
        ai4_after = next(item["set"] for item in applied["nftables"]
                         if isinstance(item, dict) and item.get("set", {}).get("name") == "ai4")
        if not any("203.0.113.77" in json.dumps(item) for item in ai4_after.get("elem", [])):
            raise AssertionError("unrelated ai4 dynamic domain marker was lost during apply")
        ai_ready_after = next(item["set"] for item in applied["nftables"]
                              if isinstance(item, dict) and item.get("set", {}).get("name") == "ai_ready4")
        if not any("203.0.113.78" in json.dumps(item) for item in ai_ready_after.get("elem", [])):
            raise AssertionError("unrelated ai_ready4 gate marker was lost during apply")
        undo_commands = delta.build_undo(applied, compiled)
        undo_batch = "\n".join(undo_commands) + "\n"
        run(["nft", "-c", "-f", "-"], input_text=undo_batch)
        run(["nft", "-f", "-"], input_text=undo_batch)
        restored = table_json()
        if _stable_timeout_fields(restored) != _stable_timeout_fields(baseline_state):
            raise AssertionError("native nft table did not return exactly to its pre-delta snapshot")


class ProfileHealthNFTDeltaNamespaceTest(unittest.TestCase):
    def test_native_render_apply_readback_and_exact_undo_in_private_namespace(self):
        if sys.platform != "linux":
            self.skipTest("native nft wire fixture requires Linux")
        missing = [name for name in ("nft", "unshare") if shutil.which(name) is None]
        if missing:
            self.skipTest("missing Linux fixture tools: " + ", ".join(missing))
        probe = subprocess.run(["unshare", "--net", "true"], check=False,
                               capture_output=True, text=True)
        if probe.returncode:
            self.skipTest("network namespace capability unavailable: " + probe.stderr.strip())
        subprocess.run(["unshare", "--net", sys.executable, str(pathlib.Path(__file__).resolve()),
                        "--isolated"], cwd=ROOT, check=True, timeout=60)


if __name__ == "__main__":
    if sys.argv[1:] == ["--isolated"]:
        namespace_roundtrip()
    else:
        unittest.main()
