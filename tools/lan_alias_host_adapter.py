#!/usr/bin/env python3
"""Fixed-argv host adapter for guarded LAN alias deployment.

Construction is read-only. Mutating methods require ``apply=True``. This module
has no apply CLI and must not be used against a host without reviewed Linux
wire validation.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shlex
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence


class HostAdapterError(RuntimeError):
    pass


TARGETS = frozenset({"/root/install.sh", "/usr/local/sbin/dnscomplex",
    "/usr/local/libexec/dnscomplex-lan-alias", "/etc/sing-box/config.json",
    "/etc/nftables.d/dnscomplex.nft", "/var/lib/dnscomplex/lan-alias.json"})
READ_PATHS = TARGETS | {"/etc/dnscomplex/config.env"}
PARSED_CONFIG_KEYS = frozenset({"DEPLOY_MODE", "WAN_IFACE", "LAN_VLAN_ID", "LINUX_LAN_IPV4",
    "AI_EGRESS_MODE", "CN_EGRESS_MODE", "AI_MARK", "CN_MARK",
    "SINGBOX_AUTO_REDIRECT_OUTPUT_MARK", "AI_QUIC_POLICY", "CN_QUIC_POLICY"})
# Complete schema emitted by the frozen install.sh write_config_cmd(). Values
# outside PARSED_CONFIG_KEYS are syntax-checked but intentionally never retained.
CONFIG_SCHEMA_KEYS = frozenset("""
ADGUARD_DNS_CACHE_MODE AI_DNS_UPSTREAMS AI_EGRESS_MODE AI_GEOSITE_SOURCES AI_IPSEC_PASSWORD
AI_IPSEC_SERVER AI_IPSEC_USERNAME AI_MARK AI_MARK_DEC AI_NFTSET_REFRESH_DOMAINS AI_QUIC_POLICY
AI_SAMPLE_DOMAINS AI_SUPPORT_DOMAINS AI_TABLE AI_XFRM_ID AI_XRAY_OUTBOUND_JSON AI_XRAY_URI
APPLE_PRIVATE_RELAY_BLOCK CN_DNS_UPSTREAMS CN_EGRESS_MODE CN_IPSEC_PASSWORD CN_IPSEC_SERVER
CN_IPSEC_USERNAME CN_MARK CN_MARK_DEC CN_NFTSET_REFRESH_DOMAINS CN_OVERRIDE_PROBE_DOMAINS
CN_OVERRIDE_PROBE_RESOLVERS CN_QUIC_POLICY CN_SAMPLE_DOMAINS CN_STATIC_A_OVERRIDES CN_TABLE
CN_VIDEO_SOURCES CN_XFRM_ID CN_XRAY_OUTBOUND_JSON CN_XRAY_URI AI_IKE_REMOTE CN_IKE_REMOTE
DEFAULT_DNS_STRATEGY
DEFAULT_DNS_UPSTREAMS DEFAULT_IPV6_MODE DEPLOY_MODE DNSCOMPLEX_IPSEC_BOOT_TIMEOUT
DNSCOMPLEX_METRICS_LISTEN DNSCOMPLEX_METRICS_PORT DNSCOMPLEX_NFTSET_REFRESH_INTERVAL
DNSCOMPLEX_NFTSET_REFRESH_TIMEOUT DNSCOMPLEX_PINNED_VERSION DNSCOMPLEX_UPDATE_CHANNEL
DNSCOMPLEX_UPDATE_LAST_LOG DNSCOMPLEX_UPDATE_TIME DNSCOMPLEX_VERSION DNSCOMPLEX_WEB_LISTEN
DNSCOMPLEX_WEB_PASSWORD DNSCOMPLEX_WEB_PORT GITHUB_RELEASE_POLICY HA_FAILOVER_POLICY HA_HEALTH_URL
HA_MODE HA_PRIMARY_IP HA_SECONDARY_IP IPSEC_REMOTE_ID IPSEC_TCP_MSS LAN_CLIENT_IPV4_CIDR
LAN_DHCP_END LAN_DHCP_START LAN_IPV4_CIDR LAN_IPV6_GATEWAY LAN_IPV6_PREFIX LAN_VLAN_ID
LINUX_LAN_IPV4 LINUX_TRANSIT_IPV4 LINUX_TRANSIT_IPV6 LOCAL_DOMAIN_IPV6_POLICY PROMETHEUS_MODE
ROUTEROS_LAN_IPV4 ROUTEROS_TRANSIT_IPV4 ROUTEROS_TRANSIT_IPV6 SINGBOX_AUTO_REDIRECT_INPUT_MARK
SINGBOX_AUTO_REDIRECT_INPUT_MARK_DEC SINGBOX_AUTO_REDIRECT_OUTPUT_MARK
SINGBOX_AUTO_REDIRECT_OUTPUT_MARK_DEC SINGBOX_DNS_LISTEN SINGBOX_DNS_PORT SINGBOX_HTTP_LISTEN
SINGBOX_HTTP_PORT SINGBOX_LOG_LEVEL SINGBOX_SOCKS_LISTEN SINGBOX_SOCKS_PORT
SING_GEOSITE_RULESET_BASE_URL SMARTDNS_AI_PORT SMARTDNS_CN_PORT SMARTDNS_DEFAULT_PORT
TRANSIT_IPV4_CIDR TRANSIT_IPV6_CIDR TRANSIT_VLAN_ID WAN_IFACE XRAY_AI_SOCKS_PORT
XRAY_CN_SOCKS_PORT XRAY_ENABLED XRAY_LISTEN_HOST
""".split())
ALIAS_SETS = ("lan_alias_source4", "lan_alias_ready4", "lan_alias_config_ready4")

# Constant source snippets only. No candidate, config, or CLI text is interpolated.
VERIFY_MANAGER = r'''set -euo pipefail
source /usr/local/sbin/dnscomplex
load_config
sas=$(timeout --signal=TERM --kill-after=1s 5s swanctl --list-sas 2>/dev/null)
for profile in ai cn; do
 vip=$(ipsec_vip_from_sas "$profile" <<<"$sas")
 ipsec_profile_runtime_ready "$profile" "$sas"
 ipsec_nat_profile_matches "$profile" "$vip"
 ipsec_alias_nat_profile_matches "$profile" "$vip"
 ipsec_bind_profile_matches "$profile" "$vip"
done
'''
RECOVER_MANAGER = r'''set -euo pipefail
source /usr/local/sbin/dnscomplex
load_config
[[ "$AI_EGRESS_MODE" == ipsec && "$CN_EGRESS_MODE" == ipsec ]]
alias_state="${FS_ROOT:-}/var/lib/dnscomplex/lan-alias.json"
alias_state_valid=0
if [[ -e "$alias_state" || -L "$alias_state" ]]; then
 [[ -f "$alias_state" && ! -L "$alias_state" ]] || exit 1
 jq -e 'type == "object" and .schema == 1 and .status == "owned" and
   .address == "198.18.255.254" and .interface == "lo" and
   .label == "lo:dc-alias" and .outbound_tag == "lan-legacy-alias" and
   .pool == "198.18.255.0/24"' "$alias_state" >/dev/null
 declare -F ipsec_alias_nat_profile_matches >/dev/null || exit 1
 alias_state_valid=1
fi
profile_egress_gate_clear ai
profile_egress_gate_clear cn
sas=$(timeout --signal=TERM --kill-after=1s 8s swanctl --list-sas 2>/dev/null)
for profile in ai cn; do
 ipsec_profile_sa_ready "$profile" "$sas"
 ensure_policy_route_profile "$profile"
 sync_ipsec_nat_profile "$profile"
done
sync_singbox_ipsec_bind_addresses
fresh_sas=$(timeout --signal=TERM --kill-after=1s 8s swanctl --list-sas 2>/dev/null)
for profile in ai cn; do
 vip=$(ipsec_vip_from_sas "$profile" <<<"$fresh_sas")
 ipsec_profile_runtime_ready "$profile" "$fresh_sas"
 ipsec_nat_profile_matches "$profile" "$vip"
 if [[ "$alias_state_valid" == 1 ]]; then ipsec_alias_nat_profile_matches "$profile" "$vip"; fi
 ipsec_bind_profile_matches "$profile" "$vip"
done
if [[ "${DNSCOMPLEX_RESTORE_AI_OPEN:-0}" == 1 ]]; then profile_egress_gate_open ai; else profile_egress_gate_clear ai; fi
if [[ "${DNSCOMPLEX_RESTORE_CN_OPEN:-0}" == 1 ]]; then profile_egress_gate_open cn; else profile_egress_gate_clear cn; fi
'''
VERIFY_RECOVERED_MANAGER = r'''set -euo pipefail
source /usr/local/sbin/dnscomplex
load_config
sas=$(timeout --signal=TERM --kill-after=1s 5s swanctl --list-sas 2>/dev/null)
for profile in ai cn; do
 vip=$(ipsec_vip_from_sas "$profile" <<<"$sas")
 ipsec_profile_runtime_ready "$profile" "$sas"
 ipsec_nat_profile_matches "$profile" "$vip"
 ipsec_bind_profile_matches "$profile" "$vip"
done
'''
CLOSE_PROFILE_GATES = r'''set -euo pipefail
source /usr/local/sbin/dnscomplex
load_config
failed=0
profile_egress_gate_clear ai || failed=1
profile_egress_gate_clear cn || failed=1
exit "$failed"
'''


def parse_config_env(text: str) -> dict[str, str]:
    result = {}
    seen = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        if not match or match[1] not in CONFIG_SCHEMA_KEYS or match[1] in seen:
            raise HostAdapterError(f"unsupported/duplicate config assignment at line {lineno}")
        seen.add(match[1])
        try:
            words = shlex.split(match[2], comments=False, posix=True)
        except ValueError as exc:
            raise HostAdapterError(f"invalid config quoting at line {lineno}") from exc
        if not words and match[1] == "LAN_VLAN_ID" and match[2] == "":
            result[match[1]] = ""
            continue
        if len(words) != 1:
            raise HostAdapterError(f"invalid config value at line {lineno}")
        if match[1] not in PARSED_CONFIG_KEYS:
            # Config values may contain shell-quoted spaces (for example DNS
            # upstream lists or credentials); shlex validates quoting only.
            continue
        if any(c.isspace() or ord(c) < 32 for c in words[0]):
            raise HostAdapterError(f"invalid config value at line {lineno}")
        result[match[1]] = words[0]
    return result


def parse_swanctl_vips(text: str) -> dict[str, str]:
    sections = {"ai": [], "cn": []}
    profile = None
    established = installed = False
    locals_ = []

    def flush():
        if profile in sections and established and installed:
            sections[profile].extend(locals_)

    for line in text.splitlines():
        if line and not line[0].isspace():
            flush()
            profile = None
            established = installed = False
            locals_ = []
            match = re.match(r"^(ai|cn):\s+#\d+,\s+ESTABLISHED(?:,|\s|$)", line)
            if match:
                profile, established = match[1], True
        elif profile:
            if re.match(rf"^\s+{profile}:\s+#\d+.*?,\s+INSTALLED(?:,|\s|$)", line):
                installed = True
            if re.match(r"^\s+local(?:\s|$)", line):
                locals_.extend(re.findall(r"\[([^][]+)\]", line))
    flush()
    parsed = {}
    for name, candidates in sections.items():
        valid = set()
        for candidate in candidates:
            try:
                addr = ipaddress.ip_address(candidate)
                if addr.version == 4 and not (addr.is_unspecified or addr.is_loopback or
                    addr.is_multicast or addr.is_link_local):
                    valid.add(str(addr))
            except ValueError:
                continue
        if len(valid) != 1:
            raise HostAdapterError(f"{name} needs one established installed IPv4 VIP")
        parsed[name] = valid.pop()
    return parsed


def _conntrack_address(value, family):
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError as exc:
        raise HostAdapterError("conntrack output has an invalid address") from exc
    expected = 4 if family == "ipv4" else 6
    if address.version != expected:
        raise HostAdapterError("conntrack tuple family does not match its address")
    return address.compressed


def _conntrack_integer(value, label, maximum=None):
    try:
        parsed = int(value, 16 if value.lower().startswith("0x") else 10)
    except (ValueError, AttributeError) as exc:
        raise HostAdapterError(f"conntrack output has an invalid {label}") from exc
    if parsed < 0 or (maximum is not None and parsed > maximum):
        raise HostAdapterError(f"conntrack output has an invalid {label}")
    return parsed


def stable_conntrack(text: str) -> dict[str, dict[str, object]]:
    """Parse stable tuple/mark/id identity separately from mutable state and TTL."""
    rows = {}
    protocol_numbers = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58", "igmp": "2"}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or fields[0] not in ("ipv4", "ipv6") or not fields[1].isdigit():
            raise HostAdapterError("conntrack output lacks extended tuple/id format")
        family, family_code, proto, proto_number = fields[0], fields[1], fields[2], fields[3]
        expected_family_code = "2" if family == "ipv4" else "10"
        if family_code != expected_family_code:
            raise HostAdapterError("conntrack output has an invalid family code")
        timeout_s = _conntrack_integer(fields[4], "timeout")
        # The second field is AF_INET/AF_INET6 (2/10), not the conntrack
        # zone. The zone is an optional key in the payload and defaults to 0.
        zone = 0
        if proto == "unknown" and proto_number == "2" and family == "ipv4":
            # The deployed conntrack formatter reports IGMP as unknown/2.
            proto = "igmp"
        if proto not in protocol_numbers or proto_number != protocol_numbers[proto]:
            raise HostAdapterError("conntrack output has an unsupported protocol")
        if (proto in ("icmp", "igmp") and family != "ipv4") or \
                (proto == "icmpv6" and family != "ipv6"):
            raise HostAdapterError("conntrack protocol does not match its address family")
        terminal = fields[-1].split("=", 1)
        if len(terminal) != 2 or terminal[0] != "id" or not terminal[1].isdigit():
            raise HostAdapterError("conntrack output lacks terminal conntrack id")
        ident = terminal[1]
        if ident in rows:
            raise HostAdapterError("conntrack output has duplicate id")
        pairs = [token.split("=", 1) for token in fields[5:-1] if "=" in token]
        values = {}
        for key, value in pairs:
            values.setdefault(key, []).append(value)
        common = {"src", "dst", "mark", "use", "packets", "bytes", "zone"}
        fields_by_protocol = {
            "tcp": common | {"sport", "dport"},
            "udp": common | {"sport", "dport"},
            "icmp": common | {"type", "code", "id"},
            "icmpv6": common | {"type", "code", "id"},
            "igmp": common,
        }
        if set(values) - fields_by_protocol[proto]:
            raise HostAdapterError("conntrack output has unsupported protocol fields")
        if len(values.get("zone", [])) > 1:
            raise HostAdapterError("conntrack output has an ambiguous zone")
        if values.get("zone"):
            zone = _conntrack_integer(values["zone"][0], "zone", 65535)
        if any(len(values.get(key, [])) != 2 for key in ("src", "dst")) or \
                len(values.get("mark", [])) != 1:
            raise HostAdapterError("conntrack output lacks an unambiguous tuple/mark/id")
        for key in ("use", "packets", "bytes"):
            if len(values.get(key, [])) > 2:
                raise HostAdapterError("conntrack output has ambiguous counters")
        mark = _conntrack_integer(values["mark"][0], "mark", 0xFFFFFFFF)
        tuples = []
        for index in range(2):
            address_src = _conntrack_address(values["src"][index], family)
            address_dst = _conntrack_address(values["dst"][index], family)
            if proto in ("tcp", "udp"):
                if any(len(values.get(key, [])) != 2 for key in ("sport", "dport")):
                    raise HostAdapterError("conntrack output lacks protocol ports")
                port_src = _conntrack_integer(values["sport"][index], "source port", 65535)
                port_dst = _conntrack_integer(values["dport"][index], "destination port", 65535)
                tuples.append((address_src, address_dst, port_src, port_dst))
            elif proto in ("icmp", "icmpv6"):
                if any(len(values.get(key, [])) != 2 for key in ("type", "code", "id")):
                    raise HostAdapterError("conntrack output lacks bidirectional ICMP identity")
                tuples.append((address_src, address_dst,
                               _conntrack_integer(values["type"][index], "ICMP type", 255),
                               _conntrack_integer(values["code"][index], "ICMP code", 255),
                               _conntrack_integer(values["id"][index], "ICMP identifier", 65535)))
            else:
                if any(key in values for key in ("sport", "dport", "type", "code", "id")):
                    raise HostAdapterError("IGMP output has unsupported tuple fields")
                tuples.append((address_src, address_dst))
        identity = (family, zone, proto, int(proto_number), tuples[0], tuples[1], mark, ident)
        rows[ident] = {"identity": identity, "timeout_s": timeout_s}
    return rows


def _ss_endpoint(value):
    if value in ("*:*", "*", ""):
        return None
    bracketed = False
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or value[end + 1:end + 2] != ":":
            return None
        host, port_text = value[1:end], value[end + 2:]
        bracketed = True
    else:
        if value.count(":") != 1:
            return None
        host, port_text = value.rsplit(":", 1)
    if host in ("*", "0.0.0.0", "::") or port_text == "*":
        return None
    if "%" in host:
        if bracketed or host.count("%") != 1:
            return None
        address_text, interface = host.split("%", 1)
        if interface in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
            return None
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            return None
        if address.version != 4:
            return None
    else:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return None
    try:
        port = int(port_text, 10)
    except ValueError:
        return None
    if not 0 < port <= 65535:
        return None
    return address.compressed, port


def parse_singbox_sockets(text: str, main_pid: int) -> set[tuple[str, str, int, str, int]]:
    """Return only concrete connected TCP/UDP sockets uniquely owned by MainPID."""
    if isinstance(main_pid, bool) or not isinstance(main_pid, int) or main_pid < 2:
        raise HostAdapterError("invalid sing-box PID for socket snapshot")
    sockets = set()
    owner_re = re.compile(r'users:\(\("([^"]+)",pid=([0-9]+),fd=([0-9]+)\)\)')
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 7 or fields[0] not in ("tcp", "udp"):
            continue
        if not fields[2].isdigit() or not fields[3].isdigit():
            continue
        local, peer = _ss_endpoint(fields[4]), _ss_endpoint(fields[5])
        if local is None or peer is None:
            continue
        owner = owner_re.fullmatch(fields[6])
        if not owner or owner.group(1) != "sing-box" or int(owner.group(2)) != main_pid:
            continue
        sockets.add((fields[0], local[0], local[1], peer[0], peer[1]))
    return sockets


def correlate_singbox_conntrack_ids(sockets, conntrack):
    """Correlate uniquely owned connected sockets with conntrack original tuples."""
    hits = {socket: [] for socket in sockets}
    for ident, entry in conntrack.items():
        family, _zone, proto, _proto_number, orig, _reply, _mark, _id = entry["identity"]
        # ss correlation is defined only for connected TCP/UDP sockets. Other
        # conntrack protocols have different tuple shapes (e.g. ICMP/IGMP).
        if proto not in ("tcp", "udp") or not isinstance(orig, tuple) or len(orig) != 4:
            continue
        socket = (proto, orig[0], orig[2], orig[1], orig[3])
        if socket in hits:
            hits[socket].append(ident)
    return {ids[0] for ids in hits.values() if len(ids) == 1}


def _set_elems(snapshot: dict, name: str) -> list:
    rows = [item["set"] for item in snapshot.get("nftables", [])
            if isinstance(item, dict) and isinstance(item.get("set"), dict)
            and (item["set"].get("family"), item["set"].get("table"), item["set"].get("name")) == ("inet", "dnscomplex", name)]
    if len(rows) != 1:
        raise HostAdapterError(f"missing or ambiguous nft set {name}")
    elements = rows[0].get("elem", [])
    if not isinstance(elements, list):
        raise HostAdapterError(f"malformed nft set elements for {name}")
    return elements


def _stable_element(value):
    if isinstance(value, dict) and "elem" in value and set(value).issubset({"elem", "expires", "timeout"}):
        return _stable_element(value["elem"])
    if isinstance(value, dict) and set(value) == {"prefix"}:
        p = value["prefix"]
        return (p.get("addr"), p.get("len"))
    if isinstance(value, (str, int)):
        return value
    raise HostAdapterError("unsupported nft set element")


def _protected_sets(snapshot):
    protected = {}
    for item in snapshot.get("nftables", []):
        entry = item.get("set") if isinstance(item, dict) else None
        if not isinstance(entry, dict):
            continue
        if entry.get("family") != "inet" or entry.get("table") != "dnscomplex":
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name or name in ALIAS_SETS:
            continue
        if name in protected:
            raise HostAdapterError(f"nft set state is malformed or duplicated: {name}")
        if set(entry) - {"family", "table", "name", "handle", "type", "flags", "policy",
                         "size", "auto-merge", "timeout", "gc-interval", "elem", "comment"}:
            raise HostAdapterError(f"unsupported nft set definition field: {name}")
        set_type = entry.get("type")
        if set_type is not None and (not isinstance(set_type, str) or not set_type):
            raise HostAdapterError(f"nft set definition is malformed: {name}")
        flags = entry.get("flags", [])
        if (not isinstance(flags, list) or any(not isinstance(flag, str) or not flag for flag in flags)
                or len(set(flags)) != len(flags)):
            raise HostAdapterError(f"nft set definition is malformed: {name}")
        durations = []
        for key in ("timeout", "gc-interval"):
            value = entry.get(key)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0):
                raise HostAdapterError(f"nft set definition is malformed: {name}")
            durations.append(value)
        policy = entry.get("policy")
        if policy is not None and (not isinstance(policy, str) or not policy):
            raise HostAdapterError(f"nft set definition is malformed: {name}")
        size = entry.get("size")
        if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size <= 0):
            raise HostAdapterError(f"nft set definition is malformed: {name}")
        auto_merge = entry.get("auto-merge")
        if auto_merge is not None and not isinstance(auto_merge, bool):
            raise HostAdapterError(f"nft set definition is malformed: {name}")
        handle = entry.get("handle")
        if handle is not None and (isinstance(handle, bool) or not isinstance(handle, int) or handle < 0):
            raise HostAdapterError(f"nft set definition is malformed: {name}")
        comment = entry.get("comment")
        if comment is not None and not isinstance(comment, str):
            raise HostAdapterError(f"nft set definition is malformed: {name}")
        raw_elements = entry.get("elem", [])
        if not isinstance(raw_elements, list):
            raise HostAdapterError(f"nft set state is malformed: {name}")
        elements = {}
        for raw in raw_elements:
            value, timeout_ms, expires_ms = _protected_element(raw)
            identity = hashlib.sha256(repr(value).encode("utf-8")).hexdigest()
            if identity in elements:
                raise HostAdapterError(f"nft set state contains duplicate members: {name}")
            elements[identity] = {"timeout_ms": timeout_ms, "expires_ms": expires_ms}
        protected[name] = {
            "definition": (set_type, tuple(sorted(flags)), *durations,
                           policy, size, auto_merge, handle, comment),
            "elements": elements,
        }
    if not protected:
        raise HostAdapterError("no existing dnscomplex nft sets were captured")
    return protected


def _duration_ms(value, *, allow_zero=False):
    if isinstance(value, bool) or not isinstance(value, int) or value < (0 if allow_zero else 1):
        raise HostAdapterError("malformed nft set element lifetime")
    return value


def _protected_element(value):
    """Normalize an nft element while retaining configured and remaining lifetime."""
    timeout_ms = expires_ms = None
    if isinstance(value, dict) and "elem" in value and set(value).issubset({"elem", "expires", "timeout"}):
        wrapped = value["elem"]
        if isinstance(wrapped, dict) and "val" in wrapped:
            if set(wrapped) != {"val", "timeout", "expires"}:
                raise HostAdapterError("malformed nft set value wrapper")
            timeout_ms = _duration_ms(wrapped["timeout"])
            expires_ms = _duration_ms(wrapped["expires"], allow_zero=True)
            value = wrapped["val"]
        else:
            if "timeout" in value:
                timeout_ms = _duration_ms(value["timeout"])
            if "expires" in value:
                expires_ms = _duration_ms(value["expires"], allow_zero=True)
            value = wrapped
    normalized = _stable_element(value)
    return normalized, timeout_ms, expires_ms


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class LanAliasHostAdapter:
    """Concrete, fixed-command adapter. Tests inject a fake subprocess runner."""
    EXECUTABLES = frozenset({"python3", "nft", "timeout", "swanctl", "systemctl",
                             "ip", "conntrack", "sing-box", "bash", "ss"})

    def __init__(self, *, apply=False, fs_root="/", runner: Callable | None = None,
                 require_root=True):
        self.apply_enabled = bool(apply)
        self.require_root = require_root
        self.root = Path(fs_root).resolve()
        self.runner = runner or self._run_process
        self.config = None
        self.initial_vips = None
        self.prepared_pid = None
        self.prepared_hash = None
        self.original_gates = None
        self.expected_bytes = {}
        self.post_prepare_config = None
        self.rollback_restart_count = 0
        self._observed_restarts = []

    @staticmethod
    def _run_process(argv, *, input_text=None, env=None):
        p = subprocess.run(list(argv), input=input_text, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, check=False, env=dict(env) if env else None)
        return Result(p.returncode, p.stdout, p.stderr)

    def _path(self, path):
        if path not in READ_PATHS:
            raise HostAdapterError(f"path not allowlisted: {path}")
        resolved = self.root
        for part in Path(path.lstrip("/")).parts:
            resolved /= part
            try:
                if stat.S_ISLNK(resolved.lstat().st_mode):
                    raise HostAdapterError(f"symlink in managed path: {path}")
            except FileNotFoundError:
                pass
        return resolved

    def _read(self, path):
        target = self._path(path)
        if not stat.S_ISREG(target.lstat().st_mode):
            raise HostAdapterError(f"managed target is not a regular file: {path}")
        return target.read_bytes()

    def _run(self, argv, *, input_text=None, env=None, mutate=False, check=True):
        if not argv or argv[0] not in self.EXECUTABLES:
            raise HostAdapterError("executable outside fixed allowlist")
        if mutate and not self.apply_enabled:
            raise HostAdapterError("dry-run adapter refuses mutation")
        result = self.runner(tuple(argv), input_text=input_text, env=env)
        if check and result.returncode:
            raise HostAdapterError(f"{argv[0]} failed: {result.stderr.strip()}")
        return result

    def _cfg(self):
        if self.config is None:
            path = self._path("/etc/dnscomplex/config.env")
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or
                    (self.require_root and info.st_uid != 0)):
                raise HostAdapterError("config.env must be a root-owned regular mode-0600 file")
            self.config = parse_config_env(path.read_text(encoding="utf-8"))
        return self.config

    def profile_modes(self):
        cfg = self._cfg()
        if cfg.get("DEPLOY_MODE", "vlan-gateway") not in ("vlan-gateway", "routeros-policy"):
            raise HostAdapterError("invalid deployment mode")
        modes = {"ai": cfg.get("AI_EGRESS_MODE", "ipsec"), "cn": cfg.get("CN_EGRESS_MODE", "ipsec")}
        if any(value not in ("ipsec", "xray") for value in modes.values()):
            raise HostAdapterError("invalid egress mode")
        for key in ("WAN_IFACE", "LAN_VLAN_ID"):
            value = cfg.get(key, "")
            if value and not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", value):
                raise HostAdapterError(f"invalid interface value: {key}")
        mark_values = []
        for key in ("AI_MARK", "CN_MARK", "SINGBOX_AUTO_REDIRECT_OUTPUT_MARK"):
            value = cfg.get(key, {"AI_MARK": "0x301", "CN_MARK": "0x351",
                                  "SINGBOX_AUTO_REDIRECT_OUTPUT_MARK": "0x2024"}[key])
            if not re.fullmatch(r"(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})", value) or not 0 < int(value, 0 if value.lower().startswith("0x") else 10) <= 0xFFFFFFFF:
                raise HostAdapterError(f"invalid mark: {key}")
            mark_values.append(int(value, 0 if value.lower().startswith("0x") else 10))
        if len(set(mark_values)) != len(mark_values):
            raise HostAdapterError("AI, CN and auto-redirect marks must be distinct")
        for key in ("AI_QUIC_POLICY", "CN_QUIC_POLICY"):
            if cfg.get(key, "reject") not in ("reject", "allow"):
                raise HostAdapterError(f"invalid QUIC policy: {key}")
        if cfg.get("LAN_VLAN_ID") and not re.fullmatch(r"[0-9]{1,4}", cfg["LAN_VLAN_ID"]):
            raise HostAdapterError("invalid LAN VLAN id")
        if cfg.get("LINUX_LAN_IPV4"):
            try:
                if ipaddress.ip_address(cfg["LINUX_LAN_IPV4"]).version != 4:
                    raise ValueError
            except ValueError as exc:
                raise HostAdapterError("invalid LINUX_LAN_IPV4") from exc
        return modes

    def _sas(self):
        return self._run(("timeout", "--signal=TERM", "--kill-after=1s", "5s", "swanctl", "--list-sas")).stdout

    def current_profile_vips(self):
        if self.profile_modes() != {"ai": "ipsec", "cn": "ipsec"}:
            raise HostAdapterError("both profiles must be IPsec")
        current = parse_swanctl_vips(self._sas())
        if self.initial_vips is None:
            self.initial_vips = current
        return current

    def _pid(self):
        if self._run(("systemctl", "is-active", "--quiet", "sing-box"), check=False).returncode:
            raise HostAdapterError("sing-box inactive")
        value = self._run(("systemctl", "show", "-p", "MainPID", "--value", "sing-box")).stdout.strip()
        if not value.isdigit() or int(value) < 2:
            raise HostAdapterError("invalid sing-box MainPID")
        return int(value)

    def _nft(self):
        return json.loads(self._run(("nft", "-j", "-a", "list", "table", "inet", "dnscomplex")).stdout)

    def _elements(self, name):
        data = json.loads(self._run(("nft", "-j", "list", "set", "inet", "dnscomplex", name)).stdout)
        return _set_elems(data, name)

    def _gate(self, name, wildcard):
        values = [_stable_element(value) for value in self._elements(name)]
        return values == [(wildcard, 0)]

    def capture_protected_state(self):
        set_capture_started = time.monotonic()
        table = self._nft()
        set_capture_completed = time.monotonic()
        sets = _protected_sets(table)
        gates = {"ai4": self._gate("ai_ready4", "0.0.0.0"), "cn4": self._gate("cn_ready4", "0.0.0.0"),
                 "ai6": self._gate("ai_ready6", "::"), "cn6": self._gate("cn_ready6", "::")}
        self.original_gates = gates
        pid_before = self._pid()
        socket_text = self._run(("ss", "-H", "-tunap")).stdout
        ct_capture_started = time.monotonic()
        ct = stable_conntrack(self._run(("conntrack", "-L", "-o", "extended,id")).stdout)
        ct_capture_completed = time.monotonic()
        pid_after = self._pid()
        if pid_before != pid_after:
            raise HostAdapterError("sing-box PID changed while capturing protected state")
        singbox_owned_ids = correlate_singbox_conntrack_ids(
            parse_singbox_sockets(socket_text, pid_before), ct)
        sas = self._sas()
        return {"sets": sets,
                "sets_capture_interval": (set_capture_started, set_capture_completed),
                "gates": gates, "conntrack": ct,
                "conntrack_capture_interval": (ct_capture_started, ct_capture_completed),
                "singbox_pid": pid_before,
                "singbox_owned_conntrack_ids": singbox_owned_ids,
                "sa_state": self._stable_sa_state(sas)}

    @staticmethod
    def _stable_sa_state(text):
        state = {"ai": [], "cn": []}
        current = None
        for line in text.splitlines():
            if line and not line[0].isspace():
                current = None
                match = re.match(r"^(ai|cn):\s+#\d+,\s+(ESTABLISHED|CONNECTING|REKEYING|PASSIVE)(?:,|\s|$)", line)
                if match:
                    current = match[1]
                    state[current].append(match[2])
                continue
            if current and re.match(rf"^\s+{current}:\s+#\d+.*?,\s+INSTALLED(?:,|\s|$)", line):
                state[current].append("INSTALLED")
        return {profile: ("ESTABLISHED" in values, "INSTALLED" in values)
                for profile, values in state.items()}

    def verify_protected_state(self, snapshot):
        now = self.capture_protected_state()
        if now["gates"] != snapshot["gates"] or now["sa_state"] != snapshot["sa_state"]:
            raise HostAdapterError("profile readiness or IPsec SA readiness changed")
        elapsed_ms = max(0, int((now["sets_capture_interval"][0] -
                                 snapshot["sets_capture_interval"][1]) * 1000))
        for name, old in snapshot["sets"].items():
            current = now["sets"].get(name)
            if current is None or current["definition"] != old["definition"]:
                raise HostAdapterError(f"existing profile set definition changed: {name}")
            for identity, member in old["elements"].items():
                if identity in current["elements"]:
                    continue
                expires_ms = member["expires_ms"]
                if expires_ms is None or expires_ms > elapsed_ms:
                    raise HostAdapterError(f"existing profile set member changed: {name}")
        elapsed_s = max(0, int(now["conntrack_capture_interval"][0] -
                               snapshot["conntrack_capture_interval"][1]))
        singbox_restarted = any(old_pid == snapshot["singbox_pid"] and old_pid != new_pid
                                for old_pid, new_pid in self._observed_restarts)
        for ident, old in snapshot["conntrack"].items():
            current = now["conntrack"].get(ident)
            if current is None:
                naturally_expired = old["timeout_s"] <= elapsed_s
                owned_socket_closed = (ident in snapshot["singbox_owned_conntrack_ids"] and
                                       singbox_restarted)
                if naturally_expired or owned_socket_closed:
                    continue
                raise HostAdapterError(f"existing conntrack entry changed: {ident}")
            if current["identity"] != old["identity"]:
                raise HostAdapterError(f"existing conntrack entry changed: {ident}")

    def _record_restart(self, before_pid, after_pid):
        if before_pid != after_pid:
            self._observed_restarts.append((before_pid, after_pid))

    def read_live_nft_json(self):
        return self._nft()

    def read_persistent_nft(self):
        raw = self._read("/etc/nftables.d/dnscomplex.nft")
        self.persistent_snapshot = raw
        return raw.decode()

    def check_nft(self, transaction, persistent):
        self._run(("nft", "-c", "-f", "-"), input_text=transaction + "\n")

    def _atomic_write(self, target, data, mode, uid, gid):
        path = self._path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.dc-", dir=path.parent)
        temp = Path(name)
        try:
            os.fchmod(fd, mode)
            if os.geteuid() == 0:
                os.fchown(fd, uid, gid)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            if path.is_symlink():
                raise HostAdapterError(f"target became a symlink during write: {target}")
            os.replace(temp, path)
            dfd = os.open(path.parent, os.O_RDONLY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            temp.unlink(missing_ok=True)
            raise

    def publish_candidate_files(self, files):
        self._require_apply()
        allowed = {"/root/install.sh", "/usr/local/sbin/dnscomplex", "/usr/local/libexec/dnscomplex-lan-alias"}
        for item in files:
            if item["target"] not in allowed:
                raise HostAdapterError("candidate code file outside allowlist")
            target_path = self._path(item["target"])
            try:
                current = target_path.read_bytes()
                current_sha = hashlib.sha256(current).hexdigest()
            except FileNotFoundError:
                current_sha = None
            if current_sha != item["preimage_sha256"]:
                raise HostAdapterError(f"code target changed after preimage check: {item['target']}")
            data = item["_candidate_bytes"]
            self._atomic_write(item["target"], data, item["candidate_mode"], 0, 0)
            self.expected_bytes[item["target"]] = data

    def publish_persistent_nft(self, persistent):
        self._require_apply()
        path = self._path("/etc/nftables.d/dnscomplex.nft")
        if getattr(self, "persistent_snapshot", None) != path.read_bytes():
            raise HostAdapterError("persistent include changed since guarded read")
        info = path.stat()
        data = persistent.encode()
        self._atomic_write("/etc/nftables.d/dnscomplex.nft", data, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
        self.expected_bytes["/etc/nftables.d/dnscomplex.nft"] = data

    def apply_additive_nft(self, transaction, undo_manifest):
        self._run(("nft", "-f", "-"), input_text=transaction + "\n", mutate=True)
        self.undo_manifest = undo_manifest

    def _helper_argv(self, command, keep_closed=False):
        cfg = self._cfg(); mode = cfg.get("DEPLOY_MODE", "vlan-gateway")
        wan = cfg.get("WAN_IFACE", "eth0"); vlan = cfg.get("LAN_VLAN_ID", "")
        lan = wan if mode == "routeros-policy" else f"{wan}.{vlan}".rstrip(".")
        vip = self.initial_vips or {"ai": "", "cn": ""}
        default_kind = "snat" if mode == "routeros-policy" else "masquerade"
        argv = ["python3", "/usr/local/libexec/dnscomplex-lan-alias", command,
            "--state", "/var/lib/dnscomplex/lan-alias.json", "--config", "/etc/sing-box/config.json",
            "--ai-mode", cfg.get("AI_EGRESS_MODE", "ipsec"), "--cn-mode", cfg.get("CN_EGRESS_MODE", "ipsec"),
            "--ai-mark", cfg.get("AI_MARK", "0x301"), "--cn-mark", cfg.get("CN_MARK", "0x351"),
            "--auto-mark", cfg.get("SINGBOX_AUTO_REDIRECT_OUTPUT_MARK", "0x2024"),
            "--ai-quic", cfg.get("AI_QUIC_POLICY", "reject"), "--cn-quic", cfg.get("CN_QUIC_POLICY", "reject"),
            "--default-snat-interface", wan, "--default-snat-kind", default_kind,
            "--default-snat-address", cfg.get("LINUX_LAN_IPV4", "192.168.50.200"),
            "--lan-interface", lan, "--ai-vip", vip["ai"], "--cn-vip", vip["cn"]]
        if keep_closed: argv.append("--keep-closed")
        return tuple(argv)

    def _state(self):
        path = self._path("/var/lib/dnscomplex/lan-alias.json")
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or
                (self.require_root and info.st_uid != 0)):
            raise HostAdapterError("alias ownership state must be root-owned mode 0600")
        data = json.loads(path.read_bytes())
        expected = {"schema": 1, "status": "owned", "address": "198.18.255.254",
                    "interface": "lo", "label": "lo:dc-alias",
                    "outbound_tag": "lan-legacy-alias", "pool": "198.18.255.0/24"}
        if any(data.get(key) != value for key, value in expected.items()):
            raise HostAdapterError("alias owner state is not exact")
        return data

    def _loaded_proof(self):
        digest = hashlib.sha256(self._read("/etc/sing-box/config.json")).hexdigest()
        pid = self._pid(); state = self._state()
        if state.get("loaded_config_sha256") != digest or state.get("loaded_main_pid") != pid:
            raise HostAdapterError("state does not prove loaded config/PID")
        return digest, pid

    def _alias_closed(self):
        return not self._elements("lan_alias_ready4") and not self._elements("lan_alias_config_ready4")

    def _alias_open(self):
        expected = [{"prefix": {"addr": "0.0.0.0", "len": 0}}]
        return (self._elements("lan_alias_ready4") == expected and
                self._elements("lan_alias_config_ready4") == expected)

    def prepare_alias_once_closed(self, profile_vips):
        self._require_apply()
        if profile_vips != self.initial_vips: raise HostAdapterError("VIP changed before prepare")
        before = self._pid()
        self._run(self._helper_argv("reconcile", keep_closed=True), mutate=True)
        self._run(("sing-box", "check", "-c", "/etc/sing-box/config.json"))
        digest, pid = self._loaded_proof()
        self._record_restart(before, pid)
        if pid == before or not self._alias_closed(): raise HostAdapterError("prepare must restart once and keep both gates closed")
        self.prepared_pid, self.prepared_hash = pid, digest
        self.post_prepare_config = self._read("/etc/sing-box/config.json")
        return {"config_valid": True, "singbox_restart_count": 1,
                "loaded_config_proven": True, "readiness_closed": True}

    def _verify_manager_state(self, vips):
        self._run(("bash", "-c", VERIFY_MANAGER))
        self._verify_persistent_alias_snat(vips)
        return {"runtime_vips": vips, "persistent_vips": vips}

    def _verify_persistent_alias_snat(self, vips):
        persistent = self.read_persistent_nft()
        for profile in ("ai", "cn"):
            comment = f'dnscomplex-lan-alias-snat-{profile}'
            found = [line.split("#", 1)[0].strip() for line in persistent.splitlines()
                     if f'comment "{comment}"' in line]
            exact = f'oifname "ipsec-{profile}" ip saddr @lan_alias_source4 snat ip to {vips[profile]} comment "{comment}"'
            if len(found) != 1 or re.sub(r"\s+", " ", found[0]) != exact:
                raise HostAdapterError(f"persistent profile SNAT VIP mismatch: {profile}")

    def _sync_owned_persistent_alias_snat(self, vips):
        state_path = self._path("/var/lib/dnscomplex/lan-alias.json")
        if not state_path.exists():
            return False
        self._state()
        target = self._path("/etc/nftables.d/dnscomplex.nft")
        original = target.read_bytes()
        expected = self.expected_bytes.get("/etc/nftables.d/dnscomplex.nft")
        if expected is not None and original != expected:
            raise HostAdapterError("persistent include changed before owned VIP update")
        try:
            lines = original.decode("utf-8").splitlines(keepends=True)
        except UnicodeDecodeError as exc:
            raise HostAdapterError("persistent nft include is not UTF-8") from exc
        changed = False
        for profile in ("ai", "cn"):
            tag = f"dnscomplex-lan-alias-snat-{profile}"
            marker = f'comment "{tag}"'
            matches = [index for index, line in enumerate(lines) if marker in line]
            if len(matches) != 1:
                raise HostAdapterError(f"owned persistent alias SNAT rule missing/ambiguous: {profile}")
            index = matches[0]
            line = lines[index]
            ending = "\n" if line.endswith("\n") else ""
            body = line[:-1] if ending else line
            pattern = re.compile(
                rf'^(?P<pre>\s*oifname\s+"ipsec-{profile}"\s+ip\s+saddr\s+@lan_alias_source4\s+'
                rf'snat\s+ip\s+to\s+)(?P<vip>(?:[0-9]{{1,3}}\.){{3}}[0-9]{{1,3}})'
                rf'(?P<post>\s+comment\s+"{re.escape(tag)}")\s*$')
            match = pattern.fullmatch(body)
            if not match:
                raise HostAdapterError(f"owned alias SNAT rule shape changed: {profile}")
            rewritten = f"{match['pre']}{vips[profile]}{match['post']}{ending}"
            if rewritten != line:
                lines[index] = rewritten
                changed = True
        if changed:
            info = target.stat()
            data = "".join(lines).encode("utf-8")
            self._atomic_write("/etc/nftables.d/dnscomplex.nft", data,
                               stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
            self.expected_bytes["/etc/nftables.d/dnscomplex.nft"] = data
        self._verify_persistent_alias_snat(vips)
        return changed

    def sync_current_profile_state(self, profile_vips):
        self._require_apply()
        if self.current_profile_vips() != profile_vips or profile_vips != self.initial_vips:
            raise HostAdapterError("VIP changed during prepare; abort rather than restart again")
        if self._pid() != self.prepared_pid: raise HostAdapterError("sing-box restarted unexpectedly")
        return self._verify_manager_state(profile_vips)

    def verify_pre_activation(self, profile_vips):
        if self.current_profile_vips() != profile_vips or self._pid() != self.prepared_pid:
            raise HostAdapterError("VIP or sing-box changed before activation")
        if hashlib.sha256(self._read("/etc/sing-box/config.json")).hexdigest() != self.prepared_hash or not self._alias_closed():
            raise HostAdapterError("loaded config drift or readiness not closed")
        self._verify_manager_state(profile_vips)

    def activate_alias(self, profile_vips):
        self._require_apply()
        self._run(self._helper_argv("reconcile"), mutate=True)
        digest, pid = self._loaded_proof()
        if (digest, pid) != (self.prepared_hash, self.prepared_pid):
            raise HostAdapterError("activation was not loaded-config fastpath")
        if not self._alias_open() or self._elements("lan_alias_source4") != ["198.18.255.254"]:
            raise HostAdapterError("activation did not produce exact open alias state")
        return {"config_valid": True, "singbox_restart_count": 0,
                "loaded_config_fastpath": True, "readiness_open": True}

    def verify_active(self, vips):
        if self.current_profile_vips() != vips or self._alias_closed(): raise HostAdapterError("active state drift")
        self._loaded_proof()

    def close_alias_readiness(self):
        self._require_apply()
        failures = []
        helper_failure = None
        try:
            self._run(self._helper_argv("close"), mutate=True)
        except Exception as exc:
            helper_failure = exc
        # Attempt both exact gates even if the helper close path stopped early.
        for name in ("lan_alias_ready4", "lan_alias_config_ready4"):
            try:
                self._run(("nft", "flush", "set", "inet", "dnscomplex", name), mutate=True)
            except Exception as exc:
                failures.append(f"{name} close: {exc}")
        try:
            self.verify_alias_closed()
        except Exception as exc:
            failures.append(str(exc))
        if failures:
            if helper_failure:
                failures.insert(0, f"helper close: {helper_failure}")
            raise HostAdapterError("; ".join(failures))

    def verify_alias_closed(self):
        if not self._alias_closed(): raise HostAdapterError("alias readiness remains open")

    def verify_alias_absent(self):
        """Prove a completed owned undo left no alias resources behind."""
        table = self._nft()
        if not isinstance(table, dict) or not isinstance(table.get("nftables"), list):
            raise HostAdapterError("malformed nft table readback")
        for item in table["nftables"]:
            if not isinstance(item, dict):
                raise HostAdapterError("malformed nft table object")
            entry = item.get("set")
            if isinstance(entry, dict) and entry.get("family") == "inet" and \
                    entry.get("table") == "dnscomplex" and entry.get("name") in ALIAS_SETS:
                raise HostAdapterError(f"alias set remains after undo: {entry['name']}")
            rule = item.get("rule")
            if isinstance(rule, dict) and rule.get("family") == "inet" and \
                    rule.get("table") == "dnscomplex" and \
                    isinstance(rule.get("comment"), str) and \
                    rule["comment"].startswith("dnscomplex-lan-alias-"):
                raise HostAdapterError("alias-owned nft rule remains after undo")

        try:
            addresses = json.loads(self._run(("ip", "-j", "address", "show")).stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise HostAdapterError("malformed loopback address readback") from exc
        if not isinstance(addresses, list):
            raise HostAdapterError("malformed loopback address readback")
        for interface in addresses:
            if not isinstance(interface, dict) or not isinstance(interface.get("addr_info", []), list):
                raise HostAdapterError("malformed loopback address entry")
            for info in interface.get("addr_info", []):
                if not isinstance(info, dict):
                    raise HostAdapterError("malformed loopback address entry")
                if info.get("label") == "lo:dc-alias" or info.get("local") == "198.18.255.254":
                    raise HostAdapterError("owned alias address remains after undo")

        state_path = self._path("/var/lib/dnscomplex/lan-alias.json")
        try:
            state_path.lstat()
        except FileNotFoundError:
            return
        raise HostAdapterError("alias ownership state remains after undo")

    def remove_owned_alias_address(self, address):
        self._require_apply()
        if address != "198.18.255.254": raise HostAdapterError("unexpected owned address")
        self._state()
        addresses = json.loads(self._run(("ip", "-j", "address", "show", "dev", "lo")).stdout)
        owned = []
        for interface in addresses:
            for info in interface.get("addr_info", []):
                if info.get("local") == address and info.get("prefixlen") == 32:
                    owned.append((interface.get("ifname"), info.get("label")))
        if owned != [("lo", "lo:dc-alias")]:
            raise HostAdapterError("alias address ownership does not prove the exact lo label")
        self._run(("ip", "address", "del", "198.18.255.254/32", "dev", "lo", "label", "lo:dc-alias"), mutate=True)

    def remove_exact_owned_source_element(self, address):
        self._require_apply()
        if address != "198.18.255.254": raise HostAdapterError("unexpected source element")
        elems = self._elements("lan_alias_source4")
        if elems == [address]: self._run(("nft", "delete", "element", "inet", "dnscomplex", "lan_alias_source4", "{", address, "}"), mutate=True)
        elif elems: raise HostAdapterError("source set has foreign elements")

    def snapshot_owned_nft(self):
        chains = {name: self._run(("nft", "-a", "list", "chain", "inet", "dnscomplex", name)).stdout
                  for name in ("output", "prerouting", "prerouting_policy_restore", "postrouting")}
        sets = {name: {"name": name, "exists": True,
                       "elem": [_stable_element(v) for v in self._elements(name)]} for name in ALIAS_SETS}
        return chains, sets

    def check_owned_nft_undo(self, commands):
        if any(not re.fullmatch(r"delete (?:rule inet dnscomplex (?:output|prerouting|prerouting_policy_restore|postrouting) handle [0-9]+|set inet dnscomplex (?:lan_alias_source4|lan_alias_ready4|lan_alias_config_ready4))", c) for c in commands):
            raise HostAdapterError("undo outside exact owned nft target allowlist")
        self._run(("nft", "-c", "-f", "-"), input_text="\n".join(commands) + "\n")

    def apply_owned_nft_undo(self, commands):
        self._require_apply(); self._run(("nft", "-f", "-"), input_text="\n".join(commands) + "\n", mutate=True)

    def restore_preimages(self, backup):
        self._require_apply()
        backup_dir = Path(backup["backup_dir"])
        manifest_path = backup_dir / "manifest.json"
        if manifest_path.is_symlink() or not stat.S_ISREG(manifest_path.lstat().st_mode): raise HostAdapterError("unsafe backup manifest")
        raw = manifest_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != backup["manifest_sha256"]: raise HostAdapterError("backup manifest digest mismatch")
        manifest = json.loads(raw)
        for record in manifest["files"]:
            target = record["target"]
            if target not in TARGETS: raise HostAdapterError("foreign restore target")
            path = self._path(target)
            expected = self.expected_bytes.get(target)
            if expected is not None and path.exists() and path.read_bytes() != expected:
                raise HostAdapterError(f"published target changed before rollback: {target}")
            if target == "/etc/sing-box/config.json" and self.post_prepare_config is not None and path.read_bytes() != self.post_prepare_config:
                raise HostAdapterError("sing-box config changed outside helper")
            if target == "/var/lib/dnscomplex/lan-alias.json" and path.exists():
                self._state()
            if record["preimage_exists"]:
                payload = record["backup_payload"]
                if not re.fullmatch(r"payload/[0-9]{4}", payload): raise HostAdapterError("invalid payload path")
                data = (backup_dir / payload).read_bytes()
                if hashlib.sha256(data).hexdigest() != record["preimage_sha256"]: raise HostAdapterError("backup payload digest mismatch")
                self._atomic_write(target, data, record["preimage_mode"], record["preimage_uid"], record["preimage_gid"])
            else:
                path.unlink(missing_ok=True)

    def sync_profile_snat_current_vips(self, profile_vips):
        self._require_apply()
        if not isinstance(self.original_gates, dict):
            raise HostAdapterError("original profile gate snapshot is missing")
        before = self._pid()
        env = {"DNSCOMPLEX_RESTORE_AI_OPEN": "1" if self.original_gates.get("ai4") else "0",
               "DNSCOMPLEX_RESTORE_CN_OPEN": "1" if self.original_gates.get("cn4") else "0"}
        try:
            self._run(("bash", "-c", RECOVER_MANAGER), env=env, mutate=True)
            self._run(("bash", "-c", VERIFY_RECOVERED_MANAGER))
        except Exception:
            try:
                self.close_unready_profile_gates()
            finally:
                raise
        after = self._pid(); self.rollback_restart_count = int(after != before)
        self._record_restart(before, after)
        if self.current_profile_vips() != profile_vips: self.close_unready_profile_gates(); raise HostAdapterError("VIP changed during rollback; gates left closed")
        self._sync_owned_persistent_alias_snat(profile_vips)
        if not self._profile_gates_match(self.original_gates): self.close_unready_profile_gates(); raise HostAdapterError("gate restoration readback failed")

    def _profile_gates_match(self, expected):
        return {"ai4": self._gate("ai_ready4", "0.0.0.0"), "cn4": self._gate("cn_ready4", "0.0.0.0"),
                "ai6": self._gate("ai_ready6", "::"), "cn6": self._gate("cn_ready6", "::")} == expected

    def _close_profile_gates(self):
        self._run(("bash", "-c", CLOSE_PROFILE_GATES), mutate=True)

    def close_unready_profile_gates(self): self._close_profile_gates()
    def verify_rollback(self, snapshot): self.verify_protected_state(snapshot)

    def _require_apply(self):
        if not self.apply_enabled: raise HostAdapterError("default dry-run adapter refuses mutation")
        if self.require_root and os.geteuid() != 0:
            raise HostAdapterError("explicit apply requires root")
