#!/usr/bin/env python3
"""Compile a narrow LAN-alias nft delta without replacing live table state.

This module is deliberately pure: it parses supplied renderer/live/persistent
snapshots and returns an additive transaction plus a surgical persistent merge.
It never invokes nft or mutates files.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any


TABLE = "dnscomplex"
ALIAS_PREFIX = "dnscomplex-lan-alias-"
ALIAS_SETS = (
    "lan_alias_source4",
    "lan_alias_ready4",
    "lan_alias_config_ready4",
)
ALIAS_GUARD = (
    'ip saddr 198.18.255.254 ip daddr != @lan_alias_ready4 counter drop '
    'comment "dnscomplex-lan-alias-owned-source-guard"'
)


class DeltaError(ValueError):
    """Input cannot be proven safe for a strictly additive delta."""


@dataclass(frozen=True)
class Block:
    start: int
    end: int
    body_start: int
    body: str


def compile_delta(candidate_text: str, live_json: str | dict[str, Any],
                  persistent_text: str, *, ai_vip: str, cn_vip: str) -> dict[str, Any]:
    """Return an additive nft transaction, persistent merge and exact undo plan."""
    candidate_table = _named_block(candidate_text, r"table\s+inet\s+dnscomplex")
    persistent_table = _named_block(persistent_text, r"table\s+inet\s+dnscomplex")
    live = _load_live(live_json)
    _reject_existing_alias(persistent_text, persistent_table.body, live)
    _validate_table_identity(live)

    set_defs = _candidate_alias_sets(candidate_table.body)
    candidate_chains = {name: _named_block(candidate_table.body,
                                             rf"chain\s+{re.escape(name)}")
                        for name in ("output", "prerouting",
                                     "prerouting_policy_restore", "postrouting")}
    persistent_chains = {name: _named_block(persistent_table.body,
                                             rf"chain\s+{re.escape(name)}")
                         for name in candidate_chains}

    out_rules = _alias_rules(candidate_chains["output"].body, "output")
    if not any(_rule_comment(line) == "dnscomplex-lan-alias-owned-source-guard"
               for line in out_rules):
        out_rules.insert(0, ALIAS_GUARD)
    _validate_output_rules(out_rules)

    pre_rules = _alias_rules(candidate_chains["prerouting"].body, "prerouting")
    restore_rules = _alias_rules(candidate_chains["prerouting_policy_restore"].body,
                                  "prerouting_policy_restore")
    if len(pre_rules) != 1 or _rule_comment(pre_rules[0]) != \
            "dnscomplex-lan-alias-fresh-flow":
        raise DeltaError("candidate must contain exactly one alias fresh-flow prerouting rule")
    if len(restore_rules) != 1 or _rule_comment(restore_rules[0]) != \
            "dnscomplex-lan-alias-fresh-flow-restore":
        raise DeltaError("candidate must contain exactly one alias fresh-flow restore rule")

    default_snat = _alias_rules(candidate_chains["postrouting"].body,
                                "postrouting")
    default_snat = [r for r in default_snat
                    if _rule_comment(r) == "dnscomplex-lan-alias-snat-default"]
    if len(default_snat) != 1:
        raise DeltaError("candidate must contain exactly one default alias SNAT rule")
    ai_vip = _ipv4(ai_vip, "AI VIP")
    cn_vip = _ipv4(cn_vip, "CN VIP")
    profile_snat = [
        f'oifname "ipsec-ai" ip saddr @lan_alias_source4 snat ip to {ai_vip} '
        'comment "dnscomplex-lan-alias-snat-ai"',
        f'oifname "ipsec-cn" ip saddr @lan_alias_source4 snat ip to {cn_vip} '
        'comment "dnscomplex-lan-alias-snat-cn"',
    ]
    # The embedded verifier checks alias-owned postrouting comments in their
    # concrete nft listing order: default, then the selected AI/CN profiles.
    post_rules = default_snat + profile_snat

    live_rules = _live_rules(live)
    _validate_baseline_sets(live)
    _validate_profile_gate_pairs(persistent_chains, live_rules)
    anchors = {
        "prerouting": _comment_anchor(
            persistent_chains["prerouting"].body, live_rules, "prerouting",
            ("dnscomplex-ai-not-ready", "dnscomplex-cn-not-ready")),
        "prerouting_policy_restore": _comment_anchor(
            persistent_chains["prerouting_policy_restore"].body, live_rules,
            "prerouting_policy_restore", _restore_anchor_comments(
                persistent_chains["prerouting_policy_restore"].body)),
        "output": _output_anchor(persistent_chains["output"].body, live_rules,
                                 candidate_chains["output"].body),
        "postrouting": _postrouting_anchor(persistent_chains["postrouting"].body,
                                            live_rules),
    }

    set_insert, set_persist_patch = _set_insertions(persistent_table.body, set_defs)
    persistent_patches: list[tuple[int, str]] = [(set_insert, set_persist_patch)]
    persistent_patches.extend([
        _chain_patch(persistent_chains["prerouting"], pre_rules,
                     before_comment=anchors["prerouting"][0]),
        _chain_patch(persistent_chains["prerouting_policy_restore"], restore_rules,
                     before_comment=anchors["prerouting_policy_restore"][0]),
        _chain_patch(persistent_chains["output"], out_rules, before_private=True),
        _chain_patch(persistent_chains["postrouting"], post_rules,
                     before_comment=(anchors["postrouting"][0]
                                     if anchors["postrouting"][1] is not None else None)),
    ])
    persistent_body_start = persistent_text.find("{", persistent_table.start) + 1
    persistent_patches = [(persistent_body_start + offset, patch_text)
                          for offset, patch_text in persistent_patches]
    # Patches are calculated against original offsets. Applying in reverse keeps
    # all original, non-alias bytes intact and makes the merge reversible.
    merged = persistent_text
    for offset, patch_text in sorted(persistent_patches, key=lambda p: p[0], reverse=True):
        merged = merged[:offset] + patch_text + merged[offset:]
    insertions = [patch_text for _, patch_text in persistent_patches]

    commands = [*_set_commands(set_defs)]
    for chain, rules in (("prerouting", pre_rules),
                         ("prerouting_policy_restore", restore_rules),
                         ("output", out_rules),
                         ("postrouting", post_rules)):
        anchor = anchors[chain][1]
        for rule in rules:
            if anchor is None:
                commands.append(f"add rule inet {TABLE} {chain} {rule}")
            else:
                commands.append(
                    f"insert rule inet {TABLE} {chain} position {anchor} {rule}"
                )

    manifest_rules = []
    for chain, rules in (("prerouting", pre_rules),
                         ("prerouting_policy_restore", restore_rules),
                         ("output", out_rules),
                         ("postrouting", post_rules)):
        for rule in rules:
            manifest_rules.append({
                "family": "inet", "table": TABLE, "chain": chain,
                "comment": _rule_comment(rule), "rule": rule,
            })
    return {
        "transaction": "\n".join(commands) + "\n",
        "persistent": merged,
        "persistent_insertions": insertions,
        "undo": {
            "family": "inet", "table": TABLE,
            "sets": [{"name": name,
                      "delete_only_if_empty_after_owned_elements_removed": True}
                     for name in reversed(ALIAS_SETS)],
            "rules": manifest_rules,
            "delete_policy": "resolve exactly one live rule by chain, comment, and normalized expression; delete handles in reverse insertion order, then delete only empty owned sets",
            "never": ["flush table", "flush ruleset", "delete dynamic AI/CN elements", "delete conntrack"],
        },
        "anchors": {name: {"comment": value[0], "handle": value[1]}
                    for name, value in anchors.items()},
    }


def _load_live(value: str | dict[str, Any]) -> dict[str, Any]:
    try:
        data = json.loads(value) if isinstance(value, str) else value
    except (TypeError, json.JSONDecodeError) as exc:
        raise DeltaError("live nft JSON is invalid") from exc
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        raise DeltaError("live nft JSON has no nftables array")
    return data


def _named_block(text: str, prefix: str) -> Block:
    matches = list(re.finditer(prefix + r"\s*\{", text))
    if len(matches) != 1:
        raise DeltaError(f"expected exactly one block matching {prefix!r}")
    opening = text.find("{", matches[0].start())
    end = _matching_brace(text, opening)
    return Block(matches[0].start(), end + 1, opening + 1, text[opening + 1:end])


def _matching_brace(text: str, opening: int) -> int:
    depth = 0
    quote = False
    escaped = False
    for idx in range(opening, len(text)):
        char = text[idx]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
            continue
        if char == '"':
            quote = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx
    raise DeltaError("unterminated nft block")


def _candidate_alias_sets(table_body: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for name in ALIAS_SETS:
        block = _named_block(table_body, rf"set\s+{re.escape(name)}")
        if re.search(r"\belements\s*=", block.body):
            raise DeltaError(f"candidate alias set {name} must start empty")
        if not re.search(r"\btype\s+ipv4_addr\b", block.body) or \
                not re.search(r"\bflags\s+interval\b", block.body):
            raise DeltaError(f"candidate alias set {name} has unexpected type/flags")
        found[name] = "type ipv4_addr; flags interval;"
    return found


def _reject_existing_alias(persistent: str, table_body: str,
                           live: dict[str, Any]) -> None:
    if ALIAS_PREFIX in persistent:
        raise DeltaError("persistent file already contains alias-owned content")
    if any(re.search(rf"\b{re.escape(name)}\b", table_body) for name in ALIAS_SETS):
        raise DeltaError("persistent table already defines an alias set")
    for obj in live["nftables"]:
        if not isinstance(obj, dict):
            continue
        entry = obj.get("set")
        if isinstance(entry, dict) and entry.get("family") == "inet" and \
                entry.get("table") == TABLE and entry.get("name") in ALIAS_SETS:
            raise DeltaError("live table already contains an alias-owned set")
        rule = obj.get("rule")
        if isinstance(rule, dict) and rule.get("family") == "inet" and \
                rule.get("table") == TABLE and str(rule.get("comment", "")).startswith(ALIAS_PREFIX):
            raise DeltaError("live table already contains an alias-owned rule")


def _validate_table_identity(live: dict[str, Any]) -> None:
    tables = [obj["table"] for obj in live["nftables"]
              if isinstance(obj, dict) and isinstance(obj.get("table"), dict)
              and obj["table"].get("family") == "inet"
              and obj["table"].get("name") == TABLE]
    if len(tables) != 1:
        raise DeltaError("live JSON must describe exactly one inet dnscomplex table")
    chains = {obj["chain"].get("name") for obj in live["nftables"]
              if isinstance(obj, dict) and isinstance(obj.get("chain"), dict)
              and obj["chain"].get("family") == "inet"
              and obj["chain"].get("table") == TABLE}
    required = {"output", "prerouting", "prerouting_policy_restore", "postrouting"}
    if not required <= chains:
        raise DeltaError("live table lacks a required alias insertion chain")


def _validate_baseline_sets(live: dict[str, Any]) -> None:
    required = {"ai4", "cn4", "ai_ready4", "cn_ready4"}
    found: dict[str, list[dict[str, Any]]] = {name: [] for name in required}
    for obj in live["nftables"]:
        if not isinstance(obj, dict) or not isinstance(obj.get("set"), dict):
            continue
        entry = obj["set"]
        if entry.get("family") == "inet" and entry.get("table") == TABLE and \
                entry.get("name") in found:
            found[entry["name"]].append(entry)
    if any(len(found[name]) != 1 or found[name][0].get("type") != "ipv4_addr"
           for name in required):
        raise DeltaError("live table lacks a unique IPv4 domain/gate set")


def _validate_profile_gate_pairs(chains: dict[str, Block],
                                 live_rules: dict[str, list[dict[str, Any]]]) -> None:
    for chain in ("prerouting", "prerouting_policy_restore"):
        persistent_comments = [_rule_comment(line.strip())
                               for line in chains[chain].body.splitlines()]
        if chain == "prerouting":
            required = ("dnscomplex-ai-not-ready", "dnscomplex-cn-not-ready")
        else:
            required = tuple(
                next((comment for comment in persistent_comments
                      if comment.startswith(f"dnscomplex-{profile}-") and
                      (comment.endswith("-restore") or "-policy-restore" in comment or
                       "-quic-reject-restore" in comment or
                       "-xray-icmp-drop-restore" in comment)), "")
                for profile in ("ai", "cn")
            )
            for profile in ("ai", "cn"):
                if not required[0 if profile == "ai" else 1]:
                    raise DeltaError(f"persistent restore chain lacks the {profile} profile rule")
        positions = []
        for comment in required:
            p = [idx for idx, value in enumerate(persistent_comments) if value == comment]
            l = [idx for idx, rule in enumerate(live_rules[chain])
                 if rule.get("comment") == comment]
            if len(p) != 1 or len(l) != 1:
                raise DeltaError(f"{chain} profile rule {comment!r} is missing or ambiguous")
            positions.append((p[0], l[0]))
        if len(positions) > 1 and (positions[0][0] >= positions[1][0] or
                                   positions[0][1] >= positions[1][1]):
            raise DeltaError(f"{chain} AI/CN profile rules are in unexpected order")


def _live_rules(live: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    result = {name: [] for name in ("output", "prerouting",
                                    "prerouting_policy_restore", "postrouting")}
    for obj in live["nftables"]:
        if not isinstance(obj, dict) or not isinstance(obj.get("rule"), dict):
            continue
        rule = obj["rule"]
        if rule.get("family") == "inet" and rule.get("table") == TABLE and \
                rule.get("chain") in result:
            result[rule["chain"]].append(rule)
    return result


def _alias_rules(chain_body: str, chain: str) -> list[str]:
    result = []
    for line in chain_body.splitlines():
        stripped = line.strip()
        if _rule_comment(stripped).startswith(ALIAS_PREFIX):
            result.append(stripped)
    comments = [_rule_comment(line) for line in result]
    if len(comments) != len(set(comments)):
        raise DeltaError(f"candidate has duplicate alias rule comments in {chain}")
    return result


def _rule_comment(rule: str) -> str:
    match = re.search(r'\bcomment\s+"([^"\n]+)"', rule)
    return match.group(1) if match else ""


def _validate_output_rules(rules: list[str]) -> None:
    comments = [_rule_comment(rule) for rule in rules]
    required = {
        "dnscomplex-lan-alias-owned-source-guard",
        "dnscomplex-lan-alias-not-ready",
        "dnscomplex-lan-alias-ai-not-ready",
        "dnscomplex-lan-alias-cn-not-ready",
        "dnscomplex-lan-alias-default-mark",
        "dnscomplex-lan-alias-default-output",
    }
    if len(comments) != len(set(comments)) or not required <= set(comments):
        raise DeltaError("candidate output rules lack unique required gate/terminal rules")
    guard = rules[comments.index("dnscomplex-lan-alias-owned-source-guard")]
    if guard != ALIAS_GUARD:
        raise DeltaError("owned-source guard differs from the reviewed literal .254 guard")
    indices = {comment: comments.index(comment) for comment in comments}
    if not (indices["dnscomplex-lan-alias-owned-source-guard"] <
            indices["dnscomplex-lan-alias-not-ready"] <
            indices["dnscomplex-lan-alias-default-mark"] <
            indices["dnscomplex-lan-alias-default-output"]):
        raise DeltaError("candidate output alias rules have unsafe guard/terminal order")
    for profile in ("ai", "cn"):
        reject = f"dnscomplex-lan-alias-quic-reject-{profile}"
        classify = f"dnscomplex-lan-alias-classified-{profile}"
        if reject in indices and classify in indices and indices[reject] > indices[classify]:
            raise DeltaError(f"candidate {profile} QUIC reject follows mark classification")


def _restore_anchor_comments(chain_body: str) -> tuple[str, ...]:
    candidates = []
    for line in chain_body.splitlines():
        comment = _rule_comment(line)
        if comment.startswith("dnscomplex-ai-") or comment.startswith("dnscomplex-cn-"):
            if comment.endswith("-restore") or "-policy-restore" in comment or \
                    "-quic-reject-restore" in comment or \
                    "-xray-icmp-drop-restore" in comment:
                candidates.append(comment)
    if not candidates:
        raise DeltaError("persistent restore chain has no profile restore gate anchor")
    return (candidates[0],)


def _comment_anchor(persistent_chain: str, live_rules: dict[str, list[dict[str, Any]]],
                    chain: str, acceptable: tuple[str, ...]) -> tuple[str, int]:
    text_rules = [line.strip() for line in persistent_chain.splitlines() if line.strip()]
    matches = [(idx, _rule_comment(line)) for idx, line in enumerate(text_rules)
               if _rule_comment(line) in acceptable]
    if len(matches) != 1:
        # For prerouting AI/CN gates, accept exactly the first profile rule; the
        # other gate must remain later and the anchor comment must be stable.
        if chain == "prerouting" and len(matches) >= 2:
            matches = [matches[0]]
        else:
            raise DeltaError(f"{chain} has missing or ambiguous persistent anchor")
    idx, comment = matches[0]
    if chain == "prerouting":
        dns_positions = [i for i, line in enumerate(text_rules)
                         if "dport { 784, 853, 8853 } drop" in line or
                         "known_doh4" in line]
        if dns_positions and max(dns_positions) >= idx:
            raise DeltaError("prerouting profile gate must follow private/DNS guards")
    found = [r for r in live_rules[chain] if r.get("comment") == comment]
    if len(found) != 1 or not isinstance(found[0].get("handle"), int):
        raise DeltaError(f"live {chain} anchor {comment!r} is missing or ambiguous")
    return comment, found[0]["handle"]


def _output_anchor(persistent_chain: str, live_rules: dict[str, list[dict[str, Any]]],
                   candidate_chain: str) -> tuple[str, int]:
    lines = [line.strip() for line in persistent_chain.splitlines() if line.strip()]
    private = [(idx, line) for idx, line in enumerate(lines)
               if re.search(r"\bip\s+daddr\s+\{[^}]+\}\s+accept\b", line)]
    if not private:
        raise DeltaError("output chain lacks its private-destination terminal anchor")
    idx, private_line = private[0]
    xray_lines = [i for i, line in enumerate(lines)
                  if "xray-underlay-" in _rule_comment(line)]
    if xray_lines and max(xray_lines) >= idx:
        raise DeltaError("Xray identity rules must precede the private output anchor")
    if not any("dport { 500, 4500 } accept" in line for line in lines[idx + 1:]):
        raise DeltaError("output private anchor must precede the IPsec UDP terminal")
    default_idx = next((i for i, line in enumerate(lines)
                        if _rule_comment(line) == "dnscomplex-domain-default-output"), None)
    if default_idx is None or default_idx <= idx:
        raise DeltaError("output private anchor must precede the default terminal")
    live = live_rules["output"]
    handle = _find_private_accept_handle(live)
    live_output = live_rules["output"]
    private_idx = next(i for i, rule in enumerate(live_output)
                       if rule.get("handle") == handle)
    persistent_xray = [_rule_comment(line) for line in lines
                       if "xray-underlay-" in _rule_comment(line)]
    candidate_xray = [_rule_comment(line.strip()) for line in candidate_chain.splitlines()
                      if "xray-underlay-" in _rule_comment(line.strip())]
    live_xray_positions = []
    for comment in persistent_xray:
        found = [i for i, rule in enumerate(live_output) if rule.get("comment") == comment]
        if len(found) != 1:
            raise DeltaError(f"live Xray output identity rule {comment!r} is missing or ambiguous")
        live_xray_positions.append(found[0])
    if (persistent_xray != candidate_xray or
            live_xray_positions != sorted(live_xray_positions) or
            any(i >= private_idx for i in live_xray_positions)):
        raise DeltaError("candidate, persistent and live Xray identity ordering differs")
    # Candidate Xray identity must also precede its alias fallback.
    candidate_alias = [i for i, line in enumerate(candidate_chain.splitlines())
                       if _rule_comment(line.strip()) == "dnscomplex-lan-alias-not-ready"]
    candidate_xray = [i for i, line in enumerate(candidate_chain.splitlines())
                      if "xray-underlay-" in _rule_comment(line.strip())]
    if not candidate_alias or (candidate_xray and max(candidate_xray) >= candidate_alias[0]):
        raise DeltaError("candidate output does not place alias policy after Xray identity")
    return "<private-destination-accept>", handle


def _find_private_accept_handle(rules: list[dict[str, Any]]) -> int:
    candidates = []
    for rule in rules:
        if _has_accept(rule.get("expr")) and _has_private_destination_match(rule.get("expr")):
            if isinstance(rule.get("handle"), int):
                candidates.append(rule["handle"])
    if len(candidates) != 1:
        raise DeltaError("live output private-destination accept anchor is missing or ambiguous")
    return candidates[0]


def _has_accept(value: Any) -> bool:
    if isinstance(value, dict):
        if "accept" in value:
            return True
        return any(_has_accept(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_accept(v) for v in value)
    return False


def _has_private_destination_match(value: Any) -> bool:
    if isinstance(value, dict):
        match = value.get("match")
        if isinstance(match, dict):
            left = match.get("left")
            if isinstance(left, dict):
                payload = left.get("payload")
                if isinstance(payload, dict) and payload.get("protocol") == "ip" and \
                        payload.get("field") == "daddr" and \
                        _contains_private_prefix(match.get("right")):
                    return True
        return any(_has_private_destination_match(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_private_destination_match(v) for v in value)
    return False


def _contains_private_prefix(value: Any) -> bool:
    private_networks = (ipaddress.ip_network("10.0.0.0/8"),
                        ipaddress.ip_network("172.16.0.0/12"),
                        ipaddress.ip_network("192.168.0.0/16"),
                        ipaddress.ip_network("127.0.0.0/8"),
                        ipaddress.ip_network("169.254.0.0/16"))
    if isinstance(value, dict):
        prefix = value.get("prefix")
        if isinstance(prefix, dict):
            try:
                network = ipaddress.ip_network(
                    f"{prefix['addr']}/{prefix['len']}", strict=False)
                return any(network.subnet_of(private) or private.subnet_of(network)
                           for private in private_networks)
            except (KeyError, ValueError):
                return False
        return any(_contains_private_prefix(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_private_prefix(v) for v in value)
    return False


def _postrouting_anchor(persistent_chain: str,
                        live_rules: dict[str, list[dict[str, Any]]]) -> tuple[str, int | None]:
    lines = [line.strip() for line in persistent_chain.splitlines() if line.strip()]
    ordinary = [line for line in lines
                if (" snat " in f" {line} " or " masquerade" in line)
                and not _rule_comment(line).startswith(ALIAS_PREFIX)]
    if not ordinary:
        return "<end-of-chain>", None
    comment = _rule_comment(ordinary[0])
    if not comment:
        raise DeltaError("ordinary default SNAT anchor must have a stable comment")
    found = [r for r in live_rules["postrouting"] if r.get("comment") == comment]
    if len(found) != 1 or not isinstance(found[0].get("handle"), int):
        raise DeltaError("live postrouting default SNAT anchor is missing or ambiguous")
    return comment, found[0]["handle"]


def _set_insertions(persistent_body: str, set_defs: dict[str, str]) -> tuple[int, str]:
    anchor = _named_block(persistent_body, r"set\s+cn_ready4")
    # Insert immediately after the complete anchor line, preserving all existing
    # whitespace and bytes outside the inserted declarations.
    line_end = persistent_body.find("\n", anchor.end)
    offset = len(persistent_body) if line_end < 0 else line_end + 1
    declarations = "".join(
        f"  set {name} {{ {set_defs[name]} }}\n" for name in ALIAS_SETS
    )
    return offset, declarations


def _chain_patch(block: Block, rules: list[str],
                 before_comment: str | None = None,
                 before_private: bool = False) -> tuple[int, str]:
    lines = block.body.splitlines(keepends=True)
    offset_cursor = block.body_start
    for line in lines:
        stripped = line.strip()
        target = (_rule_comment(stripped) == before_comment
                  if before_comment is not None else
                  bool(before_private and re.search(
                      r"\bip\s+daddr\s+\{[^}]+\}\s+accept\b", stripped)))
        if target:
            if stripped:
                indent = line[:len(line) - len(line.lstrip())]
                patch = "".join(f"{indent}{rule}\n" for rule in rules)
                return offset_cursor, patch
        offset_cursor += len(line)
    if before_comment is not None or before_private:
        raise DeltaError(f"persistent chain anchor {before_comment!r} disappeared")
    # Append at the end of the chain body, before its closing brace.
    end_offset = block.end - 1
    prefix = "" if end_offset == 0 or block.body.endswith("\n") else "\n"
    patch = prefix + "".join(f"    {rule}\n" for rule in rules)
    return block.end - 1, patch


def _set_commands(set_defs: dict[str, str]) -> list[str]:
    return [f"add set inet {TABLE} {name} {{ {set_defs[name]} }}" for name in ALIAS_SETS]


def _ipv4(value: str, label: str) -> str:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise DeltaError(f"{label} must be an IPv4 address") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise DeltaError(f"{label} must be a canonical IPv4 address")
    return value


if __name__ == "__main__":
    raise SystemExit("This module exposes compile_delta(); it does not read host state or execute nft.")
