"""Compile a narrow additive nft delta for profile data-plane health probes."""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any


FROZEN_INSTALLER_SHA256 = "856be53885775e98076a0a6e2611e2de27028970d7cde3bb3b714def77a5896f"
TABLE = "dnscomplex"
PROFILES = {
    "ai": {"set": "ai_probe_vip4", "comment": "dnscomplex-ai-dataplane-probe",
           "device": "ipsec-ai", "resolver": "104.16.248.249", "probe_mark": 929,
           "profile_mark": 769},
    "cn": {"set": "cn_probe_vip4", "comment": "dnscomplex-cn-dataplane-probe",
           "device": "ipsec-cn", "resolver": "223.6.6.6", "probe_mark": 1009,
           "profile_mark": 849},
}
PROFILE_CLASSIFIER_RE = re.compile(r"^dnscomplex-(ai|cn)-classified-")


class DeltaError(ValueError):
    """The rendered candidate or live nft state is not safe to modify."""


def _block(text: str, pattern: str, label: str) -> tuple[int, int, str]:
    matches = list(re.finditer(pattern + r"\s*\{", text))
    if len(matches) != 1:
        raise DeltaError(f"expected exactly one {label} block")
    opening = text.find("{", matches[0].start())
    depth = 0
    quoted = False
    escaped = False
    for index in range(opening, len(text)):
        char = text[index]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return matches[0].start(), index + 1, text[opening + 1:index]
    raise DeltaError(f"unterminated {label} block")


def _comment(line: str) -> str:
    match = re.search(r'\bcomment\s+"([^"\n]+)"', line)
    return match.group(1) if match else ""


def _rule_lines(chain_body: str) -> list[str]:
    return [line.strip() for line in chain_body.splitlines() if line.strip() and
            not line.strip().startswith(("type ", "policy "))]


def _norm(line: str) -> str:
    return " ".join(line.split())


def _valid_profile_inputs(profile_modes: Any, profile_vips: Any) -> tuple[dict[str, str], dict[str, str]]:
    if not isinstance(profile_modes, dict) or set(profile_modes) != {"ai", "cn"}:
        raise DeltaError("profile modes must contain exactly ai and cn")
    if any(profile_modes[name] not in {"ipsec", "xray"} for name in ("ai", "cn")):
        raise DeltaError("health probe NFT delta supports only ipsec or xray profile modes")
    if not isinstance(profile_vips, dict) or set(profile_vips) != {"ai", "cn"}:
        raise DeltaError("profile VIPs must contain exactly ai and cn")
    vips: dict[str, str] = {}
    for profile in ("ai", "cn"):
        value = profile_vips[profile]
        if not isinstance(value, str):
            raise DeltaError(f"{profile} VIP must be an IPv4 string or empty")
        if not value:
            vips[profile] = ""
            continue
        try:
            address = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError as exc:
            raise DeltaError(f"{profile} VIP is not a canonical IPv4 address") from exc
        if str(address) != value or address.is_unspecified or address.is_loopback or \
                address.is_multicast or address.is_link_local or address.is_reserved:
            raise DeltaError(f"{profile} VIP is not a usable unicast IPv4 address")
        vips[profile] = value
    return dict(profile_modes), vips


def _nft_json(value: str | dict[str, Any]) -> dict[str, Any]:
    try:
        data = json.loads(value) if isinstance(value, str) else value
    except (TypeError, json.JSONDecodeError) as exc:
        raise DeltaError("live nft JSON is invalid") from exc
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        raise DeltaError("live nft JSON has no nftables array")
    return data


def _live_inventory(data: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    tables = [entry["table"] for entry in data["nftables"] if isinstance(entry, dict) and
              isinstance(entry.get("table"), dict) and entry["table"].get("family") == "inet" and
              entry["table"].get("name") == TABLE]
    if len(tables) != 1:
        raise DeltaError("live nft JSON must describe exactly one inet dnscomplex table")
    chains: dict[str, list[dict[str, Any]]] = {}
    output_chains = []
    sets: list[dict[str, Any]] = []
    rules_by_chain: dict[str, list[dict[str, Any]]] = {}
    for entry in data["nftables"]:
        if not isinstance(entry, dict):
            continue
        chain = entry.get("chain")
        if isinstance(chain, dict) and chain.get("family") == "inet" and chain.get("table") == TABLE:
            chains.setdefault(chain.get("name", ""), []).append(chain)
            if chain.get("name") == "output":
                output_chains.append(chain)
        live_set = entry.get("set")
        if isinstance(live_set, dict) and live_set.get("family") == "inet" and live_set.get("table") == TABLE:
            sets.append(live_set)
        rule = entry.get("rule")
        if isinstance(rule, dict) and rule.get("family") == "inet" and rule.get("table") == TABLE:
            rules_by_chain.setdefault(rule.get("chain", ""), []).append(rule)
    if any(len(defs) != 1 for defs in chains.values()) or len(output_chains) != 1:
        raise DeltaError("live dnscomplex chain definitions are ambiguous")
    output = output_chains[0]
    if output.get("type") != "route" or output.get("hook") != "output":
        raise DeltaError("live output chain is not the expected route/output hook")
    return output, sets, rules_by_chain


def _set_elements(live_set: dict[str, Any]) -> list[str]:
    elements = live_set.get("elem", [])
    if not isinstance(elements, list):
        raise DeltaError("live probe set has malformed elements")
    result = []
    for element in elements:
        if isinstance(element, str):
            result.append(element)
        elif isinstance(element, dict) and isinstance(element.get("prefix"), dict) and \
                element["prefix"].get("len") == 32 and isinstance(element["prefix"].get("addr"), str):
            result.append(element["prefix"]["addr"])
        else:
            raise DeltaError("live probe set contains an unsupported element")
    return result


def _contains(value: Any, predicate) -> bool:
    if predicate(value):
        return True
    if isinstance(value, dict):
        return any(_contains(child, predicate) for child in value.values())
    if isinstance(value, list):
        return any(_contains(child, predicate) for child in value)
    return False


def _walk(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _classifier_semantics(rule: dict[str, Any], profile: str) -> bool:
    expression = rule.get("expr")
    if not isinstance(expression, list):
        return False
    wanted_match = lambda node: isinstance(node, dict) and node.get("match", {}).get("op") == "==" and \
        node.get("match", {}).get("left", {}).get("meta", {}).get("key") == "nfproto" and \
        node.get("match", {}).get("right") in ("ipv6", "ip6")
    return _contains(expression, wanted_match) and _contains(expression, lambda node: isinstance(node, dict) and "drop" in node)


def _expected_rule_text(profile: str) -> str:
    config = PROFILES[profile]
    return (f'ip saddr @{config["set"]} oifname "{config["device"]}" '
            f'ip daddr {config["resolver"]} tcp dport 443 meta mark 0x{config["probe_mark"]:x} '
            f'counter meta mark set 0x{config["profile_mark"]:x} accept '
            f'comment "{config["comment"]}"')


def _candidate_layout(candidate_text: str, modes: dict[str, str]):
    _table_start, _table_end, table_body = _block(candidate_text, r"table\s+inet\s+dnscomplex", "candidate table")
    set_defs: dict[str, str] = {}
    for profile, config in PROFILES.items():
        _start, _end, body = _block(table_body, rf"set\s+{re.escape(config['set'])}", f"{profile} probe set")
        normalized = re.sub(r"\s+", " ", body).strip().replace(";", "")
        if normalized != "type ipv4_addr flags interval" or re.search(r"\belements\s*=", body):
            raise DeltaError(f"candidate {profile} probe set definition is not the reviewed empty interval set")
        set_defs[config["set"]] = "type ipv4_addr; flags interval;"
    _start, _end, output_body = _block(table_body, r"chain\s+output", "candidate output chain")
    lines = _rule_lines(output_body)
    comments = [_comment(line) for line in lines]
    for profile, config in PROFILES.items():
        positions = [index for index, value in enumerate(comments) if value == config["comment"]]
        if modes[profile] == "ipsec":
            if len(positions) != 1 or _norm(lines[positions[0]]) != _expected_rule_text(profile):
                raise DeltaError(f"candidate {profile} probe output rule differs from the reviewed exact rule")
        elif positions:
            raise DeltaError(f"candidate {profile} Xray mode unexpectedly has a probe output rule")
    if len([c for c in comments if c.startswith("dnscomplex-") and c.endswith("-dataplane-probe")]) != sum(
            modes[profile] == "ipsec" for profile in PROFILES):
        raise DeltaError("candidate contains duplicate or unexpected dataplane probe rules")
    classifier_positions = [(index, comment) for index, comment in enumerate(comments)
                            if PROFILE_CLASSIFIER_RE.match(comment)]
    active_profiles = [profile for profile in PROFILES if modes[profile] == "ipsec"]
    if active_profiles and not classifier_positions:
        raise DeltaError("candidate has no IPsec output classifier anchor")
    classifier_comments = [comment for _index, comment in classifier_positions]
    for profile in active_profiles:
        expected_classifier = f"dnscomplex-{profile}-classified-ipv6-drop"
        if classifier_comments.count(expected_classifier) != 1:
            raise DeltaError(f"candidate {profile} output classifier is missing or ambiguous")
    if classifier_positions:
        anchor_index, anchor_comment = classifier_positions[0]
        expected_rule_positions = [comments.index(PROFILES[p]["comment"]) for p in active_profiles]
        if any(position >= anchor_index for position in expected_rule_positions):
            raise DeltaError("candidate probe exceptions must precede the first output classifier")
    else:
        anchor_comment = ""
    return (set_defs, {p: _expected_rule_text(p) for p in active_profiles}, output_body,
            anchor_comment, classifier_comments)


def _merge_persistent(persistent_text: str, set_defs: dict[str, str], rule_texts: dict[str, str],
                      modes: dict[str, str], anchor_comment: str) -> str:
    table_start, table_end, table_body = _block(persistent_text, r"table\s+inet\s+dnscomplex", "persistent table")
    for profile, config in PROFILES.items():
        if re.search(rf"\bset\s+{re.escape(config['set'])}\b", table_body):
            raise DeltaError(f"persistent include already defines owned set {config['set']}")
        if config["comment"] in table_body:
            raise DeltaError(f"persistent include already contains owned rule {config['comment']}")
    # The output block parser reports offsets relative to the table body; find
    # the actual target line rather than relying on generated line numbers.
    output_start, _output_end, _output_body = _block(
        persistent_text[table_start:table_end], r"chain\s+output", "persistent output chain")
    output_abs_start = table_start + output_start
    brace = persistent_text.find("{", output_abs_start, table_end)
    line_start = persistent_text.find("\n", brace) + 1
    lines = persistent_text[line_start:table_end].splitlines(keepends=True)
    target_offset = None
    cursor = line_start
    for line in lines:
        if _comment(line.strip()) == anchor_comment and anchor_comment:
            target_offset = cursor
            break
        cursor += len(line)
    if rule_texts:
        if target_offset is None:
            raise DeltaError("persistent output classifier anchor is missing")
        persistent_comments = [_comment(line.strip()) for line in _output_body.splitlines()]
        for profile, mode in modes.items():
            if mode == "ipsec":
                required = f"dnscomplex-{profile}-classified-ipv6-drop"
                if persistent_comments.count(required) != 1:
                    raise DeltaError(f"persistent {profile} output classifier is missing or ambiguous")
    declarations = "".join(f"  set {name} {{ {definition} }}\n" for name, definition in set_defs.items())
    # Insert new declarations after the existing cn_ready4 set so unrelated sets
    # and generated nft comments retain their byte order.
    _, ready_end, _ = _block(table_body, r"set\s+cn_ready4", "cn_ready4 set")
    set_insert = persistent_text.find("{", table_start) + 1 + ready_end
    set_line_end = persistent_text.find("\n", set_insert, table_end)
    if set_line_end < 0:
        raise DeltaError("persistent cn_ready4 set has no terminating line")
    set_insert = set_line_end + 1
    rule_insert = "".join(f"    {text}\n" for text in rule_texts.values())
    # Offsets are applied in reverse order, preserving both insertion points.
    patches = [(set_insert, declarations)]
    if rule_texts:
        patches.append((target_offset, rule_insert))
    merged = persistent_text
    for offset, text in sorted(patches, reverse=True):
        merged = merged[:offset] + text + merged[offset:]
    return merged


def compile_delta(live_json: str | dict[str, Any], persistent_text: str, candidate_nft_text: str,
                  candidate_installer_sha256: str, profile_modes: dict[str, str],
                  profile_vips: dict[str, str]) -> dict[str, Any]:
    """Compile a source-pinned, additive delta for the two health probe rules."""
    if candidate_installer_sha256 != FROZEN_INSTALLER_SHA256:
        raise DeltaError("candidate installer SHA-256 is not the reviewed 856 source")
    modes, vips = _valid_profile_inputs(profile_modes, profile_vips)
    data = _nft_json(live_json)
    output_chain, live_sets, rules_by_chain = _live_inventory(data)
    set_defs, rule_texts, _candidate_output, anchor_comment, classifier_comments = \
        _candidate_layout(candidate_nft_text, modes)

    live_set_by_name = {entry.get("name"): entry for entry in live_sets}
    for config in PROFILES.values():
        if config["set"] in live_set_by_name:
            raise DeltaError(f"live nft already contains probe set {config['set']}")
    # Refuse any owned comment regardless of the chain where it appears.
    all_live_rules = [rule for chain_rules in rules_by_chain.values() for rule in chain_rules]
    comments = [rule.get("comment", "") for rule in all_live_rules]
    for config in PROFILES.values():
        if config["comment"] in comments:
            raise DeltaError(f"live nft already contains probe rule {config['comment']}")

    active_profiles = [profile for profile in PROFILES if modes[profile] == "ipsec"]
    expected_rules = [{"chain": "output", "comment": PROFILES[p]["comment"], "handle": None,
                        "expression": rule_texts[p]} for p in active_profiles]
    expected_sets = {PROFILES[p]["set"]: ([vips[p]] if modes[p] == "ipsec" and vips[p] else [])
                     for p in PROFILES}

    live_output = rules_by_chain.get("output", [])
    anchor = []
    if expected_rules:
        found_classifiers = []
        for profile in active_profiles:
            expected_comment = f"dnscomplex-{profile}-classified-ipv6-drop"
            matches = [rule for rule in live_output if rule.get("comment") == expected_comment]
            if len(matches) != 1 or not isinstance(matches[0].get("handle"), int) or \
                    not _classifier_semantics(matches[0], profile):
                raise DeltaError(f"live {profile} output classifier is missing, ambiguous, or malformed")
            found_classifiers.append(matches[0])
        actual_order = [rule.get("comment") for rule in live_output
                        if rule.get("comment") in {f"dnscomplex-{p}-classified-ipv6-drop" for p in active_profiles}]
        expected_order = [f"dnscomplex-{p}-classified-ipv6-drop" for p in active_profiles]
        if actual_order != expected_order:
            raise DeltaError("live profile classifier order differs from the candidate")
        anchor = [rule for rule in live_output if rule.get("comment") == anchor_comment]
        if len(anchor) != 1 or not isinstance(anchor[0].get("handle"), int):
            raise DeltaError("live first output classifier anchor is missing or ambiguous")
        if not _classifier_semantics(anchor[0], anchor_comment.split("-")[1]):
            raise DeltaError("live output classifier anchor has unexpected nft JSON semantics")

    rules = []
    transaction_lines = []
    for profile, config in PROFILES.items():
        transaction_lines.append(f"add set inet {TABLE} {config['set']} {{ type ipv4_addr; flags interval; }}")
        if expected_sets[config["set"]]:
            transaction_lines.append(
                f"add element inet {TABLE} {config['set']} {{ {expected_sets[config['set']][0]} }}")
    if expected_rules:
        handle = anchor[0]["handle"]
        for profile in active_profiles:
            config = PROFILES[profile]
            line = rule_texts[profile]
            transaction_lines.append(f"insert rule inet {TABLE} output position {handle} {line}")
            rules.append({"chain": "output", "comment": config["comment"], "handle": None,
                          "expression": line})

    merged = _merge_persistent(persistent_text, set_defs, rule_texts,
                               modes, anchor_comment if rule_texts else "")
    undo_sets = dict(expected_sets)
    undo_rules = [{"chain": "output", "comment": item["comment"], "handle": None,
                   "expression": item["expression"]} for item in reversed(rules)]
    return {
        "transaction": "\n".join(transaction_lines) + ("\n" if transaction_lines else ""),
        "persistent": merged,
        "expected_rules": expected_rules,
        "expected_sets": expected_sets,
        "undo": {"family": "inet", "table": TABLE, "rules": undo_rules,
                 "sets": undo_sets,
                 "delete_policy": "resolve exact unique owned rule handles; delete in reverse order; remove only listed exact set elements; delete only when each owned set is empty; never flush table or unrelated sets"},
    }


def verify_applied(live_json: str | dict[str, Any], expected_rules: list[dict[str, Any]],
                   expected_sets: dict[str, list[str]]) -> None:
    """Semantically verify probe rule/set readback from fresh nft -j output."""
    data = _nft_json(live_json)
    _output, live_sets, rules_by_chain = _live_inventory(data)
    set_map = {entry.get("name"): entry for entry in live_sets}
    for name, values in expected_sets.items():
        if sum(entry.get("name") == name for entry in live_sets) != 1:
            raise DeltaError(f"applied probe set {name} is missing or ambiguous")
        entry = set_map.get(name)
        if not isinstance(entry, dict) or entry.get("type") != "ipv4_addr":
            raise DeltaError(f"applied probe set {name} is missing or has the wrong type")
        flags = entry.get("flags")
        if not isinstance(flags, list) or flags != ["interval"]:
            raise DeltaError(f"applied probe set {name} has unexpected flags")
        actual = sorted(_set_elements(entry))
        if actual != sorted(values):
            raise DeltaError(f"applied probe set {name} does not match the expected VIP membership")
    all_rules = [rule for chain_rules in rules_by_chain.values() for rule in chain_rules]
    expected_comments = {item["comment"] for item in expected_rules}
    actual_probe_comments = {rule.get("comment") for rule in all_rules
                             if rule.get("comment") in {config["comment"] for config in PROFILES.values()}}
    if actual_probe_comments != expected_comments:
        raise DeltaError("applied probe rule comments differ from the selected profile modes")
    output_rules = rules_by_chain.get("output", [])
    classifier_positions = [index for index, rule in enumerate(output_rules)
                            if PROFILE_CLASSIFIER_RE.match(str(rule.get("comment", "")))]
    first_classifier = min(classifier_positions) if classifier_positions else None
    for expected in expected_rules:
        matches = [rule for rule in all_rules if rule.get("comment") == expected["comment"]]
        if len(matches) != 1:
            raise DeltaError(f"applied probe rule {expected['comment']} is missing or ambiguous")
        rule = matches[0]
        if rule.get("chain") != expected["chain"] or not isinstance(rule.get("handle"), int):
            raise DeltaError(f"applied probe rule {expected['comment']} is in the wrong chain")
        if not _probe_rule_semantics(rule, expected["comment"]):
            raise DeltaError(f"applied probe rule {expected['comment']} has unexpected nft JSON semantics")
        if first_classifier is None or output_rules.index(rule) >= first_classifier:
            raise DeltaError(f"applied probe rule {expected['comment']} is not before the first output classifier")


def build_undo(live_json: str | dict[str, Any], delta: dict[str, Any]) -> list[str]:
    """Resolve an exact, verified live manifest into a surgical nft undo batch."""
    data = _nft_json(live_json)
    _output, live_sets, rules_by_chain = _live_inventory(data)
    undo = delta.get("undo")
    if not isinstance(undo, dict) or undo.get("family") != "inet" or undo.get("table") != TABLE:
        raise DeltaError("undo manifest does not target the owned dnscomplex table")
    sets = undo.get("sets")
    rules = undo.get("rules")
    if not isinstance(sets, dict) or set(sets) != {item["set"] for item in PROFILES.values()} or \
            not isinstance(rules, list):
        raise DeltaError("undo manifest does not contain the exact owned probe assets")
    set_map = {entry.get("name"): entry for entry in live_sets}
    commands: list[str] = []
    all_rules = [rule for chain_rules in rules_by_chain.values() for rule in chain_rules]
    expected_comments = {item.get("comment") for item in rules}
    owned_comments = {item["comment"] for item in PROFILES.values()}
    actual_owned_comments = {rule.get("comment") for rule in all_rules
                             if rule.get("comment") in owned_comments}
    if actual_owned_comments != expected_comments:
        raise DeltaError("live owned probe comments do not match the exact undo manifest")
    handles = set()
    for expected in rules:
        comment = expected.get("comment")
        matches = [rule for rule in all_rules if rule.get("comment") == comment]
        if len(matches) != 1 or matches[0].get("chain") != "output" or \
                not isinstance(matches[0].get("handle"), int) or \
                not _probe_rule_semantics(matches[0], comment):
            raise DeltaError(f"cannot prove exact live owned rule {comment!r} for undo")
        handle = matches[0]["handle"]
        if handle in handles:
            raise DeltaError("owned probe rules resolve to duplicate nft handles")
        handles.add(handle)
        commands.append(f"delete rule inet {TABLE} output handle {handle}")
    for name in (PROFILES["cn"]["set"], PROFILES["ai"]["set"]):
        values = sets[name]
        entry = set_map.get(name)
        if not isinstance(values, list) or not isinstance(entry, dict) or \
                entry.get("type") != "ipv4_addr" or entry.get("flags") != ["interval"]:
            raise DeltaError(f"cannot prove owned probe set {name} for undo")
        if sum(item.get("name") == name for item in live_sets) != 1:
            raise DeltaError(f"owned probe set {name} is missing or ambiguous")
        actual = sorted(_set_elements(entry))
        expected_values = sorted(values)
        if actual != expected_values:
            raise DeltaError(f"owned probe set {name} has foreign or changed membership")
        if values:
            if len(values) != 1:
                raise DeltaError(f"owned probe set {name} has unexpected expected membership")
            commands.append(f"delete element inet {TABLE} {name} {{ {values[0]} }}")
        commands.append(f"delete set inet {TABLE} {name}")
    return commands


def _probe_rule_semantics(rule: dict[str, Any], comment: str) -> bool:
    profile = "ai" if comment == PROFILES["ai"]["comment"] else "cn" if comment == PROFILES["cn"]["comment"] else ""
    if not profile:
        return False
    config = PROFILES[profile]
    expression = rule.get("expr")
    if not isinstance(expression, list) or len(expression) != 8:
        return False

    expected_matches = [
        ({"payload": {"protocol": "ip", "field": "saddr"}},
         ("@" + config["set"], {"set": "@" + config["set"]})),
        ({"meta": {"key": "oifname"}}, (config["device"],)),
        ({"payload": {"protocol": "ip", "field": "daddr"}}, (config["resolver"],)),
        ({"payload": {"protocol": "tcp", "field": "dport"}}, (443,)),
        ({"meta": {"key": "mark"}}, (config["probe_mark"],)),
    ]
    for index, (left, rights) in enumerate(expected_matches):
        node = expression[index]
        if not isinstance(node, dict) or set(node) != {"match"}:
            return False
        match = node["match"]
        if not isinstance(match, dict) or set(match) != {"op", "left", "right"} or \
                match.get("op") not in ("==", "in") or match.get("left") != left or \
                match.get("right") not in rights:
            return False

    counter = expression[5]
    if not isinstance(counter, dict) or set(counter) != {"counter"}:
        return False
    counter_value = counter["counter"]
    if not isinstance(counter_value, dict) or set(counter_value) != {"packets", "bytes"} or \
            any(not isinstance(counter_value[key], int) or counter_value[key] < 0
                for key in ("packets", "bytes")):
        return False
    expected_mangle = {"mangle": {"key": {"meta": {"key": "mark"}},
                                  "value": config["profile_mark"]}}
    return expression[6] == expected_mangle and expression[7] == {"accept": None}
