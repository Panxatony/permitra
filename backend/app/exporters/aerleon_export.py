"""Capirca/Aerleon integration: turns Permitra rules into Capirca policies and
generates native configurations for further platforms from them (Cisco, Palo Alto,
Juniper, iptables, ...).

Aerleon is the actively maintained fork of Google's Capirca (same policy language,
Apache-2.0). Permitra stays the source of truth: addresses/aliases become Capirca
network objects, services become service objects, rules become terms.
Zone-based targets (SRX, Palo Alto) group the rules per zone pair."""
from __future__ import annotations

import re

import yaml

# Target platforms: generator name -> (header template, description).
# {filter} is replaced by the filter name; zone-based targets use
# {from_zone}/{to_zone} and get one filter per zone pair.
TARGETS = {
    "cisco": ("{filter} extended", "Cisco IOS (extended ACL)"),
    "ciscoasa": ("{filter}", "Cisco ASA"),
    "juniper": ("{filter}", "Juniper (filter-based)"),
    "srx": ("from-zone {from_zone} to-zone {to_zone}", "Juniper SRX (zone-based)"),
    "paloalto": ("from-zone {from_zone} to-zone {to_zone}", "Palo Alto (Panorama XML)"),
    "iptables": ("FORWARD", "Linux iptables (FORWARD chain)"),
}
ZONE_BASED = {"srx", "paloalto"}
FILTER_NAME = "permitra"


def _token(text: str, prefix: str) -> str:
    """Turns an alias/IP into a valid Capirca object name (UPPERCASE, [A-Z0-9_])."""
    name = re.sub(r"[^A-Za-z0-9]+", "_", text.strip()).strip("_").upper()
    if not name or name[0].isdigit():
        name = f"{prefix}_{name}" if name else prefix
    return name


def _collect_definitions(rules):
    """Collects network and service objects from the rules.

    Returns (definitions_dict, addr_token_map, svc_token_map):
    addr_token_map: (ip, alias) -> token; svc_token_map: (protocol, port) -> token."""
    networks: dict[str, dict] = {}
    services: dict[str, list] = {}
    addr_tokens: dict[tuple, str] = {}
    svc_tokens: dict[tuple, str] = {}

    def add_address(entry):
        ip = (entry.get("ip") or "").strip()
        alias = (entry.get("alias") or "").strip()
        if not ip or ip.lower() == "any":
            return
        key = (ip, alias)
        if key in addr_tokens:
            return
        base = _token(alias, "NET") if alias else _token(ip, "NET")
        name = base
        n = 2
        # Same alias for a different IP -> make the name unique
        while name in networks and not any(v["address"] == _cidr(ip) for v in networks[name]["values"]):
            name = f"{base}_{n}"
            n += 1
        networks.setdefault(name, {"values": []})
        if not any(v["address"] == _cidr(ip) for v in networks[name]["values"]):
            networks[name]["values"].append(
                {"address": _cidr(ip), **({"comment": alias} if alias else {})}
            )
        addr_tokens[key] = name

    def add_service(svc):
        port = (svc.get("port") or "").strip()
        if not port:
            return
        for protocol in _protocols(svc.get("protocol")):
            if protocol in ("any", "ip"):
                continue
            key = (protocol, port)
            if key in svc_tokens:
                continue
            name = _token(f"{protocol}_{port}", "SVC")
            services[name] = [{"protocol": protocol, "port": port}]
            svc_tokens[key] = name

    for rule in rules:
        for entry in (rule.source or []) + (rule.destination or []):
            add_address(entry)
        for svc in rule.services or []:
            add_service(svc)

    return {"networks": networks, "services": services}, addr_tokens, svc_tokens


def _cidr(ip: str) -> str:
    return ip if "/" in ip else f"{ip}/32"


def _protocols(protocol: str) -> list[str]:
    """Normalises protocol specifications: "TCP/UDP" -> ["tcp", "udp"]."""
    return [p for p in (protocol or "").strip().lower().split("/") if p]


def _term_addresses(entries, addr_tokens):
    """Tokens of one side of a rule; None = any (omit the field)."""
    tokens = []
    for entry in entries or []:
        ip = (entry.get("ip") or "").strip()
        if not ip or ip.lower() == "any":
            return None
        tokens.append(addr_tokens[(ip, (entry.get("alias") or "").strip())])
    return sorted(set(tokens)) or None


def _rule_terms(rule, addr_tokens, svc_tokens):
    """One term per protocol group (exact mapping of tcp:443 + udp:53 etc.)."""
    src = _term_addresses(rule.source, addr_tokens)
    dst = _term_addresses(rule.destination, addr_tokens)
    action = "accept" if rule.action.value == "permit" else "deny"
    comment = " – ".join(x for x in (rule.name, rule.application) if x) or rule.rule_id

    by_protocol: dict[str, list[str]] = {}
    open_protocols: list[str] = []  # protocols without a port (e.g. icmp, tcp without a port)
    for svc in rule.services or []:
        port = (svc.get("port") or "").strip()
        for protocol in _protocols(svc.get("protocol")):
            if protocol in ("any", "ip"):
                continue
            if port:
                by_protocol.setdefault(protocol, []).append(svc_tokens[(protocol, port)])
            elif protocol not in open_protocols:
                open_protocols.append(protocol)

    groups = list(by_protocol.items())
    for p in open_protocols:
        if p not in by_protocol:
            groups.append((p, []))
    if not groups:
        groups = [(None, [])]  # service "any": term without a protocol

    terms = []
    for protocol, tokens in groups:
        term = {"name": rule.rule_id.lower() if len(groups) == 1 else f"{rule.rule_id.lower()}-{protocol}",
                "comment": comment, "action": action}
        if src:
            term["source-address"] = " ".join(src)
        if dst:
            term["destination-address"] = " ".join(dst)
        if protocol:
            term["protocol"] = protocol
        if tokens:
            term["destination-port"] = " ".join(sorted(set(tokens)))
        terms.append(term)
    return terms


def build_policy(rules, target: str):
    """Builds (policy_dict, definitions_dict) for Aerleon.Generate."""
    header_tpl, _ = TARGETS[target]
    definitions, addr_tokens, svc_tokens = _collect_definitions(rules)

    if target in ZONE_BASED:
        # One filter per zone pair (in order of first use)
        pairs: dict[tuple, list] = {}
        for rule in rules:
            key = (rule.source_zone or "any", rule.destination_zone or "any")
            pairs.setdefault(key, []).append(rule)
        filters = [
            {
                "header": {"targets": {target: header_tpl.format(
                    from_zone=frm, to_zone=to)},
                    "comment": f"Permitra: {frm} -> {to}"},
                "terms": [t for r in pair_rules for t in _rule_terms(r, addr_tokens, svc_tokens)],
            }
            for (frm, to), pair_rules in pairs.items()
        ]
    else:
        filters = [{
            "header": {"targets": {target: header_tpl.format(filter=FILTER_NAME)},
                       "comment": "Generated by Permitra"},
            "terms": [t for r in rules for t in _rule_terms(r, addr_tokens, svc_tokens)],
        }]

    return {"filename": FILTER_NAME, "filters": filters}, definitions


def export(rules, target: str) -> str:
    """Generates the native configuration for the target platform."""
    from aerleon.api import Generate
    from aerleon.lib.naming import Naming

    policy, definitions = build_policy(rules, target)
    naming = Naming()
    naming.ParseDefinitionsObject(definitions, FILTER_NAME)
    out = Generate([policy], naming)
    return "\n".join(out[key] for key in sorted(out))


def export_policy_yaml(rules, target: str = "cisco") -> str:
    """Exports definitions + policy as YAML for existing Capirca/Aerleon
    pipelines (with Permitra as the source of truth)."""
    policy, definitions = build_policy(rules, target)
    return (
        "# Permitra export for Capirca/Aerleon\n"
        "# Document 1: object definitions (networks/services)\n"
        "# Document 2: policy (filters/terms)\n"
        + yaml.safe_dump(definitions, sort_keys=True, allow_unicode=True)
        + "---\n"
        + yaml.safe_dump({"filters": policy["filters"]}, sort_keys=False, allow_unicode=True)
    )
