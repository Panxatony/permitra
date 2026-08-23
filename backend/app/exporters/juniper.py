"""Juniper SRX: export as set commands (CLI configuration).

Produces per rule:
  - address book entries in the zones involved
  - custom applications (tcp-443, udp-161, ...) for all services
  - one security policy from-zone/to-zone with match/then
"""
from ..models import Rule, RuleAction, RuleLogging
from .common import parse_address_entries, sanitize_name, service_ports, split_protocols


def _applications(rule: Rule) -> list[str]:
    apps = []
    for svc in rule.services or []:
        for proto in split_protocols(svc.get("protocol", "")):
            if proto == "icmp":
                apps.append("junos-icmp-all")
                continue
            ports = service_ports(svc.get("port", ""))
            if not ports:
                apps.append("any")
                continue
            for port in ports:
                apps.append(f"{proto}-{port}")
    return apps or ["any"]


# Junos names the second refusal `reject`: it answers with ICMP unreachable or a
# TCP RST instead of discarding silently.
JUNOS_ACTION = {
    RuleAction.permit: "permit",
    RuleAction.deny: "deny",
    RuleAction.reject: "reject",
}


def export_rule(rule: Rule) -> str:
    lines = [f"# {rule.rule_id}: {rule.justification or rule.description or rule.name}".rstrip()]
    if rule.change_id:
        lines.append(f"# Change: {rule.change_id}")

    src_zone = sanitize_name(rule.source_zone or "trust")
    dst_zone = sanitize_name(rule.destination_zone or "untrust")
    sources = parse_address_entries(rule.source, "net")
    destinations = parse_address_entries(rule.destination, "net")

    # Address book
    for zone, objects in ((src_zone, sources), (dst_zone, destinations)):
        for obj in objects:
            if obj.is_any or not obj.cidr:
                continue
            lines.append(
                f"set security zones security-zone {zone} address-book address {obj.name} {obj.cidr}"
            )

    # Custom applications (standard ports; junos-* applications stay untouched)
    apps = _applications(rule)
    for app in apps:
        if app in ("any",) or app.startswith("junos-"):
            continue
        proto, _, port = app.partition("-")
        lines.append(f"set applications application {app} protocol {proto}")
        lines.append(f"set applications application {app} destination-port {port}")

    # Policy
    policy = sanitize_name(rule.name or rule.rule_id)
    base = f"set security policies from-zone {src_zone} to-zone {dst_zone} policy {policy}"
    for obj in sources:
        lines.append(f"{base} match source-address {'any' if obj.is_any or not obj.cidr else obj.name}")
    for obj in destinations:
        lines.append(f"{base} match destination-address {'any' if obj.is_any or not obj.cidr else obj.name}")
    for app in apps:
        lines.append(f"{base} match application {app}")
    # The rule ID as a policy description, because it has to survive onto the
    # device. The "# SR00042" comment above is part of the export file and is
    # never applied - so without this line the drift comparison finds no link
    # between a Juniper policy and the security rule that justifies it. Check
    # Point and ACI already carry the ID in device-visible fields.
    lines.append(f'{base} description "{rule.rule_id}"')
    lines.append(f"{base} then {JUNOS_ACTION[rule.action]}")

    # Logging used to be this one hard-coded line on every rule, whatever the
    # policy said - so the export could not be wrong and could not be right
    # either. It follows the rule now (#37).
    #
    # session-close only for a permitted session: nothing closes a session that
    # was never established, so writing it on a deny reads like accounting that
    # will never arrive.
    level = rule.effective_log_level
    if level != RuleLogging.none:
        events = "session-init"
        if level == RuleLogging.detailed and rule.action == RuleAction.permit:
            events = "session-init session-close"
        lines.append(f"{base} then log {events}")
    return "\n".join(lines)


def export(rules: list[Rule]) -> str:
    header = [
        "## Permitra export – Juniper SRX (set commands)",
        f"## Rules: {', '.join(r.rule_id for r in rules)}",
        "",
    ]
    return "\n".join(header) + "\n\n".join(export_rule(r) for r in rules) + "\n"
