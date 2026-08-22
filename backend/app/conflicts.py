"""Conflict detection: warns about rules with overlapping networks, protocols and ports."""
from .models import Rule
from .validation import parse_network, parse_ports


def _entry_networks(entries: list) -> list:
    """All networks of an address field; ip='any' => 0.0.0.0/0 and ::/0."""
    networks = []
    for entry in entries or []:
        ip = (entry.get("ip") or "").strip()
        if not ip:
            continue
        if ip.lower() == "any":
            networks.append(parse_network("0.0.0.0/0"))
            networks.append(parse_network("::/0"))
            continue
        net = parse_network(ip)
        if net:
            networks.append(net)
    return [n for n in networks if n]


def _networks_overlap(nets_a: list, nets_b: list) -> bool:
    for a in nets_a:
        for b in nets_b:
            if a.version == b.version and a.overlaps(b):
                return True
    return False


def _protocols_of(rule: Rule) -> set[str]:
    protos = set()
    for svc in rule.services or []:
        p = (svc.get("protocol") or "").upper()
        if p == "ANY":
            return {"TCP", "UDP", "ICMP"}
        protos.update(p.split("/"))
    return protos


def _ports_overlap(rule_a: Rule, rule_b: Rule) -> bool:
    for sa in rule_a.services or []:
        for sb in rule_b.services or []:
            pa = set((sa.get("protocol") or "").upper().split("/"))
            pb = set((sb.get("protocol") or "").upper().split("/"))
            if "ANY" not in pa and "ANY" not in pb and not (pa & pb):
                continue
            for lo_a, hi_a in parse_ports(sa.get("port") or ""):
                for lo_b, hi_b in parse_ports(sb.get("port") or ""):
                    if lo_a <= hi_b and lo_b <= hi_a:
                        return True
    return False


def find_conflicts(rule: Rule, others: list[Rule]) -> list[dict]:
    """Compares a rule against all others and returns warnings."""
    warnings = []
    src_a, dst_a = _entry_networks(rule.source), _entry_networks(rule.destination)
    protos_a = _protocols_of(rule)

    for other in others:
        if other.id == rule.id:
            continue
        if not (_protocols_of(other) & protos_a):
            continue
        if not _ports_overlap(rule, other):
            continue
        src_b, dst_b = _entry_networks(other.source), _entry_networks(other.destination)
        if not (_networks_overlap(src_a, src_b) and _networks_overlap(dst_a, dst_b)):
            continue

        def ips(entries):
            return sorted((e.get("ip") or "").strip() for e in entries or [])

        same = (
            ips(rule.source) == ips(other.source)
            and ips(rule.destination) == ips(other.destination)
            and rule.services == other.services
        )
        if rule.action != other.action:
            kind = "shadowing"
            detail = (
                f"Overlapping networks/ports with opposite action "
                f"({rule.action.value} vs. {other.action.value})"
            )
        elif same:
            kind, detail = "duplicate", "Identical source, destination and services"
        else:
            kind, detail = "overlap", "Overlapping source/destination networks with the same protocol and overlapping ports"
        warnings.append(
            {"rule_id": rule.rule_id, "other_rule_id": other.rule_id, "kind": kind, "detail": detail}
        )
    return warnings
