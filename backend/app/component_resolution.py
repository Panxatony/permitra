"""Automatic derivation of a rule's enforcing components from source/destination.

Resolution per address entry via the address_component_map table:
  1. exact match (normalized IP or network, or "any")
  2. most specific maintained network containing the entry (containment)
Entries that cannot be resolved are reported as "unknown" - the user then
defines the mapping once.

Rule components = union over all source/destination entries, then filtered:
  - intra-zone rule (source zone == destination zone): ACI components only
  - cross-zone: firewall components only (Juniper/Check Point)
  (falls back to the unfiltered set if the filter would yield nothing)
"""
from sqlalchemy.orm import Session

from .models import AddressComponentMap, ComponentType, SecurityComponent
from .validation import parse_network


def normalize_ip(ip: str) -> str | None:
    """Normalizes an IP/network for comparison and storage ("10.10.30.5" -> "10.10.30.5/32")."""
    ip = (ip or "").strip()
    if not ip:
        return None
    if ip.lower() == "any":
        return "any"
    net = parse_network(ip)
    return str(net) if net else None


def find_mapping(ip: str, mappings: list[AddressComponentMap]) -> AddressComponentMap | None:
    norm = normalize_ip(ip)
    if norm is None:
        return None
    if norm == "any":
        return next((m for m in mappings if m.ip == "any"), None)
    net = parse_network(norm)
    best, best_prefix = None, -1
    for mapping in mappings:
        if mapping.ip == "any":
            continue
        mapped_net = parse_network(mapping.ip)
        if not mapped_net or mapped_net.version != net.version:
            continue
        if (net == mapped_net or net.subnet_of(mapped_net)) and mapped_net.prefixlen > best_prefix:
            best, best_prefix = mapping, mapped_net.prefixlen
    return best


def resolve_rule_components(
    db: Session,
    source: list[dict],
    destination: list[dict],
    source_zone: str = "",
    destination_zone: str = "",
    vrf_id: int | None = None,
) -> tuple[list[SecurityComponent], list[dict]]:
    """Returns (resolved components, unknown address entries) - within the VRF context."""
    query = db.query(AddressComponentMap)
    if vrf_id is not None:
        query = query.filter(AddressComponentMap.vrf_id == vrf_id)
    mappings = query.all()
    component_ids: set[int] = set()
    unknown: list[dict] = []
    seen_unknown: set[str] = set()

    for entries in (source or []), (destination or []):
        for entry in entries:
            ip = (entry.get("ip") or "").strip()
            if not ip:
                continue
            mapping = find_mapping(ip, mappings)
            if mapping:
                component_ids.update(mapping.component_ids or [])
            else:
                key = normalize_ip(ip) or ip
                if key not in seen_unknown:
                    seen_unknown.add(key)
                    unknown.append({"ip": ip, "alias": (entry.get("alias") or "").strip()})

    components = (
        db.query(SecurityComponent).filter(SecurityComponent.id.in_(component_ids)).all()
        if component_ids
        else []
    )

    intra = bool(source_zone and destination_zone) and source_zone.upper() == destination_zone.upper()
    filtered = [
        c for c in components
        if (c.type == ComponentType.aci) == intra
    ]
    return sorted(filtered or components, key=lambda c: c.name), unknown
