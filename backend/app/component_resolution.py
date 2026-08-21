"""Automatische Ermittlung der Umsetzungs-Komponenten einer Regel aus Quelle/Ziel.

Auflösung je Adress-Eintrag über die Tabelle address_component_map:
  1. exakter Treffer (normalisierte IP bzw. Netz, oder "any")
  2. spezifischstes gepflegtes Netz, das den Eintrag enthält (Containment)
Nicht auflösbare Einträge werden als "unknown" gemeldet – der Nutzer legt die
Zuordnung dann einmalig fest.

Regel-Komponenten = Vereinigung über alle Quell-/Ziel-Einträge, danach gefiltert:
  - Intra-Zonen-Regel (Quell-Zone == Ziel-Zone): nur ACI-Komponenten
  - zonenübergreifend: nur Firewall-Komponenten (Juniper/Check Point)
  (fällt auf die ungefilterte Menge zurück, wenn der Filter leer wäre)
"""
from sqlalchemy.orm import Session

from .models import AddressComponentMap, ComponentType, SecurityComponent
from .validation import parse_network


def normalize_ip(ip: str) -> str | None:
    """Normalisiert eine IP/ein Netz für Vergleich und Speicherung ("10.10.30.5" -> "10.10.30.5/32")."""
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
        if net == mapped_net or net.subnet_of(mapped_net):
            if mapped_net.prefixlen > best_prefix:
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
    """Liefert (ermittelte Komponenten, unbekannte Adress-Einträge) – im VRF-Kontext."""
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
