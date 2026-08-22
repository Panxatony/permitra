"""Prüfung von Regeln gegen die Zonen-Kommunikationsmatrix.

Semantik:
  - gleiche Zone (Intra-Zone)           -> erlaubt (Diagonale "-" der Matrix);
                                           hier wird typischerweise ACI eingesetzt
  - Matrix-Eintrag "allow_only"         -> erlaubt (Durchsetzung immer per Firewall)
  - Matrix-Eintrag "block_all"          -> Regel unzulässig
  - Zone oder Beziehung nicht gepflegt  -> erlaubt, aber mit Hinweis (Altdaten-Toleranz)

Zusätzlich ein Hinweis, wenn eine zonenübergreifende Regel ACI als Plattform nennt,
denn ACI wird nur innerhalb einer Zone verwendet.
"""
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from .models import Zone, ZoneNetwork, ZonePolicy, ZonePolicyType
from .validation import parse_network


def zone_for_ip(ip: str, networks: list[ZoneNetwork]) -> Zone | None:
    """Zone eines Adress-Eintrags: 'any' -> cidr='any'; sonst spezifischstes Netz."""
    ip = (ip or "").strip()
    if not ip:
        return None
    if ip.lower() == "any":
        return next((n.zone for n in networks if n.cidr == "any"), None)
    net = parse_network(ip)
    if net is None:
        return None
    best, best_prefix = None, -1
    for entry in networks:
        if entry.cidr == "any":
            continue
        candidate = parse_network(entry.cidr)
        if not candidate or candidate.version != net.version:
            continue
        if net == candidate or net.subnet_of(candidate):
            if candidate.prefixlen > best_prefix:
                best, best_prefix = entry.zone, candidate.prefixlen
    return best


def resolve_zone_for_entries(db: Session, entries: list[dict], vrf_id: int | None = None) -> tuple[str | None, list[str], set[str]]:
    """Ermittelt die Zone einer Adressliste.

    Liefert (Zonenname oder None, nicht zugeordnete IPs/Netze, alle getroffenen Zonen).
    Jedes Netzwerk MUSS einer Zone zugeordnet sein; eine Regelseite darf nur eine
    Zone umfassen."""
    query = db.query(ZoneNetwork)
    if vrf_id is not None:
        query = query.filter(ZoneNetwork.vrf_id == vrf_id)
    networks = query.all()
    zones_hit: set[str] = set()
    unassigned: list[str] = []
    for entry in entries or []:
        ip = (entry.get("ip") or "").strip()
        if not ip:
            continue
        zone = zone_for_ip(ip, networks)
        if zone is None:
            unassigned.append(ip)
        else:
            zones_hit.add(zone.name)
    resolved = zones_hit.copy().pop() if len(zones_hit) == 1 else None
    return resolved, unassigned, zones_hit


@dataclass
class ZoneCheckResult:
    allowed: bool
    policy: str | None = None       # allow_only / block_all / intra / undefined
    temporary: bool = False
    messages: list[str] = field(default_factory=list)


def find_zone(db: Session, name: str) -> Zone | None:
    name = (name or "").strip()
    if not name:
        return None
    for zone in db.query(Zone).all():
        if zone.name.upper() == name.upper():
            return zone
    return None


def get_policy(db: Session, from_zone: Zone, to_zone: Zone) -> ZonePolicy | None:
    return (
        db.query(ZonePolicy)
        .filter(ZonePolicy.from_zone_id == from_zone.id, ZonePolicy.to_zone_id == to_zone.id)
        .first()
    )


def _aci_cross_zone_hint(result: ZoneCheckResult, platforms: list[str] | None):
    if "aci" in (platforms or []):
        result.messages.append(
            "ACI wird nur innerhalb einer Zone eingesetzt – diese Regel ist zonenübergreifend, "
            "Plattform ACI prüfen"
        )


def check_zone_pair(db: Session, source_zone: str, destination_zone: str,
                    platforms: list[str] | None = None) -> ZoneCheckResult:
    src, dst = (source_zone or "").strip(), (destination_zone or "").strip()
    if not src or not dst:
        return ZoneCheckResult(True, "undefined", messages=["Quell- oder Ziel-Zone nicht angegeben"])
    if src.upper() == dst.upper():
        return ZoneCheckResult(True, "intra", messages=["Intra-Zonen-Verkehr (gleiche Zone)"])

    # Minimalprinzip (BSI): Verhalten für ungepflegte Beziehungen ist konfigurierbar
    from .settings import get_setting

    default_deny = get_setting(db, "zone_matrix_default") == "deny"

    zone_a, zone_b = find_zone(db, src), find_zone(db, dst)
    if not zone_a or not zone_b:
        missing = [n for n, z in ((src, zone_a), (dst, zone_b)) if not z]
        result = ZoneCheckResult(
            not default_deny, "undefined",
            messages=[f"Zone(n) nicht in der Zonenverwaltung gepflegt: {', '.join(missing)}"
                      + (" – default-deny: bitte Zone anlegen und Beziehung freigeben"
                         if default_deny else "")],
        )
        _aci_cross_zone_hint(result, platforms)
        return result

    policy = get_policy(db, zone_a, zone_b)
    if not policy:
        result = ZoneCheckResult(
            not default_deny, "undefined",
            messages=[f"Beziehung {zone_a.name} → {zone_b.name} ist in der Matrix nicht gepflegt"
                      + (" – Minimalprinzip (default-deny): bitte per Matrixantrag auf Allow "
                         "setzen (zwei Freigaben)" if default_deny else "")],
        )
        _aci_cross_zone_hint(result, platforms)
        return result

    result = ZoneCheckResult(
        allowed=policy.policy == ZonePolicyType.allow_only,
        policy=policy.policy.value,
        temporary=policy.temporary,
    )
    if policy.policy == ZonePolicyType.block_all:
        result.messages.append(
            f"Matrix verbietet Sicherheitsregeln von {zone_a.name} nach {zone_b.name} (Block)"
        )
        return result

    if policy.temporary:
        result.messages.append("Beziehung ist in der Matrix nur temporär erlaubt (Temp)")
    _aci_cross_zone_hint(result, platforms)
    return result
