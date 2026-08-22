"""Checks rules against the zone communication matrix.

Semantics:
  - same zone (intra-zone)              -> allowed (the "-" diagonal of the matrix);
                                           ACI is typically used here
  - matrix entry "allow_only"           -> allowed (always enforced by a firewall)
  - matrix entry "block_all"            -> rule not permitted
  - zone or relation not maintained     -> allowed, but with a warning (legacy data tolerance)

Additionally a warning is emitted when a cross-zone rule names ACI as its platform,
because ACI is only used within a single zone.
"""
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from .models import Zone, ZoneNetwork, ZonePolicy, ZonePolicyType
from .validation import parse_network


def zone_for_ip(ip: str, networks: list[ZoneNetwork]) -> Zone | None:
    """Zone of an address entry: 'any' -> cidr='any'; otherwise the most specific network."""
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
        if (net == candidate or net.subnet_of(candidate)) and candidate.prefixlen > best_prefix:
            best, best_prefix = entry.zone, candidate.prefixlen
    return best


def resolve_zone_for_entries(db: Session, entries: list[dict], vrf_id: int | None = None) -> tuple[str | None, list[str], set[str]]:
    """Determines the zone of an address list.

    Returns (zone name or None, unassigned IPs/networks, all matched zones).
    Every network MUST be assigned to a zone; one side of a rule may only span a
    single zone."""
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
            zones_hit.add(zone_ref(zone))  # authoritative: the zone ID
    resolved = zones_hit.copy().pop() if len(zones_hit) == 1 else None
    return resolved, unassigned, zones_hit


@dataclass
class ZoneCheckResult:
    allowed: bool
    policy: str | None = None       # allow_only / block_all / intra / undefined
    temporary: bool = False
    messages: list[str] = field(default_factory=list)


def zone_ref(zone: Zone) -> str:
    """Canonical reference value of a zone: the zone ID (code), otherwise the name.
    This value is stored on rules (it is authoritative for them)."""
    return (zone.code or zone.name) if zone else ""


def find_zone(db: Session, ref: str) -> Zone | None:
    """Resolves a zone by ID (code) OR name (case-insensitive). The ID takes
    precedence – it is the authoritative identifier."""
    ref = (ref or "").strip()
    if not ref:
        return None
    zones = db.query(Zone).all()
    for zone in zones:  # first by zone ID
        if (zone.code or "").upper() == ref.upper():
            return zone
    for zone in zones:  # then by name (legacy data, user input)
        if zone.name.upper() == ref.upper():
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
            "ACI is only used within a single zone – this rule crosses zones, "
            "check the ACI platform assignment"
        )


def check_zone_pair(db: Session, source_zone: str, destination_zone: str,
                    platforms: list[str] | None = None) -> ZoneCheckResult:
    src, dst = (source_zone or "").strip(), (destination_zone or "").strip()
    if not src or not dst:
        return ZoneCheckResult(True, "undefined", messages=["Source or destination zone not specified"])
    if src.upper() == dst.upper():
        return ZoneCheckResult(True, "intra", messages=["Intra-zone traffic (same zone)"])

    # Least privilege (BSI): behaviour for unmaintained relations is configurable
    from .settings import get_setting

    default_deny = get_setting(db, "zone_matrix_default") == "deny"

    zone_a, zone_b = find_zone(db, src), find_zone(db, dst)
    if not zone_a or not zone_b:
        missing = [n for n, z in ((src, zone_a), (dst, zone_b)) if not z]
        result = ZoneCheckResult(
            not default_deny, "undefined",
            messages=[f"Zone(s) not maintained in the zone administration: {', '.join(missing)}"
                      + (" – default-deny: create the zone and approve the relation"
                         if default_deny else "")],
        )
        _aci_cross_zone_hint(result, platforms)
        return result

    policy = get_policy(db, zone_a, zone_b)
    if not policy:
        result = ZoneCheckResult(
            not default_deny, "undefined",
            messages=[f"Relation {zone_a.name} → {zone_b.name} is not maintained in the matrix"
                      + (" – least privilege (default-deny): set it to allow via a matrix "
                         "request (two approvals)" if default_deny else "")],
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
            f"The matrix forbids security rules from {zone_a.name} to {zone_b.name} (Block)"
        )
        return result

    if policy.temporary:
        result.messages.append("The matrix allows this relation only temporarily (Temp)")
    _aci_cross_zone_hint(result, platforms)
    return result
