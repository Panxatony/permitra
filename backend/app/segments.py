"""Segments: the relations inside a zone, and the matrix that governs them.

The zone matrix says whether two zones may talk at all; inside a zone,
everything was allowed. Micro-segmentation lives exactly there: within a
zone, only defined segments may reach each other, everything else is
denied. A segment is a group (groups.py) that belongs to a zone; the segment
matrix is the zone matrix one level down, with the same shape - directed
allow/block cells, a default for what is not maintained, and the same
two-approver batch workflow to change it.

Zones without segments keep today's behaviour: intra-zone traffic is
allowed and the matrix is not asked. The moment a zone has a segment, its
intra-zone rules are resolved to segments and checked.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from . import groups
from .messages import _
from .models import IN_FORCE, Rule, Segment, SegmentPolicy, Zone, ZonePolicyType, active_rules
from .validation import parse_network
from .zone_check import ZoneCheckResult, check_zone_pair, find_zone, zone_ref


def zone_segments(db: Session, zone: Zone) -> list[Segment]:
    return db.query(Segment).filter(Segment.zone_id == zone.id).order_by(Segment.name).all()


def segment_networks(db: Session, segment: Segment) -> list:
    """The segment's members as parsed networks (hosts are /32 or /128)."""
    nets = []
    for entry in groups.resolve_group(db, segment.group):
        net = parse_network(entry["ip"])
        if net is not None:
            nets.append(net)
    return nets


def _segment_for_ip(ip: str, table: list[tuple[Segment, list]]) -> Segment | None:
    net = parse_network((ip or "").strip())
    if net is None:
        return None
    best, best_prefix = None, -1
    for segment, nets in table:
        for candidate in nets:
            if candidate.version != net.version:
                continue
            if (net == candidate or net.subnet_of(candidate)) and candidate.prefixlen > best_prefix:
                best, best_prefix = segment, candidate.prefixlen
    return best


def resolve_segments(db: Session, zone: Zone, entries: list[dict]) -> tuple[Segment | None, set[str], list[str]]:
    """(the one segment of these entries or None, every segment hit, addresses in no segment)."""
    table = [(s, segment_networks(db, s)) for s in zone_segments(db, zone)]
    hits: dict[str, Segment] = {}
    unsegmented: list[str] = []
    for entry in entries or []:
        ip = (entry.get("ip") or "").strip()
        if not ip or ip.lower() == "any":
            unsegmented.append(ip or "?")
            continue
        segment = _segment_for_ip(ip, table)
        if segment is None:
            unsegmented.append(ip)
        else:
            hits[segment.name] = segment
    resolved = next(iter(hits.values())) if len(hits) == 1 else None
    return resolved, set(hits), unsegmented


def get_segment_policy(db: Session, a: Segment, b: Segment) -> SegmentPolicy | None:
    return (db.query(SegmentPolicy)
              .filter(SegmentPolicy.from_segment_id == a.id, SegmentPolicy.to_segment_id == b.id)
              .first())


def intra_default(zone: Zone) -> str:
    """What an unmaintained segment relation means: "permit" or "deny".

    A zone starts at permit when it gets its first segment - an explicit Block
    cell is honoured, everything else is allowed with a hint - so that adding
    a segment never silently invalidates the zone's rules. The switch to deny
    is a matrix request with two approvals, and the approvers see which rules
    it sends back into review. Deny is what micro-segmentation means and what
    the demo and the documentation recommend."""
    return zone.intra_zone_default or "permit"


def check_segment_pair(db: Session, zone: Zone, source: list[dict], destination: list[dict]) -> ZoneCheckResult:
    """The segment matrix's verdict on an intra-zone rule."""
    if not zone_segments(db, zone):
        return ZoneCheckResult(True, "intra", messages=[_("Intra-zone traffic (same zone)")])
    deny = intra_default(zone) == "deny"
    result = ZoneCheckResult(True, "intra")
    sides = {}
    for label, field, entries in ((_("Source"), "source", source), (_("Destination"), "destination", destination)):
        segment, hits, unsegmented = resolve_segments(db, zone, entries)
        if len(hits) > 1:
            result.allowed = False
            result.messages.append(_("{label} spans several segments ({segments}) – split the rule",
                                     label=label, segments=", ".join(sorted(hits))))
        if unsegmented:
            if deny:
                result.allowed = False
                result.messages.append(
                    _("{label}: address(es) in no segment of zone {zone}: {addresses} – assign them to a "
                      "segment, or allow unsegmented traffic for the zone",
                      label=label, zone=zone_ref(zone), addresses=", ".join(unsegmented)))
            else:
                result.messages.append(_("{label}: address(es) in no segment of zone {zone}: {addresses}",
                                         label=label, zone=zone_ref(zone), addresses=", ".join(unsegmented)))
        sides[field] = segment
    if not result.allowed:
        return result
    a, b = sides["source"], sides["destination"]
    if a is None or b is None:
        # Unsegmented traffic under a permit default: allowed, the hint is above.
        result.policy = "undefined"
        return result
    policy = get_segment_policy(db, a, b)
    if policy is None:
        result.policy = "undefined"
        if deny:
            result.allowed = False
            result.messages.append(
                _("Segment relation {from_segment} → {to_segment} in zone {zone} is not maintained – "
                  "least privilege (default-deny): set it to allow via a matrix request (two approvals)",
                  from_segment=a.name, to_segment=b.name, zone=zone_ref(zone)))
        else:
            result.messages.append(_("Segment relation {from_segment} → {to_segment} in zone {zone} is not maintained",
                                     from_segment=a.name, to_segment=b.name, zone=zone_ref(zone)))
        return result
    result.policy = policy.policy.value
    if policy.policy == ZonePolicyType.block_all:
        result.allowed = False
        result.messages.append(_("The segment matrix of zone {zone} forbids {from_segment} → {to_segment} (Block)",
                                 zone=zone_ref(zone), from_segment=a.name, to_segment=b.name))
    return result


def check_rule_pair(db: Session, source_zone: str, destination_zone: str, platforms: list[str] | None,
                    source: list[dict] | None = None, destination: list[dict] | None = None) -> ZoneCheckResult:
    """The zone matrix's verdict, and inside a zone the segment matrix's."""
    verdict = check_zone_pair(db, source_zone, destination_zone, platforms)
    if verdict.policy != "intra" or source is None or destination is None:
        return verdict
    zone = find_zone(db, source_zone)
    if zone is None:
        return verdict
    return check_segment_pair(db, zone, source, destination)


def affected_intra_rules(db: Session, zone: Zone, from_segment: Segment | None, to_segment: Segment | None,
                         *, only_unmaintained: bool = False, statuses=IN_FORCE) -> list[Rule]:
    """Rules of the zone whose segments match the pair - or, for a default
    turning to deny, every rule the deny would make inadmissible: one with an
    address in no segment, or whose relation has no cell."""
    ref = zone_ref(zone).upper()
    out = []
    for rule in active_rules(db).filter(Rule.status.in_(statuses)).all():
        if (rule.source_zone or "").upper() != ref or (rule.destination_zone or "").upper() != ref:
            continue
        a, _ha, _ua = resolve_segments(db, zone, rule.source or [])
        b, _hb, _ub = resolve_segments(db, zone, rule.destination or [])
        if only_unmaintained:
            if a is None or b is None or get_segment_policy(db, a, b) is None:
                out.append(rule)
            continue
        if a is not None and b is not None and from_segment and to_segment \
                and a.id == from_segment.id and b.id == to_segment.id:
            out.append(rule)
    return out


def rules_touching_segment(db: Session, zone: Zone, segment: Segment, statuses=IN_FORCE) -> list[Rule]:
    """In-force rules of the zone with an address inside the segment on
    either side - the ones a change of the segment's boundary would move."""
    ref = zone_ref(zone).upper()
    out = []
    for rule in active_rules(db).filter(Rule.status.in_(statuses)).all():
        if (rule.source_zone or "").upper() != ref or (rule.destination_zone or "").upper() != ref:
            continue
        _a, hits_a, _ua = resolve_segments(db, zone, rule.source or [])
        _b, hits_b, _ub = resolve_segments(db, zone, rule.destination or [])
        if segment.name in hits_a or segment.name in hits_b:
            out.append(rule)
    return out
