"""The one broad rule operations may have: ICMP echo between internal zones.

Every other rule in Permitra is narrow on purpose - a source, a destination, a
service. This one is deliberately not, and the reason is a working day rather
than an application. When a system does not answer, the first question is
whether the network reaches it at all. Nobody can answer that from a rule
catalogue, so the search starts at the firewall - which is precisely the place a
rule could have answered it already. A standing ping between two zones turns
"the network is broken" into "the path is open, the service is down", which is
the difference between a change request and a restart.

So a ping baseline is an any-to-any rule that carries ICMP echo and nothing
else, between two zones the matrix already permits. What it grants is a
reachability probe that any host on either side could run anyway the moment a
single rule between those zones exists; what it saves is the hour spent proving
that.

The exception is bounded, and the bounds are the point:

- **Internal zones only.** Below the P-A-P structure the zones already trust
  each other enough to carry an allow relation. Across the P-A-P boundary or
  towards an external zone, ICMP is reconnaissance: an attacker's first question
  is the same as the operator's, and out there we do not answer it.
- **On a relation the matrix already allows.** The baseline rides on a permitted
  relation, it never creates one. Whether two zones may talk stays a matrix
  decision with its two approvals; this only says how operations may look.
- **Echo only.** Not every ICMP type - no redirect, no timestamp, no address
  mask. Ping answers the question, the rest of ICMP is a different conversation
  and some of it is a routing change.
- **One direction.** The matrix cell is directional and so is this. The answer
  to an echo request comes back through the session the firewall already tracks;
  pinging the other way is a second question and needs its own allow cell.

Nothing else about such a rule is special. It is requested, approved, exported,
recertified and expired like any other. What the declaration buys is that the
risk assessment stops reading `any` as an accident, and that the zones become
the rule's scope - a rule whose addresses are `any` has nothing to derive a zone
from, so it has to say which two zones it means.
"""
from sqlalchemy.orm import Session

from .messages import _
from .models import ComponentType, RuleAction, SecurityComponent, Zone, ZonePolicyType
from .validation import is_ping_port
from .zone_check import find_zone, get_policy

# What the services of a ping baseline are normalised to. The port is not a
# port - ICMP has none - it is the marker the exporters read to emit echo-only
# applications instead of "all ICMP", which is the difference between what this
# rule says and what the device would otherwise do.
PING_SERVICE = {"protocol": "ICMP", "port": "ping"}


def _rows(value) -> list[dict]:
    """Address or service entries as plain dicts, from models or from JSON."""
    return [v.model_dump() if hasattr(v, "model_dump") else dict(v) for v in value or []]


def is_any_only(entries) -> bool:
    """Whether every address entry is 'any' - an empty list is not."""
    rows = _rows(entries)
    return bool(rows) and all((r.get("ip") or "").strip().lower() == "any" for r in rows)


def is_ping_service(service) -> bool:
    """ICMP (or ICMPv6) restricted to echo, or with no restriction stated yet.

    An empty port is accepted because the declaration is the statement: somebody
    who ticks "ping baseline" has said echo, and `normalise_services` writes it
    down. An explicit non-echo port is refused rather than overwritten - that is
    somebody asking for something else.
    """
    row = service if isinstance(service, dict) else service.model_dump()
    protocol = (row.get("protocol") or "").strip().upper()
    port = (row.get("port") or "").strip()
    return protocol.startswith("ICMP") and (not port or is_ping_port(port))


def is_ping_only(services) -> bool:
    rows = _rows(services)
    return bool(rows) and all(is_ping_service(r) for r in rows)


def normalise_services(services) -> list[dict]:
    """Echo, spelled the way every exporter reads it."""
    return [{**row, "protocol": (row.get("protocol") or "ICMP").strip().upper(), "port": "ping"}
            for row in _rows(services)] or [dict(PING_SERVICE)]


def components_for(db: Session, source: Zone, destination: Zone) -> list[SecurityComponent]:
    """The firewalls the echo has to be permitted on.

    An ordinary rule finds its components through the address mapping. A
    baseline has no addresses to map, so the zones answer instead: each is
    attached to the clusters it is reachable through. Between those attachment
    points the topology decides - the same routing the path analysis uses - so a
    cluster that merely sits in the middle lands on the rule without anybody
    listing it by hand. Where no topology is documented, the two zones' own
    clusters are the answer, which is all an undocumented estate can honestly
    say.
    """
    from . import routing

    src = {c.id for c in source.components if c.type != ComponentType.aci}
    dst = {c.id for c in destination.components if c.type != ComponentType.aci}
    if not src or not dst:
        return []
    on_path = {cid for route in routing.shortest_routes(routing.build_graph(db), src, dst)
               for cid in route}
    found = routing.components_by_id(db, on_path or (src | dst))
    return sorted((c for c in found.values() if c.type != ComponentType.aci),
                  key=lambda c: c.name)


def zone_problems(db: Session, source_zone: str, destination_zone: str) -> list[str]:
    """Why these two zones may not carry a ping baseline - empty means they may.

    Kept apart from the rest so the UI can ask the question before a rule
    exists: the option is only worth offering where it would be granted.
    """
    src, dst = find_zone(db, source_zone), find_zone(db, destination_zone)
    missing = [name for name, zone in ((source_zone, src), (destination_zone, dst)) if not zone]
    if missing:
        return [_("Zone(s) not maintained in the zone administration: {zones}",
                  zones=", ".join(n or "?" for n in missing))]
    if src.id == dst.id:
        return [_("Source and destination zone are the same - traffic inside a zone does "
                  "not cross a firewall, so there is nothing here to permit")]

    problems = []
    for zone in (src, dst):
        if zone.pap_level != "internal":
            problems.append(
                _("A ping baseline is only permitted between internal zones, and {zone} is "
                  "classified as '{level}'. Towards the P-A-P layer and outwards, an echo "
                  "answer tells an attacker what it tells operations",
                  zone=zone.name, level=_(zone.pap_level)))

    policy = get_policy(db, src, dst)
    if not policy or policy.policy != ZonePolicyType.allow_only:
        problems.append(
            _("The matrix does not allow {from_zone} → {to_zone}. A ping baseline rides on a "
              "relation the matrix already permits - it does not create one",
              from_zone=src.name, to_zone=dst.name))

    for zone in (src, dst):
        if not [c for c in zone.components if c.type != ComponentType.aci]:
            problems.append(
                _("Zone {zone} is not attached to a firewall cluster, so there is nothing to "
                  "roll the baseline out on. Maintain the attachment on the security zone",
                  zone=zone.name))
    return problems


def problems(db: Session, payload) -> list[str]:
    """Everything that stands between this declaration and a permitted rule."""
    found = zone_problems(db, payload.source_zone, payload.destination_zone)
    if not is_any_only(payload.source) or not is_any_only(payload.destination):
        found.append(
            _("A ping baseline is an any-to-any rule: it permits every address in the source "
              "zone to ping every address in the destination zone. Name the addresses and it "
              "is an ordinary ICMP rule, which needs no exception"))
    if not is_ping_only(payload.services):
        found.append(
            _("A ping baseline carries ICMP echo and nothing else. Request the other services "
              "as their own rule, with the source and destination they actually need"))
    if payload.action != RuleAction.permit:
        found.append(_("A ping baseline permits - a baseline that denies grants nothing "
                       "and hides the rule that would"))
    return found
