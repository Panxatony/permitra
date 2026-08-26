import re
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, ping_baseline
from ..auth import get_current_user, require_roles
from ..component_resolution import find_mapping, resolve_rule_components
from ..conflicts import find_conflicts
from ..database import get_db
from ..domain_values import IMPL_STATUSES
from ..expiry import expiring_rules, invalid_validity_rules
from ..exporters.generic import rule_to_dict
from ..messages import _, render
from ..models import (
    IN_FORCE,
    AddressComponentMap,
    Comment,
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    RuleVersion,
    SecurityComponent,
    User,
    active_rules,
    utcnow,
)
from ..schemas import (
    CommentCreate,
    CommentOut,
    ConflictOut,
    EmergencyRuleCreate,
    ExpiringOut,
    ExtendRequest,
    ResolveOut,
    ResolveRequest,
    ReviewDecision,
    RuleCreate,
    RuleDetail,
    RuleListOut,
    RuleOut,
    RuleUpdate,
    RuleVersionOut,
)
from ..settings import get_setting
from ..validation import format_entry, parse_network
from ..vrf import get_vrf
from ..zone_check import check_zone_pair, find_zone, resolve_zone_for_entries, zone_ref

router = APIRouter(prefix="/api/rules", tags=["rules"])

RULE_ID_RE = re.compile(r"^SR(\d+)$")


def next_rule_id(db: Session) -> str:
    """Next free SR number, zero-padded to five digits (e.g. SR00855).

    A MAX aggregate in the database (SUBSTR+CAST) instead of loading every rule –
    this still scales at tens of thousands of rules. Collisions from concurrent
    creation are caught by the unique constraint, with a retry in the caller."""
    from sqlalchemy import Integer, cast, func

    max_num = (
        db.query(func.max(cast(func.substr(Rule.rule_id, 3), Integer)))
        .filter(Rule.rule_id.like("SR%"))
        .scalar()
    ) or 0
    return f"SR{int(max_num) + 1:05d}"


def get_rule_or_404(db: Session, rule_id: str, include_deleted: bool = False) -> Rule:
    """Fetch a rule. Soft-deleted ones count as non-existent – otherwise they would
    stay readable, editable and re-approvable through /rules/{id}. Only delete_rule
    itself needs them, in order to detect a repeated deletion."""
    q = db.query(Rule) if include_deleted else active_rules(db)
    rule = q.filter(Rule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Rule {rule_id} not found", rule_id=rule_id))
    return rule


def snapshot(rule: Rule) -> dict:
    return rule_to_dict(rule, with_meta=True)


def resolve_components(db: Session, component_ids: list[int]) -> list[SecurityComponent]:
    """Resolve component_ids; unknown IDs result in a 422."""
    if not component_ids:
        return []
    components = (
        db.query(SecurityComponent).filter(SecurityComponent.id.in_(component_ids)).all()
    )
    missing = set(component_ids) - {c.id for c in components}
    if missing:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _("Unknown component(s): {components}", components=sorted(missing)),
        )
    return components



def derive_zones(db: Session, payload, vrf_id: int):
    """Derive the source/destination zone from the addresses' network assignments.

    Every network must be assigned to a security zone, and one side of a rule may
    span only a single zone. The derived zones override whatever was submitted."""
    if getattr(payload, "ping_baseline", False):
        return declared_zones(db, payload)

    def entries_of(value):
        return [e.model_dump() if hasattr(e, "model_dump") else e for e in value]

    problems = []
    zones = {}
    for label, field in ((_("Source"), "source"), (_("Destination"), "destination")):
        zone, unassigned, hits = resolve_zone_for_entries(db, entries_of(getattr(payload, field)), vrf_id)
        if unassigned:
            problems.append(
                _("{label}: network(s) not assigned to any security zone: {networks} "
                  "– create the network on the Networks page first and assign it to a "
                  "security zone",
                  label=label, networks=", ".join(unassigned))
            )
        elif len(hits) > 1:
            problems.append(_("{label} spans several zones ({zones}) – split the rule",
                              label=label, zones=", ".join(sorted(hits))))
        zones[field] = zone
    if problems:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "; ".join(problems))
    payload.source_zone = zones["source"] or payload.source_zone
    payload.destination_zone = zones["destination"] or payload.destination_zone


def declared_zones(db: Session, payload):
    """A ping baseline names its zones instead of deriving them.

    Its addresses are `any`, and `any` has no network assignment to look up - it
    would resolve to whichever zone happens to own the 0.0.0.0/0 entry, which is
    the internet and precisely not what this rule means. So the two zones the
    requester picked are the rule, and all that happens here is resolving them
    to their authoritative reference.
    """
    resolved = {}
    for field in ("source_zone", "destination_zone"):
        zone = find_zone(db, getattr(payload, field, "") or "")
        if zone is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                _("A ping baseline covers whole zones, so it has to name zones that exist - "
                  "'{zone}' is not maintained in the zone administration",
                  zone=getattr(payload, field, "") or "-"))
        resolved[field] = zone_ref(zone)
    payload.source_zone = resolved["source_zone"]
    payload.destination_zone = resolved["destination_zone"]


def enforce_ping_baseline(db: Session, payload):
    """Refuse a declaration the exception does not cover.

    Without this the checkbox would be the whole of it - anybody could label an
    any-to-any rule a baseline and have the risk assessment stop mentioning it.
    The declaration is worth something precisely because it is checked.
    """
    if not getattr(payload, "ping_baseline", False):
        return
    problems = ping_baseline.problems(db, payload)
    if problems:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("Ping baseline: ") + "; ".join(problems))


def determine_components(db: Session, payload, vrf_id: int) -> list[SecurityComponent]:
    """Determine the enforcing components automatically from source/destination.

    Explicitly supplied component_ids (e.g. API calls, imports) take precedence.
    Addresses without a maintained assignment result in a 422 – the user has to
    define the assignment once via /api/address-map.
    """
    if getattr(payload, "ping_baseline", False):
        # Zone-wide by definition, so the zones name the components - see
        # ping_baseline.components_for(). The address mapping has nothing to say
        # about `any` except which cluster faces the internet.
        return ping_baseline.components_for(
            db, find_zone(db, payload.source_zone), find_zone(db, payload.destination_zone))
    if payload.component_ids:
        return resolve_components(db, payload.component_ids)
    source = [e.model_dump() if hasattr(e, "model_dump") else e for e in payload.source]
    destination = [e.model_dump() if hasattr(e, "model_dump") else e for e in payload.destination]
    components, unknown = resolve_rule_components(
        db, source, destination, payload.source_zone, payload.destination_zone, vrf_id
    )
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _("No component mapping is defined yet for these addresses: ")
            + ", ".join(u["ip"] for u in unknown)
            + _(". Define it once via the address mapping."),
        )
    if not components:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _("No enforcing components could be determined"),
        )
    return components


def enforce_bsi_firewall(source_zone: str, destination_zone: str, components: list[SecurityComponent]):
    """BSI principle: the transition between security zones is always a firewall.

    A cross-zone rule must involve at least one firewall component – Cisco ACI is not
    sufficient as the enforcing security component for a zone transition."""
    src, dst = (source_zone or "").strip(), (destination_zone or "").strip()
    if not src or not dst or src.upper() == dst.upper():
        return  # Intra-zone: ACI contracts are the right instrument here
    if components and not any(c.type.value != "aci" for c in components):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _("A zone transition requires a firewall (BSI definition): Cisco ACI alone is not "
              "sufficient for {src} → {dst}. Assign a firewall cluster.",
              src=src, dst=dst),
        )


def enforce_zone_matrix(db: Session, source_zone: str, destination_zone: str, platforms: list[str]):
    """Block rules that the zone communication matrix declares inadmissible."""
    result = check_zone_pair(db, source_zone, destination_zone, platforms)
    if not result.allowed:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _("Zone matrix: ") + "; ".join(result.messages),
        )


def enforce_required_fields(db: Session, payload):
    """Configurable mandatory fields (admin settings, BSI documentation duties)."""
    from ..settings import get_setting

    missing = []
    if get_setting(db, "require_justification") == "yes" and not (payload.justification or "").strip():
        missing.append(_("Justification"))
    if get_setting(db, "require_valid_until") == "yes" and not (payload.valid_until or "").strip():
        missing.append(_("Valid until (expiry date)"))
    if missing:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _("Mandatory fields are missing: ") + ", ".join(missing),
        )


def add_version(db: Session, rule: Rule, user: User, note: str, **values):
    """Records one version. `note` is the English message *template*, untranslated.

    Translating it here would freeze the entry in whichever language the
    instance was set to at the time, and a history that is half English is
    exactly what an instance switched to German ends up with. The values are
    stored beside it and the sentence is put together when somebody reads it -
    see messages.render(). A note a person typed comes through as `note` with no
    values and is never treated as a template.
    """
    db.add(
        RuleVersion(
            rule_pk=rule.id,
            version=rule.version,
            snapshot=snapshot(rule),
            change_note=note,
            change_values=values or None,
            changed_by=user.username,
        )
    )


@router.get("", response_model=RuleListOut)
def list_rules(
    q: str | None = Query(None, description="Full-text search across ID, name, source, destination, justification"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    source: str | None = None,
    destination: str | None = None,
    port: str | None = None,
    protocol: str | None = None,
    rule_status: RuleStatus | None = Query(None, alias="status"),
    impl: str | None = Query(None, description="'pending' = approved rules with a pending implementation"),
    risk: str | None = Query(None, description="'flagged' = only rules carrying a risk finding"),
    application: str | None = None,
    app_id: str | None = Query(None, description="Application ID (per-app report)"),
    platform: str | None = None,
    component: str | None = Query(None, description="Name (substring) of a component"),
    vrf: str | None = Query(None, description="Environment/VRF (name); empty = all"),
    updated_since: str | None = Query(None, description="ISO timestamp; only rules changed since then (polling)"),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    # Deleted rules stay in the overview: a rule that is no longer needed is
    # documented as `deleted`, not made to disappear. They take effect nowhere
    # else - every functional query goes through active_rules() instead.
    query = db.query(Rule)
    if vrf:
        query = query.filter(Rule.vrf_id == get_vrf(db, vrf).id)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Rule.rule_id.ilike(like), Rule.name.ilike(like),
                Rule.justification.ilike(like), Rule.change_id.ilike(like), Rule.app_id.ilike(like),
                Rule.requestor.ilike(like), Rule.business_context.ilike(like),
                # Address fields are JSON – their full-text search follows in Python below
                Rule.source_zone.ilike(like), Rule.destination_zone.ilike(like),
            )
        )
    if rule_status:
        query = query.filter(Rule.status == rule_status)
    if updated_since:
        from datetime import datetime as _dt
        try:
            query = query.filter(Rule.updated_at >= _dt.fromisoformat(updated_since))
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                _("updated_since must be an ISO timestamp")) from exc
    if application:
        query = query.filter(Rule.application.ilike(f"%{application}%"))
    if app_id:
        query = query.filter(Rule.app_id.ilike(f"%{app_id}%"))
    rules = query.order_by(Rule.rule_id.desc()).all()

    def entry_match(entries, needle):
        needle = needle.lower()
        return any(
            needle in (e.get("ip") or "").lower() or needle in (e.get("alias") or "").lower()
            for e in entries or []
        )

    # JSON field filters in Python
    if q:
        # Keep the SQL hits for q; additionally include rules whose addresses match
        sql_ids = {r.id for r in rules}
        extra = [
            r for r in active_rules(db).order_by(Rule.rule_id.desc()).all()
            if r.id not in sql_ids and (entry_match(r.source, q) or entry_match(r.destination, q))
        ]
        rules = sorted(rules + extra, key=lambda r: r.rule_id, reverse=True)
    if source:
        rules = [r for r in rules if entry_match(r.source, source) or source.lower() in r.source_zone.lower()]
    if destination:
        rules = [
            r for r in rules
            if entry_match(r.destination, destination) or destination.lower() in r.destination_zone.lower()
        ]
    if port:
        rules = [r for r in rules if any(port in (s.get("port") or "") for s in r.services)]
    if protocol:
        rules = [r for r in rules if any(protocol.upper() in (s.get("protocol") or "").upper() for s in r.services)]
    if platform:
        rules = [r for r in rules if platform.lower() in (r.platforms or [])]
    if component:
        rules = [
            r for r in rules
            if any(component.lower() in c.name.lower() for c in r.components)
        ]
    if impl == "pending":
        rules = [r for r in rules if impl_pending(r)]
    if risk == "flagged":
        from ..risk import assess_rule
        rules = [r for r in rules if assess_rule(db, r)["level"] != "none"]
    return RuleListOut(total=len(rules), items=rules[offset:offset + limit])


def impl_pending(rule: Rule) -> bool:
    """Rule with pending implementation: approved and not yet implemented on at
    least one component (missing, "open", "new", "to change") – or flagged for
    removal ("to remove", e.g. after being blocked by the zone matrix)."""
    impl = rule.impl_status or {}
    if any(impl.get(c.name) == "to remove" for c in rule.components):
        return True
    if rule.status not in IN_FORCE or not rule.components:
        return False
    return any(impl.get(c.name) not in ("implemented", "deactivated") for c in rule.components)


def _match_address_field(entries: list, query: str, net) -> tuple[list[str], str | None]:
    """Match structured address entries against the search query.

    Returns (formatted matching entries, match kind): "direct" (network overlap or a
    textual alias/IP hit) beats "any" (the entry covers every IP).
    """
    matched, kind = [], None
    q_lower = query.strip().lower()
    for entry in entries or []:
        ip = (entry.get("ip") or "").strip()
        alias = (entry.get("alias") or "").strip()
        if not ip and not alias:
            continue
        entry_kind = None
        if net is not None and ip.lower() == "any":
            entry_kind = "any"
        elif net is not None:
            entry_net = parse_network(ip)
            if entry_net and entry_net.version == net.version and entry_net.overlaps(net):
                entry_kind = "direct"
        if entry_kind is None and q_lower and (q_lower in ip.lower() or q_lower in alias.lower()):
            entry_kind = "direct"
        if entry_kind:
            matched.append(format_entry(entry))
            kind = "direct" if entry_kind == "direct" or kind == "direct" else "any"
    return matched, kind


@router.get("/ip-search")
def ip_search(
    q: str = Query(..., min_length=1, description="IP, network (CIDR) or hostname fragment"),
    vrf: str | None = Query(None),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Every rule in which the IP/network appears as source (outbound) or destination (inbound)."""
    net = parse_network(q.strip())
    outgoing, incoming = [], []
    rule_query = active_rules(db).order_by(Rule.rule_id.desc())
    vrf_id = None
    if vrf:
        vrf_obj = get_vrf(db, vrf)
        vrf_id = vrf_obj.id
        rule_query = rule_query.filter(Rule.vrf_id == vrf_obj.id)
    # Determine the zone of the searched address – a pure "any" hit is discarded
    # when the address belongs to a different zone than that side of the rule
    # (e.g. a PROD address is no source of an INET→… rule whose source is any)
    from ..models import ZoneNetwork as _ZN
    from ..zone_check import zone_for_ip

    searched_zone = None
    if net is not None:
        nets = db.query(_ZN)
        if vrf_id is not None:
            nets = nets.filter(_ZN.vrf_id == vrf_id)
        z = zone_for_ip(q.strip(), nets.all())
        searched_zone = z.name.upper() if z else None

    for rule in rule_query.all():
        for field, bucket, rule_zone in (
            ("source", outgoing, rule.source_zone),
            ("destination", incoming, rule.destination_zone),
        ):
            matched, kind = _match_address_field(getattr(rule, field), q, net)
            # Filter out hits that only match via "any" across zone boundaries
            if kind == "any" and searched_zone and rule_zone \
                    and searched_zone != rule_zone.strip().upper():
                kind = None
            if kind:
                bucket.append(
                    {
                        "rule_id": rule.rule_id,
                        "name": rule.name,
                        "status": rule.status.value,
                        "platforms": rule.platforms,
                        "components": [c.name for c in rule.components],
                        "source_zone": rule.source_zone,
                        "destination_zone": rule.destination_zone,
                        "source": rule.source,
                        "destination": rule.destination,
                        "services": rule.services,
                        "action": rule.action.value,
                        "justification": rule.justification,
                        "matched_entries": matched,
                        "match": kind,
                    }
                )
    key = lambda item: (item["match"] != "direct", item["rule_id"])  # noqa: E731 – direct hits first
    return {
        "query": q,
        "is_network": net is not None,
        "outgoing": sorted(outgoing, key=key),
        "incoming": sorted(incoming, key=key),
    }


@router.get("/path-search")
def path_search(
    src: str = Query(..., min_length=1, description="Source IP/network/hostname"),
    dst: str = Query(..., min_length=1, description="Destination IP/network/hostname"),
    vrf: str | None = Query(None),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Every rule covering traffic from src to dst (source AND destination must match)."""
    src_net, dst_net = parse_network(src.strip()), parse_network(dst.strip())
    results = []
    rule_query = active_rules(db).order_by(Rule.rule_id.desc())
    if vrf:
        rule_query = rule_query.filter(Rule.vrf_id == get_vrf(db, vrf).id)
    for rule in rule_query.all():
        src_matched, src_kind = _match_address_field(rule.source, src, src_net)
        if not src_kind:
            continue
        dst_matched, dst_kind = _match_address_field(rule.destination, dst, dst_net)
        if not dst_kind:
            continue
        results.append(
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "status": rule.status.value,
                "platforms": rule.platforms,
                "components": [c.name for c in rule.components],
                "source_zone": rule.source_zone,
                "destination_zone": rule.destination_zone,
                "source": rule.source,
                "destination": rule.destination,
                "services": rule.services,
                "action": rule.action.value,
                "justification": rule.justification,
                "matched_source": src_matched,
                "matched_destination": dst_matched,
                # "direct" only if both sides match concretely (not merely via any)
                "match": "direct" if src_kind == "direct" and dst_kind == "direct" else "any",
            }
        )
    results.sort(key=lambda item: (item["match"] != "direct", item["rule_id"]))
    return {"src": src, "dst": dst, "results": results}


@router.get("/next-id")
def get_next_id(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return {"rule_id": next_rule_id(db)}


@router.get("/path-analysis")
def path_analysis(
    src: str = Query(..., description="Source IP or network"),
    dst: str = Query(..., description="Destination IP or network"),
    vrf: str | None = Query(None),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Visual path analysis: is communication src -> dst possible, which components
    does it traverse, which rule permits it there, and for which services?"""
    src_net, dst_net = parse_network(src.strip()), parse_network(dst.strip())
    if (src_net is None and src.strip().lower() != "any") or (dst_net is None and dst.strip().lower() != "any"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("Source and destination must be an IP/network or 'any'"))

    # Components to be traversed, taken from the address mapping (in the VRF context)
    vrf_obj = get_vrf(db, vrf) if vrf else get_vrf(db)
    mappings = db.query(AddressComponentMap).filter(AddressComponentMap.vrf_id == vrf_obj.id).all()
    map_src, map_dst = find_mapping(src, mappings), find_mapping(dst, mappings)
    unknown = [ip for ip, m in ((src, map_src), (dst, map_dst)) if m is None]
    src_ids = set((map_src.component_ids if map_src else []) or [])
    dst_ids = set((map_dst.component_ids if map_dst else []) or [])
    component_ids = src_ids | dst_ids
    components = (
        db.query(SecurityComponent).filter(SecurityComponent.id.in_(component_ids)).all()
        if component_ids else []
    )
    # Same mapping (same network) => intra-zone => ACI; otherwise firewalls
    intra = map_src is not None and map_dst is not None and map_src.id == map_dst.id
    filtered = [c for c in components if (c.type == ComponentType.aci) == intra]
    components = filtered or components

    # Multi-hop ordering: source-side components -> both-sided -> destination-side
    def hop_side(component):
        in_src, in_dst = component.id in src_ids, component.id in dst_ids
        if in_src and in_dst:
            return 1, "both"
        return (0, "source") if in_src else (2, "destination")

    hop_list = [
        {"component": component, "side": hop_side(component)[1], "via_pbr": False}
        for component in components
    ]

    # PBR attachment: if src/dst lies in the network of an anycast gateway with PBR,
    # the Check Point cluster is traversed as well (service-graph redirection)
    from ..models import AciGateway  # local import avoids cycles at module load time

    for gateway in db.query(AciGateway).filter(AciGateway.pbr_enabled).all():
        gw_net = parse_network(gateway.gateway_ip)
        if not gw_net or not gateway.pbr_component:
            continue
        for _ip, net, side in ((src, src_net, "source"), (dst, dst_net, "destination")):
            if net is None or net.version != gw_net.version:
                continue
            if net.subnet_of(gw_net) and not any(
                h["component"].id == gateway.pbr_component.id for h in hop_list
            ):
                hop_list.append(
                    {"component": gateway.pbr_component, "side": side, "via_pbr": True,
                     "gateway": gateway.name}
                )

    # Rules covering the traffic src -> dst (only within the VRF context)
    matching = []
    for rule in active_rules(db).filter(Rule.vrf_id == vrf_obj.id).all():
        _src_matched, src_kind = _match_address_field(rule.source, src, src_net)
        if not src_kind:
            continue
        _dst_matched, dst_kind = _match_address_field(rule.destination, dst, dst_net)
        if not dst_kind:
            continue
        matching.append((rule, src_kind, dst_kind))

    # The path comes from the topology: the links record which clusters are
    # connected (routing.py), the address mapping says which one an address sits
    # behind, and the route is the way through. A transit cluster is found by
    # following the links, so it no longer has to be listed on every address
    # behind it - and two clusters nothing connects yield no route rather than
    # an order that reads like a working path.
    from .. import routing

    graph = routing.build_graph(db)
    # Route between the *firewalls* the addresses sit behind. The ACI fabric is
    # listed on nearly every zone because it segments inside one - it is not a
    # way from one zone to another. Left in, both endpoints would share it and
    # the route collapsed to a single fabric hop, reporting that VPN reaches the
    # production databases without crossing a firewall. `filtered` already draws
    # that line for the hop list; the route has to use the same one.
    routable = {c.id for c in filtered}
    routes = (routing.shortest_routes(graph, src_ids & routable, dst_ids & routable)
              if graph else [])
    # No links recorded at all is not the same statement as "there is no way".
    # One is an estate whose topology nobody documented, the other is a finding -
    # collapsing them would either invent routes or condemn every install that
    # has not filled the links in.
    routing_state = ("routed" if routes else "no_route") if graph else "not_documented"

    if routes:
        by_id = {hop["component"].id: hop for hop in hop_list}
        extra = routing.components_by_id(
            db, {cid for route in routes for cid in route} - set(by_id))
        ordered, seen_ids = [], set()
        for route in routes:
            for position, component_id in enumerate(route):
                if component_id in seen_ids:
                    continue
                seen_ids.add(component_id)
                hop = by_id.get(component_id)
                if hop is None:
                    component = extra.get(component_id)
                    if component is None:
                        continue
                    hop = {"component": component, "side": "transit", "via_pbr": False}
                elif component_id not in src_ids and component_id not in dst_ids:
                    hop = {**hop, "side": "transit"}
                if position == 0 and component_id in src_ids:
                    hop = {**hop, "side": "source"}
                elif position == len(route) - 1 and component_id in dst_ids:
                    hop = {**hop, "side": "destination"}
                ordered.append(hop)
        # Anything the mapping named that no route crosses is kept at the end
        # rather than dropped: it is what somebody documented, and losing it
        # silently would hide a mapping that disagrees with the topology.
        ordered += [h for h in hop_list if h["component"].id not in seen_ids]
        hop_list = ordered
    else:
        # Undocumented topology: fall back to the tiering, which is what this
        # did before there was a graph to ask.
        def avg_tier(ids):
            tiers = [c.ns_tier for c in components if c.id in ids]
            return sum(tiers) / len(tiers) if tiers else 100

        direction = -1 if avg_tier(src_ids) > avg_tier(dst_ids) else 1
        side_rank = {"source": 0, "both": 1, "destination": 2}
        hop_list.sort(
            key=lambda h: (direction * h["component"].ns_tier,
                           side_rank.get(h["side"], 1), h["component"].name)
        )

    def service_key(svc):
        return ((svc.get("protocol") or "").upper(), (svc.get("port") or "").lower())

    component_results, allowed_sets = [], []
    for hop in hop_list:
        component = hop["component"]
        rules_here = [
            (r, sk, dk) for (r, sk, dk) in matching if any(c.id == component.id for c in r.components)
        ]
        enabling = [
            r for (r, _, _) in rules_here
            if r.status in IN_FORCE and r.action == RuleAction.permit
        ]
        allowed_here = {service_key(s) for r in enabling for s in (r.services or [])}
        if enabling:
            allowed_sets.append(allowed_here)
        component_results.append(
            {
                "id": component.id,
                "name": component.name,
                "type": component.type.value,
                "location": component.location,
                "side": hop["side"],
                "via_pbr": hop["via_pbr"],
                "gateway": hop.get("gateway"),
                "covered": bool(enabling),
                "rules": sorted(
                    (
                        {
                            "rule_id": r.rule_id,
                            "name": r.name,
                            "status": r.status.value,
                            "action": r.action.value,
                            "services": r.services,
                            "via_any": sk == "any" or dk == "any",
                        }
                        for (r, sk, dk) in rules_here
                    ),
                    key=lambda item: (item["status"] != "approved", item["rule_id"]),
                ),
            }
        )

    # Which clusters a route crosses that no rule covers. Reported per route,
    # because the interesting case is precisely the one where a route is whole
    # and its alternative is not - traffic then works until the failover.
    covered_ids = {c["id"] for c in component_results if c["covered"]}
    names = {c["id"]: c["name"] for c in component_results}
    route_gaps = [
        {"route": [names.get(cid, str(cid)) for cid in route],
         "uncovered": [names.get(cid, str(cid)) for cid in route if cid not in covered_ids]}
        for route in routes
        if any(cid not in covered_ids for cid in route)
    ]

    # Permitted services = the intersection across every hop that has to be traversed
    allowed = set.intersection(*allowed_sets) if len(allowed_sets) == len(hop_list) and allowed_sets else set()
    possible = bool(hop_list) and all(c["covered"] for c in component_results) and bool(allowed)

    return {
        "src": src,
        "dst": dst,
        "unknown_addresses": unknown,
        "intra_zone": intra,
        "possible": possible,
        "allowed_services": [
            {"protocol": p, "port": port} for p, port in sorted(allowed)
        ],
        "components": component_results,
        # "routed" - the path came from the topology; "no_route" - the links are
        # documented and there is no way between these two, which is a finding;
        # "not_documented" - no links recorded at all, so the hops fall back to
        # the tiering. The three say different things and are kept apart.
        "routing": routing_state,
        "routes": [
            [{"id": cid, "name": names.get(cid, str(cid))} for cid in route]
            for route in routes
        ],
        # Redundancy is the reason a second route exists, and a rule that sits
        # on one route but not the other holds until the day it fails over.
        "route_gaps": route_gaps,
    }


@router.get("/expiring", response_model=ExpiringOut)
def get_expiring(
    days: int = Query(30, ge=0, le=365),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Expired and soon-to-expire approved rules (recertification)."""
    expired, expiring = expiring_rules(db, days)
    return ExpiringOut(days=days, expired=expired, expiring=expiring,
                       invalid=invalid_validity_rules(db))


@router.post("/resolve-components")
def resolve_components_endpoint(
    payload: ResolveRequest,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Determine the components from source/destination; report addresses without a mapping."""
    src_entries = [e.model_dump() for e in payload.source]
    dst_entries = [e.model_dump() for e in payload.destination]
    vrf_obj = get_vrf(db, payload.vrf or None)
    zone_issues = []
    src_zone, src_un, src_hits = resolve_zone_for_entries(db, src_entries, vrf_obj.id)
    dst_zone, dst_un, dst_hits = resolve_zone_for_entries(db, dst_entries, vrf_obj.id)
    for label, un, hits in ((_("Source"), src_un, src_hits), (_("Destination"), dst_un, dst_hits)):
        if not un and len(hits) > 1:
            zone_issues.append(_("{label} spans several zones: {zones}",
                                 label=label, zones=", ".join(sorted(hits))))
    # Addresses from unknown networks: create the network and assign its zone first –
    # the component mapping is not yet requested for them
    unassigned = list(dict.fromkeys(src_un + dst_un))
    components, unknown = resolve_rule_components(
        db, src_entries, dst_entries, src_zone or "", dst_zone or "", vrf_obj.id
    )
    out = ResolveOut(components=components, unknown=unknown).model_dump()
    out.update({"source_zone": src_zone, "destination_zone": dst_zone,
                "zone_issues": zone_issues, "unassigned": unassigned})
    return out


def _create_rule(db: Session, payload, user: User, *,
                 status_: RuleStatus | None = None,
                 matrix_blocking: bool = True) -> Rule:
    """Creates the rule and returns it, uncommitted.

    Shared by the normal path and the emergency one so there is exactly one
    place that derives zones, resolves components and enforces the BSI rules - a
    fast path that quietly skipped half of them would be the loophole this is
    meant not to be.

    matrix_blocking=False is the single difference the emergency path needs. The
    rule is already on the firewall; refusing to *document* it because the zone
    matrix forbids it would leave the traffic flowing and the record missing,
    which is the worst of both. The violation is recorded instead, and the
    approver decides.
    """
    # The rule ID is always assigned by the system (sequential, unique, immutable).
    # On concurrent creation the unique constraint protects us; then try a new number.
    vrf = get_vrf(db, payload.vrf or None)
    enforce_required_fields(db, payload)
    for _attempt in range(5):
        derive_zones(db, payload, vrf.id)
        enforce_ping_baseline(db, payload)
        components = determine_components(db, payload, vrf.id)
        enforce_bsi_firewall(payload.source_zone, payload.destination_zone, components)
        matrix_violation = ""
        if matrix_blocking:
            enforce_zone_matrix(
                db, payload.source_zone, payload.destination_zone,
                [c.type.value for c in components]
            )
        else:
            verdict = check_zone_pair(db, payload.source_zone, payload.destination_zone,
                                      [c.type.value for c in components])
            if not verdict.allowed:
                matrix_violation = "; ".join(verdict.messages)

        # requestor and owner are derived, never entered (see below); whatever a
        # client sends for them is ignored rather than trusted.
        data = payload.model_dump(exclude={"component_ids", "vrf", "emergency_reason",
                                           "requestor", "owner"})
        data["services"] = [s.model_dump() if hasattr(s, "model_dump") else s for s in payload.services]
        if status_ is not None:
            data["status"] = status_
        # The requestor is the account that created the rule in Permitra - not a
        # free-text name. A name somebody typed cannot be signed in, notified or
        # matched against the user list; an account can. The owner (Bearbeiter)
        # stays empty until operations first touches the implementation status,
        # because that is what it records: who last worked the rule on the
        # components, not who somebody expects to.
        rule = Rule(rule_id=next_rule_id(db), vrf_id=vrf.id, created_by=user.username,
                    requestor=user.username, components=components, **data)
        db.add(rule)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            continue
        if matrix_violation:
            # Loud, not silent: the approver has to see that this rule crosses a
            # relation the matrix forbids before deciding whether it may stay.
            rule.removal_reason = matrix_violation[:255]
            db.add(Comment(rule_pk=rule.id, author=user.username,
                           text=render("Contrary to the zone matrix: {reason}",
                                       {"reason": matrix_violation})))
        add_version(db, rule, user, "Rule created")
        return rule
    raise HTTPException(status.HTTP_409_CONFLICT, _("Assigning a rule ID failed, try again"))


@router.post("", response_model=RuleOut, status_code=201)
def create_rule(
    payload: RuleCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect)),
):
    rule = _create_rule(db, payload, user)
    db.commit()
    db.refresh(rule)
    return rule


@router.post("/emergency", response_model=RuleOut, status_code=201)
def declare_emergency_rule(
    payload: EmergencyRuleCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Document a rule that was already opened on the firewall, under time pressure.

    Permitra cannot stop somebody opening a port at three in the morning when the
    approver is unreachable. What it can do is offer a way in, so the reason is
    written down while somebody still remembers it. A tool without a documented
    fast path does not prevent emergency changes - it only prevents them from
    being recorded, which is strictly worse.

    Deliberately not an override. The rule lands in review like any other, it
    carries a mandatory reason, and it deactivates itself when the window passes
    without an approval. The path is meant to be narrow and loud, not convenient.
    """
    rule = _create_rule(db, payload, user, status_=RuleStatus.in_review,
                        matrix_blocking=False)

    hours = int(get_setting(db, "emergency_window_hours"))
    # One timestamp, not two: the window has to be exactly the configured length,
    # and two calls to utcnow() are microseconds apart.
    declared = utcnow()
    rule.emergency_declared_at = declared
    rule.emergency_declared_by = user.username
    rule.emergency_reason = payload.emergency_reason.strip()
    rule.emergency_approval_due = declared + timedelta(hours=hours)

    # The version note and the comment carry the reason, so it is visible in the
    # history rather than only in a column somebody has to know about.
    rule.version += 1
    add_version(db, rule, user, "Emergency change declared: {reason}",
                reason=rule.emergency_reason)
    db.add(Comment(rule_pk=rule.id, author=user.username,
                   text=render("Emergency change declared: {reason}",
                               {"reason": rule.emergency_reason})))

    # Its own event type, so "how often do we do this?" is answerable. An
    # emergency path used twice a year is a working control; one used weekly is
    # a finding, and that difference has to be countable.
    audit.record(db, "rule", "rule.emergency_declared", actor=user.username,
                 object=rule.rule_id,
                 detail="Emergency change, approval due within {hours} h: {reason}",
                 detail_values={"hours": hours, "reason": rule.emergency_reason},
                 source_ip=audit.client_ip(request))
    db.commit()
    db.refresh(rule)

    from .. import notifications
    notifications.rule_submitted(db, rule)
    return rule


class RequestorHandover(BaseModel):
    new_requestor: str


def _active_architect(db: Session, username: str) -> User:
    user = (db.query(User)
            .filter(User.username == username, User.is_active.is_(True)).first())
    if not user:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("'{username}' is not an active account", username=username))
    if not user.has_role(Role.architect):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("A requestor is an architect account - '{username}' is {role}",
                              username=username,
                              role=", ".join(r.value for r in user.roles)))
    return user


@router.post("/{rule_id}/requestor-handover", response_model=RuleOut)
def propose_requestor_handover(
    rule_id: str,
    payload: RequestorHandover,
    request: Request,
    db: Session = Depends(get_db),
    # Operations is here because an emergency change is requested by the ops
    # account that opened it (#36) - so an ops account can be a requestor, and a
    # requestor must be able to hand their own rule on to the architect who owns
    # the application. The real gate is is_current below, not the role.
    user: User = Depends(require_roles(Role.architect, Role.operations, Role.admin)),
):
    """Propose a new requestor for a rule - the successor still has to confirm.

    An architect who changes department or company hands their rules over. Only
    the current requestor may propose it (they are handing over their own
    responsibility), with one exception: an admin may propose when the current
    requestor is no longer an active account, because a departed requestor
    cannot hand over what they can no longer reach - and the recertification
    worklist flags exactly those rules.
    """
    rule = get_rule_or_404(db, rule_id)
    is_current = user.username == rule.requestor
    requestor_active = (db.query(User)
                        .filter(User.username == rule.requestor,
                                User.is_active.is_(True)).first() is not None)
    if not is_current and not (user.has_role(Role.admin) and not requestor_active):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            _("Only the current requestor may hand a rule over "
                              "(an admin may, once the requestor's account is gone)"))

    successor = _active_architect(db, payload.new_requestor.strip())
    if successor.username == rule.requestor:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("That is already the requestor"))

    rule.pending_requestor = successor.username
    rule.handover_proposed_by = user.username
    rule.handover_proposed_at = utcnow()
    rule.version += 1
    add_version(db, rule, user,
                "Requestor handover proposed to {successor} - awaiting confirmation",
                successor=successor.username)
    audit.record(db, "rule", "rule.requestor_handover_proposed", actor=user.username,
                 object=rule.rule_id,
                 detail="To {successor}", detail_values={"successor": successor.username},
                 source_ip=audit.client_ip(request))
    db.commit()
    db.refresh(rule)

    from .. import notifications
    notifications.requestor_handover_proposed(db, rule, successor)
    return rule


@router.post("/{rule_id}/requestor-handover/confirm", response_model=RuleOut)
def confirm_requestor_handover(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect)),
):
    """The proposed successor accepts the rule - only now does the requestor change."""
    rule = get_rule_or_404(db, rule_id)
    if not rule.pending_requestor:
        raise HTTPException(status.HTTP_409_CONFLICT, _("No handover is pending for this rule"))
    if user.username != rule.pending_requestor:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            _("Only the proposed requestor can confirm the takeover"))
    previous = rule.requestor
    rule.requestor = rule.pending_requestor
    rule.pending_requestor = ""
    rule.handover_proposed_by = ""
    rule.handover_proposed_at = None
    rule.version += 1
    add_version(db, rule, user,
                "Requestor handover confirmed: {previous} → {now}",
                previous=previous or "-", now=user.username)
    audit.record(db, "rule", "rule.requestor_handover_confirmed", actor=user.username,
                 object=rule.rule_id,
                 detail="From {previous}", detail_values={"previous": previous or "-"},
                 source_ip=audit.client_ip(request))
    db.commit()
    db.refresh(rule)
    return rule


@router.post("/{rule_id}/requestor-handover/cancel", response_model=RuleOut)
def cancel_requestor_handover(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.admin)),
):
    """Withdraw or decline a pending handover.

    Both sides may end it: the proposer withdraws, the proposed successor
    declines, an admin clears a stuck one. The requestor is unchanged - nothing
    happened but a proposal, and it leaves the same trail whether accepted or not.
    """
    rule = get_rule_or_404(db, rule_id)
    if not rule.pending_requestor:
        raise HTTPException(status.HTTP_409_CONFLICT, _("No handover is pending for this rule"))
    allowed = {rule.handover_proposed_by, rule.pending_requestor}
    if user.username not in allowed and not user.has_role(Role.admin):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            _("Only the two sides of the handover, or an admin, can end it"))
    declined_by = user.username
    target = rule.pending_requestor
    rule.pending_requestor = ""
    rule.handover_proposed_by = ""
    rule.handover_proposed_at = None
    rule.version += 1
    add_version(db, rule, user,
                "Requestor handover to {target} cancelled by {who}",
                target=target, who=declined_by)
    audit.record(db, "rule", "rule.requestor_handover_cancelled", actor=user.username,
                 object=rule.rule_id, source_ip=audit.client_ip(request))
    db.commit()
    db.refresh(rule)
    return rule


@router.get("/handovers/incoming", response_model=RuleListOut)
def incoming_handovers(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect)),
):
    """Rules proposed for this architect to take over - so a handover is not
    something the successor has to be told about out of band."""
    rules = (active_rules(db)
             .filter(Rule.pending_requestor == user.username)
             .order_by(Rule.rule_id).all())
    return {"total": len(rules), "items": rules}


class ApplicationRetirement(BaseModel):
    reason: str = ""
    # A run that only reports. The list of what would be touched has to be
    # readable before it is touched - "this proposes 34 rules for removal" is
    # the difference between a usable feature and a frightening one.
    dry_run: bool = True


@router.get("/applications/summary")
def application_summary(db: Session = Depends(get_db),
                        _user: User = Depends(get_current_user)):
    """The applications rules were opened for, and how many are in force.

    The starting point for a retirement: you cannot retire what you cannot see,
    and an app_id typed from memory is an app_id that quietly matches nothing.
    """
    rows = (active_rules(db)
            .filter(Rule.app_id != "")
            .filter(Rule.status.in_(IN_FORCE))
            .all())
    counts: dict[str, int] = {}
    for rule in rows:
        counts[rule.app_id] = counts.get(rule.app_id, 0) + 1
    return {"items": [{"app_id": app_id, "in_force": n}
                      for app_id, n in sorted(counts.items())]}


@router.post("/applications/{app_id}/retire")
def retire_application(
    app_id: str,
    payload: ApplicationRetirement,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect)),
):
    """Proposes every in-force rule of a retired application for removal (#85).

    Rules outliving the application they were opened for is one of the most
    common ways a ruleset rots: the application is gone, the holes it needed are
    not. Retirement is a decision about the application, which is why it sits
    with the architect - but it is deliberately *not* a mass deactivation. Each
    rule is only put back into review carrying a removal reason, and is then
    decided one at a time on the existing path (`_decide` deactivates it and
    sets every component to "to remove" on approval).

    Four eyes survive that by construction: proposing writes a version in the
    acting account's name, which makes it the submitter - and a submitter cannot
    approve. Whoever retires the application cannot wave its rules out alone.
    """
    reason = (payload.reason or "").strip()
    if not reason:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("A retirement needs a reason - it becomes the "
                              "removal reason on every rule"))

    candidates = (active_rules(db)
                  .filter(Rule.app_id == app_id)
                  .order_by(Rule.rule_id).all())
    if not candidates:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            _("No rules carry the application '{app_id}'", app_id=app_id))

    # Only rules in force stand on a device and can be removed from one. The
    # rest are reported rather than silently dropped: a draft for a retired
    # application is not a removal, but it is something somebody should see.
    proposed = [r for r in candidates if r.status in IN_FORCE]
    skipped = [{"rule_id": r.rule_id, "status": r.status.value}
               for r in candidates if r.status not in IN_FORCE]

    result = {
        "app_id": app_id,
        "dry_run": payload.dry_run,
        "proposed": [{"rule_id": r.rule_id, "name": r.name,
                      "source_zone": r.source_zone, "destination_zone": r.destination_zone,
                      "requestor": r.requestor} for r in proposed],
        "skipped": skipped,
        "total": len(proposed),
    }
    if payload.dry_run:
        return result

    if not proposed:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("No rule of '{app_id}' is in force", app_id=app_id))

    template = ("Application {app_id} retired: {reason} - proposed for removal")
    values = {"app_id": app_id, "reason": reason}
    for rule in proposed:
        rule.removal_reason = f"{app_id}: {reason}"[:255]
        rule.status = RuleStatus.in_review
        rule.version += 1
        add_version(db, rule, user, template, **values)
        db.add(Comment(rule_pk=rule.id, author=user.username,
                       text=render(template, values)))
    db.commit()

    audit.record(db, "rule", "application.retired", actor=user.username, object=app_id,
                 detail="{count} rule(s) proposed for removal: {reason}",
                 detail_values={"count": str(len(proposed)), "reason": reason},
                 source_ip=audit.client_ip(request))

    from .. import notifications
    for rule in proposed:
        notifications.rule_submitted(db, rule)
    return result


@router.get("/{rule_id}", response_model=RuleDetail)
def get_rule(rule_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    # Readable even once deleted - the record is the evidence. Every endpoint
    # that changes something keeps the strict lookup, so a deleted rule cannot
    # be edited or approved back into service.
    return get_rule_or_404(db, rule_id, include_deleted=True)


@router.put("/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: str,
    payload: RuleUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect)),
):
    rule = get_rule_or_404(db, rule_id)
    vrf = get_vrf(db, payload.vrf or None) if payload.vrf else rule.vrf
    enforce_required_fields(db, payload)
    derive_zones(db, payload, vrf.id)
    enforce_ping_baseline(db, payload)
    components = determine_components(db, payload, vrf.id)
    enforce_bsi_firewall(payload.source_zone, payload.destination_zone, components)
    enforce_zone_matrix(
        db, payload.source_zone, payload.destination_zone, [c.type.value for c in components]
    )
    # impl_status is maintained by operations through its own endpoint – an edit must
    # not reset it (approval sets already implemented components to "to change")
    data = payload.model_dump(exclude={"change_note", "component_ids", "vrf", "impl_status",
                                       "requestor", "owner"})
    data["services"] = [s.model_dump() if hasattr(s, "model_dump") else s for s in payload.services]
    for key, value in data.items():
        setattr(rule, key, value)
    rule.vrf_id = vrf.id
    rule.components = components
    rule.version += 1
    # The checks above (zones, matrix, BSI firewall) have all passed – any removal
    # proposal raised earlier is therefore moot.
    rule.removal_reason = ""
    # A substantive change to an approved rule resets the review
    if rule.status in (*IN_FORCE, RuleStatus.rejected):
        rule.status = RuleStatus.draft
    add_version(db, rule, user, payload.change_note or "Rule changed")
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=204)
def delete_rule(
    request: Request,
    rule_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin)),
):
    """Deletion is an end state, not a removal.

    The rule keeps its record and moves to the status `deleted`, so it stays
    visible in the overview and its history remains available as evidence. It
    stops taking effect at that moment: exports, drift, path analysis and the
    expiry check all go through `active_rules()`, which excludes it. Being
    visible and being in force are two different things, and only the first one
    survives a deletion."""
    from .. import audit
    from ..models import utcnow as _now

    rule = get_rule_or_404(db, rule_id, include_deleted=True)
    if rule.deleted_at is not None:
        return
    rule.deleted_at = _now()
    rule.status = RuleStatus.deleted
    rule.version += 1
    add_version(db, rule, user, "Rule set to deleted")
    db.commit()
    audit.record(db, "rule", "rule.deleted", actor=user.username, object=rule.rule_id,
                 detail="Rule deleted (soft delete): {name}", detail_values={"name": rule.name},
                 source_ip=(request.client.host if request and request.client else ""))


# --- Review workflow ---------------------------------------------------------

@router.post("/{rule_id}/restore/{version}", response_model=RuleOut)
def restore_version(
    rule_id: str,
    version: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect)),
):
    """Rollback: restore the snapshot of an earlier version as a new draft. The
    restored content runs through the same checks as any change (zone derivation,
    zone matrix, BSI firewall, components) and through the normal review workflow;
    the implementation status is left untouched."""
    rule = get_rule_or_404(db, rule_id)
    entry = (
        db.query(RuleVersion)
        .filter(RuleVersion.rule_pk == rule.id, RuleVersion.version == version)
        .first()
    )
    if not entry or not isinstance(entry.snapshot, dict) or "source" not in entry.snapshot:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            _("Version {version} has no restorable snapshot", version=version))
    snap = entry.snapshot

    # Validate the restored content just like a normal change
    class _Payload:
        pass

    payload = _Payload()
    payload.source = snap.get("source") or []
    payload.destination = snap.get("destination") or []
    payload.source_zone = snap.get("source_zone") or ""
    payload.destination_zone = snap.get("destination_zone") or ""
    payload.component_ids = []
    payload.services = snap.get("services") or []
    payload.action = (RuleAction(snap["action"])
                      if snap.get("action") in {a.value for a in RuleAction} else rule.action)
    # A version written before the baseline existed carries no flag. Falling
    # back to the rule's own would restore addresses from a time when it was an
    # ordinary rule while still calling it a baseline, so the snapshot's shape
    # decides: any-to-any is the only thing a baseline ever looked like.
    declared = snap.get("ping_baseline")
    if declared is None:
        declared = rule.ping_baseline and ping_baseline.is_any_only(payload.source)
    payload.ping_baseline = bool(declared)
    derive_zones(db, payload, rule.vrf_id)
    enforce_ping_baseline(db, payload)
    components = determine_components(db, payload, rule.vrf_id)
    enforce_bsi_firewall(payload.source_zone, payload.destination_zone, components)
    enforce_zone_matrix(
        db, payload.source_zone, payload.destination_zone, [c.type.value for c in components]
    )

    # requestor and owner are deliberately not restored: the creator does not
    # change because content was rolled back, and the owner records who last
    # worked the rule on the devices - also unaffected by a content rollback.
    for field in ("name", "application", "source", "destination", "services",
                  "description", "justification", "business_context", "info",
                  "change_id", "valid_from", "valid_until"):
        if field in snap:
            setattr(rule, field, snap[field])
    rule.action = payload.action
    rule.ping_baseline = payload.ping_baseline
    rule.source_zone = payload.source_zone
    rule.destination_zone = payload.destination_zone
    rule.components = components
    rule.status = RuleStatus.draft  # a rollback goes through the normal review
    rule.removal_reason = ""        # checks above passed – removal proposal is moot
    rule.version += 1
    add_version(db, rule, user, "Rolled back to version {version}", version=version)
    db.commit()
    db.refresh(rule)
    return rule


@router.post("/{rule_id}/submit", response_model=RuleOut)
def submit_for_review(
    rule_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect)),
):
    rule = get_rule_or_404(db, rule_id)
    if rule.status not in (RuleStatus.draft, RuleStatus.rejected):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            _("The rule is in status '{status}'", status=_(rule.status.value)))
    rule.status = RuleStatus.in_review
    rule.version += 1
    add_version(db, rule, user, "Submitted for review")
    db.commit()
    db.refresh(rule)
    from .. import change_management, notifications

    change_management.notify(
        "rule.submitted",
        {**change_management.rule_payload(rule), "submitted_by": user.username},
    )
    notifications.rule_submitted(db, rule)
    return rule


def _decide(db, rule_id, user, decision: ReviewDecision, new_status: RuleStatus, note: str):
    rule = get_rule_or_404(db, rule_id)
    if new_status in (RuleStatus.approved, RuleStatus.rejected) and rule.status != RuleStatus.in_review:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, _("The rule is not in review"))
    # Four-eyes principle: whoever requested, submitted or created the rule must
    # not approve it themselves (admins included) – BSI separation of duties.
    #
    # The check is on the acting *account*, which is what makes it survive
    # multi-role accounts (#78): one person holding architect and change_approver
    # still cannot approve their own rule, because it is the same account on both
    # sides. They may approve everyone else's.
    if new_status == RuleStatus.approved:
        last_version = max(rule.versions, key=lambda v: v.version, default=None)
        submitter = last_version.changed_by if last_version else rule.created_by
        if user.username in {submitter, rule.created_by, rule.requestor}:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                _("Separation of duties: you cannot approve a rule you requested, "
                  "created or submitted yourself"),
            )
    # If the rule's zone relation is set to block (e.g. after a change to the zone
    # matrix), "approve" means approving its removal: the rule is deactivated and
    # set to "to remove" for each component – so it shows up for operations as a
    # pending implementation (removal from the devices).
    if new_status == RuleStatus.approved:
        # A baseline's licence can lapse without the matrix moving: reclassify
        # either zone out of "internal" and the exception no longer covers it.
        # check_zone_pair cannot see that - it only knows the cell - so the
        # extra conditions are re-asked here, where approving means putting the
        # rule back on the devices.
        if rule.ping_baseline and not rule.removal_reason:
            lapsed = ping_baseline.zone_problems(db, rule.source_zone, rule.destination_zone)
            if lapsed:
                rule.removal_reason = "; ".join(lapsed)[:255]
        verdict = check_zone_pair(db, rule.source_zone, rule.destination_zone,
                                  rule.platforms or [])
        # An explicit removal proposal counts here as well: it arises e.g. when a
        # network was moved to another zone and the rule became inadmissible as a
        # result – because one side now spans several zones, or because the zone
        # transition lacks a firewall. Neither of those surfaces in check_zone_pair.
        if not verdict.allowed or rule.removal_reason:
            rule.status = RuleStatus.deactivated
            rule.impl_status = {
                **(rule.impl_status or {}),
                **{c.name: "to remove" for c in rule.components
                   if (rule.impl_status or {}).get(c.name) != "deactivated"},
            }
            rule.version += 1
            # Two templates rather than one with the reason nested inside it: a
            # nested reason would have to be translated before it is stored,
            # which is what froze these entries in one language to begin with.
            # A reason somebody typed stays a value and is kept as typed.
            if rule.removal_reason:
                note_template = ("Removal approved: {reason} – "
                                 "remove the rule on the components ('to remove')")
                note_values = {"reason": rule.removal_reason}
            else:
                note_template = ("Removal approved: the zone relation {from_zone} → "
                                 "{to_zone} is Block – remove the rule on the "
                                 "components ('to remove')")
                note_values = {"from_zone": rule.source_zone,
                               "to_zone": rule.destination_zone}
            rule.removal_reason = ""   # the proposal has been decided
            add_version(db, rule, user, note_template, **note_values)
            # The comment and the mail below are written now and read as they
            # were written, so those do get the language of the moment.
            removal_note = render(note_template, note_values)
            db.add(Comment(rule_pk=rule.id, author=user.username,
                           text=(decision.comment + "\n" if decision.comment else "") + removal_note))
            db.commit()
            db.refresh(rule)
            from .. import change_management, notifications

            change_management.notify(
                "rule.delete_approved",
                {**change_management.rule_payload(rule),
                 "decided_by": user.username, "comment": decision.comment},
            )
            notifications.rule_decided(db, rule, True, user.username, decision.comment)
            notifications.rule_implementation_pending(
                db, rule, _("Removal approved – remove the rule on the components"))
            return rule
    rule.status = new_status
    if new_status == RuleStatus.approved:
        # Components already implemented have to be adjusted by operations after a
        # renewed approval -> implementation status "to change"
        impl = dict(rule.impl_status or {})
        for c in rule.components:
            if impl.get(c.name) == "implemented":
                impl[c.name] = "to change"
        rule.impl_status = impl
    if rule.emergency_approval_due is not None:
        # The window closes on any decision - approved, rejected or deactivated.
        # emergency_declared_at is deliberately left standing: it is what makes
        # "how often do we do this?" answerable a year from now.
        rule.emergency_approval_due = None
    rule.version += 1
    add_version(db, rule, user, note)
    if decision.comment:
        db.add(Comment(rule_pk=rule.id, author=user.username, text=decision.comment))
    db.commit()
    db.refresh(rule)
    # Optional change management webhook (e.g. ServiceNow) – fire-and-forget
    from .. import audit, change_management, notifications

    change_management.notify(
        f"rule.{new_status.value}",
        {**change_management.rule_payload(rule),
         "decided_by": user.username, "comment": decision.comment},
    )
    audit.record(db, "rule", f"rule.{new_status.value}", actor=user.username,
                 object=rule.rule_id, detail=(decision.comment or note))
    if new_status in (RuleStatus.approved, RuleStatus.rejected):
        notifications.rule_decided(db, rule, new_status == RuleStatus.approved,
                                   user.username, decision.comment)
    if new_status == RuleStatus.approved and impl_pending(rule):
        notifications.rule_implementation_pending(
            db, rule, _("Rule approved – it has to be implemented on the components"))
    return rule


@router.post("/{rule_id}/approve", response_model=RuleOut)
def approve(
    rule_id: str,
    decision: ReviewDecision,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.change_approver)),
):
    return _decide(db, rule_id, user, decision, RuleStatus.approved, "Rule approved")


@router.post("/{rule_id}/reject", response_model=RuleOut)
def reject(
    rule_id: str,
    decision: ReviewDecision,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.change_approver)),
):
    return _decide(db, rule_id, user, decision, RuleStatus.rejected, "Rule rejected")


@router.post("/{rule_id}/deactivate", response_model=RuleOut)
def deactivate(
    rule_id: str,
    decision: ReviewDecision,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.operations, Role.architect)),
):
    return _decide(db, rule_id, user, decision, RuleStatus.deactivated, "Rule deactivated")


@router.post("/{rule_id}/extend", response_model=RuleOut)
def extend_validity(
    rule_id: str,
    payload: ExtendRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations, Role.change_approver)),
):
    """Recertification: extend the validity without resetting the approval status."""
    from datetime import date

    rule = get_rule_or_404(db, rule_id)
    if rule.status not in IN_FORCE:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            _("Only approved rules can be recertified – submit expired or deactivated ones again"),
        )
    try:
        new_date = date.fromisoformat(payload.valid_until)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("Invalid date (expected YYYY-MM-DD)")) from exc
    if new_date <= date.today():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("The new valid-until date must be in the future"))
    rule.valid_until = new_date.isoformat()
    rule.version += 1
    add_version(db, rule, user, "Recertified: validity extended until {valid_until}",
                valid_until=rule.valid_until)
    if payload.comment:
        db.add(Comment(rule_pk=rule.id, author=user.username, text=payload.comment))
    db.commit()
    db.refresh(rule)
    return rule


@router.put("/{rule_id}/impl-status", response_model=RuleOut)
def set_impl_status(
    rule_id: str,
    impl_status: dict[str, str],
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.operations)),
):
    """Maintain the implementation status per component (operations), e.g. {"FW-Cluster-FFM": "implemented"}."""
    rule = get_rule_or_404(db, rule_id)
    # Validation: only known status values, and only components of this rule
    allowed_status = set(IMPL_STATUSES)
    component_names = {c.name for c in rule.components}
    for name, value in impl_status.items():
        if name not in component_names:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                _("Component '{name}' does not belong to rule {rule_id}",
                                  name=name, rule_id=rule_id))
        if value not in allowed_status:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                _("Invalid implementation status '{value}' "
                                  "(allowed: {allowed})",
                                  value=value, allowed=", ".join(sorted(allowed_status))))
    rule.impl_status = {**(rule.impl_status or {}), **impl_status}
    # The owner is the operations account that last worked the rule on the
    # components - recorded from the act itself, not maintained by hand.
    rule.owner = user.username
    rule.version += 1
    add_version(db, rule, user, "Implementation status: {impl_status}", impl_status=impl_status)
    _sync_active_status(db, rule, user)
    db.commit()
    db.refresh(rule)
    return rule


def fully_implemented(rule: Rule) -> bool:
    """Every assigned component confirms the rule is in place.

    A rule without components cannot be confirmed by anyone, so it never counts
    as implemented - otherwise it would slip into `active` for free."""
    impl = rule.impl_status or {}
    return bool(rule.components) and all(
        impl.get(c.name) == "implemented" for c in rule.components)


def _sync_active_status(db: Session, rule: Rule, user: User) -> None:
    """Moves the rule between `approved` and `active` as operations reports in.

    Only these two states are touched. A rule in review, rejected, deactivated
    or deleted is somewhere the rollout status has no say over, and promoting it
    would overwrite a decision that was made deliberately."""
    if rule.status == RuleStatus.approved and fully_implemented(rule):
        note = "Implemented on every component – the rule is active"
        rule.status = RuleStatus.active
    elif rule.status == RuleStatus.active and not fully_implemented(rule):
        note = "No longer implemented on every component – the rule is approved again"
        rule.status = RuleStatus.approved
    else:
        return
    # A version of its own, so the status change is readable in the history
    # rather than hidden inside the entry of the rollout report that triggered
    # it - and because a version number may only be used once.
    rule.version += 1
    add_version(db, rule, user, note)


# --- Versions, comments, conflicts -------------------------------------------

@router.get("/{rule_id}/implementation")
def implementation(rule_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Show, for each assigned component, how the rule is implemented there:
    Juniper set commands, Check Point mgmt_cli, or an ACI contract (with EPG resolution)."""
    from ..exporters import aci, checkpoint, juniper

    rule = get_rule_or_404(db, rule_id)
    results = []
    for component in sorted(rule.components, key=lambda c: c.name):
        entry = {
            "component_id": component.id,
            "component": component.name,
            "type": component.type.value,
            "impl_status": (rule.impl_status or {}).get(component.name, "open"),
        }
        if component.type.value == "juniper":
            entry["format"] = "juniper"
            entry["preview"] = juniper.export_rule(rule)
        elif component.type.value == "checkpoint":
            entry["format"] = "checkpoint-cli"
            lines = checkpoint.export_cli([rule]).splitlines()
            entry["preview"] = "\n".join(
                line for line in lines
                if line.startswith(("mgmt_cli add", "#")) and not line.startswith("#!")
            )
        else:  # aci
            model = aci.build_contract_model([rule], db)
            entry["format"] = "yaml"
            entry["preview"] = aci.export_yaml([rule], db)
            if model["contracts"]:
                contract = model["contracts"][0]
                entry["aci"] = {
                    "consumer": contract["consumer"],
                    "provider": contract["provider"],
                    "contract": contract["name"],
                    "filters": sorted(contract["subjects"].keys()),
                    "service_graph": contract["service_graph"],
                }
            else:
                entry["aci"] = None
                entry["warning"] = _(
                    "No EPG mapping maintained for source/destination – the export falls back "
                    "to a single contract. Maintain it on the Objects page under ACI EPGs."
                )
        results.append(entry)
    if rule.status.value != "approved":
        for entry in results:
            entry.setdefault(
                "note", _("The rule is in status '{status}' – the preview shows the future implementation",
                          status=_(rule.status.value))
            )
    return {"rule_id": rule.rule_id, "implementations": results}


@router.get("/{rule_id}/versions", response_model=list[RuleVersionOut])
def versions(rule_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return get_rule_or_404(db, rule_id).versions


@router.post("/{rule_id}/comments", response_model=CommentOut, status_code=201)
def add_comment(
    rule_id: str,
    payload: CommentCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rule = get_rule_or_404(db, rule_id)
    comment = Comment(rule_pk=rule.id, author=user.username, text=payload.text)
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment


@router.get("/{rule_id}/conflicts", response_model=list[ConflictOut])
def conflicts(rule_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    rule = get_rule_or_404(db, rule_id)
    others = active_rules(db).filter(Rule.status.notin_((RuleStatus.deactivated, RuleStatus.deleted)),
                                     Rule.vrf_id == rule.vrf_id).all()
    warnings = find_conflicts(rule, others)
    # In addition: violations and advisories from the zone communication matrix
    zone_result = check_zone_pair(db, rule.source_zone, rule.destination_zone, rule.platforms or [])
    for msg in zone_result.messages:
        if zone_result.policy in ("intra",):
            continue
        warnings.append(
            {
                "rule_id": rule.rule_id,
                "other_rule_id": f"{rule.source_zone or '?'} → {rule.destination_zone or '?'}",
                "kind": "zone-blocked" if not zone_result.allowed else "zone-notice",
                "detail": msg,
            }
        )
    return warnings


@router.get("/{rule_id}/risk")
def rule_risk(rule_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Risk analysis of a rule (any-to-any, overly broad networks, risky services;
    severity weighted by the protection level of the destination zone)."""
    from ..risk import assess_rule

    return assess_rule(db, get_rule_or_404(db, rule_id))


@router.post("/risk/assess")
def risk_assess(payload: ResolveRequest, db: Session = Depends(get_db),
                _user: User = Depends(get_current_user)):
    """Live risk assessment for the rule form (without a stored rule)."""
    from types import SimpleNamespace

    from ..risk import assess_rule

    vrf_obj = get_vrf(db, payload.vrf or None)
    draft = SimpleNamespace(
        source=[e.model_dump() for e in payload.source],
        destination=[e.model_dump() for e in payload.destination],
        services=[s.model_dump() for s in payload.services] if getattr(payload, "services", None) else [],
        source_zone=payload.source_zone or "",
        destination_zone=payload.destination_zone or "",
        vrf_id=vrf_obj.id,
    )
    return assess_rule(db, draft)
