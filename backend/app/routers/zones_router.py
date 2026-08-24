from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..database import get_db
from ..domain_values import PAP_LEVELS, PROTECTION_LEVELS
from ..messages import _, render
from ..models import (
    IN_FORCE,
    Comment,
    Role,
    Rule,
    RuleStatus,
    SecurityComponent,
    User,
    Zone,
    ZoneNetwork,
    ZonePolicy,
    ZonePolicyChange,
    active_rules,
    utcnow,
)
from ..schemas import (
    ZoneCheckOut,
    ZoneCreate,
    ZoneMatrixOut,
    ZoneOut,
    ZonePolicyOut,
    ZonePolicySet,
)
from ..zone_check import check_zone_pair, find_zone, get_policy, zone_ref

router = APIRouter(prefix="/api/zones", tags=["zones"])


@router.get("", response_model=list[ZoneOut])
def list_zones(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return db.query(Zone).order_by(Zone.sort_order, Zone.name).all()


def next_zone_code(db: Session) -> str:
    """Next free zone ID (Z010, Z020, … in steps of ten)."""
    import re
    max_num = 0
    for (code,) in db.query(Zone.code).all():
        m = re.match(r"^Z(\d+)$", (code or "").upper())
        if m:
            max_num = max(max_num, int(m.group(1)))
    nxt = (max_num // 10 + 1) * 10 if max_num else 10
    return f"Z{nxt:03d}"


@router.get("/next-code")
def get_next_code(db: Session = Depends(get_db), _user: User = Depends(require_roles(Role.architect))):
    return {"code": next_zone_code(db)}


@router.post("", response_model=ZoneOut, status_code=201)
def create_zone(
    payload: ZoneCreate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect)),
):
    code = (payload.code or "").strip()
    if not code:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("Zone ID (code) is required"))
    if find_zone(db, code) or find_zone(db, payload.name):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("A zone with ID '{code}' or name '{name}' already exists",
                              code=code, name=payload.name))
    data = payload.model_dump()
    data["code"] = code
    zone = Zone(**data)
    db.add(zone)
    db.commit()
    db.refresh(zone)
    return zone



@router.get("/networks")
def list_networks(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """All network assignments (basis of the networks page and of future imports)."""
    return [
        {
            "id": n.id, "cidr": n.cidr, "zone": n.zone.name, "zone_id": n.zone_id,
            "vrf": n.vrf.name if n.vrf else "", "description": n.description, "source": n.source,
        }
        for n in db.query(ZoneNetwork).order_by(ZoneNetwork.cidr).all()
    ]


@router.put("/networks/{network_id}")
def update_network(
    network_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Change a network assignment. Description changes take effect immediately;
    CIDR and zone changes are security-relevant and go through the approval
    workflow as a request (two change approvers)."""
    network = db.get(ZoneNetwork, network_id)
    if not network:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Network assignment not found"))
    from ..component_resolution import normalize_ip

    new_cidr = normalize_ip(payload["cidr"]) if payload.get("cidr") else network.cidr
    if new_cidr is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("'{cidr}' is not a valid network (CIDR) and not 'any'",
                              cidr=payload["cidr"]))
    new_zone = (payload.get("zone") or network.zone.name).strip()
    needs_approval = (new_cidr != network.cidr
                      or new_zone.upper() != network.zone.name.upper())

    result = None
    if needs_approval:
        result = _create_batch(db, user, [{
            "type": "net_update", "network_id": network.id,
            "cidr": new_cidr, "zone": new_zone,
        }], payload.get("comment", ""))
    if "description" in payload and payload["description"] != network.description:
        network.description = payload["description"]
        db.commit()
        if not result:
            result = {"status": "applied", "id": network.id,
                      "detail": _("Description updated")}
    if not result:
        result = {"status": "unchanged", "id": network.id, "detail": _("No change")}
    return result


@router.post("/{name}/networks", status_code=201)
def add_zone_network(
    name: str,
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Assign a network to a zone – submitted as a request through the approval
    workflow (two change approvers), like every zone change."""
    if not find_zone(db, name):
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Zone not found"))
    return _create_batch(db, user, [{
        "type": "net_add", "zone": name, "cidr": payload.get("cidr", ""),
        "description": payload.get("description", ""), "vrf": payload.get("vrf") or None,
    }], payload.get("comment", ""))


@router.delete("/networks/{network_id}")
def delete_zone_network(
    network_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Remove a network assignment – submitted as a request through the approval workflow."""
    return _create_batch(db, user, [{"type": "net_delete", "network_id": network_id}], "")


@router.put("/{name}/components")
def set_zone_components(
    name: str,
    payload: dict,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect)),
):
    """Define which firewall cluster(s) the zone is attached to."""
    zone = find_zone(db, name)
    if not zone:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Zone not found"))
    ids = payload.get("component_ids") or []
    components = (
        db.query(SecurityComponent).filter(SecurityComponent.id.in_(ids)).all() if ids else []
    )
    missing = set(ids) - {c.id for c in components}
    if missing:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("Unknown component(s): {components}", components=sorted(missing)))
    non_fw = [c.name for c in components if c.type.value == "aci"]
    if non_fw:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _("Zones attach to firewall clusters – ACI is not a zone transition: {components}",
              components=", ".join(non_fw)),
        )
    zone.components = components
    db.commit()
    return {"zone": zone.name, "component_ids": sorted(c.id for c in components)}


@router.put("/{name}/meta", response_model=ZoneOut)
def set_zone_meta(
    name: str,
    payload: dict,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect)),
):
    """Maintain the zone's BSI documentation: owner, description and the protection
    level per security objective (CIA, each normal | high | very high)."""
    zone = find_zone(db, name)
    if not zone:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Zone not found"))
    for field in ("owner", "description", "code"):
        if field in payload:
            setattr(zone, field, str(payload[field] or "").strip())
    for field in ("cia_c", "cia_i", "cia_a"):
        if field in payload:
            value = str(payload[field] or "").strip().lower()
            if value not in PROTECTION_LEVELS:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                    _("Protection level must be one of {levels}",
                                      levels=", ".join(PROTECTION_LEVELS)))
            setattr(zone, field, value)
    db.commit()
    db.refresh(zone)
    return zone


@router.put("/{name}/pap-level", response_model=ZoneOut)
def set_pap_level(
    name: str,
    payload: dict,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect)),
):
    """Change a zone's BSI P-A-P classification (external | pap | internal)."""
    zone = find_zone(db, name)
    if not zone:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Zone not found"))
    level = (payload.get("pap_level") or "").strip().lower()
    if level not in PAP_LEVELS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("pap_level must be one of {levels}", levels=", ".join(PAP_LEVELS)))
    zone.pap_level = level
    db.commit()
    db.refresh(zone)
    return zone


@router.delete("/{name}")
def delete_zone(
    name: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Deleting a zone goes through the approval workflow like every zone change
    (two change approvers). Nothing is deleted directly – the check for rules and
    network assignments still using it happens on request and on application."""
    return _create_batch(db, user, [{"type": "zone_delete", "name": name}], "")


@router.get("/overview")
def overview(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Zone overview: per zone, the firewall clusters through which it is reachable
    (derived from the zone's active rules). ACI components are reported separately –
    they are not a zone transition in the sense of the BSI definition."""
    zones = db.query(Zone).order_by(Zone.sort_order, Zone.name).all()
    rules = active_rules(db).filter(Rule.status != RuleStatus.deactivated).all()
    firewalls_total = db.query(SecurityComponent).filter(
        SecurityComponent.type != "aci"
    ).count()

    result = []
    for zone in zones:
        zname = zone_ref(zone).upper()
        zone_rules = [
            r for r in rules
            if (r.source_zone or "").upper() == zname or (r.destination_zone or "").upper() == zname
        ]
        # "Attached to": the zone's explicitly maintained firewall attachment;
        # ACI fabrics are still derived from the intra-zone rules
        firewalls = {c.id: c for c in zone.components if c.type.value != "aci"}
        aci = {}
        for rule in zone_rules:
            # ACI contracts are provided at the destination segment (provider EPG) –
            # the fabric therefore counts only for the rule's destination zone
            if (rule.destination_zone or "").upper() != zname:
                continue
            for component in rule.components:
                if component.type.value == "aci":
                    aci[component.id] = component
        result.append(
            {
                "name": zone.name,
                "code": zone.code,
                "description": zone.description,
                "pap_level": zone.pap_level,
                "owner": zone.owner,
                "protection_level": zone.protection_level,
                "cia_c": zone.cia_c, "cia_i": zone.cia_i, "cia_a": zone.cia_a,
                "rule_count": len(zone_rules),
                "firewalls": [
                    {"id": c.id, "name": c.name, "type": c.type.value,
                     "location": c.location, "ns_tier": c.ns_tier}
                    for c in sorted(firewalls.values(), key=lambda c: c.name)
                ],
                "aci": [
                    {"id": c.id, "name": c.name}
                    for c in sorted(aci.values(), key=lambda c: c.name)
                ],
                "networks": [
                    {"id": n.id, "cidr": n.cidr, "description": n.description}
                    for n in zone.networks
                ],
                "has_firewall": bool(firewalls),
            }
        )
    return {"zones": result, "firewalls_total": firewalls_total}


@router.get("/plan/mermaid")
def zone_plan_mermaid(
    download: bool = Query(False),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """BSI-conformant zone plan as a Mermaid flowchart (NET.1.1/NET.3.2) – for
    audits, wikis and operations documentation; built entirely from live data."""
    from fastapi.responses import PlainTextResponse

    from ..zoneplan import build_mermaid

    content = build_mermaid(db, generated_at=utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    headers = {}
    if download:
        headers["Content-Disposition"] = 'attachment; filename="permitra-zone-plan.mmd"'
    return PlainTextResponse(content, media_type="text/plain", headers=headers)


@router.get("/matrix", response_model=ZoneMatrixOut)
def matrix(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    zones = db.query(Zone).order_by(Zone.sort_order, Zone.name).all()
    policies = db.query(ZonePolicy).all()
    return ZoneMatrixOut(
        zones=zones,
        policies=[
            ZonePolicyOut(
                from_zone=zone_ref(p.from_zone),
                to_zone=zone_ref(p.to_zone),
                policy=p.policy,
                temporary=p.temporary,
                note=p.note,
            )
            for p in policies
        ],
    )


def _pending_net_conflict(db: Session, cidr: str, network_id: int | None = None):
    """Is a request for this CIDR or this assignment already awaiting approval?"""
    pending = (
        db.query(ZonePolicyChange)
        .filter(ZonePolicyChange.change_type.in_(("net_add", "net_update", "net_delete")),
                ZonePolicyChange.status == "pending")
        .all()
    )
    for c in pending:
        if c.to_zone == cidr:
            return c
        if network_id and (c.extra or {}).get("network_id") == network_id:
            return c
    return None


def _create_batch(db: Session, user: User, items: list[dict], comment: str) -> dict:
    """Create a batch request. items:
    {"type": "policy", "from_zone", "to_zone", "policy", "temporary"},
    {"type": "zone_create", "name", "pap_level", "description"} or
    {"type": "net_add"|"net_update"|"net_delete", ...} (network assignments)."""
    import uuid

    from ..component_resolution import normalize_ip
    from ..vrf import get_vrf

    if not items:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, _("No changes included"))
    # A zone created in this same batch counts as existing for the rest of it:
    # the zones are applied first, then the cells. It has to answer to both its
    # name AND its code, because everything that references a zone - matrix
    # cells, network assignments - does so by `code or name`, and the interface
    # sends the code. Collecting only the name made "new zone plus its matrix
    # relations in one request" fail with "Zone 'Z130' not found".
    new_zone_names = {
        value.strip().upper()
        for i in items if i.get("type") == "zone_create"
        for value in (i.get("name") or "", i.get("code") or "")
        if value.strip()
    }
    batch_id = str(uuid.uuid4())
    rows = []
    for item in items:
        if item.get("type") == "zone_create":
            name = (item.get("name") or "").strip()
            code = (item.get("code") or "").strip()
            if not name:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, _("Zone name is missing"))
            if not code:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, _("Zone ID (code) is missing"))
            if find_zone(db, name) or find_zone(db, code):
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    _("A zone with ID '{code}' or name '{name}' already exists",
                                      code=code, name=name))
            level = (item.get("pap_level") or "internal").lower()
            if level not in PAP_LEVELS:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                    _("pap_level must be one of {levels}",
                                      levels=", ".join(PAP_LEVELS)))
            # to_zone carries the zone ID (otherwise unused for zone_create);
            # everything else a zone has goes into extra
            cia = {}
            for f in ("cia_c", "cia_i", "cia_a"):
                v = (item.get(f) or "normal").strip().lower()
                if v not in PROTECTION_LEVELS:
                    raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                        _("Protection level must be one of {levels}",
                                          levels=", ".join(PROTECTION_LEVELS)))
                cia[f] = v
            # The owner and the firewall attachment belong to the request, not to
            # a follow-up edit: a zone that comes into being without them needs a
            # second change nobody reviewed, and an unattached zone is invisible
            # to the drift comparison until somebody notices.
            cia["owner"] = (item.get("owner") or "").strip()[:128]
            requested_components = item.get("component_ids") or []
            known = {c.id for c in db.query(SecurityComponent).all()}
            unknown = [c for c in requested_components if c not in known]
            if unknown:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                    _("Unknown component: {ids}",
                                      ids=", ".join(str(c) for c in unknown)))
            cia["component_ids"] = requested_components
            rows.append(ZonePolicyChange(
                batch_id=batch_id, change_type="zone_create",
                from_zone=name, to_zone=code, old_policy=None, new_policy=level,
                requested_by=user.username, comment=item.get("description", ""),
                extra=cia,
            ))
            continue
        if item.get("type") == "zone_delete":
            name = (item.get("name") or "").strip()
            zone = find_zone(db, name)
            if not zone:
                raise HTTPException(status.HTTP_404_NOT_FOUND, _("Zone '{name}' not found", name=name))
            # Deliberately including soft-deleted rules: they still reference this
            # zone, and their history would otherwise lose its point of reference.
            used = db.query(Rule).filter(
                (Rule.source_zone.ilike(zone_ref(zone))) | (Rule.destination_zone.ilike(zone_ref(zone)))
            ).count()
            if used:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    _("Zone '{name}' is used by {used} rule(s)",
                                      name=zone.name, used=used))
            nets = db.query(ZoneNetwork).filter(ZoneNetwork.zone_id == zone.id).count()
            if nets:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    _("Zone '{name}' still has {nets} network assignment(s) – "
                                      "move or remove them first",
                                      name=zone.name, nets=nets))
            rows.append(ZonePolicyChange(
                batch_id=batch_id, change_type="zone_delete",
                from_zone=zone_ref(zone), to_zone="", old_policy=None, new_policy="delete",
                requested_by=user.username, comment=comment,
            ))
            continue
        if item.get("type") == "net_add":
            norm = normalize_ip(item.get("cidr") or "")
            if norm is None:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                    _("'{cidr}' is not a valid network (CIDR) and not 'any'",
                                      cidr=item.get("cidr")))
            zone_name = (item.get("zone") or "").strip()
            if not find_zone(db, zone_name) and zone_name.upper() not in new_zone_names:
                raise HTTPException(status.HTTP_404_NOT_FOUND,
                                    _("Zone '{name}' not found", name=zone_name))
            vrf = get_vrf(db, item.get("vrf") or None)
            existing = db.query(ZoneNetwork).filter(ZoneNetwork.cidr == norm,
                                                    ZoneNetwork.vrf_id == vrf.id).first()
            if existing:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    _("{cidr} is already assigned to zone '{zone}' "
                                      "in environment '{vrf}'",
                                      cidr=norm, zone=existing.zone.name, vrf=vrf.name))
            if _pending_net_conflict(db, norm):
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    _("A request for {cidr} is already waiting for approval",
                                      cidr=norm))
            rows.append(ZonePolicyChange(
                batch_id=batch_id, change_type="net_add",
                from_zone=zone_name, to_zone=norm, old_policy=None, new_policy="add",
                requested_by=user.username, comment=comment,
                extra={"vrf": vrf.name, "description": item.get("description", ""),
                       "source": item.get("source", "manual")},
            ))
            continue
        if item.get("type") in ("net_update", "net_delete"):
            network = db.get(ZoneNetwork, item.get("network_id") or 0)
            if not network:
                raise HTTPException(status.HTTP_404_NOT_FOUND, _("Network assignment not found"))
            if _pending_net_conflict(db, network.cidr, network.id):
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    _("A request for {cidr} is already waiting for approval",
                                      cidr=network.cidr))
            if item["type"] == "net_delete":
                rows.append(ZonePolicyChange(
                    batch_id=batch_id, change_type="net_delete",
                    from_zone=network.zone.name, to_zone=network.cidr,
                    old_policy=None, new_policy="delete",
                    requested_by=user.username, comment=comment,
                    extra={"network_id": network.id, "vrf": network.vrf.name if network.vrf else ""},
                ))
                continue
            new_cidr = network.cidr
            if item.get("cidr"):
                norm = normalize_ip(item["cidr"])
                if norm is None:
                    raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                        _("'{cidr}' is not a valid network (CIDR) and not 'any'",
                                          cidr=item["cidr"]))
                duplicate = db.query(ZoneNetwork).filter(
                    ZoneNetwork.cidr == norm, ZoneNetwork.vrf_id == network.vrf_id,
                    ZoneNetwork.id != network.id).first()
                if duplicate:
                    raise HTTPException(status.HTTP_409_CONFLICT,
                                        _("{cidr} is already assigned to zone '{zone}'",
                                          cidr=norm, zone=duplicate.zone.name))
                new_cidr = norm
            new_zone_name = (item.get("zone") or network.zone.name).strip()
            if not find_zone(db, new_zone_name) and new_zone_name.upper() not in new_zone_names:
                raise HTTPException(status.HTTP_404_NOT_FOUND,
                                    _("Zone '{name}' not found", name=new_zone_name))
            if new_cidr == network.cidr and new_zone_name.upper() == network.zone.name.upper():
                continue  # no security-relevant change
            rows.append(ZonePolicyChange(
                batch_id=batch_id, change_type="net_update",
                from_zone=new_zone_name, to_zone=new_cidr, old_policy=None, new_policy="update",
                requested_by=user.username, comment=comment,
                extra={"network_id": network.id, "old_cidr": network.cidr,
                       "old_zone": network.zone.name},
            ))
            continue
        # Zone matrix cell
        from_name, to_name = item.get("from_zone", ""), item.get("to_zone", "")
        zone_a, zone_b = find_zone(db, from_name), find_zone(db, to_name)
        for name, zone in ((from_name, zone_a), (to_name, zone_b)):
            if not zone and name.strip().upper() not in new_zone_names:
                raise HTTPException(status.HTTP_404_NOT_FOUND, _("Zone '{name}' not found", name=name))
        if from_name.strip().upper() == to_name.strip().upper():
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                _("An intra-zone relation is not maintained"))
        current = get_policy(db, zone_a, zone_b) if zone_a and zone_b else None
        new_policy = item.get("policy")
        if new_policy not in ("allow_only", "block_all"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                _("Invalid policy '{new_policy}'", new_policy=new_policy))
        if current and current.policy.value == new_policy and current.temporary == bool(item.get("temporary")):
            continue  # no change -> skip
        pending = (
            db.query(ZonePolicyChange)
            .filter(ZonePolicyChange.change_type == "policy",
                    ZonePolicyChange.from_zone == (zone_ref(zone_a) if zone_a else from_name),
                    ZonePolicyChange.to_zone == (zone_ref(zone_b) if zone_b else to_name),
                    ZonePolicyChange.status == "pending")
            .first()
        )
        if pending:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                _("A request for {from_zone} → {to_zone} is already waiting for approval",
                  from_zone=from_name, to_zone=to_name),
            )
        rows.append(ZonePolicyChange(
            batch_id=batch_id, change_type="policy",
            from_zone=zone_ref(zone_a) if zone_a else from_name,
            to_zone=zone_ref(zone_b) if zone_b else to_name,
            old_policy=current.policy.value if current else None,
            new_policy=new_policy,
            old_temporary=current.temporary if current else False,
            new_temporary=bool(item.get("temporary")),
            requested_by=user.username, comment=comment,
        ))
    if not rows:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, _("No change compared to the current state"))
    db.add_all(rows)
    db.commit()
    return {"status": "pending", "batch_id": batch_id, "items": len(rows),
            "detail": _("{count} change(s) requested – waiting for approval by two change approvers",
                        count=len(rows))}


@router.post("/matrix/changes")
def request_change_batch(
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Batch request: several zone matrix changes and new zones in a single request."""
    return _create_batch(db, user, payload.get("items") or [], payload.get("comment", ""))


@router.put("/matrix/{from_name}/{to_name}")
def request_policy_change(
    from_name: str,
    to_name: str,
    payload: ZonePolicySet,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Single request (compatibility): equivalent to a batch request with one entry."""
    return _create_batch(db, user, [{
        "type": "policy", "from_zone": from_name, "to_zone": to_name,
        "policy": payload.policy.value, "temporary": payload.temporary,
    }], payload.note)


def _affected_rules(db: Session, from_zone: str, to_zone: str, statuses=None):
    """Active rules of the zone relation from -> to (for the impact analysis of
    zone matrix changes from allow to block)."""
    statuses = statuses or (*IN_FORCE, RuleStatus.in_review, RuleStatus.draft)
    return (
        active_rules(db)
        .filter(Rule.source_zone.ilike(from_zone), Rule.destination_zone.ilike(to_zone),
                Rule.status.in_(statuses))
        .order_by(Rule.rule_id)
        .all()
    )


def _rules_touching_network(db: Session, *cidrs: str, vrf_id: int | None = None):
    """Active rules whose source or destination lies within one of the networks.

    What matters is whether the rule's address is contained in the network (or
    equals it) – only then is its zone derived from precisely this entry. A more
    broadly scoped rule network takes its zone from elsewhere and is therefore not
    affected. When a network is moved, both the old and the new network count,
    because the request may change the CIDR as well."""
    from ..validation import parse_network

    networks = [n for n in (parse_network(c) for c in cidrs if c) if n is not None]
    if not networks:
        return []

    def contained(ip: str) -> bool:
        addr = parse_network((ip or "").strip())
        if addr is None:
            return False
        return any(addr.version == n.version and (addr == n or addr.subnet_of(n))
                   for n in networks)

    query = active_rules(db).filter(
        Rule.status.in_((*IN_FORCE, RuleStatus.in_review, RuleStatus.draft)))
    if vrf_id is not None:
        query = query.filter(Rule.vrf_id == vrf_id)
    hits = []
    for rule in query.order_by(Rule.rule_id).all():
        for entries in (rule.source, rule.destination):
            if any(contained(e.get("ip")) for e in entries or []):
                hits.append(rule)
                break
    return hits


class _NetworkView:
    """Lightweight view of a network assignment – lets a move be computed through
    without anticipating it in the database."""

    __slots__ = ("cidr", "zone")

    def __init__(self, cidr: str, zone: Zone):
        self.cidr, self.zone = cidr, zone


def _zone_resolver(networks):
    """Return a function that maps a list of addresses to (zone, all hits)."""
    from ..zone_check import zone_for_ip

    def resolve(entries):
        hits = set()
        for entry in entries or []:
            zone = zone_for_ip((entry.get("ip") or "").strip(), networks)
            if zone is not None:
                hits.add(zone_ref(zone))
        return (hits.copy().pop() if len(hits) == 1 else None), hits

    return resolve


def _assess_rules(db: Session, rules, resolve) -> list[dict]:
    """Assess rules against a (possibly hypothetical) zone state (finding H6).

    When a network is moved into another zone, the zone relation of existing rules
    changes without the rule itself being touched: an intra-zone rule can silently
    become a zone transition. The stored zones are derived data and are therefore
    recomputed.

    A rule is inadmissible if the new relation is set to block in the zone matrix,
    if the now cross-zone traffic has no firewall (BSI), or if one side of the rule
    suddenly spans several zones."""
    results = []
    for rule in rules:
        new_src, hits_src = resolve(rule.source)
        new_dst, hits_dst = resolve(rule.destination)
        old_src, old_dst = rule.source_zone or "", rule.destination_zone or ""
        ambiguous = len(hits_src) > 1 or len(hits_dst) > 1
        src, dst = new_src or old_src, new_dst or old_dst

        assessment = check_zone_pair(db, src, dst, rule.platforms)
        messages = list(assessment.messages)
        admissible = assessment.allowed and not ambiguous
        reason = ""
        if ambiguous:
            reason = _("One side of the rule spans several zones – the rule has to be split")
            messages.insert(0, reason)
        elif not assessment.allowed:
            reason = next((m for m in assessment.messages), _("not permitted by the matrix"))
        # SIM102 rationale: kept nested - the outer test scopes this to cross-zone rules,
        # the inner one is the separate BSI firewall requirement.
        if admissible and (src or "").upper() != (dst or "").upper():  # noqa: SIM102
            if rule.components and not any(c.type.value != "aci" for c in rule.components):
                admissible = False
                reason = _("A zone transition requires a firewall – Cisco ACI alone is not sufficient (BSI)")
                messages.append(reason)

        results.append({
            "rule": rule,
            "rule_id": rule.rule_id,
            "name": rule.name,
            "status": rule.status.value,
            "from_zones": [old_src, old_dst],
            "to_zones": [src, dst],
            "zones_changed": (src or "") != old_src or (dst or "") != old_dst,
            "admissible": admissible,
            "reason": reason,        # the one decisive reason (short, for display)
            "messages": messages,    # full rationale (history/comment)
        })
    return results


def _preview_network_move(db: Session, network: ZoneNetwork, target_zone: Zone,
                          new_cidr: str) -> list[dict]:
    """Compute a network move through WITHOUT applying it – for the impact analysis
    shown to the approvers before they decide."""
    existing = db.query(ZoneNetwork).filter(ZoneNetwork.vrf_id == network.vrf_id).all()
    simulated = [_NetworkView(n.cidr, n.zone) for n in existing if n.id != network.id]
    simulated.append(_NetworkView(new_cidr or network.cidr, target_zone))
    rules = _rules_touching_network(db, network.cidr, new_cidr,
                                    vrf_id=network.vrf_id)
    return _assess_rules(db, rules, _zone_resolver(simulated))


def reassess_after_network_move(db: Session, network: ZoneNetwork) -> list[dict]:
    """Reassess after a move that has already been applied (actual state)."""
    existing = db.query(ZoneNetwork).filter(ZoneNetwork.vrf_id == network.vrf_id).all()
    rules = _rules_touching_network(db, network.cidr, vrf_id=network.vrf_id)
    return _assess_rules(db, rules, _zone_resolver(existing))


def _apply_reassessment(db: Session, network: ZoneNetwork, user, batch_id: str) -> list[dict]:
    """Apply the reassessment after a network move (finding H6).

    The derived zones are brought up to date. If a rule has become inadmissible as
    a result, it goes back into review and a removal is proposed for it – it cannot
    be approved again until the underlying cause is fixed."""
    from .rules_router import add_version

    recorded = []
    for entry in reassess_after_network_move(db, network):
        rule = entry["rule"]
        old_src, old_dst = entry["from_zones"]
        new_src, new_dst = entry["to_zones"]
        short_id = batch_id[:8]

        if entry["zones_changed"]:
            rule.source_zone, rule.destination_zone = new_src, new_dst

        if not entry["admissible"]:
            # Short and telling, for the display …
            rule.removal_reason = (
                f"{new_src} → {new_dst}: {entry['reason']}")[:255]
            # … the full rationale belongs in the history and the comment.
            # The reasons used to be appended after the sentence was already
            # translated, which left the note untranslatable as a whole. They
            # are a value now, so the template stays one catalogue entry.
            template = ("Network {cidr} moved to {zone} "
                        "(request {short_id}): {old_src} → {old_dst} is now "
                        "{new_src} → {new_dst} and no longer permitted – {reasons}")
            values = {"cidr": network.cidr, "zone": zone_ref(network.zone),
                      "short_id": short_id, "old_src": old_src, "old_dst": old_dst,
                      "new_src": new_src, "new_dst": new_dst,
                      "reasons": "; ".join(entry["messages"][:3])}
            if rule.status != RuleStatus.in_review:
                rule.status = RuleStatus.in_review
            rule.version += 1
            add_version(db, rule, user, template, **values)
            db.add(Comment(rule_pk=rule.id, author=user.username,
                           text=render(template, values)))
        elif entry["zones_changed"]:
            rule.version += 1
            add_version(db, rule, user,
                        "Network {cidr} moved to {zone} "
                        "(request {short_id}): zones re-derived, {old_src} → {old_dst} "
                        "becomes {new_src} → {new_dst}; still permitted",
                        cidr=network.cidr, zone=zone_ref(network.zone), short_id=short_id,
                        old_src=old_src, old_dst=old_dst, new_src=new_src, new_dst=new_dst)
            rule.removal_reason = ""   # an earlier removal proposal is now moot

        if entry["zones_changed"] or not entry["admissible"]:
            recorded.append({
                "rule_id": rule.rule_id,
                "from": f"{old_src} → {old_dst}",
                "to": f"{new_src} → {new_dst}",
                "admissible": entry["admissible"],
            })
    return recorded



@router.get("/matrix/changes")
def list_changes(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Change requests and history of the zone communication matrix (newest first).

    Pending requests that switch a relation to block carry the impact analysis:
    which active rules of that relation would be affected (approved ones would be
    sent back into review once the request is approved)."""
    changes = (
        db.query(ZonePolicyChange)
        .order_by(ZonePolicyChange.status != "pending", ZonePolicyChange.requested_at.desc())
        .limit(200)
        .all()
    )
    def impact(c):
        """Impact analysis of pending requests – the approvers should know the
        consequences before they decide."""
        if c.status != "pending":
            return {}
        # Zone matrix change to block: the affected rules of that relation
        if c.change_type == "policy" and c.new_policy == "block_all":
            rules = _affected_rules(db, c.from_zone, c.to_zone)
            return {
                "affected_count": len(rules),
                "affected_rules": [
                    {"rule_id": r.rule_id, "name": r.name, "status": r.status.value}
                    for r in rules[:50]
                ],
            }
        # Network move: preview of the reassessment (finding H6). It runs against
        # the FUTURE state, without changing anything.
        if c.change_type == "net_update":
            network = db.get(ZoneNetwork, (c.extra or {}).get("network_id") or 0)
            zone = find_zone(db, c.from_zone)
            if not network or not zone:
                return {}
            preview = _preview_network_move(db, network, zone, c.to_zone)
            inadmissible = [e for e in preview if not e["admissible"]]
            return {
                "affected_count": len(preview),
                "removal_count": len(inadmissible),
                "affected_rules": [
                    {"rule_id": e["rule_id"], "name": e["name"], "status": e["status"],
                     "from": " → ".join(e["from_zones"]), "to": " → ".join(e["to_zones"]),
                     "admissible": e["admissible"],
                     "reason": "; ".join(e["messages"][:2])}
                    for e in preview[:50]
                ],
            }
        return {}

    return [
        {
            "id": c.id, "batch_id": c.batch_id, "change_type": c.change_type,
            "from_zone": c.from_zone, "to_zone": c.to_zone,
            **impact(c),
            "old_policy": c.old_policy, "new_policy": c.new_policy,
            "old_temporary": c.old_temporary, "new_temporary": c.new_temporary,
            "status": c.status, "requested_by": c.requested_by,
            "requested_at": c.requested_at.isoformat() if c.requested_at else None,
            "first_approved_by": c.first_approved_by,
            "first_approved_at": c.first_approved_at.isoformat() if c.first_approved_at else None,
            "decided_by": c.decided_by,
            "decided_at": c.decided_at.isoformat() if c.decided_at else None,
            "comment": c.comment,
            "extra": c.extra or {},
        }
        for c in changes
    ]


def _decide_change(db: Session, change_id: int, user: User, approve: bool, comment: str):
    """Decide the ENTIRE batch request the entry belongs to.

    The batch rows are locked for the duration of the decision (SELECT … FOR
    UPDATE, a no-op on SQLite) so that two concurrent approvals cannot both pass
    as the 'first approval' (avoiding a TOCTOU race)."""
    change = db.get(ZonePolicyChange, change_id)
    if not change:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Request not found"))
    if change.batch_id:
        batch = (
            db.query(ZonePolicyChange)
            .filter(ZonePolicyChange.batch_id == change.batch_id,
                    ZonePolicyChange.status == "pending")
            .with_for_update()
            .all()
        )
    else:
        batch = (
            db.query(ZonePolicyChange)
            .filter(ZonePolicyChange.id == change.id)
            .with_for_update()
            .all()
        )
    # Re-check after taking the lock (the status may have changed between the read
    # and the lock)
    if not batch or change.status != "pending":
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            _("The request is already '{status}'", status=_(change.status)))
    # Four-eyes principle without exception – not even admins may approve their own
    # requests (BSI: separation of duties)
    if any(c.requested_by == user.username for c in batch):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            _("Separation of duties: you cannot approve your own request"),
        )
    # Zone and matrix changes need TWO approvals by two different change approvers
    if approve and not change.first_approved_by:
        for item in batch:
            item.first_approved_by = user.username
            item.first_approved_at = utcnow()
            if comment:
                item.comment = (item.comment + "\n" if item.comment else "") + comment
        db.commit()
        return {"status": "pending", "batch_id": change.batch_id, "items": len(batch),
                "approvals": "1/2",
                "detail": _("First approval granted – a second approval by a different "
                            "change approver is required")}
    if approve and change.first_approved_by == user.username:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            _("The second approval must come from a different change approver"),
        )
    reviews_reset = []
    reassessed: list[dict] = []
    if approve:
        # Create the zones first, then apply the matrix cells
        for item in batch:
            if item.change_type == "zone_create" and not find_zone(db, item.from_zone):
                cia = item.extra or {}
                zone = Zone(name=item.from_zone, code=item.to_zone, pap_level=item.new_policy,
                            description=item.comment, sort_order=db.query(Zone).count(),
                            owner=cia.get("owner", ""),
                            cia_c=cia.get("cia_c", "normal"), cia_i=cia.get("cia_i", "normal"),
                            cia_a=cia.get("cia_a", "normal"))
                # The attachment was part of what was approved, so it is applied
                # here rather than left for someone to add afterwards.
                ids = cia.get("component_ids") or []
                if ids:
                    zone.components = (db.query(SecurityComponent)
                                       .filter(SecurityComponent.id.in_(ids)).all())
                db.add(zone)
            elif item.change_type == "zone_delete":
                zone = find_zone(db, item.from_zone)
                if zone:
                    # Re-run the integrity check at application time (fail-secure)
                    # Deliberately including soft-deleted rules (see above)
                    used = db.query(Rule).filter(
                        (Rule.source_zone.ilike(zone.name)) | (Rule.destination_zone.ilike(zone.name))
                    ).count()
                    nets = db.query(ZoneNetwork).filter(ZoneNetwork.zone_id == zone.id).count()
                    if used or nets:
                        raise HTTPException(
                            status.HTTP_409_CONFLICT,
                            _("Zone '{name}' is still in use ({used} rule(s), "
                              "{nets} network assignment(s)) – deletion aborted",
                              name=zone.name, used=used, nets=nets))
                    db.query(ZonePolicy).filter(
                        (ZonePolicy.from_zone_id == zone.id) | (ZonePolicy.to_zone_id == zone.id)
                    ).delete(synchronize_session=False)
                    db.delete(zone)
        db.flush()
        # Apply the network assignments (after any newly created zones)
        from ..vrf import get_vrf

        for item in batch:
            extra = item.extra or {}
            if item.change_type == "net_add":
                zone = find_zone(db, item.from_zone)
                if not zone:
                    raise HTTPException(status.HTTP_409_CONFLICT,
                                        _("Zone '{name}' no longer exists", name=item.from_zone))
                vrf = get_vrf(db, extra.get("vrf") or None)
                if not db.query(ZoneNetwork).filter(ZoneNetwork.cidr == item.to_zone,
                                                    ZoneNetwork.vrf_id == vrf.id).first():
                    db.add(ZoneNetwork(cidr=item.to_zone, zone_id=zone.id, vrf_id=vrf.id,
                                       description=extra.get("description", ""),
                                       source=extra.get("source", "manual")))
            elif item.change_type in ("net_update", "net_delete"):
                network = db.get(ZoneNetwork, extra.get("network_id") or 0)
                if not network:
                    continue  # the assignment was removed in the meantime
                if item.change_type == "net_delete":
                    db.delete(network)
                else:
                    zone = find_zone(db, item.from_zone)
                    if not zone:
                        raise HTTPException(status.HTTP_409_CONFLICT,
                                            _("Zone '{name}' no longer exists", name=item.from_zone))
                    network.cidr = item.to_zone
                    network.zone_id = zone.id
                    db.flush()   # so the reassessment sees the new assignment
                    reassessed.extend(
                        _apply_reassessment(db, network, user, change.batch_id))
        db.flush()
        for item in batch:
            if item.change_type != "policy":
                continue
            zone_a, zone_b = find_zone(db, item.from_zone), find_zone(db, item.to_zone)
            if not zone_a or not zone_b:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    _("The zone for {from_zone} → {to_zone} no longer exists",
                                      from_zone=item.from_zone, to_zone=item.to_zone))
            policy = get_policy(db, zone_a, zone_b)
            if not policy:
                policy = ZonePolicy(from_zone_id=zone_a.id, to_zone_id=zone_b.id)
                db.add(policy)
            policy.policy = item.new_policy
            policy.temporary = item.new_temporary
            # Allow -> block invalidates the relation's existing approved rules:
            # back into review (with a version entry and a comment)
            if item.new_policy == "block_all":
                from .rules_router import add_version

                template = ("Matrix change {from_zone} → {to_zone} to Block "
                            "(request {request}): the rule has to be reassessed")
                values = {"from_zone": zone_a.name, "to_zone": zone_b.name,
                          "request": change.batch_id[:8]}
                note = render(template, values)
                for rule in _affected_rules(db, zone_a.name, zone_b.name,
                                            statuses=IN_FORCE):
                    rule.status = RuleStatus.in_review
                    rule.version += 1
                    add_version(db, rule, user, template, **values)
                    db.add(Comment(rule_pk=rule.id, author=user.username, text=note))
                    reviews_reset.append(rule.rule_id)
    for item in batch:
        item.status = "approved" if approve else "rejected"
        item.decided_by = user.username
        item.decided_at = utcnow()
        if comment:
            item.comment = (item.comment + "\n" if item.comment else "") + comment
    db.commit()
    # Optional change management webhook (e.g. ServiceNow)
    from .. import change_management

    change_management.notify(
        f"zone_change.{batch[0].status}",
        {
            "batch_id": change.batch_id,
            "decided_by": user.username,
            "requested_by": batch[0].requested_by,
            "items": [
                {"change_type": c.change_type, "from_zone": c.from_zone,
                 "to_zone": c.to_zone, "new_policy": c.new_policy, "extra": c.extra or {}}
                for c in batch
            ],
            "reviews_reset": reviews_reset,
        },
    )
    result = {"status": batch[0].status, "batch_id": change.batch_id, "items": len(batch)}
    if reviews_reset:
        result["reviews_reset"] = reviews_reset
        result["detail"] = (_("{count} approved rule(s) of this relation were "
                              "sent back into review: {rule_ids}",
                              count=len(reviews_reset),
                              rule_ids=", ".join(reviews_reset[:10]))
                            + (" …" if len(reviews_reset) > 10 else ""))
    if reassessed:
        result["reassessed"] = reassessed
        for_removal = [r["rule_id"] for r in reassessed if not r["admissible"]]
        carried_over = len(reassessed) - len(for_removal)
        parts = []
        if for_removal:
            parts.append(_("{count} rule(s) became inadmissible through the move "
                           "and are in review for removal: {rule_ids}",
                           count=len(for_removal),
                           rule_ids=", ".join(for_removal[:10]))
                         + (" …" if len(for_removal) > 10 else ""))
        if carried_over:
            parts.append(_("{count} further rule(s) were carried over to the new zones",
                           count=carried_over))
        if parts:
            result["detail"] = (result.get("detail", "") + " " if result.get("detail") else "") \
                + ". ".join(parts) + "."
    return result


@router.post("/matrix/changes/{change_id}/approve")
def approve_change(
    change_id: int,
    payload: dict | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.change_approver)),
):
    return _decide_change(db, change_id, user, True, (payload or {}).get("comment", ""))


@router.post("/matrix/changes/{change_id}/reject")
def reject_change(
    change_id: int,
    payload: dict | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.change_approver)),
):
    return _decide_change(db, change_id, user, False, (payload or {}).get("comment", ""))


@router.get("/check", response_model=ZoneCheckOut)
def check(
    source: str = Query(...),
    destination: str = Query(...),
    platforms: str = Query("", description="Comma-separated, e.g. juniper,aci"),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    plist = [p.strip().lower() for p in platforms.split(",") if p.strip()]
    result = check_zone_pair(db, source, destination, plist)
    return ZoneCheckOut(
        allowed=result.allowed, policy=result.policy,
        temporary=result.temporary, messages=result.messages,
    )
