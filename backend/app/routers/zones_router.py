from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..database import get_db
from ..models import (
    Role,
    ZoneNetwork,
    Rule,
    RuleStatus,
    SecurityComponent,
    User,
    Zone,
    ZonePolicy,
    ZonePolicyChange,
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
from ..zone_check import check_zone_pair, find_zone, get_policy

router = APIRouter(prefix="/api/zones", tags=["zones"])


@router.get("", response_model=list[ZoneOut])
def list_zones(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(Zone).order_by(Zone.sort_order, Zone.name).all()


@router.post("", response_model=ZoneOut, status_code=201)
def create_zone(
    payload: ZoneCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect)),
):
    if find_zone(db, payload.name):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Zone '{payload.name}' existiert bereits")
    zone = Zone(**payload.model_dump())
    db.add(zone)
    db.commit()
    db.refresh(zone)
    return zone



@router.get("/networks")
def list_networks(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Alle Netzwerk-Zuordnungen (Basis der Netzwerke-Seite und künftiger Importe)."""
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
    """Netzwerk-Zuordnung ändern. Beschreibungs-Änderungen wirken sofort;
    CIDR-/Zonen-Änderungen sind sicherheitsrelevant und laufen als Antrag über
    den Freigabe-Workflow (zwei Change Approver)."""
    network = db.query(ZoneNetwork).get(network_id)
    if not network:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Netzwerk-Zuordnung nicht gefunden")
    from ..component_resolution import normalize_ip

    new_cidr = normalize_ip(payload["cidr"]) if payload.get("cidr") else network.cidr
    if new_cidr is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"'{payload['cidr']}' ist kein gültiges Netz (CIDR) und nicht 'any'")
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
                      "detail": "Beschreibung aktualisiert"}
    if not result:
        result = {"status": "unchanged", "id": network.id, "detail": "Keine Änderung"}
    return result


@router.post("/{name}/networks", status_code=201)
def add_zone_network(
    name: str,
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Netzwerk einer Zone zuordnen – läuft als Antrag über den
    Freigabe-Workflow (zwei Change Approver), wie alle Zonen-Änderungen."""
    if not find_zone(db, name):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Zone nicht gefunden")
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
    """Netzwerk-Zuordnung entfernen – läuft als Antrag über den Freigabe-Workflow."""
    return _create_batch(db, user, [{"type": "net_delete", "network_id": network_id}], "")


@router.put("/{name}/components")
def set_zone_components(
    name: str,
    payload: dict,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect)),
):
    """Anbindung der Zone an einen oder mehrere Firewall-Cluster festlegen."""
    zone = find_zone(db, name)
    if not zone:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Zone nicht gefunden")
    ids = payload.get("component_ids") or []
    components = (
        db.query(SecurityComponent).filter(SecurityComponent.id.in_(ids)).all() if ids else []
    )
    missing = set(ids) - {c.id for c in components}
    if missing:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unbekannte Komponente(n): {sorted(missing)}")
    non_fw = [c.name for c in components if c.type.value == "aci"]
    if non_fw:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Zonen werden an Firewall-Cluster angebunden – ACI ist kein Zonenübergang: {', '.join(non_fw)}",
        )
    zone.components = components
    db.commit()
    return {"zone": zone.name, "component_ids": sorted(c.id for c in components)}


@router.put("/{name}/pap-level", response_model=ZoneOut)
def set_pap_level(
    name: str,
    payload: dict,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect)),
):
    """BSI P-A-P-Einstufung einer Zone ändern (extern | pap | intern)."""
    zone = find_zone(db, name)
    if not zone:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Zone nicht gefunden")
    level = (payload.get("pap_level") or "").strip().lower()
    if level not in ("extern", "pap", "intern"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "pap_level muss extern, pap oder intern sein")
    zone.pap_level = level
    db.commit()
    db.refresh(zone)
    return zone


@router.delete("/{name}", status_code=204)
def delete_zone(
    name: str,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect)),
):
    zone = find_zone(db, name)
    if not zone:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Zone nicht gefunden")
    used = db.query(Rule).filter(
        (Rule.source_zone.ilike(zone.name)) | (Rule.destination_zone.ilike(zone.name))
    ).count()
    if used:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Zone '{zone.name}' wird von {used} Regel(n) verwendet und kann nicht gelöscht werden",
        )
    # Matrix-Einträge explizit mitlöschen (SQLite erzwingt FK-Cascade nicht immer)
    db.query(ZonePolicy).filter(
        (ZonePolicy.from_zone_id == zone.id) | (ZonePolicy.to_zone_id == zone.id)
    ).delete(synchronize_session=False)
    db.delete(zone)
    db.commit()


@router.get("/overview")
def overview(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Zonen-Übersicht: je Zone die Firewall-Cluster, über die sie erreichbar ist
    (abgeleitet aus den aktiven Regeln der Zone). ACI-Komponenten werden getrennt
    ausgewiesen – sie sind kein Zonenübergang im Sinne der BSI-Definition."""
    zones = db.query(Zone).order_by(Zone.sort_order, Zone.name).all()
    rules = db.query(Rule).filter(Rule.status != RuleStatus.deactivated).all()
    firewalls_total = db.query(SecurityComponent).filter(
        SecurityComponent.type != "aci"
    ).count()

    result = []
    for zone in zones:
        zname = zone.name.upper()
        zone_rules = [
            r for r in rules
            if (r.source_zone or "").upper() == zname or (r.destination_zone or "").upper() == zname
        ]
        # "Angebunden an": explizit gepflegte Firewall-Anbindung der Zone;
        # ACI-Fabrics werden weiterhin aus den Intra-Zonen-Regeln abgeleitet
        firewalls = {c.id: c for c in zone.components if c.type.value != "aci"}
        aci = {}
        for rule in zone_rules:
            for component in rule.components:
                if component.type.value == "aci":
                    aci[component.id] = component
        result.append(
            {
                "name": zone.name,
                "description": zone.description,
                "pap_level": zone.pap_level,
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


@router.get("/matrix", response_model=ZoneMatrixOut)
def matrix(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    zones = db.query(Zone).order_by(Zone.sort_order, Zone.name).all()
    policies = db.query(ZonePolicy).all()
    return ZoneMatrixOut(
        zones=zones,
        policies=[
            ZonePolicyOut(
                from_zone=p.from_zone.name,
                to_zone=p.to_zone.name,
                policy=p.policy,
                temporary=p.temporary,
                note=p.note,
            )
            for p in policies
        ],
    )


def _pending_net_conflict(db: Session, cidr: str, network_id: int | None = None):
    """Wartet für dieses CIDR bzw. diese Zuordnung bereits ein Antrag auf Freigabe?"""
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
    """Legt einen Sammelantrag an. items:
    {"type": "policy", "from_zone", "to_zone", "policy", "temporary"},
    {"type": "zone_create", "name", "pap_level", "description"} oder
    {"type": "net_add"|"net_update"|"net_delete", ...} (Netzwerk-Zuordnungen)."""
    import uuid

    from ..component_resolution import normalize_ip
    from ..vrf import get_vrf

    if not items:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Keine Änderungen enthalten")
    new_zone_names = {
        (i.get("name") or "").strip().upper() for i in items if i.get("type") == "zone_create"
    }
    batch_id = str(uuid.uuid4())
    rows = []
    for item in items:
        if item.get("type") == "zone_create":
            name = (item.get("name") or "").strip()
            if not name:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Zonenname fehlt")
            if find_zone(db, name):
                raise HTTPException(status.HTTP_409_CONFLICT, f"Zone '{name}' existiert bereits")
            level = (item.get("pap_level") or "intern").lower()
            if level not in ("extern", "pap", "intern"):
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Ungültige P-A-P-Einstufung")
            rows.append(ZonePolicyChange(
                batch_id=batch_id, change_type="zone_create",
                from_zone=name, to_zone="", old_policy=None, new_policy=level,
                requested_by=user.username, comment=item.get("description", ""),
            ))
            continue
        if item.get("type") == "net_add":
            norm = normalize_ip(item.get("cidr") or "")
            if norm is None:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                    f"'{item.get('cidr')}' ist kein gültiges Netz (CIDR) und nicht 'any'")
            zone_name = (item.get("zone") or "").strip()
            if not find_zone(db, zone_name) and zone_name.upper() not in new_zone_names:
                raise HTTPException(status.HTTP_404_NOT_FOUND, f"Zone '{zone_name}' nicht gefunden")
            vrf = get_vrf(db, item.get("vrf") or None)
            existing = db.query(ZoneNetwork).filter(ZoneNetwork.cidr == norm,
                                                    ZoneNetwork.vrf_id == vrf.id).first()
            if existing:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    f"{norm} ist in Umgebung '{vrf.name}' bereits der Zone "
                                    f"'{existing.zone.name}' zugeordnet")
            if _pending_net_conflict(db, norm):
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    f"Für {norm} wartet bereits ein Antrag auf Freigabe")
            rows.append(ZonePolicyChange(
                batch_id=batch_id, change_type="net_add",
                from_zone=zone_name, to_zone=norm, old_policy=None, new_policy="add",
                requested_by=user.username, comment=comment,
                extra={"vrf": vrf.name, "description": item.get("description", "")},
            ))
            continue
        if item.get("type") in ("net_update", "net_delete"):
            network = db.query(ZoneNetwork).get(item.get("network_id") or 0)
            if not network:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Netzwerk-Zuordnung nicht gefunden")
            if _pending_net_conflict(db, network.cidr, network.id):
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    f"Für {network.cidr} wartet bereits ein Antrag auf Freigabe")
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
                    raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                        f"'{item['cidr']}' ist kein gültiges Netz (CIDR) und nicht 'any'")
                duplicate = db.query(ZoneNetwork).filter(
                    ZoneNetwork.cidr == norm, ZoneNetwork.vrf_id == network.vrf_id,
                    ZoneNetwork.id != network.id).first()
                if duplicate:
                    raise HTTPException(status.HTTP_409_CONFLICT,
                                        f"{norm} ist bereits der Zone '{duplicate.zone.name}' zugeordnet")
                new_cidr = norm
            new_zone_name = (item.get("zone") or network.zone.name).strip()
            if not find_zone(db, new_zone_name) and new_zone_name.upper() not in new_zone_names:
                raise HTTPException(status.HTTP_404_NOT_FOUND, f"Zone '{new_zone_name}' nicht gefunden")
            if new_cidr == network.cidr and new_zone_name.upper() == network.zone.name.upper():
                continue  # keine sicherheitsrelevante Änderung
            rows.append(ZonePolicyChange(
                batch_id=batch_id, change_type="net_update",
                from_zone=new_zone_name, to_zone=new_cidr, old_policy=None, new_policy="update",
                requested_by=user.username, comment=comment,
                extra={"network_id": network.id, "old_cidr": network.cidr,
                       "old_zone": network.zone.name},
            ))
            continue
        # Matrix-Zelle
        from_name, to_name = item.get("from_zone", ""), item.get("to_zone", "")
        zone_a, zone_b = find_zone(db, from_name), find_zone(db, to_name)
        for name, zone in ((from_name, zone_a), (to_name, zone_b)):
            if not zone and name.strip().upper() not in new_zone_names:
                raise HTTPException(status.HTTP_404_NOT_FOUND, f"Zone '{name}' nicht gefunden")
        if from_name.strip().upper() == to_name.strip().upper():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Intra-Zonen-Beziehung wird nicht gepflegt")
        current = get_policy(db, zone_a, zone_b) if zone_a and zone_b else None
        new_policy = item.get("policy")
        if new_policy not in ("allow_only", "block_all"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Ungültige Policy '{new_policy}'")
        if current and current.policy.value == new_policy and current.temporary == bool(item.get("temporary")):
            continue  # keine Änderung -> überspringen
        pending = (
            db.query(ZonePolicyChange)
            .filter(ZonePolicyChange.change_type == "policy",
                    ZonePolicyChange.from_zone == (zone_a.name if zone_a else from_name),
                    ZonePolicyChange.to_zone == (zone_b.name if zone_b else to_name),
                    ZonePolicyChange.status == "pending")
            .first()
        )
        if pending:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Für {from_name} → {to_name} wartet bereits ein Antrag auf Freigabe",
            )
        rows.append(ZonePolicyChange(
            batch_id=batch_id, change_type="policy",
            from_zone=zone_a.name if zone_a else from_name,
            to_zone=zone_b.name if zone_b else to_name,
            old_policy=current.policy.value if current else None,
            new_policy=new_policy,
            old_temporary=current.temporary if current else False,
            new_temporary=bool(item.get("temporary")),
            requested_by=user.username, comment=comment,
        ))
    if not rows:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Keine Änderung gegenüber dem aktuellen Stand")
    db.add_all(rows)
    db.commit()
    return {"status": "pending", "batch_id": batch_id, "items": len(rows),
            "detail": f"{len(rows)} Änderung(en) beantragt – warten auf Freigabe durch zwei Change Approver"}


@router.post("/matrix/changes")
def request_change_batch(
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Sammelantrag: mehrere Matrix-Änderungen und Zonen-Anlagen in einem Antrag."""
    return _create_batch(db, user, payload.get("items") or [], payload.get("comment", ""))


@router.put("/matrix/{from_name}/{to_name}")
def request_policy_change(
    from_name: str,
    to_name: str,
    payload: ZonePolicySet,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Einzelantrag (Kompatibilität): entspricht einem Sammelantrag mit einem Eintrag."""
    return _create_batch(db, user, [{
        "type": "policy", "from_zone": from_name, "to_zone": to_name,
        "policy": payload.policy.value, "temporary": payload.temporary,
    }], payload.note)


@router.get("/matrix/changes")
def list_changes(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Änderungsanträge und Historie der Kommunikationsmatrix (neueste zuerst)."""
    changes = (
        db.query(ZonePolicyChange)
        .order_by(ZonePolicyChange.status != "pending", ZonePolicyChange.requested_at.desc())
        .limit(200)
        .all()
    )
    return [
        {
            "id": c.id, "batch_id": c.batch_id, "change_type": c.change_type,
            "from_zone": c.from_zone, "to_zone": c.to_zone,
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
    """Entscheidet den GESAMTEN Sammelantrag, zu dem der Eintrag gehört."""
    change = db.query(ZonePolicyChange).get(change_id)
    if not change:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Antrag nicht gefunden")
    if change.status != "pending":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Antrag ist bereits '{change.status}'")
    if change.batch_id:
        batch = (
            db.query(ZonePolicyChange)
            .filter(ZonePolicyChange.batch_id == change.batch_id,
                    ZonePolicyChange.status == "pending")
            .all()
        )
    else:
        batch = [change]
    if any(c.requested_by == user.username for c in batch) and user.role != Role.admin:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Vier-Augen-Prinzip: eigene Anträge können nicht selbst freigegeben werden",
        )
    # Zonen-/Matrix-Änderungen brauchen ZWEI Freigaben durch verschiedene Change Approver
    if approve and not change.first_approved_by:
        for item in batch:
            item.first_approved_by = user.username
            item.first_approved_at = utcnow()
            if comment:
                item.comment = (item.comment + "\n" if item.comment else "") + comment
        db.commit()
        return {"status": "pending", "batch_id": change.batch_id, "items": len(batch),
                "approvals": "1/2",
                "detail": "Erste Freigabe erteilt – eine zweite Freigabe durch einen anderen "
                          "Change Approver ist erforderlich"}
    if approve and change.first_approved_by == user.username:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Die zweite Freigabe muss durch einen anderen Change Approver erfolgen",
        )
    if approve:
        # Erst Zonen anlegen, dann Matrix-Zellen anwenden
        for item in batch:
            if item.change_type == "zone_create" and not find_zone(db, item.from_zone):
                db.add(Zone(name=item.from_zone, pap_level=item.new_policy,
                            description=item.comment, sort_order=db.query(Zone).count()))
        db.flush()
        # Netzwerk-Zuordnungen anwenden (nach evtl. neu angelegten Zonen)
        from ..vrf import get_vrf

        for item in batch:
            extra = item.extra or {}
            if item.change_type == "net_add":
                zone = find_zone(db, item.from_zone)
                if not zone:
                    raise HTTPException(status.HTTP_409_CONFLICT,
                                        f"Zone '{item.from_zone}' existiert nicht mehr")
                vrf = get_vrf(db, extra.get("vrf") or None)
                if not db.query(ZoneNetwork).filter(ZoneNetwork.cidr == item.to_zone,
                                                    ZoneNetwork.vrf_id == vrf.id).first():
                    db.add(ZoneNetwork(cidr=item.to_zone, zone_id=zone.id, vrf_id=vrf.id,
                                       description=extra.get("description", ""), source="manual"))
            elif item.change_type in ("net_update", "net_delete"):
                network = db.query(ZoneNetwork).get(extra.get("network_id") or 0)
                if not network:
                    continue  # Zuordnung wurde zwischenzeitlich entfernt
                if item.change_type == "net_delete":
                    db.delete(network)
                else:
                    zone = find_zone(db, item.from_zone)
                    if not zone:
                        raise HTTPException(status.HTTP_409_CONFLICT,
                                            f"Zone '{item.from_zone}' existiert nicht mehr")
                    network.cidr = item.to_zone
                    network.zone_id = zone.id
        db.flush()
        for item in batch:
            if item.change_type != "policy":
                continue
            zone_a, zone_b = find_zone(db, item.from_zone), find_zone(db, item.to_zone)
            if not zone_a or not zone_b:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    f"Zone für {item.from_zone} → {item.to_zone} existiert nicht mehr")
            policy = get_policy(db, zone_a, zone_b)
            if not policy:
                policy = ZonePolicy(from_zone_id=zone_a.id, to_zone_id=zone_b.id)
                db.add(policy)
            policy.policy = item.new_policy
            policy.temporary = item.new_temporary
    for item in batch:
        item.status = "approved" if approve else "rejected"
        item.decided_by = user.username
        item.decided_at = utcnow()
        if comment:
            item.comment = (item.comment + "\n" if item.comment else "") + comment
    db.commit()
    return {"status": batch[0].status, "batch_id": change.batch_id, "items": len(batch)}


@router.post("/matrix/changes/{change_id}/approve")
def approve_change(
    change_id: int,
    payload: dict = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.change_approver)),
):
    return _decide_change(db, change_id, user, True, (payload or {}).get("comment", ""))


@router.post("/matrix/changes/{change_id}/reject")
def reject_change(
    change_id: int,
    payload: dict = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.change_approver)),
):
    return _decide_change(db, change_id, user, False, (payload or {}).get("comment", ""))


@router.get("/check", response_model=ZoneCheckOut)
def check(
    source: str = Query(...),
    destination: str = Query(...),
    platforms: str = Query("", description="Kommagetrennt, z.B. juniper,aci"),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    plist = [p.strip().lower() for p in platforms.split(",") if p.strip()]
    result = check_zone_pair(db, source, destination, plist)
    return ZoneCheckOut(
        allowed=result.allowed, policy=result.policy,
        temporary=result.temporary, messages=result.messages,
    )
