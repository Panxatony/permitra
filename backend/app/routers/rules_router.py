import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..component_resolution import find_mapping, resolve_rule_components
from ..conflicts import find_conflicts
from ..validation import format_entry, parse_network
from ..vrf import get_vrf
from ..zone_check import check_zone_pair, resolve_zone_for_entries
from ..database import get_db
from ..exporters.generic import rule_to_dict
from ..models import (
    active_rules,
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
)
from ..expiry import expiring_rules, invalid_validity_rules
from ..schemas import (
    CommentCreate,
    CommentOut,
    ConflictOut,
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

router = APIRouter(prefix="/api/rules", tags=["rules"])

RULE_ID_RE = re.compile(r"^SR(\d+)$")


def next_rule_id(db: Session) -> str:
    """Nächste freie SR-Nummer, 5-stellig aufgefüllt (z.B. SR00855).

    Max-Aggregat in der DB (SUBSTR+CAST) statt Laden aller Regeln – skaliert
    auch bei zehntausenden Regeln. Kollisionen bei paralleler Anlage fängt der
    Unique-Constraint mit Retry im Aufrufer ab."""
    from sqlalchemy import Integer, cast, func

    max_num = (
        db.query(func.max(cast(func.substr(Rule.rule_id, 3), Integer)))
        .filter(Rule.rule_id.like("SR%"))
        .scalar()
    ) or 0
    return f"SR{int(max_num) + 1:05d}"


def get_rule_or_404(db: Session, rule_id: str, include_deleted: bool = False) -> Rule:
    """Holt eine Regel. Gelöschte (Soft-Delete) gelten als nicht vorhanden –
    sonst blieben sie über /rules/{id} les-, änder- und erneut freigebbar.
    Nur delete_rule selbst braucht sie, um doppeltes Löschen zu erkennen."""
    q = db.query(Rule) if include_deleted else active_rules(db)
    rule = q.filter(Rule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Regel {rule_id} nicht gefunden")
    return rule


def snapshot(rule: Rule) -> dict:
    return rule_to_dict(rule, with_meta=True)


def resolve_components(db: Session, component_ids: list[int]) -> list[SecurityComponent]:
    """Löst component_ids auf; unbekannte IDs führen zu 422."""
    if not component_ids:
        return []
    components = (
        db.query(SecurityComponent).filter(SecurityComponent.id.in_(component_ids)).all()
    )
    missing = set(component_ids) - {c.id for c in components}
    if missing:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Unbekannte Komponente(n): {sorted(missing)}",
        )
    return components



def derive_zones(db: Session, payload, vrf_id: int):
    """Leitet Quell-/Ziel-Zone aus den Netzwerk-Zuordnungen der Adressen ab.

    Jedes Netzwerk muss einer Zone zugeordnet sein; eine Regelseite darf nur
    eine Zone umfassen. Die abgeleiteten Zonen überschreiben die Eingabe."""
    def entries_of(value):
        return [e.model_dump() if hasattr(e, "model_dump") else e for e in value]

    problems = []
    zones = {}
    for label, field in (("Quelle", "source"), ("Ziel", "destination")):
        zone, unassigned, hits = resolve_zone_for_entries(db, entries_of(getattr(payload, field)), vrf_id)
        if unassigned:
            problems.append(
                f"{label}: Netz(e) keiner Sicherheitszone zugeordnet: {', '.join(unassigned)} "
                "– bitte das Netzwerk zuerst auf der Seite „Netzwerke“ anlegen und einer "
                "Sicherheitszone zuordnen"
            )
        elif len(hits) > 1:
            problems.append(f"{label} umfasst mehrere Zonen ({', '.join(sorted(hits))}) – bitte aufteilen")
        zones[field] = zone
    if problems:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "; ".join(problems))
    payload.source_zone = zones["source"] or payload.source_zone
    payload.destination_zone = zones["destination"] or payload.destination_zone


def determine_components(db: Session, payload, vrf_id: int) -> list[SecurityComponent]:
    """Ermittelt die Umsetzungs-Komponenten automatisch aus Quelle/Ziel.

    Explizit übergebene component_ids (z.B. API-Aufrufe, Import) haben Vorrang.
    Adressen ohne gepflegte Zuordnung führen zu 422 – der Nutzer muss die
    Zuordnung einmalig über /api/address-map festlegen.
    """
    if payload.component_ids:
        return resolve_components(db, payload.component_ids)
    source = [e.model_dump() if hasattr(e, "model_dump") else e for e in payload.source]
    destination = [e.model_dump() if hasattr(e, "model_dump") else e for e in payload.destination]
    components, unknown = resolve_rule_components(
        db, source, destination, payload.source_zone, payload.destination_zone, vrf_id
    )
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Für folgende Adressen ist noch keine Komponenten-Zuordnung festgelegt: "
            + ", ".join(u["ip"] for u in unknown)
            + ". Bitte einmalig über die Adress-Zuordnung festlegen.",
        )
    if not components:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Es konnten keine Umsetzungs-Komponenten ermittelt werden",
        )
    return components


def enforce_bsi_firewall(source_zone: str, destination_zone: str, components: list[SecurityComponent]):
    """BSI-Prinzip: Der Übergang zwischen Sicherheitszonen ist immer eine Firewall.

    Eine zonenübergreifende Regel muss mindestens eine Firewall-Komponente enthalten –
    Cisco ACI ist als Sicherheitskomponente für den Zonenübergang nicht ausreichend."""
    src, dst = (source_zone or "").strip(), (destination_zone or "").strip()
    if not src or not dst or src.upper() == dst.upper():
        return  # Intra-Zone: ACI Contracts sind hier das richtige Mittel
    if components and not any(c.type.value != "aci" for c in components):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Zonenübergang erfordert eine Firewall (BSI-Definition): Cisco ACI allein ist "
            f"für {src} → {dst} nicht zulässig. Bitte einen Firewall-Cluster zuordnen.",
        )


def enforce_zone_matrix(db: Session, source_zone: str, destination_zone: str, platforms: list[str]):
    """Blockiert Regeln, die laut Zonen-Kommunikationsmatrix unzulässig sind."""
    result = check_zone_pair(db, source_zone, destination_zone, platforms)
    if not result.allowed:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Zonen-Matrix: " + "; ".join(result.messages),
        )


def enforce_required_fields(db: Session, payload):
    """Konfigurierbare Pflichtfelder (Admin-Einstellungen, BSI-Dokumentationspflichten)."""
    from ..settings import get_setting

    missing = []
    if get_setting(db, "require_justification") == "yes" and not (payload.justification or "").strip():
        missing.append("Begründung (Anlass)")
    if get_setting(db, "require_requestor") == "yes" and not (payload.requestor or "").strip():
        missing.append("Requestor (Verantwortlicher)")
    if get_setting(db, "require_valid_until") == "yes" and not (payload.valid_until or "").strip():
        missing.append("Gültig-bis (Ablaufdatum)")
    if missing:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Pflichtfelder fehlen: " + ", ".join(missing),
        )


def add_version(db: Session, rule: Rule, user: User, note: str):
    db.add(
        RuleVersion(
            rule_pk=rule.id,
            version=rule.version,
            snapshot=snapshot(rule),
            change_note=note,
            changed_by=user.username,
        )
    )


@router.get("", response_model=RuleListOut)
def list_rules(
    q: str | None = Query(None, description="Volltextsuche über ID, Name, Quelle, Ziel, Anlass"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    source: str | None = None,
    destination: str | None = None,
    port: str | None = None,
    protocol: str | None = None,
    rule_status: RuleStatus | None = Query(None, alias="status"),
    impl: str | None = Query(None, description="'pending' = freigegebene Regeln mit offener Umsetzung"),
    risk: str | None = Query(None, description="'flagged' = nur Regeln mit Risiko-Hinweis"),
    application: str | None = None,
    app_id: str | None = Query(None, description="Anwendungs-ID (Report je App)"),
    platform: str | None = None,
    component: str | None = Query(None, description="Name (Teilstring) einer Komponente"),
    vrf: str | None = Query(None, description="Umgebung/VRF (Name); leer = alle"),
    updated_since: str | None = Query(None, description="ISO-Zeitstempel; nur seither geänderte Regeln (Polling)"),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = db.query(Rule).filter(Rule.deleted_at.is_(None))
    if vrf:
        query = query.filter(Rule.vrf_id == get_vrf(db, vrf).id)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Rule.rule_id.ilike(like), Rule.name.ilike(like),
                Rule.justification.ilike(like), Rule.change_id.ilike(like), Rule.app_id.ilike(like),
                Rule.requestor.ilike(like), Rule.business_context.ilike(like),
                # Adressfelder sind JSON – Volltext dazu unten in Python
                Rule.source_zone.ilike(like), Rule.destination_zone.ilike(like),
            )
        )
    if rule_status:
        query = query.filter(Rule.status == rule_status)
    if updated_since:
        from datetime import datetime as _dt
        try:
            query = query.filter(Rule.updated_at >= _dt.fromisoformat(updated_since))
        except ValueError:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "updated_since muss ein ISO-Zeitstempel sein")
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

    # JSON-Feld-Filter in Python
    if q:
        # q-Treffer aus SQL beibehalten; zusätzlich Regeln aufnehmen, deren Adressen passen
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
    """Regel mit offener Umsetzung: freigegeben und auf mindestens einer
    Komponente noch nicht umgesetzt (fehlt, "offen", "neu", "zu ändern") –
    oder für den Rückbau markiert ("zu löschen", z.B. nach Matrix-Block)."""
    impl = rule.impl_status or {}
    if any(impl.get(c.name) == "zu löschen" for c in rule.components):
        return True
    if rule.status != RuleStatus.approved or not rule.components:
        return False
    return any(impl.get(c.name) not in ("umgesetzt", "deaktiviert") for c in rule.components)


def _match_address_field(entries: list, query: str, net) -> tuple[list[str], str | None]:
    """Prüft strukturierte Adress-Einträge gegen die Suchanfrage.

    Liefert (getroffene Einträge formatiert, Trefferart): "direct" (Netz-Überlappung
    oder Alias-/IP-Texttreffer) schlägt "any" (Eintrag deckt jede IP ab).
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
    q: str = Query(..., min_length=1, description="IP, Netz (CIDR) oder Hostname-Fragment"),
    vrf: str | None = Query(None),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Alle Regeln, in denen die IP / das Netz als Quelle (ausgehend) oder Ziel (eingehend) vorkommt."""
    net = parse_network(q.strip())
    outgoing, incoming = [], []
    rule_query = active_rules(db).order_by(Rule.rule_id.desc())
    vrf_id = None
    if vrf:
        vrf_obj = get_vrf(db, vrf)
        vrf_id = vrf_obj.id
        rule_query = rule_query.filter(Rule.vrf_id == vrf_obj.id)
    # Zone der gesuchten Adresse ermitteln – ein reiner "any"-Treffer wird
    # verworfen, wenn die Adresse einer anderen Zone angehört als die Regelseite
    # (z.B. eine PROD-Adresse ist keine Quelle einer INET→…-Regel mit Quelle any)
    from ..zone_check import zone_for_ip
    from ..models import ZoneNetwork as _ZN

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
            # Nur-über-any-Treffer über Zonengrenzen hinweg herausfiltern
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
    key = lambda item: (item["match"] != "direct", item["rule_id"])  # noqa: E731 – direkte Treffer zuerst
    return {
        "query": q,
        "is_network": net is not None,
        "outgoing": sorted(outgoing, key=key),
        "incoming": sorted(incoming, key=key),
    }


@router.get("/path-search")
def path_search(
    src: str = Query(..., min_length=1, description="Quell-IP/Netz/Hostname"),
    dst: str = Query(..., min_length=1, description="Ziel-IP/Netz/Hostname"),
    vrf: str | None = Query(None),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Alle Regeln, die Verkehr von src nach dst abdecken (Quelle UND Ziel treffen)."""
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
                # "direct" nur, wenn beide Seiten konkret getroffen sind (nicht nur über any)
                "match": "direct" if src_kind == "direct" and dst_kind == "direct" else "any",
            }
        )
    results.sort(key=lambda item: (item["match"] != "direct", item["rule_id"]))
    return {"src": src, "dst": dst, "results": results}


@router.get("/next-id")
def get_next_id(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return {"rule_id": next_rule_id(db)}


@router.get("/path-analysis")
def path_analysis(
    src: str = Query(..., description="Quell-IP oder -Netz"),
    dst: str = Query(..., description="Ziel-IP oder -Netz"),
    vrf: str | None = Query(None),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Visuelle Pfad-Analyse: Ist Kommunikation src -> dst möglich, über welche
    Komponenten läuft sie, welche Regel erlaubt sie dort und für welche Dienste?"""
    src_net, dst_net = parse_network(src.strip()), parse_network(dst.strip())
    if (src_net is None and src.strip().lower() != "any") or (dst_net is None and dst.strip().lower() != "any"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Quelle und Ziel müssen IP/Netz oder 'any' sein")

    # Zu passierende Komponenten aus der Adress-Zuordnung (im VRF-Kontext)
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
    # Gleiche Zuordnung (gleiches Netz) => Intra-Zone => ACI; sonst Firewalls
    intra = map_src is not None and map_dst is not None and map_src.id == map_dst.id
    filtered = [c for c in components if (c.type == ComponentType.aci) == intra]
    components = filtered or components

    # Mehr-Hop-Reihenfolge: quellseitige Komponenten -> beidseitige -> zielseitige
    def hop_side(component):
        in_src, in_dst = component.id in src_ids, component.id in dst_ids
        if in_src and in_dst:
            return 1, "beide"
        return (0, "quelle") if in_src else (2, "ziel")

    hop_list = [
        {"component": component, "side": hop_side(component)[1], "via_pbr": False}
        for component in components
    ]

    # PBR-Anbindung: liegt src/dst im Netz eines Anycast Gateways mit PBR, wird der
    # Check Point Cluster zusätzlich passiert (Service-Graph-Umleitung)
    from ..models import AciGateway  # lokaler Import vermeidet Zyklen beim Modulstart

    for gateway in db.query(AciGateway).filter(AciGateway.pbr_enabled).all():
        gw_net = parse_network(gateway.gateway_ip)
        if not gw_net or not gateway.pbr_component:
            continue
        for ip, net, side in ((src, src_net, "quelle"), (dst, dst_net, "ziel")):
            if net is None or net.version != gw_net.version:
                continue
            if net.subnet_of(gw_net) and not any(
                h["component"].id == gateway.pbr_component.id for h in hop_list
            ):
                hop_list.append(
                    {"component": gateway.pbr_component, "side": side, "via_pbr": True,
                     "gateway": gateway.name}
                )

    # Regeln, die den Verkehr src -> dst abdecken (nur im VRF-Kontext)
    matching = []
    for rule in active_rules(db).filter(Rule.vrf_id == vrf_obj.id).all():
        src_matched, src_kind = _match_address_field(rule.source, src, src_net)
        if not src_kind:
            continue
        dst_matched, dst_kind = _match_address_field(rule.destination, dst, dst_net)
        if not dst_kind:
            continue
        matching.append((rule, src_kind, dst_kind))

    # Hop-Reihenfolge: entlang der Nord-Süd-Ordnung in Flussrichtung
    # (Quelle südlicher als Ziel => Süd->Nord, sonst Nord->Süd); danach quell- vor zielseitig.
    def avg_tier(ids):
        tiers = [c.ns_tier for c in components if c.id in ids]
        return sum(tiers) / len(tiers) if tiers else 100

    direction = -1 if avg_tier(src_ids) > avg_tier(dst_ids) else 1
    side_rank = {"quelle": 0, "beide": 1, "ziel": 2}
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
            if r.status == RuleStatus.approved and r.action == RuleAction.permit
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

    # Erlaubte Dienste = Schnittmenge über alle zu passierenden Hops
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
    }


@router.get("/expiring", response_model=ExpiringOut)
def get_expiring(
    days: int = Query(30, ge=0, le=365),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Abgelaufene und demnächst ablaufende freigegebene Regeln (Rezertifizierung)."""
    expired, expiring = expiring_rules(db, days)
    return ExpiringOut(days=days, expired=expired, expiring=expiring,
                       invalid=invalid_validity_rules(db))


@router.post("/resolve-components")
def resolve_components_endpoint(
    payload: ResolveRequest,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Ermittelt aus Quelle/Ziel die Komponenten; meldet Adressen ohne Zuordnung."""
    src_entries = [e.model_dump() for e in payload.source]
    dst_entries = [e.model_dump() for e in payload.destination]
    vrf_obj = get_vrf(db, payload.vrf or None)
    zone_issues = []
    src_zone, src_un, src_hits = resolve_zone_for_entries(db, src_entries, vrf_obj.id)
    dst_zone, dst_un, dst_hits = resolve_zone_for_entries(db, dst_entries, vrf_obj.id)
    for label, un, hits in (("Quelle", src_un, src_hits), ("Ziel", dst_un, dst_hits)):
        if not un and len(hits) > 1:
            zone_issues.append(f"{label} umfasst mehrere Zonen: {', '.join(sorted(hits))}")
    # Adressen aus unbekannten Netzen: erst Netzwerk anlegen und Zone zuordnen –
    # die Komponenten-Zuordnung wird für sie noch nicht abgefragt
    unassigned = list(dict.fromkeys(src_un + dst_un))
    components, unknown = resolve_rule_components(
        db, src_entries, dst_entries, src_zone or "", dst_zone or "", vrf_obj.id
    )
    out = ResolveOut(components=components, unknown=unknown).model_dump()
    out.update({"source_zone": src_zone, "destination_zone": dst_zone,
                "zone_issues": zone_issues, "unassigned": unassigned})
    return out


@router.post("", response_model=RuleOut, status_code=201)
def create_rule(
    payload: RuleCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect)),
):
    # Rule-ID wird immer vom System vergeben (fortlaufend, eindeutig, nicht änderbar).
    # Bei parallelen Anlagen schützt der Unique-Constraint; dann neue Nummer versuchen.
    vrf = get_vrf(db, payload.vrf or None)
    enforce_required_fields(db, payload)
    for _ in range(5):
        derive_zones(db, payload, vrf.id)
        components = determine_components(db, payload, vrf.id)
        enforce_bsi_firewall(payload.source_zone, payload.destination_zone, components)
        enforce_zone_matrix(
            db, payload.source_zone, payload.destination_zone, [c.type.value for c in components]
        )
        data = payload.model_dump(exclude={"component_ids", "vrf"})
        data["services"] = [s.model_dump() if hasattr(s, "model_dump") else s for s in payload.services]
        rule = Rule(rule_id=next_rule_id(db), vrf_id=vrf.id, created_by=user.username,
                    components=components, **data)
        db.add(rule)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            continue
        add_version(db, rule, user, "Regel angelegt")
        db.commit()
        db.refresh(rule)
        return rule
    raise HTTPException(status.HTTP_409_CONFLICT, "Rule-ID-Vergabe fehlgeschlagen, bitte erneut versuchen")


@router.get("/{rule_id}", response_model=RuleDetail)
def get_rule(rule_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return get_rule_or_404(db, rule_id)


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
    components = determine_components(db, payload, vrf.id)
    enforce_bsi_firewall(payload.source_zone, payload.destination_zone, components)
    enforce_zone_matrix(
        db, payload.source_zone, payload.destination_zone, [c.type.value for c in components]
    )
    # impl_status pflegt der Betrieb über den eigenen Endpunkt – ein Edit darf ihn
    # nicht zurücksetzen (die Freigabe setzt umgesetzte Komponenten auf "zu ändern")
    data = payload.model_dump(exclude={"change_note", "component_ids", "vrf", "impl_status"})
    data["services"] = [s.model_dump() if hasattr(s, "model_dump") else s for s in payload.services]
    for key, value in data.items():
        setattr(rule, key, value)
    rule.vrf_id = vrf.id
    rule.components = components
    rule.version += 1
    # Inhaltliche Änderung einer freigegebenen Regel setzt den Review zurück
    if rule.status in (RuleStatus.approved, RuleStatus.rejected):
        rule.status = RuleStatus.draft
    add_version(db, rule, user, payload.change_note or "Regel geändert")
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
    """Soft-Delete: die Regel wird als gelöscht markiert (verschwindet aus
    Listen/Exporten), die Versionshistorie bleibt für den Audit-Trail erhalten.
    Der Löschvorgang wird revisionssicher protokolliert."""
    from .. import audit
    from ..models import utcnow as _now

    rule = get_rule_or_404(db, rule_id, include_deleted=True)
    if rule.deleted_at is not None:
        return
    rule.deleted_at = _now()
    db.commit()
    audit.record(db, "rule", "rule.deleted", actor=user.username, object=rule.rule_id,
                 detail=f"Regel gelöscht (Soft-Delete): {rule.name}",
                 source_ip=(request.client.host if request and request.client else ""))


# --- Review-Workflow ---------------------------------------------------------

@router.post("/{rule_id}/restore/{version}", response_model=RuleOut)
def restore_version(
    rule_id: str,
    version: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect)),
):
    """Rollback: stellt den Snapshot einer früheren Version als neuen Entwurf
    wieder her. Die wiederhergestellten Inhalte durchlaufen dieselben Prüfungen
    wie eine Änderung (Zonen-Ableitung, Matrix, BSI, Komponenten) und den
    normalen Review-Workflow; der Umsetzungsstatus bleibt unangetastet."""
    rule = get_rule_or_404(db, rule_id)
    entry = (
        db.query(RuleVersion)
        .filter(RuleVersion.rule_pk == rule.id, RuleVersion.version == version)
        .first()
    )
    if not entry or not isinstance(entry.snapshot, dict) or "source" not in entry.snapshot:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            f"Version {version} hat keinen wiederherstellbaren Snapshot")
    snap = entry.snapshot

    # Wiederhergestellte Inhalte wie eine normale Änderung validieren
    class _Payload:
        pass

    payload = _Payload()
    payload.source = snap.get("source") or []
    payload.destination = snap.get("destination") or []
    payload.source_zone = snap.get("source_zone") or ""
    payload.destination_zone = snap.get("destination_zone") or ""
    payload.component_ids = []
    derive_zones(db, payload, rule.vrf_id)
    components = determine_components(db, payload, rule.vrf_id)
    enforce_bsi_firewall(payload.source_zone, payload.destination_zone, components)
    enforce_zone_matrix(
        db, payload.source_zone, payload.destination_zone, [c.type.value for c in components]
    )

    for field in ("name", "application", "source", "destination", "services",
                  "description", "justification", "business_context", "info",
                  "requestor", "owner", "change_id", "valid_from", "valid_until"):
        if field in snap:
            setattr(rule, field, snap[field])
    if snap.get("action") in (a.value for a in RuleAction):
        rule.action = RuleAction(snap["action"])
    rule.source_zone = payload.source_zone
    rule.destination_zone = payload.destination_zone
    rule.components = components
    rule.status = RuleStatus.draft  # Rollback durchläuft den normalen Review
    rule.version += 1
    add_version(db, rule, user, f"Rollback auf Version {version}")
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
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Regel ist im Status '{rule.status.value}'")
    rule.status = RuleStatus.in_review
    rule.version += 1
    add_version(db, rule, user, "Zum Review eingereicht")
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
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Regel ist nicht im Review")
    # Vier-Augen-Prinzip: wer die Regel eingereicht/erstellt hat, darf sie nicht
    # selbst freigeben (gilt auch für Admins) – BSI-Funktionstrennung
    if new_status == RuleStatus.approved:
        last_version = max(rule.versions, key=lambda v: v.version, default=None)
        submitter = last_version.changed_by if last_version else rule.created_by
        if user.username in {submitter, rule.created_by}:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Vier-Augen-Prinzip: eigene bzw. selbst eingereichte Regeln können nicht "
                "selbst freigegeben werden",
            )
    # Steht die Zonen-Beziehung der Regel auf Block (z.B. nach einer
    # Matrix-Änderung), ist "Freigeben" die Löschungsfreigabe: Die Regel wird
    # deaktiviert und je Komponente auf "zu löschen" gesetzt – sie erscheint
    # damit beim Betrieb als offene Umsetzung (Rückbau auf den Geräten).
    if new_status == RuleStatus.approved:
        verdict = check_zone_pair(db, rule.source_zone, rule.destination_zone,
                                  rule.platforms or [])
        if not verdict.allowed:
            rule.status = RuleStatus.deactivated
            rule.impl_status = {
                **(rule.impl_status or {}),
                **{c.name: "zu löschen" for c in rule.components
                   if (rule.impl_status or {}).get(c.name) != "deaktiviert"},
            }
            rule.version += 1
            removal_note = (f"Löschung freigegeben: Zonen-Beziehung "
                            f"{rule.source_zone} → {rule.destination_zone} ist Block – "
                            f"Regel auf den Komponenten entfernen ('zu löschen')")
            add_version(db, rule, user, removal_note)
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
                db, rule, "Löschung freigegeben – Regel auf den Komponenten entfernen")
            return rule
    rule.status = new_status
    if new_status == RuleStatus.approved:
        # Bereits umgesetzte Komponenten müssen nach einer erneuten Freigabe vom
        # Betrieb angepasst werden -> Umsetzungsstatus "zu ändern"
        impl = dict(rule.impl_status or {})
        for c in rule.components:
            if impl.get(c.name) == "umgesetzt":
                impl[c.name] = "zu ändern"
        rule.impl_status = impl
    rule.version += 1
    add_version(db, rule, user, note)
    if decision.comment:
        db.add(Comment(rule_pk=rule.id, author=user.username, text=decision.comment))
    db.commit()
    db.refresh(rule)
    # Optionaler Change-Management-Webhook (z.B. ServiceNow) – fire-and-forget
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
            db, rule, "Regel freigegeben – Umsetzung auf den Komponenten erforderlich")
    return rule


@router.post("/{rule_id}/approve", response_model=RuleOut)
def approve(
    rule_id: str,
    decision: ReviewDecision,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.change_approver)),
):
    return _decide(db, rule_id, user, decision, RuleStatus.approved, "Regel freigegeben")


@router.post("/{rule_id}/reject", response_model=RuleOut)
def reject(
    rule_id: str,
    decision: ReviewDecision,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.change_approver)),
):
    return _decide(db, rule_id, user, decision, RuleStatus.rejected, "Regel abgelehnt")


@router.post("/{rule_id}/deactivate", response_model=RuleOut)
def deactivate(
    rule_id: str,
    decision: ReviewDecision,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.operations, Role.architect)),
):
    return _decide(db, rule_id, user, decision, RuleStatus.deactivated, "Regel deaktiviert")


@router.post("/{rule_id}/extend", response_model=RuleOut)
def extend_validity(
    rule_id: str,
    payload: ExtendRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations, Role.change_approver)),
):
    """Rezertifizierung: Gültigkeit verlängern, ohne den Freigabe-Status zurückzusetzen."""
    from datetime import date

    rule = get_rule_or_404(db, rule_id)
    if rule.status != RuleStatus.approved:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Nur freigegebene Regeln können rezertifiziert werden – abgelaufene/deaktivierte bitte neu einreichen",
        )
    try:
        new_date = date.fromisoformat(payload.valid_until)
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Ungültiges Datum (erwartet YYYY-MM-DD)")
    if new_date <= date.today():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Neues Gültig-bis muss in der Zukunft liegen")
    rule.valid_until = new_date.isoformat()
    rule.version += 1
    add_version(db, rule, user, f"Rezertifiziert: Gültigkeit verlängert bis {rule.valid_until}")
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
    """Umsetzungsstatus je Komponente pflegen (Betrieb), z.B. {"FW-Cluster-FFM": "umgesetzt"}."""
    rule = get_rule_or_404(db, rule_id)
    # Validierung: nur bekannte Statuswerte und nur Komponenten dieser Regel
    allowed_status = {"offen", "neu", "zu ändern", "zu löschen", "umgesetzt", "deaktiviert"}
    component_names = {c.name for c in rule.components}
    for name, value in impl_status.items():
        if name not in component_names:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"Komponente '{name}' gehört nicht zur Regel {rule_id}")
        if value not in allowed_status:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"Ungültiger Umsetzungsstatus '{value}' "
                                f"(erlaubt: {', '.join(sorted(allowed_status))})")
    rule.impl_status = {**(rule.impl_status or {}), **impl_status}
    rule.version += 1
    add_version(db, rule, user, f"Umsetzungsstatus: {impl_status}")
    db.commit()
    db.refresh(rule)
    return rule


# --- Versionen, Kommentare, Konflikte ---------------------------------------

@router.get("/{rule_id}/implementation")
def implementation(rule_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Zeigt je zugeordneter Komponente, wie die Regel dort umgesetzt wird:
    Juniper set-Kommandos, Check Point mgmt_cli bzw. ACI Contract (mit EPG-Auflösung)."""
    from ..exporters import aci, checkpoint, juniper

    rule = get_rule_or_404(db, rule_id)
    results = []
    for component in sorted(rule.components, key=lambda c: c.name):
        entry = {
            "component_id": component.id,
            "component": component.name,
            "type": component.type.value,
            "impl_status": (rule.impl_status or {}).get(component.name, "offen"),
        }
        if component.type.value == "juniper":
            entry["format"] = "juniper"
            entry["preview"] = juniper.export_rule(rule)
        elif component.type.value == "checkpoint":
            entry["format"] = "checkpoint-cli"
            lines = checkpoint.export_cli([rule]).splitlines()
            entry["preview"] = "\n".join(
                l for l in lines
                if l.startswith(("mgmt_cli add", "#")) and not l.startswith("#!")
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
                entry["warning"] = (
                    "Keine EPG-Zuordnung für Quelle/Ziel gepflegt – Export erfolgt als "
                    "Einzel-Contract (Fallback). EPG-Zuordnung: Seite Objekte → ACI EPGs."
                )
        results.append(entry)
    if rule.status.value != "approved":
        for entry in results:
            entry.setdefault(
                "note", f"Regel ist im Status '{rule.status.value}' – Vorschau zeigt die künftige Umsetzung"
            )
    return {"rule_id": rule.rule_id, "implementations": results}


@router.get("/{rule_id}/versions", response_model=list[RuleVersionOut])
def versions(rule_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
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
def conflicts(rule_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    rule = get_rule_or_404(db, rule_id)
    others = active_rules(db).filter(Rule.status != RuleStatus.deactivated,
                                     Rule.vrf_id == rule.vrf_id).all()
    warnings = find_conflicts(rule, others)
    # Zusätzlich: Verstöße/Hinweise aus der Zonen-Kommunikationsmatrix
    zone_result = check_zone_pair(db, rule.source_zone, rule.destination_zone, rule.platforms or [])
    for msg in zone_result.messages:
        if zone_result.policy in ("intra",):
            continue
        warnings.append(
            {
                "rule_id": rule.rule_id,
                "other_rule_id": f"{rule.source_zone or '?'} → {rule.destination_zone or '?'}",
                "kind": "zone-blocked" if not zone_result.allowed else "zone-hinweis",
                "detail": msg,
            }
        )
    return warnings


@router.get("/{rule_id}/risk")
def rule_risk(rule_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Risikoanalyse einer Regel (any-to-any, breite Netze, riskante Dienste;
    Schweregrad gewichtet nach Schutzbedarf der Ziel-Zone)."""
    from ..risk import assess_rule

    return assess_rule(db, get_rule_or_404(db, rule_id))


@router.post("/risk/assess")
def risk_assess(payload: ResolveRequest, db: Session = Depends(get_db),
                _: User = Depends(get_current_user)):
    """Live-Risikobewertung fürs Regelformular (ohne gespeicherte Regel)."""
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
