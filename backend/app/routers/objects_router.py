"""Object catalogue: reusable address and service objects.

Address objects tie a name (alias) to an IP or network. When an object's IP changes,
every rule address entry carrying that alias is updated along with it automatically
(including a version entry for each affected rule). The new address goes through
the same checks an edit of the rule would face, and a rule in force loses its
approval: what was approved was the old address.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..component_resolution import resolve_rule_components
from ..database import get_db
from ..messages import _
from ..models import IN_FORCE, AddressObject, Role, RuleStatus, RuleVersion, ServiceObject, User, active_rules
from ..validation import validate_ip_entry, validate_service
from ..zone_check import check_zone_pair, resolve_zone_for_entries

router = APIRouter(prefix="/api/objects", tags=["objects"])


class AddressObjectIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    ip: str
    description: str = ""

    @field_validator("ip")
    @classmethod
    def check_ip(cls, v):
        return validate_ip_entry(v)


class ServiceObjectIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    protocol: str
    port: str = ""
    description: str = ""

    @field_validator("protocol")
    @classmethod
    def check(cls, v, info):
        return v.strip().upper()


class AddressObjectOut(AddressObjectIn):
    model_config = ConfigDict(from_attributes=True)

    id: int


class ServiceObjectOut(ServiceObjectIn):
    model_config = ConfigDict(from_attributes=True)

    id: int


def _reassess(db: Session, rule, source: list[dict], destination: list[dict]) -> tuple[dict, list[str]]:
    """Run a rule's new addresses through the checks an edit of the rule would face.

    Zones are derived data, so they are derived again; the components follow the
    addresses; and the zone matrix and the BSI firewall requirement are asked
    about the pair that results. Returns the state to apply and the reasons it
    must not be applied - the same reasons the rule form would show.
    """
    reasons: list[str] = []
    zones = {}
    for label, field, entries in ((_("Source"), "source", source),
                                  (_("Destination"), "destination", destination)):
        zone, unassigned, hits = resolve_zone_for_entries(db, entries, rule.vrf_id)
        if unassigned:
            reasons.append(
                _("{label}: network(s) not assigned to any security zone: {networks} "
                  "– create the network on the Networks page first and assign it to a "
                  "security zone",
                  label=label, networks=", ".join(unassigned)))
        elif len(hits) > 1:
            reasons.append(_("{label} spans several zones ({zones}) – split the rule",
                             label=label, zones=", ".join(sorted(hits))))
        zones[field] = zone or getattr(rule, f"{field}_zone") or ""
    src, dst = zones["source"], zones["destination"]
    components, unknown = resolve_rule_components(db, source, destination, src, dst, rule.vrf_id)
    if unknown:
        reasons.append(_("No component mapping is defined yet for these addresses: ")
                       + ", ".join(u["ip"] for u in unknown)
                       + _(". Define it once via the address mapping."))
    elif not components:
        reasons.append(_("No enforcing components could be determined"))
    if not reasons:
        if src.upper() != dst.upper() and not any(c.is_firewall for c in components):
            reasons.append(_("A zone transition requires a firewall – Cisco ACI alone is not sufficient (BSI)"))
        verdict = check_zone_pair(db, src, dst, [c.type.value for c in components])
        if not verdict.allowed:
            reasons.append(_("Zone matrix: ") + "; ".join(verdict.messages))
    state = {"source": source, "destination": destination,
             "source_zone": src, "destination_zone": dst, "components": components}
    return state, reasons


def propagate_ip_change(db: Session, obj: AddressObject, old_ip: str, username: str) -> int:
    """Propagate the new IP into every rule entry that carries this alias.

    Two passes: first every affected rule is assessed, then the change is
    applied to all of them or to none. A single rule the new address would
    leave inadmissible refuses the whole object change (422 naming the rule),
    because the alternative - some rules changed, one of them silently out of
    policy - is the state the checks exist to prevent.

    A rule in force (or rejected) goes back to draft. The approval covered the
    old address, and an object edit needs no approver - without the reset, this
    would be the one way to point an approved rule at a new target unreviewed.
    """
    plans, problems = [], []
    for rule in active_rules(db).all():
        if getattr(rule, "ping_baseline", False):
            continue  # addresses are `any` by definition; zones are declared, not derived
        new, touched = {}, False
        for field in ("source", "destination"):
            entries = []
            for entry in getattr(rule, field) or []:
                if (entry.get("alias") or "").strip() == obj.name and entry.get("ip") != obj.ip:
                    entries.append({**entry, "ip": obj.ip})
                    touched = True
                else:
                    entries.append(entry)
            new[field] = entries
        if not touched:
            continue
        state, reasons = _reassess(db, rule, new["source"], new["destination"])
        if reasons:
            problems.append(f"{rule.rule_id}: " + "; ".join(reasons))
        else:
            plans.append((rule, state))
    if problems:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _("Address object '{name}': the new IP {ip} would leave rule(s) inadmissible – {problems}",
              name=obj.name, ip=obj.ip, problems=" | ".join(problems)),
        )
    for rule, state in plans:
        rule.source, rule.destination = state["source"], state["destination"]
        rule.source_zone, rule.destination_zone = state["source_zone"], state["destination_zone"]
        rule.components = state["components"]
        rule.removal_reason = ""   # the checks above passed; an earlier proposal is moot
        rule.version += 1
        template = "Address object '{name}': IP {old_ip} → {new_ip}"
        if rule.status in (*IN_FORCE, RuleStatus.rejected):
            rule.status = RuleStatus.draft
            template = ("Address object '{name}': IP {old_ip} → {new_ip} "
                        "– the approval is withdrawn, the rule needs a new review")
        db.add(
            RuleVersion(
                rule_pk=rule.id, version=rule.version,
                snapshot={"auto": "address-object-update"},
                change_note=template,
                change_values={"name": obj.name, "old_ip": old_ip, "new_ip": obj.ip},
                changed_by=username,
            )
        )
    return len(plans)


# --- Address objects ---------------------------------------------------------

@router.get("/addresses", response_model=list[AddressObjectOut])
def list_addresses(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return db.query(AddressObject).order_by(AddressObject.name).all()


@router.post("/addresses", response_model=AddressObjectOut, status_code=201)
def create_address(
    payload: AddressObjectIn,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    if db.query(AddressObject).filter(AddressObject.name.ilike(payload.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Address object '{name}' already exists", name=payload.name))
    obj = AddressObject(**payload.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/addresses/{object_id}", response_model=AddressObjectOut)
def update_address(
    object_id: int,
    payload: AddressObjectIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    obj = db.get(AddressObject, object_id)
    if not obj:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Address object not found"))
    old_ip = obj.ip
    obj.name = payload.name
    obj.ip = payload.ip
    obj.description = payload.description
    changed = propagate_ip_change(db, obj, old_ip, user.username) if old_ip != obj.ip else 0
    db.commit()
    db.refresh(obj)
    # Report the number of updated rules in the description line, standing in for a header
    out = AddressObjectOut.model_validate(obj)
    if changed:
        out.description = _("{description} [{changed} rule(s) updated]",
                            description=obj.description, changed=changed).strip()
    return out


@router.delete("/addresses/{object_id}", status_code=204)
def delete_address(
    object_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    obj = db.get(AddressObject, object_id)
    if not obj:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Address object not found"))
    db.delete(obj)
    db.commit()


# --- Service objects ---------------------------------------------------------

@router.get("/services", response_model=list[ServiceObjectOut])
def list_services(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return db.query(ServiceObject).order_by(ServiceObject.name).all()


@router.post("/services", response_model=ServiceObjectOut, status_code=201)
def create_service(
    payload: ServiceObjectIn,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    try:
        validate_service(payload.protocol, payload.port)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    if db.query(ServiceObject).filter(ServiceObject.name.ilike(payload.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Service object '{name}' already exists", name=payload.name))
    obj = ServiceObject(**payload.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/services/{object_id}", status_code=204)
def delete_service(
    object_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    obj = db.get(ServiceObject, object_id)
    if not obj:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Service object not found"))
    db.delete(obj)
    db.commit()
