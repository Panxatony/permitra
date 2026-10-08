"""Object catalogue: reusable address and service objects.

Address objects tie a name (alias) to an IP or network. When an object's IP changes,
every rule address entry carrying that alias is updated along with it automatically
(including a version entry for each affected rule). The new address goes through
the same checks an edit of the rule would face, and a rule in force loses its
approval: what was approved was the old address.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from .. import groups, rule_recheck
from ..auth import get_current_user, require_roles
from ..database import get_db
from ..messages import _
from ..models import (
    IN_FORCE,
    AddressGroup,
    AddressObject,
    GroupKind,
    Role,
    RuleStatus,
    RuleVersion,
    ServiceObject,
    User,
    active_rules,
)
from ..validation import validate_ip_entry, validate_service
from ..vrf import get_vrf

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
        state, reasons = rule_recheck.reassess(db, rule, new["source"], new["destination"])
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



# --- Address groups -----------------------------------------------------------

class GroupIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    kind: GroupKind = GroupKind.selector
    selector: str = Field("", max_length=256)
    members: list[dict] = Field(default_factory=list)
    description: str = Field("", max_length=256)
    vrf: str = ""

    @field_validator("name")
    @classmethod
    def single_line(cls, v):
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
            raise ValueError(_("{field} must not contain line breaks or control characters", field="name"))
        return v.strip()

    @model_validator(mode="after")
    def shape(self):
        if self.kind == GroupKind.selector:
            self.selector = groups.validate_selector(self.selector)
            self.members = []
        else:
            cleaned = []
            for m in self.members:
                if m.get("workload"):
                    cleaned.append({"workload": str(m["workload"]).strip()})
                elif m.get("ip"):
                    cleaned.append({"ip": validate_ip_entry(str(m["ip"])), "alias": str(m.get("alias") or "").strip()})
            if not cleaned:
                raise ValueError(_("A static group needs at least one member"))
            self.members, self.selector = cleaned, ""
        return self


class GroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    kind: GroupKind
    selector: str
    members: list[dict]
    description: str
    vrf_id: int


def resync_groups(db: Session, names: set[str], username: str, *, reset_review: bool) -> list[str]:
    """Bring every rule that refers to one of the groups up to date.

    Each rule's group references are expanded against the current membership;
    a rule whose addresses did not move is left alone. Every rule that moved
    is re-checked first, and one inadmissible rule refuses the whole change
    (422 naming it) - the alternative is a rule silently out of policy.
    `reset_review` is the caller's statement about what kind of change this
    is (see rule_recheck.apply). Returns the rule IDs that were rewritten."""
    if not names:
        return []
    plans, problems = [], []
    for rule in groups.rules_referencing(db, names):
        new = {}
        for field in ("source", "destination"):
            expanded, issues = groups.expand_entries(db, getattr(rule, field) or [], rule.vrf_id)
            if issues:
                problems.append(f"{rule.rule_id}: " + "; ".join(issues))
            new[field] = expanded
        if problems and problems[-1].startswith(rule.rule_id):
            continue
        if new["source"] == (rule.source or []) and new["destination"] == (rule.destination or []):
            continue
        state, reasons = rule_recheck.reassess(db, rule, new["source"], new["destination"])
        if reasons:
            problems.append(f"{rule.rule_id}: " + "; ".join(reasons))
        else:
            plans.append((rule, state))
    if problems:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _("The change would leave rule(s) inadmissible – {problems}", problems=" | ".join(problems)),
        )
    for rule, state in plans:
        before = {e.get("ip") for e in (rule.source or []) + (rule.destination or []) if e.get("group")}
        after = {e.get("ip") for e in state["source"] + state["destination"] if e.get("group")}
        rule_recheck.apply(
            db, rule, state, username,
            "Group membership changed: {added} address(es) added, {removed} removed",
            {"added": str(len(after - before)), "removed": str(len(before - after))},
            reset_review=reset_review,
        )
    return [rule.rule_id for rule, _state in plans]


@router.get("/groups", response_model=list[GroupOut])
def list_groups(vrf: str | None = None, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    query = db.query(AddressGroup)
    if vrf:
        query = query.filter(AddressGroup.vrf_id == get_vrf(db, vrf).id)
    return query.order_by(AddressGroup.name).all()


@router.get("/groups/{group_id}/members")
def group_members(group_id: int, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """What the group resolves to right now - the preview the rule form shows."""
    group = db.get(AddressGroup, group_id)
    if not group:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Group not found"))
    members = groups.resolve_group(db, group)
    return {"group": group.name, "kind": group.kind.value, "count": len(members), "members": members,
            "rules": [r.rule_id for r in groups.rules_referencing(db, {group.name})]}


@router.post("/groups", response_model=GroupOut, status_code=201)
def create_group(
    payload: GroupIn,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    vrf = get_vrf(db, payload.vrf or None)
    if groups.find_group(db, payload.name, vrf.id):
        raise HTTPException(status.HTTP_409_CONFLICT, _("Group '{name}' already exists", name=payload.name))
    group = AddressGroup(vrf_id=vrf.id, name=payload.name, kind=payload.kind, selector=payload.selector,
                         members=payload.members, description=payload.description)
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


@router.put("/groups/{group_id}", response_model=GroupOut)
def update_group(
    group_id: int,
    payload: GroupIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    group = db.get(AddressGroup, group_id)
    if not group:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Group not found"))
    other = groups.find_group(db, payload.name, group.vrf_id)
    if other and other.id != group.id:
        raise HTTPException(status.HTTP_409_CONFLICT, _("Group '{name}' already exists", name=payload.name))
    if payload.name.lower() != group.name.lower() and groups.rules_referencing(db, {group.name}):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Group '{name}' is referenced by rules and cannot be renamed", name=group.name))
    definition_changed = (payload.kind != group.kind or payload.selector != group.selector
                          or payload.members != group.members)
    group.name, group.kind, group.selector = payload.name, payload.kind, payload.selector
    group.members, group.description = payload.members, payload.description
    db.flush()
    if definition_changed:
        # Somebody changed what the group *means*: that is a content change
        # to every rule using it, and the approval is withdrawn.
        resync_groups(db, {group.name}, user.username, reset_review=True)
    db.commit()
    db.refresh(group)
    return group


@router.delete("/groups/{group_id}", status_code=204)
def delete_group(
    group_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    group = db.get(AddressGroup, group_id)
    if not group:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Group not found"))
    used = groups.rules_referencing(db, {group.name})
    if used:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Group '{name}' is referenced by rule(s): {rules}",
                              name=group.name, rules=", ".join(r.rule_id for r in used)))
    db.delete(group)
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
