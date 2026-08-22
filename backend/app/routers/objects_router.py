"""Object catalogue: reusable address and service objects.

Address objects tie a name (alias) to an IP or network. When an object's IP changes,
every rule address entry carrying that alias is updated along with it automatically
(including a version entry for each affected rule).
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..database import get_db
from ..models import AddressObject, Role, RuleVersion, ServiceObject, User, active_rules
from ..validation import validate_ip_entry, validate_service

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
    """Propagate the new IP into every rule entry that carries this alias."""
    changed = 0
    for rule in active_rules(db).all():
        touched = False
        for field in ("source", "destination"):
            entries = getattr(rule, field) or []
            new_entries = []
            for entry in entries:
                if (entry.get("alias") or "").strip() == obj.name and entry.get("ip") != obj.ip:
                    new_entries.append({**entry, "ip": obj.ip})
                    touched = True
                else:
                    new_entries.append(entry)
            if touched:
                setattr(rule, field, new_entries)
        if touched:
            rule.version += 1
            db.add(
                RuleVersion(
                    rule_pk=rule.id, version=rule.version,
                    snapshot={"auto": "address-object-update"},
                    change_note=f"Address object '{obj.name}': IP {old_ip} → {obj.ip}",
                    changed_by=username,
                )
            )
            changed += 1
    return changed


# --- Address objects ---------------------------------------------------------

@router.get("/addresses", response_model=list[AddressObjectOut])
def list_addresses(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(AddressObject).order_by(AddressObject.name).all()


@router.post("/addresses", response_model=AddressObjectOut, status_code=201)
def create_address(
    payload: AddressObjectIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    if db.query(AddressObject).filter(AddressObject.name.ilike(payload.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, f"Address object '{payload.name}' already exists")
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
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Address object not found")
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
        out.description = f"{obj.description} [{changed} rule(s) updated]".strip()
    return out


@router.delete("/addresses/{object_id}", status_code=204)
def delete_address(
    object_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    obj = db.get(AddressObject, object_id)
    if not obj:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Address object not found")
    db.delete(obj)
    db.commit()


# --- Service objects ---------------------------------------------------------

@router.get("/services", response_model=list[ServiceObjectOut])
def list_services(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(ServiceObject).order_by(ServiceObject.name).all()


@router.post("/services", response_model=ServiceObjectOut, status_code=201)
def create_service(
    payload: ServiceObjectIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    try:
        validate_service(payload.protocol, payload.port)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    if db.query(ServiceObject).filter(ServiceObject.name.ilike(payload.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, f"Service object '{payload.name}' already exists")
    obj = ServiceObject(**payload.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/services/{object_id}", status_code=204)
def delete_service(
    object_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    obj = db.get(ServiceObject, object_id)
    if not obj:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Service object not found")
    db.delete(obj)
    db.commit()
