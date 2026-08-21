"""ACI EPG-Katalog und Adresse->EPG-Zuordnung (Basis des Contract-Exports)."""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..component_resolution import normalize_ip
from ..database import get_db
from ..models import AddressEpgMap, Epg, Role, User
from ..validation import validate_ip_entry
from ..vrf import get_vrf

router = APIRouter(prefix="/api/epgs", tags=["epgs"])


class EpgIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    tenant: str = ""
    app_profile: str = ""
    bridge_domain: str = ""
    description: str = ""


class EpgOut(EpgIn):
    model_config = ConfigDict(from_attributes=True)
    id: int


class EpgMapIn(BaseModel):
    ip: str
    vrf: str = ""
    alias: str = ""
    epg_id: int

    @field_validator("ip")
    @classmethod
    def check_ip(cls, v):
        return validate_ip_entry(v)


class EpgMapOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ip: str
    alias: str
    epg_id: int
    epg_name: str = ""


def map_out(m: AddressEpgMap) -> EpgMapOut:
    out = EpgMapOut.model_validate(m)
    out.epg_name = m.epg.name if m.epg else ""
    return out


@router.get("", response_model=list[EpgOut])
def list_epgs(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(Epg).order_by(Epg.name).all()


@router.post("", response_model=EpgOut, status_code=201)
def create_epg(
    payload: EpgIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    if db.query(Epg).filter(Epg.name.ilike(payload.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, f"EPG '{payload.name}' existiert bereits")
    epg = Epg(**payload.model_dump())
    db.add(epg)
    db.commit()
    db.refresh(epg)
    return epg


@router.delete("/{epg_id}", status_code=204)
def delete_epg(
    epg_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    epg = db.query(Epg).get(epg_id)
    if not epg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "EPG nicht gefunden")
    used = db.query(AddressEpgMap).filter(AddressEpgMap.epg_id == epg_id).count()
    if used:
        raise HTTPException(status.HTTP_409_CONFLICT, f"EPG wird von {used} Adress-Zuordnung(en) verwendet")
    db.delete(epg)
    db.commit()


@router.get("/address-map", response_model=list[EpgMapOut])
def list_map(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return [map_out(m) for m in db.query(AddressEpgMap).order_by(AddressEpgMap.ip).all()]


@router.post("/address-map", response_model=EpgMapOut)
def upsert_map(
    payload: EpgMapIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    if not db.query(Epg).get(payload.epg_id):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "EPG nicht gefunden")
    norm = normalize_ip(payload.ip)
    if norm is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Ungültige Adresse: '{payload.ip}'")
    vrf = get_vrf(db, payload.vrf or None)
    mapping = db.query(AddressEpgMap).filter(AddressEpgMap.ip == norm,
                                             AddressEpgMap.vrf_id == vrf.id).first()
    if not mapping:
        mapping = AddressEpgMap(ip=norm, vrf_id=vrf.id, created_by=user.username)
        db.add(mapping)
    mapping.alias = payload.alias
    mapping.epg_id = payload.epg_id
    db.commit()
    db.refresh(mapping)
    return map_out(mapping)


@router.delete("/address-map/{mapping_id}", status_code=204)
def delete_map(
    mapping_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    mapping = db.query(AddressEpgMap).get(mapping_id)
    if not mapping:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Zuordnung nicht gefunden")
    db.delete(mapping)
    db.commit()
