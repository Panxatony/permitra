from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..component_resolution import normalize_ip
from ..database import get_db
from ..messages import _
from ..models import AddressComponentMap, Role, SecurityComponent, User
from ..schemas import AddressMapCreate, AddressMapOut
from ..vrf import get_vrf

router = APIRouter(prefix="/api/address-map", tags=["address-map"])


@router.get("", response_model=list[AddressMapOut])
def list_mappings(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return db.query(AddressComponentMap).order_by(AddressComponentMap.ip).all()


@router.post("", response_model=AddressMapOut)
def upsert_mapping(
    payload: AddressMapCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Set (or update) the component assignment for an address."""
    known = {
        c.id for c in db.query(SecurityComponent).filter(
            SecurityComponent.id.in_(payload.component_ids)
        )
    }
    missing = set(payload.component_ids) - known
    if missing:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("Unknown component(s): {components}", components=sorted(missing)))

    norm = normalize_ip(payload.ip)
    if norm is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("Invalid address: '{ip}'", ip=payload.ip))
    vrf = get_vrf(db, getattr(payload, "vrf", "") or None)
    mapping = db.query(AddressComponentMap).filter(
        AddressComponentMap.ip == norm, AddressComponentMap.vrf_id == vrf.id).first()
    if not mapping:
        mapping = AddressComponentMap(ip=norm, vrf_id=vrf.id, created_by=user.username)
        db.add(mapping)
    mapping.alias = payload.alias
    mapping.component_ids = sorted(set(payload.component_ids))
    db.commit()
    db.refresh(mapping)
    return mapping


@router.delete("/{mapping_id}", status_code=204)
def delete_mapping(
    mapping_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    mapping = db.get(AddressComponentMap, mapping_id)
    if not mapping:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Mapping not found"))
    db.delete(mapping)
    db.commit()
