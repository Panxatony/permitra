"""VRF/tenant management (e.g. IT and OT with overlapping networks)."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..database import get_db
from ..messages import _
from ..models import Role, Rule, User, Vrf, ZoneNetwork

router = APIRouter(prefix="/api/vrfs", tags=["vrfs"])


@router.get("")
def list_vrfs(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return [
        {"id": v.id, "name": v.name, "description": v.description}
        for v in db.query(Vrf).order_by(Vrf.id).all()
    ]


@router.post("", status_code=201)
def create_vrf(
    payload: dict,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect)),
):
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, _("Name is missing"))
    if db.query(Vrf).filter(Vrf.name.ilike(name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, _("VRF '{name}' already exists", name=name))
    vrf = Vrf(name=name, description=payload.get("description", ""))
    db.add(vrf)
    db.commit()
    return {"id": vrf.id, "name": vrf.name}


@router.delete("/{vrf_id}", status_code=204)
def delete_vrf(
    vrf_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.admin)),
):
    vrf = db.get(Vrf, vrf_id)
    if not vrf:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("VRF not found"))
    # Deliberately including soft-deleted rules: Rule.vrf_id is a foreign key, so
    # deleting the VRF would leave them orphaned.
    rules = db.query(Rule).filter(Rule.vrf_id == vrf_id).count()
    nets = db.query(ZoneNetwork).filter(ZoneNetwork.vrf_id == vrf_id).count()
    if rules or nets:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("VRF '{name}' still contains {rules} rule(s) and {nets} network(s)",
                              name=vrf.name, rules=rules, nets=nets))
    db.delete(vrf)
    db.commit()
