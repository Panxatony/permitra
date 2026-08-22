"""VRF-/Mandanten-Verwaltung (z.B. IT und OT mit überlappenden Netzen)."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..database import get_db
from ..models import Role, Rule, User, Vrf, ZoneNetwork

router = APIRouter(prefix="/api/vrfs", tags=["vrfs"])


@router.get("")
def list_vrfs(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return [
        {"id": v.id, "name": v.name, "description": v.description}
        for v in db.query(Vrf).order_by(Vrf.id).all()
    ]


@router.post("", status_code=201)
def create_vrf(
    payload: dict,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect)),
):
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Name fehlt")
    if db.query(Vrf).filter(Vrf.name.ilike(name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, f"VRF '{name}' existiert bereits")
    vrf = Vrf(name=name, description=payload.get("description", ""))
    db.add(vrf)
    db.commit()
    return {"id": vrf.id, "name": vrf.name}


@router.delete("/{vrf_id}", status_code=204)
def delete_vrf(
    vrf_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    vrf = db.get(Vrf, vrf_id)
    if not vrf:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VRF nicht gefunden")
    # Bewusst inklusive gelöschter Regeln: Rule.vrf_id ist ein Fremdschlüssel,
    # ein Löschen des VRF würde sie verwaisen lassen.
    rules = db.query(Rule).filter(Rule.vrf_id == vrf_id).count()
    nets = db.query(ZoneNetwork).filter(ZoneNetwork.vrf_id == vrf_id).count()
    if rules or nets:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"VRF '{vrf.name}' enthält noch {rules} Regel(n) und {nets} Netz(e)")
    db.delete(vrf)
    db.commit()
