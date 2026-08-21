"""VRF-Kontext: Default ist der erste (älteste) VRF, üblicherweise 'IT'."""
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from .models import Vrf


def get_vrf(db: Session, name: str | None = None) -> Vrf:
    if name:
        vrf = db.query(Vrf).filter(Vrf.name.ilike(name.strip())).first()
        if not vrf:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"VRF '{name}' nicht gefunden")
        return vrf
    vrf = db.query(Vrf).order_by(Vrf.id).first()
    if not vrf:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Kein VRF angelegt")
    return vrf
