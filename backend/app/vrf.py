"""VRF context: the default is the first (oldest) VRF, usually 'IT'."""
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from .messages import _
from .models import Vrf


def get_vrf(db: Session, name: str | None = None) -> Vrf:
    if name:
        vrf = db.query(Vrf).filter(Vrf.name.ilike(name.strip())).first()
        if not vrf:
            raise HTTPException(status.HTTP_404_NOT_FOUND, _("VRF '{name}' not found", name=name))
        return vrf
    vrf = db.query(Vrf).order_by(Vrf.id).first()
    if not vrf:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, _("No VRF configured"))
    return vrf
