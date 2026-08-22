"""Permitra-Einstellungen: lesen für alle angemeldeten Rollen (die UI zeigt
z.B. das Matrix-Default-Verhalten an), ändern nur für Admins."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..database import get_db
from ..models import Role, User
from ..settings import KNOWN_SETTINGS, all_settings, set_setting

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
def read_settings(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return all_settings(db)


@router.put("")
def update_settings(
    payload: dict,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    for key, value in payload.items():
        if key not in KNOWN_SETTINGS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unbekannte Einstellung '{key}'")
        try:
            set_setting(db, key, str(value))
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    return all_settings(db)
