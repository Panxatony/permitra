"""Permitra settings: readable by every signed-in role (the UI shows, for example,
the zone matrix default behaviour); only admins may change them."""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import audit
from ..auth import get_current_user, require_roles
from ..database import get_db
from ..models import Role, User
from ..settings import KNOWN_SETTINGS, all_settings, get_setting, set_setting

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/public")
def read_public_settings(db: Session = Depends(get_db)):
    """The few settings the interface needs BEFORE anyone is signed in.

    The login page has to render in the configured language, but the regular
    settings endpoint requires authentication. Only the language is exposed
    here - nothing about it is sensitive, and keeping the response minimal
    avoids leaking configuration to unauthenticated callers."""
    return {"ui_language": get_setting(db, "ui_language")}


@router.get("")
def read_settings(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return all_settings(db)


@router.put("")
def update_settings(
    request: Request,
    payload: dict,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.admin)),
):
    for key, value in payload.items():
        if key not in KNOWN_SETTINGS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown setting '{key}'")
        try:
            set_setting(db, key, str(value))
            audit.record(db, "admin", "setting.changed", actor=admin.username, object=key, detail=str(value), source_ip=audit.client_ip(request))
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return all_settings(db)
