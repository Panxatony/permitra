"""Audit-Log-Endpunkt für SIEM-Integration (Issue #11)."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..audit import collect
from ..auth import require_roles
from ..database import get_db
from ..models import Role, User

router = APIRouter(prefix="/api/audit-log", tags=["audit"])


@router.get("")
def audit_log(
    since: str | None = Query(None, description="Nur Ereignisse ab diesem ISO-Zeitstempel"),
    type: str | None = Query(None, description="'rule' | 'zone_change'"),
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    """Einheitliches, maschinenlesbares Audit-Log (neueste zuerst) für SIEM-Abruf."""
    return collect(db, since=since, limit=limit, event_type=type)
