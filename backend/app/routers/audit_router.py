"""Audit-Log-Endpunkt für SIEM-Integration (Issue #11) sowie Integritäts-
prüfung und Zustellstatus (Issue #26)."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..audit import collect, siem_status, verify_chain
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


@router.get("/verify")
def audit_verify(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    """Prüft die Integrität der Audit-Hash-Kette (#26). ok=False, sobald ein
    Eintrag verändert wurde oder die Reihenfolge/Lückenlosigkeit verletzt ist."""
    return verify_chain(db)


@router.get("/siem-status")
def audit_siem_status(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    """Zustellzustand an das SIEM (#26): konfiguriert, ausstehend, gesendet."""
    return siem_status(db)
