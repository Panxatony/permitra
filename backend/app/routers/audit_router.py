"""Audit log endpoint for SIEM integration (issue #11), plus integrity
verification and delivery status (issue #26)."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..audit import collect, create_checkpoint, siem_status, verify_chain
from ..auth import require_roles
from ..database import get_db
from ..models import Role, User

router = APIRouter(prefix="/api/audit-log", tags=["audit"])


@router.get("")
def audit_log(
    since: str | None = Query(None, description="Only events from this ISO timestamp onwards"),
    type: str | None = Query(None, description="'rule' | 'zone_change'"),
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    """Unified, machine-readable audit log (newest first) for SIEM retrieval."""
    return collect(db, since=since, limit=limit, event_type=type)


@router.get("/verify")
def audit_verify(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    """Verify the integrity of the audit hash chain (#26). ok=False as soon as an
    entry was altered or the ordering/gap-free sequence is broken."""
    return verify_chain(db)


@router.post("/checkpoint", status_code=201)
def audit_checkpoint(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    """Anchor the current chain head immediately (#26) instead of waiting for the
    periodic job – e.g. before securing evidence."""
    cp = create_checkpoint(db)
    if cp is None:
        return {"detail": "No audit events yet – nothing to anchor."}
    return {"event_count": cp.event_count, "head_hash": cp.head_hash,
            "ts": cp.ts.isoformat() if cp.ts else None,
            "delivered": cp.delivered_at is not None}


@router.get("/siem-status")
def audit_siem_status(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    """Delivery state towards the SIEM (#26): configured, pending, sent."""
    return siem_status(db)
