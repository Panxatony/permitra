from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..expiry import expiring_rules
from ..models import (
    AciGateway,
    Rule,
    RuleStatus,
    RuleVersion,
    SecurityComponent,
    User,
    Zone,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("")
def dashboard(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    status_counts = dict(
        db.query(Rule.status, func.count(Rule.id)).filter(Rule.deleted_at.is_(None)).group_by(Rule.status).all()
    )
    expired, expiring = expiring_rules(db, days=30)

    recent = (
        db.query(RuleVersion, Rule.rule_id)
        .join(Rule, RuleVersion.rule_pk == Rule.id)
        .order_by(RuleVersion.changed_at.desc())
        .limit(10)
        .all()
    )

    per_component = [
        {
            "id": c.id,
            "name": c.name,
            "type": c.type.value,
            "rules": db.query(Rule).filter(Rule.components.any(SecurityComponent.id == c.id), Rule.deleted_at.is_(None)).count(),
        }
        for c in db.query(SecurityComponent).order_by(SecurityComponent.name).all()
    ]

    # Umzusetzende Regeln: freigegeben, aber auf mind. einer Komponente noch offen
    from .rules_router import impl_pending

    # Freigegebene mit offener Umsetzung + deaktivierte mit Rückbau ("zu löschen")
    candidate_rules = db.query(Rule).filter(
        Rule.status.in_((RuleStatus.approved, RuleStatus.deactivated)),
        Rule.deleted_at.is_(None)
    ).all()
    to_implement = sum(1 for r in candidate_rules if impl_pending(r))

    return {
        "rules_total": db.query(Rule).filter(Rule.deleted_at.is_(None)).count(),
        "by_status": {s.value: status_counts.get(s, 0) for s in RuleStatus},
        "open_reviews": status_counts.get(RuleStatus.in_review, 0),
        "to_implement": to_implement,
        "expired": len(expired),
        "expiring_30d": len(expiring),
        "zones": db.query(Zone).count(),
        "components": per_component,
        "aci_gateways": db.query(AciGateway).count(),
        "recent_changes": [
            {
                "rule_id": rule_id,
                "version": v.version,
                "change_note": v.change_note,
                "changed_by": v.changed_by,
                "changed_at": v.changed_at.isoformat() if v.changed_at else None,
            }
            for v, rule_id in recent
        ],
    }
