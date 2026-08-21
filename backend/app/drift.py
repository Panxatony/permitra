"""Soll-Ist-Abgleich (Drift Detection) je Komponente.

Soll: alle freigegebenen Regeln, die der Komponente zugeordnet sind.
Ist:  die hinterlegte Gerätekonfiguration (hochgeladen oder – später – per
      Geräte-API abgerufen). Der Abgleich arbeitet über die Rule-IDs (SR####),
      die Permitra in Policy-Namen/Kommentaren aller Exporte mitführt.

Befunde:
  - missing:  freigegeben, aber nicht auf dem Gerät (Umsetzung fehlt)
  - stale:    auf dem Gerät, aber in Permitra nicht (mehr) freigegeben
  - unknown:  Rule-IDs auf dem Gerät, die Permitra gar nicht kennt (Schatten-Regeln)
"""
import re

from sqlalchemy.orm import Session

from .models import ComponentActualConfig, Rule, RuleStatus, SecurityComponent

RULE_ID_RE = re.compile(r"\bSR\d{3,6}\b")


def rule_brief(rule: Rule) -> dict:
    return {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "status": rule.status.value,
        "justification": rule.justification,
        "services": rule.services,
    }


def analyze_drift(db: Session, component: SecurityComponent) -> dict:
    config = (
        db.query(ComponentActualConfig)
        .filter(ComponentActualConfig.component_id == component.id)
        .first()
    )
    if not config or not config.content.strip():
        return {"has_config": False, "component_id": component.id, "component": component.name}

    actual_ids = set(RULE_ID_RE.findall(config.content))

    assigned = (
        db.query(Rule)
        .filter(Rule.components.any(SecurityComponent.id == component.id))
        .all()
    )
    approved = {r.rule_id: r for r in assigned if r.status == RuleStatus.approved}
    all_rules = {r.rule_id: r for r in db.query(Rule).all()}

    missing = [rule_brief(r) for rid, r in sorted(approved.items()) if rid not in actual_ids]
    stale = [
        rule_brief(all_rules[rid])
        for rid in sorted(actual_ids)
        if rid in all_rules and all_rules[rid].status != RuleStatus.approved
    ]
    unknown = sorted(rid for rid in actual_ids if rid not in all_rules)

    in_sync = not missing and not stale and not unknown
    return {
        "has_config": True,
        "component_id": component.id,
        "component": component.name,
        "fetched_at": config.fetched_at.isoformat() if config.fetched_at else None,
        "uploaded_by": config.uploaded_by,
        "actual_rule_count": len(actual_ids),
        "expected_rule_count": len(approved),
        "in_sync": in_sync,
        "missing": missing,
        "stale": stale,
        "unknown": unknown,
    }
