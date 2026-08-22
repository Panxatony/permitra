"""Target/actual comparison (drift detection) per component.

Target: all approved rules assigned to the component.
Actual: the stored device configuration (uploaded or - later - retrieved via
        device API). The comparison works on the rule IDs (SR####) that Permitra
        carries in policy names/comments of every export.

Findings:
  - missing:  approved, but not on the device (implementation is missing)
  - stale:    on the device, but no longer approved in Permitra
  - unknown:  rule IDs on the device that Permitra does not know at all (shadow rules)
"""
import re

from sqlalchemy.orm import Session

from .models import ComponentActualConfig, Rule, RuleStatus, SecurityComponent, active_rules

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

    # Exclude deleted rules: they keep their status (usually approved) and would
    # otherwise be reported as "missing" - operations would be instructed to
    # recreate a deliberately deleted rule on the device.
    assigned = (
        active_rules(db)
        .filter(Rule.components.any(SecurityComponent.id == component.id))
        .all()
    )
    approved = {r.rule_id: r for r in assigned if r.status == RuleStatus.approved}
    # For classifying what sits on the device, deleted rules count as well: a
    # deleted rule still present on the firewall is a removal case ("to be torn
    # down") - not an unknown third-party rule.
    all_rules = {r.rule_id: r for r in db.query(Rule).all()}

    missing = [rule_brief(r) for rid, r in sorted(approved.items()) if rid not in actual_ids]
    stale = [
        rule_brief(all_rules[rid])
        for rid in sorted(actual_ids)
        if rid in all_rules
        and (all_rules[rid].deleted_at is not None
             or all_rules[rid].status != RuleStatus.approved)
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
