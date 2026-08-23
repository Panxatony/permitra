"""Target/actual comparison (drift detection) per component.

Target: all approved rules assigned to the component.
Actual: the stored device configuration (uploaded or - later - retrieved via
        device API). The comparison works on the rule IDs (SR####) that Permitra
        carries in policy names/comments of every export.

Findings:
  - missing:      approved, but not on the device (implementation is missing)
  - stale:        on the device, but no longer approved in Permitra
  - unknown:      rule IDs on the device that Permitra does not know at all
  - unjustified:  rules on the device carrying no rule ID at all

The last one is the point of the whole exercise and used to be invisible: the
comparison only ever looked for SR IDs, so a rule somebody opened by hand
produced nothing to find. `unknown` catches typos and stale references;
`unjustified` catches the actual failure mode. See app/config_blocks.py.
"""
import re

from sqlalchemy.orm import Session

from . import config_blocks
from .models import IN_FORCE, ComponentActualConfig, Rule, SecurityComponent, active_rules

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
    approved = {r.rule_id: r for r in assigned if r.status in IN_FORCE}
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
             or all_rules[rid].status not in IN_FORCE)
    ]
    unknown = sorted(rid for rid in actual_ids if rid not in all_rules)

    # How many rules the device carries in total, and how many of them claim a
    # security rule. Without this there is no denominator - and a report that
    # says "in sync" while unjustified rules sit on the firewall.
    blocks = config_blocks.scan(config.content, component.type)
    coverage = config_blocks.coverage(blocks)

    # A configuration in an unrecognised format cannot disprove compliance, so
    # it must not be allowed to claim it either: in_sync then means only what it
    # meant before, and the report says the coverage is unknown.
    in_sync = not missing and not stale and not unknown and not coverage["unjustified"]
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
        "coverage": coverage,
    }
