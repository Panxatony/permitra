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

from . import config_blocks, config_semantics
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


def _check_fidelity(content, component, approved, blocks):
    """Returns (widened findings, fidelity flag).

    fidelity is "checked" when the device rules were parsed and compared,
    "not_checked" when the platform's format could not be read to this depth -
    which must not be reported as a pass.
    """
    device = config_semantics.parse(content, component.type)
    if device is None:
        return [], [], "not_checked"

    # Map each device block's identifier to the SR ID it claims (from the block
    # scan, which already handled the description/comment lookup).
    id_by_identifier = {b.identifier: b.rule_id for b in (blocks or []) if b.rule_id}

    widened = []
    unverified = []
    for identifier, perm in device.items():
        rule_id = id_by_identifier.get(identifier)
        if not rule_id or rule_id not in approved:
            continue  # unjustified/unknown are the block scan's job, not this one
        if perm.unresolved:
            # Names we could not resolve to addresses or services (a missing
            # address book, a hand-written config). Cannot be compared, so it is
            # reported as unverified rather than passed or flagged.
            unverified.append({"rule_id": rule_id, "identifier": identifier,
                               "unresolved": sorted(set(perm.unresolved))})
            continue
        diffs = config_semantics.widening(perm, config_semantics.approved_permission(approved[rule_id]))
        if diffs:
            widened.append({"rule_id": rule_id, "identifier": identifier,
                            "differences": diffs})
    widened.sort(key=lambda w: w["rule_id"])
    unverified.sort(key=lambda w: w["rule_id"])
    # "checked" only when everything claimed was actually compared; "partial"
    # when some rules could not be resolved - never silently a pass.
    fidelity = "partial" if unverified else "checked"
    return widened, unverified, fidelity


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
    # A declared emergency change is in review and therefore not IN_FORCE, but it
    # is on the device on purpose and within its window. Reporting it as stale
    # would tell operations to tear down the rule that is keeping the incident
    # closed - and would train them to ignore the finding.
    stale = [
        rule_brief(all_rules[rid])
        for rid in sorted(actual_ids)
        if rid in all_rules
        and not all_rules[rid].emergency_pending
        and (all_rules[rid].deleted_at is not None
             or all_rules[rid].status not in IN_FORCE)
    ]
    unknown = sorted(rid for rid in actual_ids if rid not in all_rules)

    # How many rules the device carries in total, and how many of them claim a
    # security rule. Without this there is no denominator - and a report that
    # says "in sync" while unjustified rules sit on the firewall.
    blocks = config_blocks.scan(config.content, component.type)
    coverage = config_blocks.coverage(blocks)

    # The expensive half (#48): does the rule on the device permit only what was
    # approved? Coverage proves a rule *claims* an approval; this proves it
    # matches one. Narrower than approved is fine (operations may implement
    # less); wider is a finding - a rule opened up during an incident still
    # carries its SR ID and would otherwise read green.
    widened, unverified, fidelity = _check_fidelity(config.content, component, approved, blocks)

    # A configuration in an unrecognised format cannot disprove compliance, so
    # it must not be allowed to claim it either: in_sync then means only what it
    # meant before, and the report says the coverage is unknown.
    in_sync = (not missing and not stale and not unknown
               and not coverage["unjustified"] and not widened)
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
        # #48: rules on the device permitting more than they were approved for.
        "widened": widened,
        # Rules whose device configuration could not be resolved deeply enough
        # to compare (missing address book, hand-written names): cannot tell.
        "unverified": unverified,
        # "checked" (all compared), "partial" (some unverifiable), or
        # "not_checked" (format unparseable). Never silently a pass.
        "fidelity": fidelity,
    }
