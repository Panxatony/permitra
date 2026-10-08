"""Re-check a rule whose addresses changed underneath it.

An address object's IP, a group's membership, a workload's labels: each can
move a rule's addresses without anybody touching the rule. Whatever moved
them, the rule then faces the checks an edit of it would face - zones are
derived again, the components follow, the zone matrix and the BSI firewall
requirement are asked - and either every affected rule passes or nothing is
applied. One module, so the address-object propagation and the group
resynchronisation cannot drift apart in what they ask.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .component_resolution import resolve_rule_components
from .messages import _
from .models import IN_FORCE, Rule, RuleStatus, RuleVersion
from .zone_check import check_zone_pair, resolve_zone_for_entries


def reassess(db: Session, rule: Rule, source: list[dict], destination: list[dict]) -> tuple[dict, list[str]]:
    """The state to apply, and the reasons it must not be applied."""
    reasons: list[str] = []
    zones = {}
    for label, field, entries in ((_("Source"), "source", source),
                                  (_("Destination"), "destination", destination)):
        zone, unassigned, hits = resolve_zone_for_entries(db, entries, rule.vrf_id)
        if unassigned:
            reasons.append(
                _("{label}: network(s) not assigned to any security zone: {networks} "
                  "– create the network on the Networks page first and assign it to a "
                  "security zone",
                  label=label, networks=", ".join(unassigned)))
        elif len(hits) > 1:
            reasons.append(_("{label} spans several zones ({zones}) – split the rule",
                             label=label, zones=", ".join(sorted(hits))))
        zones[field] = zone or getattr(rule, f"{field}_zone") or ""
    src, dst = zones["source"], zones["destination"]
    components, unknown = resolve_rule_components(db, source, destination, src, dst, rule.vrf_id)
    if unknown:
        reasons.append(_("No component mapping is defined yet for these addresses: ")
                       + ", ".join(u["ip"] for u in unknown)
                       + _(". Define it once via the address mapping."))
    elif not components:
        reasons.append(_("No enforcing components could be determined"))
    if not reasons:
        if src.upper() != dst.upper() and not any(c.is_firewall for c in components):
            reasons.append(_("A zone transition requires a firewall – Cisco ACI alone is not sufficient (BSI)"))
        verdict = check_zone_pair(db, src, dst, [c.type.value for c in components])
        if not verdict.allowed:
            reasons.append(_("Zone matrix: ") + "; ".join(verdict.messages))
    state = {"source": source, "destination": destination,
             "source_zone": src, "destination_zone": dst, "components": components}
    return state, reasons


def apply(db: Session, rule: Rule, state: dict, username: str, note: str, values: dict,
          *, reset_review: bool) -> None:
    """Write the re-checked state and one version.

    reset_review decides what the change means for the approval. A content
    change somebody made - an address object's IP, a group's selector, a
    static member list - withdraws the approval: what was approved was the old
    addresses. A change in the inventory under a selector group - a workload
    gained a label, a new one appeared - does not: the approval covered the
    selector, and the inventory is a fact, not a policy. What it does change
    is the device configuration, so components already implemented go to "to
    change" and an active rule drops back to approved until operations has
    re-applied it.
    """
    zones_changed = (state["source_zone"] != (rule.source_zone or "")
                     or state["destination_zone"] != (rule.destination_zone or ""))
    rule.source, rule.destination = state["source"], state["destination"]
    rule.source_zone, rule.destination_zone = state["source_zone"], state["destination_zone"]
    rule.components = state["components"]
    rule.removal_reason = ""
    rule.version += 1
    if rule.status in (*IN_FORCE, RuleStatus.rejected) and (reset_review or zones_changed):
        rule.status = RuleStatus.draft
        note = note + " – the approval is withdrawn, the rule needs a new review"
    elif rule.status in IN_FORCE:
        impl = dict(rule.impl_status or {})
        for c in rule.components:
            if impl.get(c.name) == "implemented":
                impl[c.name] = "to change"
        rule.impl_status = impl
        if rule.status == RuleStatus.active:
            rule.status = RuleStatus.approved
    db.add(RuleVersion(
        rule_pk=rule.id, version=rule.version,
        snapshot={"auto": "address-recheck"},
        change_note=note, change_values=values, changed_by=username,
    ))
