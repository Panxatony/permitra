"""Reports: the questions someone asks across the whole ruleset.

The pages elsewhere are for working - creating, deciding, maintaining. This is
for looking: the target/actual comparison lives here in the interface, and the
requestor overview answers "who asked for all of this?" - which, per BSI
documentation duties, every rule records but nothing summed up until now.
"""
import csv
import io
from datetime import datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .. import audit
from ..auth import require_roles
from ..database import get_db
from ..exporters.common import csv_safe
from ..messages import _, render
from ..models import (
    IN_FORCE,
    AuditEvent,
    Role,
    Rule,
    RuleVersion,
    User,
    ZonePolicyChange,
)
from .recert_router import _known_accounts

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/requestors")
def requestor_summary(db: Session = Depends(get_db),
                      user: User = Depends(require_roles(
                          Role.change_approver, Role.architect, Role.operations))):
    """Rules per requestor: how many, how many in force, and whether the person
    still exists.

    The unknown-flag is the finding, same argument as in the recertification
    worklist: a requestor matching no active user cannot be asked whether their
    rules are still needed - and a pile of in-force rules whose requester is
    gone is where a ruleset starts to rot.
    """
    known = _known_accounts(db)
    rows: dict[str, dict] = {}
    for rule in db.query(Rule).filter(Rule.deleted_at.is_(None)).all():
        name = (rule.requestor or "").strip()
        entry = rows.setdefault(name, {"requestor": name, "total": 0, "in_force": 0})
        entry["total"] += 1
        if rule.status in IN_FORCE:
            entry["in_force"] += 1
    result = sorted(rows.values(), key=lambda e: (-e["total"], e["requestor"]))
    for entry in result:
        entry["unknown"] = bool(entry["requestor"]) and entry["requestor"].lower() not in known
    return {"requestors": result,
            "without_requestor": rows.get("", {}).get("total", 0)}


def _period(date_from: str, date_to: str) -> tuple[datetime, datetime]:
    """The requested window as an inclusive pair of aware datetimes.

    `to` covers the whole day it names: an auditor asking for "up to 30 June"
    means the evening of the 30th, and a report that stopped at midnight would
    silently omit that day's changes.
    """
    try:
        start = datetime.combine(datetime.strptime(date_from, "%Y-%m-%d").date(),
                                 time.min, tzinfo=timezone.utc)
        end = datetime.combine(datetime.strptime(date_to, "%Y-%m-%d").date(),
                               time.max, tzinfo=timezone.utc)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("Dates must be given as YYYY-MM-DD")) from exc
    if end < start:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("The period ends before it starts"))
    return start, end


def _aware(value):
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _integrity(db: Session, start: datetime) -> dict:
    """What the report can and cannot vouch for, stated rather than implied.

    The change records themselves are complete: rule versions and matrix changes
    are never deleted, and a deleted rule is only marked as such. What retention
    can remove is the *audit log* (#34) - the corroborating trail, not the
    record. So the report carries the chain's verification result and says
    whether the log still covers the window, rather than handing an auditor a
    document that looks complete over a gap.
    """
    chain = audit.verify_chain(db)
    oldest = (db.query(AuditEvent).order_by(AuditEvent.id.asc()).first())
    oldest_at = _aware(oldest.ts) if oldest else None
    collapsed = bool(audit.latest_seal(db))

    # Retention only ever removes events *older than the configured period*, so
    # that cutoff - not the oldest surviving event - is what decides whether the
    # window could have lost anything. Judging by the oldest survivor instead
    # would flag every report whose period simply predates the last login, which
    # would make the flag noise and then make people ignore it.
    retention = audit.retention_days(db)
    if not collapsed:
        covers = True
    elif retention > 0:
        covers = start >= datetime.now(timezone.utc) - timedelta(days=retention)
    else:
        # A seal from a retention period since switched off: no cutoff to reason
        # with, so fall back to the conservative bound.
        covers = oldest_at is None or start >= oldest_at

    return {
        "chain_ok": chain["ok"],
        "chain_checked": chain.get("checked", 0),
        "chain_collapsed": chain.get("collapsed", 0),
        "audit_log_from": oldest_at.isoformat() if oldest_at else None,
        "audit_log_covers_period": covers,
        # The change history is not subject to retention - saying so is the
        # difference between "we kept everything" and "we kept what matters".
        "change_history_complete": True,
    }


def _touches_zone(rule: Rule, zone: str) -> bool:
    return not zone or zone in (rule.source_zone, rule.destination_zone)


@router.get("/evidence")
def evidence_report(
    date_from: str = Query(..., description="Start of the period, YYYY-MM-DD"),
    date_to: str = Query(..., description="End of the period, inclusive, YYYY-MM-DD"),
    zone: str = Query("", description="Only changes touching this zone (source or destination)"),
    app_id: str = Query("", description="Only rules of this application"),
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(
        Role.change_approver, Role.architect, Role.operations)),
):
    """What an auditor actually asks for: every change to a zone in a period,
    with who requested it, who approved it, why, and when (#86).

    All of this was reachable before - through the audit log API, one query at a
    time - and nobody assembles that during an audit. This is the same records,
    put together as a document.

    It reads; it changes nothing. Two sources, because a firewall is documented
    by both: the rules themselves (their version history) and the zone matrix
    they are judged against (its approved change requests).
    """
    start, end = _period(date_from, date_to)

    rule_query = db.query(Rule)
    if app_id:
        rule_query = rule_query.filter(Rule.app_id == app_id)
    # Deleted rules stay in the report on purpose: a rule removed during the
    # period is exactly the kind of change an audit asks about, and leaving it
    # out would make the removal invisible.
    rules = {r.id: r for r in rule_query.all() if _touches_zone(r, zone)}

    versions = (db.query(RuleVersion)
                .filter(RuleVersion.rule_pk.in_(rules.keys()))
                .filter(RuleVersion.changed_at >= start, RuleVersion.changed_at <= end)
                .order_by(RuleVersion.changed_at.asc()).all()) if rules else []

    by_rule: dict[int, list] = {}
    for version in versions:
        by_rule.setdefault(version.rule_pk, []).append({
            "version": version.version,
            "date": _aware(version.changed_at).isoformat(),
            "actor": version.changed_by,
            # Stored as a template plus its values so it can be read in the
            # instance's language; rendered here, at reading time.
            "what": render(version.change_note, version.change_values or {}),
        })

    rule_changes = [{
        "rule_id": rules[pk].rule_id,
        "name": rules[pk].name,
        "source_zone": rules[pk].source_zone,
        "destination_zone": rules[pk].destination_zone,
        "requestor": rules[pk].requestor,
        "justification": rules[pk].justification,
        "change_id": rules[pk].change_id,
        "status": rules[pk].status.value,
        "deleted": rules[pk].deleted_at is not None,
        "changes": entries,
    } for pk, entries in sorted(by_rule.items(), key=lambda kv: rules[kv[0]].rule_id)]

    zone_query = (db.query(ZonePolicyChange)
                  .filter(ZonePolicyChange.requested_at >= start,
                          ZonePolicyChange.requested_at <= end))
    if zone:
        zone_query = zone_query.filter(
            (ZonePolicyChange.from_zone == zone) | (ZonePolicyChange.to_zone == zone))
    zone_changes = [{
        "date": _aware(c.requested_at).isoformat(),
        "type": c.change_type,
        "from_zone": c.from_zone,
        "to_zone": c.to_zone,
        "old_policy": c.old_policy,
        "new_policy": c.new_policy,
        "requested_by": c.requested_by,
        # Both approvers, because two is what a matrix change requires - naming
        # only the one who finished it would misrepresent the control.
        "first_approved_by": c.first_approved_by,
        "approved_by": c.decided_by,
        "decided_at": _aware(c.decided_at).isoformat() if c.decided_at else None,
        "status": c.status,
        "justification": c.comment,
    } for c in sorted(zone_query.all(), key=lambda c: c.requested_at)]

    return {
        "scope": {"from": date_from, "to": date_to, "zone": zone, "app_id": app_id},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "integrity": _integrity(db, start),
        "rule_changes": rule_changes,
        "zone_changes": zone_changes,
        "totals": {"rules": len(rule_changes),
                   "rule_changes": sum(len(r["changes"]) for r in rule_changes),
                   "zone_changes": len(zone_changes)},
    }


@router.get("/evidence.csv")
def evidence_report_csv(
    date_from: str = Query(...),
    date_to: str = Query(...),
    zone: str = Query(""),
    app_id: str = Query(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(
        Role.change_approver, Role.architect, Role.operations)),
):
    """The same report as one flat table, for the auditor who wants to sort it."""
    data = evidence_report(date_from, date_to, zone, app_id, db, user)
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow(["Kind", "Reference", "Date", "Actor", "What",
                     "Requested by", "First approval", "Approval", "Justification"])
    for rule in data["rule_changes"]:
        for change in rule["changes"]:
            # csv_safe on every cell: names, notes and justifications are free
            # text and this file is opened in a spreadsheet.
            writer.writerow([csv_safe(c) for c in [
                "rule", rule["rule_id"], change["date"], change["actor"], change["what"],
                rule["requestor"], "", "", rule["justification"]]])
    for change in data["zone_changes"]:
        writer.writerow([csv_safe(c) for c in [
            change["type"], f'{change["from_zone"]} → {change["to_zone"]}'.strip(" →"),
            change["date"], change["approved_by"] or change["requested_by"],
            f'{change["old_policy"] or "-"} → {change["new_policy"]} ({change["status"]})',
            change["requested_by"], change["first_approved_by"], change["approved_by"],
            change["justification"]]])
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(buffer.getvalue(), media_type="text/csv", headers={
        "Content-Disposition":
            f'attachment; filename="evidence-{date_from}-{date_to}.csv"'})
