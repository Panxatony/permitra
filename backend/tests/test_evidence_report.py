"""The document an auditor actually asks for (#86).

*Every change to zone Z in period T, with requester, approver, justification and
date.* All of it was reachable before - through the audit log API, one query at
a time - and nobody assembles that during an audit.

It reads and changes nothing, so the risk here is not damage but a document that
quietly says something untrue. That is what these tests are about: the period
must include the day it names, a removed rule must not vanish from the record of
its own removal, a matrix change must name **both** approvers because two is
what the control requires, and the report must state where the audit log stops
covering the window instead of looking complete over a gap.
"""
import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import audit
from app.database import Base
from app.models import (
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    RuleVersion,
    SecurityComponent,
    User,
    Vrf,
    ZonePolicyChange,
    utcnow,
)
from app.routers.reports_router import evidence_report, evidence_report_csv
from app.settings import set_setting


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    s.add(User(username="alex", password_hash="x", role=Role.architect, is_active=True))
    s.commit()
    yield s
    s.close()


def user(db):
    return db.query(User).filter(User.username == "alex").one()


def make_rule(db, rule_id="SR00001", *, src="Z010", dst="Z020", app_id="",
              justification="admin access", deleted=False):
    rule = Rule(rule_id=rule_id, vrf_id=1, name=rule_id.lower(), app_id=app_id,
                requestor="alex", created_by="alex", justification=justification,
                components=[db.get(SecurityComponent, 1)],
                source=[{"ip": "10.0.0.1", "alias": ""}],
                destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}],
                action=RuleAction.permit, status=RuleStatus.approved,
                source_zone=src, destination_zone=dst,
                deleted_at=utcnow() if deleted else None)
    db.add(rule)
    db.commit()
    return rule


def version(db, rule, *, at, note="Rule approved", values=None, by="kim"):
    db.add(RuleVersion(rule_pk=rule.id, version=rule.version, snapshot={},
                       change_note=note, change_values=values,
                       changed_by=by, changed_at=at))
    rule.version += 1
    db.commit()


def report(db, date_from="2026-06-01", date_to="2026-06-30", **kw):
    return evidence_report(date_from, date_to, kw.get("zone", ""),
                           kw.get("app_id", ""), db, user(db))


JUNE = datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc)


# ---------- the period means what it says ----------

def test_the_last_day_of_the_period_is_included(db):
    """"Up to 30 June" means the evening of the 30th. A report that stopped at
    midnight would silently omit that day - the day most likely to matter."""
    rule = make_rule(db)
    version(db, rule, at=datetime(2026, 6, 30, 23, 30, tzinfo=timezone.utc))

    assert report(db)["totals"]["rule_changes"] == 1


def test_changes_outside_the_period_are_not_in_the_report(db):
    rule = make_rule(db)
    version(db, rule, at=datetime(2026, 5, 31, 23, 59, tzinfo=timezone.utc))
    version(db, rule, at=datetime(2026, 7, 1, 0, 1, tzinfo=timezone.utc))

    assert report(db)["totals"]["rule_changes"] == 0


def test_a_period_that_ends_before_it_starts_is_refused(db):
    with pytest.raises(HTTPException) as exc:
        report(db, "2026-06-30", "2026-06-01")
    assert exc.value.status_code == 422


def test_a_malformed_date_is_refused_rather_than_guessed(db):
    with pytest.raises(HTTPException) as exc:
        report(db, "30.06.2026", "2026-06-30")
    assert exc.value.status_code == 422


# ---------- scope ----------

def test_a_zone_scope_covers_both_directions(db):
    """A change to a rule out of the zone is as much its business as one into
    it - an auditor asking about Z040 means both."""
    out_of = make_rule(db, "SR00001", src="Z040", dst="Z020")
    into = make_rule(db, "SR00002", src="Z010", dst="Z040")
    elsewhere = make_rule(db, "SR00003", src="Z010", dst="Z020")
    for rule in (out_of, into, elsewhere):
        version(db, rule, at=JUNE)

    ids = [r["rule_id"] for r in report(db, zone="Z040")["rule_changes"]]
    assert ids == ["SR00001", "SR00002"]


def test_a_rule_removed_during_the_period_stays_in_the_report(db):
    """The removal is exactly the change an audit asks about. Filtering deleted
    rules out would make the record of the removal disappear with it."""
    rule = make_rule(db, "SR00001", deleted=True)
    version(db, rule, at=JUNE, note="Rule deleted")

    entry = report(db)["rule_changes"][0]
    assert entry["rule_id"] == "SR00001"
    assert entry["deleted"] is True


def test_an_application_scope_narrows_to_that_application(db):
    shop = make_rule(db, "SR00001", app_id="SHOP")
    crm = make_rule(db, "SR00002", app_id="CRM")
    for rule in (shop, crm):
        version(db, rule, at=JUNE)

    ids = [r["rule_id"] for r in report(db, app_id="SHOP")["rule_changes"]]
    assert ids == ["SR00001"]


# ---------- what each entry has to carry ----------

def test_a_rule_change_carries_who_when_what_and_why(db):
    """The four things the question names. Missing any one of them turns the
    document back into something that needs a follow-up question."""
    rule = make_rule(db, justification="RDP for the migration weekend")
    version(db, rule, at=JUNE, by="kim", note="Rule approved")

    entry = report(db)["rule_changes"][0]
    assert entry["requestor"] == "alex"
    assert entry["justification"] == "RDP for the migration weekend"
    change = entry["changes"][0]
    assert change["actor"] == "kim"
    assert change["date"].startswith("2026-06-15")
    assert change["what"] == "Rule approved"


def test_a_stored_change_note_is_rendered_with_its_values(db):
    """Notes are stored as a template plus values so they can be read in the
    instance's language. A report printing the raw template would hand an
    auditor '{reason}'."""
    rule = make_rule(db)
    version(db, rule, at=JUNE,
            note="Application {app_id} retired: {reason} - proposed for removal",
            values={"app_id": "SHOP", "reason": "replaced by SAP"})

    what = report(db)["rule_changes"][0]["changes"][0]["what"]
    assert "SHOP" in what and "replaced by SAP" in what
    assert "{" not in what


def test_a_matrix_change_names_both_approvers(db):
    """Two approvals by two different accounts is the control. Naming only the
    one who finished it would misrepresent what actually happened."""
    db.add(ZonePolicyChange(
        batch_id="b1", change_type="policy", from_zone="Z010", to_zone="Z040",
        old_policy="block_all", new_policy="allow_only", status="approved",
        requested_by="alex", requested_at=JUNE,
        first_approved_by="kim", first_approved_at=JUNE,
        decided_by="robin", decided_at=JUNE, comment="new interface"))
    db.commit()

    change = report(db)["zone_changes"][0]
    assert change["requested_by"] == "alex"
    assert change["first_approved_by"] == "kim"
    assert change["approved_by"] == "robin"
    assert change["justification"] == "new interface"


def test_a_zone_scope_also_narrows_the_matrix_changes(db):
    db.add(ZonePolicyChange(batch_id="b1", from_zone="Z010", to_zone="Z040",
                            new_policy="allow_only", requested_by="alex",
                            requested_at=JUNE))
    db.add(ZonePolicyChange(batch_id="b2", from_zone="Z050", to_zone="Z060",
                            new_policy="allow_only", requested_by="alex",
                            requested_at=JUNE))
    db.commit()

    changes = report(db, zone="Z040")["zone_changes"]
    assert [c["to_zone"] for c in changes] == ["Z040"]


# ---------- the honesty of the document ----------

def test_the_report_states_that_the_change_history_is_complete(db):
    """Rule versions and matrix changes are never deleted, so the change record
    itself does not have holes - and saying so is part of the evidence."""
    assert report(db)["integrity"]["change_history_complete"] is True


def test_an_intact_chain_is_reported_as_intact(db):
    audit.record(db, "auth", "auth.login", actor="alex", source_ip="10.0.0.1")
    integrity = report(db)["integrity"]
    assert integrity["chain_ok"] is True
    assert integrity["audit_log_covers_period"] is True


def test_a_collapsed_audit_log_is_declared_rather_than_hidden(db):
    """The line the issue draws: a report that silently omitted collapsed
    events would be worse than no report. Retention removes audit events (#34),
    so a period reaching back before the oldest surviving one is only partly
    corroborated - and the document has to say so."""
    old = utcnow() - timedelta(days=400)
    import app.audit as audit_mod
    real = audit_mod.utcnow
    audit_mod.utcnow = lambda: old
    try:
        for _ in range(3):
            audit.record(db, "auth", "auth.login", actor="alex", source_ip="10.0.0.1")
    finally:
        audit_mod.utcnow = real
    for ev in db.query(__import__("app.models", fromlist=["AuditEvent"]).AuditEvent).all():
        ev.siem_status = "skipped"
    db.commit()
    audit.record(db, "auth", "auth.login", actor="alex", source_ip="10.0.0.1")

    set_setting(db, "audit_retention_days", "365")
    assert audit.collapse_expired(db)["collapsed"] == 3

    # a period that begins before the oldest surviving event
    start = (utcnow() - timedelta(days=500)).strftime("%Y-%m-%d")
    end = utcnow().strftime("%Y-%m-%d")
    integrity = evidence_report(start, end, "", "", db, user(db))["integrity"]

    assert integrity["audit_log_covers_period"] is False
    assert integrity["chain_collapsed"] == 3
    assert integrity["chain_ok"] is True          # still provable, just shorter


def test_a_recent_period_over_a_collapsed_log_still_reads_as_covered(db):
    """The counter-check: a collapse in the distant past must not brand every
    later report as incomplete, or the flag stops meaning anything."""
    old = utcnow() - timedelta(days=400)
    import app.audit as audit_mod
    real = audit_mod.utcnow
    audit_mod.utcnow = lambda: old
    try:
        audit.record(db, "auth", "auth.login", actor="alex", source_ip="10.0.0.1")
    finally:
        audit_mod.utcnow = real
    from app.models import AuditEvent
    for ev in db.query(AuditEvent).all():
        ev.siem_status = "skipped"
    db.commit()
    audit.record(db, "auth", "auth.login", actor="alex", source_ip="10.0.0.1")
    set_setting(db, "audit_retention_days", "365")
    audit.collapse_expired(db)

    start = (utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
    end = utcnow().strftime("%Y-%m-%d")
    integrity = evidence_report(start, end, "", "", db, user(db))["integrity"]
    assert integrity["audit_log_covers_period"] is True


# ---------- the flat table ----------

def test_the_csv_carries_both_kinds_of_change(db):
    rule = make_rule(db)
    version(db, rule, at=JUNE, by="kim")
    db.add(ZonePolicyChange(batch_id="b1", from_zone="Z010", to_zone="Z040",
                            new_policy="allow_only", requested_by="alex",
                            requested_at=JUNE, decided_by="robin", status="approved"))
    db.commit()

    body = evidence_report_csv("2026-06-01", "2026-06-30", "", "", db, user(db)).body.decode()
    assert "SR00001" in body
    assert "Z010" in body and "robin" in body


def test_a_justification_that_looks_like_a_formula_is_neutralised(db):
    """This file is opened in a spreadsheet and the justification is free text."""
    rule = make_rule(db, justification="=cmd|'/c calc'!A1")
    version(db, rule, at=JUNE)

    body = evidence_report_csv("2026-06-01", "2026-06-30", "", "", db, user(db)).body.decode()
    assert "'=cmd" in body
