"""Retiring an application proposes its rules for removal (#85).

Rules outliving the application they were opened for is one of the most common
ways a ruleset rots: the application is switched off, the holes it needed stay.
`app_id` already grouped the rules; what was missing was the trigger.

The workflow itself is not new - it is the one zone re-assignment uses, pointed
at a different cause: set a removal reason, put the rule back into review, and
let `_decide` deactivate it and mark the components "to remove" on approval.

So these tests are mostly about the ways a bulk action can go wrong. It must
propose rather than deactivate, it must be previewable before it bites, it must
not quietly swallow rules it did not touch, and - the one that matters most - it
must not become a way around four eyes just because it acts on many rules at
once.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    Comment,
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
)
from app.routers.rules_router import (
    ApplicationRetirement,
    ReviewDecision,
    _decide,
    application_summary,
    retire_application,
)


class Req:
    headers: dict = {}  # noqa: RUF012

    class client:
        host = "203.0.113.9"


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    s.add(User(username="alex", password_hash="x", role=Role.architect, is_active=True))
    s.add(User(username="kim", password_hash="x", role=Role.change_approver, is_active=True))
    s.commit()
    yield s
    s.close()


def user(db, name):
    return db.query(User).filter(User.username == name).one()


def make_rule(db, rule_id, *, app_id="SHOP", status=RuleStatus.approved, requestor="alex"):
    rule = Rule(rule_id=rule_id, vrf_id=1, name=rule_id.lower(), app_id=app_id,
                requestor=requestor, created_by=requestor,
                components=[db.get(SecurityComponent, 1)],
                source=[{"ip": "10.0.0.1", "alias": ""}],
                destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}],
                action=RuleAction.permit, status=status,
                source_zone="Z010", destination_zone="Z020",
                impl_status={"FW": "implemented"})
    db.add(rule)
    db.commit()
    return rule


def retire(db, app_id="SHOP", *, reason="switched off", dry_run=False, actor="alex"):
    return retire_application(app_id, ApplicationRetirement(reason=reason, dry_run=dry_run),
                              Req(), db, user(db, actor))


# ---------- it proposes, it does not decide ----------

def test_retiring_puts_the_rules_back_into_review_rather_than_deactivating_them(db):
    """The whole safety of the feature: a bulk action that deactivated rules
    directly would take dozens of rules off the devices on one person's say-so."""
    make_rule(db, "SR00001")
    make_rule(db, "SR00002")

    result = retire(db)
    assert result["total"] == 2

    rules = db.query(Rule).order_by(Rule.rule_id).all()
    assert [r.status for r in rules] == [RuleStatus.in_review, RuleStatus.in_review]
    assert all(r.removal_reason for r in rules)
    # nothing has been marked for removal on the components yet
    assert all(r.impl_status == {"FW": "implemented"} for r in rules)


def test_the_reason_reaches_the_rule_the_history_and_a_comment(db):
    """A removal proposal nobody can explain later is a removal nobody can
    defend in a review."""
    make_rule(db, "SR00001")
    retire(db, reason="shop replaced by SAP")

    rule = db.query(Rule).one()
    assert "shop replaced by SAP" in rule.removal_reason
    assert "SHOP" in rule.removal_reason
    notes = [v.change_note for v in rule.versions]
    assert any("retired" in n for n in notes)
    assert db.query(Comment).filter(Comment.rule_pk == rule.id).count() == 1


def test_a_retirement_without_a_reason_is_refused(db):
    make_rule(db, "SR00001")
    with pytest.raises(HTTPException) as exc:
        retire(db, reason="   ")
    assert exc.value.status_code == 422
    assert db.query(Rule).one().status == RuleStatus.approved


# ---------- four eyes survive the bulk action ----------

def test_whoever_retires_the_application_cannot_approve_its_removals(db):
    """The property that keeps this from being a way around separation of
    duties: proposing writes a version in the acting account's name, which makes
    it the submitter - and a submitter cannot approve."""
    make_rule(db, "SR00001", requestor="alex")
    retire(db, actor="alex")

    with pytest.raises(HTTPException) as exc:
        _decide(db, "SR00001", user(db, "alex"), ReviewDecision(),
                RuleStatus.approved, "Rule approved")
    assert exc.value.status_code == 403


def test_a_second_person_approves_and_the_rule_goes_to_to_remove(db):
    """The counter-check, and the point of the whole exercise: once somebody
    else approves, the rule is deactivated and the components are told to remove
    it - the existing removal path, reached through a new trigger."""
    make_rule(db, "SR00001", requestor="alex")
    retire(db, actor="alex")

    _decide(db, "SR00001", user(db, "kim"), ReviewDecision(),
            RuleStatus.approved, "Rule approved")

    rule = db.query(Rule).one()
    assert rule.status == RuleStatus.deactivated
    assert rule.impl_status["FW"] == "to remove"


# ---------- the dry run ----------

def test_a_dry_run_reports_without_touching_anything(db):
    """"This will propose 34 rules for removal" has to be readable before it is
    true."""
    make_rule(db, "SR00001")
    make_rule(db, "SR00002")

    result = retire(db, dry_run=True)
    assert result["total"] == 2
    assert {r["rule_id"] for r in result["proposed"]} == {"SR00001", "SR00002"}

    rules = db.query(Rule).all()
    assert all(r.status == RuleStatus.approved for r in rules)
    assert all(not r.removal_reason for r in rules)
    assert db.query(Comment).count() == 0


def test_the_dry_run_is_the_default(db):
    """A bulk removal that fires because a flag was forgotten is the one thing
    this endpoint must never do."""
    make_rule(db, "SR00001")
    retire_application("SHOP", ApplicationRetirement(reason="off"), Req(), db, user(db, "alex"))
    assert db.query(Rule).one().status == RuleStatus.approved


# ---------- what it does not touch, it says out loud ----------

def test_only_rules_of_that_application_are_proposed(db):
    make_rule(db, "SR00001", app_id="SHOP")
    make_rule(db, "SR00002", app_id="CRM")

    retire(db, "SHOP")

    by_id = {r.rule_id: r for r in db.query(Rule).all()}
    assert by_id["SR00001"].status == RuleStatus.in_review
    assert by_id["SR00002"].status == RuleStatus.approved


def test_rules_not_in_force_are_reported_rather_than_silently_dropped(db):
    """A draft for a retired application is not a removal - it stands on no
    device. But it is something somebody should see, so it is listed rather than
    passed over in silence."""
    make_rule(db, "SR00001", status=RuleStatus.approved)
    make_rule(db, "SR00002", status=RuleStatus.draft)

    result = retire(db)
    assert [r["rule_id"] for r in result["proposed"]] == ["SR00001"]
    assert result["skipped"] == [{"rule_id": "SR00002", "status": "draft"}]
    assert db.query(Rule).filter(Rule.rule_id == "SR00002").one().status == RuleStatus.draft


def test_an_unknown_application_is_a_404_not_an_empty_success(db):
    """An app_id typed from memory that matches nothing must not report a
    successful retirement of zero rules."""
    make_rule(db, "SR00001", app_id="SHOP")
    with pytest.raises(HTTPException) as exc:
        retire(db, "SHOPP")
    assert exc.value.status_code == 404


def test_an_application_with_only_drafts_refuses_rather_than_reporting_success(db):
    make_rule(db, "SR00001", status=RuleStatus.draft)
    with pytest.raises(HTTPException) as exc:
        retire(db)
    assert exc.value.status_code == 409


# ---------- finding the application in the first place ----------

def test_the_summary_lists_applications_with_their_in_force_count(db):
    make_rule(db, "SR00001", app_id="SHOP")
    make_rule(db, "SR00002", app_id="SHOP")
    make_rule(db, "SR00003", app_id="CRM")
    make_rule(db, "SR00004", app_id="CRM", status=RuleStatus.draft)
    make_rule(db, "SR00005", app_id="")

    items = application_summary(db, user(db, "alex"))["items"]
    assert items == [{"app_id": "CRM", "in_force": 1}, {"app_id": "SHOP", "in_force": 2}]
