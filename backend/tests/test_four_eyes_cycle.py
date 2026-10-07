"""Separation of duties covers everyone who shaped the content under review,
not just whoever touched it last.

The check used to exclude three names: creator, current requestor, and the
writer of the newest version. So an architect who edited a draft could
approve it once somebody else had submitted, and a submitter could approve
their own submission once any later version - an implementation status, a
handover, an address propagation - had replaced them as "newest". The set is
the current review cycle now, and a cycle ends with a decision.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
    apply_roles,
)
from app.routers.rules_router import ReviewDecision, _decide, accounts_involved, add_version


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    for name in ("alex", "bea", "chris", "ops"):
        u = User(username=name, password_hash="x", is_active=True)
        apply_roles(u, [Role.architect, Role.change_approver] if name != "ops" else [Role.operations])
        s.add(u)
    s.commit()
    yield s
    s.close()


def user(db, name):
    return db.query(User).filter(User.username == name).one()


def make_rule(db, *, requestor="alex", created_by="alex"):
    rule = Rule(rule_id="SR00001", vrf_id=1, name="sr00001", requestor=requestor, created_by=created_by,
                components=[db.get(SecurityComponent, 1)],
                source=[{"ip": "10.0.0.1", "alias": ""}], destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
                status=RuleStatus.draft, source_zone="Z010", destination_zone="Z020")
    db.add(rule)
    db.commit()
    return rule


def write(db, rule, who, status, note="Rule changed"):
    """A version in `who`'s name with the rule in `status` - what every edit,
    submit, decision or status update leaves behind."""
    rule.status = status
    rule.version += 1
    add_version(db, rule, user(db, who), note)
    db.commit()


def approve(db, who):
    return _decide(db, "SR00001", user(db, who), ReviewDecision(), RuleStatus.approved, "Rule approved")


def refused(db, who):
    with pytest.raises(HTTPException) as exc:
        approve(db, who)
    assert exc.value.status_code == 403


# ---------- the gaps ----------

def test_an_earlier_editor_of_the_draft_cannot_approve_it(db):
    """bea edited alex's draft, alex submitted: the newest version is alex's,
    and bea used to be free to approve content she wrote."""
    rule = make_rule(db)
    write(db, rule, "bea", RuleStatus.draft)
    write(db, rule, "alex", RuleStatus.in_review)
    refused(db, "bea")


def test_a_later_status_update_does_not_clear_the_submitter(db):
    """chris submitted alex's rule; ops wrote a version while it was in
    review. The newest version was now ops', and chris could approve."""
    rule = make_rule(db)
    write(db, rule, "chris", RuleStatus.in_review)
    write(db, rule, "ops", RuleStatus.in_review, "Implementation status changed")
    refused(db, "chris")


def test_a_requestor_handed_over_during_the_cycle_stays_excluded(db):
    rule = make_rule(db, requestor="bea", created_by="alex")
    write(db, rule, "alex", RuleStatus.in_review)
    rule.requestor = "chris"                      # handover confirmed
    write(db, rule, "chris", RuleStatus.in_review, "Requestor handover")
    refused(db, "bea")
    refused(db, "chris")


def test_a_rollback_by_another_account_makes_them_involved(db):
    rule = make_rule(db)
    write(db, rule, "bea", RuleStatus.draft, "Rolled back to version 1")
    write(db, rule, "alex", RuleStatus.in_review)
    refused(db, "bea")


def test_names_are_compared_case_insensitively(db):
    rule = make_rule(db, requestor="BEA", created_by="alex")
    write(db, rule, "alex", RuleStatus.in_review)
    refused(db, "bea")


# ---------- what must stay possible ----------

def test_an_uninvolved_approver_still_approves(db):
    rule = make_rule(db)
    write(db, rule, "bea", RuleStatus.draft)
    write(db, rule, "alex", RuleStatus.in_review)
    assert approve(db, "chris").status == RuleStatus.approved


def test_a_closed_cycle_does_not_poison_the_next_one(db):
    """chris submitted the first version and bea approved it. Later alex edits
    and resubmits; chris, who did nothing in the new cycle, may approve it -
    involvement is not for life."""
    rule = make_rule(db)
    write(db, rule, "chris", RuleStatus.in_review)
    write(db, rule, "bea", RuleStatus.approved, "Rule approved")
    write(db, rule, "ops", RuleStatus.active, "Implementation status changed")
    write(db, rule, "alex", RuleStatus.draft)
    write(db, rule, "alex", RuleStatus.in_review)
    assert "chris" not in accounts_involved(rule)
    assert approve(db, "chris").status == RuleStatus.approved


def test_a_system_actor_counts_for_nobody_and_clears_nobody(db):
    rule = make_rule(db)
    write(db, rule, "chris", RuleStatus.in_review)
    rule.version += 1
    from app.models import RuleVersion
    db.add(RuleVersion(rule_pk=rule.id, version=rule.version, snapshot={"status": "in_review"},
                       change_note="Expiry check", changed_by="system"))
    db.commit()
    involved = accounts_involved(rule)
    assert "system" not in involved
    assert "chris" in involved
