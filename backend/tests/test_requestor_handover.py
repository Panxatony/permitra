"""Handing a rule's requestor to a successor who has to agree.

An architect changes department or company, and the rules they requested need a
new accountable person. The current requestor proposes a successor - but the
requestor does not change until that successor confirms. An accountable person
is not assigned a rule without their consent, or the record would name someone
who never agreed to carry it.

These tests pin that consent: a proposal alone changes nothing, only the
proposed successor can confirm, and the departed-requestor case (the reason the
feature exists) is reachable by an admin without becoming a way to reassign
anybody's rules at will.
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
)
from app.routers.rules_router import (
    RequestorHandover,
    cancel_requestor_handover,
    confirm_requestor_handover,
    propose_requestor_handover,
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
    s.add(User(username="anna", password_hash="x", role=Role.architect, is_active=True))
    s.add(User(username="bea", password_hash="x", role=Role.architect, is_active=True))
    s.add(User(username="cyril", password_hash="x", role=Role.operations, is_active=True))
    s.add(User(username="admin", password_hash="x", role=Role.admin, is_active=True))
    s.commit()
    yield s
    s.close()


def user(db, name):
    return db.query(User).filter(User.username == name).one()


def make_rule(db, requestor="anna"):
    rule = Rule(rule_id="SR00001", vrf_id=1, name="r", requestor=requestor,
                components=[db.get(SecurityComponent, 1)],
                source=[{"ip": "10.0.0.1", "alias": ""}],
                destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}],
                action=RuleAction.permit, status=RuleStatus.approved)
    db.add(rule)
    db.commit()
    return rule


def propose(db, actor, new):
    return propose_requestor_handover("SR00001", RequestorHandover(new_requestor=new),
                                      Req(), db, user(db, actor))


# ---------- consent: a proposal changes nothing on its own ----------

def test_a_proposal_does_not_change_the_requestor(db):
    make_rule(db, requestor="anna")
    rule = propose(db, "anna", "bea")
    assert rule.requestor == "anna"        # still anna
    assert rule.pending_requestor == "bea"


def test_only_the_proposed_successor_can_confirm(db):
    make_rule(db, requestor="anna")
    propose(db, "anna", "bea")

    # anna cannot confirm her own handover into being
    with pytest.raises(HTTPException) as exc:
        confirm_requestor_handover("SR00001", Req(), db, user(db, "anna"))
    assert exc.value.status_code == 403

    rule = confirm_requestor_handover("SR00001", Req(), db, user(db, "bea"))
    assert rule.requestor == "bea"
    assert rule.pending_requestor == ""


def test_the_confirmation_is_recorded_on_the_rule_history(db):
    make_rule(db, requestor="anna")
    propose(db, "anna", "bea")
    confirm_requestor_handover("SR00001", Req(), db, user(db, "bea"))

    rule = db.query(Rule).one()
    notes = [v.change_note for v in rule.versions]
    assert any("handover confirmed" in n for n in notes)


# ---------- who may propose ----------

def test_only_the_current_requestor_proposes(db):
    """bea is an architect but not anna's rule's requestor - she cannot hand
    away a responsibility that is not hers."""
    make_rule(db, requestor="anna")
    with pytest.raises(HTTPException) as exc:
        propose(db, "bea", "bea")
    assert exc.value.status_code == 403


def test_the_successor_must_be_an_architect(db):
    """A requestor is an architect account; operations rolls rules out, it does
    not own the decision that they are needed."""
    make_rule(db, requestor="anna")
    with pytest.raises(HTTPException) as exc:
        propose(db, "anna", "cyril")      # operations
    assert exc.value.status_code == 422


def test_handing_to_the_current_requestor_is_refused(db):
    make_rule(db, requestor="anna")
    with pytest.raises(HTTPException) as exc:
        propose(db, "anna", "anna")
    assert exc.value.status_code == 422


# ---------- the departed requestor: the reason it exists ----------

def test_an_admin_may_propose_once_the_requestor_has_left(db):
    """The motivating case: the architect already left, their account is gone,
    and the rule cannot be handed over by someone who can no longer reach it."""
    make_rule(db, requestor="anna")
    user(db, "anna").is_active = False
    db.commit()

    rule = propose(db, "admin", "bea")
    assert rule.pending_requestor == "bea"


def test_an_admin_may_not_reassign_while_the_requestor_is_still_active(db):
    """The admin path is for the orphan case only - not a way to move anybody's
    rules around at will while they are still here to do it themselves."""
    make_rule(db, requestor="anna")     # anna is active
    with pytest.raises(HTTPException) as exc:
        propose(db, "admin", "bea")
    assert exc.value.status_code == 403


# ---------- operations as requestor: the emergency-change case ----------

def test_operations_requestor_can_hand_a_rule_over(db):
    """An emergency change is requested by the ops account that opened it (#36),
    so an ops account can be a requestor - and must be able to hand its own rule
    to the architect who owns the application. Blocking that stranded the rule
    with the wrong accountable person."""
    make_rule(db, requestor="cyril")   # cyril is operations
    rule = propose_requestor_handover("SR00001", RequestorHandover(new_requestor="anna"),
                                      Req(), db, user(db, "cyril"))
    assert rule.pending_requestor == "anna"

    confirmed = confirm_requestor_handover("SR00001", Req(), db, user(db, "anna"))
    assert confirmed.requestor == "anna"


def test_a_non_requestor_operations_account_still_cannot(db):
    """Loosening the role gate must not let just any ops account hand away
    someone else's rule - the requestor check still holds."""
    make_rule(db, requestor="anna")
    # a second ops account with no part in this rule
    db.add(User(username="cyril2", password_hash="x", role=Role.operations, is_active=True))
    db.commit()
    with pytest.raises(HTTPException) as exc:
        propose_requestor_handover("SR00001", RequestorHandover(new_requestor="bea"),
                                   Req(), db, user(db, "cyril2"))
    assert exc.value.status_code == 403


# ---------- ending a proposal ----------

def test_the_successor_can_decline(db):
    make_rule(db, requestor="anna")
    propose(db, "anna", "bea")
    rule = cancel_requestor_handover("SR00001", Req(), db, user(db, "bea"))
    assert rule.pending_requestor == ""
    assert rule.requestor == "anna"       # unchanged


def test_a_bystander_cannot_end_someone_elses_handover(db):
    make_rule(db, requestor="anna")
    propose(db, "anna", "bea")
    # a third architect with no part in it
    db.add(User(username="dora", password_hash="x", role=Role.architect, is_active=True))
    db.commit()
    with pytest.raises(HTTPException) as exc:
        cancel_requestor_handover("SR00001", Req(), db, user(db, "dora"))
    assert exc.value.status_code == 403
