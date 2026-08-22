"""Tests for the implementation workflow: re-approval -> "to change" for operations."""
import pytest
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
from app.routers.rules_router import _decide, impl_pending
from app.schemas import ReviewDecision


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Vrf(id=1, name="IT"))
    session.flush()
    yield session
    session.close()


def make_rule(db, fw, status=RuleStatus.in_review, impl=None):
    rule = Rule(
        rule_id="SR0001", vrf_id=1, name="Test", components=[fw],
        source=[{"ip": "10.0.0.1", "alias": ""}], destination=[{"ip": "10.0.0.2", "alias": ""}],
        services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
        status=status, impl_status=impl or {},
    )
    db.add(rule)
    db.commit()
    return rule


def approver():
    return User(username="chris", password_hash="x", role=Role.change_approver)


def test_reapproval_marks_implemented_components_as_change(db):
    fw = SecurityComponent(name="FW-Test", type=ComponentType.juniper)
    db.add(fw)
    db.flush()
    rule = make_rule(db, fw, impl={"FW-Test": "implemented"})

    _decide(db, "SR0001", approver(), ReviewDecision(comment=""), RuleStatus.approved, "Regel freigegeben")
    db.refresh(rule)
    assert rule.status == RuleStatus.approved
    assert rule.impl_status["FW-Test"] == "to change"
    assert impl_pending(rule)

    # After the change, operations sets it back to "implemented" -> no longer open
    rule.impl_status = {"FW-Test": "implemented"}
    db.commit()
    assert not impl_pending(rule)


def test_first_approval_keeps_open_status(db):
    fw = SecurityComponent(name="FW-Test", type=ComponentType.juniper)
    db.add(fw)
    db.flush()
    rule = make_rule(db, fw)  # new rule, never implemented before

    _decide(db, "SR0001", approver(), ReviewDecision(comment=""), RuleStatus.approved, "Regel freigegeben")
    db.refresh(rule)
    # no "to change" (it was never implemented), but counted as to be implemented
    assert rule.impl_status.get("FW-Test") in (None, "open")
    assert impl_pending(rule)


def test_impl_pending_only_for_approved_rules_with_components(db):
    fw = SecurityComponent(name="FW-Test", type=ComponentType.juniper)
    db.add(fw)
    db.flush()
    draft = make_rule(db, fw, status=RuleStatus.draft)
    assert not impl_pending(draft)  # only approved rules count
    draft.status = RuleStatus.approved
    draft.impl_status = {"FW-Test": "deactivated"}
    assert not impl_pending(draft)  # "deactivated" does not count as open
