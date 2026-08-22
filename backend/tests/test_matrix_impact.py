"""Tests for the impact analysis of matrix changes (allow -> block): affected
approved rules are reset to review once the change is approved."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    User,
    Vrf,
    Zone,
    ZonePolicy,
    ZonePolicyType,
)
from app.routers.zones_router import _affected_rules, _create_batch, _decide_change


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Vrf(id=1, name="IT"))
    a = Zone(name="MGMT", sort_order=1)
    b = Zone(name="PROD", sort_order=2)
    session.add_all([a, b])
    session.flush()
    session.add(ZonePolicy(from_zone_id=a.id, to_zone_id=b.id, policy=ZonePolicyType.allow_only))
    for i, status in enumerate((RuleStatus.approved, RuleStatus.approved,
                                RuleStatus.draft, RuleStatus.deactivated), start=1):
        session.add(Rule(
            rule_id=f"SR{i:05d}", vrf_id=1, name=f"Regel {i}",
            source=[{"ip": "10.10.80.5", "alias": ""}], destination=[{"ip": "10.10.30.5", "alias": ""}],
            services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
            status=status, source_zone="MGMT", destination_zone="PROD",
        ))
    session.commit()
    yield session
    session.close()


def user(name, role=Role.architect):
    return User(username=name, password_hash="x", role=role)


def test_affected_rules_analysis(db):
    rules = _affected_rules(db, "MGMT", "PROD")
    # A deactivated rule does not count, drafts and approved ones do
    assert [r.rule_id for r in rules] == ["SR00001", "SR00002", "SR00003"]
    # The reverse direction is not affected (the matrix is directed)
    assert _affected_rules(db, "PROD", "MGMT") == []


def test_block_resets_approved_rules_to_review(db):
    _create_batch(db, user("alex"), [
        {"type": "policy", "from_zone": "MGMT", "to_zone": "PROD", "policy": "block_all"},
    ], "Härtung")
    from app.models import ZonePolicyChange
    change = db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()

    _decide_change(db, change.id, user("chris", Role.change_approver), True, "")
    # After the first approval: nothing has happened yet
    assert db.query(Rule).filter(Rule.status == RuleStatus.approved).count() == 2

    result = _decide_change(db, change.id, user("kim", Role.change_approver), True, "")
    assert sorted(result["reviews_reset"]) == ["SR00001", "SR00002"]

    reset = db.query(Rule).filter(Rule.rule_id == "SR00001").one()
    assert reset.status == RuleStatus.in_review
    assert any("Block" in c.text for c in reset.comments)
    assert any("Block" in v.change_note for v in reset.versions)
    # The draft and the deactivated rule stay unchanged
    assert db.query(Rule).filter(Rule.rule_id == "SR00003").one().status == RuleStatus.draft
    assert db.query(Rule).filter(Rule.rule_id == "SR00004").one().status == RuleStatus.deactivated


def test_allow_change_has_no_rule_impact(db):
    db.query(ZonePolicy).delete()
    db.commit()
    _create_batch(db, user("alex"), [
        {"type": "policy", "from_zone": "PROD", "to_zone": "MGMT", "policy": "allow_only"},
    ], "")
    from app.models import ZonePolicyChange
    change = db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()
    _decide_change(db, change.id, user("chris", Role.change_approver), True, "")
    result = _decide_change(db, change.id, user("kim", Role.change_approver), True, "")
    assert "reviews_reset" not in result
    assert db.query(Rule).filter(Rule.status == RuleStatus.approved).count() == 2


def test_approve_of_blocked_rule_becomes_removal(db):
    """After a matrix block: 'approve' in the review means approving removal."""
    from app.models import ComponentType, SecurityComponent, ZonePolicyChange
    from app.routers.rules_router import _decide, impl_pending
    from app.schemas import ReviewDecision

    fw = SecurityComponent(name="FW-Test", type=ComponentType.juniper)
    db.add(fw)
    db.flush()
    rule = db.query(Rule).filter(Rule.rule_id == "SR00001").one()
    rule.components = [fw]
    rule.impl_status = {"FW-Test": "implemented"}
    db.commit()

    # Switch the matrix to block (puts SR00001/SR00002 into review)
    _create_batch(db, user("alex"), [
        {"type": "policy", "from_zone": "MGMT", "to_zone": "PROD", "policy": "block_all"},
    ], "")
    change = db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()
    _decide_change(db, change.id, user("chris", Role.change_approver), True, "")
    _decide_change(db, change.id, user("kim", Role.change_approver), True, "")
    db.refresh(rule)
    assert rule.status == RuleStatus.in_review

    result = _decide(db, "SR00001", user("chris", Role.change_approver),
                     ReviewDecision(comment="Rückbau ok"), RuleStatus.approved, "Regel freigegeben")
    assert result.status == RuleStatus.deactivated
    assert result.impl_status["FW-Test"] == "to remove"
    assert impl_pending(result)  # shows up for operations as an open implementation
    assert any("Removal approved" in v.change_note for v in result.versions)

    # Operations rolls it back and sets "deactivated" -> no longer open
    result.impl_status = {"FW-Test": "deactivated"}
    assert not impl_pending(result)
