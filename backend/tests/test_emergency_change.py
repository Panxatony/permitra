"""A way in for the rule that was opened on the firewall at three in the morning.

Every rule needs somebody else's approval, and that holds until the application
is down and the only change approver is unreachable. The rule gets opened on the
device anyway. A tool without a documented fast path does not prevent that - it
only prevents it from being recorded, which is strictly worse.

These tests pin the two halves that make this a control rather than a loophole.
It has to be *possible*: the reason is written down, and documenting the rule is
not refused because the zone matrix forbids it - the traffic is already flowing
and refusing the record would lose the only thing still obtainable. And it has
to be *narrow*: the reason is mandatory, the window is short, the rule
deactivates itself when nobody approves it, and the declaration is never erased,
because "how often do we do this?" is the question that separates a working
emergency path from a habit.
"""
import os
from datetime import timedelta
from typing import ClassVar

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.expiry import expire_emergency_rules
from app.models import (
    AddressComponentMap,
    AuditEvent,
    Comment,
    ComponentType,
    Role,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
    Zone,
    ZoneNetwork,
    ZonePolicy,
    utcnow,
)
from app.routers.rules_router import declare_emergency_rule
from app.schemas import EmergencyRuleCreate

REASON = "Payment gateway down, INC-4711, approver unreachable at 03:00"


class Req:
    headers: ClassVar[dict] = {}

    class client:
        host = "203.0.113.9"


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-BER", type=ComponentType.juniper))
    s.add(Zone(id=1, code="Z010", name="DMZ", sort_order=10, pap_level="external"))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20, cia_c="high"))
    s.commit()
    s.add(ZoneNetwork(cidr="10.0.0.0/24", zone_id=1, vrf_id=1))
    s.add(ZoneNetwork(cidr="10.0.1.0/24", zone_id=2, vrf_id=1))
    for net in ("10.0.0.0/24", "10.0.1.0/24"):
        s.add(AddressComponentMap(ip=net, vrf_id=1, component_ids=[1]))
    s.add(ZonePolicy(from_zone_id=1, to_zone_id=2, policy="allow_only"))
    s.commit()
    yield s
    s.close()


def ops(db):
    user = User(username="betrieb", password_hash="x", role=Role.operations, is_active=True)
    db.add(user)
    db.commit()
    return user


def payload(reason=REASON, **over):
    data = {
        "name": "incident-fix",
        "source": [{"ip": "10.0.0.5", "alias": ""}],
        "destination": [{"ip": "10.0.1.9", "alias": ""}],
        "services": [{"protocol": "TCP", "port": "443"}],
        "action": RuleAction.permit,
        "justification": "Payment gateway must reach the acquirer",
        "requestor": "betrieb",
        "valid_until": "2027-01-01",
        "emergency_reason": reason,
    }
    data.update(over)
    return EmergencyRuleCreate(**data)


def declare(db, user, **over):
    return declare_emergency_rule(payload(**over), Req(), db, user)


# ---------- it has to be possible ----------

def test_the_reason_is_written_down_while_somebody_remembers_it(db):
    """The whole point. Days later, when drift notices, nobody knows why."""
    rule = declare(db, ops(db))

    assert rule.emergency_reason == REASON
    assert rule.emergency_declared_by == "betrieb"
    assert rule.emergency_declared_at is not None


def test_the_rule_goes_into_review_not_into_force(db):
    """An emergency change is not approved - it is waiting for approval."""
    rule = declare(db, ops(db))
    assert rule.status == RuleStatus.in_review


def test_operations_may_declare_one(db):
    """The person at the firewall at three in the morning is operations, not an
    architect. A fast path only they cannot use is not a fast path."""
    assert declare(db, ops(db)).rule_id.startswith("SR")


def test_the_reason_travels_into_the_history_and_a_comment(db):
    """A column somebody has to know about is not a record. It belongs where
    anybody reading the rule will see it."""
    rule = declare(db, ops(db))

    notes = [v.change_note for v in rule.versions]
    assert "Emergency change declared: {reason}" in notes
    assert any(REASON in c.text for c in db.query(Comment).all())


def test_it_is_its_own_audit_event(db):
    """"How often do we do this?" has to be answerable. Twice a year is a working
    control; weekly is a finding, and the difference must be countable."""
    declare(db, ops(db))

    events = [e.event for e in db.query(AuditEvent).all()]
    assert "rule.emergency_declared" in events


# ---------- documenting it must not be refused ----------

def test_a_rule_against_the_zone_matrix_is_still_recorded(db):
    """The traffic is already flowing. Refusing the *documentation* because the
    matrix forbids it leaves the rule on the device and the record missing -
    the worst of both, and it teaches people not to bother next time."""
    policy = db.query(ZonePolicy).first()
    policy.policy = "block_all"
    db.commit()

    rule = declare(db, ops(db))
    assert rule.status == RuleStatus.in_review
    assert rule.removal_reason, "the violation has to be recorded, not swallowed"
    assert any("matrix" in c.text.lower() or "Matrix" in c.text
               for c in db.query(Comment).all())


def test_the_normal_path_still_refuses_it(db):
    """The exception is the emergency path's alone. If the ordinary create
    started tolerating the matrix too, this would be a hole rather than a door."""
    from app.routers.rules_router import create_rule
    from app.schemas import RuleCreate

    policy = db.query(ZonePolicy).first()
    policy.policy = "block_all"
    db.commit()

    data = payload().model_dump(exclude={"emergency_reason"})
    with pytest.raises(HTTPException) as exc:
        create_rule(RuleCreate(**data), db,
                    User(username="arch", password_hash="x", role=Role.architect))
    assert exc.value.status_code == 422


# ---------- and it has to stay narrow ----------

def test_a_thin_reason_is_refused(db):
    """Free text, and it has to say something. "asap" is not evidence."""
    with pytest.raises(ValueError):
        payload(reason="asap")


def test_the_window_is_short_and_recorded(db):
    rule = declare(db, ops(db))

    assert rule.emergency_approval_due is not None
    hours = (rule.emergency_approval_due - rule.emergency_declared_at).total_seconds() / 3600
    assert 0 < hours <= 24


def test_an_unapproved_emergency_change_deactivates_itself(db):
    """The window is not a reminder. If nobody approves, the rule loses its
    standing and operations is told to remove it."""
    rule = declare(db, ops(db))
    rule.emergency_approval_due = utcnow() - timedelta(minutes=1)
    db.commit()

    assert expire_emergency_rules(db) == 1
    db.refresh(rule)
    assert rule.status == RuleStatus.deactivated
    assert rule.impl_status["FW-BER"] == "to remove"


def test_it_is_left_alone_while_the_window_is_open(db):
    rule = declare(db, ops(db))

    assert expire_emergency_rules(db) == 0
    db.refresh(rule)
    assert rule.status == RuleStatus.in_review


def test_the_declaration_survives_the_decision(db):
    """The window closes, the record does not. Erasing it would make the one
    question worth asking - how often do we do this? - unanswerable."""
    rule = declare(db, ops(db))
    rule.emergency_approval_due = utcnow() - timedelta(minutes=1)
    db.commit()
    expire_emergency_rules(db)
    db.refresh(rule)

    assert rule.emergency_approval_due is None      # decided, by the clock
    assert rule.emergency_declared_at is not None   # but it happened
    assert rule.emergency_reason == REASON


def test_approval_closes_the_window_and_keeps_the_declaration(db):
    from app.routers.rules_router import _decide
    from app.schemas import ReviewDecision

    rule = declare(db, ops(db))
    approver = User(username="chris", password_hash="x",
                    role=Role.change_approver, is_active=True)
    db.add(approver)
    db.commit()

    _decide(db, rule.rule_id, approver, ReviewDecision(comment="checked, keep it"),
            RuleStatus.approved, "Rule approved")
    db.refresh(rule)

    assert rule.status == RuleStatus.approved
    assert rule.emergency_approval_due is None
    assert rule.emergency_declared_at is not None


def test_an_expired_one_is_not_deactivated_twice(db):
    rule = declare(db, ops(db))
    rule.emergency_approval_due = utcnow() - timedelta(hours=2)
    db.commit()

    assert expire_emergency_rules(db) == 1
    assert expire_emergency_rules(db) == 0


# ---------- the interaction that would have made it unusable ----------

def test_a_pending_emergency_rule_is_not_reported_as_stale(db):
    """It is in review and therefore not in force, but it is on the device on
    purpose. Reporting it as stale would tell operations to tear down the rule
    keeping the incident closed - and teach them to ignore the finding."""
    from app.drift import analyze_drift
    from app.models import ComponentActualConfig

    rule = declare(db, ops(db))
    db.add(ComponentActualConfig(
        component_id=1, uploaded_by="test",
        content=f'set security policies from-zone Z010 to-zone Z020 policy fix '
                f'description "{rule.rule_id}"\n'))
    db.commit()

    result = analyze_drift(db, db.get(SecurityComponent, 1))
    assert result["stale"] == []


def test_it_does_become_stale_once_the_window_has_passed(db):
    """The exemption lasts exactly as long as the window. Afterwards the rule
    is deactivated and belongs off the device like any other."""
    from app.drift import analyze_drift
    from app.models import ComponentActualConfig

    rule = declare(db, ops(db))
    db.add(ComponentActualConfig(
        component_id=1, uploaded_by="test",
        content=f'set security policies from-zone Z010 to-zone Z020 policy fix '
                f'description "{rule.rule_id}"\n'))
    rule.emergency_approval_due = utcnow() - timedelta(minutes=1)
    db.commit()
    expire_emergency_rules(db)

    result = analyze_drift(db, db.get(SecurityComponent, 1))
    assert [s["rule_id"] for s in result["stale"]] == [rule.rule_id]
