"""Tests for the append-only audit store and soft delete (issue #24)."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import audit
from app.database import Base
from app.models import AuditEvent, Rule, RuleAction, RuleStatus, RuleVersion, User, Vrf
from app.routers.rules_router import delete_rule


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    r = Rule(rule_id="SR00001", vrf_id=1, name="Regel A",
             source=[{"ip": "10.0.0.1", "alias": ""}], destination=[{"ip": "10.0.0.2", "alias": ""}],
             services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
             status=RuleStatus.approved)
    s.add(r)
    s.flush()
    s.add(RuleVersion(rule_pk=r.id, version=1, snapshot={}, change_note="angelegt", changed_by="alex"))
    s.commit()
    yield s
    s.close()


class Req:
    class client:
        host = "203.0.113.5"


def test_record_persists_and_appears_in_collect(db):
    audit.record(db, "admin", "user.created", actor="root", object="bob",
                 detail="Benutzer angelegt", source_ip="203.0.113.9")
    stored = db.query(AuditEvent).all()
    assert len(stored) == 1 and stored[0].event == "user.created"
    events = audit.collect(db)
    assert any(e["event"] == "user.created" and e["source_ip"] == "203.0.113.9" for e in events)


def test_soft_delete_keeps_history_and_audits(db):
    admin = User(username="root", password_hash="x", role="admin", is_active=True)
    delete_rule(Req(), "SR00001", db, admin)
    rule = db.query(Rule).filter(Rule.rule_id == "SR00001").one()
    # The rule is preserved and carries the deletion as its state
    assert rule.deleted_at is not None
    assert rule.status == RuleStatus.deleted
    # The previous version is untouched and the deletion is a version of its own,
    # so the history shows when the rule left service and who decided it.
    versions = (db.query(RuleVersion).filter(RuleVersion.rule_pk == rule.id)
                .order_by(RuleVersion.version).all())
    assert len(versions) == 2
    assert versions[-1].changed_by == "root"
    # The deletion is logged (including the source IP)
    ev = db.query(AuditEvent).filter(AuditEvent.event == "rule.deleted").one()
    assert ev.object == "SR00001" and ev.source_ip == "203.0.113.5"


def test_soft_deleted_excluded_from_list(db):
    admin = User(username="root", password_hash="x", role="admin", is_active=True)
    delete_rule(Req(), "SR00001", db, admin)
    active = db.query(Rule).filter(Rule.deleted_at.is_(None)).count()
    assert active == 0
    # but still findable in the audit log
    assert any(e["event"] == "rule.deleted" for e in audit.collect(db))
