"""Tests for target/actual comparison (drift) and validity monitoring."""
from datetime import date, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.drift import analyze_drift
from app.expiry import expire_rules, expiring_rules
from app.models import (
    ComponentActualConfig,
    ComponentType,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    Vrf,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Vrf(id=1, name="IT"))
    session.flush()
    yield session
    session.close()


def make_rule(db, rule_id, component, status=RuleStatus.approved, valid_until=None):
    rule = Rule(
        rule_id=rule_id, vrf_id=1, name=rule_id, components=[component] if component else [],
        source=[{"ip": "10.0.0.1", "alias": ""}], destination=[{"ip": "10.0.0.2", "alias": ""}],
        services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
        status=status, valid_until=valid_until,
    )
    db.add(rule)
    db.flush()
    return rule


def test_drift_report(db):
    fw = SecurityComponent(name="FW-Test", type=ComponentType.juniper)
    db.add(fw)
    db.flush()
    make_rule(db, "SR0001", fw, RuleStatus.approved)      # implemented
    make_rule(db, "SR0002", fw, RuleStatus.approved)      # missing on the device
    make_rule(db, "SR0003", fw, RuleStatus.deactivated)   # still on the device (stale)
    db.add(ComponentActualConfig(
        component_id=fw.id,
        content="set security policies policy SR0001 ...\n"
                "set security policies policy SR0003 ...\n"
                "set security policies policy SR7777 ...\n",  # shadow rule
    ))
    db.commit()

    report = analyze_drift(db, fw)
    assert report["has_config"] and not report["in_sync"]
    assert [m["rule_id"] for m in report["missing"]] == ["SR0002"]
    assert [s["rule_id"] for s in report["stale"]] == ["SR0003"]
    assert report["unknown"] == ["SR7777"]


def test_drift_without_config(db):
    fw = SecurityComponent(name="FW-Test", type=ComponentType.juniper)
    db.add(fw)
    db.commit()
    assert analyze_drift(db, fw)["has_config"] is False


def test_expiry(db):
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    soon = (date.today() + timedelta(days=10)).isoformat()
    later = (date.today() + timedelta(days=300)).isoformat()
    make_rule(db, "SR0010", None, RuleStatus.approved, valid_until=yesterday)
    make_rule(db, "SR0011", None, RuleStatus.approved, valid_until=soon)
    make_rule(db, "SR0012", None, RuleStatus.approved, valid_until=later)
    make_rule(db, "SR0013", None, RuleStatus.draft, valid_until=yesterday)  # not a candidate
    db.commit()

    expired, expiring = expiring_rules(db, days=30)
    assert [r.rule_id for r in expired] == ["SR0010"]
    assert [r.rule_id for r in expiring] == ["SR0011"]

    count = expire_rules(db)
    assert count == 1
    assert db.query(Rule).filter(Rule.rule_id == "SR0010").one().status == RuleStatus.deactivated
    # A comment and a version entry were created
    rule = db.query(Rule).filter(Rule.rule_id == "SR0010").one()
    assert any("expired" in c.text for c in rule.comments)
