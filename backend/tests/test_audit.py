"""Tests for the unified audit log (issue #11)."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.audit import collect
from app.database import Base
from app.models import (
    Rule,
    RuleAction,
    RuleStatus,
    RuleVersion,
    Vrf,
    ZonePolicyChange,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    r = Rule(rule_id="SR00001", vrf_id=1, name="r",
             source=[{"ip": "10.0.0.1", "alias": ""}], destination=[{"ip": "10.0.0.2", "alias": ""}],
             services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
             status=RuleStatus.approved)
    s.add(r)
    s.flush()
    s.add(RuleVersion(rule_pk=r.id, version=1, snapshot={}, change_note="angelegt", changed_by="alex"))
    s.add(ZonePolicyChange(batch_id="b1", change_type="policy", from_zone="A", to_zone="B",
                           new_policy="block_all", status="approved",
                           requested_by="alex", decided_by="chris", comment="Härtung"))
    s.commit()
    yield s
    s.close()


def test_collect_merges_sources(db):
    events = collect(db)
    types = {e["type"] for e in events}
    assert types == {"rule", "zone_change"}
    rule_ev = next(e for e in events if e["type"] == "rule")
    assert rule_ev["object"] == "SR00001" and rule_ev["actor"] == "alex"
    zone_ev = next(e for e in events if e["type"] == "zone_change")
    assert zone_ev["actor"] == "chris" and zone_ev["status"] == "approved"


def test_filter_by_type(db):
    assert all(e["type"] == "rule" for e in collect(db, event_type="rule"))
