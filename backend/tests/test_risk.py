"""Tests for the risk analysis (issue #10)."""
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import RuleLogging, Vrf, Zone
from app.risk import assess_rule


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add_all([
        Zone(name="INET", pap_level="external", sort_order=0),
        Zone(name="PROD-DB", pap_level="internal", sort_order=1,
             cia_c="very high", cia_i="very high", cia_a="very high"),
        Zone(name="DEV", pap_level="internal", sort_order=2),
    ])
    s.commit()
    yield s
    s.close()


def rule(**kw):
    base = {"source": [{"ip": "10.0.0.1", "alias": ""}], "destination": [{"ip": "10.0.0.2", "alias": ""}],
            "services": [{"protocol": "TCP", "port": "443"}], "source_zone": "DEV", "destination_zone": "DEV",
            # A stub stands in for a Rule, so it carries what a Rule carries -
            # including the logging level the assessment now reads. Same default
            # as the column, so these tests keep asking what they asked before.
            "effective_log_level": RuleLogging.detailed}
    base.update(kw)
    return SimpleNamespace(**base)


def test_any_to_any_is_high(db):
    r = assess_rule(db, rule(source=[{"ip": "any", "alias": ""}],
                             destination=[{"ip": "any", "alias": ""}]))
    assert r["level"] == "high"
    assert any(f["code"] == "any-to-any" for f in r["findings"])


def test_clean_rule_has_no_findings(db):
    assert assess_rule(db, rule())["level"] == "none"


def test_risky_service_from_internet_to_high_protection(db):
    # RDP from INET (exposed) to PROD-DB (very high protection) -> high
    r = assess_rule(db, rule(source=[{"ip": "any", "alias": ""}], source_zone="INET",
                             destination_zone="PROD-DB",
                             services=[{"protocol": "TCP", "port": "3389"}]))
    assert r["level"] == "high"
    assert any(f["code"] == "risky-service" for f in r["findings"])


def test_broad_network_flagged(db):
    r = assess_rule(db, rule(source=[{"ip": "10.0.0.0/8", "alias": ""}]))
    assert any(f["code"] == "broad-network" for f in r["findings"])


def test_any_service_cross_zone(db):
    r = assess_rule(db, rule(source_zone="DEV", destination_zone="PROD-DB",
                             services=[{"protocol": "ANY", "port": ""}]))
    assert any(f["code"] == "any-service" for f in r["findings"])
