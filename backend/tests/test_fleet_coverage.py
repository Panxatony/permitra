"""One coverage figure for the estate - and what it must never hide.

The per-component drift report answers "is this firewall covered?". Nobody
watches six of those, so #40 asked for the figure across all of them, with a
trend, because the direction is the signal.

The danger in an aggregate is that it improves by looking away. Stop uploading a
configuration and the component drops out of the average; leave a device out
entirely and it never counted. These tests pin the opposite: what could not be
measured travels with the figure, and a percentage is never produced without the
denominator that gives it meaning.
"""
import os
from datetime import timedelta

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import coverage
from app.database import Base
from app.models import (
    ComponentActualConfig,
    ComponentType,
    CoverageSnapshot,
    SecurityComponent,
    Vrf,
    utcnow,
)

# Two policies, one of them carrying no rule ID: 50 per cent covered.
HALF = """\
set security policies from-zone Z100 to-zone Z040 policy jump-to-app description "SR00001"
set security policies from-zone Z100 to-zone Z040 policy jump-to-app then permit
set security policies from-zone Z010 to-zone Z050 policy quickfix-friday then permit
"""

# Both carry one: fully covered.
FULL = """\
set security policies from-zone Z100 to-zone Z040 policy jump-to-app description "SR00001"
set security policies from-zone Z110 to-zone Z040 policy mon-to-app description "SR00002"
"""


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.commit()
    yield s
    s.close()


def component(db, name, type_=ComponentType.juniper):
    c = SecurityComponent(name=name, type=type_)
    db.add(c)
    db.commit()
    return c


def upload(db, comp, content, when=None):
    row = (db.query(ComponentActualConfig)
           .filter(ComponentActualConfig.component_id == comp.id).first())
    if not row:
        row = ComponentActualConfig(component_id=comp.id)
        db.add(row)
    row.content = content
    row.fetched_at = when or utcnow()
    coverage.record_snapshot(db, comp, content, "test")
    db.commit()


# ---------- the figure itself ----------

def test_the_figure_adds_up_across_components(db):
    upload(db, component(db, "FW-A"), HALF)   # 1 of 2
    upload(db, component(db, "FW-B"), FULL)   # 2 of 2

    result = coverage.fleet_coverage(db)
    assert (result["total"], result["justified"], result["unjustified"]) == (4, 3, 1)
    assert result["percent"] == 75


def test_the_percentage_is_none_when_there_is_nothing_to_divide(db):
    """Reporting 100 per cent for an estate nobody uploaded a configuration for
    is the one answer worse than reporting none."""
    component(db, "FW-A")

    result = coverage.fleet_coverage(db)
    assert result["percent"] is None
    assert result["measured"] == 0


# ---------- what it must not hide ----------

def test_a_component_without_a_configuration_is_named_not_skipped(db):
    """The failure mode of every aggregate: it improves by looking away. Stop
    uploading and the component silently leaves the average."""
    upload(db, component(db, "FW-A"), HALF)
    component(db, "FW-never-uploaded")

    result = coverage.fleet_coverage(db)
    assert result["percent"] == 50
    assert result["measured"] == 1 and result["components_total"] == 2
    assert result["not_measured"] == [
        {"component": "FW-never-uploaded", "reason": "no configuration"}]


def test_an_unreadable_configuration_is_named_too(db):
    """It is not evidence of compliance, so it must not quietly become one."""
    upload(db, component(db, "FW-A"), FULL)
    upload(db, component(db, "ACI-A", ComponentType.aci), "some format we do not parse")

    result = coverage.fleet_coverage(db)
    assert result["percent"] == 100        # true of what was measured...
    assert result["measured"] == 1 and result["components_total"] == 2   # ...which was half
    assert result["not_measured"][0]["reason"] == "configuration format not recognised"


def test_the_age_of_the_oldest_measurement_travels_with_the_figure(db):
    """Coverage from a configuration uploaded three months ago is a souvenir,
    not a control."""
    upload(db, component(db, "FW-A"), FULL, when=utcnow() - timedelta(days=90))
    upload(db, component(db, "FW-B"), FULL)

    result = coverage.fleet_coverage(db)
    assert result["oldest_measurement_age_days"] == 90
    assert result["stale"] is True


def test_a_recent_estate_is_not_reported_as_stale(db):
    upload(db, component(db, "FW-A"), FULL)
    assert coverage.fleet_coverage(db)["stale"] is False


# ---------- the trend ----------

def test_the_trend_reports_unjustified_rules_appearing(db):
    """The signal #40 asked for: the number going the wrong way."""
    comp = component(db, "FW-A")
    upload(db, comp, FULL)   # 0 unjustified
    upload(db, comp, HALF)   # 1 unjustified

    result = coverage.fleet_coverage(db)
    assert result["unjustified_change"] == 1
    assert result["per_component"][0]["change"] == 1


def test_the_trend_reports_them_disappearing_too(db):
    comp = component(db, "FW-A")
    upload(db, comp, HALF)
    upload(db, comp, FULL)

    assert coverage.fleet_coverage(db)["unjustified_change"] == -1


def test_one_measurement_is_not_a_trend(db):
    """"No change" and "nothing to compare" are different answers, and showing a
    reassuring zero for the second one would be the wrong one."""
    upload(db, component(db, "FW-A"), HALF)

    result = coverage.fleet_coverage(db)
    assert result["unjustified_change"] is None
    assert result["compared"] == 0
    assert result["per_component"][0]["change"] is None


def test_a_component_measured_once_does_not_dilute_the_trend(db):
    comp = component(db, "FW-A")
    upload(db, comp, FULL)
    upload(db, comp, HALF)          # +1, and comparable
    upload(db, component(db, "FW-B"), HALF)   # 1 unjustified, but nothing to compare

    result = coverage.fleet_coverage(db)
    assert result["unjustified_change"] == 1   # not 2
    assert result["compared"] == 1


def test_an_unreadable_upload_is_recorded_as_unreadable(db):
    """A snapshot saying "we looked and could not tell" is a measurement. Storing
    nothing would leave a gap indistinguishable from no upload at all."""
    comp = component(db, "ACI-A", ComponentType.aci)
    upload(db, comp, "not a format we parse")

    snapshot = db.query(CoverageSnapshot).one()
    assert snapshot.recognised is False
    assert snapshot.total is None and snapshot.justified is None


def test_an_unreadable_measurement_is_not_compared_against(db):
    """Otherwise a component that became unreadable would look like its
    unjustified rules had all disappeared."""
    comp = component(db, "FW-A")
    upload(db, comp, HALF)
    upload(db, comp, "### suddenly unreadable")
    upload(db, comp, HALF)

    result = coverage.fleet_coverage(db)
    assert result["per_component"][0]["change"] == 0   # HALF vs HALF, not vs nothing
