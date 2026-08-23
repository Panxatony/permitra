"""Rules on the device that no security rule claims.

The drift comparison used to look only for SR IDs, which answers "did my rules
arrive?" and misses the question Permitra exists for. A rule somebody opened by
hand carries no ID, produced nothing to find, and was therefore not reported at
all - while the report said `in_sync: true`.

These tests pin the two properties that fix requires: unclaimed rules are found
and named, and a configuration nobody can read is reported as unreadable rather
than as clean.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import config_blocks
from app.database import Base
from app.drift import analyze_drift
from app.models import (
    ComponentActualConfig,
    ComponentType,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    Vrf,
)

# What Permitra's own Juniper export looks like: the ID in a comment above and,
# since it has to survive onto the device, in the policy description.
JUNIPER_EXPORT = """\
# SR00001: Jump host to application server
set security policies from-zone Z100 to-zone Z040 policy jump-to-app match source-address jump01
set security policies from-zone Z100 to-zone Z040 policy jump-to-app match destination-address app20
set security policies from-zone Z100 to-zone Z040 policy jump-to-app description "SR00001"
set security policies from-zone Z100 to-zone Z040 policy jump-to-app then permit

# SR00002: Monitoring
set security policies from-zone Z110 to-zone Z040 policy mon-to-app match source-address mon01
set security policies from-zone Z110 to-zone Z040 policy mon-to-app description "SR00002"
set security policies from-zone Z110 to-zone Z040 policy mon-to-app then permit
"""

# The failure mode: somebody opened a port by hand. No comment, no description,
# no ID anywhere.
HAND_ADDED = """\
set security policies from-zone Z010 to-zone Z050 policy quickfix-friday match source-address any
set security policies from-zone Z010 to-zone Z050 policy quickfix-friday match destination-address db01
set security policies from-zone Z010 to-zone Z050 policy quickfix-friday then permit
"""


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-A", type=ComponentType.juniper))
    s.add(SecurityComponent(id=2, name="ACI-A", type=ComponentType.aci))
    s.commit()
    yield s
    s.close()


def add_rule(db, rule_id, component_id=1):
    rule = Rule(rule_id=rule_id, vrf_id=1, name=rule_id.lower(),
                components=[db.get(SecurityComponent, component_id)],
                source=[{"ip": "10.0.0.1", "alias": ""}],
                destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}],
                action=RuleAction.permit, status=RuleStatus.approved)
    db.add(rule)
    db.commit()


def upload(db, text, component_id=1):
    db.add(ComponentActualConfig(component_id=component_id, content=text,
                                 uploaded_by="test"))
    db.commit()


# ---------- Counting, which is the whole point ----------

def test_every_rule_on_the_device_is_counted(db):
    """Not the SR IDs - the rules. Without a total there is no coverage."""
    blocks = config_blocks.scan(JUNIPER_EXPORT + HAND_ADDED, ComponentType.juniper)
    assert [b.identifier for b in blocks] == ["jump-to-app", "mon-to-app", "quickfix-friday"]


def test_a_policy_is_counted_once_however_many_lines_it_spans(db):
    """Juniper repeats the policy name on every match line; counting lines
    would inflate the denominator and quietly improve the coverage figure."""
    blocks = config_blocks.scan(JUNIPER_EXPORT, ComponentType.juniper)
    assert len(blocks) == 2


def test_a_hand_added_rule_is_reported_as_unjustified(db):
    """The actual failure mode, and the one that used to be invisible."""
    coverage = config_blocks.coverage(
        config_blocks.scan(JUNIPER_EXPORT + HAND_ADDED, ComponentType.juniper))

    assert coverage["total"] == 3
    assert coverage["justified"] == 2
    assert coverage["percent"] == 67
    assert [u["identifier"] for u in coverage["unjustified"]] == ["quickfix-friday"]


def test_the_unjustified_rule_carries_a_line_number(db):
    """So somebody can find it on the device."""
    coverage = config_blocks.coverage(
        config_blocks.scan(JUNIPER_EXPORT + HAND_ADDED, ComponentType.juniper))
    # JUNIPER_EXPORT ends on line 10; the hand-added block starts right after.
    assert coverage["unjustified"][0]["line"] == 11


def test_the_id_is_found_in_the_description_alone(db):
    """A real device dump has no export comments - only what was applied. The
    exporter writes the ID into the policy description for exactly this."""
    device_only = "\n".join(
        line for line in JUNIPER_EXPORT.splitlines() if not line.startswith("#"))
    coverage = config_blocks.coverage(
        config_blocks.scan(device_only, ComponentType.juniper))
    assert coverage["unjustified"] == []


def test_check_point_rules_are_recognised(db):
    script = (
        'mgmt_cli add-access-rule layer "Network" name "SR00001 jump-to-app" '
        'source "h_1" destination "h_2" action "Accept"\n'
        'mgmt_cli add-access-rule layer "Network" name "manual-fix" '
        'source "any" destination "h_3" action "Accept"\n'
    )
    coverage = config_blocks.coverage(
        config_blocks.scan(script, ComponentType.checkpoint))
    assert coverage["total"] == 2
    assert [u["identifier"] for u in coverage["unjustified"]] == ["manual-fix"]


# ---------- Saying "I cannot tell" instead of "all clear" ----------

def test_an_unrecognised_platform_reports_unknown_not_zero(db):
    """The rule that matters most here. Claiming zero unjustified rules because
    nothing could be read would be worse than admitting we cannot read it."""
    coverage = config_blocks.coverage(config_blocks.scan("anything", ComponentType.aci))

    assert coverage["recognised"] is False
    assert coverage["total"] is None
    assert coverage["percent"] is None
    assert coverage["unjustified"] == []


def test_unreadable_content_on_a_known_platform_is_also_unknown(db):
    assert config_blocks.scan("### a backup header and nothing else",
                              ComponentType.juniper) is None


# ---------- What the drift report now says ----------

def test_in_sync_is_false_while_an_unjustified_rule_sits_there(db):
    """It used to be true: the rule had no ID, so nothing found it."""
    add_rule(db, "SR00001")
    add_rule(db, "SR00002")
    upload(db, JUNIPER_EXPORT + HAND_ADDED)

    result = analyze_drift(db, db.get(SecurityComponent, 1))
    assert result["in_sync"] is False
    assert result["coverage"]["percent"] == 67
    assert result["missing"] == [] and result["stale"] == [] and result["unknown"] == []


def test_a_fully_documented_device_is_in_sync(db):
    add_rule(db, "SR00001")
    add_rule(db, "SR00002")
    upload(db, JUNIPER_EXPORT)

    result = analyze_drift(db, db.get(SecurityComponent, 1))
    assert result["in_sync"] is True
    assert result["coverage"] == {
        "recognised": True, "total": 2, "justified": 2, "percent": 100, "unjustified": [],
    }


def test_an_unreadable_config_does_not_make_the_report_fail(db):
    """Coverage unknown, but missing/stale/unknown still work as before - the
    old answer is not lost just because the new one is unavailable."""
    add_rule(db, "SR00001", component_id=2)
    upload(db, "SR00001 appears here but the format is not one we parse", component_id=2)

    result = analyze_drift(db, db.get(SecurityComponent, 2))
    assert result["coverage"]["recognised"] is False
    assert result["in_sync"] is True
    assert result["missing"] == []
