"""Does the rule on the device permit only what was approved? (#48)

Coverage proves a rule *claims* an approval. This proves it *matches* one. The
sharp failure it exists for: a rule widened during an incident - one host on
port 443 opened to `any` - keeps its SR ID in the description, so it wears the
approval of the narrow rule it used to be, and every earlier check reads green.

The one asymmetry is the whole feature: narrower than approved is fine
(operations may implement less), wider is a finding. These tests pin it from
both sides, and pin the honesty rule around it - a rule that cannot be resolved
to compare is reported as unverified, never as a pass.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import config_semantics as cs
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


# A device config that carries its address book, so it can be resolved fully.
# jump01 = 10.0.0.5/32, app20 = 10.0.1.0/24; the policy claims SR00001.
def juniper(source_cidr="10.0.0.5/32", dest_cidr="10.0.1.0/24",
            app="tcp-443", src_ref="jump01", action="permit"):
    return f"""\
set security zones security-zone Z100 address-book address jump01 {source_cidr}
set security zones security-zone Z040 address-book address app20 {dest_cidr}
set security policies from-zone Z100 to-zone Z040 policy p match source-address {src_ref}
set security policies from-zone Z100 to-zone Z040 policy p match destination-address app20
set security policies from-zone Z100 to-zone Z040 policy p match application {app}
set security policies from-zone Z100 to-zone Z040 policy p description "SR00001"
set security policies from-zone Z100 to-zone Z040 policy p then {action}
"""


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    s.commit()
    yield s
    s.close()


def approve(db, *, source="10.0.0.5", dest="10.0.1.0/24", port="443",
            protocol="TCP", action=RuleAction.permit):
    rule = Rule(rule_id="SR00001", vrf_id=1, name="p",
                components=[db.get(SecurityComponent, 1)],
                source=[{"ip": source, "alias": ""}],
                destination=[{"ip": dest, "alias": ""}],
                services=[{"protocol": protocol, "port": port}],
                action=action, status=RuleStatus.approved)
    db.add(rule)
    db.commit()
    return rule


def upload(db, content):
    db.add(ComponentActualConfig(component_id=1, content=content, uploaded_by="t"))
    db.commit()


def drift(db):
    return analyze_drift(db, db.get(SecurityComponent, 1))


# ---------- the comparator, in isolation ----------

def test_a_wider_source_is_a_finding():
    approved = cs.Permission(sources=[cs.ipaddress.ip_network("10.0.0.5/32")],
                             services=[cs.Service("tcp", 443, 443)])
    device = cs.Permission(src_any=True, services=[cs.Service("tcp", 443, 443)])
    assert cs.widening(device, approved)          # any source vs one host


def test_a_narrower_source_is_not_a_finding():
    approved = cs.Permission(sources=[cs.ipaddress.ip_network("10.0.0.0/24")],
                             services=[cs.Service("tcp", 443, 443)])
    device = cs.Permission(sources=[cs.ipaddress.ip_network("10.0.0.5/32")],
                           services=[cs.Service("tcp", 443, 443)])
    assert cs.widening(device, approved) == []    # a subnet is within


def test_a_wider_port_range_is_a_finding():
    approved = cs.Permission(src_any=True, services=[cs.Service("tcp", 443, 443)])
    device = cs.Permission(src_any=True, services=[cs.Service("tcp", 1, 65535)])
    assert any("service" in d for d in cs.widening(device, approved))


def test_a_narrower_service_is_fine():
    approved = cs.Permission(src_any=True, services=[cs.Service("tcp", 20, 25)])
    device = cs.Permission(src_any=True, services=[cs.Service("tcp", 22, 22)])
    assert cs.widening(device, approved) == []


def test_the_same_thing_written_differently_is_not_a_finding():
    """10.0.0.5 and 10.0.0.5/32 are the same host - normalisation must not read
    the second as wider."""
    approved = cs.approved_permission(_stub(source="10.0.0.5"))
    device = cs.Permission(sources=[cs.ipaddress.ip_network("10.0.0.5/32")],
                           services=[cs.Service("tcp", 443, 443)])
    assert cs.widening(device, approved) == []


def _stub(source="10.0.0.5"):
    from types import SimpleNamespace
    return SimpleNamespace(action=SimpleNamespace(value="permit"),
                           source=[{"ip": source}], destination=[{"ip": "10.0.1.0/24"}],
                           services=[{"protocol": "TCP", "port": "443"}])


# ---------- end to end through drift ----------

def test_a_faithful_rule_is_in_sync(db):
    approve(db)
    upload(db, juniper())
    result = drift(db)
    assert result["widened"] == []
    assert result["fidelity"] == "checked"
    assert result["in_sync"] is True


def test_a_source_widened_to_any_is_caught(db):
    """The headline case: approved for one host, opened to any on the device,
    SR ID still in the description."""
    approve(db, source="10.0.0.5")
    upload(db, juniper(src_ref="any"))
    result = drift(db)
    assert [w["rule_id"] for w in result["widened"]] == ["SR00001"]
    assert result["in_sync"] is False
    assert any("source" in d for d in result["widened"][0]["differences"])


def test_a_port_widened_on_the_device_is_caught(db):
    approve(db, port="443")
    upload(db, juniper(app="tcp-1-65535"))
    result = drift(db)
    assert any("service" in d for w in result["widened"] for d in w["differences"])


def test_a_rule_implemented_narrower_stays_in_sync(db):
    """Approved for a /24, rolled out for a single host - operations is allowed
    to implement less than was approved."""
    approve(db, dest="10.0.1.0/24")
    upload(db, juniper(dest_cidr="10.0.1.9/32"))
    assert drift(db)["widened"] == []
    assert drift(db)["in_sync"] is True


# ---------- the honesty rule ----------

def test_an_unresolvable_rule_is_unverified_not_passed(db):
    """A device rule whose address book is missing cannot be compared - it is
    reported as unverified, never silently as within approval."""
    approve(db)
    # a config with a policy referencing a name that has no address-book line
    upload(db, "set security policies from-zone A to-zone B policy p "
               "match source-address ghost\n"
               "set security policies from-zone A to-zone B policy p description \"SR00001\"\n"
               "set security policies from-zone A to-zone B policy p then permit\n")
    result = drift(db)
    assert result["widened"] == []                       # not flagged
    assert [u["rule_id"] for u in result["unverified"]] == ["SR00001"]
    assert result["fidelity"] == "partial"               # not a clean "checked"


def test_an_unparseable_platform_reports_not_checked(db):
    """ACI is a different shape and is not parsed to this depth yet - the report
    says so rather than claiming everything matched."""
    aci = db.get(SecurityComponent, 1)
    aci.type = ComponentType.aci
    db.commit()
    approve(db)
    upload(db, "some aci json we do not parse for fidelity")
    result = drift(db)
    assert result["fidelity"] == "not_checked"
    assert result["widened"] == []
