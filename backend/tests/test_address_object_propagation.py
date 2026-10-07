"""Changing an address object rewrites the rules that use it - and that must
not be a way around the review.

The new IP used to be written into every rule carrying the alias with no
further look: the derived zones stayed as they were, the zone matrix was not
asked, the components did not follow, and the approval stood. An architect or
operations account could point an approved rule at a new target that nobody
had approved. The change now faces the checks an edit of the rule faces, and a
rule in force goes back to draft.
"""
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    AddressComponentMap,
    AddressObject,
    ComponentType,
    Rule,
    RuleAction,
    RuleStatus,
    RuleVersion,
    SecurityComponent,
    Vrf,
    Zone,
    ZoneNetwork,
    ZonePolicy,
    ZonePolicyType,
)
from app.routers.objects_router import propagate_ip_change


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-BER", type=ComponentType.juniper))
    s.add(SecurityComponent(id=2, name="ACI-FFM", type=ComponentType.aci))
    s.add(Zone(id=1, code="Z010", name="DEV", sort_order=10))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20))
    s.add(Zone(id=3, code="Z030", name="TEST", sort_order=30))
    s.add(Zone(id=4, code="Z040", name="LAB", sort_order=40))
    s.add(ZoneNetwork(zone_id=1, vrf_id=1, cidr="10.0.1.0/24"))
    s.add(ZoneNetwork(zone_id=2, vrf_id=1, cidr="10.0.2.0/24"))
    s.add(ZoneNetwork(zone_id=3, vrf_id=1, cidr="10.0.3.0/24"))
    s.add(ZoneNetwork(zone_id=4, vrf_id=1, cidr="10.0.4.0/24"))
    # DEV and PROD are enforced by the firewall; TEST and LAB only by the fabric.
    s.add(AddressComponentMap(vrf_id=1, ip="10.0.1.0/24", component_ids=[1]))
    s.add(AddressComponentMap(vrf_id=1, ip="10.0.2.0/24", component_ids=[1]))
    s.add(AddressComponentMap(vrf_id=1, ip="10.0.3.0/24", component_ids=[2]))
    s.add(AddressComponentMap(vrf_id=1, ip="10.0.4.0/24", component_ids=[2]))
    s.commit()
    yield s
    s.close()


def make_rule(db, rule_id="SR00001", status=RuleStatus.approved, src="10.0.1.5",
              dst="10.0.1.7", zone="Z010", component=1):
    """An intra-zone rule whose source carries the alias web01 (DEV by default)."""
    r = Rule(
        rule_id=rule_id, vrf_id=1, name=rule_id, components=[db.get(SecurityComponent, component)],
        source=[{"ip": src, "alias": "web01"}], destination=[{"ip": dst, "alias": ""}],
        services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
        status=status, source_zone=zone, destination_zone=zone,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def change(db, new_ip, old_ip="10.0.1.5"):
    obj = AddressObject(name="web01", ip=new_ip)
    db.add(obj)
    db.commit()
    changed = propagate_ip_change(db, obj, old_ip, "arch")
    db.commit()
    return changed


def test_a_rule_in_force_goes_back_to_draft(db):
    """What was approved was the old address."""
    rule = make_rule(db)
    assert change(db, "10.0.1.9") == 1
    db.refresh(rule)
    assert rule.source[0]["ip"] == "10.0.1.9"
    assert rule.status == RuleStatus.draft
    note = db.query(RuleVersion).filter(RuleVersion.rule_pk == rule.id).one().change_note
    assert "new review" in note


def test_a_draft_stays_a_draft(db):
    """Nothing to withdraw; the history still records the change."""
    rule = make_rule(db, status=RuleStatus.draft)
    change(db, "10.0.1.9")
    db.refresh(rule)
    assert rule.status == RuleStatus.draft
    assert rule.version == 2


def test_zones_and_components_follow_the_address(db):
    """Zones are derived data; a rule whose source moves to another zone is a
    different rule, and its components come from the new addresses."""
    rule = make_rule(db)
    change(db, "10.0.2.9")
    db.refresh(rule)
    assert (rule.source_zone, rule.destination_zone) == ("Z020", "Z010")
    assert [c.name for c in rule.components] == ["FW-BER"]


def test_a_change_the_matrix_forbids_is_refused(db):
    """One rule out of policy refuses the object change and names the rule;
    nothing is changed, not even the rules the change would have been fine for."""
    db.add(ZonePolicy(from_zone_id=2, to_zone_id=1, policy=ZonePolicyType.block_all))
    db.commit()
    blocked = make_rule(db, "SR00001")
    fine = make_rule(db, "SR00002", src="10.0.1.6")  # untouched: a different IP under the alias
    fine.source = [{"ip": "10.0.9.9", "alias": "other"}]
    db.commit()
    with pytest.raises(HTTPException) as exc:
        change(db, "10.0.2.9")
    assert exc.value.status_code == 422
    assert "SR00001" in exc.value.detail
    db.rollback()
    db.refresh(blocked)
    assert blocked.source[0]["ip"] == "10.0.1.5"
    assert blocked.status == RuleStatus.approved


def test_a_zone_transition_without_a_firewall_is_refused(db):
    """An intra-zone rule in TEST, enforced by the fabric. Its source moves to
    LAB, which only the fabric reaches too - and ACI alone is no zone transition (BSI)."""
    make_rule(db, src="10.0.3.5", dst="10.0.3.7", zone="Z030", component=2)
    with pytest.raises(HTTPException) as exc:
        change(db, "10.0.4.9", old_ip="10.0.3.5")
    assert exc.value.status_code == 422
    assert "firewall" in exc.value.detail


def test_an_address_in_no_zone_is_refused(db):
    make_rule(db)
    with pytest.raises(HTTPException) as exc:
        change(db, "192.168.9.9")
    assert exc.value.status_code == 422
    assert "192.168.9.9" in exc.value.detail
