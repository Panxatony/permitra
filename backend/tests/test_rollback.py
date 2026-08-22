"""Tests for rolling a rule back to an earlier version (issue #9)."""
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    AddressComponentMap,
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
    Zone,
    ZoneNetwork,
    ZonePolicy,
    ZonePolicyType,
)
from app.routers.rules_router import add_version, restore_version


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Vrf(id=1, name="IT"))
    mgmt = Zone(name="MGMT", sort_order=1)
    prod = Zone(name="PROD", sort_order=2)
    session.add_all([mgmt, prod])
    session.flush()
    session.add_all([
        ZoneNetwork(cidr="10.10.80.0/24", zone_id=mgmt.id, vrf_id=1),
        ZoneNetwork(cidr="10.10.30.0/24", zone_id=prod.id, vrf_id=1),
        ZonePolicy(from_zone_id=mgmt.id, to_zone_id=prod.id, policy=ZonePolicyType.allow_only),
    ])
    fw = SecurityComponent(id=1, name="FW-Test", type=ComponentType.juniper)
    session.add(fw)
    session.add_all([
        AddressComponentMap(vrf_id=1, ip="10.10.80.0/24", component_ids=[1]),
        AddressComponentMap(vrf_id=1, ip="10.10.30.0/24", component_ids=[1]),
    ])
    session.commit()
    yield session
    session.close()


def make_versioned_rule(db):
    """Rule with a v1 snapshot (port 443), then changed in content (v2, port 22)."""
    fw = db.query(SecurityComponent).one()
    rule = Rule(
        rule_id="SR00001", vrf_id=1, name="HTTPS", components=[fw],
        source=[{"ip": "10.10.80.5", "alias": "jump01"}],
        destination=[{"ip": "10.10.30.5", "alias": "app01"}],
        services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
        status=RuleStatus.approved, source_zone="MGMT", destination_zone="PROD",
        justification="HTTPS-Zugriff",
    )
    db.add(rule)
    db.flush()
    architect = User(username="alex", password_hash="x", role=Role.architect)
    add_version(db, rule, architect, "Regel angelegt")  # v1 snapshot with port 443
    rule.services = [{"protocol": "TCP", "port": "22"}]
    rule.name = "SSH"
    rule.version = 2
    add_version(db, rule, architect, "Auf SSH geändert")
    db.commit()
    return rule, architect


def test_restore_previous_version(db):
    _rule, architect = make_versioned_rule(db)
    restored = restore_version("SR00001", 1, db, architect)
    assert restored.name == "HTTPS"
    assert restored.services == [{"protocol": "TCP", "port": "443"}]
    assert restored.status == RuleStatus.draft          # rollback -> normal review
    assert restored.version == 3
    assert any("Rolled back to version 1" in v.change_note for v in restored.versions)
    assert [c.name for c in restored.components] == ["FW-Test"]


def test_restore_unknown_version(db):
    _rule, architect = make_versioned_rule(db)
    with pytest.raises(HTTPException) as exc:
        restore_version("SR00001", 99, db, architect)
    assert exc.value.status_code == 404


def test_restore_respects_current_matrix(db):
    """If the relation is set to block by now, the rollback is rejected."""
    _rule, architect = make_versioned_rule(db)
    policy = db.query(ZonePolicy).one()
    policy.policy = ZonePolicyType.block_all
    db.commit()
    with pytest.raises(HTTPException) as exc:
        restore_version("SR00001", 1, db, architect)
    assert exc.value.status_code == 422
    db.rollback()
    assert db.query(Rule).one().name == "SSH"  # unchanged
