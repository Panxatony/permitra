"""A component says how it enforces: as a firewall at a zone transition, or
as micro-segmentation within a zone.

Every check that separated the two keyed on the component type being ACI,
so a micro-segmentation platform Permitra has no exporter for (NSX, Illumio,
a host-firewall fleet) could not be documented as the enforcing instance at
all - and had it been added as a type, the BSI check would have treated it
as a firewall. The enforcement model is the component's own attribute now,
derived from the type where nothing says otherwise, and the checks ask it.
"""
import csv
import io
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.component_resolution import resolve_rule_components
from app.database import Base, get_db
from app.exporters.generic import export_csv, rule_to_dict
from app.main import app
from app.models import (
    AddressComponentMap,
    ComponentType,
    Enforcement,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
    default_enforcement,
)
from app.routers.rules_router import enforce_bsi_firewall

# ---------- the attribute ----------

def test_the_enforcement_follows_the_type_unless_given():
    assert SecurityComponent(name="fw", type=ComponentType.juniper).enforcement == Enforcement.firewall
    assert SecurityComponent(name="cp", type="checkpoint").enforcement == Enforcement.firewall
    assert SecurityComponent(name="aci", type=ComponentType.aci).enforcement == Enforcement.microsegmentation
    assert SecurityComponent(name="nsx", type=ComponentType.microsegmentation).enforcement == Enforcement.microsegmentation
    explicit = SecurityComponent(name="odd", type=ComponentType.aci, enforcement=Enforcement.firewall)
    assert explicit.enforcement == Enforcement.firewall and explicit.is_firewall
    assert default_enforcement("microsegmentation") == Enforcement.microsegmentation


# ---------- the checks ask the attribute, not the vendor ----------

def test_a_zone_transition_on_micro_segmentation_alone_is_refused_whatever_the_platform():
    nsx = SecurityComponent(name="NSX", type=ComponentType.microsegmentation, platform="NSX")
    aci = SecurityComponent(name="ACI", type=ComponentType.aci)
    fw = SecurityComponent(name="FW", type=ComponentType.juniper)
    with pytest.raises(HTTPException) as exc:
        enforce_bsi_firewall("Z010", "Z020", [nsx])
    assert exc.value.status_code == 422
    with pytest.raises(HTTPException):
        enforce_bsi_firewall("Z010", "Z020", [nsx, aci])
    enforce_bsi_firewall("Z010", "Z020", [nsx, fw])      # a firewall is on the path
    enforce_bsi_firewall("Z010", "Z010", [nsx])          # intra-zone: micro-segmentation's job


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    s.add(SecurityComponent(id=2, name="Illumio", type=ComponentType.microsegmentation, platform="Illumio"))
    s.add(AddressComponentMap(vrf_id=1, ip="10.0.1.0/24", component_ids=[1, 2]))
    s.add(AddressComponentMap(vrf_id=1, ip="10.0.2.0/24", component_ids=[1, 2]))
    s.commit()
    yield s
    s.close()


def test_resolution_keeps_micro_segmentation_inside_a_zone_and_firewalls_across(db):
    src, dst = [{"ip": "10.0.1.5"}], [{"ip": "10.0.2.5"}]
    inside, _ = resolve_rule_components(db, src, dst, "Z010", "Z010", 1)
    assert [c.name for c in inside] == ["Illumio"]
    across, _ = resolve_rule_components(db, src, dst, "Z010", "Z020", 1)
    assert [c.name for c in across] == ["FW"]


# ---------- it is visible where the question is asked ----------

def test_the_export_and_the_api_say_how_a_rule_is_enforced(db):
    rule = Rule(rule_id="SR00001", vrf_id=1, name="r", status=RuleStatus.approved,
                components=[db.get(SecurityComponent, 1), db.get(SecurityComponent, 2)],
                source=[{"ip": "10.0.1.5", "alias": ""}], destination=[{"ip": "10.0.2.5", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
                source_zone="Z010", destination_zone="Z020")
    db.add(rule)
    db.commit()
    assert rule_to_dict(rule)["enforcement"] == ["firewall", "microsegmentation"]
    assert "microsegmentation" in rule_to_dict(rule)["platforms"]
    rows = list(csv.reader(io.StringIO(export_csv([rule])), delimiter=";"))
    assert rows[0][4] == "Enforcement"
    assert rows[1][4] == "firewall/microsegmentation"


def test_the_component_api_derives_and_accepts_the_generic_type():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    s.add(User(username="arch", full_name="arch", role=Role.architect, is_active=True,
               password_hash=hash_password("arch-pw-12345")))
    s.commit()
    s.close()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    try:
        c = TestClient(app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", data={"username": "arch", "password": "arch-pw-12345"})
        headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
        nsx = c.post("/api/components", headers=headers,
                     json={"name": "NSX-DC1", "type": "microsegmentation", "platform": "NSX"})
        assert nsx.status_code == 201, nsx.text
        assert nsx.json()["enforcement"] == "microsegmentation"
        assert nsx.json()["platform"] == "NSX"
        fw = c.post("/api/components", headers=headers, json={"name": "FW-1", "type": "checkpoint"})
        assert fw.json()["enforcement"] == "firewall"
        listed = {x["name"]: x["enforcement"] for x in c.get("/api/components", headers=headers).json()}
        assert listed == {"NSX-DC1": "microsegmentation", "FW-1": "firewall"}
    finally:
        app.dependency_overrides.clear()
