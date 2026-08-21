"""Tests für den EPG-basierten, aggregierenden ACI-Contract-Export."""
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.exporters import aci
from app.models import (
    AciGateway,
    Vrf,
    AddressEpgMap,
    ComponentType,
    Epg,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    ServiceObject,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Vrf(id=1, name="IT"))
    session.flush()
    app_epg = Epg(name="epg-prod-app", tenant="DEMO", app_profile="AP-DEMO", bridge_domain="BD-PROD-APP")
    db_epg = Epg(name="epg-prod-db", tenant="DEMO", app_profile="AP-DEMO", bridge_domain="BD-PROD-DB")
    session.add_all([app_epg, db_epg])
    session.flush()
    session.add_all([
        AddressEpgMap(vrf_id=1, ip="10.10.30.0/24", epg_id=app_epg.id),
        AddressEpgMap(vrf_id=1, ip="10.10.31.0/24", epg_id=db_epg.id),
        ServiceObject(name="Postgres", protocol="TCP", port="5432"),
    ])
    checkpoint = SecurityComponent(name="FW-FFM", type=ComponentType.checkpoint)
    session.add(checkpoint)
    session.flush()
    session.add(
        AciGateway(name="GW-PROD-DB", bridge_domain="BD-PROD-DB", gateway_ip="10.10.31.1/24",
                   pbr_enabled=True, pbr_component_id=checkpoint.id,
                   pbr_node_ip="10.10.35.10", pbr_service_graph="SG-CHKP")
    )
    session.commit()
    yield session
    session.close()


def make_rule(rid, src, dst, port="5432"):
    return Rule(
        rule_id=rid, vrf_id=1, name=rid,
        source=[{"ip": src, "alias": ""}], destination=[{"ip": dst, "alias": ""}],
        services=[{"protocol": "TCP", "port": port}], action=RuleAction.permit,
        status=RuleStatus.approved,
    )


def test_rules_aggregate_into_one_contract(db):
    rules = [
        make_rule("SR0001", "10.10.30.5", "10.10.31.7"),
        make_rule("SR0002", "10.10.30.9", "10.10.31.8"),         # gleiches EPG-Paar, gleicher Dienst
        make_rule("SR0003", "10.10.30.0/24", "10.10.31.7", "443"),  # gleiches Paar, anderer Dienst
    ]
    model = aci.build_contract_model(rules, db)
    assert len(model["contracts"]) == 1
    contract = model["contracts"][0]
    assert contract["name"] == "con-epg-prod-app-to-epg-prod-db"
    # Filter aus dem Objektkatalog wiederverwendet, generischer Name für 443
    assert set(contract["subjects"].keys()) == {"flt-postgres", "flt-tcp-443"}
    assert contract["subjects"]["flt-postgres"] == {"SR0001", "SR0002"}
    # PBR: Provider-BD hat Service Graph
    assert contract["service_graph"] == "SG-CHKP"
    assert not model["legacy"]


def test_vzany_and_unknown(db):
    rules = [
        make_rule("SR0010", "any", "10.10.31.7"),          # Consumer vzAny
        make_rule("SR0011", "192.168.1.1", "10.10.31.7"),  # keine EPG-Zuordnung -> legacy
    ]
    model = aci.build_contract_model(rules, db)
    assert any(c["consumer"] == "vzAny" for c in model["contracts"])
    assert [r.rule_id for r in model["legacy"]] == ["SR0011"]
    assert model["warnings"]


def test_json_structure(db):
    out = json.loads(aci.export_json([make_rule("SR0001", "10.10.30.5", "10.10.31.7")], db))
    tenant = out["fvTenant"]
    assert tenant["attributes"]["name"] == "DEMO"
    kinds = [list(c.keys())[0] for c in tenant["children"]]
    assert "vzFilter" in kinds and "vzBrCP" in kinds and "fvAp" in kinds
    # EPG-Bindings: Provider/Consumer-Referenzen vorhanden
    ap = next(c["fvAp"] for c in tenant["children"] if "fvAp" in c)
    epg_names = [e["fvAEPg"]["attributes"]["name"] for e in ap["children"]]
    assert "epg-prod-app" in epg_names and "epg-prod-db" in epg_names
    # SR-IDs in Subject-Beschreibung (Drift-Rückverfolgbarkeit)
    assert "SR0001" in json.dumps(out)
