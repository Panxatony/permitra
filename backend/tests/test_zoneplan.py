"""Tests for the Mermaid zone plan (issue #15)."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    ComponentType,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    Vrf,
    Zone,
)
from app.zoneplan import build_mermaid


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Vrf(id=1, name="IT"))
    fw = SecurityComponent(name="FW-Cluster-BER", type=ComponentType.juniper)
    aci = SecurityComponent(name="ACI-Fabric-FFM", type=ComponentType.aci)
    session.add_all([fw, aci])
    session.flush()
    inet = Zone(name="INET", pap_level="external", sort_order=0)
    prod = Zone(name="PROD-APP", pap_level="internal", sort_order=1,
                owner="Team Applikationen", cia_c="high", cia_i="high", cia_a="very high")
    prod.components = [fw]
    session.add_all([inet, prod])
    session.add(Rule(
        rule_id="SR00001", vrf_id=1, name="Intra", components=[aci],
        source=[{"ip": "10.10.30.5", "alias": ""}], destination=[{"ip": "10.10.30.9", "alias": ""}],
        services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
        status=RuleStatus.approved, source_zone="PROD-APP", destination_zone="PROD-APP",
    ))
    session.commit()
    yield session
    session.close()


def test_mermaid_plan(db):
    plan = build_mermaid(db, generated_at="2026-08-23 12:00 UTC")
    assert plan.startswith("%% Permitra zone plan")
    assert "NET.1.1" in plan and "NET.3.2" in plan
    assert "Generated: 2026-08-23 12:00 UTC" in plan
    assert "flowchart TB" in plan
    # Bands, zones with protection level/owner, firewall as a hexagon
    assert 'subgraph BAND_external' in plan and 'subgraph BAND_internal' in plan
    assert "Protection level: very high" in plan and "Owner: Team Applikationen" in plan
    assert 'FW_FW_Cluster_BER{{"FW-Cluster-BER<br/><i>Juniper SRX</i>"}}' in plan
    # Intra-zone ACI segmentation on the zone node
    assert "ACI intra-zone: ACI-Fabric-FFM" in plan
    # Edge zone -- firewall and colour classes
    assert "Z_PROD_APP --- FW_FW_Cluster_BER" in plan
    assert "class Z_PROD_APP sbVeryhigh;" in plan
    assert "class Z_INET sbNormal;" in plan
