"""Tests für die automatische Ermittlung der Umsetzungs-Komponenten aus Quelle/Ziel."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.component_resolution import normalize_ip, resolve_rule_components
from app.database import Base
from app.models import AddressComponentMap, ComponentType, SecurityComponent, Vrf


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Vrf(id=1, name="IT"))
    session.flush()
    fw_ffm = SecurityComponent(id=1, name="FW-Cluster-FFM", type=ComponentType.checkpoint)
    fw_ber = SecurityComponent(id=2, name="FW-Cluster-BER", type=ComponentType.juniper)
    aci = SecurityComponent(id=3, name="ACI-Fabric-FFM", type=ComponentType.aci)
    session.add_all([fw_ffm, fw_ber, aci])
    session.add_all([
        AddressComponentMap(vrf_id=1, ip="10.10.30.0/24", alias="NET-PROD-APP", component_ids=[1, 3]),
        AddressComponentMap(vrf_id=1, ip="10.10.20.0/24", alias="NET-VPN", component_ids=[2, 3]),
        AddressComponentMap(vrf_id=1, ip="10.10.20.5/32", alias="vpn-gw", component_ids=[2]),
        AddressComponentMap(vrf_id=1, ip="any", alias="Internet", component_ids=[1]),
    ])
    session.commit()
    yield session
    session.close()


def test_normalize_ip():
    assert normalize_ip("10.10.30.5") == "10.10.30.5/32"
    assert normalize_ip("10.10.30.0/24") == "10.10.30.0/24"
    assert normalize_ip("ANY") == "any"
    assert normalize_ip("keine-ip") is None


def test_containment_resolution(db):
    # Host-IP im gepflegten Netz -> Komponenten des Netzes, Inter-Zone -> nur Firewalls
    components, unknown = resolve_rule_components(
        db,
        [{"ip": "10.10.20.77", "alias": ""}],
        [{"ip": "10.10.30.5", "alias": ""}],
        "VPN", "PROD-APP",
    )
    assert not unknown
    assert [c.name for c in components] == ["FW-Cluster-BER", "FW-Cluster-FFM"]


def test_most_specific_mapping_wins(db):
    # 10.10.20.5 hat eine eigene /32-Zuordnung (nur BER, ohne ACI)
    components, unknown = resolve_rule_components(
        db, [{"ip": "10.10.20.5", "alias": ""}], [{"ip": "10.10.30.0/24", "alias": ""}],
        "VPN", "PROD-APP",
    )
    assert not unknown
    assert "FW-Cluster-BER" in [c.name for c in components]


def test_intra_zone_prefers_aci(db):
    components, unknown = resolve_rule_components(
        db,
        [{"ip": "10.10.30.5", "alias": ""}],
        [{"ip": "10.10.30.9", "alias": ""}],
        "PROD-APP", "PROD-APP",
    )
    assert not unknown
    assert [c.name for c in components] == ["ACI-Fabric-FFM"]


def test_any_mapping(db):
    components, unknown = resolve_rule_components(
        db, [{"ip": "any", "alias": "Internet"}], [{"ip": "10.10.30.5", "alias": ""}],
        "INET", "PROD-APP",
    )
    assert not unknown
    assert "FW-Cluster-FFM" in [c.name for c in components]


def test_unknown_address_reported_once(db):
    components, unknown = resolve_rule_components(
        db,
        [{"ip": "192.168.99.1", "alias": "neu01"}, {"ip": "192.168.99.1", "alias": ""}],
        [{"ip": "10.10.30.5", "alias": ""}],
        "NEU", "PROD-APP",
    )
    assert len(unknown) == 1
    assert unknown[0]["ip"] == "192.168.99.1"
    # Bekannte Seite wird trotzdem aufgelöst
    assert components
