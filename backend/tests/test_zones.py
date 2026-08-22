"""Tests for the zone matrix: cell parsing and rule checking."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Zone, ZonePolicy, ZonePolicyType
from app.zone_check import check_zone_pair
from import_zones import norm, parse_cell


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    a = Zone(name="D-PRD", sort_order=1)
    b = Zone(name="D-SHS", sort_order=2)
    c = Zone(name="Internet", sort_order=0)
    session.add_all([a, b, c])
    session.flush()
    session.add_all([
        ZonePolicy(from_zone_id=a.id, to_zone_id=b.id, policy=ZonePolicyType.allow_only),
        ZonePolicy(from_zone_id=c.id, to_zone_id=a.id, policy=ZonePolicyType.block_all),
    ])
    session.commit()
    yield session
    session.close()


def test_parse_cell():
    # The enforcement element in parentheses is ignored - only allow/block counts
    assert parse_cell("Allow Only (FW)") == (ZonePolicyType.allow_only, False)
    assert parse_cell("Allow Only (FW/ACI)") == (ZonePolicyType.allow_only, False)
    assert parse_cell("Allow Only (ACI)") == (ZonePolicyType.allow_only, False)
    assert parse_cell("Allow Only (FW) Temp") == (ZonePolicyType.allow_only, True)
    assert parse_cell("Block All (ACI)") == (ZonePolicyType.block_all, False)
    assert parse_cell("-") is None
    assert parse_cell("") is None


def test_norm():
    assert norm("T-VPN-S") == norm("T-VPNS")
    assert norm("o-shs") == norm("O-SHS")


def test_allow_with_firewall_platform(db):
    result = check_zone_pair(db, "D-PRD", "D-SHS", ["juniper"])
    assert result.allowed and result.policy == "allow_only" and not result.messages


def test_aci_cross_zone_hint(db):
    # ACI is intra-zone only - a cross-zone ACI rule produces a hint
    result = check_zone_pair(db, "d-prd", "d-shs", ["juniper", "aci"])
    assert result.allowed
    assert any("ACI" in m and "within a single zone" in m for m in result.messages)


def test_block_all(db):
    result = check_zone_pair(db, "Internet", "D-PRD", ["juniper"])
    assert not result.allowed
    assert result.policy == "block_all"


def test_reverse_direction_not_defined(db):
    result = check_zone_pair(db, "D-SHS", "D-PRD", ["aci"])
    assert result.allowed and result.policy == "undefined"


def test_intra_zone_allowed(db):
    result = check_zone_pair(db, "D-PRD", "d-prd", ["aci"])
    assert result.allowed and result.policy == "intra"


def test_unknown_zone_allowed_with_hint(db):
    result = check_zone_pair(db, "ITSG", "D-PRD", [])
    assert result.allowed and result.policy == "undefined"
    assert any("ITSG" in m for m in result.messages)


def test_ip_search_matching():
    from app.routers.rules_router import _match_address_field
    from app.validation import parse_network

    entries = [
        {"ip": "10.40.105.13", "alias": "pdw0400-dc0007.carbon.nublar.de"},
        {"ip": "2a0f:2687:1007:2::13", "alias": "pdw0400-dc0007.carbon.nublar.de"},
        {"ip": "10.0.1.0/24", "alias": "NET-TEST"},
        {"ip": "any", "alias": ""},
    ]

    # An exact IP hits the host entry directly, "any" only as a fallback
    matched, kind = _match_address_field(entries, "10.40.105.13", parse_network("10.40.105.13"))
    assert kind == "direct" and "10.40.105.13" in matched[0] and "any" in matched

    # Network overlap
    matched, kind = _match_address_field(entries, "10.0.1.128/25", parse_network("10.0.1.128/25"))
    assert kind == "direct" and any("10.0.1.0/24" in m for m in matched)

    # IP without overlap: only the any hit
    matched, kind = _match_address_field(entries, "192.168.5.5", parse_network("192.168.5.5"))
    assert kind == "any" and matched == ["any"]

    # Alias fragment (not a valid IP -> text search)
    matched, kind = _match_address_field(entries, "dc0007", None)
    assert kind == "direct" and len(matched) == 2

    # IPv6
    matched, kind = _match_address_field(
        entries, "2a0f:2687:1007:2::13", parse_network("2a0f:2687:1007:2::13")
    )
    assert kind == "direct"

    # No hit
    matched, kind = _match_address_field([{"ip": "10.99.0.0/16", "alias": ""}], "kein-treffer", None)
    assert kind is None and matched == []
