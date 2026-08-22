"""Tests für Einstellungen und das Minimalprinzip (default-deny) der Zonen-Matrix."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Zone, ZonePolicy, ZonePolicyType
from app.settings import all_settings, get_setting, set_setting
from app.zone_check import check_zone_pair


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    a = Zone(name="MGMT", sort_order=1)
    b = Zone(name="PROD", sort_order=2)
    c = Zone(name="TEST", sort_order=3)
    session.add_all([a, b, c])
    session.flush()
    session.add(ZonePolicy(from_zone_id=a.id, to_zone_id=b.id, policy=ZonePolicyType.allow_only))
    session.commit()
    yield session
    session.close()


def test_setting_default_and_update(db):
    assert get_setting(db, "zone_matrix_default") == "permit"  # Bestandsverhalten
    set_setting(db, "zone_matrix_default", "deny")
    assert get_setting(db, "zone_matrix_default") == "deny"
    assert all_settings(db)["zone_matrix_default"] == "deny"
    with pytest.raises(ValueError):
        set_setting(db, "zone_matrix_default", "quatsch")
    with pytest.raises(ValueError):
        set_setting(db, "unbekannt", "x")


def test_permit_keeps_legacy_behaviour(db):
    result = check_zone_pair(db, "MGMT", "TEST", [])  # ungepflegtes Paar
    assert result.allowed and result.policy == "undefined"


def test_default_deny_blocks_unmaintained_pairs(db):
    set_setting(db, "zone_matrix_default", "deny")
    result = check_zone_pair(db, "MGMT", "TEST", [])
    assert not result.allowed and result.policy == "undefined"
    assert any("default-deny" in m for m in result.messages)


def test_default_deny_keeps_explicit_and_intra(db):
    set_setting(db, "zone_matrix_default", "deny")
    assert check_zone_pair(db, "MGMT", "PROD", []).allowed          # explizit Allow
    assert check_zone_pair(db, "PROD", "PROD", []).allowed          # intra
    assert not check_zone_pair(db, "PROD", "MGMT", []).allowed      # Gegenrichtung ungepflegt


def test_default_deny_blocks_unknown_zone(db):
    set_setting(db, "zone_matrix_default", "deny")
    result = check_zone_pair(db, "UNBEKANNT", "PROD", [])
    assert not result.allowed


def test_zone_schutzbedarf_maximum(db):
    zone = db.query(Zone).filter(Zone.name == "MGMT").one()
    assert zone.schutzbedarf == "normal"
    zone.cia_i = "hoch"
    assert zone.schutzbedarf == "hoch"
    zone.cia_a = "sehr hoch"
    assert zone.schutzbedarf == "sehr hoch"
