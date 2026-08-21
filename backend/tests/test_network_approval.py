"""Tests für den Freigabe-Workflow von Netzwerk-Zuordnungen (Netz → Zone).

Wie Matrix-/Zonen-Änderungen brauchen auch Änderungen an der Netzwerk-Zuordnung
zwei Freigaben durch verschiedene Change Approver, bevor sie angewendet werden.
"""
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Role, User, Vrf, Zone, ZoneNetwork, ZonePolicyChange
from app.routers.zones_router import _create_batch, _decide_change


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Vrf(id=1, name="IT"))
    session.add_all([Zone(name="PROD-APP", sort_order=1), Zone(name="DMZ-WEB", sort_order=2)])
    session.flush()
    session.add(ZoneNetwork(cidr="10.10.30.0/24", zone_id=1, vrf_id=1, description="App-Netz"))
    session.commit()
    yield session
    session.close()


def user(name, role=Role.architect):
    return User(username=name, password_hash="x", role=role)


ARCHITECT = lambda: user("alex")
APPROVER1 = lambda: user("chris", Role.change_approver)
APPROVER2 = lambda: user("kim", Role.change_approver)


def pending_change(db):
    return db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()


def test_net_add_needs_two_approvals(db):
    result = _create_batch(db, ARCHITECT(), [
        {"type": "net_add", "zone": "DMZ-WEB", "cidr": "10.10.99.0/24", "description": "Neu"},
    ], "")
    assert result["status"] == "pending"
    # Noch nicht angewendet
    assert not db.query(ZoneNetwork).filter(ZoneNetwork.cidr == "10.10.99.0/24").first()

    change = pending_change(db)
    first = _decide_change(db, change.id, APPROVER1(), True, "")
    assert first["approvals"] == "1/2"
    assert not db.query(ZoneNetwork).filter(ZoneNetwork.cidr == "10.10.99.0/24").first()

    # Zweite Freigabe durch denselben Approver ist verboten
    with pytest.raises(HTTPException) as exc:
        _decide_change(db, change.id, APPROVER1(), True, "")
    assert exc.value.status_code == 403

    _decide_change(db, change.id, APPROVER2(), True, "")
    created = db.query(ZoneNetwork).filter(ZoneNetwork.cidr == "10.10.99.0/24").one()
    assert created.zone.name == "DMZ-WEB" and created.description == "Neu"


def test_net_update_reassigns_zone_after_approval(db):
    network = db.query(ZoneNetwork).one()
    _create_batch(db, ARCHITECT(), [
        {"type": "net_update", "network_id": network.id, "zone": "DMZ-WEB"},
    ], "Umzug")
    assert network.zone.name == "PROD-APP"  # bis zur Freigabe unverändert

    change = pending_change(db)
    assert change.extra["old_zone"] == "PROD-APP"
    _decide_change(db, change.id, APPROVER1(), True, "")
    _decide_change(db, change.id, APPROVER2(), True, "")
    db.refresh(network)
    assert network.zone.name == "DMZ-WEB"


def test_net_delete_and_rejection(db):
    network = db.query(ZoneNetwork).one()
    _create_batch(db, ARCHITECT(), [{"type": "net_delete", "network_id": network.id}], "")
    change = pending_change(db)
    _decide_change(db, change.id, APPROVER1(), False, "abgelehnt")
    assert db.query(ZoneNetwork).count() == 1  # Ablehnung: nichts passiert

    _create_batch(db, ARCHITECT(), [{"type": "net_delete", "network_id": network.id}], "")
    change = pending_change(db)
    _decide_change(db, change.id, APPROVER1(), True, "")
    _decide_change(db, change.id, APPROVER2(), True, "")
    assert db.query(ZoneNetwork).count() == 0


def test_pending_conflict_blocks_second_request(db):
    network = db.query(ZoneNetwork).one()
    _create_batch(db, ARCHITECT(), [
        {"type": "net_update", "network_id": network.id, "zone": "DMZ-WEB"},
    ], "")
    with pytest.raises(HTTPException) as exc:
        _create_batch(db, ARCHITECT(), [{"type": "net_delete", "network_id": network.id}], "")
    assert exc.value.status_code == 409


def test_requester_cannot_approve_own_request(db):
    requester = user("sam", Role.change_approver)
    _create_batch(db, requester, [
        {"type": "net_add", "zone": "DMZ-WEB", "cidr": "10.10.98.0/24"},
    ], "")
    change = pending_change(db)
    with pytest.raises(HTTPException) as exc:
        _decide_change(db, change.id, requester, True, "")
    assert exc.value.status_code == 403


def test_noop_update_rejected(db):
    network = db.query(ZoneNetwork).one()
    with pytest.raises(HTTPException) as exc:
        _create_batch(db, ARCHITECT(), [
            {"type": "net_update", "network_id": network.id, "zone": "PROD-APP"},
        ], "")
    assert exc.value.status_code == 400  # keine Änderung gegenüber dem aktuellen Stand
