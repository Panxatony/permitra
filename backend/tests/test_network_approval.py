"""Tests for the approval workflow of network assignments (network -> zone).

Like matrix/zone changes, changes to the network assignment also need two
approvals by different change approvers before they are applied.
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


def ARCHITECT():
    return user("alex")


def APPROVER1():
    return user("chris", Role.change_approver)


def APPROVER2():
    return user("kim", Role.change_approver)


def pending_change(db):
    return db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()


def test_net_add_needs_two_approvals(db):
    result = _create_batch(db, ARCHITECT(), [
        {"type": "net_add", "zone": "DMZ-WEB", "cidr": "10.10.99.0/24", "description": "Neu"},
    ], "")
    assert result["status"] == "pending"
    # Not applied yet
    assert not db.query(ZoneNetwork).filter(ZoneNetwork.cidr == "10.10.99.0/24").first()

    change = pending_change(db)
    first = _decide_change(db, change.id, APPROVER1(), True, "")
    assert first["approvals"] == "1/2"
    assert not db.query(ZoneNetwork).filter(ZoneNetwork.cidr == "10.10.99.0/24").first()

    # A second approval by the same approver is forbidden
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
    assert network.zone.name == "PROD-APP"  # unchanged until the approval

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
    assert db.query(ZoneNetwork).count() == 1  # rejection: nothing happens

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
    assert exc.value.status_code == 400  # no change compared to the current state


# ---------- a new zone arrives complete (#: zone request carries everything) ----------

def test_a_requested_zone_is_created_with_its_owner_and_attachment(db):
    """Everything a zone has belongs in the request, not in a follow-up edit.
    A zone created without its owner and firewall attachment needs a second
    change nobody reviewed - and an unattached zone is invisible to the drift
    comparison until somebody notices."""
    from app.models import ComponentType, SecurityComponent, Zone
    db.add(SecurityComponent(id=1, name="FW-A", type=ComponentType.juniper))
    db.add(SecurityComponent(id=2, name="FW-B", type=ComponentType.juniper))
    db.commit()

    _create_batch(db, ARCHITECT(), [{
        "type": "zone_create", "name": "T-NEW", "code": "Z900",
        "pap_level": "internal", "description": "Test zone",
        "owner": "Team Netzwerk", "component_ids": [1, 2],
        "cia_c": "high", "cia_i": "normal", "cia_a": "normal",
    }], "")
    change = pending_change(db)
    _decide_change(db, change.id, APPROVER1(), True, "")
    _decide_change(db, change.id, APPROVER2(), True, "")

    zone = db.query(Zone).filter(Zone.name == "T-NEW").one()
    assert zone.owner == "Team Netzwerk"
    assert zone.description == "Test zone"
    assert zone.protection_level == "high"
    assert sorted(c.name for c in zone.components) == ["FW-A", "FW-B"]


def test_a_zone_request_naming_an_unknown_component_is_refused(db):
    """Refused when it is requested, not silently dropped when it is applied -
    an approval has to be an approval of something real."""
    with pytest.raises(HTTPException) as exc:
        _create_batch(db, ARCHITECT(), [{
            "type": "zone_create", "name": "T-NEW", "code": "Z900",
            "pap_level": "internal", "component_ids": [999],
        }], "")
    assert exc.value.status_code == 422


def test_a_zone_can_still_be_requested_without_owner_or_attachment(db):
    """Both are optional: a zone whose owner is not yet decided must not be
    impossible to request."""
    from app.models import Zone
    _create_batch(db, ARCHITECT(), [{
        "type": "zone_create", "name": "T-BARE", "code": "Z901", "pap_level": "internal",
    }], "")
    change = pending_change(db)
    _decide_change(db, change.id, APPROVER1(), True, "")
    _decide_change(db, change.id, APPROVER2(), True, "")

    zone = db.query(Zone).filter(Zone.name == "T-BARE").one()
    assert zone.owner == ""
    assert zone.components == []


def test_a_new_zone_and_its_matrix_relations_go_in_one_request(db):
    """A new zone is useless until its relations are maintained, and needing a
    second request for them means the zone exists for a while with none. The
    batch applies the zones first and then the cells, so both belong in one.

    The cells reference the zone the way everything does - by `code or name`,
    and the interface sends the code - so a zone created in the same batch has
    to be recognised under both. Collecting only the name made exactly this
    fail with "Zone 'Z900' not found"."""
    from app.models import Zone, ZonePolicy
    _create_batch(db, ARCHITECT(), [
        {"type": "zone_create", "name": "T-NEW", "code": "Z900", "pap_level": "internal"},
        # referenced by code, as the matrix does
        {"type": "policy", "from_zone": "Z900", "to_zone": "PROD-APP", "policy": "allow_only"},
        {"type": "policy", "from_zone": "DMZ-WEB", "to_zone": "Z900", "policy": "block_all"},
    ], "")
    change = pending_change(db)
    _decide_change(db, change.id, APPROVER1(), True, "")
    _decide_change(db, change.id, APPROVER2(), True, "")

    zone = db.query(Zone).filter(Zone.name == "T-NEW").one()
    assert db.query(ZonePolicy).count() == 2
    policies = db.query(ZonePolicy).all()
    assert {p.from_zone_id for p in policies} | {p.to_zone_id for p in policies} >= {zone.id}


def test_a_matrix_cell_for_a_zone_nobody_creates_is_still_refused(db):
    """The exception is for zones this batch creates - not a way to request
    relations for a zone that does not and will not exist."""
    with pytest.raises(HTTPException) as exc:
        _create_batch(db, ARCHITECT(), [
            {"type": "policy", "from_zone": "Z999", "to_zone": "PROD-APP", "policy": "allow_only"},
        ], "")
    assert exc.value.status_code == 404
