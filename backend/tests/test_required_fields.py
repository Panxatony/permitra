"""Tests for configurable required fields (issue #8)."""
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.routers.rules_router import enforce_required_fields
from app.settings import set_setting


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


class Payload:
    def __init__(self, justification="", requestor="", valid_until=""):
        self.justification = justification
        self.requestor = requestor
        self.valid_until = valid_until


def test_defaults_enforce(db):
    # Required fields are active by default
    with pytest.raises(HTTPException) as exc:
        enforce_required_fields(db, Payload())
    assert "Justification" in exc.value.detail
    # The admin can switch them off
    for key in ("require_justification", "require_valid_until"):
        set_setting(db, key, "no")
    enforce_required_fields(db, Payload())


def test_enforced_fields_rejected_when_missing(db):
    with pytest.raises(HTTPException) as exc:
        enforce_required_fields(db, Payload())
    assert exc.value.status_code == 422
    assert "Justification" in exc.value.detail and "Valid until" in exc.value.detail
    # Complete -> ok
    enforce_required_fields(db, Payload(justification="HTTPS", valid_until="2027-01-01"))


def test_the_requestor_needs_no_setting_because_it_cannot_be_missing(db):
    """The requestor is the signed-in account that creates the rule - derived,
    never entered. A mandatory-field toggle for a field the user cannot leave
    empty is a knob that does nothing, so it is gone."""
    from app.settings import KNOWN_SETTINGS

    assert "require_requestor" not in KNOWN_SETTINGS




# ---------- requestor and owner are recorded, not entered ----------

def _full_db():
    import os
    os.environ.setdefault("PERMITRA_DEV", "1")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.database import Base
    from app.models import (
        AddressComponentMap,
        ComponentType,
        Role,
        SecurityComponent,
        User,
        Vrf,
        Zone,
        ZoneNetwork,
        ZonePolicy,
    )
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-BER", type=ComponentType.juniper))
    s.add(Zone(id=1, code="Z010", name="DMZ", sort_order=10))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20))
    s.add(User(username="alex", password_hash="x", role=Role.architect, is_active=True))
    s.add(User(username="ben", password_hash="x", role=Role.operations, is_active=True))
    s.commit()
    s.add(ZoneNetwork(cidr="10.0.0.0/24", zone_id=1, vrf_id=1))
    s.add(ZoneNetwork(cidr="10.0.1.0/24", zone_id=2, vrf_id=1))
    s.add(AddressComponentMap(ip="10.0.0.0/24", vrf_id=1, component_ids=[1]))
    s.add(AddressComponentMap(ip="10.0.1.0/24", vrf_id=1, component_ids=[1]))
    s.add(ZonePolicy(from_zone_id=1, to_zone_id=2, policy="allow_only"))
    s.commit()
    return s


def _payload(**over):
    from app.schemas import RuleCreate
    data = {
        "name": "web", "source": [{"ip": "10.0.0.5", "alias": ""}],
        "destination": [{"ip": "10.0.1.9", "alias": ""}],
        "services": [{"protocol": "TCP", "port": "443"}],
        "justification": "HTTPS", "valid_until": "2027-01-01",
    }
    data.update(over)
    return RuleCreate(**data)


def test_the_requestor_is_the_account_that_created_the_rule():
    from app.models import User
    from app.routers.rules_router import create_rule

    db = _full_db()
    alex = db.query(User).filter(User.username == "alex").one()
    rule = create_rule(_payload(), db, alex)
    assert rule.requestor == "alex"


def test_a_typed_requestor_is_ignored_not_trusted():
    """Whatever a client sends for the field is discarded: the record says who
    acted, and an API caller must not be able to write somebody else's name in."""
    from app.models import User
    from app.routers.rules_router import create_rule

    db = _full_db()
    alex = db.query(User).filter(User.username == "alex").one()
    rule = create_rule(_payload(requestor="Somebody Else", owner="Somebody Else"), db, alex)
    assert rule.requestor == "alex"
    assert rule.owner == ""


def test_the_owner_is_whoever_last_worked_the_components():
    from app.models import User
    from app.routers.rules_router import create_rule, set_impl_status

    db = _full_db()
    alex = db.query(User).filter(User.username == "alex").one()
    ben = db.query(User).filter(User.username == "ben").one()
    rule = create_rule(_payload(), db, alex)
    assert rule.owner == ""   # nobody has touched the components yet

    from app.models import RuleStatus
    rule.status = RuleStatus.approved
    db.commit()
    set_impl_status(rule.rule_id, {"FW-BER": "implemented"}, db, ben)
    db.refresh(rule)
    assert rule.owner == "ben"


def test_an_edit_does_not_change_who_created_or_who_worked():
    """update_rule replaces content; requestor and owner are records of acts,
    and editing content is neither of those acts."""
    from app.models import RuleStatus, User
    from app.routers.rules_router import create_rule, set_impl_status, update_rule
    from app.schemas import RuleUpdate

    db = _full_db()
    alex = db.query(User).filter(User.username == "alex").one()
    ben = db.query(User).filter(User.username == "ben").one()
    rule = create_rule(_payload(), db, alex)
    rule.status = RuleStatus.approved
    db.commit()
    set_impl_status(rule.rule_id, {"FW-BER": "implemented"}, db, ben)

    payload = _payload(name="web-renamed")
    update_rule(rule.rule_id, RuleUpdate(**payload.model_dump()), db, alex)
    db.refresh(rule)
    assert rule.requestor == "alex"
    assert rule.owner == "ben"
