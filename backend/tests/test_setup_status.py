"""The first-run checklist: what a fresh instance says is missing (#67).

Deploying Permitra ends at a login form; what a working instance needs next was
scattered and unspoken, and a new operator hit "network not assigned to any
zone" before the mental model arrived. The checklist names the essentials in
dependency order and disappears when they exist.

The properties pinned here: done is judged by what exists rather than what was
clicked, the language counts only as a deliberate choice, and fewer than two
active change approvers is warned about permanently - the matrix workflow
silently cannot complete without them, and approvers leave after setup too.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    ComponentType,
    Role,
    SecurityComponent,
    User,
    Vrf,
    Zone,
    ZoneNetwork,
    ZonePolicy,
)
from app.routers.setup_router import setup_status
from app.settings import set_setting


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(User(username="admin", password_hash="x", role=Role.admin, is_active=True))
    s.commit()
    yield s
    s.close()


def status(db):
    return setup_status(db, db.query(User).first())


def step(db, sid):
    return next(s for s in status(db)["steps"] if s["id"] == sid)


def approver_warnings(db):
    """Only the approver warning - the base-URL warning depends on the test
    process's environment and is asserted in its own test, not incidentally."""
    return [w for w in status(db)["warnings"] if w["code"] == "too-few-approvers"]


def test_a_fresh_instance_has_everything_open(db):
    result = status(db)
    assert result["complete"] is False
    assert all(not s["done"] for s in result["steps"])


def test_the_default_language_does_not_count_as_a_choice(db):
    """The default works - but a default nobody chose is how an instance shows
    German screenshots to an English team for a year. Done means decided."""
    assert step(db, "language")["done"] is False
    set_setting(db, "ui_language", "en")
    assert step(db, "language")["done"] is True


def test_done_is_judged_by_what_exists_not_what_was_clicked(db):
    """An instance configured entirely through the API shows a finished
    checklist it has never looked at."""
    db.add(Zone(id=1, code="Z010", name="DMZ", sort_order=10))
    db.commit()
    assert step(db, "zones")["done"] is True
    db.add(ZoneNetwork(cidr="10.0.0.0/24", zone_id=1, vrf_id=1))
    db.add(SecurityComponent(name="FW-A", type=ComponentType.juniper))
    db.commit()
    assert step(db, "networks")["done"] is True
    assert step(db, "components")["done"] is True


def test_the_matrix_step_accepts_either_deliberate_act(db):
    """Maintained relations or the explicit default-deny decision - both are
    the decision the step asks for. An untouched legacy default is neither."""
    assert step(db, "matrix")["done"] is False
    set_setting(db, "zone_matrix_default", "deny")
    assert step(db, "matrix")["done"] is True


def test_the_matrix_step_also_accepts_maintained_relations(db):
    db.add(Zone(id=1, code="Z010", name="DMZ", sort_order=10))
    db.add(Zone(id=2, code="Z020", name="PROD", sort_order=20))
    db.commit()
    db.add(ZonePolicy(from_zone_id=1, to_zone_id=2, policy="allow_only"))
    db.commit()
    assert step(db, "matrix")["done"] is True


def test_accounts_need_two_approvers_not_one(db):
    """The four-eyes principle on matrix requests needs two DIFFERENT approvers.
    With one, the workflow silently never completes - today you find that out
    when the second approval never comes."""
    db.add(User(username="arch", password_hash="x", role=Role.architect, is_active=True))
    db.add(User(username="ops", password_hash="x", role=Role.operations, is_active=True))
    db.add(User(username="ap1", password_hash="x", role=Role.change_approver, is_active=True))
    db.commit()
    assert step(db, "accounts")["done"] is False
    assert approver_warnings(db) == [{"code": "too-few-approvers", "count": 1}]

    db.add(User(username="ap2", password_hash="x", role=Role.change_approver, is_active=True))
    db.commit()
    assert step(db, "accounts")["done"] is True
    assert approver_warnings(db) == []


def test_a_deactivated_approver_does_not_count(db):
    """Deactivated is gone, as far as the workflow is concerned - the warning
    has to fire when the second approver leaves, not only on a fresh instance."""
    for name in ("ap1", "ap2"):
        db.add(User(username=name, password_hash="x",
                    role=Role.change_approver, is_active=True))
    db.commit()
    assert status(db)["approvers_active"] == 2

    db.query(User).filter(User.username == "ap2").first().is_active = False
    db.commit()
    assert approver_warnings(db) == [{"code": "too-few-approvers", "count": 1}]


def test_the_steps_come_in_handover_order(db):
    """Two phases, because two different people act: the admin prepares the
    instance (language, accounts) and hands over - everything from the zones on
    is the architects' work. Accounts before the domain steps, or the admin
    working top to bottom reaches "create accounts" after the steps that needed
    those accounts to exist."""
    steps = status(db)["steps"]
    assert [s["id"] for s in steps] == ["language", "accounts", "zones", "networks",
                                        "components", "matrix", "first_rule"]
    assert [s["phase"] for s in steps] == ["admin"] * 2 + ["architect"] * 5


def test_an_unset_base_url_is_a_standing_warning(db, monkeypatch):
    """Activation and reset links fall back to localhost while it is unset -
    discovered only when a colleague cannot open the link they were sent. And
    deliberately never derived from the request Host header: a reset link built
    from an attacker-controlled Host is an account-takeover vector."""
    monkeypatch.delenv("PERMITRA_BASE_URL", raising=False)
    assert any(w["code"] == "base-url-not-set" for w in status(db)["warnings"])

    monkeypatch.setenv("PERMITRA_BASE_URL", "https://permitra.example.org")
    assert not any(w["code"] == "base-url-not-set" for w in status(db)["warnings"])
