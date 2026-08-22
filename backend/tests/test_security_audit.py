"""Tests für die Sicherheits-Audit-Fixes (Issues #16-#22)."""
from datetime import timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import auth
from app.database import Base
from app.models import (
    ComponentType, Role, Rule, RuleAction, RuleStatus, SecurityComponent, User,
    Vrf, Zone, ZoneNetwork, ZonePolicy, ZonePolicyChange, ZonePolicyType, utcnow,
)
from app.routers.rules_router import set_impl_status
from app.routers.zones_router import _create_batch, _decide_change


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.commit()
    yield s
    s.close()


def make_user(s, name, role=Role.change_approver, active=True):
    u = User(username=name, password_hash=auth.hash_password("passwort123"),
             role=role, is_active=active)
    s.add(u); s.commit(); s.refresh(u)
    return u


# --- H1: is_active + Token-Invalidierung -----------------------------------

def test_inactive_user_rejected(db, monkeypatch):
    u = make_user(db, "alex", Role.architect, active=False)
    token = auth.create_token(u)
    monkeypatch.setattr(auth, "SECRET_KEY", auth.SECRET_KEY or "x")
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(token=token, db=db)
    assert exc.value.status_code == 401


def test_token_before_invalidation_rejected(db):
    u = make_user(db, "alex", Role.architect)
    old_token = auth.create_token(u)
    # Passwortwechsel/Deaktivierung setzt token_valid_from in die Zukunft
    u.token_valid_from = utcnow() + timedelta(seconds=5)
    db.commit()
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(token=old_token, db=db)
    assert exc.value.status_code == 401


def test_valid_token_after_invalidation_accepted(db):
    u = make_user(db, "alex", Role.architect)
    u.token_valid_from = utcnow() - timedelta(hours=1)
    db.commit()
    fresh = auth.create_token(u)
    assert auth.get_current_user(token=fresh, db=db).username == "alex"


# --- H2: Vier-Augen-Prinzip auch für Admins --------------------------------

def _zone_pair(db):
    a = Zone(name="MGMT", sort_order=1); b = Zone(name="PROD", sort_order=2)
    db.add_all([a, b]); db.flush()
    db.add(ZonePolicy(from_zone_id=a.id, to_zone_id=b.id, policy=ZonePolicyType.allow_only))
    db.commit()


def test_admin_cannot_self_approve_zone_change(db):
    _zone_pair(db)
    admin = make_user(db, "root", Role.admin)
    _create_batch(db, admin, [
        {"type": "policy", "from_zone": "MGMT", "to_zone": "PROD", "policy": "block_all"},
    ], "")
    change = db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()
    with pytest.raises(HTTPException) as exc:
        _decide_change(db, change.id, admin, True, "")
    assert exc.value.status_code == 403


# --- H3: Zonen-Löschung über Freigabe + Integritätsprüfung -----------------

def test_zone_delete_requires_no_networks(db):
    z = Zone(name="OLD", sort_order=1); db.add(z); db.flush()
    db.add(ZoneNetwork(cidr="10.9.0.0/24", zone_id=z.id, vrf_id=1)); db.commit()
    arch = make_user(db, "alex", Role.architect)
    with pytest.raises(HTTPException) as exc:  # Netz-Zuordnung verhindert Antrag
        _create_batch(db, arch, [{"type": "zone_delete", "name": "OLD"}], "")
    assert exc.value.status_code == 409


def test_zone_delete_two_approvals(db):
    db.add(Zone(name="OLD", sort_order=1)); db.commit()
    arch = make_user(db, "alex", Role.architect)
    ap1 = make_user(db, "chris"); ap2 = make_user(db, "kim")
    _create_batch(db, arch, [{"type": "zone_delete", "name": "OLD"}], "")
    change = db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()
    _decide_change(db, change.id, ap1, True, "")
    assert db.query(Zone).filter(Zone.name == "OLD").count() == 1  # noch da
    _decide_change(db, change.id, ap2, True, "")
    assert db.query(Zone).filter(Zone.name == "OLD").count() == 0  # gelöscht


# --- H4: impl_status-Validierung -------------------------------------------

def test_impl_status_rejects_unknown_component(db):
    fw = SecurityComponent(name="FW-A", type=ComponentType.juniper)
    db.add(fw); db.flush()
    rule = Rule(rule_id="SR00001", vrf_id=1, name="r", components=[fw],
                source=[{"ip": "10.0.0.1", "alias": ""}], destination=[{"ip": "10.0.0.2", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
                status=RuleStatus.approved)
    db.add(rule); db.commit()
    ops = make_user(db, "bob", Role.operations)
    with pytest.raises(HTTPException) as exc:
        set_impl_status("SR00001", {"FremdKomponente": "umgesetzt"}, db, ops)
    assert exc.value.status_code == 422
    with pytest.raises(HTTPException) as exc:
        set_impl_status("SR00001", {"FW-A": "quatsch"}, db, ops)
    assert exc.value.status_code == 422
    # gültig
    r = set_impl_status("SR00001", {"FW-A": "umgesetzt"}, db, ops)
    assert r.impl_status["FW-A"] == "umgesetzt"


# --- M2: Login-Lockout ------------------------------------------------------

def test_login_lockout(db, monkeypatch):
    import app.routers.auth_router as ar
    monkeypatch.setattr(ar, "LOGIN_MAX_FAILS", 3)
    monkeypatch.setattr(ar, "LOGIN_LOCK_MINUTES", 15)
    u = make_user(db, "target", Role.architect)
    # 3 Fehlversuche -> Konto gesperrt
    for _ in range(3):
        ar._register_failure(db, u)
    db.refresh(u)
    from datetime import timezone
    locked = u.locked_until
    if locked.tzinfo is None:
        locked = locked.replace(tzinfo=timezone.utc)
    assert locked is not None and locked > utcnow()
    assert u.failed_logins == 0  # Zähler nach Sperre zurückgesetzt


# --- M4: next_rule_id per SQL-Aggregat --------------------------------------

def test_next_rule_id_uses_max(db):
    from app.routers.rules_router import next_rule_id
    fw = SecurityComponent(name="FW", type=ComponentType.juniper)
    db.add(fw); db.flush()
    for rid in ("SR00001", "SR00042", "SR00007"):
        db.add(Rule(rule_id=rid, vrf_id=1, name=rid, components=[fw],
                    source=[{"ip": "10.0.0.1", "alias": ""}], destination=[{"ip": "10.0.0.2", "alias": ""}],
                    services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
                    status=RuleStatus.approved))
    db.commit()
    assert next_rule_id(db) == "SR00043"
