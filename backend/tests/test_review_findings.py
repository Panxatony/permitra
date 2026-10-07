"""Findings of the functional review of 2026-10-07, each fixed here and pinned.

Every test names the behaviour the review observed on a demo instance and
asserts the behaviour the documentation promised all along. They are kept
together because they came from one pass over the whole product, not from
one feature.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.database import Base, get_db
from app.exporters import aci
from app.main import app
from app.models import (
    AddressComponentMap,
    AuditEvent,
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
    Zone,
    ZoneNetwork,
    ZonePolicy,
    ZonePolicyType,
    apply_roles,
)
from app.routers.rules_router import ReviewDecision, _decide, accounts_involved, add_version
from app.routers.zones_router import _create_batch, _decide_change


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    s.add(Zone(id=1, code="Z010", name="MGMT", sort_order=10))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20))
    s.add(ZoneNetwork(cidr="10.0.0.0/24", zone_id=1, vrf_id=1))
    s.add(ZoneNetwork(cidr="10.0.1.0/24", zone_id=2, vrf_id=1))
    s.add(AddressComponentMap(ip="10.0.0.0/24", vrf_id=1, component_ids=[1]))
    s.add(AddressComponentMap(ip="10.0.1.0/24", vrf_id=1, component_ids=[1]))
    s.add(ZonePolicy(from_zone_id=1, to_zone_id=2, policy=ZonePolicyType.allow_only))
    for name in ("alex", "bea", "chris", "ops"):
        u = User(username=name, password_hash="x", is_active=True)
        apply_roles(u, [Role.operations] if name == "ops" else [Role.architect, Role.change_approver])
        s.add(u)
    s.commit()
    yield s
    s.close()


def user(db, name):
    return db.query(User).filter(User.username == name).one()


def make_rule(db, rule_id="SR00001", status=RuleStatus.approved, action=RuleAction.permit,
              requestor="alex", created_by="alex", **extra):
    """A rule MGMT -> PROD that stores the zone *codes*, as every rule does
    since rules reference zones by code."""
    rule = Rule(rule_id=rule_id, vrf_id=1, name=rule_id.lower(), requestor=requestor, created_by=created_by,
                components=[db.get(SecurityComponent, 1)],
                source=[{"ip": "10.0.0.5", "alias": ""}], destination=[{"ip": "10.0.1.5", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}], action=action, status=status,
                source_zone="Z010", destination_zone="Z020", **extra)
    db.add(rule)
    db.commit()
    return rule


# ---------- B-10: allow -> block reaches the rules that store codes ----------

def test_a_block_decision_sends_rules_with_coded_zones_into_review(db):
    """The preview named the rules; the decision found none, because it asked
    by zone name while the rules store the code."""
    make_rule(db, "SR00001", RuleStatus.approved)
    make_rule(db, "SR00002", RuleStatus.active)
    _create_batch(db, user(db, "alex"), [
        {"type": "policy", "from_zone": "Z010", "to_zone": "Z020", "policy": "block_all"}], "lockdown")
    from app.models import ZonePolicyChange
    change = db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()
    _decide_change(db, change.id, user(db, "bea"), True, "")
    result = _decide_change(db, change.id, user(db, "chris"), True, "")
    assert sorted(result["reviews_reset"]) == ["SR00001", "SR00002"]
    assert db.query(Rule).filter_by(rule_id="SR00002").one().status == RuleStatus.in_review


# ---------- A-11: a cycle closes on a decision, not on any closed-status version ----------

def test_a_requestor_who_handed_over_an_approved_rule_cannot_approve_its_next_revision(db):
    rule = make_rule(db, requestor="bea", created_by="alex")
    rule.version += 1
    add_version(db, rule, user(db, "chris"), "Rule approved")        # decision: in_review -> approved
    rule.version += 1
    add_version(db, rule, user(db, "bea"), "Handover proposed")       # bea proposes, still requestor
    rule.requestor = "chris"                                           # chris confirms
    rule.version += 1
    add_version(db, rule, user(db, "chris"), "Requestor handover")
    rule.status = RuleStatus.draft
    rule.version += 1
    add_version(db, rule, user(db, "alex"), "Rule changed")
    rule.status = RuleStatus.in_review
    rule.version += 1
    add_version(db, rule, user(db, "alex"), "Submitted")
    db.commit()
    assert "bea" in accounts_involved(rule)
    with pytest.raises(Exception) as exc:
        _decide(db, "SR00001", user(db, "bea"), ReviewDecision(), RuleStatus.approved, "Rule approved")
    assert getattr(exc.value, "status_code", None) == 403


def test_the_approver_of_the_previous_cycle_is_not_involved_in_the_next(db):
    rule = make_rule(db, status=RuleStatus.in_review)
    rule.status = RuleStatus.approved
    rule.version += 1
    add_version(db, rule, user(db, "bea"), "Rule approved")
    rule.status = RuleStatus.draft
    rule.version += 1
    add_version(db, rule, user(db, "chris"), "Rule changed")
    rule.status = RuleStatus.in_review
    rule.version += 1
    add_version(db, rule, user(db, "chris"), "Submitted")
    db.commit()
    assert "bea" not in accounts_involved(rule)


# ---------- A-20 / A-26 / C-21: smaller promises ----------

def test_approving_a_removal_closes_the_emergency_window(db):
    from datetime import timedelta

    from app.models import utcnow
    make_rule(db, status=RuleStatus.in_review, removal_reason="matrix: block",
              emergency_approval_due=utcnow() + timedelta(hours=20))
    decided = _decide(db, "SR00001", user(db, "bea"), ReviewDecision(), RuleStatus.approved, "Rule approved")
    assert decided.status == RuleStatus.deactivated
    assert decided.emergency_approval_due is None


def test_deactivating_a_rule_in_force_leaves_the_removal_as_open_work(db):
    rule = make_rule(db, status=RuleStatus.active, impl_status={"FW": "implemented"})
    decided = _decide(db, "SR00001", user(db, "ops"), ReviewDecision(), RuleStatus.deactivated, "Rule deactivated")
    assert decided.impl_status == {"FW": "to remove"}
    assert rule.status == RuleStatus.deactivated


def test_a_deny_rule_is_not_rendered_as_a_permitting_contract(db):
    from app.models import AddressEpgMap, Epg
    epg = Epg(name="epg-a", tenant="T", app_profile="AP", bridge_domain="BD")
    db.add(epg)
    db.flush()
    db.add(AddressEpgMap(vrf_id=1, ip="10.0.0.0/24", epg_id=epg.id))
    db.add(AddressEpgMap(vrf_id=1, ip="10.0.1.0/24", epg_id=epg.id))
    db.commit()
    rule = make_rule(db, action=RuleAction.deny)
    model = aci.build_contract_model([rule], db)
    assert model["contracts"] == []
    assert [r.rule_id for r in model["legacy"]] == ["SR00001"]
    assert any("deny" in w for w in model["warnings"])


# ---------- HTTP-level findings ----------

@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    s.add(Zone(id=1, code="Z010", name="MGMT", sort_order=10))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20, cia_c="very high"))
    s.add(ZoneNetwork(cidr="10.0.0.0/24", zone_id=1, vrf_id=1))
    s.add(ZoneNetwork(cidr="10.0.1.0/24", zone_id=2, vrf_id=1))
    s.add(User(username="arch", full_name="arch", role=Role.architect, is_active=True,
               password_hash=hash_password("arch-pw-12345")))
    s.add(User(username="ops", full_name="ops", role=Role.operations, is_active=True,
               password_hash=hash_password("ops-pw-12345")))
    s.commit()
    s.close()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    yield TestClient(app, raise_server_exceptions=False), Session
    app.dependency_overrides.clear()


def auth(c, name):
    r = c.post("/api/auth/login", data={"username": name, "password": f"{name}-pw-12345"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_the_live_risk_assessment_answers_for_a_draft(client):
    """It answered 500 - the draft lacked the logging attribute the assessment
    reads - so the form had no live warnings at all."""
    c, _ = client
    r = c.post("/api/rules/risk/assess", headers=auth(c, "arch"), json={
        "source": [{"ip": "any"}], "destination": [{"ip": "10.0.1.5"}],
        "services": [{"protocol": "TCP", "port": "23"}],
        "source_zone": "Z010", "destination_zone": "Z020", "log_level": "none"})
    assert r.status_code == 200, r.text
    codes = {f["code"] for f in r.json()["findings"]}
    assert "no-logging" in codes and "risky-service" in codes


def test_an_unreadable_configuration_is_never_in_sync(client):
    c, _ = client
    up = c.put("/api/components/1/actual-config", headers=auth(c, "ops"),
               json={"content": "this is not a firewall configuration SR00001"})
    assert up.status_code == 200, up.text
    drift = c.get("/api/components/1/drift", headers=auth(c, "ops")).json()
    assert drift["coverage"]["recognised"] is False
    assert drift["in_sync"] is False


def test_two_factor_events_carry_the_source_address(client):
    c, Session = client
    headers = auth(c, "arch")
    secret = c.post("/api/auth/totp/setup", headers=headers).json()["secret"]
    import time

    from app import totp
    code = totp._code_at(secret, int(time.time()) // 30)
    assert c.post("/api/auth/totp/enable", headers=headers, json={"code": code}).status_code == 200
    db = Session()
    event = db.query(AuditEvent).filter_by(event="auth.totp_enabled").one()
    db.close()
    assert event.source_ip
