"""The change process hears about every step of a rule's life, and can write
its ticket number back without touching the approval.

The webhook fired on submit, approve, reject and the zone decisions - and
not on an emergency declaration, an implementation report, a removal
proposal or an expiry, which are the steps a change ticket is opened,
closed or escalated on. Writing the ticket number back went through the
full rule PUT, which needs the architect role and resets an approved rule
to draft. Delivery was one attempt, unsigned.
"""
import hashlib
import hmac
import json
import os
import threading
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import change_management, expiry
from app.auth import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import (
    AddressComponentMap,
    AuditEvent,
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    RuleVersion,
    SecurityComponent,
    User,
    Vrf,
    Zone,
    ZoneNetwork,
)


@pytest.fixture()
def sent(monkeypatch):
    """Every event notify() would have sent, without a network."""
    calls = []
    monkeypatch.setattr(change_management, "notify", lambda event, data: calls.append((event, data)))
    return calls


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    s.add(Zone(id=1, code="Z010", name="DMZ", sort_order=10))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20))
    s.add(ZoneNetwork(cidr="10.0.0.0/24", zone_id=1, vrf_id=1))
    s.add(ZoneNetwork(cidr="10.0.1.0/24", zone_id=2, vrf_id=1))
    s.add(AddressComponentMap(ip="10.0.0.0/24", vrf_id=1, component_ids=[1]))
    s.add(AddressComponentMap(ip="10.0.1.0/24", vrf_id=1, component_ids=[1]))
    for name, role in (("arch", Role.architect), ("ops", Role.operations), ("adm", Role.admin)):
        s.add(User(username=name, full_name=name, role=role, is_active=True,
                   password_hash=hash_password(f"{name}-pw-12345")))
    s.add(Rule(rule_id="SR00001", vrf_id=1, name="r", status=RuleStatus.approved, created_by="arch",
               requestor="arch", components=[s.get(SecurityComponent, 1)],
               source=[{"ip": "10.0.0.1", "alias": ""}], destination=[{"ip": "10.0.1.1", "alias": ""}],
               services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
               source_zone="Z010", destination_zone="Z020", change_id="CHN0001"))
    s.commit()
    s.close()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    c = TestClient(app, raise_server_exceptions=False)
    yield c, Session
    app.dependency_overrides.clear()


def auth(c, user):
    r = c.post("/api/auth/login", data={"username": user, "password": f"{user}-pw-12345"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ---------- the write-back ----------

def test_the_ticket_number_is_written_back_without_touching_the_approval(client, sent):
    c, Session = client
    r = c.patch("/api/rules/SR00001/change-id", json={"change_id": "CHG0042"}, headers=auth(c, "ops"))
    assert r.status_code == 200, r.text
    assert r.json()["change_id"] == "CHG0042"
    assert r.json()["status"] == "approved"
    db = Session()
    rule = db.query(Rule).filter_by(rule_id="SR00001").one()
    assert rule.version == 2
    note = db.query(RuleVersion).filter_by(rule_pk=rule.id, version=2).one().change_note
    assert "Change ID" in note
    assert db.query(AuditEvent).filter_by(event="rule.change_id_set").count() == 1
    db.close()


def test_a_ticket_number_with_a_line_break_or_no_session_is_refused(client, sent):
    c, _ = client
    assert c.patch("/api/rules/SR00001/change-id", json={"change_id": "a\nb"},
                   headers=auth(c, "ops")).status_code == 422
    assert c.patch("/api/rules/SR00001/change-id", json={"change_id": "x"}).status_code == 401
    assert c.patch("/api/rules/SR00001/change-id", json={"change_id": "x"},
                   headers=auth(c, "adm")).status_code == 403


def test_setting_the_same_number_again_writes_nothing(client, sent):
    c, Session = client
    c.patch("/api/rules/SR00001/change-id", json={"change_id": "CHN0001"}, headers=auth(c, "ops"))
    db = Session()
    assert db.query(Rule).filter_by(rule_id="SR00001").one().version == 1
    db.close()


# ---------- the events ----------

def test_an_implementation_report_is_an_event(client, sent):
    c, _ = client
    r = c.put("/api/rules/SR00001/impl-status", json={"FW": "implemented"}, headers=auth(c, "ops"))
    assert r.status_code == 200, r.text
    events = {e for e, _ in sent}
    assert "rule.implementation" in events
    payload = next(d for e, d in sent if e == "rule.implementation")
    assert payload["status"] == "active" and payload["reported_by"] == "ops"
    assert payload["enforcement"] == ["firewall"]


def test_an_emergency_declaration_is_an_event(client, sent):
    c, _ = client
    r = c.post("/api/rules/emergency", headers=auth(c, "ops"), json={
        "name": "hotfix", "source": [{"ip": "10.0.0.1"}], "destination": [{"ip": "10.0.1.1"}],
        "services": [{"protocol": "TCP", "port": "22"}], "component_ids": [1],
        "justification": "incident", "emergency_reason": "application down at 03:00",
        "valid_until": (date.today() + timedelta(days=30)).isoformat(),
    })
    assert r.status_code == 201, r.text
    payload = next(d for e, d in sent if e == "rule.emergency_declared")
    assert payload["declared_by"] == "ops" and payload["status"] == "in_review"


def test_an_expiry_is_an_event(client, sent):
    _, Session = client
    db = Session()
    rule = db.query(Rule).filter_by(rule_id="SR00001").one()
    rule.valid_until = (date.today() - timedelta(days=1)).isoformat()
    db.commit()
    assert expiry.expire_rules(db) == 1
    db.close()
    assert [e for e, _ in sent] == ["rule.expired"]


# ---------- delivery ----------

def test_delivery_retries_and_signs(monkeypatch):
    received = []
    done = threading.Event()
    state = {"calls": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            state["calls"] += 1
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if state["calls"] == 1:
                self.send_response(503)
                self.end_headers()
                return
            received.append((self.headers.get("X-Permitra-Signature"), body))
            self.send_response(200)
            self.end_headers()
            done.set()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("CHANGE_WEBHOOK_URL", f"http://127.0.0.1:{server.server_port}/hook")
        monkeypatch.setenv("CHANGE_WEBHOOK_SECRET", "s3cret")
        monkeypatch.setattr(change_management, "RETRY_DELAYS", (0.05,))
        change_management.notify("rule.expired", {"rule_id": "SR0001"})
        assert done.wait(5), "the retry never arrived"
    finally:
        server.shutdown()
    assert state["calls"] == 2
    signature, body = received[0]
    expected = hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert signature == f"sha256={expected}"
    assert json.loads(body)["event"] == "rule.expired"
