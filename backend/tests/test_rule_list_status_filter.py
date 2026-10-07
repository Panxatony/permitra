"""`GET /api/rules?status=` takes several values.

"In force" is two statuses: `approved` says the rule may exist, `active` says
operations confirmed it does. A feed that asked for `approved` alone - as the
documented Ansible and Terraform examples did - lost every rule the moment it
was marked implemented, which is exactly when the automation needed it most.
"""
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("PERMITRA_DEV", "1")

from app.auth import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import Role, Rule, RuleAction, RuleStatus, User, Vrf


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    s.add(User(username="ops", full_name="ops", role=Role.operations, is_active=True,
               password_hash=hash_password("ops-pw-123")))
    for rid, st in (("SR00001", RuleStatus.approved), ("SR00002", RuleStatus.active),
                    ("SR00003", RuleStatus.draft)):
        s.add(Rule(rule_id=rid, vrf_id=1, name=rid, status=st, action=RuleAction.permit,
                   source=[{"ip": "10.0.0.1", "alias": ""}], destination=[{"ip": "10.0.0.2", "alias": ""}],
                   services=[{"protocol": "TCP", "port": "443"}]))
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
    r = c.post("/api/auth/login", data={"username": "ops", "password": "ops-pw-123"})
    c.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
    yield c
    app.dependency_overrides.clear()


def ids(response):
    assert response.status_code == 200, response.text
    return sorted(r["rule_id"] for r in response.json()["items"])


def test_several_statuses_select_their_union(client):
    assert ids(client.get("/api/rules?status=approved,active")) == ["SR00001", "SR00002"]


def test_a_single_status_still_works(client):
    assert ids(client.get("/api/rules?status=active")) == ["SR00002"]


def test_an_unknown_status_is_refused(client):
    r = client.get("/api/rules?status=approved,whatever")
    assert r.status_code == 422
    assert "whatever" in r.json()["detail"]
