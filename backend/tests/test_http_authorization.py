"""HTTP layer: enforcement of role permissions through the real FastAPI app.

The other tests call router functions directly and pass the user object as a
parameter - and in doing so the `require_roles` dependency is NEVER executed. If
it were dropped from an endpoint, those tests would stay green. These tests
therefore go through the real HTTP layer including all dependencies and thereby
protect the permission check itself.
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
from app.models import Role, User, Vrf


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    s = Session()
    s.add(Vrf(id=1, name="IT"))
    for name, role in [("arch", Role.architect), ("ops", Role.operations),
                       ("appr", Role.change_approver), ("adm", Role.admin)]:
        s.add(User(username=name, full_name=name, role=role, is_active=True,
                   password_hash=hash_password(f"{name}-pw-123")))
    s.commit()
    s.close()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    # Deliberately WITHOUT `with`: this keeps the startup hooks (Alembic migrations
    # against the real file DB, seeding, background jobs) from running. What is
    # tested is only the HTTP/dependency layer against the in-memory DB above.
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


def token(client, username):
    r = client.post("/api/auth/login",
                    data={"username": username, "password": f"{username}-pw-123"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def auth(client, username):
    return {"Authorization": f"Bearer {token(client, username)}"}


# ---------- Admin-only endpoints -------------------------------------------

ADMIN_ONLY_GET = [
    "/api/users",
    "/api/audit-log",
    "/api/audit-log/verify",
    "/api/audit-log/siem-status",
    "/api/api-tokens",
    "/api/netbox/config",
]


@pytest.mark.parametrize("path", ADMIN_ONLY_GET)
def test_admin_only_endpoints_reject_other_roles(client, path):
    """Non-admins must not read administrative endpoints."""
    for user in ("arch", "ops", "appr"):
        r = client.get(path, headers=auth(client, user))
        assert r.status_code == 403, f"{path} was reachable for {user}: {r.status_code}"


@pytest.mark.parametrize("path", ADMIN_ONLY_GET)
def test_admin_only_endpoints_require_authentication(client, path):
    """Without a token there is no access."""
    r = client.get(path)
    assert r.status_code == 401, f"{path} without a token: {r.status_code}"


@pytest.mark.parametrize("path", ADMIN_ONLY_GET)
def test_admin_reaches_admin_endpoints(client, path):
    """Counter-check: the admin gets through (otherwise the tests above check nothing)."""
    r = client.get(path, headers=auth(client, "adm"))
    assert r.status_code == 200, f"{path} not reachable for the admin: {r.text}"


def test_settings_write_is_admin_only(client):
    """Only the admin may change settings - reading is allowed for everyone."""
    body = {"require_justification": "no"}
    for user in ("arch", "ops", "appr"):
        r = client.put("/api/settings", json=body, headers=auth(client, user))
        assert r.status_code == 403, f"{user} was able to change settings"
    assert client.put("/api/settings", json=body,
                      headers=auth(client, "adm")).status_code == 200


def test_user_creation_is_admin_only(client):
    payload = {"username": "eindringling", "email": "x@example.org", "role": "admin"}
    for user in ("arch", "ops", "appr"):
        r = client.post("/api/users", json=payload, headers=auth(client, user))
        assert r.status_code == 403, f"{user} was able to create a user"


def test_rule_deletion_is_admin_only(client):
    """Deletion (soft delete) is reserved for admins."""
    for user in ("arch", "ops", "appr"):
        r = client.delete("/api/rules/SR00001", headers=auth(client, user))
        assert r.status_code == 403, f"{user} was allowed to delete ({r.status_code})"


def test_risk_criteria_are_readable_for_every_role(client):
    """An approver has to know what a risk hint was raised by, so reading the
    criteria is deliberately not administrative."""
    for user in ("arch", "ops", "appr", "adm"):
        r = client.get("/api/risk/criteria", headers=auth(client, user))
        assert r.status_code == 200, f"{user} cannot read the criteria: {r.text}"
        assert r.json()["risky_ports"], "criteria without any service list"
    assert client.get("/api/risk/criteria").status_code == 401


def test_risk_ports_are_admin_only(client):
    """Changing the yardstick is an administrative act."""
    for user in ("arch", "ops", "appr"):
        headers = auth(client, user)
        assert client.put("/api/risk/ports/22", json={"label": "SSH"},
                          headers=headers).status_code == 403, f"{user} could add a service"
        assert client.delete("/api/risk/ports/23",
                             headers=headers).status_code == 403, f"{user} could remove a service"

    assert client.put("/api/risk/ports/22", json={"label": "SSH"},
                      headers=auth(client, "adm")).status_code == 200
    assert client.delete("/api/risk/ports/22", headers=auth(client, "adm")).status_code == 204


# ---------- Read-only API tokens --------------------------------------------

def _create_pat(client) -> str:
    r = client.post("/api/api-tokens", json={"name": "ci-readonly"},
                    headers=auth(client, "adm"))
    assert r.status_code == 201, r.text
    return r.json()["token"]


def test_api_token_allows_reading(client):
    pat = _create_pat(client)
    r = client.get("/api/rules", headers={"Authorization": f"Bearer {pat}"})
    assert r.status_code == 200


@pytest.mark.parametrize("method,path,body", [
    ("post", "/api/rules", {"name": "x"}),
    ("put", "/api/settings", {"require_justification": "no"}),
    ("post", "/api/users", {"username": "y", "role": "admin"}),
    ("delete", "/api/rules/SR00001", None),
    ("put", "/api/risk/ports/22", {"label": "SSH"}),
    ("delete", "/api/risk/ports/23", None),
])
def test_api_token_cannot_write(client, method, path, body):
    """Read-only tokens may only read - every write operation yields 403."""
    pat = _create_pat(client)
    headers = {"Authorization": f"Bearer {pat}"}
    call = getattr(client, method)
    r = call(path, json=body, headers=headers) if body is not None else call(path, headers=headers)
    assert r.status_code == 403, f"{method.upper()} {path} was possible with a read-only token"


def test_api_token_cannot_reach_admin_endpoints(client):
    """The token principal has operations permissions, so no admin GETs."""
    pat = _create_pat(client)
    r = client.get("/api/users", headers={"Authorization": f"Bearer {pat}"})
    assert r.status_code == 403


def test_revoked_token_is_rejected(client):
    pat = _create_pat(client)
    listed = client.get("/api/api-tokens", headers=auth(client, "adm")).json()
    tid = listed[0]["id"]
    assert client.delete(f"/api/api-tokens/{tid}", headers=auth(client, "adm")).status_code == 204
    r = client.get("/api/rules", headers={"Authorization": f"Bearer {pat}"})
    assert r.status_code == 401, "revoked token was still accepted"


# ---------- Token robustness ------------------------------------------------

def test_garbage_and_missing_tokens_are_rejected(client):
    for value in ("Bearer nonsense", "Bearer ", "nonsense", ""):
        r = client.get("/api/users", headers={"Authorization": value})
        assert r.status_code == 401, f"invalid header {value!r} yielded {r.status_code}"


def test_deactivated_user_cannot_use_existing_token(client, ):
    """An already issued token loses its effect when the account is deactivated."""
    tok = token(client, "arch")
    headers = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/rules", headers=headers).status_code == 200
    assert client.put("/api/users/arch", json={"is_active": False},
                      headers=auth(client, "adm")).status_code == 200
    assert client.get("/api/rules", headers=headers).status_code == 401
