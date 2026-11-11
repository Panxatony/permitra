"""The auditor role (GitLab issue 41): reads what an audit asks for, writes nothing.

Supporting an audit is one of the goals of version one, and the four roles
before this one could all write. These tests go through the real HTTP layer,
because "read-only" is a property of the dependency chain and a test that
passes the user object in by hand never runs it.
"""
import os

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("PERMITRA_DEV", "1")

from app import auth as auth_module
from app.auth import create_token, hash_password
from app.database import Base, get_db
from app.main import app
from app.models import Role, User, Vrf, apply_roles, primary_role

READ_METHODS = {"GET", "HEAD", "OPTIONS"}


@pytest.fixture()
def session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    for name, role in [("aud", Role.auditor), ("arch", Role.architect), ("adm", Role.admin)]:
        s.add(User(username=name, full_name=name, role=role, is_active=True,
                   password_hash=hash_password(f"{name}-pw-123")))
    s.commit()
    s.close()
    return Session


@pytest.fixture()
def client(session_factory):
    def override_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    # Without `with`, so the startup hooks (migrations against the file
    # database, seeding, background jobs) stay out of the test.
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


def headers(username):
    # A session token minted directly: the walk below sends a request per
    # route, and a login per request would only exercise the login limiter.
    return {"Authorization": f"Bearer {session_token(username)}"}


def session_token(username):
    # The role in the token is informational; the account is re-read on every request.
    return create_token(User(username=username, password_hash="", full_name=username,
                             role=Role.architect))


def _endpoints(routes):
    """Every endpoint of the application, through the included routers."""
    for route in routes:
        if hasattr(route, "original_router"):
            yield from _endpoints(route.original_router.routes)
        elif hasattr(route, "dependant"):
            yield route


def _writes():
    found = []
    for route in _endpoints(app.routes):
        for method in sorted(route.methods - READ_METHODS):
            found.append((method, route.path))
    return found


def _concrete(path):
    """A path with its parameters filled in - the refusal comes before any
    lookup, so the values only have to parse."""
    out = []
    for part in path.split("/"):
        out.append("1" if part.startswith("{") else part)
    return "/".join(out)


AUDITOR_READS = [
    "/api/rules",
    "/api/zones",
    "/api/zones/matrix",
    "/api/components",
    "/api/workloads",
    "/api/objects/groups",
    "/api/dashboard",
    "/api/audit-log",
    "/api/audit-log/verify",
    "/api/audit-log/siem-status",
    "/api/recertification/campaigns",
    "/api/reports/requestors",
    "/api/reports/evidence?date_from=2026-01-01&date_to=2026-12-31",
    "/api/reports/evidence.csv?date_from=2026-01-01&date_to=2026-12-31",
]


@pytest.mark.parametrize("path", AUDITOR_READS)
def test_auditor_reads_what_an_audit_asks_for(client, path):
    """Rules, model, reports, recertification and the audit log with its chain
    check are readable with one account - before, the log needed the admin and
    the reports a working role."""
    r = client.get(path, headers=headers("aud"))
    assert r.status_code == 200, f"{path}: {r.status_code} {r.text[:200]}"


@pytest.mark.parametrize("path", ["/api/recertification/campaigns/1",
                                  "/api/recertification/campaigns/1/report"])
def test_auditor_is_admitted_to_a_single_campaign(client, path):
    """No campaign exists here, so the answer is "not found" - which is the
    answer of the endpoint, not of its guard."""
    r = client.get(path, headers=headers("aud"))
    assert r.status_code == 404, f"{path}: {r.status_code}"


@pytest.mark.parametrize("path", ["/api/users", "/api/api-tokens", "/api/netbox/config"])
def test_auditor_does_not_read_the_administration(client, path):
    """Accounts, API tokens and the NetBox connection are how Permitra is run,
    not what an audit of the rule set examines - they stay with the admin."""
    r = client.get(path, headers=headers("aud"))
    assert r.status_code == 403, f"{path}: {r.status_code}"


def test_every_writing_endpoint_refuses_an_auditor(client):
    """Walks every route instead of naming the ones known today: several
    writing endpoints ask for a login only (comments, the risk assessment), and
    an endpoint added next month must not be the one an auditor can write to."""
    outside_account = [(m, p) for m, p in _writes()
                       if not p.startswith(auth_module.AUDITOR_WRITABLE_PREFIX)]
    assert len(outside_account) > 80, "the route walk found too little - did the app layout change?"
    passed = []
    for method, path in outside_account:
        r = client.request(method, _concrete(path), headers=headers("aud"))
        detail = r.json().get("detail") if r.status_code == 403 else None
        if r.status_code != 403 or "auditor" not in str(detail).lower():
            passed.append(f"{method} {path} -> {r.status_code}")
    assert not passed, "an auditor got past the read-only rule on:\n" + "\n".join(passed)


def test_the_same_request_is_not_refused_for_a_working_role(client):
    """The counterpart to the walk: the 403 there comes from the auditor rule
    and not from the request being unanswerable for everybody."""
    r = client.post("/api/rules/risk/assess", headers=headers("arch"),
                    json={"source": [{"ip": "10.0.0.1"}], "destination": [{"ip": "10.0.1.1"}],
                          "services": [{"protocol": "TCP", "port": "443"}]})
    assert r.status_code != 403, r.text
    r = client.post("/api/rules/risk/assess", headers=headers("aud"),
                    json={"source": [{"ip": "10.0.0.1"}], "destination": [{"ip": "10.0.1.1"}],
                          "services": [{"protocol": "TCP", "port": "443"}]})
    assert r.status_code == 403


def test_the_own_account_is_the_only_thing_an_auditor_changes(client):
    """An account that cannot change its own password or set up a second factor
    would be a worse account, not a safer one. The exception is spelled out
    here, so a new endpoint under the account prefix is a decision and not an
    accident."""
    account_writes = {(m, p) for m, p in _writes()
                      if p.startswith(auth_module.AUDITOR_WRITABLE_PREFIX)}
    assert account_writes == {
        ("POST", "/api/auth/login"),
        ("POST", "/api/auth/forgot"),
        ("POST", "/api/auth/set-password"),
        ("POST", "/api/auth/passkey/login-options"),
        ("POST", "/api/auth/passkey/login"),
        ("PUT", "/api/auth/notifications"),
        ("POST", "/api/auth/change-password"),
        ("POST", "/api/auth/totp/setup"),
        ("POST", "/api/auth/totp/enable"),
        ("POST", "/api/auth/totp/disable"),
        ("POST", "/api/auth/passkey/register-options"),
        ("POST", "/api/auth/passkey/register"),
        ("DELETE", "/api/auth/passkeys/{passkey_id}"),
    }
    r = client.put("/api/auth/notifications", headers=headers("aud"),
                   json={"notify_email": False})
    assert r.status_code == 200, r.text
    assert r.json()["notify_email"] is False


def test_without_a_request_an_auditor_is_refused(session_factory):
    """Fails closed like the read-only API token: with no request there is no
    method to look at, and "could not tell" must not read as "read-only"."""
    db = session_factory()
    try:
        with pytest.raises(HTTPException) as exc:
            auth_module.get_current_user(request=None, token=session_token("aud"), db=db)
        assert exc.value.status_code == 403
        # A working role is not touched by the rule.
        user = auth_module.get_current_user(request=None, token=session_token("arch"), db=db)
        assert user.username == "arch"
    finally:
        db.close()


@pytest.mark.parametrize("roles", [["auditor", "architect"], ["auditor", "admin"],
                                   ["operations", "auditor", "change_approver"]])
def test_auditor_cannot_be_combined_with_another_role(client, roles):
    """Read-only has to be a property of the account. An auditor who also held
    a working role could write after all, and nobody could say afterwards that
    the audit account changed nothing."""
    r = client.post("/api/users", headers=headers("adm"),
                    json={"username": "mixed", "full_name": "Mixed", "roles": roles})
    assert r.status_code == 422, r.text
    r = client.put("/api/users/arch", headers=headers("adm"), json={"roles": roles})
    assert r.status_code == 422, r.text
    r = client.put("/api/users/aud", headers=headers("adm"), json={"roles": roles})
    assert r.status_code == 422, r.text


def test_admin_creates_an_auditor_and_can_change_the_role_later(client):
    """The role is assigned like any other, and an account can leave it - what
    is refused is holding it together with another one."""
    r = client.post("/api/users", headers=headers("adm"),
                    json={"username": "pruefer", "full_name": "External audit",
                          "roles": ["auditor"]})
    assert r.status_code == 201, r.text
    assert r.json()["user"]["roles"] == ["auditor"]
    assert r.json()["user"]["role"] == "auditor"
    r = client.put("/api/users/pruefer", headers=headers("adm"), json={"roles": ["architect"]})
    assert r.status_code == 200, r.text
    assert r.json()["roles"] == ["architect"]


def test_the_role_writer_refuses_the_combination_itself():
    """The backstop behind the 422: every caller of `apply_roles`, not only the
    users router, gets the same answer."""
    user = User(username="x", password_hash="", full_name="x")
    with pytest.raises(ValueError):
        apply_roles(user, [Role.auditor, Role.operations])
    apply_roles(user, [Role.auditor])
    assert user.roles == [Role.auditor]


def test_auditor_is_its_own_primary_role():
    """Without a place in the precedence the badge and the landing page would
    fall back to "architect" - the account would look like it may plan rules."""
    assert primary_role([Role.auditor]) == Role.auditor
