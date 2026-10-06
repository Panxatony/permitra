"""The forgotten-password request is reachable without a session, so it has to
hold up against whoever reaches it.

Each request used to create a token and send a mail, for anyone, as often as
they asked: a mailbox and the operator's relay could be flooded from one
address. And a reset link activated the account it was for, so a user an admin
had deactivated could let themselves back in. The answer must stay the same in
every case - the endpoint must not confirm that an account exists, and a 429
would say which ceiling a request hit.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import mailer
from app.auth import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import AuditEvent, AuthToken, Role, User, Vrf
from app.routers import auth_router
from app.routers.users_router import issue_token

FORGOT = "/api/auth/forgot"
ANSWER = "If the account exists and has an e-mail address on file, a reset link has been sent."


@pytest.fixture()
def client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    s.add(User(username="arch", full_name="arch", email="arch@example.org",
               role=Role.architect, is_active=True, password_hash=hash_password("arch-pw-123")))
    s.add(User(username="gone", full_name="gone", email="gone@example.org",
               role=Role.architect, is_active=False, password_hash=hash_password("gone-pw-123")))
    s.commit()
    s.close()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(mailer, "enabled", lambda: True)
    monkeypatch.setattr(mailer, "send", lambda to, subj, body: (sent.append((to, subj)) or True))
    # The counter is process-wide and every test client has the same address.
    auth_router._forgot_limiter.reset()
    app.dependency_overrides[get_db] = override_db
    yield TestClient(app, raise_server_exceptions=False), Session, sent
    app.dependency_overrides.clear()
    auth_router._forgot_limiter.reset()


def reset_tokens(Session, username):
    db = Session()
    try:
        return (db.query(AuthToken).join(User)
                .filter(User.username == username, AuthToken.purpose == "reset").all())
    finally:
        db.close()


def outcomes(Session):
    db = Session()
    try:
        return [e.detail for e in db.query(AuditEvent)
                .filter(AuditEvent.event == "auth.reset_requested").order_by(AuditEvent.id)]
    finally:
        db.close()


# ---------- the ceilings ----------

def test_the_address_ceiling_drops_requests_but_answers_the_same(client, monkeypatch):
    """Beyond FORGOT_MAX_REQUESTS from one address nothing is issued and nothing
    is sent - and the caller cannot tell, because the answer does not change."""
    c, Session, sent = client
    monkeypatch.setattr(auth_router._forgot_limiter, "max_requests", 2)
    answers = [c.post(FORGOT, json={"username": f"nobody-{i}"}) for i in range(3)]
    over = c.post(FORGOT, json={"username": "arch"})
    assert all(a.status_code == 200 for a in [*answers, over])
    assert over.json()["detail"] == answers[0].json()["detail"] == ANSWER
    assert reset_tokens(Session, "arch") == []
    assert sent == []
    assert outcomes(Session)[-1] == "rate limited"


def test_one_mail_per_account_per_window(client):
    """A second request for the same account inside the window sends nothing,
    so a known address cannot be flooded by asking again and again."""
    c, Session, sent = client
    first = c.post(FORGOT, json={"username": "arch"})
    second = c.post(FORGOT, json={"username": "arch@example.org"})
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert len(sent) == 1
    assert len(reset_tokens(Session, "arch")) == 1
    assert outcomes(Session) == ["sent", "cooldown"]


def test_a_new_link_replaces_the_previous_one(client):
    """Otherwise every request leaves another valid token behind for two hours."""
    c, Session, _sent = client
    db = Session()
    user = db.query(User).filter(User.username == "arch").one()
    first = issue_token(db, user, "reset").split("token=")[1]
    second = issue_token(db, user, "reset").split("token=")[1]
    db.close()
    stale = c.post("/api/auth/set-password", json={"token": first, "password": "new-pw-12345"})
    assert stale.status_code == 400
    fresh = c.post("/api/auth/set-password", json={"token": second, "password": "new-pw-12345"})
    assert fresh.status_code == 200


# ---------- deactivated accounts stay deactivated ----------

def test_a_deactivated_account_gets_no_link(client):
    c, Session, sent = client
    r = c.post(FORGOT, json={"username": "gone"})
    assert r.status_code == 200 and r.json()["detail"] == ANSWER
    assert sent == []
    assert reset_tokens(Session, "gone") == []
    assert outcomes(Session) == ["account deactivated"]


def test_a_reset_link_does_not_activate(client):
    """Only an activation link activates. A reset link that reached a deactivated
    account by any route changes the password and nothing else."""
    c, Session, _sent = client
    db = Session()
    user = db.query(User).filter(User.username == "gone").one()
    raw = issue_token(db, user, "reset").split("token=")[1]
    db.close()
    r = c.post("/api/auth/set-password", json={"token": raw, "password": "new-pw-12345"})
    assert r.status_code == 200
    db = Session()
    assert db.query(User).filter(User.username == "gone").one().is_active is False
    db.close()
    denied = c.post("/api/auth/login", data={"username": "gone", "password": "new-pw-12345"})
    assert denied.status_code == 403


def test_an_activation_link_still_activates(client):
    """The guard above must not break the one link that is meant to activate."""
    c, Session, _sent = client
    db = Session()
    user = db.query(User).filter(User.username == "gone").one()
    raw = issue_token(db, user, "activate").split("token=")[1]
    db.close()
    r = c.post("/api/auth/set-password", json={"token": raw, "password": "new-pw-12345"})
    assert r.status_code == 200
    db = Session()
    assert db.query(User).filter(User.username == "gone").one().is_active is True
    db.close()


# ---------- the audit log sees every request ----------

def test_every_request_is_recorded_with_its_outcome(client):
    """Flooding was invisible: the endpoint wrote no audit record at all."""
    c, Session, _sent = client
    c.post(FORGOT, json={"username": "nobody-here"})
    c.post(FORGOT, json={"username": "x" * 200})
    c.post(FORGOT, json={"username": "arch"})
    assert outcomes(Session) == ["unknown account", "unknown account", "sent"]
    db = Session()
    actors = [e.actor for e in db.query(AuditEvent).filter(AuditEvent.event == "auth.reset_requested")]
    db.close()
    # The identifier is whatever was typed; it must fit the column on PostgreSQL.
    assert max(len(a) for a in actors) == 64
