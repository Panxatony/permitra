"""Two properties the sign-in has to hold, both easy to lose again.

A second factor is only worth having if a code cannot be replayed and the seed
is not readable from the database. And a login form must not answer the question
"does this account exist" - not through its wording, not through its status
code, and not through how long it takes.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import crypto, totp
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
    s.add(User(username="arch", full_name="arch", role=Role.architect, is_active=True,
               password_hash=hash_password("arch-pw-123")))
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


def login(client, username, password, otp=None):
    data = {"username": username, "password": password}
    if otp is not None:
        data["otp"] = otp
    return client.post("/api/auth/login", data=data)


# ---------- TOTP: single use and not readable from the database ----------

def test_the_seed_is_not_stored_in_plaintext(client):
    c, Session = client
    token = login(c, "arch", "arch-pw-123").json()["access_token"]
    setup = c.post("/api/auth/totp/setup", headers={"Authorization": f"Bearer {token}"})
    seed = setup.json()["secret"]

    db = Session()
    stored = db.query(User).filter(User.username == "arch").one().totp_secret
    db.close()
    assert stored != seed, "the seed is readable straight from the database"
    assert crypto.decrypt(stored) == seed, "and it has to remain usable"


def test_a_code_cannot_be_used_twice(client):
    """Within the tolerance window an observed code would otherwise stay valid
    for about 90 seconds - long enough to be replayed."""
    c, _session = client
    token = login(c, "arch", "arch-pw-123").json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    seed = c.post("/api/auth/totp/setup", headers=headers).json()["secret"]
    code = totp._code_at(seed, int(time.time()) // 30)
    assert c.post("/api/auth/totp/enable", json={"code": code},
                  headers=headers).status_code == 200

    # The code that switched 2FA on must not also open a session.
    replay = login(c, "arch", "arch-pw-123", otp=code)
    assert replay.status_code == 401, "a used code was accepted a second time"

    # The next time step works again.
    fresh = totp._code_at(seed, int(time.time()) // 30 + 1)
    assert login(c, "arch", "arch-pw-123", otp=fresh).status_code == 200


def test_a_used_code_is_refused_but_a_newer_one_is_not():
    """The rule in isolation, without the HTTP layer around it."""
    seed = totp.new_secret()
    counter = int(time.time()) // 30
    code = totp._code_at(seed, counter)
    assert totp.verify(seed, code) == counter
    assert totp.verify(seed, code, last_counter=counter) is None
    later = totp._code_at(seed, counter + 1)
    assert totp.verify(seed, later, last_counter=counter) == counter + 1


def test_disabling_clears_the_seed_and_the_counter(client):
    c, Session = client
    token = login(c, "arch", "arch-pw-123").json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    seed = c.post("/api/auth/totp/setup", headers=headers).json()["secret"]
    c.post("/api/auth/totp/enable",
           json={"code": totp._code_at(seed, int(time.time()) // 30)}, headers=headers)
    assert c.post("/api/auth/totp/disable", json={"password": "arch-pw-123"},
                  headers=headers).status_code == 200
    db = Session()
    user = db.query(User).filter(User.username == "arch").one()
    db.close()
    assert user.totp_secret is None and user.totp_last_counter is None


# ---------- The login must not confirm that an account exists ----------

def test_unknown_and_known_accounts_answer_identically(client):
    c, _ = client
    unknown = login(c, "nobody-here", "whatever-123")
    known = login(c, "arch", "wrong-password-123")
    assert unknown.status_code == known.status_code == 401
    assert unknown.json()["detail"] == known.json()["detail"]


def test_a_locked_account_is_not_revealed_to_someone_guessing(client):
    """The lock used to answer 429 for existing accounts only - which both named
    them and let anyone lock them out on purpose."""
    c, _ = client
    for _i in range(8):
        login(c, "arch", "wrong-password-123")

    guessing = login(c, "arch", "still-wrong-123")
    assert guessing.status_code == 401, "the lock is visible without the password"
    unknown = login(c, "nobody-here", "still-wrong-123")
    assert guessing.status_code == unknown.status_code
    assert guessing.json()["detail"] == unknown.json()["detail"]


def test_the_lock_is_still_enforced_for_the_right_password(client):
    """Hiding the lock must not mean dropping it."""
    c, _ = client
    for _i in range(8):
        login(c, "arch", "wrong-password-123")
    blocked = login(c, "arch", "arch-pw-123")
    assert blocked.status_code == 429


def test_the_passkey_endpoint_answers_the_same_for_unknown_accounts(client):
    c, _ = client
    unknown = c.post("/api/auth/passkey/login-options", json={"username": "nobody-here"})
    known = c.post("/api/auth/passkey/login-options", json={"username": "arch"})
    assert unknown.status_code == known.status_code == 400
    assert unknown.json()["detail"] == known.json()["detail"]
