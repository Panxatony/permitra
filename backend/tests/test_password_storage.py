"""A password hash has to say how it was made, and a password has to be more
than eight characters of anything.

The stored hash was `<salt>$<digest>` with the iteration count hard-coded, so
the cost could not be raised without invalidating every hash, and nothing
ever rewrote an old one. Three endpoints set passwords and each checked one
thing: eight characters. The username was a valid password, so was
`password1`, so was a megabyte of text.
"""
import hashlib
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import auth, passwords
from app.database import Base, get_db
from app.main import app
from app.models import Role, User, Vrf


def legacy_hash(password: str, salt: str = "ab" * 16) -> str:
    """What every hash looked like before the format carried its cost."""
    return f"{salt}${hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200_000).hex()}"


# ---------- the format ----------

def test_a_new_hash_states_its_algorithm_and_cost():
    stored = auth.hash_password("correct horse battery")
    algorithm, iterations, salt, digest = stored.split("$")
    assert algorithm == "pbkdf2_sha256"
    assert int(iterations) == auth.PBKDF2_ITERATIONS
    assert len(salt) == 32 and len(digest) == 64
    assert auth.verify_password("correct horse battery", stored)
    assert not auth.verify_password("wrong", stored)
    assert not auth.needs_rehash(stored)


def test_a_legacy_hash_still_verifies_and_asks_to_be_rewritten():
    stored = legacy_hash("neuespasswort")
    assert auth.verify_password("neuespasswort", stored)
    assert not auth.verify_password("falsch", stored)
    assert auth.needs_rehash(stored)


def test_a_hash_below_the_current_cost_asks_to_be_rewritten():
    cheap = auth.hash_password("x" * 12, iterations=max(1, auth.PBKDF2_ITERATIONS - 1))
    assert auth.verify_password("x" * 12, cheap)
    assert auth.needs_rehash(cheap)


def test_an_unreadable_hash_verifies_nothing():
    assert not auth.verify_password("anything", "")
    assert not auth.verify_password("anything", "garbage")


# ---------- the upgrade happens on login ----------

@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    s.add(User(username="old", full_name="old", email="old@example.org", role=Role.architect,
               is_active=True, password_hash=legacy_hash("old-pw-12345")))
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


def stored_hash(Session, username):
    db = Session()
    try:
        return db.query(User).filter(User.username == username).one().password_hash
    finally:
        db.close()


def test_a_legacy_hash_is_rewritten_on_the_next_login(client):
    c, Session = client
    assert not stored_hash(Session, "old").startswith("pbkdf2_sha256$")
    r = c.post("/api/auth/login", data={"username": "old", "password": "old-pw-12345"})
    assert r.status_code == 200, r.text
    after = stored_hash(Session, "old")
    assert after.startswith(f"pbkdf2_sha256${auth.PBKDF2_ITERATIONS}$")
    assert auth.verify_password("old-pw-12345", after)
    # and a second login leaves it alone
    c.post("/api/auth/login", data={"username": "old", "password": "old-pw-12345"})
    assert stored_hash(Session, "old") == after


def test_a_wrong_password_does_not_rewrite_anything(client):
    c, Session = client
    before = stored_hash(Session, "old")
    c.post("/api/auth/login", data={"username": "old", "password": "wrong-pw-12345"})
    assert stored_hash(Session, "old") == before


# ---------- the policy ----------

@pytest.mark.parametrize("password, fragment", [
    ("short", "at least 8"),
    ("x" * 129, "at most 128"),
    ("password1", "too common"),
    ("Password1", "too common"),
    ("mmustermann2024", "username"),
    ("my-max-secret", "username"),          # the e-mail's local part
])
def test_the_policy_refuses(password, fragment):
    reason = passwords.problem(password, "mmustermann", "max@example.org")
    assert reason and fragment in reason


def test_the_policy_accepts_a_reasonable_passphrase():
    assert passwords.problem("correct horse battery staple", "mmustermann", "max@example.org") is None


def test_the_blocklist_is_bundled():
    assert len(passwords.common_passwords()) > 9000


def test_every_endpoint_that_sets_a_password_enforces_the_policy(client):
    c, _session = client
    login = c.post("/api/auth/login", data={"username": "old", "password": "old-pw-12345"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    r = c.post("/api/auth/change-password", json={"current": "old-pw-12345", "new": "password1"},
               headers=headers)
    assert r.status_code == 422 and "too common" in r.json()["detail"]
    with pytest.raises(HTTPException) as exc:
        passwords.enforce("old-and-more", "old", "")
    assert exc.value.status_code == 422
