"""Passkeys: the whole ceremony, and the ways it has to refuse.

Until now not one line of this code was covered. That is the uncomfortable kind
of gap: a second factor is the control that is supposed to hold once the
password has already failed, and it is also the one nobody notices is broken.
A registration that silently stops working produces no error anyone sees, and
an authentication that wrongly *accepts* produces none at all.

It showed when Dependabot proposed webauthn 2.x → 3.0.0 (#17). Every check was
green and every check was meaningless. It was merged after reading the library's
signatures by hand - which worked once and is not a process.

The rejections below matter more than the happy path. Anyone can make a login
succeed; the security property is that it fails for a replayed challenge, a
foreign origin, another user's credential, or a signature that does not verify.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")
# WebAuthn binds a credential to one relying party and one origin. Fixing both
# here means the tests can also assert what happens when they do not match.
os.environ.setdefault("PERMITRA_RP_ID", "permitra.test")
os.environ.setdefault("PERMITRA_ORIGIN", "https://permitra.test")

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from webauthn.helpers import base64url_to_bytes

from app.auth import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import Passkey, Role, User, Vrf
from tests.softauthenticator import SoftAuthenticator

RP_ID = "permitra.test"
ORIGIN = "https://permitra.test"


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    for name in ("arch", "other"):
        s.add(User(username=name, full_name=name, role=Role.architect, is_active=True,
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
    yield TestClient(app, raise_server_exceptions=False), Session
    app.dependency_overrides.clear()


def token_for(c, username):
    r = c.post("/api/auth/login", data={"username": username, "password": f"{username}-pw-123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def challenge_from(response) -> bytes:
    """The options are returned as JSON text, challenge base64url-encoded."""
    return base64url_to_bytes(json.loads(response.text)["challenge"])


def register(c, username="arch", authenticator=None, name="Test key"):
    """Runs the full registration ceremony and returns the authenticator."""
    headers = token_for(c, username)
    options = c.post("/api/auth/passkey/register-options", headers=headers)
    assert options.status_code == 200, options.text

    device = authenticator or SoftAuthenticator()
    credential = device.register(RP_ID, challenge_from(options), ORIGIN)
    done = c.post("/api/auth/passkey/register",
                  json={"credential": credential, "name": name}, headers=headers)
    assert done.status_code == 200, done.text
    return device


def sign_in(c, device, username="arch", **kwargs):
    options = c.post("/api/auth/passkey/login-options", json={"username": username})
    assert options.status_code == 200, options.text
    credential = device.authenticate(RP_ID, challenge_from(options), ORIGIN, **kwargs)
    return c.post("/api/auth/passkey/login",
                  json={"username": username, "credential": credential})


# ---------- The ceremony works end to end ----------

def test_a_registered_passkey_signs_a_user_in(client):
    c, Session = client
    device = register(c)

    response = sign_in(c, device)
    assert response.status_code == 200, response.text
    assert response.json()["user"]["username"] == "arch"

    db = Session()
    stored = db.query(Passkey).one()
    db.close()
    assert stored.name == "Test key"
    assert stored.public_key, "the public key was not stored"


def test_the_signature_counter_moves_with_each_use(client):
    """The one signal WebAuthn gives that a credential has been cloned - it is
    only worth anything if the server actually records it."""
    c, Session = client
    device = register(c)
    sign_in(c, device)
    sign_in(c, device)

    db = Session()
    count = db.query(Passkey).one().sign_count
    db.close()
    assert count == 2, f"the counter stayed at {count}"


def test_a_passkey_can_be_listed_and_removed(client):
    c, _session = client
    register(c)
    headers = token_for(c, "arch")

    listed = c.get("/api/auth/passkeys", headers=headers).json()
    assert len(listed) == 1 and listed[0]["name"] == "Test key"

    assert c.delete(f"/api/auth/passkeys/{listed[0]['id']}", headers=headers).status_code == 204
    assert c.get("/api/auth/passkeys", headers=headers).json() == []


def test_a_second_passkey_can_be_added(client):
    c, _ = client
    register(c, name="First")
    register(c, name="Second")
    assert len(c.get("/api/auth/passkeys", headers=token_for(c, "arch")).json()) == 2


# ---------- The refusals, which are the actual security property ----------

def test_a_challenge_cannot_be_used_twice(client):
    """The challenge store is single-use.

    The second attempt signs the SAME challenge again with an ADVANCED counter.
    That matters: replaying the identical assertion byte for byte is rejected by
    the signature counter instead, so such a test would pass even with the
    challenge store leaking - it did, until a mutation showed it. Here the only
    thing left that can refuse is the consumed challenge.
    """
    c, _ = client
    device = register(c)

    options = c.post("/api/auth/passkey/login-options", json={"username": "arch"})
    challenge = challenge_from(options)

    first = c.post("/api/auth/passkey/login", json={
        "username": "arch", "credential": device.authenticate(RP_ID, challenge, ORIGIN)})
    assert first.status_code == 200

    again = c.post("/api/auth/passkey/login", json={
        "username": "arch", "credential": device.authenticate(RP_ID, challenge, ORIGIN)})
    assert again.status_code in (400, 401), "the challenge was accepted a second time"


def test_an_identical_assertion_replayed_is_refused(client):
    """The other half of the same protection, and the one an eavesdropper would
    actually attempt: the exact same bytes sent twice."""
    c, _ = client
    device = register(c)

    options = c.post("/api/auth/passkey/login-options", json={"username": "arch"})
    credential = device.authenticate(RP_ID, challenge_from(options), ORIGIN)

    assert c.post("/api/auth/passkey/login",
                  json={"username": "arch", "credential": credential}).status_code == 200
    assert c.post("/api/auth/passkey/login",
                  json={"username": "arch", "credential": credential}).status_code in (400, 401)


def test_a_cloned_authenticator_is_refused(client):
    """A counter that does not move means the credential exists in two places.
    It is the only signal WebAuthn offers for that, and it only works if the
    stored counter is compared rather than merely recorded."""
    c, _ = client
    device = register(c)
    assert sign_in(c, device).status_code == 200

    stalled = sign_in(c, device, advance_counter=False)
    assert stalled.status_code == 401, "an authenticator whose counter stood still was accepted"


def test_a_signature_over_the_wrong_challenge_is_refused(client):
    c, _ = client
    device = register(c)

    c.post("/api/auth/passkey/login-options", json={"username": "arch"})
    credential = device.authenticate(RP_ID, b"a challenge nobody issued", ORIGIN)
    response = c.post("/api/auth/passkey/login",
                      json={"username": "arch", "credential": credential})
    assert response.status_code == 401


def test_an_assertion_from_a_foreign_origin_is_refused(client):
    """What stops a phishing page from relaying a real credential."""
    c, _ = client
    device = register(c)

    options = c.post("/api/auth/passkey/login-options", json={"username": "arch"})
    credential = device.authenticate(RP_ID, challenge_from(options), "https://permitra.example.net")
    response = c.post("/api/auth/passkey/login",
                      json={"username": "arch", "credential": credential})
    assert response.status_code == 401


def test_an_assertion_for_a_different_relying_party_is_refused(client):
    c, _ = client
    device = register(c)

    options = c.post("/api/auth/passkey/login-options", json={"username": "arch"})
    credential = device.authenticate("evil.test", challenge_from(options), ORIGIN)
    response = c.post("/api/auth/passkey/login",
                      json={"username": "arch", "credential": credential})
    assert response.status_code == 401


def test_a_credential_that_does_not_verify_is_refused(client):
    """A well-formed signature over the wrong payload: this reaches the
    cryptographic check rather than failing at the parser."""
    c, _ = client
    device = register(c)

    options = c.post("/api/auth/passkey/login-options", json={"username": "arch"})
    credential = device.authenticate(RP_ID, challenge_from(options), ORIGIN)
    from webauthn.helpers import bytes_to_base64url
    credential["response"]["signature"] = bytes_to_base64url(device.sign_garbage(b"x"))

    response = c.post("/api/auth/passkey/login",
                      json={"username": "arch", "credential": credential})
    assert response.status_code == 401


def test_another_users_passkey_does_not_sign_you_in(client):
    """The credential is looked up within the named account, not globally."""
    c, _ = client
    device = register(c, username="arch")

    options = c.post("/api/auth/passkey/login-options", json={"username": "other"})
    assert options.status_code == 400, "'other' has no passkey and should say so uniformly"

    credential = device.authenticate(RP_ID, b"unused", ORIGIN)
    response = c.post("/api/auth/passkey/login",
                      json={"username": "other", "credential": credential})
    assert response.status_code == 401


def test_a_deleted_passkey_no_longer_signs_anyone_in(client):
    c, _ = client
    register(c)
    headers = token_for(c, "arch")
    passkey_id = c.get("/api/auth/passkeys", headers=headers).json()[0]["id"]
    c.delete(f"/api/auth/passkeys/{passkey_id}", headers=headers)

    options = c.post("/api/auth/passkey/login-options", json={"username": "arch"})
    assert options.status_code == 400, "no passkey left, so no options"


def test_you_cannot_delete_someone_elses_passkey(client):
    """The lookup is scoped to the signed-in user. Without that scope, any
    account could strip the second factor from any other and then only need
    the password."""
    c, _ = client
    register(c, username="arch")
    passkey_id = c.get("/api/auth/passkeys", headers=token_for(c, "arch")).json()[0]["id"]

    stolen = c.delete(f"/api/auth/passkeys/{passkey_id}", headers=token_for(c, "other"))
    assert stolen.status_code == 404
    assert len(c.get("/api/auth/passkeys", headers=token_for(c, "arch")).json()) == 1


def test_a_deactivated_account_cannot_use_its_passkey(client):
    c, Session = client
    device = register(c)

    db = Session()
    db.query(User).filter(User.username == "arch").one().is_active = False
    db.commit()
    db.close()

    assert c.post("/api/auth/passkey/login-options",
                  json={"username": "arch"}).status_code == 400
    credential = device.authenticate(RP_ID, b"unused", ORIGIN)
    assert c.post("/api/auth/passkey/login",
                  json={"username": "arch", "credential": credential}).status_code == 401


def test_registration_needs_the_challenge_the_server_issued(client):
    c, _ = client
    headers = token_for(c, "arch")
    c.post("/api/auth/passkey/register-options", headers=headers)

    device = SoftAuthenticator()
    credential = device.register(RP_ID, b"a challenge nobody issued", ORIGIN)
    response = c.post("/api/auth/passkey/register",
                      json={"credential": credential}, headers=headers)
    assert response.status_code == 400


def test_registration_without_asking_for_options_first_is_refused(client):
    """There is no stored challenge to bind the response to."""
    c, _ = client
    device = SoftAuthenticator()
    credential = device.register(RP_ID, b"self-invented", ORIGIN)
    response = c.post("/api/auth/passkey/register",
                      json={"credential": credential}, headers=token_for(c, "arch"))
    assert response.status_code == 400


# ---------- The contract with the library ----------

def test_the_webauthn_api_this_code_relies_on_still_exists():
    """A major bump of the library changed nothing last time, but nothing in CI
    could say so. This makes the next one fail here instead of in production."""
    import inspect

    import webauthn

    expected = {
        "generate_registration_options": {"rp_id", "rp_name", "user_id", "user_name",
                                          "user_display_name", "exclude_credentials"},
        "generate_authentication_options": {"rp_id", "allow_credentials"},
        "verify_registration_response": {"credential", "expected_challenge",
                                         "expected_rp_id", "expected_origin"},
        "verify_authentication_response": {"credential", "expected_challenge",
                                           "expected_rp_id", "expected_origin",
                                           "credential_public_key",
                                           "credential_current_sign_count"},
    }
    for name, arguments in expected.items():
        function = getattr(webauthn, name, None)
        assert function, f"webauthn.{name} is gone"
        parameters = set(inspect.signature(function).parameters)
        missing = arguments - parameters
        assert not missing, f"webauthn.{name} no longer accepts {sorted(missing)}"
