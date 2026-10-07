"""SECRET_KEY can be rotated without locking anyone out, and each use of it
has a key of its own.

The raw secret signed session tokens, and sha256 of it encrypted both the
TOTP seeds and the NetBox token: one secret, three uses, no separation.
Rotating it made every seed unreadable; the login treated that as wrong
codes, five of them locked the account, and no admin function could undo
it. These tests walk a rotation end to end and the two ways out of a seed
nobody can read.
"""
import base64
import hashlib
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import jwt
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import auth, crypto, key_rotation, totp
from app.auth import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import AuditEvent, NetboxConfig, Role, User, Vrf

KEY_A, KEY_B = "a" * 64, "b" * 64


@pytest.fixture()
def keys(monkeypatch):
    """Start under KEY_A with no previous key; the test moves on from there."""
    monkeypatch.setattr(auth, "SECRET_KEY", KEY_A)
    monkeypatch.setattr(auth, "PREVIOUS_SECRET_KEYS", [])

    def switch(current, previous=()):
        monkeypatch.setattr(auth, "SECRET_KEY", current)
        monkeypatch.setattr(auth, "PREVIOUS_SECRET_KEYS", list(previous))
    return switch


def legacy_ciphertext(secret: str, raw: str) -> str:
    """What encrypt() produced before: one sha256-derived key for everything."""
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())).encrypt(raw.encode()).decode()


# ---------- derivation ----------

def test_each_purpose_has_its_own_key(keys):
    enc = crypto.encrypt("JBSWY3DPEHPK3PXP", "totp")
    assert crypto.decrypt(enc, "totp") == "JBSWY3DPEHPK3PXP"
    assert crypto.decrypt(enc, "netbox") == ""
    assert auth.derive_key(KEY_A, "jwt") != auth.derive_key(KEY_A, "totp")


def test_a_value_from_before_the_derivation_still_reads_and_is_not_current(keys):
    old = legacy_ciphertext(KEY_A, "seed")
    assert crypto.decrypt(old, "totp") == "seed"
    assert not crypto.is_current(old, "totp")
    fresh = crypto.reencrypt(old, "totp")
    assert crypto.is_current(fresh, "totp") and crypto.decrypt(fresh, "totp") == "seed"


# ---------- the rotation ----------

def test_a_rotation_keeps_the_previous_key_readable_until_everything_is_rewritten(keys):
    under_a = crypto.encrypt("seed", "totp")
    keys(KEY_B, previous=[KEY_A])
    assert crypto.decrypt(under_a, "totp") == "seed"
    assert not crypto.is_current(under_a, "totp")
    under_b = crypto.reencrypt(under_a, "totp")
    keys(KEY_B)
    assert crypto.decrypt(under_a, "totp") == "", "the previous key is gone, and so is what it protected"
    assert crypto.decrypt(under_b, "totp") == "seed"


def test_a_session_signed_under_the_previous_key_or_the_raw_secret_still_decodes(keys):
    user = User(username="arch", role=Role.architect, is_active=True, password_hash="x")
    user.id = 1
    derived = auth.create_token(user)
    raw = jwt.encode({"sub": "arch", "iat": 1, "exp": 4102444800}, KEY_A, algorithm="HS256")
    keys(KEY_B, previous=[KEY_A])
    assert auth.decode_token(derived)["sub"] == "arch"
    assert auth.decode_token(raw)["sub"] == "arch"
    keys(KEY_B)
    with pytest.raises(jwt.PyJWTError):
        auth.decode_token(derived)


def test_the_startup_job_rewrites_seeds_and_the_netbox_token_and_names_what_it_cannot(keys):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(User(username="u1", password_hash="x", totp_enabled=True,
                totp_secret=crypto.encrypt("seed1", "totp")))
    db.add(User(username="u2", password_hash="x", totp_enabled=True,
                totp_secret=legacy_ciphertext("z" * 64, "seed2")))   # a key nobody has
    db.add(NetboxConfig(url="https://netbox.example.org", token_enc=crypto.encrypt("tok", "netbox")))
    db.commit()
    keys(KEY_B, previous=[KEY_A])
    result = key_rotation.reencrypt_all(db)
    assert result == {"rewritten": 2, "unreadable": ["u2"]}
    keys(KEY_B)
    assert crypto.decrypt(db.query(User).filter_by(username="u1").one().totp_secret, "totp") == "seed1"
    assert crypto.decrypt(db.query(NetboxConfig).one().token_enc, "netbox") == "tok"
    u2 = db.query(User).filter_by(username="u2").one()
    assert u2.totp_secret.startswith("gAAAA"), "left alone, not overwritten"
    db.close()


# ---------- the two ways out of an unreadable seed ----------

@pytest.fixture()
def client(keys):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    s.add(User(username="adm", full_name="adm", role=Role.admin, is_active=True,
               password_hash=hash_password("adm-pw-12345")))
    s.add(User(username="arch", full_name="arch", role=Role.architect, is_active=True,
               password_hash=hash_password("arch-pw-12345"), totp_enabled=True,
               totp_secret=legacy_ciphertext("z" * 64, totp.new_secret())))
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


def test_an_unreadable_seed_refuses_the_login_with_a_reason_and_no_strike(client):
    c, Session = client
    for _ in range(6):
        r = c.post("/api/auth/login", data={"username": "arch", "password": "arch-pw-12345", "otp": "123456"})
    assert r.status_code == 401
    assert "administrator" in r.json()["detail"]
    db = Session()
    user = db.query(User).filter_by(username="arch").one()
    assert user.failed_logins == 0 and user.locked_until is None
    assert db.query(AuditEvent).filter(AuditEvent.detail == "2FA seed unreadable").count() == 6
    db.close()


def test_the_admin_sees_the_state_and_can_reset_it(client):
    c, Session = client
    r = c.post("/api/auth/login", data={"username": "adm", "password": "adm-pw-12345"})
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    listed = {u["username"]: u for u in c.get("/api/users", headers=headers).json()}
    assert listed["arch"]["totp_unreadable"] is True
    assert listed["adm"]["totp_unreadable"] is False

    own = c.post("/api/users/adm/reset-totp", headers=headers)
    assert own.status_code == 400

    reset = c.post("/api/users/arch/reset-totp", headers=headers)
    assert reset.status_code == 200 and reset.json()["totp_enabled"] is False
    back_in = c.post("/api/auth/login", data={"username": "arch", "password": "arch-pw-12345"})
    assert back_in.status_code == 200
    db = Session()
    assert db.query(AuditEvent).filter(AuditEvent.event == "user.totp_reset").count() == 1
    db.close()


def test_only_an_admin_resets(client):
    c, _ = client
    r = c.post("/api/auth/login", data={"username": "adm", "password": "adm-pw-12345"})
    assert r.status_code == 200
    anon = c.post("/api/users/arch/reset-totp")
    assert anon.status_code == 401
