"""Tests for account features: TOTP, activation/reset tokens, user creation."""
import time

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import totp
from app.auth import hash_password, verify_password
from app.database import Base
from app.models import AuthToken, Role, User
from app.routers.users_router import consume_token, issue_token


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(User(id=1, username="alex", password_hash=hash_password("geheim123"),
                     email="alex@example.org", role=Role.architect))
    session.commit()
    yield session
    session.close()


def test_totp_roundtrip():
    secret = totp.new_secret()
    counter = int(time.time()) // 30
    code = totp._code_at(secret, counter)
    assert totp.verify(secret, code)
    assert totp.verify(secret, totp._code_at(secret, counter - 1))  # ±1 window
    assert not totp.verify(secret, "000000") or code == "000000"
    assert not totp.verify(secret, "abc")
    assert not totp.verify("", code)


def test_otpauth_uri():
    uri = totp.otpauth_uri("alex", "ABC234")
    assert uri.startswith("otpauth://totp/Permitra:alex?secret=ABC234")


def test_issue_and_consume_token(db):
    user = db.query(User).one()
    link = issue_token(db, user, "reset")
    raw = link.split("token=")[1]
    resolved, purpose = consume_token(db, raw)
    assert resolved.id == user.id and purpose == "reset"
    db.commit()
    # One-time token: the second use fails
    with pytest.raises(HTTPException):
        consume_token(db, raw)


def test_expired_token_rejected(db):
    user = db.query(User).one()
    raw = issue_token(db, user, "reset").split("token=")[1]
    token = db.query(AuthToken).one()
    from datetime import timedelta
    token.expires_at = token.expires_at - timedelta(hours=100)
    db.commit()
    with pytest.raises(HTTPException):
        consume_token(db, raw)


def test_password_hash_roundtrip():
    stored = hash_password("neuespasswort")
    assert verify_password("neuespasswort", stored)
    assert not verify_password("falsch", stored)
