"""Tests for read-only API tokens (issue #14)."""
import hashlib

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import auth
from app.database import Base
from app.models import ApiToken, utcnow


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


class FakeReq:
    def __init__(self, method):
        self.method = method


# A fixture value, not a credential: the tests hash it and check the lookup.
FIXTURE_TOKEN = "pat_secret123"  # skipcq: SCT-A000


def _make(db, raw=FIXTURE_TOKEN, revoked=False, expires_at=None):
    t = ApiToken(name="ansible", prefix=raw[:12],
                 token_hash=hashlib.sha256(raw.encode()).hexdigest(),
                 revoked=revoked, expires_at=expires_at)
    db.add(t)
    db.commit()
    return t


def test_pat_allows_get_readonly(db):
    _make(db)
    principal = auth.get_current_user(request=FakeReq("GET"), token=FIXTURE_TOKEN, db=db)
    assert principal.username == "token:ansible"
    assert getattr(principal, "is_service_token", False)


def test_pat_blocks_write_methods(db):
    _make(db)
    for method in ("POST", "PUT", "DELETE"):
        with pytest.raises(HTTPException) as exc:
            auth.get_current_user(request=FakeReq(method), token=FIXTURE_TOKEN, db=db)
        assert exc.value.status_code == 403


def test_revoked_token_rejected(db):
    _make(db, revoked=True)
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(request=FakeReq("GET"), token=FIXTURE_TOKEN, db=db)
    assert exc.value.status_code == 401


def test_expired_token_rejected(db):
    from datetime import timedelta
    _make(db, expires_at=utcnow() - timedelta(days=1))
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(request=FakeReq("GET"), token=FIXTURE_TOKEN, db=db)
    assert exc.value.status_code == 401
