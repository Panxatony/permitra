"""An audit entry that does not fit its columns must still be an audit entry.

PostgreSQL refuses a value longer than its column. The audit write swallowed
that refusal - auditing must not take the business operation down - so the
event was simply gone: no row, no gap in the chain, nothing for the SIEM. A
login attempt with a username of 65 characters was enough to keep that
attempt out of the log. Values are cut to their columns now, BEFORE the hash
is computed, so the chain verifies and the cut is visible in the entry.

SQLite does not enforce widths, which is why none of this ever failed a test
run; these tests therefore assert on the stored length, not on an error.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import audit
from app.database import Base, get_db
from app.main import app
from app.models import AuditEvent, Vrf


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def test_an_over_long_actor_is_cut_to_the_column_and_the_chain_verifies(db):
    audit.record(db, "auth", "auth.login_failed", actor="x" * 300, source_ip="203.0.113.1")
    row = db.query(AuditEvent).one()
    assert len(row.actor) == 64
    assert row.actor.endswith("…")
    assert row.extra[audit.TRUNCATED] == ["actor"]
    assert audit.verify_chain(db)["ok"] is True


def test_an_over_long_detail_and_its_values_are_capped(db):
    audit.record(db, "rule", "rule.reviewed", actor="appr", object="SR00001",
                 detail="d" * 10_000, detail_values={"comment": "c" * 10_000, "n": 3})
    row = db.query(AuditEvent).one()
    assert len(row.detail) == audit.DETAIL_MAX
    assert len(row.extra[audit.DETAIL_VALUES]["comment"]) == audit.DETAIL_MAX
    assert row.extra[audit.DETAIL_VALUES]["n"] == 3
    assert row.extra[audit.TRUNCATED] == ["detail", "detail_values.comment"]
    assert audit.verify_chain(db)["ok"] is True


def test_a_value_that_fits_is_stored_as_is(db):
    """The cut must not touch what fits, and must not mark it."""
    audit.record(db, "admin", "setting.changed", actor="root", object="k" * 128)
    row = db.query(AuditEvent).one()
    assert row.object == "k" * 128
    assert audit.TRUNCATED not in (row.extra or {})


def test_a_failed_login_with_a_long_username_is_still_logged():
    """The endpoint needs no session, so this was a way to hide attempts."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    s.commit()
    s.close()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    try:
        c = TestClient(app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", data={"username": "u" * 100, "password": "whatever-123"})
        assert r.status_code == 401
    finally:
        app.dependency_overrides.clear()
    db = Session()
    rows = db.query(AuditEvent).filter(AuditEvent.event == "auth.login_failed").all()
    db.close()
    assert len(rows) == 1
    assert len(rows[0].actor) == 64
