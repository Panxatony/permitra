"""The first admin password must never reach the log.

It used to be logged, which in the kind of installation this is built for means
stdout → docker logs → a log aggregator: a durable, replicated, widely readable
store holding a working administrator credential for the system that documents
who may open which firewall rule.

These tests pin the three ways out of that: the operator supplies the password,
or it is written to a file only they can read, or startup is refused. What none
of them do is log it.
"""
import logging
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import seed
from app.auth import verify_password
from app.database import Base
from app.models import Role, User


@pytest.fixture()
def db(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    monkeypatch.setattr(seed, "SessionLocal", Session)
    monkeypatch.delenv("PERMITRA_DEMO", raising=False)
    monkeypatch.delenv("PERMITRA_INITIAL_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("PERMITRA_INITIAL_ADMIN_PASSWORD_FILE", raising=False)
    return Session


def admin_of(Session) -> User:
    s = Session()
    user = s.query(User).filter(User.username == "admin").one()
    s.expunge(user)
    s.close()
    return user


# ---------- The password never appears in the log ----------

def test_the_password_is_not_logged(db, tmp_path, monkeypatch, caplog):
    """The finding itself: a credential in a stream that gets shipped off-host."""
    target = tmp_path / "initial-admin-password.txt"
    monkeypatch.setenv("PERMITRA_INITIAL_ADMIN_PASSWORD_FILE", str(target))
    with caplog.at_level(logging.DEBUG):
        seed.seed_users()

    password = target.read_text().strip()
    assert password, "no password was written"
    assert password not in caplog.text, "the password is in the log"
    # The path is what the operator needs, and it is there.
    assert str(target) in caplog.text


def test_the_file_is_readable_only_by_its_owner(db, tmp_path, monkeypatch):
    target = tmp_path / "pw.txt"
    monkeypatch.setenv("PERMITRA_INITIAL_ADMIN_PASSWORD_FILE", str(target))
    seed.seed_users()
    assert oct(target.stat().st_mode)[-3:] == "600"


def test_the_written_password_actually_works(db, tmp_path, monkeypatch):
    """A file nobody can sign in with would be worse than the log."""
    target = tmp_path / "pw.txt"
    monkeypatch.setenv("PERMITRA_INITIAL_ADMIN_PASSWORD_FILE", str(target))
    seed.seed_users()
    assert verify_password(target.read_text().strip(), admin_of(db).password_hash)


# ---------- The supplied password is used and stays quiet ----------

def test_a_supplied_password_is_used_and_no_file_is_written(db, tmp_path, monkeypatch, caplog):
    target = tmp_path / "should-not-exist.txt"
    monkeypatch.setenv("PERMITRA_INITIAL_ADMIN_PASSWORD", "operator-chosen-pw-123")
    monkeypatch.setenv("PERMITRA_INITIAL_ADMIN_PASSWORD_FILE", str(target))
    with caplog.at_level(logging.DEBUG):
        seed.seed_users()

    assert verify_password("operator-chosen-pw-123", admin_of(db).password_hash)
    assert not target.exists(), "nothing needs handing back when the operator knows it"
    assert "operator-chosen-pw-123" not in caplog.text


# ---------- Fail-secure rather than falling back to logging ----------

def test_startup_is_refused_when_the_file_cannot_be_written(db, monkeypatch, caplog):
    """The point of the change: no unsafe fallback. Same stance auth.py takes
    on a missing SECRET_KEY."""
    monkeypatch.setenv("PERMITRA_INITIAL_ADMIN_PASSWORD_FILE", "/proc/permitra/nope.txt")
    with caplog.at_level(logging.DEBUG), pytest.raises(RuntimeError, match="fail-secure"):
        seed.seed_users()
    assert "password" not in caplog.text.lower() or "written to" not in caplog.text


def test_no_admin_is_created_when_the_password_cannot_be_delivered(db, monkeypatch):
    """Otherwise an account would exist that nobody can sign in to."""
    monkeypatch.setenv("PERMITRA_INITIAL_ADMIN_PASSWORD_FILE", "/proc/permitra/nope.txt")
    with pytest.raises(RuntimeError):
        seed.seed_users()
    s = db()
    assert s.query(User).count() == 0
    s.close()


# ---------- The surrounding behaviour is unchanged ----------

def test_demo_mode_still_creates_the_well_known_accounts(db, monkeypatch):
    monkeypatch.setenv("PERMITRA_DEMO", "1")
    seed.seed_users()
    s = db()
    names = {u.username for u in s.query(User).all()}
    s.close()
    assert {"admin", "architekt", "betrieb", "approver", "approver2"} <= names


def test_an_existing_installation_is_left_alone(db, tmp_path, monkeypatch):
    """Seeding runs on every start; it must not mint a second admin."""
    s = db()
    s.add(User(username="someone", password_hash="x", role=Role.admin, is_active=True))
    s.commit()
    s.close()

    target = tmp_path / "pw.txt"
    monkeypatch.setenv("PERMITRA_INITIAL_ADMIN_PASSWORD_FILE", str(target))
    seed.seed_users()
    assert not target.exists()
    s = db()
    assert s.query(User).count() == 1
    s.close()
