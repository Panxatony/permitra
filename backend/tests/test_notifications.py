"""Tests für E-Mail-Benachrichtigungen (Issue #5)."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import mailer, notifications
from app.database import Base
from app.models import Role, Rule, RuleAction, RuleStatus, User, Vrf


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add_all([
        User(username="alex", password_hash="x", role=Role.architect,
             email="alex@example.org", is_active=True, notify_email=True),
        User(username="chris", password_hash="x", role=Role.change_approver,
             email="chris@example.org", is_active=True, notify_email=True),
        User(username="kim", password_hash="x", role=Role.change_approver,
             email="kim@example.org", is_active=True, notify_email=False),  # Opt-out
        User(username="noemail", password_hash="x", role=Role.change_approver,
             email="", is_active=True, notify_email=True),                  # ohne Mail
        User(username="bob", password_hash="x", role=Role.operations,
             email="bob@example.org", is_active=True, notify_email=True),
    ])
    s.commit()
    yield s
    s.close()


def make_rule(db, created_by="alex"):
    r = Rule(rule_id="SR00001", vrf_id=1, name="HTTPS",
             source=[{"ip": "10.0.0.1", "alias": ""}], destination=[{"ip": "10.0.0.2", "alias": ""}],
             services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
             status=RuleStatus.in_review, source_zone="A", destination_zone="B",
             created_by=created_by, requestor="alex")
    db.add(r); db.commit()
    return r


@pytest.fixture(autouse=True)
def _smtp_on(monkeypatch):
    # Mailer als "aktiv" simulieren und Versand abfangen
    sent = []
    monkeypatch.setattr(mailer, "enabled", lambda: True)
    monkeypatch.setattr(mailer, "base_url", lambda: "https://permitra.example.org")
    monkeypatch.setattr(mailer, "send", lambda to, subj, body: (sent.append((to, subj)) or True))
    return sent


def test_submitted_notifies_only_optin_approvers_with_email(db, _smtp_on):
    notifications.rule_submitted(db, make_rule(db))
    to = {t for t, _ in _smtp_on}
    assert to == {"chris@example.org"}  # kim (opt-out) und noemail (ohne Mail) raus


def test_decided_notifies_creator(db, _smtp_on):
    notifications.rule_decided(db, make_rule(db), approved=True, decided_by="chris", comment="ok")
    assert {t for t, _ in _smtp_on} == {"alex@example.org"}


def test_implementation_pending_notifies_operations(db, _smtp_on):
    notifications.rule_implementation_pending(db, make_rule(db), "Regel freigegeben")
    assert {t for t, _ in _smtp_on} == {"bob@example.org"}


def test_disabled_mailer_sends_nothing(db, monkeypatch):
    monkeypatch.setattr(mailer, "enabled", lambda: False)
    sent = []
    monkeypatch.setattr(mailer, "send", lambda *a: sent.append(a))
    notifications.rule_submitted(db, make_rule(db))
    assert sent == []
