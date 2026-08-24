"""Tests for email notifications (issue #5)."""
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
             email="", is_active=True, notify_email=True),                  # no address
        User(username="bob", password_hash="x", role=Role.operations,
             email="bob@example.org", is_active=True, notify_email=True),
        # An admin who wants mail and could receive it. Present so the exact-set
        # assertions below actually guard the recipient list: without an admin
        # in the fixture they proved nothing about admins either way.
        User(username="root", password_hash="x", role=Role.admin,
             email="root@example.org", is_active=True, notify_email=True),
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
    db.add(r)
    db.commit()
    return r


@pytest.fixture(autouse=True)
def _smtp_on(monkeypatch):
    # Simulate the mailer as "enabled" and intercept the sending
    sent = []
    monkeypatch.setattr(mailer, "enabled", lambda: True)
    monkeypatch.setattr(mailer, "base_url", lambda: "https://permitra.example.org")
    monkeypatch.setattr(mailer, "send", lambda to, subj, body: (sent.append((to, subj)) or True))
    return sent


def test_submitted_notifies_only_optin_approvers_with_email(db, _smtp_on):
    notifications.rule_submitted(db, make_rule(db))
    to = {t for t, _ in _smtp_on}
    assert to == {"chris@example.org"}  # kim (opt-out) and noemail (no address) drop out


def test_decided_notifies_creator(db, _smtp_on):
    notifications.rule_decided(db, make_rule(db), approved=True, decided_by="chris", comment="ok")
    assert {t for t, _ in _smtp_on} == {"alex@example.org"}


def test_implementation_pending_notifies_operations(db, _smtp_on):
    notifications.rule_implementation_pending(db, make_rule(db), "Rule approved")
    assert {t for t, _ in _smtp_on} == {"bob@example.org"}


def test_an_admin_is_not_mailed_about_work_it_cannot_do(db, _smtp_on):
    """An admin installs and administers Permitra; it reaches neither the
    reviews nor the recertification (#81, #82). Mailing it about a rule waiting
    for approval would point it at a page that answers 403 - and a notification
    that leads nowhere teaches people to ignore the rest."""
    rule = make_rule(db)
    notifications.rule_submitted(db, rule)
    notifications.rule_implementation_pending(db, rule, "Rule approved")
    assert "root@example.org" not in {t for t, _ in _smtp_on}


def test_someone_who_holds_both_roles_is_still_reached(db, _smtp_on):
    """The counter-check, and the reason this is keyed on the role set rather
    than on the job title: an admin who is also a change approver does the
    reviewing, so they are mailed through that role (#78)."""
    from app.models import apply_roles
    root = db.query(User).filter(User.username == "root").one()
    apply_roles(root, [Role.admin, Role.change_approver])
    db.commit()

    notifications.rule_submitted(db, make_rule(db))
    assert "root@example.org" in {t for t, _ in _smtp_on}


def test_disabled_mailer_sends_nothing(db, monkeypatch):
    monkeypatch.setattr(mailer, "enabled", lambda: False)
    sent = []
    monkeypatch.setattr(mailer, "send", lambda *a: sent.append(a))
    notifications.rule_submitted(db, make_rule(db))
    assert sent == []
