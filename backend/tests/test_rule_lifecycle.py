"""The two states the workflow was missing: `active` and `deleted`.

`approved` used to mean two different things at once - "may exist" and "does
exist". A rule that operations had rolled out everywhere was indistinguishable
from one nobody had touched since the approval, so "approved but never
implemented" was invisible. Splitting them makes that gap readable.

`deleted` turns the soft delete into a state instead of an absence. A rule that
is no longer needed must stay documented and visible; what it must stop doing is
taking effect. Both halves are tested here, because keeping them apart is the
whole point.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

from typing import ClassVar

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    IN_FORCE,
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    RuleVersion,
    SecurityComponent,
    User,
    Vrf,
    active_rules,
)
from app.routers.rules_router import (
    delete_rule,
    fully_implemented,
    get_rule,
    list_rules,
    set_impl_status,
)


class Req:
    headers: ClassVar[dict] = {}

    class client:
        host = "203.0.113.5"


def ops():
    return User(username="ops", role=Role.operations, is_active=True)


def admin():
    return User(username="root", role=Role.admin, is_active=True)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-A", type=ComponentType.juniper))
    s.add(SecurityComponent(id=2, name="FW-B", type=ComponentType.checkpoint))
    s.commit()
    yield s
    s.close()


def make_rule(db, components=(1,), status=RuleStatus.approved, rule_id="SR00001"):
    rule = Rule(rule_id=rule_id, vrf_id=1, name="r", status=status,
                components=[db.get(SecurityComponent, i) for i in components],
                source=[{"ip": "10.0.0.1", "alias": ""}],
                destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}],
                action=RuleAction.permit, version=1)
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


# ---------- approved → active ----------

def test_a_rule_stays_approved_until_every_component_reports_in(db):
    """The point of the split: partial rollout must not read as "in service"."""
    make_rule(db, components=(1, 2))
    set_impl_status("SR00001", {"FW-A": "implemented"}, db=db, user=ops())
    assert db.query(Rule).one().status == RuleStatus.approved


def test_the_last_confirmation_makes_the_rule_active(db):
    make_rule(db, components=(1, 2))
    set_impl_status("SR00001", {"FW-A": "implemented"}, db=db, user=ops())
    set_impl_status("SR00001", {"FW-B": "implemented"}, db=db, user=ops())
    assert db.query(Rule).one().status == RuleStatus.active


def test_the_promotion_is_a_version_of_its_own(db):
    """Otherwise the status change hides inside the rollout report."""
    rule = make_rule(db)
    set_impl_status("SR00001", {"FW-A": "implemented"}, db=db, user=ops())
    notes = [v.change_note for v in db.query(RuleVersion)
             .filter(RuleVersion.rule_pk == rule.id).order_by(RuleVersion.version)]
    assert "active" in notes[-1]
    versions = [v.version for v in db.query(RuleVersion).all()]
    assert len(versions) == len(set(versions)), "version numbers must not repeat"


def test_withdrawing_a_confirmation_takes_the_rule_back_to_approved(db):
    make_rule(db, components=(1, 2))
    set_impl_status("SR00001", {"FW-A": "implemented", "FW-B": "implemented"},
                    db=db, user=ops())
    assert db.query(Rule).one().status == RuleStatus.active
    set_impl_status("SR00001", {"FW-B": "to change"}, db=db, user=ops())
    assert db.query(Rule).one().status == RuleStatus.approved


def test_a_rule_in_review_is_not_promoted(db):
    """The rollout status must not overrule a decision that is still pending."""
    make_rule(db, status=RuleStatus.in_review)
    set_impl_status("SR00001", {"FW-A": "implemented"}, db=db, user=ops())
    assert db.query(Rule).one().status == RuleStatus.in_review


def test_a_deactivated_rule_is_not_promoted(db):
    make_rule(db, status=RuleStatus.deactivated)
    set_impl_status("SR00001", {"FW-A": "implemented"}, db=db, user=ops())
    assert db.query(Rule).one().status == RuleStatus.deactivated


def test_a_rule_without_components_is_never_implemented(db):
    """Nobody can confirm it, so it must not slip into active for free."""
    rule = make_rule(db, components=())
    assert fully_implemented(rule) is False


# ---------- active counts as in force ----------

def test_active_is_in_force(db):
    assert RuleStatus.active in IN_FORCE and RuleStatus.approved in IN_FORCE


def test_an_active_rule_is_exported(db):
    """Checking for `approved` alone after the split would drop exactly the
    rules that are actually on the devices."""
    from app.exporters.hostfw import matching_rules

    make_rule(db, status=RuleStatus.active)
    assert matching_rules(db.query(Rule).all(), "10.0.1.1")


# ---------- deleted stays visible but stops taking effect ----------

def test_deleting_sets_the_status_and_keeps_the_rule(db):
    make_rule(db)
    delete_rule(Req(), "SR00001", db, admin())
    rule = db.query(Rule).one()
    assert rule.status == RuleStatus.deleted
    assert rule.deleted_at is not None


def test_a_deleted_rule_stays_in_the_overview(db):
    make_rule(db)
    delete_rule(Req(), "SR00001", db, admin())
    listed = list_rules(q=None, limit=50, offset=0, source=None, destination=None,
                        port=None, protocol=None, rule_status=None, impl=None,
                        risk=None, application=None, app_id=None, platform=None,
                        component=None, vrf=None, updated_since=None,
                        db=db, _user=admin())
    ids = [r.rule_id for r in listed.items]
    assert "SR00001" in ids, "a deleted rule must remain documented"


def test_a_deleted_rule_can_still_be_opened(db):
    """The record is the evidence - a 404 would hide it."""
    make_rule(db)
    delete_rule(Req(), "SR00001", db, admin())
    assert get_rule("SR00001", db=db, _user=admin()).status == RuleStatus.deleted


def test_a_deleted_rule_no_longer_takes_effect(db):
    """Visible and in force are different things; only the first survives."""
    make_rule(db, status=RuleStatus.active)
    delete_rule(Req(), "SR00001", db, admin())
    assert active_rules(db).count() == 0


def test_a_deleted_rule_is_not_exported(db):
    from app.exporters.hostfw import matching_rules

    make_rule(db, status=RuleStatus.active)
    delete_rule(Req(), "SR00001", db, admin())
    assert matching_rules(active_rules(db).all(), "10.0.1.1") == []


def test_deleting_twice_changes_nothing(db):
    make_rule(db)
    delete_rule(Req(), "SR00001", db, admin())
    first = db.query(Rule).one().deleted_at
    delete_rule(Req(), "SR00001", db, admin())
    assert db.query(Rule).one().deleted_at == first
