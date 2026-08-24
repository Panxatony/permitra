"""One account, several roles - without opening a hole in separation of duties.

Real deployments are smaller than the role split assumes: the same person is
architect *and* operations, or an approver who also writes rules (#78). An
account therefore holds a set of roles and its permission is their union.

The union widens who reaches an endpoint. It must not widen what one person can
carry alone, and that is what these tests are for. Both four-eyes invariants key
on the acting *account*, never on a role, because the account is the person - so
wearing two hats is still one pair of eyes:

- an account that is architect and change_approver cannot approve the rule it
  requested, created or submitted (but may approve everyone else's), and
- the two approvals on a zone or matrix change must come from two different
  accounts, so one multi-role account cannot supply both halves.

Get these backwards and multi-role quietly dismantles the control the product
exists to provide, which is why they are the first tests here and not the last.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    UserRole,
    Vrf,
    Zone,
    ZoneNetwork,
    ZonePolicyChange,
    apply_roles,
    primary_role,
)
from app.routers.rules_router import ReviewDecision, _decide
from app.routers.zones_router import _create_batch, _decide_change


class Req:
    headers: dict = {}  # noqa: RUF012

    class client:
        host = "203.0.113.9"


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    s.add_all([Zone(name="PROD-APP", sort_order=1), Zone(name="DMZ-WEB", sort_order=2)])
    s.flush()
    s.add(ZoneNetwork(cidr="10.10.30.0/24", zone_id=1, vrf_id=1, description="App"))
    s.commit()
    yield s
    s.close()


def account(db, name, *roles, commit=True):
    user = User(username=name, password_hash="x", is_active=True)
    apply_roles(user, list(roles))
    db.add(user)
    if commit:
        db.commit()
    return user


def make_rule(db, rule_id="SR00001", *, requestor, created_by=None, status=RuleStatus.in_review):
    rule = Rule(rule_id=rule_id, vrf_id=1, name=rule_id.lower(),
                requestor=requestor, created_by=created_by or requestor,
                components=[db.get(SecurityComponent, 1)],
                source=[{"ip": "10.0.0.1", "alias": ""}],
                destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}],
                action=RuleAction.permit, status=status,
                source_zone="PROD-APP", destination_zone="DMZ-WEB")
    db.add(rule)
    db.commit()
    return rule


def approve(db, rule_id, user):
    return _decide(db, rule_id, user, ReviewDecision(), RuleStatus.approved, "Rule approved")


# ---------- invariant 1: no approving your own rule, however many hats ----------

def test_a_two_hat_account_cannot_approve_the_rule_it_requested(db):
    """The headline of the issue. Holding change_approver does not make the
    requestor a second person."""
    both = account(db, "mia", Role.architect, Role.change_approver)
    make_rule(db, "SR00001", requestor="mia", created_by="mia")

    with pytest.raises(HTTPException) as exc:
        approve(db, "SR00001", both)
    assert exc.value.status_code == 403


def test_a_two_hat_account_cannot_approve_a_rule_it_only_requested(db):
    """Requestor alone is enough to be refused - even when somebody else typed
    the rule in. The requestor is the person accountable for it."""
    both = account(db, "mia", Role.architect, Role.change_approver)
    account(db, "tom", Role.architect)
    make_rule(db, "SR00001", requestor="mia", created_by="tom")

    with pytest.raises(HTTPException) as exc:
        approve(db, "SR00001", both)
    assert exc.value.status_code == 403


def test_the_same_account_may_still_approve_somebody_elses_rule(db):
    """The counter-check that keeps the feature useful: multi-role is refused on
    its own rules, not disarmed everywhere. Without this, the two tests above
    would also pass if approval were simply broken."""
    both = account(db, "mia", Role.architect, Role.change_approver)
    account(db, "tom", Role.architect)
    make_rule(db, "SR00001", requestor="tom", created_by="tom")

    result = approve(db, "SR00001", both)
    assert result.status == RuleStatus.approved


# ---------- invariant 2: two approvals means two accounts ----------

def test_one_multi_role_account_cannot_give_both_zone_approvals(db):
    """A zone or matrix change needs two approvals from two different change
    approvers. An account holding several roles is still one account, so it
    cannot supply the second half of its own first approval."""
    architect = account(db, "alex", Role.architect)
    both = account(db, "mia", Role.architect, Role.change_approver)

    _create_batch(db, architect, [
        {"type": "net_add", "zone": "DMZ-WEB", "cidr": "10.10.99.0/24", "description": "Neu"},
    ], "")
    change = db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()

    first = _decide_change(db, change.id, both, True, "")
    assert first["approvals"] == "1/2"

    with pytest.raises(HTTPException) as exc:
        _decide_change(db, change.id, both, True, "")
    assert exc.value.status_code == 403
    # and the change really did not take effect
    assert not db.query(ZoneNetwork).filter(ZoneNetwork.cidr == "10.10.99.0/24").first()


def test_a_multi_role_account_cannot_approve_a_change_it_requested(db):
    """The same account requesting and then approving is one person twice, no
    matter which of its roles did which."""
    both = account(db, "mia", Role.architect, Role.change_approver)
    _create_batch(db, both, [
        {"type": "net_add", "zone": "DMZ-WEB", "cidr": "10.10.99.0/24", "description": "Neu"},
    ], "")
    change = db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()

    with pytest.raises(HTTPException) as exc:
        _decide_change(db, change.id, both, True, "")
    assert exc.value.status_code == 403


def test_two_different_accounts_still_complete_the_change(db):
    """Counter-check: the four-eyes path still works, so the refusals above are
    about the second person being the same one, not about approval being broken."""
    architect = account(db, "alex", Role.architect)
    both = account(db, "mia", Role.architect, Role.change_approver)
    approver = account(db, "kim", Role.change_approver)

    _create_batch(db, architect, [
        {"type": "net_add", "zone": "DMZ-WEB", "cidr": "10.10.99.0/24", "description": "Neu"},
    ], "")
    change = db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()
    _decide_change(db, change.id, both, True, "")
    _decide_change(db, change.id, approver, True, "")

    assert db.query(ZoneNetwork).filter(ZoneNetwork.cidr == "10.10.99.0/24").one()


# ---------- the union itself ----------

def test_permission_is_the_union_of_the_roles(db):
    both = account(db, "mia", Role.architect, Role.operations)
    assert both.has_role(Role.architect)
    assert both.has_role(Role.operations)
    assert not both.has_role(Role.change_approver)
    assert not both.has_role(Role.admin)


def test_has_role_admits_through_any_held_role(db):
    """require_roles(...) means "any of these", and an account can now match
    through more than one of its own."""
    both = account(db, "mia", Role.operations, Role.change_approver)
    # the shape require_roles uses
    assert both.has_role(Role.architect, Role.operations)
    assert not both.has_role(Role.architect, Role.admin)


def test_an_admin_may_also_hold_a_working_role(db):
    """Admin is deliberately not a superuser (#71); admin+architect is two hats
    on one person, which is the case this feature is for. The four-eyes checks
    apply to it like any other account."""
    both = account(db, "mia", Role.admin, Role.architect)
    assert both.has_role(Role.admin) and both.has_role(Role.architect)

    make_rule(db, "SR00001", requestor="mia", created_by="mia")
    with pytest.raises(HTTPException) as exc:
        approve(db, "SR00001", both)
    assert exc.value.status_code == 403


def test_the_primary_role_is_derived_not_stored_separately(db):
    """The badge must never promise something the permission set does not back."""
    both = account(db, "mia", Role.operations, Role.admin)
    assert both.role == Role.admin           # highest precedence wins
    assert set(both.roles) == {Role.operations, Role.admin}


def test_an_account_must_hold_at_least_one_role(db):
    """An account with no roles can sign in and reach nothing - a broken account
    rather than a deliberate one."""
    user = User(username="ghost", password_hash="x")
    with pytest.raises(ValueError):
        apply_roles(user, [])


# ---------- the set is what SQL asks, so it must always be there ----------

def test_an_account_written_with_only_a_role_still_lands_in_the_set(db):
    """Permission lookups ask the set in SQL, where a Python-side fallback
    cannot reach. An account built the old way (fixtures, scripts, older code)
    must still be found by "who holds role X" - otherwise it would authorise
    in-process but be invisible to every such query."""
    db.add(User(username="old", password_hash="x", role=Role.change_approver))
    db.commit()

    found = (db.query(User)
             .filter(User.role_rows.any(UserRole.role == Role.change_approver))
             .all())
    assert [u.username for u in found] == ["old"]


def test_a_role_query_finds_an_account_through_its_secondary_role(db):
    """The union has to be visible to the lookups too, not just to has_role -
    an architect+operations account belongs in the operations recipient list."""
    account(db, "mia", Role.architect, Role.operations)
    found = (db.query(User)
             .filter(User.role_rows.any(UserRole.role == Role.operations))
             .all())
    assert [u.username for u in found] == ["mia"]


def test_changing_the_roles_replaces_the_set_rather_than_adding_to_it(db):
    """Taking a role away has to actually take it away."""
    user = account(db, "mia", Role.architect, Role.change_approver)
    apply_roles(user, [Role.architect])
    db.commit()
    db.refresh(user)

    assert set(user.roles) == {Role.architect}
    assert not user.has_role(Role.change_approver)


def test_primary_role_precedence_is_stable(db):
    assert primary_role([Role.operations, Role.admin]) == Role.admin
    assert primary_role([Role.operations, Role.change_approver]) == Role.change_approver
    assert primary_role([Role.operations, Role.architect]) == Role.architect
    assert primary_role([Role.operations]) == Role.operations
