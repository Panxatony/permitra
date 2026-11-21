"""The implementation view names what changed since a component was configured.

A component in "to change" used to show only the rule as approved now. An
address dropped from the rule was then simply absent from the preview, and
operations had to compare by eye what to take off the device. These tests pin
the version that counts as "implemented" and the difference shown against it.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import impl_diff
from app.database import Base
from app.models import (
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    RuleVersion,
    SecurityComponent,
    User,
    Vrf,
)
from app.routers.rules_router import add_version, implementation, set_impl_status


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Vrf(id=1, name="IT"))
    session.add(SecurityComponent(name="FW-BER", type=ComponentType.juniper))
    session.add(SecurityComponent(name="FW-FFM", type=ComponentType.juniper))
    session.flush()
    yield session
    session.close()


def ops():
    return User(username="olga", password_hash="x", role=Role.operations)


def architect():
    return User(username="anna", password_hash="x", role=Role.architect)


def make_rule(db, status=RuleStatus.approved, impl=None):
    components = db.query(SecurityComponent).order_by(SecurityComponent.name).all()
    rule = Rule(
        rule_id="SR0001", vrf_id=1, name="Web to app", components=components,
        source=[{"ip": "10.0.0.1", "alias": "web1"}, {"ip": "10.0.0.2", "alias": "web2"}],
        destination=[{"ip": "10.0.1.10", "alias": "app"}],
        services=[{"protocol": "TCP", "port": "443"}, {"protocol": "TCP", "port": "8080"}],
        action=RuleAction.permit, status=status, impl_status=impl or {},
    )
    db.add(rule)
    db.commit()
    return rule


def edit_and_reapprove(db, rule, **changes):
    """What an edit followed by an approval leaves behind: two versions, the
    content changed in the first, implemented components "to change" after the
    second."""
    for field, value in changes.items():
        setattr(rule, field, value)
    rule.version += 1
    add_version(db, rule, architect(), "Edited")
    rule.impl_status = {name: ("to change" if value == "implemented" else value)
                        for name, value in (rule.impl_status or {}).items()}
    rule.version += 1
    add_version(db, rule, architect(), "Approved")
    db.commit()
    db.refresh(rule)


def view(db, component):
    result = implementation("SR0001", db, architect())
    return next(e for e in result["implementations"] if e["component"] == component)


def test_difference_to_the_version_operations_confirmed(db):
    """The view shows what was added and what was dropped since the confirmation,
    and says that dropped entries are not in the preview."""
    rule = make_rule(db)
    set_impl_status("SR0001", {"FW-BER": "implemented"}, db, ops())
    confirmed = rule.version
    edit_and_reapprove(
        db, rule,
        source=[{"ip": "10.0.0.1", "alias": "web1"}, {"ip": "10.0.0.3", "alias": "web3"}],
        services=[{"protocol": "TCP", "port": "443"}],
    )

    entry = view(db, "FW-BER")
    assert entry["impl_status"] == "to change"
    assert entry["implemented"]["version"] == confirmed
    assert entry["implemented"]["by"] == "olga"
    assert [e["ip"] for e in entry["changes"]["source"]["added"]] == ["10.0.0.3"]
    assert [e["ip"] for e in entry["changes"]["source"]["removed"]] == ["10.0.0.2"]
    assert entry["changes"]["destination"] == {"added": [], "removed": []}
    assert entry["changes"]["services"]["removed"] == [{"protocol": "TCP", "port": "8080"}]
    assert entry["changes"]["fields"] == []
    assert "by hand" in entry["changes_note"]


def test_each_component_is_compared_with_its_own_confirmation(db):
    """Two firewalls confirmed at different versions get different differences;
    a component that is not "to change" gets none."""
    rule = make_rule(db)
    set_impl_status("SR0001", {"FW-BER": "implemented"}, db, ops())
    edit_and_reapprove(db, rule, destination=[{"ip": "10.0.1.10", "alias": "app"},
                                              {"ip": "10.0.1.11", "alias": "app2"}])
    set_impl_status("SR0001", {"FW-FFM": "implemented"}, db, ops())
    edit_and_reapprove(db, rule, action=RuleAction.deny)

    ber, ffm = view(db, "FW-BER"), view(db, "FW-FFM")
    assert [e["ip"] for e in ber["changes"]["destination"]["added"]] == ["10.0.1.11"]
    assert ffm["changes"]["destination"]["added"] == []
    assert ffm["changes"]["fields"] == [{"field": "action", "old": "permit", "new": "deny"}]
    assert ber["changes"]["fields"] == ffm["changes"]["fields"]

    set_impl_status("SR0001", {"FW-BER": "implemented"}, db, ops())
    assert "changes" not in view(db, "FW-BER")


def test_an_edit_does_not_move_the_confirmed_version(db):
    """An edit leaves the status "implemented" standing until the next approval,
    so its snapshot shows new content under an old confirmation. Taking the
    newest snapshot that says "implemented" would compare the rule with itself
    and report nothing to do."""
    rule = make_rule(db)
    set_impl_status("SR0001", {"FW-BER": "implemented"}, db, ops())
    confirmed = rule.version
    edit_and_reapprove(db, rule, services=[{"protocol": "TCP", "port": "443"},
                                           {"protocol": "TCP", "port": "8080"},
                                           {"protocol": "UDP", "port": "53"}])

    entry = view(db, "FW-BER")
    assert entry["implemented"]["version"] == confirmed
    assert entry["changes"]["services"]["added"] == [{"protocol": "UDP", "port": "53"}]
    assert entry["changes_note"] == ""


def test_imported_rule_counts_from_the_version_it_arrived_implemented(db):
    """An imported rule is implemented from its first version, without a status
    report by operations. That version is the baseline."""
    rule = make_rule(db, impl={"FW-BER": "implemented"})
    add_version(db, rule, architect(), "Imported")
    edit_and_reapprove(db, rule, name="Web to app v2")

    entry = view(db, "FW-BER")
    assert entry["implemented"]["version"] == 1
    assert entry["changes"]["fields"] == [{"field": "name", "old": "Web to app", "new": "Web to app v2"}]


def test_automatic_entries_are_skipped(db):
    """Address re-checks and expiry write versions without rule content. They
    must neither become the baseline nor hide the confirmation before them."""
    rule = make_rule(db)
    set_impl_status("SR0001", {"FW-BER": "implemented"}, db, ops())
    confirmed = rule.version
    rule.version += 1
    rule.destination = [{"ip": "10.0.1.20", "alias": "app"}]
    rule.impl_status = {**rule.impl_status, "FW-BER": "to change"}
    db.add(RuleVersion(rule_pk=rule.id, version=rule.version, snapshot={"auto": "address-recheck"},
                       change_note="Address object 'app': IP {old_ip} → {new_ip}",
                       change_values={"old_ip": "10.0.1.10", "new_ip": "10.0.1.20"}, changed_by="anna"))
    db.commit()
    db.refresh(rule)

    entry = view(db, "FW-BER")
    assert entry["implemented"]["version"] == confirmed
    assert [e["ip"] for e in entry["changes"]["destination"]["added"]] == ["10.0.1.20"]
    assert [e["ip"] for e in entry["changes"]["destination"]["removed"]] == ["10.0.1.10"]


def test_no_recorded_confirmation_is_said_plainly(db):
    """Without a version to compare with, the view says so instead of showing an
    empty difference that reads like "nothing to do"."""
    make_rule(db, impl={"FW-BER": "to change"})

    entry = view(db, "FW-BER")
    assert entry["implemented"] is None
    assert entry["changes"] is None
    assert "compare the preview with the device" in entry["changes_note"]


def test_a_change_that_does_not_reach_the_device(db):
    """A renewed approval after a new expiry date or justification also sets
    "to change". The view then says there is nothing to configure."""
    rule = make_rule(db)
    set_impl_status("SR0001", {"FW-BER": "implemented"}, db, ops())
    edit_and_reapprove(db, rule, justification="Renewed for another year", valid_until="2028-01-01")

    entry = view(db, "FW-BER")
    assert impl_diff.is_empty(entry["changes"])
    assert "can be confirmed" in entry["changes_note"]


def test_an_alias_rename_is_not_a_new_address():
    """The device matches on the address. Renaming the alias must not show up as
    one entry removed and one added."""
    old = {"source": [{"ip": "10.0.0.1", "alias": "web1"}]}
    new = {"source": [{"ip": "10.0.0.1", "alias": "web-frontend-1"}]}
    assert impl_diff.is_empty(impl_diff.difference(old, new))
