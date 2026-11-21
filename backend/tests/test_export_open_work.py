"""The export can be narrowed down to what operations still has to configure.

The rule list and the dashboard have shown the open work for a long time
(`impl=pending`), but the export only knew "every rule in force on this
component" or "the rule IDs somebody typed in". Getting from the first to the
second was copying IDs by hand, at exactly the step Permitra exists to
support: turning an approved rule into device configuration.

The filter is asked per component, because that is how the work is handed out.
"""
from typing import ClassVar

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    AuditEvent,
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
    Zone,
)
from app.routers.export_router import aerleon, export


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-BER", type=ComponentType.juniper))
    s.add(SecurityComponent(id=2, name="FW-FFM", type=ComponentType.juniper))
    s.add(SecurityComponent(id=3, name="CP-MGMT", type=ComponentType.checkpoint))
    s.add(Zone(id=1, code="Z010", name="DMZ", sort_order=10))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20))
    s.commit()
    yield s
    s.close()


def make_rule(db, rule_id, impl, components=(1,), status=RuleStatus.approved):
    comps = [db.get(SecurityComponent, i) for i in components]
    r = Rule(
        rule_id=rule_id, vrf_id=1, name=rule_id, components=comps,
        source=[{"ip": "10.0.0.1", "alias": ""}],
        destination=[{"ip": "10.0.1.2", "alias": ""}],
        services=[{"protocol": "TCP", "port": "443"}],
        action=RuleAction.permit, status=status, impl_status=impl,
        source_zone="Z010", destination_zone="Z020",
    )
    db.add(r)
    db.commit()
    return r


class Req:
    headers: ClassVar[dict] = {}

    class client:
        host = "203.0.113.9"


def _export(db, **kw):
    params = {"request": Req(), "fmt": "csv", "ids": None, "component_id": None, "app_id": None,
              "only_approved": True, "platform_filter": True, "download": False,
              "db": db, "user": User(username="ops", role=Role.operations, is_active=True)}
    params.update(kw)
    return export(**params).body.decode()


def test_only_the_open_rules_of_a_component_are_exported(db):
    """The case from the requirement: of the rules in force on one firewall,
    the export holds the ones still to be configured there - new, never
    reported, or changed after a renewed approval - and none already in place."""
    make_rule(db, "SR00001", {"FW-BER": "implemented"}, status=RuleStatus.active)
    make_rule(db, "SR00002", {})                       # approved, never reported
    make_rule(db, "SR00003", {"FW-BER": "new"})
    make_rule(db, "SR00004", {"FW-BER": "to change"})
    make_rule(db, "SR00005", {"FW-BER": "deactivated"})

    out = _export(db, fmt="juniper", component_id=1, impl="pending")
    assert "SR00001" not in out and "SR00005" not in out
    assert all(rule_id in out for rule_id in ("SR00002", "SR00003", "SR00004"))


def test_the_status_of_the_named_component_decides(db):
    """A rule on two firewalls, in place on one and open on the other, is
    open work for the second only. Asking "open anywhere" would put it back
    into the export of the firewall that is already done."""
    make_rule(db, "SR00001", {"FW-BER": "implemented", "FW-FFM": "new"}, components=(1, 2))

    assert "SR00001" in _export(db, fmt="juniper", component_id=2, impl="pending")
    with pytest.raises(HTTPException) as exc:
        _export(db, fmt="juniper", component_id=1, impl="pending")
    assert exc.value.status_code == 404
    assert "open implementation" in exc.value.detail


def test_without_a_component_the_platform_of_the_format_decides(db):
    """The Juniper export without a component named covers every Juniper
    device. A rule that is done there and still open on Check Point belongs
    in the Check Point export, not in this one."""
    make_rule(db, "SR00001", {"FW-BER": "implemented", "CP-MGMT": "new"}, components=(1, 3))
    make_rule(db, "SR00002", {"FW-BER": "new", "CP-MGMT": "implemented"}, components=(1, 3))

    juniper = _export(db, fmt="juniper", impl="pending")
    assert "SR00002" in juniper and "SR00001" not in juniper
    checkpoint = _export(db, fmt="checkpoint-cli", impl="pending")
    assert "SR00001" in checkpoint and "SR00002" not in checkpoint
    # A format without a platform asks for open work on any component.
    listing = _export(db, fmt="csv", impl="pending")
    assert "SR00001" in listing and "SR00002" in listing


def test_rules_not_in_force_are_never_open_work(db):
    """Turning off "approved only" is for previews. It must not let a draft or
    a rule on its way off the device into a file named after the open work -
    the export only creates, so a rule to remove has nothing in it to apply."""
    make_rule(db, "SR00001", {}, status=RuleStatus.draft)
    make_rule(db, "SR00002", {"FW-BER": "to remove"}, status=RuleStatus.deactivated)
    make_rule(db, "SR00003", {"FW-BER": "new"})

    out = _export(db, fmt="juniper", component_id=1, impl="pending", only_approved=False)
    assert "SR00003" in out
    assert "SR00001" not in out and "SR00002" not in out


def test_an_unknown_filter_value_is_refused(db):
    """A typo must not read as "no filter" and hand back the whole ruleset
    under the name of a work package."""
    make_rule(db, "SR00001", {"FW-BER": "new"})
    with pytest.raises(HTTPException) as exc:
        _export(db, fmt="juniper", impl="open")
    assert exc.value.status_code == 422


def test_the_audit_entry_says_it_was_the_open_work(db):
    """An export of five rules and an export of the five open rules are
    different events for whoever reads the log afterwards."""
    make_rule(db, "SR00001", {"FW-BER": "new"})
    _export(db, fmt="juniper", component_id=1, impl="pending")
    event = db.query(AuditEvent).filter(AuditEvent.event == "export.rules").one()
    assert event.detail == "{count} rule(s) with an open implementation"


def test_the_capirca_export_takes_the_same_filter(db):
    """The Aerleon targets are how the remaining platforms get their
    configuration; the work package has to exist for them as well."""
    make_rule(db, "SR00001", {"FW-BER": "implemented"}, status=RuleStatus.active)
    make_rule(db, "SR00002", {"FW-BER": "new"})
    out = aerleon(request=Req(), target="policy", component_id=1, only_approved=True,
                  impl="pending", download=False, db=db,
                  user=User(username="ops", role=Role.operations, is_active=True)).body.decode()
    assert "SR00002" in out and "SR00001" not in out
