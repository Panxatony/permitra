"""The risk criteria are visible and maintainable.

The list of risky services used to live in the source. That made the yardstick
invisible: an approver sees a hint before deciding and an auditor asks by which
standard it was raised, but neither could look it up - and an absent hint reads
as "harmless" when it may only mean "not on the list".

These tests cover the three properties that matter: the criteria are complete
and readable by everyone who has to act on them, changing them is reserved for
administrators, and every change lands in the audit log because moving the
yardstick is itself subject to review.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")  # importing the router pulls in auth

from typing import ClassVar

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import messages
from app.database import Base
from app.models import (
    AuditEvent,
    ComponentType,
    RiskyPort,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
    Zone,
)
from app.risk import DEFAULT_RISKY_PORTS, assess_rule, configured_risky_ports
from app.routers.risk_router import (
    _seed_if_empty,
    delete_risky_port,
    read_criteria,
    set_risky_port,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    s.add(Zone(id=1, code="Z010", name="INET", sort_order=10, pap_level="external"))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20, cia_c="very high"))
    s.commit()
    yield s
    s.close()


class Req:
    headers: ClassVar[dict] = {}

    class client:
        host = "203.0.113.7"


def admin():
    return User(username="adm", role=Role.admin, is_active=True)


def make_rule(db, port="3389"):
    r = Rule(rule_id="SR00001", vrf_id=1, name="test",
             components=[db.get(SecurityComponent, 1)],
             source=[{"ip": "10.0.0.1", "alias": ""}],
             destination=[{"ip": "10.0.1.2", "alias": ""}],
             services=[{"protocol": "TCP", "port": port}],
             action=RuleAction.permit, status=RuleStatus.approved,
             source_zone="Z010", destination_zone="Z020")
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


# ---------- The criteria are complete and readable ----------

def test_criteria_list_every_pattern(db):
    """A criterion that is not listed cannot be reviewed by anyone."""
    out = read_criteria(db=db, _user=User(username="appr", role=Role.change_approver))
    codes = {p["code"] for p in out["patterns"]}
    assert codes == {"any-to-any", "any-source", "broad-network",
                     "risky-service", "any-service", "no-logging"}
    assert all(p["severity"] in ("low", "medium", "high") for p in out["patterns"])


def test_criteria_expose_thresholds_and_weighting(db):
    """The numbers behind a hint belong in the answer, not only the wording."""
    out = read_criteria(db=db, _user=admin())
    broad = next(p for p in out["patterns"] if p["code"] == "broad-network")
    assert broad["threshold"] == "<= /8"
    assert out["protection_level_weight"] == {"normal": 0, "high": 1, "very high": 2}
    assert out["exposed_pap_levels"] == ["external"]


def test_criteria_show_the_default_list_before_any_change(db):
    out = read_criteria(db=db, _user=admin())
    assert out["risky_ports_are_default"] is True
    assert len(out["risky_ports"]) == len(DEFAULT_RISKY_PORTS)
    assert any(p["port"] == "3389" and p["label"] == "RDP (remote access)"
               for p in out["risky_ports"])


def test_the_seeded_defaults_still_count_as_default(db):
    """The migration writes the defaults into the table, so "has rows" is not
    the same as "adapted" - saying otherwise would claim a decision nobody made."""
    _seed_if_empty(db)
    assert read_criteria(db=db, _user=admin())["risky_ports_are_default"] is True


def test_default_labels_follow_the_instance_language(db):
    """The shipped labels are in the catalogue; an own wording is not and comes
    back as it was entered."""
    set_risky_port(request=Req(), port="8080", payload={"label": "Hausinterner Proxy"},
                   db=db, admin=admin())
    messages.set_language("de")
    try:
        labels = {p["port"]: p["label"] for p in read_criteria(db=db, _user=admin())["risky_ports"]}
    finally:
        messages.set_language("en")
    assert labels["445"] == "SMB (Dateifreigabe)"
    assert labels["8080"] == "Hausinterner Proxy"


def test_the_stored_wording_is_returned_alongside_the_translation(db):
    """An editor works on what is stored - saving the translated text back would
    turn a shipped default into own wording and freeze it in one language."""
    _seed_if_empty(db)
    messages.set_language("de")
    try:
        entry = next(p for p in read_criteria(db=db, _user=admin())["risky_ports"]
                     if p["port"] == "445")
    finally:
        messages.set_language("en")
    assert entry["label"] == "SMB (Dateifreigabe)"
    assert entry["source_label"] == "SMB (file sharing)"

    # Saving it back unchanged leaves the list on the defaults.
    set_risky_port(request=Req(), port="445", payload={"label": entry["source_label"]},
                   db=db, admin=admin())
    assert read_criteria(db=db, _user=admin())["risky_ports_are_default"] is True


def test_ports_are_sorted_numerically(db):
    """Sorted as text, port 3389 would come before 445."""
    out = read_criteria(db=db, _user=admin())
    numbers = [int(p["port"]) for p in out["risky_ports"]]
    assert numbers == sorted(numbers)


# ---------- Changing them is administrative and recorded ----------

def test_adding_a_port_is_recorded(db):
    set_risky_port(request=Req(), port="22", payload={"label": "SSH"}, db=db, admin=admin())
    assert configured_risky_ports(db)["22"] == "SSH"
    entry = db.query(AuditEvent).filter(AuditEvent.event == "risk.port_added").one()
    assert entry.object == "22" and entry.actor == "adm"
    assert entry.source_ip == "203.0.113.7"


def test_removing_a_port_is_recorded(db):
    delete_risky_port(request=Req(), port="3389", db=db, admin=admin())
    assert "3389" not in configured_risky_ports(db)
    entry = db.query(AuditEvent).filter(AuditEvent.event == "risk.port_removed").one()
    assert entry.object == "3389"
    assert "RDP" in entry.detail


def test_renaming_a_port_is_recorded_as_a_change(db):
    set_risky_port(request=Req(), port="23", payload={"label": "Telnet (forbidden here)"},
                   db=db, admin=admin())
    assert db.query(AuditEvent).filter(AuditEvent.event == "risk.port_changed").count() == 1


def test_first_change_materialises_the_defaults(db):
    """Removing one entry from an empty table must not silently keep the rest
    as defaults - the deletion would appear to do nothing."""
    delete_risky_port(request=Req(), port="23", db=db, admin=admin())
    stored = {p.port for p in db.query(RiskyPort).all()}
    assert "23" not in stored
    assert len(stored) == len(DEFAULT_RISKY_PORTS) - 1
    out = read_criteria(db=db, _user=admin())
    assert out["risky_ports_are_default"] is False


def test_invalid_port_is_rejected(db):
    for bad in ("0", "70000", "abc", ""):
        with pytest.raises(HTTPException) as exc:
            set_risky_port(request=Req(), port=bad, payload={"label": "x"}, db=db, admin=admin())
        assert exc.value.status_code == 422


def test_label_is_required(db):
    with pytest.raises(HTTPException) as exc:
        set_risky_port(request=Req(), port="22", payload={"label": "  "}, db=db, admin=admin())
    assert exc.value.status_code == 422


def test_removing_an_unlisted_port_is_404(db):
    with pytest.raises(HTTPException) as exc:
        delete_risky_port(request=Req(), port="8443", db=db, admin=admin())
    assert exc.value.status_code == 404


# ---------- The list actually drives the assessment ----------

def test_a_removed_service_stops_being_flagged(db):
    """The whole point of maintaining the list."""
    rule = make_rule(db, port="3389")
    before = [f for f in assess_rule(db, rule)["findings"] if f["code"] == "risky-service"]
    assert before, "RDP should be flagged by default"

    delete_risky_port(request=Req(), port="3389", db=db, admin=admin())
    after = [f for f in assess_rule(db, rule)["findings"] if f["code"] == "risky-service"]
    assert after == []


def test_an_added_service_starts_being_flagged(db):
    rule = make_rule(db, port="8080")
    assert not [f for f in assess_rule(db, rule)["findings"] if f["code"] == "risky-service"]

    set_risky_port(request=Req(), port="8080", payload={"label": "Internal proxy"},
                   db=db, admin=admin())
    findings = [f for f in assess_rule(db, rule)["findings"] if f["code"] == "risky-service"]
    assert len(findings) == 1
    assert "Internal proxy" in findings[0]["detail"]


def test_added_service_is_found_inside_a_range(db):
    """Ranges are expanded against the configured list, not only the defaults."""
    set_risky_port(request=Req(), port="8080", payload={"label": "Internal proxy"},
                   db=db, admin=admin())
    rule = make_rule(db, port="8000-8100")
    findings = [f for f in assess_rule(db, rule)["findings"] if f["code"] == "risky-service"]
    assert len(findings) == 1 and "8080" in findings[0]["detail"]
