"""Zwei Befunde aus dem Audit:

M2 – Export per ausdrücklicher Rule-ID übersprang den Statusfilter. Damit ließ
sich eine deaktivierte oder abgelaufene Regel als fertige Geräte-Konfiguration
exportieren und geriet unbemerkt zurück auf die Firewall.

M3 – Die Risikoprüfung schlug nur bei exakten Einzelports an. Bereiche wie
"20-25" (enthält FTP und Telnet) oder Listen wie "22,23" erzeugten keinen
Hinweis – gerade die weit gefassten Regeln blieben also stumm.
"""
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    ComponentType,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Role,
    Vrf,
    Zone,
)
from app.risk import assess_rule, risky_ports_in
from app.routers.export_router import export


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-BER", type=ComponentType.juniper))
    s.add(Zone(id=1, code="Z010", name="DMZ", sort_order=10, pap_level="extern"))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20, cia_c="hoch"))
    s.commit()
    yield s
    s.close()


def make_rule(db, rule_id, status=RuleStatus.approved, services=None,
              src_zone="Z010", dst_zone="Z020"):
    comp = db.get(SecurityComponent, 1)
    r = Rule(
        rule_id=rule_id, vrf_id=1, name=rule_id, components=[comp],
        source=[{"ip": "10.0.0.1", "alias": ""}],
        destination=[{"ip": "10.0.1.2", "alias": ""}],
        services=services or [{"protocol": "TCP", "port": "443"}],
        action=RuleAction.permit, status=status,
        source_zone=src_zone, destination_zone=dst_zone,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


class Req:
    headers = {}

    class client:
        host = "203.0.113.9"


def _user():
    return User(username="ops", role=Role.operations, is_active=True)


def _export(db, **kw):
    params = dict(request=Req(), fmt="csv", ids=None, component_id=None, app_id=None,
                  only_approved=True, platform_filter=True, download=False,
                  db=db, user=_user())
    params.update(kw)
    return export(**params)


# ---------- M2: Statusfilter gilt auch bei genannten IDs ----------

def test_deactivated_rule_is_not_exported_by_id(db):
    """Der Kern des Befunds: eine deaktivierte Regel geriet über ?ids= zurück
    in eine Geräte-Konfiguration."""
    make_rule(db, "SR00001", status=RuleStatus.deactivated)
    with pytest.raises(HTTPException) as exc:
        _export(db, ids="SR00001")
    assert exc.value.status_code == 404
    assert "Nicht freigegeben" in exc.value.detail
    assert "SR00001" in exc.value.detail


def test_draft_rule_is_not_exported_by_id(db):
    make_rule(db, "SR00002", status=RuleStatus.draft)
    with pytest.raises(HTTPException) as exc:
        _export(db, ids="SR00002")
    assert "deactivated" not in exc.value.detail and "draft" in exc.value.detail


def test_approved_rule_is_still_exported_by_id(db):
    """Gegenprobe – der Normalfall muss unverändert funktionieren."""
    make_rule(db, "SR00003")
    result = _export(db, ids="SR00003")
    assert "SR00003" in result.body.decode()


def test_preview_of_unapproved_rule_needs_explicit_opt_in(db):
    """Vorschau bleibt möglich, aber nur als bewusste Entscheidung."""
    make_rule(db, "SR00004", status=RuleStatus.draft)
    result = _export(db, ids="SR00004", only_approved=False)
    assert "SR00004" in result.body.decode()


def test_mixed_ids_export_only_the_approved_ones(db):
    make_rule(db, "SR00010", status=RuleStatus.approved)
    make_rule(db, "SR00011", status=RuleStatus.deactivated)
    body = _export(db, ids="SR00010,SR00011").body.decode()
    assert "SR00010" in body and "SR00011" not in body


def test_unapproved_export_is_marked_in_the_audit_trail(db):
    """Wenn nicht freigegebene Regeln bewusst exportiert werden, muss das in
    der Spur stehen – sonst ist später nicht nachvollziehbar, was das Gerät
    bekommen hat."""
    from app.models import AuditEvent

    make_rule(db, "SR00020", status=RuleStatus.draft)
    _export(db, ids="SR00020", only_approved=False)
    entry = db.query(AuditEvent).filter(AuditEvent.event == "export.rules").one()
    assert "NICHT freigegeben" in entry.detail and "SR00020" in entry.detail


def test_normal_export_trail_stays_clean(db):
    from app.models import AuditEvent

    make_rule(db, "SR00021")
    _export(db, ids="SR00021")
    entry = db.query(AuditEvent).filter(AuditEvent.event == "export.rules").one()
    assert "NICHT freigegeben" not in entry.detail


# ---------- M3: Port-Bereiche und -Listen ----------

@pytest.mark.parametrize("spec,erwartet", [
    ("23", {"23"}),                       # Einzelport – Bestandsverhalten
    ("20-25", {"21", "23"}),              # FTP und Telnet im Bereich
    ("22,23", {"23"}),                    # Liste
    ("22, 23", {"23"}),                   # Liste mit Leerzeichen
    ("80,3300-3400", {"3306", "3389"}),   # gemischt – der Bereich deckt MySQL UND RDP ab
    ("25-20", {"21", "23"}),              # verdrehte Grenzen
    ("443", set()),                       # unauffällig
    ("80,8000-8080", set()),
    ("any", set()),                       # nicht numerisch
    ("", set()),
])
def test_risky_ports_in_spec(spec, erwartet):
    assert {p for p, _ in risky_ports_in(spec)} == erwartet


def test_range_triggers_a_risk_finding(db):
    """Vorher stumm: der Bereich enthält FTP und Telnet."""
    rule = make_rule(db, "SR00030", services=[{"protocol": "TCP", "port": "20-25"}])
    findings = assess_rule(db, rule)["findings"]
    risky = [f for f in findings if f["code"] == "risky-service"]
    assert len(risky) == 2
    details = " ".join(f["detail"] for f in risky)
    assert "Telnet" in details and "FTP" in details


def test_finding_names_the_concrete_port_inside_the_range(db):
    """Sonst sucht der Prüfer in '20-25' vergeblich nach dem Problem."""
    rule = make_rule(db, "SR00031", services=[{"protocol": "TCP", "port": "20-25"}])
    risky = [f for f in assess_rule(db, rule)["findings"] if f["code"] == "risky-service"]
    assert any("Port 23 in 20-25" in f["detail"] for f in risky)


def test_single_port_wording_unchanged(db):
    rule = make_rule(db, "SR00032", services=[{"protocol": "TCP", "port": "3389"}])
    risky = [f for f in assess_rule(db, rule)["findings"] if f["code"] == "risky-service"]
    assert len(risky) == 1 and "Port 3389" in risky[0]["detail"]
    assert " in " not in risky[0]["detail"]


def test_harmless_range_stays_silent(db):
    rule = make_rule(db, "SR00033", services=[{"protocol": "TCP", "port": "8000-8080"}])
    risky = [f for f in assess_rule(db, rule)["findings"] if f["code"] == "risky-service"]
    assert risky == []


def test_wide_range_reports_every_risky_port_once(db):
    rule = make_rule(db, "SR00034", services=[{"protocol": "TCP", "port": "1-65535"}])
    risky = [f for f in assess_rule(db, rule)["findings"] if f["code"] == "risky-service"]
    ports = [f["detail"] for f in risky]
    assert len(ports) == len(set(ports)) and len(risky) >= 10
