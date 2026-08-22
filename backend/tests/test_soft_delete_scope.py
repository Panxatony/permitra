"""Gelöschte Regeln dürfen nirgends mehr fachlich wirken.

Regeln werden per Soft-Delete entfernt (`deleted_at`), damit die Historie als
Compliance-Nachweis erhalten bleibt. Der Status bleibt dabei stehen – meist
`approved`. Genau deshalb muss jede Abfrage sie ausschließen; sonst wirkt eine
gelöschte Regel weiter:

  * die Pfad-Analyse meldet Verkehr als erlaubt, den es nicht mehr gibt,
  * der Soll-Ist-Abgleich fordert, sie auf dem Gerät wieder anzulegen,
  * der Zonenplan (BSI-Nachweis) leitet Segmentierung aus ihr ab.

Die vorherige Testsuite hat diese Lücken nicht bemerkt, weil sie den
`deleted_at`-Filter nirgends geprüft hat.
"""
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.drift import analyze_drift
from app.models import (
    AddressObject,
    ComponentActualConfig,
    ComponentType,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    Vrf,
    Zone,
    ZoneNetwork,
    active_rules,
    utcnow,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-BER", type=ComponentType.juniper))
    s.add(Zone(id=1, code="Z010", name="DMZ", sort_order=10))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20))
    s.add(ZoneNetwork(zone_id=1, vrf_id=1, cidr="10.0.0.0/24"))
    s.add(ZoneNetwork(zone_id=2, vrf_id=1, cidr="10.0.1.0/24"))
    s.commit()
    yield s
    s.close()


def make_rule(db, rule_id, deleted=False, status=RuleStatus.approved):
    comp = db.get(SecurityComponent, 1)
    r = Rule(
        rule_id=rule_id, vrf_id=1, name=f"Regel {rule_id}", components=[comp],
        source=[{"ip": "10.0.0.5", "alias": "web01"}],
        destination=[{"ip": "10.0.1.7", "alias": ""}],
        services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
        status=status, source_zone="Z010", destination_zone="Z020",
        deleted_at=utcnow() if deleted else None,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


# ---------- zentrale Abfrage ----------

def test_active_rules_excludes_deleted(db):
    make_rule(db, "SR00001")
    make_rule(db, "SR00002", deleted=True)
    ids = {r.rule_id for r in active_rules(db).all()}
    assert ids == {"SR00001"}


def test_deleted_rule_keeps_its_status_for_the_record(db):
    """Der Soft-Delete verändert den Status bewusst nicht – genau deshalb
    braucht es den Filter überall."""
    r = make_rule(db, "SR00009", deleted=True)
    assert r.status == RuleStatus.approved and r.deleted_at is not None


# ---------- Soll-Ist-Abgleich ----------

def test_drift_does_not_demand_recreating_a_deleted_rule(db):
    """Der gefährlichste Fall: der Betrieb bekäme sonst die Anweisung, eine
    bewusst gelöschte Regel auf der Firewall wieder anzulegen."""
    make_rule(db, "SR00010")                 # aktiv, nicht auf dem Gerät
    make_rule(db, "SR00011", deleted=True)   # gelöscht, nicht auf dem Gerät
    comp = db.get(SecurityComponent, 1)
    db.add(ComponentActualConfig(component_id=1, content="set security policies SR00099"))
    db.commit()

    result = analyze_drift(db, comp)
    missing = {r["rule_id"] for r in result["missing"]}
    assert "SR00010" in missing
    assert "SR00011" not in missing, "gelöschte Regel wird zum Wiederanlegen gefordert"


def test_drift_reports_deleted_rule_left_on_device_as_stale(db):
    """Umkehrprobe: liegt die gelöschte Regel noch auf dem Gerät, muss sie als
    abzubauen erkannt werden – vorher galt sie als 'bekannt' und fiel durch."""
    make_rule(db, "SR00012", deleted=True)
    comp = db.get(SecurityComponent, 1)
    db.add(ComponentActualConfig(component_id=1, content="set security policies SR00012"))
    db.commit()

    result = analyze_drift(db, comp)
    stale_ids = {s["rule_id"] for s in result["stale"]}
    assert "SR00012" in stale_ids, "gelöschte Regel auf dem Gerät nicht als Rückbau erkannt"
    assert "SR00012" not in result["unknown"]


# ---------- Zonenplan / BSI-Nachweis ----------

def test_zoneplan_ignores_deleted_rules(db):
    from app.zoneplan import build_mermaid

    make_rule(db, "SR00020", deleted=True)
    diagram = build_mermaid(db)
    assert "SR00020" not in diagram


# ---------- Objekt-Katalog ----------

def test_ip_change_does_not_touch_deleted_rules(db):
    """Eine Adressänderung darf nicht in gelöschte Regeln zurückschreiben."""
    from app.routers.objects_router import propagate_ip_change

    active = make_rule(db, "SR00030")
    deleted = make_rule(db, "SR00031", deleted=True)
    obj = AddressObject(name="web01", ip="10.0.0.9")
    db.add(obj)
    db.commit()

    propagate_ip_change(db, obj, "10.0.0.5", "pruefer")
    db.commit()          # der Router committet nach dem Nachziehen
    db.refresh(active)
    db.refresh(deleted)
    assert active.source[0]["ip"] == "10.0.0.9", "aktive Regel wurde nicht nachgezogen"
    assert deleted.source[0]["ip"] == "10.0.0.5", "gelöschte Regel wurde verändert"
    assert deleted.version == 1, "gelöschte Regel wurde fortgeschrieben"


# ---------- Zugriff über die Regel-ID ----------

def test_deleted_rule_is_not_retrievable(db):
    from app.routers.rules_router import get_rule_or_404

    make_rule(db, "SR00040", deleted=True)
    with pytest.raises(HTTPException) as exc:
        get_rule_or_404(db, "SR00040")
    assert exc.value.status_code == 404


def test_delete_handler_can_still_see_deleted_rule(db):
    """Gegenprobe: das Löschen selbst muss den Zustand erkennen können,
    sonst wäre doppeltes Löschen nicht abfangbar."""
    from app.routers.rules_router import get_rule_or_404

    make_rule(db, "SR00041", deleted=True)
    rule = get_rule_or_404(db, "SR00041", include_deleted=True)
    assert rule.deleted_at is not None


# ---------- Auswirkungsanalyse der Matrix ----------

def test_matrix_impact_ignores_deleted_rules(db):
    """Eine Matrix-Änderung auf Block darf keine gelöschte Regel in den
    Review zurückholen."""
    from app.routers.zones_router import _affected_rules

    make_rule(db, "SR00050")
    make_rule(db, "SR00051", deleted=True)
    affected = {r.rule_id for r in _affected_rules(db, "Z010", "Z020")}
    assert affected == {"SR00050"}
