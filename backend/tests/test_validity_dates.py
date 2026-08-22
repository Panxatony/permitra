"""Ungültige Gültigkeitsdaten (Audit-Befund H5).

`valid_until` war ein reiner String; der einzige Prüfer verglich nur zeichenweise.
Ein Wert wie "2020-02-30" (den 30. Februar gibt es nicht) passierte die Anlage,
passierte den SQL-Filter – und ließ dann `date.fromisoformat` abstürzen. Eine
einzige solche Regel genügte, um Dashboard, Ablaufliste und den täglichen
Deaktivierungs-Job für ALLE Nutzer lahmzulegen.

Zwei Ebenen werden geprüft: die Abwehr an der Tür (Validierung) und die
Widerstandsfähigkeit gegenüber Altbestand, der die Tür nie passiert hat.
"""
from datetime import date, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.expiry import expiring_rules, expire_rules, invalid_validity_rules
from app.database import Base
from app.models import Rule, RuleAction, RuleStatus, Vrf
from app.schemas import ExtendRequest, RuleCreate


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.commit()
    yield s
    s.close()


def make_rule(db, rule_id, valid_until, status=RuleStatus.approved):
    """Legt eine Regel direkt an – umgeht die Validierung bewusst, um
    Altbestand/Importe nachzustellen."""
    r = Rule(
        rule_id=rule_id, vrf_id=1, name=rule_id,
        source=[{"ip": "10.0.0.1", "alias": ""}],
        destination=[{"ip": "10.0.0.2", "alias": ""}],
        services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
        status=status, valid_until=valid_until,
    )
    db.add(r)
    db.commit()
    return r


def _payload(**over):
    base = dict(
        name="Testregel",
        source=[{"ip": "10.0.0.1", "alias": ""}],
        destination=[{"ip": "10.0.0.2", "alias": ""}],
        services=[{"protocol": "TCP", "port": "443"}],
    )
    base.update(over)
    return base


# ---------- Abwehr an der Tür ----------

@pytest.mark.parametrize("bad", [
    "2020-02-30",   # 30. Februar – der Fall aus dem Audit
    "2026-13-01",   # Monat 13
    "31.12.2026",   # deutsches Format statt ISO
    "morgen",
    "2026-1-1x",
])
def test_invalid_valid_until_is_rejected(bad):
    with pytest.raises(ValidationError) as exc:
        RuleCreate(**_payload(valid_until=bad))
    assert "Gültig-bis" in str(exc.value)


def test_invalid_valid_from_is_rejected():
    with pytest.raises(ValidationError) as exc:
        RuleCreate(**_payload(valid_from="2026-02-31"))
    assert "Gültig-ab" in str(exc.value)


def test_valid_dates_are_accepted_and_normalised():
    rule = RuleCreate(**_payload(valid_from=" 2026-01-01 ", valid_until="2027-03-31"))
    assert rule.valid_from == "2026-01-01"      # getrimmt
    assert rule.valid_until == "2027-03-31"


def test_empty_date_becomes_none():
    rule = RuleCreate(**_payload(valid_until=""))
    assert rule.valid_until is None


def test_period_order_is_still_checked():
    with pytest.raises(ValidationError) as exc:
        RuleCreate(**_payload(valid_from="2027-01-01", valid_until="2026-01-01"))
    assert "Gültig-bis liegt vor Gültig-ab" in str(exc.value)


def test_extend_request_rejects_invalid_date():
    """Auch die Verlängerung bei der Rezertifizierung war ein Einfallsweg."""
    with pytest.raises(ValidationError):
        ExtendRequest(valid_until="2020-02-30")
    assert ExtendRequest(valid_until="2028-06-30").valid_until == "2028-06-30"


# ---------- Widerstandsfähigkeit gegenüber Altbestand ----------

def test_bad_legacy_date_does_not_break_the_expiry_check(db):
    """Der Kern des Befunds: eine einzige unlesbare Regel legte alles lahm."""
    gestern = (date.today() - timedelta(days=1)).isoformat()
    make_rule(db, "SR00001", gestern)          # echt abgelaufen
    make_rule(db, "SR00002", "2020-02-30")     # Altbestand, unlesbar

    expired, expiring = expiring_rules(db, days=30)      # darf nicht werfen
    assert [r.rule_id for r in expired] == ["SR00001"]
    assert "SR00002" not in [r.rule_id for r in expired + expiring]


def test_bad_legacy_date_does_not_break_the_daily_job(db):
    gestern = (date.today() - timedelta(days=1)).isoformat()
    make_rule(db, "SR00010", gestern)
    make_rule(db, "SR00011", "2020-02-30")

    count = expire_rules(db)                             # darf nicht werfen
    assert count == 1
    assert db.query(Rule).filter(Rule.rule_id == "SR00010").one().status == RuleStatus.deactivated
    # Die unlesbare Regel wird bewusst NICHT automatisch deaktiviert
    assert db.query(Rule).filter(Rule.rule_id == "SR00011").one().status == RuleStatus.approved


def test_invalid_rules_are_reported_not_swallowed(db):
    """Übersprungen heißt nicht unsichtbar – sonst bliebe der Fehler ewig liegen."""
    make_rule(db, "SR00020", (date.today() + timedelta(days=5)).isoformat())
    make_rule(db, "SR00021", "2020-02-30")
    make_rule(db, "SR00022", "kein-datum")

    bad = {r.rule_id for r in invalid_validity_rules(db)}
    assert bad == {"SR00021", "SR00022"}


def test_deleted_rules_are_not_reported_as_invalid(db):
    from app.models import utcnow

    r = make_rule(db, "SR00030", "2020-02-30")
    r.deleted_at = utcnow()
    db.commit()
    assert invalid_validity_rules(db) == []
