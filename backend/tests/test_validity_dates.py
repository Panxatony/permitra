"""Invalid validity dates (audit finding H5).

`valid_until` was a plain string; the only check compared it character by
character. A value such as "2020-02-30" (there is no 30 February) passed
creation, passed the SQL filter - and then made `date.fromisoformat` crash. A
single such rule was enough to paralyse the dashboard, the expiry list and the
daily deactivation job for ALL users.

Two levels are checked: the defence at the door (validation) and the resilience
against legacy data that never passed through that door.
"""
from datetime import date, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.expiry import expire_rules, expiring_rules, invalid_validity_rules
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
    """Creates a rule directly - deliberately bypassing validation in order to
    simulate legacy data/imports."""
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
    base = {
        "name": "Testregel",
        "source": [{"ip": "10.0.0.1", "alias": ""}],
        "destination": [{"ip": "10.0.0.2", "alias": ""}],
        "services": [{"protocol": "TCP", "port": "443"}],
    }
    base.update(over)
    return base


# ---------- Defence at the door ----------

@pytest.mark.parametrize("bad", [
    "2020-02-30",   # 30 February - the case from the audit
    "2026-13-01",   # month 13
    "31.12.2026",   # German format instead of ISO
    "morgen",
    "2026-1-1x",
])
def test_invalid_valid_until_is_rejected(bad):
    with pytest.raises(ValidationError) as exc:
        RuleCreate(**_payload(valid_until=bad))
    assert "Valid until" in str(exc.value)


def test_invalid_valid_from_is_rejected():
    with pytest.raises(ValidationError) as exc:
        RuleCreate(**_payload(valid_from="2026-02-31"))
    assert "Valid from" in str(exc.value)


def test_valid_dates_are_accepted_and_normalised():
    rule = RuleCreate(**_payload(valid_from=" 2026-01-01 ", valid_until="2027-03-31"))
    assert rule.valid_from == "2026-01-01"      # trimmed
    assert rule.valid_until == "2027-03-31"


def test_empty_date_becomes_none():
    rule = RuleCreate(**_payload(valid_until=""))
    assert rule.valid_until is None


def test_period_order_is_still_checked():
    with pytest.raises(ValidationError) as exc:
        RuleCreate(**_payload(valid_from="2027-01-01", valid_until="2026-01-01"))
    assert "Valid until is earlier than valid from" in str(exc.value)


def test_extend_request_rejects_invalid_date():
    """The extension during recertification was another way in as well."""
    with pytest.raises(ValidationError):
        ExtendRequest(valid_until="2020-02-30")
    assert ExtendRequest(valid_until="2028-06-30").valid_until == "2028-06-30"


# ---------- Resilience against legacy data ----------

def test_bad_legacy_date_does_not_break_the_expiry_check(db):
    """The core of the finding: a single unreadable rule paralysed everything."""
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    make_rule(db, "SR00001", yesterday)          # genuinely expired
    make_rule(db, "SR00002", "2020-02-30")     # legacy data, unreadable

    expired, expiring = expiring_rules(db, days=30)      # must not raise
    assert [r.rule_id for r in expired] == ["SR00001"]
    assert "SR00002" not in [r.rule_id for r in expired + expiring]


def test_bad_legacy_date_does_not_break_the_daily_job(db):
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    make_rule(db, "SR00010", yesterday)
    make_rule(db, "SR00011", "2020-02-30")

    count = expire_rules(db)                             # must not raise
    assert count == 1
    assert db.query(Rule).filter(Rule.rule_id == "SR00010").one().status == RuleStatus.deactivated
    # The unreadable rule is deliberately NOT deactivated automatically
    assert db.query(Rule).filter(Rule.rule_id == "SR00011").one().status == RuleStatus.approved


def test_invalid_rules_are_reported_not_swallowed(db):
    """Skipped does not mean invisible - otherwise the error would linger forever."""
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
