"""Deleting old audit events without breaking the proof that the rest is intact.

Two forces pull opposite ways (#34). GDPR Art. 5(1)(e) and BSI CON.6 require a
retention period for personal data - audit events hold usernames and source IPs.
The hash chain requires keeping everything - delete one event and verification
fails from that point forever.

The resolution is to collapse whole prefixes behind a retention seal: the
oldest segment is deleted, and a seal records the boundary hash the first
survivor links back to, so verify_chain starts there instead of at genesis.

These tests pin what makes that safe rather than merely convenient: the chain
still verifies after a collapse, a tampered survivor is still caught, retention
is off unless an admin turns it on, and - the line between externalising
evidence and destroying it - nothing a configured SIEM has not acknowledged is
ever collapsed.
"""
import os
from datetime import timedelta

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import audit
from app.database import Base
from app.models import AuditEvent, AuditRetentionSeal, utcnow
from app.settings import set_setting


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def write(db, n, *, age_days=0, siem="skipped", monkeypatch=None):
    """Writes n chained events at a controlled age via the real record path.

    The timestamp is part of the hashed content, so back-dating an event after
    the fact would break its own hash. Instead the events are created with the
    aged clock by patching the utcnow() record() reads - the hashes are then
    genuine for that timestamp."""
    aged = utcnow() - timedelta(days=age_days)
    import app.audit as audit_mod
    real = audit_mod.utcnow
    audit_mod.utcnow = lambda: aged
    try:
        before = db.query(AuditEvent.id).count()
        for i in range(n):
            audit.record(db, "auth", "auth.login", actor=f"user{i}", source_ip="10.0.0.1")
    finally:
        audit_mod.utcnow = real
    new = (db.query(AuditEvent).order_by(AuditEvent.id.asc()).offset(before).all())
    for ev in new:
        ev.siem_status = siem
    db.commit()


# ---------- the chain survives a collapse ----------

def test_the_chain_still_verifies_after_a_prefix_is_collapsed(db):
    """The whole point: delete the old start, keep the proof."""
    write(db, 6, age_days=400)
    write(db, 4, age_days=0)          # recent, must survive
    set_setting(db, "audit_retention_days", "365")

    assert audit.verify_chain(db)["ok"] is True     # intact to begin with
    result = audit.collapse_expired(db)
    assert result["collapsed"] == 6

    v = audit.verify_chain(db)
    assert v["ok"] is True
    assert v["checked"] == 4          # only the survivors are walked
    assert v["collapsed"] == 6        # but the collapsed ones are accounted for


def test_a_seal_records_the_boundary_the_survivor_links_to(db):
    write(db, 5, age_days=400)
    write(db, 3, age_days=0)
    set_setting(db, "audit_retention_days", "365")
    audit.collapse_expired(db)

    seal = db.query(AuditRetentionSeal).one()
    first_survivor = db.query(AuditEvent).order_by(AuditEvent.id.asc()).first()
    # The seal's boundary hash is exactly what the first surviving event chains
    # back to - that identity is why verification can resume from the seal.
    assert first_survivor.prev_hash == seal.boundary_hash


def test_a_legitimate_collapse_does_not_read_as_truncation(db):
    """The count check must add the collapsed events back, or a checkpoint taken
    before the collapse would make an honest retention look like someone had
    removed the newest entries - a false alarm that would train people to
    ignore the real one."""
    write(db, 6, age_days=400)
    write(db, 4, age_days=0)
    audit.create_checkpoint(db)       # records "10 events"
    set_setting(db, "audit_retention_days", "365")
    audit.collapse_expired(db)        # 6 gone, 4 survive - legitimately

    v = audit.verify_chain(db)
    assert v["ok"] is True            # 4 checked + 6 collapsed == 10 anchored


def test_tampering_with_a_survivor_is_still_caught_after_a_collapse(db):
    """Collapsing the past must not blind the check to the present."""
    write(db, 5, age_days=400)
    write(db, 3, age_days=0)
    set_setting(db, "audit_retention_days", "365")
    audit.collapse_expired(db)

    victim = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    victim.actor = "forged"
    db.commit()
    assert audit.verify_chain(db)["ok"] is False


def test_deleting_a_survivor_is_still_caught_after_a_collapse(db):
    """The end-checkpoint count check has to keep working across a seal: the
    collapsed events are added back before comparing."""
    write(db, 5, age_days=400)
    write(db, 4, age_days=0)
    audit.create_checkpoint(db)       # anchors "9 events total"
    set_setting(db, "audit_retention_days", "365")
    audit.collapse_expired(db)        # 5 collapsed, 4 survive

    survivor = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    db.delete(survivor)
    db.commit()
    assert audit.verify_chain(db)["ok"] is False


# ---------- retention is a decision, not a default ----------

def test_nothing_is_collapsed_while_retention_is_disabled(db):
    """Zero is the default and means keep forever - no surprise deletion on
    upgrade."""
    write(db, 5, age_days=999)
    assert audit.collapse_expired(db)["collapsed"] == 0
    assert db.query(AuditEvent).count() == 5


def test_only_events_past_the_period_are_collapsed(db):
    write(db, 4, age_days=400)         # expired
    write(db, 3, age_days=10)          # within a 365-day window
    set_setting(db, "audit_retention_days", "365")

    assert audit.collapse_expired(db)["collapsed"] == 4
    assert db.query(AuditEvent).count() == 3


# ---------- the SIEM line: externalise, never destroy ----------

def test_undelivered_events_are_not_collapsed_when_a_siem_is_configured(monkeypatch, db):
    """The rule that separates retention from data loss: with a SIEM configured,
    an event it has not acknowledged is evidence not yet externalised, and
    collapsing it would destroy rather than move it."""
    monkeypatch.setattr(audit, "push_enabled", lambda: True)
    write(db, 5, age_days=400, siem="pending")   # expired but NOT delivered
    set_setting(db, "audit_retention_days", "365")

    assert audit.collapse_expired(db)["collapsed"] == 0
    assert db.query(AuditEvent).count() == 5


def test_delivered_events_are_collapsed_but_the_collapse_stops_at_the_first_gap(monkeypatch, db):
    """Delivery is in order and stops at the first failure, so the delivered
    events form a contiguous prefix. Collapse follows that prefix and stops at
    the first undelivered event, even if older ones behind it are expired."""
    monkeypatch.setattr(audit, "push_enabled", lambda: True)
    write(db, 6, age_days=400)
    events = db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()
    for ev in events[:3]:
        ev.siem_status = "sent"
    events[3].siem_status = "pending"     # the gap
    for ev in events[4:]:
        ev.siem_status = "sent"           # delivered, but behind the gap
    db.commit()
    set_setting(db, "audit_retention_days", "365")

    # Only the three before the gap may go.
    assert audit.collapse_expired(db)["collapsed"] == 3
    assert db.query(AuditEvent).count() == 3


def test_a_second_collapse_continues_from_the_first_seal(monkeypatch, db):
    """Retention runs repeatedly; each pass collapses the next expired prefix
    from where the last seal left off, and the chain stays verifiable."""
    write(db, 4, age_days=400)
    set_setting(db, "audit_retention_days", "365")
    audit.collapse_expired(db)
    assert db.query(AuditRetentionSeal).count() == 1

    write(db, 3, age_days=400)             # more, now also expired
    audit.collapse_expired(db)
    assert db.query(AuditRetentionSeal).count() == 2
    assert audit.verify_chain(db)["ok"] is True
