"""Anchoring the end of the chain against truncation (audit finding H2).

The hash chain detects modifications and gaps *within* the existing records. If
the NEWEST entries are deleted, however, the remainder stays internally
consistent - without a fixed reference point the truncation goes unnoticed. That
was exactly the gap: after deleting all entries, `verify_chain` reported
`ok=True` with `checked=0`.

A checkpoint records how far the chain reached. It only takes full effect
outside the database - which is why it is handed to the SIEM over the same
reliable delivery path.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import audit
from app.database import Base
from app.models import AuditCheckpoint, AuditEvent


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _seed(db, n=5, start=0):
    for i in range(start, start + n):
        audit.record(db, "admin", "setting.changed", actor="root",
                     object=f"key{i}", detail=f"value{i}", source_ip="203.0.113.1")


# ---------- Creating a checkpoint ----------

def test_checkpoint_records_current_head(db):
    _seed(db, 4)
    cp = audit.create_checkpoint(db)
    head = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    assert cp.event_count == 4
    assert cp.head_hash == head.hash
    assert cp.last_event_id == head.id


def test_no_checkpoint_without_events(db):
    assert audit.create_checkpoint(db) is None


def test_checkpoint_not_duplicated_without_new_events(db):
    _seed(db, 2)
    first = audit.create_checkpoint(db)
    second = audit.create_checkpoint(db)
    assert first.id == second.id
    assert db.query(AuditCheckpoint).count() == 1


def test_new_events_produce_a_new_checkpoint(db):
    _seed(db, 2)
    audit.create_checkpoint(db)
    _seed(db, 3, start=2)
    cp = audit.create_checkpoint(db)
    assert cp.event_count == 5
    assert db.query(AuditCheckpoint).count() == 2


# ---------- The actual finding: truncation ----------

def test_truncating_the_tail_is_detected(db):
    """The attack from the audit: make the newest entries - typically one's own
    traces - disappear."""
    _seed(db, 6)
    audit.create_checkpoint(db)

    newest = db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(2).all()
    for ev in newest:
        db.delete(ev)
    db.commit()

    result = audit.verify_chain(db)
    assert result["ok"] is False
    assert "truncated" in result["reason"]


def test_wiping_the_whole_chain_is_detected(db):
    """Previously, a wiped chain reported ok=True with checked=0."""
    _seed(db, 4)
    audit.create_checkpoint(db)
    db.query(AuditEvent).delete()
    db.commit()

    result = audit.verify_chain(db)
    assert result["ok"] is False, "a wiped chain is still considered intact"
    assert result["checked"] == 0


def test_recomputed_chain_is_detected_via_anchor(db):
    """Recomputing the chain after a modification shifts the head - the
    checkpoint holds the old value against it."""
    _seed(db, 3)
    audit.create_checkpoint(db)

    anchor_event = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    anchor_event.hash = "f" * 64          # simulate a recomputation
    db.commit()

    result = audit.verify_chain(db)
    assert result["ok"] is False


def test_intact_chain_with_anchor_passes(db):
    """Counter-check: an unmodified chain including its checkpoint stays valid,
    even when further events are added afterwards."""
    _seed(db, 3)
    audit.create_checkpoint(db)
    _seed(db, 2, start=3)

    result = audit.verify_chain(db)
    assert result["ok"] is True
    assert result["checked"] == 5
    assert result["anchor"]["event_count"] == 3


def test_verify_without_any_checkpoint_still_works(db):
    _seed(db, 2)
    result = audit.verify_chain(db)
    assert result["ok"] is True and result["anchor"] is None


# ---------- Delivery to the SIEM ----------

def test_checkpoint_is_pending_delivery_when_siem_configured(db, monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "http://siem.example/ingest")
    _seed(db, 2)
    cp = audit.create_checkpoint(db)
    assert cp.delivered_at is None
    assert audit.siem_status(db)["anchors_pending"] == 1


def test_checkpoint_marked_delivered_after_push(db, monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "http://siem.example/ingest")
    _seed(db, 2)
    audit.create_checkpoint(db)

    sent = []
    monkeypatch.setattr(audit, "deliver", lambda ev: (sent.append(ev) or True))
    result = audit.deliver_pending_checkpoints(db)

    assert result == {"sent": 1, "pending": 0}
    assert sent[0]["event"] == "audit.checkpoint"
    assert sent[0]["head_hash"] and sent[0]["event_count"] == 2
    assert audit.latest_checkpoint(db).delivered_at is not None


def test_checkpoint_delivery_retries_after_failure(db, monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "http://siem.example/ingest")
    _seed(db, 2)
    audit.create_checkpoint(db)

    monkeypatch.setattr(audit, "deliver", lambda ev: False)
    assert audit.deliver_pending_checkpoints(db)["pending"] == 1
    assert audit.latest_checkpoint(db).attempts == 1

    monkeypatch.setattr(audit, "deliver", lambda ev: True)
    assert audit.deliver_pending_checkpoints(db) == {"sent": 1, "pending": 0}


def test_checkpoint_needs_no_delivery_without_siem(db, monkeypatch):
    monkeypatch.delenv("AUDIT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("AUDIT_SYSLOG_HOST", raising=False)
    _seed(db, 2)
    cp = audit.create_checkpoint(db)
    assert cp.delivered_at is not None, "without a SIEM target there is nothing to deliver"
    assert audit.siem_status(db)["anchors_pending"] == 0
