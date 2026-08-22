"""Tests for integrity protection (hash chain) and reliable SIEM delivery of the
audit log (issue #26)."""
import itertools

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import audit
from app.database import Base
from app.models import AuditEvent


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _seed(db, n=5):
    for i in range(n):
        audit.record(db, "admin", "setting.changed", actor="root",
                     object=f"key{i}", detail=f"value{i}", source_ip="203.0.113.1")


def test_chain_links_and_verifies(db):
    _seed(db, 5)
    rows = db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()
    assert rows[0].prev_hash == audit.GENESIS
    # Every entry references the hash of its predecessor
    for prev, cur in itertools.pairwise(rows):
        assert cur.prev_hash == prev.hash
    result = audit.verify_chain(db)
    assert result["ok"] is True
    assert result["checked"] == 5
    assert result["head_hash"] == rows[-1].hash


def test_tamper_content_is_detected(db):
    _seed(db, 4)
    victim = db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()[1]
    victim.detail = "changed in secret"      # tamper with the content, leave the hash unchanged
    db.commit()
    result = audit.verify_chain(db)
    assert result["ok"] is False
    assert result["broken_at_id"] == victim.id
    assert "content" in result["reason"]


def test_deletion_breaks_chain(db):
    _seed(db, 4)
    rows = db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()
    db.delete(rows[1])                        # remove one entry
    db.commit()
    result = audit.verify_chain(db)
    assert result["ok"] is False
    # The successor of the deleted entry no longer matches its predecessor
    assert result["broken_at_id"] == rows[2].id
    assert "prev_hash" in result["reason"]


def test_empty_chain_is_valid(db):
    result = audit.verify_chain(db)
    assert result["ok"] is True and result["checked"] == 0
    assert result["head_hash"] == audit.GENESIS


def test_siem_status_pending_when_enabled(db, monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "http://siem.example/ingest")
    _seed(db, 3)
    status = audit.siem_status(db)
    assert status["enabled"] is True
    assert status["pending"] == 3 and status["sent"] == 0


def test_siem_status_skipped_when_disabled(db, monkeypatch):
    monkeypatch.delenv("AUDIT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("AUDIT_SYSLOG_HOST", raising=False)
    _seed(db, 3)
    status = audit.siem_status(db)
    assert status["enabled"] is False
    assert status["skipped"] == 3 and status["pending"] == 0


def test_deliver_pending_marks_sent_in_order(db, monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "http://siem.example/ingest")
    _seed(db, 3)
    calls = []
    monkeypatch.setattr(audit, "deliver", lambda ev: (calls.append(ev["object"]) or True))
    result = audit.deliver_pending(db)
    assert result == {"sent": 3, "pending": 0}
    assert calls == ["key0", "key1", "key2"]      # strict ordering
    assert all(e.siem_status == "sent" and e.siem_sent_at is not None
               for e in db.query(AuditEvent).all())


def test_deliver_pending_stops_on_failure_preserving_order(db, monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "http://siem.example/ingest")
    _seed(db, 4)

    # Delivery fails starting with the third event
    def flaky(ev):
        return ev["object"] in ("key0", "key1")
    monkeypatch.setattr(audit, "deliver", flaky)

    result = audit.deliver_pending(db)
    assert result["sent"] == 2 and result["pending"] == 2
    rows = db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()
    assert [r.siem_status for r in rows] == ["sent", "sent", "pending", "pending"]
    # The failed entry was attempted once, the one behind it not at all
    assert rows[2].siem_attempts == 1 and rows[3].siem_attempts == 0

    # The next run delivers the remaining ones as soon as the SIEM is available again
    monkeypatch.setattr(audit, "deliver", lambda ev: True)
    result2 = audit.deliver_pending(db)
    assert result2 == {"sent": 2, "pending": 0}
