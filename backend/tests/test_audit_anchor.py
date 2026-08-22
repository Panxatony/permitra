"""Verankerung des Ketten-Endes gegen Kürzung (Audit-Befund H2).

Die Hash-Kette erkennt Änderungen und Lücken *innerhalb* des Bestands. Werden
dagegen die JÜNGSTEN Einträge gelöscht, bleibt der Rest in sich schlüssig – ohne
festen Bezugspunkt fällt die Kürzung nicht auf. Genau das war die Lücke:
`verify_chain` meldete nach dem Löschen aller Einträge `ok=True` bei `checked=0`.

Ein Prüfpunkt hält fest, wie weit die Kette reichte. Seine volle Wirkung
entfaltet er erst außerhalb der Datenbank – deshalb wird er über dieselbe
zuverlässige Zustellung an das SIEM gegeben.
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


# ---------- Prüfpunkt anlegen ----------

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


# ---------- Der eigentliche Befund: Kürzung ----------

def test_truncating_the_tail_is_detected(db):
    """Der Angriff aus dem Audit: die jüngsten Einträge – typischerweise die
    eigenen Spuren – verschwinden lassen."""
    _seed(db, 6)
    audit.create_checkpoint(db)

    newest = db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(2).all()
    for ev in newest:
        db.delete(ev)
    db.commit()

    result = audit.verify_chain(db)
    assert result["ok"] is False
    assert "gekürzt" in result["reason"]


def test_wiping_the_whole_chain_is_detected(db):
    """Vorher meldete eine leergeräumte Kette ok=True bei checked=0."""
    _seed(db, 4)
    audit.create_checkpoint(db)
    db.query(AuditEvent).delete()
    db.commit()

    result = audit.verify_chain(db)
    assert result["ok"] is False, "leergeräumte Kette gilt weiterhin als unversehrt"
    assert result["checked"] == 0


def test_recomputed_chain_is_detected_via_anchor(db):
    """Wer die Kette nach einer Änderung neu berechnet, verschiebt den Head –
    der Prüfpunkt hält den alten Wert dagegen."""
    _seed(db, 3)
    audit.create_checkpoint(db)

    anchor_event = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    anchor_event.hash = "f" * 64          # Neuberechnung nachstellen
    db.commit()

    result = audit.verify_chain(db)
    assert result["ok"] is False


def test_intact_chain_with_anchor_passes(db):
    """Gegenprobe: unveränderte Kette samt Prüfpunkt bleibt gültig, auch wenn
    danach weitere Ereignisse hinzukommen."""
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


# ---------- Zustellung an das SIEM ----------

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
    assert cp.delivered_at is not None, "ohne SIEM-Ziel gibt es nichts zuzustellen"
    assert audit.siem_status(db)["anchors_pending"] == 0
