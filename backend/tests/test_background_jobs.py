"""Die Hintergrund-Jobs dürfen den Event-Loop nicht blockieren (Befund H7).

Die Zustellung an ein SIEM macht synchrones Netz-I/O mit je 5 Sekunden
Zeitlimit. Direkt in einer async-Funktion aufgerufen, stand damit der gesamte
Webserver still, sobald das Ziel nicht erreichbar war – ausgerechnet der Ausfall
des Log-Ziels legte die Anwendung lahm.

Geprüft wird deshalb nicht "wird to_thread verwendet", sondern die Wirkung:
Läuft eine bewusst langsame Zustellung, muss der Loop nebenher weiterarbeiten.
"""
import asyncio
import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import audit, main
from app.database import Base


@pytest.fixture()
def session_factory(monkeypatch):
    """In-Memory-DB, die main.SessionLocal für die Jobs ersetzt."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Factory = sessionmaker(bind=engine)
    monkeypatch.setattr(main, "SessionLocal", Factory)
    return Factory


def _seed(factory, n=3):
    db = factory()
    try:
        for i in range(n):
            audit.record(db, "admin", "setting.changed", actor="root", object=f"k{i}")
    finally:
        db.close()


async def _ticker(counter, stop):
    """Zählt, wie oft der Loop während der Zustellung drankommt."""
    while not stop.is_set():
        await asyncio.sleep(0.01)
        counter.append(1)


def test_slow_delivery_keeps_the_event_loop_responsive(session_factory, monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "http://siem.example/ingest")
    _seed(session_factory, 3)

    # Zustellung, die wie ein hängendes SIEM-Ziel blockiert
    monkeypatch.setattr(audit, "deliver", lambda ev: (time.sleep(0.25), True)[1])

    async def scenario():
        ticks, stop = [], asyncio.Event()
        tick_task = asyncio.create_task(_ticker(ticks, stop))
        started = time.monotonic()
        result, _ = await asyncio.to_thread(main._siem_delivery_once)
        elapsed = time.monotonic() - started
        stop.set()
        await tick_task
        return result, elapsed, len(ticks)

    result, elapsed, ticks = asyncio.run(scenario())

    assert result["sent"] == 3
    assert elapsed >= 0.6, "die Zustellung war unerwartet schnell – Test greift nicht"
    # Bei blockiertem Loop käme der Ticker praktisch nie dran.
    assert ticks > 10, f"Event-Loop war blockiert (nur {ticks} Durchläufe in {elapsed:.2f}s)"


def test_delivery_once_returns_events_and_anchors(session_factory, monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "http://siem.example/ingest")
    _seed(session_factory, 2)
    db = session_factory()
    try:
        audit.create_checkpoint(db)
    finally:
        db.close()

    monkeypatch.setattr(audit, "deliver", lambda ev: True)
    events, anchors = main._siem_delivery_once()
    assert events["sent"] == 2 and events["pending"] == 0
    assert anchors["sent"] == 1 and anchors["pending"] == 0


def test_checkpoint_once_anchors_and_reports(session_factory):
    _seed(session_factory, 4)
    summary = main._checkpoint_once()
    assert summary is not None
    count, head = summary
    assert count == 4 and len(head) == 12


def test_checkpoint_once_without_events(session_factory):
    assert main._checkpoint_once() is None


def test_expiry_once_runs_without_rules(session_factory):
    """Der Gültigkeits-Job läuft jetzt ebenfalls im Thread – er muss auch auf
    leerem Bestand fehlerfrei durchlaufen."""
    assert main._expiry_once() == 0


# ---------- Backoff bei nicht erreichbarem Ziel ----------

def test_backoff_grows_while_target_is_unreachable(session_factory, monkeypatch):
    """Ohne Backoff liefe jeder Durchlauf im 10-Sekunden-Takt in dieselben
    Zeitlimits. Geprüft wird der berechnete Abstand, nicht echtes Warten."""
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "http://siem.example/ingest")
    _seed(session_factory, 2)
    monkeypatch.setattr(audit, "deliver", lambda ev: False)

    delays = []

    async def scenario():
        delay = main.SIEM_INTERVAL
        for _ in range(8):
            result, _anchors = await asyncio.to_thread(main._siem_delivery_once)
            stuck = (result.get("pending") or 0) and not result.get("sent")
            delay = min(delay * 2, main.SIEM_MAX_BACKOFF) if stuck else main.SIEM_INTERVAL
            delays.append(delay)

    asyncio.run(scenario())

    assert delays[0] == 20 and delays[1] == 40          # wächst
    assert delays[-1] == main.SIEM_MAX_BACKOFF          # und ist gedeckelt
    assert all(d <= main.SIEM_MAX_BACKOFF for d in delays)
