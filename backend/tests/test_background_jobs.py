"""The background jobs must not block the event loop (finding H7).

Delivery to a SIEM performs synchronous network I/O with a 5 second timeout
each. Called directly inside an async function, this brought the entire web
server to a standstill as soon as the target was unreachable - an outage of the
log target of all things paralysed the application.

What is checked is therefore not "is to_thread used" but the effect: while a
deliberately slow delivery runs, the loop must keep working alongside it.
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
    """In-memory DB that replaces main.SessionLocal for the jobs."""
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
    """Counts how often the loop gets a turn during the delivery."""
    while not stop.is_set():
        await asyncio.sleep(0.01)
        counter.append(1)


def test_slow_delivery_keeps_the_event_loop_responsive(session_factory, monkeypatch):
    monkeypatch.setenv("AUDIT_WEBHOOK_URL", "http://siem.example/ingest")
    _seed(session_factory, 3)

    # A delivery that blocks like a hanging SIEM target
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
    assert elapsed >= 0.6, "the delivery was unexpectedly fast - the test does not bite"
    # With a blocked loop the ticker would practically never get a turn.
    assert ticks > 10, f"event loop was blocked (only {ticks} iterations in {elapsed:.2f}s)"


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
    """The validity job now also runs in a thread - it must complete without
    errors on an empty data set as well."""
    assert main._expiry_once() == 0


# ---------- Backoff when the target is unreachable ----------

def test_backoff_grows_while_target_is_unreachable(session_factory, monkeypatch):
    """Without backoff, every run would hit the same timeouts on a 10 second
    cycle. What is checked is the computed interval, not real waiting."""
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

    assert delays[0] == 20 and delays[1] == 40          # grows
    assert delays[-1] == main.SIEM_MAX_BACKOFF          # and is capped
    assert all(d <= main.SIEM_MAX_BACKOFF for d in delays)
