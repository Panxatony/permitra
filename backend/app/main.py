import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import SessionLocal
from .expiry import expire_rules
from .migrations import run_migrations
from .routers import (
    aci_gateways_router,
    address_map_router,
    api_tokens_router,
    audit_router,
    auth_router,
    components_router,
    dashboard_router,
    epgs_router,
    export_router,
    netbox_router,
    objects_router,
    risk_router,
    rules_router,
    settings_router,
    users_router,
    vrfs_router,
    zones_router,
)
from .seed import seed_users


def _lifespan(app):          # eigentliche Implementierung weiter unten
    return lifespan(app)


app = FastAPI(
    lifespan=_lifespan,
    title="Permitra",
    description="Central management of security rules for firewalls (Juniper SRX, Check Point) and ACI contracts",
    version="0.7.4-alpha",
)

# CORS origins are configurable (PERMITRA_CORS_ORIGINS, comma-separated).
# Default: local development origins only. In production set the real frontend
# URL; empty/"*" is deliberately NOT accepted as a wildcard (credentials=True).
_cors_env = os.environ.get("PERMITRA_CORS_ORIGINS", "").strip()
CORS_ORIGINS = (
    [o.strip() for o in _cors_env.split(",") if o.strip() and o.strip() != "*"]
    if _cors_env
    else ["http://localhost:5173", "http://localhost:8080", "http://localhost:3000"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth_router.router)
app.include_router(rules_router.router)
app.include_router(export_router.router)
app.include_router(users_router.router)
app.include_router(zones_router.router)
app.include_router(components_router.router)
app.include_router(aci_gateways_router.router)
app.include_router(address_map_router.router)
app.include_router(dashboard_router.router)
app.include_router(settings_router.router)
app.include_router(audit_router.router)
app.include_router(api_tokens_router.router)
app.include_router(netbox_router.router)
app.include_router(objects_router.router)
app.include_router(epgs_router.router)
app.include_router(risk_router.router)
app.include_router(vrfs_router.router)


logger = logging.getLogger("permitra")


# The background jobs use synchronous I/O: SQLAlchemy sessions, SMTP and the
# SIEM delivery (urllib/socket, 5 s timeout each). Called directly inside an
# async function this would block the event loop - an unreachable SIEM would
# then temporarily stall the entire web server. The actual work therefore runs
# via asyncio.to_thread in a worker thread; the session is created and closed
# there, so it never travels between threads.

def _expiry_once() -> int:
    """One pass of the validity check (blocking, runs in a thread)."""
    from . import notifications
    from .expiry import expiring_rules

    db = SessionLocal()
    try:
        # Capture the state for the recertification mail before deactivating
        soon_expired, soon_expiring = expiring_rules(db, days=30)
        count = expire_rules(db)
        notifications.recertification_due(db, soon_expired, soon_expiring)
        return count
    finally:
        db.close()


EMERGENCY_CHECK_INTERVAL = 15 * 60


async def emergency_job():
    """Checks every quarter hour whether an emergency change ran out of time.

    Not folded into the daily validity job: the emergency window is measured in
    hours, so a once-a-day pass would let a rule stand most of another day past
    it. A window that is not enforced promptly is a reminder, and a reminder is
    what the fast path must not degrade into.
    """
    from .expiry import expire_emergency_rules

    def once() -> int:
        db = SessionLocal()
        try:
            return expire_emergency_rules(db)
        finally:
            db.close()

    while True:
        try:
            count = await asyncio.to_thread(once)
            if count:
                logger.warning("Emergency changes not approved in time: %d deactivated", count)
        except Exception:  # the job must never take the app down with it
            logger.exception("Emergency window job failed")
        await asyncio.sleep(EMERGENCY_CHECK_INTERVAL)


async def expiry_job():
    """Daily job: automatically deactivate expired approved rules."""
    while True:
        try:
            count = await asyncio.to_thread(_expiry_once)
            if count:
                logger.info("Validity job: %d rule(s) automatically deactivated", count)
        except Exception:  # the job must never take the app down with it
            logger.exception("Validity job failed")
        await asyncio.sleep(24 * 3600)


def _siem_delivery_once() -> tuple[dict, dict]:
    """One delivery pass (blocking, runs in a thread): first the events, then the
    checkpoints that anchor the end of the chain."""
    from . import audit

    db = SessionLocal()
    try:
        return audit.deliver_pending(db), audit.deliver_pending_checkpoints(db)
    finally:
        db.close()


SIEM_INTERVAL = 10          # seconds between two passes
SIEM_MAX_BACKOFF = 300      # upper bound when the target is unreachable


async def siem_delivery_job():
    """Reliably delivers pending audit events to a SIEM (#26).
    The state lives in the database, so delivery survives restarts
    (at-least-once). Runs only if a SIEM target is configured.

    If the target is unreachable, the interval grows step by step up to
    SIEM_MAX_BACKOFF - otherwise every pass would run into the same timeouts."""
    from . import audit

    delay = SIEM_INTERVAL
    while True:
        try:
            if audit.push_enabled():
                result, anchors = await asyncio.to_thread(_siem_delivery_once)
                if result.get("sent"):
                    logger.info("SIEM delivery: %d event(s) sent, "
                                "%d pending", result["sent"], result["pending"])
                if anchors.get("sent"):
                    logger.info("SIEM delivery: %d checkpoint(s) anchored",
                                anchors["sent"])
                stuck = (result.get("pending") or 0) and not result.get("sent")
                delay = min(delay * 2, SIEM_MAX_BACKOFF) if stuck else SIEM_INTERVAL
            else:
                delay = SIEM_INTERVAL
        except Exception:  # the delivery job must never take the app down with it
            logger.exception("SIEM delivery failed")
            delay = min(delay * 2, SIEM_MAX_BACKOFF)
        await asyncio.sleep(delay)


def _checkpoint_once() -> tuple[int, str] | None:
    """Writes a checkpoint (blocking, runs in a thread)."""
    from . import audit

    db = SessionLocal()
    try:
        cp = audit.create_checkpoint(db)
        return (cp.event_count, (cp.head_hash or "")[:12]) if cp else None
    finally:
        db.close()


async def audit_checkpoint_job():
    """Regularly anchors the end of the audit chain (#26).

    The hash chain detects modifications of existing entries, but not the
    truncation of the most recent ones. A checkpoint pins down the state
    reached; via the SIEM delivery it leaves the application and is thus beyond
    the reach of anyone with database access."""
    while True:
        try:
            summary = await asyncio.to_thread(_checkpoint_once)
            if summary:
                logger.debug("Audit checkpoint: %d events, head %s", *summary)
        except Exception:  # must never take the app down with it
            logger.exception("Audit checkpoint failed")
        await asyncio.sleep(int(os.environ.get("AUDIT_CHECKPOINT_INTERVAL", "3600")))


def _load_instance_language() -> None:
    """Applies the configured interface language to the message catalogue.

    Messages are raised on every request, so the language is cached rather
    than read from the database each time; settings_router refreshes it when
    an administrator changes it."""
    from . import messages
    from .settings import get_setting

    db = SessionLocal()
    try:
        messages.set_language(get_setting(db, "ui_language"))
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Startup and shutdown.

    Migrations and seeding are blocking database work and therefore run in a
    worker thread - otherwise they would stall the event loop while the
    application is coming up. The background tasks are cancelled on shutdown so
    a reload does not leave orphaned jobs behind."""
    await asyncio.to_thread(run_migrations)
    await asyncio.to_thread(seed_users)
    await asyncio.to_thread(_load_instance_language)
    tasks = [
        asyncio.create_task(expiry_job()),
        asyncio.create_task(emergency_job()),
        asyncio.create_task(siem_delivery_job()),
        asyncio.create_task(audit_checkpoint_job()),
    ]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@app.get("/api/health")
def health():
    return {"status": "ok"}
