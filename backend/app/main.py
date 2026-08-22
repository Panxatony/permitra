import asyncio
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import SessionLocal
from .expiry import expire_rules
from .migrations import run_migrations
from .routers import (
    netbox_router,
    api_tokens_router,
    audit_router,
    settings_router,
    aci_gateways_router,
    address_map_router,
    auth_router,
    dashboard_router,
    epgs_router,
    objects_router,
    components_router,
    export_router,
    rules_router,
    users_router,
    vrfs_router,
    zones_router,
)
from .seed import seed_users

app = FastAPI(
    title="Permitra",
    description="Zentrale Verwaltung von Sicherheitsregeln für Firewalls (Juniper SRX, Check Point) und ACI Contracts",
    version="0.1.0",
)

# CORS-Origins konfigurierbar (PERMITRA_CORS_ORIGINS, kommagetrennt).
# Default: nur lokale Entwicklungs-Origins. In Produktion die echte Frontend-URL
# setzen; leer/"*" wird bewusst NICHT als Wildcard akzeptiert (credentials=True).
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
app.include_router(vrfs_router.router)


logger = logging.getLogger("permitra")


# Die Hintergrund-Jobs arbeiten mit synchronem I/O: SQLAlchemy-Sessions, SMTP
# und die SIEM-Zustellung (urllib/socket, je 5 s Zeitlimit). In einer
# async-Funktion direkt aufgerufen, würde das den Event-Loop blockieren – ein
# nicht erreichbares SIEM legte damit den gesamten Webserver zeitweise still.
# Deshalb läuft die eigentliche Arbeit über asyncio.to_thread in einem
# Arbeits-Thread; die Session wird dort erzeugt und geschlossen, sie wandert
# also nie zwischen Threads.

def _expiry_once() -> int:
    """Ein Durchlauf der Gültigkeitsprüfung (blockierend, läuft im Thread)."""
    from . import notifications
    from .expiry import expiring_rules

    db = SessionLocal()
    try:
        # Vor dem Deaktivieren den Stand für die Rezertifizierungs-Mail erfassen
        soon_expired, soon_expiring = expiring_rules(db, days=30)
        count = expire_rules(db)
        notifications.recertification_due(db, soon_expired, soon_expiring)
        return count
    finally:
        db.close()


async def expiry_job():
    """Täglicher Job: abgelaufene freigegebene Regeln automatisch deaktivieren."""
    while True:
        try:
            count = await asyncio.to_thread(_expiry_once)
            if count:
                logger.info("Gültigkeits-Job: %d Regel(n) automatisch deaktiviert", count)
        except Exception:  # Job darf die App nie mitreißen
            logger.exception("Gültigkeits-Job fehlgeschlagen")
        await asyncio.sleep(24 * 3600)


def _siem_delivery_once() -> tuple[dict, dict]:
    """Ein Zustelldurchlauf (blockierend, läuft im Thread): erst die Ereignisse,
    dann die Prüfpunkte zur Verankerung des Ketten-Endes."""
    from . import audit

    db = SessionLocal()
    try:
        return audit.deliver_pending(db), audit.deliver_pending_checkpoints(db)
    finally:
        db.close()


SIEM_INTERVAL = 10          # Sekunden zwischen zwei Durchläufen
SIEM_MAX_BACKOFF = 300      # Obergrenze, wenn das Ziel nicht erreichbar ist


async def siem_delivery_job():
    """Stellt ausstehende Audit-Ereignisse zuverlässig an ein SIEM zu (#26).
    Der Zustand liegt in der Datenbank, deshalb übersteht die Zustellung
    Neustarts (at-least-once). Läuft nur, wenn ein SIEM-Ziel konfiguriert ist.

    Ist das Ziel nicht erreichbar, wächst der Abstand schrittweise bis
    SIEM_MAX_BACKOFF – sonst liefe jeder Durchlauf in dieselben Zeitlimits."""
    from . import audit

    delay = SIEM_INTERVAL
    while True:
        try:
            if audit.push_enabled():
                result, anchors = await asyncio.to_thread(_siem_delivery_once)
                if result.get("sent"):
                    logger.info("SIEM-Zustellung: %d Ereignis(se) gesendet, "
                                "%d ausstehend", result["sent"], result["pending"])
                if anchors.get("sent"):
                    logger.info("SIEM-Zustellung: %d Prüfpunkt(e) verankert",
                                anchors["sent"])
                stuck = (result.get("pending") or 0) and not result.get("sent")
                delay = min(delay * 2, SIEM_MAX_BACKOFF) if stuck else SIEM_INTERVAL
            else:
                delay = SIEM_INTERVAL
        except Exception:  # Zustell-Job darf die App nie mitreißen
            logger.exception("SIEM-Zustellung fehlgeschlagen")
            delay = min(delay * 2, SIEM_MAX_BACKOFF)
        await asyncio.sleep(delay)


def _checkpoint_once() -> tuple[int, str] | None:
    """Setzt einen Prüfpunkt (blockierend, läuft im Thread)."""
    from . import audit

    db = SessionLocal()
    try:
        cp = audit.create_checkpoint(db)
        return (cp.event_count, (cp.head_hash or "")[:12]) if cp else None
    finally:
        db.close()


async def audit_checkpoint_job():
    """Verankert das Ende der Audit-Kette regelmäßig (#26).

    Die Verkettung erkennt Änderungen im Bestand, nicht aber das Abschneiden
    der jüngsten Einträge. Ein Prüfpunkt hält den erreichten Stand fest; über
    die SIEM-Zustellung verlässt er die Anwendung und ist damit dem Zugriff
    auf die Datenbank entzogen."""
    while True:
        try:
            summary = await asyncio.to_thread(_checkpoint_once)
            if summary:
                logger.debug("Audit-Prüfpunkt: %d Ereignisse, Head %s", *summary)
        except Exception:  # darf die App nie mitreißen
            logger.exception("Audit-Prüfpunkt fehlgeschlagen")
        await asyncio.sleep(int(os.environ.get("AUDIT_CHECKPOINT_INTERVAL", "3600")))


@app.on_event("startup")
def startup():
    run_migrations()
    seed_users()
    asyncio.get_event_loop().create_task(expiry_job())
    asyncio.get_event_loop().create_task(siem_delivery_job())
    asyncio.get_event_loop().create_task(audit_checkpoint_job())


@app.get("/api/health")
def health():
    return {"status": "ok"}
