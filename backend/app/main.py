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


async def expiry_job():
    """Täglicher Job: abgelaufene freigegebene Regeln automatisch deaktivieren."""
    while True:
        try:
            db = SessionLocal()
            try:
                from .expiry import expiring_rules
                from . import notifications

                # Vor dem Deaktivieren den Stand für die Rezertifizierungs-Mail erfassen
                soon_expired, soon_expiring = expiring_rules(db, days=30)
                count = expire_rules(db)
                if count:
                    logger.info("Gültigkeits-Job: %d Regel(n) automatisch deaktiviert", count)
                notifications.recertification_due(db, soon_expired, soon_expiring)
            finally:
                db.close()
        except Exception:  # Job darf die App nie mitreißen
            logger.exception("Gültigkeits-Job fehlgeschlagen")
        await asyncio.sleep(24 * 3600)


async def siem_delivery_job():
    """Stellt ausstehende Audit-Ereignisse zuverlässig an ein SIEM zu (#26).
    Der Zustand liegt in der Datenbank, deshalb übersteht die Zustellung
    Neustarts (at-least-once). Läuft nur, wenn ein SIEM-Ziel konfiguriert ist."""
    from . import audit

    while True:
        try:
            if audit.push_enabled():
                db = SessionLocal()
                try:
                    result = audit.deliver_pending(db)
                    if result.get("sent"):
                        logger.info("SIEM-Zustellung: %d Ereignis(se) gesendet, "
                                    "%d ausstehend", result["sent"], result["pending"])
                finally:
                    db.close()
        except Exception:  # Zustell-Job darf die App nie mitreißen
            logger.exception("SIEM-Zustellung fehlgeschlagen")
        await asyncio.sleep(10)


@app.on_event("startup")
def startup():
    run_migrations()
    seed_users()
    asyncio.get_event_loop().create_task(expiry_job())
    asyncio.get_event_loop().create_task(siem_delivery_job())


@app.get("/api/health")
def health():
    return {"status": "ok"}
