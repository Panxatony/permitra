import asyncio
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import SessionLocal
from .expiry import expire_rules
from .migrations import run_migrations
from .routers import (
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:8080", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
                count = expire_rules(db)
                if count:
                    logger.info("Gültigkeits-Job: %d Regel(n) automatisch deaktiviert", count)
            finally:
                db.close()
        except Exception:  # Job darf die App nie mitreißen
            logger.exception("Gültigkeits-Job fehlgeschlagen")
        await asyncio.sleep(24 * 3600)


@app.on_event("startup")
def startup():
    run_migrations()
    seed_users()
    asyncio.get_event_loop().create_task(expiry_job())


@app.get("/api/health")
def health():
    return {"status": "ok"}
