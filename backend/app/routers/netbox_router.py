"""NetBox-Import (Issue #23): Konfiguration/Import durch Admins, Übernahme in
die Zonen-Registry durch Architekt/Betrieb über den Freigabe-Workflow."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from fastapi import Request
from ..auth import require_roles
from .. import audit
from ..database import get_db
from ..models import NetboxConfig, NetboxPrefix, Role, User, ZoneNetwork

router = APIRouter(prefix="/api/netbox", tags=["netbox"])


def _config_out(cfg: NetboxConfig | None) -> dict:
    return {
        "configured": bool(cfg and cfg.url and cfg.token_enc),
        "url": cfg.url if cfg else "",
        "verify_tls": cfg.verify_tls if cfg else True,
        "statuses": (cfg.statuses if cfg and cfg.statuses else "active,reserved"),
        "last_import_at": cfg.last_import_at.isoformat() if cfg and cfg.last_import_at else None,
    }


@router.get("/config")
def get_config(db: Session = Depends(get_db), _: User = Depends(require_roles(Role.admin))):
    from ..netbox import get_config as _get
    return _config_out(_get(db))


@router.put("/config")
def set_config(payload: dict, db: Session = Depends(get_db),
               admin: User = Depends(require_roles(Role.admin)), request: Request = None):
    """URL/Token/TLS speichern. Ein leeres Token-Feld lässt das gespeicherte unverändert."""
    from ..netbox import encrypt_token, get_config as _get

    cfg = _get(db) or NetboxConfig()
    cfg.url = (payload.get("url") or "").strip()
    cfg.verify_tls = bool(payload.get("verify_tls", True))
    if "statuses" in payload:
        cfg.statuses = (payload.get("statuses") or "active,reserved").strip()
    token = (payload.get("token") or "").strip()
    if token:
        cfg.token_enc = encrypt_token(token)
    if cfg.id is None:
        db.add(cfg)
    db.commit()
    audit.record(db, "admin", "netbox.config", actor=admin.username, object=cfg.url,
                 source_ip=audit.client_ip(request))
    return _config_out(cfg)


@router.post("/test")
def test(db: Session = Depends(get_db), _: User = Depends(require_roles(Role.admin))):
    from ..netbox import get_config as _get, test_connection
    cfg = _get(db)
    if not cfg or not cfg.url or not cfg.token_enc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "NetBox ist nicht konfiguriert")
    try:
        return test_connection(cfg)
    except Exception as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"NetBox nicht erreichbar: {exc}")


@router.post("/import")
def run_import(db: Session = Depends(get_db), admin: User = Depends(require_roles(Role.admin)),
               request: Request = None):
    from ..netbox import import_prefixes
    try:
        result = import_prefixes(db)
        audit.record(db, "admin", "netbox.import", actor=admin.username,
                     detail=f"{result.get('fetched', 0)} Prefixe", source_ip=audit.client_ip(request))
        return result
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    except Exception as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"NetBox-Import fehlgeschlagen: {exc}")


@router.get("/prefixes")
def list_prefixes(db: Session = Depends(get_db), _: User = Depends(require_roles(Role.admin, Role.architect, Role.operations))):
    """Importierte, noch nicht übernommene Prefixe (Vorschau vor der Zonen-Zuordnung).
    Bereits in der Registry vorhandene CIDRs werden markiert."""
    existing = {n.cidr for n in db.query(ZoneNetwork.cidr).all()}
    rows = (db.query(NetboxPrefix)
            .filter(NetboxPrefix.adopted == False)  # noqa: E712
            .order_by(NetboxPrefix.cidr).all())
    return [
        {"id": p.id, "cidr": p.cidr, "status": p.status, "vrf": p.vrf,
         "description": p.description, "in_registry": p.cidr in existing}
        for p in rows
    ]


@router.post("/adopt")
def adopt(payload: dict, db: Session = Depends(get_db),
          user: User = Depends(require_roles(Role.architect, Role.operations))):
    """Übernimmt importierte Prefixe in die Zonen-Registry: erzeugt einen
    Sammelantrag (net_add, Quelle 'netbox') mit der je Prefix gewählten Zone.
    Wird nach zwei Freigaben wirksam (wie alle Zonen-Änderungen)."""
    from .zones_router import _create_batch

    items = []
    for entry in payload.get("items") or []:
        prefix = db.get(NetboxPrefix, entry.get("prefix_id") or 0)
        zone = (entry.get("zone") or "").strip()
        if not prefix or not zone:
            continue
        items.append({"type": "net_add", "zone": zone, "cidr": prefix.cidr,
                      "description": prefix.description or f"NetBox-Import ({prefix.status})",
                      "source": "netbox"})
    if not items:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "Keine Prefixe mit Zone ausgewählt")
    return _create_batch(db, user, items, "NetBox-Import")
