"""NetBox-Anbindung: Prefix-Import (konfigurierbare Status) in die Staging-Tabelle.

Der API-Token wird mit Fernet verschlüsselt gespeichert (Schlüssel aus
SECRET_KEY abgeleitet). Der Import ist ein reiner Lesevorgang gegen die
NetBox-REST-API (/api/ipam/prefixes)."""
from __future__ import annotations

import base64
import hashlib
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from .auth import SECRET_KEY
from .models import NetboxConfig, NetboxPrefix, utcnow

DEFAULT_STATUSES = ("active", "reserved")


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
    return Fernet(key)


def encrypt_token(raw: str) -> str:
    return _fernet().encrypt(raw.encode()).decode() if raw else ""


def decrypt_token(enc: str) -> str:
    if not enc:
        return ""
    try:
        return _fernet().decrypt(enc.encode()).decode()
    except InvalidToken:
        return ""


def get_config(db: Session) -> NetboxConfig | None:
    return db.query(NetboxConfig).first()


def _request(cfg: NetboxConfig, path_or_url: str) -> dict:
    # Absolute URL (z.B. aus dem 'next'-Feld) direkt verwenden, sonst an die
    # Basis-URL anhängen
    url = path_or_url if path_or_url.startswith("http") else cfg.url.rstrip("/") + path_or_url
    req = urllib.request.Request(url, headers={
        "Authorization": f"Token {decrypt_token(cfg.token_enc)}",
        "Accept": "application/json",
    })
    ctx = None
    if not cfg.verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()[:400]
        except Exception:
            pass
        raise RuntimeError(f"NetBox HTTP {exc.code} bei {url}: {body or exc.reason}")


def test_connection(cfg: NetboxConfig) -> dict:
    """Verbindungstest: liefert die Prefix-Anzahl."""
    data = _request(cfg, "/api/ipam/prefixes/?limit=1")
    return {"ok": True, "prefix_total": data.get("count", 0)}


def import_prefixes(db: Session) -> dict:
    """Holt Prefixe der konfigurierten Status aus NetBox in die Staging-Tabelle.

    Bereits übernommene (adopted) Einträge bleiben unangetastet; neue kommen
    hinzu, vorhandene werden aktualisiert; in NetBox verschwundene, noch nicht
    übernommene werden entfernt."""
    cfg = get_config(db)
    if not cfg or not cfg.url or not cfg.token_enc:
        raise ValueError("NetBox ist nicht konfiguriert")

    seen_netbox_ids: set[int] = set()
    fetched = 0
    skipped: list[str] = []
    # Jeden Status EINZELN abfragen – so scheitert der Import nicht, wenn ein
    # Status (z.B. 'planned') auf der Instanz für Prefixe gar nicht existiert
    statuses = [s.strip() for s in (cfg.statuses or "").split(",") if s.strip()] or list(DEFAULT_STATUSES)
    for wanted in statuses:
        query = urllib.parse.urlencode([("status", wanted), ("limit", 500)])
        path = f"/api/ipam/prefixes/?{query}"
        try:
            data = _request(cfg, path)
        except RuntimeError as exc:
            if "not one of the available choices" in str(exc):
                skipped.append(wanted)
                continue
            raise
        while path:
            for p in data.get("results", []):
                fetched += 1
                nid = p["id"]
                seen_netbox_ids.add(nid)
                cidr = p.get("prefix") or ""
                status_val = (p.get("status") or {}).get("value", "")
                vrf = ((p.get("vrf") or {}).get("name") or "") if p.get("vrf") else ""
                desc = p.get("description") or ""
                row = db.query(NetboxPrefix).filter(NetboxPrefix.netbox_id == nid).first()
                if row:
                    row.cidr, row.status, row.vrf, row.description = cidr, status_val, vrf, desc
                    row.last_seen = utcnow()
                else:
                    db.add(NetboxPrefix(netbox_id=nid, cidr=cidr, status=status_val,
                                        vrf=vrf, description=desc, last_seen=utcnow()))
            path = data.get("next")  # absolute URL der nächsten Seite
            if path:
                data = _request(cfg, path)

    # Nicht mehr vorhandene, noch nicht übernommene Staging-Einträge entfernen
    stale = (db.query(NetboxPrefix)
             .filter(NetboxPrefix.adopted == False,  # noqa: E712
                     NetboxPrefix.netbox_id.notin_(seen_netbox_ids or {-1}))
             .all())
    for row in stale:
        db.delete(row)

    cfg.last_import_at = utcnow()
    db.commit()
    pending = db.query(NetboxPrefix).filter(NetboxPrefix.adopted == False).count()  # noqa: E712
    return {"fetched": fetched, "pending": pending, "skipped_statuses": skipped}
