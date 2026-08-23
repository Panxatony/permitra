"""NetBox integration: prefix import (configurable statuses) into the staging table.

The API token is stored Fernet-encrypted (the key is derived from SECRET_KEY).
The import is a read-only operation against the NetBox REST API
(/api/ipam/prefixes)."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from .auth import SECRET_KEY
from .messages import _
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
    # Use an absolute URL (e.g. from the 'next' field) as is, otherwise append
    # it to the base URL
    url = path_or_url if path_or_url.startswith("http") else cfg.url.rstrip("/") + path_or_url
    # S310 rationale: the NetBox base URL is operator-configured and stored by an admin,
    # not user-supplied; see the SSRF note in the security audit.
    req = urllib.request.Request(url, headers={  # noqa: S310
        "Authorization": f"Token {decrypt_token(cfg.token_enc)}",
        "Accept": "application/json",
    })
    ctx = None
    if not cfg.verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:  # noqa: S310
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = ""
        with contextlib.suppress(Exception):  # the error body is best-effort context only
            body = exc.read().decode()[:400]
        raise RuntimeError(f"NetBox HTTP {exc.code} bei {url}: {body or exc.reason}") from exc


def test_connection(cfg: NetboxConfig) -> dict:
    """Connection test: returns the number of prefixes."""
    data = _request(cfg, "/api/ipam/prefixes/?limit=1")
    return {"ok": True, "prefix_total": data.get("count", 0)}


def import_prefixes(db: Session) -> dict:
    """Fetches prefixes with the configured statuses from NetBox into the staging table.

    Entries that have already been adopted stay untouched; new ones are added,
    existing ones are updated, and entries that disappeared from NetBox and were
    not adopted yet are removed."""
    cfg = get_config(db)
    if not cfg or not cfg.url or not cfg.token_enc:
        raise ValueError(_("NetBox is not configured"))

    seen_netbox_ids: set[int] = set()
    fetched = 0
    skipped: list[str] = []
    # Query each status SEPARATELY – this way the import does not fail if a
    # status (e.g. 'planned') does not exist for prefixes on that instance
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
            path = data.get("next")  # absolute URL of the next page
            if path:
                data = _request(cfg, path)

    # Remove staging entries that vanished from NetBox and were not adopted yet
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
