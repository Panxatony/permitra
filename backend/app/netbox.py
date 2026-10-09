"""NetBox integration: prefix import (configurable statuses) into the staging table.

The API token is stored Fernet-encrypted (the key is derived from SECRET_KEY).
The import is a read-only operation against the NetBox REST API
(/api/ipam/prefixes)."""
from __future__ import annotations

import contextlib
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

from sqlalchemy.orm import Session

from . import crypto
from .messages import _
from .models import NetboxConfig, NetboxPrefix, Workload, WorkloadKind, utcnow

DEFAULT_STATUSES = ("active", "reserved")
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Kept as names of their own: at the call sites "token" says what is being
# handled, and the module stays readable when other secrets join it.


def encrypt_token(raw: str) -> str:
    return crypto.encrypt(raw, "netbox")


def decrypt_token(enc: str) -> str:
    return crypto.decrypt(enc, "netbox")


def get_config(db: Session) -> NetboxConfig | None:
    return db.query(NetboxConfig).first()


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuses to follow a redirect.

    urllib follows redirects by default and carries the Authorization header
    along, so a NetBox that answers 302 could send the token to a host of its
    choosing - and walk the request past the address check below on the way."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError(_("NetBox redirected to {url} – not followed", url=newurl))


def validate_url(raw: str) -> str:
    """Checks a NetBox address before the server is made to call it.

    The address is configured by an admin, but "an admin typed it" is not the
    same as "it is safe to fetch": the server calls it from inside the network,
    so http://169.254.169.254/ or a management interface is reachable from here
    even when it is not from the browser. What is allowed is a plain http(s)
    URL whose host is not loopback (unless switched on), link-local, multicast,
    reserved or unspecified.

    Private ranges (RFC 1918, IPv6 ULA) ARE allowed, on purpose: NetBox is an
    internal service and almost always lives in one of them. So this does not
    keep the server away from internal addresses in general - it keeps it away
    from the special-purpose ones. Names are not resolved here either - DNS can
    change between check and call - so this rejects the obvious literals rather
    than claiming to close SSRF entirely."""
    import ipaddress

    url = (raw or "").strip()
    if not url:
        return ""
    # NetboxConfig.url is String(256); the audit entry for a config change
    # names the URL as its object, which holds less. Refusing here keeps both.
    if len(url) > 128:
        raise ValueError(_("The address is too long (at most 128 characters)"))
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(_("Only http:// and https:// are allowed"))
    host = (parsed.hostname or "").strip("[]")
    if not host:
        raise ValueError(_("The address has no host"))
    # An installation where NetBox really does run on this host is a legitimate
    # setup, so loopback is allowed - but only when it is switched on
    # deliberately, because it is also the classic way into a service that
    # binds to localhost precisely to stay unreachable.
    allow_local = os.getenv("PERMITRA_ALLOW_LOCAL_NETBOX", "").lower() in ("1", "true", "yes")
    if host.lower() in ("localhost", "metadata.google.internal"):
        if not (allow_local and host.lower() == "localhost"):
            raise ValueError(_("'{host}' is not an allowed target", host=host))
        return url
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return url  # a name - checked by the network, not here
    if ip.is_loopback and allow_local:
        return url
    if (ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        raise ValueError(_("'{host}' is not an allowed target", host=host))
    return url


def _request(cfg: NetboxConfig, path_or_url: str) -> dict:
    # An absolute URL only ever comes from the paginating 'next' field, i.e.
    # from the remote side. It has to stay on the configured host - otherwise
    # the response would decide where the next request with our token goes.
    if path_or_url.startswith("http"):
        base, target = urllib.parse.urlparse(cfg.url), urllib.parse.urlparse(path_or_url)
        if (target.scheme, target.netloc) != (base.scheme, base.netloc):
            raise RuntimeError(_("NetBox referred to a different host ({host}) – ignored",
                                 host=target.netloc))
        url = path_or_url
    else:
        url = validate_url(cfg.url).rstrip("/") + path_or_url
    # S310 rationale: the scheme and target are checked in validate_url, and
    # redirects are refused below.
    req = urllib.request.Request(url, headers={  # noqa: S310
        "Authorization": f"Token {decrypt_token(cfg.token_enc)}",
        "Accept": "application/json",
    })
    ctx = None
    if not cfg.verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirects, urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=15) as resp:
            # A NetBox page is small; a bounded read keeps a hostile or broken
            # endpoint from streaming until memory runs out.
            return json.loads(resp.read(MAX_RESPONSE_BYTES))
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


# ---------- workloads ----------

def _slug(obj) -> str:
    return ((obj or {}).get("slug") or (obj or {}).get("name") or "") if isinstance(obj, dict) else ""


def _labels_of(item: dict, kind: str) -> dict:
    """NetBox's classifications as flat labels: role, tenant, site, platform,
    status, cluster, and every tag as `tag.<slug>`. The names are NetBox's
    own, so a selector written against them reads like the NetBox filter."""
    labels = {"kind": kind}
    for key, field in (("role", "role"), ("role", "device_role"), ("tenant", "tenant"), ("site", "site"),
                       ("platform", "platform"), ("cluster", "cluster"), ("device_type", "device_type")):
        value = _slug(item.get(field))
        if value and key not in labels:
            labels[key] = value
    status_val = ((item.get("status") or {}).get("value") or "") if isinstance(item.get("status"), dict) else ""
    if status_val:
        labels["status"] = status_val
    for tag in item.get("tags") or []:
        slug = _slug(tag)
        if slug:
            labels[f"tag.{slug}"] = "true"
    return labels


def _addresses_of(item: dict) -> list[str]:
    out = []
    for field in ("primary_ip4", "primary_ip6"):
        addr = ((item.get(field) or {}).get("address") or "") if isinstance(item.get(field), dict) else ""
        if addr:
            # NetBox stores the interface address with its prefix length; the
            # workload is the host, not its subnet.
            out.append(addr.split("/")[0])
    return out


def import_workloads(db: Session, vrf_id: int) -> dict:
    """Devices and virtual machines with a primary address become workloads.

    Only objects with a primary IP are taken - a workload without an address
    cannot be in a rule. Objects imported earlier are updated in place
    (matched by their NetBox id and kind); ones that vanished from NetBox are
    removed; manual workloads are not touched."""
    cfg = get_config(db)
    if not cfg or not cfg.url or not cfg.token_enc:
        raise ValueError(_("NetBox is not configured"))
    seen: set[str] = set()
    imported, without_address = 0, 0
    for path, kind in (("/api/dcim/devices/?limit=500", WorkloadKind.device),
                       ("/api/virtualization/virtual-machines/?limit=500", WorkloadKind.vm)):
        data = _request(cfg, path)
        while True:
            for item in data.get("results", []):
                addresses = _addresses_of(item)
                if not addresses:
                    without_address += 1
                    continue
                key = f"{kind.value}:{item['id']}"
                seen.add(key)
                name = (item.get("name") or f"{kind.value}-{item['id']}").strip()
                row = (db.query(Workload)
                         .filter(Workload.vrf_id == vrf_id, Workload.source == "netbox",
                                 Workload.netbox_id == item["id"], Workload.kind == kind).first())
                if row is None:
                    # A manual workload of the same name is left alone; the
                    # import gets a distinguishable name instead of overwriting.
                    if db.query(Workload).filter(Workload.vrf_id == vrf_id, Workload.name.ilike(name)).first():
                        name = f"{name} (netbox)"
                    row = Workload(vrf_id=vrf_id, name=name, kind=kind, source="netbox", netbox_id=item["id"])
                    db.add(row)
                else:
                    row.name = name
                row.addresses = addresses
                row.labels = _labels_of(item, kind.value)
                row.description = (item.get("description") or "")[:256]
                row.last_seen = utcnow()
                imported += 1
            nxt = data.get("next")
            if not nxt:
                break
            data = _request(cfg, nxt)
    removed = 0
    for row in db.query(Workload).filter(Workload.vrf_id == vrf_id, Workload.source == "netbox").all():
        if f"{row.kind.value}:{row.netbox_id}" not in seen:
            db.delete(row)
            removed += 1
    db.commit()
    return {"imported": imported, "removed": removed, "without_address": without_address}
