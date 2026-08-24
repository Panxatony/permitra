"""Unified audit log for SIEM integration (issue #11, BSI OPS.1.1.5) with
integrity protection and reliable delivery (issue #26).

Consolidates the distributed, person-attributable change events (rule versions,
zone/matrix/network requests) into a machine-readable, chronological audit trail
and adds security-relevant events (login, administration, access) in an
append-only store.

Integrity (#26): every entry in the store carries a SHA-256 `hash` over its own
content AND the `hash` of its predecessor (hash chain). Later modifications to
an event or to the ordering break the chain and are detected by
`verify_chain()`. In addition, checkpoints (`AuditCheckpoint`) regularly anchor
the end of the chain; otherwise truncating the most recent entries would go
unnoticed, because the remainder would still be internally consistent.

WHAT THIS PROTECTION ACHIEVES - AND WHAT IT DOES NOT:
The hash is keyless (SHA-256, not an HMAC). Anyone with WRITE access to the
database can modify an event and recompute the chain from that point on using
the same public function; if they also delete the checkpoints, the forgery can
no longer be proven from within the database. On its own the chain therefore
protects against accidental corruption and against tampering without
recomputation - not against an attacker with database write access.

The load-bearing protection is therefore externalization: events AND checkpoints
are reliably transmitted to a SIEM. What is stored there is beyond the reach of
database access; a comparison exposes any later forgery. Without a configured
SIEM target the protection stays limited to what is described above - that is a
deliberate operational decision, not a property of the application.

Delivery (#26): events are persistently marked as `siem_status='pending'` and
delivered in order to a SIEM by a background worker (see main.siem_delivery_job,
at-least-once). Only after acknowledgement is `siem_status='sent'` set; a crash
or restart loses nothing, because the state lives in the database.

Configuration (optional):
  AUDIT_SYSLOG_HOST / AUDIT_SYSLOG_PORT   syslog target (port defaults to 514)
  AUDIT_SYSLOG_PROTO                       'udp' (default, best-effort) or 'tcp' (acknowledged)
  AUDIT_WEBHOOK_URL                        JSON POST per event (2xx = delivered)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import threading
import urllib.request
from datetime import timezone

from sqlalchemy.orm import Session

from .messages import _, render
from .models import (
    AuditCheckpoint,
    AuditEvent,
    AuditRetentionSeal,
    Rule,
    RuleVersion,
    ZonePolicyChange,
    utcnow,
)

log = logging.getLogger("permitra.audit")

GENESIS = "0" * 64  # prev_hash of the very first event

# Writes to the store are serialized so that the hash chain stays consistently
# linked even under concurrent requests (one process/multiple threads). For the
# multi-process case (uvicorn --workers>1) a Postgres advisory lock inside the
# transaction is used in addition.
_write_lock = threading.Lock()
_PG_ADVISORY_KEY = 0x50524D5452  # "PRMTR"


def _trusted_proxies() -> list:
    """The proxy addresses/networks whose X-Forwarded-For we believe.

    Empty by default, and that is the safe default: X-Forwarded-For is a
    request header, so anything not vouched for by a proxy we placed there is
    attacker-controlled. Parsed fresh (cheap, and lets a container pick up a
    changed value on restart without special-casing)."""
    import ipaddress

    nets = []
    for entry in os.environ.get("PERMITRA_TRUSTED_PROXIES", "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log.warning("Ignoring unparseable PERMITRA_TRUSTED_PROXIES entry %r", entry)
    return nets


def client_ip(request) -> str:
    """Source IP of a request, and never a forgeable one.

    X-Forwarded-For is trusted only when the immediate peer is a configured
    trusted proxy (PERMITRA_TRUSTED_PROXIES) - otherwise the header is ignored
    entirely and the peer address is recorded. This matters more here than
    almost anywhere: the value is hash-chained into the append-only audit log
    as evidence, so a client able to set its own source IP could sign a forged
    origin into the record. Without a trusted proxy configured, the peer is the
    only thing that cannot be spoofed, and it is what we use.

    From a trusted proxy we take the RIGHTMOST X-Forwarded-For entry - the
    address that proxy actually observed. The leftmost entries are whatever the
    client chose to prepend; only the rightmost was appended by infrastructure
    we trust.
    """
    import ipaddress

    if request is None or request.client is None:
        return ""
    peer = request.client.host
    fwd = request.headers.get("x-forwarded-for", "")
    if not fwd:
        return peer
    try:
        peer_addr = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not any(peer_addr in net for net in _trusted_proxies()):
        # The header exists but reached us from an untrusted hop - ignore it.
        return peer
    hops = [h.strip() for h in fwd.split(",") if h.strip()]
    return hops[-1] if hops else peer


# ---------- Hash chain (integrity) -----------------------------------------

def _ts_canonical(dt) -> str:
    """Timestamp rendered deterministically as UTC with microseconds - identical
    when writing and when verifying, even across the DB roundtrip."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")


def event_hash(ts, category, event, actor, object, detail, source_ip, extra,
               prev_hash) -> str:
    """SHA-256 over the canonically serialized content of an event plus the
    predecessor hash. The SIEM delivery columns are deliberately NOT included."""
    payload = {
        "ts": _ts_canonical(ts),
        "category": category or "",
        "event": event or "",
        "actor": actor or "",
        "object": object or "",
        "detail": detail or "",
        "source_ip": source_ip or "",
        "extra": extra,
        "prev_hash": prev_hash or GENESIS,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _row_hash(ev: AuditEvent) -> str:
    return event_hash(ev.ts, ev.category, ev.event, ev.actor, ev.object,
                      ev.detail, ev.source_ip, ev.extra, ev.prev_hash or GENESIS)


def _advisory_lock(db: Session) -> None:
    """Serializes audit writes across processes on Postgres (no-op otherwise).
    The lock is released automatically at transaction end (commit/rollback)."""
    try:
        if db.bind and db.bind.dialect.name == "postgresql":
            from sqlalchemy import text
            db.execute(text("SELECT pg_advisory_xact_lock(:k)"),
                       {"k": _PG_ADVISORY_KEY})
    except Exception:
        log.debug("Advisory lock not available", exc_info=True)


DETAIL_VALUES = "detail_values"   # reserved key in `extra`, see record()


def record(db: Session, category: str, event: str, actor: str = "", object: str = "",
           detail: str = "", source_ip: str = "", extra: dict | None = None,
           detail_values: dict | None = None) -> None:
    """Writes ONE audit entry into the append-only store in a tamper-evident
    (chained) way and marks it for SIEM delivery. Errors must never block the
    business operation.

    `detail` is the English message *template*, untranslated, and its values go
    beside it in `extra`. The store is language-neutral on purpose: an entry is
    a record, it is read long after it was written and possibly by a SIEM that
    has no language at all, so the sentence is put together when somebody reads
    it - see collect(). Translating on the way in froze each entry in whatever
    language the instance was set to that day, which is how an instance running
    in German ends up with an audit log half in English.
    """
    if detail_values:
        extra = {**(extra or {}), DETAIL_VALUES: detail_values}
    ts = utcnow()
    with _write_lock:
        try:
            _advisory_lock(db)
            last = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
            if last and last.hash:
                prev_hash = last.hash
            else:
                # No event to chain from - but if retention has collapsed the
                # whole surviving tail away, the chain does not restart at
                # genesis: it continues from the newest seal's boundary hash,
                # or verification would break across the seal.
                seal = latest_seal(db)
                prev_hash = seal.boundary_hash if seal else GENESIS
            h = event_hash(ts, category, event, actor, object, detail,
                           source_ip, extra, prev_hash)
            db.add(AuditEvent(
                ts=ts, category=category, event=event, actor=actor, object=object,
                detail=detail, source_ip=source_ip, extra=extra,
                prev_hash=prev_hash, hash=h,
                siem_status=("pending" if push_enabled() else "skipped"),
            ))
            db.commit()
        except Exception:  # auditing must not take the business operation down
            log.exception("Audit entry could not be stored")
            db.rollback()


def latest_checkpoint(db: Session) -> AuditCheckpoint | None:
    return db.query(AuditCheckpoint).order_by(AuditCheckpoint.id.desc()).first()


def latest_seal(db: Session):
    """The newest retention seal, or None. Its boundary_hash is where the
    surviving chain begins - verification starts from there instead of genesis."""
    return db.query(AuditRetentionSeal).order_by(AuditRetentionSeal.id.desc()).first()


def _collapsed_total(db: Session) -> int:
    """How many events all seals together have removed - needed to make the
    surviving count add up against the end-checkpoint's total."""
    from sqlalchemy import func
    return db.query(func.coalesce(func.sum(AuditRetentionSeal.collapsed_count), 0)).scalar() or 0


def retention_days(db: Session) -> int:
    from .settings import get_setting
    try:
        return int(get_setting(db, "audit_retention_days"))
    except (ValueError, TypeError):
        return 0


def collapse_expired(db: Session) -> dict:
    """Deletes the audit prefix past the retention period, behind a seal.

    The boundary is the newest event that is older than the retention period AND
    - if a SIEM is configured - has been delivered to it. Delivery is in order
    and stops at the first failure, so the delivered events form a contiguous
    prefix; taking the newest delivered-and-expired one keeps the collapse to a
    provable prefix. Refusing to collapse an undelivered event is the line
    between externalising evidence and destroying it: without it, retention
    would quietly delete records the SIEM never received.

    Returns a small summary. Does nothing when retention is disabled (0), which
    is the default - deletion of personal data is an operator decision, never a
    surprise.
    """
    from datetime import timedelta

    days = retention_days(db)
    if days <= 0:
        return {"collapsed": 0, "reason": "retention disabled"}

    cutoff = utcnow() - timedelta(days=days)
    siem = push_enabled()

    # Walk the remaining events oldest-first and advance the boundary while each
    # is both expired and (if a SIEM is configured) delivered. No id watermark:
    # previously collapsed events are already deleted, so the oldest remaining
    # one is exactly where the surviving chain begins - and not depending on ids
    # keeps this correct even where they are reused (SQLite after a full delete).
    boundary = None
    collapsed = 0
    q = db.query(AuditEvent).order_by(AuditEvent.id.asc()).yield_per(500)
    for ev in q:
        ts = _aware(ev.ts)
        if ts >= cutoff:
            break  # reached events still within the retention window
        if siem and ev.siem_status == "pending":
            break  # not yet externalised - would destroy evidence, so stop here
        boundary = ev
        collapsed += 1

    if boundary is None or collapsed == 0:
        return {"collapsed": 0, "reason": "nothing expired and deliverable"}

    # Snapshot before the delete: after commit the boundary row is gone, so
    # reading its attributes back would raise.
    boundary_id = boundary.id
    boundary_hash = boundary.hash or ""

    new_seal = AuditRetentionSeal(
        sealed_at=utcnow(),
        boundary_event_id=boundary_id,
        boundary_hash=boundary_hash,
        collapsed_count=collapsed,
        delivered_at=None if siem else utcnow(),
    )
    db.add(new_seal)
    db.flush()
    seal_id = new_seal.id
    deleted = (db.query(AuditEvent)
               .filter(AuditEvent.id <= boundary_id)
               .delete(synchronize_session=False))
    db.commit()
    # The bulk delete bypasses the session, so any collapsed rows still held in
    # the identity map are now stale - drop them, or the next access raises
    # ObjectDeletedError.
    db.expire_all()
    log.info("Audit retention: collapsed %d event(s) up to id %d behind seal %d",
             deleted, boundary_id, seal_id)
    return {"collapsed": deleted, "boundary_event_id": boundary_id, "seal_id": seal_id}


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def create_checkpoint(db: Session) -> AuditCheckpoint | None:
    """Records the current state of the chain as a checkpoint (anchoring).

    Without events there is nothing to anchor. If nothing has happened since the
    last checkpoint, no new one is created."""
    last = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    if last is None:
        return None
    previous = latest_checkpoint(db)
    if previous and previous.last_event_id == last.id:
        return previous
    cp = AuditCheckpoint(
        ts=utcnow(),
        last_event_id=last.id,
        event_count=db.query(AuditEvent).count(),
        head_hash=last.hash or "",
        delivered_at=None if push_enabled() else utcnow(),
    )
    db.add(cp)
    db.commit()
    db.refresh(cp)
    return cp


def _check_against_checkpoint(db: Session, checked: int) -> dict | None:
    """Compares the current data against the most recent checkpoint. Detects the
    truncation of the newest entries, which the chaining alone cannot see."""
    cp = latest_checkpoint(db)
    if cp is None:
        return None
    seal = latest_seal(db)
    anchor = db.get(AuditEvent, cp.last_event_id)
    if anchor is None:
        # A missing anchor is truncation - unless it was legitimately collapsed
        # behind a seal, in which case only the count still has to add up.
        if seal and cp.last_event_id <= seal.boundary_event_id:
            if checked < cp.event_count:
                return {"ok": False, "checked": checked, "broken_at_id": None,
                        "reason": _("Only {checked} entries accounted for, the "
                                    "checkpoint records {count}",
                                    checked=checked, count=cp.event_count)}
            return None
        return {"ok": False, "checked": checked, "broken_at_id": cp.last_event_id,
                "reason": _("Anchored entry {event_id} is missing – the chain was "
                            "truncated after the checkpoint of {ts:%Y-%m-%d %H:%M}",
                            event_id=cp.last_event_id, ts=cp.ts)}
    if (anchor.hash or "") != cp.head_hash:
        return {"ok": False, "checked": checked, "broken_at_id": cp.last_event_id,
                "reason": _("Anchored entry no longer matches the checkpoint "
                            "(the chain was recalculated afterwards)")}
    if checked < cp.event_count:
        return {"ok": False, "checked": checked, "broken_at_id": None,
                "reason": _("Only {checked} entries present, the checkpoint records "
                            "{count} – entries have been removed",
                            checked=checked, count=cp.event_count)}
    return None


def verify_chain(db: Session) -> dict:
    """Verifies the complete hash chain. Returns ok=True only if every entry is
    unchanged in content, links seamlessly to its predecessor AND the most
    recent checkpoint is still covered (protection against truncation)."""
    # A retention seal moves the start of the provable chain forward: the events
    # before it are gone, but the seal records the hash the first survivor links
    # back to, so verification begins there instead of at genesis.
    seal = latest_seal(db)
    prev = seal.boundary_hash if seal else GENESIS
    collapsed = _collapsed_total(db)
    checked = 0
    for ev in db.query(AuditEvent).order_by(AuditEvent.id.asc()).yield_per(500):
        checked += 1
        if (ev.prev_hash or GENESIS) != prev:
            return {"ok": False, "checked": checked, "broken_at_id": ev.id,
                    "reason": _("prev_hash does not match the predecessor "
                                "(order changed or entry removed)")}
        if _row_hash(ev) != (ev.hash or ""):
            return {"ok": False, "checked": checked, "broken_at_id": ev.id,
                    "reason": _("Hash does not match the content (entry modified)")}
        prev = ev.hash

    broken = _check_against_checkpoint(db, checked + collapsed)
    if broken:
        return broken

    cp = latest_checkpoint(db)
    return {
        "ok": True,
        "checked": checked,
        "collapsed": collapsed,
        "head_hash": prev if checked else (seal.boundary_hash if seal else GENESIS),
        "anchor": {
            "event_count": cp.event_count,
            "ts": _iso(cp.ts),
            "delivered": cp.delivered_at is not None,
            "delivered_at": _iso(cp.delivered_at),
        } if cp else None,
    }


def _iso(dt):
    return dt.isoformat() if dt else None


def collect(db: Session, since: str | None = None, limit: int = 500,
            event_type: str | None = None) -> list[dict]:
    """Chronological audit log (newest first).

    event_type: 'rule' | 'zone_change' | a store category | None (all)."""
    events: list[dict] = []

    # Persistent append-only store (rule.deleted, auth, admin, ...)
    aq = db.query(AuditEvent).order_by(AuditEvent.ts.desc())
    if event_type:
        aq = aq.filter(AuditEvent.category == event_type)
    for a in aq.limit(2000).all():
        events.append({
            "type": a.category,
            "event": a.event,
            "object": a.object,
            "actor": a.actor,
            # Stored language-neutral, put into words here - see record()
            "detail": render(a.detail, (a.extra or {}).get(DETAIL_VALUES)),
            "source_ip": a.source_ip,
            "hash": a.hash,
            "timestamp": _iso(a.ts),
        })

    if event_type in (None, "rule"):
        q = (
            db.query(RuleVersion, Rule.rule_id)
            .join(Rule, RuleVersion.rule_pk == Rule.id)
            .order_by(RuleVersion.changed_at.desc())
            .limit(2000)
        )
        for v, rid in q.all():
            events.append({
                "type": "rule",
                "event": "rule.version",
                "object": rid,
                "version": v.version,
                "actor": v.changed_by,
                "detail": render(v.change_note, v.change_values),
                "timestamp": _iso(v.changed_at),
            })

    if event_type in (None, "zone_change"):
        for c in (db.query(ZonePolicyChange)
                  .order_by(ZonePolicyChange.requested_at.desc()).limit(2000).all()):
            events.append({
                "type": "zone_change",
                "event": f"zone_change.{c.change_type}",
                "object": f"{c.from_zone}" + (f" → {c.to_zone}" if c.to_zone else ""),
                "actor": c.decided_by or c.requested_by,
                "status": c.status,
                "detail": (c.comment or "").strip(),
                "timestamp": _iso(c.decided_at or c.requested_at),
            })

    events.sort(key=lambda e: e["timestamp"] or "", reverse=True)
    if since:
        events = [e for e in events if (e["timestamp"] or "") >= since]
    return events[:limit]


# ---------- SIEM delivery (at-least-once outbox) ----------------------------

def push_enabled() -> bool:
    return bool(os.environ.get("AUDIT_SYSLOG_HOST", "").strip()
                or os.environ.get("AUDIT_WEBHOOK_URL", "").strip())


def _event_payload(ev: AuditEvent) -> dict:
    return {
        "type": ev.category, "event": ev.event, "actor": ev.actor,
        "object": ev.object, "detail": ev.detail, "source_ip": ev.source_ip,
        "extra": ev.extra, "hash": ev.hash, "timestamp": _iso(ev.ts),
    }


def _syslog(event: dict) -> bool:
    """Sends an event via syslog. UDP is best-effort (success = no error while
    sending); TCP is acknowledged by the connection."""
    host = os.environ.get("AUDIT_SYSLOG_HOST", "").strip()
    if not host:
        return True  # no syslog target configured
    port = int(os.environ.get("AUDIT_SYSLOG_PORT", "514"))
    proto = os.environ.get("AUDIT_SYSLOG_PROTO", "udp").strip().lower()
    # RFC 5424, facility 13 (log audit) * 8 + severity 6 (info) = 110
    msg = f"<110>1 - permitra - {event.get('event')} - - {json.dumps(event, default=str)}"
    try:
        if proto == "tcp":
            # RFC 6587 octet-counting framing
            data = msg.encode()
            framed = f"{len(data)} ".encode() + data
            with socket.create_connection((host, port), timeout=5) as s:
                s.sendall(framed)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(msg.encode()[:2048], (host, port))
        return True
    except Exception as exc:
        log.warning("Audit syslog delivery failed: %s", exc)
        return False


def _webhook(event: dict) -> bool:
    url = os.environ.get("AUDIT_WEBHOOK_URL", "").strip()
    if not url:
        return True  # no webhook target configured
    body = json.dumps({"source": "permitra", **event}, default=str).encode()
    # S310 rationale: the target URL is operator-configured (AUDIT_WEBHOOK_URL), not
    # user-supplied; see the SSRF note in the security audit.
    req = urllib.request.Request(url, data=body, method="POST",  # noqa: S310
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            return 200 <= resp.status < 300
    except Exception as exc:
        log.warning("Audit webhook delivery failed: %s", exc)
        return False


def deliver(event: dict) -> bool:
    """Delivers an event to all configured targets. Success only if every
    configured target acknowledges (or UDP syslog sends without error)."""
    return _syslog(event) and _webhook(event)


def deliver_pending(db: Session, batch: int = 200) -> dict:
    """Delivers pending events in strict order (id ascending). Stops at the
    first failure so that the ordering is preserved and the next run retries
    from the same position."""
    if not push_enabled():
        return {"sent": 0, "pending": 0}
    rows = (db.query(AuditEvent)
            .filter(AuditEvent.siem_status == "pending")
            .order_by(AuditEvent.id.asc()).limit(batch).all())
    sent = 0
    for ev in rows:
        ok = deliver(_event_payload(ev))
        ev.siem_attempts = (ev.siem_attempts or 0) + 1
        if ok:
            ev.siem_status = "sent"
            ev.siem_sent_at = utcnow()
            db.commit()
            sent += 1
        else:
            db.commit()  # persist the attempt counter, preserve the ordering
            break
    remaining = (db.query(AuditEvent)
                 .filter(AuditEvent.siem_status == "pending").count())
    return {"sent": sent, "pending": remaining}


def deliver_pending_checkpoints(db: Session, batch: int = 20) -> dict:
    """Delivers checkpoints that have not been transmitted yet to the SIEM.

    A checkpoint only takes effect outside the database: whoever tampers with
    the audit table cannot reach the copy stored there."""
    if not push_enabled():
        return {"sent": 0, "pending": 0}
    rows = (db.query(AuditCheckpoint)
            .filter(AuditCheckpoint.delivered_at.is_(None))
            .order_by(AuditCheckpoint.id.asc()).limit(batch).all())
    sent = 0
    for cp in rows:
        payload = {
            "type": "audit", "event": "audit.checkpoint",
            "actor": "permitra", "object": f"#{cp.event_count}",
            "detail": "Anchoring of the audit chain head",
            "event_count": cp.event_count, "last_event_id": cp.last_event_id,
            "head_hash": cp.head_hash, "timestamp": _iso(cp.ts),
        }
        cp.attempts = (cp.attempts or 0) + 1
        if deliver(payload):
            cp.delivered_at = utcnow()
            db.commit()
            sent += 1
        else:
            db.commit()
            break
    remaining = (db.query(AuditCheckpoint)
                 .filter(AuditCheckpoint.delivered_at.is_(None)).count())
    return {"sent": sent, "pending": remaining}


def deliver_pending_seals(db: Session, batch: int = 20) -> dict:
    """Delivers retention seals to the SIEM.

    A seal is the anchor for a segment whose individual events have been
    deleted, so its copy at the SIEM is the only remaining proof the collapsed
    prefix ever linked up. Same durable outbox as events and checkpoints."""
    if not push_enabled():
        return {"sent": 0, "pending": 0}
    rows = (db.query(AuditRetentionSeal)
            .filter(AuditRetentionSeal.delivered_at.is_(None))
            .order_by(AuditRetentionSeal.id.asc()).limit(batch).all())
    sent = 0
    for seal in rows:
        payload = {
            "type": "audit", "event": "audit.retention_seal",
            "actor": "permitra", "object": f"seal#{seal.id}",
            "detail": "Audit prefix collapsed under the retention period",
            "collapsed_count": seal.collapsed_count,
            "boundary_event_id": seal.boundary_event_id,
            "boundary_hash": seal.boundary_hash, "timestamp": _iso(seal.sealed_at),
        }
        seal.attempts = (seal.attempts or 0) + 1
        if deliver(payload):
            seal.delivered_at = utcnow()
            db.commit()
            sent += 1
        else:
            db.commit()
            break
    remaining = (db.query(AuditRetentionSeal)
                 .filter(AuditRetentionSeal.delivered_at.is_(None)).count())
    return {"sent": sent, "pending": remaining}


def siem_status(db: Session) -> dict:
    """Overview of the delivery state for the admin view."""
    def _count(status):
        return db.query(AuditEvent).filter(AuditEvent.siem_status == status).count()
    cp = latest_checkpoint(db)
    return {
        "enabled": push_enabled(),
        "pending": _count("pending"),
        "sent": _count("sent"),
        "skipped": _count("skipped"),
        "anchor": {
            "event_count": cp.event_count,
            "ts": _iso(cp.ts),
            "delivered": cp.delivered_at is not None,
        } if cp else None,
        "anchors_pending": db.query(AuditCheckpoint).filter(
            AuditCheckpoint.delivered_at.is_(None)).count(),
        # Retention: how far the chain has been collapsed, and whether the seals
        # that prove the collapsed segments still owe delivery to the SIEM.
        "retention_days": retention_days(db),
        "events_collapsed": _collapsed_total(db),
        "seals": db.query(AuditRetentionSeal).count(),
        "seals_pending": db.query(AuditRetentionSeal).filter(
            AuditRetentionSeal.delivered_at.is_(None)).count(),
    }
