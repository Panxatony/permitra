"""Einheitliches Audit-Log für SIEM-Integration (Issue #11, BSI OPS.1.1.5)
mit Integritätssicherung und zuverlässiger Zustellung (Issue #26).

Fasst die verteilten, personengebundenen Änderungsereignisse (Regel-Versionen,
Zonen-/Matrix-/Netzwerk-Anträge) zu einem maschinenlesbaren, chronologischen
Audit-Log zusammen und ergänzt sicherheitsrelevante Ereignisse (Anmeldung,
Administration, Zugriffe) in einem append-only Store.

Integrität (#26): Jeder Eintrag im Store trägt einen SHA-256-`hash` über seinen
Inhalt UND den `hash` des Vorgängers (Hash-Kette). Nachträgliche Änderungen an
einem Ereignis oder an der Reihenfolge brechen die Kette und werden von
`verify_chain()` erkannt.

Zustellung (#26): Ereignisse werden persistent als `siem_status='pending'`
markiert und von einem Hintergrund-Worker (siehe main.siem_delivery_job) in
Reihenfolge an ein SIEM zugestellt (at-least-once). Erst nach Bestätigung wird
`siem_status='sent'` gesetzt; ein Absturz/Neustart verliert nichts, weil der
Zustand in der Datenbank liegt.

Konfiguration (optional):
  AUDIT_SYSLOG_HOST / AUDIT_SYSLOG_PORT   Syslog-Ziel (Port default 514)
  AUDIT_SYSLOG_PROTO                       'udp' (default, best-effort) oder 'tcp' (quittiert)
  AUDIT_WEBHOOK_URL                        JSON-POST je Ereignis (2xx = zugestellt)
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

from .models import AuditEvent, Rule, RuleVersion, ZonePolicyChange, utcnow

log = logging.getLogger("permitra.audit")

GENESIS = "0" * 64  # prev_hash des allerersten Ereignisses

# Schreibvorgänge in den Store werden serialisiert, damit die Hash-Kette auch
# bei nebenläufigen Requests konsistent verkettet wird (ein Prozess/mehrere
# Threads). Für den Mehr-Prozess-Fall (uvicorn --workers>1) kommt zusätzlich ein
# Postgres-Advisory-Lock innerhalb der Transaktion zum Einsatz.
_write_lock = threading.Lock()
_PG_ADVISORY_KEY = 0x50524D5452  # "PRMTR"


def client_ip(request) -> str:
    """Quell-IP eines Requests: erster Hop aus X-Forwarded-For (hinter dem
    Reverse-Proxy), sonst die direkte Peer-Adresse."""
    if request is None:
        return ""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


# ---------- Hash-Kette (Integrität) ----------------------------------------

def _ts_canonical(dt) -> str:
    """Zeitstempel deterministisch als UTC mit Mikrosekunden – identisch beim
    Schreiben und beim Verifizieren, auch über den DB-Roundtrip hinweg."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")


def event_hash(ts, category, event, actor, object, detail, source_ip, extra,
               prev_hash) -> str:
    """SHA-256 über den kanonisch serialisierten Inhalt eines Ereignisses plus
    den Vorgänger-Hash. Die SIEM-Zustellspalten fließen bewusst NICHT ein."""
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
    """Serialisiert Audit-Writes prozessübergreifend auf Postgres (no-op sonst).
    Der Lock wird am Transaktionsende (commit/rollback) automatisch freigegeben."""
    try:
        if db.bind and db.bind.dialect.name == "postgresql":
            from sqlalchemy import text
            db.execute(text("SELECT pg_advisory_xact_lock(:k)"),
                       {"k": _PG_ADVISORY_KEY})
    except Exception:
        log.debug("Advisory-Lock nicht verfügbar", exc_info=True)


def record(db: Session, category: str, event: str, actor: str = "", object: str = "",
           detail: str = "", source_ip: str = "", extra: dict | None = None) -> None:
    """Schreibt EINEN Audit-Eintrag revisionssicher (verkettet) in den
    Append-only-Store und markiert ihn für die SIEM-Zustellung. Fehler dürfen
    den fachlichen Vorgang nie blockieren."""
    ts = utcnow()
    with _write_lock:
        try:
            _advisory_lock(db)
            last = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
            prev_hash = last.hash if (last and last.hash) else GENESIS
            h = event_hash(ts, category, event, actor, object, detail,
                           source_ip, extra, prev_hash)
            db.add(AuditEvent(
                ts=ts, category=category, event=event, actor=actor, object=object,
                detail=detail, source_ip=source_ip, extra=extra,
                prev_hash=prev_hash, hash=h,
                siem_status=("pending" if push_enabled() else "skipped"),
            ))
            db.commit()
        except Exception:  # Audit darf den fachlichen Vorgang nicht mitreißen
            log.exception("Audit-Eintrag konnte nicht gespeichert werden")
            db.rollback()


def verify_chain(db: Session) -> dict:
    """Prüft die vollständige Hash-Kette. Liefert ok=True nur, wenn jeder
    Eintrag inhaltlich unverändert ist und lückenlos an den Vorgänger anschließt."""
    prev = GENESIS
    checked = 0
    for ev in db.query(AuditEvent).order_by(AuditEvent.id.asc()).yield_per(500):
        checked += 1
        if (ev.prev_hash or GENESIS) != prev:
            return {"ok": False, "checked": checked, "broken_at_id": ev.id,
                    "reason": "prev_hash passt nicht zum Vorgänger "
                              "(Reihenfolge verändert oder Eintrag entfernt)"}
        if _row_hash(ev) != (ev.hash or ""):
            return {"ok": False, "checked": checked, "broken_at_id": ev.id,
                    "reason": "Hash passt nicht zum Inhalt (Eintrag verändert)"}
        prev = ev.hash
    return {"ok": True, "checked": checked,
            "head_hash": prev if checked else GENESIS}


def _iso(dt):
    return dt.isoformat() if dt else None


def collect(db: Session, since: str | None = None, limit: int = 500,
            event_type: str | None = None) -> list[dict]:
    """Chronologisches Audit-Log (neueste zuerst).

    event_type: 'rule' | 'zone_change' | Kategorie des Stores | None (alle)."""
    events: list[dict] = []

    # Persistenter Append-only-Store (rule.deleted, auth, admin, …)
    aq = db.query(AuditEvent).order_by(AuditEvent.ts.desc())
    if event_type:
        aq = aq.filter(AuditEvent.category == event_type)
    for a in aq.limit(2000).all():
        events.append({
            "type": a.category,
            "event": a.event,
            "object": a.object,
            "actor": a.actor,
            "detail": a.detail,
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
                "detail": v.change_note,
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


# ---------- SIEM-Zustellung (at-least-once Outbox) --------------------------

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
    """Sendet ein Ereignis per Syslog. UDP ist best-effort (Erfolg = kein
    Fehler beim Senden); TCP wird durch die Verbindung quittiert."""
    host = os.environ.get("AUDIT_SYSLOG_HOST", "").strip()
    if not host:
        return True  # kein Syslog-Ziel konfiguriert
    port = int(os.environ.get("AUDIT_SYSLOG_PORT", "514"))
    proto = os.environ.get("AUDIT_SYSLOG_PROTO", "udp").strip().lower()
    # RFC 5424, Facility 13 (log audit) * 8 + Severity 6 (info) = 110
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
        log.warning("Audit-Syslog fehlgeschlagen: %s", exc)
        return False


def _webhook(event: dict) -> bool:
    url = os.environ.get("AUDIT_WEBHOOK_URL", "").strip()
    if not url:
        return True  # kein Webhook-Ziel konfiguriert
    body = json.dumps({"source": "permitra", **event}, default=str).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        log.warning("Audit-Webhook fehlgeschlagen: %s", exc)
        return False


def deliver(event: dict) -> bool:
    """Stellt ein Ereignis an alle konfigurierten Ziele zu. Erfolg nur, wenn
    jedes konfigurierte Ziel bestätigt (bzw. UDP-Syslog fehlerfrei sendet)."""
    return _syslog(event) and _webhook(event)


def deliver_pending(db: Session, batch: int = 200) -> dict:
    """Stellt ausstehende Ereignisse in strenger Reihenfolge (id aufsteigend)
    zu. Bricht beim ersten Fehlschlag ab, damit die Reihenfolge erhalten bleibt
    und im nächsten Lauf ab derselben Stelle erneut versucht wird."""
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
            db.commit()  # Zählerstand festhalten, Reihenfolge wahren
            break
    remaining = (db.query(AuditEvent)
                 .filter(AuditEvent.siem_status == "pending").count())
    return {"sent": sent, "pending": remaining}


def siem_status(db: Session) -> dict:
    """Überblick über den Zustellzustand für die Admin-Ansicht."""
    def _count(status):
        return db.query(AuditEvent).filter(AuditEvent.siem_status == status).count()
    return {
        "enabled": push_enabled(),
        "pending": _count("pending"),
        "sent": _count("sent"),
        "skipped": _count("skipped"),
    }
