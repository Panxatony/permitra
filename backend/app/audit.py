"""Einheitliches Audit-Log für SIEM-Integration (Issue #11, BSI OPS.1.1.5).

Fasst die verteilten, personengebundenen Änderungsereignisse (Regel-Versionen,
Zonen-/Matrix-/Netzwerk-Anträge) zu einem maschinenlesbaren, chronologischen
Audit-Log zusammen. Zusätzlich optionaler Push je Ereignis an ein SIEM über
Syslog (RFC 5424, UDP) oder Webhook.

Konfiguration (optional):
  AUDIT_SYSLOG_HOST / AUDIT_SYSLOG_PORT   Syslog-Ziel (UDP, Port default 514)
  AUDIT_WEBHOOK_URL                       JSON-POST je Ereignis
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
import urllib.request

from sqlalchemy.orm import Session

from .models import AuditEvent, Rule, RuleVersion, User, ZonePolicyChange, utcnow

log = logging.getLogger("permitra.audit")


def client_ip(request) -> str:
    """Quell-IP eines Requests: erster Hop aus X-Forwarded-For (hinter dem
    Reverse-Proxy), sonst die direkte Peer-Adresse."""
    if request is None:
        return ""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


def record(db: Session, category: str, event: str, actor: str = "", object: str = "",
           detail: str = "", source_ip: str = "", extra: dict | None = None) -> None:
    """Schreibt EINEN Audit-Eintrag in den persistenten Append-only-Store und
    pusht ihn optional an ein SIEM. Fehler dürfen den Vorgang nie blockieren."""
    ev = {"category": category, "event": event, "actor": actor, "object": object,
          "detail": detail, "source_ip": source_ip, "extra": extra}
    try:
        db.add(AuditEvent(ts=utcnow(), **{k: v for k, v in ev.items() if k != "extra"},
                          extra=extra))
        db.commit()
    except Exception:  # Audit darf den fachlichen Vorgang nicht mitreißen
        log.exception("Audit-Eintrag konnte nicht gespeichert werden")
        db.rollback()
    emit({"type": category, **ev, "timestamp": utcnow().isoformat()})


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


# ---------- Optionaler Push an ein SIEM ------------------------------------

def push_enabled() -> bool:
    return bool(os.environ.get("AUDIT_SYSLOG_HOST", "").strip()
                or os.environ.get("AUDIT_WEBHOOK_URL", "").strip())


def _syslog(event: dict) -> None:
    host = os.environ.get("AUDIT_SYSLOG_HOST", "").strip()
    if not host:
        return
    port = int(os.environ.get("AUDIT_SYSLOG_PORT", "514"))
    # RFC 5424, Facility 13 (log audit) * 8 + Severity 6 (info) = 110
    msg = f"<110>1 - permitra - {event.get('event')} - - {json.dumps(event, default=str)}"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(msg.encode()[:1024], (host, port))
    except Exception as exc:
        log.warning("Audit-Syslog fehlgeschlagen: %s", exc)


def _webhook(event: dict) -> None:
    url = os.environ.get("AUDIT_WEBHOOK_URL", "").strip()
    if not url:
        return
    body = json.dumps({"source": "permitra", **event}, default=str).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception as exc:
        log.warning("Audit-Webhook fehlgeschlagen: %s", exc)


def emit(event: dict) -> None:
    """Ein Audit-Ereignis an das SIEM pushen (asynchron, optional)."""
    if not push_enabled():
        return
    def _run():
        _syslog(event)
        _webhook(event)
    threading.Thread(target=_run, daemon=True).start()
