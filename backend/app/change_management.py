"""Optionale Anbindung an Change-Management-Systeme (z.B. ServiceNow).

Permitra sendet bei relevanten Ereignissen (Regel eingereicht/freigegeben/
abgelehnt, Zonen-/Netzwerk-Antrag entschieden) einen generischen JSON-Webhook.
Die Integration ist per Umgebungsvariablen aktivierbar und darf den eigentlichen
Vorgang niemals blockieren (fire-and-forget, kurzer Timeout, Fehler nur im Log).

Konfiguration:
  CHANGE_WEBHOOK_URL    Ziel-URL (leer = Integration aus)
  CHANGE_WEBHOOK_TOKEN  optional; wird als "Authorization: Bearer <token>" gesendet

Payload (stabil, für Adapter wie ServiceNow gedacht):
  {"event": "rule.approved", "source": "permitra",
   "timestamp": "2026-08-22T09:00:00+00:00", "data": {...}}

Ein ServiceNow-Adapter (z.B. Scripted REST API oder MID-Server) kann daraus ein
Change-Ticket erzeugen; die Ticket-Nummer lässt sich anschließend über
PUT /api/rules/{id} im Feld change_id zurückschreiben.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import urllib.request

from .models import utcnow

log = logging.getLogger("permitra.change_management")


def enabled() -> bool:
    return bool(os.environ.get("CHANGE_WEBHOOK_URL", "").strip())


def _send(url: str, token: str, body: bytes) -> None:
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Permitra"},
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            log.info("Change-Webhook %s: HTTP %s", url, response.status)
    except Exception as exc:  # Integration darf den Vorgang nie blockieren
        log.warning("Change-Webhook fehlgeschlagen (%s): %s", url, exc)


def notify(event: str, data: dict) -> None:
    """Sendet ein Ereignis an das Change-Management-System (asynchron, optional)."""
    url = os.environ.get("CHANGE_WEBHOOK_URL", "").strip()
    if not url:
        return
    token = os.environ.get("CHANGE_WEBHOOK_TOKEN", "").strip()
    body = json.dumps({
        "event": event,
        "source": "permitra",
        "timestamp": utcnow().isoformat(),
        "data": data,
    }, ensure_ascii=False, default=str).encode()
    threading.Thread(target=_send, args=(url, token, body), daemon=True).start()


def rule_payload(rule) -> dict:
    """Kompakte, stabile Regel-Darstellung für Change-Tickets."""
    return {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "status": rule.status.value,
        "action": rule.action.value,
        "source_zone": rule.source_zone,
        "destination_zone": rule.destination_zone,
        "source": rule.source,
        "destination": rule.destination,
        "services": rule.services,
        "components": [c.name for c in rule.components],
        "change_id": rule.change_id,
        "requested_by": rule.created_by,
        "version": rule.version,
    }
