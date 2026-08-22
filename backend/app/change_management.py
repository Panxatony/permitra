"""Optional integration with change management systems (e.g. ServiceNow).

Permitra sends a generic JSON webhook on relevant events (rule submitted/
approved/rejected, zone or network request decided). The integration is enabled
via environment variables and must never block the actual operation
(fire-and-forget, short timeout, errors only in the log).

Configuration:
  CHANGE_WEBHOOK_URL    target URL (empty = integration disabled)
  CHANGE_WEBHOOK_TOKEN  optional; sent as "Authorization: Bearer <token>"

Payload (stable, intended for adapters such as ServiceNow):
  {"event": "rule.approved", "source": "permitra",
   "timestamp": "2026-08-22T09:00:00+00:00", "data": {...}}

A ServiceNow adapter (e.g. Scripted REST API or MID server) can turn this into a
change ticket; the ticket number can then be written back via
PUT /api/rules/{id} in the change_id field.
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
    # S310 rationale: the target URL is operator-configured (CHANGE_WEBHOOK_URL), not
    # user-supplied; see the SSRF note in the security audit.
    request = urllib.request.Request(  # noqa: S310
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Permitra"},
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
            log.info("Change webhook %s: HTTP %s", url, response.status)
    except Exception as exc:  # the integration must never block the operation
        log.warning("Change webhook failed (%s): %s", url, exc)


def notify(event: str, data: dict) -> None:
    """Sends an event to the change management system (asynchronous, optional)."""
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
    """Compact, stable rule representation for change tickets."""
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
