"""Optional integration with change management systems (e.g. ServiceNow).

Permitra sends a generic JSON webhook on the events of a rule's life that a
change process cares about, and on zone/network decisions. The integration is
enabled via environment variables and must never block the actual operation:
delivery runs on a thread, retries a few times with a growing pause, and
ends up in the log - never in the caller's response.

Configuration:
  CHANGE_WEBHOOK_URL     target URL (empty = integration disabled)
  CHANGE_WEBHOOK_TOKEN   optional; sent as "Authorization: Bearer <token>"
  CHANGE_WEBHOOK_SECRET  optional; the body is signed with HMAC-SHA256 and the
                         hex digest sent as "X-Permitra-Signature: sha256=<hex>",
                         so the receiver can tell Permitra's calls from anyone
                         else's who learned the URL

Payload (stable, intended for adapters such as ServiceNow):
  {"event": "rule.approved", "source": "permitra",
   "timestamp": "2026-08-22T09:00:00+00:00", "data": {...}}

Events: rule.submitted, rule.approved, rule.rejected, rule.deactivated,
rule.delete_approved, rule.emergency_declared, rule.implementation (the
implementation status changed; `status` says whether the rule is active now),
rule.removal_proposed (application retired, or a network move made the rule
inadmissible), rule.expired, rule.emergency_expired, zone_change.approved,
zone_change.rejected.

An adapter writes the ticket number back with PATCH /api/rules/{id}/change-id -
the one write that changes metadata only and leaves the approval standing.
Delivery is at-most-a-few-tries, not guaranteed: an adapter that must not miss
anything reconciles by polling GET /api/rules?updated_since=.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import urllib.request

from .models import utcnow

log = logging.getLogger("permitra.change_management")

# Seconds to wait before each retry: three tries in just over a minute cover
# a restart of the receiver without holding a thread for long.
RETRY_DELAYS = (10, 60)


def enabled() -> bool:
    return bool(os.environ.get("CHANGE_WEBHOOK_URL", "").strip())


def _attempt(url: str, token: str, secret: str, body: bytes) -> bool:
    # S310 rationale: the target URL is operator-configured (CHANGE_WEBHOOK_URL), not
    # user-supplied; see the SSRF note in the security audit.
    request = urllib.request.Request(  # noqa: S310
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Permitra"},
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    if secret:
        digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        request.add_header("X-Permitra-Signature", f"sha256={digest}")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
            log.info("Change webhook %s: HTTP %s", url, response.status)
            return True
    except Exception as exc:  # the integration must never block the operation
        log.warning("Change webhook failed (%s): %s", url, exc)
        return False


def _send(url: str, token: str, secret: str, body: bytes, delays=None) -> None:
    # Read at call time, not bound at definition: a test shortens the pauses.
    delays = RETRY_DELAYS if delays is None else delays
    if _attempt(url, token, secret, body):
        return
    for delay in delays:
        time.sleep(delay)
        if _attempt(url, token, secret, body):
            return
    log.error("Change webhook gave up after %d attempts: %s", len(delays) + 1, url)


def notify(event: str, data: dict) -> None:
    """Sends an event to the change management system (asynchronous, optional)."""
    url = os.environ.get("CHANGE_WEBHOOK_URL", "").strip()
    if not url:
        return
    token = os.environ.get("CHANGE_WEBHOOK_TOKEN", "").strip()
    secret = os.environ.get("CHANGE_WEBHOOK_SECRET", "").strip()
    body = json.dumps({
        "event": event,
        "source": "permitra",
        "timestamp": utcnow().isoformat(),
        "data": data,
    }, ensure_ascii=False, default=str).encode()
    threading.Thread(target=_send, args=(url, token, secret, body), daemon=True).start()


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
        "enforcement": sorted({c.enforcement.value for c in rule.components if c.enforcement}),
        "change_id": rule.change_id,
        "requested_by": rule.created_by,
        "version": rule.version,
    }
