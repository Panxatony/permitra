"""E-Mail-Benachrichtigungen für Workflow-Ereignisse (Issue #5).

Baut auf dem optionalen Mailer auf (SMTP, fire-and-forget). Ohne konfiguriertes
SMTP passiert nichts. Empfänger werden aus den Benutzerrollen bestimmt; jeder
Benutzer kann E-Mail-Benachrichtigungen individuell abschalten (notify_email).

Ereignisse:
- Regel zum Review eingereicht  -> alle Change Approver
- Regel freigegeben/abgelehnt   -> Ersteller/Requestor der Regel
- Regel zur Umsetzung/Rückbau   -> Betrieb
- Rezertifizierung (Ablauf)     -> Betrieb (Sammelmail)
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from . import mailer
from .models import Role, User

log = logging.getLogger("permitra.notifications")


def _recipients_by_role(db: Session, *roles: Role) -> list[User]:
    return [
        u for u in db.query(User).filter(User.role.in_(roles)).all()
        if u.is_active and u.notify_email and (u.email or "").strip()
    ]


def _recipients_by_name(db: Session, *usernames: str) -> list[User]:
    names = {n for n in usernames if n}
    if not names:
        return []
    return [
        u for u in db.query(User).filter(User.username.in_(names)).all()
        if u.is_active and u.notify_email and (u.email or "").strip()
    ]


def _rule_line(rule) -> str:
    return (f"{rule.rule_id} „{rule.name}“ ({rule.source_zone or '?'} → "
            f"{rule.destination_zone or '?'})")


def _send_each(recipients: list[User], subject: str, body_for) -> int:
    sent = 0
    for user in recipients:
        greeting = user.full_name or user.username
        if mailer.send(user.email, subject, body_for(greeting)):
            sent += 1
    return sent


def rule_submitted(db: Session, rule) -> None:
    """Regel zum Review eingereicht -> Change Approver informieren."""
    if not mailer.enabled():
        return
    link = f"{mailer.base_url()}/rules/{rule.rule_id}"
    _send_each(
        _recipients_by_role(db, Role.change_approver, Role.admin),
        f"Permitra: Regel {rule.rule_id} wartet auf Freigabe",
        lambda g: (f"Hallo {g},\n\n{_rule_line(rule)} wurde zum Review eingereicht "
                   f"und wartet auf deine Freigabe.\n\n  {link}\n\nPermitra"),
    )


def rule_decided(db: Session, rule, approved: bool, decided_by: str, comment: str = "") -> None:
    """Regel freigegeben/abgelehnt -> Ersteller/Requestor informieren."""
    if not mailer.enabled():
        return
    link = f"{mailer.base_url()}/rules/{rule.rule_id}"
    status = "freigegeben" if approved else "abgelehnt"
    extra = f"\n\nKommentar: {comment}" if comment else ""
    _send_each(
        _recipients_by_name(db, rule.created_by, rule.requestor),
        f"Permitra: Regel {rule.rule_id} {status}",
        lambda g: (f"Hallo {g},\n\n{_rule_line(rule)} wurde von {decided_by} {status}."
                   f"{extra}\n\n  {link}\n\nPermitra"),
    )


def rule_implementation_pending(db: Session, rule, reason: str) -> None:
    """Regel zur Umsetzung/Rückbau -> Betrieb informieren."""
    if not mailer.enabled():
        return
    link = f"{mailer.base_url()}/rules/{rule.rule_id}"
    _send_each(
        _recipients_by_role(db, Role.operations, Role.admin),
        f"Permitra: Regel {rule.rule_id} umzusetzen",
        lambda g: (f"Hallo {g},\n\n{_rule_line(rule)}: {reason}\n"
                   f"Bitte auf den Komponenten umsetzen bzw. zurückbauen und den "
                   f"Umsetzungsstatus pflegen.\n\n  {link}\n\nPermitra"),
    )


def recertification_due(db: Session, expired: list, expiring: list) -> None:
    """Sammelmail an den Betrieb über abgelaufene/ablaufende Regeln."""
    if not mailer.enabled() or not (expired or expiring):
        return
    lines = []
    if expired:
        lines.append("Abgelaufen (automatisch deaktiviert):")
        lines += [f"  - {_rule_line(r)} (bis {r.valid_until})" for r in expired]
    if expiring:
        lines.append("\nLäuft demnächst ab:")
        lines += [f"  - {_rule_line(r)} (bis {r.valid_until})" for r in expiring]
    body = "\n".join(lines)
    link = f"{mailer.base_url()}/recertification"
    _send_each(
        _recipients_by_role(db, Role.operations, Role.admin),
        "Permitra: Rezertifizierung – abgelaufene/ablaufende Regeln",
        lambda g: f"Hallo {g},\n\n{body}\n\nRezertifizierung:\n  {link}\n\nPermitra",
    )
