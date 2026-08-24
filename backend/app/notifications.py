"""E-mail notifications for workflow events (issue #5).

Built on top of the optional mailer (SMTP, fire-and-forget). Without configured
SMTP nothing happens. Recipients are derived from the user roles; every user can
turn e-mail notifications off individually (notify_email).

Events:
- rule submitted for review        -> all change approvers
- rule approved/rejected           -> creator/requestor of the rule
- rule pending rollout/rollback    -> operations
- recertification (expiry)         -> operations (digest mail)
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from . import mailer
from .messages import _
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
    return (f"{rule.rule_id} “{rule.name}” ({rule.source_zone or '?'} → "
            f"{rule.destination_zone or '?'})")


def _send_each(recipients: list[User], subject: str, body_for) -> int:
    sent = 0
    for user in recipients:
        greeting = user.full_name or user.username
        if mailer.send(user.email, subject, body_for(greeting)):
            sent += 1
    return sent


def rule_submitted(db: Session, rule) -> None:
    """Rule submitted for review -> notify the change approvers."""
    if not mailer.enabled():
        return
    link = f"{mailer.base_url()}/rules/{rule.rule_id}"
    _send_each(
        _recipients_by_role(db, Role.change_approver, Role.admin),
        _("Permitra: rule {rule_id} is waiting for approval", rule_id=rule.rule_id),
        lambda g: _("Hello {g},\n\n{rule_line} has been submitted for review "
                    "and is waiting for your approval.\n\n  {link}\n\nPermitra",
                    g=g, rule_line=_rule_line(rule), link=link),
    )


def rule_decided(db: Session, rule, approved: bool, decided_by: str, comment: str = "") -> None:
    """Rule approved/rejected -> notify the creator/requestor."""
    if not mailer.enabled():
        return
    link = f"{mailer.base_url()}/rules/{rule.rule_id}"
    # The status is an enum value; translated only here, where it is inserted
    # into a sentence – what is stored and served stays "approved"/"rejected".
    status = _("approved") if approved else _("rejected")
    extra = _("\n\nComment: {comment}", comment=comment) if comment else ""
    _send_each(
        _recipients_by_name(db, rule.created_by, rule.requestor),
        _("Permitra: rule {rule_id} {status}", rule_id=rule.rule_id, status=status),
        lambda g: _("Hello {g},\n\n{rule_line} was {status} by {decided_by}."
                    "{extra}\n\n  {link}\n\nPermitra",
                    g=g, rule_line=_rule_line(rule), status=status,
                    decided_by=decided_by, extra=extra, link=link),
    )


def rule_implementation_pending(db: Session, rule, reason: str) -> None:
    """Rule pending rollout/rollback -> notify operations."""
    if not mailer.enabled():
        return
    link = f"{mailer.base_url()}/rules/{rule.rule_id}"
    _send_each(
        _recipients_by_role(db, Role.operations, Role.admin),
        _("Permitra: rule {rule_id} needs to be implemented", rule_id=rule.rule_id),
        lambda g: _("Hello {g},\n\n{rule_line}: {reason}\n"
                    "Roll the rule out on the components or remove it, and update the "
                    "implementation status.\n\n  {link}\n\nPermitra",
                    g=g, rule_line=_rule_line(rule), reason=reason, link=link),
    )


def requestor_handover_proposed(db, rule, successor) -> None:
    """Tells the proposed successor a rule is waiting for them to take over."""
    if not (successor.email and successor.notify_email):
        return
    subject = _("Permitra: rule {rule_id} handed over to you", rule_id=rule.rule_id)

    def body(_u):
        return _("Hello {name},\n\n{rule_line} has been proposed for you to take "
                 "over as requestor. Confirm the takeover in Permitra - until you do, "
                 "the requestor does not change.\n\n  {link}\n\nPermitra",
                 name=successor.full_name or successor.username,
                 rule_line=_rule_line(rule), link=f"{mailer.base_url()}/rules/{rule.rule_id}")
    _send_each([successor], subject, body)


def recertification_due(db: Session, expired: list, expiring: list) -> None:
    """Digest mail to operations about expired/expiring rules."""
    if not mailer.enabled() or not (expired or expiring):
        return
    lines = []
    if expired:
        lines.append(_("Expired (automatically disabled):"))
        lines += [_("  - {rule_line} (until {valid_until})",
                    rule_line=_rule_line(r), valid_until=r.valid_until) for r in expired]
    if expiring:
        lines.append(_("\nExpiring soon:"))
        lines += [_("  - {rule_line} (until {valid_until})",
                    rule_line=_rule_line(r), valid_until=r.valid_until) for r in expiring]
    body = "\n".join(lines)
    link = f"{mailer.base_url()}/recertification"
    _send_each(
        _recipients_by_role(db, Role.operations, Role.admin),
        _("Permitra: recertification – expired/expiring rules"),
        lambda g: _("Hello {g},\n\n{body}\n\nRecertification:\n  {link}\n\nPermitra",
                    g=g, body=body, link=link),
    )
