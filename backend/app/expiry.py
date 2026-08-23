"""Validity monitoring: expiring and expired rules.

- expiring_rules(): approved rules whose valid_until falls within the next N days
  or has already passed (for the recertification view).
- expire_rules(): daily job - automatically deactivates approved rules once their
  validity has expired (adding a version and a comment entry).
"""
import logging
from datetime import date, timedelta

from sqlalchemy.orm import Session

from .messages import _
from .models import Comment, Rule, RuleStatus, RuleVersion

log = logging.getLogger("permitra.expiry")


def _split_by_due(rules: list[Rule], today: date):
    """Splits into already expired and expiring soon.

    An unparsable date must NOT propagate here: new rules are validated
    server-side (schemas.parse_iso_date), but legacy data and imports may
    contain nonsense such as '2020-02-30'. A single such rule would otherwise
    have taken down the dashboard, the expiry list and the daily job for all
    users. Such rules are skipped and reported - deliberately not deactivated
    automatically, since a teardown decision based on unusable data would be
    worse than leaving the rule in place."""
    expired, expiring = [], []
    for rule in rules:
        try:
            due = date.fromisoformat((rule.valid_until or "").strip())
        except ValueError:
            log.warning("Rule %s has an unreadable valid-until (%r) and is skipped by the "
                        "expiry check – please correct it",
                        rule.rule_id, rule.valid_until)
            continue
        (expired if due < today else expiring).append(rule)
    return expired, expiring


def invalid_validity_rules(db: Session) -> list[Rule]:
    """Rules with an unparsable valid-until - a data quality problem that would
    otherwise go unnoticed, because the expiry check skips them."""
    rows = (db.query(Rule)
            .filter(Rule.valid_until.isnot(None), Rule.valid_until != "",
                    Rule.deleted_at.is_(None))
            .all())
    bad = []
    for rule in rows:
        try:
            date.fromisoformat((rule.valid_until or "").strip())
        except ValueError:
            bad.append(rule)
    return bad


def expiring_rules(db: Session, days: int = 30) -> tuple[list[Rule], list[Rule]]:
    """Returns (expired, expiring within <days> days) - approved rules only."""
    today = date.today()
    horizon = today + timedelta(days=days)
    candidates = (
        db.query(Rule)
        .filter(Rule.status == RuleStatus.approved, Rule.valid_until.isnot(None), Rule.deleted_at.is_(None))
        .filter(Rule.valid_until <= horizon.isoformat())
        .order_by(Rule.valid_until)
        .all()
    )
    return _split_by_due(candidates, today)


def expire_rules(db: Session) -> int:
    """Deactivates expired approved rules. Returns the number of rules affected."""
    expired, _expiring = expiring_rules(db, days=0)
    for rule in expired:
        rule.status = RuleStatus.deactivated
        rule.version += 1
        db.add(
            RuleVersion(
                rule_pk=rule.id,
                version=rule.version,
                snapshot={"auto": "expiry"},
                change_note=_("Automatically deactivated: validity until {valid_until} has expired",
                              valid_until=rule.valid_until),
                changed_by="system",
            )
        )
        db.add(
            Comment(
                rule_pk=rule.id,
                author="system",
                text=_("Rule automatically deactivated – validity until {valid_until} has expired. "
                       "If it is still needed, recertify it (submit it again).",
                       valid_until=rule.valid_until),
            )
        )
    if expired:
        db.commit()
    return len(expired)
