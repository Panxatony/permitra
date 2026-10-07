"""Matching a name against the accounts - one definition for every place that asks.

The requestor on a rule is an account username, and the four-eyes check keys
on it. Two places compared names in two different ways: the approval compared
exactly, the recertification lowercased. A requestor typed into an Excel sheet
("Max Mustermann") matched neither as an account, so the one exclusion that
names the person accountable for the rule quietly did not apply to anything
that came in through the import.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .models import User


def account_key(name: str | None) -> str:
    """The form two names are compared in: trimmed, case-folded."""
    return (name or "").strip().casefold()


def same_account(a: str | None, b: str | None) -> bool:
    key = account_key(a)
    return bool(key) and key == account_key(b)


def resolve_account(db: Session, text: str) -> User | None:
    """The account a typed name refers to, or None.

    Username first, then full name, then e-mail address, each compared
    case-insensitively. Active accounts win over deactivated ones, so a name
    reused after someone left resolves to the person who holds it now.
    """
    key = account_key(text)
    if not key:
        return None
    candidates = db.query(User).order_by(User.is_active.desc(), User.id).all()
    for attr in ("username", "full_name", "email"):
        for user in candidates:
            if account_key(getattr(user, attr, "")) == key:
                return user
    return None
