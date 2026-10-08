"""What a password has to be, checked wherever one is set.

Three endpoints set passwords (activation and reset link, change on the
account page, admin-created account) and each checked one thing: eight
characters. Nothing refused the username as a password, a password longer
than the hashing had any use for, or the ten thousand passwords every
guessing list starts with.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from fastapi import HTTPException, status

from .messages import _

MIN_LENGTH = 8
# PBKDF2 takes any length, so a multi-megabyte password is a cheap way to
# burn CPU; 128 characters is more than any passphrase needs.
MAX_LENGTH = 128
# The 10,000 most common passwords from SecLists (MIT), see LICENSE beside it.
_BLOCKLIST = Path(__file__).parent / "wordlists" / "common-passwords.txt"


@lru_cache(maxsize=1)
def common_passwords() -> frozenset[str]:
    try:
        return frozenset(line.strip().casefold()
                         for line in _BLOCKLIST.read_text(encoding="utf-8").splitlines()
                         if line.strip())
    except OSError:
        return frozenset()


def problem(password: str, *identities: str | None) -> str | None:
    """The reason a password is not acceptable, or None. `identities` are the
    names it must not be built from: username, e-mail address."""
    if len(password) < MIN_LENGTH:
        return _("Password must be at least 8 characters long")
    if len(password) > MAX_LENGTH:
        return _("Password must be at most 128 characters long")
    folded = password.casefold()
    if folded in common_passwords():
        return _("This password is too common – choose another one")
    for identity in identities:
        for part in (identity or "", (identity or "").partition("@")[0]):
            part = part.strip().casefold()
            if len(part) >= 3 and part in folded:
                return _("Password must not contain the username or e-mail address")
    return None


def enforce(password: str, *identities: str | None) -> None:
    """Raise 422 with the reason when a password is not acceptable."""
    reason = problem(password, *identities)
    if reason:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, reason)
