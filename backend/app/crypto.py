"""Symmetric encryption for secrets Permitra has to be able to read back.

Password hashes are one-way and belong in `auth`. What lives here is the other
kind: values the application must recover in plaintext to use them - the NetBox
API token and the TOTP seed. Storing those as they are means anyone who can
read the database can use them, which for a TOTP seed means minting valid second
factors at will.

The key is derived from SECRET_KEY, so it shares that key's fate: an attacker
holding both the database and the environment gains nothing here. What it does
buy is that a database dump, a backup file or a stray replica is not enough on
its own. That is the honest scope of this module, and it is worth stating,
because "encrypted at rest" is easily read as more than it is.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from .auth import SECRET_KEY


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
    return Fernet(key)


def encrypt(raw: str) -> str:
    return _fernet().encrypt(raw.encode()).decode() if raw else ""


def decrypt(enc: str) -> str:
    """Returns the plaintext, or "" when the value cannot be read.

    A wrong or rotated SECRET_KEY must not turn every request into a 500 - the
    caller sees "no secret" and can act on it (ask for the token again, treat
    the second factor as unconfigured)."""
    if not enc:
        return ""
    try:
        return _fernet().decrypt(enc.encode()).decode()
    except (InvalidToken, ValueError):
        return ""


def looks_encrypted(value: str) -> bool:
    """Whether the value was produced by encrypt().

    Needed while both forms exist side by side: rows written before the change
    hold plaintext, and a migration cannot tell them apart by shape alone."""
    return bool(value) and value.startswith("gAAAAA")
