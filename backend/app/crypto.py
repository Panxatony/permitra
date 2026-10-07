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

Each purpose has its own key (auth.derive_key), and a value written under a
previous SECRET_KEY, or under the old derivation (sha256 of the secret, one
key for everything), still decrypts: decryption tries the current key first,
then every previous one, then the old derivation of each. Encryption only
ever uses the current key for the purpose. `is_current` and `reencrypt` are
what a rotation needs - see key_rotation.py.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from . import auth


def _legacy_key(secret: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())


def _primary(purpose: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(auth.derive_key(auth.SECRET_KEY, purpose)))


def _all(purpose: str) -> MultiFernet:
    fernets = [_primary(purpose)]
    fernets += [Fernet(base64.urlsafe_b64encode(auth.derive_key(s, purpose)))
                for s in auth.PREVIOUS_SECRET_KEYS]
    fernets += [Fernet(_legacy_key(s)) for s in auth.secrets_in_order()]
    return MultiFernet(fernets)


def encrypt(raw: str, purpose: str) -> str:
    return _primary(purpose).encrypt(raw.encode()).decode() if raw else ""


def decrypt(enc: str, purpose: str) -> str:
    """Returns the plaintext, or "" when the value cannot be read.

    A wrong or rotated SECRET_KEY must not turn every request into a 500 - the
    caller sees "no secret" and decides what that means for its purpose: the
    login refuses the second factor and says why (auth_router), NetBox asks
    for its token again."""
    if not enc:
        return ""
    try:
        return _all(purpose).decrypt(enc.encode()).decode()
    except (InvalidToken, ValueError):
        return ""


def is_current(enc: str, purpose: str) -> bool:
    """Whether the value was encrypted under the current key for this purpose."""
    if not enc:
        return True
    try:
        _primary(purpose).decrypt(enc.encode())
        return True
    except (InvalidToken, ValueError):
        return False


def reencrypt(enc: str, purpose: str) -> str | None:
    """The value under the current key, unchanged if it already is, None if
    it cannot be read under any key we hold."""
    if is_current(enc, purpose):
        return enc
    raw = decrypt(enc, purpose)
    return encrypt(raw, purpose) if raw else None


def looks_encrypted(value: str) -> bool:
    """Whether the value was produced by encrypt().

    Needed while both forms exist side by side: rows written before the change
    hold plaintext, and a migration cannot tell them apart by shape alone."""
    return bool(value) and value.startswith("gAAAAA")
