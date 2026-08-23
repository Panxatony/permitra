"""TOTP two-factor authentication (RFC 6238) without external dependencies."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def matching_counter(secret: str, code: str, window: int = 1) -> int | None:
    """The time step this code belongs to, or None if it belongs to none.

    Returning the counter rather than a bare yes/no is what makes single use
    enforceable: the caller stores it and refuses anything not newer. Without
    that, a code stays valid for the whole tolerance window (about 90 seconds),
    so an observed code - shoulder-surfed, phished, read from a log - can be
    replayed for as long as it is on screen."""
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit():
        return None
    now = int(time.time()) // 30
    for offset in range(-window, window + 1):
        counter = now + offset
        if hmac.compare_digest(_code_at(secret, counter), code):
            return counter
    return None


def verify(secret: str, code: str, window: int = 1, last_counter: int | None = None) -> int | None:
    """Checks a code and rejects one that was already used.

    `last_counter` is the time step accepted the last time. A code from that
    step or an earlier one is refused even though it is arithmetically correct -
    that is the whole point of remembering it."""
    counter = matching_counter(secret, code, window)
    if counter is None:
        return None
    if last_counter is not None and counter <= last_counter:
        return None
    return counter


def otpauth_uri(username: str, secret: str, issuer: str = "Permitra") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}"
            f"?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30")
