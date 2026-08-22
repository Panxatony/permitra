"""TOTP-Zwei-Faktor (RFC 6238) ohne externe Abhängigkeiten."""
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


def verify(secret: str, code: str, window: int = 1) -> bool:
    """Prüft den Code mit ±window Zeitschritten (30s) Toleranz."""
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit():
        return False
    counter = int(time.time()) // 30
    return any(
        hmac.compare_digest(_code_at(secret, counter + offset), code)
        for offset in range(-window, window + 1)
    )


def otpauth_uri(username: str, secret: str, issuer: str = "Permitra") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}"
            f"?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30")
