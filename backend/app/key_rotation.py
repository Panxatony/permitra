"""Bring every encrypted value under the current SECRET_KEY.

Rotating the key used to lock every 2FA user out: their seed no longer
decrypted, every code failed, and five codes later the account was locked -
with no way back in short of editing the database. The NetBox token went
quietly blank. Now the previous key stays in SECRET_KEY_PREVIOUS, values are
read under it, and this re-encrypts them under the current key at startup
(and on demand: `python -m app.key_rotation`), so the previous key can be
dropped once it reports nothing left.

What cannot be read under any key we hold is named, per user, at ERROR -
and left alone: overwriting it would turn a recoverable mistake (the old
key is still in a backup) into a certain one.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from . import crypto
from .models import NetboxConfig, User

log = logging.getLogger("permitra.keys")


def reencrypt_all(db: Session) -> dict:
    """Re-encrypt what was written under a previous key. Returns counts."""
    rewritten, unreadable = 0, []
    for user in db.query(User).filter(User.totp_secret.isnot(None)).all():
        if not user.totp_secret:
            continue
        new = crypto.reencrypt(user.totp_secret, "totp")
        if new is None:
            unreadable.append(user.username)
        elif new != user.totp_secret:
            user.totp_secret = new
            rewritten += 1
    for cfg in db.query(NetboxConfig).all():
        if not cfg.token_enc:
            continue
        new = crypto.reencrypt(cfg.token_enc, "netbox")
        if new is None:
            unreadable.append("netbox token")
        elif new != cfg.token_enc:
            cfg.token_enc = new
            rewritten += 1
    db.commit()
    if rewritten:
        log.info("Re-encrypted %d secret(s) under the current SECRET_KEY", rewritten)
    for name in unreadable:
        log.error("Secret of %s cannot be read under SECRET_KEY or SECRET_KEY_PREVIOUS "
                  "- the key it was written with is not configured", name)
    return {"rewritten": rewritten, "unreadable": unreadable}


def reencrypt_at_startup() -> None:
    from .database import SessionLocal
    db = SessionLocal()
    try:
        reencrypt_all(db)
    except Exception:  # a failed rotation must not keep the application down
        log.exception("Key rotation at startup failed")
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    from .database import SessionLocal
    session = SessionLocal()
    try:
        print(reencrypt_all(session))
    finally:
        session.close()
