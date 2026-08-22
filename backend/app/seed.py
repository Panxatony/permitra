"""Initial user provisioning.

Security (fail-secure): well-known demo credentials are created ONLY in demo mode
(PERMITRA_DEMO=1). In every other case an empty user table yields a single admin
account with a random password that is written to the log exactly once – this way
no production installation ever starts with publicly known credentials."""
import logging
import os
import secrets

from .auth import hash_password
from .database import SessionLocal
from .models import Role, User

log = logging.getLogger("permitra.seed")

DEMO_USERS = [
    ("admin", "admin123", "Administrator", Role.admin),
    ("architekt", "architekt123", "Alex Architekt", Role.architect),
    ("betrieb", "betrieb123", "Bernd Betrieb", Role.operations),
    ("approver", "approver123", "Chris Approver", Role.change_approver),
    ("approver2", "approver123", "Dana Approver", Role.change_approver),
]


def seed_users():
    db = SessionLocal()
    try:
        existing = {u.username for u in db.query(User).all()}
        if os.environ.get("PERMITRA_DEMO") == "1":
            # Demo/test operation: create the well-known accounts (missing ones only)
            for username, password, full_name, role in DEMO_USERS:
                if username not in existing:
                    db.add(User(username=username, password_hash=hash_password(password),
                                full_name=full_name, role=role, is_active=True))
            db.commit()
            return

        if existing:
            return  # already initialised – nothing to do

        # Production start: initial admin with a random password (logged once)
        password = secrets.token_urlsafe(18)
        db.add(User(username="admin", password_hash=hash_password(password),
                    full_name="Administrator", role=Role.admin, is_active=True))
        db.commit()
        log.warning(
            "Initial admin created: user 'admin', password '%s' – "
            "change it immediately (this password is shown only once).",
            password,
        )
    finally:
        db.close()
