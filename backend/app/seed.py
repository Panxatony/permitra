"""Legt Demo-Benutzer an (nur wenn die Benutzer-Tabelle leer ist)."""
from .auth import hash_password
from .database import SessionLocal
from .models import Role, User

DEMO_USERS = [
    ("admin", "admin123", "Administrator", Role.admin),
    ("architekt", "architekt123", "Alex Architekt", Role.architect),
    ("betrieb", "betrieb123", "Bernd Betrieb", Role.operations),
    ("approver", "approver123", "Chris Approver", Role.change_approver),
    ("approver2", "approver123", "Dana Approver", Role.change_approver),
]


def seed_users():
    """Legt fehlende Demo-Benutzer an (bestehende bleiben unverändert)."""
    db = SessionLocal()
    try:
        existing = {u.username for u in db.query(User).all()}
        for username, password, full_name, role in DEMO_USERS:
            if username not in existing:
                db.add(
                    User(
                        username=username,
                        password_hash=hash_password(password),
                        full_name=full_name,
                        role=role,
                    )
                )
        db.commit()
    finally:
        db.close()
