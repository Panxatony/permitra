"""Erstinitialisierung der Benutzer.

Sicherheit (fail-secure): Bekannte Demo-Zugangsdaten werden NUR im Demo-Modus
(PERMITRA_DEMO=1) angelegt. In allen anderen Fällen entsteht bei leerer
Benutzer-Tabelle ein einziges Admin-Konto mit einem zufälligen Passwort, das
einmalig ins Log geschrieben wird – so startet keine Produktivinstallation mit
öffentlich bekannten Credentials."""
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
            # Demo-/Testbetrieb: bekannte Konten anlegen (nur fehlende)
            for username, password, full_name, role in DEMO_USERS:
                if username not in existing:
                    db.add(User(username=username, password_hash=hash_password(password),
                                full_name=full_name, role=role, is_active=True))
            db.commit()
            return

        if existing:
            return  # bereits initialisiert – nichts tun

        # Produktivstart: Erst-Admin mit zufälligem Passwort (einmalig im Log)
        password = secrets.token_urlsafe(18)
        db.add(User(username="admin", password_hash=hash_password(password),
                    full_name="Administrator", role=Role.admin, is_active=True))
        db.commit()
        log.warning(
            "Erst-Admin angelegt: Benutzer 'admin', Passwort '%s' – "
            "bitte umgehend ändern (dieses Passwort wird nur einmal angezeigt).",
            password,
        )
    finally:
        db.close()
