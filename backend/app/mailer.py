"""Optionaler E-Mail-Versand (SMTP) – Basis für Aktivierungs-/Reset-Mails und
spätere Benachrichtigungen (Reviews, Freigaben, Rezertifizierung).

Konfiguration über Umgebungsvariablen (leerer SMTP_HOST = Versand aus):
  SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASSWORD,
  SMTP_FROM (Absender), SMTP_STARTTLS (true)
  PERMITRA_BASE_URL  Basis-URL für Links in Mails, z.B. https://demo.permitra.de

Versand läuft fire-and-forget in einem Thread und darf den eigentlichen
Vorgang nie blockieren; Fehler landen nur im Log."""
from __future__ import annotations

import logging
import os
import smtplib
import threading
from email.message import EmailMessage

log = logging.getLogger("permitra.mailer")


def enabled() -> bool:
    return bool(os.environ.get("SMTP_HOST", "").strip())


def base_url() -> str:
    return os.environ.get("PERMITRA_BASE_URL", "").strip().rstrip("/") or "http://localhost:8090"


def _send(to: str, subject: str, body: str) -> None:
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    sender = os.environ.get("SMTP_FROM", "").strip() or (user or "permitra@localhost")
    starttls = os.environ.get("SMTP_STARTTLS", "true").strip().lower() != "false"

    message = EmailMessage()
    message["From"] = sender
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if starttls:
                smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(message)
        log.info("Mail an %s gesendet: %s", to, subject)
    except Exception as exc:  # Versand darf nie den Vorgang blockieren
        log.warning("Mail an %s fehlgeschlagen: %s", to, exc)


def send(to: str, subject: str, body: str) -> bool:
    """Asynchroner Versand; False, wenn Versand deaktiviert oder keine Adresse."""
    if not enabled() or not (to or "").strip():
        return False
    threading.Thread(target=_send, args=(to.strip(), subject, body), daemon=True).start()
    return True


def activation_mail(user, link: str) -> bool:
    return send(
        user.email,
        "Permitra: Konto aktivieren",
        f"Hallo {user.full_name or user.username},\n\n"
        f"für dich wurde ein Permitra-Konto angelegt (Benutzername: {user.username}).\n"
        f"Bitte setze über folgenden Link dein Passwort und aktiviere damit das Konto:\n\n"
        f"  {link}\n\n"
        f"Der Link ist 72 Stunden gültig.\n\nPermitra",
    )


def reset_mail(user, link: str) -> bool:
    return send(
        user.email,
        "Permitra: Passwort zurücksetzen",
        f"Hallo {user.full_name or user.username},\n\n"
        f"über folgenden Link kannst du ein neues Passwort setzen:\n\n"
        f"  {link}\n\n"
        f"Der Link ist 2 Stunden gültig. Falls du das nicht angefordert hast, "
        f"ignoriere diese Mail.\n\nPermitra",
    )
