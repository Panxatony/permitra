"""Optional email delivery (SMTP) - the basis for activation/reset mails and
later notifications (reviews, approvals, recertification).

Configured via environment variables (empty SMTP_HOST = delivery disabled):
  SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASSWORD,
  SMTP_FROM (sender), SMTP_STARTTLS (true)
  PERMITRA_BASE_URL  base URL for links in mails, e.g. https://demo.permitra.de

Delivery runs fire-and-forget in a thread and must never block the actual
operation; errors only end up in the log."""
from __future__ import annotations

import logging
import os
import smtplib
import threading
from email.message import EmailMessage

from .messages import _

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
        log.info("Mail sent to %s: %s", to, subject)
    except Exception as exc:  # delivery must never block the operation
        log.warning("Mail to %s failed: %s", to, exc)


def send(to: str, subject: str, body: str) -> bool:
    """Asynchronous delivery; False if delivery is disabled or no address is given."""
    if not enabled() or not (to or "").strip():
        return False
    threading.Thread(target=_send, args=(to.strip(), subject, body), daemon=True).start()
    return True


def activation_mail(user, link: str) -> bool:
    return send(
        user.email,
        _("Permitra: activate your account"),
        _("Hello {name},\n\n"
          "a Permitra account has been created for you (username: {username}).\n"
          "Use the following link to set your password and activate the account:\n\n"
          "  {link}\n\n"
          "The link is valid for 72 hours.\n\nPermitra",
          name=user.full_name or user.username, username=user.username, link=link),
    )


def reset_mail(user, link: str) -> bool:
    return send(
        user.email,
        _("Permitra: reset your password"),
        _("Hello {name},\n\n"
          "use the following link to set a new password:\n\n"
          "  {link}\n\n"
          "The link is valid for 2 hours. If you did not request this, "
          "ignore this mail.\n\nPermitra",
          name=user.full_name or user.username, link=link),
    )
