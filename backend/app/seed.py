"""Initial user provisioning.

Security (fail-secure): well-known demo credentials are created ONLY in demo
mode (PERMITRA_DEMO=1). In every other case an empty user table yields a single
admin account, so no production installation ever starts with publicly known
credentials.

How that first password reaches the operator is the delicate part. It used to be
written into the application log, which goes to stdout, from there to
`docker logs`, and from there - in exactly the kind of installation this is built
for - into a log aggregator or SIEM. That is a durable, replicated, widely
readable store, and it would hold a working administrator credential for the
system that documents who may open which firewall rule.

So it is never logged. Either the operator supplies the password
(PERMITRA_INITIAL_ADMIN_PASSWORD, the normal case for a real deployment) or it is
generated and written to a file only they can read, and only the *path* is
logged. If neither is possible, startup is refused rather than falling back to
the unsafe option - the same stance auth.py takes on a missing SECRET_KEY.
"""
import logging
import os
import secrets
import stat
from pathlib import Path

from .auth import hash_password
from .database import SessionLocal
from .messages import _
from .models import Role, User

log = logging.getLogger("permitra.seed")

DEMO_USERS = [
    ("admin", "admin123", "Administrator", Role.admin),
    ("architekt", "architekt123", "Alex Architekt", Role.architect),
    ("betrieb", "betrieb123", "Bernd Betrieb", Role.operations),
    ("approver", "approver123", "Chris Approver", Role.change_approver),
    ("approver2", "approver123", "Dana Approver", Role.change_approver),
]

# A path, not a secret - the whole point is that the value lives in the file
# rather than in the code or the log.
DEFAULT_PASSWORD_FILE = "/app/initial-admin-password.txt"  # noqa: S105


def _write_password_file(password: str) -> str:
    """Writes the password where only the owner can read it, returns the path.

    Created with 0600 from the start rather than written and then chmod'ed:
    between those two calls the file is world-readable, and that window is
    exactly what an attacker on a shared host waits for.
    """
    path = Path(os.environ.get("PERMITRA_INITIAL_ADMIN_PASSWORD_FILE")
                or DEFAULT_PASSWORD_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as handle:
        handle.write(password + "\n")
    return str(path)


def _initial_admin_password() -> tuple[str, str | None]:
    """The password for the first admin, and where to find it.

    Returns (password, path). A path of None means the operator supplied the
    password themselves and there is nothing to hand back to them.
    """
    supplied = (os.environ.get("PERMITRA_INITIAL_ADMIN_PASSWORD") or "").strip()
    if supplied:
        return supplied, None

    password = secrets.token_urlsafe(18)
    try:
        return password, _write_password_file(password)
    except OSError as exc:
        # Refused rather than logged. A start that cannot deliver the credential
        # safely should fail loudly, not quietly do the unsafe thing.
        raise RuntimeError(
            _("Cannot write the initial admin password to {path} ({error}) – "
              "startup refused (fail-secure). Set PERMITRA_INITIAL_ADMIN_PASSWORD, "
              "or point PERMITRA_INITIAL_ADMIN_PASSWORD_FILE at a writable path.",
              path=os.environ.get("PERMITRA_INITIAL_ADMIN_PASSWORD_FILE")
                   or DEFAULT_PASSWORD_FILE,
              error=exc)
        ) from exc


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

        password, path = _initial_admin_password()
        db.add(User(username="admin", password_hash=hash_password(password),
                    full_name="Administrator", role=Role.admin, is_active=True))
        db.commit()
        if path:
            # The path, never the value.
            log.warning(
                "Initial admin 'admin' created. The password was written to %s "
                "(readable only by the owner). Read it once, sign in, change it, "
                "and delete the file.", path,
            )
        else:
            log.info("Initial admin 'admin' created with the password from "
                     "PERMITRA_INITIAL_ADMIN_PASSWORD.")
    finally:
        db.close()
