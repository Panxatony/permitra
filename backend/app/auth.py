import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .database import get_db
from .messages import _
from .models import Role, User

# Fail-secure: startup is refused unless SECRET_KEY is set. Only in explicit
# dev mode (PERMITRA_DEV=1) a random per-process secret is used - this allows
# local startup, but issued tokens do not survive a restart. No hardcoded
# default (that would allow forged admin tokens).
SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
if not SECRET_KEY:
    if os.environ.get("PERMITRA_DEV") == "1":
        SECRET_KEY = secrets.token_hex(32)
    else:
        raise RuntimeError(
            _("SECRET_KEY is not set – startup refused (fail-secure). "
              "Set SECRET_KEY (e.g. `openssl rand -hex 32`) or PERMITRA_DEV=1 for local development.")
        )
ALGORITHM = "HS256"
TOKEN_LIFETIME_HOURS = int(os.environ.get("TOKEN_LIFETIME_HOURS", "8"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt, _, _digest = stored.partition("$")
    return secrets.compare_digest(hash_password(password, salt), stored)


def create_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.username,
        # Informational only - authorisation re-reads the account from the
        # database on every request, so a role change takes effect at once
        # instead of lingering in an already-issued token.
        "role": user.role.value,
        "roles": [r.value for r in user.roles],
        "iat": int(now.timestamp()),
        "exp": now + timedelta(hours=TOKEN_LIFETIME_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


API_TOKEN_PREFIX = "pat_"  # noqa: S105 - identifying prefix of a token, not a secret


def _service_principal_from_pat(request, token: str, db: Session) -> User:
    """Validates a read-only API token and returns a (non-persisted)
    service principal. Only GET access is permitted (fail-secure)."""
    from .models import ApiToken

    if request is not None and request.method not in ("GET", "HEAD", "OPTIONS"):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            _("API tokens are read-only – only read access is permitted"))
    digest = hashlib.sha256(token.encode()).hexdigest()
    pat = db.query(ApiToken).filter(ApiToken.token_hash == digest).first()
    if not pat or pat.revoked:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _("API token is invalid or revoked"))
    if pat.expires_at is not None:
        exp = pat.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, _("API token has expired"))
    # Update last usage sparingly (avoid a write on every request)
    now = datetime.now(timezone.utc)
    if pat.last_used_at is None or (now - (pat.last_used_at if pat.last_used_at.tzinfo
                                           else pat.last_used_at.replace(tzinfo=timezone.utc))).total_seconds() > 60:
        pat.last_used_at = now
        db.commit()
    principal = User(username=f"token:{pat.name}", password_hash="", role=Role.operations,
                     is_active=True)
    principal.is_service_token = True
    return principal


def get_current_user(request: Request = None, token: str = Depends(oauth2_scheme),
                     db: Session = Depends(get_db)) -> User:
    # Read-only service token (automation) instead of a JWT
    if token and token.startswith(API_TOKEN_PREFIX):
        return _service_principal_from_pat(request, token, db)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _("Token is invalid or expired")) from exc
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _("User not found"))
    # Fail-secure: disabled accounts get no access (even with a valid token)
    if not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _("The account is deactivated"))
    # Immediate revocation: tokens issued before the last invalidation (deactivation,
    # password change/reset) are no longer valid
    if user.token_valid_from is not None:
        iat = payload.get("iat")
        valid_from = user.token_valid_from
        if valid_from.tzinfo is None:
            valid_from = valid_from.replace(tzinfo=timezone.utc)
        if iat is None or iat < int(valid_from.timestamp()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, _("Session is no longer valid"))
    return user


def require_roles(*roles: Role):
    """Admits exactly the roles named - the admin is not one unless listed.

    There used to be an implicit bypass here: `user.role != Role.admin` let
    admins through every check in the application. That quietly contradicted
    everything the product says about itself - the role table promises the
    admin manages Permitra, not rules, and the four-eyes principle is worth
    little when a fifth role can slip past it. Separation of duties is a
    property of the checks, not of the documentation; an endpoint that wants
    the admin says Role.admin.

    An account holds a set of roles and is admitted when it holds any of the
    named ones. That widens who reaches an endpoint, never what happens once
    they are in: the four-eyes checks key on the acting account, so holding two
    roles does not let one account fill both halves of an approval.
    """
    def dependency(user: User = Depends(get_current_user)) -> User:
        if not user.has_role(*roles):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                _("Role '{role}' is not permitted to perform this action",
                  role=", ".join(r.value for r in user.roles)),
            )
        return user

    return dependency
