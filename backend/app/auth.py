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
# Keys that were SECRET_KEY before a rotation, newest first. What they signed
# or encrypted is still accepted; nothing new is made with them. Drop a key
# from this list once the re-encryption on startup has reported nothing left
# under it and its sessions have expired (TOKEN_LIFETIME_HOURS).
PREVIOUS_SECRET_KEYS = [k.strip() for k in os.environ.get("SECRET_KEY_PREVIOUS", "").split(",") if k.strip()]
ALGORITHM = "HS256"
TOKEN_LIFETIME_HOURS = int(os.environ.get("TOKEN_LIFETIME_HOURS", "8"))


def derive_key(secret: str, purpose: str) -> bytes:
    """A 32-byte key for one purpose, from one secret.

    SECRET_KEY used to be the JWT signing key as it is, and sha256(SECRET_KEY)
    the Fernet key for both the TOTP seeds and the NetBox token: one secret,
    three uses, no separation. HKDF with the purpose as `info` gives each use
    its own key; a weakness or leak in one use says nothing about the others.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"permitra-keys-v1",
                info=purpose.encode()).derive(secret.encode())


def secrets_in_order() -> list[str]:
    """The current secret first, then the previous ones, newest first."""
    return [SECRET_KEY, *PREVIOUS_SECRET_KEYS]


def _signing_keys() -> list[bytes | str]:
    """Keys a session token may have been signed with, current first. The raw
    secrets are in the list because tokens issued before the derivation
    existed were signed with SECRET_KEY itself - they keep working until
    they expire, so an upgrade logs nobody out."""
    keys: list[bytes | str] = []
    for secret in secrets_in_order():
        keys.append(derive_key(secret, "jwt"))
    keys.extend(secrets_in_order())
    return keys

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


# PBKDF2-HMAC-SHA256 cost. 600,000 is the OWASP figure (2023); the format
# below records the count per hash, so raising this number upgrades every
# hash on its owner's next login (see needs_rehash) and invalidates none.
# The environment override exists for test runs, where hashing hundreds of
# fixture users at full cost would cost minutes and prove nothing.
PBKDF2_ITERATIONS = int(os.environ.get("PERMITRA_PBKDF2_ITERATIONS", "600000"))
_LEGACY_ITERATIONS = 200_000   # what every hash without a prefix was made with
_ALGORITHM = "pbkdf2_sha256"


def hash_password(password: str, salt: str | None = None, iterations: int | None = None) -> str:
    """`pbkdf2_sha256$<iterations>$<salt>$<digest>` - a hash that says how it was made.

    The stored string used to be `<salt>$<digest>` with the iteration count
    hard-coded in the code, so the cost could not be raised without either
    guessing the format by its shape or invalidating every existing hash.
    """
    salt = salt or secrets.token_hex(16)
    iterations = iterations or PBKDF2_ITERATIONS
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"{_ALGORITHM}${iterations}${salt}${digest.hex()}"


def _parse(stored: str) -> tuple[int, str] | None:
    """(iterations, salt) of a stored hash, in either format; None if unreadable."""
    parts = (stored or "").split("$")
    if len(parts) == 4 and parts[0] == _ALGORITHM and parts[1].isdigit():
        return int(parts[1]), parts[2]
    if len(parts) == 2 and parts[0]:
        return _LEGACY_ITERATIONS, parts[0]
    return None


def verify_password(password: str, stored: str) -> bool:
    parsed = _parse(stored)
    if parsed is None:
        return False
    iterations, salt = parsed
    if stored.startswith(_ALGORITHM + "$"):
        candidate = hash_password(password, salt, iterations)
    else:
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
        candidate = f"{salt}${digest.hex()}"
    return secrets.compare_digest(candidate, stored)


def needs_rehash(stored: str) -> bool:
    """Whether a hash is below the current cost or in the old format."""
    parsed = _parse(stored)
    return parsed is None or parsed[0] < PBKDF2_ITERATIONS or not stored.startswith(_ALGORITHM + "$")


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
    return jwt.encode(payload, derive_key(SECRET_KEY, "jwt"), algorithm=ALGORITHM)


API_TOKEN_PREFIX = "pat_"  # noqa: S105 - identifying prefix of a token, not a secret


def _service_principal_from_pat(request, token: str, db: Session) -> User:
    """Validates a read-only API token and returns a (non-persisted)
    service principal. Only GET access is permitted (fail-secure)."""
    from .models import ApiToken

    # Fail closed: without a request there is no method to check, and "could
    # not tell" must not read as "read-only". Over HTTP FastAPI always passes
    # the request; this only bites a direct call - which is where it should.
    if request is None or request.method not in ("GET", "HEAD", "OPTIONS"):
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


def decode_token(token: str) -> dict:
    """Decode a session token under the current key, else under a previous
    one. Only a signature mismatch moves on to the next key; an expired or
    malformed token is reported as such under the first."""
    keys = _signing_keys()
    for i, key in enumerate(keys):
        try:
            return jwt.decode(token, key, algorithms=[ALGORITHM])
        except jwt.InvalidSignatureError:
            if i == len(keys) - 1:
                raise
    raise jwt.InvalidSignatureError("no key")


def get_current_user(request: Request = None, token: str = Depends(oauth2_scheme),
                     db: Session = Depends(get_db)) -> User:
    # Read-only service token (automation) instead of a JWT
    if token and token.startswith(API_TOKEN_PREFIX):
        return _service_principal_from_pat(request, token, db)
    try:
        payload = decode_token(token)
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
