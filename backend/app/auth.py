import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import Role, User

# Fail-secure: ohne gesetztes SECRET_KEY wird der Start verweigert. Nur im
# ausdrücklichen Dev-Modus (PERMITRA_DEV=1) ein zufälliges Prozess-Secret –
# damit lässt sich lokal starten, ausgestellte Tokens überleben aber keinen
# Neustart. Kein hartkodierter Default (sonst fälschbare Admin-Tokens).
SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
if not SECRET_KEY:
    if os.environ.get("PERMITRA_DEV") == "1":
        SECRET_KEY = secrets.token_hex(32)
    else:
        raise RuntimeError(
            "SECRET_KEY ist nicht gesetzt – Start verweigert (fail-secure). "
            "Setze SECRET_KEY (z.B. `openssl rand -hex 32`) oder PERMITRA_DEV=1 für lokale Entwicklung."
        )
ALGORITHM = "HS256"
TOKEN_LIFETIME_HOURS = int(os.environ.get("TOKEN_LIFETIME_HOURS", "8"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt, _, digest = stored.partition("$")
    return secrets.compare_digest(hash_password(password, salt), stored)


def create_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.username,
        "role": user.role.value,
        "iat": int(now.timestamp()),
        "exp": now + timedelta(hours=TOKEN_LIFETIME_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


API_TOKEN_PREFIX = "pat_"


def _service_principal_from_pat(request, token: str, db: Session) -> User:
    """Validiert einen read-only API-Token und liefert einen (nicht persistierten)
    Service-Principal. Nur GET-Zugriffe sind erlaubt (fail-secure)."""
    from .models import ApiToken

    if request is not None and request.method not in ("GET", "HEAD", "OPTIONS"):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "API-Token sind read-only – nur lesende Zugriffe erlaubt")
    digest = hashlib.sha256(token.encode()).hexdigest()
    pat = db.query(ApiToken).filter(ApiToken.token_hash == digest).first()
    if not pat or pat.revoked:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API-Token ungültig oder widerrufen")
    if pat.expires_at is not None:
        exp = pat.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API-Token ist abgelaufen")
    # Letzte Nutzung sparsam aktualisieren (nicht bei jedem Request schreiben)
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
    # Read-only Service-Token (Automatisierung) statt JWT
    if token and token.startswith(API_TOKEN_PREFIX):
        return _service_principal_from_pat(request, token, db)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token ungültig oder abgelaufen")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Benutzer nicht gefunden")
    # Fail-secure: deaktivierte Konten haben keinen Zugriff (auch mit gültigem Token)
    if not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Konto ist deaktiviert")
    # Sofortige Rücknahme: Tokens, die vor der letzten Invalidierung (Deaktivierung,
    # Passwortwechsel/-reset) ausgestellt wurden, gelten nicht mehr
    if user.token_valid_from is not None:
        iat = payload.get("iat")
        valid_from = user.token_valid_from
        if valid_from.tzinfo is None:
            valid_from = valid_from.replace(tzinfo=timezone.utc)
        if iat is None or iat < int(valid_from.timestamp()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sitzung ist nicht mehr gültig")
    return user


def require_roles(*roles: Role):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles and user.role != Role.admin:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Rolle '{user.role.value}' ist für diese Aktion nicht berechtigt",
            )
        return user

    return dependency
