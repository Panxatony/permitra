"""Benutzerverwaltung (Admin-Bereich).

Neue Benutzer können mit Passwort (sofort aktiv) oder ohne angelegt werden –
dann erzeugt Permitra einen Aktivierungslink (Mailversand, falls SMTP
konfiguriert; der Link wird zusätzlich dem Admin angezeigt)."""
import hashlib
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from fastapi import Request
from ..auth import hash_password, require_roles
from .. import audit
from ..database import get_db
from .. import mailer
from ..models import AuthToken, Passkey, Role, User, utcnow
from ..schemas import UserCreate, UserOut, UserUpdate

router = APIRouter(prefix="/api/users", tags=["users"])

TOKEN_HOURS = {"activate": 72, "reset": 2}


def issue_token(db: Session, user: User, purpose: str) -> str:
    """Erzeugt einen Einmal-Token (nur der Hash wird gespeichert) und gibt den Link zurück."""
    raw = secrets.token_urlsafe(32)
    db.add(AuthToken(
        user_id=user.id, purpose=purpose,
        token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        expires_at=utcnow() + timedelta(hours=TOKEN_HOURS[purpose]),
    ))
    db.commit()
    return f"{mailer.base_url()}/set-password?token={raw}"


def consume_token(db: Session, raw: str) -> tuple[User, str]:
    """Validiert einen Aktivierungs-/Reset-Token; wirft 400 bei ungültig/abgelaufen."""
    token = (
        db.query(AuthToken)
        .filter(AuthToken.token_hash == hashlib.sha256((raw or "").encode()).hexdigest(),
                AuthToken.used == False)  # noqa: E712
        .first()
    )
    if token:
        expires = token.expires_at
        if expires.tzinfo is None:  # SQLite liefert naive Datetimes
            from datetime import timezone
            expires = expires.replace(tzinfo=timezone.utc)
    if not token or expires < utcnow():
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Link ist ungültig oder abgelaufen – bitte neuen anfordern")
    token.used = True
    return token.user, token.purpose


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_roles(Role.admin))):
    return db.query(User).order_by(User.username).all()


@router.post("", status_code=201)
def create_user(
    request: Request,
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.admin)),
):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Benutzername bereits vergeben")
    with_password = bool(payload.password)
    user = User(
        username=payload.username,
        # Ohne Passwort: unbrauchbarer Zufalls-Hash, bis der Nutzer per Link aktiviert
        password_hash=hash_password(payload.password or secrets.token_urlsafe(24)),
        full_name=payload.full_name,
        email=payload.email,
        role=payload.role,
        is_active=with_password,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.record(db, "admin", "user.created", actor=admin.username, object=user.username,
                 detail=f"Rolle {user.role.value}", source_ip=audit.client_ip(request))

    result = {"user": UserOut.model_validate(user).model_dump()}
    if not with_password:
        link = issue_token(db, user, "activate")
        mail_sent = mailer.activation_mail(user, link)
        result.update({
            "activation_link": link,
            "mail_sent": mail_sent,
            "detail": ("Aktivierungsmail versendet" if mail_sent
                       else "Kein Mailversand konfiguriert – Aktivierungslink bitte manuell übermitteln"),
        })
    return result


@router.put("/{username}", response_model=UserOut)
def update_user(
    request: Request,
    username: str,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.admin)),
):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Benutzer nicht gefunden")
    if username == admin.username and payload.role not in (None, Role.admin):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Eigene Admin-Rolle nicht entziehbar")
    if username == admin.username and payload.is_active is False:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Eigener Account nicht deaktivierbar")
    for field in ("full_name", "email", "role", "is_active"):
        value = getattr(payload, field)
        if value is not None:
            setattr(user, field, value)
    # Deaktivierung und Rollenwechsel entziehen bestehende Tokens sofort
    if payload.is_active is False or payload.role is not None:
        user.token_valid_from = utcnow()
    # Reaktivierung durch den Admin hebt eine Kontosperre auf
    if payload.is_active is True:
        user.failed_logins = 0
        user.locked_until = None
    db.commit()
    db.refresh(user)
    changed = {f: getattr(payload, f) for f in ("role", "is_active", "email", "full_name")
               if getattr(payload, f) is not None}
    audit.record(db, "admin", "user.updated", actor=admin.username, object=username,
                 detail=str({k: (v.value if hasattr(v, "value") else v) for k, v in changed.items()}),
                 source_ip=audit.client_ip(request))
    return user


@router.post("/{username}/send-reset")
def send_reset(
    username: str,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    """Admin stößt einen Passwort-Reset an (z.B. wenn der Nutzer keinen Zugriff mehr hat)."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Benutzer nicht gefunden")
    link = issue_token(db, user, "reset")
    mail_sent = mailer.reset_mail(user, link)
    return {
        "reset_link": link,
        "mail_sent": mail_sent,
        "detail": ("Reset-Mail versendet" if mail_sent
                   else "Kein Mailversand konfiguriert – Reset-Link bitte manuell übermitteln"),
    }


@router.delete("/{username}", status_code=204)
def delete_user(
    request: Request,
    username: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.admin)),
):
    if username == admin.username:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Eigenen Account nicht löschbar")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Benutzer nicht gefunden")
    db.query(AuthToken).filter(AuthToken.user_id == user.id).delete()
    db.query(Passkey).filter(Passkey.user_id == user.id).delete()
    db.delete(user)
    db.commit()
    audit.record(db, "admin", "user.deleted", actor=admin.username, object=username,
                 source_ip=audit.client_ip(request))
