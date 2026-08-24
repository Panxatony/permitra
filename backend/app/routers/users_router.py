"""User management (admin area).

New users can be created with a password (active immediately) or without one –
in that case Permitra issues an activation link (sent by mail if SMTP is
configured; the link is additionally shown to the admin)."""
import hashlib
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import audit, mailer
from ..auth import hash_password, require_roles
from ..database import get_db
from ..messages import _
from ..models import AuthToken, Passkey, Role, User, utcnow
from ..schemas import UserCreate, UserOut, UserUpdate

router = APIRouter(prefix="/api/users", tags=["users"])

TOKEN_HOURS = {"activate": 72, "reset": 2}


def issue_token(db: Session, user: User, purpose: str) -> str:
    """Create a one-time token (only its hash is stored) and return the link."""
    raw = secrets.token_urlsafe(32)
    db.add(AuthToken(
        user_id=user.id, purpose=purpose,
        token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        expires_at=utcnow() + timedelta(hours=TOKEN_HOURS[purpose]),
    ))
    db.commit()
    return f"{mailer.base_url()}/set-password?token={raw}"


def consume_token(db: Session, raw: str) -> tuple[User, str]:
    """Validate an activation/reset token; raises 400 if invalid or expired."""
    token = (
        db.query(AuthToken)
        .filter(AuthToken.token_hash == hashlib.sha256((raw or "").encode()).hexdigest(),
                AuthToken.used == False)  # noqa: E712
        .first()
    )
    if token:
        expires = token.expires_at
        if expires.tzinfo is None:  # SQLite returns naive datetimes
            from datetime import timezone
            expires = expires.replace(tzinfo=timezone.utc)
    if not token or expires < utcnow():
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            _("The link is invalid or expired – request a new one"))
    token.used = True
    return token.user, token.purpose


@router.get("/architects")
def list_architects(db: Session = Depends(get_db),
                    user: User = Depends(require_roles(Role.architect, Role.admin))):
    """Active architect accounts, for picking a handover successor.

    Deliberately narrow: username and name only, architects (the accounts that
    can be a requestor), no email or status - an architect may choose a
    successor without being handed the whole user table."""
    rows = (db.query(User)
            .filter(User.role == Role.architect, User.is_active.is_(True))
            .order_by(User.username).all())
    return [{"username": u.username, "full_name": u.full_name} for u in rows]


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _user: User = Depends(require_roles(Role.admin))):
    return db.query(User).order_by(User.username).all()


@router.post("", status_code=201)
def create_user(
    request: Request,
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.admin)),
):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status.HTTP_409_CONFLICT, _("Username is already taken"))
    with_password = bool(payload.password)
    user = User(
        username=payload.username,
        # Without a password: an unusable random hash until the user activates via link
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
                 detail="Role {role}", detail_values={"role": user.role.value},
                 source_ip=audit.client_ip(request))

    result = {"user": UserOut.model_validate(user).model_dump()}
    if not with_password:
        link = issue_token(db, user, "activate")
        mail_sent = mailer.activation_mail(user, link)
        result.update({
            "activation_link": link,
            "mail_sent": mail_sent,
            "detail": (_("Activation mail sent") if mail_sent
                       else _("No mail delivery configured – pass on the activation link manually")),
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
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("User not found"))
    if username == admin.username and payload.role not in (None, Role.admin):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, _("You cannot remove your own admin role"))
    if username == admin.username and payload.is_active is False:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, _("You cannot deactivate your own account"))
    for field in ("full_name", "email", "role", "is_active"):
        value = getattr(payload, field)
        if value is not None:
            setattr(user, field, value)
    # Deactivation and role changes revoke existing tokens immediately
    if payload.is_active is False or payload.role is not None:
        user.token_valid_from = utcnow()
    # Reactivation by the admin lifts an account lock
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
    _user: User = Depends(require_roles(Role.admin)),
):
    """An admin triggers a password reset (e.g. when the user has lost access)."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("User not found"))
    link = issue_token(db, user, "reset")
    mail_sent = mailer.reset_mail(user, link)
    return {
        "reset_link": link,
        "mail_sent": mail_sent,
        "detail": (_("Reset mail sent") if mail_sent
                   else _("No mail delivery configured – pass on the reset link manually")),
    }


@router.delete("/{username}", status_code=204)
def delete_user(
    request: Request,
    username: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.admin)),
):
    if username == admin.username:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, _("You cannot delete your own account"))
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("User not found"))
    db.query(AuthToken).filter(AuthToken.user_id == user.id).delete()
    db.query(Passkey).filter(Passkey.user_id == user.id).delete()
    db.delete(user)
    db.commit()
    audit.record(db, "admin", "user.deleted", actor=admin.username, object=username,
                 source_ip=audit.client_ip(request))
