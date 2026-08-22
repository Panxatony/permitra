"""Sign-in and account security: login (with optional TOTP second factor),
forgotten/new password, 2FA management and WebAuthn passkeys."""
import base64
import os
import time
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from .. import audit, mailer, totp
from ..auth import create_token, get_current_user, hash_password, verify_password
from ..database import get_db
from ..models import Passkey, User, utcnow
from ..schemas import Token, UserOut
from .users_router import consume_token, issue_token

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _login_ok(user: User) -> Token:
    return Token(access_token=create_token(user), user=UserOut.model_validate(user))


# Brute-force protection: after LOGIN_MAX_FAILS failed attempts, lock the account for LOGIN_LOCK_MINUTES
LOGIN_MAX_FAILS = int(os.environ.get("LOGIN_MAX_FAILS", "5"))
LOGIN_LOCK_MINUTES = int(os.environ.get("LOGIN_LOCK_MINUTES", "15"))


def _register_failure(db: Session, user: User) -> None:
    from datetime import timedelta
    user.failed_logins = (user.failed_logins or 0) + 1
    if user.failed_logins >= LOGIN_MAX_FAILS:
        user.locked_until = utcnow() + timedelta(minutes=LOGIN_LOCK_MINUTES)
        user.failed_logins = 0
    db.commit()


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == form.username).first()
    # Check the account lock (fail-secure; identical message, no user enumeration)
    if user and user.locked_until is not None:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            from datetime import timezone
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > utcnow():
            audit.record(db, "auth", "auth.login_locked", actor=form.username,
                         source_ip=audit.client_ip(request))
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "Account temporarily locked – try again later")
    if not user or not verify_password(form.password, user.password_hash):
        if user:
            _register_failure(db, user)
        audit.record(db, "auth", "auth.login_failed", actor=form.username,
                     source_ip=audit.client_ip(request),
                     detail="account locked" if (user and user.locked_until) else "")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong username or password")
    if not user.is_active:
        audit.record(db, "auth", "auth.login_denied", actor=user.username,
                     source_ip=audit.client_ip(request), detail="account deactivated")
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "The account is deactivated or not activated yet")
    if user.totp_enabled:
        # Second factor: optional form field "otp"
        otp = ((await request.form()).get("otp") or "").strip()
        if not otp:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "otp_required")
        if not totp.verify(user.totp_secret, otp):
            _register_failure(db, user)
            audit.record(db, "auth", "auth.login_failed", actor=user.username,
                         source_ip=audit.client_ip(request), detail="wrong 2FA code")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "otp_invalid")
    # Success: reset the failure counter and the lock
    if user.failed_logins or user.locked_until:
        user.failed_logins = 0
        user.locked_until = None
        db.commit()
    audit.record(db, "auth", "auth.login", actor=user.username,
                 source_ip=audit.client_ip(request))
    return _login_ok(user)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.put("/notifications", response_model=UserOut)
def set_notifications(
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Turn email notifications on or off (self-service)."""
    user.notify_email = bool(payload.get("notify_email", True))
    db.commit()
    db.refresh(user)
    return user


# ---------- Forgotten password / set password ----------

@router.post("/forgot")
def forgot_password(payload: dict, db: Session = Depends(get_db)):
    """Request a reset link. The response is always the same (no user enumeration)."""
    ident = (payload.get("username") or "").strip()
    user = None
    if ident:
        user = db.query(User).filter(
            (User.username == ident) | (User.email == ident)
        ).first()
    if user and user.email:
        mailer.reset_mail(user, issue_token(db, user, "reset"))
    return {"detail": "If the account exists and has an e-mail address on file, "
                      "a reset link has been sent."}


@router.post("/set-password")
def set_password(request: Request, payload: dict, db: Session = Depends(get_db)):
    """Set the password via an activation or reset link; this activates the account."""
    password = payload.get("password") or ""
    if len(password) < 8:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            "Password must be at least 8 characters long")
    user, purpose = consume_token(db, payload.get("token") or "")
    user.password_hash = hash_password(password)
    user.is_active = True
    user.token_valid_from = utcnow()  # a password change revokes existing tokens
    user.failed_logins = 0
    user.locked_until = None
    db.commit()
    audit.record(db, "auth", "auth.activated" if purpose == "activate" else "auth.password_reset",
                 actor=user.username, source_ip=audit.client_ip(request))
    return {"detail": ("Account activated – you can sign in now"
                       if purpose == "activate" else "Password changed"),
            "username": user.username}


@router.post("/change-password")
def change_password(
    request: Request,
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not verify_password(payload.get("current") or "", user.password_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "The current password is wrong")
    new = payload.get("new") or ""
    if len(new) < 8:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            "Password must be at least 8 characters long")
    user.password_hash = hash_password(new)
    user.token_valid_from = utcnow()  # revokes other existing sessions
    db.commit()
    audit.record(db, "auth", "auth.password_changed", actor=user.username,
                 source_ip=audit.client_ip(request))
    # Fresh token for the current session so it does not expire itself
    return {"detail": "Password changed", "access_token": create_token(user)}


# ---------- Two-factor (TOTP) ----------

@router.post("/totp/setup")
def totp_setup(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Generate a new secret (only becomes active once confirmed with a valid code)."""
    if user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Two-factor authentication is already enabled")
    user.totp_secret = totp.new_secret()
    db.commit()
    return {"secret": user.totp_secret,
            "otpauth_url": totp.otpauth_uri(user.username, user.totp_secret)}


@router.post("/totp/enable")
def totp_enable(payload: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.totp_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Start the setup first")
    if not totp.verify(user.totp_secret, payload.get("code") or ""):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "The code is invalid")
    user.totp_enabled = True
    db.commit()
    audit.record(db, "auth", "auth.totp_enabled", actor=user.username)
    return {"detail": "Two-factor authentication enabled"}


@router.post("/totp/disable")
def totp_disable(payload: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not verify_password(payload.get("password") or "", user.password_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "The password is wrong")
    user.totp_enabled = False
    user.totp_secret = None
    db.commit()
    audit.record(db, "auth", "auth.totp_disabled", actor=user.username)
    return {"detail": "Two-factor authentication disabled"}


# ---------- Passkeys (WebAuthn) ----------

# Keep challenges short-lived in-process (single-worker deployment)
_challenges: dict[str, tuple[bytes, float]] = {}


def _rp_id() -> str:
    explicit = os.environ.get("PERMITRA_RP_ID", "").strip()
    if explicit:
        return explicit
    return urlparse(mailer.base_url()).hostname or "localhost"


def _origins() -> list[str]:
    explicit = os.environ.get("PERMITRA_ORIGIN", "").strip()
    if explicit:
        return [o.strip() for o in explicit.split(",") if o.strip()]
    return [mailer.base_url()]


def _store_challenge(key: str, challenge: bytes) -> None:
    now = time.time()
    for k in [k for k, (_, exp) in _challenges.items() if exp < now]:
        _challenges.pop(k, None)
    _challenges[key] = (challenge, now + 300)


def _take_challenge(key: str) -> bytes:
    entry = _challenges.pop(key, None)
    if not entry or entry[1] < time.time():
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "The request has expired – try again")
    return entry[0]


@router.post("/passkey/register-options", response_class=PlainTextResponse)
def passkey_register_options(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers import base64url_to_bytes
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor

    options = generate_registration_options(
        rp_id=_rp_id(), rp_name="Permitra",
        user_id=str(user.id).encode(), user_name=user.username,
        user_display_name=user.full_name or user.username,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(p.credential_id))
            for p in user.passkeys
        ],
    )
    _store_challenge(f"reg:{user.id}", options.challenge)
    return PlainTextResponse(options_to_json(options), media_type="application/json")


@router.post("/passkey/register")
def passkey_register(payload: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    from webauthn import verify_registration_response
    from webauthn.helpers import bytes_to_base64url

    challenge = _take_challenge(f"reg:{user.id}")
    try:
        verification = verify_registration_response(
            credential=payload.get("credential"),
            expected_challenge=challenge,
            expected_rp_id=_rp_id(),
            expected_origin=_origins(),
        )
    except Exception as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Passkey registration failed: {exc}") from exc
    db.add(Passkey(
        user_id=user.id,
        credential_id=bytes_to_base64url(verification.credential_id),
        public_key=base64.b64encode(verification.credential_public_key).decode(),
        sign_count=verification.sign_count,
        name=(payload.get("name") or "Passkey")[:64],
    ))
    db.commit()
    return {"detail": "Passkey registered"}


@router.get("/passkeys")
def list_passkeys(user: User = Depends(get_current_user)):
    return [
        {"id": p.id, "name": p.name,
         "created_at": p.created_at.isoformat() if p.created_at else None}
        for p in user.passkeys
    ]


@router.delete("/passkeys/{passkey_id}", status_code=204)
def delete_passkey(passkey_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    passkey = db.query(Passkey).filter(Passkey.id == passkey_id, Passkey.user_id == user.id).first()
    if not passkey:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passkey not found")
    db.delete(passkey)
    db.commit()


@router.post("/passkey/login-options", response_class=PlainTextResponse)
def passkey_login_options(payload: dict, db: Session = Depends(get_db)):
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers import base64url_to_bytes
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor

    username = (payload.get("username") or "").strip()
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.passkeys or not user.is_active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "No passkey is registered for this account")
    options = generate_authentication_options(
        rp_id=_rp_id(),
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(p.credential_id))
            for p in user.passkeys
        ],
    )
    _store_challenge(f"auth:{username}", options.challenge)
    return PlainTextResponse(options_to_json(options), media_type="application/json")


@router.post("/passkey/login", response_model=Token)
def passkey_login(payload: dict, db: Session = Depends(get_db)):
    from webauthn import verify_authentication_response

    username = (payload.get("username") or "").strip()
    credential = payload.get("credential") or {}
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign-in failed")
    passkey = next((p for p in user.passkeys if p.credential_id == credential.get("id")), None)
    if not passkey:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign-in failed")
    challenge = _take_challenge(f"auth:{username}")
    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=_rp_id(),
            expected_origin=_origins(),
            credential_public_key=base64.b64decode(passkey.public_key),
            credential_current_sign_count=passkey.sign_count,
        )
    except Exception as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign-in failed") from exc
    passkey.sign_count = verification.new_sign_count
    db.commit()
    # A passkey counts as a strong factor – no additional TOTP required
    return _login_ok(user)
