"""Anmeldung und Konto-Sicherheit: Login (mit optionalem TOTP-Zweitfaktor),
Passwort vergessen/setzen, 2FA-Verwaltung und WebAuthn-Passkeys."""
import base64
import json
import os
import time
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from ..auth import create_token, get_current_user, hash_password, verify_password
from ..database import get_db
from .. import mailer, totp
from ..models import Passkey, User
from ..schemas import Token, UserOut
from .users_router import consume_token, issue_token

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _login_ok(user: User) -> Token:
    return Token(access_token=create_token(user), user=UserOut.model_validate(user))


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Benutzername oder Passwort falsch")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Konto ist deaktiviert bzw. noch nicht aktiviert")
    if user.totp_enabled:
        # Zweiter Faktor: optionales Formularfeld "otp"
        otp = ((await request.form()).get("otp") or "").strip()
        if not otp:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "otp_required")
        if not totp.verify(user.totp_secret, otp):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "otp_invalid")
    return _login_ok(user)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


# ---------- Passwort vergessen / setzen ----------

@router.post("/forgot")
def forgot_password(payload: dict, db: Session = Depends(get_db)):
    """Reset-Link anfordern. Antwort ist immer gleich (kein Nutzer-Enumerieren)."""
    ident = (payload.get("username") or "").strip()
    user = None
    if ident:
        user = db.query(User).filter(
            (User.username == ident) | (User.email == ident)
        ).first()
    if user and user.email:
        mailer.reset_mail(user, issue_token(db, user, "reset"))
    return {"detail": "Falls das Konto existiert und eine E-Mail-Adresse hinterlegt ist, "
                      "wurde ein Reset-Link versendet."}


@router.post("/set-password")
def set_password(payload: dict, db: Session = Depends(get_db)):
    """Passwort über Aktivierungs- oder Reset-Link setzen; aktiviert das Konto."""
    password = payload.get("password") or ""
    if len(password) < 8:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "Passwort muss mindestens 8 Zeichen haben")
    user, purpose = consume_token(db, payload.get("token") or "")
    user.password_hash = hash_password(password)
    user.is_active = True
    user.token_valid_from = utcnow()  # Passwortänderung entzieht bestehende Tokens
    db.commit()
    return {"detail": ("Konto aktiviert – du kannst dich jetzt anmelden"
                       if purpose == "activate" else "Passwort geändert"),
            "username": user.username}


@router.post("/change-password")
def change_password(
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not verify_password(payload.get("current") or "", user.password_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Aktuelles Passwort ist falsch")
    new = payload.get("new") or ""
    if len(new) < 8:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "Passwort muss mindestens 8 Zeichen haben")
    user.password_hash = hash_password(new)
    user.token_valid_from = utcnow()  # entzieht andere bestehende Sitzungen
    db.commit()
    # Frisches Token für die aktuelle Sitzung, damit sie nicht selbst abläuft
    return {"detail": "Passwort geändert", "access_token": create_token(user)}


# ---------- Zwei-Faktor (TOTP) ----------

@router.post("/totp/setup")
def totp_setup(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Neues Secret erzeugen (aktiv erst nach Bestätigung mit gültigem Code)."""
    if user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "2FA ist bereits aktiviert")
    user.totp_secret = totp.new_secret()
    db.commit()
    return {"secret": user.totp_secret,
            "otpauth_url": totp.otpauth_uri(user.username, user.totp_secret)}


@router.post("/totp/enable")
def totp_enable(payload: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.totp_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Bitte zuerst das Setup starten")
    if not totp.verify(user.totp_secret, payload.get("code") or ""):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Code ist ungültig")
    user.totp_enabled = True
    db.commit()
    return {"detail": "Zwei-Faktor-Authentifizierung aktiviert"}


@router.post("/totp/disable")
def totp_disable(payload: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not verify_password(payload.get("password") or "", user.password_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Passwort ist falsch")
    user.totp_enabled = False
    user.totp_secret = None
    db.commit()
    return {"detail": "Zwei-Faktor-Authentifizierung deaktiviert"}


# ---------- Passkeys (WebAuthn) ----------

# Challenges kurzlebig im Prozess halten (Single-Worker-Deployment)
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
                            "Anfrage abgelaufen – bitte erneut versuchen")
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
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Passkey-Registrierung fehlgeschlagen: {exc}")
    db.add(Passkey(
        user_id=user.id,
        credential_id=bytes_to_base64url(verification.credential_id),
        public_key=base64.b64encode(verification.credential_public_key).decode(),
        sign_count=verification.sign_count,
        name=(payload.get("name") or "Passkey")[:64],
    ))
    db.commit()
    return {"detail": "Passkey registriert"}


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
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passkey nicht gefunden")
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
                            "Für dieses Konto ist kein Passkey hinterlegt")
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
    from webauthn.helpers import bytes_to_base64url

    username = (payload.get("username") or "").strip()
    credential = payload.get("credential") or {}
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Anmeldung fehlgeschlagen")
    passkey = next((p for p in user.passkeys if p.credential_id == credential.get("id")), None)
    if not passkey:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Anmeldung fehlgeschlagen")
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
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Anmeldung fehlgeschlagen")
    passkey.sign_count = verification.new_sign_count
    db.commit()
    # Passkey gilt als starker Faktor – kein zusätzliches TOTP nötig
    return _login_ok(user)
