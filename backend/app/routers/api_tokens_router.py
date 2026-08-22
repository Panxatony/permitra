"""Read-only API tokens for automation (Ansible/Terraform, issue #14).

Managed by admins only. The plaintext token is shown exactly once, at creation
time; only its hash is stored. Tokens grant read access (GET) exclusively; that
restriction is enforced in auth.get_current_user."""
import hashlib
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import audit
from ..auth import API_TOKEN_PREFIX, require_roles
from ..database import get_db
from ..models import ApiToken, Role, User, utcnow

router = APIRouter(prefix="/api/api-tokens", tags=["api-tokens"])


def _out(t: ApiToken) -> dict:
    return {
        "id": t.id, "name": t.name, "prefix": t.prefix,
        "created_by": t.created_by,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
        "revoked": t.revoked,
    }


@router.get("")
def list_tokens(db: Session = Depends(get_db), _: User = Depends(require_roles(Role.admin))):
    return [_out(t) for t in db.query(ApiToken).order_by(ApiToken.created_at.desc()).all()]


@router.post("", status_code=201)
def create_token(
    payload: dict,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.admin)),
    request: Request = None,
):
    """Create a read-only token. The plaintext is returned ONLY here."""
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Name is required")
    expires_at = None
    days = payload.get("expires_days")
    if days:
        try:
            expires_at = utcnow() + timedelta(days=int(days))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "expires_days must be a number") from exc

    raw = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = ApiToken(
        name=name, prefix=raw[:12],
        token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        created_by=admin.username, expires_at=expires_at,
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    audit.record(db, "admin", "apitoken.created", actor=admin.username, object=token.name,
                 source_ip=audit.client_ip(request))
    return {**_out(token), "token": raw,
            "detail": "The token is shown only now – store it somewhere safe."}


@router.delete("/{token_id}", status_code=204)
def revoke_token(
    token_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.admin)),
    request: Request = None,
):
    token = db.get(ApiToken, token_id)
    if not token:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token not found")
    token.revoked = True
    db.commit()
    audit.record(db, "admin", "apitoken.revoked", actor=admin.username, object=token.name,
                 source_ip=audit.client_ip(request))
