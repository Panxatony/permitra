from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import hash_password, require_roles
from ..database import get_db
from ..models import Role, User
from ..schemas import UserCreate, UserOut

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_roles(Role.admin))):
    return db.query(User).order_by(User.username).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.admin)),
):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Benutzername bereits vergeben")
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        email=payload.email,
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{username}", status_code=204)
def delete_user(
    username: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.admin)),
):
    if username == admin.username:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Eigenen Account nicht löschbar")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Benutzer nicht gefunden")
    db.delete(user)
    db.commit()
