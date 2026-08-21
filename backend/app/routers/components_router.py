from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from pydantic import BaseModel

from ..auth import get_current_user, require_roles
from ..database import get_db
from ..drift import analyze_drift
from ..models import (
    AciGateway,
    ComponentActualConfig,
    ComponentLink,
    Role,
    SecurityComponent,
    User,
)
from ..schemas import ComponentCreate, ComponentOut


class ActualConfigIn(BaseModel):
    content: str


class LinkIn(BaseModel):
    component_a_id: int
    component_b_id: int
    link_type: str = ""   # Art der Verbindung, z.B. "OSPF Routing", "BGP Peering"
    description: str = ""

router = APIRouter(prefix="/api/components", tags=["components"])


def get_component_or_404(db: Session, component_id: int) -> SecurityComponent:
    component = db.query(SecurityComponent).get(component_id)
    if not component:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Komponente nicht gefunden")
    return component


@router.get("", response_model=list[ComponentOut])
def list_components(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(SecurityComponent).order_by(SecurityComponent.name).all()


@router.post("", response_model=ComponentOut, status_code=201)
def create_component(
    payload: ComponentCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    if db.query(SecurityComponent).filter(SecurityComponent.name.ilike(payload.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, f"Komponente '{payload.name}' existiert bereits")
    component = SecurityComponent(**payload.model_dump())
    db.add(component)
    db.commit()
    db.refresh(component)
    return component


# --- Kommunikationsbeziehungen (vor den /{component_id}-Routen definiert) ----

@router.get("/links")
def list_links(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return [
        {
            "id": link.id,
            "a_id": link.component_a_id,
            "a_name": link.component_a.name,
            "a_type": link.component_a.type.value,
            "b_id": link.component_b_id,
            "b_name": link.component_b.name,
            "b_type": link.component_b.type.value,
            "link_type": link.link_type,
            "description": link.description,
        }
        for link in db.query(ComponentLink).all()
    ]


@router.post("/links", status_code=201)
def create_link(
    payload: LinkIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    if payload.component_a_id == payload.component_b_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Eine Komponente spricht nicht mit sich selbst")
    a, b = sorted((payload.component_a_id, payload.component_b_id))
    for cid in (a, b):
        if not db.query(SecurityComponent).get(cid):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Komponente {cid} nicht gefunden")
    existing = (
        db.query(ComponentLink)
        .filter(ComponentLink.component_a_id == a, ComponentLink.component_b_id == b)
        .first()
    )
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Beziehung existiert bereits")
    link = ComponentLink(component_a_id=a, component_b_id=b,
                         link_type=payload.link_type, description=payload.description)
    db.add(link)
    db.commit()
    return {"id": link.id}


@router.delete("/links/{link_id}", status_code=204)
def delete_link(
    link_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    link = db.query(ComponentLink).get(link_id)
    if not link:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Beziehung nicht gefunden")
    db.delete(link)
    db.commit()


@router.put("/{component_id}", response_model=ComponentOut)
def update_component(
    component_id: int,
    payload: ComponentCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    component = get_component_or_404(db, component_id)
    duplicate = (
        db.query(SecurityComponent)
        .filter(SecurityComponent.name.ilike(payload.name), SecurityComponent.id != component_id)
        .first()
    )
    if duplicate:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Komponente '{payload.name}' existiert bereits")
    for key, value in payload.model_dump().items():
        setattr(component, key, value)
    db.commit()
    db.refresh(component)
    return component


@router.put("/{component_id}/actual-config")
def upload_actual_config(
    component_id: int,
    payload: ActualConfigIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    """Hinterlegt die Ist-Konfiguration des Geräts für den Soll-Ist-Abgleich."""
    component = get_component_or_404(db, component_id)
    config = (
        db.query(ComponentActualConfig)
        .filter(ComponentActualConfig.component_id == component.id)
        .first()
    )
    if not config:
        config = ComponentActualConfig(component_id=component.id)
        db.add(config)
    config.content = payload.content
    config.uploaded_by = user.username
    from ..models import utcnow

    config.fetched_at = utcnow()
    db.commit()
    return {"status": "ok", "bytes": len(payload.content)}


@router.get("/{component_id}/drift")
def drift(
    component_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Soll-Ist-Abgleich: fehlende, veraltete und unbekannte Regeln auf dem Gerät."""
    return analyze_drift(db, get_component_or_404(db, component_id))


@router.delete("/{component_id}", status_code=204)
def delete_component(
    component_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    component = get_component_or_404(db, component_id)
    used = db.query(AciGateway).filter(AciGateway.pbr_component_id == component_id).count()
    if used:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Komponente '{component.name}' ist PBR-Ziel von {used} ACI Gateway(s)",
        )
    db.delete(component)
    db.commit()
