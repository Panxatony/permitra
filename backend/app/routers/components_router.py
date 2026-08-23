from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import coverage
from ..auth import get_current_user, require_roles
from ..database import get_db
from ..drift import analyze_drift
from ..messages import _
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
    # A device configuration is text, and a large one is still only a few
    # hundred kilobytes. Without a bound, one request can fill the database and
    # every later drift run loads all of it into memory. 4 MB is roomy for a
    # policy dump and small enough that a hostile upload cannot do either.
    content: str = Field(max_length=4 * 1024 * 1024)


class LinkIn(BaseModel):
    component_a_id: int
    component_b_id: int
    link_type: str = ""   # kind of connection, e.g. "OSPF Routing", "BGP Peering"
    description: str = ""

router = APIRouter(prefix="/api/components", tags=["components"])


def get_component_or_404(db: Session, component_id: int) -> SecurityComponent:
    component = db.get(SecurityComponent, component_id)
    if not component:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Component not found"))
    return component


@router.get("", response_model=list[ComponentOut])
def list_components(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return db.query(SecurityComponent).order_by(SecurityComponent.name).all()


@router.post("", response_model=ComponentOut, status_code=201)
def create_component(
    payload: ComponentCreate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    if db.query(SecurityComponent).filter(SecurityComponent.name.ilike(payload.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Component '{name}' already exists", name=payload.name))
    component = SecurityComponent(**payload.model_dump())
    db.add(component)
    db.commit()
    db.refresh(component)
    return component


# --- Communication relations (defined before the /{component_id} routes) ----

@router.get("/links")
def list_links(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
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
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    if payload.component_a_id == payload.component_b_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("A component cannot be linked to itself"))
    a, b = sorted((payload.component_a_id, payload.component_b_id))
    for cid in (a, b):
        if not db.get(SecurityComponent, cid):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                _("Component {component_id} not found", component_id=cid))
    existing = (
        db.query(ComponentLink)
        .filter(ComponentLink.component_a_id == a, ComponentLink.component_b_id == b)
        .first()
    )
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, _("The link already exists"))
    link = ComponentLink(component_a_id=a, component_b_id=b,
                         link_type=payload.link_type, description=payload.description)
    db.add(link)
    db.commit()
    return {"id": link.id}


@router.delete("/links/{link_id}", status_code=204)
def delete_link(
    link_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    link = db.get(ComponentLink, link_id)
    if not link:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Link not found"))
    db.delete(link)
    db.commit()


@router.put("/{component_id}", response_model=ComponentOut)
def update_component(
    component_id: int,
    payload: ComponentCreate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    component = get_component_or_404(db, component_id)
    duplicate = (
        db.query(SecurityComponent)
        .filter(SecurityComponent.name.ilike(payload.name), SecurityComponent.id != component_id)
        .first()
    )
    if duplicate:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Component '{name}' already exists", name=payload.name))
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
    """Store the device's actual configuration for the target/actual drift comparison."""
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
    # The arrival of a configuration is the only moment a new measurement exists.
    # Recording it here, rather than when somebody opens the dashboard, is what
    # makes the trend a series of measurements instead of a series of page views.
    snapshot = coverage.record_snapshot(db, component, payload.content, user.username)
    db.commit()
    return {"status": "ok", "bytes": len(payload.content),
            "coverage": {"recognised": snapshot.recognised,
                         "total": snapshot.total, "justified": snapshot.justified}}


@router.get("/{component_id}/drift")
def drift(
    component_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Target/actual comparison: rules missing, outdated or unknown on the device."""
    return analyze_drift(db, get_component_or_404(db, component_id))


@router.delete("/{component_id}", status_code=204)
def delete_component(
    component_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    component = get_component_or_404(db, component_id)
    used = db.query(AciGateway).filter(AciGateway.pbr_component_id == component_id).count()
    if used:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            _("Component '{name}' is the PBR target of {used} ACI gateway(s)",
              name=component.name, used=used),
        )
    db.delete(component)
    db.commit()
