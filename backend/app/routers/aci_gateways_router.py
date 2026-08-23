from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..database import get_db
from ..messages import _
from ..models import AciGateway, ComponentType, Role, SecurityComponent, User
from ..schemas import AciGatewayCreate, AciGatewayOut

router = APIRouter(prefix="/api/aci-gateways", tags=["aci-gateways"])


def to_out(gw: AciGateway) -> AciGatewayOut:
    out = AciGatewayOut.model_validate(gw)
    out.pbr_component_name = gw.pbr_component.name if gw.pbr_component else None
    return out


def get_gateway_or_404(db: Session, gateway_id: int) -> AciGateway:
    gateway = db.get(AciGateway, gateway_id)
    if not gateway:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("ACI gateway not found"))
    return gateway


def validate_pbr_target(db: Session, payload: AciGatewayCreate):
    """The PBR target must be an existing Check Point component."""
    if not payload.pbr_component_id:
        return
    component = db.get(SecurityComponent, payload.pbr_component_id)
    if not component:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, _("PBR target component not found"))
    if component.type != ComponentType.checkpoint:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _("PBR attaches to Check Point firewalls – '{name}' "
              "is of type {component_type}",
              name=component.name, component_type=component.type.value),
        )


@router.get("", response_model=list[AciGatewayOut])
def list_gateways(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return [to_out(g) for g in db.query(AciGateway).order_by(AciGateway.name).all()]


@router.post("", response_model=AciGatewayOut, status_code=201)
def create_gateway(
    payload: AciGatewayCreate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    if db.query(AciGateway).filter(AciGateway.name.ilike(payload.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Gateway '{name}' already exists", name=payload.name))
    validate_pbr_target(db, payload)
    gateway = AciGateway(**payload.model_dump())
    db.add(gateway)
    db.commit()
    db.refresh(gateway)
    return to_out(gateway)


@router.put("/{gateway_id}", response_model=AciGatewayOut)
def update_gateway(
    gateway_id: int,
    payload: AciGatewayCreate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    gateway = get_gateway_or_404(db, gateway_id)
    duplicate = (
        db.query(AciGateway)
        .filter(AciGateway.name.ilike(payload.name), AciGateway.id != gateway_id)
        .first()
    )
    if duplicate:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Gateway '{name}' already exists", name=payload.name))
    validate_pbr_target(db, payload)
    for key, value in payload.model_dump().items():
        setattr(gateway, key, value)
    db.commit()
    db.refresh(gateway)
    return to_out(gateway)


@router.delete("/{gateway_id}", status_code=204)
def delete_gateway(
    gateway_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    db.delete(get_gateway_or_404(db, gateway_id))
    db.commit()
