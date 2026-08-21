from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_roles
from ..database import get_db
from ..models import AciGateway, ComponentType, Role, SecurityComponent, User
from ..schemas import AciGatewayCreate, AciGatewayOut

router = APIRouter(prefix="/api/aci-gateways", tags=["aci-gateways"])


def to_out(gw: AciGateway) -> AciGatewayOut:
    out = AciGatewayOut.model_validate(gw)
    out.pbr_component_name = gw.pbr_component.name if gw.pbr_component else None
    return out


def get_gateway_or_404(db: Session, gateway_id: int) -> AciGateway:
    gateway = db.query(AciGateway).get(gateway_id)
    if not gateway:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "ACI Gateway nicht gefunden")
    return gateway


def validate_pbr_target(db: Session, payload: AciGatewayCreate):
    """PBR-Ziel muss eine existierende Check Point Komponente sein."""
    if not payload.pbr_component_id:
        return
    component = db.query(SecurityComponent).get(payload.pbr_component_id)
    if not component:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "PBR-Ziel-Komponente nicht gefunden")
    if component.type != ComponentType.checkpoint:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"PBR-Anbindung erfolgt an Check Point Firewalls – '{component.name}' "
            f"ist vom Typ {component.type.value}",
        )


@router.get("", response_model=list[AciGatewayOut])
def list_gateways(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return [to_out(g) for g in db.query(AciGateway).order_by(AciGateway.name).all()]


@router.post("", response_model=AciGatewayOut, status_code=201)
def create_gateway(
    payload: AciGatewayCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    if db.query(AciGateway).filter(AciGateway.name.ilike(payload.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, f"Gateway '{payload.name}' existiert bereits")
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
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    gateway = get_gateway_or_404(db, gateway_id)
    duplicate = (
        db.query(AciGateway)
        .filter(AciGateway.name.ilike(payload.name), AciGateway.id != gateway_id)
        .first()
    )
    if duplicate:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Gateway '{payload.name}' existiert bereits")
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
    _: User = Depends(require_roles(Role.architect, Role.operations)),
):
    db.delete(get_gateway_or_404(db, gateway_id))
    db.commit()
