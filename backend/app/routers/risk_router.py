"""The criteria behind the risk hints - visible and maintainable.

A risk hint is shown to an approver before they decide, so the standard it was
raised by is part of the evidence, not an implementation detail. Previously the
list of risky services sat in the source and could neither be looked up nor
adapted; silence then read as "harmless" when it only meant "not in the list".

Reading the criteria is open to every signed-in role - approvers need to know
what they are being warned about. Changing them is an administrative act and is
recorded in the audit log, because moving the yardstick is itself relevant to a
review.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import audit
from ..auth import get_current_user, require_roles
from ..database import get_db
from ..messages import _
from ..models import RiskyPort, Role, User
from ..risk import (
    _SB_WEIGHT,
    BROAD_PREFIX_MAX,
    DEFAULT_RISKY_PORTS,
    UNTRUSTED_PAP,
    configured_risky_ports,
)

router = APIRouter(prefix="/api/risk", tags=["risk"])


@router.get("/criteria")
def read_criteria(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Every criterion the risk analysis applies, with its severity.

    Deliberately complete rather than a summary: a criterion that is not listed
    cannot be checked by anyone reviewing the tool."""
    ports = configured_risky_ports(db)
    return {
        "patterns": [
            {"code": "any-to-any", "severity": "high",
             "detail": _("Source and destination are both 'any' – the rule is too broad")},
            {"code": "any-source", "severity": "medium",
             "detail": _("Source is 'any' – every address may connect")},
            {"code": "broad-network", "severity": "medium",
             "detail": _("Source or destination contains a very broad network"),
             "threshold": f"<= /{BROAD_PREFIX_MAX}"},
            {"code": "risky-service", "severity": "medium",
             "detail": _("A service from the list below is used"),
             "note": _("Raised to high when the source zone is exposed")},
            {"code": "any-service", "severity": "medium",
             "detail": _("Service 'any' on a cross-zone rule")},
        ],
        # The destination zone's protection level raises the severity by this
        # many steps (none < low < medium < high).
        "protection_level_weight": dict(_SB_WEIGHT),
        "exposed_pap_levels": sorted(UNTRUSTED_PAP),
        # The shipped default labels are in the message catalogue and therefore
        # follow the instance language; a label an administrator typed is not,
        # and comes back exactly as it was entered. `source_label` is what is
        # actually stored - an editor has to work on that, otherwise saving an
        # unchanged entry would silently freeze the translation as own wording.
        "risky_ports": [{"port": p, "label": _(label), "source_label": label} for p, label in
                        sorted(ports.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0)],
        "risky_ports_are_default": ports == DEFAULT_RISKY_PORTS,
        "default_port_count": len(DEFAULT_RISKY_PORTS),
    }


def _normalise_port(value) -> str:
    port = str(value or "").strip()
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("'{port}' is not a valid port (1-65535)", port=port))
    return str(int(port))


@router.put("/ports/{port}", status_code=200)
def set_risky_port(
    request: Request,
    port: str,
    payload: dict,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.admin)),
):
    """Adds a service to the list or renames it."""
    port = _normalise_port(port)
    label = str(payload.get("label") or "").strip()
    if not label:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, _("Name is required"))

    _seed_if_empty(db)
    entry = db.query(RiskyPort).filter(RiskyPort.port == port).first()
    action = "risk.port_changed" if entry else "risk.port_added"
    if entry:
        entry.label = label
    else:
        db.add(RiskyPort(port=port, label=label))
    db.commit()
    audit.record(db, "admin", action, actor=admin.username, object=port, detail=label,
                 source_ip=audit.client_ip(request))
    return {"port": port, "label": label}


@router.delete("/ports/{port}", status_code=204)
def delete_risky_port(
    request: Request,
    port: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_roles(Role.admin)),
):
    """Removes a service from the list - rules using it stop being flagged."""
    port = _normalise_port(port)
    _seed_if_empty(db)
    entry = db.query(RiskyPort).filter(RiskyPort.port == port).first()
    if not entry:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            _("Port {port} is not on the list", port=port))
    label = entry.label
    db.delete(entry)
    db.commit()
    audit.record(db, "admin", "risk.port_removed", actor=admin.username, object=port,
                 detail=label, source_ip=audit.client_ip(request))


def _seed_if_empty(db: Session) -> None:
    """Writes the defaults out before the first change.

    Without this, removing one entry from an empty table would silently promote
    the remaining defaults to "the configured list" - the deletion would appear
    to do nothing."""
    if db.query(RiskyPort).first():
        return
    for default_port, default_label in DEFAULT_RISKY_PORTS.items():
        db.add(RiskyPort(port=default_port, label=default_label))
    db.commit()
