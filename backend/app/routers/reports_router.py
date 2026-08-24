"""Reports: the questions someone asks across the whole ruleset.

The pages elsewhere are for working - creating, deciding, maintaining. This is
for looking: the target/actual comparison lives here in the interface, and the
requestor overview answers "who asked for all of this?" - which, per BSI
documentation duties, every rule records but nothing summed up until now.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import require_roles
from ..database import get_db
from ..models import IN_FORCE, Role, Rule, User
from .recert_router import _known_accounts

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/requestors")
def requestor_summary(db: Session = Depends(get_db),
                      user: User = Depends(require_roles(
                          Role.change_approver, Role.architect, Role.operations))):
    """Rules per requestor: how many, how many in force, and whether the person
    still exists.

    The unknown-flag is the finding, same argument as in the recertification
    worklist: a requestor matching no active user cannot be asked whether their
    rules are still needed - and a pile of in-force rules whose requester is
    gone is where a ruleset starts to rot.
    """
    known = _known_accounts(db)
    rows: dict[str, dict] = {}
    for rule in db.query(Rule).filter(Rule.deleted_at.is_(None)).all():
        name = (rule.requestor or "").strip()
        entry = rows.setdefault(name, {"requestor": name, "total": 0, "in_force": 0})
        entry["total"] += 1
        if rule.status in IN_FORCE:
            entry["in_force"] += 1
    result = sorted(rows.values(), key=lambda e: (-e["total"], e["requestor"]))
    for entry in result:
        entry["unknown"] = bool(entry["requestor"]) and entry["requestor"].lower() not in known
    return {"requestors": result,
            "without_requestor": rows.get("", {}).get("total", 0)}
