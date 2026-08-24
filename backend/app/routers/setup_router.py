"""First-run setup: the checklist between "it starts" and "it works" (#67).

Deploying Permitra ends at a login form. What a working instance needs next -
language, zones, networks, components, matrix, accounts - is scattered across
the admin area and the zones page, and nothing tells a new operator the order
or the why. A person who knows Permitra does it in half an hour; a person
evaluating it hits "network not assigned to any zone" on their first rule and
concludes the product is broken. The failure arrives before the mental model.

This endpoint computes the checklist; the interface shows it until the
essentials exist. Deliberately a guide, not a gate: nothing here blocks
anything, every step links to the normal page, and everything written on the
way goes through the normal endpoints into the audit log. A wizard with its
own forms would be a second implementation of six pages that already exist.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import (
    AddressComponentMap,
    Role,
    Rule,
    SecurityComponent,
    Setting,
    User,
    Zone,
    ZoneNetwork,
    ZonePolicy,
)

router = APIRouter(prefix="/api/setup", tags=["setup"])


@router.get("/status")
def setup_status(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """The state of the essentials, in the order they depend on each other.

    Readable by every signed-in role: the steps belong to different roles
    (language to the admin, zones to an architect), so each person has to be
    able to see what is still missing and whose move it is.

    "Done" is judged by what exists, not by what was clicked through - an
    instance configured entirely through the API shows a finished checklist it
    has never seen.
    """
    # The language counts as decided only when the setting row exists. The
    # default works, but a default nobody chose is how an instance ends up
    # showing German screenshots to an English team for a year.
    language_chosen = db.get(Setting, "ui_language") is not None

    zones = db.query(Zone).count()
    networks = db.query(ZoneNetwork).count()
    components = db.query(SecurityComponent).count()
    mappings = db.query(AddressComponentMap).count()
    policies = db.query(ZonePolicy).count()
    matrix_default_chosen = db.get(Setting, "zone_matrix_default") is not None
    rules = db.query(Rule).count()

    def active(role: Role) -> int:
        return (db.query(User)
                .filter(User.role == role, User.is_active.is_(True)).count())

    architects = active(Role.architect)
    operations = active(Role.operations)
    approvers = active(Role.change_approver)
    accounts_done = architects >= 1 and operations >= 1 and approvers >= 2

    # Two phases, because two different people act. The admin prepares the
    # instance - language, accounts - and then hands over: everything from the
    # zones on is the architects' work, which is exactly why the accounts come
    # before the domain steps rather than after them. An admin working the list
    # top to bottom reaches "create accounts" while it is still their move.
    steps = [
        # (id, done, count-or-None, phase, who acts, where)
        ("language", language_chosen, None, "admin", "admin", "/admin"),
        ("accounts", accounts_done, None, "admin", "admin", "/admin"),
        ("zones", zones > 0, zones, "architect", "architect", "/zones"),
        ("networks", networks > 0, networks, "architect", "architect", "/networks"),
        ("components", components > 0, components, "architect", "architect", "/components"),
        # Done when either relations are maintained or the default-deny decision
        # was made explicitly - both are the deliberate act the step asks for;
        # an untouched legacy default is neither. Maintained by architects,
        # approved by two change approvers.
        ("matrix", policies > 0 or matrix_default_chosen, policies,
         "architect", "architect", "/zones"),
        # The proof step: the first rule exercises zone derivation and the
        # address mapping (the form asks once per new address), so reaching it
        # means the steps above actually fit together.
        ("first_rule", rules > 0, rules, "architect", "architect", "/rules/new"),
    ]

    warnings = []
    # The matrix workflow needs two DIFFERENT approvers; with fewer it cannot
    # complete, and today you find that out when the second approval never
    # comes. Warned permanently, not only during setup - approvers leave.
    if approvers < 2:
        warnings.append({"code": "too-few-approvers", "count": approvers})

    return {
        "complete": all(done for _, done, *_ in steps),
        "steps": [
            {"id": sid, "done": done, "count": count, "phase": phase,
             "role": role, "route": route}
            for sid, done, count, phase, role, route in steps
        ],
        "mappings": mappings,
        "approvers_active": approvers,
        "warnings": warnings,
    }
