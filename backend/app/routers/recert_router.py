"""Recertification campaigns: the ruleset is reviewed, not just expired (#35).

Extending a date is a decision about a calendar. Recertification is a decision
about a rule - is it still needed, still scoped correctly, still owned by
someone who exists - and a decision has to be asked for, recorded, and
reportable. The campaign is that process: a scope, a cut-off date, a worklist
per owner, and a report of who confirmed what, which is the deliverable an
auditor actually asks for.

Three decisions per item, and the vocabulary is deliberately not yes/no:

  confirmed   still required, as it stands
  rework      still needed but wrong - the rule goes back into review
  retired     no longer needed - deactivated, components set to "to remove"

The middle one matters most. Without it, a reviewer facing a rule that is
almost right has two bad options - wave it through or kill it - and both
produce a ruleset the review was supposed to prevent.
"""
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit
from ..auth import require_roles
from ..database import get_db
from ..messages import _, render
from ..models import (
    IN_FORCE,
    Comment,
    RecertCampaign,
    RecertItem,
    Role,
    Rule,
    RuleStatus,
    SecurityComponent,
    User,
    active_rules,
    utcnow,
)
from .rules_router import add_version

router = APIRouter(prefix="/api/recertification/campaigns", tags=["recertification"])

DECISIONS = ("confirmed", "rework", "retired")


class CampaignCreate(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    due_date: str
    # "all" | "zone:<code-or-name>" | "component:<id>"
    scope: str = "all"


class Decision(BaseModel):
    comment: str = ""
    # Confirming may carry a new expiry in the same act: the confirmation is
    # the decision, the date is its consequence. Without this, "still required"
    # on a rule expiring next week means the daily job undoes the review.
    valid_until: str | None = None


def _scope_rules(db: Session, scope: str) -> list[Rule]:
    """The rules a scope covers - in force only.

    Draft, rejected and deactivated rules have nothing to recertify: they are
    not standing on any device with an approval behind them.
    """
    rules = active_rules(db).filter(Rule.status.in_(IN_FORCE))
    if scope == "all":
        return rules.all()
    kind, _sep, value = scope.partition(":")
    if kind == "zone" and value:
        needle = value.strip().upper()
        return [r for r in rules.all()
                if needle in ((r.source_zone or "").upper(), (r.destination_zone or "").upper())]
    if kind == "component" and value.isdigit():
        component = db.get(SecurityComponent, int(value))
        if not component:
            raise HTTPException(status.HTTP_404_NOT_FOUND, _("Component not found"))
        return [r for r in rules.all() if component in r.components]
    raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                        _("Unknown scope '{scope}' (use 'all', 'zone:<name>' or "
                          "'component:<id>')", scope=scope))


def _known_owners(db: Session) -> set[str]:
    """Every name an active user answers to, lowercased.

    rule.owner is free text, so the match is by username or full name. The
    point is the inverse: an owner matching nobody is a finding - rules whose
    owner has left the organisation surface here first, and until now nothing
    noticed them at all.
    """
    names: set[str] = set()
    for user in db.query(User).filter(User.is_active.is_(True)).all():
        names.add(user.username.lower())
        if user.full_name:
            names.add(user.full_name.lower())
    return names


def _item_out(item: RecertItem, known: set[str]) -> dict:
    rule = item.rule
    return {
        "item_id": item.id,
        "rule_id": rule.rule_id,
        "name": rule.name,
        "owner": item.owner,
        "owner_unknown": bool(item.owner) and item.owner.lower() not in known,
        "rule_status": rule.status.value,
        "valid_until": rule.valid_until,
        "decision": item.decision,
        "decided_by": item.decided_by,
        "decided_at": item.decided_at.isoformat() if item.decided_at else None,
        "comment": item.comment,
    }


def _campaign_out(campaign: RecertCampaign, db: Session, with_items: bool = False) -> dict:
    known = _known_owners(db)
    items = campaign.items
    open_items = [i for i in items if i.decision is None]
    out = {
        "id": campaign.id,
        "name": campaign.name,
        "scope": campaign.scope,
        "due_date": campaign.due_date,
        "created_by": campaign.created_by,
        "created_at": campaign.created_at.isoformat() if campaign.created_at else None,
        "closed_at": campaign.closed_at.isoformat() if campaign.closed_at else None,
        "closed_by": campaign.closed_by,
        "total": len(items),
        "open": len(open_items),
        "confirmed": sum(1 for i in items if i.decision == "confirmed"),
        "rework": sum(1 for i in items if i.decision == "rework"),
        "retired": sum(1 for i in items if i.decision == "retired"),
        "overdue": campaign.closed_at is None and campaign.due_date < date.today().isoformat(),
        # Owners who match no active user: their open rules will not be worked
        # on by anybody, and that is the first thing worth knowing.
        "owners_unknown": sorted({i.owner for i in open_items
                                  if i.owner and i.owner.lower() not in known}),
    }
    if with_items:
        out["items"] = [_item_out(i, known) for i in items]
    return out


@router.post("", status_code=201)
def create_campaign(
    payload: CampaignCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin, Role.change_approver)),
):
    """Starts a campaign over every rule the scope covers right now.

    Membership is fixed at creation. A worklist that grows and shrinks under
    the people working through it cannot be finished, only abandoned - a rule
    created after the campaign started belongs to the next campaign.
    """
    try:
        due = date.fromisoformat(payload.due_date.strip())
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("'{value}' is not a valid date (YYYY-MM-DD)",
                              value=payload.due_date)) from exc
    if due < date.today():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("The cut-off date must not lie in the past"))

    rules = _scope_rules(db, payload.scope)
    if not rules:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("The scope covers no rules in force - nothing to recertify"))

    campaign = RecertCampaign(name=payload.name.strip(), scope=payload.scope,
                              due_date=due.isoformat(), created_by=user.username)
    db.add(campaign)
    db.flush()
    for rule in rules:
        db.add(RecertItem(campaign_id=campaign.id, rule_pk=rule.id, owner=rule.owner or ""))

    audit.record(db, "admin", "recert.campaign_created", actor=user.username,
                 object=campaign.name,
                 detail="Recertification campaign over {count} rule(s), scope {scope}, due {due}",
                 detail_values={"count": len(rules), "scope": payload.scope,
                                "due": campaign.due_date},
                 source_ip=audit.client_ip(request))
    db.commit()
    db.refresh(campaign)
    return _campaign_out(campaign, db)


@router.get("")
def list_campaigns(db: Session = Depends(get_db),
                   user: User = Depends(require_roles(
                       Role.admin, Role.change_approver, Role.architect, Role.operations))):
    campaigns = db.query(RecertCampaign).order_by(RecertCampaign.created_at.desc()).all()
    return [_campaign_out(c, db) for c in campaigns]


@router.get("/{campaign_id}")
def campaign_detail(campaign_id: int, db: Session = Depends(get_db),
                    user: User = Depends(require_roles(
                        Role.admin, Role.change_approver, Role.architect, Role.operations))):
    campaign = db.get(RecertCampaign, campaign_id)
    if not campaign:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Campaign not found"))
    return _campaign_out(campaign, db, with_items=True)


def _get_open_item(db: Session, campaign_id: int, item_id: int) -> RecertItem:
    item = db.get(RecertItem, item_id)
    if not item or item.campaign_id != campaign_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Item not found"))
    if item.campaign.closed_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("The campaign is closed - its record does not change any more"))
    if item.decision is not None:
        # Refused rather than overwritten: who decided is the point of the record.
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Already decided by {user} ({decision})",
                              user=item.decided_by, decision=_(item.decision)))
    return item


def _decide_item(item: RecertItem, decision: str, user: User, comment: str) -> None:
    item.decision = decision
    item.decided_by = user.username
    item.decided_at = utcnow()
    item.comment = comment.strip()


@router.post("/{campaign_id}/items/{item_id}/confirm")
def confirm_item(
    campaign_id: int,
    item_id: int,
    payload: Decision,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations,
                                       Role.change_approver, Role.admin)),
):
    """Reviewed, still required - the act the whole feature exists to record."""
    item = _get_open_item(db, campaign_id, item_id)
    rule = item.rule
    if rule.status not in IN_FORCE or rule.deleted_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("The rule is no longer in force - there is nothing "
                              "to confirm (status '{status}')", status=_(rule.status.value)))

    new_until = None
    if payload.valid_until:
        try:
            new_until = date.fromisoformat(payload.valid_until.strip())
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                _("'{value}' is not a valid date (YYYY-MM-DD)",
                                  value=payload.valid_until)) from exc
        if new_until <= date.today():
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                _("The new valid-until date must be in the future"))

    _decide_item(item, "confirmed", user, payload.comment)
    rule.last_confirmed_at = item.decided_at
    rule.last_confirmed_by = user.username
    rule.version += 1
    if new_until is not None:
        rule.valid_until = new_until.isoformat()
        add_version(db, rule, user,
                    "Recertified in campaign '{campaign}': still required, "
                    "validity extended until {valid_until}",
                    campaign=item.campaign.name, valid_until=rule.valid_until)
    else:
        add_version(db, rule, user,
                    "Recertified in campaign '{campaign}': still required",
                    campaign=item.campaign.name)
    if payload.comment.strip():
        db.add(Comment(rule_pk=rule.id, author=user.username, text=payload.comment.strip()))

    audit.record(db, "rule", "rule.recert_confirmed", actor=user.username,
                 object=rule.rule_id,
                 detail="Campaign '{campaign}'", detail_values={"campaign": item.campaign.name},
                 source_ip=audit.client_ip(request))
    db.commit()
    return {"status": "confirmed", "rule_id": rule.rule_id}


@router.post("/{campaign_id}/items/{item_id}/rework")
def rework_item(
    campaign_id: int,
    item_id: int,
    payload: Decision,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations,
                                       Role.change_approver, Role.admin)),
):
    """Still needed, but wrong - back into review.

    This path is why the decision is not yes/no. A reviewer facing a rule that
    is almost right must not have to choose between waving it through and
    killing it; both produce the ruleset the review was supposed to prevent.
    """
    if len(payload.comment.strip()) < 5:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("Say what is wrong with the rule - the next reviewer "
                              "starts from this comment"))
    item = _get_open_item(db, campaign_id, item_id)
    rule = item.rule
    if rule.status not in IN_FORCE or rule.deleted_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("The rule is no longer in force - there is nothing "
                              "to confirm (status '{status}')", status=_(rule.status.value)))

    _decide_item(item, "rework", user, payload.comment)
    rule.status = RuleStatus.in_review
    rule.version += 1
    add_version(db, rule, user,
                "Recertification '{campaign}': still needed but wrong - back into "
                "review: {reason}",
                campaign=item.campaign.name, reason=item.comment)
    db.add(Comment(rule_pk=rule.id, author=user.username, text=item.comment))

    audit.record(db, "rule", "rule.recert_rework", actor=user.username,
                 object=rule.rule_id,
                 detail="Campaign '{campaign}': {reason}",
                 detail_values={"campaign": item.campaign.name, "reason": item.comment},
                 source_ip=audit.client_ip(request))
    db.commit()

    from .. import notifications
    notifications.rule_submitted(db, rule)
    return {"status": "rework", "rule_id": rule.rule_id}


@router.post("/{campaign_id}/items/{item_id}/retire")
def retire_item(
    campaign_id: int,
    item_id: int,
    payload: Decision,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations,
                                       Role.change_approver, Role.admin)),
):
    """No longer needed - deactivated, and operations is told to remove it."""
    if len(payload.comment.strip()) < 5:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("Say why the rule is no longer needed - retiring it "
                              "is a decision, and the reason is the evidence"))
    item = _get_open_item(db, campaign_id, item_id)
    rule = item.rule
    if rule.status not in IN_FORCE or rule.deleted_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("The rule is no longer in force - there is nothing "
                              "to confirm (status '{status}')", status=_(rule.status.value)))

    _decide_item(item, "retired", user, payload.comment)
    rule.status = RuleStatus.deactivated
    rule.impl_status = {
        **(rule.impl_status or {}),
        **{c.name: "to remove" for c in rule.components},
    }
    rule.version += 1
    add_version(db, rule, user,
                "Recertification '{campaign}': no longer required - deactivated: {reason}",
                campaign=item.campaign.name, reason=item.comment)
    db.add(Comment(rule_pk=rule.id, author=user.username, text=item.comment))

    audit.record(db, "rule", "rule.recert_retired", actor=user.username,
                 object=rule.rule_id,
                 detail="Campaign '{campaign}': {reason}",
                 detail_values={"campaign": item.campaign.name, "reason": item.comment},
                 source_ip=audit.client_ip(request))
    db.commit()

    from .. import notifications
    notifications.rule_implementation_pending(
        db, rule, render("Retired in recertification - remove the rule on the components",
                         None))
    return {"status": "retired", "rule_id": rule.rule_id}


@router.post("/{campaign_id}/close")
def close_campaign(
    campaign_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.admin, Role.change_approver)),
):
    """Closes the campaign as it stands - open items stay open, on the record.

    Deliberately no force-decision of the remainder: an undecided rule is a
    finding, and the report exists to show it. Closing with thirty open items
    says something true; auto-confirming them would say something false.
    """
    campaign = db.get(RecertCampaign, campaign_id)
    if not campaign:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Campaign not found"))
    if campaign.closed_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, _("The campaign is already closed"))
    campaign.closed_at = utcnow()
    campaign.closed_by = user.username
    open_count = sum(1 for i in campaign.items if i.decision is None)
    audit.record(db, "admin", "recert.campaign_closed", actor=user.username,
                 object=campaign.name,
                 detail="Closed with {open} of {total} item(s) still undecided",
                 detail_values={"open": open_count, "total": len(campaign.items)},
                 source_ip=audit.client_ip(request))
    db.commit()
    return _campaign_out(campaign, db)


@router.get("/{campaign_id}/report")
def campaign_report(
    campaign_id: int,
    format: str = "json",
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(
        Role.admin, Role.change_approver, Role.architect, Role.operations)),
):
    """Who confirmed what, when - and what is still outstanding.

    This is the deliverable. Everything else in this router exists so that this
    report can be produced without reconstructing it from memory during an
    audit. CSV because that is the format an auditor takes away.
    """
    campaign = db.get(RecertCampaign, campaign_id)
    if not campaign:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Campaign not found"))
    data = _campaign_out(campaign, db, with_items=True)

    if format != "csv":
        return data

    import csv
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";")
    from ..exporters.common import csv_safe

    writer.writerow(["campaign", "scope", "due_date", "rule_id", "rule_name", "owner",
                     "owner_unknown", "decision", "decided_by", "decided_at", "comment"])
    for item in data["items"]:
        # csv_safe on every cell: campaign name, rule name and comment are free
        # text, and this report is opened in a spreadsheet.
        writer.writerow([csv_safe(c) for c in
                         [campaign.name, campaign.scope, campaign.due_date,
                          item["rule_id"], item["name"], item["owner"],
                          "yes" if item["owner_unknown"] else "",
                          item["decision"] or "OUTSTANDING",
                          item["decided_by"], item["decided_at"] or "", item["comment"]]])
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(buffer.getvalue(), media_type="text/csv", headers={
        "Content-Disposition":
            f'attachment; filename="recertification-{campaign.id}.csv"'})
