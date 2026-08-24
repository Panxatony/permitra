"""Recertification as a decision about a rule, not a calendar (#35).

Permitra deactivated rules when their valid_until passed. That is expiry
control; BSI NET.3.2 asks that the ruleset is *reviewed* - is each rule still
needed, still scoped correctly, still owned by someone who exists - and the gap
was that nobody was ever asked.

These tests pin what makes the campaign a record rather than a checkbox: every
decision names who made it and survives unchanged, the report says what is
outstanding instead of hiding it, a requestor who matches no active user is a
finding, and the auditor's question - when did somebody last deliberately
confirm this rule? - is answerable on the rule itself.
"""
import os
from datetime import date, timedelta

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    ComponentType,
    RecertItem,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
)
from app.routers.recert_router import (
    CampaignCreate,
    Decision,
    campaign_detail,
    campaign_report,
    close_campaign,
    confirm_item,
    create_campaign,
    list_campaigns,
    retire_item,
    rework_item,
)

TOMORROW = (date.today() + timedelta(days=30)).isoformat()


class Req:
    headers: dict = {}  # noqa: RUF012

    class client:
        host = "203.0.113.9"


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-BER", type=ComponentType.juniper))
    s.add(User(username="anna", full_name="Anna Admin", password_hash="x",
               role=Role.admin, is_active=True))
    s.add(User(username="ben", full_name="Ben Betrieb", password_hash="x",
               role=Role.operations, is_active=True))
    s.add(User(username="clara", full_name="Clara Approver", password_hash="x",
               role=Role.change_approver, is_active=True))
    s.commit()
    yield s
    s.close()


def admin(db):
    return db.query(User).filter(User.username == "anna").one()


def ops(db):
    return db.query(User).filter(User.username == "ben").one()


def approver(db):
    return db.query(User).filter(User.username == "clara").one()


def make_rule(db, rule_id, *, status=RuleStatus.approved, requestor="ben",
              src_zone="Z010", dst_zone="Z020"):
    rule = Rule(rule_id=rule_id, vrf_id=1, name=rule_id.lower(), requestor=requestor,
                components=[db.get(SecurityComponent, 1)],
                source=[{"ip": "10.0.0.1", "alias": ""}],
                destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}],
                action=RuleAction.permit, status=status,
                source_zone=src_zone, destination_zone=dst_zone,
                valid_until="2027-06-30")
    db.add(rule)
    db.commit()
    return rule


def campaign(db, scope="all", name="Q3 review"):
    return create_campaign(CampaignCreate(name=name, due_date=TOMORROW, scope=scope),
                           Req(), db, approver(db))


def item_of(db, rule):
    return db.query(RecertItem).filter(RecertItem.rule_pk == rule.id).one()


# ---------- the campaign covers what it says ----------

def test_only_rules_in_force_are_asked_about(db):
    """A draft or deactivated rule stands on no device with an approval behind
    it - there is nothing to recertify."""
    make_rule(db, "SR00001", status=RuleStatus.approved)
    make_rule(db, "SR00002", status=RuleStatus.active)
    make_rule(db, "SR00003", status=RuleStatus.draft)
    make_rule(db, "SR00004", status=RuleStatus.deactivated)

    assert campaign(db)["total"] == 2


def test_a_zone_scope_covers_both_directions(db):
    """A rule out of the zone is as much its business as one into it."""
    make_rule(db, "SR00001", src_zone="Z040", dst_zone="Z020")
    make_rule(db, "SR00002", src_zone="Z010", dst_zone="Z040")
    make_rule(db, "SR00003", src_zone="Z010", dst_zone="Z020")

    assert campaign(db, scope="zone:Z040")["total"] == 2


def test_membership_is_fixed_at_creation(db):
    """A worklist that grows under the people working through it cannot be
    finished, only abandoned. A rule created later belongs to the next
    campaign."""
    make_rule(db, "SR00001")
    result = campaign(db)
    make_rule(db, "SR00002")

    assert campaign_detail(result["id"], db, admin(db))["total"] == 1


def test_an_empty_scope_is_refused_not_recorded(db):
    """A campaign over nothing would close at 100 percent and read as evidence
    of a review that never happened."""
    make_rule(db, "SR00001", status=RuleStatus.draft)
    with pytest.raises(HTTPException) as exc:
        campaign(db)
    assert exc.value.status_code == 422


# The change-approver-only gate on starting and closing a campaign is enforced by
# require_roles, a FastAPI dependency that direct function calls here never run.
# It is tested at the HTTP layer in test_http_authorization.py instead.


# ---------- the three decisions ----------

def test_confirming_answers_the_auditors_question_on_the_rule(db):
    """"When did somebody last deliberately confirm that this rule is still
    needed?" - on the rule, not through a join."""
    rule = make_rule(db, "SR00001")
    c = campaign(db)
    confirm_item(c["id"], item_of(db, rule).id, Decision(), Req(), db, ops(db))
    db.refresh(rule)

    assert rule.last_confirmed_by == "ben"
    assert rule.last_confirmed_at is not None
    assert rule.status == RuleStatus.approved   # confirming changes no status


def test_confirming_may_carry_a_new_expiry_in_the_same_act(db):
    """"Still required" on a rule expiring next week is otherwise undone by the
    daily job - the confirmation is the decision, the date its consequence."""
    rule = make_rule(db, "SR00001")
    c = campaign(db)
    until = (date.today() + timedelta(days=365)).isoformat()
    confirm_item(c["id"], item_of(db, rule).id, Decision(valid_until=until),
                 Req(), db, ops(db))
    db.refresh(rule)

    assert rule.valid_until == until


def test_rework_sends_the_rule_back_into_review(db):
    """The middle path, and the reason the decision is not yes/no: a reviewer
    facing an almost-right rule must not have to wave it through or kill it."""
    rule = make_rule(db, "SR00001")
    c = campaign(db)
    rework_item(c["id"], item_of(db, rule).id,
                Decision(comment="Destination is far too broad for one application"),
                Req(), db, ops(db))
    db.refresh(rule)

    assert rule.status == RuleStatus.in_review


def test_rework_without_a_reason_is_refused(db):
    """The next reviewer starts from this comment; an empty one hands them a
    rule in review and no idea why."""
    rule = make_rule(db, "SR00001")
    c = campaign(db)
    with pytest.raises(HTTPException) as exc:
        rework_item(c["id"], item_of(db, rule).id, Decision(comment="ok"),
                    Req(), db, ops(db))
    assert exc.value.status_code == 422
    db.refresh(rule)
    assert rule.status == RuleStatus.approved   # nothing half-happened


def test_retiring_deactivates_and_tells_operations(db):
    rule = make_rule(db, "SR00001")
    c = campaign(db)
    retire_item(c["id"], item_of(db, rule).id,
                Decision(comment="Application was decommissioned in June"),
                Req(), db, ops(db))
    db.refresh(rule)

    assert rule.status == RuleStatus.deactivated
    assert rule.impl_status["FW-BER"] == "to remove"


# ---------- the record does not bend ----------

def test_a_decision_is_refused_not_overwritten(db):
    """Who decided is the point of the record. The second decision names the
    first decider instead of replacing them."""
    rule = make_rule(db, "SR00001")
    c = campaign(db)
    confirm_item(c["id"], item_of(db, rule).id, Decision(), Req(), db, ops(db))

    with pytest.raises(HTTPException) as exc:
        confirm_item(c["id"], item_of(db, rule).id, Decision(), Req(), db, admin(db))
    assert exc.value.status_code == 409
    assert "ben" in exc.value.detail


def test_a_rule_decided_elsewhere_cannot_be_confirmed(db):
    """Deactivated mid-campaign through the normal workflow: confirming it now
    would record a review of a rule that no longer stands."""
    rule = make_rule(db, "SR00001")
    c = campaign(db)
    rule.status = RuleStatus.deactivated
    db.commit()

    with pytest.raises(HTTPException) as exc:
        confirm_item(c["id"], item_of(db, rule).id, Decision(), Req(), db, ops(db))
    assert exc.value.status_code == 409


def test_a_closed_campaign_takes_no_more_decisions(db):
    """Closed means the record stands. Decisions after the fact belong to the
    next campaign, not retro-fitted into this one's report."""
    rule = make_rule(db, "SR00001")
    c = campaign(db)
    close_campaign(c["id"], Req(), db, approver(db))

    with pytest.raises(HTTPException) as exc:
        confirm_item(c["id"], item_of(db, rule).id, Decision(), Req(), db, ops(db))
    assert exc.value.status_code == 409


def test_closing_keeps_open_items_open(db):
    """An undecided rule is a finding. Closing with thirty open items says
    something true; auto-confirming them would say something false."""
    make_rule(db, "SR00001")
    make_rule(db, "SR00002")
    c = campaign(db)
    confirm_item(c["id"], item_of(db, db.query(Rule).first()).id,
                 Decision(), Req(), db, ops(db))

    closed = close_campaign(c["id"], Req(), db, admin(db))
    assert closed["open"] == 1
    assert closed["confirmed"] == 1


# ---------- the report, which is the deliverable ----------

def test_the_report_marks_the_outstanding_not_just_the_done(db):
    rule_a = make_rule(db, "SR00001")
    make_rule(db, "SR00002")
    c = campaign(db)
    confirm_item(c["id"], item_of(db, rule_a).id, Decision(), Req(), db, ops(db))

    csv_text = campaign_report(c["id"], "csv", db, admin(db)).body.decode()
    assert "OUTSTANDING" in csv_text
    assert "confirmed" in csv_text


def test_a_requestor_who_matches_no_active_user_is_a_finding(db):
    """A rule whose requester has left the organisation is one nobody can be
    asked to recertify - this is where that first surfaces."""
    make_rule(db, "SR00001", requestor="gerd-gegangen")
    make_rule(db, "SR00002", requestor="ben")

    result = campaign(db)
    assert result["requestors_unknown"] == ["gerd-gegangen"]


def test_a_deactivated_user_does_not_count_as_present(db):
    """Deactivated is left, as far as open work is concerned."""
    user = ops(db)
    user.is_active = False
    db.commit()
    make_rule(db, "SR00001", requestor="ben")

    assert campaign(db)["requestors_unknown"] == ["ben"]


def test_the_requestor_on_the_item_is_a_snapshot(db):
    """Reassigning a rule mid-campaign must not silently move open work."""
    rule = make_rule(db, "SR00001", requestor="ben")
    c = campaign(db)
    rule.requestor = "anna"
    db.commit()

    detail = campaign_detail(c["id"], db, admin(db))
    assert detail["items"][0]["requestor"] == "ben"


def test_a_campaign_past_its_cutoff_reports_overdue(db):
    from app.models import RecertCampaign

    make_rule(db, "SR00001")
    c = campaign(db)
    db.get(RecertCampaign, c["id"]).due_date = (date.today() - timedelta(days=1)).isoformat()
    db.commit()

    assert list_campaigns(db, admin(db))[0]["overdue"] is True
