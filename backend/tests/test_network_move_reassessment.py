"""Reassessment after moving a network to another zone (audit finding H6).

Rules store source and destination zone as derived fields. When a network is
moved to a different zone, the zone relation of existing rules changes without
the rule itself having been touched: an intra-zone rule can silently turn into a
zone transition - and that was neither reassessed nor displayed.

Required business logic: after the move, all affected rules are reassessed. If
that turns allow into block, they go into review and are proposed for removal.
The approval then means approving the removal - the rule is deactivated and set
to "to remove" per component.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
    Zone,
    ZoneNetwork,
    ZonePolicy,
    ZonePolicyType,
)
from app.routers.zones_router import (
    _apply_reassessment,
    _preview_network_move,
    reassess_after_network_move,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-BER", type=ComponentType.juniper))
    s.add(SecurityComponent(id=2, name="ACI-FFM", type=ComponentType.aci))
    s.add(Zone(id=1, code="Z010", name="DEV", sort_order=10))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20))
    s.add(Zone(id=3, code="Z030", name="TEST", sort_order=30))
    # Both networks initially sit in DEV -> the rule is intra-zone
    s.add(ZoneNetwork(id=1, zone_id=1, vrf_id=1, cidr="10.0.1.0/24"))
    s.add(ZoneNetwork(id=2, zone_id=1, vrf_id=1, cidr="10.0.2.0/24"))
    s.commit()
    yield s
    s.close()


def set_policy(db, source: int, target: int, policy: ZonePolicyType):
    db.add(ZonePolicy(from_zone_id=source, to_zone_id=target, policy=policy))
    db.commit()


def make_rule(db, rule_id="SR00001", components=(1,), src="10.0.1.5", dst="10.0.2.7",
              status=RuleStatus.approved):
    comps = [db.get(SecurityComponent, c) for c in components]
    r = Rule(
        rule_id=rule_id, vrf_id=1, name=rule_id, components=comps,
        source=[{"ip": src, "alias": ""}], destination=[{"ip": dst, "alias": ""}],
        services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
        status=status, source_zone="Z010", destination_zone="Z010",
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def approver():
    """The approver who approved the network move."""
    return User(username="appr", role=Role.change_approver, is_active=True)


def second_approver():
    """Four-eyes principle: the removal is approved by someone other than the
    person who triggered the removal proposal through the move."""
    return User(username="appr2", role=Role.change_approver, is_active=True)


def move(db, network_id: int, target_zone_id: int):
    """Moves a network to another zone (as the approved change does)."""
    net = db.get(ZoneNetwork, network_id)
    net.zone_id = target_zone_id
    db.flush()
    return net


# ---------- Preview before the decision ----------

def test_preview_shows_consequences_without_changing_anything(db):
    """The approvers must know the consequences BEFORE they agree."""
    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)

    preview = _preview_network_move(db, db.get(ZoneNetwork, 2), db.get(Zone, 2), "10.0.2.0/24")

    assert len(preview) == 1
    entry = preview[0]
    assert entry["rule_id"] == "SR00001"
    assert entry["to_zones"] == ["Z010", "Z020"]
    assert entry["admissible"] is False
    # Nothing was touched
    db.refresh(rule)
    assert rule.destination_zone == "Z010" and rule.status == RuleStatus.approved
    assert db.get(ZoneNetwork, 2).zone_id == 1


def test_unrelated_rules_are_not_affected(db):
    make_rule(db, "SR00001")
    # Rule in a completely different network
    other = Rule(rule_id="SR00002", vrf_id=1, name="andere",
                 source=[{"ip": "192.168.5.5", "alias": ""}],
                 destination=[{"ip": "192.168.5.6", "alias": ""}],
                 services=[{"protocol": "TCP", "port": "443"}],
                 action=RuleAction.permit, status=RuleStatus.approved)
    db.add(other)
    db.commit()

    preview = _preview_network_move(db, db.get(ZoneNetwork, 2), db.get(Zone, 2), "10.0.2.0/24")
    assert {e["rule_id"] for e in preview} == {"SR00001"}


def test_wider_rule_network_is_not_touched(db):
    """A more broadly scoped rule network derives its zone from elsewhere."""
    db.add(ZoneNetwork(id=3, zone_id=1, vrf_id=1, cidr="10.0.0.0/16"))
    db.commit()
    make_rule(db, "SR00003", src="10.0.0.0/16", dst="10.0.0.0/16")

    preview = _preview_network_move(db, db.get(ZoneNetwork, 2), db.get(Zone, 2), "10.0.2.0/24")
    assert "SR00003" not in {e["rule_id"] for e in preview}


# ---------- Reassessment after the move ----------

def test_rule_becomes_inadmissible_and_is_proposed_for_removal(db):
    """The core: allow (intra-zone) turns into block because of the move."""
    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)

    net = move(db, 2, 2)                       # 10.0.2.0/24 to PROD
    recorded = _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)

    assert rule.status == RuleStatus.in_review, "the rule must go into review"
    assert rule.removal_reason, "the rule must be proposed for removal"
    assert rule.removal_reason.startswith("Z010 → Z020"), rule.removal_reason
    assert "Block" in rule.removal_reason
    assert rule.source_zone == "Z010" and rule.destination_zone == "Z020"
    assert recorded and recorded[0]["admissible"] is False


def test_still_allowed_rule_only_gets_its_zones_updated(db):
    """If the relation stays allowed, only the zones are updated - no review."""
    set_policy(db, 1, 2, ZonePolicyType.allow_only)
    rule = make_rule(db)

    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)

    assert rule.status == RuleStatus.approved
    assert rule.removal_reason == ""
    assert rule.destination_zone == "Z020", "the zones must be updated"


def test_cross_zone_without_firewall_is_inadmissible(db):
    """A zone transition via ACI alone is inadmissible per BSI - the pure matrix
    check does not catch this, so it has to bite here."""
    set_policy(db, 1, 2, ZonePolicyType.allow_only)
    rule = make_rule(db, components=(2,))      # ACI only

    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)

    assert rule.status == RuleStatus.in_review
    assert "firewall" in rule.removal_reason


def test_rule_side_spanning_two_zones_is_inadmissible(db):
    """After the move the destination side spans two zones - the rule has to be
    split and is not tenable in this form."""
    set_policy(db, 1, 2, ZonePolicyType.allow_only)
    rule = make_rule(db, dst="10.0.2.7")
    rule.destination = [{"ip": "10.0.1.9", "alias": ""}, {"ip": "10.0.2.7", "alias": ""}]
    db.commit()

    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)

    assert rule.status == RuleStatus.in_review
    assert "several zones" in rule.removal_reason


def test_history_and_comment_record_the_reason(db):
    """The operation must be traceable - version entry and comment."""
    from app.models import Comment, RuleVersion

    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)
    before = rule.version

    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)

    assert rule.version == before + 1
    version = db.query(RuleVersion).filter(RuleVersion.rule_pk == rule.id,
                                           RuleVersion.version == rule.version).one()
    assert "moved" in version.change_note
    comment = db.query(Comment).filter(Comment.rule_pk == rule.id).one()
    assert "abc12345" in comment.text


def test_draft_rules_are_reassessed_too(db):
    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db, status=RuleStatus.draft)

    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)
    assert rule.removal_reason and rule.status == RuleStatus.in_review


def test_deleted_rules_are_ignored(db):
    from app.models import utcnow

    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)
    rule.deleted_at = utcnow()
    db.commit()

    net = move(db, 2, 2)
    assert _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455") == []


# ---------- The review leads to removal ----------

def test_approving_a_proposed_rule_approves_its_removal(db):
    """For a rule proposed for removal, "approve" means: removal approved -
    deactivate it and roll it back on the components."""
    from app.routers.rules_router import _decide
    from app.schemas import ReviewDecision

    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)
    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()

    _decide(db, "SR00001", second_approver(), ReviewDecision(comment="geprüft"),
            RuleStatus.approved, "Freigabe")
    db.refresh(rule)

    assert rule.status == RuleStatus.deactivated
    assert rule.impl_status.get("FW-BER") == "to remove"
    assert rule.removal_reason == "", "the proposal has been decided"


def test_reworking_the_rule_clears_the_proposal(db):
    """If the rule is reworked and passes the checks, the removal proposal
    becomes moot."""
    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)
    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    assert rule.removal_reason

    # Move the network back to DEV and reassess
    move(db, 2, 1)
    _apply_reassessment(db, db.get(ZoneNetwork, 2), approver(), "def67890-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)
    assert rule.removal_reason == ""
    assert rule.destination_zone == "Z010"


def test_reassessment_is_idempotent(db):
    """A second run without any change must not touch anything further."""
    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)
    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    state = rule.version

    second_run = reassess_after_network_move(db, net)
    assert all(not e["zones_changed"] for e in second_run)
    db.refresh(rule)
    assert rule.version == state


# ---------- Wiring: does the reassessment really run on approval? ----------

def test_reassessment_runs_through_the_real_approval_flow(db):
    """The most important test: the reassessment must be triggered by the real
    approval flow, not merely exist as a function. Without this test the whole
    file would still pass even if the wiring were missing."""
    from app.models import ZonePolicyChange
    from app.routers.zones_router import _create_batch, _decide_change

    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)

    architect = User(username="alex", role=Role.architect, is_active=True)
    _create_batch(db, architect, [{
        "type": "net_update", "network_id": 2,
        "cidr": "10.0.2.0/24", "zone": "PROD",
    }], "Netz wandert nach PROD")
    change = db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()

    _decide_change(db, change.id, approver(), True, "")
    db.refresh(rule)
    assert rule.status == RuleStatus.approved, "nothing may happen before the second approval"

    result = _decide_change(db, change.id, second_approver(), True, "")
    db.refresh(rule)

    assert db.get(ZoneNetwork, 2).zone_id == 2, "the move was applied"
    assert rule.status == RuleStatus.in_review
    assert rule.removal_reason
    assert "for removal" in (result.get("detail") or ""), result
    assert any(e["rule_id"] == "SR00001" and not e["admissible"]
               for e in result.get("reassessed", []))


def test_preview_is_offered_on_the_pending_request(db):
    """The impact analysis has to be attached to the pending request so that the
    approvers see it - not only after the decision."""
    from app.routers.zones_router import _create_batch, list_changes

    set_policy(db, 1, 2, ZonePolicyType.block_all)
    make_rule(db)
    architect = User(username="alex", role=Role.architect, is_active=True)
    _create_batch(db, architect, [{
        "type": "net_update", "network_id": 2,
        "cidr": "10.0.2.0/24", "zone": "PROD",
    }], "")

    entries = list_changes(db=db, _=approver())
    pending = next(e for e in entries if e["status"] == "pending")
    assert pending["affected_count"] == 1
    assert pending["removal_count"] == 1
    assert pending["affected_rules"][0]["rule_id"] == "SR00001"
    assert pending["affected_rules"][0]["admissible"] is False
    # and the request has not been applied yet
    assert db.get(ZoneNetwork, 2).zone_id == 1
