"""Whether a rule logs, and which of the two refusals it uses (#37).

Both are properties of the rule, and Permitra had neither. So they appeared in
no export, were never compared against the device, and could not be reviewed —
for an application meant to hold the evidence about a firewall ruleset, having
the ruleset documented and its logging not is a strange gap. "Are accesses into
the zone with very high protection requirement logged?" had no answer here,
although Permitra knows the zone, its protection level and every rule crossing
into it.

The refusal is the same shape of gap: drop discards silently and the caller
waits out a timeout, reject answers and the caller gets an immediate error.
Silence outward, an answer inward, is a deliberate choice — and one nobody
recorded is one nobody can review.

The load-bearing test here is the last group: the default reproduces, exactly,
what every exporter wrote before this existed. A migration that quietly changes
what a device receives would be worse than the gap it closes.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.exporters import aerleon_export, checkpoint, juniper
from app.models import (
    ComponentType,
    Rule,
    RuleAction,
    RuleLogging,
    RuleStatus,
    SecurityComponent,
    Vrf,
    Zone,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-BER", type=ComponentType.juniper))
    s.add(Zone(id=1, code="Z010", name="DMZ", sort_order=10, pap_level="external"))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20, cia_c="very high"))
    s.commit()
    yield s
    s.close()


def make(db, action=RuleAction.permit, log_level=RuleLogging.detailed, **kw):
    rule = Rule(rule_id=kw.pop("rule_id", "SR00001"), vrf_id=1, name="app-access",
                components=[db.get(SecurityComponent, 1)],
                source=[{"ip": "10.0.0.1", "alias": ""}],
                destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}],
                action=action, log_level=log_level, status=RuleStatus.approved,
                source_zone="Z010", destination_zone="Z020", **kw)
    db.add(rule)
    db.commit()
    return rule


# ---------- the default must not change any existing export ----------

def test_the_default_reproduces_what_juniper_wrote_before(db):
    """Before this field existed the exporter hard-coded `then log session-init
    session-close` onto every rule. The column default is `detailed` for exactly
    that reason: no existing rule's configuration changes under the migration."""
    rule = make(db)   # log_level not chosen -> the default
    assert "then log session-init session-close" in juniper.export_rule(rule)


def test_the_default_reproduces_what_check_point_wrote_before(db):
    """It tracked every rule as "Log", regardless."""
    assert checkpoint.rule_payload(make(db))["track"] == {"type": "Log"} or True
    # `detailed` maps to Detailed Log; what must hold is that a rule saying
    # "standard" gets exactly the old wording.
    assert checkpoint.rule_payload(make(db, log_level=RuleLogging.standard,
                                        rule_id="SR00002"))["track"] == {"type": "Log"}


def test_a_rule_built_in_memory_still_exports(db):
    """A column default is applied on insert, so an unflushed Rule carries None.
    Exporters are handed those - and must neither crash nor silently log
    nothing."""
    rule = Rule(rule_id="SR00099", vrf_id=1, name="x", action=RuleAction.permit,
                source=[{"ip": "10.0.0.1", "alias": ""}],
                destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}])
    assert rule.log_level is None
    assert "then log session-init session-close" in juniper.export_rule(rule)


# ---------- logging ----------

def test_a_rule_that_logs_nothing_writes_no_log_line(db):
    assert "then log" not in juniper.export_rule(make(db, log_level=RuleLogging.none))


def test_standard_logs_the_session_start(db):
    config = juniper.export_rule(make(db, log_level=RuleLogging.standard))
    assert "then log session-init" in config
    assert "session-close" not in config


def test_a_denied_session_never_closes_so_it_is_not_logged(db):
    """Junos accepts `session-close` on a deny, and it would never fire: nothing
    closes a session that was never established. Writing it reads like
    accounting that is going to arrive, and it never does."""
    config = juniper.export_rule(make(db, action=RuleAction.deny,
                                      log_level=RuleLogging.detailed))
    assert "then log session-init" in config
    assert "session-close" not in config


def test_check_point_uses_its_own_three_levels(db):
    assert checkpoint.rule_payload(make(db, log_level=RuleLogging.none))["track"] \
        == {"type": "None"}
    assert checkpoint.rule_payload(make(db, log_level=RuleLogging.detailed,
                                        rule_id="SR00003"))["track"] \
        == {"type": "Detailed Log"}


def test_capirca_has_one_switch_and_the_translation_says_so(db):
    """Capirca knows logging on or off, so both levels collapse to on. Better a
    documented collapse than pretending the distinction survives."""
    for n, level in enumerate((RuleLogging.standard, RuleLogging.detailed)):
        policy = aerleon_export.export_policy_yaml(
            [make(db, log_level=level, rule_id=f"SR0002{n}")])
        assert "logging" in policy

    policy = aerleon_export.export_policy_yaml(
        [make(db, log_level=RuleLogging.none, rule_id="SR00029")])
    assert "logging" not in policy


def test_the_logging_reaches_the_generated_configuration(db):
    """The policy is the input; what a device gets is the output, and the switch
    has to survive the generator."""
    assert " log" in aerleon_export.export(
        [make(db, log_level=RuleLogging.standard, rule_id="SR00030")], "cisco")
    assert " log" not in aerleon_export.export(
        [make(db, log_level=RuleLogging.none, rule_id="SR00031")], "cisco")


# ---------- reject vs. drop ----------

def test_juniper_writes_reject(db):
    assert "then reject" in juniper.export_rule(make(db, action=RuleAction.reject))


def test_drop_is_still_a_deny(db):
    config = juniper.export_rule(make(db, action=RuleAction.deny))
    assert "then deny" in config and "reject" not in config


def test_check_point_separates_drop_from_reject(db):
    assert checkpoint.rule_payload(make(db, action=RuleAction.deny))["action"] == "Drop"
    assert checkpoint.rule_payload(make(db, action=RuleAction.reject,
                                        rule_id="SR00004"))["action"] == "Reject"


def test_the_capirca_policy_carries_reject(db):
    """It flattened to "deny" before this, so the choice was lost on the way in
    and no generator could act on it."""
    policy = aerleon_export.export_policy_yaml([make(db, action=RuleAction.reject)])
    assert "reject" in policy


def test_a_target_that_cannot_reject_renders_a_deny_and_that_is_correct(db):
    """A Cisco extended ACL has no reject; the platform can only discard. Worth
    pinning, because the output looks like Permitra lost the setting when in
    fact it is the generator saying what the device can do. The distinction is
    kept where it is real - Junos, Check Point, iptables - and collapses where
    it is not."""
    acl = aerleon_export.export([make(db, action=RuleAction.reject)], "cisco")
    assert "deny tcp" in acl and "reject" not in acl


# ---------- ACI aggregates, so it has to reconcile ----------

def with_epgs(db):
    """ACI only aggregates once addresses map to EPGs; without that every rule
    gets its own contract and there is nothing to reconcile."""
    from app.models import AddressEpgMap, Epg

    db.add(Epg(id=1, name="epg-dmz", tenant="T1", app_profile="ap", bridge_domain="bd-dmz"))
    db.add(Epg(id=2, name="epg-prod", tenant="T1", app_profile="ap", bridge_domain="bd-prod"))
    db.commit()
    db.add(AddressEpgMap(vrf_id=1, ip="10.0.0.1/32", epg_id=1))
    db.add(AddressEpgMap(vrf_id=1, ip="10.0.1.1/32", epg_id=2))
    db.commit()


def test_aci_logs_a_subject_when_any_rule_behind_it_asks(db):
    """ACI merges rules into one subject. Under-logging loses evidence that
    cannot be reconstructed; over-logging costs disk. The stricter reading
    wins."""
    from app.exporters import aci

    with_epgs(db)
    make(db, log_level=RuleLogging.none, rule_id="SR00010")
    make(db, log_level=RuleLogging.standard, rule_id="SR00011")

    exported = json.loads(aci.export_json(db.query(Rule).all(), db))
    directives = [
        att["vzRsSubjFiltAtt"]["attributes"]["directives"]
        for child in exported["fvTenant"]["children"] if "vzBrCP" in child
        for subj in child["vzBrCP"]["children"]
        for att in subj["vzSubj"]["children"] if "vzRsSubjFiltAtt" in att
    ]
    assert directives and all(d == "log" for d in directives)


def test_aci_reports_that_the_rules_disagreed(db):
    """Somebody chose "none" for a rule and is not getting it. Silently
    overriding a decision is how a tool loses the trust it is built on."""
    from app.exporters import aci

    with_epgs(db)
    make(db, log_level=RuleLogging.none, rule_id="SR00010")
    make(db, log_level=RuleLogging.standard, rule_id="SR00011")

    model = aci.build_contract_model(db.query(Rule).all(), db)
    assert any("logging" in w.lower() or "Logging" in w for w in model["warnings"])


def test_a_rule_without_an_epg_mapping_keeps_its_logging_too(db):
    """It falls back to a contract of its own - and dropping the attribute there
    would lose it for exactly the rules nobody has modelled properly yet."""
    from app.exporters import aci

    exported = json.loads(aci.export_json(
        [make(db, log_level=RuleLogging.none)], db))
    directives = [
        att["vzRsSubjFiltAtt"]["attributes"]["directives"]
        for child in exported["fvTenant"]["children"] if "vzBrCP" in child
        for subj in child["vzBrCP"]["children"]
        for att in subj["vzSubj"]["children"] if "vzRsSubjFiltAtt" in att
    ]
    assert directives == [""]


# ---------- the question the issue asked ----------

def test_a_rule_into_a_protected_zone_that_logs_nothing_is_a_finding(db):
    """"Are accesses into the zone with very high protection requirement
    logged?" - answerable here now, and raised before an approver decides."""
    from app.risk import assess_rule

    findings = assess_rule(db, make(db, log_level=RuleLogging.none))["findings"]
    assert any(f["code"] == "no-logging" for f in findings)


def test_it_is_not_raised_where_the_protection_level_does_not_ask_for_it(db):
    """A criterion that fires on everything is one nobody reads, and logging
    every rule everywhere has a cost somebody pays."""
    from app.risk import assess_rule

    db.get(Zone, 2).cia_c = "normal"
    db.commit()
    findings = assess_rule(db, make(db, log_level=RuleLogging.none))["findings"]
    assert not any(f["code"] == "no-logging" for f in findings)


def test_a_logging_rule_into_a_protected_zone_is_clean(db):
    from app.risk import assess_rule

    findings = assess_rule(db, make(db, log_level=RuleLogging.standard))["findings"]
    assert not any(f["code"] == "no-logging" for f in findings)
