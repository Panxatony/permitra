"""A conflict is two rules meeting at the same firewall, not two rules that
happen to share an address family.

The comparison rests on overlapping networks, and that carried an unstated
assumption: a network belongs to exactly one security zone, so two rules whose
addresses overlap are two rules on the same zone transition. It held for as long
as every rule named its addresses.

`any` is where it stops holding. Expanded to 0.0.0.0/0 it overlaps every address
there is, so an any-to-any rule was reported against rules on the far side of
the estate - a "duplicate" of a rule between two entirely different zones, which
is the kind of finding that teaches people to close the warning box unread.

These tests pin the zone pair as a precondition, and pin what must not be lost
with it: rules from before the zone administration existed have nothing but
their addresses, and they are exactly the data conflict detection was written
for.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

from app.conflicts import find_conflicts
from app.models import Rule, RuleAction


def rule(pk, rule_id, *, src_zone="Z100", dst_zone="Z200", source="10.0.0.0/24",
         destination="10.9.0.0/24", services=None, action=RuleAction.permit):
    r = Rule(rule_id=rule_id, source_zone=src_zone, destination_zone=dst_zone,
             source=[{"ip": source}], destination=[{"ip": destination}],
             services=services or [{"protocol": "TCP", "port": "443"}], action=action)
    r.id = pk
    return r


def kinds(subject, *others):
    return {w["other_rule_id"]: w["kind"] for w in find_conflicts(subject, list(others))}


# ---------- the zone pair is the precondition ----------

def test_two_rules_on_different_zone_transitions_are_not_in_conflict():
    """They are enforced on different policies, quite possibly on different
    firewalls. Whatever their addresses look like, neither can shadow the
    other."""
    subject = rule(1, "SR00001")
    elsewhere = rule(2, "SR00002", src_zone="Z300", dst_zone="Z400")

    assert kinds(subject, elsewhere) == {}


def test_an_any_to_any_rule_is_not_a_duplicate_of_every_other_any_to_any_rule():
    """The finding that started this: two ping baselines, one between clients
    and servers, one between monitoring and the databases. Both are `any` on
    both sides, so by address alone they are indistinguishable - and they have
    nothing to do with each other."""
    here = rule(1, "SR00104", source="any", destination="any",
                services=[{"protocol": "ICMP", "port": "ping"}])
    there = rule(2, "SR00105", src_zone="Z110", dst_zone="Z050",
                 source="any", destination="any",
                 services=[{"protocol": "ICMP", "port": "ping"}])

    assert kinds(here, there) == {}


def test_an_any_to_any_rule_does_not_swallow_unrelated_rules():
    """0.0.0.0/0 overlaps every address in the estate, so without the zone pair
    every specific rule anywhere became an "overlap"."""
    baseline = rule(1, "SR00104", source="any", destination="any",
                    services=[{"protocol": "ICMP", "port": "ping"}])
    far_away = rule(2, "SR00035", src_zone="Z110", dst_zone="Z130",
                    source="10.10.90.136", destination="10.10.96.100",
                    services=[{"protocol": "ICMP", "port": ""}])

    assert kinds(baseline, far_away) == {}


def test_on_the_same_transition_the_any_rule_still_covers_the_specific_one():
    """The other half: where the two rules do meet, an any-to-any rule genuinely
    does overlap a specific one, and saying so is the point of the check."""
    baseline = rule(1, "SR00104", source="any", destination="any",
                    services=[{"protocol": "ICMP", "port": "ping"}])
    specific = rule(2, "SR00052", source="10.10.80.223", destination="10.10.96.0/24",
                    services=[{"protocol": "ICMP", "port": ""}])

    assert kinds(baseline, specific) == {"SR00052": "overlap"}


# ---------- and what the precondition must not cost ----------

def test_rules_without_zones_are_still_compared():
    """Legacy rules imported from the Excel matrix carry no zones. Requiring a
    matching pair would silently exempt them - and they are the data this check
    exists for."""
    subject = rule(1, "SR00001", src_zone="", dst_zone="")
    other = rule(2, "SR00002", src_zone="", dst_zone="")

    assert kinds(subject, other) == {"SR00002": "duplicate"}


def test_one_rule_without_zones_is_compared_against_a_maintained_one():
    """Half-maintained data is the normal state during a migration, and it is
    where a duplicate is most likely to be hiding."""
    legacy = rule(1, "SR00001", src_zone="", dst_zone="")
    maintained = rule(2, "SR00002")

    assert kinds(legacy, maintained) == {"SR00002": "duplicate"}


def test_the_same_transition_still_finds_the_ordinary_conflicts():
    """The guard against over-correcting: on one zone pair, everything the check
    found before it must still find."""
    subject = rule(1, "SR00001")
    duplicate = rule(2, "SR00002")
    overlapping = rule(3, "SR00003", source="10.0.0.0/25")
    opposite = rule(4, "SR00004", action=RuleAction.deny)

    assert kinds(subject, duplicate, overlapping, opposite) == {
        "SR00002": "duplicate", "SR00003": "overlap", "SR00004": "shadowing"}


def test_the_zone_pair_is_directional():
    """Z100 → Z200 and Z200 → Z100 are two relations with their own matrix cells
    and their own approvals, so a rule on one does not shadow a rule on the
    other. Two ping baselines in opposite directions make the point: by address
    they are the same `any` on both sides, and they are still two rules that
    both have to exist for the ping to work either way."""
    outbound = rule(1, "SR00001", source="any", destination="any",
                    services=[{"protocol": "ICMP", "port": "ping"}])
    inbound = rule(2, "SR00002", src_zone="Z200", dst_zone="Z100",
                   source="any", destination="any",
                   services=[{"protocol": "ICMP", "port": "ping"}])

    assert kinds(outbound, inbound) == {}
