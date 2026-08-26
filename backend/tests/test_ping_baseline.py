"""The one broad rule operations may have, and the fence around it.

Permitra's whole argument is that a rule names what it permits. A ping baseline
does not: it is any-to-any, deliberately, so that when a system stops answering
somebody can tell "the network does not reach it" from "the service is down"
without raising a change to find out. That is worth granting - and worth
granting narrowly, because an exemption that anybody can claim is not an
exemption, it is a hole with a checkbox in front of it.

So these tests come in two halves. The exception has to *work*: it can be
created without addresses to derive a zone from, it finds the firewalls between
the two zones on its own, and the risk assessment stops calling it too broad,
because a criterion that fires on every rule of a kind is one reviewers learn to
scroll past. And it has to *hold*: not across the P-A-P boundary, not on a
relation the matrix has not already allowed, not carrying anything but echo, and
not on a device where the export would quietly permit every ICMP type there is.
"""
import os
from types import SimpleNamespace

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import ping_baseline, risk
from app.database import Base
from app.exporters import juniper
from app.models import (
    ComponentLink,
    ComponentType,
    Role,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
    Zone,
    ZoneNetwork,
    ZonePolicy,
)
from app.routers.rules_router import _create_rule, _decide
from app.schemas import ReviewDecision, RuleCreate

# Z100 and Z110 are both internal and the matrix allows Z100 -> Z110. Z900 sits
# in the P-A-P layer, which is where the exception stops.
INTERNAL_A, INTERNAL_B, PAP = "Z100", "Z110", "Z900"


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    for i, name in ((1, "FW-A"), (2, "FW-CORE"), (3, "FW-B")):
        s.add(SecurityComponent(id=i, name=name, type=ComponentType.juniper))
    s.commit()
    zones = {
        1: Zone(id=1, code=INTERNAL_A, name="CLIENTS", pap_level="internal"),
        2: Zone(id=2, code=INTERNAL_B, name="SERVERS", pap_level="internal"),
        3: Zone(id=3, code=PAP, name="DMZ", pap_level="pap"),
    }
    for zone in zones.values():
        s.add(zone)
    s.commit()
    # Attached to: each zone is reachable through the firewall in front of it.
    zones[1].components = [s.get(SecurityComponent, 1)]
    zones[2].components = [s.get(SecurityComponent, 3)]
    zones[3].components = [s.get(SecurityComponent, 3)]
    s.add(ZoneNetwork(cidr="10.100.0.0/24", zone_id=1, vrf_id=1))
    s.add(ZoneNetwork(cidr="10.110.0.0/24", zone_id=2, vrf_id=1))
    s.add(ZonePolicy(from_zone_id=1, to_zone_id=2, policy="allow_only"))
    s.add(ZonePolicy(from_zone_id=1, to_zone_id=3, policy="allow_only"))
    s.add(ZonePolicy(from_zone_id=2, to_zone_id=1, policy="block_all"))
    s.commit()
    yield s
    s.close()


def architect(db, username="planer"):
    user = User(username=username, password_hash="x", role=Role.architect, is_active=True)
    db.add(user)
    db.commit()
    return user


def payload(**over):
    data = {
        "name": "ping-clients-servers",
        "source_zone": INTERNAL_A,
        "destination_zone": INTERNAL_B,
        "source": [{"ip": "any", "alias": ""}],
        "destination": [{"ip": "any", "alias": ""}],
        "services": [{"protocol": "ICMP", "port": ""}],
        "ping_baseline": True,
        "justification": "Operations has to be able to prove reachability",
        "valid_until": "2027-06-30",
    }
    data.update(over)
    return RuleCreate(**data)


def create(db, user=None, **over):
    rule = _create_rule(db, payload(**over), user or architect(db))
    db.commit()
    db.refresh(rule)
    return rule


# ---------- it has to work ----------

def test_a_baseline_can_be_created_although_it_has_no_address_to_place(db):
    """The headline. Every other rule derives its zones from its addresses, and
    this one has none - `any` belongs to no network. The two zones it names are
    what it is, so they have to be enough."""
    rule = create(db)

    assert rule.ping_baseline is True
    assert (rule.source_zone, rule.destination_zone) == (INTERNAL_A, INTERNAL_B)
    assert rule.status == RuleStatus.draft


def test_the_services_are_written_down_as_echo_not_as_icmp(db):
    """"ICMP" and "ICMP echo" are different permissions on every platform here.
    Left as the first, the export would grant redirects and timestamps that
    nobody asked for, and the rule would document something else than the
    device does."""
    assert create(db).services == [{"protocol": "ICMP", "port": "ping"}]


def test_the_export_permits_the_ping_and_not_every_icmp_type(db):
    """Where the previous test's point becomes a line in a configuration."""
    out = juniper.export_rule(create(db))

    assert "junos-ping" in out
    assert "junos-icmp-all" not in out


def test_the_firewalls_come_from_the_topology_between_the_two_zones(db):
    """A transit cluster nobody listed is still crossed by the ping.

    The zones are attached to FW-A and FW-B; FW-CORE sits between them and is on
    no zone at all. An address-based rule would find it through the address
    mapping - a baseline has no addresses, so the routing has to answer, the
    same routing the path analysis uses.
    """
    db.add(ComponentLink(component_a_id=1, component_b_id=2, link_type="OSPF"))
    db.add(ComponentLink(component_a_id=2, component_b_id=3, link_type="OSPF"))
    db.commit()

    assert sorted(c.name for c in create(db).components) == ["FW-A", "FW-B", "FW-CORE"]


def test_without_a_documented_topology_the_two_zones_answer(db):
    """An estate that never filled in its links must still be able to have one.
    What it gets is what it knows: the clusters the zones hang off."""
    assert sorted(c.name for c in create(db).components) == ["FW-A", "FW-B"]


def test_the_risk_assessment_names_it_instead_of_calling_it_too_broad(db):
    """any-to-any is what an approver granted here, on stated conditions. Filing
    it as "the rule is too broad" says the assessment does not know what was
    decided - and a finding that fires on every rule of a kind is one reviewers
    learn to skip, which costs the findings beside it their weight."""
    result = risk.assess_rule(db, create(db))
    codes = {f["code"] for f in result["findings"]}

    assert "any-to-any" not in codes
    assert "ping-baseline" in codes
    assert result["level"] == "low"


def test_an_ordinary_any_to_any_rule_is_still_too_broad(db):
    """The mutation guard for the test above: the exemption has to hang on the
    declaration, not on the shape. Otherwise every any-to-any rule quietly
    inherits it."""
    rule = create(db)
    rule.ping_baseline = False
    rule.services = [{"protocol": "TCP", "port": "443"}]

    codes = {f["code"] for f in risk.assess_rule(db, rule)["findings"]}
    assert "any-to-any" in codes


# ---------- and it has to hold ----------

def test_not_towards_the_pap_layer(db):
    """Out there an echo answer tells an attacker exactly what it tells
    operations: that something is alive at this address. Inside, where the
    matrix already allows the relation, that is a fact the attacker would have
    anyway; across the boundary it is the first thing reconnaissance asks."""
    with pytest.raises(HTTPException) as exc:
        create(db, destination_zone=PAP)
    assert "internal" in exc.value.detail


def test_not_on_a_relation_the_matrix_has_not_allowed(db):
    """The baseline rides on a permitted relation - it does not create one.
    Z110 -> Z100 is Block, and a ping is still communication."""
    with pytest.raises(HTTPException) as exc:
        create(db, source_zone=INTERNAL_B, destination_zone=INTERNAL_A)
    # The baseline check has to be the one refusing, not the general matrix
    # enforcement further down - otherwise the exemption is only as narrow as
    # the rules everybody already had.
    assert exc.value.detail.startswith("Ping baseline")
    assert "matrix" in exc.value.detail.lower()


def test_an_unmaintained_relation_is_not_an_allowed_one(db):
    """Nothing is recorded for Z100 -> itself... nor for these two. Elsewhere
    Permitra tolerates an unmaintained cell as a warning; an exemption granted
    on the strength of the matrix cannot, or it is granted on nothing."""
    db.add(Zone(id=4, code="Z120", name="BACKUP", pap_level="internal"))
    db.commit()
    db.get(Zone, 4).components = [db.get(SecurityComponent, 3)]
    db.commit()

    with pytest.raises(HTTPException) as exc:
        create(db, destination_zone="Z120")
    assert exc.value.detail.startswith("Ping baseline")
    assert "matrix" in exc.value.detail.lower()


def test_not_carrying_anything_besides_echo(db):
    """SSH between all clients and all servers is a different request, and one
    somebody has to justify address by address."""
    with pytest.raises(ValidationError) as exc:
        payload(services=[{"protocol": "TCP", "port": "22"}])
    assert "echo" in str(exc.value)


def test_not_carrying_every_icmp_type_under_the_name_of_ping(db):
    """An explicit port that is not echo is somebody asking for something else,
    so it is refused rather than quietly rewritten into what was declared."""
    with pytest.raises(ValidationError):
        payload(services=[{"protocol": "ICMP", "port": "any"}])


def test_not_with_addresses_that_make_it_an_ordinary_rule(db):
    """Named addresses need no exception - and a rule that claims one while
    naming them would carry the exemption into a shape nobody assessed."""
    with pytest.raises(ValidationError) as exc:
        payload(source=[{"ip": "10.100.0.0/24", "alias": ""}])
    assert "any-to-any" in str(exc.value)


def test_the_shape_is_checked_where_the_zones_are_too(db):
    """The payload model refuses TCP, named addresses and a denying baseline
    before the router ever sees them - so this checks the second lock.

    Both exist on purpose: the schema is the one an API client meets, and
    `problems()` is what every other caller into the domain goes through. A
    check that lives in only one of them is a check the other way round is
    missing.
    """
    claim = SimpleNamespace(
        source_zone=INTERNAL_A, destination_zone=INTERNAL_B,
        source=[{"ip": "10.100.0.5"}], destination=[{"ip": "any"}],
        services=[{"protocol": "TCP", "port": "22"}], action=RuleAction.deny)

    found = " | ".join(ping_baseline.problems(db, claim))

    assert "any-to-any" in found
    assert "echo" in found
    assert "denies" in found


def test_not_between_two_zones_that_are_the_same_zone(db):
    """Traffic inside a zone crosses no firewall, so there is no rule to write
    and nothing the baseline would buy."""
    with pytest.raises(HTTPException) as exc:
        create(db, destination_zone=INTERNAL_A)
    assert "same" in exc.value.detail.lower()


def test_not_naming_a_zone_that_does_not_exist(db):
    """The zones are the rule's whole scope, so an unknown one is not a
    tolerable gap - it is an unbounded permission."""
    with pytest.raises(HTTPException) as exc:
        create(db, destination_zone="Z999")
    assert "Z999" in exc.value.detail


def test_a_zone_with_no_firewall_has_nothing_to_roll_it_out_on(db):
    """The rule would exist in Permitra and nowhere else, which is the state
    this tool exists to make visible rather than to create."""
    db.get(Zone, 2).components = []
    db.commit()

    with pytest.raises(HTTPException) as exc:
        create(db, source_zone=INTERNAL_A, destination_zone=INTERNAL_B)
    assert "firewall" in exc.value.detail.lower()


def test_the_licence_lapses_when_a_zone_is_reclassified(db):
    """The matrix cell can stay exactly as it was while the exception stops
    covering the rule: move either zone out of "internal" and the ping now
    crosses the boundary it was never granted for. Nothing in the matrix check
    can see that, so approving - which means putting the rule back on the
    devices - has to ask again."""
    rule = create(db)
    rule.status = RuleStatus.in_review
    db.commit()
    db.get(Zone, 2).pap_level = "pap"
    db.commit()

    decided = _decide(db, rule.rule_id, architect(db, "freigeber"),
                      ReviewDecision(), RuleStatus.approved, "Rule approved")

    assert decided.status == RuleStatus.deactivated
    assert all(state == "to remove" for state in decided.impl_status.values())
