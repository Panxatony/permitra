"""The firewalls a packet crosses, derived from the topology rather than sorted.

The path used to come from the address mapping, ordered by each component's
north-south tier. That holds while an estate is one straight stack, and it can
never answer whether there is a way from here to there at all - a tier is a
number on a box, not a fact about the network.

These tests pin what routing buys over ordering, which is mostly the answers
ordering could not give: no route is an answer, a transit cluster appears
without anyone listing it, and a redundant second route is reported rather than
hidden - because a rule sitting on one route and missing on the other lets
traffic through right up until the day it fails over.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import ComponentLink, ComponentType, SecurityComponent
from app.routing import build_graph, routes_between, shortest_routes


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def fw(db, id_, name):
    db.add(SecurityComponent(id=id_, name=name, type=ComponentType.juniper))
    db.commit()


def link(db, a, b, transit=True):
    db.add(ComponentLink(component_a_id=min(a, b), component_b_id=max(a, b),
                         link_type="OSPF Routing", carries_transit=transit))
    db.commit()


def chain(db, n):
    """1 - 2 - ... - n, the plain case."""
    for i in range(1, n + 1):
        fw(db, i, f"FW-{i}")
    for i in range(1, n):
        link(db, i, i + 1)


# ---------- the route itself ----------

def test_a_packet_crosses_every_firewall_on_the_way(db):
    """The headline: four clusters in a row are four hops, in order, and nobody
    had to list the middle two anywhere."""
    chain(db, 4)
    assert routes_between(db, {1}, {4}) == [[1, 2, 3, 4]]


def test_the_route_is_the_short_way_round(db):
    """1-2-3-4 and a 1-4 shortcut: traffic takes the shortcut, and a report
    naming the long way would be describing something that does not happen."""
    chain(db, 4)
    link(db, 1, 4)
    assert routes_between(db, {1}, {4}) == [[1, 4]]


def test_two_addresses_behind_the_same_cluster_cross_one(db):
    chain(db, 3)
    assert routes_between(db, {2}, {2}) == [[2]]


def test_direction_does_not_change_the_route(db):
    """A transfer network carries both ways; an asymmetric path is a routing
    accident, not the normal case to model."""
    chain(db, 4)
    assert routes_between(db, {4}, {1}) == [[4, 3, 2, 1]]


# ---------- what ordering could never say ----------

def test_no_connection_means_no_route_rather_than_an_invented_order(db):
    """Sorting two unconnected clusters by tier produces a sequence that reads
    like a working path. Routing produces nothing, which is the truth."""
    fw(db, 1, "FW-A")
    fw(db, 2, "FW-B")           # deliberately no link
    assert routes_between(db, {1}, {2}) == []


def test_a_link_that_carries_no_traffic_is_not_a_route(db):
    """A documented relationship is not a data path. Routing over one would
    offer a way through that no packet can take."""
    chain(db, 2)
    fw(db, 9, "FW-MGMT")
    link(db, 2, 9, transit=False)
    assert routes_between(db, {1}, {9}) == []


def test_both_redundant_routes_are_reported(db):
    """Two uplinks are the reason redundancy exists. A rule on one and not the
    other works until the failover, so the analysis has to show both."""
    for i, name in ((1, "SRC"), (2, "UP-A"), (3, "UP-B"), (4, "DST")):
        fw(db, i, name)
    link(db, 1, 2)
    link(db, 1, 3)
    link(db, 2, 4)
    link(db, 3, 4)

    routes = routes_between(db, {1}, {4})
    assert sorted(routes) == [[1, 2, 4], [1, 3, 4]]


def test_a_longer_alternative_is_left_out(db):
    """What routing would fall back to if the short way broke is not what the
    traffic does today, and reporting it as if it were is noise."""
    for i in range(1, 6):
        fw(db, i, f"FW-{i}")
    link(db, 1, 2)
    link(db, 2, 5)              # short: 1-2-5
    link(db, 1, 3)
    link(db, 3, 4)
    link(db, 4, 5)              # long:  1-3-4-5

    assert routes_between(db, {1}, {5}) == [[1, 2, 5]]


def test_several_attachment_points_are_all_starting_points(db):
    """An address can hang off more than one cluster - a redundantly attached
    network is normal - and each is a way in."""
    for i, name in ((1, "A"), (2, "B"), (3, "CORE"), (4, "DST")):
        fw(db, i, name)
    link(db, 1, 3)
    link(db, 2, 3)
    link(db, 3, 4)

    assert sorted(routes_between(db, {1, 2}, {4})) == [[1, 3, 4], [2, 3, 4]]


# ---------- the guards ----------

def test_a_graph_without_transit_links_is_empty(db):
    chain(db, 2)
    db.query(ComponentLink).one().carries_transit = False
    db.commit()
    assert build_graph(db) == {}


def test_a_route_never_visits_the_same_cluster_twice(db):
    """A ring must not produce a lap."""
    for i in range(1, 5):
        fw(db, i, f"FW-{i}")
    for a, b in ((1, 2), (2, 3), (3, 4), (4, 1)):
        link(db, a, b)
    for route in routes_between(db, {1}, {3}):
        assert len(route) == len(set(route))


def test_an_endpoint_with_no_attachment_has_no_route(db):
    chain(db, 2)
    assert shortest_routes(build_graph(db), set(), {2}) == []
    assert shortest_routes(build_graph(db), {1}, set()) == []


# ---------- through the analysis endpoint ----------

def analysis_db():
    """A small estate: SRC-FW - CORE - DST-FW, with an address behind each end."""
    from app.models import AddressComponentMap, Vrf
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    for i, name in ((1, "SRC-FW"), (2, "CORE-FW"), (3, "DST-FW")):
        s.add(SecurityComponent(id=i, name=name, type=ComponentType.juniper))
    s.commit()
    s.add(AddressComponentMap(ip="10.0.0.0/24", alias="A", vrf_id=1,
                              component_ids=[1], created_by="t"))
    s.add(AddressComponentMap(ip="10.0.9.0/24", alias="B", vrf_id=1,
                              component_ids=[3], created_by="t"))
    s.commit()
    return s


def analyse(db, src="10.0.0.5", dst="10.0.9.5"):
    from app.models import Role, User
    from app.routers.rules_router import path_analysis
    user = User(username="t", password_hash="x", role=Role.architect)
    return path_analysis(src=src, dst=dst, vrf=None, db=db, _user=user)


def test_the_analysis_names_the_transit_cluster_nobody_mapped(db):
    """The point of routing: CORE-FW is on no address mapping, and it is on the
    path anyway - because the links say so. Under the old tier ordering it could
    only appear if somebody remembered to list it on both networks."""
    s = analysis_db()
    link(s, 1, 2)
    link(s, 2, 3)

    result = analyse(s)
    assert result["routing"] == "routed"
    assert [c["name"] for c in result["components"]] == ["SRC-FW", "CORE-FW", "DST-FW"]
    assert [c["side"] for c in result["components"]] == ["source", "transit", "destination"]
    s.close()


def test_the_analysis_says_no_route_rather_than_ordering_two_islands(db):
    """Documented topology, no way between them. Ordering by tier produced a
    sequence here that looked like a path."""
    s = analysis_db()
    link(s, 1, 2)                     # DST-FW deliberately unconnected
    result = analyse(s)
    assert result["routing"] == "no_route"
    assert result["routes"] == []
    s.close()


def test_an_undocumented_topology_is_not_reported_as_no_route(db):
    """"Nobody wrote the links down" and "there is no way" are different
    statements. An estate that never filled the topology in must not have every
    analysis condemned as unreachable."""
    s = analysis_db()                 # no links at all
    result = analyse(s)
    assert result["routing"] == "not_documented"
    assert {c["name"] for c in result["components"]} == {"SRC-FW", "DST-FW"}
    s.close()
