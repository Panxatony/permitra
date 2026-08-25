"""Which firewalls a packet actually crosses, derived from the topology.

The path used to be sorted, not routed: the components came from the address
mapping and were put in order by their north-south tier. That works while an
estate is one straight stack and stops working the moment it is not - and it can
never answer the question that matters, which is whether there *is* a way from
here to there at all. A tier is a number on a box; a route is a fact about the
network.

`ComponentLink` already recorded that fact (OSPF, BGP, transfer networks) and
nothing read it. This module does: the links are the graph, an address is
attached to the component in front of it, and the path is the shortest way
through. Three things follow that the tier ordering could not give:

- **No route is an answer.** Two clusters nothing connects produce no path,
  instead of an invented order that reads like a working one.
- **Every shortest route, not one.** Redundant uplinks are the reason
  redundancy exists; a rule that sits on one route and not the other lets the
  traffic through until the day it fails over.
- **Transit hops appear on their own.** A cluster between the endpoints no
  longer has to be listed by hand on every address behind it.
"""
from collections import deque

from sqlalchemy.orm import Session

from .models import ComponentLink, SecurityComponent

# More than this and the answer is not a path any more, it is a maze. Real
# estates are far below it; the cap is here so a mis-modelled graph cannot turn
# one analysis into an unbounded walk.
MAX_ROUTES = 8
MAX_HOPS = 12


def build_graph(db: Session) -> dict[int, set[int]]:
    """Adjacency of the components, from the links that carry traffic.

    Undirected: a transfer network or an OSPF adjacency carries both ways, and
    an asymmetric path is a routing accident rather than something to model as
    the normal case. Links marked as not carrying transit are documentation of a
    relationship - a management connection, say - and are left out, because a
    packet cannot travel down one.
    """
    graph: dict[int, set[int]] = {}
    for link in db.query(ComponentLink).all():
        if not link.carries_transit:
            continue
        graph.setdefault(link.component_a_id, set()).add(link.component_b_id)
        graph.setdefault(link.component_b_id, set()).add(link.component_a_id)
    return graph


def shortest_routes(graph: dict[int, set[int]], sources: set[int],
                    targets: set[int]) -> list[list[int]]:
    """Every shortest route from any source to any target, as component ids.

    All of them, not the first one found: two uplinks are two ways in, and a
    rule present on one and missing on the other is a hole that only opens on
    the day the first one fails. Longer alternatives are left out - they are
    what routing would use if the short one broke, and reporting them as if
    traffic took them would be noise.
    """
    if not sources or not targets:
        return []
    # An endpoint that is already the other end is a route of one component:
    # both addresses sit behind the same cluster.
    direct = sorted(sources & targets)
    if direct:
        return [[component_id] for component_id in direct]

    frontier = deque((source, [source]) for source in sorted(sources))
    seen = dict.fromkeys(sources, 0)
    found: list[list[int]] = []
    best: int | None = None

    while frontier:
        node, path = frontier.popleft()
        if best is not None and len(path) > best:
            break
        if len(path) > MAX_HOPS:
            continue
        for neighbour in sorted(graph.get(node, ())):
            if neighbour in path:                 # no going back on itself
                continue
            route = [*path, neighbour]
            if neighbour in targets:
                if best is None:
                    best = len(route)
                if len(route) == best:
                    found.append(route)
                    if len(found) >= MAX_ROUTES:
                        return found
                continue
            # A node is worth revisiting on an equally short path, because that
            # is how a second shortest route through it is found at all.
            if seen.get(neighbour, 99) >= len(route) and (best is None or len(route) < best):
                seen[neighbour] = len(route)
                frontier.append((neighbour, route))
    return found


def routes_between(db: Session, source_ids: set[int], target_ids: set[int]) -> list[list[int]]:
    """The shortest routes between two sets of attachment points."""
    return shortest_routes(build_graph(db), set(source_ids), set(target_ids))


def components_by_id(db: Session, ids) -> dict[int, SecurityComponent]:
    if not ids:
        return {}
    rows = db.query(SecurityComponent).filter(SecurityComponent.id.in_(list(ids))).all()
    return {c.id: c for c in rows}
