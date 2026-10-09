"""Segments: inside a zone, only defined relations may exist.

The zone matrix governs who may talk across zones; inside a zone everything
was allowed. A segmented zone has a matrix one level down - the same shape,
the same two-approver request - and, once switched to default-deny, an
intra-zone rule needs an allow cell between its two segments. These tests
walk the segment's boundary, the matrix verdict on every rule path, the
switch to deny with its impact, and what happens to a segment that rules
depend on.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import (
    AddressComponentMap,
    AddressGroup,
    ComponentType,
    GroupKind,
    Role,
    Rule,
    RuleStatus,
    SecurityComponent,
    Segment,
    User,
    Vrf,
    Workload,
    Zone,
    ZoneNetwork,
)


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    s.add(SecurityComponent(id=2, name="ACI", type=ComponentType.aci))
    s.add(Zone(id=1, code="Z010", name="APP", sort_order=10))
    s.add(Zone(id=2, code="Z020", name="DB", sort_order=20))
    s.add(ZoneNetwork(cidr="10.0.1.0/24", zone_id=1, vrf_id=1))
    s.add(ZoneNetwork(cidr="10.0.2.0/24", zone_id=2, vrf_id=1))
    s.add(AddressComponentMap(ip="10.0.1.0/24", vrf_id=1, component_ids=[1, 2]))
    s.add(AddressComponentMap(ip="10.0.2.0/24", vrf_id=1, component_ids=[1, 2]))
    for name, role in (("arch", Role.architect), ("ops", Role.operations),
                       ("appr", Role.change_approver), ("appr2", Role.change_approver),
                       ("adm", Role.admin)):
        s.add(User(username=name, full_name=name, role=role, is_active=True,
                   password_hash=hash_password(f"{name}-pw-12345")))
    for name, ip, labels in (("web01", "10.0.1.11", {"app": "shop", "tier": "web"}),
                             ("web02", "10.0.1.12", {"app": "shop", "tier": "web"}),
                             ("app01", "10.0.1.21", {"app": "shop", "tier": "app"}),
                             ("db01", "10.0.2.21", {"app": "shop", "tier": "db"})):
        s.add(Workload(vrf_id=1, name=name, addresses=[ip], labels=labels))
    s.add(AddressGroup(vrf_id=1, name="shop-web", kind=GroupKind.selector, selector="app=shop, tier=web"))
    s.add(AddressGroup(vrf_id=1, name="shop-app", kind=GroupKind.selector, selector="app=shop, tier=app"))
    s.add(AddressGroup(vrf_id=1, name="shop-db", kind=GroupKind.selector, selector="app=shop, tier=db"))
    s.add(AddressGroup(vrf_id=1, name="shop-all", kind=GroupKind.selector, selector="app=shop"))
    s.commit()
    s.close()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    c = TestClient(app, raise_server_exceptions=False)
    yield c, Session
    app.dependency_overrides.clear()


def auth(c, name):
    r = c.post("/api/auth/login", data={"username": name, "password": f"{name}-pw-12345"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def rule_payload(**over):
    payload = {"name": "web-to-app", "source": [{"group": "shop-web"}], "destination": [{"group": "shop-app"}],
               "services": [{"protocol": "TCP", "port": "8080"}], "justification": "app traffic",
               "valid_until": "2027-12-31"}
    payload.update(over)
    return payload


def status_of(Session, rid="SR00001"):
    db = Session()
    try:
        return db.query(Rule).filter_by(rule_id=rid).one().status
    finally:
        db.close()


def segment(c, name, group):
    r = c.post("/api/zones/Z010/segments", json={"name": name, "group": group}, headers=auth(c, "arch"))
    assert r.status_code == 201, r.text
    return r.json()


def request_and_approve(c, items, comment="segmentation"):
    """A matrix request with its two approvals; returns the final decision."""
    r = c.post("/api/zones/matrix/changes", json={"items": items, "comment": comment}, headers=auth(c, "arch"))
    assert r.status_code == 200, r.text
    batch = r.json()["batch_id"]
    change = next(ch for ch in c.get("/api/zones/matrix/changes", headers=auth(c, "arch")).json()
                  if ch["batch_id"] == batch)
    assert c.post(f"/api/zones/matrix/changes/{change['id']}/approve", json={}, headers=auth(c, "appr")).status_code == 200
    r = c.post(f"/api/zones/matrix/changes/{change['id']}/approve", json={}, headers=auth(c, "appr2"))
    assert r.status_code == 200, r.text
    return r.json()


def segmented(c, default="deny"):
    """The zone with two segments and, by default, deny between them."""
    segment(c, "web", "shop-web")
    segment(c, "app", "shop-app")
    if default:
        request_and_approve(c, [{"type": "segment_default", "zone": "Z010", "default": default}])


# ---------- the boundary ----------

def test_a_zone_without_segments_allows_intra_zone_traffic_as_before(client):
    c, _ = client
    r = c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch"))
    assert r.status_code == 201, r.text


def test_a_segment_has_to_lie_inside_its_zone(client):
    """A group with members in another zone would make the zone's matrix
    speak about traffic the zone does not govern."""
    c, _ = client
    r = c.post("/api/zones/Z010/segments", json={"name": "all", "group": "shop-all"}, headers=auth(c, "arch"))
    assert r.status_code == 422 and "Z020" in r.json()["detail"], r.text
    r = c.post("/api/zones/Z010/segments", json={"name": "db", "group": "shop-db"}, headers=auth(c, "arch"))
    assert r.status_code == 422
    r = c.post("/api/zones/Z010/segments", json={"name": "ghost", "group": "nope"}, headers=auth(c, "arch"))
    assert r.status_code == 404
    segment(c, "web", "shop-web")
    assert c.post("/api/zones/Z010/segments", json={"name": "WEB", "group": "shop-app"},
                  headers=auth(c, "arch")).status_code == 409
    assert c.post("/api/zones/Z010/segments", json={"name": "web2", "group": "shop-web"},
                  headers=auth(c, "arch")).status_code == 409


# ---------- the verdict ----------

def test_under_the_permit_default_an_unmaintained_relation_is_allowed_with_a_hint(client):
    """Adding a segment must not silently invalidate the zone's rules; deny is
    a decision with two approvals (below)."""
    c, _ = client
    segmented(c, default=None)
    r = c.post("/api/rules/resolve-components", json={"source": [{"ip": "10.0.1.11"}],
                                                      "destination": [{"ip": "10.0.1.21"}]},
               headers=auth(c, "arch"))
    check = r.json()["segment_check"]
    assert check["allowed"] and check["policy"] == "undefined"
    assert any("not maintained" in m for m in check["messages"])
    assert c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch")).status_code == 201


def test_a_block_cell_refuses_the_rule_whatever_the_default(client):
    c, _ = client
    segmented(c, default=None)
    request_and_approve(c, [{"type": "segment_policy", "zone": "Z010",
                             "from_segment": "web", "to_segment": "app", "policy": "block_all"}])
    r = c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch"))
    assert r.status_code == 422 and "Block" in r.json()["detail"], r.text
    # The matrix is directed: app -> web is a different cell
    r = c.post("/api/rules", json=rule_payload(source=[{"group": "shop-app"}], destination=[{"group": "shop-web"}]),
               headers=auth(c, "arch"))
    assert r.status_code == 201, r.text


def test_under_default_deny_a_rule_needs_an_allow_cell(client):
    c, _ = client
    segmented(c)
    r = c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch"))
    assert r.status_code == 422 and "default-deny" in r.json()["detail"], r.text
    request_and_approve(c, [{"type": "segment_policy", "zone": "Z010",
                             "from_segment": "web", "to_segment": "app", "policy": "allow_only"}])
    r = c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch"))
    assert r.status_code == 201, r.text
    # ... and the allow cell is visible in the matrix and its CSV
    m = c.get("/api/zones/Z010/segments", headers=auth(c, "arch")).json()
    assert m["intra_zone_default"] == "deny"
    assert [s["name"] for s in m["segments"]] == ["app", "web"]
    assert m["policies"] == [{"from_segment": "web", "to_segment": "app", "policy": "allow_only", "note": ""}]
    csv = c.get("/api/zones/Z010/segments/matrix.csv", headers=auth(c, "arch")).text.splitlines()
    assert csv[0].startswith("Z010 from") and csv[2] == "web;Allow;-"
    assert csv[1] == "app;-;Block (default)"


def test_under_default_deny_unsegmented_addresses_and_a_split_side_are_refused(client):
    c, _ = client
    segmented(c)
    request_and_approve(c, [{"type": "segment_policy", "zone": "Z010",
                             "from_segment": "web", "to_segment": "app", "policy": "allow_only"}])
    # An address of the zone that belongs to no segment
    r = c.post("/api/rules", json=rule_payload(source=[{"ip": "10.0.1.99"}]), headers=auth(c, "arch"))
    assert r.status_code == 422 and "no segment" in r.json()["detail"], r.text
    # A source that spans both segments
    r = c.post("/api/rules", json=rule_payload(source=[{"ip": "10.0.1.11"}, {"ip": "10.0.1.21"}]),
               headers=auth(c, "arch"))
    assert r.status_code == 422 and "several segments" in r.json()["detail"], r.text


def test_the_edit_and_restore_paths_face_the_segment_matrix_too(client):
    c, _ = client
    segmented(c)
    request_and_approve(c, [{"type": "segment_policy", "zone": "Z010",
                             "from_segment": "web", "to_segment": "app", "policy": "allow_only"}])
    assert c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch")).status_code == 201
    r = c.put("/api/rules/SR00001", json=rule_payload(source=[{"group": "shop-app"}], destination=[{"group": "shop-web"}]),
              headers=auth(c, "arch"))
    assert r.status_code == 422 and "default-deny" in r.json()["detail"], r.text


# ---------- the switch to deny ----------

def test_switching_to_deny_shows_and_resets_the_rules_it_makes_inadmissible(client):
    """The approvers see which rules the deny would invalidate; once approved,
    those rules go back into review - like a zone cell switched to block."""
    c, Session = client
    segmented(c, default=None)
    assert c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch")).status_code == 201
    assert c.post("/api/rules", json=rule_payload(name="app-to-web", source=[{"group": "shop-app"}],
                                                   destination=[{"group": "shop-web"}]),
                  headers=auth(c, "arch")).status_code == 201
    for rid in ("SR00001", "SR00002"):
        assert c.post(f"/api/rules/{rid}/submit", headers=auth(c, "arch")).status_code == 200
        assert c.post(f"/api/rules/{rid}/approve", json={}, headers=auth(c, "appr")).status_code == 200
    # One relation is maintained before the switch: that rule survives it
    request_and_approve(c, [{"type": "segment_policy", "zone": "Z010",
                             "from_segment": "web", "to_segment": "app", "policy": "allow_only"}])
    r = c.post("/api/zones/matrix/changes",
               json={"items": [{"type": "segment_default", "zone": "Z010", "default": "deny"}]},
               headers=auth(c, "arch"))
    assert r.status_code == 200, r.text
    pending = next(ch for ch in c.get("/api/zones/matrix/changes", headers=auth(c, "arch")).json()
                   if ch["status"] == "pending")
    assert pending["change_type"] == "segment_default"
    assert [a["rule_id"] for a in pending["affected_rules"]] == ["SR00002"]
    # A second request for the same default is refused while this one waits
    assert c.post("/api/zones/matrix/changes",
                  json={"items": [{"type": "segment_default", "zone": "Z010", "default": "deny"}]},
                  headers=auth(c, "arch")).status_code == 409
    assert c.post(f"/api/zones/matrix/changes/{pending['id']}/approve", json={}, headers=auth(c, "appr")).status_code == 200
    assert status_of(Session, "SR00002") == RuleStatus.approved  # nothing before the second approval
    result = c.post(f"/api/zones/matrix/changes/{pending['id']}/approve", json={}, headers=auth(c, "appr2")).json()
    assert result["reviews_reset"] == ["SR00002"]
    assert status_of(Session, "SR00001") == RuleStatus.approved
    assert status_of(Session, "SR00002") == RuleStatus.in_review


def test_a_block_cell_resets_the_rules_of_that_relation(client):
    c, Session = client
    segmented(c)
    request_and_approve(c, [{"type": "segment_policy", "zone": "Z010",
                             "from_segment": "web", "to_segment": "app", "policy": "allow_only"}])
    assert c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch")).status_code == 201
    assert c.post("/api/rules/SR00001/submit", headers=auth(c, "arch")).status_code == 200
    assert c.post("/api/rules/SR00001/approve", json={}, headers=auth(c, "appr")).status_code == 200
    result = request_and_approve(c, [{"type": "segment_policy", "zone": "Z010",
                                      "from_segment": "web", "to_segment": "app", "policy": "block_all"}])
    assert result["reviews_reset"] == ["SR00001"]
    assert status_of(Session) == RuleStatus.in_review


def test_the_default_needs_segments_and_a_change(client):
    c, _ = client
    r = c.post("/api/zones/matrix/changes",
               json={"items": [{"type": "segment_default", "zone": "Z010", "default": "deny"}]},
               headers=auth(c, "arch"))
    assert r.status_code == 422
    segment(c, "web", "shop-web")
    r = c.post("/api/zones/matrix/changes",
               json={"items": [{"type": "segment_default", "zone": "Z010", "default": "permit"}]},
               headers=auth(c, "arch"))
    assert r.status_code == 400  # permit is the state already
    r = c.post("/api/zones/matrix/changes",
               json={"items": [{"type": "segment_policy", "zone": "Z010",
                                "from_segment": "web", "to_segment": "web", "policy": "allow_only"}]},
               headers=auth(c, "arch"))
    assert r.status_code == 400


# ---------- membership and the segment's life ----------

def test_a_workload_joining_a_segment_keeps_the_rule_inside_its_cell(client):
    """The inventory moves, the rule follows the group, and the segment follows
    the group too - so the re-check still finds the allow cell."""
    c, Session = client
    segmented(c)
    request_and_approve(c, [{"type": "segment_policy", "zone": "Z010",
                             "from_segment": "web", "to_segment": "app", "policy": "allow_only"}])
    assert c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch")).status_code == 201
    r = c.post("/api/workloads", json={"name": "web03", "addresses": ["10.0.1.13"],
                                       "labels": {"app": "shop", "tier": "web"}}, headers=auth(c, "ops"))
    assert r.status_code == 201, r.text
    db = Session()
    rule = db.query(Rule).filter_by(rule_id="SR00001").one()
    assert [e["ip"] for e in rule.source] == ["10.0.1.11", "10.0.1.12", "10.0.1.13"]
    db.close()
    # A label change that would put a web host into the app segment makes the
    # rule's source span two segments: refused, the inventory stays as it was
    wid = next(w["id"] for w in c.get("/api/workloads", headers=auth(c, "ops")).json() if w["name"] == "web03")
    r = c.put(f"/api/workloads/{wid}", json={"name": "web03", "addresses": ["10.0.1.21"],
                                             "labels": {"app": "shop", "tier": "web"}}, headers=auth(c, "ops"))
    assert r.status_code == 422 and "several segments" in r.json()["detail"], r.text


def test_a_segment_rules_depend_on_cannot_be_removed_or_rebased(client):
    """An approved rule was checked against the segment's boundary; moving or
    removing the boundary underneath it would leave it out of policy unnoticed.
    A draft is re-checked on approval anyway, so it does not hold the segment."""
    c, Session = client
    segmented(c)
    request_and_approve(c, [{"type": "segment_policy", "zone": "Z010",
                             "from_segment": "web", "to_segment": "app", "policy": "allow_only"}])
    assert c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch")).status_code == 201
    assert c.post("/api/rules/SR00001/submit", headers=auth(c, "arch")).status_code == 200
    assert c.post("/api/rules/SR00001/approve", json={}, headers=auth(c, "appr")).status_code == 200
    db = Session()
    web = db.query(Segment).filter_by(name="web").one().id
    app_seg = db.query(Segment).filter_by(name="app").one().id
    db.close()
    r = c.delete(f"/api/zones/Z010/segments/{web}", headers=auth(c, "arch"))
    assert r.status_code == 409 and "SR00001" in r.json()["detail"]
    r = c.put(f"/api/zones/Z010/segments/{web}", json={"name": "web", "group": "shop-all"}, headers=auth(c, "arch"))
    assert r.status_code == 409
    # A rename is harmless
    r = c.put(f"/api/zones/Z010/segments/{web}", json={"name": "frontend", "group": "shop-web"}, headers=auth(c, "arch"))
    assert r.status_code == 200 and r.json()["name"] == "frontend"
    assert c.delete("/api/rules/SR00001", headers=auth(c, "adm")).status_code == 204
    assert c.delete(f"/api/zones/Z010/segments/{web}", headers=auth(c, "arch")).status_code == 204
    assert c.delete(f"/api/zones/Z010/segments/{app_seg}", headers=auth(c, "arch")).status_code == 204
    # Without segments the zone is not segmented any more: the default is gone
    m = c.get("/api/zones/Z010/segments", headers=auth(c, "arch")).json()
    assert m["segments"] == [] and m["intra_zone_default"] is None


def test_any_service_between_segments_is_a_risk_finding(client):
    c, _ = client
    segmented(c)
    request_and_approve(c, [{"type": "segment_policy", "zone": "Z010",
                             "from_segment": "web", "to_segment": "app", "policy": "allow_only"}])
    r = c.post("/api/rules", json=rule_payload(services=[{"protocol": "any", "port": ""}]), headers=auth(c, "arch"))
    assert r.status_code == 201, r.text
    risk = c.get("/api/rules/SR00001/risk", headers=auth(c, "arch")).json()
    assert any(f["code"] == "any-service" for f in risk["findings"])
