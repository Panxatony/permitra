"""Groups: a rule refers to "the web tier", and the addresses follow the inventory.

A micro-segmentation policy names groups, not addresses. Permitra keeps its
rules address-based - that is what a firewall and a drift comparison check -
so a group is expanded when a rule is written and re-synchronised when its
membership moves. These tests walk that: the selector, the expansion, the
checks the expanded addresses still face, and what a membership change does
to a rule that is already approved.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ.setdefault("PERMITRA_DEV", "1")
os.environ.setdefault("PERMITRA_ALLOW_LOCAL_NETBOX", "1")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import groups, netbox
from app.auth import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import (
    AddressComponentMap,
    AddressGroup,
    ComponentType,
    GroupKind,
    NetboxConfig,
    Role,
    Rule,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
    Workload,
    Zone,
    ZoneNetwork,
    ZonePolicy,
    ZonePolicyType,
)

# ---------- selectors ----------

def test_selector_terms_are_a_conjunction():
    assert groups.selector_matches({"app": "shop", "tier": "web"}, "app=shop, tier=web")
    assert not groups.selector_matches({"app": "shop", "tier": "db"}, "app=shop,tier=web")
    assert groups.selector_matches({"app": "shop", "tier": "db"}, "app=shop,tier!=web")
    assert groups.selector_matches({"env": "prod"}, "env")
    assert not groups.selector_matches({}, "env")


def test_a_selector_has_to_name_a_label():
    with pytest.raises(ValueError):
        groups.validate_selector("   ")
    with pytest.raises(ValueError):
        groups.validate_selector("bad key=1")
    assert groups.validate_selector(" app=shop ,tier=web ") == "app=shop, tier=web"


# ---------- the instance ----------

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
    s.add(ZonePolicy(from_zone_id=1, to_zone_id=2, policy=ZonePolicyType.allow_only))
    for name, role in (("arch", Role.architect), ("ops", Role.operations), ("appr", Role.change_approver)):
        s.add(User(username=name, full_name=name, role=role, is_active=True,
                   password_hash=hash_password(f"{name}-pw-12345")))
    for name, ip, labels in (("web01", "10.0.1.11", {"app": "shop", "tier": "web"}),
                             ("web02", "10.0.1.12", {"app": "shop", "tier": "web"}),
                             ("db01", "10.0.2.21", {"app": "shop", "tier": "db"})):
        s.add(Workload(vrf_id=1, name=name, addresses=[ip], labels=labels))
    s.add(AddressGroup(vrf_id=1, name="shop-web", kind=GroupKind.selector, selector="app=shop, tier=web"))
    s.add(AddressGroup(vrf_id=1, name="shop-db", kind=GroupKind.selector, selector="app=shop, tier=db"))
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
    payload = {"name": "web-to-db", "source": [{"group": "shop-web"}], "destination": [{"group": "shop-db"}],
               "services": [{"protocol": "TCP", "port": "5432"}], "justification": "app traffic",
               "valid_until": "2027-12-31"}
    payload.update(over)
    return payload


def get_rule(Session, rid="SR00001"):
    db = Session()
    try:
        rule = db.query(Rule).filter_by(rule_id=rid).one()
        db.refresh(rule)
        return {"status": rule.status, "source": rule.source, "destination": rule.destination,
                "impl": rule.impl_status, "zones": (rule.source_zone, rule.destination_zone),
                "version": rule.version}
    finally:
        db.close()


# ---------- expansion ----------

def test_a_rule_written_with_groups_stores_the_members_and_the_group_name(client):
    c, Session = client
    r = c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch"))
    assert r.status_code == 201, r.text
    rule = get_rule(Session)
    assert sorted(e["ip"] for e in rule["source"]) == ["10.0.1.11", "10.0.1.12"]
    assert {e["group"] for e in rule["source"]} == {"shop-web"}
    assert [e["alias"] for e in rule["source"]] == ["web01", "web02"]
    assert rule["destination"] == [{"ip": "10.0.2.21", "alias": "db01", "group": "shop-db"}]
    assert rule["zones"] == ("Z010", "Z020")


def test_a_group_that_spans_two_zones_is_refused_like_any_address_list(client):
    c, Session = client
    db = Session()
    db.add(AddressGroup(vrf_id=1, name="everything", kind=GroupKind.selector, selector="app=shop"))
    db.commit()
    db.close()
    r = c.post("/api/rules", json=rule_payload(source=[{"group": "everything"}]), headers=auth(c, "arch"))
    assert r.status_code == 422
    assert "several zones" in r.json()["detail"]


def test_an_unknown_or_empty_group_is_refused(client):
    c, Session = client
    assert c.post("/api/rules", json=rule_payload(source=[{"group": "nope"}]), headers=auth(c, "arch")).status_code == 422
    db = Session()
    db.add(AddressGroup(vrf_id=1, name="ghosts", kind=GroupKind.selector, selector="app=nothing"))
    db.commit()
    db.close()
    r = c.post("/api/rules", json=rule_payload(source=[{"group": "ghosts"}]), headers=auth(c, "arch"))
    assert r.status_code == 422 and "no members" in r.json()["detail"]


def test_a_members_preview_is_available_to_the_form(client):
    c, Session = client
    db = Session()
    gid = db.query(AddressGroup).filter_by(name="shop-web").one().id
    db.close()
    r = c.get(f"/api/objects/groups/{gid}/members", headers=auth(c, "arch"))
    assert r.status_code == 200
    assert r.json()["count"] == 2 and r.json()["rules"] == []


# ---------- membership moves ----------

def approve_and_implement(c, Session):
    c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch"))
    assert c.post("/api/rules/SR00001/submit", headers=auth(c, "arch")).status_code == 200
    assert c.post("/api/rules/SR00001/approve", json={}, headers=auth(c, "appr")).status_code == 200
    assert c.put("/api/rules/SR00001/impl-status", json={"FW": "implemented"}, headers=auth(c, "ops")).status_code == 200
    assert get_rule(Session)["status"] == RuleStatus.active


def test_a_new_workload_with_matching_labels_joins_the_rule_without_a_review(client):
    """The approval covered the selector; the inventory is a fact, not a
    policy. What changes is the device, so the implementation goes back to
    'to change' and the rule drops from active to approved."""
    c, Session = client
    approve_and_implement(c, Session)
    r = c.post("/api/workloads", json={"name": "web03", "addresses": ["10.0.1.13"],
                                       "labels": {"app": "shop", "tier": "web"}}, headers=auth(c, "ops"))
    assert r.status_code == 201, r.text
    rule = get_rule(Session)
    assert sorted(e["ip"] for e in rule["source"]) == ["10.0.1.11", "10.0.1.12", "10.0.1.13"]
    assert rule["status"] == RuleStatus.approved
    assert rule["impl"] == {"FW": "to change"}
    assert rule["version"] >= 4


def test_a_label_change_that_would_move_the_rule_across_zones_is_refused(client):
    """web01 is relabelled as a database: the group would then span two zones
    and the rule could not exist. The inventory change is refused and names
    the rule, nothing is half-applied."""
    c, Session = client
    approve_and_implement(c, Session)
    db = Session()
    wid = db.query(Workload).filter_by(name="web01").one().id
    db.close()
    r = c.put(f"/api/workloads/{wid}", json={"name": "web01", "addresses": ["10.0.1.11"],
                                             "labels": {"app": "shop", "tier": "db"}}, headers=auth(c, "ops"))
    assert r.status_code == 422
    assert "SR00001" in r.json()["detail"]
    assert get_rule(Session)["destination"] == [{"ip": "10.0.2.21", "alias": "db01", "group": "shop-db"}]


def test_editing_the_selector_withdraws_the_approval(client):
    """Somebody changed what the group means: that is a content change."""
    c, Session = client
    approve_and_implement(c, Session)
    db = Session()
    gid = db.query(AddressGroup).filter_by(name="shop-web").one().id
    db.close()
    r = c.put(f"/api/objects/groups/{gid}", json={"name": "shop-web", "kind": "selector",
                                                 "selector": "app=shop, tier=web, env!=test"},
              headers=auth(c, "arch"))
    assert r.status_code == 200, r.text
    # membership unchanged -> no rule rewritten
    assert get_rule(Session)["status"] == RuleStatus.active
    db = Session()
    db.add(Workload(vrf_id=1, name="web09", addresses=["10.0.1.19"], labels={"app": "shop", "tier": "web", "env": "test"}))
    db.commit()
    db.close()
    r = c.put(f"/api/objects/groups/{gid}", json={"name": "shop-web", "kind": "static",
                                                 "members": [{"workload": "web01"}]}, headers=auth(c, "arch"))
    assert r.status_code == 200, r.text
    rule = get_rule(Session)
    assert [e["ip"] for e in rule["source"]] == ["10.0.1.11"]
    assert rule["status"] == RuleStatus.draft


def test_a_referenced_group_cannot_be_deleted_or_renamed(client):
    c, Session = client
    c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch"))
    db = Session()
    gid = db.query(AddressGroup).filter_by(name="shop-web").one().id
    db.close()
    assert c.delete(f"/api/objects/groups/{gid}", headers=auth(c, "arch")).status_code == 409
    r = c.put(f"/api/objects/groups/{gid}", json={"name": "web-tier", "kind": "selector",
                                                 "selector": "app=shop, tier=web"}, headers=auth(c, "arch"))
    assert r.status_code == 409


def test_a_rule_sent_back_as_stored_re_expands_instead_of_keeping_stale_members(client):
    c, Session = client
    c.post("/api/rules", json=rule_payload(), headers=auth(c, "arch"))
    db = Session()
    db.add(Workload(vrf_id=1, name="web03", addresses=["10.0.1.13"], labels={"app": "shop", "tier": "web"}))
    db.commit()
    rule = db.query(Rule).filter_by(rule_id="SR00001").one()
    stored = {"name": rule.name, "source": rule.source, "destination": rule.destination,
              "services": rule.services, "justification": rule.justification, "valid_until": rule.valid_until}
    db.close()
    r = c.put("/api/rules/SR00001", json=stored, headers=auth(c, "arch"))
    assert r.status_code == 200, r.text
    assert sorted(e["ip"] for e in get_rule(Session)["source"]) == ["10.0.1.11", "10.0.1.12", "10.0.1.13"]


# ---------- the NetBox side ----------

DEVICES = {"count": 2, "next": None, "results": [
    {"id": 7, "name": "srv-web-01", "status": {"value": "active"},
     "role": {"slug": "web-server"}, "tenant": {"slug": "shop"}, "site": {"slug": "ffm"},
     "primary_ip4": {"address": "10.0.1.31/24"}, "tags": [{"slug": "pci"}]},
    {"id": 8, "name": "no-address", "status": {"value": "planned"}, "primary_ip4": None, "tags": []},
]}
VMS = {"count": 1, "next": None, "results": [
    {"id": 3, "name": "vm-db-01", "status": {"value": "active"}, "role": {"slug": "database"},
     "cluster": {"name": "ffm-cluster"}, "primary_ip4": {"address": "10.0.2.31/24"}, "tags": []},
]}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = DEVICES if "dcim/devices" in self.path else VMS
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *a):
        pass


def test_netbox_devices_and_vms_become_labelled_workloads(client):
    _c, Session = client
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        db = Session()
        db.add(NetboxConfig(url=f"http://127.0.0.1:{server.server_port}", token_enc=netbox.encrypt_token("x")))
        db.add(AddressGroup(vrf_id=1, name="pci-web", kind=GroupKind.selector, selector="role=web-server, tag.pci=true"))
        db.commit()
        db.close()
        result = netbox.import_workloads(Session(), 1)
        assert result == {"imported": 2, "removed": 0, "without_address": 1}
        db = Session()
        web = db.query(Workload).filter_by(name="srv-web-01").one()
        assert web.addresses == ["10.0.1.31"] and web.source == "netbox"
        assert web.labels == {"kind": "device", "role": "web-server", "tenant": "shop", "site": "ffm",
                              "status": "active", "tag.pci": "true"}
        assert groups.resolve_group(db, db.query(AddressGroup).filter_by(name="pci-web").one())[0]["ip"] == "10.0.1.31"
        db.close()
        # idempotent, and a vanished device is removed
        DEVICES["results"].pop(0)
        netbox.import_workloads(Session(), 1)
        db = Session()
        assert db.query(Workload).filter_by(source="netbox").count() == 1
        db.close()
    finally:
        server.shutdown()


def test_the_form_preview_resolves_a_group_to_its_zone(client):
    """resolve-components is what the form asks while it is being filled in;
    a group reference has to derive the zone the way the submit will."""
    c, _ = client
    r = c.post("/api/rules/resolve-components",
               json={"source": [{"group": "shop-web"}], "destination": [{"group": "nope"}]},
               headers=auth(c, "arch"))
    assert r.status_code == 200, r.text
    assert r.json()["source_zone"] == "Z010"
    assert any("nope" in m for m in r.json()["zone_issues"])
