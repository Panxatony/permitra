"""A rule's life, through the API and out the other side into the overview.

The backend tests cover the transitions in isolation. What they cannot cover is
the promise as a user experiences it: that a rule confirmed on every component
reads as active, and that a deleted rule is still *there* - documented, visible,
and no longer taking effect.

These tests create and delete data. conftest refuses to run them against
anything that is not local for exactly that reason.
"""
import pytest

from conftest import api_call


@pytest.fixture
def architect(sessions):
    return sessions["architekt"]["access_token"]


@pytest.fixture
def operations(sessions):
    return sessions["betrieb"]["access_token"]


@pytest.fixture
def admin(sessions):
    return sessions["admin"]["access_token"]


def test_confirming_every_component_makes_a_rule_active(admin, operations):
    """The point of splitting `approved` from `active`: partial rollout must not
    read as "in service"."""
    _, listing = api_call("GET", "/api/rules?status=approved&limit=200", admin)
    candidate = None
    for rule in listing["items"]:
        impl = rule.get("impl_status") or {}
        names = [c["name"] for c in rule.get("components", [])]
        if names and any(impl.get(n) != "implemented" for n in names):
            candidate = (rule["rule_id"], names, dict(impl))
            break
    assert candidate, "no approved rule with an open component in the demo data"

    rule_id, components, before = candidate
    try:
        api_call("PUT", f"/api/rules/{rule_id}/impl-status", operations,
                 dict.fromkeys(components, "implemented"))
        assert api_call("GET", f"/api/rules/{rule_id}", admin)[1]["status"] == "active"

        # Taking one back returns it to approved.
        api_call("PUT", f"/api/rules/{rule_id}/impl-status", operations,
                 {components[0]: "to change"})
        assert api_call("GET", f"/api/rules/{rule_id}", admin)[1]["status"] == "approved"
    finally:
        api_call("PUT", f"/api/rules/{rule_id}/impl-status", operations,
                 {n: before.get(n, "open") for n in components})


@pytest.fixture
def throwaway_rule(architect, admin):
    """A rule built from addresses that already exist, so the zone derivation
    has something to work with."""
    _, listing = api_call("GET", "/api/rules?limit=1", architect)
    template = listing["items"][0]
    source = template["source"][0]["ip"]
    destination = template["destination"][0]["ip"]

    status, created = api_call("POST", "/api/rules", architect, {
        "name": "e2e-lifecycle", "justification": "created by the end-to-end check",
        "source": [{"ip": source, "alias": ""}],
        "destination": [{"ip": destination, "alias": ""}],
        "services": [{"protocol": "TCP", "port": "8443"}],
        "action": "permit", "component_ids": [], "vrf": "IT",
        "requestor": "e2e", "valid_until": "2027-12-31",
    })
    assert status in (200, 201), created
    # The destination comes back too: asserting against a hard-coded address
    # would pass whether or not the rule was excluded.
    yield created["rule_id"], destination


def test_a_deleted_rule_stays_visible_and_stops_taking_effect(
        throwaway_rule, admin, open_page, instance_language):
    """Visible and in force are two different properties. Only the first one
    survives a deletion - that is the whole design."""
    rule_id, destination = throwaway_rule
    assert api_call("DELETE", f"/api/rules/{rule_id}", admin)[0] == 204

    # Still readable, and it says what happened to it.
    assert api_call("GET", f"/api/rules/{rule_id}", admin)[1]["status"] == "deleted"

    # Still in the overview - a rule that is no longer needed is documented,
    # not made to disappear.
    _, listing = api_call("GET", f"/api/rules?q={rule_id}&limit=50", admin)
    assert rule_id in [r["rule_id"] for r in listing["items"]]

    # But it no longer counts anywhere it would take effect.
    _, search = api_call("GET", f"/api/rules/ip-search?q={destination}", admin)
    hits = [r["rule_id"] for bucket in ("outgoing", "incoming")
            for r in (search or {}).get(bucket, [])]
    assert rule_id not in hits, "a deleted rule still counts in the path analysis"

    # And the overview shows it as such rather than as an ordinary rule.
    instance_language("en")
    page = open_page(f"/rules?q={rule_id}", "architekt")
    assert "Deleted" in page.inner_text("body")
    assert page.locator("tr.row-deleted").count(), "not marked as deleted in the list"
