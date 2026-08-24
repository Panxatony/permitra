"""Handing a rule's requestor over, through the clicks a person makes.

Both the propose and the confirm endpoints return RuleOut - without the
versions and comments the rule page renders - so setting that partial object as
the page state crashed the render to a grey screen, while the handover itself
had gone through (a reload showed it). An action that succeeds but blanks the
screen teaches people it failed. The page reloads the full rule after each
handover step now; these tests are those two clicks, asserting the page
survives them.
"""
import json
import urllib.request

from conftest import BASE_URL


def _rule_owned_by(token, username):
    req = urllib.request.Request(f"{BASE_URL}/api/rules?status=approved&limit=100",
                                 headers={"Authorization": f"Bearer {token}"})
    for r in json.load(urllib.request.urlopen(req))["items"]:
        if r["requestor"] == username and not r["pending_requestor"]:
            return r["rule_id"]
    return None


def test_proposing_and_confirming_a_handover_never_greys_the_screen(open_page, sessions):
    rid = _rule_owned_by(sessions["architekt"]["access_token"], "architekt")
    assert rid, "no architekt-owned rule to hand over"

    # propose, as the current requestor
    page = open_page(f"/rules/{rid}", user="architekt", wait=1.5)
    page.get_by_role("button", name="Übergeben").click()
    page.locator(".modal select").select_option(value="architekt2")
    page.get_by_role("button", name="Übergabe vorschlagen").click()
    page.wait_for_timeout(1200)
    assert page.permitra_errors == [], page.permitra_errors
    assert "architekt2" in page.inner_text("body")        # pending shown, not blank

    # confirm, as the successor
    page2 = open_page(f"/rules/{rid}", user="architekt2", wait=1.5)
    page2.get_by_role("button", name="Übernahme bestätigen").click()
    page2.wait_for_timeout(1200)
    assert page2.permitra_errors == [], page2.permitra_errors

    # hand it back so the run is repeatable
    back = urllib.request.Request(
        f"{BASE_URL}/api/rules/{rid}/requestor-handover",
        data=json.dumps({"new_requestor": "architekt"}).encode(),
        headers={"Authorization": f"Bearer {sessions['architekt2']['access_token']}",
                 "Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(back)
    confirm = urllib.request.Request(
        f"{BASE_URL}/api/rules/{rid}/requestor-handover/confirm",
        data=b"", headers={"Authorization": f"Bearer {sessions['architekt']['access_token']}"},
        method="POST")
    urllib.request.urlopen(confirm)
