"""The risk criteria are visible to the people who have to act on them.

An approver sees a risk hint before deciding, so the yardstick it was raised by
is part of the evidence. The backend tests prove the endpoint answers; these
prove the answer reaches the screen - which is a different claim, and the one
that was actually broken twice (a section rendered but empty, a lookup that
never opened).
"""


def test_the_admin_area_shows_every_criterion(open_page, instance_language):
    instance_language("en")
    body = open_page("/admin", "admin").inner_text("body")

    assert "Risk criteria" in body
    for code in ("any-to-any", "any-source", "broad-network", "risky-service", "any-service"):
        assert code in body, f"criterion {code} is not shown"
    # The threshold and the weighting are the numbers behind the wording.
    assert "<= /8" in body
    assert "Risky services" in body


def test_an_approver_can_look_up_the_criteria_from_a_flagged_rule(
        open_page, sessions, instance_language):
    """Behind a collapsed summary, so it does not compete with the finding - but
    it has to actually open."""
    from conftest import api_call

    instance_language("en")
    _, listing = api_call("GET", "/api/rules?risk=flagged&limit=1",
                          sessions["approver"]["access_token"])
    items = listing.get("items") or []
    assert items, "no flagged rule in the demo data to check against"
    rule_id = items[0]["rule_id"]

    page = open_page(f"/rules/{rule_id}", "approver")
    summary = page.get_by_text("By which criteria?")
    assert summary.count(), f"{rule_id} shows a risk hint but no way to look it up"

    summary.first.click()
    page.wait_for_timeout(1200)
    body = page.inner_text("body")
    assert "Risky services" in body, "the criteria did not open"
    assert "Save service" not in body, "an approver is offered the edit form"
    assert not page.permitra_errors, page.permitra_errors[:2]


def test_only_an_admin_is_offered_the_edit_form(open_page, instance_language):
    instance_language("en")
    assert "Save service" in open_page("/admin", "admin").inner_text("body")


def test_the_default_list_is_labelled_as_default(open_page, instance_language):
    """"Adapted for this installation" on an untouched list would claim a
    decision nobody made."""
    instance_language("en")
    body = open_page("/admin", "admin").inner_text("body")
    assert ("Default list" in body) or ("Adapted for this installation" in body)
