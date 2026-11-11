"""The read-only role, seen through the interface.

The API refuses an auditor every write, and the backend tests prove that for
each endpoint. What they cannot show is the other half: an interface that
offers such an account buttons which then answer 403 is a broken interface, and
one that hides the audit log from the role made to read it is a useless one.
"""
from conftest import api_call


def _a_rule_in_force(sessions) -> str:
    token = sessions["auditor"]["access_token"]
    _, page = api_call("GET", "/api/rules?status=active&limit=1", token)
    return page["items"][0]["rule_id"]


def test_the_navigation_is_the_reading_one(open_page, instance_language):
    instance_language("en")
    page = open_page("/rules", user="auditor")

    assert page.permitra_errors == [], page.permitra_errors
    nav = page.inner_text("nav")
    for label in ("Rules", "Recertification", "Reports", "Audit log"):
        assert label in nav, f"{label} is missing from the auditor's navigation"
    for label in ("Components", "Export", "Administration", "Approvals"):
        assert label not in nav, f"{label} is offered to an account that cannot use it"
    # Creating a rule is the first thing the list offers a working role.
    assert page.locator("button", has_text="New rule").count() == 0


def test_a_rule_is_shown_without_anything_to_act_on(open_page, sessions, instance_language):
    instance_language("en")
    rule_id = _a_rule_in_force(sessions)
    page = open_page(f"/rules/{rule_id}", user="auditor", wait=1.5)

    assert page.permitra_errors == [], page.permitra_errors
    assert rule_id in page.inner_text("body")
    # The history is the point of the visit ...
    assert "Version history" in page.inner_text("body")
    # ... and nothing on the page changes the rule: no workflow button, no
    # comment form, no way into the export, and the implementation status of
    # each component is shown but locked.
    for label in ("Edit", "Submit for review", "Deactivate rule", "Comment", "Approve"):
        assert page.locator("button", has_text=label).count() == 0, label
    assert page.locator("textarea").count() == 0
    assert page.locator(".impl-status select:not([disabled])").count() == 0
    assert page.locator("a", has_text="Export configuration").count() == 0


def test_the_audit_log_is_read_and_verified_but_not_anchored(open_page, instance_language):
    instance_language("en")
    page = open_page("/audit-log", user="auditor", wait=1.5)

    assert page.permitra_errors == [], page.permitra_errors
    # Signing in for this test is itself an entry, so the table is never empty.
    assert page.locator("table tbody tr").count() > 0
    assert page.locator("button", has_text="Anchor now").count() == 0

    page.locator("button", has_text="Verify integrity").click()
    page.wait_for_timeout(1500)
    assert page.permitra_errors == [], page.permitra_errors
    assert "intact" in page.inner_text("body").lower()


def test_pages_of_the_working_roles_send_an_auditor_back(open_page):
    """A typed address must not get further than a link would."""
    for route in ("/rules/new", "/admin", "/export", "/components"):
        page = open_page(route, user="auditor")
        assert page.url.rstrip("/").endswith("/rules"), f"{route} stayed on {page.url}"
        assert page.permitra_errors == [], page.permitra_errors
