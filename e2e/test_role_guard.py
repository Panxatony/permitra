"""A typed URL is not a way around the role model.

The navigation hides pages a role has no business on - and hiding is worth
exactly nothing against a link: an admin following /zones from the setup
checklist landed on the zones page. The backend now rejects every action there
(the admin bypass in require_roles is gone), and the route guard is the visible
half: the role is redirected to its home instead of standing on a page whose
every button would 403.
"""


def test_an_admin_following_a_zones_link_lands_on_their_own_page(open_page):
    page = open_page("/zones", user="admin", wait=1.5)
    assert page.url.endswith("/admin"), page.url
    assert page.permitra_errors == [], page.permitra_errors


def test_an_architect_cannot_wander_into_administration(open_page):
    page = open_page("/admin", user="architekt", wait=1.5)
    assert page.url.rstrip("/").endswith("8090") or page.url.endswith("/"), page.url


def test_an_approver_keeps_their_working_pages(open_page):
    """The guard must not overshoot: approvers deliberately reach the rules,
    zones and networks pages read-only - their decisions need the context."""
    page = open_page("/zones", user="approver", wait=1.5)
    assert "/zones" in page.url, page.url
    assert page.permitra_errors == [], page.permitra_errors
