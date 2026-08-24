"""Deleting a user, through the interface a person actually clicks.

The deletion always worked - the backend answers 204 - but the client called
res.json() on the empty body, and Safari surfaced that as "The string did not
match the expected pattern" to an admin who had just successfully deleted an
account. An error message after a successful action teaches people to distrust
both. The Chromium suite never caught it because nothing in it ever deleted a
user; this test is that click.
"""
import json
import urllib.request

from conftest import BASE_URL


def test_deleting_a_user_reports_success_not_a_parser_error(open_page, sessions):
    token = sessions["admin"]["access_token"]
    request = urllib.request.Request(
        f"{BASE_URL}/api/users",
        data=json.dumps({"username": "wegwerf", "password": "Wegwerf2026!x",
                         "full_name": "Wegwerf", "role": "architect"}).encode(),
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"})
    urllib.request.urlopen(request)

    page = open_page("/admin", user="admin", wait=1.5)
    page.on("dialog", lambda d: d.accept())
    # Scoped to the users table: the audit log further down the page also
    # carries the name (user.created, user.deleted) - correctly so, and an
    # unscoped locator mistakes that evidence for a failed deletion.
    users_table = page.locator("table").first
    users_table.locator("tr", has_text="wegwerf").get_by_role(
        "button", name="Löschen").click()
    page.wait_for_timeout(1200)

    assert page.locator(".error").count() == 0
    assert users_table.locator("tr", has_text="wegwerf").count() == 0
    assert page.permitra_errors == [], page.permitra_errors
