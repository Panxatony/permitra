"""Generates a few audit events and captures the audit log card in the
admin area as a screenshot (feature #25: source IP per event)."""
import json
import sys
import time
import urllib.parse
import urllib.request

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8090"
# The website lives in its own repository; pass its img/ directory as the
# second argument. The default assumes it sits next to this one.
OUT = sys.argv[2] if len(sys.argv) > 2 else "../permitra-website/img"
CHROME = "/usr/bin/chromium"


def login(username, password, otp=None):
    payload = {"username": username, "password": password}
    if otp:
        payload["otp"] = otp
    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(f"{BASE}/api/auth/login", data=data)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return None


def api(method, path, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


# --- generate a few realistic events -----------------------------------------
admin = login("admin", "admin123")["access_token"]
login("architekt", "architekt123")            # auth.login
login("betrieb", "betrieb123")                # auth.login
login("approver", "falsch")                   # auth.login_failed
api("PUT", "/api/settings", admin, {"require_justification": "yes"})   # setting.changed
api("POST", "/api/api-tokens", admin, {"name": "ansible-readonly"})    # apitoken.created
# Log an export
urllib.request.urlopen(urllib.request.Request(
    f"{BASE}/api/export/csv",
    headers={"Authorization": f"Bearer {admin}"}), timeout=15).read()

time.sleep(1)

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
    ctx = browser.new_context(viewport={"width": 1440, "height": 1400},
                              device_scale_factor=2)
    page = ctx.new_page()
    page.goto(f"{BASE}/login", wait_until="domcontentloaded")
    page.evaluate(
        """([tok, usr]) => {
            localStorage.setItem('permitra_token', tok);
            localStorage.setItem('permitra_user', JSON.stringify(usr));
            localStorage.setItem('permitra_lang', 'de');
        }""",
        [admin, login("admin", "admin123")["user"]],
    )
    page.goto(f"{BASE}/admin", wait_until="networkidle")
    time.sleep(2.5)
    # Capture just the audit log card - trigger the integrity check first (#26)
    card = page.locator("section.card", has=page.get_by_text("Audit-Log")).last
    card.scroll_into_view_if_needed()
    time.sleep(0.5)
    try:
        card.get_by_role("button", name="Integrität prüfen").click()
        page.wait_for_load_state("networkidle")
        time.sleep(1.0)
    except Exception as exc:
        print(f"Note: integrity check not triggered ({exc})")
    card.screenshot(path=f"{OUT}/admin-audit.png")
    print("shot admin-audit.png (audit card)")
    browser.close()
print("done")
