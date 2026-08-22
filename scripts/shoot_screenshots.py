"""Creates screenshots of the running Permitra demo for the website.

Logs in via the API, sets token/user in localStorage and takes one screenshot
per page at a fixed window size. Uses the system Chromium.
"""
import json
import sys
import time
import urllib.parse
import urllib.request

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8090"
OUT = sys.argv[2] if len(sys.argv) > 2 else "website/img"
CHROME = "/usr/bin/chromium"


def login(username, password):
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(f"{BASE}/api/auth/login", data=data)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


# (file, route, user, wait seconds, optional full page)
SHOTS = [
    ("dashboard.png", "/", "architekt", 2.5, False),
    ("rules.png", "/rules", "architekt", 3.0, False),
    ("zones.png", "/zones", "architekt", 3.0, False),
    ("analysis.png", "/search", "architekt", 2.0, False),
    ("admin-audit.png", "/admin", "admin", 3.0, False),
]

CRED = {
    "architekt": "architekt123",
    "admin": "admin123",
    "approver": "approver123",
    "betrieb": "betrieb123",
}

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
    sessions = {}
    for user in set(s[2] for s in SHOTS):
        sessions[user] = login(user, CRED[user])
        print(f"login {user} OK")

    for fname, route, user, wait, full in SHOTS:
        ctx = browser.new_context(viewport={"width": 1440, "height": 900},
                                  device_scale_factor=2)
        page = ctx.new_page()
        sess = sessions[user]
        page.goto(f"{BASE}/login", wait_until="domcontentloaded")
        page.evaluate(
            """([tok, usr]) => {
                localStorage.setItem('permitra_token', tok);
                localStorage.setItem('permitra_user', JSON.stringify(usr));
                localStorage.setItem('permitra_lang', 'de');
            }""",
            [sess["access_token"], sess["user"]],
        )
        page.goto(f"{BASE}{route}", wait_until="networkidle")
        time.sleep(wait)
        path = f"{OUT}/{fname}"
        page.screenshot(path=path, full_page=full)
        print(f"shot {fname}  ({route}, {user})")
        ctx.close()

    browser.close()
print("done")
