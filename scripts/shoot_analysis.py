"""Führt eine Pfad-Analyse aus und nimmt das Ergebnis als Screenshot auf."""
import json
import sys
import time
import urllib.parse
import urllib.request

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8090"
OUT = sys.argv[2] if len(sys.argv) > 2 else "website/img"
CHROME = "/usr/bin/chromium"


def login(u, p):
    data = urllib.parse.urlencode({"username": u, "password": p}).encode()
    with urllib.request.urlopen(urllib.request.Request(f"{BASE}/api/auth/login", data=data), timeout=15) as r:
        return json.load(r)


sess = login("architekt", "architekt123")

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
    ctx = browser.new_context(viewport={"width": 1440, "height": 1100}, device_scale_factor=2)
    page = ctx.new_page()
    page.goto(f"{BASE}/login", wait_until="domcontentloaded")
    page.evaluate(
        """([tok, usr]) => {
            localStorage.setItem('permitra_token', tok);
            localStorage.setItem('permitra_user', JSON.stringify(usr));
            localStorage.setItem('permitra_lang', 'de');
        }""",
        [sess["access_token"], sess["user"]],
    )
    page.goto(f"{BASE}/search", wait_until="networkidle")
    time.sleep(1.5)
    inputs = page.locator("input[type='text'], input:not([type])")
    # Quelle: Jump-Host (Z100-MGMT) -> Ziel: PROD-APP (Z040)
    page.locator("input").nth(0).fill("10.10.80.10")
    page.locator("input").nth(1).fill("10.10.30.20")
    page.get_by_role("button", name="Analysieren").click()
    page.wait_for_load_state("networkidle")
    time.sleep(2.0)
    page.screenshot(path=f"{OUT}/analysis.png", full_page=True)
    print("shot analysis.png (with path result)")
    browser.close()
print("done")
