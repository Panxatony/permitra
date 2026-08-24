"""Shared setup for the browser checks.

These tests answer a question the unit tests and the build cannot: does the
interface actually run? A component that calls t() without useLang() is valid
JavaScript and builds cleanly - it fails the moment it mounts. A React major
bump compiles fine and then behaves differently. Both happened here, and both
were caught by starting the application and looking at it.

They talk to a real instance over HTTP, so they need one running. See README.md.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request

import pytest
from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("PERMITRA_E2E_URL", "http://localhost:8090").rstrip("/")

# The demo accounts. Deliberately the well-known ones: these tests only ever run
# against an instance started with PERMITRA_DEMO=1.
CREDENTIALS = {
    "admin": "admin123",
    "architekt": "architekt123",
    "architekt2": "architekt2123",
    "betrieb": "betrieb123",
    "approver": "approver123",
}


def _is_local(url: str) -> bool:
    host = urllib.parse.urlparse(url).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "backend", "frontend")


def pytest_configure(config):
    """Refuses to point a mutating test suite at something that is not local.

    These tests create rules, delete them, flip the instance language and change
    implementation statuses. Against the public demo or a real installation that
    is vandalism, and the mistake is one environment variable away - the URL is
    the only thing that differs. PERMITRA_E2E_ALLOW_REMOTE=1 is the deliberate
    way past this, for a throwaway stack that happens not to be on localhost.
    """
    if not _is_local(BASE_URL) and os.environ.get("PERMITRA_E2E_ALLOW_REMOTE") != "1":
        raise pytest.UsageError(
            f"PERMITRA_E2E_URL points at {BASE_URL}, which is not local. These tests "
            "change data. Set PERMITRA_E2E_ALLOW_REMOTE=1 if that instance is "
            "genuinely disposable."
        )


def api_call(method: str, path: str, token: str | None = None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{BASE_URL}{path}", method=method, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        raw = response.read()
        return response.status, (json.loads(raw) if raw else None)


@pytest.fixture(scope="session")
def sessions() -> dict:
    """One signed-in session per demo role, obtained through the API.

    Signing in through the form would test the form on every single case and
    make each test slower and more brittle for no gain; the form has its own
    test.
    """
    out = {}
    for user, password in CREDENTIALS.items():
        data = urllib.parse.urlencode({"username": user, "password": password}).encode()
        req = urllib.request.Request(f"{BASE_URL}/api/auth/login", data=data)
        with urllib.request.urlopen(req, timeout=30) as response:
            out[user] = json.load(response)
    return out


@pytest.fixture(scope="session")
def browser():
    chrome = os.environ.get("PERMITRA_E2E_CHROME")  # a system Chromium, if preferred
    with sync_playwright() as p:
        launched = p.chromium.launch(
            executable_path=chrome or None, args=["--no-sandbox"])
        yield launched
        launched.close()


@pytest.fixture
def instance_language(sessions):
    """Sets the instance language and puts it back afterwards.

    The language is one binding setting for the whole instance, not a per-user
    toggle, so a test that changes it changes it for everything that follows.
    """
    original = api_call("GET", "/api/settings/public")[1].get("ui_language", "en")
    applied = []

    def _set(language: str):
        api_call("PUT", "/api/settings", sessions["admin"]["access_token"],
                 {"ui_language": language})
        applied.append(language)

    yield _set
    if applied:
        _set(original)


@pytest.fixture
def open_page(browser, sessions):
    """Opens a route as a role, with the session already in place.

    Collects page errors and console errors: a blank page caused by a missing
    hook shows up there and nowhere else. Requests that legitimately 403
    (a role reaching for an endpoint it may not have) are not errors.
    """
    contexts = []

    def _open(route: str, user: str = "architekt", wait: float = 1.2):
        context = browser.new_context(viewport={"width": 1400, "height": 1000})
        contexts.append(context)
        page = context.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
        page.on("console", lambda m: errors.append(f"console: {m.text}")
                if m.type == "error" else None)

        session = sessions[user]
        page.goto(f"{BASE_URL}/login", wait_until="domcontentloaded")
        page.evaluate(
            """([token, user]) => {
                localStorage.setItem('permitra_token', token);
                localStorage.setItem('permitra_user', JSON.stringify(user));
            }""", [session["access_token"], session["user"]])
        page.goto(f"{BASE_URL}{route}", wait_until="networkidle")
        page.wait_for_timeout(int(wait * 1000))

        page.permitra_errors = [  # type: ignore[attr-defined]
            e for e in errors
            if "403" not in e and "Failed to load resource" not in e
        ]
        return page

    yield _open
    for context in contexts:
        context.close()
