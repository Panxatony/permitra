"""The imprint and privacy links: who they may name, and what may end up in them.

Two things have to hold at once and they pull against each other. A publicly
reachable instance needs the links - § 5 DDG asks for them, and asks that a
visitor who has not signed in can reach them. A self-hosted instance must not
carry ours: its operator is the one the imprint names, and printing our address
under somebody else's service is worse than printing none.

The answer is that they are configuration, absent by default. What that leaves
is an operator-supplied string rendered into an `href` on every page, which is a
stored cross-site scripting hole waiting for a typo - so the shape of the value
is checked, not trusted.
"""
import logging
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("PERMITRA_DEV", "1")

from app import legal
from app.database import Base, get_db
from app.main import app


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Neither variable set, whatever the machine running the tests has."""
    monkeypatch.delenv("PERMITRA_IMPRINT_URL", raising=False)
    monkeypatch.delenv("PERMITRA_PRIVACY_URL", raising=False)


# ---------- a fresh installation names nobody ----------

def test_an_unconfigured_instance_offers_no_links():
    """The default has to be silence. A Permitra inside a company network has no
    imprint obligation, and a link pointing at the supplier of the software
    would name the wrong controller on somebody else's service."""
    assert legal.links() == {"imprint_url": "", "privacy_url": ""}


def test_the_public_endpoint_carries_them_before_sign_in(client):
    """The whole point of putting them on the public endpoint: somebody who
    cannot get past the sign-in page is exactly the visitor § 5 DDG has in
    mind."""
    os.environ["PERMITRA_IMPRINT_URL"] = "https://permitra.de/impressum.html"
    os.environ["PERMITRA_PRIVACY_URL"] = "https://permitra.de/datenschutz.html"

    r = client.get("/api/settings/public")   # no Authorization header

    assert r.status_code == 200
    assert r.json()["imprint_url"] == "https://permitra.de/impressum.html"
    assert r.json()["privacy_url"] == "https://permitra.de/datenschutz.html"


def test_the_public_endpoint_reports_them_empty_when_unset(client):
    r = client.get("/api/settings/public")
    assert r.json()["imprint_url"] == ""
    assert r.json()["privacy_url"] == ""
    # The keys are always present, so the interface never has to guess whether
    # an old backend simply does not know about them.
    assert "version" in r.json()


def test_one_link_without_the_other_is_allowed():
    """An operator whose privacy policy lives on the same page as the imprint
    should not be forced to invent a second URL."""
    os.environ["PERMITRA_IMPRINT_URL"] = "https://example.org/impressum"

    assert legal.links() == {"imprint_url": "https://example.org/impressum",
                             "privacy_url": ""}


# ---------- what an operator may put in an href ----------

@pytest.mark.parametrize("value", [
    "javascript:alert(document.cookie)",   # the reason this is checked at all
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "/impressum.html",                     # resolves against the current page
    "impressum.html",
    "permitra.de/impressum.html",          # looks absolute, has no scheme
    "https://",                            # scheme without a host
    "   ",
])
def test_a_value_that_is_not_an_absolute_http_url_is_dropped(value):
    """It is rendered into an `href` on every page of the application. A
    `javascript:` URL there is stored XSS handed over by a typo, and a relative
    path silently points at whatever page the visitor is on."""
    os.environ["PERMITRA_IMPRINT_URL"] = value

    assert legal.links()["imprint_url"] == ""


def test_a_rejected_value_says_so(caplog):
    """Dropping it silently would look like compliance from a distance: the
    operator set the variable, the footer stays empty, and nothing explains
    why."""
    os.environ["PERMITRA_PRIVACY_URL"] = "javascript:alert(1)"

    with caplog.at_level(logging.WARNING):
        legal.links()

    assert "PERMITRA_PRIVACY_URL" in caplog.text


def test_plain_http_is_accepted():
    """An instance on a company network may well not have TLS, and refusing the
    link would leave it without an imprint rather than with a plain one."""
    os.environ["PERMITRA_IMPRINT_URL"] = "http://intranet.example/impressum"

    assert legal.links()["imprint_url"] == "http://intranet.example/impressum"


def test_surrounding_whitespace_is_ignored():
    """A trailing newline out of a .env file must not silently disable the
    imprint."""
    os.environ["PERMITRA_IMPRINT_URL"] = "  https://example.org/impressum\n"

    assert legal.links()["imprint_url"] == "https://example.org/impressum"
