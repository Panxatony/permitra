"""The NetBox address decides where the server makes a request.

"An admin typed it" is not the same as "it is safe to fetch": the call leaves
from inside the network, so a cloud metadata endpoint or a management interface
is reachable from there even when it is not from the admin's browser. And the
answer must not be able to steer the next request either - a redirect or a
`next` field pointing elsewhere would carry the API token along.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest

from app import netbox
from app.models import NetboxConfig


@pytest.fixture(autouse=True)
def no_local_allowance(monkeypatch):
    """The default: loopback is not a permitted target."""
    monkeypatch.delenv("PERMITRA_ALLOW_LOCAL_NETBOX", raising=False)


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",   # AWS/Azure metadata
    "http://metadata.google.internal/",           # GCP metadata
    "http://127.0.0.1:8000/api/",                 # a service bound to localhost
    "http://localhost:8000/api/",
    "http://[::1]:8000/api/",
    "http://0.0.0.0:8000/",
])
def test_internal_targets_are_refused(url):
    with pytest.raises(ValueError):
        netbox.validate_url(url)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://10.0.0.1:70/",
    "ftp://10.0.0.1/",
])
def test_only_http_and_https_are_allowed(url):
    with pytest.raises(ValueError):
        netbox.validate_url(url)


@pytest.mark.parametrize("url", [
    "https://netbox.example.org/",
    "http://10.20.30.40:8000/",       # a NetBox on the internal network is normal
    "https://netbox.internal:8443/",
])
def test_a_real_netbox_is_accepted(url):
    """The check must not get in the way of the ordinary case."""
    assert netbox.validate_url(url) == url


def test_loopback_is_allowed_only_when_switched_on(monkeypatch):
    monkeypatch.setenv("PERMITRA_ALLOW_LOCAL_NETBOX", "1")
    assert netbox.validate_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000/"


def test_the_response_cannot_point_the_next_request_elsewhere():
    """`next` comes from the remote side; following it blindly would hand the
    token to whatever host that side names."""
    cfg = NetboxConfig(url="https://netbox.example.org", token_enc="", verify_tls=True)
    with pytest.raises(RuntimeError, match="different host"):
        netbox._request(cfg, "https://attacker.example.net/api/ipam/prefixes/")


def test_a_redirect_is_not_followed():
    """urllib follows redirects by default and keeps the Authorization header."""
    handler = netbox._NoRedirects()
    with pytest.raises(RuntimeError, match="redirect"):
        handler.redirect_request(None, None, 302, "Found", {},
                                 "http://169.254.169.254/latest/meta-data/")
