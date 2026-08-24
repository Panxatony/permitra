"""The source IP in the audit log must not be forgeable.

X-Forwarded-For is a request header - a client can set it to anything. The
audit log hash-chains the source IP in as evidence, so trusting the header
unconditionally lets a client sign a forged origin into the record. SECURITY.md
lists "no forgeable source IPs" under what the release holds; this pins that it
actually does.

The header is believed only from a configured trusted proxy, and then only its
rightmost entry - the address that proxy observed, not whatever the client
prepended.
"""
import os
from types import SimpleNamespace

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest

from app import audit


def request_from(peer, xff=None):
    headers = {"x-forwarded-for": xff} if xff else {}
    return SimpleNamespace(client=SimpleNamespace(host=peer),
                           headers=SimpleNamespace(get=lambda k, d="": headers.get(k, d)))


@pytest.fixture(autouse=True)
def _no_trusted_proxies(monkeypatch):
    monkeypatch.delenv("PERMITRA_TRUSTED_PROXIES", raising=False)
    yield


def test_a_forged_header_from_an_untrusted_peer_is_ignored():
    """The attack: any client sets X-Forwarded-For and expects it recorded."""
    req = request_from("203.0.113.9", xff="1.2.3.4")
    assert audit.client_ip(req) == "203.0.113.9"


def test_without_a_trusted_proxy_the_header_is_never_believed(monkeypatch):
    req = request_from("10.0.0.5", xff="8.8.8.8")
    assert audit.client_ip(req) == "10.0.0.5"


def test_a_trusted_proxy_is_believed_but_only_its_own_observation(monkeypatch):
    """Behind a real proxy, the rightmost entry is what the proxy saw; the
    leftmost is whatever the client chose to prepend."""
    monkeypatch.setenv("PERMITRA_TRUSTED_PROXIES", "10.0.0.0/8")
    # client prepends a lie, the trusted proxy appends the real client
    req = request_from("10.0.0.5", xff="1.2.3.4, 198.51.100.7")
    assert audit.client_ip(req) == "198.51.100.7"


def test_a_forged_header_still_loses_even_with_a_proxy_configured(monkeypatch):
    """The peer is not the trusted proxy - so its header is ignored, forged or
    not."""
    monkeypatch.setenv("PERMITRA_TRUSTED_PROXIES", "10.0.0.0/8")
    req = request_from("203.0.113.9", xff="1.2.3.4")
    assert audit.client_ip(req) == "203.0.113.9"


def test_no_header_means_the_peer(monkeypatch):
    assert audit.client_ip(request_from("192.0.2.1")) == "192.0.2.1"
